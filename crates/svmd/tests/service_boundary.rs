#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{
    fs, io::{Read, Write}, net::TcpStream, path::{Path, PathBuf},
    sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}}, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use svm_core::engine::FakeEngine;
use svmd::{networks::FakeSwitches, Service};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("service-boundary-{}-{stamp}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn open(path: &Path) -> Service {
    Service::open(path, 0, Box::new(FakeEngine::default()), Box::<FakeSwitches>::default()).unwrap()
}
fn single_reply(text: &str) -> (u16, &str) {
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().strip_prefix("HTTP/1.1 ").unwrap()
        .split_ascii_whitespace().next().unwrap().parse().unwrap();
    let length: usize = lines.find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().parse().unwrap();
    assert_eq!(body.len(), length, "The connection must end after the declared response body");
    (status, body)
}

fn connect(port: u16, token: Option<&str>) -> TcpStream {
    let mut stream = TcpStream::connect((svm_core::local_auth::SERVICE_HOST, port)).unwrap();
    if let Some(token) = token {
        svm_core::local_auth::client(&mut stream, token, port, Instant::now() + Duration::from_secs(5)).unwrap();
    }
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream
}

fn exchange(port: u16, token: Option<&str>, target: &str, headers: &str) -> (u16, String) {
    let mut stream = connect(port, token);
    write!(stream, "{target} HTTP/1.1\r\n{headers}\r\n\r\n").unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).unwrap();
    let (status, body) = single_reply(&text);
    (status, body.to_string())
}

#[test]
fn authenticates_every_endpoint_and_rejects_browser_or_ambiguous_requests() {
    let home = Temp::new();
    let service = open(&home.0);
    let port = service.port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let task = thread::spawn(move || service.run(flag));
    let token = fs::read_to_string(home.0.join("api-token")).unwrap();
    let host = format!("Host: 127.77.0.1:{port}");
    let good = &host;
    let missing = exchange(port, None, "GET /v1/health", &host);
    let wrong = exchange(port, None, "GET /v1/health", &format!("{host}\r\nAuthorization: invalid"));
    let check = |target, headers: &str| exchange(port, Some(&token), target, headers);
    assert_eq!(missing, wrong);
    assert_eq!(missing.0, 401);
    assert_eq!(exchange(port, None, "POST /v1/shutdown", &host).0, 401);
    assert_eq!(check("GET /v1/health", &format!("Host: example.invalid:{port}")).0, 403);
    for origin in ["null", "http://localhost", "https://example.invalid"] {
        assert_eq!(check("GET /v1/health", &format!("{good}\r\nOrigin: {origin}")).0, 403);
    }
    assert_eq!(check("GET /v1/health", &format!("{good}\r\n{host}")).0, 400);
    assert_eq!(check("GET /v1/health", &format!("{good}\r\nTransfer-Encoding: chunked")).0, 400);
    assert_eq!(check("GET /v1/health", &format!("{good}\r\nContent-Length: 999999")).0, 413);
    assert_eq!(check("GET /v1/events?since=no", good).0, 400);
    assert_eq!(check("POST /v1/shutdown?", good).0, 400);
    let expect = "Expect: 100-continue\r\nContent-Type: application/json\r\nContent-Length: 2";
    for (headers, status) in [
        (format!("{host}\r\n{expect}\r\nAuthorization: invalid"), 401),
        (format!("Host: elsewhere.invalid\r\n{expect}"), 403),
        (format!("{good}\r\nOrigin: null\r\n{expect}"), 403),
        (format!("{good}\r\n{expect}\r\nContent-Length: 2"), 400),
        (format!("{good}\r\n{expect}\r\nExpect: 100-continue"), 400),
        (format!("{good}\r\n{expect}\r\nTransfer-Encoding: chunked"), 400),
        (format!("{good}\r\nExpect: 100-continue\r\nContent-Length: 262145"), 413),
        (format!("{good}\r\nExpect: 100-continue\r\nContent-Length: 2\r\nContent-Type: text/plain"), 415),
        (format!("{good}\r\nExpect: something-else\r\nContent-Length: 2\r\nContent-Type: application/json"), 417),
    ] {
        // The client sends only headers. Each rejection must be final, without a 100 handshake.
        assert_eq!(check("POST /v1/networks", &headers).0, status);
    }
    assert_eq!(check("GET /v1/health", &format!("{good}\r\nExpect: 100-continue\r\nContent-Length: 0")).0, 200);
    assert_eq!(check("GET /v1/unknown", good).0, 404);
    // Only the service address is a valid Host; 127.0.0.1 is where a guest's user-mode network lands.
    for other in ["localhost", "127.0.0.1"] {
        assert_eq!(check("GET /v1/health", &format!("Host: {other}:{port}")).0, 403);
    }
    assert_eq!(check("POST /v1/shutdown", good).0, 200);
    task.join().unwrap().unwrap();
    assert!(stop.load(Ordering::Acquire));
    assert!(!home.0.join("api-port").exists());
    assert!(!fs::read_to_string(home.0.join("svmd.log")).unwrap().contains(&token));
}

#[test]
fn continue_handshake_reads_segmented_body_then_closes_after_one_dispatch() {
    use std::net::Shutdown;
    let home = Temp::new();
    let service = open(&home.0);
    let port = service.port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let task = thread::spawn(move || service.run(flag));
    let token = fs::read_to_string(home.0.join("api-token")).unwrap();
    let credentials = format!("Host: 127.77.0.1:{port}");
    let authenticated = || connect(port, Some(&token));
    let body = format!("{}{}", " ".repeat(8192), r#"{"id":"segmented","name":"Segmented request","mode":"Routed"}"#);
    let header = format!("POST /v1/networks HTTP/1.1\r\n{credentials}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nExpect: 100-Continue\r\n\r\n", body.len());
    let mut stream = authenticated();
    stream.write_all(header.trim_end_matches("\r\n\r\n").as_bytes()).unwrap();
    stream.write_all(b"\r\n\r").unwrap();
    stream.write_all(b"\n").unwrap();
    let mut interim = [0; 25];
    stream.read_exact(&mut interim).unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    for part in body.as_bytes().chunks(513) { stream.write_all(part).unwrap(); }
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (status, data) = single_reply(&response);
    assert_eq!(status, 201);
    assert_eq!(serde_json::from_str::<serde_json::Value>(data).unwrap()["id"], "segmented");

    let mut partial = authenticated();
    write!(partial, "POST /v1/networks HTTP/1.1\r\n{credentials}\r\nContent-Length: 12\r\nContent-Type: application/json\r\n\r\n{{").unwrap();
    partial.shutdown(Shutdown::Write).unwrap();
    response.clear();
    partial.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 400 "));

    let mut stalled = authenticated();
    write!(stalled, "POST /v1/networks HTTP/1.1\r\n{credentials}\r\nContent-Length: 12\r\nContent-Type: application/json\r\n\r\n{{").unwrap();
    response.clear();
    stalled.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 408 "));

    let mut pipelined = authenticated();
    let two = format!("GET /v1/health HTTP/1.1\r\n{credentials}\r\n\r\nPOST /v1/shutdown HTTP/1.1\r\n{credentials}\r\n\r\n");
    pipelined.write_all(two.as_bytes()).unwrap();
    response.clear();
    pipelined.read_to_string(&mut response).unwrap();
    // Coalesced requests are rejected. A split second request can arrive after the one permitted reply.
    assert!(matches!(single_reply(&response).0, 200 | 400));
    assert_eq!(exchange(port, Some(&token), "GET /v1/health", &credentials).0, 200);
    assert_eq!(exchange(port, Some(&token), "POST /v1/shutdown", &credentials).0, 200);
    task.join().unwrap().unwrap();
}

#[test]
fn upgrade_seeds_the_machine_key_from_the_previous_token() {
    // A data folder from before the token rotation: only api-token exists, and running QEMU
    // supervisors derived their identity from it. The first new start must keep that value.
    let home = Temp::new();
    let first = open(&home.0);
    first.run(Arc::new(AtomicBool::new(true))).unwrap();
    let old = fs::read_to_string(home.0.join("api-token")).unwrap();
    fs::remove_file(home.0.join("machine-key")).unwrap();
    let reopened = open(&home.0);
    assert_eq!(fs::read_to_string(home.0.join("machine-key")).unwrap(), old);
    assert!(fs::read_to_string(home.0.join("api-token")).unwrap() != old);
    reopened.run(Arc::new(AtomicBool::new(true))).unwrap();
}

#[test]
fn one_owner_rotating_token_and_crash_tail_recovery() {
    let home = Temp::new();
    let service = open(&home.0);
    assert!(Service::open(&home.0, 0, Box::new(FakeEngine::default()), Box::<FakeSwitches>::default()).is_err());
    let token = fs::read_to_string(home.0.join("api-token")).unwrap();
    assert_eq!(token.len(), 64);
    let machine_key = fs::read_to_string(home.0.join("machine-key")).unwrap();
    assert_eq!(machine_key.len(), 64);
    let stop = Arc::new(AtomicBool::new(true));
    service.run(stop).unwrap();
    let path = home.0.join("svmd.log");
    fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"{\"interrupted\"").unwrap();
    let reopened = open(&home.0);
    assert!(fs::read_to_string(home.0.join("api-token")).unwrap() != token);
    // QEMU supervisors that outlive the restart derive their identity from this key: it must not rotate.
    assert_eq!(fs::read_to_string(home.0.join("machine-key")).unwrap(), machine_key);
    reopened.run(Arc::new(AtomicBool::new(true))).unwrap();
    let log = fs::read_to_string(path).unwrap();
    for (i, line) in log.lines().enumerate() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["id"].as_u64().unwrap(), i as u64 + 1);
    }
}
