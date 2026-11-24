use super::*;
use crate::client::Response;
use std::{collections::BTreeMap, fs, io::{Read, Write}, net::TcpListener, thread, time::{SystemTime, UNIX_EPOCH}};

fn arguments(items: &[&str]) -> Vec<String> { items.iter().map(|s| s.to_string()).collect() }
fn command(items: &[&str]) -> Command { args::parse(&arguments(items)).unwrap() }

#[test]
fn commands_use_the_documented_methods_and_paths() {
    let cases: &[(&[&str], &str, &str)] = &[
        (&["list"], "GET", "/v1/machines"),
        (&["show", "x"], "GET", "/v1/machines/x"),
        (&["start", "x"], "POST", "/v1/machines/x/start"),
        (&["stop", "x"], "POST", "/v1/machines/x/stop"),
        (&["power-off", "x"], "POST", "/v1/machines/x/stop"),
        (&["shutdown", "x"], "POST", "/v1/machines/x/shutdown"),
        (&["restart", "x"], "POST", "/v1/machines/x/restart"),
        (&["trash", "list"], "GET", "/v1/trash"),
        (&["trash", "restore", "abcd"], "POST", "/v1/trash/abcd/restore"),
        (&["trash", "delete", "abcd", "--confirm-name", "Guest A"], "DELETE", "/v1/trash/abcd"),
        (&["pause", "x"], "POST", "/v1/machines/x/pause"),
        (&["resume", "x"], "POST", "/v1/machines/x/resume"),
        (&["snapshots", "x"], "GET", "/v1/machines/x/snapshots"),
        (&["snapshot", "x"], "POST", "/v1/machines/x/snapshots"),
        (&["revert", "x", "sid"], "POST", "/v1/machines/x/snapshots/sid/revert"),
        (&["clone", "x", "--name", "Copy"], "POST", "/v1/machines/x/clone"),
        (&["delete", "x"], "DELETE", "/v1/machines/x"),
        (&["why", "x"], "GET", "/v1/machines/x/capabilities"),
        (&["net", "list"], "GET", "/v1/networks"),
        (&["net", "delete", "lab"], "DELETE", "/v1/networks/lab"),
        (&["net", "leases", "lab"], "GET", "/v1/networks/lab/leases"),
        (&["guard"], "GET", "/v1/guard"),
        (&["guard", "--set", "23"], "PUT", "/v1/guard"),
        (&["host"], "GET", "/v1/host"),
        (&["events", "--since", "7"], "GET", "/v1/events?since=7"),
        (&["service", "status"], "GET", "/v1/health"),
        (&["service", "stop"], "POST", "/v1/shutdown"),
    ];
    for (words, method, path) in cases {
        let mut input = arguments(words);
        input.insert(0, "--json".into());
        let cmd = args::parse(&input).unwrap();
        assert_eq!((cmd.method, cmd.path.as_str(), cmd.json), (*method, *path, true));
    }
}

#[test]
fn options_form_typed_json() {
    let vm = command(&["create", "--os", "Firmware", "--name", "Guest", "--vcpu", "2",
        "--ram", "4", "--disk", "12", "--iso", "image.iso", "--net", "nat", "--json"]);
    assert_eq!(vm.body, Some(json!({"os":"Firmware","name":"Guest","vcpu":2,"ramGb":4,
        "diskGb":12,"isoPath":"image.iso","net":"nat"})));
    assert_eq!(command(&["create", "--name", "g", "--os", "f", "--disk", "base.VHDX"]).body.unwrap()["diskPath"], "base.VHDX");
    let net = command(&["net", "create", "--name", "Lab", "--mode", "isolated", "--id", "lab", "--subnet", "10.77.8.0/24"]);
    assert_eq!(net.body, Some(json!({"id":"lab","name":"Lab","mode":"Isolated segment","subnet":"10.77.8.0/24"})));
    assert_eq!(command(&["snapshot", "vm", "--no-memory", "--name", "Clean"]).body,
               Some(json!({"withMemory":false,"name":"Clean"})));
    assert_eq!(command(&["guard", "--set", "24"]).body, Some(json!({"budgetPct":24})));
    assert_eq!(command(&["delete", "vm", "--keep-copy"]).body, Some(json!({"keepCopy":true})));
    let key = "c2".repeat(150);
    let delete = command(&["trash","delete",&key,"--confirm-name","Installed guest"]);
    assert_eq!(delete.path, format!("/v1/trash/{key}"));
    assert_eq!(delete.body, Some(json!({"confirmName":"Installed guest"})));
    assert_eq!(command(&["trash","delete",&key,"--confirm-name=--json"]).body, Some(json!({"confirmName":"--json"})));
}

#[test]
fn parse_errors_do_not_contact_the_service() {
    for bad in [&["show", "../x"][..], &["guard", "--set", "-2"], &["service", "stop", "extra"],
                &["trash","delete","abcd"], &["trash","delete","abcd","--confirm-name",""],
                &["trash","delete","abcd","--confirm-name","Guest","--confirm-name","Guest"],
                &["trash","restore","../a"], &["trash","restore","invalid"], &["trash","restore","abc"],
                &["restart"], &["shutdown"], &["create", "--name", "a", "--name", "b", "--os", "x"],
                &["create", "--name", "--os", "x"], &["snapshot", "vm", "--unspecified"]] {
        let result = run(&arguments(bad), || panic!("Unexpected connection attempt"));
        assert_eq!(result.code, 1);
    }
}

fn response(status: u16, body: &[u8]) -> Result<Response, ClientError> {
    Ok(Response { status, body: body.to_vec(), headers: BTreeMap::new() })
}

#[test]
fn exit_codes_and_structured_failures() {
    let refused = br#"{"error":{"code":"guard","message":"The host budget is full."}}"#;
    assert_eq!(finish(response(409, refused), false).text, "The host budget is full.");
    let output = finish(response(409, refused), true);
    assert_eq!(output.code, 2);
    assert_eq!(serde_json::from_str::<Value>(&output.text).unwrap()["error"]["code"], "guard");
    assert_eq!(finish(response(500, b""), false).code, 1);
    let offline = run(&arguments(&["service", "status"]), || Err(ClientError::Offline));
    assert_eq!(offline.code, 3);
    assert!(offline.text.ends_with("Start it with: svmd"));
    let ok = finish(response(200, br#"{"status":"ok"}"#), true);
    assert_eq!(ok.code, 0);
    assert_eq!(serde_json::from_str::<Value>(&ok.text).unwrap(), json!({"status":"ok"}));
    assert_eq!(finish(response(204, b""), true).text, "null");
    assert_eq!(finish(response(200, b"malformed"), true).code, 1);
}

#[test]
fn human_output_displays_rows_and_reason_without_terminal_controls() {
    let answer = json!([{"id":"a","name":"Sample\nA","state":"running"}]);
    assert_eq!(table(&answer), "id\tname\tstate\na\tSample A\trunning");
    assert_eq!(table(&json!([])), "No entries.");
    assert!(table(&json!([{"key":"abcd","id":"guest","name":"Guest"}])).starts_with("key\tid\tname\nabcd\tguest\tGuest"));
    for (ip,source) in [(json!("192.0.2.9"),"reported by the guest"),(Value::Null,"not reported by the guest")] {
        let detail = table(&json!({"id":"guest","ip":ip,"addressSource":source}));
        assert!(detail.contains(&format!("addressSource\t{source}")));
        assert!(detail.contains(&format!("ip\t{}",cell(&ip))));
    }
    assert!(table(&json!([{"capability":"USB","allowed":false,"reason":"Unavailable."}])).contains("Unavailable."));
}

#[test]
fn cli_sends_authenticated_loopback_request_and_emits_json() {
    let listener = TcpListener::bind((svm_core::local_auth::SERVICE_HOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let folder = std::env::temp_dir().join(format!("svm-cli-{}-{}", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("api-token"), "d".repeat(64)).unwrap();
    fs::write(folder.join("api-port"), port.to_string()).unwrap();
    let _owner = lock_owner(&folder);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        svm_core::local_auth::server(&mut stream, &"d".repeat(64), port, auth_deadline()).unwrap();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut buffer = [0; 128];
        let mut headers = Vec::new();
        while !headers.windows(4).any(|part| part == b"\r\n\r\n") {
            let n = stream.read(&mut buffer).unwrap();
            assert!(n > 0 && headers.len() < 4096);
            headers.extend_from_slice(&buffer[..n]);
        }
        let headers = String::from_utf8(headers).unwrap();
        assert!(headers.starts_with("GET /v1/health HTTP/1.1\r\n"));
        assert!(headers.contains(&format!("Host: 127.77.0.1:{port}\r\n")));
        assert!(!headers.contains("Authorization:"));
        assert!(!headers.contains(&"d".repeat(64)));
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}").unwrap();
    });
    let output = run(&arguments(&["service", "--json", "status"]), || Client::load(&folder, None));
    server.join().unwrap();
    drop(_owner);
    fs::remove_dir_all(folder).unwrap();
    assert_eq!(output.code, 0);
    assert_eq!(output.text, r#"{"status":"ok"}"#);
}

#[test]
fn stopped_service_with_a_stale_credential_does_not_choose_a_port() {
    let folder = std::env::temp_dir().join(format!("svm-cli-discovery-{}-{}", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("api-token"), "a".repeat(64)).unwrap();
    fs::write(folder.join("api-port"), "47800").unwrap();
    assert!(matches!(Client::load(&folder, None), Err(ClientError::Offline)));
    drop(lock_owner(&folder));
    assert!(matches!(Client::load(&folder, None), Err(ClientError::Offline)));
    fs::write(folder.join("api-port"), "not a port").unwrap();
    let _owner = lock_owner(&folder);
    assert!(matches!(Client::load(&folder, None), Err(ClientError::Other(_))));
    drop(_owner);
    fs::remove_dir_all(folder).unwrap();
}

fn lock_owner(folder: &std::path::Path) -> fs::File {
    let file = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(folder.join("service.lock")).unwrap();
    file.try_lock().unwrap();
    file
}

fn auth_deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(5)
}

#[test]
fn unverified_listener_receives_only_the_public_hello() {
    use std::time::Duration;
    let listener = TcpListener::bind((svm_core::local_auth::SERVICE_HOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let folder = std::env::temp_dir().join(format!("svm-unverified-peer-{}-{}", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir(&folder).unwrap();
    let owner = lock_owner(&folder);
    let token = "b".repeat(64);
    fs::write(folder.join("api-token"), &token).unwrap();
    fs::write(folder.join("api-port"), port.to_string()).unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut hello = [0; 44];
        stream.read_exact(&mut hello).unwrap();
        assert!(hello.starts_with(b"\0SVM-AUTH/1\n"));
        assert!(!hello.windows(16).any(|bytes| bytes == &token.as_bytes()[..16]));
        stream.write_all(&[0; 64]).unwrap();
        assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0, "the client must send no proof or request");
    });
    let client = Client::load(&folder, None).unwrap();
    assert!(client.request_with_timeout("GET", "/v1/health", None, Duration::from_secs(3)).is_err());
    peer.join().unwrap();
    drop(owner);
    fs::remove_dir_all(folder).unwrap();
}
