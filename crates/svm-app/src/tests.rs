use super::*;
use std::{
    fs, io::{BufRead, BufReader, Write}, net::TcpListener,
    path::{Path,PathBuf}, sync::atomic::{AtomicU64,Ordering}, thread, time::{Duration,Instant,SystemTime,UNIX_EPOCH},
};

struct Folder(PathBuf);
impl Folder {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1,Ordering::Relaxed);
        let folder = std::env::temp_dir().join(format!("svm-proxy-{}-{stamp}-{sequence}",std::process::id()));
        fs::create_dir(&folder).unwrap(); Self(folder)
    }
}
impl Drop for Folder { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

#[test]
fn malformed_requests_fail_before_service_discovery() {
    let empty = Folder::new();
    for path in ["/api/v2/x","/api/v1/","/api/v1/../x","/api/v1//x","/api/v1/./shutdown",
        "/api/v1/shutdown","/api/v1/shutdown?","/api/v1/shutdown?x=1","/api/v1/%73hutdown",
        "/api/v1/x\\y","/api/v1/x\r\n","/api/v1/x\0","/api/v1/x?since=%30"] {
        assert_eq!(handle(&empty.0,"POST",path,None,&[]).status,400);
    }
    for method in ["OPTIONS","TRACE","HEAD","CONNECT","get"] {
        assert_eq!(handle(&empty.0,method,"/api/v1/health",None,&[]).status,400);
    }
    for method in ["GET","POST","PUT","PATCH","DELETE"] {
        let reply = handle(&empty.0,method,"/api/v1/health",None,&[]);
        assert_eq!(reply.status,503);
        assert_eq!(serde_json::from_slice::<Value>(&reply.body).unwrap()["error"]["code"],"service_offline");
    }
    for (method,mime,body) in [("POST","text/plain",b"{}".as_slice()),("GET","application/json",b"{}"),
        ("PUT","application/json",b"not json"),("PATCH","application/json",b"[]")] {
        assert_eq!(handle(&empty.0,method,"/api/v1/guard",Some(mime),body).status,400);
    }
    assert_eq!(handle(&empty.0,"POST","/api/v1/machines",Some("application/json"),&vec![b' ';256*1024+1]).status,400);
    assert_eq!(handle(&empty.0,"PUT","/api/v1/settings/qemu",Some("application/json"),br#"{"path":"x"}"#).status,503);
}

fn peer(body: Vec<u8>, extra: &str, mime: &str, path: &str, reply_secret: bool) -> PageResponse {
    let home = Folder::new();
    let listener = TcpListener::bind((svm_core::local_auth::SERVICE_HOST,0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    // A disposable credential, scoped to this in-process fixture.
    let fixture = format!("{:064x}",SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
    fs::write(home.0.join("api-token"), &fixture).unwrap();
    fs::write(home.0.join("api-port"),port.to_string()).unwrap();
    let owner = fs::OpenOptions::new().read(true).write(true).create_new(true).open(home.0.join("service.lock")).unwrap();
    owner.try_lock().unwrap();
    thread::scope(|scope| {
        let secret = fixture.as_str();
        scope.spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            svm_core::local_auth::server(&mut socket, secret, port, Instant::now() + Duration::from_secs(5)).unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut first = String::new(); reader.read_line(&mut first).unwrap();
            assert!(first.starts_with(&format!("GET {path} HTTP/1.1")));
            loop {
                let mut line = String::new(); reader.read_line(&mut line).unwrap();
                if line == "\r\n" { break; }
                assert!(!line.to_ascii_lowercase().starts_with("origin:"));
                assert!(!line.to_ascii_lowercase().starts_with("authorization:"));
                assert!(!line.contains(secret));
            }
            let data = if reply_secret { json!({"unsafeEcho":secret}).to_string().into_bytes() } else { body };
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nX-Private: {secret}\r\n{extra}\r\n",data.len()).unwrap();
            socket.write_all(&data).unwrap();
        });
        let response = handle(&home.0,"GET",&format!("/api{path}"),None,&[]);
        assert!(!response.headers.iter().any(|(k,v)| k=="X-Private" || v.contains(&fixture)));
        assert!(!response.body.windows(fixture.len()).any(|b| b==fixture.as_bytes()));
        response
    })
}
#[test]
fn client_authenticates_privately_and_filters_response_metadata() {
    assert_eq!(peer(b"{}".to_vec(),"","application/json","/v1/health",false).status,200);
    assert_eq!(peer(Vec::new(),"","application/json","/v1/health",true).status,502);
}
#[test]
fn forwards_only_well_formed_frames_and_their_dimensions() {
    let reply = peer(vec![12,34,56,255],"X-Width: 1\r\nX-Height: 1\r\nX-Pixel-Format: RGBA8\r\n",
        "application/octet-stream","/v1/machines/opaque/thumbnail",false);
    assert_eq!(reply.body,[12,34,56,255]);
    assert!(reply.headers.contains(&("X-Width".to_string(),"1".to_string())));
    assert_eq!(peer(vec![0;3],"X-Width: 1\r\nX-Height: 1\r\nX-Pixel-Format: RGBA8\r\n","application/octet-stream","/v1/machines/opaque/thumbnail",false).status,502);
}
#[test]
fn every_ui_file_has_its_original_bytes_mime_type_and_policy() {
    fn visit(dir: &Path, root: &Path, count:&mut usize) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                // ui/tools holds development checks, which the app does not serve.
                if dir == root && path.file_name().is_some_and(|name| name == "tools") {
                    assert_eq!(asset("/tools/check.mjs").status, 404);
                    continue;
                }
                visit(&path,root,count);
                continue;
            }
            let key = format!("/{}",path.strip_prefix(root).unwrap().to_string_lossy().replace('\\',"/"));
            let reply = asset(&key);
            assert_eq!(reply.status,200);
            assert_eq!(reply.body,fs::read(&path).unwrap());
            let expected = match path.extension().unwrap().to_str().unwrap() {
                "html"=>"text/html","js"|"mjs"=>"text/javascript","css"=>"text/css","svg"=>"image/svg+xml",
                "png"=>"image/png","json"=>"application/json","txt"|"md"=>"text/plain",other=>panic!("Missing type: {other}"),
            };
            assert!(reply.headers.iter().any(|(k,v)|k=="Content-Type" && v.starts_with(expected)));
            assert!(reply.headers.iter().any(|(k,v)| k=="Content-Security-Policy" && v==CSP));
            *count+=1;
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui");
    let mut count=0; visit(&root,&root,&mut count);
    assert_eq!(count,ASSETS.len());
    assert_eq!(asset("/not-here.html").status,404);
    assert_eq!(handle(&root,"GET","/screens/../index.html",None,&[]).status,400);
    assert!(!asset("/notices.txt").body.is_empty());
}
