use crate::{agent::{Agent, AgentCall}, err, local, tools::io_error, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs, io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf}, process::Stdio,
    sync::{atomic::{AtomicBool, Ordering}, Arc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(unix)]
pub(crate) use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(windows)]
pub(crate) use uds_windows::UnixStream;
#[cfg(windows)]
use uds_windows::UnixListener;

const MAX_CALL: usize = crate::guest_file::ENCODED_CHUNK + 16 * 1024;

fn socket_path(directory: &Path, name: &str) -> Result<PathBuf> {
    let absolute = ordinary_path(directory)?.join(name);
    // A pathname socket has O/S limits on the bytes passed to bind and connect.
    // The supervisor, QEMU and the relay client can share the bundle as their working directory.
    if absolute.as_os_str().as_encoded_bytes().len() < 104 { return Ok(absolute); }
    let folder = directory.file_name().ok_or_else(|| err("The guest-agent directory has no name."))?;
    Ok(Path::new(folder).join(name))
}

pub(crate) fn directory(bundle: &Path, ticket: &str) -> PathBuf {
    let hash = format!("{:x}", Sha256::digest(ticket.as_bytes()));
    bundle.join(format!(".ga{}", &hash[..8]))
}

/// Remove the private socket folder of a run whose supervisor is gone (crash or power cut).
/// Call only while no supervisor owns the bundle. A missing folder is fine; anything other than
/// a plain directory holding the two socket names is refused.
pub(crate) fn discard_stale(bundle: &Path, ticket: &str) -> Result<()> {
    let folder = directory(bundle, ticket);
    match fs::symlink_metadata(&folder) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(error)),
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
            return Err(err("The stale guest-agent folder is not a plain directory."));
        }
        Ok(_) => {}
    }
    {
        // Holding the folder and its ancestors stops anyone swapping it for a link while the
        // socket names are removed.
        let held = crate::transfer::LocalFolder::hold(&folder)?;
        for name in ["q", "a"] {
            match fs::remove_file(held.path.join(name)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                other => other.map_err(io_error)?,
            }
        }
    }
    fs::remove_dir(&folder).map_err(io_error)
}

fn ordinary_path(path: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let text = path.to_str().ok_or_else(|| err("The guest-agent socket path is not Unicode."))?;
        Ok(PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(text)))
    }
    #[cfg(unix)]
    Ok(path.to_owned())
}

#[cfg(windows)]
pub(crate) fn protect(path: &Path) -> Result<()> { directory_acl(path,"protect") }
#[cfg(windows)]
pub(crate) fn directory_acl(path:&Path, mode:&str) -> Result<()> {
    let windows = std::env::var_os("SystemRoot").ok_or_else(|| err("Windows system folder is unavailable."))?;
    let exe = PathBuf::from(windows).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut command = crate::tools::command(&exe);
    command.args(["-NoProfile", "-NonInteractive", "-Command", include_str!("agent-directory.ps1")])
        .env("SVM_GUEST_AGENT_DIRECTORY", path).env("SVM_DIRECTORY_ACL_MODE",mode);
    crate::tools::run(command, 8).map(drop)
}

#[cfg(unix)]
pub(crate) fn protect(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)
}

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("q"));
        let _ = fs::remove_file(self.0.join("a"));
        let _ = fs::remove_dir(&self.0);
    }
}

pub(crate) struct Endpoint {
    wire: UnixListener,
    relay: UnixListener,
    _directory: Directory,
    wire_path: PathBuf,
}

impl Endpoint {
    pub(crate) fn open(bundle: &Path, ticket: &str) -> Result<Self> {
        let path = ordinary_path(&directory(bundle, ticket))?;
        #[cfg(windows)]
        fs::create_dir(&path).map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path).map_err(io_error)?;
        }
        let directory = Directory(path);
        local(&directory.0, true)?;
        protect(&directory.0)?;
        let wire_path = socket_path(&directory.0, "q")?;
        let relay_path = socket_path(&directory.0, "a")?;
        if wire_path.is_relative() && std::env::current_dir().map_err(io_error)?.canonicalize().map_err(io_error)? != bundle {
            return Err(err("The QEMU supervisor did not start in its bundle directory."));
        }
        let wire = UnixListener::bind(&wire_path).map_err(io_error)?;
        let relay = UnixListener::bind(relay_path).map_err(io_error)?;
        wire.set_nonblocking(true).map_err(io_error)?;
        relay.set_nonblocking(true).map_err(io_error)?;
        Ok(Self { wire, relay, _directory: directory, wire_path })
    }

    pub(crate) fn arguments(&self) -> [String; 4] {
        let path = self.wire_path.to_string_lossy().replace(',', ",,");
        [
            "-chardev".into(), format!("socket,id=qga0,path={path},server=off"),
            "-device".into(), "virtserialport,bus=svm-agent-bus.0,chardev=qga0,name=org.qemu.guest_agent.0".into(),
        ]
    }

    pub(crate) fn discard_prior_connection(&self) {
        while self.wire.accept().is_ok() {}
    }

    pub(crate) fn serve(self) -> Relay {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let worker = thread::spawn(move || self.serve_until(&flag));
        Relay { stop, worker: Some(worker) }
    }

    fn serve_until(self, stop: &AtomicBool) {
        let mut agent = None;
        while !stop.load(Ordering::Acquire) {
            if agent.is_none() {
                if let Ok((stream, _)) = self.wire.accept() {
                    if stream.set_nonblocking(false).is_ok() { agent = Some(Agent::new(stream)); }
                }
            }
            match self.relay.accept() {
                Ok((mut stream, _)) => {
                    let result = serve_call(&mut stream, agent.as_mut());
                    let _ = send_reply(&mut stream, &encode_result(result));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(30)),
                Err(_) => break,
            }
        }
    }
}

pub(crate) struct Relay {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn send_reply(stream: &mut UnixStream, response: &RelayReply) -> Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(3))).map_err(io_error)?;
    serde_json::to_writer(&mut *stream, response).map_err(io_error)?;
    stream.write_all(b"\n").map_err(io_error)
}

fn read_frame(stream: &mut UnixStream, limit: usize, deadline: Instant) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    let mut bytes = Vec::new();
    loop {
        let time = deadline.checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero()).ok_or_else(|| err("The guest-agent request timed out."))?;
        reader.get_mut().set_read_timeout(Some(time)).map_err(io_error)?;
        let data = reader.fill_buf().map_err(io_error)?;
        if data.is_empty() { return Err(err("The guest-agent request was incomplete.")); }
        let line = data.iter().position(|byte| *byte == b'\n');
        let length = line.unwrap_or(data.len());
        if bytes.len().saturating_add(length) > limit {
            return Err(err("The guest-agent frame was too large."));
        }
        bytes.extend_from_slice(&data[..length]);
        if line.is_some() { return Ok(bytes); }
        reader.consume(length);
    }
}

fn serve_call(stream: &mut UnixStream, agent: Option<&mut Agent>) -> Result<Value> {
    stream.set_nonblocking(false).map_err(io_error)?;
    let raw = read_frame(stream, MAX_CALL, Instant::now() + Duration::from_secs(2))?;
    let request: AgentCall = serde_json::from_slice(&raw).map_err(|_| err("The guest-agent request was invalid."))?;
    let agent = agent.ok_or_else(|| err("The guest agent is not running in this machine."))?;
    agent.call(request)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum RelayReply { Reply(Value), Timeout(u64), Error(String) }

fn encode_result(result: Result<Value>) -> RelayReply {
    match result {
        Ok(value) => RelayReply::Reply(value),
        Err(svm_core::engine::EngineError::Timeout {seconds}) => RelayReply::Timeout(seconds),
        Err(error) => RelayReply::Error(error.to_string()),
    }
}

fn live_directory(bundle: &Path, ticket: &str) -> Result<PathBuf> {
    local(&directory(bundle, ticket), true)
        .map_err(|_| err("The guest agent is not running in this machine."))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RelayInput {
    ticket: String,
    request: AgentCall,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

fn remaining(deadline: Option<Instant>) -> Result<Option<Duration>> {
    deadline.map(|until| until.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())
        .ok_or_else(|| err("The QEMU file download exceeded its time limit."))).transpose()
}

pub(crate) fn call(bundle: &Path, ticket: &str, request: AgentCall, supervisor: &Path, deadline: Option<Instant>) -> Result<Value> {
    let socket = socket_path(&live_directory(bundle, ticket)?, "a")?;
    if socket.is_absolute() { return call_socket(&socket, request, remaining(deadline)?); }
    // A child can set its working directory without changing the service process or other VM requests.
    let timeout_ms = remaining(deadline)?.map(|time| time.as_millis().clamp(1, u64::MAX as u128) as u64);
    let limit = request.reply_limit();
    let mut child = crate::tools::command(supervisor).arg("--qemu-agent-relay").current_dir(bundle)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(io_error)?;
    let sent = serde_json::to_writer(child.stdin.take().expect("piped relay input"), &RelayInput { ticket: ticket.to_owned(), request, timeout_ms });
    let mut bytes = Vec::new();
    let read = child.stdout.take().expect("piped relay output").take((limit + 1) as u64).read_to_end(&mut bytes);
    let status = child.wait().map_err(io_error)?;
    sent.map_err(io_error)?;
    read.map_err(io_error)?;
    if !status.success() { return Err(err("The private guest-agent relay did not complete.")); }
    decode_result(&bytes, limit)
}

/// Private stdio entry point for the service’s validated session in a long bundle path.
pub fn relay_call() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin().lock().take((MAX_CALL + 1) as u64).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() > MAX_CALL { return Err(err("The guest-agent request was too large.")); }
    let input: RelayInput = serde_json::from_slice(&bytes).map_err(io_error)?;
    let bundle = local(&std::env::current_dir().map_err(io_error)?, true)?;
    let socket = socket_path(&live_directory(&bundle, &input.ticket)?, "a")?;
    let result = encode_result(call_socket(&socket, input.request, input.timeout_ms.map(Duration::from_millis)));
    serde_json::to_writer(std::io::stdout().lock(), &result).map_err(io_error)
}

pub(crate) fn call_here(bundle: &Path, ticket: &str, request: AgentCall) -> Result<Value> {
    let socket = socket_path(&live_directory(bundle, ticket)?, "a")?;
    call_socket(&socket, request, None)
}

fn call_socket(socket: &Path, request: AgentCall, timeout: Option<Duration>) -> Result<Value> {
    let budget = timeout.map_or(request.deadline(), |left| left.min(request.deadline()));
    let deadline = Instant::now() + budget;
    let mut stream = UnixStream::connect(socket)
        .map_err(|_| err("The guest agent is not running in this machine."))?;
    stream.set_write_timeout(Some(budget.min(Duration::from_secs(2)))).map_err(io_error)?;
    serde_json::to_writer(&mut stream, &request).map_err(io_error)?;
    stream.write_all(b"\n").map_err(io_error)?;
    let limit = request.reply_limit();
    let bytes = read_frame(&mut stream, limit, deadline)?;
    decode_result(&bytes, limit)
}

fn decode_result(bytes: &[u8], limit: usize) -> Result<Value> {
    if bytes.len() > limit { return Err(err("The guest-agent relay returned too much data.")); }
    match serde_json::from_slice(bytes).map_err(|_| err("The guest-agent relay returned invalid data."))? {
        RelayReply::Reply(value) => Ok(value),
        RelayReply::Timeout(seconds) => Err(svm_core::engine::EngineError::Timeout {seconds}),
        RelayReply::Error(message) => Err(err(message)),
    }
}

#[cfg(test)]
#[test]
fn a_mebibyte_file_chunk_fits_the_private_relay_frames() {
    use crate::guest_file::{FileCall, CHUNK};
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let request = AgentCall::FileTransfer {
        request: FileCall::Write { handle: u64::MAX, data: STANDARD.encode(vec![0xff; CHUNK]) },
    };
    let input = RelayInput { ticket: "fixture-ticket".into(), request, timeout_ms: None };
    assert!(serde_json::to_vec(&input.request).unwrap().len() < MAX_CALL);
    assert!(serde_json::to_vec(&input).unwrap().len() < MAX_CALL);
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn a_stale_socket_folder_from_a_crashed_run_is_discarded() {
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let bundle = std::env::temp_dir().join(format!("svm-ga-stale-{}-{unique}", std::process::id()));
        fs::create_dir(&bundle).unwrap();
        let ticket = "aa-bb-cc";
        discard_stale(&bundle, ticket).expect("no folder is fine");
        let folder = directory(&bundle, ticket);
        fs::create_dir(&folder).unwrap();
        fs::write(folder.join("q"), b"").unwrap();
        fs::write(folder.join("a"), b"").unwrap();
        discard_stale(&bundle, ticket).unwrap();
        assert!(!folder.exists());
        fs::write(&folder, b"not a folder").unwrap();
        assert!(discard_stale(&bundle, ticket).is_err(), "a file in place of the folder is refused");
        fs::remove_file(&folder).unwrap();
        fs::remove_dir(&bundle).unwrap();
    }

    #[test]
    fn socket_directory_is_private_and_removed_with_the_endpoint() {
        let parent = std::env::temp_dir().join(format!("svm-qga-unit-{}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        let bundle = local(&parent, true).unwrap();
        let endpoint = Endpoint::open(&bundle, "fixture").unwrap();
        let protected = endpoint._directory.0.clone();
        // Endpoint creation verifies the Windows ACL before binding either socket.
        assert!(protected.join("q").exists());
        assert!(protected.join("a").exists());
        drop(endpoint);
        assert!(!protected.exists());
        fs::remove_dir(parent).unwrap();
    }
}
