use crate::{err, guest_file::{FileCall, CHUNK, ENCODED_CHUNK}, tools::io_error, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, BufReader, Write},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use crate::agent_transport::UnixStream;

const MAX_OUTPUT: usize = 1024 * 1024;
const SMALL_FILE: usize = 64 * 1024;
const SMALL_REPLY: usize = 8 * 1024;
const INFO_REPLY: usize = 64 * 1024;
const EXEC_REPLY: usize = 2 * ENCODED_CHUNK + SMALL_REPLY;
const SHORT_TIMEOUT: Duration = Duration::from_secs(2);

use svm_core::engine::GuestExecRequest as ExecRequest;

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Reply<T> { Return(T), Error(AgentError) }

#[derive(Deserialize)]
struct AgentError { class: Option<String> }

#[derive(Deserialize)]
struct Empty {}

#[derive(Deserialize)]
struct AgentInfo { version: String, supported_commands: Option<Vec<CommandInfo>> }

#[derive(Deserialize)]
struct CommandInfo { name: String, enabled: bool }

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct OsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pretty_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_version: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Interface {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_addresses: Option<Vec<InterfaceAddress>>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct InterfaceAddress {
    ip_address: String,
    ip_address_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<u8>,
}

#[derive(Deserialize)]
struct ProcessId { pid: u64 }

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ProcessStatus {
    exited: bool,
    exitcode: Option<i64>,
    signal: Option<i64>,
    out_data: Option<String>,
    err_data: Option<String>,
    out_truncated: Option<bool>,
    err_truncated: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct FileRead { count: u64, buf_b64: Option<String>, eof: bool }

#[derive(Deserialize, Serialize)]
struct FileWrite {
    count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    eof: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum FreezeStatus { Thawed, Frozen }

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum AgentCall {
    Status,
    Addresses,
    Exec { request: ExecRequest },
    ReadSmallFile { path: String },
    WriteSmallFile { path: String, data: String },
    FileTransfer { request: FileCall },
    Shutdown,
    SnapshotProbe,
    Freeze,
    Thaw,
}

impl AgentCall {
    pub(crate) fn reply_limit(&self) -> usize {
        match self {
            // The relay returns bounded decoded text, which may be JSON-escaped.
            Self::Exec { .. } => 2 * MAX_OUTPUT * 6 + SMALL_REPLY,
            Self::FileTransfer { request: FileCall::Read { .. } } => ENCODED_CHUNK + 2 * SMALL_REPLY,
            _ => 2 * INFO_REPLY + SMALL_REPLY,
        }
    }

    pub(crate) fn deadline(&self) -> Duration {
        match self {
            Self::Exec { request } => Duration::from_secs(request.timeout_sec.min(120) + 4),
            Self::ReadSmallFile { .. } | Self::WriteSmallFile { .. } => Duration::from_secs(9),
            Self::SnapshotProbe | Self::Freeze => Duration::from_secs(8),
            Self::Thaw => Duration::from_secs(11),
            _ => Duration::from_secs(5),
        }
    }
}

fn agent_io(error: io::Error) -> svm_core::engine::EngineError {
    if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
        svm_core::engine::EngineError::Timeout { seconds: 0 }
    } else {
        io_error(error)
    }
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline.checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(svm_core::engine::EngineError::Timeout { seconds: 0 })
}

pub(crate) struct Agent {
    stream: BufReader<UnixStream>,
}

impl Agent {
    pub(crate) fn new(stream: UnixStream) -> Self {
        Self { stream: BufReader::new(stream) }
    }

    fn send(&mut self, value: Value, delimiter: bool, deadline: Instant) -> Result<()> {
        let stream = self.stream.get_mut();
        stream.set_write_timeout(Some(remaining(deadline)?)).map_err(io_error)?;
        let mut frame = Vec::new();
        if delimiter { frame.push(0xff); }
        serde_json::to_writer(&mut frame, &value).map_err(io_error)?;
        frame.push(b'\n');
        stream.write_all(&frame).map_err(agent_io)
    }

    fn read_through(&mut self, delimiter: u8, limit: usize, deadline: Instant) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        loop {
            self.stream.get_mut().set_read_timeout(Some(remaining(deadline)?)).map_err(io_error)?;
            let buffer = self.stream.fill_buf().map_err(agent_io)?;
            if buffer.is_empty() { return Err(err("The guest agent disconnected.")); }
            let end = buffer.iter().position(|byte| *byte == delimiter);
            let length = end.unwrap_or(buffer.len());
            if result.len().saturating_add(length) > limit {
                return Err(err("The guest agent reply exceeded its size limit."));
            }
            result.extend_from_slice(&buffer[..length]);
            self.stream.consume(length + usize::from(end.is_some()));
            if end.is_some() { return Ok(result); }
        }
    }

    fn reply<T: DeserializeOwned>(&mut self, limit: usize, deadline: Instant) -> Result<T> {
        let data = self.read_through(b'\n', limit, deadline)?;
        match serde_json::from_slice(&data).map_err(|_| err("The guest agent returned invalid data."))? {
            Reply::Return(value) => Ok(value),
            Reply::Error(error) => {
                let class = error.class.filter(|class| class.len() <= 64 && class.bytes().all(|byte| byte.is_ascii_alphanumeric()));
                Err(err(match class {
                    Some(class) => format!("The guest agent declined the operation ({class})."),
                    None => "The guest agent declined the operation.".to_owned(),
                }))
            }
        }
    }

    fn synchronize(&mut self) -> Result<()> {
        self.synchronize_until(Instant::now() + SHORT_TIMEOUT)
    }

    fn send_sync(&mut self, deadline: Instant) -> Result<u64> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed) & i64::MAX as u64;
        self.send(json!({"execute":"guest-sync-delimited","arguments":{"id":id}}), true, deadline)?;
        Ok(id)
    }

    fn await_sync(&mut self, id: u64, deadline: Instant) -> Result<()> {
        loop {
            self.read_through(0xff, EXEC_REPLY, deadline)?;
            if self.reply::<u64>(SMALL_REPLY, deadline)? == id { return Ok(()); }
        }
    }

    fn synchronize_until(&mut self, deadline: Instant) -> Result<()> {
        let id = self.send_sync(deadline)?;
        self.await_sync(id, deadline)
    }

    fn thaw(&mut self) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let id = self.send_sync(deadline)?;
        // Queue thaw behind the delimiter immediately, even when the preceding freeze is still blocked.
        self.send(json!({"execute":"guest-fsfreeze-thaw","arguments":{}}), false, deadline)?;
        self.await_sync(id, deadline)?;
        Ok(json!(self.reply::<u64>(SMALL_REPLY, deadline)?))
    }

    fn execute<T: DeserializeOwned>(&mut self, name: &str, arguments: Value, limit: usize, deadline: Instant) -> Result<T> {
        self.send(json!({"execute":name,"arguments":arguments}), false, deadline)?;
        self.reply(limit, deadline)
    }

    fn inspect(&mut self) -> Result<Value> {
        let deadline = Instant::now() + SHORT_TIMEOUT;
        self.execute::<Empty>("guest-ping", json!({}), SMALL_REPLY, deadline)?;
        let info: AgentInfo = self.execute("guest-info", json!({}), INFO_REPLY, deadline)?;
        let os = self.execute::<OsInfo>("guest-get-osinfo", json!({}), SMALL_REPLY, deadline).ok();
        Ok(json!({"present":true,"version":info.version,"os":os}))
    }

    fn run_command(&mut self, request: ExecRequest) -> Result<Value> {
        request.check()?;
        let deadline = Instant::now() + Duration::from_secs(request.timeout_sec);
        let timeout = request.timeout_sec;
        self.run_until(request, deadline).map_err(|error| {
            if matches!(error, svm_core::engine::EngineError::Timeout { .. }) || Instant::now() >= deadline {
                svm_core::engine::EngineError::Timeout {seconds:timeout}
            }
            else { error }
        })
    }

    fn run_until(&mut self, request: ExecRequest, deadline: Instant) -> Result<Value> {
        let mut args = json!({"path":request.argv[0],"arg":&request.argv[1..],"capture-output":true});
        if let Some(stdin) = request.stdin { args["input-data"] = json!(STANDARD.encode(stdin)); }
        let ProcessId { pid } = self.execute("guest-exec", args, SMALL_REPLY, deadline)?;
        if pid == 0 { return Err(err("The guest agent did not provide a command ID.")); }
        loop {
            let status: ProcessStatus = self.execute("guest-exec-status", json!({"pid":pid}), EXEC_REPLY, deadline)?;
            if status.exited { return command_output(status); }
            thread::sleep(remaining(deadline)?.min(Duration::from_millis(100)));
        }
    }

    fn small_file(&mut self, path: String, data: Option<String>) -> Result<Value> {
        if path.is_empty() || path.len() > 4096 || path.contains('\0') {
            return Err(err("Supply a valid path inside the guest."));
        }
        let (mode, write_len) = if let Some(data) = data.as_deref() {
            let length = STANDARD.decode(data).map_err(|_|err("Guest file data must be base64."))?.len();
            if length > SMALL_FILE {
                return Err(err("Guest file data exceeds 64 KiB."));
            }
            ("wb", Some(length))
        } else { ("rb", None) };
        let deadline = Instant::now() + SHORT_TIMEOUT;
        let handle: u64 = self.execute("guest-file-open", json!({"path":path,"mode":mode}), SMALL_REPLY, deadline)?;
        let result = match data {
            Some(data) => self.execute::<FileWrite>("guest-file-write", json!({"handle":handle,"buf-b64":data}), SMALL_REPLY, deadline)
                .and_then(|reply| {
                    if Some(reply.count as usize) != write_len || reply.count > SMALL_FILE as u64 {
                        return Err(err("The guest agent did not write the complete file."));
                    }
                    Ok(json!(reply))
                }),
            None => self.execute::<FileRead>("guest-file-read", json!({"handle":handle,"count":SMALL_FILE}), 128 * 1024, deadline)
                .and_then(|reply| {
                    let bytes = STANDARD.decode(reply.buf_b64.as_deref().unwrap_or_default())
                        .map_err(|_| err("The guest agent returned invalid file data."))?;
                    if reply.count != bytes.len() as u64 || bytes.len() > SMALL_FILE {
                        return Err(err("The guest agent returned an invalid file byte count."));
                    }
                    Ok(json!(reply))
                }),
        };
        // Recover framing after a failure before trying to close the guest's handle.
        let ready_to_close = if result.is_err() { self.synchronize() } else { Ok(()) };
        let close = ready_to_close.and_then(|()|
            self.execute::<Empty>("guest-file-close", json!({"handle":handle}), SMALL_REPLY, Instant::now() + SHORT_TIMEOUT));
        result.and_then(|value| close.map(|_| value))
    }

    fn file_transfer(&mut self, request: FileCall) -> Result<Value> {
        let deadline = Instant::now() + SHORT_TIMEOUT;
        match request {
            FileCall::Open { path, write } => {
                if path.is_empty() || path.len() > 8192 || path.contains('\0') {
                    return Err(err("Supply a valid path inside the guest."));
                }
                let mode = if write { "r+b" } else { "rb" };
                Ok(json!(self.execute::<u64>("guest-file-open", json!({"path":path,"mode":mode}), SMALL_REPLY, deadline)?))
            }
            FileCall::Read { handle } => Ok(json!(self.execute::<FileRead>(
                "guest-file-read", json!({"handle":handle,"count":CHUNK}), ENCODED_CHUNK + SMALL_REPLY, deadline,
            )?)),
            FileCall::Write { handle, data } => {
                if data.is_empty() || data.len() > ENCODED_CHUNK {
                    return Err(err("The guest file chunk exceeded its size limit or was empty."));
                }
                Ok(json!(self.execute::<FileWrite>("guest-file-write", json!({"handle":handle,"buf-b64":data}), SMALL_REPLY, deadline)?))
            }
            FileCall::Close { handle } => {
                self.execute::<Empty>("guest-file-close", json!({"handle":handle}), SMALL_REPLY, deadline)?;
                Ok(json!({}))
            }
        }
    }

    pub(crate) fn call(&mut self, call: AgentCall) -> Result<Value> {
        if !matches!(&call, AgentCall::Thaw) {
            self.synchronize().map_err(|_| err("The guest agent is not running in this machine."))?;
        }
        match call {
            AgentCall::Status => self.inspect(),
            AgentCall::Addresses => Ok(json!(self.execute::<Vec<Interface>>(
                "guest-network-get-interfaces", json!({}), INFO_REPLY, Instant::now() + SHORT_TIMEOUT,
            )?)),
            AgentCall::Exec { request } => self.run_command(request),
            AgentCall::ReadSmallFile { path } => self.small_file(path, None),
            AgentCall::WriteSmallFile { path, data } => self.small_file(path, Some(data)),
            AgentCall::FileTransfer { request } => self.file_transfer(request),
            AgentCall::SnapshotProbe => {
                let deadline = Instant::now() + Duration::from_secs(5);
                let info: AgentInfo = self.execute("guest-info", json!({}), INFO_REPLY, deadline)?;
                let commands = info.supported_commands
                    .ok_or_else(|| err("The guest agent did not report its checkpoint capabilities."))?;
                let capable = ["guest-fsfreeze-freeze", "guest-fsfreeze-thaw", "guest-fsfreeze-status"]
                    .iter().all(|name| commands.iter().any(|row| row.name == *name && row.enabled));
                if !capable { return Ok(Value::Null); }
                Ok(json!(self.execute::<FreezeStatus>("guest-fsfreeze-status", json!({}), SMALL_REPLY, deadline)?))
            }
            AgentCall::Freeze => Ok(json!(self.execute::<u64>("guest-fsfreeze-freeze", json!({}), SMALL_REPLY, Instant::now() + Duration::from_secs(5))?)),
            AgentCall::Thaw => self.thaw(),
            AgentCall::Shutdown => {
                self.send(json!({"execute":"guest-shutdown","arguments":{"mode":"powerdown"}}), false, Instant::now() + SHORT_TIMEOUT)?;
                Ok(json!({"accepted":true}))
            }
        }
    }
}

fn bounded_output(data: Option<&str>, guest_truncated: Option<bool>) -> Result<(String, bool)> {
    let (mut bytes, mut truncated) = match data {
        Some(encoded) => {
            // Decode only enough complete groups to detect truncation.
            let encoded_limit = ((MAX_OUTPUT + 3) / 3) * 4;
            let prefix = encoded.get(..encoded_limit.min(encoded.len())).ok_or_else(|| err("The guest agent returned invalid output."))?;
            let bytes = STANDARD.decode(prefix).map_err(|_| err("The guest agent returned invalid output."))?;
            let truncated = bytes.len() > MAX_OUTPUT || prefix.len() < encoded.len();
            (bytes, truncated)
        }
        None => (Vec::new(), false),
    };
    bytes.truncate(MAX_OUTPUT);
    let mut output = String::from_utf8_lossy(&bytes).into_owned();
    if output.len() > MAX_OUTPUT {
        let mut end = MAX_OUTPUT;
        while !output.is_char_boundary(end) { end -= 1; }
        output.truncate(end);
        truncated = true;
    }
    Ok((output, truncated || guest_truncated.unwrap_or(false)))
}

fn command_output(status: ProcessStatus) -> Result<Value> {
    let (stdout, stdout_cut) = bounded_output(status.out_data.as_deref(), status.out_truncated)?;
    let (stderr, stderr_cut) = bounded_output(status.err_data.as_deref(), status.err_truncated)?;
    Ok(json!({"exitCode":status.exitcode,"signal":status.signal,"stdout":stdout,"stderr":stderr,
        "stdoutTruncated":stdout_cut,"stderrTruncated":stderr_cut,"channel":"qemu-ga"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_reply_rejects_an_ambiguous_envelope_and_a_frame_over_its_limit() {
        for reply in [
            b"{\"return\":{},\"error\":{\"class\":\"GenericError\"}}\n".to_vec(),
            [b"{\"return\":{\"padding\":\"".as_slice(), &vec![b'x'; SMALL_REPLY], b"\"}}\n"].concat(),
        ] {
            let (host, mut guest) = UnixStream::pair().unwrap();
            let sender = thread::spawn(move || { let _ = guest.write_all(&reply); });
            assert!(Agent::new(host).reply::<Empty>(SMALL_REPLY, Instant::now() + SHORT_TIMEOUT).is_err());
            sender.join().unwrap();
        }
    }

    #[test]
    fn the_agent_caps_each_output_and_propagates_guest_truncation() {
        let data = json!({"exitcode":0,"exited":true,"out-data":STANDARD.encode(vec![b'x'; MAX_OUTPUT + 160]),
            "err-data":STANDARD.encode("short"),"err-truncated":true});
        let reply = command_output(serde_json::from_value(data).unwrap()).unwrap();
        assert_eq!(reply["stdout"].as_str().unwrap().len(), MAX_OUTPUT);
        assert_eq!(reply["stderr"], "short");
        assert_eq!(reply["stdoutTruncated"], true);
        assert_eq!(reply["stderrTruncated"], true);
    }


    fn exchange_fake(stream: &mut BufReader<UnixStream>, command: &str, reply: Value) {
        let mut data = String::new();
        stream.read_line(&mut data).unwrap();
        let sent: Value = serde_json::from_str(&data).unwrap();
        assert_eq!(sent["execute"], command);
        writeln!(stream.get_mut(), "{}", json!({"return":reply})).unwrap();
    }

    fn finish_sync(stream: &mut BufReader<UnixStream>) {
        let mut line = Vec::new();
        stream.read_until(b'\n', &mut line).unwrap();
        assert_eq!(line[0], 0xff);
        let request: Value = serde_json::from_slice(&line[1..]).unwrap();
        assert_eq!(request["execute"], "guest-sync-delimited");
        stream.get_mut().write_all(b"stale partial frame\xff").unwrap();
        writeln!(stream.get_mut(), "{}", json!({"return":request["arguments"]["id"]})).unwrap();
    }

    #[test]
    fn status_synchronizes_after_stale_data() {
        let (host, guest) = UnixStream::pair().unwrap();
        let fixture = thread::spawn(move || {
            let mut guest = BufReader::new(guest);
            finish_sync(&mut guest);
            exchange_fake(&mut guest, "guest-ping", json!({}));
            exchange_fake(&mut guest, "guest-info", json!({"version":"11.1.0"}));
            exchange_fake(&mut guest, "guest-get-osinfo", json!({"id":"debian"}));
        });
        let status = Agent::new(host).call(AgentCall::Status).unwrap();
        assert_eq!(status["present"], true);
        assert_eq!(status["os"]["id"], "debian");
        fixture.join().unwrap();
    }

    #[test]
    fn a_disconnected_agent_has_a_clear_missing_message() {
        let (host, guest) = UnixStream::pair().unwrap();
        drop(guest);
        let error = Agent::new(host).call(AgentCall::Status).unwrap_err();
        assert!(error.to_string().contains("The guest agent is not running"));
    }

    #[test]
    fn a_running_guest_command_has_a_bounded_wait() {
        let (host, guest) = UnixStream::pair().unwrap();
        let fixture = thread::spawn(move || {
            let mut guest = BufReader::new(guest);
            finish_sync(&mut guest);
            exchange_fake(&mut guest, "guest-exec", json!({"pid":42}));
            thread::sleep(Duration::from_millis(1200));
        });
        let request = ExecRequest { argv: vec!["uname".into(), "-a".into()], timeout_sec: 1, stdin: None };
        let error = Agent::new(host).call(AgentCall::Exec {request}).unwrap_err();
        assert!(matches!(error, svm_core::engine::EngineError::Timeout {seconds:1}));
        fixture.join().unwrap();
    }

    #[test]
    fn a_small_file_read_is_followed_by_a_close() {
        let (host, guest) = UnixStream::pair().unwrap();
        let fixture = thread::spawn(move || {
            let mut guest = BufReader::new(guest);
            finish_sync(&mut guest);
            exchange_fake(&mut guest, "guest-file-open", json!(5));
            exchange_fake(&mut guest, "guest-file-read", json!({"count":3,"buf-b64":"YWJj","eof":true}));
            exchange_fake(&mut guest, "guest-file-close", json!({}));
        });
        let reply = Agent::new(host).call(AgentCall::ReadSmallFile { path: "/fixture.txt".into() }).unwrap();
        assert_eq!(reply["count"], 3);
        fixture.join().unwrap();
    }

    #[test]
    fn a_partial_guest_file_write_is_reported_and_the_handle_closed() {
        let (host, guest) = UnixStream::pair().unwrap();
        let fixture = thread::spawn(move || {
            let mut guest = BufReader::new(guest);
            finish_sync(&mut guest);
            exchange_fake(&mut guest, "guest-file-open", json!(5));
            exchange_fake(&mut guest, "guest-file-write", json!({"count":1}));
            finish_sync(&mut guest);
            exchange_fake(&mut guest, "guest-file-close", json!({}));
        });
        let reply = Agent::new(host).call(AgentCall::WriteSmallFile { path: "/fixture.txt".into(), data: "YWJj".into() });
        assert!(reply.unwrap_err().to_string().contains("did not write the complete file"));
        fixture.join().unwrap();
    }

    #[test]
    fn thaw_is_sent_before_the_agent_acknowledges_synchronization() {
        let (host, guest) = UnixStream::pair().unwrap();
        let fixture = thread::spawn(move || {
            let mut guest = BufReader::new(guest);
            let mut marker = Vec::new();
            guest.read_until(0xff, &mut marker).unwrap();
            assert_eq!(marker, [0xff]);
            let mut sync = String::new();
            guest.read_line(&mut sync).unwrap();
            let sync: Value = serde_json::from_str(&sync).unwrap();
            let mut thaw = String::new();
            guest.get_mut().set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            guest.read_line(&mut thaw).unwrap();
            let thaw: Value = serde_json::from_str(&thaw).unwrap();
            assert_eq!(thaw["execute"],"guest-fsfreeze-thaw");
            guest.get_mut().write_all(&[0xff]).unwrap();
            writeln!(guest.get_mut(),"{}",json!({"return":sync["arguments"]["id"]})).unwrap();
            writeln!(guest.get_mut(),"{}",json!({"return":2})).unwrap();
        });
        assert_eq!(Agent::new(host).call(AgentCall::Thaw).unwrap(),json!(2));
        fixture.join().unwrap();
    }

    #[test]
    fn the_agent_validates_inputs_before_sending() {
        let mut request = ExecRequest { argv: vec!["uname".into(), "-a".into()], timeout_sec: 120, stdin: None };
        assert!(request.check().is_ok());
        request.timeout_sec = 121;
        assert!(request.check().is_err());
        request.timeout_sec = 1;
        request.argv.clear();
        assert!(request.check().is_err());
    }
}
