use serde_json::Value;
use std::{path::Path, time::Duration};
use svm_core::engine::{EngineError, EngineResult, FileTransferUpdate};

/// Only built-in scripts can be submitted to the real runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script { NetworkAddresses, Definition, LinkedDisk, Throwaway, Host, Storage, Guest, FileGuestService, InstallerBoot, Bridge, Service, Management, Trash, GuestExec, GuestUpload, GuestCopy, Checkpoint }

impl Script {
    pub fn source(self) -> &'static str {
        match self {
            Self::NetworkAddresses => include_str!("network_addresses.ps1"),
            Self::Bridge => crate::scripts::BRIDGE,
            Self::Storage => crate::scripts::STORAGE,
            Self::Guest => crate::scripts::GUEST,
            Self::FileGuestService => crate::scripts::FILE_GUEST_SERVICE,
            Self::InstallerBoot => crate::scripts::INSTALLER_BOOT,
            Self::Host => crate::scripts::HOST,
            Self::Service => crate::scripts::SERVICE,
            Self::Trash => crate::scripts::TRASH,
            Self::Definition => crate::scripts::DEFINITION,
            Self::LinkedDisk => crate::scripts::LINKED_DISK,
            Self::Throwaway => crate::scripts::THROWAWAY,
            Self::Management => crate::scripts::MANAGEMENT,
            Self::GuestExec => crate::scripts::GUEST_EXEC,
            Self::GuestUpload => crate::scripts::GUEST_UPLOAD,
            Self::GuestCopy => crate::scripts::GUEST_COPY,
            Self::Checkpoint => crate::scripts::CHECKPOINT,
        }
    }
}

pub trait PsRunner {
    fn run(&self, script: Script, parameters: &Value) -> EngineResult<Value>;
    /// A separate runner can execute a retained operation without sharing mutable service state.
    fn background(&self) -> Option<Box<dyn PsRunner + Send>> { None }

    fn run_guest_exec(&self, _parameters: &Value, _timeout: Duration) -> EngineResult<Value> {
        Err(EngineError::Invalid("PowerShell Direct is unavailable from this runner.".into()))
    }


    fn run_guest_download(
        &self, _parameters: &Value, _stage: &Path, _timeout: Duration,
        _progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        Err(EngineError::Invalid("PowerShell Direct file transfer is unavailable from this runner.".into()))
    }

    fn run_guest_upload(&self, _parameters: &Value, _timeout: Duration) -> EngineResult<Value> {
        Err(EngineError::Invalid("PowerShell Direct file transfer is unavailable from this runner.".into()))
    }

    /// Export and import may transfer whole disks and use this longer deadline.
    fn run_retained(&self, script: Script, parameters: &Value) -> EngineResult<Value> {
        self.run(script, parameters)
    }
}

impl PsRunner for Box<dyn PsRunner + Send> {
    fn run(&self, script: Script, parameters: &Value) -> EngineResult<Value> {
        (**self).run(script, parameters)
    }
    fn run_guest_exec(&self, parameters: &Value, timeout: Duration) -> EngineResult<Value> {
        (**self).run_guest_exec(parameters, timeout)
    }
    fn run_guest_download(
        &self, parameters: &Value, stage: &Path, timeout: Duration,
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        (**self).run_guest_download(parameters, stage, timeout, progress)
    }
    fn run_guest_upload(&self, parameters: &Value, timeout: Duration) -> EngineResult<Value> {
        (**self).run_guest_upload(parameters, timeout)
    }
    fn run_retained(&self, script: Script, parameters: &Value) -> EngineResult<Value> {
        (**self).run_retained(script, parameters)
    }
}

pub struct WindowsPowerShell { timeout: Duration }

impl Default for WindowsPowerShell {
    fn default() -> Self { Self::with_timeout(Duration::from_secs(120)) }
}

impl WindowsPowerShell {
    pub fn with_timeout(timeout: Duration) -> Self { Self { timeout } }
    pub fn timeout(&self) -> Duration { self.timeout }
}

/// Text without a leading byte-order mark and surrounding white space, in whatever order they come.
#[cfg(any(windows, test))]
fn unframed(text: &str) -> &str {
    text.trim_start_matches(|c: char| c == '\u{feff}' || c.is_whitespace()).trim_end()
}

/// True when stderr holds nothing but Windows PowerShell's CLIXML progress records.
/// Found on the real build host: cmdlets from auto-loaded modules (Get-NetAdapter, Get-NetIPAddress) make
/// PowerShell 5.1 write "Preparing modules for first use" progress to stderr as CLIXML even when the script
/// succeeds with exit code 0 and `$ProgressPreference` is silent. That is not an error.
#[cfg(any(windows, test))]
pub(crate) fn only_progress(stderr: &str) -> bool {
    let text = unframed(stderr);
    let Some(body) = text.strip_prefix("#< CLIXML") else { return false };
    // Every stream-tagged element counts, whatever its tag: progress arrives as <Obj S="progress">, while error,
    // warning and verbose lines arrive as <S S="Error">, <S S="warning">... One non-progress entry means failure.
    let tagged = body.matches(" S=\"").count();
    tagged > 0 && tagged == body.matches(" S=\"progress\"").count()
}

/// Plain text of a CLIXML error stream, so a raw XML blob never reaches a user.
#[cfg(any(windows, test))]
pub(crate) fn plain_stderr(stderr: &str) -> String {
    let text = unframed(stderr);
    let Some(body) = text.strip_prefix("#< CLIXML") else { return text.to_owned() };
    let mut out = String::new();
    let mut in_tag = false;
    for c in body.replace("_x000D__x000A_", " ").chars() {
        match c { '<' => in_tag = true, '>' => { in_tag = false; out.push(' '); } _ if !in_tag => out.push(c), _ => {} }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(any(windows, test))]
pub(crate) fn diagnostic(message: &str) -> EngineError {
    let envelope = serde_json::from_str::<Value>(message.trim().trim_start_matches('\u{feff}')).ok();
    let detail = envelope.as_ref().and_then(|v| v["error"].as_str());
    let message = detail.unwrap_or(message).trim();
    if message.contains("unable to find a virtual machine") {
        return EngineError::Missing(message.into());
    }
    let lower = message.to_ascii_lowercase();
    if let Some(detail) = message.strip_prefix("SVM_TPM_PERMISSION:") {
        return EngineError::Permission(format!(
            "Hyper-V refused the requested virtual TPM without elevation. {}", detail.trim()
        ));
    }
    // Hyper-V words an unreadable differencing parent as "Access is denied". It is a disk problem,
    // and the Hyper-V Administrators advice below would mislead.
    if lower.contains("chain of virtual hard disks") {
        return EngineError::Invalid("Hyper-V could not open this machine's virtual disk chain. A parent disk is missing, damaged or not readable by the virtual machine.".into());
    }
    if message.starts_with("SVM_PERMISSION:") || lower.contains("do not have the required permission")
        || lower.contains("access is denied") || lower.contains("access denied") {
        return EngineError::Permission("Hyper-V denied access. Your Windows account must be in the Hyper-V Administrators group. Sign out and sign in after joining it.".into());
    }
    if let Some(id) = message.strip_prefix("SVM_MISSING:") {
        return EngineError::Missing(id.trim().into());
    }
    if let Some(detail) = message.strip_prefix("SVM_REFUSED:") {
        return EngineError::Invalid(detail.trim().into());
    }
    EngineError::Engine(format!("Hyper-V management failed. {message}"))
}

#[cfg(not(windows))]
impl PsRunner for WindowsPowerShell {
    fn run(&self, _: Script, _: &Value) -> EngineResult<Value> {
        Err(EngineError::Engine("Hyper-V exists only on Windows.".into()))
    }
}

#[cfg(any(windows, test))]
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for part in bytes.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        out.push(char::from(ALPHABET[usize::from(a >> 2)]));
        out.push(char::from(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))]));
        out.push(if part.len() > 1 { char::from(ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))]) } else { '=' });
        out.push(if part.len() > 2 { char::from(ALPHABET[usize::from(c & 63)]) } else { '=' });
    }
    out
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        fs::OpenOptions,
        io::{self, BufRead, BufReader, Read, Write},
        os::windows::{fs::{MetadataExt, OpenOptionsExt}, process::CommandExt},
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::mpsc, thread,
        time::Instant,
    };

    const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    fn io_error(err: impl std::fmt::Display) -> EngineError {
        EngineError::Engine(format!("Could not complete the PowerShell request. {err}"))
    }

    type Pipe = (Vec<u8>, bool);
    type ToolOutput = (std::process::ExitStatus, [Pipe; 2]);

    fn read_pipe(mut pipe: impl Read, limit: usize, truncate: bool) -> io::Result<Pipe> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        let mut cut = false;
        loop {
            let count = pipe.read(&mut chunk)?;
            if count == 0 { return Ok((bytes, cut)); }
            let keep = count.min(limit - bytes.len());
            cut |= keep != count;
            if cut && !truncate { return Err(io::Error::other("PowerShell output exceeded its size limit.")); }
            bytes.extend_from_slice(&chunk[..keep]);
        }
    }

    // Covers early I/O errors as well as a timeout. Owns only the process created for this call.
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    fn capture(mut child: OwnedChild, start: Instant, deadline: Duration, limit: usize, truncate: bool) -> EngineResult<ToolOutput> {
        let output = child.0.stdout.take().ok_or_else(|| io_error("Missing output pipe."))?;
        let error = child.0.stderr.take().ok_or_else(|| io_error("Missing error pipe."))?;
        let (send, receive) = mpsc::channel();
        let output_done = send.clone();
        let _ = thread::spawn(move || { let _ = output_done.send((0, read_pipe(output, limit, truncate))); });
        let _ = thread::spawn(move || { let _ = send.send((1, read_pipe(error, limit, truncate))); });

        let timeout = || EngineError::Timeout { seconds: deadline.as_secs() };
        let mut streams = [(Vec::new(), false), (Vec::new(), false)];
        for _ in 0..2 {
            let left = deadline.checked_sub(start.elapsed()).ok_or_else(timeout)?;
            let (index, result) = receive.recv_timeout(left).map_err(|e| match e {
                mpsc::RecvTimeoutError::Timeout => timeout(),
                mpsc::RecvTimeoutError::Disconnected => io_error("A PowerShell pipe closed unexpectedly."),
            })?;
            streams[index] = result.map_err(io_error)?;
        }
        let status = loop {
            if let Some(status) = child.0.try_wait().map_err(io_error)? { break status; }
            if start.elapsed() >= deadline { return Err(timeout()); }
            thread::sleep(Duration::from_millis(10));
        };
        Ok((status, streams))
    }

    pub(crate) fn run_guest_tool(mut command: Command, input: Vec<u8>, timeout: Duration) -> EngineResult<ToolOutput> {
        let start = Instant::now();
        let mut child = OwnedChild(command.creation_flags(CREATE_NO_WINDOW).stdin(Stdio::piped())
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(io_error)?);
        let mut stdin = child.0.stdin.take().ok_or_else(|| io_error("Missing input pipe."))?;
        thread::spawn(move || { let _ = stdin.write_all(&input); });
        capture(child, start, timeout, crate::guest_exec::OUTPUT_LIMIT, true)
    }

    fn guest_shell(script: Script) -> EngineResult<Command> {
        let root = std::env::var_os("SystemRoot").ok_or_else(|| EngineError::Engine("Windows system directory unavailable.".into()))?;
        let exe = PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        let script: Vec<u8> = script.source().encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut command = Command::new(exe);
        command.args(["-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand"]).arg(base64(&script)).env_clear();
        for name in ["SystemRoot","WINDIR","SystemDrive","TEMP","TMP","USERPROFILE","LOCALAPPDATA"] {
            if let Some(value) = std::env::var_os(name) { command.env(name, value); }
        }
        Ok(command)
    }

    // Only the bounded header is text. The rest of the pipe carries the file bytes.
    fn read_file_pipe(output: impl Read, send: &mpsc::SyncSender<io::Result<Vec<u8>>>) -> io::Result<()> {
        let mut pipe = BufReader::new(output);
        let mut header = Vec::new();
        pipe.by_ref().take(96).read_until(b'\n', &mut header)?;
        if send.send(Ok(header)).is_err() { return Ok(()); }
        let mut buffer = [0; 65536];
        loop {
            let count = pipe.read(&mut buffer)?;
            if count == 0 || send.send(Ok(buffer[..count].to_vec())).is_err() { return Ok(()); }
        }
    }

    pub(crate) fn stream_guest_download(
        mut command: Command, input: Vec<u8>, stage: &Path, timeout: Duration,
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        let failed = || EngineError::Invalid("The guest file could not be read over its verified connection.".into());
        let stage_error = || EngineError::Invalid("The private download file could not be written.".into());
        progress(FileTransferUpdate::Progress { bytes: 0, total: None })?;
        let mut file = OpenOptions::new().write(true).share_mode(1).custom_flags(0x0020_0000)
            .open(stage).map_err(|_| stage_error())?;
        let metadata = file.metadata().map_err(|_| stage_error())?;
        if !metadata.is_file() || metadata.len() != 0 || metadata.file_attributes() & 0x400 != 0 {
            return Err(stage_error());
        }
        let mut child = OwnedChild(command.creation_flags(CREATE_NO_WINDOW).stdin(Stdio::piped())
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_| failed())?);
        let stdout = child.0.stdout.take().ok_or_else(failed)?;
        let mut stdin = child.0.stdin.take().ok_or_else(failed)?;
        thread::spawn(move || { let _ = stdin.write_all(&input); });
        let (send, receive) = mpsc::sync_channel(2);
        thread::spawn(move || {
            if let Err(error) = read_file_pipe(stdout, &send) { let _ = send.send(Err(error)); }
        });

        let deadline = Instant::now() + timeout;
        let timeout_error = || EngineError::Timeout { seconds: timeout.as_secs() };
        let next_wait = || deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())
            .map(|left| left.min(Duration::from_millis(100))).ok_or_else(timeout_error);
        let mut expected: Option<(u64, String)> = None;
        let mut bytes = 0_u64;
        loop {
            progress(FileTransferUpdate::Progress { bytes, total: expected.as_ref().map(|entry| entry.0) })?;
            match receive.recv_timeout(next_wait()?) {
                Ok(Ok(frame)) if expected.is_none() => expected = Some(guest_file_header(&frame)?),
                Ok(Ok(frame)) => {
                    bytes = bytes.checked_add(frame.len() as u64).ok_or_else(failed)?;
                    if bytes > expected.as_ref().expect("file header received").0 { return Err(failed()); }
                    file.write_all(&frame).map_err(|_| stage_error())?;
                }
                Ok(Err(_)) => return Err(failed()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let (length, hash) = expected.ok_or_else(failed)?;
        if bytes != length { return Err(failed()); }
        loop {
            progress(FileTransferUpdate::Progress { bytes, total: Some(length) })?;
            if let Some(status) = child.0.try_wait().map_err(|_| failed())? {
                if !status.success() { return Err(failed()); }
                break;
            }
            thread::sleep(next_wait()?);
        }
        file.sync_all().map_err(|_| stage_error())?;
        Ok((bytes, hash))
    }

    fn run_guest_json(script: Script, parameters: &Value, timeout: Duration) -> EngineResult<Value> {
        let failed = |_| EngineError::Engine("The private PowerShell Direct helper did not complete.".into());
        let mut command = guest_shell(script)?;
        let payload = serde_json::to_vec(parameters).map_err(|_| EngineError::Invalid("Invalid guest command parameters.".into()))?;
        let start = Instant::now();
        let mut child = OwnedChild(command.creation_flags(CREATE_NO_WINDOW).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(failed)?);
        let mut input = child.0.stdin.take().ok_or_else(|| EngineError::Engine("The private PowerShell Direct input was unavailable.".into()))?;
        thread::spawn(move || { let _ = input.write_all(&payload); });
        let (status, streams) = capture(child, start, timeout, OUTPUT_LIMIT, false).map_err(|error| match error {
            EngineError::Timeout { .. } => error,
            _ => EngineError::Engine("The private PowerShell Direct helper did not complete.".into()),
        })?;
        let stderr = String::from_utf8_lossy(&streams[1].0);
        if !status.success() || (!stderr.trim().is_empty() && !only_progress(&stderr)) {
            return Err(EngineError::Engine("The private PowerShell Direct helper did not complete.".into()));
        }
        serde_json::from_slice(&streams[0].0).map_err(|_| EngineError::Engine("The private PowerShell Direct reply was invalid.".into()))
    }

    impl PsRunner for WindowsPowerShell {
        fn background(&self) -> Option<Box<dyn PsRunner + Send>> {
            Some(Box::new(Self::with_timeout(self.timeout)))
        }
        fn run_retained(&self, script: Script, parameters: &Value) -> EngineResult<Value> {
            WindowsPowerShell::with_timeout(Duration::from_secs(7200)).run(script, parameters)
        }
        fn run_guest_exec(&self, parameters: &Value, timeout: Duration) -> EngineResult<Value> {
            run_guest_json(Script::GuestExec, parameters, timeout)
        }
        fn run_guest_upload(&self, parameters: &Value, timeout: Duration) -> EngineResult<Value> {
            run_guest_json(Script::GuestUpload, parameters, timeout)
        }
        fn run_guest_download(
            &self, parameters: &Value, stage: &Path, timeout: Duration,
            progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
        ) -> EngineResult<(u64, String)> {
            let payload = serde_json::to_vec(parameters)
                .map_err(|_| EngineError::Invalid("Invalid guest file parameters.".into()))?;
            stream_guest_download(guest_shell(Script::GuestExec)?, payload, stage, timeout, progress)
        }
        fn run(&self, script: Script, parameters: &Value) -> EngineResult<Value> {
            if matches!(script, Script::GuestExec | Script::GuestUpload) {
                return Err(EngineError::Invalid("Use the private guest command input channel.".into()));
            }
            if !parameters.is_object() {
                return Err(EngineError::Invalid("PowerShell parameters must be a JSON object.".into()));
            }
            let payload = base64(&serde_json::to_vec(parameters).map_err(io_error)?);
            if payload.len() > 30000 {
                return Err(EngineError::Invalid("The management request is too large.".into()));
            }
            let root = std::env::var_os("SystemRoot").ok_or_else(|| io_error("Windows system directory unavailable."))?;
            let exe = PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
            let utf16: Vec<u8> = script.source().encode_utf16().flat_map(u16::to_le_bytes).collect();
            let encoded = base64(&utf16);
            let start = Instant::now();
            let child = OwnedChild(Command::new(exe)
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-OutputFormat", "Text", "-EncodedCommand"])
                .arg(encoded)
                .env("SVM_PARAMS", payload)
                .creation_flags(CREATE_NO_WINDOW)
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
                .spawn().map_err(io_error)?);
            // The encoded script and JSON environment leave stdin closed for the entire call.
            let deadline = if script == Script::Guest && matches!(parameters["op"].as_str(), Some("shutdown" | "restart")) {
                self.timeout.min(Duration::from_secs(35))
            } else { self.timeout };
            let (status, streams) = capture(child, start, deadline, OUTPUT_LIMIT, false)?;
            let stderr = String::from_utf8_lossy(&streams[1].0);
            // Progress-only CLIXML on stderr is not a failure (see only_progress). Anything else on stderr still is,
            // also with exit code 0, and it is reduced to plain text before it can reach a user.
            if !stderr.trim().is_empty() && !only_progress(&stderr) { return Err(diagnostic(&plain_stderr(&stderr))); }
            if !status.success() { return Err(io_error(format!("PowerShell exited with {status}."))); }
            serde_json::from_slice(streams[0].0.strip_prefix(&[0xef,0xbb,0xbf]).unwrap_or(&streams[0].0)).map_err(io_error)
        }
    }
}

#[cfg(windows)]
pub(crate) use windows::{run_guest_tool, stream_guest_download};

#[cfg(any(windows, test))]
fn guest_file_header(frame: &[u8]) -> EngineResult<(u64, String)> {
    let failed = || EngineError::Invalid("The guest returned invalid file metadata.".into());
    let text = std::str::from_utf8(frame).ok().and_then(|text| text.strip_suffix('\n')).ok_or_else(failed)?;
    let mut fields = text.split(' ');
    if fields.next() != Some("SVMFILE") { return Err(failed()); }
    let length = fields.next().filter(|s| !s.is_empty() && s.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|s| s.parse::<u64>().ok()).ok_or_else(failed)?;
    let hash = fields.next().filter(|s| s.len() == 64 && s.bytes().all(|byte| byte.is_ascii_hexdigit()
        && !byte.is_ascii_uppercase())).ok_or_else(failed)?;
    if fields.next().is_some() { return Err(failed()); }
    Ok((length, hash.to_owned()))
}

#[cfg(test)]
mod guest_file_tests {
    use super::*;

    #[test]
    fn file_stream_header_requires_a_length_and_a_lowercase_sha256() {
        let hash = "a".repeat(64);
        let header = format!("SVMFILE 50000000 {hash}\n");
        assert_eq!(guest_file_header(header.as_bytes()).unwrap(), (50_000_000, hash.clone()));
        for invalid in [
            format!("SVMFILE 7 {hash}"),
            format!("SVMFILE -1 {hash}\n"),
            format!("SVMFILE 0 {hash} extra\n"),
            format!("SVMFILE 0 {}\n", hash.to_uppercase()),
            format!("SVMFILE 0 {hash}\r\n"),
        ] {
            assert!(guest_file_header(invalid.as_bytes()).is_err());
        }
    }
}
