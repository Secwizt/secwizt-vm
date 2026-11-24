use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::time::Duration;
use svm_core::engine::{FileTransferUpdate, GuestExecRequest};

pub(super) const OUTPUT_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsGuestCredentials {
    pub username: String,
    pub password: String,
}

impl WindowsGuestCredentials {
    pub fn check(&self) -> EngineResult<()> {
        if self.username.trim().is_empty() || self.username.len() > 512 || self.password.is_empty()
            || self.password.len() > 8192 || self.username.chars().any(char::is_control)
            || self.password.contains('\0') {
            return Err(invalid("Enter the Windows guest username and password for this run."));
        }
        Ok(())
    }
}

impl<R: PsRunner> HyperV<R> {
    pub fn download_windows(
        &self, vm: &Vm, guest_path: &str, stage: &Path, credentials: WindowsGuestCredentials,
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        if vm.family != GuestFamily::Windows || vm.engine != EngineKind::HyperV {
            return Err(invalid("PowerShell Direct file transfer requires a Windows guest on Hyper-V."));
        }
        credentials.check()?;
        if !windows_file_path(guest_path) {
            return Err(invalid("Choose an absolute local drive path to a guest file."));
        }
        let registration = self.inspect(&vm.id, false)?;
        if state::from_native(registration.state, registration.state_name.as_deref())? != VmState::Running {
            return Err(invalid("Start the Hyper-V guest before getting a file."));
        }
        let parameters = json!({
            "id": vm.id,
            "guid": registration.guid,
            "filePath": guest_path,
            "username": credentials.username,
            "password": credentials.password,
        });
        self.runner.run_guest_download(&parameters, stage, Duration::from_secs(120), progress)
    }

    pub fn exec_windows(
        &self, vm: &Vm, command: GuestExecRequest, credentials: WindowsGuestCredentials,
    ) -> EngineResult<Value> {
        if vm.family != GuestFamily::Windows || vm.engine != EngineKind::HyperV {
            return Err(invalid("PowerShell Direct requires a Windows guest on Hyper-V."));
        }
        command.check()?;
        credentials.check()?;
        let utf16_args = command.argv.iter().map(|arg| {
            // Literal Windows quoting can at most double an argument.
            2 * arg.encode_utf16().count() + 3
        }).sum::<usize>();
        if utf16_args > 30_000 {
            return Err(invalid("The guest command arguments are too long for Windows."));
        }
        let registration = self.inspect(&vm.id, false)?;
        if state::from_native(registration.state, registration.state_name.as_deref())? != VmState::Running {
            return Err(invalid("Start the Hyper-V guest before running a command."));
        }
        let timeout = command.timeout_sec;
        let parameters = json!({
            "id": vm.id,
            "guid": registration.guid,
            "command": command,
            "username": credentials.username,
            "password": credentials.password,
        });
        let result = self.runner.run_guest_exec(&parameters, Duration::from_secs(timeout + 15))?;
        if result["timeout"] == true { return Err(EngineError::Timeout { seconds: timeout }); }
        if let Some(failure) = result["error"].as_str() {
            let message = match failure {
                "ownership" => "The running Hyper-V registration could not be verified.",
                "session" => "PowerShell Direct could not sign in. Check the guest username, password and readiness.",
                "start" => "The executable could not run inside the Windows guest.",
                _ => "PowerShell Direct could not complete the guest command.",
            };
            return Err(invalid(message));
        }
        let exit_code = result["exitCode"].as_i64()
            .ok_or_else(|| EngineError::Engine("The Windows guest did not return an exit code.".into()))?;
        let decode = |field: &str| -> EngineResult<Vec<u8>> {
            result[field].as_str().filter(|data| data.len() <= OUTPUT_LIMIT.div_ceil(3) * 4)
                .and_then(|data| STANDARD.decode(data).ok())
                .ok_or_else(|| EngineError::Engine("The Windows guest returned invalid output.".into()))
        };
        let output = clip_output(decode("stdoutB64")?, result["stdoutTruncated"] == true);
        let error = clip_output(decode("stderrB64")?, result["stderrTruncated"] == true);
        Ok(command_result("powershell-direct", exit_code, output, error))
    }
}

pub(super) fn windows_file_path(path: &str) -> bool {
    let prefix = path.as_bytes();
    if !(4..=4096).contains(&prefix.len()) || !prefix[0].is_ascii_alphabetic()
        || prefix[1] != b':' || !matches!(prefix[2], b'\\' | b'/') {
        return false;
    }
    path[3..].split(['\\', '/']).all(|part| {
        !part.is_empty() && !part.ends_with(['.', ' '])
            && !part.chars().any(|ch| ch.is_control() || ":*?<>|\"".contains(ch))
            && !matches!(part.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase().as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
                | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
                | "COM¹" | "COM²" | "COM³" | "LPT¹" | "LPT²" | "LPT³")
    })
}

pub(super) fn clip_output(mut bytes: Vec<u8>, mut cut: bool) -> (String, bool) {
    cut |= bytes.len() > OUTPUT_LIMIT;
    bytes.truncate(OUTPUT_LIMIT);
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if text.len() > OUTPUT_LIMIT {
        let mut end = OUTPUT_LIMIT;
        while !text.is_char_boundary(end) { end -= 1; }
        text.truncate(end);
        cut = true;
    }
    (text, cut)
}

pub(super) fn command_result(channel: &str, code: i64, output: (String, bool), error: (String, bool)) -> Value {
    json!({"channel":channel,"exitCode":code,"signal":null,"stdout":output.0,"stderr":error.0,
        "stdoutTruncated":output.1,"stderrTruncated":error.1})
}


#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::WindowsPowerShell;

    #[test]
    #[ignore = "native PowerShell Direct integration check"]
    fn the_native_private_input_returns_a_sanitized_ownership_refusal() {
        let response = WindowsPowerShell::default().run_guest_exec(&json!({
            "id": "!invalid-disposable-provider-fixture",
            "guid": "01234567-89ab-cdef-0123-456789abcdef",
            "username": "synthetic-local-fixture",
            "password": "synthetic-local-fixture-password",
            "command": {"argv":["hostname.exe"],"timeoutSec":1}
        }), Duration::from_secs(15)).unwrap();
        assert_eq!(response, json!({"error":"ownership"}));
    }
}
