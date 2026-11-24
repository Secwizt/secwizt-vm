use super::*;
use std::time::Duration;
use svm_core::engine::FileTransferUpdate;

pub(super) const CONTROL_TIMEOUT: Duration = Duration::from_secs(45);

impl<R: PsRunner> HyperV<R> {
    pub fn upload_windows(
        &self, vm: &Vm, guest_path: &str, host_path: &Path, expected: (u64, &str),
        access: WindowsGuestCredentials, progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        if vm.engine != EngineKind::HyperV || vm.family != GuestFamily::Windows {
            return Err(invalid("PowerShell Direct file transfer requires a Windows guest on Hyper-V."));
        }
        access.check()?;
        if !guest_exec::windows_file_path(guest_path) || guest_path.contains('%') {
            return Err(invalid("Choose an absolute local drive path to a guest file without percent signs."));
        }
        let guest_path = guest_path.replace('/', "\\");
        let registration = self.inspect(&vm.id, false)?;
        if state::from_native(registration.state, registration.state_name.as_deref())? != VmState::Running {
            return Err(invalid("Start the Hyper-V guest before sending a file."));
        }
        self.upload_guest(vm, &registration.guid, &guest_path, '\\', host_path, expected, progress,
            |op, stage, token| {
                let reply = self.runner.run_guest_upload(&json!({
                    "id": vm.id, "guid": registration.guid, "username": access.username, "password": access.password,
                    "op": op, "finalPath": guest_path, "stage": stage, "token": token,
                    "length": expected.0.to_string(), "sha256": expected.1,
                }), CONTROL_TIMEOUT)?;
                if reply["ok"] == true { return Ok(()); }
                Err(control_failed(op, reply["error"].as_str()))
            })
    }

    pub fn upload_linux(
        &self, vm: &Vm, guest_path: &str, host_path: &Path, expected: (u64, &str),
        access: LinuxSshAccess, progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        guest_ssh::linux_guest(vm)?;
        access.check()?;
        if !guest_ssh::linux_file_path(guest_path) || guest_path.contains('%') {
            return Err(invalid("Choose an absolute path to a Linux guest file without percent signs."));
        }
        let (guid, ip) = self.linux_ssh_registration(vm)?;
        let bundle = self.bundle(&vm.id)?;
        self.upload_guest(vm, &guid, guest_path, '/', host_path, expected, progress, |op, stage, token| {
            let (current_guid, current_ip) = self.linux_ssh_registration(vm)?;
            if current_guid != guid || current_ip != ip {
                return Err(invalid("The Hyper-V guest registration or SSH address changed during the upload."));
            }
            guest_ssh::upload_control(bundle, ip, &access, op, guest_path, stage, token, expected)
        })
    }

    fn upload_guest(
        &self, vm: &Vm, guid: &str, guest: &str, separator: char, source: &Path, expected: (u64, &str),
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
        mut control: impl FnMut(&str, &str, &str) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        let raw = source.to_str().ok_or_else(|| invalid("Choose a Unicode local source file path."))?;
        let source = raw.strip_prefix(r"\\?\").unwrap_or(raw);
        if !guest_exec::windows_file_path(source) || source.contains('%') {
            return Err(invalid("Choose an absolute local drive path to a source file without percent signs."));
        }
        let (length, checksum) = expected;
        if !lower_hex(checksum, 64) { return Err(invalid("The upload source checksum was invalid.")); }
        let empty = FileTransferUpdate::Progress { bytes: 0, total: Some(length) };
        progress(empty)?;
        let receipt = self.runner.run(Script::GuestCopy, &json!({ "op": "preflight", "id": vm.id, "guid": guid }))?;
        let token = receipt["token"].as_str().filter(|value| lower_hex(value, 32))
            .ok_or_else(|| invalid("Hyper-V file copy could not prepare an upload."))?;
        let (parent, _) = guest.rsplit_once(separator).expect("validated guest path");
        let stage = format!("{parent}{separator}.svm-file-{token}");
        if separator == '/' {
            if !stage.bytes().all(|byte| (b' '..=b'~').contains(&byte) && byte != b'\\') {
                return Err(invalid("The Linux guest folder must use printable ASCII for Hyper-V Guest Services."));
            }
            if stage.len() + "/data.part".len() >= 260 {
                return Err(invalid("The Linux guest folder path is too long for Hyper-V Guest Services."));
            }
        }
        progress(empty)?;
        let result = (|| {
            control("prepare", &stage, token)?;
            progress(empty)?;
            let destination = format!("{stage}{separator}data.part");
            // Cancellation waits for the synchronous native copy boundary before cleaning the guest.
            let copied = self.runner.run(Script::GuestCopy, &json!({
                "op": "copy", "id": vm.id, "guid": guid, "source": source, "destination": destination,
            })).and_then(|reply| {
                if reply["ok"] == true { Ok(()) }
                else { Err(invalid("Hyper-V did not confirm the guest file copy.")) }
            });
            let bytes = if copied.is_ok() { length } else { 0 };
            progress(FileTransferUpdate::Progress { bytes, total: Some(length) })?;
            copied?;
            control("verify", &stage, token)?;
            progress(FileTransferUpdate::Publish)?;
            control("publish", &stage, token)?;
            Ok((length, checksum.to_owned()))
        })();
        if control("clear", &stage, token).is_err() {
            return Err(EngineError::Invalid(match result {
                Ok(_) => "The verified file was sent, but its private guest staging folder could not be removed.".into(),
                Err(error) => format!("{error} The private guest staging folder could not be confirmed removed. Check the destination folder in the guest."),
            }));
        }
        result
    }
}

fn lower_hex(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn control_failed(operation: &str, error: Option<&str>) -> EngineError {
    invalid(match error {
        Some("destination") => "Choose a guest destination that does not already exist.",
        Some("checksum") => "The guest upload did not match the source file.",
        Some("session") => "PowerShell Direct could not sign in. Check the guest credentials and readiness.",
        _ => match operation {
            "prepare" => "The guest could not create its private upload staging folder.",
            "verify" => "The guest could not verify the staged upload.",
            "publish" => "The guest could not publish the verified file.",
            _ => "The guest could not remove its private upload staging folder.",
        },
    })
}
