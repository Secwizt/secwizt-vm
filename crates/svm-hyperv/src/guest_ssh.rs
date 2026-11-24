use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use svm_core::engine::{FileTransferUpdate, GuestExecRequest};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxSshAccess {
    pub username: String,
    pub host_key: String,
}

impl LinuxSshAccess {
    pub fn check(&self) -> EngineResult<()> {
        if self.username.len() > 64
            || !self.username.as_bytes().first().is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            || !self.username.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte)) {
            return Err(invalid("Enter the Linux guest username."));
        }
        host_key(&self.host_key).map(drop)
    }
}

fn host_key(record: &str) -> EngineResult<&str> {
    let fail = || invalid("Paste the Linux guest’s ssh-ed25519 host public key from its console.");
    let line = record.trim();
    if line.len() > 1024 || line.contains(['\r','\n','\0']) { return Err(fail()); }
    let mut fields = line.split_ascii_whitespace();
    if fields.next() != Some("ssh-ed25519") { return Err(fail()); }
    let encoded = fields.next().ok_or_else(fail)?;
    let decoded = STANDARD.decode(encoded).map_err(|_| fail())?;
    if decoded.len() != 51 || !decoded.starts_with(b"\0\0\0\x0bssh-ed25519\0\0\0 ") {
        return Err(fail());
    }
    Ok(encoded)
}

#[cfg(any(windows, test))]
fn command_line(argv: &[String]) -> String {
    argv.iter().map(|value| format!("'{}'", value.replace('\'', "'\\''"))).collect::<Vec<_>>().join(" ")
}

impl<R: PsRunner> HyperV<R> {
    pub fn linux_ssh_public_key(&self, vm: &Vm) -> EngineResult<String> {
        linux_guest(vm)?;
        self.inspect(&vm.id, false)?;
        platform::setup(self.bundle(&vm.id)?)
    }

    pub fn exec_linux(&self, vm: &Vm, command: GuestExecRequest, access: LinuxSshAccess) -> EngineResult<Value> {
        linux_guest(vm)?;
        command.check()?;
        access.check()?;
        let (_, ip) = self.linux_ssh_registration(vm)?;
        platform::execute(self.bundle(&vm.id)?, ip, command, access)
    }

    pub fn download_linux(
        &self, vm: &Vm, guest_path: &str, stage: &Path, access: LinuxSshAccess,
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        linux_guest(vm)?;
        access.check()?;
        if !linux_file_path(guest_path) {
            return Err(invalid("Choose an absolute path to a Linux guest file."));
        }
        let (_, ip) = self.linux_ssh_registration(vm)?;
        platform::download(self.bundle(&vm.id)?, ip, guest_path, stage, access, progress)
    }

    pub(super) fn linux_ssh_registration(&self, vm: &Vm) -> EngineResult<(String, std::net::Ipv4Addr)> {
        let actual_nic = vm.mac.to_string().replace(':', "");
        let registration = self.inspect_with_mac(&vm.id, false, Some(actual_nic))?;
        if state::from_native(registration.state, registration.state_name.as_deref())? != VmState::Running {
            return Err(invalid("Start the Hyper-V guest before running a command."));
        }
        let addresses: std::collections::BTreeSet<_> = registration.addresses.iter()
            .filter_map(|address| address.parse::<std::net::Ipv4Addr>().ok())
            .filter(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast() && !ip.is_link_local())
            .collect();
        let mut addresses = addresses.into_iter();
        let ip = addresses.next().ok_or_else(|| invalid("Hyper-V has not reported a usable IPv4 address for this guest’s virtual adapter."))?;
        if addresses.next().is_some() {
            return Err(invalid("The guest’s virtual adapter reported multiple IPv4 addresses. Leave one active IPv4 address for SSH."));
        }
        if !private_ssh_target(ip) {
            return Err(invalid("The guest reported a public IPv4 address. SSH connects only to private guest addresses."));
        }
        Ok((registration.guid, ip))
    }
}

/// The guest reports its own address, so a hostile guest could name a server on the internet that
/// holds a copy of its host key. SSH therefore connects only to private (RFC 1918) or shared
/// (100.64.0.0/10) addresses, never to a public host.
fn private_ssh_target(ip: std::net::Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    ip.is_private() || (first == 100 && second & 0xC0 == 64)
}

#[cfg(test)]
mod ssh_target_tests {
    use super::private_ssh_target;

    #[test]
    fn ssh_connects_only_to_private_or_shared_guest_addresses() {
        for ok in ["10.77.8.2", "172.20.1.8", "192.168.1.20", "100.64.0.1", "100.127.255.254"] {
            assert!(private_ssh_target(ok.parse().unwrap()), "{ok}");
        }
        for public in ["8.8.8.8", "100.128.0.1", "100.63.255.255", "172.32.0.1", "203.0.113.5"] {
            assert!(!private_ssh_target(public.parse().unwrap()), "{public}");
        }
    }
}

pub(super) fn linux_guest(vm: &Vm) -> EngineResult<()> {
    if vm.engine == EngineKind::HyperV && vm.family == GuestFamily::Linux { return Ok(()); }
    Err(invalid("SSH guest commands require a Linux guest on Hyper-V."))
}

pub(super) fn linux_file_path(path: &str) -> bool {
    path.len() <= 4096 && path.starts_with('/') && !path.chars().any(char::is_control)
        && path.split('/').skip(1).all(|part| !matches!(part, "" | "." | ".."))
}

pub(super) use platform::upload_control;

#[cfg(not(windows))]
mod platform {
    use super::*;
    fn unavailable() -> EngineError { invalid("Hyper-V guest SSH is available only from Windows.") }
    pub(crate) fn upload_control(
        _: &Path, _: std::net::Ipv4Addr, _: &LinuxSshAccess, _: &str, _: &str, _: &str, _: &str, _: (u64, &str),
    ) -> EngineResult<()> { Err(unavailable()) }
    pub(super) fn setup(_: &Path) -> EngineResult<String> { Err(unavailable()) }
    pub(super) fn execute(_: &Path, _: std::net::Ipv4Addr, _: GuestExecRequest, _: LinuxSshAccess) -> EngineResult<Value> {
        Err(unavailable())
    }
    pub(super) fn download(
        _bundle: &Path, _ip: std::net::Ipv4Addr, _guest_path: &str, _stage: &Path, _access: LinuxSshAccess,
        _progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        Err(unavailable())
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::{guest_exec::{clip_output, command_result}, runner::{run_guest_tool, stream_guest_download}};
    use std::{
        fs, io::Write, net::Ipv4Addr, process::Command,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    const ALIAS: &str = "secwizt-managed-guest";

    fn ordinary(path: &Path) -> EngineResult<PathBuf> {
        let text = path.to_str().ok_or_else(|| invalid("The Linux guest bundle path must be Unicode."))?;
        Ok(PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(text)))
    }

    fn command(relative: &str) -> EngineResult<Command> {
        let root = std::env::var_os("SystemRoot").ok_or_else(|| invalid("Windows system directory unavailable."))?;
        let mut tool = Command::new(PathBuf::from(root).join(relative));
        tool.env_clear();
        // Windows OpenSSH needs ProgramData to initialize even with an explicit private config.
        for name in ["SystemRoot","WINDIR","SystemDrive","TEMP","TMP","USERPROFILE","LOCALAPPDATA","ProgramData"] {
            if let Some(value) = std::env::var_os(name) { tool.env(name, value); }
        }
        Ok(tool)
    }

    fn permissions(directory: &Path, action: &str) -> EngineResult<()> {
        let failed = || invalid("Could not verify the owner-only SSH directory and key permissions.");
        let mut tool = command(r"System32\WindowsPowerShell\v1.0\powershell.exe")?;
        tool.args(["-NoProfile", "-NonInteractive", "-Command", include_str!("guest_ssh_permissions.ps1")])
            .env("SVM_SSH_DIRECTORY", directory)
            .env("SVM_SSH_CREATE", action);
        let (status, _) = run_guest_tool(tool, Vec::new(), Duration::from_secs(10)).map_err(|_| failed())?;
        if status.success() { Ok(()) } else { Err(failed()) }
    }

    struct KeyStage(PathBuf);
    impl Drop for KeyStage {
        fn drop(&mut self) {
            for name in ["id_ed25519", "id_ed25519.pub", "id_ed25519.sealed", "id_ed25519.pub.sealed"] {
                let _ = fs::remove_file(self.0.join(name));
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn nonce() -> u128 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos()
    }

    pub(super) fn setup(bundle: &Path) -> EngineResult<String> {
        let bundle = ordinary(bundle)?;
        let dir = bundle.join(".guest-ssh");
        match fs::symlink_metadata(&dir) {
            Ok(_) => permissions(&dir, "no")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let path = bundle.join(format!(".guest-ssh-{:x}.pending", nonce()));
                permissions(&path, "yes")?;
                let stage = KeyStage(path);
                let mut keygen = command(r"System32\OpenSSH\ssh-keygen.exe")?;
                keygen.current_dir(&stage.0).args(["-q", "-t", "ed25519", "-N", "", "-f", "id_ed25519", "-C", "secwizt-vm"]);
                let unavailable = || invalid("Windows OpenSSH could not create the per-machine guest key.");
                let (status, _) = run_guest_tool(keygen, Vec::new(), Duration::from_secs(10)).map_err(|_| unavailable())?;
                if !status.success() { return Err(unavailable()); }
                permissions(&stage.0, "seal")?;
                fs::rename(&stage.0, &dir).map_err(|_| invalid("Could not publish the verified per-machine SSH keys."))?;
            }
            Err(_) => return Err(invalid("Could not verify the existing per-machine SSH directory.")),
        }
        let line = fs::read_to_string(dir.join("id_ed25519.pub"))
            .map_err(|_| invalid("Could not read the guest’s SSH enrollment line."))?;
        host_key(&line)?;
        Ok(line.trim().to_owned())
    }

    struct Pin(PathBuf);
    impl Drop for Pin {
        fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
    }

    fn write_pin(dir: &Path, key: &str) -> EngineResult<Pin> {
        let name = format!("host-{:x}.pin", nonce());
        let path = dir.join(name);
        let failure = || invalid("Could not write the SSH host-key pin inside this guest’s private directory.");
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|_|failure())?;
        let pin = Pin(path);
        writeln!(file, "{ALIAS} ssh-ed25519 {key}").map_err(|_|failure())?;
        Ok(pin)
    }

    fn pinned_command(bundle: &Path, ip: Ipv4Addr, access: &LinuxSshAccess, argv: &[String]) -> EngineResult<(Command, Pin)> {
        let line = command_line(argv);
        if line.encode_utf16().count() > 12_000 {
            return Err(invalid("The command arguments are too long for Windows OpenSSH."));
        }
        let dir = ordinary(bundle)?.join(".guest-ssh");
        if !dir.is_dir() { return Err(invalid("Generate the guest’s SSH enrollment key first.")); }
        permissions(&dir, "no")?;
        let pin = write_pin(&dir, host_key(&access.host_key)?)?;
        let known = pin.0.file_name().and_then(|value| value.to_str()).expect("fixed pin filename");
        let mut ssh = command(r"System32\OpenSSH\ssh.exe")?;
        ssh.current_dir(&dir).args(["-F", "none", "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "StrictHostKeyChecking=yes",
            "-o", "GlobalKnownHostsFile=none", "-o", "CheckHostIP=no", "-o", "UpdateHostKeys=no",
            "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "PreferredAuthentications=publickey", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR"])
            .arg("-o").arg(format!("HostKeyAlias={ALIAS}")).arg("-o").arg(format!("UserKnownHostsFile={known}"))
            .args(["-i", "id_ed25519", "-l", &access.username]).arg(ip.to_string()).arg(line);
        Ok((ssh, pin))
    }

    pub(super) fn download(
        bundle: &Path, ip: Ipv4Addr, guest_path: &str, stage: &Path, access: LinuxSshAccess,
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>,
    ) -> EngineResult<(u64, String)> {
        let script = r#"set -eu
export LC_ALL=C
if [ ! -f "$1" ] || [ -L "$1" ]; then exit 2; fi
exec 3< "$1"
source=/proc/self/fd/3
[ -f "$source" ]
length=$(stat -Lc %s -- "$source")
checksum=$(sha256sum < "$source")
printf 'SVMFILE %s %s\n' "$length" "${checksum%% *}"
exec cat -- "$source"
"#;
        let argv = ["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned(), "svm-file".to_owned(), guest_path.to_owned()];
        progress(FileTransferUpdate::Progress { bytes: 0, total: None })?;
        let (ssh, _pin) = pinned_command(bundle, ip, &access, &argv)?;
        stream_guest_download(ssh, Vec::new(), stage, Duration::from_secs(120), progress)
    }

    pub(crate) fn upload_control(
        bundle: &Path, ip: Ipv4Addr, access: &LinuxSshAccess, op: &str, guest: &str, stage: &str,
        token: &str, expected: (u64, &str),
    ) -> EngineResult<()> {
        let argv = ["/bin/sh".to_owned(), "-c".to_owned(), include_str!("guest_upload.sh").to_owned(),
            "svm-file".to_owned(), op.to_owned(), guest.to_owned(), stage.to_owned(), token.to_owned(),
            expected.0.to_string(), expected.1.to_owned()];
        let (ssh, _pin) = pinned_command(bundle, ip, access, &argv)?;
        let (status, _) = run_guest_tool(ssh, Vec::new(), crate::guest_upload::CONTROL_TIMEOUT)
            .map_err(|error| match error {
                EngineError::Timeout { .. } => error,
                _ => crate::guest_upload::control_failed(op, None),
            })?;
        if status.success() { return Ok(()); }
        let reason = match status.code() {
            Some(20) => Some("destination"),
            Some(21) => Some("checksum"),
            _ => None,
        };
        Err(crate::guest_upload::control_failed(op, reason))
    }

    pub(super) fn execute(bundle: &Path, ip: Ipv4Addr, request: GuestExecRequest, access: LinuxSshAccess) -> EngineResult<Value> {
        let (ssh, _pin) = pinned_command(bundle, ip, &access, &request.argv)?;
        let timeout = Duration::from_secs(request.timeout_sec);
        let (status, [output, errors]) = run_guest_tool(ssh, request.stdin.unwrap_or_default().into_bytes(), timeout)
            .map_err(|error| match error {
                EngineError::Timeout { .. } => error,
                _ => invalid("Windows OpenSSH could not open the guest command session."),
            })?;
        let code = status.code().ok_or_else(|| invalid("The SSH guest command session ended unexpectedly."))?;
        // OpenSSH also uses code 255 for connection failures. Preserve its status and stderr.
        Ok(command_result("ssh", i64::from(code), clip_output(output.0, output.1), clip_output(errors.0, errors.1)))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_key_has_one_ed25519_record_and_commands_preserve_literal_arguments() {
        let mut key = b"\0\0\0\x0bssh-ed25519\0\0\0 ".to_vec();
        key.extend_from_slice(&[7; 32]);
        let encoded = STANDARD.encode(key);
        let record = format!("ssh-ed25519 {encoded} fixture host");
        assert_eq!(host_key(&record).unwrap(), encoded);
        assert!(host_key(&format!("{record}\n{record}")).is_err());
        assert!(host_key("ssh-ed25519 invalid").is_err());
        assert_eq!(command_line(&["printf".into(), "%s".into(), "spaces and 'quotes'".into(), "".into()]),
            "'printf' '%s' 'spaces and '\\''quotes'\\''' ''");
    }
}
