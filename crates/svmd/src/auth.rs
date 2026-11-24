use crate::ApiError;
use std::{fs, path::Path};

fn protection() -> ApiError {
    ApiError::new(500, "token_permissions", "The service could not verify a private API token. Check access to the data folder.")
}

/// The API token is replaced at every service start. The machine key is NOT: QEMU supervisors
/// that outlive a service restart prove their identity with a key derived from it (svm-qemu control.rs),
/// so rotating it would make the new service disown machines that are still running.
pub fn token(home: &Path) -> Result<String, ApiError> {
    machine_secret(home)?;
    replace_private(home, "api-token", None)
}

/// Create the long-lived machine key once. On the first start after the upgrade it is seeded from the
/// previous API token, because machines already running derived their identity from that value.
fn machine_secret(home: &Path) -> Result<(), ApiError> {
    match fs::symlink_metadata(home.join("machine-key")) {
        Ok(meta) if meta.file_type().is_file() => return Ok(()),
        Ok(_) => return Err(protection()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(ApiError::storage(e)),
    }
    let previous = match fs::symlink_metadata(home.join("api-token")) {
        Ok(meta) if meta.file_type().is_file() => fs::read_to_string(home.join("api-token")).ok().filter(|text| valid(text)),
        _ => None,
    };
    replace_private(home, "machine-key", previous.as_deref()).map(|_| ())
}

fn valid(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn replace_private(home: &Path, name: &str, value: Option<&str>) -> Result<String, ApiError> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| protection())?;
    let pending = home.join(format!(".{name}-{:032x}.pending", u128::from_ne_bytes(random)));
    let result = (|| {
        write_private_token(home, name, &pending, value)?;
        let text = fs::read_to_string(&pending).map_err(ApiError::storage)?;
        if !valid(&text) || value.is_some_and(|wanted| wanted != text) {
            return Err(protection());
        }
        fs::rename(&pending, home.join(name)).map_err(ApiError::storage)?;
        Ok(text)
    })();
    if result.is_err() { let _ = fs::remove_file(&pending); }
    result
}

// The token length is public. Compare every byte of every candidate with the correct length.
pub(crate) fn accepts(expected: &[u8], candidate: &[u8]) -> bool {
    if expected.len() != candidate.len() { return false; }
    let mut diff = 0u8;
    for (&a, &b) in expected.iter().zip(candidate) {
        diff |= std::hint::black_box(a ^ b);
    }
    std::hint::black_box(diff) == 0
}

#[cfg(windows)]
fn write_private_token(home: &Path, name: &str, pending: &Path, value: Option<&str>) -> Result<(), ApiError> {
    use std::process::{Command, Stdio};
    const PREPARE: &str = r#"
$ErrorActionPreference = 'Stop'
$p = [IO.Path]::Combine($env:SVM_PRIVATE_HOME, $env:SVM_PRIVATE_NAME)
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
function AssertPrivate([string]$path) {
    if (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 4 }
    $acl = [IO.File]::GetAccessControl($path)
    if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value) { exit 4 }
    $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $user.Value -or $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') { exit 4 }
}
if ([IO.File]::Exists($p)) { AssertPrivate $p }
$t = $env:SVM_PRIVATE_TOKEN_PENDING
$security = New-Object Security.AccessControl.FileSecurity
$security.SetOwner($user)
$security.SetAccessRuleProtection($true, $false)
$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'Allow'))
$f = [IO.FileStream]::new($t, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security)
try {
    if ($env:SVM_PRIVATE_VALUE) {
        $encoded = [Text.Encoding]::ASCII.GetBytes($env:SVM_PRIVATE_VALUE)
    } else {
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $raw = New-Object byte[] 32; $rng.GetBytes($raw) } finally { $rng.Dispose() }
        $encoded = [Text.Encoding]::ASCII.GetBytes([BitConverter]::ToString($raw).Replace('-','').ToLowerInvariant())
    }
    $f.Write($encoded,0,$encoded.Length)
    $f.Flush($true)
} finally { $f.Dispose() }
AssertPrivate $t
"#;
    let system = std::env::var_os("SystemRoot").ok_or_else(protection)?;
    let exe = Path::new(&system).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut command = Command::new(exe);
    command.args(["-NoProfile","-NonInteractive","-Command",PREPARE])
        .env("SVM_PRIVATE_HOME", home).env("SVM_PRIVATE_NAME", name).env("SVM_PRIVATE_TOKEN_PENDING", pending)
        .env_remove("SVM_PRIVATE_VALUE")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    if let Some(value) = value { command.env("SVM_PRIVATE_VALUE", value); }
    let outcome = command.status().map_err(|_| protection())?;
    if outcome.success() { Ok(()) } else { Err(protection()) }
}

#[cfg(unix)]
fn write_private_token(home: &Path, name: &str, pending: &Path, value: Option<&str>) -> Result<(), ApiError> {
    use std::{fmt::Write as _, fs::OpenOptions, io::Write, os::unix::fs::{MetadataExt, OpenOptionsExt}};
    let path = home.join(name);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() && meta.mode() & 0o777 == 0o600 && meta.nlink() == 1 => {}
        Ok(_) => return Err(protection()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(ApiError::storage(e)),
    }
    let hex = match value {
        Some(value) => value.to_owned(),
        None => {
            let mut raw = [0u8;32];
            getrandom::fill(&mut raw).map_err(|_| protection())?;
            let mut hex = String::with_capacity(64);
            for b in raw { write!(hex, "{b:02x}").map_err(|_| protection())?; }
            hex
        }
    };
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(pending).map_err(ApiError::storage)?;
    f.write_all(hex.as_bytes()).and_then(|()| f.sync_all()).map_err(ApiError::storage)
}

#[cfg(not(any(unix,windows)))]
fn write_private_token(_: &Path, _: &str, _: &Path, _: Option<&str>) -> Result<(), ApiError> { Err(protection()) }
