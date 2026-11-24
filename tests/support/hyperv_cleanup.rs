use std::{io, path::{Path,PathBuf}, process::{Command,Stdio}};

/// Last resort after the fixture service exits. The test chose the IDs before creating any objects.
pub fn remove_owned(home: &Path, machine: Option<&str>, network: Option<&str>) -> io::Result<()> {
    if machine.is_none() && network.is_none() { return Ok(()); }
    let windows = std::env::var_os("SystemRoot").ok_or_else(||io::Error::other("Cannot locate Windows PowerShell."))?;
    let output = Command::new(PathBuf::from(windows).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile","-NonInteractive","-Command",include_str!("fixture_cleanup.ps1")])
        .env("SVM_FIXTURE_FOLDER",home).env("SVM_FIXTURE_MACHINE",machine.unwrap_or(""))
        .env("SVM_FIXTURE_NETWORK",network.unwrap_or("")).stdin(Stdio::null()).output()?;
    if output.status.success() { Ok(()) }
    else { Err(io::Error::other(format!("Could not verify fixture cleanup: {}",String::from_utf8_lossy(&output.stderr).trim()))) }
}
