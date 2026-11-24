use std::{
    io, process::{Child, ExitStatus}, thread, time::{Duration, Instant},
};

/// Wait for the viewer helper, then terminate and reap only that child on timeout.
pub fn wait_for_viewer_helper(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }

    if let Err(error) = child.kill() {
        // Windows can report that the process already exited between try_wait and kill.
        if child.try_wait()?.is_none() {
            return Err(error);
        }
    }
    child.wait()?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, os::windows::process::CommandExt, path::PathBuf, process::{Command, Stdio}};

    #[test]
    fn expired_viewer_helper_is_reaped() {
        let exe = PathBuf::from(env::var_os("SystemRoot").unwrap())
            .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        let mut child = Command::new(exe)
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 5"])
            .creation_flags(0x0800_0000)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().unwrap();
        let status = wait_for_viewer_helper(&mut child, Duration::ZERO).unwrap();
        assert!(status.is_none());
        assert!(child.try_wait().unwrap().is_some());
    }
}
