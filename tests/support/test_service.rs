// A test owns the original Child handle. A late startup or an early assertion must
// never leave a service running or keep Cargo's output pipes open.
use std::{io, path::Path, process::{Child, Command, Stdio}, thread, time::{Duration, Instant}};

pub struct TestService {
    pub child: Child,
}

impl TestService {
    pub fn spawn(daemon: &Path, home: &Path) -> io::Result<Self> {
        let mut command = Command::new(daemon);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let child = command.env("SVM_HOME", home).env("SVM_PORT", "0")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
        Ok(Self { child })
    }

    /// Allow an acknowledged shutdown to finish, then reap this exact child on failure.
    pub fn finish(&mut self, grace: Duration) -> io::Result<()> {
        let deadline = Instant::now() + grace;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return if status.success() { Ok(()) } else { Err(io::Error::other(format!("Test service exited with {status}."))) };
            }
            if Instant::now() >= deadline { break; }
            thread::sleep(Duration::from_millis(75));
        }
        self.reap()?;
        Err(io::Error::new(io::ErrorKind::TimedOut, "The test service exceeded its shutdown deadline and was reaped."))
    }

    fn reap(&mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_none() {
            if let Err(error) = self.child.kill() {
                if self.child.try_wait()?.is_none() { return Err(error); }
            }
        }
        self.child.wait().map(|_| ())
    }
}

impl Drop for TestService {
    fn drop(&mut self) { let _ = self.reap(); }
}
