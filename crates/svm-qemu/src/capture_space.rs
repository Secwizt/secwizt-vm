use crate::{err, Result};
use std::path::Path;

pub(super) const FREE_SPACE_RESERVE: u64 = 2 * 1024 * 1024 * 1024;

#[cfg(windows)]
mod windows {
    use crate::{err, tools, Result};
    use std::{
        io::{BufRead, BufReader, Read, Write},
        path::{Component, Path, PathBuf, Prefix},
        process::{ChildStdin, Stdio},
        sync::{mpsc, Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };

    use super::FREE_SPACE_RESERVE;

    const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
    const MAX_SAMPLE_AGE: Duration = Duration::from_millis(250);
    const INITIAL_TIMEOUT: Duration = Duration::from_secs(5);
    const UNAVAILABLE: &str = "Free space on the capture volume could not be verified.";
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$volume = [IO.DriveInfo]::new($env:SVM_CAPTURE_DRIVE)
if ($volume.DriveType -notin @('Fixed','Removable','Ram')) { exit 1 }
while ($null -ne [Console]::ReadLine()) {
    [Console]::WriteLine($volume.AvailableFreeSpace.ToString([Globalization.CultureInfo]::InvariantCulture))
    [Console]::Out.Flush()
}
"#;

    #[derive(Default)]
    struct Sample {
        latest: Option<(u64, Instant)>,
        below_reserve: Option<u64>,
    }

    pub(super) struct Monitor {
        input: Arc<Mutex<Option<ChildStdin>>>,
        sample: Arc<Mutex<Sample>>,
        worker: thread::Thread,
    }

    impl Monitor {
        pub(super) fn start(bundle: &Path) -> Result<Self> {
            let drive = match bundle.components().next() {
                Some(Component::Prefix(prefix)) => match prefix.kind() {
                    Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                    _ => return Err(err(UNAVAILABLE)),
                },
                _ => return Err(err(UNAVAILABLE)),
            };
            if !bundle.is_absolute() || !drive.is_ascii_alphabetic() {
                return Err(err(UNAVAILABLE));
            }
            let volume = format!("{}:\\", char::from(drive.to_ascii_uppercase()));
            let system = std::env::var_os("SystemRoot").ok_or_else(|| err(UNAVAILABLE))?;
            let executable = PathBuf::from(system).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
            let mut child = tools::command(&executable)
                .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", SCRIPT])
                .env("SVM_CAPTURE_DRIVE", volume)
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
                .spawn().map_err(|_| err(UNAVAILABLE))?;

            let input = Arc::new(Mutex::new(child.stdin.take()));
            let output = child.stdout.take().expect("piped free-space output");
            let sample = Arc::new(Mutex::new(Sample::default()));
            let (ready, first) = mpsc::sync_channel(1);
            let worker_input = Arc::clone(&input);
            let worker_sample = Arc::clone(&sample);
            let worker = thread::Builder::new().name("qemu-capture-space".into()).spawn(move || {
                let mut reader = BufReader::new(output);
                let mut ready = Some(ready);
                loop {
                    let sent = worker_input.lock().ok().is_some_and(|mut stdin| {
                        stdin.as_mut().is_some_and(|pipe| pipe.write_all(b"\n").is_ok())
                    });
                    if !sent {
                        break;
                    }
                    let Some(bytes) = read_bytes(&mut reader) else { break; };
                    {
                        let Ok(mut sample) = worker_sample.lock() else { break; };
                        sample.latest = Some((bytes, Instant::now()));
                        if bytes < FREE_SPACE_RESERVE {
                            sample.below_reserve.get_or_insert(bytes);
                        }
                    }
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(());
                    }
                    thread::park_timeout(SAMPLE_INTERVAL);
                }
                if let Ok(mut sample) = worker_sample.lock() {
                    sample.latest = None;
                }
                if let Ok(mut stdin) = worker_input.lock() {
                    stdin.take();
                }
                drop(reader);
                let _ = child.wait();
            }).map_err(|_| err(UNAVAILABLE))?;

            let monitor = Self { input, sample, worker: worker.thread().clone() };
            first.recv_timeout(INITIAL_TIMEOUT).map_err(|_| err(UNAVAILABLE))?;
            Ok(monitor)
        }

        pub(super) fn available(&self) -> Option<u64> {
            let sample = self.sample.lock().ok()?;
            sample.below_reserve.or_else(|| {
                sample.latest.filter(|(_, at)| at.elapsed() <= MAX_SAMPLE_AGE).map(|(bytes, _)| bytes)
            })
        }
    }

    impl Drop for Monitor {
        fn drop(&mut self) {
            if let Ok(mut stdin) = self.input.lock() {
                stdin.take();
            }
            self.worker.unpark();
        }
    }

    fn read_bytes(reader: &mut impl BufRead) -> Option<u64> {
        let mut line = Vec::new();
        reader.take(24).read_until(b'\n', &mut line).ok()?;
        let line = std::str::from_utf8(line.strip_suffix(b"\n")?).ok()?.trim_end_matches('\r');
        if line.is_empty() || !line.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        line.parse().ok()
    }
}

pub(super) struct SpaceWatch {
    #[cfg(windows)]
    monitor: windows::Monitor,
}

impl SpaceWatch {
    pub(super) fn start(bundle: &Path) -> Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self { monitor: windows::Monitor::start(bundle)? })
        }
        #[cfg(not(windows))]
        {
            let _ = bundle;
            Err(err("The capture volume free-space monitor is unavailable on this host."))
        }
    }

    pub(super) fn available(&self) -> Option<u64> {
        #[cfg(windows)]
        {
            self.monitor.available()
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    pub(super) fn check_initial_space(&self) -> Result<()> {
        let bytes = self.available().ok_or_else(|| err("Free space on the capture volume could not be verified."))?;
        if bytes < FREE_SPACE_RESERVE {
            return Err(err("At least 2 GiB of free space is needed on the capture volume."));
        }
        Ok(())
    }
}
