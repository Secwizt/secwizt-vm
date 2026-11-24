use super::*;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::Read,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Instant,
};
use svm_qemu::{GuestAgentSession, LocalFolder};

const CANCELLED: &str = "File transfer cancelled.";
const HISTORY: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Direction { Send, Get }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    direction: Direction,
    guest_path: String,
    host_path: PathBuf,
    credentials: Option<WindowsGuestCredentials>,
    ssh: Option<LinuxSshAccess>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Phase { Running, Cancelling, Finalizing, Completed, Failed, Cancelled }

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    id: String,
    direction: Direction,
    state: Phase,
    bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl Status {
    fn new(direction: Direction) -> Self {
        Self { id: next_id(), direction, state: Phase::Running, bytes: 0, total_bytes: None, sha256: None, message: None }
    }

    fn cancel(&mut self) -> Result<(), ApiError> {
        match self.state {
            Phase::Running => self.state = Phase::Cancelling,
            Phase::Cancelling | Phase::Cancelled => {}
            _ => return Err(refused("The transfer is already verifying or finished.")),
        }
        Ok(())
    }

    fn update(&mut self, update: FileTransferUpdate) -> EngineResult<()> {
        if self.state == Phase::Cancelling {
            return Err(EngineError::Invalid(CANCELLED.into()));
        }
        match update {
            FileTransferUpdate::Progress { bytes, total } => {
                self.bytes = bytes;
                if total.is_some() { self.total_bytes = total; }
            }
            FileTransferUpdate::Publish => self.state = Phase::Finalizing,
        }
        Ok(())
    }

    fn finish(&mut self, result: EngineResult<(u64, String)>) {
        match result {
            Ok((bytes, digest)) => {
                self.state = Phase::Completed;
                self.bytes = bytes;
                self.total_bytes = Some(bytes);
                self.sha256 = Some(digest);
            }
            Err(EngineError::Invalid(reason)) if reason == CANCELLED => {
                self.state = Phase::Cancelled;
            }
            Err(error) => {
                self.state = Phase::Failed;
                self.message = Some(error.to_string());
            }
        }
    }
}

type SharedStatus = Arc<Mutex<Status>>;
struct Active { machine: String, status: SharedStatus, worker: JoinHandle<()> }

#[derive(Default)]
pub(super) struct FileTransfers {
    active: Option<Active>,
    history: VecDeque<(String, Status)>,
}

fn status_lock(status: &Mutex<Status>) -> std::sync::MutexGuard<'_, Status> {
    status.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl FileTransfers {
    pub(super) fn busy(&self) -> bool {
        self.active.as_ref().is_some_and(|active| !active.worker.is_finished())
    }

    pub(super) fn owns(&self, id: &str) -> bool {
        self.active.as_ref().is_some_and(|active| active.machine == id && !active.worker.is_finished())
    }

    fn reap(&mut self) {
        if self.busy() { return; }
        let Some(active) = self.active.take() else { return; };
        if active.worker.join().is_err() {
            status_lock(&active.status).finish(Err(EngineError::Engine("The file-transfer worker ended unexpectedly.".into())));
        }
        if self.history.len() == HISTORY { self.history.pop_front(); }
        self.history.push_back((active.machine, status_lock(&active.status).clone()));
    }

    fn latest(&mut self, machine: &str) -> Reply {
        self.reap();
        let job = self.active.as_ref().filter(|item| item.machine == machine)
            .map(|item| status_lock(&item.status).clone())
            .or_else(|| self.history.iter().rev().find(|(owner, _)| owner == machine).map(|(_, status)| status.clone()));
        Reply::json(json!({"job":job}))
    }

    pub(super) fn forget(&mut self, machine: &str) {
        self.reap();
        self.history.retain(|(owner, _)| owner != machine);
    }

    fn current(&mut self, machine: &str, job: &str, cancel: bool) -> Result<Reply, ApiError> {
        self.reap();
        if let Some(active) = self.active.as_ref().filter(|item| item.machine == machine) {
            let mut status = status_lock(&active.status);
            if status.id == job {
                if cancel { status.cancel()?; }
                return Ok(Reply::json(json!(&*status)));
            }
        }
        let (_, status) = self.history.iter().find(|(owner, status)| owner == machine && status.id == job)
            .ok_or_else(ApiError::missing)?;
        if cancel && status.state != Phase::Cancelled {
            return Err(refused("The transfer already finished."));
        }
        Ok(Reply::json(json!(status)))
    }

    fn start(&mut self, machine: String, request: Request, backend: Backend, location: (LocalFolder, PathBuf)) -> Result<Reply, ApiError> {
        self.reap();
        if self.active.is_some() { return Err(refused("Wait for the current file transfer or cancel it first.")); }
        let status = Status::new(request.direction);
        let response = Reply::json_status(202, json!(status));
        let status = Arc::new(Mutex::new(status));
        let report = status.clone();
        let worker = thread::Builder::new().name("guest-file-transfer".into()).spawn(move || {
            let mut progress = |update| status_lock(&report).update(update);
            let result = transfer(backend, request, location, &mut progress);
            status_lock(&report).finish(result);
        }).map_err(io_error)?;
        self.active = Some(Active { machine, status, worker });
        Ok(response)
    }

    fn shutdown(&mut self) {
        if let Some(active) = self.active.take() {
            {
                let mut status = status_lock(&active.status);
                if status.state == Phase::Running { status.state = Phase::Cancelling; }
            }
            let _ = active.worker.join();
        }
    }
}

impl Drop for FileTransfers {
    fn drop(&mut self) { self.shutdown(); }
}

enum GuestAccess { Windows(WindowsGuestCredentials), Linux(LinuxSshAccess) }
/// The `Option<u64>` is the destination volume's free space, measured for downloads.
enum Backend { Qemu(GuestAgentSession, Option<u64>), HyperV(Box<dyn MachineEngine>, Vm, GuestAccess, Option<u64>) }

/// Hyper-V guest downloads get the same limits as QEMU ones: at most 4 GiB, and 64 MiB must stay free
/// on the destination volume. The guest announces the length before any of its data is written.
fn check_guest_download(total: u64, available: u64) -> EngineResult<()> {
    const MAX: u64 = 4 * 1024 * 1024 * 1024;
    const RESERVE: u64 = 64 * 1024 * 1024;
    if total > MAX { return Err(EngineError::Invalid("Guest downloads are limited to 4 GiB.".into())); }
    if total.saturating_add(RESERVE) > available {
        return Err(EngineError::Invalid("The destination volume needs enough free space for the file plus 64 MiB.".into()));
    }
    Ok(())
}

fn storage() -> EngineError { EngineError::Invalid("The selected local file could not be opened or saved.".into()) }

fn host_location(path: &Path, service_home: &Path) -> EngineResult<(LocalFolder, PathBuf)> {
    let leaf = path.file_name().and_then(|name| name.to_str())
        .filter(|name| svm_core::library::ordinary_file_name(name)).ok_or_else(storage)?;
    let parent = LocalFolder::open(path.parent().filter(|_| path.is_absolute()).ok_or_else(storage)?)?;
    if parent.path.starts_with(service_home) {
        return Err(EngineError::Invalid("Choose a host file outside the service data and machine library.".into()));
    }
    let file = parent.path.join(leaf);
    Ok((parent, file))
}

fn regular_file(path: &Path, writable: bool) -> EngineResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x0020_0000);
    }
    let file = options.open(path).map_err(|_| storage())?;
    let meta = file.metadata().map_err(|_| storage())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 { return Err(storage()); }
    }
    if !meta.is_file() || fs::symlink_metadata(path).map_err(|_| storage())?.file_type().is_symlink()
        || path.canonicalize().map_err(|_| storage())? != path {
        return Err(storage());
    }
    Ok(file)
}

struct DownloadStage { directory: Option<LocalFolder>, path: PathBuf }

impl DownloadStage {
    fn create(parent: &LocalFolder) -> EngineResult<Self> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| storage())?;
        let directory = parent.create_private_child(&format!(".svm-file-{:032x}", u128::from_ne_bytes(random)))?;
        let path = directory.path.join("data.part");
        Ok(Self { directory: Some(directory), path })
    }

    fn clear(&mut self) -> EngineResult<()> {
        if self.directory.is_none() { return Ok(()); }
        let cleanup_error = || EngineError::Invalid("The service could not remove its temporary download. Check the destination folder.".into());
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(cleanup_error()),
        }
        let folder = self.directory.take().expect("held staging folder");
        let path = folder.path.clone();
        drop(folder);
        fs::remove_dir(path).map_err(|_| cleanup_error())
    }
}

impl Drop for DownloadStage { fn drop(&mut self) { let _ = self.clear(); } }

fn digest(file: &mut File, progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>, bytes: u64, copied: u64) -> EngineResult<String> {
    if file.metadata().map_err(|_| storage())?.len() != bytes {
        return Err(EngineError::Invalid("The file size changed during the transfer.".into()));
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        progress(FileTransferUpdate::Progress { bytes: copied, total: Some(bytes) })?;
        let count = file.read(&mut buffer).map_err(|_| storage())?;
        if count == 0 { break; }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn transfer(backend: Backend, request: Request, location: (LocalFolder, PathBuf), progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>) -> EngineResult<(u64, String)> {
    let deadline = matches!(backend, Backend::Qemu(_, Some(_))).then(|| Instant::now() + svm_qemu::DOWNLOAD_TIMEOUT);
    let hyperv_free = match &backend { Backend::HyperV(_, _, _, free) => *free, Backend::Qemu(..) => None };
    let mut bounded_progress = |update: FileTransferUpdate| {
        if deadline.is_some_and(|until| Instant::now() >= until) {
            return Err(EngineError::Invalid("The QEMU file download exceeded its 15-minute limit.".into()));
        }
        if let (Some(free), FileTransferUpdate::Progress { total: Some(total), .. }) = (hyperv_free, &update) {
            check_guest_download(*total, free)?;
        }
        progress(update)
    };
    let progress = &mut bounded_progress;
    progress(FileTransferUpdate::Progress { bytes: 0, total: None })?;
    let (parent, path) = location;
    let guest = &request.guest_path;
    if matches!(request.direction, Direction::Send) {
        let mut source = regular_file(&path, false)?;
        return match backend {
            Backend::Qemu(session, _) => session.upload_file(guest, &mut source, progress),
            Backend::HyperV(driver, vm, access, _) => {
                let bytes = source.metadata().map_err(|_| storage())?.len();
                let hash = digest(&mut source, progress, bytes, 0)?;
                let expected = (bytes, hash.as_str());
                let result = match access {
                    GuestAccess::Windows(access) => driver.windows_file_upload(&vm, guest, &path, expected, access, progress),
                    GuestAccess::Linux(access) => driver.linux_file_upload(&vm, guest, &path, expected, access, progress),
                };
                drop(source);
                result
            }
        };
    }
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => return Err(EngineError::Invalid("Choose a local destination that does not already exist.".into())),
    }
    let mut temporary = DownloadStage::create(&parent)?;
    let result = (|| {
        let mut output = OpenOptions::new().read(true).write(true).create_new(true).open(&temporary.path).map_err(|_| storage())?;
        let (bytes, expected) = match backend {
            Backend::Qemu(session, available) => {
                let available = available.ok_or_else(storage)?;
                let receipt = session.download_file(guest, &mut output, available, deadline.ok_or_else(storage)?, progress)?;
                drop(output);
                receipt
            }
            Backend::HyperV(driver, vm, access, _) => {
                drop(output);
                match access {
                    GuestAccess::Windows(access) => driver.windows_file_download(&vm, guest, &temporary.path, access, progress)?,
                    GuestAccess::Linux(access) => driver.linux_file_download(&vm, guest, &temporary.path, access, progress)?,
                }
            }
        };
        let mut downloaded = regular_file(&temporary.path, true)?;
        let actual = digest(&mut downloaded, progress, bytes, bytes)?;
        downloaded.sync_all().map_err(|_| storage())?;
        drop(downloaded);
        if actual != expected {
            return Err(EngineError::Invalid("The downloaded file checksum did not match the guest.".into()));
        }
        progress(FileTransferUpdate::Publish)?;
        svm_qemu::publish_disk(&temporary.path, &path)
            .map_err(|_| EngineError::Invalid("The destination already exists or the file could not be saved.".into()))?;
        Ok((bytes, actual))
    })();
    if let Err(error) = temporary.clear() {
        if result.is_ok() {
            return Err(EngineError::Invalid("The verified file was saved. The service could not remove its empty temporary folder.".into()));
        }
        return Err(error);
    }
    result
}

impl Machines {
    pub(crate) fn file_service_route(&mut self, id: &str, method: &str, body: &Value) -> Result<Reply, ApiError> {
        let vm = self.vm(id)?;
        self.available(id)?;
        if vm.engine != EngineKind::HyperV || !matches!(vm.family, GuestFamily::Linux | GuestFamily::Windows) {
            return Err(refused("This machine has no supported Hyper-V Guest Service Interface."));
        }
        let enabled = match method {
            "GET" => None,
            "POST" => {
                if vm.state != VmState::Off {
                    return Err(refused("Shut down the machine before changing Guest Service Interface."));
                }
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Setting { enabled: bool }
                Some(parsed::<Setting>(body)?.enabled)
            }
            _ => return Err(ApiError::missing()),
        };
        let mut status = self.engine.file_guest_service(&vm, enabled).map_err(engine)?;
        status["sendSupported"] = json!(true);
        Ok(Reply::json(status))
    }

    pub(crate) fn stop_file_transfers(&mut self) { self.file_transfers.shutdown(); }

    pub(crate) fn file_transfer_busy(&self) -> bool { self.file_transfers.busy() }

    pub(crate) fn file_transfer_owns(&self, id: &str) -> bool { self.file_transfers.owns(id) }

    pub(crate) fn file_route(
        &mut self, method: &str, parts: &[&str], body: &Value, networks: &[Network], events: &mut Events,
    ) -> Result<Reply, ApiError> {
        let id = match (method, parts) {
            ("GET", ["machines", id, "files"]) => {
                self.vm(id)?;
                return Ok(self.file_transfers.latest(id));
            }
            ("GET" | "DELETE", ["machines", id, "files", job]) => {
                self.vm(id)?;
                return self.file_transfers.current(id, job, method == "DELETE");
            }
            ("POST", ["machines", id, "files"]) => *id,
            _ => return Err(ApiError::missing()),
        };
        if self.converting() || self.background_busy() || self.file_transfers.busy() || self.catalog_busy() {
            return Err(refused("Wait for the current machine or transfer operation, or cancel it first."));
        }
        let mut request: Request = parsed(body)?;
        if !request.host_path.is_absolute() || request.guest_path.is_empty() || request.guest_path.len() > 4096
            || request.guest_path.chars().any(char::is_control) {
            return Err(bad("Choose a local file and enter an absolute guest file path."));
        }
        let home = self.library_dir.parent().unwrap_or(&self.library_dir);
        let location = host_location(&request.host_path, home).map_err(engine)?;
        self.refresh_after(events, Some(id), None)?;
        self.available(id)?;
        let vm = self.vm(id)?;
        if vm.state != VmState::Running { return Err(refused("Start the machine before transferring files.")); }
        // Every download, from either engine, is checked against the destination's free space.
        let available = if matches!(request.direction, Direction::Get) {
            let free = self.engine.capacity(&location.0.path).map_err(engine)?["freeBytes"].as_u64()
                .ok_or_else(|| refused("The destination volume's free space could not be measured."))?;
            Some(free)
        } else { None };
        let backend = match vm.engine {
            EngineKind::Qemu if matches!(vm.family, GuestFamily::Linux | GuestFamily::Windows)
                && request.credentials.is_none() && request.ssh.is_none() => {
                let session = self.qemu.guest_agent(&vm).map_err(engine)?;
                Backend::Qemu(session, available)
            }
            EngineKind::HyperV => {
                let access = match vm.family {
                    GuestFamily::Linux if request.credentials.is_none() => {
                        let access = request.ssh.take().ok_or_else(|| bad("Supply a Linux guest username and its SSH host key."))?;
                        access.check().map_err(engine)?;
                        GuestAccess::Linux(access)
                    }
                    GuestFamily::Windows if request.ssh.is_none() => {
                        let access = request.credentials.take().ok_or_else(|| bad("Enter the Windows guest username and password for this transfer."))?;
                        access.check().map_err(engine)?;
                        GuestAccess::Windows(access)
                    }
                    _ => return Err(refused("This Hyper-V guest has no supported file transfer connection.")),
                };
                self.engine.set_networks(networks);
                let driver = self.engine.background_driver().ok_or_else(|| refused("This host cannot transfer Hyper-V guest files."))?;
                Backend::HyperV(driver, vm, access, available)
            }
            _ => return Err(refused("This machine has no requested file transfer connection.")),
        };
        self.file_transfers.start(id.to_owned(), request, backend, location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyperv_downloads_have_the_qemu_size_and_free_space_limits() {
        const GIB: u64 = 1024 * 1024 * 1024;
        assert!(check_guest_download(GIB, 2 * GIB).is_ok());
        assert!(check_guest_download(4 * GIB, 5 * GIB).is_ok());
        assert!(check_guest_download(4 * GIB + 1, u64::MAX).is_err());
        assert!(check_guest_download(GIB, GIB + 63 * 1024 * 1024).is_err());
        assert!(check_guest_download(u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn host_file_locations_reject_the_service_and_nested_library_folders() {
        let root = std::env::temp_dir().join(next_id());
        let private = root.join("service");
        let library = private.join("library").join("machine");
        let outside = root.join("service-external");
        fs::create_dir_all(&library).unwrap();
        fs::create_dir(&outside).unwrap();
        let private = private.canonicalize().unwrap();
        assert!(host_location(&private.join("api-token"), &private).is_err());
        assert!(host_location(&library.join("guest-file"), &private).is_err());
        assert!(host_location(&outside.join("guest-file"), &private).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_and_publication_are_mutually_exclusive() {
        let mut accepted = Status::new(Direction::Send);
        accepted.update(FileTransferUpdate::Progress { bytes: 20, total: Some(50) }).unwrap();
        accepted.cancel().unwrap();
        let refused = accepted.update(FileTransferUpdate::Publish).unwrap_err();
        accepted.finish(Err(refused));
        assert_eq!(accepted.state, Phase::Cancelled);
        assert_eq!(accepted.bytes, 20);

        let mut publishing = Status::new(Direction::Get);
        publishing.update(FileTransferUpdate::Publish).unwrap();
        assert_eq!(publishing.state, Phase::Finalizing);
        assert_eq!(publishing.cancel().unwrap_err().status, 409);
    }
}
