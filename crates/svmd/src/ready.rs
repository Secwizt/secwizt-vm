//! Ready-to-run images. "Get" downloads a publisher's ready-made disk with the verified catalog
//! downloader, then prepares it once on a worker thread: unpack (archives only), strict
//! inspection, conversion to a fresh standalone qcow2 and its SHA-256, and then a sealed
//! read-only template. "Launch" makes a linked clone of that template after the template's
//! SHA-256 is re-checked on a worker thread, with private first-boot settings for cloud images.
//! No installer runs, and no long hash runs on the service thread.

use super::*;
use super::{
    catalog::{self, Entry, FirstBoot, Phase},
    catalog_store as store, ready_archive, ready_seed,
    templates::TemplateFile,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    sync::{atomic::{AtomicBool, AtomicU8, Ordering}, Arc},
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};
use svm_core::model::{ReadyOrigin, TemplateDisk};

const STAGING: &str = "ready-images";
const UNPACKED: &str = "unpacked.qcow2";
const PREPARED: &str = "prepared.qcow2";
const GIB: u64 = 1 << 30;
/// How long the Ready list may reuse its free-space and QEMU readings.
const ENVIRONMENT_TTL: Duration = Duration::from_secs(10);
/// How often queued Get requests look at their downloads.
const QUEUE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
#[repr(u8)]
enum Stage { Checking = 0, Unpacking = 1, Converting = 2, Hashing = 3 }

impl Stage {
    fn name(value: u8) -> &'static str {
        match value {
            1 => "unpacking",
            2 => "converting",
            3 => "hashing",
            _ => "checking",
        }
    }
}

struct Shared {
    stage: AtomicU8,
    unpack_percent: AtomicU8,
    hash_percent: AtomicU8,
    cancel: AtomicBool,
    convert: Arc<svm_qemu::TransferControl>,
}

impl Shared {
    fn cancelled(&self) -> bool { self.cancel.load(Ordering::Acquire) }

    fn status(&self, id: &str) -> Value {
        let stage = self.stage.load(Ordering::Acquire);
        let percent = match stage {
            1 => self.unpack_percent.load(Ordering::Acquire),
            2 => self.convert.percent(),
            3 => self.hash_percent.load(Ordering::Acquire),
            _ => 0,
        };
        json!({"id": id, "stage": Stage::name(stage), "percent": percent,
            "state": if self.cancelled() { "cancelling" } else { "running" }})
    }
}

/// The worker's result: the prepared disk and its SHA-256, read through a handle that denied
/// writers. Size and last-write time identify the same file after its rename into the bundle.
struct Prepared { disk: PathBuf, sha256: String, bytes: u64, modified: SystemTime }

struct Job {
    entry: Entry,
    shared: Arc<Shared>,
    folder: PathBuf,
    worker: Option<JoinHandle<Result<Prepared, String>>>,
    _folder_handle: svm_qemu::LocalFolder,
}

#[derive(Default)]
pub(super) struct ReadyJobs {
    current: Option<Job>,
    outcomes: BTreeMap<String, Value>,
    /// Images whose Get waits for their download to finish verification.
    queued: BTreeSet<String>,
    queue_checked: Option<Instant>,
    environment: Option<(Instant, Option<u64>, Value)>,
}

impl ReadyJobs {
    pub(super) fn active(&self) -> bool { self.current.is_some() }
}

impl Drop for ReadyJobs {
    fn drop(&mut self) {
        if let Some(mut job) = self.current.take() {
            job.shared.cancel.store(true, Ordering::Release);
            job.shared.convert.cancel();
            if let Some(worker) = job.worker.take() { let _ = worker.join(); }
            let folder = job.folder.clone();
            drop(job);
            let _ = clean_staging(&folder);
        }
    }
}

/// Remove only the files this module writes, then the folder. Anything else stops the cleanup.
fn clean_staging(folder: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(folder) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("The image staging folder could not be read.".into()),
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { return Err("The image staging folder is a link.".into()); }
    }
    if !metadata.is_dir() { return Err("The image staging path is not a folder.".into()); }
    for name in [UNPACKED, PREPARED] {
        let path = folder.join(name);
        match fs::symlink_metadata(&path) {
            Ok(file) if file.is_file() => fs::remove_file(&path)
                .map_err(|_| "A staged image file is still in use. Retry after the disk tool exits.".to_owned())?,
            Ok(_) => return Err("The image staging folder holds an unexpected item.".into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err("The image staging folder could not be read.".into()),
        }
    }
    fs::remove_dir(folder).map_err(|_| "The image staging folder holds unexpected files.".to_owned())
}

fn ready_entry(id: &str) -> Result<&'static Entry, ApiError> {
    catalog::ready_images()?.iter().find(|entry| entry.id == id).ok_or_else(ApiError::missing)
}

fn spec(entry: &Entry) -> Result<&catalog::ReadySpec, ApiError> {
    entry.ready.as_ref().ok_or_else(|| ApiError::new(500, "catalog_invalid", "The ready image entry is incomplete."))
}

/// Free space needed to prepare: the unpacked archive member (if any) plus the converted disk.
/// A converted cloud image holds at most its virtual size; a converted archive member holds at
/// most the member's allocated bytes.
fn space_needed(entry: &Entry) -> Result<u64, ApiError> {
    let ready = spec(entry)?;
    Ok(match &ready.archive {
        Some(member) => member.bytes.saturating_mul(2),
        None => ready.disk_bytes,
    }.saturating_add(GIB))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Launch {
    name: String,
    user: Option<String>,
    password: Option<String>,
    #[serde(default)]
    generate_password: bool,
    ssh_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultLogin { changed: bool }

/// Checked first-boot values for a cloud image. The password exists here only as its hash.
struct FirstBootValues { user: String, hash: String, key: Option<String> }

/// Hash a file through a handle that denies writers, and return its size and last-write time.
fn hash_file(path: &Path, percent: &AtomicU8, cancelled: &dyn Fn() -> bool) -> Result<(String, u64, SystemTime), String> {
    let unreadable = || "The prepared disk could not be read for its checksum.".to_owned();
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut file = options.open(path).map_err(|_| unreadable())?;
    let before = file.metadata().map_err(|_| unreadable())?;
    let total = before.len().max(1);
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut done = 0_u64;
    loop {
        if cancelled() { return Err(ready_archive::CANCELLED.into()); }
        let count = file.read(&mut buffer).map_err(|_| unreadable())?;
        if count == 0 { break; }
        hash.update(&buffer[..count]);
        done += count as u64;
        percent.store(u8::try_from((done.saturating_mul(100) / total).min(100)).unwrap_or(100), Ordering::Release);
    }
    let after = file.metadata().map_err(|_| unreadable())?;
    let modified = after.modified().map_err(|_| unreadable())?;
    if done != before.len() || after.len() != before.len() || before.modified().ok() != Some(modified) {
        return Err("The prepared disk changed while it was checked.".into());
    }
    Ok((format!("{:x}", hash.finalize()), done, modified))
}

fn prepare_worker(
    entry: Entry, installers: PathBuf, folder: PathBuf, tool: svm_qemu::ImageTool, shared: Arc<Shared>,
) -> Result<Prepared, String> {
    let ready = entry.ready.as_ref().ok_or("The ready image entry is incomplete.")?;
    // Re-read the download and check it against its verification receipt and the catalog pin.
    let held = store::verified_installer(&installers, &entry)?;
    if shared.cancelled() { return Err(ready_archive::CANCELLED.into()); }
    let source_path = match &ready.archive {
        Some(member) => {
            shared.stage.store(Stage::Unpacking as u8, Ordering::Release);
            let target = folder.join(UNPACKED);
            ready_archive::unpack_member(held.path(), member, &target, &shared.unpack_percent, &|| shared.cancelled())?;
            target
        }
        None => held.path().to_owned(),
    };
    if shared.cancelled() { return Err(ready_archive::CANCELLED.into()); }
    shared.stage.store(Stage::Converting as u8, Ordering::Release);
    let source = tool.disk_source(&source_path).map_err(|error| error.to_string())?;
    if source.info.format != "qcow2" || source.info.bytes != ready.disk_bytes {
        return Err("The image is not the qcow2 disk that the catalog describes.".into());
    }
    let output = folder.join(PREPARED);
    // A fresh conversion writes a new standalone qcow2: no compressed clusters, snapshots or
    // other structures carried over from the publisher's file.
    source.convert(&output, "qcow2", shared.convert.clone()).map_err(|error| error.to_string())?;
    drop(held);
    if ready.archive.is_some() { let _ = fs::remove_file(&source_path); }
    if shared.cancelled() { return Err(ready_archive::CANCELLED.into()); }
    tool.grow_qcow2(&output, ready.template_bytes(&entry)).map_err(|error| error.to_string())?;
    shared.stage.store(Stage::Hashing as u8, Ordering::Release);
    let (sha256, bytes, modified) = hash_file(&output, &shared.hash_percent, &|| shared.cancelled())?;
    Ok(Prepared { disk: output, sha256, bytes, modified })
}

fn write_seed(bundle: &Path, seed: &ready_seed::Seed) -> Result<(), ApiError> {
    let parent = svm_qemu::LocalFolder::open(bundle).map_err(engine)?;
    let folder = parent.create_private_child(svm_qemu::FIRST_BOOT).map_err(engine)?;
    for (name, text) in [("meta-data", &seed.meta_data), ("user-data", &seed.user_data)] {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(folder.path.join(name)).map_err(io_error)?;
        file.write_all(text.as_bytes()).and_then(|()| file.sync_all()).map_err(io_error)?;
    }
    Ok(())
}

/// Check the launch fields for a ready image before anything is created.
fn first_boot_values(ready: &catalog::ReadySpec, request: &Launch) -> Result<(Option<FirstBootValues>, Option<String>), ApiError> {
    match ready.first_boot {
        FirstBoot::CloudInit => {
            let user = request.user.as_deref().ok_or_else(|| bad("Choose a user name for the first sign-in."))?;
            if !ready_seed::valid_user(user) {
                return Err(bad("Choose a user name of lowercase letters, digits, - or _ (up to 31) that is not a system account."));
            }
            let mut generated = None;
            let hash = match (request.password.as_deref(), request.generate_password) {
                (Some(_), true) => return Err(bad("Type a password or ask for a generated one, not both.")),
                (Some(password), false) => {
                    if !ready_seed::valid_password(password) {
                        return Err(bad("Use a password of 8 to 128 characters without line breaks or outer spaces."));
                    }
                    ready_seed::hash_password(password).map_err(refused)?
                }
                (None, _) => {
                    let password = ready_seed::generate_password().map_err(refused)?;
                    let hash = ready_seed::hash_password(&password).map_err(refused)?;
                    generated = Some(password);
                    hash
                }
            };
            let key = request.ssh_key.as_deref().map(str::trim).filter(|line| !line.is_empty())
                .map(|line| ready_seed::normalized_ssh_key(line).ok_or_else(|| bad("Paste one OpenSSH public key line.")))
                .transpose()?;
            Ok((Some(FirstBootValues { user: user.to_owned(), hash, key }), generated))
        }
        FirstBoot::DefaultLogin => {
            if request.user.is_some() || request.password.is_some() || request.generate_password || request.ssh_key.is_some() {
                return Err(bad("This image starts with its publisher's default login. Change the password after the first sign-in."));
            }
            Ok((None, None))
        }
    }
}

impl Machines {
    fn ready_template(&self, image: &str) -> Option<&Vm> {
        self.inventory.iter().find(|vm| vm.template.is_some() && vm.linked_from.is_none()
            && vm.engine == EngineKind::Qemu && vm.ready.as_ref().is_some_and(|ready| ready.image == image))
    }

    /// A machine created from this image whose seal did not finish (for example after a power cut).
    fn unsealed_ready_copy(&self, image: &str) -> Option<&Vm> {
        self.inventory.iter().find(|vm| vm.template.is_none() && vm.linked_from.is_none()
            && vm.ready.as_ref().is_some_and(|ready| ready.image == image))
    }

    fn ready_staging_root(&self) -> Result<PathBuf, ApiError> {
        Ok(self.library_dir.parent().ok_or_else(|| refused("The service data folder could not be found."))?.join(STAGING))
    }

    /// Other work that writes large files or needs the machine library to itself.
    fn ready_blocked(&self) -> bool {
        self.ready_jobs.active() || self.transfers.active() || self.catalog_busy() || self.background_busy()
            || self.file_transfer_busy()
    }

    fn unique_template_name(&self, base: &str) -> Result<String, ApiError> {
        let held = self.held_identities()?;
        for number in 1..100 {
            let name = if number == 1 { base.to_owned() } else { format!("{base} {number}") };
            if !held.iter().any(|vm| vm.name.eq_ignore_ascii_case(&name)) { return Ok(name); }
        }
        Err(refused("Rename or remove older copies of this ready image first."))
    }

    /// Free space and QEMU state for the Ready list, reused for a few seconds: the list is polled
    /// while work runs, and measuring free space starts a helper process.
    fn ready_environment(&mut self) -> (Option<u64>, Value) {
        if let Some((at, free, qemu)) = &self.ready_jobs.environment {
            if at.elapsed() < ENVIRONMENT_TTL { return (*free, qemu.clone()); }
        }
        let (free, qemu) = (self.installer_free_bytes(), self.qemu.prerequisites());
        self.ready_jobs.environment = Some((Instant::now(), free, qemu.clone()));
        (free, qemu)
    }

    pub(crate) fn ready_route(
        &mut self, method: &str, parts: &[&str], body: &Value, networks: &[Network], events: &mut Events,
    ) -> Result<Reply, ApiError> {
        self.finish_ready(networks, events)?;
        match (method, parts) {
            ("GET", ["ready"]) => self.ready_list(),
            ("POST", ["ready", id, "prepare"]) => self.ready_prepare(id, body),
            ("DELETE", ["ready", id, "prepare"]) => self.ready_cancel(id),
            _ => Err(ApiError::missing()),
        }
    }

    fn ready_list(&mut self) -> Result<Reply, ApiError> {
        let base = self.library_dir.join("installers");
        let (free, qemu) = self.ready_environment();
        let mut images = Vec::new();
        for entry in catalog::ready_images()? {
            let ready = spec(entry)?;
            let download = self.catalog_downloads.status(&base, entry);
            let template = self.ready_template(&entry.id).map(|vm| {
                let machines = self.inventory.iter().filter(|other| other.linked_from.as_deref() == Some(vm.id.as_str())).count();
                json!({"id": vm.id, "name": vm.name, "machines": machines})
            });
            let unsealed = self.unsealed_ready_copy(&entry.id).map(|vm| json!({"id": vm.id, "name": vm.name}));
            let preparing = self.ready_jobs.current.as_ref().filter(|job| job.entry.id == entry.id)
                .map(|job| job.shared.status(&entry.id));
            images.push(json!({
                "id": entry.id, "name": entry.name, "version": entry.version, "edition": entry.edition,
                "publisher": ready.publisher, "desktop": ready.desktop, "firstBoot": ready.first_boot,
                "defaultUser": ready.default_user, "note": ready.note,
                "verification": if entry.signature_required() { "Signed" } else { "Checksum" },
                "sourceHost": entry.official_hosts.first(), "bytes": entry.bytes, "fileName": entry.file_name,
                "unpackedBytes": ready.archive.as_ref().map(|member| member.bytes),
                "diskGb": ready.template_bytes(entry).div_ceil(GIB), "spaceNeeded": space_needed(entry)?,
                "vcpu": entry.vcpu, "ramGb": entry.ram_gb,
                "download": download, "template": template, "unsealed": unsealed, "preparing": preparing,
                "queued": self.ready_jobs.queued.contains(&entry.id),
                "outcome": self.ready_jobs.outcomes.get(&entry.id),
            }));
        }
        Ok(Reply::json(json!({"freeBytes": free, "qemu": qemu, "images": images})))
    }

    /// Get: start or continue the download, then prepare the image once it is verified.
    fn ready_prepare(&mut self, id: &str, body: &Value) -> Result<Reply, ApiError> {
        if !(body.is_null() || body.as_object().is_some_and(|fields| fields.is_empty())) {
            return Err(bad("Choose a bundled ready image without supplying a path or URL."));
        }
        let entry = ready_entry(id)?;
        if self.ready_template(id).is_some() { return Err(refused("This image is already prepared.")); }
        if let Some(copy) = self.unsealed_ready_copy(id) {
            return Err(refused(format!("An unfinished copy of this image exists ({}). Make it a template from its machine page, or delete it, then choose Get again.", copy.name)));
        }
        let queued = json!({"id": id, "queued": true});
        if self.ready_jobs.queued.contains(id) { return Ok(Reply::json_status(202, queued)); }
        if let Some(job) = self.ready_jobs.current.as_ref().filter(|job| job.entry.id == id) {
            return Ok(Reply::json_status(202, job.shared.status(id)));
        }
        let status = self.qemu.prerequisites();
        if status["available"] != true {
            return Err(refused(status["reason"].as_str().unwrap_or("Select QEMU in Settings first.")));
        }
        let installers = self.library_dir.join("installers");
        match self.catalog_downloads.status(&installers, entry).state {
            Phase::Verified => self.start_prepare(entry),
            Phase::Downloading | Phase::Verifying | Phase::Publishing => {
                self.ready_jobs.outcomes.remove(id);
                self.ready_jobs.queued.insert(id.to_owned());
                Ok(Reply::json_status(202, queued))
            }
            Phase::Cancelling => Err(refused("Wait for the download to stop, then choose Get again.")),
            Phase::Idle | Phase::Paused | Phase::Failed => {
                // The catalog download checks space, official hosts and the pinned checksum.
                self.catalog_route("POST", &["catalog", id, "download"], &json!({}))?;
                self.ready_jobs.outcomes.remove(id);
                self.ready_jobs.queued.insert(id.to_owned());
                Ok(Reply::json_status(202, queued))
            }
        }
    }

    fn start_prepare(&mut self, entry: &Entry) -> Result<Reply, ApiError> {
        let id = entry.id.as_str();
        if self.ready_blocked() || self.converting() {
            return Err(refused("Wait for the current download, conversion or machine operation to finish."));
        }
        let installers = self.library_dir.join("installers");
        if self.catalog_downloads.status(&installers, entry).state != Phase::Verified {
            return Err(refused("Download and verify this image first."));
        }
        let needed = space_needed(entry)?;
        let free = self.installer_free_bytes().ok_or_else(|| refused("The free space on the library drive could not be measured."))?;
        if free < needed {
            return Err(refused(format!("Preparing this image needs about {} GB free on the library drive.", needed.div_ceil(1_000_000_000))));
        }
        let tool = self.qemu.image_tool().map_err(engine)?;
        let root_path = self.ready_staging_root()?;
        let root = if root_path.try_exists().map_err(io_error)? {
            svm_qemu::LocalFolder::open(&root_path)
        } else {
            svm_qemu::LocalFolder::open(root_path.parent().ok_or_else(|| refused("The service data folder could not be found."))?)
                .and_then(|home| home.create_private_child(STAGING))
        }.map_err(engine)?;
        let folder = root.path.join(id);
        clean_staging(&folder).map_err(|message| refused(&message))?;
        let held_folder = root.create_private_child(id).map_err(engine)?;
        let shared = Arc::new(Shared {
            stage: AtomicU8::new(Stage::Checking as u8), unpack_percent: AtomicU8::new(0), hash_percent: AtomicU8::new(0),
            cancel: AtomicBool::new(false), convert: Arc::new(svm_qemu::TransferControl::default()),
        });
        let (job_entry, job_folder, job_shared) = (entry.clone(), held_folder.path.clone(), shared.clone());
        let worker = std::thread::Builder::new().name("ready-image".into())
            .spawn(move || prepare_worker(job_entry, installers, job_folder, tool, job_shared))
            .map_err(io_error)?;
        self.ready_jobs.outcomes.remove(id);
        let reply = Reply::json_status(202, shared.status(id));
        self.ready_jobs.current = Some(Job {
            entry: entry.clone(), shared, folder: held_folder.path.clone(), worker: Some(worker), _folder_handle: held_folder,
        });
        Ok(reply)
    }

    fn ready_cancel(&mut self, id: &str) -> Result<Reply, ApiError> {
        if self.ready_jobs.queued.remove(id) {
            // The queued Get is dropped; the download itself keeps its own cancel control.
            return Ok(Reply::json(json!({"id": id, "queued": false})));
        }
        let job = self.ready_jobs.current.as_ref().filter(|job| job.entry.id == id)
            .ok_or_else(|| refused("This image is not being prepared."))?;
        job.shared.cancel.store(true, Ordering::Release);
        job.shared.convert.cancel();
        Ok(Reply::json(job.shared.status(id)))
    }

    /// Runs on every service tick: finishes a prepared image and starts queued ones.
    pub(crate) fn finish_ready(&mut self, networks: &[Network], events: &mut Events) -> Result<(), ApiError> {
        if self.ready_jobs.current.as_ref().and_then(|job| job.worker.as_ref()).is_some_and(|worker| worker.is_finished()) {
            let mut job = self.ready_jobs.current.take().expect("finished ready job");
            let cancelled = job.shared.cancelled();
            let result = job.worker.take().expect("ready worker").join()
                .map_err(|_| "Preparing the image stopped unexpectedly.".to_owned())
                .and_then(|result| result);
            let outcome = match result {
                Ok(_) if cancelled => Err(ready_archive::CANCELLED.to_owned()),
                Ok(prepared) => self.adopt_ready_template(&job.entry, &prepared, networks, events),
                Err(message) => Err(message),
            };
            let (id, folder) = (job.entry.id.clone(), job.folder.clone());
            drop(job);
            let cleanup = clean_staging(&folder);
            self.ready_jobs.environment = None;
            match outcome {
                Ok(template) => {
                    self.ready_jobs.outcomes.remove(&id);
                    events.record("ready image prepared", &format!("{id} is ready as the sealed template {template}."))?;
                }
                Err(message) => {
                    let state = if cancelled { "cancelled" } else { "failed" };
                    events.record("ready image not prepared", &format!("{id}: {message}"))?;
                    self.ready_jobs.outcomes.insert(id, json!({"state": state, "message": message}));
                }
            }
            if let Err(message) = cleanup { events.record("ready image cleanup", &message)?; }
        }
        self.advance_ready_queue(events)
    }

    fn advance_ready_queue(&mut self, events: &mut Events) -> Result<(), ApiError> {
        if self.ready_jobs.queued.is_empty()
            || self.ready_jobs.queue_checked.is_some_and(|at| at.elapsed() < QUEUE_INTERVAL) {
            return Ok(());
        }
        self.ready_jobs.queue_checked = Some(Instant::now());
        let installers = self.library_dir.join("installers");
        for id in self.ready_jobs.queued.clone() {
            let Ok(entry) = ready_entry(&id) else { self.ready_jobs.queued.remove(&id); continue; };
            let status = self.catalog_downloads.status(&installers, entry);
            match status.state {
                Phase::Verified => {
                    if self.ready_blocked() || self.converting() { continue; }
                    self.ready_jobs.queued.remove(&id);
                    if let Err(error) = self.start_prepare(entry) {
                        events.record("ready image not prepared", &format!("{id}: {}", error.message))?;
                        self.ready_jobs.outcomes.insert(id, json!({"state": "failed", "message": error.message}));
                    }
                }
                Phase::Idle | Phase::Paused | Phase::Failed => {
                    self.ready_jobs.queued.remove(&id);
                    let message = status.message.unwrap_or_else(|| "The download stopped before it was verified.".into());
                    self.ready_jobs.outcomes.insert(id, json!({"state": "failed", "message": message}));
                }
                Phase::Downloading | Phase::Cancelling | Phase::Verifying | Phase::Publishing => {}
            }
        }
        Ok(())
    }

    fn adopt_ready_template(&mut self, entry: &Entry, prepared: &Prepared, networks: &[Network], events: &mut Events) -> Result<String, String> {
        let ready = spec(entry).map_err(|error| error.message)?;
        let id = next_id();
        let name = self.unique_template_name(&format!("{} {} ready image", entry.name, entry.version)).map_err(|error| error.message)?;
        let machine = json!({"id": id, "name": name, "os": format!("{} {}", entry.name, entry.version),
            "family": "linux", "engine": "QEMU", "net": "nat", "vcpu": entry.vcpu, "ramGb": entry.ram_gb,
            "secureBoot": false, "tpm": false});
        let origin = ReadyOrigin { image: entry.id.clone(), default_login: ready.default_user.clone(), seed: false };
        let request = parsed(&machine).map_err(|error| error.message)?;
        self.create_ready(request, networks, events, (&prepared.disk, ready.template_bytes(entry)), origin)
            .map_err(|error| error.message)?;
        match self.seal_template_with_digest(&id, &prepared.sha256, prepared.bytes, prepared.modified, networks, events) {
            Ok(_) => Ok(id),
            Err(error) => {
                // Do not leave a full-size, unsealed copy behind.
                let removal = self.discard_machine(&id, &name, networks, events);
                Err(match removal {
                    Ok(()) => error.message,
                    Err(problem) => format!("{} The unfinished copy {name} could not be removed: {}", error.message, problem.message),
                })
            }
        }
    }

    /// Move a machine this module created to the trash and empty that trash entry.
    fn discard_machine(&mut self, id: &str, name: &str, networks: &[Network], events: &mut Events) -> Result<(), ApiError> {
        self.route("DELETE", &["machines", id], &json!({"keepCopy": false}), networks, events)?;
        let key = self.library.list_trash().map_err(store)?.into_iter()
            .find(|entry| entry.machine.id == id).map(|entry| entry.key)
            .ok_or_else(|| refused("The unfinished copy was not found in the trash."))?;
        self.delete_trash(&key, &json!({"confirmName": name}), events).map(drop)
    }

    /// Launch: re-check the template's SHA-256 on a worker thread, then make the linked clone.
    pub(super) fn prepare_ready_launch(&mut self, method: &str, parts: &[&str], body: &Value) -> Result<Option<BackgroundTask>, ApiError> {
        let ("POST", ["ready", image, "launch"]) = (method, parts) else { return Ok(None); };
        let request: Launch = parsed(body)?;
        let entry = ready_entry(image)?;
        let ready = spec(entry)?;
        if self.ready_blocked() || self.converting() {
            return Err(refused("Wait for the current download, conversion or machine operation to finish."));
        }
        let template = self.ready_template(image).map(|vm| vm.id.clone()).ok_or_else(|| refused("Get this image first."))?;
        let child = next_id();
        self.ensure_identity(&child, &request.name)?;
        let (values, generated) = first_boot_values(ready, &request)?;
        let (saved, file): (TemplateDisk, TemplateFile) = self.held_template(&template)?;
        let (name, image, default_login) = (request.name, entry.id.clone(), ready.default_user.clone());
        let task_template = template.clone();
        let run = move || -> MachineCompletion {
            let digest = file.sha256();
            Box::new(move |machines, networks, events| {
                let digest = digest?;
                if digest != saved.sha256 {
                    return Err(refused("The template disk does not match its recorded SHA-256. The machine was not created."));
                }
                let reply = machines.finish_ready_launch(&task_template, child, name, &digest,
                    (image, default_login, values, generated), networks, events);
                drop(file);
                reply
            })
        };
        Ok(Some(BackgroundTask { machines: vec![template], reserved: None, hyperv: false, qemu_checkpoint: false,
            catalog_io: false, accepted: None, run: Box::new(run) }))
    }

    fn finish_ready_launch(
        &mut self, template: &str, child: String, name: String, digest: &str,
        (image, default_login, values, generated): (String, Option<String>, Option<FirstBootValues>, Option<String>),
        networks: &[Network], events: &mut Events,
    ) -> Result<Reply, ApiError> {
        self.link_template(template, name, Some(child.clone()), Some(digest), networks, events)?;
        let mut machine = self.vm(&child)?;
        let finished = (|| -> Result<(), ApiError> {
            if let Some(values) = &values {
                let host = machine.dns.split('.').next().unwrap_or_default().to_owned();
                let seed = ready_seed::cloud_seed(&machine.id, &host, &values.user, &values.hash, values.key.as_deref()).map_err(bad)?;
                write_seed(&self.library.bundle_path(&machine.id).map_err(store)?, &seed)?;
            }
            machine.ready = Some(ReadyOrigin { image: image.clone(), default_login: default_login.clone(), seed: values.is_some() });
            self.save(&machine)
        })();
        if let Err(error) = finished {
            let _ = self.remove_incomplete_linked_clone(&machine.id, events);
            return Err(error);
        }
        events.record("ready machine created", &format!("{} was made from the ready image {image}.", machine.id))?;
        let mut reply = json!({"machine": self.published(&machine, networks)});
        if let Some(password) = generated { reply["password"] = json!(password); }
        Ok(Reply::created(reply))
    }

    /// Plain linked clones of a cloud image would start with no user: they need first-boot settings.
    pub(super) fn refuse_plain_clone(&self, id: &str) -> Result<(), ApiError> {
        let vm = self.vm(id)?;
        let Some(origin) = &vm.ready else { return Ok(()); };
        let default_login = ready_entry(&origin.image).ok().and_then(|entry| entry.ready.as_ref())
            .is_some_and(|ready| ready.first_boot == FirstBoot::DefaultLogin);
        if vm.template.is_some() && !default_login {
            return Err(refused("Machines from this image need their own first-boot settings. Use Marketplace, Ready to run, Launch."));
        }
        Ok(())
    }

    /// The owner confirms that the publisher's default password was changed inside the guest.
    pub(super) fn confirm_default_login(&mut self, id: &str, body: &Value, networks: &[Network], events: &mut Events) -> Result<Reply, ApiError> {
        let request: DefaultLogin = parsed(body)?;
        if !request.changed { return Err(bad("Confirm that the default password was changed.")); }
        let mut vm = self.vm(id)?;
        if vm.template.is_some() { return Err(refused("A template keeps the publisher's image unchanged.")); }
        if vm.throwaway || self.throwaway_pending(&vm) {
            return Err(refused("Turn off throwaway mode first: a password changed during a throwaway run is discarded when the machine powers off."));
        }
        self.require_recovered(&vm)?;
        match vm.ready.as_mut() {
            Some(ready) if ready.default_login.is_some() => ready.default_login = None,
            _ => return Err(refused("This machine has no publisher default login to clear.")),
        }
        self.save(&vm)?;
        events.record("default login cleared", &format!("The owner confirmed a new password for {id}."))?;
        Ok(Reply::json(self.published(&vm, networks)))
    }

    /// Remove staging left by a crash or power cut. Downloads and templates are not touched, and a
    /// problem here is recorded instead of stopping the service from starting.
    pub(super) fn recover_ready(&self, events: &mut Events) -> Result<(), ApiError> {
        let root = self.ready_staging_root()?;
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return events.record("ready image cleanup", "The image staging folder could not be read."),
        };
        for item in entries {
            let Ok(item) = item else {
                events.record("ready image cleanup", "An image staging entry could not be read.")?;
                continue;
            };
            let known = item.file_name().to_str().is_some_and(|name| ready_entry(name).is_ok());
            let result = if known { clean_staging(&item.path()) } else { Err("The image staging folder holds an unknown item.".into()) };
            if let Err(message) = result { events.record("ready image cleanup", &message)?; }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_ready_images_are_valid_and_pinned() {
        let images = catalog::ready_images().expect("valid ready images");
        assert_eq!(images.len(), 3);
        for entry in images {
            let ready = entry.ready.as_ref().unwrap();
            assert_eq!(entry.engine, EngineKind::Qemu);
            assert!(ready.template_bytes(entry) >= ready.disk_bytes);
            match ready.first_boot {
                FirstBoot::CloudInit => assert!(ready.default_user.is_none() && ready.template_bytes(entry) >= 20 * GIB),
                FirstBoot::DefaultLogin => assert_eq!(ready.template_bytes(entry), ready.disk_bytes),
            }
        }
        let kali = images.iter().find(|entry| entry.id == "kali-2026-3-qemu-amd64").unwrap();
        assert!(kali.signature_required() && kali.ready.as_ref().unwrap().archive.is_some());
        assert!(kali.url.starts_with("https://kali.download/"), "Kali's own CDN, not the mirror redirector");
        let debian = images.iter().find(|entry| entry.id == "debian-13-20261123-cloud-amd64").unwrap();
        assert!(!debian.signature_required(), "Debian publishes no signature for its cloud image list");
        assert!(catalog::selection("kali-2026-3-qemu-amd64").is_err(), "ready images never reach the installer wizard");
    }

    #[test]
    fn ready_catalog_refuses_unsafe_entries() {
        let data = include_str!("../catalog/ready.json");
        let parse = |text: &str| -> bool {
            serde_json::from_str::<Vec<Entry>>(text).ok().is_some_and(|rows| rows.iter().all(|row| row.ready.is_some() && row.valid()))
        };
        assert!(parse(data));
        for (from, to) in [
            ("\"engine\": \"QEMU\"", "\"engine\": \"Hyper-V\""),
            ("https://kali.download/base-images/kali-2026.3/kali", "https://mirror.example/base-images/kali-2026.3/kali"),
            ("\"member\": \"kali-linux-2026.3-qemu-amd64.qcow2\"", "\"member\": \"../kali.qcow2\""),
            ("\"defaultUser\": \"kali\"", "\"defaultUser\": \"root\""),
            ("\"firstBoot\": \"cloud-init\"", "\"firstBoot\": \"default-login\""),
            ("\"diskBytes\": 86000000000", "\"diskBytes\": 0"),
            ("\"fileName\": \"kali-linux-2026.3-qemu-amd64.7z\"", "\"fileName\": \"kali-linux-2026.3-qemu-amd64.iso\""),
            ("827C8569F2518CC677FECA1AED65462EC8D5E4C5", "827C8569"),
        ] {
            assert!(data.contains(from), "{from}");
            assert!(!parse(&data.replacen(from, to, 1)), "{from} -> {to} was accepted");
        }
        assert!(serde_json::from_str::<Vec<Entry>>(&data.replacen("\"desktop\": true", "\"desktop\": true, \"url\": \"x\"", 1)).is_err());
    }

    #[test]
    fn staging_cleanup_removes_only_its_own_files() {
        let root = std::env::temp_dir().join(next_id());
        fs::create_dir(&root).unwrap();
        let folder = root.join("debian-13-20261123-cloud-amd64");
        fs::create_dir(&folder).unwrap();
        fs::write(folder.join(UNPACKED), b"x").unwrap();
        fs::write(folder.join(PREPARED), b"y").unwrap();
        clean_staging(&folder).unwrap();
        assert!(!folder.exists());
        fs::create_dir(&folder).unwrap();
        fs::write(folder.join("owner-notes.txt"), b"keep").unwrap();
        assert!(clean_staging(&folder).is_err());
        assert!(folder.join("owner-notes.txt").exists());
        assert!(clean_staging(&root.join("missing")).is_ok());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn hashing_reports_the_digest_size_and_refuses_after_cancel() {
        let root = std::env::temp_dir().join(next_id());
        fs::create_dir(&root).unwrap();
        let disk = root.join(PREPARED);
        let data = b"prepared disk bytes".repeat(70_000);
        fs::write(&disk, &data).unwrap();
        let percent = AtomicU8::new(0);
        let (digest, bytes, _) = hash_file(&disk, &percent, &|| false).unwrap();
        assert_eq!(digest, format!("{:x}", Sha256::digest(&data)));
        assert_eq!(bytes, data.len() as u64);
        assert_eq!(percent.load(Ordering::Acquire), 100);
        assert_eq!(hash_file(&disk, &percent, &|| true).unwrap_err(), ready_archive::CANCELLED);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn launch_fields_are_checked_before_anything_is_created() {
        let images = catalog::ready_images().unwrap();
        let cloud = images.iter().find(|entry| entry.id == "debian-13-20261123-cloud-amd64").unwrap().ready.as_ref().unwrap();
        let kali = images.iter().find(|entry| entry.id == "kali-2026-3-qemu-amd64").unwrap().ready.as_ref().unwrap();
        let launch = |value: Value| -> Launch { serde_json::from_value(value).unwrap() };
        let (values, generated) = first_boot_values(cloud, &launch(json!({"name": "Lab", "user": "labuser", "generatePassword": true}))).unwrap();
        let values = values.unwrap();
        assert!(values.hash.starts_with("$6$") && generated.is_some_and(|password| password.len() == ready_seed::GENERATED_PASSWORD_LENGTH));
        let (values, generated) = first_boot_values(cloud, &launch(json!({"name": "Lab", "user": "labuser", "password": "eight chars"}))).unwrap();
        assert!(values.unwrap().hash.starts_with("$6$") && generated.is_none());
        for refused_body in [
            json!({"name": "Lab"}),
            json!({"name": "Lab", "user": "root", "generatePassword": true}),
            json!({"name": "Lab", "user": "labuser", "password": "short"}),
            json!({"name": "Lab", "user": "labuser", "password": "eight chars", "generatePassword": true}),
            json!({"name": "Lab", "user": "labuser", "generatePassword": true, "sshKey": "not a key"}),
        ] {
            assert!(first_boot_values(cloud, &launch(refused_body.clone())).is_err(), "{refused_body}");
        }
        assert!(first_boot_values(kali, &launch(json!({"name": "Kali"}))).unwrap().0.is_none());
        assert!(first_boot_values(kali, &launch(json!({"name": "Kali", "user": "labuser"}))).is_err());
        assert!(serde_json::from_value::<Launch>(json!({"name": "Lab", "path": "C:\\x"})).is_err());
    }
}
