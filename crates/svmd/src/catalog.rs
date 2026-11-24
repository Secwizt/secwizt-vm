use super::*;
use super::{catalog_http::official_destination, catalog_store as store, catalog_upstream as upstream};
use std::{collections::BTreeMap, sync::{Arc, LazyLock, Mutex, MutexGuard}, thread::JoinHandle};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ChecksumFormat { DebianSha512, FreebsdSha256, Sha256Sums }

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedChecksum {
    pub(super) format: ChecksumFormat,
    sums_url: String,
    signature_url: Option<String>,
    pub(super) fingerprint: String,
}

impl SignedChecksum {
    fn valid(&self, entry_hosts: &[String]) -> bool {
        let hosts = match self.format {
            ChecksumFormat::DebianSha512 => vec!["cdimage.debian.org".to_owned()],
            ChecksumFormat::FreebsdSha256 => vec!["www.freebsd.org".to_owned()],
            // A standard SHA256SUMS list sits next to the image on the publisher's own host.
            ChecksumFormat::Sha256Sums => entry_hosts.to_vec(),
        };
        self.fingerprint.len() == 40 && self.fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            && official_destination(&self.sums_url, &hosts)
            && match self.format {
                ChecksumFormat::DebianSha512 | ChecksumFormat::Sha256Sums => self.signature_url.as_deref()
                    .is_some_and(|url| official_destination(url, &hosts)),
                ChecksumFormat::FreebsdSha256 => self.signature_url.is_none(),
            }
    }
}

/// How a ready-to-run image is configured at its first start.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum FirstBoot {
    /// cloud-init reads the machine's private NoCloud settings volume.
    CloudInit,
    /// The publisher ships a public default login that the owner must change.
    DefaultLogin,
}

/// The one disk inside a publisher's archive.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ArchiveMember {
    pub(super) member: String,
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

/// A publisher's ready-made disk image: no operating-system installer runs.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ReadySpec {
    pub(super) publisher: String,
    pub(super) desktop: bool,
    pub(super) first_boot: FirstBoot,
    #[serde(default)]
    pub(super) default_user: Option<String>,
    #[serde(default)]
    pub(super) archive: Option<ArchiveMember>,
    /// The exact virtual size of the publisher's disk.
    pub(super) disk_bytes: u64,
    pub(super) note: String,
}

const MAX_READY_DISK: u64 = 256 << 30;

impl ReadySpec {
    fn valid(&self, entry: &Entry) -> bool {
        let name_ok = match &self.archive {
            Some(archive) => entry.file_name.ends_with(".7z")
                && svm_core::library::ordinary_file_name(&archive.member) && archive.member.ends_with(".qcow2")
                && archive.bytes > 0 && archive.bytes <= MAX_READY_DISK && lower_hex(&archive.sha256, 64),
            None => entry.file_name.ends_with(".qcow2") || entry.file_name.ends_with(".img"),
        };
        let login_ok = match self.first_boot {
            FirstBoot::CloudInit => self.default_user.is_none(),
            FirstBoot::DefaultLogin => self.default_user.as_deref().is_some_and(super::ready_seed::valid_user),
        };
        name_ok && login_ok
            && entry.engine == EngineKind::Qemu && entry.architecture == GuestArchitecture::X86_64
            && self.disk_bytes > 0 && self.disk_bytes <= MAX_READY_DISK
            && self.template_bytes(entry) >= self.disk_bytes && self.template_bytes(entry) <= MAX_READY_DISK
            && !self.publisher.trim().is_empty() && self.publisher.len() <= 80
            && !self.note.trim().is_empty() && self.note.len() <= 400
    }

    /// The virtual size of the prepared template. A cloud image grows its root file system at
    /// its first start, so its template is enlarged. Other images keep the publisher's size.
    pub(super) fn template_bytes(&self, entry: &Entry) -> u64 {
        match self.first_boot {
            FirstBoot::CloudInit => self.disk_bytes.max(u64::from(entry.disk_gb) << 30),
            FirstBoot::DefaultLogin => self.disk_bytes,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) edition: String,
    pub(super) architecture: GuestArchitecture,
    pub(super) engine: EngineKind,
    pub(super) vcpu: u16,
    pub(super) ram_gb: u32,
    pub(super) disk_gb: u32,
    pub(super) bytes: u64,
    pub(super) file_name: String,
    pub(super) sha256: String,
    pub(super) url: String,
    pub(super) archive_url: Option<String>,
    pub(super) official_hosts: Vec<String>,
    pub(super) signed_checksum: Option<SignedChecksum>,
    #[serde(default)]
    pub(super) ready: Option<ReadySpec>,
    #[serde(skip)]
    pub(super) upstream: Option<Arc<upstream::Release>>,
}

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CatalogProfile {
    #[serde(skip)]
    pub(super) os: String,
    pub(super) family: GuestFamily,
    pub(super) architecture: GuestArchitecture,
    pub(super) engine: EngineKind,
    pub(super) allowed_engines: Vec<EngineKind>,
    pub(super) vcpu: u16,
    pub(super) ram_gb: u32,
    pub(super) disk_gb: u32,
    pub(super) min_vcpu: u16,
    pub(super) min_ram_gb: u32,
    pub(super) min_disk_gb: u32,
    pub(super) tpm: bool,
    pub(super) secure_boot: bool,
    #[serde(default, skip_serializing)]
    pub(super) legacy_windows: bool,
}

impl Entry {
    pub(super) fn publisher_release(source: &upstream::Publisher, release: Arc<upstream::Release>) -> Option<Self> {
        Some(Self {
            id: release.id(), name: source.name.clone(), version: source.version(&release.file_name)?.to_owned(),
            edition: source.edition.clone(), architecture: GuestArchitecture::X86_64, engine: EngineKind::HyperV,
            vcpu: source.vcpu, ram_gb: source.ram_gb, disk_gb: source.disk_gb, bytes: release.bytes,
            file_name: release.file_name.clone(), sha256: release.sha256.clone(), url: release.url.clone(),
            archive_url: None, official_hosts: source.media_hosts.clone(), signed_checksum: None,
            ready: None, upstream: Some(release),
        })
    }

    pub(super) fn signature_required(&self) -> bool {
        self.upstream.is_some() || self.signed_checksum.is_some()
    }

    pub(super) fn profile(&self) -> CatalogProfile {
        let family = if self.upstream.is_some() { GuestFamily::Linux } else { family(&self.name) };
        let allowed_engines = match (self.architecture, family) {
            (GuestArchitecture::Aarch64, _) => vec![EngineKind::Qemu],
            (GuestArchitecture::X86_64, GuestFamily::Linux | GuestFamily::Bsd) => {
                vec![EngineKind::HyperV, EngineKind::Qemu]
            }
            _ => vec![self.engine],
        };
        CatalogProfile {
            os: format!("{} {}", self.name, self.version),
            family,
            architecture: self.architecture,
            engine: self.engine,
            allowed_engines,
            vcpu: self.vcpu,
            ram_gb: self.ram_gb,
            disk_gb: self.disk_gb,
            min_vcpu: 1,
            min_ram_gb: 1,
            min_disk_gb: 1,
            tpm: false,
            secure_boot: false,
            legacy_windows: false,
        }
    }

    fn summary(&self) -> Value {
        let profile = self.profile();
        let publisher_id = self.upstream.as_ref().map(|release| release.publisher_id());
        let publisher = publisher_id.and_then(upstream::publisher);
        let collection = publisher.map_or("Open source", |source| source.collection.as_str());
        json!({
            "id":self.id,"name":self.name,"version":self.version,"edition":self.edition,"collection":collection,
            "publisherId":publisher_id,"verification":if self.signature_required() {"Signed"} else {"Checksum"},
            "versionVerified":publisher.map(upstream::Publisher::signs_version_name),
            "architecture":profile.architecture,"engine":profile.engine,"family":profile.family,
            "allowedEngines":profile.allowed_engines,"tpm":profile.tpm,"secureBoot":profile.secure_boot,
            "vcpu":profile.vcpu,"ramGb":profile.ram_gb,"diskGb":profile.disk_gb,
            "bytes":self.bytes,"fileName":self.file_name,
            "sourceHost":self.official_hosts.first(),"signatureRequired":self.signature_required(),
        })
    }

    pub(super) fn valid(&self) -> bool {
        let media_ok = match &self.ready {
            None => self.file_name.ends_with(".iso"),
            Some(ready) => ready.valid(self),
        };
        valid_id(&self.id) && self.bytes > 0 && self.bytes <= 128 * 1024 * 1024 * 1024
            && media_ok && svm_core::library::ordinary_file_name(&self.file_name)
            && lower_hex(&self.sha256, 64)
            && official_destination(&self.url, &self.official_hosts)
            && self.archive_url.as_deref().is_none_or(|url| official_destination(url, &self.official_hosts))
            && self.signed_checksum.as_ref().is_none_or(|rule| rule.valid(&self.official_hosts))
            && self.profile().allowed_engines.contains(&self.engine)
            && self.vcpu > 0 && self.ram_gb > 0 && self.disk_gb > 0
    }
}

/// Ready-to-run images. They share the verified downloader with the installers but are listed,
/// prepared and launched by the ready-image routes, never by the installer wizard.
pub(super) fn ready_images() -> Result<&'static [Entry], ApiError> {
    static ENTRIES: LazyLock<Option<Vec<Entry>>> = LazyLock::new(|| {
        let entries: Vec<Entry> = serde_json::from_str(include_str!("../catalog/ready.json")).ok()?;
        let mut ids: std::collections::BTreeSet<&str> = catalog().ok()?.iter().map(|entry| entry.id.as_str()).collect();
        entries.iter().all(|entry| entry.ready.is_some() && entry.valid() && ids.insert(entry.id.as_str()))
            .then_some(entries)
    });
    ENTRIES.as_deref().ok_or_else(|| ApiError::new(500, "catalog_invalid", "The bundled ready-to-run images are invalid."))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64
        && id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(super) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn catalog() -> Result<&'static [Entry], ApiError> {
    static ENTRIES: LazyLock<Option<Vec<Entry>>> = LazyLock::new(|| {
        let entries: Vec<Entry> = serde_json::from_str(include_str!("../catalog/entries.json")).ok()?;
        let mut ids = std::collections::BTreeSet::new();
        entries.iter().all(|entry| entry.valid() && ids.insert(entry.id.as_str())).then_some(entries)
    });
    ENTRIES.as_deref().ok_or_else(|| ApiError::new(500, "catalog_invalid", "The bundled OS catalog is invalid."))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Reference {
    id: String,
    name: String,
    version: Option<String>,
    edition: Option<String>,
    collection: String,
    note: Option<String>,
    source_url: Option<String>,
    sha256: Option<String>,
    profile: Option<CatalogProfile>,
}

impl Reference {
    fn valid(&self) -> bool {
        valid_id(&self.id) && !self.name.trim().is_empty()
            && matches!(self.collection.as_str(), "Open source" | "Security" | "Windows")
            && self.source_url.as_deref().is_none_or(|source| {
                let host = url::Url::parse(source).ok()
                    .and_then(|url| url.domain().map(str::to_owned));
                host.is_some_and(|host| official_destination(source, &[host]))
            })
            && self.sha256.as_deref().is_none_or(|digest| {
                self.profile.is_some() && self.source_url.is_some() && lower_hex(digest, 64)
            })
            && self.profile.as_ref().is_none_or(|profile| {
                profile.min_vcpu > 0 && profile.min_vcpu <= profile.vcpu
                    && profile.min_ram_gb > 0 && profile.min_ram_gb <= profile.ram_gb
                    && profile.min_disk_gb > 0 && profile.min_disk_gb <= profile.disk_gb
                    && profile.allowed_engines.contains(&profile.engine)
                    && (!profile.legacy_windows || (profile.engine == EngineKind::Qemu
                        && profile.allowed_engines.as_slice() == [EngineKind::Qemu]
                        && profile.architecture == GuestArchitecture::X86_64
                        && profile.family == GuestFamily::Windows
                        && !profile.secure_boot && !profile.tpm))
            })
    }

    fn summary(&self) -> Value {
        let mut summary = json!({
            "id":self.id, "name":self.name, "version":self.version, "edition":self.edition,
            "collection":self.collection, "note":self.note, "sourceUrl":self.source_url,
            "localIso":self.profile.is_some(), "checksumRequired":self.sha256.is_some(),
        });
        if let Some(profile) = &self.profile {
            let settings = json!(profile);
            let fields = settings.as_object().expect("catalog profile is an object");
            summary.as_object_mut().expect("reference summary is an object").extend(fields.clone());
        }
        summary
    }
}

fn references() -> Result<&'static [Reference], ApiError> {
    static REFERENCES: LazyLock<Option<Vec<Reference>>> = LazyLock::new(|| {
        let mut rows: Vec<Reference> = serde_json::from_str(include_str!("../catalog/references.json")).ok()?;
        let windows: Vec<Reference> = serde_json::from_str(include_str!("../catalog/windows.json")).ok()?;
        rows.extend(windows);
        let mut ids: std::collections::BTreeSet<&str> = catalog().ok()?.iter()
            .map(|entry| entry.id.as_str()).collect();
        rows.iter().all(|reference| reference.valid() && ids.insert(reference.id.as_str()))
            .then_some(rows)
    });
    REFERENCES.as_deref().ok_or_else(|| ApiError::new(500, "catalog_invalid", "The bundled OS collections are invalid."))
}

#[derive(Clone)]
pub(super) enum Selection {
    Verified(Entry),
    Local(&'static Reference),
}

impl Selection {
    pub(super) fn profile(&self) -> CatalogProfile {
        match self {
            Self::Verified(entry) => entry.profile(),
            Self::Local(reference) => {
                let mut profile = reference.profile.as_ref().expect("local profile exists").clone();
                profile.os = match &reference.version {
                    Some(version) => format!("{} {}", reference.name, version),
                    None => reference.name.clone(),
                };
                profile
            }
        }
    }
}

pub(super) fn selection(id: &str) -> Result<Selection, ApiError> {
    if let Some(entry) = catalog()?.iter().find(|entry| entry.id == id) {
        return Ok(Selection::Verified(entry.clone()));
    }
    let reference = references()?.iter().find(|reference| reference.id == id)
        .ok_or_else(ApiError::missing)?;
    if reference.profile.is_none() {
        return Err(bad("This catalog entry provides publisher information."));
    }
    Ok(Selection::Local(reference))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Phase { Idle, Downloading, Cancelling, Verifying, Publishing, Paused, Verified, Failed }

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Status {
    pub(super) id: String,
    pub(super) state: Phase,
    pub(super) bytes: u64,
    pub(super) total_bytes: u64,
    pub(super) can_resume: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) signature_verified: Option<bool>,
}

impl Status {
    pub(super) fn idle(entry: &Entry) -> Self {
        Self { id: entry.id.clone(), state: Phase::Idle, bytes: 0, total_bytes: entry.bytes,
            can_resume: false, message: None, sha256: None, signature_verified: None }
    }

    fn cancel(&mut self) -> Result<(), ApiError> {
        match self.state {
            Phase::Downloading | Phase::Verifying => self.state = Phase::Cancelling,
            Phase::Cancelling => {}
            _ => return Err(refused("The download is already publishing or finished.")),
        }
        Ok(())
    }

    pub(super) fn progress(&mut self, bytes: u64) -> Result<(), store::Failure> {
        self.bytes = bytes;
        self.check_cancelled()
    }

    pub(super) fn check_cancelled(&self) -> Result<(), store::Failure> {
        if self.state == Phase::Cancelling { Err(store::Failure::Cancelled) } else { Ok(()) }
    }

    pub(super) fn publish(&mut self) -> Result<(), store::Failure> {
        self.check_cancelled()?;
        self.state = Phase::Publishing;
        Ok(())
    }

    pub(super) fn verify(&mut self, bytes: u64) -> Result<(), store::Failure> {
        self.progress(bytes)?;
        self.state = Phase::Verifying;
        Ok(())
    }
}

pub(super) fn lock_status(status: &Mutex<Status>) -> MutexGuard<'_, Status> {
    status.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Active { status: Arc<Mutex<Status>>, worker: JoinHandle<()> }

#[derive(Default)]
pub(super) struct Downloads {
    active: Option<Active>,
    recent: BTreeMap<String, Status>,
}

impl Downloads {
    pub(super) fn busy(&self) -> bool {
        self.active.as_ref().is_some_and(|active| !active.worker.is_finished())
    }

    fn reap(&mut self) {
        if self.busy() { return; }
        let Some(active) = self.active.take() else { return; };
        let failed = active.worker.join().is_err();
        let mut status = lock_status(&active.status).clone();
        if failed {
            status.state = Phase::Failed;
            status.message = Some("The installer download worker ended unexpectedly.".into());
        }
        self.recent.insert(status.id.clone(), status);
    }

    pub(super) fn status(&mut self, directory: &Path, entry: &Entry) -> Status {
        self.reap();
        if let Some(active) = &self.active {
            let status = lock_status(&active.status);
            if status.id == entry.id { return status.clone(); }
        }
        let mut current = store::observe(directory, entry);
        if current.state != Phase::Verified {
            if let Some(recent) = self.recent.get(&entry.id).filter(|recent| {
                matches!(recent.state, Phase::Failed | Phase::Paused)
            }) {
                current.state = recent.state;
                current.message = recent.message.clone();
            }
        }
        current
    }

    fn start(&mut self, directory: PathBuf, entry: Entry, mut status: Status) -> Result<Reply, ApiError> {
        self.reap();
        if self.active.is_some() { return Err(refused("Wait for the current installer download or cancel it first.")); }
        status.state = Phase::Downloading;
        status.message = None;
        let reply = Reply::json_status(202, json!(status));
        let status = Arc::new(Mutex::new(status));
        let shared = status.clone();
        let worker = std::thread::Builder::new().name("installer-download".into()).spawn(move || {
            let outcome = store::download(&directory, &entry, &shared);
            let mut result = store::observe(&directory, &entry);
            let mut current = lock_status(&shared);
            let outcome = current.check_cancelled().and(outcome);
            match outcome {
                Ok(()) if result.state == Phase::Verified => {}
                Ok(()) => {
                    result.state = Phase::Failed;
                    result.message = Some("The verified installer receipt could not be read.".into());
                }
                Err(store::Failure::Cancelled) => {
                    result.state = Phase::Paused;
                    result.message = Some("Download stopped before verification.".into());
                }
                Err(store::Failure::Failed(message)) => {
                    result.state = Phase::Failed;
                    result.message = Some(message);
                }
            }
            *current = result;
        }).map_err(io_error)?;
        self.active = Some(Active { status, worker });
        Ok(reply)
    }

    fn cancel(&mut self, id: &str) -> Result<Reply, ApiError> {
        self.reap();
        let active = self.active.as_ref().ok_or_else(|| refused("There is no active download to cancel."))?;
        let mut status = lock_status(&active.status);
        if status.id != id { return Err(refused("This installer has no active download.")); }
        status.cancel()?;
        Ok(Reply::json(json!(&*status)))
    }

    pub(super) fn shutdown(&mut self) {
        if let Some(active) = self.active.take() {
            let _ = lock_status(&active.status).cancel();
            let _ = active.worker.join();
        }
    }
}

impl Drop for Downloads {
    fn drop(&mut self) { self.shutdown(); }
}

impl Machines {
    pub(super) fn catalog_selection(&mut self, id: &str) -> Result<Selection, ApiError> {
        self.catalog_updates.reap(&self.library_dir);
        self.catalog_updates.entry(&self.library_dir, id).map(Selection::Verified).map_or_else(|| selection(id), Ok)
    }

    pub(super) fn open_catalog_installer(&self, choice: &Selection, supplied: Option<&Path>) -> Result<store::HeldInstaller, ApiError> {
        if self.catalog_busy() || self.converting() || self.file_transfer_busy() {
            return Err(refused("Finish the current installer or file transfer before creating a catalog VM."));
        }
        let result = match choice {
            Selection::Verified(entry) => store::verified_installer(&self.library_dir.join("installers"), entry),
            Selection::Local(reference) => store::local_installer(
                supplied.ok_or_else(|| bad("Choose a local ISO for this catalog profile."))?,
                reference.sha256.as_deref(),
            ),
        };
        result.map_err(|message| refused(&message))
    }

    pub(crate) fn catalog_busy(&self) -> bool { self.catalog_downloads.busy() || self.catalog_updates.busy() || self.pending_catalog_io }

    pub(crate) fn stop_catalog_downloads(&mut self) {
        self.catalog_downloads.shutdown();
        self.catalog_updates.stop();
    }

    pub(super) fn installer_free_bytes(&self) -> Option<u64> {
        if self.background_hyperv() { return None; }
        self.engine.capacity(&self.library_dir).ok().and_then(|value| value["freeBytes"].as_u64())
    }

    pub(crate) fn catalog_route(&mut self, method: &str, parts: &[&str], body: &Value) -> Result<Reply, ApiError> {
        let entries = catalog()?;
        let publishers = upstream::publishers().map_err(|message| ApiError::new(500,"catalog_invalid",&message))?;
        self.catalog_updates.reap(&self.library_dir);
        let base = self.library_dir.join("installers");
        let id = match (method, parts) {
            ("GET", ["catalog"]) => {
                let current = self.catalog_updates.entries();
                let summaries: Vec<_> = entries.iter().chain(&current).map(Entry::summary).collect();
                let transfers: Vec<_> = entries.iter().chain(&current).map(|entry| self.catalog_downloads.status(&base, entry)).collect();
                let references: Vec<_> = references()?.iter().filter(|reference| {
                    !publishers.iter().any(|publisher| publisher.reference_id == reference.id)
                }).map(Reference::summary).collect();
                let publishers: Vec<_> = publishers.iter().map(|publisher| self.catalog_updates.summary(publisher)).collect();
                return Ok(Reply::json(json!({"freeBytes":self.installer_free_bytes(),
                    "entries":summaries,"transfers":transfers,"references":references,"publishers":publishers})));
            }
            ("POST", ["catalog", id, "latest"]) => {
                if !body.as_object().is_some_and(|value| value.is_empty()) {
                    return Err(bad("Choose a bundled publisher without supplying a URL."));
                }
                let source = upstream::publisher(id).ok_or_else(ApiError::missing)?;
                if self.catalog_busy() || self.background_busy() || self.converting() || self.file_transfer_busy() {
                    return Err(refused("Wait for the current machine or installer operation to finish."));
                }
                let status = self.catalog_updates.start(&self.library_dir, source).map_err(|message| refused(&message))?;
                return Ok(Reply::json_status(202, status));
            }
            ("GET" | "POST" | "DELETE", ["catalog", id, "download"]) => *id,
            _ => return Err(ApiError::missing()),
        };
        let current = self.catalog_updates.entry(&self.library_dir, id);
        let entry = entries.iter().chain(ready_images()?).find(|entry| entry.id == id).or(current.as_ref())
            .ok_or_else(ApiError::missing)?;
        match method {
            "GET" => Ok(Reply::json(json!(self.catalog_downloads.status(&base, entry)))),
            "DELETE" if body.is_null() || body.as_object().is_some_and(|value| value.is_empty()) => {
                self.catalog_downloads.cancel(id)
            }
            "POST" if body.as_object().is_some_and(|value| value.is_empty()) => {
                if self.catalog_busy() || self.background_busy() || self.converting() || self.file_transfer_busy() {
                    return Err(refused("Wait for the current machine or transfer operation, or cancel it first."));
                }
                let status = self.catalog_downloads.status(&base, entry);
                if status.state == Phase::Verified { return Err(refused("This installer is already verified.")); }
                let free_bytes = self.installer_free_bytes()
                    .ok_or_else(|| refused("The service could not verify available installer storage."))?;
                if free_bytes < entry.bytes.saturating_sub(status.bytes) {
                    return Err(refused("The machine library does not have enough free space for this installer."));
                }
                self.catalog_downloads.start(base, entry.clone(), status)
            }
            _ => Err(bad("Choose a catalog installer without supplying a URL or destination.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_distinguishes_a_signed_image_from_a_signed_version_name() {
        for (id, file_name, expected) in [
            ("arch-linux", "archlinux-2026.11.01-x86_64.iso", false),
            ("security-onion", "securityonion-3.4.0-20261102.iso", false),
            ("ubuntu", "ubuntu-26.04.1-desktop-amd64.iso", true),
        ] {
            let publisher = upstream::publisher(id).unwrap();
            let release = serde_json::from_value(json!({
                "publisherId":id, "fileName":file_name, "url":"https://example.invalid/fixture.iso",
                "bytes":1024, "sha256":"a".repeat(64), "keyring":[], "manifest":[], "fallback":false
            })).unwrap();
            let summary = Entry::publisher_release(publisher, Arc::new(release)).unwrap().summary();
            assert_eq!(summary["versionVerified"], expected);
            assert_eq!(summary["verification"], "Signed");
        }
    }

    #[test]
    fn collections_keep_publisher_pins_and_local_media_profiles_separate() {
        let rows = references().expect("valid bundled collections");
        let legacy: Vec<_> = rows.iter().filter(|row| {
            row.profile.as_ref().is_some_and(|profile| profile.legacy_windows)
        }).collect();
        assert_eq!(legacy.len(), 4);
        assert!(legacy.iter().all(|row| row.source_url.is_none() && row.sha256.is_none()));
        for id in ["windows-10", "windows-11"] {
            let row = rows.iter().find(|row| row.id == id).expect("consumer Windows profile");
            assert!(row.sha256.as_deref().is_some_and(|digest| lower_hex(digest, 64)));
            assert!(row.profile.as_ref().is_some_and(|profile| {
                profile.engine == EngineKind::HyperV && profile.tpm && profile.secure_boot
            }));
        }
        assert!(matches!(selection("debian-13-7-amd64-netinst"), Ok(Selection::Verified(_))));
        assert!(matches!(selection("windows-xp"), Ok(Selection::Local(_))));
        let isolated = rows.iter().find(|row| row.name.contains("Metasploitable")).expect("isolated network guidance");
        assert_eq!(isolated.note.as_deref(), Some("Isolated network only"));
        assert!(isolated.profile.is_none() && isolated.source_url.is_none());
        assert!(selection(&isolated.id).is_err());
    }
}
