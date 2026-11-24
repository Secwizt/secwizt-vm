//! Owner-initiated encrypted backups. Normal reads only use the local snapshot index.
use super::*;
use serde::{Deserialize, Serialize};
use std::{fs::File, thread::JoinHandle, time::Instant};
use svm_qemu::LocalFolder;

#[path = "backup_tools.rs"]
mod tools;
pub use tools::console;
use tools::{ordinary, Launch, Operation, Paths, Settings};

fn snapshot_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn timestamp(text: &str) -> Option<time::OffsetDateTime> {
    if text.len() > 40 { return None; }
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).ok()
}
fn valid_time(text: &str) -> bool { timestamp(text).is_some() }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase")]
struct SnapshotRow { id: String, machine_id: String, time: String, #[serde(default)] bytes:Option<u64> }

fn parse_snapshots(bytes: &[u8]) -> Result<Vec<SnapshotRow>, ApiError> {
    #[derive(Deserialize)]
    struct Summary { total_bytes_processed: Option<u64> }
    #[derive(Deserialize)]
    struct Row { id: String, time: String, #[serde(default)] tags: Option<Vec<String>>, summary:Option<Summary> }
    let rows: Vec<Row> = serde_json::from_slice(bytes).map_err(|_| bad("Invalid restic snapshot list."))?;
    if rows.len() > 4096 { return Err(refused("The backup list exceeds 4096 snapshots.")); }
    let mut snapshots = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let tags = row.tags.unwrap_or_default();
        if !tags.iter().any(|t| t == "secwiz-vm") { continue; }
        let mut ids = tags.iter().filter_map(|t| t.strip_prefix("machine:"));
        let Some(machine) = ids.next() else { continue; }; // Manual whole-library backups have no machine tag.
        if !id_ok(machine) || ids.next().is_some() || !snapshot_id(&row.id) || !valid_time(&row.time)
            || !seen.insert(row.id.clone()) { return Err(bad("Invalid tagged backup metadata.")); }
        snapshots.push(SnapshotRow { id: row.id, time: row.time, machine_id: machine.to_owned(), bytes:row.summary.and_then(|summary|summary.total_bytes_processed) });
    }
    snapshots.sort_by_cached_key(|row|std::cmp::Reverse(timestamp(&row.time)));
    Ok(snapshots)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_requires_an_off_source_with_unchanged_length_and_write_time() {
        let initial=(1024,UNIX_EPOCH);
        let later=(1024,UNIX_EPOCH+std::time::Duration::from_secs(1));
        assert!(confirm_source(VmState::Off,initial,initial).is_ok());
        assert!(confirm_source(VmState::Running,initial,initial).is_err());
        assert!(confirm_source(VmState::Off,initial,(512,UNIX_EPOCH)).is_err());
        assert!(confirm_source(VmState::Off,initial,later).is_err());
    }
    fn source_fixture() -> Vm {
        serde_json::from_value(json!({"id":"fixture","name":"Fixture","os":"Linux","family":"linux","accel":true,
            "state":"off","vcpu":1,"ramGb":1,"net":"nat","ip":"192.0.2.10","mac":"02:00:00:00:00:10","dns":"fixture.test","diskGb":1})).unwrap()
    }
    #[test]
    fn backup_refuses_linked_checkpointed_and_tpm_sources() {
        let original=source_fixture();assert!(portable(&original).is_ok());
        let mut linked=original.clone();linked.linked_from=Some("template".into());
        let mut checkpoint=original.clone();checkpoint.snaps=1;
        let mut tpm=original;tpm.tpm=Some(true);
        for (vm,reason) in [(linked,"Linked"),(checkpoint,"checkpoints"),(tpm,"TPM")] {
            assert!(portable(&vm).unwrap_err().message.contains(reason));
        }
    }
    #[test]
    fn simulated_native_attachment_must_match_the_managed_disk() {
        let dir=std::env::temp_dir().join(next_id());fs::create_dir(&dir).unwrap();
        let native=dir.join("system.vhdx");let external=dir.join("external.vhdx");
        fs::write(&native,[]).unwrap();fs::write(&external,[]).unwrap();
        let engine=FakeEngine::default();let mut vm=source_fixture();
        let held=native.canonicalize().unwrap();assert!(engine.verify_backup_disk(&vm,&held).is_ok());
        vm.disk_path=Some(external.clone());assert!(engine.verify_backup_disk(&vm,&held).is_err());
        fs::remove_file(native).unwrap();fs::remove_file(external).unwrap();fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn snapshot_index_validates_tags_and_sorts_timezones() {
        let row = |id:&str,time:&str|json!({"id":id.repeat(64),"time":time,"tags":["secwiz-vm","machine:one"]});
        let first=row("a","2026-11-20T18:00:00+05:30");
        let last=row("b","2026-11-20T17:00:00Z");
        let parsed=parse_snapshots(&serde_json::to_vec(&[&first,&last]).unwrap()).unwrap();
        assert_eq!(parsed[0].id,"b".repeat(64));
        for invalid in [row("q","2026-11-20T17:00:00Z"),row("c","2026-33-90T17:00:00Z"),json!({
            "id":"d".repeat(64),"time":"2026-11-20T17:00:00Z","tags":["secwiz-vm","machine:one","machine:two"]})] {
            assert!(parse_snapshots(&serde_json::to_vec(&[invalid]).unwrap()).is_err());
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Catalog { settings: Settings, snapshots: Vec<SnapshotRow>, #[serde(default)] rejected:BTreeSet<String> }

#[derive(Serialize, Deserialize)]
struct Publication { id: String, legacy_windows: bool, #[serde(default)] phase:PublishPhase }
#[derive(Default,Clone,Copy,Serialize,Deserialize,PartialEq)]
enum PublishPhase { #[default] Prepared, Defining, Defined, Failed }

fn entry_exists(path:&Path)->Result<bool,ApiError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind()==io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(error)),
    }
}

struct Stage { path: PathBuf, journal: PathBuf }
impl Stage {
    fn id(&self) -> Result<&str,ApiError> {
        self.path.file_name().and_then(|s|s.to_str()).and_then(|s|s.strip_prefix(".svm-restore-")).filter(|id|id_ok(id)).ok_or_else(||refused("Invalid restore location."))
    }
    fn begin(library: &Path, id: &str) -> Result<Self, ApiError> {
        let root = LocalFolder::hold(library).map_err(engine)?;
        let journal = library.with_file_name("backup-restore.json");
        let name = format!(".svm-restore-{id}");
        if entry_exists(&journal)? || entry_exists(&root.path.join(&name))? {
            return Err(refused("The previous restore still needs cleanup."));
        }
        svm_core::write_json(&journal, id).map_err(store)?;
        let stage = Self { path: root.path.join(&name), journal };
        let prepared = (|| {
            let folder = root.create_private_child(&name).map_err(engine)?;
            fs::create_dir(folder.path.join("data")).map_err(io_error)?;
            File::create_new(folder.path.join("lease")).map_err(io_error)?;
            Ok(())
        })();
        if let Err(error) = prepared { stage.clean(library)?; return Err(error); }
        Ok(stage)
    }

    fn pending(library: &Path) -> Result<Option<(String,Self)>, ApiError> {
        let journal = library.with_file_name("backup-restore.json");
        if !entry_exists(&journal)? { return Ok(None); }
        let id: String = serde_json::from_slice(&tools::bounded(ordinary(&journal)?,256)?).map_err(|_| bad("Invalid restore receipt."))?;
        if !id.starts_with("vm-") || !id_ok(&id) { return Err(refused("Invalid restore receipt.")); }
        let root = LocalFolder::hold(library).map_err(engine)?;
        let path = root.path.join(format!(".svm-restore-{id}"));
        Ok(Some((id, Self { path, journal })))
    }

    fn clean(&self, library: &Path) -> Result<(), ApiError> {
        let root = LocalFolder::hold(library).map_err(engine)?;
        if self.path.parent() != Some(root.path.as_path()) { return Err(refused("Invalid restore location.")); }
        match fs::symlink_metadata(&self.path) {
            Ok(_) => {
                let held = LocalFolder::hold(&self.path).map_err(engine)?;
                let lease = self.path.join("lease");
                if lease.try_exists().map_err(io_error)? {
                    // Restic's inherited read handle denies deletion. Retire the name atomically so a late helper cannot acquire it.
                    fs::remove_file(lease).map_err(|_|refused("The restore console is still using its staging folder."))?;
                }
                drop(held);
                // The private, receipt-named child is below the held library. remove_dir_all does not follow links.
                fs::remove_dir_all(&self.path).map_err(io_error)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        }
        fs::remove_file(&self.journal).map_err(io_error)
    }
}

enum Work {
    Backup { id:String, disk:File, disk_len:u64, modified:SystemTime, _guard:Option<File>, _folder:LocalFolder },
    List,
    Restore { source: SnapshotRow, name: String, stage: Stage },
}
impl Work {
    fn kind(&self) -> &'static str { match self { Self::Backup{..}=>"backup", Self::List=>"list", Self::Restore{..}=>"restore" } }
    fn machine(&self) -> Option<&str> { match self { Self::Backup{id,..}=>Some(id), Self::Restore{source,..}=>Some(&source.machine_id), Self::List=>None } }
}
#[derive(Serialize,Deserialize)]
struct Lease { id: String, machine: Option<String>, #[serde(default)] kind:String, #[serde(default)] snapshot:Option<String> }
fn lease_path(home:&Path,id:&str)->Result<PathBuf,ApiError> {
    if !id.starts_with("vm-") || !id_ok(id) { return Err(refused("Invalid backup lease identifier.")); }
    Ok(home.join(format!(".backup-{id}.lock")))
}
impl Lease {
    fn begin(home:&Path,work:&Work)->Result<(Self,File),ApiError> {
        let snapshot=match work { Work::Restore{source,..}=>Some(source.id.clone()), _=>None };
        let lease=Self { id:next_id(),machine:work.machine().map(str::to_owned),kind:work.kind().into(),snapshot };
        let file=lease_path(home,&lease.id)?;
        let record=home.join("backup-owner.json");
        if entry_exists(&record)? { return Err(refused("Wait for the previous backup console to finish.")); }
        svm_core::write_json(&record,&lease).map_err(store)?;
        File::create_new(&file).map_err(io_error)?;
        Ok((lease,ordinary(&file)?))
    }
    fn read(home:&Path)->Result<Option<Self>,ApiError> {
        let record=home.join("backup-owner.json");
        if !entry_exists(&record)? {return Ok(None);}
        serde_json::from_slice(&tools::bounded(ordinary(&record)?,512)?).map(Some).map_err(|_|refused("Invalid backup owner receipt."))
    }
    fn retire(&self,home:&Path)->Result<(),ApiError> {
        match fs::remove_file(lease_path(home,&self.id)?) {
            Ok(())=>{}, Err(e) if e.kind()==io::ErrorKind::NotFound=>{},
            Err(_)=>return Err(refused("The previous backup console is still active.")),
        }
        fs::remove_file(home.join("backup-owner.json")).map_err(io_error)
    }
}

struct Prepared { vm: Vm, bytes: u64, legacy_windows: bool }
struct WorkerResult { output: Result<tools::ToolResult, ApiError>, prepared: Option<Result<Prepared,ApiError>> }
struct Job { _lease: File, work: Work, start: Instant, worker: JoinHandle<WorkerResult> }
pub(super) struct Backups { pub(super) incomplete: BTreeSet<String>, helper: Option<(PathBuf,LocalFolder,File)>, current: Option<Job>, last: Value, orphan: Option<Lease>, retry_at: Option<Instant>, prompt_after: Option<Instant>, blocked_receipt:Option<&'static str> }
impl Backups {
    pub(super) fn forget(&mut self, id: &str) {
        self.incomplete.remove(id);
        if self.last["newId"] == id && self.last["state"] == "pending" {
            self.last["state"] = json!("failed");
            self.last["message"] = json!("The incomplete copy was moved to library trash.");
        }
    }

    pub(super) fn new(helper: &Path) -> Self {
        // In production this is current_exe. Pin its directory and running image at service startup.
        let held = helper.canonicalize().ok().and_then(|file| {
            let dir = LocalFolder::hold(file.parent()?).ok()?;
            let handle = ordinary(&file).ok()?;
            Some((file,dir,handle))
        });
        Self { incomplete: BTreeSet::new(), helper: held, current: None, last: Value::Null, orphan: None, retry_at:None, prompt_after:None, blocked_receipt:None }
    }
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct BackupRequest { machine_id: String }
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct RestoreRequest { snapshot_id: String, name: String }

fn load_catalog(home: &Path) -> Result<Option<Catalog>, ApiError> {
    let path = home.join("backup-settings.json");
    if !entry_exists(&path)? { return Ok(None); }
    serde_json::from_slice(&tools::bounded(ordinary(&path)?, 2*1024*1024)?)
        .map(Some).map_err(|_| refused("The saved backup settings could not be read."))
}

impl Machines {
    fn backup_catalog_file(&self) -> PathBuf { self.library_dir.with_file_name("backup-settings.json") }
    fn backup_catalog(&self) -> Result<Option<Catalog>, ApiError> {
        load_catalog(self.library_dir.parent().expect("library has a parent"))
    }
    pub(super) fn cleanup_backup_tools(&self, events: &mut Events) -> Result<(),ApiError> {
        // An unreadable catalog may still name the active copy. Preserve it until the owner repairs it.
        if let Ok(catalog) = self.backup_catalog() {
            let home = self.library_dir.parent().expect("library has a parent");
            if tools::prune_tool_copies(home, catalog.as_ref().map(|c| &c.settings)).is_err() {
                events.record("backup tools cleanup pending", "An unused backup tools folder is still in use.")?;
            }
        }
        Ok(())
    }
    pub(super) fn inspect_restore_marker(&mut self, id: &str, bundle: &Path) {
        if entry_exists(&bundle.join("backup-publishing.json")).unwrap_or(true) {
            self.backups.incomplete.insert(id.to_owned());
        }
    }
    fn recovery_status(&mut self, id: &str, state: &str, message: Option<String>) {
        if self.backups.last["newId"].as_str() != Some(id) {
            self.backups.last = json!({"kind":"restore","newId":id});
        }
        self.backups.last["state"] = json!(state);
        self.backups.last["message"] = json!(message);
    }
    fn reconcile_restore(&mut self, events: &mut Events) -> Result<(),ApiError> {
        let Some((id, stage)) = Stage::pending(&self.library_dir).map_err(|_|refused("Inspect backup-restore.json in the service data folder before retrying recovery."))? else { return Ok(()); };
        if let Ok(vm) = self.vm(&id) {
            let bundle = self.library.bundle_path(&id).map_err(store)?;
            let pending = bundle.join("backup-publishing.json");
            if entry_exists(&pending)? {
                let owner: Publication = serde_json::from_slice(&tools::bounded(ordinary(&pending)?,256)?).map_err(|_|bad("Invalid restore receipt."))?;
                if owner.id != id { return Err(refused("The restore receipt does not identify its machine.")); }
                let state = self.driver_mut(vm.engine)?.state(&id);
                let finished = match (owner.phase,state) {
                    (PublishPhase::Defined,Ok(_)) => {
                        if fs::remove_file(&pending).is_err() {
                            self.recovery_status(&id,"pending",Some("Registration finished. Waiting to clear the restore marker.".into()));
                            return Err(refused("The restore marker is still in use."));
                        }
                        Ok(())
                    }
                    (PublishPhase::Prepared,Err(EngineError::Missing(_))) => {
                        let file = ordinary(&bundle.join(disk_name(vm.engine)?))?;
                        let bytes = svm_qemu::backup_disk_size(&file, vm.engine).map_err(engine)?;
                        drop(file);
                        self.define_publication(&vm,&bundle,bytes,owner,events)
                    }
                    _ => Err(refused(format!("Restore registration is unconfirmed for {id}. Inspect its bundle and engine registration."))),
                };
                match finished {
                    Ok(()) => {
                        // Recovering Prepared can finish the definition while the marker is still locked.
                        if entry_exists(&pending)? {
                            self.recovery_status(&id,"pending",Some("Registration finished. Waiting to clear the restore marker.".into()));
                            return Err(refused("The restore marker is still in use."));
                        }
                        self.backups.incomplete.remove(&id);
                        self.recovery_status(&id,"completed",None);
                        events.record("restored", &id)?;
                    }
                    Err(error) => {
                        events.record("restore failed", &id)?;
                        self.recovery_status(&id,"failed",Some(error.message));
                    }
                }
            }
        }
        stage.clean(&self.library_dir)
    }
    pub(super) fn recover_backup(&mut self, events: &mut Events) -> Result<(), ApiError> {
        let home = self.library_dir.parent().expect("library has a parent");
        self.backups.blocked_receipt = None;
        self.backups.orphan = match Lease::read(home) {
            Ok(owner) => owner,
            Err(_) => {
                self.backups.blocked_receipt = Some("backup-owner.json");
                if self.backups.retry_at.is_none() { events.record("backup cleanup pending","")?; }
                self.backups.retry_at=Some(Instant::now()+std::time::Duration::from_secs(3));
                return Ok(());
            }
        };
        let pending = self.backups.orphan.as_ref().is_some_and(|owner| owner.retire(home).is_err());
        if !pending { self.backups.orphan = None; }
        if Stage::pending(&self.library_dir).is_err() { self.backups.blocked_receipt = Some("backup-restore.json"); }
        if self.backups.blocked_receipt.is_some() || pending || self.reconcile_restore(events).is_err() {
            if self.backups.retry_at.is_none() { events.record("backup cleanup pending","")?; }
            self.backups.retry_at = Some(Instant::now()+std::time::Duration::from_secs(3));
        } else { self.backups.retry_at = None; }
        Ok(())
    }
    pub(super) fn guard_backup_request(&self, method: &str, parts: &[&str]) -> Result<(), ApiError> {
        if let ["machines", id, ..] = parts {
            if method != "GET" && !(method == "DELETE" && parts.len() == 2) && self.backups.incomplete.contains(*id) {
                return Err(refused("Restore incomplete. Move this copy to trash and retry the backup restore."));
            }
        }
        if method == "PUT" && parts == ["settings","backup"] && self.backups.last["state"] == "pending" {
            return Err(refused("Wait for restore registration cleanup before changing backup settings."));
        }
        if let Some(file) = self.backups.blocked_receipt {
            if method != "GET" && matches!(parts,["backups" | "transfers" | "shutdown", ..] | ["settings","backup"]) {
                return Err(refused(format!("Wait for any backup console to close, then inspect and remove the unreadable {file} in the service data folder.")));
            }
        }
        let machine = if let Some(job) = &self.backups.current { job.work.machine() }
            else if let Some(owner) = &self.backups.orphan { owner.machine.as_deref() }
            else { return Ok(()); };
        if method != "GET" && (matches!(parts, ["backups" | "transfers" | "shutdown", ..] | ["settings","backup"] | ["ready", _, "prepare" | "launch"])
            || matches!(parts, ["machines", id, ..] if machine==Some(*id))) {
            return Err(refused("Wait for the current backup operation to finish."));
        }
        Ok(())
    }

    pub(crate) fn backup_route(&mut self, method: &str, parts: &[&str], filter: Option<&str>, body: &Value,
        events: &mut Events) -> Result<Reply, ApiError> {
        self.guard_backup_request(method, parts)?;
        if method == "PUT" && parts == ["settings","backup"] {
            let paths: Paths = parsed(body)?;
            let settings = Settings::select(paths, self.library_dir.parent().ok_or_else(||bad("Missing service home."))?)?;
            let previous = self.backup_catalog()?.filter(|old|old.settings.paths.repository==settings.paths.repository);
            let (snapshots,rejected) = previous.map(|old|(old.snapshots,old.rejected)).unwrap_or_default();
            let saved = Catalog { settings, snapshots, rejected };
            svm_core::write_json(&self.backup_catalog_file(), &saved).map_err(store)?;
            self.backups.last = Value::Null;
            self.cleanup_backup_tools(events)?;
            return Ok(Reply::json(saved.settings.details()));
        }
        let catalog = self.backup_catalog()?;
        if method == "GET" && parts == ["settings","backup"] {
            return Ok(Reply::json(catalog.map(|c|c.settings.details()).unwrap_or_else(||json!({"configured":false,"paths":null,"hashes":{}}))));
        }
        if method == "GET" && parts == ["backups"] {
            let machine = filter.map(|s| s.strip_prefix("machineId=").filter(|id| id_ok(id)).ok_or_else(||bad("Invalid machine filter."))).transpose()?;
            let rows: Vec<_> = catalog.as_ref().into_iter().flat_map(|c| &c.snapshots)
                .filter(|r| machine.is_none_or(|id| id == r.machine_id)).collect();
            let throwaway_pending = machine.and_then(|id|self.vm(id).ok()).is_some_and(|vm|self.throwaway_pending(&vm));
            let current = self.backups.current.as_ref().map(|j|json!({"kind":j.work.kind(),"machineId":j.work.machine(),"seconds":j.start.elapsed().as_secs()}))
                .or_else(||self.backups.orphan.as_ref().map(|owner|json!({"kind":"previous console","machineId":owner.machine,"seconds":null})));
            let remaining = self.backups.prompt_after.map(|after|after.saturating_duration_since(Instant::now()).as_millis().div_ceil(1000)).unwrap_or(0);
            return Ok(Reply::json(json!({"cooldownSeconds":remaining as u64,"unreadableReceipt":self.backups.blocked_receipt,"configured":catalog.is_some(),"snapshots":rows,"throwawayPending":throwaway_pending,"current":current,"last":self.backups.last})));
        }
        if method != "POST" || !matches!(parts, ["backups"] | ["backups","restore"|"refresh"]) { return Err(ApiError::missing()); }
        let catalog = catalog.ok_or_else(||refused("Configure encrypted backups in Settings first."))?;
        if self.backups.prompt_after.is_some_and(|after|Instant::now()<after) {
            return Err(refused("Wait five seconds after a failed or cancelled operation before opening the key prompt again."));
        }
        if self.converting() || self.file_transfer_busy() || self.background_busy() || self.catalog_busy() {
            return Err(refused("Finish the current disk, checkpoint or transfer task first."));
        }
        self.reconcile_restore(events)?;
        let helper = self.backups.helper.as_ref().ok_or_else(||refused("The running service executable could not be verified for the owner console."))?.0.clone();
        let (work, op) = match parts {
            ["backups"] => {
                let req: BackupRequest = parsed(body)?;
                self.refresh_after(events,Some(&req.machine_id),None)?;
                let vm = self.vm(&req.machine_id)?;
                self.available(&vm.id)?;
                self.require_recovered(&vm)?;
                portable(&vm)?;
                if !self.driver_mut(vm.engine)?.list_snapshots(&vm.id).map_err(engine)?.is_empty() { return Err(refused("Merge the machine's checkpoints before backing up.")); }
                let bundle = LocalFolder::hold(&self.library.bundle_path(&vm.id).map_err(store)?).map_err(engine)?;
                let filename = disk_name(vm.engine)?;
                let disk = ordinary(&bundle.path.join(filename))?;
                let guard = if vm.engine == EngineKind::Qemu {
                    Some(self.qemu.guard_hardware_change(&vm).map_err(engine)?)
                } else { self.engine.verify_backup_disk(&vm, &bundle.path.join(filename)).map_err(engine)?; None };
                svm_qemu::backup_disk_size(&disk, vm.engine).map_err(engine)?;
                let op = Operation::Backup { machine: vm.id.clone(), disk: filename.into() };
                let meta = disk.metadata().map_err(io_error)?;
                (Work::Backup { id:vm.id, disk, disk_len:meta.len(), modified:meta.modified().map_err(io_error)?, _guard:guard, _folder:bundle }, op)
            }
            ["backups","refresh"] => {
                if !body.as_object().is_some_and(|o| o.is_empty()) { return Err(bad("No options are required to list backups.")); }
                (Work::List, Operation::List)
            }
            ["backups","restore"] => {
                let req: RestoreRequest = parsed(body)?;
                let source = catalog.snapshots.into_iter().find(|r| r.id == req.snapshot_id && snapshot_id(&r.id))
                    .ok_or_else(||refused("Refresh the backup list and choose a tagged snapshot."))?;
                let free = self.library_capacity()?["freeBytes"].as_u64().ok_or_else(||refused("The free space on the library drive could not be measured."))?;
                check_restore_space(source.bytes,free)?;
                let mut id = next_id();
                if id == source.machine_id { id = next_id(); }
                self.ensure_identity(&id, &req.name)?;
                let stage = Stage::begin(&self.library_dir, &id)?;
                let op = Operation::Restore { snapshot: source.id.clone() };
                (Work::Restore { source, name:req.name, stage }, op)
            }
            _ => unreachable!(),
        };
        let home=self.library_dir.parent().expect("library has a parent").to_owned();
        let (lease,handle)=match Lease::begin(&home,&work) {
            Ok(pair)=>pair, Err(error)=>{self.recover_backup(events)?;return Err(error);}
        };
        let launch = Launch { lease_id:lease.id.clone(), op };
        let kind = work.kind();
        let machine = work.machine().unwrap_or("").to_owned();
        let restore_source = match &work {
            Work::Restore{source,stage,..} => Some((source.machine_id.clone(),stage.path.clone(),source.bytes.unwrap_or(0))),
            _ => None,
        };
        let spawned = std::thread::Builder::new().name("encrypted-backup".into()).spawn(move || {
            let output = tools::execute(&helper, &home, &launch);
            let prepared = restore_source.filter(|_| output.as_ref().is_ok_and(|v|v.exit_code == Some(0)))
                .map(|(source,path,bytes)|prepare_restore(&path,&source,bytes));
            WorkerResult {output,prepared}
        });
        let worker = match spawned {
            Ok(worker) => worker,
            Err(e) => { drop(handle); self.recover_backup(events)?; return Err(io_error(e)); }
        };
        self.backups.current = Some(Job { _lease:handle, work, worker, start:Instant::now() });
        events.record(&format!("{kind} started"), &machine)?;
        Ok(Reply::json_status(202,json!({"kind":kind,"state":"running","machineId":machine})))
    }

    pub(crate) fn finish_backup(&mut self, networks: &[Network], events: &mut Events) -> Result<bool,ApiError> {
        if self.backups.current.is_none() {
            if self.backups.retry_at.is_some_and(|time|time<=Instant::now()) { self.recover_backup(events)?; }
            return Ok(false);
        }
        if !self.backups.current.as_ref().is_some_and(|j|j.worker.is_finished()) || self.background_hyperv() { return Ok(false); }
        let job = self.backups.current.take().unwrap();
        drop(job._lease);
        let kind = job.work.kind();
        let machine = job.work.machine().unwrap_or("").to_owned();
        let WorkerResult { output:result, prepared } = job.worker.join().unwrap_or_else(|_| WorkerResult { output:Err(refused("The backup console closed unexpectedly.")), prepared:None });
        let exit_code = result.as_ref().ok().and_then(|v|v.exit_code);
        let reason = result.as_ref().ok().and_then(|v|v.reason);
        let partial = if kind=="backup" && exit_code.is_some_and(|code|code!=0) {
            result.as_ref().ok().and_then(|v|v.result["id"].as_str()).filter(|s|snapshot_id(s)).map(str::to_owned)
        } else { None };
        if let Some(id) = &partial { self.reject_snapshot(id)?; }
        let result = result.and_then(|v| if exit_code == Some(0) {
            Ok(v.result)
        } else { Err(refused(reason.unwrap_or(tools::Failure::Unknown).message(kind == "restore"))) });
        let mut snapshot = partial.unwrap_or_default();
        let mut attempted = None;
        let done = match job.work {
            Work::List => result.and_then(|v| {
                let rows = serde_json::from_value(v).map_err(|_|bad("Invalid snapshot list."))?;
                self.save_snapshot_rows(rows)?;
                Ok(Value::Null)
            }),
            Work::Backup{id,disk,disk_len,modified,..} => result.and_then(|v| {
                snapshot = v["id"].as_str().filter(|s|snapshot_id(s)).ok_or_else(||bad("Missing snapshot identifier."))?.into();
                let time = v["time"].as_str().filter(|s|valid_time(s)).ok_or_else(||bad("Missing backup time."))?;
                let catalog = self.backup_catalog()?.ok_or_else(||bad("Missing backup settings."))?;
                let confirmed = (|| {
                    let vm = self.vm(&id)?;
                    let state = self.driver_mut(vm.engine)?.state(&id).map_err(engine)?;
                    let after = disk.metadata().map_err(io_error)?;
                    confirm_source(state, (disk_len,modified), (after.len(),after.modified().map_err(io_error)?))
                })();
                if let Err(error) = confirmed {
                    self.reject_snapshot(&snapshot)?;
                    return Err(error);
                }
                let mut rows = catalog.snapshots;
                rows.retain(|r|r.id != snapshot);
                rows.insert(0,SnapshotRow{id:snapshot.clone(),machine_id:id,time:time.into(),bytes:v["bytes"].as_u64()});
                rows.truncate(4096);
                self.save_snapshot_rows(rows)?;
                Ok(Value::Null)
            }),
            Work::Restore{source,name,stage} => {
                snapshot = source.id;
                let restored = result.and_then(|_|prepared.ok_or_else(||refused("Missing prepared disk."))?)
                    .and_then(|disk|{
                        attempted=Some(stage.id()?.to_owned());
                        self.publish_backup(&stage, disk, &name, networks, events)
                    });
                if restored.is_err() && stage.clean(&self.library_dir).is_err() {
                    events.record("backup cleanup pending",&source.machine_id)?;
                }
                restored
            }
        };
        self.recover_backup(events)?;
        if done.is_err() { self.backups.prompt_after = Some(Instant::now()+std::time::Duration::from_secs(5)); }
        let new_id = done.as_ref().ok().and_then(|v|v.as_str()).or(attempted.as_deref());
        let event_id = new_id.unwrap_or(&machine);
        let awaiting_marker = kind == "restore" && done.is_ok() && new_id.is_some_and(|id| self.backups.incomplete.contains(id));
        let recovery_state = self.backups.last["state"].as_str().filter(|_| self.backups.last["newId"].as_str() == new_id);
        let state = if done.is_err() || (awaiting_marker && recovery_state == Some("failed")) { "failed" }
            else if awaiting_marker { "pending" } else { "completed" };
        let message = if awaiting_marker {
            recovery_state.and_then(|_|self.backups.last["message"].as_str()).map(str::to_owned)
                .or_else(|| Some("Waiting to verify the restore marker.".into()))
        } else { done.as_ref().err().map(|e|e.message.clone()) };
        let event = if state == "pending" { "restore cleanup pending".into() } else if state == "failed" { format!("{kind} failed") } else if kind=="restore" { "restored".into() } else { format!("{kind} finished") };
        events.record(&event, format!("{event_id} {snapshot}").trim())?;
        self.backups.last = json!({"kind":kind,"machineId":machine,"snapshotId":snapshot,"newId":new_id,
            "seconds":job.start.elapsed().as_secs(),"exitCode":exit_code,"reason":reason,"state":state,"message":message});
        Ok(kind=="restore")
    }
    fn reject_snapshot(&self,id:&str)->Result<(),ApiError> {
        let mut catalog=self.backup_catalog()?.ok_or_else(||bad("Missing backup settings."))?;
        catalog.snapshots.retain(|row|row.id!=id);
        catalog.rejected.insert(id.into());
        svm_core::write_json(&self.backup_catalog_file(),&catalog).map_err(store)
    }
    fn save_snapshot_rows(&self, snapshots: Vec<SnapshotRow>) -> Result<(),ApiError> {
        let mut catalog = self.backup_catalog()?.ok_or_else(||bad("Missing backup settings."))?;
        catalog.snapshots = snapshots.into_iter().filter(|row|!catalog.rejected.contains(&row.id)).collect();
        svm_core::write_json(&self.backup_catalog_file(),&catalog).map_err(store)
    }
}

fn confirm_source(state:VmState, before:(u64,SystemTime), after:(u64,SystemTime))->Result<(),ApiError> {
    if state!=VmState::Off || before!=after {return Err(refused("The source power state or disk changed during the backup."));}
    Ok(())
}

fn check_restore_space(bytes:Option<u64>,free:u64)->Result<(),ApiError> {
    let size=bytes.filter(|n|*n>0).ok_or_else(||refused("The snapshot has no size estimate. Refresh the backup list or create a new backup."))?;
    let required=size.checked_mul(2).and_then(|n|n.checked_add(256<<20));
    if required.is_none_or(|n|free<n) { return Err(refused("Restore requires twice the snapshot size plus 256 MiB free on the library drive.")); }
    Ok(())
}

fn prepare_restore(stage: &Path, source: &str, max_bytes:u64) -> Result<Prepared,ApiError> {
        let folder = LocalFolder::hold(stage).map_err(engine)?;
        let _lease = ordinary(&folder.path.join("lease"))?;
        let data = LocalFolder::hold(&folder.path.join("data")).map_err(engine)?;
        let mut files = BTreeMap::new();
        let mut total = 0u64;
        for entry in fs::read_dir(&data.path).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name().into_string().map_err(|_|bad("Unexpected restore filename."))?;
            if !matches!(name.as_str(),"vm.json"|"system.qcow2"|"system.vhdx"|"uefi-vars.fd"|"qemu-vm.json") {
                return Err(refused("The snapshot contains an unexpected restore file."));
            }
            let file = ordinary(&entry.path())?;
            total = total.checked_add(file.metadata().map_err(io_error)?.len()).filter(|n|*n<=max_bytes)
                .ok_or_else(||refused("The restored data exceeds the recorded snapshot size."))?;
            files.insert(name,file);
        }
        let invalid = || refused("The backup does not contain a complete standalone machine.");
        let mut vm: Vm = serde_json::from_slice(&tools::bounded(files.remove("vm.json").ok_or_else(invalid)?,65536)?)
            .map_err(|_|invalid())?;
        if vm.id != source { return Err(refused("The backup definition does not match the machine tag.")); }
        portable(&vm)?;
        let arm = vm.architecture == GuestArchitecture::Aarch64;
        let disk = disk_name(vm.engine)?;
        let mut image = files.remove(disk).ok_or_else(invalid)?;
        let bytes = svm_qemu::backup_disk_size(&image,vm.engine).map_err(engine)?;
        let vars = files.remove("uefi-vars.fd");
        let legacy_windows = if vm.engine == EngineKind::Qemu {
            #[derive(Deserialize)]
            struct Profile { id: String, #[serde(default)] legacy_windows: bool }
            let profile: Profile = serde_json::from_slice(&tools::bounded(files.remove("qemu-vm.json").ok_or_else(invalid)?,65536)?).map_err(|_|invalid())?;
            if profile.id != vm.id { return Err(invalid()); }
            if profile.legacy_windows { svm_qemu::validate_legacy_windows_profile(vm.architecture,vm.family,vm.vcpu,vm.ram_gb).map_err(engine)?; }
            profile.legacy_windows
        } else { false };
        if let Some(file) = &vars { if file.metadata().map_err(io_error)?.len() > 128 << 20 { return Err(invalid()); } }
        if !files.is_empty() || arm != vars.is_some() || (arm && vm.engine != EngineKind::Qemu) { return Err(invalid()); }
        if vm.vcpu == 0 || vm.ram_gb == 0 || vm.os.trim().is_empty() || vm.os.len() > 180 { return Err(invalid()); }
        if vm.engine == EngineKind::Qemu {
            svm_qemu::validate_profile(vm.architecture,vm.family,!arm,vm.vcpu,vm.ram_gb).map_err(engine)?;
        }
        vm.cores.clear(); vm.port_forwards.clear(); vm.share_clipboard = false; vm.throwaway = false;
        vm.template = None; vm.iso_path = None; vm.accel = !arm;
        if arm {
            if vm.disk_gb.is_none_or(|n| u64::from(n)<<30 != bytes) { return Err(invalid()); }
            vm.disk_path = None;
        } else {
            vm.disk_gb = None; vm.disk_path = Some(disk.into());
        }
        let prepared = folder.create_private_child("prepared").map_err(engine)?;
        // Copy unnamed data streams into new private files. Do not adopt snapshot ACLs, alternate streams or hard links.
        use std::io::Seek;
        image.rewind().map_err(io_error)?;
        copy_private(&mut image, &prepared.path.join(disk))?;
        if let Some(mut vars) = vars { copy_private(&mut vars,&prepared.path.join("uefi-vars.fd"))?; }
        if vm.engine == EngineKind::HyperV { svm_core::write_json(&prepared.path.join("boot-order.json"),"disk").map_err(store)?; }
        Ok(Prepared { vm, bytes, legacy_windows })
}
impl Machines {
    fn publish_backup(&mut self, stage: &Stage, prepared: Prepared, name: &str, networks: &[Network], events: &mut Events) -> Result<Value,ApiError> {
        let Prepared { mut vm, bytes, legacy_windows } = prepared;
        let id = stage.id()?;
        self.ensure_identity(id,name)?;
        let network_id = if vm.engine == EngineKind::Qemu { "nat" } else { vm.net.as_str() };
        let net = network(networks,network_id).map_err(|_|refused("The original Hyper-V network is unavailable. Restore it before restoring this machine."))?;
        let mut reserved = self.held_identities()?;
        // The source can still be on the network even if it is absent from this library.
        reserved.push(vm.clone());
        let identity = identity::allocate(id, name, net, &reserved).map_err(store)?;
        vm.id = id.to_owned(); vm.name = name.to_owned();
        vm.net = net.id.clone(); vm.mac = identity.mac; vm.ip = identity.ip; vm.dns = identity.dns;
        let prepared = LocalFolder::hold(&stage.path.join("prepared")).map_err(engine)?;
        let receipt = Publication {id:id.into(),legacy_windows,phase:PublishPhase::Prepared};
        svm_core::write_json(&prepared.path.join("backup-publishing.json"), &receipt).map_err(store)?;
        drop(prepared);
        let bundle = self.library.publish_backup(&vm).map_err(store)?;
        self.inventory.push(vm.clone());
        self.backups.incomplete.insert(id.into());
        if self.driver_mut(vm.engine)?.register(id,&bundle).is_err() {
            return Err(refused(format!("The restored bundle {id} was published but registration failed. Inspect it before use.")));
        }
        self.define_publication(&vm,&bundle,bytes,receipt,events)?;
        Ok(json!(id))
    }

    fn define_publication(&mut self, vm:&Vm,bundle:&Path,bytes:u64,mut receipt:Publication,events:&mut Events)->Result<(),ApiError> {
        let marker = bundle.join("backup-publishing.json");
        receipt.phase=PublishPhase::Defining;
        svm_core::write_json(&marker,&receipt).map_err(store)?;
        if self.define_staged_with_disk(vm,events,Some(bytes),receipt.legacy_windows).is_err() {
            if !bundle.try_exists().map_err(io_error)? {
                return Err(refused(format!("Registration failed for {}. The disk copy for {} is in library trash.",vm.id,vm.name)));
            }
            receipt.phase=PublishPhase::Failed;
            svm_core::write_json(&marker,&receipt).map_err(store)?;
            return Err(refused(format!("Registration failed for {}. Inspect its retained bundle and engine registration.",vm.id)));
        }
        receipt.phase=PublishPhase::Defined;
        svm_core::write_json(&marker,&receipt).map_err(store)?;
        // The durable Defined receipt proves registration finished. A sharing violation only delays availability.
        if fs::remove_file(marker).is_ok() { self.backups.incomplete.remove(&vm.id); }
        Ok(())
    }
}

fn copy_private(input: &mut File, target: &Path) -> Result<(),ApiError> {
    let mut output = File::create_new(target).map_err(io_error)?;
    std::io::copy(input,&mut output).map_err(io_error)?;
    output.sync_all().map_err(io_error)
}

fn disk_name(kind: EngineKind) -> Result<&'static str,ApiError> {
    match kind { EngineKind::Qemu=>Ok("system.qcow2"), EngineKind::HyperV=>Ok("system.vhdx"), _=>Err(refused("Backups require a QEMU or Hyper-V machine.")) }
}
fn portable(vm: &Vm) -> Result<(),ApiError> {
    disk_name(vm.engine)?;
    if vm.state != VmState::Off { return Err(refused("Power off the machine before backing it up.")); }
    if vm.linked_from.is_some() { return Err(refused("Linked clones depend on their template. Back up the template or make a full clone first.")); }
    if vm.snaps != 0 { return Err(refused("Merge the checkpoints into a standalone disk first.")); }
    if vm.tpm == Some(true) { return Err(refused("The virtual TPM is bound to this host and cannot move to a new machine.")); }
    Ok(())
}
