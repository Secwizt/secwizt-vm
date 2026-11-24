use crate::{ApiError, Events, Reply};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet}, fs, io, path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering}, time::{SystemTime, UNIX_EPOCH},
};
use svm_core::{
    capability::Capability, engine::{EngineDriver, EngineError, EngineResult, FakeEngine, FileTransferUpdate, GuestExecRequest},
    guard::{thread_budget, Decision, HostGuard}, identity,
    library::{validate_name, Library}, model::{EngineKind, GuestArchitecture, GuestFamily, HostInfo, Network, NetworkMode, Snapshot, Vm, VmState},
    Error,
};
use svm_hyperv::{HyperV, LinuxSshAccess, PsRunner, RemovalPlan, RemovalReceipt, WindowsGuestCredentials};

#[path = "machine_agent.rs"]
mod agent;
#[path = "app_catalog.rs"]
mod app_catalog;
#[path = "machine_apps.rs"]
mod machine_apps;
#[path = "machine_routes.rs"]
mod routes;
#[path = "machine_trash.rs"]
mod trash;
#[path = "machine_template.rs"]
mod templates;
#[path = "machine_qemu.rs"]
mod qemu;
#[path = "backups.rs"]
mod backups;
pub use backups::console as backup_console;
#[path = "disk_transfers.rs"]
mod transfers;
#[path = "guest_files.rs"]
mod files;
#[path = "catalog.rs"]
mod catalog;
#[path = "catalog_http.rs"]
mod catalog_http;
#[path = "catalog_feeds.rs"]
mod catalog_feeds;
#[path = "catalog_upstream.rs"]
mod catalog_upstream;
#[path = "catalog_signature.rs"]
mod catalog_signature;
#[path = "catalog_store.rs"]
mod catalog_store;
#[path = "ready.rs"]
mod ready;
#[path = "ready_archive.rs"]
mod ready_archive;
#[path = "ready_seed.rs"]
mod ready_seed;
use svm_qemu::Qemu;

#[derive(Clone, Deserialize)]
pub struct HostProfile {
    pub cpu: String,
    #[serde(default,rename="hostKey")]
    pub host_key: Option<String>,
    #[serde(flatten)]
    pub info: HostInfo,
}

/// The worker owns the driver and its bundle mapping for the life of the service.
pub trait MachineEngine: EngineDriver + Send {
    fn observe(&mut self, vm: &Vm) -> EngineResult<(VmState, Option<std::net::Ipv4Addr>)> {
        self.state(&vm.id).map(|state| (state, None))
    }
    fn define_new(&mut self, vm: &Vm, _bundle: &Path) -> EngineResult<()> { self.define(vm) }
    fn installer_status(&self, _vm: &Vm, _bundle: &Path) -> EngineResult<Value> {
        Ok(json!({"available":false,"reason":"This engine has no installer boot keyboard."}))
    }
    fn installer_start(&mut self, vm: &Vm, _bundle: &Path, press: Option<bool>) -> EngineResult<Value> {
        if press == Some(true) { return Err(EngineError::Invalid("This engine has no installer boot keyboard.".into())); }
        self.start(&vm.id).map(|()|Value::Null)
    }
    fn start_managed(&mut self, vm: &Vm, _parents: &[PathBuf]) -> EngineResult<()> {
        if vm.throwaway { return Err(EngineError::Invalid("Throwaway startup is unavailable for this engine.".into())); }
        self.start(&vm.id)
    }
    fn recover_throwaway(&mut self, _id: &str) -> EngineResult<bool> { Ok(false) }
    fn protect_throwaway_base(&mut self, _id: &str, _enabled: bool) -> EngineResult<()> { Ok(()) }
    fn verify_throwaway_disk(&mut self, _id: &str) -> EngineResult<()> { Ok(()) }
    fn register(&mut self, id: &str, bundle: &Path) -> EngineResult<()>;
    fn background_driver(&self) -> Option<Box<dyn MachineEngine>> { None }
    fn set_networks(&mut self, networks: &[Network]);
    fn profile(&self) -> EngineResult<HostProfile>;
    fn policy_directory(&self,_service_home:&Path)->Option<PathBuf> {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from).map(|base|base.join("SecwizVM Host"))
    }
    fn capacity(&self, _directory: &Path) -> EngineResult<Value> {
        Err(EngineError::Invalid("Library capacity is unavailable.".into()))
    }
    fn read_storage(&self, _vm: &Vm, _bundle: &Path) -> EngineResult<Value> {
        Err(EngineError::Invalid("This engine cannot inspect storage.".into()))
    }
    fn change_storage(&self, _vm: &Vm, _field: &str, _value: &Value) -> EngineResult<Value> {
        Err(EngineError::Invalid("This engine cannot change storage.".into()))
    }
    fn console_id(&self, _id: &str) -> EngineResult<String> {
        Err(EngineError::Invalid("This engine has no native console viewer.".into()))
    }
    fn windows_guest_exec(&self, _: &Vm, _: GuestExecRequest, _: WindowsGuestCredentials) -> EngineResult<Value> {
        Err(EngineError::Invalid("PowerShell Direct is unavailable from this engine.".into()))
    }
    fn linux_guest_exec(&self, _: &Vm, _: GuestExecRequest, _: LinuxSshAccess) -> EngineResult<Value> {
        Err(EngineError::Invalid("Guest SSH is unavailable from this engine.".into()))
    }
    fn file_guest_service(&self, _: &Vm, _: Option<bool>) -> EngineResult<Value> {
        Ok(json!({"available":false,"enabled":false,"canChange":false,"reason":"This engine has no Hyper-V Guest Service Interface."}))
    }
    fn windows_file_download(&self, _: &Vm, _: &str, _: &Path, _: WindowsGuestCredentials,
        _: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>) -> EngineResult<(u64, String)> {
        Err(EngineError::Invalid("PowerShell Direct file downloads are unavailable from this engine.".into()))
    }
    fn linux_file_download(&self, _: &Vm, _: &str, _: &Path, _: LinuxSshAccess,
        _: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>) -> EngineResult<(u64, String)> {
        Err(EngineError::Invalid("SSH file downloads are unavailable from this engine.".into()))
    }
    fn windows_file_upload(&self, _: &Vm, _: &str, _: &Path, _: (u64, &str), _: WindowsGuestCredentials,
        _: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>) -> EngineResult<(u64, String)> {
        Err(EngineError::Invalid("PowerShell Direct file uploads are unavailable from this engine.".into()))
    }
    fn linux_file_upload(&self, _: &Vm, _: &str, _: &Path, _: (u64, &str), _: LinuxSshAccess,
        _: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>) -> EngineResult<(u64, String)> {
        Err(EngineError::Invalid("SSH file uploads are unavailable from this engine.".into()))
    }
    fn guest_ssh_key(&self, _: &Vm) -> EngineResult<String> {
        Err(EngineError::Invalid("Guest SSH enrollment is unavailable from this engine.".into()))
    }
    fn configure(&mut self, vm: &Vm) -> EngineResult<()>;
    fn clone_disk(&mut self, source: &Vm, from: &Path, target: &Vm, to: &Path) -> EngineResult<bool>;
    fn verify_backup_disk(&self, vm: &Vm, expected: &Path) -> EngineResult<()> {
        let actual = self.template_disk(&vm.id)?.canonicalize().map_err(|_| EngineError::Invalid("The attached backup disk is unavailable.".into()))?;
        if actual != expected { return Err(EngineError::Invalid("Backups require the machine's own system disk. Detach external disks first.".into())); }
        Ok(())
    }
    fn template_disk(&self, _id: &str) -> EngineResult<PathBuf> {
        Err(EngineError::Invalid("This engine cannot verify a standalone template disk.".into()))
    }
    fn create_linked(&mut self, _source: &Vm, _target: &Vm, _parent: &Path) -> EngineResult<()> {
        Err(EngineError::Invalid("Linked clones are unavailable for this engine.".into()))
    }
    fn trash_detached(&mut self,_id:&str,_bundle:&Path)->EngineResult<()> {
        Err(EngineError::Invalid("This engine cannot verify detached storage.".into()))
    }
    fn restored_registration(&mut self,_id:&str)->EngineResult<bool> {
        Err(EngineError::Invalid("This engine cannot verify a restored registration.".into()))
    }
    fn import_retained(&mut self,_vm:&Vm,_bundle:&Path,_rel:&str)->EngineResult<()> {
        Err(EngineError::Invalid("This engine cannot import retained registrations.".into()))
    }
    fn removal_plan(&mut self,vm:&Vm)->EngineResult<RemovalPlan>;
    fn unregister(&mut self,vm:&Vm,bundle:&Path,plan:&RemovalPlan,keep:bool)->EngineResult<RemovalReceipt>;
}
impl<R: PsRunner + Send> MachineEngine for HyperV<R> {
    fn windows_guest_exec(&self, vm: &Vm, command: GuestExecRequest, access: WindowsGuestCredentials) -> EngineResult<Value> {
        self.exec_windows(vm, command, access)
    }
    fn linux_guest_exec(&self, vm: &Vm, command: GuestExecRequest, access: LinuxSshAccess) -> EngineResult<Value> {
        self.exec_linux(vm, command, access)
    }
    fn file_guest_service(&self, vm: &Vm, enabled: Option<bool>) -> EngineResult<Value> {
        HyperV::file_guest_service(self, vm, enabled)
    }
    fn windows_file_download(&self, vm: &Vm, guest_path: &str, stage: &Path, access: WindowsGuestCredentials,
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>) -> EngineResult<(u64, String)> {
        self.download_windows(vm, guest_path, stage, access, progress)
    }
    fn linux_file_download(&self, vm: &Vm, guest_path: &str, stage: &Path, access: LinuxSshAccess,
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>) -> EngineResult<(u64, String)> {
        self.download_linux(vm, guest_path, stage, access, progress)
    }
    fn windows_file_upload(&self, vm: &Vm, guest_path: &str, source: &Path, expected: (u64, &str), access: WindowsGuestCredentials,
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>) -> EngineResult<(u64, String)> {
        self.upload_windows(vm, guest_path, source, expected, access, progress)
    }
    fn linux_file_upload(&self, vm: &Vm, guest_path: &str, source: &Path, expected: (u64, &str), access: LinuxSshAccess,
        progress: &mut dyn FnMut(FileTransferUpdate) -> EngineResult<()>) -> EngineResult<(u64, String)> {
        self.upload_linux(vm, guest_path, source, expected, access, progress)
    }
    fn guest_ssh_key(&self, vm: &Vm) -> EngineResult<String> { self.linux_ssh_public_key(vm) }
    fn background_driver(&self) -> Option<Box<dyn MachineEngine>> {
        self.background().map(|driver| Box::new(driver) as Box<dyn MachineEngine>)
    }
    fn installer_status(&self, vm: &Vm, _: &Path) -> EngineResult<Value> { self.installer_request(&vm.id, false, None) }
    fn installer_start(&mut self, vm: &Vm, _: &Path, press: Option<bool>) -> EngineResult<Value> {
        self.installer_request(&vm.id, true, press).map(|v| v["bootKey"].clone())
    }
    fn start_managed(&mut self, vm: &Vm, parents: &[PathBuf]) -> EngineResult<()> {
        if vm.throwaway { self.start_throwaway(vm, parents) } else { self.start_with_parents(&vm.id, parents) }
    }
    fn recover_throwaway(&mut self, id: &str) -> EngineResult<bool> { HyperV::recover_throwaway(self, id) }
    fn protect_throwaway_base(&mut self, id: &str, enabled: bool) -> EngineResult<()> { HyperV::protect_throwaway_base(self, id, enabled) }
    fn verify_throwaway_disk(&mut self, id: &str) -> EngineResult<()> { HyperV::verify_throwaway_disk(self, id) }
    fn observe(&mut self, vm: &Vm) -> EngineResult<(VmState, Option<std::net::Ipv4Addr>)> { self.observe_guest(vm) }
    fn register(&mut self,id:&str,bundle:&Path)->EngineResult<()> { self.register_bundle(id,bundle) }
    fn set_networks(&mut self, networks:&[Network]) { HyperV::set_networks(self,networks); }
    fn capacity(&self, directory: &Path) -> EngineResult<Value> { self.library_capacity(directory) }
    fn read_storage(&self, vm: &Vm, _: &Path) -> EngineResult<Value> { self.storage(&vm.id) }
    fn change_storage(&self, vm: &Vm, field: &str, value: &Value) -> EngineResult<Value> { self.set_storage(&vm.id,field,value) }
    fn console_id(&self, id: &str) -> EngineResult<String> { self.console_guid(id) }
    fn profile(&self)->EngineResult<HostProfile> {
        serde_json::from_value(self.host_summary()?).map_err(|_|EngineError::Engine("Windows returned incomplete host information.".into()))
    }
    fn configure(&mut self,vm:&Vm)->EngineResult<()> { self.configure_offline(vm) }
    fn clone_disk(&mut self,source:&Vm,_:&Path,target:&Vm,_:&Path)->EngineResult<bool> { self.copy_disk(&source.id,&target.id) }
    fn template_disk(&self, id: &str) -> EngineResult<PathBuf> { HyperV::template_disk(self, id) }
    fn create_linked(&mut self, source: &Vm, target: &Vm, parent: &Path) -> EngineResult<()> { self.create_linked_clone(source, target, parent) }
    fn trash_detached(&mut self,id:&str,bundle:&Path)->EngineResult<()> { HyperV::trash_detached(self,id,bundle) }
    fn restored_registration(&mut self,id:&str)->EngineResult<bool> { HyperV::restored_registration(self,id) }
    fn import_retained(&mut self,vm:&Vm,_:&Path,rel:&str)->EngineResult<()> { HyperV::import_retained(self,&vm.id,rel) }
    fn removal_plan(&mut self,vm:&Vm)->EngineResult<RemovalPlan> { HyperV::removal_plan(self,&vm.id) }
    fn unregister(&mut self,vm:&Vm,_:&Path,plan:&RemovalPlan,keep:bool)->EngineResult<RemovalReceipt> {
        self.finish_removal(&vm.id,plan,keep)
    }
}
impl MachineEngine for FakeEngine {
    fn verify_backup_disk(&self, vm: &Vm, expected: &Path) -> EngineResult<()> {
        let folder = expected.parent().ok_or_else(||EngineError::Invalid("Missing bundle.".into()))?;
        let storage = self.read_storage(vm,folder)?;
        let drives = storage["disks"].as_array();
        let actual = drives.filter(|rows|rows.len()==1).and_then(|rows|rows[0]["path"].as_str())
            .and_then(|path|Path::new(path).canonicalize().ok());
        if actual.as_deref()!=Some(expected) { return Err(EngineError::Invalid("The machine must use its own standalone disk.".into())); }
        Ok(())
    }
    fn define_new(&mut self, vm: &Vm, bundle: &Path) -> EngineResult<()> {
        self.define(vm)?;
        if vm.family == GuestFamily::Windows && vm.disk_gb.is_some() && vm.disk_path.is_none() {
            svm_core::write_json(&bundle.join(INSTALLER_RECEIPT), &vm.id)
                .map_err(|_|EngineError::Engine("Could not save the simulated new disk.".into()))?;
        }
        Ok(())
    }
    fn installer_status(&self, vm: &Vm, bundle: &Path) -> EngineResult<Value> {
        let storage=self.read_storage(vm,bundle)?;
        let available=vm.state==VmState::Off && storage["isoPath"].is_string() && storage["bootFirst"]=="image"
            && svm_core::read_json::<String>(&bundle.join(INSTALLER_RECEIPT)).is_ok_and(|id| id==vm.id);
        Ok(json!({"available":available,"reason":(!available).then_some("The machine needs a new empty disk and an installer image first.")}))
    }
    fn installer_start(&mut self, vm: &Vm, bundle: &Path, press: Option<bool>) -> EngineResult<Value> {
        let status=self.installer_status(vm,bundle)?;
        let eligible=status["available"]==true;
        if press==Some(true) && !eligible {return Err(EngineError::Invalid(status["reason"].as_str().unwrap_or("The installer key is unavailable.").into()));}
        fs::remove_file(bundle.join(INSTALLER_RECEIPT)).map_err(|_|EngineError::Engine("Could not consume the simulated new disk record.".into()))?;
        self.start(&vm.id)?;
        Ok(if eligible && press!=Some(false) {json!({"sent":1,"retried":false,"message":"Enter sent to the machine during the installer boot window."})} else {Value::Null})
    }
    fn capacity(&self, _: &Path) -> EngineResult<Value> {
        Ok(json!({"freeBytes":160_u64 << 30, "freeRamGb":32, "tpmCommands":true}))
    }
    fn read_storage(&self, vm: &Vm, bundle: &Path) -> EngineResult<Value> {
        let path = bundle.join(vm.disk_path.as_deref().unwrap_or(Path::new("system.vhdx")));
        let disks = if vm.disk_gb.is_some() || vm.disk_path.is_some() {
            vec![json!({"path":path,"maximumBytes":vm.disk_gb.map(|n|u64::from(n)<<30),"hostBytes":fs::metadata(path).map(|m|m.len()).unwrap_or(0)})]
        } else { Vec::new() };
        let default = if vm.iso_path.is_some() {"image"} else if !disks.is_empty() {"disk"} else {"other"};
        let boot = svm_core::read_json::<String>(&bundle.join("boot-order.json")).unwrap_or_else(|_|default.into());
        Ok(json!({"disks":disks,"isoPath":vm.iso_path,"bootFirst":boot,"canEditMedia":matches!(vm.state,VmState::Off|VmState::Running),
            "canEditBoot":vm.state==VmState::Off,"mediaReason":"Media changes require an off or running machine.","bootReason":"Boot order changes require the machine to be off."}))
    }
    fn change_storage(&self, vm: &Vm, field: &str, value: &Value) -> EngineResult<Value> {
        if field=="bootFirst" && (vm.state!=VmState::Off || (value=="image" && vm.iso_path.is_none())
            || (value=="disk" && vm.disk_gb.is_none() && vm.disk_path.is_none())) {
            return Err(EngineError::Invalid("Boot order changes require an off machine and an attached boot device.".into()));
        }
        if field=="isoPath" && !matches!(vm.state,VmState::Off|VmState::Running) {
            return Err(EngineError::Invalid("Media changes require an off or running machine.".into()));
        }
        Ok(Value::Null)
    }
    fn register(&mut self,_:&str,_:&Path)->EngineResult<()> { Ok(()) }
    fn set_networks(&mut self,_:&[Network]) {}
    fn policy_directory(&self,service_home:&Path)->Option<PathBuf> {Some(service_home.join("fake-host-settings"))}
    fn profile(&self)->EngineResult<HostProfile> {
        Ok(HostProfile {cpu:"Test processor".into(),host_key:Some("00000000-0000-4000-8000-000000000001".into()),info:HostInfo {logical:32,p_cores:[0,15],e_cores:[16,31],ram_gb:64}})
    }
    fn configure(&mut self,vm:&Vm)->EngineResult<()> {
        if self.state(&vm.id)?!=VmState::Off {return Err(EngineError::Invalid("The machine must be off to change its hardware.".into()));}
        if !self.list_snapshots(&vm.id)?.is_empty() {return Err(EngineError::Invalid("Remove checkpoints before changing hardware.".into()));}
        Ok(())
    }
    fn clone_disk(&mut self,source:&Vm,from:&Path,_:&Vm,to:&Path)->EngineResult<bool> {
        if source.disk_path.is_none() && source.disk_gb.is_none() {return Ok(false);}
        let source_disk=from.join(source.disk_path.as_deref().unwrap_or(Path::new("system.vhdx")));
        let target=to.join("system.vhdx");
        if source_disk.exists() {
            fs::copy(source_disk,target).map_err(|_|EngineError::Engine("Could not copy the test disk.".into()))?;
        } else if source.disk_gb.is_some() {
            fs::File::create_new(target).map_err(|_|EngineError::Engine("Could not materialize the empty test disk.".into()))?;
        } else {return Err(EngineError::Missing("source disk".into()));}
        Ok(true)
    }
    fn trash_detached(&mut self,id:&str,_:&Path)->EngineResult<()> {
        match self.state(id) {
            Err(EngineError::Missing(_))=>Ok(()),Err(e)=>Err(e),Ok(_)=>Err(EngineError::Invalid("Machine is still registered.".into()))
        }
    }
    fn restored_registration(&mut self,id:&str)->EngineResult<bool> {
        match self.state(id) {Ok(_)=>Ok(true),Err(EngineError::Missing(_))=>Ok(false),Err(e)=>Err(e)}
    }
    fn import_retained(&mut self,vm:&Vm,bundle:&Path,rel:&str)->EngineResult<()> {
        let archive:Value=svm_core::read_json(&bundle.join(rel).join("state.json"))
            .map_err(|_|EngineError::Invalid("The retained test archive is missing.".into()))?;
        self.import_registration(vm,&archive)
    }
    fn removal_plan(&mut self,vm:&Vm)->EngineResult<RemovalPlan> {
        let state=self.state(&vm.id)?;
        if !matches!(state,VmState::Off|VmState::Saved) {
            return Err(EngineError::Invalid("The machine must be off or saved to remove it.".into()));
        }
        let snaps=self.list_snapshots(&vm.id)?;
        let stamp=format!("{state:?}|{:?}|{:?}",vm.tpm,snaps.iter().map(|s|s.id.as_str()).collect::<Vec<_>>());
        Ok(RemovalPlan {guid:vm.id.clone(),stamp,required:state==VmState::Saved || !snaps.is_empty() || vm.tpm==Some(true)})
    }
    fn unregister(&mut self,vm:&Vm,bundle:&Path,plan:&RemovalPlan,keep:bool)->EngineResult<RemovalReceipt> {
        let current=self.removal_plan(vm)?;
        if plan.guid!=vm.id || plan.stamp!=current.stamp {return Err(EngineError::Invalid("The guest changed before removal.".into()));}
        let failure=|_|EngineError::Engine("The test engine could not save its retained copy.".into());
        let mut receipt=RemovalReceipt {id:vm.id.clone(),retained:None,bytes:None};
        if current.required || keep {
            let relative=format!("retained/{}",next_id());
            let dir=bundle.join(&relative);
            fs::create_dir_all(&dir).map_err(failure)?;
            let data=serde_json::to_vec(&json!({"vm":vm,"snapshots":self.list_snapshots(&vm.id)?,"registration":self.archive_registration(&vm.id)?})).map_err(|_|EngineError::Engine("Could not encode the retained test state.".into()))?;
            fs::write(dir.join("state.json"),&data).map_err(failure)?;
            let mut bytes=data.len() as u64;
            let disk=bundle.join(vm.disk_path.as_deref().unwrap_or(Path::new("system.vhdx")));
            if disk.is_file() {bytes+=fs::copy(disk,dir.join("system.vhdx")).map_err(failure)?;}
            receipt.retained=Some(relative); receipt.bytes=Some(bytes);
        }
        if vm.state==VmState::Saved {self.unregister_saved(&vm.id)?;} else {self.remove(&vm.id)?;}
        svm_core::write_json(&bundle.join("removal-complete.json"),&receipt)
            .map_err(|_|EngineError::Engine("Could not save the verified removal receipt.".into()))?;
        Ok(receipt)
    }

}

const INSTALLER_RECEIPT: &str = "installer-first-boot.json";
fn new_installer_disk(vm:&Vm, bundle:&Path)->bool {
    vm.family==GuestFamily::Windows && vm.disk_gb.is_some() && vm.disk_path.is_none()
        && fs::symlink_metadata(bundle.join(INSTALLER_RECEIPT)).is_ok_and(|m|m.is_file() && !m.is_symlink())
}

fn bad(message:impl Into<String>)->ApiError { ApiError::new(400,"invalid_request",message) }
fn refused(message:impl Into<String>)->ApiError { ApiError::new(409,"refused",message) }
fn absent()->ApiError { ApiError::new(404,"not_found","The requested machine or checkpoint is unavailable.") }
fn engine(error:EngineError)->ApiError {
    match error {
        EngineError::Missing(_)=>absent(),
        EngineError::Invalid(message)=>refused(format!("The engine refused the operation. {message}")),
        EngineError::GuestPowerTimeout=>ApiError::new(504,"guest_power_timeout",error.to_string()),
        EngineError::Permission(message)=>ApiError::new(403,"engine_permission",format!("The engine denied access. {message}")),
        EngineError::Timeout{seconds}=>ApiError::new(504,"engine_timeout",format!("The engine did not finish within {seconds} seconds. Check the machine before retrying.")),
        other=>ApiError::new(502,"engine_error",format!("The engine could not complete the operation. {other}")),
    }
}
fn store(error:Error)->ApiError {
    match error {
        Error::Missing(_)=>absent(), Error::Conflict(message)=>refused(format!("A library entry conflicts with this request. {message}")),
        Error::Invalid(message)=>bad(message),
        _=>ApiError::new(500,"storage","The machine library could not read or save its data."),
    }
}
fn io_error(_:io::Error)->ApiError { ApiError::new(500,"storage","The machine bundle could not be read or written.") }
fn parsed<T:serde::de::DeserializeOwned>(body:&Value)->Result<T,ApiError> {
    serde_json::from_value(if body.is_null() {json!({})} else {body.clone()}).map_err(|e|bad(format!("Check the request fields. {e}")))
}
fn id_ok(id:&str)->bool {
    !id.is_empty() && id.len()<=80 && id.as_bytes()[0].is_ascii_alphanumeric()
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
}
fn next_id()->String {
    static SERIAL:AtomicU64=AtomicU64::new(0);
    let nanos=SystemTime::now().duration_since(UNIX_EPOCH).map_or(0,|v|v.as_nanos());
    format!("vm-{nanos:x}-{:x}-{:x}",std::process::id(),SERIAL.fetch_add(1,Ordering::Relaxed))
}
fn family(os:&str)->GuestFamily {
    let s=os.to_ascii_lowercase();
    if s.contains("windows") {GuestFamily::Windows}
    else if s.contains("linux") || ["ubuntu","debian","fedora","arch","suse","kali"].iter().any(|name|s.contains(name)) {GuestFamily::Linux}
    else if s.contains("android") {GuestFamily::Android}
    else if s.contains("bsd") {GuestFamily::Bsd}
    else if s.contains("macos") {GuestFamily::Macos}
    else if s.contains("dos") {GuestFamily::Dos} else {GuestFamily::Other}
}
fn network<'a>(networks:&'a [Network],id:&str)->Result<&'a Network,ApiError> {
    let n=networks.iter().find(|n|n.id==id).ok_or_else(||bad("Choose an existing network."))?;
    if n.mode==NetworkMode::Bridged && n.bridge.as_ref().and_then(|b|b.switch_guid.as_ref()).is_none() {
        return Err(refused("Finish the wired bridge setup and verify the network before attaching a guest."));
    }
    Ok(n)
}
fn wire(vm:&Vm, networks:&[Network], reported: Option<std::net::Ipv4Addr>)->Value {
    let mut value=json!(vm);
    if vm.engine == EngineKind::Qemu {
        value["portForwardAddress"] = json!(svm_qemu::PORT_FORWARD_HOST);
    }
    if networks.iter().any(|n| n.id==vm.net && matches!(n.mode,NetworkMode::Nat|NetworkMode::Bridged)) {
        value["ip"]=json!(reported);
        value["addressSource"]=json!(if reported.is_some() {"reported by the guest"} else {"not reported by the guest"});
    }
    value
}
fn checked_media(path:&Path,extension:&str)->Result<PathBuf,ApiError> {
    use std::path::Component;
    let invalid=||bad("Choose an existing regular file on a local drive, without links or device names.");
    if !path.is_absolute() || !path.extension().is_some_and(|e|e.eq_ignore_ascii_case(extension)) {return Err(invalid());}
    #[cfg(windows)]
    {
        use std::path::Prefix;
        match path.components().next() {
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(),Prefix::Disk(_)|Prefix::VerbatimDisk(_))=>{}
            _=>return Err(invalid()),
        }
    }
    for part in path.components() {
        match part {
            Component::ParentDir=>return Err(invalid()),
            Component::Normal(name)=>{
                let text=name.to_str().ok_or_else(invalid)?;
                validate_name(text).map_err(|_|invalid())?;
            }
            _=>{}
        }
    }
    for item in path.ancestors() {
        let meta=fs::symlink_metadata(item).map_err(|_|invalid())?;
        if meta.file_type().is_symlink() {return Err(invalid());}
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {return Err(invalid());}
        }
    }
    if !path.is_file() {return Err(invalid());}
    path.canonicalize().map_err(|_|invalid())
}
fn active(state:VmState)->bool {matches!(state,VmState::Running|VmState::Paused)}

fn host_key(value:&str)->bool {
    value.len()==36 && value.bytes().enumerate().all(|(i,c)|if matches!(i,8|13|18|23) { c==b'-' } else { c.is_ascii_hexdigit() })
}
fn load_guard(path:&Path)->Result<HostGuard,ApiError> {
    match svm_core::read_json(path) {
        Ok(settings)=>Ok(settings),
        Err(Error::Io(error)) if error.kind()==io::ErrorKind::NotFound=>Ok(HostGuard::default()),
        Err(_)=>Err(ApiError::new(500,"host_settings","The saved protection settings for this host could not be read.")),
    }
}

pub(crate) type MachineCompletion =
    Box<dyn FnOnce(&mut Machines, &[Network], &mut Events) -> Result<Reply, ApiError> + Send>;

type MachineWork = Box<dyn FnOnce(&mut dyn MachineEngine) -> MachineCompletion + Send>;

pub(crate) struct BackgroundTask {
    machines: Vec<String>,
    reserved: Option<Vm>,
    hyperv: bool,
    qemu_checkpoint: bool,
    catalog_io: bool,
    pub(crate) accepted: Option<Reply>,
    run: Box<dyn FnOnce() -> MachineCompletion + Send>,
}

impl BackgroundTask {
    pub(crate) fn run(self) -> MachineCompletion {
        (self.run)()
    }
}

pub(crate) struct MachineTask {
    machines: Vec<String>,
    reserved: Option<Vm>,
    run: MachineWork,
}

impl MachineTask {
    fn new(
        machines: Vec<String>,
        reserved: Option<Vm>,
        run: impl FnOnce(&mut dyn MachineEngine) -> MachineCompletion + Send + 'static,
    ) -> Self {
        Self { machines, reserved, run: Box::new(run) }
    }

    fn bind(self, mut driver: Box<dyn MachineEngine>) -> BackgroundTask {
        let Self { machines, reserved, run } = self;
        BackgroundTask { machines, reserved, hyperv: true, qemu_checkpoint: false, catalog_io: false, accepted: None, run: Box::new(move || run(&mut *driver)) }
    }

    pub(crate) fn run(self, engine: &mut dyn MachineEngine) -> MachineCompletion {
        (self.run)(engine)
    }
}

pub struct Machines {
    pending_machines: Vec<String>,
    pending_reservation: Option<Vm>,
    pending_hyperv: bool,
    pending_qemu_checkpoint: bool,
    pending_catalog_io: bool,
    pending_app_operation: bool,
    agent_ipv4: BTreeMap<String, std::net::Ipv4Addr>,
    transfers:transfers::Transfers,
    file_transfers: files::FileTransfers,
    backups: backups::Backups,
    catalog_downloads: catalog::Downloads,
    catalog_updates: catalog_upstream::Updates,
    guest_apps: machine_apps::GuestApps,
    ready_jobs: ready::ReadyJobs,
    engine:Box<dyn MachineEngine>, qemu:Qemu, library:Library, inventory:Vec<Vm>, host:Result<HostProfile,String>,
    unavailable:BTreeSet<String>, uncertain:BTreeSet<String>, guard:HostGuard, guard_path:Option<PathBuf>,
    guard_unavailable:bool, library_dir:PathBuf,
    recovery_failures: BTreeSet<String>,
    // Guest reports are observations. The on-disk reservation belongs to the library.
    reported_ipv4: BTreeMap<String, std::net::Ipv4Addr>,
    last_refresh: std::time::Instant,
    ram_sample:std::cell::Cell<Option<(std::time::Instant,u64)>>,
    capacity_sample: std::cell::RefCell<Option<Value>>,
    tpm_verified: Option<bool>,
}
impl Machines {
    pub fn open(home:&Path, engine_driver:Box<dyn MachineEngine>,networks:&[Network],events:&mut Events)->Result<Self,ApiError> {
        let supervisor=std::env::current_exe().map_err(io_error)?;
        Self::open_with_supervisor(home,engine_driver,networks,events,&supervisor)
    }
    pub(crate) fn open_with_supervisor(home:&Path,engine_driver:Box<dyn MachineEngine>,networks:&[Network],events:&mut Events,supervisor:&Path)->Result<Self,ApiError> {
        let library_dir=home.join("library");
        let library=Library::open_stable(&library_dir).map_err(store)?;
        let inventory=library.load_all().map_err(store)?;
        let qemu=Qemu::new(home,supervisor);
        let host=engine_driver.profile().map_err(|e|e.to_string());
        let directory=engine_driver.policy_directory(home);
        let key=host.as_ref().ok().and_then(|h|h.host_key.as_deref()).filter(|s| host_key(s));
        let guard_path=directory.as_ref().zip(key).map(|(d,k)|d.join(format!("{}.json",k.to_ascii_lowercase())));
        // A portable guard.json has no host identity. Only an explicit settings save opts this host in.
        let guard=match &guard_path {
            Some(path)=>load_guard(path)?,
            None=>HostGuard::default(),
        };
        // An existing policy must not be bypassed when this host's identity cannot be read.
        let guard_unavailable=guard_path.is_none() && directory.as_ref().is_some_and(|dir|
            fs::read_dir(dir).map(|mut entries|entries.any(|entry|match entry {
                Ok(entry) if entry.path().extension().is_some_and(|s|s=="json")=>load_guard(&entry.path()).map_or(true,|p|p.enabled),
                Ok(_)=>false,Err(_)=>true,
            })).unwrap_or_else(|e|e.kind()!=io::ErrorKind::NotFound));
        let mut this=Self {backups:backups::Backups::new(supervisor),pending_machines:Vec::new(),pending_reservation:None,pending_hyperv:false,pending_qemu_checkpoint:false,pending_catalog_io:false,pending_app_operation:false,guest_apps:machine_apps::GuestApps::default(),ready_jobs:ready::ReadyJobs::default(),agent_ipv4:BTreeMap::new(),transfers:transfers::Transfers::default(),file_transfers:files::FileTransfers::default(),catalog_downloads:catalog::Downloads::default(),catalog_updates:catalog_upstream::Updates::default(),engine:engine_driver,qemu,library,inventory,host,guard,guard_path,guard_unavailable,library_dir,tpm_verified:None,
            reported_ipv4:BTreeMap::new(),last_refresh: std::time::Instant::now(),ram_sample:std::cell::Cell::new(None),capacity_sample:std::cell::RefCell::new(None),
            unavailable:BTreeSet::new(),uncertain:BTreeSet::new(),recovery_failures:BTreeSet::new()};
        this.engine.set_networks(networks);
        for vm in this.inventory.clone() {
            let bundle=this.library.bundle_path(&vm.id).map_err(store)?;
            this.inspect_restore_marker(&vm.id,&bundle);
            if vm.engine!=EngineKind::AppleVz {this.driver_mut(vm.engine)?.register(&vm.id,&bundle).map_err(engine)?;}
        }
        this.recover_interrupted_runs(events)?;
        this.reconcile_throwaway_protection(events)?;
        this.recover_backup(events)?;
        this.cleanup_backup_tools(events)?;
        this.recover_transfer(events)?;
        this.recover_ready(events)?;
        this.refresh(events)?;
        this.recover_template_permissions(events)?;
        Ok(this)
    }
    /// A crash or power cut can leave a throwaway disk attached or a QEMU run receipt behind.
    /// Reconcile both before any other recovery reads a machine disk. A failure is retried by
    /// the next refresh and never stops the service from starting.
    fn recover_interrupted_runs(&mut self, events: &mut Events) -> Result<(), ApiError> {
        for vm in self.inventory.clone() {
            let (discarded, cleared) = self.recover_machine_run(&vm, events)?;
            if (discarded || cleared) && vm.engine == EngineKind::Qemu && active(vm.state) {
                let mut stopped = vm;
                stopped.state = VmState::Off;
                stopped.cores.clear();
                self.save(&stopped)?;
            }
        }
        Ok(())
    }

    fn recover_machine_run(&mut self, vm: &Vm, events: &mut Events) -> Result<(bool, bool), ApiError> {
        let result = match vm.engine {
            EngineKind::Qemu => self.qemu.recover_throwaway(vm).and_then(|discarded| {
                self.qemu.recover_interrupted_run(vm).map(|cleared| (discarded, cleared))
            }),
            EngineKind::HyperV => self.engine.recover_throwaway(&vm.id).map(|discarded| (discarded, false)),
            EngineKind::AppleVz => return Ok((false, false)),
        };
        let (discarded, cleared) = match result {
            Ok(outcome) => {
                // A live supervisor can still hold the operation lock. Ok(false) then means
                // recovery deferred and the next error belongs to the same pending run.
                if self.recovery_failures.contains(&vm.id) && !self.throwaway_pending(vm) {
                    let receipt_pending = vm.engine == EngineKind::Qemu && self.has_run_record(vm, "qemu-run.json");
                    if !receipt_pending { self.recovery_failures.remove(&vm.id); }
                }
                outcome
            }
            Err(error) => {
                if self.recovery_failures.insert(vm.id.clone()) {
                    events.record("throwaway recovery failed", &format!("{}: {error}", vm.id))?;
                }
                return Ok((false, false));
            }
        };
        if discarded {
            let message = if vm.engine == EngineKind::HyperV {
                format!("Discarded the temporary disk for {} after the guest powered off or was saved.", vm.id)
            } else {
                format!("Cleaned up after an interrupted run of {}: its temporary disk, if any, was discarded.", vm.id)
            };
            events.record("throwaway disk discarded", &message)?;
        }
        if cleared {
            events.record("interrupted run recovered", &format!("{} was not shut down cleanly. Its stale run record was cleared.", vm.id))?;
        }
        Ok((discarded, cleared))
    }
    /// The read-only flag on a Hyper-V machine's own disk follows its saved throwaway mode. A crash
    /// between changing the flag and saving the mode is settled here, before anything can start it.
    /// Templates keep their own read-only disk. Throwaway machines are always protected, open
    /// runs included (a read-only parent never blocks a run on its temporary disk); the flag is
    /// lifted only on a normal machine with no open run, and only if throwaway mode set it.
    fn reconcile_throwaway_protection(&mut self, events: &mut Events) -> Result<(), ApiError> {
        let plan = throwaway_protection_plan(&self.inventory, |vm| self.throwaway_pending(vm));
        for (id, protect) in plan {
            if let Err(error) = self.engine.protect_throwaway_base(&id, protect) {
                let what = if protect { "could not be made read-only" } else { "is still read-only" };
                events.record("throwaway protection", &format!("The original disk of {id} {what}. {error}"))?;
            }
        }
        Ok(())
    }
    fn hyperv_disk_parents(&self, vm: &Vm, bundle: &Path) -> Result<Vec<PathBuf>, ApiError> {
        let mut parents = Vec::new();
        if vm.throwaway { parents.push(bundle.join("system.vhdx")); }
        if let Some(id) = &vm.linked_from {
            let source = self.vm(id)?;
            let seal = source.template.as_ref().filter(|_| source.engine == EngineKind::HyperV && source.linked_from.is_none())
                .ok_or_else(|| refused("The linked machine's Hyper-V template is unavailable."))?;
            // Only the standard disk name qualifies for a new access grant.
            if seal.disk.eq_ignore_ascii_case("system.vhdx") {
                parents.push(self.library.bundle_path(id).map_err(store)?.join("system.vhdx"));
            }
        }
        Ok(parents)
    }

    /// True while a throwaway run has a record that recovery has not cleared yet.
    pub(crate) fn throwaway_pending(&self, vm: &Vm) -> bool {
        let record = match vm.engine {
            EngineKind::HyperV => "hyperv-throwaway.json",
            EngineKind::Qemu => "qemu-throwaway.json",
            EngineKind::AppleVz => return false,
        };
        self.has_run_record(vm, record)
    }

    fn has_run_record(&self, vm: &Vm, record: &str) -> bool {
        let Ok(bundle) = self.library.bundle_path(&vm.id) else { return true; };
        // A dangling link or unreadable record still needs recovery.
        !matches!(fs::symlink_metadata(bundle.join(record)), Err(e) if e.kind() == io::ErrorKind::NotFound)
    }
    fn driver(&self, kind:EngineKind)->Result<&dyn MachineEngine,ApiError> {
        match kind {
            EngineKind::HyperV=>Ok(&*self.engine),
            EngineKind::Qemu=>Ok(&self.qemu),
            EngineKind::AppleVz=>Err(refused("Apple VZ requires a supported Mac.")),
        }
    }
    fn driver_mut(&mut self, kind:EngineKind)->Result<&mut dyn MachineEngine,ApiError> {
        match kind {
            EngineKind::HyperV=>Ok(&mut *self.engine),
            EngineKind::Qemu=>Ok(&mut self.qemu),
            EngineKind::AppleVz=>Err(refused("Apple VZ requires a supported Mac.")),
        }
    }
    pub(crate) fn track_background(&mut self, task: Option<&BackgroundTask>) {
        self.pending_machines = task.map(|task| task.machines.clone()).unwrap_or_default();
        self.pending_reservation = task.and_then(|task| task.reserved.clone());
        self.pending_hyperv = task.is_some_and(|task| task.hyperv);
        self.pending_qemu_checkpoint = task.is_some_and(|task| task.qemu_checkpoint);
        self.pending_catalog_io = task.is_some_and(|task| task.catalog_io);
        self.pending_app_operation = task.is_some_and(|task| task.accepted.is_some());
    }

    pub(crate) fn background_busy(&self) -> bool {
        !self.pending_machines.is_empty()
    }

    pub(crate) fn background_hyperv(&self) -> bool {
        self.pending_hyperv
    }

    pub(crate) fn background_checkpoint(&self) -> bool { self.pending_qemu_checkpoint }

    pub(crate) fn background_app_operation(&self) -> bool { self.pending_app_operation }

    pub(crate) fn background_owns(&self, id: &str) -> bool {
        self.pending_machines.iter().any(|machine| machine == id)
    }

    pub(crate) fn uses_hyperv(&self, id: &str) -> bool {
        self.inventory.iter().any(|vm| vm.id == id && vm.engine == EngineKind::HyperV)
    }

    pub(crate) fn converting(&self)->bool {self.transfers.active() || self.ready_jobs.active()}
    pub fn inventory(&self)->&[Vm] {&self.inventory}
    pub(crate) fn may_close_service(&mut self, events:&mut Events)->Result<bool,ApiError> {
        self.refresh(events)?;
        Ok(self.uncertain.is_empty() && !self.allocated().iter().any(|vm|active(vm.state)))
    }
    pub fn uses_network(&self,id:&str)->bool {self.inventory.iter().any(|v|v.net==id)}
    fn vm(&self,id:&str)->Result<Vm,ApiError> {self.inventory.iter().find(|v|v.id==id).cloned().ok_or_else(absent)}
    fn save(&mut self,v:&Vm)->Result<(),ApiError> {
        self.library.save(v).map_err(store)?;
        if v.state != VmState::Running { self.agent_ipv4.remove(&v.id); }
        if let Some(row)=self.inventory.iter_mut().find(|x|x.id==v.id) {
            if row.net!=v.net || row.mac!=v.mac || v.state!=VmState::Running { self.reported_ipv4.remove(&v.id); }
            *row=v.clone();
        }
        Ok(())
    }
    fn forget(&mut self,id:&str)->Result<PathBuf,ApiError> {
        let trash=self.library.delete(id).map_err(store)?;
        self.file_transfers.forget(id);
        self.guest_apps.forget(id);
        self.inventory.retain(|v|v.id!=id);
        self.recovery_failures.remove(id);
        self.backups.forget(id);
        self.unavailable.remove(id); self.uncertain.remove(id); self.reported_ipv4.remove(id); self.agent_ipv4.remove(id);
        Ok(trash)
    }
    pub(crate) fn tick(&mut self, events: &mut Events, client_interested: bool) -> Result<(), ApiError> {
        let elapsed = self.last_refresh.elapsed().as_secs();
        if elapsed >= 15 && !self.inventory.is_empty() && (client_interested || elapsed >= 60 || self.inventory.iter().any(|vm|active(vm.state))) {
            self.refresh(events)?;
        }
        Ok(())
    }
    fn refresh(&mut self,events:&mut Events)->Result<(),ApiError> {
        self.refresh_after(events, None, None)
    }
    // For a successful engine call, record its own event and persist the observed state.
    // Other changes discovered in the same pass still belong to reconciliation.
    fn refresh_after(&mut self,events:&mut Events,selected:Option<&str>,operation: Option<(&str,Option<VmState>)>)->Result<(),ApiError> {
        let observed_guests:Vec<_>=self.inventory.iter().filter(|v|selected.is_none_or(|id|id==v.id) && !(self.background_hyperv() && v.engine == EngineKind::HyperV)
            && !(self.background_checkpoint() && self.background_owns(&v.id))).cloned().collect();
        for mut vm in observed_guests {
            self.reported_ipv4.remove(&vm.id);
            let recovered_qemu = vm.engine == EngineKind::Qemu && self.recover_machine_run(&vm, events)?.0;
            let observed = self.driver_mut(vm.engine)
                .map_err(|e| EngineError::Invalid(e.message))
                .and_then(|driver| driver.observe(&vm));
            let state=match observed {
                Ok((mut state, reported)) => {
                    // Discarding a saved Hyper-V run also discards its saved memory.
                    if vm.engine == EngineKind::HyperV && matches!(state, VmState::Off | VmState::Saved)
                        && self.recover_machine_run(&vm, events)?.0 {
                        state = VmState::Off;
                    }
                    if vm.throwaway && vm.engine == EngineKind::Qemu && active(vm.state) && state == VmState::Off
                        && !recovered_qemu && !self.recovery_failures.contains(&vm.id) && !self.throwaway_pending(&vm) {
                        events.record("throwaway disk discarded", &format!("Discarded the temporary disk for {} at power-off.", vm.id))?;
                    }
                    if let Some(ip)=reported {self.reported_ipv4.insert(vm.id.clone(),ip); }
                    let was_missing=self.unavailable.remove(&vm.id);
                    let was_unknown=self.uncertain.remove(&vm.id);
                    if was_missing || was_unknown {events.record("registration restored",&format!("The engine verified the registration for {}.",vm.id))?;}
                    state
                }
                Err(EngineError::Missing(_))=>{
                    self.uncertain.remove(&vm.id);
                    if self.unavailable.insert(vm.id.clone()) {
                        events.record("registration missing",&format!("{} has a library bundle but no engine registration.",vm.id))?;
                    }
                    continue;
                }
                Err(error)=>{
                    if self.uncertain.insert(vm.id.clone()) {
                        events.record("state unavailable",&format!("The engine could not confirm the state of {}. {error}",vm.id))?;
                    }
                    continue;
                }
            };
            let old=vm.state;
            if old!=state || (!active(state) && !vm.cores.is_empty()) {
                vm.state=state;
                if !active(state) {vm.cores.clear();}
                self.save(&vm)?;
                let explained = operation.is_some_and(|(id, expected)| id == vm.id && expected.is_none_or(|s| s == state));
                if old!=state && !explained {events.record("reconciled",&format!("{} changed from {old:?} to {state:?} in the engine.",vm.id))?;}
            }
        }
        // A guest may have been started externally while the service was down.
        if let Ok(host)=&self.host {
            let host=host.info.clone();
            let mut placed=Vec::new();
            for mut vm in self.allocated().into_iter().filter(|v|active(v.state)) {
                let count=usize::from(vm.vcpu.min(host.logical));
                if vm.cores.len()!=count || vm.cores.iter().any(|c|*c>=host.logical)
                    || vm.cores.iter().collect::<BTreeSet<_>>().len()!=vm.cores.len() {
                    vm.cores=self.guard.advisory(&host,&placed,&vm);
                    self.save(&vm)?;
                    events.record("placement",&format!("{} received an advisory placement after reconciliation.",vm.id))?;
                }
                placed.push(vm);
            }
        }
        if selected.is_none() {self.last_refresh=std::time::Instant::now();}
        Ok(())
    }
    fn published(&self,v:&Vm,networks:&[Network])->Value {
        let agent = if v.state == VmState::Running && self.available(&v.id).is_ok() {
            self.agent_ipv4.get(&v.id).copied()
        } else { None };
        let mut value=wire(v,networks,agent.or_else(||self.reported_ipv4.get(&v.id).copied()));
        if let Some(ip) = agent {
            value["ip"] = json!(ip);
            value["addressSource"] = json!("guest agent");
        }
        let status=if self.backups.incomplete.contains(&v.id) {"restore incomplete"} else if self.uncertain.contains(&v.id) {"unknown"} else if self.unavailable.contains(&v.id) {"missing"} else {"registered"};
        value["registration"]=json!(status);
        if status!="registered" {value["lastKnownState"]=value["state"].clone();value["state"]=Value::Null;}
        value
    }
    fn allocated(&self)->Vec<Vm> {
        self.inventory.iter().filter(|v|!self.unavailable.contains(&v.id) || self.uncertain.contains(&v.id)).cloned().collect()
    }
    fn available(&self,id:&str)->Result<(),ApiError> {
        if self.backups.incomplete.contains(id) { return Err(refused("Restore incomplete. Move this copy to trash and retry the backup restore.")); }
        if self.unavailable.contains(id) {return Err(refused("The machine's bundle is present, but its engine registration is missing."));}
        if self.uncertain.contains(id) {return Err(refused("The engine could not verify this machine. Check its registration and try again."));}
        Ok(())
    }
    fn free_ram(&self)->Result<u64,String> {
        if let Some((at,free))=self.ram_sample.get() {
            if at.elapsed()<std::time::Duration::from_secs(3) {return Ok(free);}
        }
        let data=self.engine.capacity(&self.library_dir).map_err(|_|"Host protection could not measure the current free memory.")?;
        let free=data["freeRamGb"].as_u64().ok_or("Host protection could not measure the current free memory.")?;
        self.ram_sample.set(Some((std::time::Instant::now(),free)));Ok(free)
    }
    fn admit(&self,candidate:&Vm)->Result<Vec<u16>,String> {
        if self.guard_unavailable {return Err("The saved protection settings could not be matched to this host.".into());}
        if !self.guard.enabled {
            return Ok(self.host.as_ref().map(|h|self.guard.advisory(&h.info,&self.allocated(),candidate)).unwrap_or_default());
        }
        if !self.uncertain.is_empty() {return Err("Host protection cannot confirm the resource use of all registered machines.".into());}
        let host=self.host.as_ref().map_err(|e|format!("Host protection could not read the host. {e}"))?;
        match self.guard.admit(&host.info,&self.allocated(),candidate) {
            Decision::Admit{cores}=>{
                if self.guard.reserve_gb>0 {
                    let add=if candidate.state==VmState::Paused {0} else {u64::from(candidate.ram_gb)};
                    let need=add+u64::from(self.guard.reserve_gb);let free=self.free_ram()?;
                    if need>free {return Err(format!("This operation requires {need} GB of free memory including the host reserve. Windows reports {free} GB free."));}
                }
                Ok(cores)
            }
            Decision::Refuse{reason}=>Err(reason),
        }
    }
    fn checked_admit(&self,v:&Vm,events:&mut Events)->Result<Vec<u16>,ApiError> {
        self.ram_sample.set(None);
        self.admit(v).map_err(|reason|match events.record("refused",&format!("{}: {reason}",v.id)) {
            Ok(())=>refused(reason),Err(error)=>error,
        })
    }
}

/// Which Hyper-V machines should have a read-only own disk (true) or a writable one (false).
fn throwaway_protection_plan(inventory: &[Vm], pending: impl Fn(&Vm) -> bool) -> Vec<(String, bool)> {
    inventory.iter()
        .filter(|vm| vm.engine == EngineKind::HyperV && vm.template.is_none() && (vm.throwaway || !pending(vm)))
        .map(|vm| (vm.id.clone(), vm.throwaway))
        .collect()
}

#[cfg(test)]
mod machine_tests {
    use super::*;
    #[test]
    fn throwaway_protection_follows_the_saved_mode_except_templates_and_open_runs() {
        let mut normal = guest(VmState::Off, false);
        normal.id = "normal".into();
        let mut throwaway = normal.clone();
        throwaway.id = "throwaway".into();
        throwaway.throwaway = true;
        let mut template = normal.clone();
        template.id = "template".into();
        template.template = Some(svm_core::model::TemplateDisk { disk: "system.vhdx".into(), sha256: "0".repeat(64), originally_read_only: false });
        let mut open_run = throwaway.clone();
        open_run.id = "open-run".into();
        let mut qemu = throwaway.clone();
        qemu.id = "qemu".into();
        qemu.engine = EngineKind::Qemu;
        let inventory = vec![normal, throwaway, template, open_run, qemu];
        let plan = throwaway_protection_plan(&inventory, |vm| vm.id == "open-run");
        assert_eq!(plan, vec![("normal".to_string(), false), ("throwaway".to_string(), true), ("open-run".to_string(), true)]);
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new()->Self {
            let folder=std::env::temp_dir().join(next_id());
            fs::create_dir(&folder).unwrap();
            Self(folder)
        }
    }
    impl Drop for Fixture {fn drop(&mut self) {let _=fs::remove_dir_all(&self.0);}}
    fn guest(state:VmState,tpm:bool)->Vm {
        serde_json::from_value(json!({"id":"test-state","name":"State fixture","os":"Test","family":"other",
            "engine":"Hyper-V","accel":true,"state":state,"vcpu":1,"ramGb":1,"net":"nat",
            "mac":"02:77:00:00:00:01","ip":"192.0.2.2","dns":"state.example","tpm":tpm})).unwrap()
    }
    #[test]
    fn hyperv_parent_grants_follow_the_registered_template_and_throwaway_mode() {
        let root = Fixture::new();
        let library = Library::open_stable(root.0.join("library")).unwrap();
        let mut template = guest(VmState::Off, false);
        template.template = Some(svm_core::model::TemplateDisk {
            disk: "system.vhdx".into(), sha256: "0".repeat(64), originally_read_only: false,
        });
        library.create(&template).unwrap();
        let parent = library.bundle_path(&template.id).unwrap().join("system.vhdx");
        let mut events = Events::open(&root.0).unwrap();
        let machines = Machines::open(&root.0, Box::new(FakeEngine::default()), &[], &mut events).unwrap();
        let mut child = guest(VmState::Off, false);
        child.id = "child".into();
        let bundle = root.0.join("library").join("child.swvm");
        let base = bundle.join("system.vhdx");
        assert!(machines.hyperv_disk_parents(&child, &bundle).unwrap().is_empty());
        child.throwaway = true;
        assert_eq!(machines.hyperv_disk_parents(&child, &bundle).unwrap(), [base.clone()]);
        child.linked_from = Some(template.id);
        assert_eq!(machines.hyperv_disk_parents(&child, &bundle).unwrap(), [base, parent.clone()]);
        child.throwaway = false;
        assert_eq!(machines.hyperv_disk_parents(&child, &bundle).unwrap(), [parent]);
        child.linked_from = Some("missing-template".into());
        assert!(machines.hyperv_disk_parents(&child, &bundle).is_err());
    }

    #[test]
    fn reload_routes_each_persisted_machine_to_its_own_engine() {
        let root=Fixture::new();
        let library=Library::open_stable(root.0.join("library")).unwrap();
        let mut hyperv=FakeEngine::default();
        let hv=guest(VmState::Off,false);
        library.create(&hv).unwrap();
        let legacy_bundle=library.bundle_path(&hv.id).unwrap();
        let mut old=json!(hv);
        old.as_object_mut().unwrap().remove("engine");
        svm_core::write_json(&legacy_bundle.join("vm.json"),&old).unwrap();
        hyperv.define(&hv).unwrap();
        let mut qvm=hv.clone();
        qvm.id="qemu-route".into();qvm.name="QEMU route".into();qvm.engine=EngineKind::Qemu;
        qvm.mac="02:77:00:00:00:02".parse().unwrap();qvm.ip="192.0.2.3".parse().unwrap();qvm.dns="qemu.example".into();
        library.create(&qvm).unwrap();
        // A running decoy makes an accidental lookup in the Hyper-V driver observable.
        hyperv.define(&qvm).unwrap();
        hyperv.start(&qvm.id).unwrap();
        let mut events=Events::open(&root.0).unwrap();
        let mut machines=Machines::open(&root.0,Box::new(hyperv),&[],&mut events).unwrap();
        assert_eq!(machines.vm(&hv.id).unwrap().engine,EngineKind::HyperV);
        assert_eq!(machines.published(&machines.vm(&hv.id).unwrap(),&[])["state"],"off");
        assert_eq!(machines.published(&qvm,&[])["registration"],"missing");
        assert!(machines.route("POST",&["machines",&qvm.id,"stop"],&json!({}),&[],&mut events).is_err());
        assert_eq!(machines.engine.state(&qvm.id).unwrap(),VmState::Running);
        let settings:Value=serde_json::from_slice(&machines.qemu_settings("GET",&Value::Null).unwrap().body).unwrap();
        assert_eq!(settings["available"],false);
        assert!(settings["path"].is_null());
        assert!(settings["reason"].is_string());
        assert!(machines.qemu_settings("PUT",&json!({})).is_err());
        assert!(machines.qemu_settings("PUT",&json!({"path":"relative.exe"})).is_err());
    }

    #[test]
    fn qemu_trash_requires_its_own_detached_receipt() {
        let root=Fixture::new();
        let library=Library::open_stable(root.0.join("library")).unwrap();
        let mut vm=guest(VmState::Off,false);
        vm.engine=EngineKind::Qemu;
        library.create(&vm).unwrap();
        let discarded=library.delete(&vm.id).unwrap();
        let key=library.list_trash().unwrap()[0].key.clone();
        let mut events=Events::open(&root.0).unwrap();
        let mut machines=Machines::open(&root.0,Box::new(FakeEngine::default()),&[],&mut events).unwrap();
        let trash=["trash",key.as_str()];
        let confirm=json!({"confirmName":vm.name});
        assert!(machines.route("POST",&["trash",&key,"restore"],&json!({}),&[],&mut events).is_err());
        assert!(machines.route("DELETE",&trash,&confirm,&[],&mut events).is_err());
        let receipt=RemovalReceipt {id:vm.id.clone(),retained:None,bytes:None};
        svm_core::write_json(&discarded.join("removal-complete.json"),&receipt).unwrap();
        fs::write(discarded.join("qemu-run.json"),"uncertain").unwrap();
        assert!(machines.route("DELETE",&trash,&confirm,&[],&mut events).is_err());
        fs::remove_file(discarded.join("qemu-run.json")).unwrap();
        assert!(machines.route("DELETE",&trash,&confirm,&[],&mut events).is_ok());
    }

    fn remove_fixture(state:VmState,tpm:bool,checkpoint:bool,keep:bool)->(Fixture,Value) {
        let root=Fixture::new();
        let mut events=Events::open(&root.0).unwrap();
        let library=Library::open_stable(root.0.join("library")).unwrap();
        let mut fake=FakeEngine::default();
        let vm=guest(state,tpm);
        fake.define(&vm).unwrap();
        if checkpoint {fake.snapshot(&vm.id,"Retain me",false).unwrap();}
        library.create(&vm).unwrap();
        let mut machines=Machines::open(&root.0,Box::new(fake),&[],&mut events).unwrap();
        let reply=machines.route("DELETE",&["machines",&vm.id],&json!({"keepCopy":keep}),&[],&mut events).unwrap();
        let result:Value=serde_json::from_slice(&reply.body).unwrap();
        assert!(machines.inventory().is_empty());
        let kinds:Vec<_>=events.reader().since(0).unwrap().into_iter().map(|e|e.kind).collect();
        assert_eq!(kinds.contains(&"retaining".into()),result["retainedPath"].is_string());
        (root,result)
    }
    #[test]
    fn removal_keeps_each_protected_state_even_when_copy_is_false() {
        for (state,tpm,snapshot) in [(VmState::Saved,false,false),(VmState::Off,true,false),(VmState::Off,false,true)] {
            let (root,result)=remove_fixture(state,tpm,snapshot,false);
            let path=PathBuf::from(result["retainedPath"].as_str().unwrap());
            assert!(path.starts_with(root.0.join("library/trash").canonicalize().unwrap()));
            assert!(path.join("state.json").is_file());
            assert!(result["retainedBytes"].as_u64().unwrap()>0);
            assert_eq!(result["removalPath"],"retained-copy");
        }
    }
    #[test]
    fn ordinary_removal_skips_export_and_explicit_copy_preserves_it() {
        let (_root,plain)=remove_fixture(VmState::Off,false,false,false);
        assert_eq!(plain["removalPath"],"bundle-only");
        assert!(plain["retainedPath"].is_null());
        assert!(plain["retainedBytes"].is_null());
        let (_root,explicit)=remove_fixture(VmState::Off,false,false,true);
        assert_eq!(explicit["removalPath"],"retained-copy");
    }
    fn trash_test_networks()->Vec<Network> {
        vec![Network {bridge:None, id:"nat".into(),name:"NAT".into(),mode:NetworkMode::Nat,subnet:"192.0.2.0/24".parse().unwrap(),gateway:None,dhcp:true,note:String::new()}]
    }
    #[test]
    fn published_guest_address_does_not_replace_a_permanent_reservation() {
        let guest=guest(VmState::Running,false);
        let mut networks=trash_test_networks();
        networks[0].id=guest.net.clone();
        let reported=Some(std::net::Ipv4Addr::new(172,20,4,8));
        for mode in [NetworkMode::Nat,NetworkMode::Bridged] {
            networks[0].mode=mode;
            let row=wire(&guest,&networks,reported);
            assert_eq!(row["ip"],"172.20.4.8");
            assert_eq!(row["addressSource"],"reported by the guest");
            assert!(wire(&guest,&networks,None)["ip"].is_null());
        }
        networks[0].mode=NetworkMode::Routed;
        assert_eq!(wire(&guest,&networks,reported)["ip"],json!(guest.ip));
    }
    #[test]
    fn trash_restore_recreates_the_engine_and_retained_checkpoint() {
        for keep in [false,true] {
            let (root,_)=remove_fixture(VmState::Off,false,keep,keep);
            let mut events=Events::open(&root.0).unwrap();
            let nets=trash_test_networks();
            let mut m=Machines::open(&root.0,Box::new(FakeEngine::default()),&nets,&mut events).unwrap();
            let list=m.route("GET",&["trash"],&Value::Null,&nets,&mut events).unwrap();
            let rows:Value=serde_json::from_slice(&list.body).unwrap();let key=rows[0]["key"].as_str().unwrap();
            assert!(rows[0]["restoreReason"].is_null());
            m.route("POST",&["trash",key,"restore"],&Value::Null,&nets,&mut events).unwrap();
            assert_eq!(m.inventory().len(),1);
            assert_eq!(m.engine.state("test-state").unwrap(),VmState::Off);
            assert_eq!(m.engine.list_snapshots("test-state").unwrap().len(),if keep {1} else {0});
            assert!(m.library.list_trash().unwrap().is_empty());
        }
    }
    #[test]
    fn trash_requires_matching_confirmation_and_verified_removal_before_restore() {
        let (root,r)=remove_fixture(VmState::Off,false,false,false);
        let mut events=Events::open(&root.0).unwrap();let nets=trash_test_networks();
        let mut m=Machines::open(&root.0,Box::new(FakeEngine::default()),&nets,&mut events).unwrap();
        let path=PathBuf::from(r["trashPath"].as_str().unwrap());
        fs::remove_file(path.join("removal-complete.json")).unwrap();
        let key=m.library.list_trash().unwrap()[0].key.clone();
        assert!(m.route("POST",&["trash",&key,"restore"],&Value::Null,&nets,&mut events).is_err());
        for (body, status) in [(json!({}),400),(json!({"confirmName":null}),400),
            (json!({"confirmName":false}),400),(json!({"confirmName":"other"}),409)] {
            let error = m.route("DELETE", &["trash",&key], &body, &nets, &mut events).err().unwrap();
            assert_eq!(error.status, status);
            assert!(error.message.contains("confirmName"));
            assert!(error.message.contains("State fixture"));
            assert!(path.exists());
        }
        assert!(m.route("DELETE",&["trash",&key],&json!({"confirmName":"State fixture","unexpected":true}),&nets,&mut events).is_err());
        assert!(path.exists());
        m.route("DELETE",&["trash",&key],&json!({"confirmName":"State fixture"}),&nets,&mut events).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn idle_worker_reconciles_guest_initiated_shutdown_without_a_client() {
        let root=Fixture::new();
        let library=Library::open_stable(root.0.join("library")).unwrap();
        let vm=guest(VmState::Running,false);
        library.create(&vm).unwrap();
        let mut fake=FakeEngine::default();
        fake.define(&vm).unwrap();
        let mut events=Events::open(&root.0).unwrap();
        let mut machines=Machines::open(&root.0,Box::new(fake),&[],&mut events).unwrap();
        machines.engine.shutdown(&vm.id).unwrap();
        machines.last_refresh=std::time::Instant::now()-std::time::Duration::from_secs(16);
        machines.tick(&mut events,false).unwrap();
        assert_eq!(machines.vm(&vm.id).unwrap().state,VmState::Off);
    }

    #[test]
    fn unknown_registration_without_completed_receipt_stays_in_library() {
        let root=Fixture::new();
        let library=Library::open_stable(root.0.join("library")).unwrap();
        let vm=guest(VmState::Off,false);
        library.create(&vm).unwrap();
        let mut events=Events::open(&root.0).unwrap();
        let mut machines=Machines::open(&root.0,Box::new(FakeEngine::default()),&[],&mut events).unwrap();
        let result=machines.route("DELETE",&["machines",&vm.id],&json!({}),&[],&mut events);
        assert!(matches!(result,Err(e) if e.status==409 && e.message.contains("registration")));
        assert!(library.bundle_path(&vm.id).unwrap().is_dir());
    }
}
