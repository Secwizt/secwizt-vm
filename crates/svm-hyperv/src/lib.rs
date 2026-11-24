#![forbid(unsafe_code)]
#![deny(warnings)]

mod checkpoint;
mod guest_exec;
mod guest_ssh;
mod guest_upload;
pub use guest_ssh::LinuxSshAccess;
mod runner;
pub use guest_exec::WindowsGuestCredentials;
mod scripts;
mod state;
pub use runner::{PsRunner, Script, WindowsPowerShell};
pub use state::{map_state, rgb565_to_rgba};

use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::{Component, Path, PathBuf}};
use svm_core::{
    capability::{Capability, CapabilitySet},
    engine::{EngineDriver, EngineError, EngineResult, GuestKeyReport, GuestKeys, Thumbnail},
    model::{EngineKind, GuestFamily, Network, NetworkMode, Snapshot, Vm, VmState},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Registration {
    name: String,
    notes: String,
    guid: String,
    state: i32,
    #[serde(default)]
    state_name: Option<String>,
    own_link: bool,
    #[serde(default)]
    external_guid: Option<String>,
    #[serde(default)]
    addresses: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RemovalPlan { pub guid:String, pub stamp:String, pub required:bool }

#[derive(Debug, serde::Serialize, Deserialize)]
pub struct RemovalReceipt { pub id:String, pub retained:Option<String>, pub bytes:Option<u64> }

#[derive(Debug, Deserialize)]
pub struct SwitchReceipt { pub guid: String, pub created: bool }

pub struct HyperV<R> {
    runner: R,
    networks: BTreeMap<String, Network>,
    bundles: BTreeMap<String, PathBuf>,
}

fn invalid(message: &str) -> EngineError { EngineError::Invalid(message.into()) }

fn check_id(id: &str) -> EngineResult<()> {
    let valid = id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && id.len() <= 80
        && id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c));
    if valid { Ok(()) } else { Err(invalid("Use an alphanumeric project ID with optional dashes, dots or underscores.")) }
}

fn decode<T: DeserializeOwned>(value: Value) -> EngineResult<T> {
    serde_json::from_value(value).map_err(|e| EngineError::Engine(format!("Unexpected Hyper-V response. {e}")))
}
fn internal(net: &Network) -> EngineResult<()> {
    if !matches!(net.mode, NetworkMode::Routed | NetworkMode::HostOnly | NetworkMode::Isolated | NetworkMode::LinkLocal) {
        return Err(invalid("Select a project internal network. External switches require the wired bridge workflow."));
    }
    check_id(&net.id)
}

impl<R: PsRunner> HyperV<R> {
    pub fn new(runner: R, networks: impl IntoIterator<Item = Network>) -> Self {
        Self { runner, networks: networks.into_iter().map(|n| (n.id.clone(), n)).collect(), bundles: BTreeMap::new() }
    }

    pub fn background(&self) -> Option<HyperV<Box<dyn PsRunner + Send>>> {
        Some(HyperV {
            runner: self.runner.background()?,
            networks: self.networks.clone(),
            bundles: self.bundles.clone(),
        })
    }

    /// Supply the existing bundle from the VM library; its path is independent of the display name.
    pub fn register_bundle(&mut self, id: &str, path: impl AsRef<Path>) -> EngineResult<()> {
        check_id(id)?;
        let path = path.as_ref();
        if !path.is_absolute() || path.components().any(|p| p == Component::ParentDir)
            || !path.extension().and_then(|s| s.to_str()).is_some_and(|s| s.eq_ignore_ascii_case("swvm")) {
            return Err(invalid("Provide the absolute path to the machine's library bundle."));
        }
        self.bundles.insert(id.into(), path.into());
        Ok(())
    }
    fn bundle(&self, id: &str) -> EngineResult<&Path> {
        self.bundles.get(id).map(PathBuf::as_path).ok_or_else(|| invalid("Register the machine's library bundle first."))
    }
    fn run(&self, request: Value) -> EngineResult<Value> {
        let script = match request["op"].as_str() {
            Some("define") => Script::Definition,
            Some("templateDisk" | "prepareLinkedDisk") => Script::LinkedDisk,
            Some("throwawayStart" | "throwawayRecover") => Script::Throwaway,
            Some("installerBootStatus" | "installerStart") => Script::InstallerBoot,
            Some("trashDetached" | "restoreRegistration" | "importRetained") => Script::Trash,
            Some("bridgeAdapters" | "resolveBridge") => Script::Bridge,
            Some("storage" | "setStorage" | "confirmStorage" | "capacity") => Script::Storage,
            Some("guestStatus" | "shutdown" | "restart" | "keys") => Script::Guest,
            Some("fileGuestService" | "setFileGuestService") => Script::FileGuestService,
            Some("host") => Script::Host,
            Some("snapshot") => Script::Checkpoint,
            Some("snapshots" | "configure" | "copyDisk" | "removePlan" | "remove") => Script::Service,
            _ => Script::Management,
        };
        if (request["op"] == "remove" && request["keepCopy"] == true) || request["op"] == "importRetained" {
            self.runner.run_retained(script, &request)
        } else { self.runner.run(script, &request) }
    }
    fn inspect(&self, id: &str, link: bool) -> EngineResult<Registration> {
        self.inspect_with_mac(id, link, None)
    }
    fn inspect_with_mac(&self, id: &str, link: bool, mac: Option<String>) -> EngineResult<Registration> {
        check_id(id)?;
        let reg: Registration = decode(self.run(json!({"op":"inspect","id":id,"probeLink":link,"addressMac":mac}))?)?;
        if reg.name != format!("svm-{id}") || reg.notes != format!("secwiz-vm:{id}") || reg.guid.is_empty() {
            return Err(invalid("The registration does not have the expected project name and ownership marker."));
        }
        Ok(reg)
    }
    /// Read power and the matching virtual NIC in one provider process.
    pub fn observe_guest(&self, vm: &Vm) -> EngineResult<(VmState, Option<std::net::Ipv4Addr>)> {
        let external = self.networks.get(&vm.net).is_some_and(|n| matches!(n.mode, NetworkMode::Nat | NetworkMode::Bridged));
        let mac = external.then(|| vm.mac.to_string().replace(':', ""));
        let reg = self.inspect_with_mac(&vm.id, false, mac)?;
        let state = state::from_native(reg.state, reg.state_name.as_deref())?;
        let reported = if external && state == VmState::Running {
            reg.addresses.iter().filter_map(|address| address.parse::<std::net::Ipv4Addr>().ok())
                .filter(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast())
                .min_by_key(|ip| ip.is_link_local())
        } else { None };
        Ok((state, reported))
    }
    /// Resolve the current project-owned registration before opening the native viewer.
    pub fn console_guid(&self, id: &str) -> EngineResult<String> {
        let guid = self.inspect(id, false)?.guid;
        let canonical = guid.len() == 36 && guid.bytes().enumerate().all(|(i, byte)| {
            if matches!(i, 8 | 13 | 18 | 23) { byte == b'-' } else { byte.is_ascii_hexdigit() }
        });
        if canonical && guid != "00000000-0000-0000-0000-000000000000" { Ok(guid) }
        else { Err(invalid("The engine returned an invalid console registration ID.")) }
    }
    fn action(&self, id: &str, op: &'static str, mut parameters: Value) -> EngineResult<Value> {
        let current = self.inspect(id, false)?;
        parameters["op"] = json!(op);
        parameters["id"] = json!(id);
        parameters["guid"] = json!(current.guid);
        self.run(parameters)
    }
    pub fn file_guest_service(&self, vm: &Vm, enabled: Option<bool>) -> EngineResult<Value> {
        if vm.engine != EngineKind::HyperV || !matches!(vm.family, GuestFamily::Linux | GuestFamily::Windows) {
            return Err(invalid("This machine has no supported Hyper-V file transfer connection."));
        }
        match enabled {
            Some(enabled) => self.action(&vm.id, "setFileGuestService", json!({"enabled":enabled})),
            None => self.action(&vm.id, "fileGuestService", json!({})),
        }
    }
    pub fn ensure_switch(&mut self, network: &Network) -> EngineResult<SwitchReceipt> {
        internal(network)?;
        let result = decode(self.run(json!({"op":"ensureSwitch","networkId":network.id}))?)?;
        self.networks.insert(network.id.clone(), network.clone());
        Ok(result)
    }
    pub fn remove_switch(&self, network: &Network) -> EngineResult<()> {
        self.remove_switch_if_same(network, None)
    }
    /// The receipt is useful for cleanup when a switch might have been recreated.
    pub fn remove_switch_if_same(&self, network: &Network, guid: Option<&str>) -> EngineResult<()> {
        internal(network)?;
        self.run(json!({"op":"removeSwitch","networkId":network.id,"guid":guid}))?;
        Ok(())
    }
    pub fn list_our_switches(&self) -> EngineResult<Vec<String>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Entry { name: String, switch_type: i32, notes: Option<String> }
        let reply = self.run(json!({"op":"listSwitches"}))?;
        let entries: Vec<Value> = match reply {
            Value::Null => Vec::new(), Value::Array(items) => items, item => vec![item],
        };
        let mut names = Vec::new();
        for item in entries {
            let sw: Entry = decode(item)?;
            if let Some(id) = sw.name.strip_prefix("SVM-") {
                if sw.switch_type == 1 && check_id(id).is_ok()
                    && sw.notes == Some(format!("secwiz-switch:{id}")) {
                    names.push(sw.name);
                }
            }
        }
        Ok(names)
    }
    pub fn set_networks(&mut self, networks: &[Network]) {
        self.networks = networks.iter().cloned().map(|n| (n.id.clone(), n)).collect();
    }
    pub fn host_summary(&self) -> EngineResult<Value> {
        self.run(json!({"op":"host"}))
    }
    fn guest_power(&self, id: &str, operation: &'static str, expected: &str) -> EngineResult<()> {
        let guid=self.inspect(id,false)?.guid;
        match self.run(json!({"op":operation,"id":id,"guid":guid})) {
            Ok(reply) if reply["power"] == expected => Ok(()),
            Ok(reply) if reply["power"] == "timeout" => Err(EngineError::GuestPowerTimeout),
            Err(EngineError::Timeout { .. }) => Err(EngineError::GuestPowerTimeout),
            Err(error) => Err(error),
            Ok(_) => Err(invalid("Hyper-V returned an unrecognized response to the guest power request.")),
        }
    }
    pub fn bridge_adapters(&self)->EngineResult<Value> { self.run(json!({"op":"bridgeAdapters"})) }
    pub fn resolve_bridge(&self,n:&Network)->EngineResult<Value> {
        let b=n.bridge.as_ref().ok_or_else(||invalid("Select a wired bridge."))?;
        self.run(json!({"op":"resolveBridge","networkId":n.id,"adapterId":b.adapter_id,"switchGuid":b.switch_guid}))
    }
    pub fn library_capacity(&self, path: &Path) -> EngineResult<Value> {
        self.run(json!({"op":"capacity","path":path}))
    }
    pub fn storage(&self, id: &str) -> EngineResult<Value> {
        self.action(id, "storage", json!({}))
    }
    /// Eligibility is advisory in the UI. The native start rechecks it immediately before power-on.
    pub fn installer_request(&self, id: &str, start: bool, press_key: Option<bool>) -> EngineResult<Value> {
        let op = if start { "installerStart" } else { "installerBootStatus" };
        self.action(id, op, json!({"bundle":self.bundle(id)?, "pressKeyAtBoot":press_key}))
    }
    pub fn set_storage(&self, id: &str, field: &str, value: &Value) -> EngineResult<Value> {
        #[derive(Deserialize)]
        struct Readback { confirmed: bool, storage: Value }

        let guid = self.inspect(id, false)?.guid;
        let mut request = json!({"op":"setStorage", "id":id, "guid":guid, "edit":field, "value":value});
        self.run(request.clone())?;

        // The provider can retain the old DVD path in the process that set it.
        // Each verification opens a fresh PowerShell process and pins the original VM registration.
        request["op"] = json!("confirmStorage");
        for attempt in 0..3 {
            let state: Readback = decode(self.run(request.clone())?)?;
            if state.confirmed { return Ok(state.storage); }
            if attempt < 2 { std::thread::sleep(std::time::Duration::from_millis(150)); }
        }
        let target = if field == "bootFirst" { "selected first boot device" } else { "requested DVD media" };
        Err(invalid(&format!("Hyper-V did not confirm the {target}. Refresh Storage before retrying.")))
    }
    pub fn configure_offline(&self, vm: &Vm) -> EngineResult<()> {
        let network = self.networks.get(&vm.net).ok_or_else(|| invalid("The selected network is unavailable."))?;
        self.action(&vm.id, "configure", json!({"vcpu":vm.vcpu,"ramGb":vm.ram_gb,
            "networkId":network.id,"networkMode":network.mode,"bridge":network.bridge})).map(drop)
    }
    fn definition_request(&self, vm: &Vm) -> EngineResult<Value> {
        check_id(&vm.id)?;
        if vm.engine != EngineKind::HyperV || vm.vcpu == 0 || vm.ram_gb == 0 || !vm.mac.is_station() {
            return Err(invalid("A Hyper-V definition needs a valid MAC, memory and processor count."));
        }
        if vm.disk_gb == Some(0) || (vm.disk_gb.is_some() && vm.disk_path.is_some()) {
            return Err(invalid("Choose a positive new disk size or an existing VHDX."));
        }
        let network = self.networks.get(&vm.net).ok_or_else(|| invalid("The machine's network definition is missing."))?;
        if network.mode==NetworkMode::Bridged {
            if network.bridge.as_ref().and_then(|b|b.switch_guid.as_ref()).is_none() {return Err(invalid("Finish bridge setup and verify the switch before attaching a guest."));}
        } else if network.mode != NetworkMode::Nat { internal(network)?; }
        let template = match vm.family {
            GuestFamily::Windows => Some("MicrosoftWindows"),
            GuestFamily::Linux => Some("MicrosoftUEFICertificateAuthority"),
            _ => None,
        };
        let secure = vm.secure_boot.unwrap_or(template.is_some());
        if secure && template.is_none() {
            return Err(invalid("This guest family has no configured Secure Boot template."));
        }
        let saved_order=match svm_core::read_json::<String>(&self.bundle(&vm.id)?.join("boot-order.json")) {
            Ok(order) if matches!(order.as_str(),"image"|"disk")=>Some(order),
            Err(svm_core::Error::Io(e)) if e.kind()==std::io::ErrorKind::NotFound=>None,
            _=>return Err(invalid("The saved boot order is unreadable.")),
        };
        let mut request=json!({
            "op":"define", "id":vm.id, "displayName":vm.name, "bundle":self.bundle(&vm.id)?,
            "vcpu":vm.vcpu, "ramGb":vm.ram_gb, "mac":vm.mac.to_string().replace(':',""),
            "networkId":network.id, "networkMode":network.mode,
            "diskGb":vm.disk_gb, "diskPath":vm.disk_path, "isoPath":vm.iso_path,
            "secureBoot":secure, "template":template, "tpm":vm.tpm.unwrap_or(false),
        });
        if vm.family == GuestFamily::Windows && vm.disk_gb.is_some() { request["windowsInstaller"] = json!(true); }
        if let Some(order)=saved_order {request["bootFirst"]=json!(order);}
        if let Some(bridge)=&network.bridge {request["bridge"]=json!(bridge);}
        Ok(request)
    }

    pub fn start_with_parents(&self, id: &str, parents: &[PathBuf]) -> EngineResult<()> {
        self.action(id, "start", json!({ "bundle": self.bundles.get(id), "parents": parents })).map(drop)
    }

    pub fn start_throwaway(&self, vm: &Vm, parents: &[PathBuf]) -> EngineResult<()> {
        if vm.engine != EngineKind::HyperV || !vm.throwaway || vm.state != VmState::Off
            || vm.template.is_some() || vm.tpm == Some(true)
        {
            return Err(invalid("Throwaway mode requires a stopped Hyper-V guest without a template or virtual TPM."));
        }
        let template = vm.linked_from.as_deref().map(|id| self.template_disk(id)).transpose()?;
        let started = self.action(&vm.id, "throwawayStart", json!({
            "bundle": self.bundle(&vm.id)?, "templateDisk": template, "parents": parents,
        })).and_then(|reply| if reply["started"] == true { Ok(()) } else {
            Err(invalid("Hyper-V did not confirm the throwaway start."))
        });
        // The script rolls back by itself, but Hyper-V cannot attach the read-only base there.
        if started.is_err() { let _ = self.recover_throwaway(&vm.id); }
        started
    }

    /// While throwaway mode is on, the persistent VHDX stays read-only. Hyper-V then refuses to run
    /// the guest on it from any other tool, and the temporary disk still uses it as its parent.
    pub fn protect_throwaway_base(&self, id: &str, enabled: bool) -> EngineResult<()> {
        let bundle = self.bundle(id)?;
        let base = bundle.join("system.vhdx");
        // This marker records that throwaway mode set the flag, so a flag set by anyone else (an
        // originally read-only disk, an unsealed template) is never lifted.
        let marker = bundle.join("throwaway-protected.json");
        let failed = |error: std::io::Error| invalid(&format!("The machine disk's read-only setting could not be changed. {error}"));
        // Only this machine's own record counts; a stale or damaged one does not. A record that can't
        // be read right now (a scanner holding it) proves nothing either way, so stop and let the
        // caller retry instead of guessing.
        let owned = if marker.try_exists().map_err(failed)? {
            match svm_core::read_json::<String>(&marker) {
                Ok(owner) => owner == id,
                Err(svm_core::Error::Io(error)) => return Err(failed(error)),
                Err(_) => false,
            }
        } else { false };
        if !enabled && !owned { return Ok(()); }
        let metadata = std::fs::symlink_metadata(&base).map_err(failed)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 { return Err(invalid("The machine disk cannot be a link.")); }
        }
        if !metadata.is_file() { return Err(invalid("The machine disk must be the bundle's own system.vhdx.")); }
        let mut permissions = metadata.permissions();
        if enabled && permissions.readonly() { return Ok(()); }
        if enabled && !owned {
            svm_core::write_json(&marker, &id).map_err(|_| invalid("The throwaway protection record could not be saved."))?;
        }
        if permissions.readonly() != enabled {
            permissions.set_readonly(enabled);
            std::fs::set_permissions(&base, permissions).map_err(failed)?;
        }
        if !enabled { std::fs::remove_file(&marker).map_err(failed)?; }
        Ok(())
    }

    pub fn recover_throwaway(&self, id: &str) -> EngineResult<bool> {
        let bundle = self.bundle(id)?;
        match std::fs::symlink_metadata(bundle.join("hyperv-throwaway.json")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(invalid(&format!("The Hyper-V throwaway record could not be inspected. {error}"))),
            Ok(_) => {}
        }
        // Hyper-V cannot attach a read-only disk. The script validates everything first, lifts the
        // flag only for the reattach, and sets it again before it retires the record.
        let reply = self.action(id, "throwawayRecover", json!({ "bundle": bundle }));
        if reply.is_err() {
            // A record exists only for a throwaway run, whose original disk must stay read-only, and a
            // script that died in the middle of the swap could not put the flag back itself.
            let _ = self.protect_throwaway_base(id, true);
        }
        decode(reply?["recovered"].clone())
    }

    /// Throwaway mode protects and swaps `bundle\system.vhdx`, so that must be the machine's only
    /// attached disk. A machine restored from a retained export runs on copies elsewhere in its bundle.
    pub fn verify_throwaway_disk(&self, id: &str) -> EngineResult<()> {
        self.action(id, "throwawayDisk", json!({ "bundle": self.bundle(id)? })).map(|_| ())
    }

    /// Locate the exact native disk of a stopped standalone template candidate.
    pub fn template_disk(&self, id: &str) -> EngineResult<PathBuf> {
        let reply = self.action(id, "templateDisk", json!({ "bundle": self.bundle(id)? }))?;
        decode(reply)
    }

    /// Create and attach a private child of the caller's verified, held template.
    pub fn create_linked_clone(&self, source: &Vm, target: &Vm, parent: &Path) -> EngineResult<()> {
        if source.engine != EngineKind::HyperV || source.id.eq_ignore_ascii_case(&target.id)
            || target.state != VmState::Off || target.disk_gb.is_some()
            || target.disk_path.as_deref() != Some(Path::new("system.vhdx"))
            || target.iso_path.is_some() || target.tpm == Some(true)
            || !parent.is_absolute() || parent.components().any(|part| part == Component::ParentDir)
        {
            return Err(invalid("A linked Hyper-V clone needs a fresh identity and its own system.vhdx."));
        }

        let mut definition = self.definition_request(target)?;
        let owner = self.inspect(&source.id, false)?;
        let reply = self.run(json!({
            "op": "prepareLinkedDisk", "id": target.id, "bundle": self.bundle(&target.id)?,
            "source": { "id": source.id, "guid": owner.guid, "bundle": self.bundle(&source.id)?, "parent": parent },
        }))?;
        if reply["created"] != true { return Err(invalid("Hyper-V could not confirm the linked disk was created.")); }

        definition["linkedParent"] = json!(parent);
        self.run(definition).map(drop)
    }

    pub fn copy_disk(&self, source: &str, target: &str) -> EngineResult<bool> {
        let reply = self.action(source, "copyDisk", json!({"bundle":self.bundle(source)?,
            "targetId":target,"targetBundle":self.bundle(target)?}))?;
        decode(reply["copied"].clone())
    }
    pub fn trash_detached(&self,id:&str,bundle:&Path)->EngineResult<()> {
        check_id(id)?;
        self.run(json!({"op":"trashDetached","id":id,"bundle":bundle})).map(drop)
    }
    pub fn restored_registration(&self,id:&str)->EngineResult<bool> {
        decode(self.run(json!({"op":"restoreRegistration","id":id,"bundle":self.bundle(id)?}))?)
    }
    pub fn import_retained(&self,id:&str,relative:&str)->EngineResult<()> {
        self.run(json!({"op":"importRetained","id":id,"bundle":self.bundle(id)?,"retained":relative})).map(drop)
    }
    pub fn removal_plan(&self,id:&str)->EngineResult<RemovalPlan> {
        decode(self.action(id,"removePlan",json!({"bundle":self.bundle(id)?}))?)
    }
    pub fn finish_removal(&self,id:&str,plan:&RemovalPlan,keep_copy:bool)->EngineResult<RemovalReceipt> {
        let receipt:RemovalReceipt=decode(self.run(json!({"op":"remove","id":id,"guid":plan.guid,"stamp":plan.stamp,
            "bundle":self.bundle(id)?,"keepCopy":keep_copy || plan.required}))?)?;
        if receipt.id!=id {return Err(invalid("The removal receipt belongs to a different machine."));}
        Ok(receipt)
    }
    pub fn remove_with_copy(&mut self,id:&str,keep_copy:bool)->EngineResult<()> {
        self.action(id,"remove",json!({"bundle":self.bundle(id)?,"keepCopy":keep_copy})).map(drop)
    }
    pub fn default_switch_info(&self) -> EngineResult<Value> {
        self.run(json!({"op":"defaultSwitchInfo"}))
    }
}

impl<R: PsRunner> EngineDriver for HyperV<R> {
    fn capabilities(&self, vm: &Vm) -> CapabilitySet {
        let reg = match self.inspect(&vm.id, true) {
            Ok(info) => info,
            Err(error) => return CapabilitySet::unavailable(&error.to_string()),
        };
        use Capability::*;
        let mut caps = CapabilitySet::unavailable("This machine has no adapter on an owned internal switch.");
        for cap in [Start, Stop, Pause, Resume, Snapshot, SnapshotWithMemory, Accelerated, Thumbnail, Console, Clone, Delete, RevertSnapshot, DeleteSnapshot] {
            caps.allow(cap);
        }
        let running = reg.state_name.as_deref().map_or(reg.state == 2, |name|name == "Running");
        let status = if running {
            self.run(json!({"op":"guestStatus","id":vm.id,"guid":reg.guid}))
        } else { Err(invalid("Start or resume the machine before using guest controls.")) };
        for (cap, key) in [(Shutdown,"powerReason"),(Restart,"powerReason"),(SendKeys,"keyReason")] {
            match &status {
                Ok(reply) => match reply.get(key) {
                    Some(Value::Null) => caps.allow(cap),
                    Some(Value::String(reason)) => caps.deny(cap,reason),
                    _ => caps.deny(cap,"Hyper-V did not confirm the guest control is available."),
                },
                Err(error) => caps.deny(cap,&error.to_string()),
            }
        }
        // Msvm_ComputerSystem::EnhancedSessionModeState is provider-reported availability.
        let enhanced_session = status.as_ref().ok().and_then(|reply| reply["enhancedSessionModeState"].as_u64());
        match enhanced_session {
            Some(2) => caps.allow(EnhancedSession),
            Some(3) => caps.deny(EnhancedSession, "Hyper-V does not allow Enhanced Session for this machine."),
            Some(6) => caps.deny(EnhancedSession, "Enhanced Session is currently unavailable in this guest."),
            _ if !running => caps.deny(EnhancedSession, "Start or resume this guest to check Enhanced Session."),
            _ => caps.deny(EnhancedSession, "Hyper-V could not confirm this guest’s Enhanced Session availability."),
        }
        let bridged=self.networks.get(&vm.net).and_then(|n|n.bridge.as_ref()).and_then(|b|b.switch_guid.as_ref())
            .zip(reg.external_guid.as_ref()).is_some_and(|(bound,observed)|bound.eq_ignore_ascii_case(observed));
        if reg.own_link || bridged { caps.allow(OwnLanAddress); }
        caps.deny(UsbPassthrough, "The Hyper-V engine has no USB passthrough.");
        caps
    }
    fn define(&mut self, vm: &Vm) -> EngineResult<()> {
        self.run(self.definition_request(vm)?).map(drop)
    }
    fn start(&mut self, id: &str) -> EngineResult<()> {
        self.start_with_parents(id, &[])
    }
    fn stop(&mut self, id: &str) -> EngineResult<()> { self.action(id, "stop", json!({})).map(drop) }
    fn shutdown(&mut self, id:&str) -> EngineResult<()> { self.guest_power(id,"shutdown","off") }
    fn restart(&mut self, id:&str) -> EngineResult<()> { self.guest_power(id,"restart","accepted") }
    fn send_keys(&mut self, id:&str, keys:&GuestKeys) -> EngineResult<GuestKeyReport> {
        let reply: GuestKeyReport = decode(self.action(id,"keys",json!({"strokes":keys.strokes()}))?)?;
        if reply.sent > keys.strokes().len() || (reply.error.is_none() && reply.sent != keys.strokes().len()) {
            return Err(invalid("Hyper-V returned an incomplete key count. Check the machine before sending more keys."));
        }
        Ok(reply)
    }
    fn pause(&mut self, id: &str) -> EngineResult<()> { self.action(id, "pause", json!({})).map(drop) }
    fn resume(&mut self, id: &str) -> EngineResult<()> { self.action(id, "resume", json!({})).map(drop) }
    fn snapshot(&mut self, id: &str, name: &str, with_memory: bool) -> EngineResult<Snapshot> {
        if name.trim().is_empty() { return Err(invalid("A checkpoint needs a name.")); }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Checkpoint { id: String, name: String, parent_snapshot_id: Option<String>, with_memory: Option<bool>, consistency: Option<svm_core::model::SnapshotConsistency> }
        let labels = self.checkpoint_labels(id)?;
        let row: Checkpoint = decode(self.action(id, "snapshot", json!({"label":name,"withMemory":with_memory}))?)?;
        let snapshot = Snapshot { id:row.id, name:row.name, parent:row.parent_snapshot_id,
            with_memory:row.with_memory.unwrap_or(with_memory), consistency:row.consistency };
        self.record_checkpoint_label(id, &snapshot, labels)?;
        Ok(snapshot)
    }
    fn list_snapshots(&mut self,id:&str)->EngineResult<Vec<Snapshot>> {
        let value=self.action(id,"snapshots",json!({}))?;
        let mut snapshots: Vec<Snapshot> = decode(value["items"].clone())?;
        match self.checkpoint_labels(id) {
            Ok(labels) => for row in &mut snapshots {
                if let Some(label) = labels.get(&row.id) { row.consistency = Some(*label); }
            },
            Err(_) => for row in &mut snapshots {
                row.consistency = Some(svm_core::model::SnapshotConsistency::Unverified);
            },
        }
        Ok(snapshots)
    }
    fn revert(&mut self, id: &str, snapshot_id: &str) -> EngineResult<()> {
        self.action(id, "revert", json!({"snapshotId":snapshot_id})).map(drop)
    }
    fn delete_snapshot(&mut self, id: &str, snapshot_id: &str) -> EngineResult<()> {
        self.action(id, "deleteSnapshot", json!({"snapshotId":snapshot_id})).map(drop)
    }
    fn remove(&mut self, id: &str) -> EngineResult<()> {
        self.remove_with_copy(id,false)
    }
    fn state(&mut self, id: &str) -> EngineResult<VmState> {
        let reg = self.inspect(id, false)?;
        state::from_native(reg.state, reg.state_name.as_deref())
    }
    fn thumbnail(&mut self, id: &str) -> EngineResult<Thumbnail> {
        #[derive(Deserialize)]
        struct Frame { width: u16, height: u16, pixels: String }
        let value = self.action(id, "thumbnail", json!({}))?;
        match value["returnValue"].as_u64() {
            Some(0) => {}
            Some(32775) => return Err(invalid("The machine has no active display.")),
            other => return Err(EngineError::Engine(format!("Hyper-V could not capture the thumbnail (status {other:?})."))),
        }
        let frame: Frame = decode(value)?;
        state::decode_frame(frame.width, frame.height, &frame.pixels)
    }
}

#[cfg(test)]
mod tests;
