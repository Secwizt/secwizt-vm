use super::*;
use svm_core::model::PortForward;

#[test]
fn a_failed_qemu_import_publish_leaves_purgeable_trash() {
    let home = std::env::temp_dir().join(next_id());
    let mut service = crate::Service::open(&home, 0, Box::<FakeEngine>::default(), Box::<crate::networks::FakeSwitches>::default()).unwrap();
    let machines = &mut service.worker.machines;
    let vm: Vm = serde_json::from_value(json!({
        "id":"qemu-import", "name":"QEMU import fixture", "os":"Linux", "family":"linux",
        "engine":"QEMU", "accel":true, "state":"off", "vcpu":1, "ramGb":2, "net":"nat",
        "ip":"192.0.2.10", "mac":"02:77:00:00:00:10", "dns":"qemu-import.vm.lan",
        "diskPath":"system.qcow2"
    })).unwrap();
    let bundle = machines.stage(&vm).unwrap();
    assert!(machines.publish_imported_disk(&vm, &bundle, &home.join("missing.qcow2")).is_err());
    assert!(machines.vm(&vm.id).is_err());
    let trash = machines.library.list_trash().unwrap();
    assert_eq!(trash.len(), 1);
    let receipt: RemovalReceipt = svm_core::read_json(&trash[0].path.join("removal-complete.json")).unwrap();
    assert_eq!(receipt.id, vm.id);
    assert!(machines.delete_trash(&trash[0].key, &json!({"confirmName":vm.name}), &mut service.worker.events).is_ok());
    assert!(machines.library.list_trash().unwrap().is_empty());
    drop(service);
    fs::remove_dir_all(home).unwrap();
}

const MAX_VHDX_GIB: u32 = 64 * 1024;

fn disk_limit(capacity:&Value)->Option<u32> {
    capacity["freeBytes"].as_u64().map(|bytes|(bytes >> 30).min(u64::from(MAX_VHDX_GIB)) as u32)
}

fn open_standalone_disk(path: &Path) -> Result<(PathBuf, fs::File), ApiError> {
    let path = checked_media(path, "vhdx")?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x0020_0000);
    }
    let mut source = options.open(&path).map_err(io_error)?;
    svm_qemu::check_standalone_vhdx(&mut source).map_err(|e| bad(e.to_string()))?;
    Ok((path, source))
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Create {
    name:String, id:Option<String>, os:Option<String>, family:Option<GuestFamily>, engine:Option<EngineKind>, net:Option<String>,
    #[serde(default,deserialize_with="explicit_create_architecture")]
    architecture:Option<GuestArchitecture>,
    vcpu:Option<u16>,ram_gb:Option<u32>,disk_gb:Option<u32>,disk_path:Option<PathBuf>,
    iso_path:Option<PathBuf>,secure_boot:Option<bool>,tpm:Option<bool>,catalog_id:Option<String>,
}

fn explicit_create_architecture<'de,D:serde::Deserializer<'de>>(input:D)->Result<Option<GuestArchitecture>,D::Error> {
    GuestArchitecture::deserialize(input).map(Some)
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Edit {name:Option<String>,os:Option<String>,vcpu:Option<u16>,ram_gb:Option<u32>,net:Option<String>,ip:Option<std::net::Ipv4Addr>,share_clipboard:Option<bool>,port_forwards:Option<Vec<PortForward>>,throwaway:Option<bool>,isolated:Option<bool>}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Capture {name:Option<String>,with_memory:Option<bool>}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct PacketCapture {
    #[serde(rename = "limitMiB")]
    limit_mib: Option<u16>,
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct StartOptions {press_key_at_boot:Option<bool>}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloneGuest {name:String,id:Option<String>}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Removal {#[serde(default)] keep_copy:bool}

enum RemovalWork {
    AlreadyRemoved(RemovalReceipt),
    Unregister(RemovalPlan, bool),
}


enum CheckpointWork {
    Create { name: String, with_memory: bool },
    Apply(String),
    Delete(String),
}

enum CheckpointResult {
    Created(Snapshot),
    Applied,
    Deleted(String),
}

impl CheckpointWork {
    fn create(body: &Value) -> Result<Self, ApiError> {
        let request: Capture = parsed(body)?;
        let name = request.name.unwrap_or_else(|| "Checkpoint".to_owned());
        if name.trim().is_empty() || name.len()>180 { return Err(bad("Use a checkpoint name of one to 180 bytes.")); }
        Ok(Self::Create { name, with_memory: request.with_memory.unwrap_or(false) })
    }

    fn run(self, id: &str, driver: &mut dyn MachineEngine) -> Result<CheckpointResult, ApiError> {
        match self {
            Self::Create { name, with_memory } => driver.snapshot(id, &name, with_memory).map(CheckpointResult::Created),
            Self::Apply(snapshot) => driver.revert(id, &snapshot).map(|()| CheckpointResult::Applied),
            Self::Delete(snapshot) => driver.delete_snapshot(id, &snapshot).map(|()| CheckpointResult::Deleted(snapshot)),
        }.map_err(engine)
    }
}

impl Machines {
    fn prepare_checkpoint(
        &mut self, method: &str, parts: &[&str], body: &Value, networks: &[Network], events: &mut Events,
    ) -> Result<Option<BackgroundTask>, ApiError> {
        let (id, native_edit) = match (method, parts) {
            ("POST", ["machines", id, "snapshots"]) => (*id, None),
            ("POST", ["machines", id, "snapshots", snapshot, "revert"]) => (*id, Some(CheckpointWork::Apply((*snapshot).to_owned()))),
            ("DELETE", ["machines", id, "snapshots", snapshot]) => (*id, Some(CheckpointWork::Delete((*snapshot).to_owned()))),
            _ => return Ok(None),
        };
        let vm = self.vm(id)?;
        self.check_template_checkpoint(&vm)?;
        let qemu_checkpoint = vm.engine == EngineKind::Qemu;
        if !qemu_checkpoint && native_edit.is_some() { return Ok(None); }
        let mut driver: Box<dyn MachineEngine> = if qemu_checkpoint {
            Box::new(self.qemu.clone())
        } else if vm.engine == EngineKind::HyperV {
            let Some(driver) = self.engine.background_driver() else { return Ok(None); };
            driver
        } else { return Ok(None); };
        if self.background_busy() || self.converting() {
            return Err(refused("Wait for the current machine or disk operation to finish."));
        }
        self.engine.set_networks(networks);
        driver.set_networks(networks);
        self.refresh_after(events, Some(id), None)?;
        self.available(id)?;
        let work = match native_edit { Some(edit) => edit, None => CheckpointWork::create(body)? };
        let id = id.to_owned();
        let machine = id.clone();
        let run = move || -> MachineCompletion {
            let result = work.run(&id, &mut *driver);
            Box::new(move |machines, networks, events| machines.finish_checkpoint(&id, result?, networks, events))
        };
        Ok(Some(BackgroundTask {machines:vec![machine], reserved:None, hyperv:!qemu_checkpoint, qemu_checkpoint, catalog_io:false, accepted:None, run:Box::new(run)}))
    }

    fn finish_checkpoint(&mut self, id: &str, result: CheckpointResult, networks: &[Network], events: &mut Events) -> Result<Reply, ApiError> {
        match result {
            CheckpointResult::Created(snapshot) => {
                self.refresh_snapshot_count(&mut self.vm(id)?)?;
                events.record("snapshot taken",&format!("A checkpoint was created on {id}."))?;
                Ok(Reply::created(json!(snapshot)))
            }
            CheckpointResult::Applied => {
                self.refresh_after(events, Some(id), Some((id,None)))?;
                events.record("reverted",&format!("A checkpoint was restored on {id}."))?;
                Ok(Reply::json(self.published(&self.vm(id)?,networks)))
            }
            CheckpointResult::Deleted(snapshot) => {
                self.refresh_snapshot_count(&mut self.vm(id)?)?;
                events.record("snapshot deleted",&format!("A checkpoint was deleted on {id}."))?;
                Ok(Reply::json(json!({"id":snapshot,"deleted":true})))
            }
        }
    }

    pub(crate) fn prepare_background(
        &mut self, request: &crate::http::Request, networks: &[Network], events: &mut Events,
    ) -> Result<Option<BackgroundTask>, ApiError> {
        let Some(path) = request.target.strip_prefix("/v1/") else {
            return Ok(None);
        };
        self.guard_backup_request(&request.method, &path.split('?').next().unwrap_or(path).split('/').collect::<Vec<_>>())?;
        if path.contains('?') {
            return Ok(None);
        }
        let parts: Vec<_> = path.split('/').collect();
        if let Some(task) = self.prepare_ready_launch(&request.method, &parts, &request.body)? { return Ok(Some(task)); }
        if matches!(parts.as_slice(), ["machines", _, "files", ..]) { return Ok(None); }
        if request.method == "POST" && parts.as_slice() == ["machines"] {
            if let Some(task) = self.prepare_catalog_creation(&request.body, networks)? { return Ok(Some(task)); }
        }
        if matches!(parts.as_slice(), ["machines", id, ..] if self.file_transfer_owns(id))
            && (request.method != "GET" || matches!(parts.as_slice(), ["machines", _, "agent"])) {
            return Err(refused("Wait for the file transfer on this machine or cancel it first."));
        }
        if let Some(app) = self.prepare_app(&request.method, &parts, &request.body, networks, events)? {
            return Ok(Some(app));
        }
        if let Some(agent) = self.prepare_agent(&request.method, &parts, &request.body, events)? {
            return Ok(Some(agent));
        }
        if let Some(checkpoint) = self.prepare_checkpoint(&request.method, &parts, &request.body, networks, events)? {
            return Ok(Some(checkpoint));
        }
        match (request.method.as_str(), parts.as_slice()) {
            ("POST", ["machines", id, "clone"]) | ("DELETE", ["machines", id]) => {
                if self.vm(id)?.engine != EngineKind::HyperV {
                    return Ok(None);
                }
            }
            ("POST", ["trash", _, "restore"]) => {}
            _ => return Ok(None),
        }
        let mut driver = match self.engine.background_driver() {
            Some(driver) => driver,
            None => return Ok(None),
        };
        if self.background_busy() || self.converting() {
            return Err(refused("Wait for the current machine or disk operation to finish."));
        }
        self.engine.set_networks(networks);
        driver.set_networks(networks);
        let task = match (request.method.as_str(), parts.as_slice()) {
            ("POST", ["machines", id, "clone"]) => {
                self.refresh_after(events, Some(id), None)?;
                self.prepare_clone(id, parsed(&request.body)?, networks)?
            }
            ("DELETE", ["machines", id]) => {
                self.refresh_after(events, Some(id), None)?;
                self.prepare_remove(id, parsed(&request.body)?, events)?
            }
            ("POST", ["trash", key, "restore"]) => self.prepare_restore(key, networks)?,
            _ => return Ok(None),
        };
        Ok(Some(task.bind(driver)))
    }

    pub fn route(&mut self,method:&str,parts:&[&str],body:&Value,networks:&[Network],events:&mut Events)->Result<Reply,ApiError> {
        self.engine.set_networks(networks);
        if method!="GET" && matches!(parts,["machines",id,..] if self.transfers.owns_machine(id)) {
            return Err(refused("Wait for the disk export to finish, or cancel it first."));
        }
        if matches!(parts,["host" | "guard"] | ["machines",_,"capabilities" | "start" | "resume"] | ["machines",_,"snapshots",_,"revert"]) {
            if let Some(path)=&self.guard_path {self.guard=load_guard(path)?;}
        }
        // Only host-wide admission and inventory requests need observations from other engines.
        if let ["machines",id, ..]=parts {
            let admission=self.guard.enabled && matches!(parts,["machines",_,"start"|"resume"]|["machines",_,"snapshots",_,"revert"]);
            let cached=method=="GET" && matches!(parts,["machines",_,"capabilities"|"thumbnail"|"console"|"snapshots"]);
            if admission { self.refresh(events)?; }
            else if !cached || self.last_refresh.elapsed().as_secs()>=15 { self.refresh_after(events,Some(id),None)?; }
        } else if !(method=="POST" && parts==["machines"]) && !matches!(parts,["trash",..]) {
            self.refresh(events)?;
        }
        match (method,parts) {
            ("GET",["host"])|("GET",["guard"])=>{
                let profile=self.host.as_ref().ok();
                let allocated=self.allocated();
                let memory:u64=allocated.iter().filter(|v|active(v.state)).map(|v|u64::from(v.ram_gb)).sum();
                let threads:u64=allocated.iter().filter(|v|v.state==VmState::Running).map(|v|u64::from(v.vcpu)).sum();
                let mut value=profile.map(|p|json!(p.info)).unwrap_or_else(||json!({}));
                if let Some(settings)=json!(self.guard).as_object() {
                    for (key,setting) in settings {value[key]=setting.clone();}
                }
                value["name"]=json!("This host");value["cpu"]=json!(profile.map(|p|&p.cpu));
                value["protectionAvailable"]=json!(self.guard_path.is_some());
                value["threadBudget"]=json!(profile.and_then(|p|if self.guard.enabled {
                    thread_budget(&p.info,self.guard.budget_pct).ok()
                } else {Some(p.info.logical)}));
                value["usedThreads"]=json!(threads); value["usedRamGb"]=json!(memory);value["placement"]=json!("advisory");
                if parts == ["host"] {
                    let capacity = self.library_capacity().unwrap_or(Value::Null);
                    value["freeRamGb"] = capacity["freeRamGb"].clone();
                    value["libraryFreeBytes"] = capacity["freeBytes"].clone();
                    value["maxDiskGb"] = json!(disk_limit(&capacity));
                    let available = if capacity["tpmCommands"] == false { Some(false) } else { self.tpm_verified };
                    let reason = match available {
                        Some(true) => "This service account has successfully enabled a local virtual TPM.",
                        Some(false) => "The virtual TPM commands or local key protector permission are unavailable. Choose Windows 10.",
                        None => "Local key protector permission is checked when creating a Windows 11 machine. Windows 10 can be created without a virtual TPM.",
                    };
                    value["tpm"] = json!({"available":available,"reason":reason});
                }
                Ok(Reply::json(value))
            }
            ("PUT",["guard"])=>self.update_guard(body,events),
            ("GET",["trash"])=>self.trash_list(),
            ("POST",["trash",key,"restore"])=>self.restore_trash(key,networks,events),
            ("DELETE",["trash",key])=>self.delete_trash(key,body,events),
            ("GET",["machines"])=>Ok(Reply::json(Value::Array(self.inventory.iter().map(|v|self.published(v,networks)).collect()))),
            ("POST",["machines"])=>self.create(parsed(body)?,networks,events,None),
            ("GET",["machines",id])=>Ok(Reply::json(self.published(&self.vm(id)?,networks))),
            ("PATCH",["machines",id])=>self.update(id,parsed(body)?,networks,events),
            ("DELETE",["machines",id])=>self.remove_guest(id,parsed(body)?,events),
            ("POST",["machines",id,"clone"])=>self.clone_guest(id,parsed(body)?,networks,events),
            ("POST", ["machines", id, "template"]) => self.seal_template(id, networks, events),
            ("POST", ["machines", id, "default-login"]) => self.confirm_default_login(id, body, networks, events),
            ("DELETE", ["machines", id, "template"]) => self.unseal_template(id, networks, events),
            ("POST", ["machines", id, "linked-clones"]) => {
                let request: CloneGuest = parsed(body)?;
                self.refuse_plain_clone(id)?;
                self.link_template(id, request.name, request.id, None, networks, events)
            }
            ("GET",["machines",id,"storage"])=>{
                let vm=self.vm(id)?;self.available(id)?;
                let bundle=self.library.bundle_path(id).map_err(store)?;
                Ok(Reply::json(self.driver(vm.engine)?.read_storage(&vm,&bundle).map_err(engine)?))
            }
            ("PUT",["machines",id,"storage"])=>self.edit_storage(id,body,events),
            ("GET",["machines",id,"capabilities"])=>self.caps(id,networks),
            ("GET",["machines",id,"console"])=>{
                let vm=self.vm(id)?;
                self.available(id)?;
                let caps=self.driver(vm.engine)?.capabilities(&vm);
                if !caps.has(Capability::Console) {
                    return Err(refused(caps.reason(Capability::Console).unwrap_or("The native console is unavailable.")));
                }
                let guid=self.driver(vm.engine)?.console_id(id).map_err(engine)?;
                let state=self.driver_mut(vm.engine)?.state(id).map_err(engine)?;
                Ok(Reply::json(json!({"hypervId":guid,"state":state})))
            }
            ("GET",["machines",id,"thumbnail"])=>{
                let vm=self.vm(id)?;self.available(id)?;
                let frame=self.driver_mut(vm.engine)?.thumbnail(id).map_err(engine)?;
                Ok(Reply::rgba(frame.width,frame.height,frame.rgba))
            }
            ("POST",["machines",id,op @ ("start"|"stop"|"shutdown"|"restart"|"pause"|"resume")])=>self.transition(id,op,body,networks,events),
            ("POST",["machines",id,"keys"])=>{
                use svm_core::engine::GuestKeys;
                #[derive(Deserialize)]
                #[serde(untagged)]
                enum Input { Text(TextInput), Named(NamedInput) }
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields, rename_all="camelCase")]
                struct TextInput { text:String, #[serde(default)] append_enter:bool }
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct NamedInput { keys:Vec<String> }
                let input = serde_json::from_value(body.clone()).map_err(|_|bad("Send printable US-ASCII text with optional appendEnter, or a list of named keys."))?;
                let keys = match input {
                    Input::Text(t) => GuestKeys::from_text_with_enter(&t.text,t.append_enter),
                    Input::Named(n) => GuestKeys::from_names(&n.keys),
                }.map_err(|e|bad(e.to_string()))?;
                let vm=self.vm(id)?; self.available(id)?;
                let report=self.driver_mut(vm.engine)?.send_keys(id,&keys).map_err(engine)?;
                let total=keys.strokes().len();
                let message=format!("{} of {total} keys sent to the machine.", report.sent);
                let mut response=json!({"sent":report.sent,"retried":report.retried,"layout":"us","message":message});
                if let Some(reason)=report.error {
                    response["error"]=json!({"code":"guest_keys_incomplete","message":format!("{message} {reason}")});
                    return Ok(Reply::json_status(409,response));
                }
                Ok(Reply::json(response))
            }
            ("GET", ["machines", id, "captures"]) => {
                self.capture_machine(id)?;
                Ok(Reply::json(self.qemu.capture_list(id).map_err(engine)?))
            }
            ("POST", ["machines", id, "captures"]) => {
                let vm = self.capture_machine(id)?;
                if vm.state != VmState::Running {
                    return Err(refused("Start the QEMU machine before capturing packets."));
                }
                let options: PacketCapture = parsed(body)?;
                let limit = options.limit_mib.unwrap_or(512);
                if !(1..=512).contains(&limit) {
                    return Err(bad("Choose a capture size from 1 to 512 MiB."));
                }
                let capture = self.qemu.start_capture(id, limit).map_err(engine)?;
                events.record("capture started", &format!("Packet capture started for {id}."))?;
                Ok(Reply::created(capture))
            }
            ("POST", ["machines", id, "captures", "stop"]) => {
                self.capture_machine(id)?;
                let capture = self.qemu.stop_capture(id).map_err(engine)?;
                events.record("capture stopped", &format!("Packet capture stopped for {id}."))?;
                Ok(Reply::json(capture))
            }
            ("GET", ["machines", id, "captures", capture, "file"]) => {
                self.capture_machine(id)?;
                let path = self.qemu.capture_path(id, capture).map_err(engine)?;
                Ok(Reply::json(json!({"path":path})))
            }
            ("DELETE", ["machines", id, "captures", capture]) => {
                self.capture_machine(id)?;
                self.qemu.delete_capture(id, capture).map_err(engine)?;
                events.record("capture deleted", &format!("A packet capture was deleted for {id}."))?;
                Ok(Reply::json(json!({"deleted":true})))
            }
            ("GET",["machines",id,"snapshots"])=>{
                let vm=self.vm(id)?;self.available(id)?;
                if vm.engine==EngineKind::AppleVz {return Err(refused("Checkpoints are unavailable for this engine."));}
                Ok(Reply::json(json!(self.driver_mut(vm.engine)?.list_snapshots(id).map_err(engine)?)))
            }
            ("POST",["machines",id,"snapshots"])=>{
                let vm=self.vm(id)?;self.available(id)?;
                self.check_template_checkpoint(&vm)?;
                let result=CheckpointWork::create(body)?.run(id,self.driver_mut(vm.engine)?)?;
                self.finish_checkpoint(id,result,networks,events)
            }
            ("DELETE",["machines",id,"snapshots",sid])=>{
                let mut vm=self.vm(id)?;self.available(id)?;
                self.check_template_checkpoint(&vm)?;
                self.driver_mut(vm.engine)?.delete_snapshot(id,sid).map_err(engine)?;
                self.refresh_snapshot_count(&mut vm)?;
                events.record("snapshot deleted",&format!("A checkpoint was deleted on {id}."))?;
                Ok(Reply::json(json!({"id":sid,"deleted":true})))
            }
            ("POST",["machines",id,"snapshots",sid,"revert"])=>{
                let mut vm=self.vm(id)?;self.available(id)?;
                self.check_template_checkpoint(&vm)?;
                let snap=self.driver_mut(vm.engine)?.list_snapshots(id).map_err(engine)?.into_iter().find(|s|s.id==*sid).ok_or_else(absent)?;
                if snap.with_memory && vm.state!=VmState::Running {
                    vm.cores=self.checked_admit(&vm,events)?;
                    self.save(&vm)?;
                }
                self.driver_mut(vm.engine)?.revert(id,sid).map_err(engine)?;
                self.refresh_after(events,Some(id),Some((id,None)))?;
                events.record("reverted",&format!("A checkpoint was restored on {id}."))?;
                Ok(Reply::json(self.published(&self.vm(id)?,networks)))
            }
            _=>Err(ApiError::new(404,"route_not_found","The requested machine operation is unavailable.")),
        }
    }
    fn update_guard(&mut self,body:&Value,events:&mut Events)->Result<Reply,ApiError> {
        let fields=body.as_object().filter(|m|!m.is_empty()).ok_or_else(||bad("Choose a protection setting to update."))?;
        if let Some(pct)=fields.get("budgetPct") {
            if !pct.as_u64().is_some_and(|n|(1..=100).contains(&n)) {return Err(bad("Choose a whole-number CPU budget between 1 and 100 percent."));}
        }
        if fields.get("maxRunning").is_some_and(|n|!n.is_null() && !n.as_u64().is_some_and(|v|v>0)) {
            return Err(bad("Set a positive running-machine limit or leave it unlimited."));
        }
        let path=self.guard_path.as_ref().ok_or_else(||refused("Windows could not identify this host for saving protection settings."))?;
        let dir=path.parent().ok_or_else(||bad("The host settings path is unavailable."))?;
        fs::create_dir_all(dir).map_err(io_error)?;
        let lock=fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(path.with_extension("lock")).map_err(io_error)?;
        lock.try_lock().map_err(|_|refused("Another service is changing this host's protection settings. Try again."))?;
        let mut merged=json!(load_guard(path)?);
        for (key,value) in fields { merged[key]=value.clone(); }
        if fields.len()==1 && fields.contains_key("budgetPct") { merged["enabled"]=json!(true); }
        let policy:HostGuard=parsed(&merged)?;
        if policy.enabled && !self.uncertain.is_empty() {return Err(refused("Host protection cannot confirm the current allocation."));}
        if let Some(profile)=self.host.as_ref().ok() {
            if let Err(error)=policy.check_configuration(&profile.info,&self.allocated()) {
                let reason=error.to_string();events.record("refused",&reason)?;return Err(refused(reason));
            }
        } else if policy.enabled {return Err(refused("The service could not verify the host's capacity."));}
        if policy.enabled && policy.reserve_gb>0 {
            self.ram_sample.set(None);
            if u64::from(policy.reserve_gb)>self.free_ram().map_err(refused)? {
                return Err(refused("The requested host reserve exceeds the free memory currently reported by Windows."));
            }
        }
        svm_core::write_json(path,&policy).map_err(store)?;
        self.guard=policy;
        let description=if self.guard.enabled {"Host protection is enabled."} else {"Host protection is off."};
        events.record("budget",description)?;
        Ok(Reply::json(json!(self.guard)))
    }

    pub(super) fn library_capacity(&self)->Result<Value,ApiError> {
        if self.background_hyperv() {
            return Ok(self.capacity_sample.borrow().clone().unwrap_or(Value::Null));
        }
        let data=self.engine.capacity(&self.library_dir).map_err(engine)?;
        *self.capacity_sample.borrow_mut() = Some(data.clone());
        if let Some(free)=data["freeRamGb"].as_u64() {self.ram_sample.set(Some((std::time::Instant::now(),free)));}
        Ok(data)
    }
    fn edit_storage(&mut self,id:&str,body:&Value,events:&mut Events)->Result<Reply,ApiError> {
        let fields=body.as_object().filter(|m|m.len()==1).ok_or_else(||bad("Choose one media or boot order change."))?;
        let mut vm=self.vm(id)?;
        self.available(id)?;
        if vm.template.is_some() { return Err(refused("Remove the read-only template before editing its storage.")); }
        let bundle=self.library.bundle_path(id).map_err(store)?;
        if vm.engine==EngineKind::Qemu {
            let image=fields.get("isoPath").ok_or_else(||bad("Choose Remove installer disc or Reattach installer disc."))?;
            vm.iso_path=match image {
                Value::Null=>None,
                Value::String(p)=>Some(checked_media(Path::new(p),"iso")?),
                _=>return Err(bad("Supply the original installer path or null to remove it.")),
            };
            let _guard=self.qemu.guard_installer_change(&vm).map_err(|e|refused(e.to_string()))?;
            let observed=self.qemu.read_storage(&vm,&bundle).map_err(engine)?;
            self.save(&vm)?;
            events.record("storage updated",&format!("Installer disc updated for {id}."))?;
            return Ok(Reply::json(observed));
        }
        if vm.engine!=EngineKind::HyperV {return Err(refused("Storage changes are unavailable for this engine."));}
        let state = if let Some(input)=fields.get("isoPath") {
            let selected=if input.is_null() {None} else {
                let path=input.as_str().ok_or_else(||bad("Choose a local installer image."))?;
                Some(checked_media(Path::new(path),"iso")?)
            };
            let old=self.driver(vm.engine)?.read_storage(&vm,&bundle).map_err(engine)?;
            self.driver(vm.engine)?.change_storage(&vm,"isoPath",&json!(selected)).map_err(engine)?;
            vm.iso_path=selected;
            let observed=self.driver(vm.engine)?.read_storage(&vm,&bundle).map_err(engine)?;
            if vm.iso_path.is_none() && observed.get("isoPath")!=Some(&Value::Null) {
                return Err(refused("The DVD drive did not report empty after eject. Refresh Storage before retrying."));
            }
            if let Err(error)=self.save(&vm) {
                self.driver(vm.engine)?.change_storage(&vm,"isoPath",&old["isoPath"]).map_err(engine)?;
                return Err(error);
            }
            observed
        } else if let Some(order)=fields.get("bootFirst").and_then(Value::as_str).filter(|s|matches!(*s,"disk"|"image")) {
            let file=bundle.join("boot-order.json");
            let old=match svm_core::read_json::<String>(&file) {
                Ok(order)=>Some(order),Err(Error::Io(e)) if e.kind()==io::ErrorKind::NotFound=>None,Err(e)=>return Err(store(e)),
            };
            svm_core::write_json(&file,&order).map_err(store)?;
            let confirmed=(|| {
                self.driver(vm.engine)?.change_storage(&vm,"bootFirst",&json!(order)).map_err(engine)?;
                let observed=self.driver(vm.engine)?.read_storage(&vm,&bundle).map_err(engine)?;
                if observed["bootFirst"].as_str()!=Some(order) {
                    return Err(refused("Firmware did not report the requested first boot device. Refresh Storage before retrying."));
                }
                Ok(observed)
            })();
            match confirmed {
                Ok(observed)=>observed,
                Err(error)=>{
                    if let Some(before)=old {svm_core::write_json(&file,&before).map_err(store)?;} else {fs::remove_file(file).map_err(io_error)?;}
                    return Err(error);
                }
            }
        } else {return Err(bad("Choose an installer image, eject it, or select disk first or image first."));};
        events.record("storage updated",&format!("Storage settings for {id} changed."))?;
        Ok(Reply::json(state))
    }
    fn check_template_checkpoint(&self, vm: &Vm) -> Result<(), ApiError> {
        if vm.throwaway {
            return Err(refused("Turn off throwaway mode before using checkpoints."));
        }
        if vm.template.is_some() || vm.linked_from.is_some() {
            return Err(refused("Checkpoints are unavailable for templates and linked clones."));
        }
        Ok(())
    }

    fn capture_machine(&self, id: &str) -> Result<Vm, ApiError> {
        let vm = self.vm(id)?;
        if vm.engine != EngineKind::Qemu {
            return Err(refused("Packet capture is available for QEMU. Hyper-V capture requires administrator tools such as pktmon."));
        }
        self.available(id)?;
        Ok(vm)
    }

    fn refresh_snapshot_count(&mut self,vm:&mut Vm)->Result<(),ApiError> {
        let count=self.driver_mut(vm.engine)?.list_snapshots(&vm.id).map_err(engine)?.len();
        vm.snaps=u32::try_from(count).map_err(|_|refused("The machine has too many checkpoints."))?;
        self.save(vm)
    }
    pub(super) fn held_identities(&self)->Result<Vec<Vm>,ApiError> {
        let mut held=self.inventory.clone();
        held.extend(self.pending_reservation.iter().cloned());
        for entry in self.library.list_trash().map_err(store)? {held.push(entry.machine);}
        Ok(held)
    }
    pub(super) fn ensure_identity(&self,id:&str,name:&str)->Result<(),ApiError> {
        validate_name(name).map_err(store)?;
        if !id_ok(id) {return Err(bad("Use a lowercase machine ID containing letters, digits, periods, hyphens or underscores."));}
        if self.held_identities()?.iter().any(|vm|vm.id==id || vm.name.eq_ignore_ascii_case(name)) {return Err(refused("A machine in the library or trash already holds that ID or name."));}
        Ok(())
    }
    fn prepare_catalog_creation(&mut self, body: &Value, networks: &[Network]) -> Result<Option<BackgroundTask>, ApiError> {
        let Some(catalog_id) = body["catalogId"].as_str() else { return Ok(None); };
        let super::catalog::Selection::Verified(entry) = self.catalog_selection(catalog_id)? else { return Ok(None); };
        if entry.upstream.is_none() { return Ok(None); }
        let mut request: Create = parsed(body)?;
        let profile = entry.profile();
        if request.iso_path.is_some() || request.disk_path.is_some()
            || request.architecture.is_some_and(|architecture| architecture != profile.architecture)
            || request.family.is_some_and(|family| family != profile.family)
            || request.engine.is_some_and(|engine| !profile.allowed_engines.contains(&engine))
            || request.os.as_ref().is_some_and(|os| os != &profile.os)
            || request.vcpu == Some(0) || request.ram_gb == Some(0) || request.disk_gb == Some(0)
        {
            return Err(bad("Use the selected catalog installer with a compatible machine profile and a new disk."));
        }
        if self.background_busy() || self.catalog_busy() || self.converting() || self.file_transfer_busy() {
            return Err(refused("Wait for the current machine or installer operation to finish."));
        }
        let id = request.id.take().unwrap_or_else(next_id);
        self.ensure_identity(&id, &request.name)?;
        network(networks, request.net.as_deref().unwrap_or("nat"))?;
        request.id = Some(id.clone());
        let library = self.library_dir.join("installers");
        let run = move || {
            let held = super::catalog_store::verified_installer(&library, &entry)
                .map_err(|message| refused(&message));
            Box::new(move |machines: &mut Machines, networks: &[Network], events: &mut Events| {
                let held = held?;
                machines.engine.set_networks(networks);
                machines.create_with_installer(request, networks, events, None, Some(held), None)
            }) as MachineCompletion
        };
        Ok(Some(BackgroundTask {
            machines: vec![id], reserved: None, hyperv: false, qemu_checkpoint: false,
            catalog_io: true, accepted: None, run: Box::new(run),
        }))
    }

    pub(super) fn create(&mut self,r:Create,networks:&[Network],events:&mut Events,imported:Option<(&Path,u64)>)->Result<Reply,ApiError> {
        self.create_with_installer(r, networks, events, imported, None, None)
    }

    /// Create a machine from a prepared ready image. The ready marker (and with it the
    /// default-login guard) is part of the very first record written for the machine.
    pub(super) fn create_ready(
        &mut self, r: Create, networks: &[Network], events: &mut Events, imported: (&Path, u64),
        ready: svm_core::model::ReadyOrigin,
    ) -> Result<Reply, ApiError> {
        self.create_with_installer(r, networks, events, Some(imported), None, Some(ready))
    }

    fn create_with_installer(
        &mut self, mut r: Create, networks: &[Network], events: &mut Events, imported: Option<(&Path, u64)>,
        held: Option<super::catalog_store::HeldInstaller>, ready: Option<svm_core::model::ReadyOrigin>,
    ) -> Result<Reply, ApiError> {
        if r.catalog_id.is_some() && (r.disk_path.is_some() || imported.is_some()) {
            return Err(bad("A catalog machine uses a new virtual disk."));
        }
        let id=r.id.take().unwrap_or_else(next_id);
        self.ensure_identity(&id,&r.name)?;
        let catalog_choice = r.catalog_id.as_deref().map(|id| self.catalog_selection(id)).transpose()?;
        let mut legacy_windows = false;
        if let Some(choice) = catalog_choice.as_ref() {
            use super::catalog::Selection;
            match (choice, r.iso_path.is_some()) {
                (Selection::Verified(_), true) => return Err(bad("Choose the verified installer from the OS catalog.")),
                (Selection::Local(_), false) => return Err(bad("Choose a local ISO for this catalog profile.")),
                _ => {}
            }
            let profile = choice.profile();
            legacy_windows = profile.legacy_windows;
            if r.os.as_ref().is_some_and(|os|os!=&profile.os) || r.family.is_some_and(|family|family!=profile.family) {
                return Err(bad("The operating system is fixed by the selected catalog installer."));
            }
            if r.architecture.is_some_and(|architecture|architecture!=profile.architecture) {
                return Err(bad("Choose the architecture of the selected catalog installer."));
            }
            let engine=r.engine.unwrap_or(profile.engine);
            if !profile.allowed_engines.contains(&engine) {
                return Err(bad("Choose an engine supported by this catalog installer."));
            }
            r.os=Some(profile.os);
            r.family=Some(profile.family);
            r.architecture=Some(profile.architecture);
            r.engine=Some(engine);
            let cpu = *r.vcpu.get_or_insert(profile.vcpu);
            let ram = *r.ram_gb.get_or_insert(profile.ram_gb);
            let disk = *r.disk_gb.get_or_insert(profile.disk_gb);
            if cpu < profile.min_vcpu || ram < profile.min_ram_gb || disk < profile.min_disk_gb {
                return Err(bad(&format!("This installer needs at least {} virtual CPUs, {} GiB of memory and {} GiB of disk space.",
                    profile.min_vcpu, profile.min_ram_gb, profile.min_disk_gb)));
            }
            if matches!(choice, Selection::Local(_))
                && (r.secure_boot.is_some_and(|setting| setting != profile.secure_boot)
                    || r.tpm.is_some_and(|setting| setting != profile.tpm)) {
                return Err(bad("Use the Secure Boot and TPM settings of the selected Windows profile."));
            }
            r.secure_boot.get_or_insert(profile.secure_boot);
            r.tpm.get_or_insert(profile.tpm);
        }
        let net=network(networks,r.net.as_deref().unwrap_or("nat"))?;
        let ident=identity::allocate(&id,&r.name,net,&self.held_identities()?).map_err(store)?;
        let os=r.os.unwrap_or_else(||"Other".into());
        if os.trim().is_empty() || os.len()>180 {return Err(bad("Supply a short operating system name."));}
        let family=r.family.unwrap_or_else(||family(&os));
        let kind=r.engine.unwrap_or(EngineKind::HyperV);
        let architecture=r.architecture.unwrap_or_default();
        let arm=architecture==GuestArchitecture::Aarch64;
        if arm && kind!=EngineKind::Qemu {return Err(bad("Select Emulated Arm (slow) with the QEMU engine."));}
        if kind==EngineKind::Qemu {
            let limits = if legacy_windows {
                svm_qemu::validate_legacy_windows_profile(architecture,family,r.vcpu.unwrap_or(1),r.ram_gb.unwrap_or(2))
            } else {
                svm_qemu::validate_profile(architecture,family,imported.is_some(),r.vcpu.unwrap_or(1),r.ram_gb.unwrap_or(2))
            };
            limits.map_err(|e|bad(e.to_string()))?;
            if net.mode!=NetworkMode::Nat || r.disk_path.is_some() || r.secure_boot==Some(true) || r.tpm==Some(true) {
                return Err(bad("QEMU requires its own qcow2 disk, NAT, and Secure Boot and TPM off."));
            }
            if imported.is_none() && family==GuestFamily::Android && r.iso_path.is_none() && catalog_choice.is_none() {
                return Err(bad("Choose a local Android x86-64 installer image."));
            }
            let status=self.qemu.prerequisites();
            if status["available"]!=true {return Err(refused(status["reason"].as_str().unwrap_or("QEMU is not set up on this PC.")));}
            if arm && status["armAvailable"]!=true {return Err(refused(status["armReason"].as_str().unwrap_or("Select QEMU in Settings to verify the Arm tools.")));}
        } else {self.driver(kind)?;}
        let disk_gb=if imported.is_some(){None}else if kind==EngineKind::Qemu{Some(r.disk_gb.unwrap_or(8))}else{r.disk_gb};
        if disk_gb.is_some_and(|size| size > MAX_VHDX_GIB) {
            return Err(bad("A virtual disk can be at most 65,536 GiB (64 TiB)."));
        }
        if r.disk_gb==Some(0) || (r.disk_gb.is_some() && r.disk_path.is_some()) {return Err(bad("Choose a positive disk size or a single existing VHDX."));}
        if let Some(size)=disk_gb {
            let limit=disk_limit(&self.library_capacity()?).ok_or_else(||refused("The free space on the library drive could not be measured."))?;
            if size>limit {return Err(bad(format!("The library currently has space for at most {limit} GiB.")));}
        }
        let source=r.disk_path.as_deref().map(open_standalone_disk).transpose()?;
        if r.vcpu==Some(0) || r.ram_gb==Some(0) {return Err(bad("A machine needs positive CPU and RAM allocations."));}
        let supplied = r.iso_path.as_deref().map(|path| checked_media(path, "iso")).transpose()?;
        let catalog_installer = match held {
            Some(held) => Some(held),
            None => catalog_choice.as_ref().map(|choice| self.open_catalog_installer(choice, supplied.as_deref())).transpose()?,
        };
        let iso = catalog_installer.as_ref().map(|file| file.path().to_owned()).or(supplied);
        let vm=Vm {id,name:r.name,os,family,architecture,engine:kind,accel:!arm,state:VmState::Off,
            vcpu:r.vcpu.unwrap_or(1),ram_gb:r.ram_gb.unwrap_or(if kind==EngineKind::Qemu {2} else {1}),cores:Vec::new(),net:net.id.clone(),
            ip:ident.ip,mac:ident.mac,dns:ident.dns,snaps:0,disk_gb,share_clipboard:false,port_forwards:Vec::new(),template:None,linked_from:None,throwaway:false,isolated:false,
            disk_path:if imported.is_some(){Some(PathBuf::from(if kind==EngineKind::Qemu {"system.qcow2"}else{"system.vhdx"}))}
                else{r.disk_path.as_ref().map(|_|PathBuf::from("system.vhdx"))},iso_path:iso,secure_boot:r.secure_boot,tpm:r.tpm,ready};
        let dest=self.stage(&vm)?;
        if let Some((ready,_))=imported {
            self.publish_imported_disk(&vm, &dest, ready)?;
            if kind==EngineKind::HyperV {
                // A fresh Gen 2 registration without media otherwise tries PXE before its imported disk.
                if let Err(e)=svm_core::write_json(&dest.join("boot-order.json"),&"disk"){self.forget(&vm.id)?;return Err(store(e));}
            }
        }
        if let Some((source, _hold))=source {
            let disk = dest.join("system.vhdx");
            let copy = fs::copy(source, &disk).map_err(io_error)
                .and_then(|_| open_standalone_disk(&disk).map(drop));
            if let Err(error)=copy {self.forget(&vm.id)?;return Err(error);}
        }
        self.define_staged_with_disk(&vm,events,imported.map(|(_,bytes)|bytes),legacy_windows)?;
        events.record("created",&format!("{} was created.",vm.id))?;
        // The engine attaches the same installer whose held bytes the catalog verified.
        drop(catalog_installer);
        Ok(Reply::created(self.published(&vm,networks)))
    }
    pub(super) fn stage(&mut self,vm:&Vm)->Result<PathBuf,ApiError> {
        self.library.create(vm).map_err(store)?;
        self.inventory.push(vm.clone());
        let bundle=self.library.bundle_path(&vm.id).map_err(store)?;
        if let Err(e)=self.driver_mut(vm.engine)?.register(&vm.id,&bundle) {self.forget(&vm.id)?;return Err(engine(e));}
        Ok(bundle)
    }
    fn define_staged(&mut self,vm:&Vm,events:&mut Events)->Result<(),ApiError> {
        self.define_staged_with_disk(vm,events,None,false)
    }
    fn publish_imported_disk(&mut self, vm: &Vm, bundle: &Path, ready: &Path) -> Result<(), ApiError> {
        let filename = vm.disk_path.as_ref().expect("imported disk has a bundle name");
        let transfer = svm_qemu::LocalFolder::open(bundle)
            .and_then(|folder| svm_qemu::publish_disk(ready, &folder.path.join(filename)));
        if let Err(error) = transfer {
            self.forget_failed_definition(vm, bundle)?;
            return Err(engine(error));
        }
        Ok(())
    }
    fn forget_failed_definition(&mut self, vm: &Vm, bundle: &Path) -> Result<(), ApiError> {
        if vm.engine == EngineKind::Qemu {
            self.qemu.trash_detached(&vm.id, bundle).map_err(engine)?;
            let receipt = RemovalReceipt { id: vm.id.clone(), retained: None, bytes: None };
            svm_core::write_json(&bundle.join("removal-complete.json"), &receipt).map_err(store)?;
        }
        self.forget(&vm.id)?;
        Ok(())
    }

    pub(super) fn define_staged_with_disk(&mut self,vm:&Vm,events:&mut Events,bytes:Option<u64>,legacy_windows:bool)->Result<(),ApiError> {
        let bundle=self.library.bundle_path(&vm.id).map_err(store)?;
        let definition=match (vm.engine,bytes) {
            (EngineKind::Qemu,Some(size))=>self.qemu.define_import(vm,size,legacy_windows),
            (EngineKind::Qemu,None) if legacy_windows=>self.qemu.define_legacy_windows(vm),
            _=>self.driver_mut(vm.engine)?.define_new(vm,&bundle),
        };
        if let Err(error)=definition {
            if vm.tpm==Some(true) && matches!(&error,EngineError::Permission(message) if message.contains("TPM")) {self.tpm_verified=Some(false);}
            // A timed-out definition may still own files. Keep its bundle until its registration is known.
            if matches!(self.driver_mut(vm.engine)?.state(&vm.id),Err(EngineError::Missing(_))) {
                self.forget_failed_definition(vm, &bundle)?;
            }
            else {events.record("definition incomplete",&format!("Inspect the existing bundle and registration for {}.",vm.id))?;}
            return Err(engine(error));
        }
        if vm.tpm==Some(true) {self.tpm_verified=Some(true);}
        Ok(())
    }
    fn clone_guest(&mut self,id:&str,r:CloneGuest,networks:&[Network],events:&mut Events)->Result<Reply,ApiError> {
        let task = self.prepare_clone(id, r, networks)?;
        task.run(&mut *self.engine)(self, networks, events)
    }

    fn prepare_clone(&mut self,id:&str,r:CloneGuest,networks:&[Network])->Result<MachineTask,ApiError> {
        let source=self.vm(id)?;self.available(id)?;
        if source.template.is_some() || source.linked_from.is_some() {
            return Err(refused("Full cloning is unavailable for templates and linked clones."));
        }
        if source.engine!=EngineKind::HyperV {return Err(refused("Cloning is unavailable for this engine."));}
        if source.state!=VmState::Off {return Err(refused("The source machine must be off before you make a full clone."));}
        if source.throwaway {return Err(refused("Turn off throwaway mode before making a full clone."));}
        if source.tpm==Some(true) {return Err(refused("A new machine identity cannot reuse the source virtual TPM."));}
        let mut vm=source.clone();vm.id=r.id.unwrap_or_else(next_id);vm.name=r.name;self.ensure_identity(&vm.id,&vm.name)?;
        let net=network(networks,&source.net)?;
        let identity=identity::allocate(&vm.id,&vm.name,net,&self.held_identities()?).map_err(store)?;
        vm.mac=identity.mac;vm.ip=identity.ip;vm.dns=identity.dns;vm.cores.clear();vm.snaps=0;
        vm.disk_gb=None;vm.disk_path=None;
        let src=self.library.bundle_path(id).map_err(store)?;
        // Shared read-only installation media stays shared; bundle-local media follows the clone.
        let current_storage=self.driver(vm.engine)?.read_storage(&source,&src).map_err(engine)?;
        let local_iso=current_storage["isoPath"].as_str().map(|p|checked_media(&src.join(p),"iso")).transpose()?;
        let copy_iso=local_iso.as_deref().filter(|p|p.starts_with(&src)).map(Path::to_path_buf);
        if copy_iso.is_some() {vm.iso_path=Some(PathBuf::from("install.iso"));} else {vm.iso_path=local_iso.clone();}
        let boot=current_storage["bootFirst"].as_str()
            .filter(|v|*v=="disk" || (*v=="image" && vm.iso_path.is_some()))
            .map(str::to_owned);
        let dst=self.stage(&vm)?;
        // Keep the identity reserved while the clone is incomplete, but publish it only after copying.
        self.inventory.retain(|row| row.id != vm.id);
        let affected = vec![source.id.clone(), vm.id.clone()];
        let reservation = vm.clone();
        Ok(MachineTask::new(affected, Some(reservation), move |driver| {
            let copied = (|| {
                if let Some(iso) = copy_iso {
                    fs::copy(iso, dst.join("install.iso")).map_err(io_error)?;
                }
                driver.register(&vm.id, &dst).map_err(engine)?;
                driver.clone_disk(&source, &src, &vm, &dst).map_err(engine)
            })();
            Box::new(move |machines, networks, events| {
                let copied = match copied {
                    Ok(copied) => copied,
                    Err(error) => { machines.forget(&vm.id)?; return Err(error); }
                };
                if copied {
                    vm.disk_path=Some(PathBuf::from("system.vhdx"));
                    machines.save(&vm)?;
                }
                if let Some(order)=boot {
                    if let Err(error)=svm_core::write_json(&dst.join("boot-order.json"),&order) {
                        machines.forget(&vm.id)?;
                        return Err(store(error));
                    }
                }
                machines.inventory.push(vm.clone());
                machines.define_staged(&vm,events)?;
                events.record("cloned",&format!("{} is an independent clone of {}.",vm.id,source.id))?;
                Ok(Reply::created(machines.published(&vm,networks)))
            })
        }))
    }
    fn check_port_forwards(&self, vm: &Vm, networks: &[Network]) -> Result<(), ApiError> {
        if !vm.port_forwards.is_empty() && vm.ready.as_ref().is_some_and(|ready| ready.default_login.is_some()) {
            return Err(refused("This machine still uses its publisher's default password. Change it inside the guest and confirm it before adding port forwards."));
        }
        if vm.engine != EngineKind::Qemu || network(networks, &vm.net)?.mode != NetworkMode::Nat {
            return Err(refused("Port forwarding requires a QEMU NAT machine."));
        }
        svm_qemu::validate_port_forwards(&vm.port_forwards).map_err(|error| bad(error.to_string()))?;
        for rule in &vm.port_forwards {
            if let Some(peer) = self.inventory.iter().find(|peer| peer.id != vm.id && peer.engine == EngineKind::Qemu
                && peer.port_forwards.iter().any(|other| other.protocol == rule.protocol && other.host_port == rule.host_port)) {
                return Err(refused(format!("{} port {} is already assigned to {}.",
                    rule.protocol.as_str().to_ascii_uppercase(), rule.host_port, peer.name)));
            }
        }
        Ok(())
    }

    fn update(&mut self,id:&str,updates:Edit,networks:&[Network],events:&mut Events)->Result<Reply,ApiError> {
        // Edits wait until the previous throwaway run is reconciled and the original disk is attached again.
        if updates.throwaway.is_some() || self.vm(id)?.throwaway {
            self.refresh_after(events, Some(id), None)?;
        }
        let old=self.vm(id)?;
        if old.template.is_some() { return Err(refused("Remove the read-only template before editing this machine.")); }
        let mut vm=old.clone();
        if let Some(name)=updates.name {
            validate_name(&name).map_err(store)?;
            if self.held_identities()?.iter().any(|peer|peer.id!=vm.id && peer.name.eq_ignore_ascii_case(&name)) {return Err(refused("The display name is already in use."));}
            vm.name=name;
        }
        if let Some(os)=updates.os {
            if os.trim().is_empty() || os.len()>180 {return Err(bad("Supply a short operating system name."));}
            vm.os=os;
        }
        if let Some(vcpus)=updates.vcpu {vm.vcpu=vcpus;}
        if let Some(ram)=updates.ram_gb {vm.ram_gb=ram;}
        if vm.vcpu==0 || vm.ram_gb==0 {return Err(bad("A machine needs at least one CPU thread and one GB of RAM."));}
        if let Some(id)=updates.net {
            if id!=vm.net {
                let net=network(networks,&id)?;
                let others:Vec<_>=self.held_identities()?.into_iter().filter(|v|v.id!=vm.id).collect();
                vm.ip=identity::allocate(&vm.id,&vm.name,net,&others).map_err(store)?.ip;
                vm.net=id;
            }
        }
        if let Some(ip)=updates.ip {
            let n=network(networks,&vm.net)?;
            if matches!(n.mode,NetworkMode::Nat|NetworkMode::Bridged) {return Err(bad("The external DHCP authority chooses the address on this network."));}
            self.available(id)?;
            if vm.state!=VmState::Off {return Err(refused("The machine must be off to change its permanent address."));}
            if !n.subnet.usable(ip) || n.gateway==Some(ip) || (n.mode==NetworkMode::LinkLocal && !(1..255).contains(&ip.octets()[2])) {
                return Err(bad("Choose a usable guest address inside this subnet, distinct from the host address."));
            }
            if self.held_identities()?.iter().any(|other|other.id!=vm.id && other.ip==ip) {return Err(refused("Another machine already holds that address."));}
            vm.ip=ip;
        }
        if let Some(share) = updates.share_clipboard {
            if vm.engine != EngineKind::Qemu { return Err(refused("Clipboard sharing for this machine follows VMConnect settings.")); }
            if vm.state != VmState::Off { return Err(refused("Power off the machine before changing clipboard sharing.")); }
            vm.share_clipboard = share;
        }
        if let Some(isolated) = updates.isolated {
            if vm.engine != EngineKind::Qemu { return Err(refused("Network isolation is a QEMU machine setting.")); }
            if vm.state != VmState::Off { return Err(refused("Power off the machine before changing network isolation.")); }
            vm.isolated = isolated;
        }
        let forwards_changed = updates.port_forwards.is_some();
        if let Some(rules) = updates.port_forwards {
            if vm.state != VmState::Off { return Err(refused("Power off the machine before changing port forwarding.")); }
            vm.port_forwards = rules;
            self.check_port_forwards(&vm, networks)?;
        } else if vm.net != old.net && !vm.port_forwards.is_empty() {
            self.check_port_forwards(&vm, networks)?;
        }
        let mut protect_base = None;
        if let Some(enabled) = updates.throwaway {
            self.throwaway_eligibility(&vm, enabled)?;
            if enabled && !self.driver_mut(vm.engine)?.list_snapshots(id).map_err(engine)?.is_empty() {
                return Err(refused("Remove the checkpoints before enabling throwaway mode."));
            }
            // Turning the mode off again also retries a cleanup an earlier attempt could not finish.
            if vm.engine == EngineKind::HyperV && (enabled != old.throwaway || !enabled) {
                // Throwaway mode guards bundle\system.vhdx; it must be the only disk Hyper-V attaches.
                if enabled { self.engine.verify_throwaway_disk(id).map_err(engine)?; }
                protect_base = Some(enabled);
            }
            // A throwaway machine is for untrusted software: unless the caller chooses otherwise, a
            // QEMU one also loses its route to this PC's local services and to the internet.
            if enabled && !old.throwaway && vm.engine == EngineKind::Qemu && updates.isolated.is_none() { vm.isolated = true; }
            vm.throwaway = enabled;
        }
        let hardware=(vm.vcpu,vm.ram_gb,&vm.net)!=(old.vcpu,old.ram_gb,&old.net);
        let mut qemu_guard=None;
        if hardware || updates.share_clipboard.is_some() || forwards_changed || updates.isolated.is_some() || (vm.engine == EngineKind::Qemu && updates.throwaway.is_some()) {
            self.available(id)?;
            if vm.state!=VmState::Off {return Err(refused("The machine must be off to change its hardware."));}
            if vm.engine==EngineKind::Qemu {
                qemu_guard=Some(self.qemu.guard_hardware_change(&vm).map_err(engine)?);
            }else{self.driver_mut(vm.engine)?.configure(&vm).map_err(engine)?;}
        }
        // Enabling protects the disk before the saved mode promises a discard; disabling lifts the
        // flag only after the saved mode stops promising it. A crash in between leaves a protected
        // normal machine, which the next service start corrects, never an unprotected throwaway one.
        if protect_base == Some(true) {
            if let Err(error) = self.engine.protect_throwaway_base(id, true) {
                if hardware && qemu_guard.is_none() {self.driver_mut(vm.engine)?.configure(&old).map_err(engine)?;}
                return Err(engine(error));
            }
        }
        if let Err(error)=self.save(&vm) {
            if protect_base == Some(true) {
                if let Err(lift) = self.engine.protect_throwaway_base(id, false) {
                    events.record("throwaway protection", &format!("The original disk of {id} is still read-only. {lift}"))?;
                }
            }
            if hardware && qemu_guard.is_none() {self.driver_mut(vm.engine)?.configure(&old).map_err(engine)?;}
            return Err(error);
        }
        drop(qemu_guard);
        if protect_base == Some(false) {
            if let Err(error) = self.engine.protect_throwaway_base(id, false) {
                events.record("throwaway protection", &format!("The original disk of {id} is still read-only. {error}"))?;
                // The mode is saved off, but the caller must not read success while the disk stays protected.
                return Err(refused("Throwaway mode is off, but the original disk is still read-only. Turn throwaway off again to retry."));
            }
        }
        events.record("updated",&format!("The settings for {id} were saved."))?;
        Ok(Reply::json(self.published(&vm,networks)))
    }
    pub(super) fn remove_incomplete_linked_clone(&mut self,id:&str,events:&mut Events)->Result<Reply,ApiError> {
        self.remove_guest(id, Removal { keep_copy: false }, events)
    }

    fn remove_guest(&mut self,id:&str,request:Removal,events:&mut Events)->Result<Reply,ApiError> {
        let kind = self.vm(id)?.engine;
        let task = self.prepare_remove(id, request, events)?;
        task.run(self.driver_mut(kind)?)(self, &[], events)
    }

    fn prepare_remove(&mut self,id:&str,request:Removal,events:&mut Events)->Result<MachineTask,ApiError> {
        let vm=self.vm(id)?;
        // The base disk of a throwaway machine is read-only and may still sit under a temporary disk.
        if vm.throwaway {
            return Err(refused("Turn off throwaway mode before moving this machine to trash."));
        }
        if vm.template.is_some() { self.require_no_linked_clones(id)?; }
        if request.keep_copy && (vm.template.is_some() || vm.linked_from.is_some()) {
            return Err(refused("Retained exports are unavailable for templates and linked clones."));
        }
        if self.uncertain.contains(id) {
            return Err(refused("The engine could not verify the state that must be preserved, so the bundle was kept."));
        }
        let bundle=self.library.bundle_path(id).map_err(store)?;
        let work=if self.unavailable.contains(id) && self.backups.incomplete.contains(id) {
            // A never-registered restore has no removal receipt. Verify the disk is detached before trashing it.
            self.driver_mut(vm.engine)?.trash_detached(id,&bundle).map_err(engine)?;
            RemovalWork::AlreadyRemoved(RemovalReceipt { id:id.into(), retained:None, bytes:None })
        } else if self.unavailable.contains(id) {
            // Recover only a removal whose unregister finished and whose receipt reached disk.
            let receipt=svm_core::read_json::<RemovalReceipt>(&bundle.join("removal-complete.json")).map_err(|_|
                refused("The registration is missing and there is no verified removal receipt, so the bundle was kept."))?;
            RemovalWork::AlreadyRemoved(receipt)
        } else {
            if !matches!(vm.state,VmState::Saved|VmState::Off) {return Err(refused("The machine must be off or saved to move it to trash."));}
            if vm.engine==EngineKind::Qemu && request.keep_copy {return Err(refused("QEMU retained exports are unavailable. Normal removal keeps the qcow2 disk in trash."));}
            let plan=self.driver_mut(vm.engine)?.removal_plan(&vm).map_err(|error| if vm.engine==EngineKind::HyperV {
                refused("The engine could not verify the checkpoints, saved state and virtual TPM, so the bundle was kept.")
            } else {engine(error)})?;
            if plan.required && (vm.template.is_some() || vm.linked_from.is_some()) {
                return Err(refused("Power off this template or linked clone and clear any externally created checkpoints before removal."));
            }
            let keep=plan.required || request.keep_copy;
            if keep {events.record("retaining",&format!("Exporting {id} before removal to preserve its state. Large disks can take up to two hours."))?;}
            RemovalWork::Unregister(plan, keep)
        };
        Ok(MachineTask::new(vec![vm.id.clone()], None, move |driver| {
            let receipt = match work {
                RemovalWork::AlreadyRemoved(receipt) => Ok(receipt),
                RemovalWork::Unregister(plan, keep) => driver.unregister(&vm, &bundle, &plan, keep).map_err(engine),
            };
            Box::new(move |machines, _, events| {
                machines.finish_remove(&vm, &bundle, receipt?, events)
            })
        }))
    }

    fn finish_remove(&mut self,vm:&Vm,bundle:&Path,receipt:RemovalReceipt,events:&mut Events)->Result<Reply,ApiError> {
        let id=&vm.id;
        if receipt.id!=id.as_str() || receipt.bytes.is_some()!=receipt.retained.is_some() {
            return Err(refused("The engine removal receipt is incomplete, so the bundle was kept."));
        }
        let relative=if let Some(value)=receipt.retained {
            let suffix=value.strip_prefix("retained/").filter(|v|id_ok(v))
                .ok_or_else(||refused("The retained copy location could not be verified."))?;
            let rel=PathBuf::from("retained").join(suffix);
            let retained=bundle.join(&rel);
            let checked=retained.canonicalize().map_err(io_error)?;
            if !retained.is_dir() || !checked.starts_with(bundle) || receipt.bytes==Some(0) {
                return Err(refused("The retained copy is unavailable, so the bundle was kept."));
            }
            Some(rel)
        } else {None};
        if !matches!(self.driver_mut(vm.engine)?.state(id),Err(EngineError::Missing(_))) {
            return Err(refused("The engine could not confirm removal of the registration, so the bundle was kept."));
        }
        let trash=self.forget(id)?;
        let path=relative.map(|rel|trash.join(rel));
        let how=if path.is_some() {"retained-copy"} else {"bundle-only"};
        events.record("removed",&format!("{id} was moved to library trash using {how}."))?;
        Ok(Reply::json(json!({"id":id,"trashed":true,"trashPath":trash,"removalPath":how,"retainedPath":path,"retainedBytes":receipt.bytes})))
    }
    fn may_force_off(&self,vm:&Vm)->bool {
        vm.engine==EngineKind::Qemu && self.uncertain.contains(&vm.id) && self.qemu.can_power_off_owned(&vm.id)
    }
    pub(super) fn require_recovered(&self, vm: &Vm) -> Result<(), ApiError> {
        if self.throwaway_pending(vm) {
            return Err(refused("The previous throwaway run is still being recovered. Power the machine off and try again."));
        }
        Ok(())
    }

    fn throwaway_eligibility(&self, vm: &Vm, enabled: bool) -> Result<(), ApiError> {
        self.available(&vm.id)?;
        if vm.state != VmState::Off || vm.template.is_some()
            || !matches!(vm.engine, EngineKind::Qemu | EngineKind::HyperV)
        {
            return Err(refused("Throwaway mode can be changed on a stopped QEMU or Hyper-V machine that is not a template."));
        }
        self.require_recovered(vm)?;
        if enabled && (vm.tpm == Some(true) || vm.snaps != 0) {
            return Err(refused("Throwaway mode requires a machine without checkpoints or a virtual TPM."));
        }
        // An unfinished QEMU checkpoint change would make every throwaway start fail.
        if enabled && vm.engine == EngineKind::Qemu { self.qemu.throwaway_ready(vm).map_err(engine)?; }
        if enabled && self.background_owns(&vm.id) {
            return Err(refused("Wait for this machine's running background task, such as a checkpoint, to finish."));
        }
        Ok(())
    }

    fn transition(&mut self,id:&str,op:&str,body:&Value,networks:&[Network],events:&mut Events)->Result<Reply,ApiError> {
        // A throwaway machine that just powered off keeps its temporary disk until this reconciliation.
        if op == "start" && self.vm(id)?.throwaway { self.refresh_after(events, Some(id), None)?; }
        let mut vm=self.vm(id)?;
        if op!="stop" || !self.may_force_off(&vm) {self.available(id)?;}
        if vm.template.is_some() && matches!(op, "start" | "restart" | "resume") {
            return Err(refused("Remove the read-only template before starting this machine."));
        }
        let press=if op=="start" {parsed::<StartOptions>(body)?.press_key_at_boot} else {None};
        let bundle=self.library.bundle_path(id).map_err(store)?;
        if op == "start" && vm.engine == EngineKind::Qemu && !vm.port_forwards.is_empty() {
            self.check_port_forwards(&vm, networks)?;
        }
        if op == "start" && !vm.throwaway { self.require_recovered(&vm)?; }
        // A normal Hyper-V machine never keeps a read-only flag that throwaway mode set: lift a leftover
        // one (after a failed cleanup) before starting. A flag the mode did not set is left alone.
        if op == "start" && !vm.throwaway && vm.engine == EngineKind::HyperV && vm.template.is_none() {
            self.engine.protect_throwaway_base(id, false).map_err(engine)?;
        }
        let fresh=op=="start" && !vm.throwaway && vm.engine==EngineKind::HyperV && new_installer_disk(&vm,&bundle);
        if op == "start" && vm.throwaway {
            if vm.state != VmState::Off {
                return Err(refused("A throwaway run starts only from a powered-off machine. Discard its saved state first."));
            }
            self.throwaway_eligibility(&vm, true)?;
            if press == Some(true) {
                return Err(refused("Turn off throwaway mode before starting with the Windows installer key."));
            }
        }
        if press==Some(true) && !fresh {return Err(refused("The installer key requires an unused Windows machine with a new empty disk."));}
        let parents = if op == "start" && vm.engine == EngineKind::HyperV && !fresh {
            self.hyperv_disk_parents(&vm, &bundle)?
        } else { Vec::new() };
        if op=="start" || op=="resume" {
            if (op=="start" && !matches!(vm.state,VmState::Off|VmState::Saved)) || (op=="resume" && vm.state!=VmState::Paused) {
                let reason=format!("Cannot {op} this machine in its current state.");
                events.record("refused",&format!("{id}: {reason}"))?;return Err(refused(reason));
            }
            vm.cores=self.checked_admit(&vm,events)?;
            self.save(&vm)?;
            if self.guard.enabled {events.record("admitted",&format!("Host protection admitted {id} on {:?}.",vm.cores))?;}
        }
        let mut boot_key=Value::Null;
        let (result,kind,expected)=match op {
            "start" if vm.engine == EngineKind::HyperV && !fresh =>
                (self.engine.start_managed(&vm, &parents), "started", VmState::Running),
            "start" if fresh=>(self.driver_mut(vm.engine)?.installer_start(&vm,&bundle,press).map(|receipt|boot_key=receipt),"started",VmState::Running),
            "start"=>(self.driver_mut(vm.engine)?.start(id),"started",VmState::Running), "resume"=>(self.driver_mut(vm.engine)?.resume(id),"resumed",VmState::Running),
            "pause"=>(self.driver_mut(vm.engine)?.pause(id),"paused",VmState::Paused), "stop"=>(self.driver_mut(vm.engine)?.stop(id),"stopped",VmState::Off),
            "shutdown"=>(self.driver_mut(vm.engine)?.shutdown(id),"shut down",VmState::Off), "restart"=>(self.driver_mut(vm.engine)?.restart(id),"restart requested",VmState::Running),
            _=>return Err(bad("Unknown state transition.")),
        };
        if let Err(e)=result {
            events.record("refused",&format!("The engine could not {op} {id}."))?;
            self.refresh_after(events,Some(id),None)?;return Err(engine(e));
        }
        self.refresh_after(events,Some(id),Some((id,Some(expected))))?;
        self.available(id)?;
        let mut current=self.vm(id)?;
        if op=="start" && current.engine==EngineKind::Qemu { self.refresh_snapshot_count(&mut current)?; }
        let mut value=self.published(&current,networks);
        if let Some(message)=boot_key["message"].as_str() {
            events.record("installer boot key",&format!("{id}: {message}"))?;
            value["bootKey"]=boot_key;
        }
        if op == "start" && vm.engine == EngineKind::Qemu {
            if let Some(warning) = self.qemu.console_restore_warning(id) {
                events.record("console warning", &format!("{id}: {warning}"))?;
            }
        }
        if op=="restart" {
            events.record(kind,&format!("The guest accepted a restart request for {id}."))?;
            value["guestPowerStatus"]=json!("restart_requested");
        } else { events.record(kind,&format!("Machine {id} was {kind}."))?; }
        Ok(Reply::json(value))
    }
    fn caps(&self,id:&str,networks:&[Network])->Result<Reply,ApiError> {
        let vm=self.vm(id)?;
        let mut caps=match self.driver(vm.engine) {
            Ok(driver)=>driver.capabilities(&vm),
            Err(error)=>svm_core::capability::CapabilitySet::unavailable(&error.message),
        };
        use Capability::*;
        for (cap,allowed,reason) in [
            (Start,matches!(vm.state,VmState::Off|VmState::Saved),"Start requires an off or saved machine."),
            (Stop,vm.state!=VmState::Off,"The machine is already off."),
            (Shutdown,vm.state==VmState::Running,"Shut down requires a running guest."),
            (Restart,vm.state==VmState::Running,"Restart requires a running guest."),
            (SendKeys,vm.state==VmState::Running,"Sending keys requires a running guest."),
            (Pause,vm.state==VmState::Running,"Pause requires a running machine."),
            (Resume,vm.state==VmState::Paused,"Resume requires a paused machine."),
            (Thumbnail,active(vm.state),"The machine has no active display."),
            (SnapshotWithMemory,active(vm.state),"Memory capture requires a running or paused machine."),
            (Clone,vm.state==VmState::Off && vm.tpm!=Some(true),"Cloning requires an off machine without a sealed virtual TPM."),
            (Delete,matches!(vm.state,VmState::Off|VmState::Saved),"The machine must be off or saved to move it to trash."),
        ] {if !allowed {caps.deny(cap,reason);}}
        if vm.state == VmState::Off {
            if let Err(error) = self.require_recovered(&vm) { caps.deny(Start, &error.message); }
        }
        let template_block = if vm.template.is_some() {
            self.require_no_linked_clones(id).err().map(|error| error.message)
        } else { None };
        if vm.template.is_some() {
            for cap in [Start, Resume, Restart] { caps.deny(cap, "Remove the read-only template before starting this machine."); }
            if let Some(reason) = &template_block { caps.deny(Delete, reason); }
        }
        if vm.template.is_some() || vm.linked_from.is_some() {
            for cap in [Snapshot, SnapshotWithMemory, RevertSnapshot, DeleteSnapshot, Clone] {
                caps.deny(cap, "This operation is unavailable for templates and linked clones.");
            }
        }
        if vm.throwaway {
            for cap in [Snapshot, SnapshotWithMemory, RevertSnapshot, DeleteSnapshot] {
                caps.deny(cap, "Turn off throwaway mode before using checkpoints.");
            }
            if caps.has(Clone) { caps.deny(Clone, "Turn off throwaway mode before making a full clone."); }
            if caps.has(Delete) { caps.deny(Delete, "Turn off throwaway mode before moving this machine to trash."); }
        }
        if networks.iter().any(|n|n.id==vm.net && n.mode==NetworkMode::Nat) {
            let reason=if vm.engine==EngineKind::Qemu {"QEMU user-mode NAT supplies addresses inside each guest."} else {"Windows supplies the NAT address through the Default Switch."};
            caps.deny(OwnLanAddress,reason);
        }
        for c in [Start,Resume].into_iter().filter(|_|self.guard.enabled || self.guard_unavailable) {
            if caps.has(c) {if let Err(reason)=self.admit(&vm) {caps.deny(c,&reason);}}
        }
        if let Err(error) = self.available(id) { caps = svm_core::capability::CapabilitySet::unavailable(&error.message); }
        if self.may_force_off(&vm) {caps.allow(Stop);}
        let mut values=serde_json::Map::new();
        for cap in Capability::ALL {
            values.insert(format!("{cap:?}"),json!({"available":caps.has(cap),"reason":caps.reason(cap)}));
        }
        let bundle=self.library.bundle_path(id).map_err(store)?;
        for (key,operation) in [("EditHardware","Hardware changes"),("EditStorage","Live media and boot-order changes"),("ListSnapshots","Checkpoints")] {
            let ok=vm.engine==EngineKind::HyperV || (key=="ListSnapshots" && vm.engine==EngineKind::Qemu);
            let reason=(!ok).then(||format!("{operation} are unavailable for this engine."));
            values.insert(key.into(),json!({"available":ok,"reason":reason}));
        }
        if vm.engine==EngineKind::Qemu {
            let sound=self.qemu.audio_status(&vm);
            values.insert("AudioOutput".into(),json!({"available":sound["enabled"]==true,"message":sound["message"],"reason":sound["message"]}));
            let stopped=vm.state==VmState::Off && self.available(id).is_ok();
            values.insert("EditStorage".into(),json!({"available":stopped,"reason":(!stopped).then_some("Power off the QEMU machine and verify its registration before changing its installer disc.")}));
            let adjustable=stopped && vm.family!=GuestFamily::Android;
            let reason=if vm.family==GuestFamily::Android {"Android uses one CPU and 2 GiB of memory."}
                else {"Power off the QEMU machine and verify its registration before changing its hardware."};
            values.insert("EditHardware".into(),json!({"available":adjustable,"reason":(!adjustable).then_some(reason)}));
        }
        if vm.template.is_some() {
            for key in ["EditHardware", "EditStorage"] {
                values.insert(key.into(), json!({"available":false,"reason":"This machine is a read-only template."}));
            }
        }
        if vm.template.is_some() || vm.linked_from.is_some() {
            values.insert("ListSnapshots".into(), json!({"available":false,"reason":"Checkpoints are unavailable for templates and linked clones."}));
        }
        let template_reason = self.template_eligibility(&vm).err().map(|error| error.message);
        let create_template = template_reason.clone().or_else(|| vm.template.is_some().then_some("This machine is already a template.".into()));
        let create_link = template_reason.or_else(|| vm.template.is_none().then_some("Make this machine a template first.".into()));
        let remove_template = create_link.clone().or(template_block);
        for (action, reason) in [("CreateTemplate",create_template),("CreateLinkedClone",create_link),("RemoveTemplate",remove_template)] {
            values.insert(action.into(), json!({"available":reason.is_none(),"reason":reason}));
        }
        let throwaway_reason = self.throwaway_eligibility(&vm, !vm.throwaway).err().map(|error| error.message);
        values.insert("EditThrowaway".into(), json!({"available":throwaway_reason.is_none(),"reason":throwaway_reason}));
        if vm.throwaway && vm.state != VmState::Off {
            values.insert("ListSnapshots".into(), json!({"available":false,"reason":"Checkpoints are unavailable during a throwaway run."}));
        }
        let installer=if vm.throwaway {
            json!({"available":false,"reason":"The Windows installer key is unavailable in throwaway mode."})
        } else if vm.engine!=EngineKind::HyperV {
            json!({"available":false,"reason":"The Windows installer key is available on Hyper-V only."})
        } else if !caps.has(Start) {
            json!({"available":false,"reason":caps.reason(Start)})
        } else if new_installer_disk(&vm,&bundle) {
            self.driver(vm.engine)?.installer_status(&vm,&bundle).unwrap_or_else(|_|json!({"available":false,"reason":"The installer disk and boot order could not be verified."}))
        } else {json!({"available":false,"reason":"The installer key requires an unused Windows machine with a new empty disk."})};
        values.insert("PressKeyAtBoot".into(),installer);
        if self.backups.incomplete.contains(id) {
            for value in values.values_mut() { *value = json!({"available":false,"reason":"Restore incomplete."}); }
            if !self.uncertain.contains(id) && matches!(vm.state,VmState::Off|VmState::Saved) {
                values.insert("Delete".into(),json!({"available":true,"reason":null}));
            }
        }
        Ok(Reply::json(Value::Object(values)))
    }
}
