#![forbid(unsafe_code)]
#![deny(warnings)]

mod agent;
mod agent_transport;
mod guest_file;
pub use svm_core::engine::GuestExecRequest as ExecRequest;
pub use agent_transport::relay_call;
mod arm;
mod audio;
mod control;
mod capture;
mod capture_space;
mod vnc;
mod provision;
mod linked;
mod throwaway;
mod recovery;
mod profile;
mod port_forward;
pub use port_forward::{PORT_FORWARD_HOST, validate_port_forwards};
pub use profile::{validate_hardware,validate_legacy_windows_profile,validate_profile};
use provision::{validate,Definition};
mod supervisor;
mod snapshot;
mod tools;
mod image_info;
mod transfer;
pub use image_info::{backup_disk_size, check_standalone_vhdx};
pub use guest_file::DOWNLOAD_TIMEOUT;
pub use transfer::{DiskInfo, DiskSource, ImageTool, LocalFolder, TransferControl, publish_disk};
pub use supervisor::supervise;
/// Folder in a machine bundle that holds its first-boot settings (cloud-init NoCloud).
pub const FIRST_BOOT: &str = "first-boot";

use control::{machine_key,read_run,request,unique,Run};
use serde::{de::DeserializeOwned,Deserialize,Serialize};
use serde_json::{json,Value};
use std::{
    collections::BTreeMap,fs::{self,File,OpenOptions},io::{Read,Write},path::{Component,Path,PathBuf},
    process::Stdio,thread,time::{Duration,Instant},
};
use svm_core::{
    capability::{Capability,CapabilitySet},engine::{EngineDriver,EngineError,EngineResult,GuestKeyReport,GuestKeys,Thumbnail},
    model::{EngineKind,GuestArchitecture,GuestFamily,Snapshot,Vm,VmState},
};
use tools::{io_error,Tools};
type Result<T>=EngineResult<T>;
fn err(value:impl Into<String>)->EngineError{EngineError::Invalid(value.into())}

fn local(path:&Path,directory:bool)->Result<PathBuf>{
    if !path.is_absolute() || path.components().any(|p|p==Component::ParentDir){return Err(err("Choose an absolute local path without parent components."));}
    #[cfg(windows)] {
        use std::{os::windows::fs::MetadataExt,path::Prefix};
        if !matches!(path.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_)|Prefix::VerbatimDisk(_))){
            return Err(err("Select an ordinary local drive path."));
        }
        if path.components().any(|part|matches!(part,Component::Normal(s) if s.to_string_lossy().contains(':'))){
            return Err(err("Device streams cannot be used as QEMU files."));
        }
        for p in path.ancestors().filter(|p|p.parent().is_some()){
            if fs::symlink_metadata(p).map_err(io_error)?.file_attributes()&0x400!=0{return Err(err("A QEMU path crosses a link or junction."));}
        }
    }
    #[cfg(not(windows))]
    for p in path.ancestors(){if fs::symlink_metadata(p).map_err(io_error)?.is_symlink(){return Err(err("A QEMU path crosses a link."));}}
    let m=fs::metadata(path).map_err(io_error)?;
    if (directory && !m.is_dir()) || (!directory && !m.is_file()){return Err(err("The selected QEMU path has an unexpected file type."));}
    path.canonicalize().map_err(io_error)
}
fn record<T:DeserializeOwned>(path:&Path)->Result<T>{
    let mut f=File::open(local(path,false)?).map_err(io_error)?;
    if f.metadata().map_err(io_error)?.len()>65536{return Err(err("The QEMU metadata record is too large."));}
    let mut raw=Vec::new();(&mut f).take(65537).read_to_end(&mut raw).map_err(io_error)?;
    if raw.len()>65536{return Err(err("The QEMU metadata record is too large."));}
    serde_json::from_slice(&raw).map_err(|_|err("The QEMU metadata record is invalid."))
}
fn save<T:Serialize>(path:&Path,data:&T)->Result<()>{
    svm_core::write_json(path,data).map_err(io_error)
}

pub struct ConsoleEndpoint {
    key: String,
    run: Run,
}

impl ConsoleEndpoint {
    pub fn connect(&self) -> EngineResult<std::net::TcpStream> {
        let (reply, stream) = control::request_with_stream(&self.key, &self.run, "console")?;
        if reply["ready"] != true { return Err(err("The owned QEMU display is unavailable.")); }
        Ok(stream)
    }
}

pub struct GuestAgentSession {
    family: GuestFamily,
    bundle: PathBuf,
    ticket: String,
    unavailable: Option<String>,
    supervisor: PathBuf,
}

impl GuestAgentSession {
    pub fn status(&self) -> Value {
        match self.call(agent::AgentCall::Status) {
            Ok(report) => report,
            Err(error) => json!({"present":false,"version":null,"os":null,"reason":error.to_string()}),
        }
    }

    pub fn interfaces(&self) -> Result<Value> {
        self.call(agent::AgentCall::Addresses)
    }

    pub fn execute(&self, request: ExecRequest) -> Result<Value> {
        request.check()?;
        self.call(agent::AgentCall::Exec { request })
    }

    pub fn read_small_file(&self, path: String) -> Result<Value> {
        self.call(agent::AgentCall::ReadSmallFile { path })
    }

    pub fn write_small_file(&self, path: String, data: String) -> Result<Value> {
        self.call(agent::AgentCall::WriteSmallFile { path, data })
    }

    pub fn shutdown(&self) -> Result<Value> {
        self.call(agent::AgentCall::Shutdown)
    }

    fn call(&self, request: agent::AgentCall) -> Result<Value> {
        self.call_before(request, None)
    }

    fn call_before(&self, request: agent::AgentCall, deadline: Option<Instant>) -> Result<Value> {
        if let Some(reason) = self.unavailable.as_deref() { return Err(err(reason)); }
        agent_transport::call(&self.bundle, &self.ticket, request, &self.supervisor, deadline)
    }
}

#[derive(Clone)]
pub struct Qemu {home:PathBuf,supervisor:PathBuf,bundles:BTreeMap<String,PathBuf>,tools:std::result::Result<Tools,String>}

fn validate_clipboard_display(share_clipboard: bool, separate_window: bool) -> Result<()> {
    if share_clipboard && separate_window {
        return Err(err("Turn off clipboard sharing or the separate QEMU window before starting this machine."));
    }
    Ok(())
}

#[test]
fn qemu_clipboard_requires_the_embedded_display() {
    for (clipboard, separate) in [(false, false), (false, true), (true, false)] {
        assert!(validate_clipboard_display(clipboard, separate).is_ok());
    }
    assert!(validate_clipboard_display(true, true).is_err());
}
impl Qemu {
    pub fn new(home:&Path,supervisor_exe:&Path)->Self{
        let config=home.join("qemu-engine.json");
        let tools=match fs::symlink_metadata(&config){
            Ok(_)=>record::<Tools>(&config).map(|mut saved|{
                if saved.arm.is_none() && saved.arm_reason.is_none() {
                    match saved.system.verified() {
                        Ok(_verified) => { saved.detect_arm(); if save(&config,&saved).is_err(){saved.arm=None;saved.arm_reason=Some("Select QEMU in Settings to save the verified Arm installation.".into());} }
                        Err(error) => saved.arm_reason=Some(error.to_string()),
                    }
                }
                saved
            }).map_err(|e|e.to_string()),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Err("Choose a local qemu-system-x86_64.exe in Settings.".into()),
            Err(e)=>Err(e.to_string()),
        };
        Self{home:home.into(),supervisor:supervisor_exe.into(),bundles:BTreeMap::new(),tools}
    }
    pub fn set_executable(&mut self,path:Option<&Path>)->Result<()>{
        let config=self.home.join("qemu-engine.json");
        if let Some(path)=path {
            let tools=Tools::select(path)?;
            save(&config,&tools)?;self.tools=Ok(tools);
        } else {
            match fs::remove_file(config){Ok(())=>(),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),Err(e)=>return Err(io_error(e))}
            self.tools=Err("Choose a local qemu-system-x86_64.exe in Settings.".into());
        }
        Ok(())
    }
    fn available(&self)->Result<&Tools>{
        let tools=self.tools.as_ref().map_err(|r|err(format!("QEMU is not set up on this PC. {r}")))?;
        tools.unchanged()?;Ok(tools)
    }
    fn separate_window(&self) -> Result<bool> {
        let path = self.home.join("qemu-console.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_error(e)),
            Ok(_) => record(&path),
        }
    }

    pub fn set_separate_window(&mut self, open: bool) -> Result<()> {
        save(&self.home.join("qemu-console.json"), &open)
    }

    pub fn console_endpoint(&self, vm: &Vm) -> Result<ConsoleEndpoint> {
        if !matches!(vm.state, VmState::Running | VmState::Paused) {
            return Err(err("Start the machine to open its console."));
        }
        let (bundle, _) = self.definition(&vm.id)?;
        let key = machine_key(&self.home, &vm.id, bundle)?;
        let run = read_run(bundle, &key)?.filter(|r| r.port != 0)
            .ok_or_else(|| err("The running QEMU session could not be verified."))?;
        Ok(ConsoleEndpoint { key, run })
    }

    pub fn prerequisites(&self)->Value{
        let configured=self.tools.as_ref().ok();
        let reason=self.available().err().map(|e|e.to_string());
        let path=configured.map(|t|&t.system.path);
        let arm_reason=self.available().and_then(Tools::arm_tools).err().map(|e|e.to_string());
        json!({"armAvailable":arm_reason.is_none(),"armReason":arm_reason,"available":reason.is_none(),"reason":reason,"executable":path,"path":path,"version":configured.map(|t|&t.version),"openSeparateWindow":self.separate_window().ok()})
    }
    pub fn register_bundle(&mut self,id:&str,bundle:&Path)->Result<()>{
        if id.is_empty() || id.len()>80 || !id.bytes().all(|b|b.is_ascii_alphanumeric() || b"-_.".contains(&b)) ||
            !bundle.extension().is_some_and(|s|s.eq_ignore_ascii_case("swvm")){return Err(err("The QEMU library identity is invalid."));}
        let dir=local(bundle,true)?;
        let vm:Vm=record(&dir.join("vm.json"))?;
        if vm.id!=id || vm.engine!=EngineKind::Qemu{return Err(err("This bundle does not belong to the specified QEMU machine."));}
        self.bundles.insert(id.into(),dir);Ok(())
    }
    fn bundle(&self,id:&str)->Result<&Path>{
        self.bundles.get(id).map(PathBuf::as_path).ok_or_else(||EngineError::Missing(id.into()))
    }
    fn definition(&self,id:&str)->Result<(&Path,Definition)>{
        let dir=self.bundle(id)?;
        let path=dir.join("qemu-vm.json");
        if fs::symlink_metadata(&path).is_err_and(|e|e.kind()==std::io::ErrorKind::NotFound){return Err(EngineError::Missing(id.into()));}
        let def:Definition=record(&path)?;
        if def.id!=id {return Err(err("The QEMU registration belongs to a different machine."));}
        Ok((dir,def))
    }
    /// Allows recovery of an unresponsive guest monitor only if the private supervisor still
    /// authenticates and proves it holds the original, live child process.
    pub fn can_power_off_owned(&self,id:&str)->bool {
        let probe=(|| -> Result<bool> {
            let (dir,_)=self.definition(id)?;
            let key=machine_key(&self.home,id,dir)?;
            let Some(run)=read_run(dir,&key)? else{return Ok(false)};
            Ok(run.port!=0 && request(&key,&run,"probe")?["owned"]==true)
        })();
        probe.unwrap_or(false)
    }
    pub fn guest_agent(&self, vm: &Vm) -> Result<GuestAgentSession> {
        if vm.family == GuestFamily::Android {
            return Err(err("Android guests have no guest agent."));
        }
        if vm.state != VmState::Running {
            return Err(err("Start or resume the machine before using its guest agent."));
        }
        let (bundle, _) = self.definition(&vm.id)?;
        let key = machine_key(&self.home, &vm.id, bundle)?;
        let run = read_run(bundle, &key)?.ok_or_else(|| err("No running QEMU session."))?;
        if run.port == 0 { return Err(err("The running QEMU session could not be verified.")); }
        let report = request(&key, &run, "probe")?;
        if report["owned"] != true { return Err(err("The running QEMU session could not be verified.")); }
        let unavailable = report["guestAgentUnavailable"].as_str().map(str::to_owned);
        Ok(GuestAgentSession { family: vm.family, bundle: bundle.to_owned(), ticket: run.ticket, unavailable, supervisor: self.supervisor.clone() })
    }

    pub fn console_restore_warning(&self, id: &str) -> Option<String> {
        let (bundle, _) = self.definition(id).ok()?;
        let key = machine_key(&self.home, id, bundle).ok()?;
        let active = read_run(bundle, &key).ok()??;
        if active.port == 0 {
            return None;
        }
        let report = request(&key, &active, "probe").ok()?;
        if report["owned"] != true {
            return None;
        }
        report["presentationWarning"].as_str().map(str::to_owned)
    }

    pub fn audio_status(&self,vm:&Vm)->Value {
        if vm.family!=GuestFamily::Android {return json!({"enabled":false,"message":audio::silent_reason(vm.architecture)});}
        if vm.state==VmState::Off {
            return json!({"enabled":null,"message":"Guest sound uses the PC’s default output device when available. Output is checked at startup."});
        }
        let active=(|| -> Result<Value> {
            let (bundle,_)=self.definition(&vm.id)?;
            let key=machine_key(&self.home,&vm.id,bundle)?;
            let run=read_run(bundle,&key)?.ok_or_else(||err("No active QEMU session."))?;
            let report=request(&key,&run,"probe")?;
            if report["owned"]!=true || !report["audio"]["enabled"].is_boolean() || !report["audio"]["message"].is_string() {
                return Err(err("No playback report from this session."));
            }
            Ok(report["audio"].clone())
        })();
        active.unwrap_or_else(|_|json!({"enabled":null,"message":"The running session has not reported its audio output."}))
    }

    fn status(&self,id:&str)->Result<VmState>{
        let (dir,_)=self.definition(id)?;
        let key=machine_key(&self.home,id,dir)?;
        let Some(run)=read_run(dir,&key)? else{idle(dir)?;return Ok(VmState::Off)};
        if run.port==0{return Err(err("The QEMU startup is pending. Wait before starting again."));}
        match request(&key,&run,"state"){
            Ok(v)=>match v["state"].as_str(){Some("running")=>Ok(VmState::Running),Some("paused")=>Ok(VmState::Paused),Some("off")=>Ok(VmState::Off),_=>Err(err("QEMU returned an unknown state."))},
            Err(error)=>{
                // A guest can shut itself down between the authenticated request and the reply.
                // Allow the supervisor to retire its receipt, and prove the lifetime lock is free.
                let until=Instant::now()+Duration::from_millis(450);
                loop {
                    if read_run(dir,&key)?.is_none() && runtime_lock(dir).is_ok(){return Ok(VmState::Off);}
                    if Instant::now()>=until {return Err(error);}
                    thread::sleep(Duration::from_millis(30));
                }
            }
        }
    }
}

impl EngineDriver for Qemu {
    fn capabilities(&self,vm:&Vm)->CapabilitySet{
        let mut caps=CapabilitySet::unavailable("This QEMU profile does not provide this control.");
        caps.deny(Capability::Console,"Open this QEMU machine’s embedded console.");
        caps.deny(Capability::OwnLanAddress,"This QEMU profile uses QEMU user-mode NAT.");
        if vm.template.is_none() && vm.linked_from.is_none() {
            if vm.state==VmState::Running { caps.allow(Capability::Snapshot); }
            if vm.state==VmState::Off { caps.allow(Capability::RevertSnapshot); caps.allow(Capability::DeleteSnapshot); }
        }
        caps.deny(Capability::SnapshotWithMemory,"Memory snapshots are unavailable for this QEMU profile.");
        let arm=vm.architecture==GuestArchitecture::Aarch64;
        let imported=vm.disk_path.is_some() && (!arm || vm.linked_from.is_none());
        let ready=validate_profile(vm.architecture,vm.family,imported,vm.vcpu,vm.ram_gb).and_then(|()|{
            let tools=self.available()?;
            if arm {tools.arm_tools()?;}
            Ok(())
        });
        if let Err(e)=ready{caps.deny(Capability::Start,&e.to_string());caps.deny(Capability::Accelerated,&e.to_string());}
        else{
            caps.allow(Capability::Start);
            if arm {caps.deny(Capability::Accelerated,"Arm guests use software emulation on this PC.");}
            else {caps.allow(Capability::Accelerated);}
        }
        if vm.template.is_some() {caps.deny(Capability::Start,"A QEMU template cannot be started.");}
        if matches!(vm.state,VmState::Running|VmState::Paused){caps.allow(Capability::Stop);}
        if vm.state==VmState::Off{caps.allow(Capability::Delete);}
        caps
    }
    fn define(&mut self,vm:&Vm)->Result<()>{
        self.provision(vm,false)
    }
    fn state(&mut self,id:&str)->Result<VmState>{self.status(id)}
    fn start(&mut self,id:&str)->Result<()>{
        let bins=self.available()?.clone();
        let (bundle,def)=self.definition(id)?;
        let _lock=operation_lock(bundle)?;
        let vm:Vm=record(&bundle.join("vm.json"))?;
        validate(&vm,&def)?;
        if vm.template.is_some() {return Err(err("A QEMU template cannot be started."));}
        if self.status(id)?!=VmState::Off{return Err(err("The QEMU machine is already active."));}
        let open_separate_window = self.separate_window()?;
        validate_clipboard_display(vm.share_clipboard, open_separate_window)?;
        snapshot::recover_before_start(bundle,&bins,def.bytes(),def.linked_from.is_some() || vm.throwaway)?;
        let key=machine_key(&self.home,id,bundle)?;
        let run=Run::new(&key,unique(),0);
        let receipt=bundle.join("qemu-run.json");
        if vm.throwaway {
            throwaway::reserve(bundle, &vm.id, &run.ticket)?;
        }
        save(&receipt,&run)?;
        let spawned=tools::command(&self.supervisor).arg("--qemu-supervisor").arg(bundle).current_dir(bundle)
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
        let mut child=match spawned{Ok(c)=>c,Err(e)=>{fs::remove_file(receipt).map_err(io_error)?;return Err(io_error(e));}};
        let input=supervisor::Launch{key:key.clone(),ticket:run.ticket.clone(),tools:bins,home:self.home.clone(),open_separate_window};
        {
            let mut pipe=child.stdin.take().expect("piped supervisor input");
            serde_json::to_writer(&mut pipe,&input).map_err(io_error)?;pipe.flush().map_err(io_error)?;
        }
        // Allow the bounded playback probe and one paused, silent retry before timing out.
        let until=Instant::now()+Duration::from_secs(90);
        loop{
            if let Some(current)=read_run(bundle,&key)?{
                if current.ticket!=run.ticket{return Err(err("The QEMU start identity changed."));}
                if current.port!=0 && request(&key,&current,"state")?["state"]=="running"{
                    // Reap only this helper when it eventually exits. Its handle is not needed to reconnect.
                    thread::spawn(move||{let _=child.wait();});
                    return Ok(());
                }
            }
            if child.try_wait().map_err(io_error)?.is_some(){
                let outcome=record::<supervisor::Outcome>(&bundle.join("qemu-outcome.json")).ok().filter(|v|v.ticket==run.ticket);
                return Err(err(outcome.map(|v|v.message).filter(|s|!s.is_empty()).unwrap_or_else(||"The QEMU supervisor exited before it confirmed startup.".into())));
            }
            if Instant::now()>=until{return Err(err("The QEMU supervisor did not confirm startup. Check machine state before retrying."));}
            thread::sleep(Duration::from_millis(60));
        }
    }
    fn stop(&mut self,id:&str)->Result<()> {
        let (bundle,_)=self.definition(id)?;
        let _lock=operation_lock(bundle)?;
        let key=machine_key(&self.home,id,bundle)?;
        let Some(run)=read_run(bundle,&key)?else{idle(bundle)?;return Ok(())};
        if run.port==0{return Err(err("The QEMU supervisor has not confirmed startup."));}
        let result=request(&key,&run,"stop");
        let until=Instant::now()+Duration::from_secs(2);
        loop{
            if read_run(bundle,&key)?.is_none(){return Ok(());}
            if Instant::now()>=until{break;}
            thread::sleep(Duration::from_millis(30));
        }
        result?;Err(err("The QEMU worker has not been confirmed off."))
    }
    fn remove(&mut self,id:&str)->Result<()>{
        let (bundle,_)=self.definition(id)?;
        let _lock=operation_lock(bundle)?;
        if self.status(id)?!=VmState::Off{return Err(err("Power off this QEMU machine before removing it."));}
        fs::remove_file(bundle.join("qemu-vm.json")).map_err(io_error)
    }
    fn list_snapshots(&mut self,id:&str)->Result<Vec<Snapshot>> { snapshot::list(self.definition(id)?.0) }
    fn snapshot(&mut self,id:&str,name:&str,with_memory:bool)->Result<Snapshot> { self.take_snapshot(id,name,with_memory) }
    fn revert(&mut self,id:&str,snapshot:&str)->Result<()> { self.edit_snapshot(id,snapshot,false) }
    fn delete_snapshot(&mut self,id:&str,snapshot:&str)->Result<()> { self.edit_snapshot(id,snapshot,true) }
    fn pause(&mut self,_:&str)->Result<()>{Err(err("QEMU pause is unavailable in this profile."))}
    fn resume(&mut self,_:&str)->Result<()>{Err(err("QEMU resume is unavailable in this profile."))}
    fn shutdown(&mut self,_:&str)->Result<()>{Err(err("Guest shutdown integration is unavailable in this profile."))}
    fn restart(&mut self,_:&str)->Result<()>{Err(err("Guest restart integration is unavailable in this profile."))}
    fn send_keys(&mut self,_:&str,_:&GuestKeys)->Result<GuestKeyReport>{Err(err("Use the QEMU display for guest input."))}
    fn thumbnail(&mut self,_:&str)->Result<Thumbnail>{Err(err("Use the QEMU display to see this machine."))}
}
fn operation_lock(bundle:&Path)->Result<File>{ file_lock(bundle,"qemu-control.lock","Another operation owns this QEMU machine.") }
// A supervisor retires its receipt just before it releases the lifetime lock. Allow that moment.
fn idle(bundle:&Path)->Result<()>{
    let until=Instant::now()+Duration::from_millis(450);
    loop{
        match runtime_lock(bundle){
            Ok(_)=>return Ok(()),
            Err(error) if Instant::now()>=until=>return Err(error),
            Err(_)=>thread::sleep(Duration::from_millis(15)),
        }
    }
}
fn runtime_lock(bundle:&Path)->Result<File>{ file_lock(bundle,"qemu-lifetime.lock","A QEMU supervisor still owns this machine. Wait for its verified state.") }
fn file_lock(bundle:&Path,name:&str,reason:&str)->Result<File>{
    let path=bundle.join(name);
    let lock=OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path).map_err(io_error)?;
    local(&path,false)?;
    lock.try_lock().map_err(|_|err(reason))?;
    Ok(lock)
}
