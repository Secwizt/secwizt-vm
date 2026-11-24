use crate::{
    capture::{self,Capture,StopReason},
    control::{self,Run},err,io_error,local,record,save,tools::{self,Tools},Definition,Result,
};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use std::{
    fs,io::{BufRead,BufReader,Read,Write},net::{Shutdown,TcpListener,TcpStream},path::Path,
    process::{Child,ChildStdin,Stdio},sync::mpsc::{self,Receiver},thread,time::{Duration,Instant},
};
use svm_core::model::Vm;

#[derive(Serialize,Deserialize)]
pub(crate) struct Launch {pub key:String,pub ticket:String,pub tools:Tools,pub home:std::path::PathBuf, #[serde(default)] pub open_separate_window:bool}
#[derive(Serialize,Deserialize)]
pub(crate) struct Outcome {pub ticket:String,pub message:String}

fn disk_arguments(bundle:&Path,vm:&Vm,legacy_windows:bool,backing:Option<&Path>,overlay:Option<&Path>)->Result<Vec<String>> {
    let network = crate::port_forward::user_network(&vm.port_forwards, vm.isolated)?;
    let (machine,video)=if legacy_windows {("pc,i8042=on","VGA")} else {("pc,i8042=off","virtio-vga")};
    let mut args:Vec<String>=["-no-user-config","-nodefaults","-machine",machine,"-accel","whpx","-smp",&vm.vcpu.to_string(),"-m",&(u64::from(vm.ram_gb)*1024).to_string(),
        "-name",&format!("svm-{}",vm.id),"-qmp","stdio","-monitor","none","-serial","none"].iter().map(|s|s.to_string()).collect();
    crate::linked::append_block_devices(&mut args,bundle,backing,overlay)?;
    args.extend(["-device","ide-hd,drive=system,bus=ide.0,unit=0",
        "-device",video,"-netdev",&network,"-device",&format!("e1000,netdev=nat0,mac={}",vm.mac)].map(str::to_owned));
    if let Some(seed)=first_boot_seed(bundle,vm)? {
        // Read-only FAT view of the machine's private first-boot settings (cloud-init NoCloud).
        let drive=json!({"driver":"vvfat","node-name":"first-boot","dir":seed,"label":"CIDATA","read-only":true}).to_string();
        // IDE disks cannot be read-only in QEMU; virtio-blk reports the read-only flag to the guest.
        args.extend(["-blockdev".into(),drive,"-device".into(),"virtio-blk-pci,drive=first-boot".into()]);
    }
    if !legacy_windows {
        // The PS/2 mouse becomes current before Android loads the absolute tablet.
        // Keeping the default input pair on USB avoids that mouse in the boot menu too.
        args.extend(["-device","qemu-xhci","-device","usb-kbd","-device","usb-tablet"].map(str::to_owned));
    }
    let order=if let Some(path)=vm.iso_path.as_deref() {
        let iso=local(path,false)?;
        let file=json!({"driver":"file","node-name":"iso-file","filename":iso,"read-only":true}).to_string();
        let image=json!({"driver":"raw","node-name":"installer","file":"iso-file","read-only":true}).to_string();
        args.extend(["-blockdev".into(),file,"-blockdev".into(),image,"-device".into(),
            "ide-cd,drive=installer,bus=ide.1,unit=0".into()]);
        "order=c,once=d"
    } else {"order=c"};
    args.extend(["-boot".into(),order.into()]);
    Ok(args)
}

/// The machine's private first-boot settings folder, when its ready image asks for one.
fn first_boot_seed(bundle:&Path,vm:&Vm)->Result<Option<String>> {
    if !vm.ready.as_ref().is_some_and(|ready|ready.seed) {return Ok(None);}
    if vm.architecture!=svm_core::model::GuestArchitecture::X86_64 {
        return Err(err("First-boot settings are available for x86 QEMU machines only."));
    }
    let folder=local(&bundle.join(crate::FIRST_BOOT),true)?;
    if !fs::symlink_metadata(&folder).map_err(crate::io_error)?.is_dir() {
        return Err(err("The machine's first-boot settings folder is missing."));
    }
    let text=folder.to_str().ok_or_else(||err("The first-boot settings folder path is not valid text."))?;
    // QEMU lists this folder through the C runtime, which does not accept the verbatim prefix.
    let plain=text.strip_prefix(r"\\?\").unwrap_or(text);
    if !plain.as_bytes().get(1).is_some_and(|byte|*byte==b':') {
        return Err(err("The first-boot settings folder must be on a local drive."));
    }
    Ok(Some(plain.to_owned()))
}

#[cfg(windows)]
fn limit_worker(cores:&[u16],vcpu:u16)->Result<()> {
    let root=std::env::var_os("SystemRoot").ok_or_else(||err("Windows system folder is unavailable."))?;
    let mut c=tools::command(&std::path::PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"));
    // This helper is alive while the child PowerShell runs, so its own PID cannot be recycled.
    // The QEMU worker inherits the restricted affinity on creation, before guest code runs.
    let script=r#"$ErrorActionPreference='Stop'
$p=[Diagnostics.Process]::GetProcessById([int]$env:SVM_QEMU_PARENT)
$allowed=$p.ProcessorAffinity.ToInt64()
$wanted=[int]$env:SVM_QEMU_CPUS
$preferred=@($env:SVM_QEMU_CORES -split ',' | Where-Object {$_ -match '^\d+$'} | ForEach-Object {[int]$_})
$mask=[int64]0
$selected=0
foreach($bit in @($preferred+@(0..62))){
    if($bit -lt 0 -or $bit -gt 62){continue}
    $slot=[int64]1 -shl $bit
    if(($allowed -band $slot) -and !($mask -band $slot)){$mask=$mask -bor $slot;$selected++}
    if($selected -ge $wanted){break}
}
if ($mask -eq 0) { throw 'No permitted CPU for the QEMU worker.' }
$p.ProcessorAffinity=[IntPtr]$mask
$p.PriorityClass='BelowNormal'
if($p.ProcessorAffinity.ToInt64() -ne $mask) { throw 'The QEMU worker CPU limit could not be confirmed.' }"#;
    c.args(["-NoProfile","-NonInteractive","-Command",script]).env("SVM_QEMU_PARENT",std::process::id().to_string())
        .env("SVM_QEMU_CPUS",vcpu.to_string())
        .env("SVM_QEMU_CORES",cores.iter().map(u16::to_string).collect::<Vec<_>>().join(","));
    tools::run(c,8).map(drop)
}
#[cfg(not(windows))]
fn limit_worker(_: &[u16],_:u16)->Result<()> {Ok(())}

#[cfg(windows)]
fn present_console(child: &Child, id: &str) -> Result<()> {
    let root = std::env::var_os("SystemRoot").ok_or_else(|| err("Windows system folder is unavailable."))?;
    let exe = std::path::PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut helper = tools::command(&exe);
    helper.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", include_str!("present-console.ps1")])
        .env("SVM_CONSOLE_PID", child.id().to_string())
        .env("SVM_CONSOLE_ID", id);
    tools::run(helper, 8).map(drop)
}

#[cfg(any(windows, test))]
fn presentation_warning(restore: Result<()>) -> Option<&'static str> {
    restore.err().map(|_| "Windows could not restore the QEMU console during startup.")
}

struct Worker {child:Child,input:ChildStdin,frames:Receiver<Value>,errors:Receiver<Vec<u8>>,next:u64,broken:bool,late_through:Option<u64>,audio:Value,presentation_warning:Option<&'static str>}

fn frames(input:impl Read+Send+'static)->Receiver<Value> {
    let (tx,rx)=mpsc::sync_channel(8);
    thread::spawn(move||{
        let mut reader=BufReader::new(input);
        loop {
            let mut bytes=Vec::new();
            let n=(&mut reader).take(65537).read_until(b'\n',&mut bytes);
            if !matches!(n,Ok(1..=65536)) || bytes.last()!=Some(&b'\n'){break;}
            let Ok(v)=serde_json::from_slice(&bytes) else {break};
            if tx.send(v).is_err(){break;}
        }
    });
    rx
}
fn audio_error(message:&str)->bool {
    let lower=message.to_ascii_lowercase();
    ["audio:","-audiodev","dsound:","directsound","sdl audio","hda-output","intel-hda"].iter().any(|hint|lower.contains(hint))
}
impl Worker {
    fn launch(bundle:&Path,vm:&Vm,def:&Definition,bins:&Tools,backing:Option<&Path>,throwaway:Option<&crate::throwaway::Disk>,agent:Option<&crate::agent_transport::Endpoint>,open_separate_window:bool,exit_proven:&mut bool)->Result<(Self, crate::vnc::Vnc)> {
        let (system,mut args,_firmware)=if vm.architecture==svm_core::model::GuestArchitecture::Aarch64 {
            let arm=bins.arm_tools()?;
            let firmware=arm.code.verified()?;
            let vars=local(&bundle.join("uefi-vars.fd"),false)?;
            if std::fs::metadata(&vars).map_err(io_error)?.len()!=arm.variables_size() {
                return Err(err("The machine's Arm UEFI variables file is incomplete."));
            }
            (&arm.system,crate::arm::arguments(bundle,vm,&arm.code.path,backing,throwaway)?,Some(firmware))
        } else {
            (&bins.system,disk_arguments(bundle,vm,def.legacy_windows,backing,throwaway.map(|run| run.disk.as_path()))?,None)
        };
        let _binary=system.verified()?;
        if agent.is_some() || vm.share_clipboard {
            args.extend(["-device", "virtio-serial-pci,id=svm-agent-bus"].map(str::to_owned));
        }
        if let Some(agent) = agent { args.extend(agent.arguments()); }
        if vm.share_clipboard {
            args.extend([
                "-chardev", "qemu-vdagent,id=svm-clipboard,clipboard=on,mouse=off",
                "-device", "virtserialport,bus=svm-agent-bus.0,chardev=svm-clipboard,name=com.redhat.spice.0",
            ].map(str::to_owned));
        }
        if open_separate_window {
            let mut displays=tools::command(&system.path);
            displays.args(["-display","help"]);
            let graphical = if tools::run(displays,5)?.lines().any(|line|line.trim()=="gtk") {
                "gtk,grab-on-hover=off"
            } else { "default" };
            args.extend(["-display".into(), graphical.into()]);
        } else {
            args.extend(["-display".into(), "none".into()]);
        }
        args.extend(["-vnc".into(), crate::vnc::ARGUMENT.into()]);
        if backing.is_none() {bins.inspect_disk(&bundle.join(crate::linked::DISK),def.bytes())?;}
        limit_worker(&vm.cores,vm.vcpu)?;
        let audio=crate::audio::for_guest(bins,vm.family,vm.architecture);
        // Keep vCPUs paused until the output backend has initialized. An audio-only failure
        // can then retry silently without ever booting the same guest twice.
        args.push("-S".into());
        let silent_len=args.len();
        args.extend(audio.args);
        crate::port_forward::check_available(&vm.port_forwards)?;
        let mut worker=match Self::open_paused(bundle,&system.path,&args,audio.status.clone(),exit_proven) {
            Ok(worker)=>worker,
            Err(error) if *exit_proven && audio.status["enabled"]==true && audio_error(&error.to_string())=>{
                args.truncate(silent_len);
                if let Some(agent) = agent { agent.discard_prior_connection(); }
                let muted=json!({"enabled":false,"message":"Sound is off because QEMU could not open the PC’s audio output."});
                crate::port_forward::check_available(&vm.port_forwards)?;
                Self::open_paused(bundle,&system.path,&args,muted,exit_proven)?
            }
            Err(error)=>return Err(error),
        };
        // Handle presentation once, before the guest starts accepting input. Later minimizes belong to the user.
        #[cfg(windows)]
        if open_separate_window {
            worker.presentation_warning = presentation_warning(present_console(&worker.child, &vm.id));
        }
        let start = (|| {
            let display = crate::vnc::Vnc::new(&worker.execute("query-vnc-servers")?)?;
            worker.execute_with("set_password", Some(json!({"protocol":"vnc","password":display.password()})), Duration::from_secs(3))
                .map_err(|_| err("QEMU could not set the private display password."))?;
            worker.execute("cont")?;
            if worker.state()? != "running" { return Err(err("The QEMU guest did not begin running.")); }
            Ok(display)
        })();
        match start {
            Ok(display) => Ok((worker, display)),
            Err(error) => { worker.force_off()?; *exit_proven = true; Err(error) }
        }
    }
    fn open_paused(bundle:&Path,exe:&Path,args:&[String],audio:Value,exit_proven:&mut bool)->Result<Self> {
        let mut child=tools::command(exe).args(args).current_dir(bundle)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(io_error)?;
        *exit_proven=false;
        let input=child.stdin.take().expect("piped stdin");
        let inbox=frames(child.stdout.take().expect("piped stdout"));
        let errors=tools::drain(child.stderr.take().expect("piped stderr"),2048);
        let mut worker=Self{child,input,frames:inbox,errors,next:0,broken:false,late_through:None,audio,presentation_warning:None};
        let initialized=(|| {
            let greeting=worker.frames.recv_timeout(Duration::from_secs(12)).map_err(|_|err("QEMU did not open its private control channel."))?;
            if !greeting["QMP"].is_object(){return Err(err("QEMU returned an invalid QMP greeting."));}
            worker.execute("qmp_capabilities")?;
            let state=worker.execute("query-status")?;
            if state["running"]!=false || !matches!(state["status"].as_str(),Some("prelaunch"|"paused")) {
                return Err(err("QEMU did not confirm paused initialization."));
            }
            Ok(())
        })();
        if let Err(e)=initialized{
            worker.force_off()?;
            *exit_proven=true;
            let detail=worker.errors.recv_timeout(Duration::from_millis(750)).unwrap_or_default();
            return Err(err(format!("The QEMU guest did not start. {e} {}",String::from_utf8_lossy(&detail).trim())));
        }
        Ok(worker)
    }
    fn execute(&mut self,op:&str)->Result<Value> {
        let result = self.execute_with(op, None, Duration::from_secs(3));
        if result.is_err() && self.late_through.is_none() { self.broken = true; }
        result
    }
    fn execute_with(&mut self, op: &str, arguments: Option<Value>, timeout: Duration) -> Result<Value> {
        if self.broken { return Err(err("The private QEMU control stream is unavailable.")); }
        self.next += 1;
        let id = self.next;
        let mut wait_expired = false;
        let answer = (|| {
            let mut request = json!({"execute":op,"id":id});
            if let Some(arguments) = arguments { request["arguments"] = arguments; }
            writeln!(self.input, "{request}").map_err(io_error)?;
            self.input.flush().map_err(io_error)?;
            let limit = Instant::now() + timeout;
            loop {
                let left = limit.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()).ok_or_else(|| {
                    wait_expired = true;
                    err("QEMU did not answer its control request in time.")
                })?;
                let value = match self.frames.recv_timeout(left) {
                    Ok(frame) => frame,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        wait_expired = true;
                        return Err(err("QEMU did not answer its control request in time."));
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Err(err("The QEMU control stream closed.")),
                };
                if value.get("event").is_some() { continue; }
                let reply_id = value["id"].as_u64();
                if let (Some(limit), Some(old)) = (self.late_through, reply_id) {
                    if (1..=limit).contains(&old) { continue; }
                }
                if reply_id != Some(id) { return Err(err("QEMU returned an unexpected control identity.")); }
                return Ok(value);
            }
        })();
        if wait_expired && (self.late_through.is_some() || matches!(op,"blockdev-snapshot-internal-sync"|"object-add"|"object-del")) {
            // Checkpoints and capture changes can finish after the caller times out. Match later replies by ID.
            self.late_through = Some(id);
        } else if answer.is_err() {
            self.broken = true;
        } else {
            self.late_through = None;
        }
        let answer = answer?;
        if let Some(value) = answer.get("return") { return Ok(value.clone()); }
        Err(err(answer.pointer("/error/desc").and_then(Value::as_str).unwrap_or("QEMU declined the operation.")))
    }
    fn state(&mut self)->Result<&'static str>{
        let v=self.execute("query-status")?;
        match v["status"].as_str(){
            Some("running")=>Ok("running"),Some("paused"|"io-error"|"watchdog"|"suspended")=>Ok("paused"),
            _=>Err(err("QEMU has not confirmed a supported machine state."))
        }
    }
    fn force_off(&mut self)->Result<()> {
        if self.child.try_wait().map_err(io_error)?.is_some(){return Ok(());}
        if let Err(e)=self.child.kill(){if self.child.try_wait().map_err(io_error)?.is_none(){return Err(io_error(e));}}
        let limit=Instant::now()+Duration::from_secs(3);
        while Instant::now()<limit {
            if self.child.try_wait().map_err(io_error)?.is_some(){return Ok(());}
            thread::sleep(Duration::from_millis(25));
        }
        Err(err("The owned QEMU child has not confirmed exit."))
    }
    fn stop(&mut self)->Result<()> {
        let _=self.execute("quit");
        let limit=Instant::now()+Duration::from_secs(2);
        while Instant::now()<limit{
            if self.child.try_wait().map_err(io_error)?.is_some(){return Ok(());}
            thread::sleep(Duration::from_millis(30));
        }
        self.force_off()
    }
}
impl Drop for Worker {fn drop(&mut self){let _=self.force_off();}}

fn finish_capture(worker: &mut Worker, active: &mut Option<Capture>, reason: StopReason) -> Result<()> {
    if active.is_some() {
        if let Err(error) = worker.execute_with("object-del", Some(json!({"id":capture::FILTER_ID})), Duration::from_secs(3)) {
            // A delayed deletion can finish after its reply timed out. Publish only if
            // a fresh answer proves that the filter no longer exists.
            let absent = worker.execute_with("qom-list", Some(json!({"path":"/objects"})), Duration::from_secs(3))
                .is_ok_and(|objects| objects.as_array().is_some_and(|properties| properties.iter()
                    .all(|property| property["name"].as_str().is_some_and(|name| name != capture::FILTER_ID))));
            if !absent { return Err(error); }
        }
        if let Some(owned) = active.take() {
            owned.finish(reason)?;
        }
    }
    Ok(())
}

const ORPHAN_GRACE:Duration=Duration::from_secs(600);

fn orphan_expired(last_owner:Instant,now:Instant)->bool {
    now.duration_since(last_owner)>=ORPHAN_GRACE
}

/// Windows reports a connection that was reset or aborted before accept() as an accept error. That
/// concerns only the one peer, so the control loop keeps serving instead of powering the machine off.
fn accept_is_transient(kind:std::io::ErrorKind)->bool {
    matches!(kind,std::io::ErrorKind::ConnectionReset|std::io::ErrorKind::ConnectionAborted|std::io::ErrorKind::Interrupted)
}

fn service_is_present(home:&Path)->bool {
    let Ok(file)=fs::OpenOptions::new().read(true).write(true).open(home.join("service.lock")) else {return false};
    matches!(file.try_lock_shared(),Err(std::fs::TryLockError::WouldBlock))
}

fn run(bundle:&Path,vm:&Vm,def:&Definition,input:&Launch,exit_proven:&mut bool)->Result<()> {
    crate::validate_clipboard_display(vm.share_clipboard, input.open_separate_window)?;
    // Keep the checked parent and leaf handles for the life of this QEMU process.
    let backing = crate::linked::runtime_parent(&input.home,bundle,vm,def)?;
    let throwaway = vm.throwaway.then(|| crate::throwaway::prepare(bundle, vm, def, input)).transpose()?;
    let (agent, agent_unavailable) = match crate::agent_transport::Endpoint::open(bundle, &input.ticket) {
        Ok(endpoint) => (Some(endpoint), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let (mut worker, display) = Worker::launch(bundle, vm, def, &input.tools, backing.as_ref().map(crate::linked::RuntimeBacking::path),
        throwaway.as_ref(), agent.as_ref(), input.open_separate_window, exit_proven)?;
    let display = std::sync::Arc::new(display);
    let mut viewers: Vec<(TcpStream, thread::JoinHandle<()>)> = Vec::new();
    let relay = agent.map(crate::agent_transport::Endpoint::serve);
    let mut active_capture: Option<Capture> = None;
    let result=(|| {
    // Let QEMU claim its forward ports before allocating this private endpoint.
    // The service loopback address: a guest's user-mode network reaches only 127.0.0.1 on the host.
    let listener=TcpListener::bind((svm_core::local_auth::SERVICE_HOST,0)).map_err(io_error)?;
    listener.set_nonblocking(true).map_err(io_error)?;
    let endpoint=Run::new(&input.key,input.ticket.clone(),listener.local_addr().map_err(io_error)?.port());
    save(&bundle.join("qemu-run.json"),&endpoint)?;
    let mut owner_seen=Instant::now();
    let mut next_check=Instant::now();
    let mut next_capture_check=Instant::now();
    loop {
        if Instant::now() >= next_capture_check {
            next_capture_check = Instant::now() + Duration::from_millis(100);
            if let Some(reason) = active_capture.as_ref().and_then(Capture::stop_reason) {
                if finish_capture(&mut worker, &mut active_capture, reason).is_err() {
                    next_capture_check = Instant::now() + Duration::from_secs(1);
                }
            }
        }
        if Instant::now()>=next_check {
            next_check=Instant::now()+Duration::from_secs(5);
            if service_is_present(&input.home) {owner_seen=Instant::now();}
            if orphan_expired(owner_seen,Instant::now()) {
                worker.stop()?;
                return Ok(());
            }
        }
        if let Some(status)=worker.child.try_wait().map_err(io_error)?{
            if !status.success(){return Err(err(format!("QEMU exited with {status}.")));}
            return Ok(());
        }
        match listener.accept(){
            Ok((stream,_))=>{
                let mut stopped=false;
                viewers.retain(|(_, viewer)| !viewer.is_finished());
                let opened=control::serve(stream,&input.key,&endpoint,|op| {
                    owner_seen=Instant::now();
                    if op=="probe" {Ok(json!({"owned":worker.child.try_wait().map_err(io_error)?.is_none(),"audio":worker.audio,"presentationWarning":worker.presentation_warning,"guestAgentUnavailable":agent_unavailable,"checkpoints":def.linked_from.is_none() && !vm.throwaway}))}
                    else if op == "console" {
                        if viewers.len() >= 2 { return Err(err("This machine already has two console connections.")); }
                        if worker.child.try_wait().map_err(io_error)?.is_some() { return Err(err("The owned QEMU display already stopped.")); }
                        Ok(json!({"ready":true}))
                    }
                    else if op=="stop" {
                        worker.stop()?;
                        if let Some(owned) = active_capture.take() { let _ = owned.finish(StopReason::MachineStopped); }
                        stopped=true;
                        Ok(json!({"state":"off"}))
                    }
                    else if op=="capture-status" { Ok(json!({"active":active_capture.is_some()})) }
                    else if op=="capture-stop" {
                        finish_capture(&mut worker,&mut active_capture,StopReason::Stopped)?;
                        Ok(json!({"active":false}))
                    }
                    else if let Some(limit) = capture::start_limit(op) {
                        if active_capture.is_some() { return Err(err("A packet capture is already active.")); }
                        if worker.state()? != "running" { return Err(err("Start or resume the QEMU machine before capturing packets.")); }
                        let owned = Capture::prepare(bundle, limit)?;
                        let added = worker.execute_with("object-add",Some(owned.arguments()),Duration::from_secs(3));
                        if added.is_ok() || worker.broken || worker.late_through.is_some() {
                            active_capture = Some(owned);
                        } else {
                            owned.discard();
                        }
                        added?;
                        Ok(json!({"active":true}))
                    }
                    else if op == "snapshot" {
                        if vm.throwaway {return Err(err("Checkpoints are unavailable during a throwaway run."));}
                        if def.linked_from.is_some() {return Err(err("Checkpoints are unavailable for QEMU linked disks."));}
                        if worker.state()? != "running" { return Err(err("The QEMU guest is no longer running.")); }
                        crate::snapshot::capture_pending(bundle, &endpoint,
                            |call| crate::agent_transport::call_here(bundle, &endpoint.ticket, call),
                            |tag| worker.execute_with("blockdev-snapshot-internal-sync",
                                Some(json!({"device":"system","name":tag})), Duration::from_secs(10)).map(drop))
                    }
                    else{Ok(json!({"state":worker.state()?}))}
                });
                if let Ok(Some(stream)) = opened {
                    if let Ok(peer) = stream.try_clone() {
                        let display = display.clone();
                        let viewer = thread::spawn(move || { let _ = display.serve(stream); });
                        viewers.push((peer, viewer));
                    }
                }
                if stopped{return Ok(());}
            }
            Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>thread::sleep(Duration::from_millis(30)),
            // A local peer that resets or aborts before the accept completes must not stop the machine.
            Err(e) if accept_is_transient(e.kind())=>continue,
            Err(e)=>return Err(io_error(e)),
        }
    }
    })();
    display.close();
    let exited = worker.force_off();
    for (peer, _) in &viewers { let _ = peer.shutdown(Shutdown::Both); }
    for (_, viewer) in viewers { let _ = viewer.join(); }
    exited?;
    if let Some(owned) = active_capture.take() { let _ = owned.finish(StopReason::MachineStopped); }
    drop(relay);
    *exit_proven=true;
    result
}

/// Entry point reserved for the child launched by the local service. Input stays on its private stdin.
pub fn supervise(bundle:&Path)->Result<()> {
    let bundle=local(bundle,true)?;
    let mut raw=Vec::new();
    std::io::stdin().lock().take(65537).read_to_end(&mut raw).map_err(io_error)?;
    if raw.len()>65536{return Err(err("The QEMU startup record was too large."));}
    let input:Launch=serde_json::from_slice(&raw).map_err(|_|err("The private QEMU startup record is invalid."))?;
    if input.key.len()!=64 || !input.key.bytes().all(|b|b.is_ascii_hexdigit()){return Err(err("The QEMU startup identity is invalid."));}
    // Lock first: crash recovery retires a receipt only while it holds this lock, so a supervisor that
    // starts late finds the receipt gone and never launches from a retired request.
    let lifetime=crate::runtime_lock(&bundle)?;
    let pending=control::read_run(&bundle,&input.key)?.ok_or_else(||err("No owned QEMU start is pending."))?;
    if pending.ticket!=input.ticket || pending.port!=0{return Err(err("The QEMU start identity changed."));}
    let mut exit_proven=true;
    let mut throwaway_id = None;
    let result=(|| {
        let vm:Vm=record(&bundle.join("vm.json"))?;
        let def:Definition=record(&bundle.join("qemu-vm.json"))?;
        if control::machine_key(&input.home,&vm.id,&bundle)?!=input.key {
            return Err(err("The supervisor identity does not belong to this service and bundle."));
        }
        crate::validate(&vm,&def)?;
        if vm.template.is_some() {return Err(err("A QEMU template cannot be started."));}
        if vm.throwaway { throwaway_id = Some(vm.id.clone()); }
        run(&bundle,&vm,&def,&input,&mut exit_proven)
    })();
    // Release this process’s working directory before publishing that the bundle is idle.
    let _ = std::env::set_current_dir(&input.home);
    // Write completion before releasing the live receipt. An interrupted supervisor stays uncertain.
    save(&bundle.join("qemu-outcome.json"),&Outcome{ticket:input.ticket.clone(),message:result.as_ref().err().map_or_else(String::new,ToString::to_string)})?;
    if exit_proven {
        if let Some(id) = throwaway_id {
            crate::throwaway::finish(&bundle, &id, &input.ticket)?;
        } else {
            fs::remove_file(bundle.join("qemu-run.json")).map_err(io_error)?;
        }
    }
    drop(lifetime);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reset_peer_does_not_end_the_control_loop() {
        use std::io::ErrorKind;
        for kind in [ErrorKind::ConnectionReset,ErrorKind::ConnectionAborted,ErrorKind::Interrupted] { assert!(accept_is_transient(kind)); }
        for kind in [ErrorKind::PermissionDenied,ErrorKind::InvalidInput,ErrorKind::Other] { assert!(!accept_is_transient(kind)); }
    }

    #[test]
    fn legacy_windows_uses_bios_devices_without_changing_the_default_pc()->Result<()> {
        let home=std::env::temp_dir().canonicalize().map_err(io_error)?
            .join(format!("svm-bios-{}",control::unique()));
        fs::create_dir(&home).map_err(io_error)?;
        let disk=home.join("system.qcow2");
        let iso=home.join("fixture.iso");
        fs::write(&disk,[]).map_err(io_error)?;
        fs::write(&iso,[]).map_err(io_error)?;
        let mut vm:Vm=serde_json::from_value(json!({
            "id":"fixture","name":"Fixture","os":"An arbitrary display label","family":"windows",
            "engine":"QEMU","accel":true,"state":"off","vcpu":1,"ramGb":2,"diskGb":16,"net":"nat",
            "ip":"10.0.2.15","mac":"02:00:00:00:00:01","dns":"fixture","isoPath":iso
        })).expect("synthetic VM");
        let before:Definition=serde_json::from_value(json!({"id":vm.id,"gib":16,"iso":iso}))
            .expect("existing QEMU record");
        let installed:Definition=serde_json::from_value(json!({"id":vm.id,"gib":16,"iso":iso,"legacy_windows":true}))
            .expect("BIOS Windows record");
        let expected_validation=crate::provision::validate(&vm,&installed);
        let legacy=disk_arguments(&home,&vm,installed.legacy_windows,None,None);
        let default=disk_arguments(&home,&vm,before.legacy_windows,None,None);
        vm.iso_path=None;
        let eject_validation=crate::provision::validate(&vm,&installed);
        let ejected=disk_arguments(&home,&vm,installed.legacy_windows,None,None);
        fs::remove_file(&iso).map_err(io_error)?;
        fs::remove_file(&disk).map_err(io_error)?;
        fs::remove_dir(home).map_err(io_error)?;

        expected_validation?;
        eject_validation?;
        let legacy=legacy?;
        let default=default?;
        let ejected=ejected?;
        let has=|args:&[String],flag:&str| args.iter().any(|arg|arg==flag);
        assert!(!before.legacy_windows);
        for flag in ["pc,i8042=on","VGA","ide-hd,drive=system,bus=ide.0,unit=0","ide-cd,drive=installer,bus=ide.1,unit=0","order=c,once=d"] {
            assert!(has(&legacy,flag),"{flag}");
        }
        for flag in ["pc,i8042=off","virtio-vga","qemu-xhci","usb-kbd","usb-tablet"] {
            assert!(has(&default,flag),"{flag}");
            assert!(!has(&legacy,flag),"{flag}");
        }
        assert!(has(&ejected,"order=c"));
        assert!(!has(&ejected,"ide-cd,drive=installer,bus=ide.1,unit=0"));
        Ok(())
    }

    #[test]
    fn a_restore_error_is_a_plain_startup_warning() {
        assert_eq!(presentation_warning(Ok(())), None);
        assert_eq!(
            presentation_warning(Err(err("internal Windows helper error"))),
            Some("Windows could not restore the QEMU console during startup."),
        );
    }

    #[test]
    fn orphan_grace_begins_again_after_service_contact() {
        let initial=Instant::now();
        let later=initial+Duration::from_secs(590);
        assert!(!orphan_expired(initial,later));
        assert!(orphan_expired(initial,initial+ORPHAN_GRACE));
        assert!(!orphan_expired(later,initial+ORPHAN_GRACE));
        assert!(orphan_expired(later,later+ORPHAN_GRACE));
    }

    #[test]
    fn only_a_held_service_lock_indicates_an_owner()->std::io::Result<()> {
        let home=std::env::temp_dir().join(format!("svm-owner-{}",control::unique()));
        fs::create_dir(&home)?;
        let path=home.join("service.lock");
        let absent=!service_is_present(&home);
        let owner=fs::File::create_new(&path)?;
        owner.lock()?;
        let present=service_is_present(&home);
        drop(owner);
        let gone=!service_is_present(&home);
        fs::remove_file(path)?;
        fs::remove_dir(home)?;
        assert!(absent && present && gone);
        Ok(())
    }
}
