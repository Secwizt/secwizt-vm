use super::*;
use serde::{Deserialize,Serialize};
use std::{sync::Arc, thread::{self,JoinHandle}};
use svm_qemu::{DiskSource,LocalFolder,TransferControl};

#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Import { path:PathBuf, name:String, os:String, family:GuestFamily, firmware:String, id:Option<String> }

#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Export { machine_id:String, folder:PathBuf, format:String, file_name:Option<String> }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspect { path:PathBuf }

#[derive(Serialize,Deserialize)]
struct Receipt { id:String, directory:PathBuf, format:String, #[serde(default)] filename:Option<String> }

struct Stage { record:Receipt, parent:LocalFolder, journal:PathBuf }

impl Stage {
    fn prepare(parent:LocalFolder,journal:PathBuf,id:&str,format:&str,filename:Option<String>)->Result<Self,ApiError> {
        if journal.try_exists().map_err(io_error)? {return Err(refused("A previous disk conversion still needs cleanup."));}
        let directory=parent.path.join(format!(".svm-transfer-{id}"));
        let record=Receipt{id:id.into(),directory:directory.clone(),format:format.into(),filename};
        if directory.try_exists().map_err(io_error)? {return Err(refused("The temporary conversion folder already exists."));}
        svm_core::write_json(&journal,&record).map_err(store)?;
        if let Err(e)=fs::create_dir(&directory){let _=fs::remove_file(&journal);return Err(io_error(e));}
        let stage=Self{record,parent,journal};
        if let Err(e)=fs::write(directory.join("owner"),id){
            let _=fs::remove_dir(&directory);let _=fs::remove_file(&stage.journal);return Err(io_error(e));
        }
        Ok(stage)
    }
    fn output(&self)->PathBuf {self.record.directory.join(self.record.filename.clone().unwrap_or_else(||format!("converted.{}",self.record.format)))}
    fn clean(&self)->Result<(),ApiError> {
        let dir=&self.record.directory;
        if !dir.try_exists().map_err(io_error)? {return fs::remove_file(&self.journal).map_err(io_error);}
        let verified=LocalFolder::open(dir).map_err(engine)?;
        if verified.path.parent()!=Some(self.parent.path.as_path()) ||
            dir.file_name().and_then(|n|n.to_str())!=Some(format!(".svm-transfer-{}",self.record.id).as_str()) {
            return Err(refused("The interrupted conversion folder could not be verified."));
        }
        let owner=dir.join("owner");
        let owner_exists=owner.try_exists().map_err(io_error)?;
        if owner_exists {
            if !regular(&owner)? || fs::read_to_string(&owner).map_err(io_error)?!=self.record.id {
                return Err(refused("The conversion receipt did not match its staging folder."));
            }
            for pending in [self.output(),dir.join("qemu-output.tmp")] {
                if !pending.try_exists().map_err(io_error)? {continue;}
                if !regular(&pending)? {return Err(refused("The conversion's partial disk is linked."));}
                // An orphaned converter may still hold the file after a service crash. Retry later.
                #[cfg(windows)] {
                    use std::os::windows::fs::OpenOptionsExt;
                    drop(fs::OpenOptions::new().read(true).write(true).share_mode(0).open(&pending)
                        .map_err(|_|refused("The partial disk is still in use. Retry after the converter exits."))?);
                }
                fs::remove_file(pending).map_err(io_error)?;
            }
            fs::remove_file(owner).map_err(io_error)?;
        }
        drop(verified);
        fs::remove_dir(dir).map_err(io_error)?;
        fs::remove_file(&self.journal).map_err(io_error)
    }
    fn recover(journal:&Path)->Result<(),ApiError>{
        if !journal.try_exists().map_err(io_error)? {return Ok(());}
        if !regular(journal)?{return Err(refused("The conversion receipt is linked."));}
        let record:Receipt=svm_core::read_json(journal).map_err(store)?;
        if record.filename.as_ref().is_some_and(|n|validate_name(n).is_err() || !Path::new(n).extension().is_some_and(|e|e.eq_ignore_ascii_case(record.format.as_str()))) ||
            !id_ok(&record.id) || !matches!(record.format.as_str(),"qcow2"|"vhdx"|"vdi"|"vmdk") || !record.directory.is_absolute() ||
            record.directory.file_name().and_then(|n|n.to_str())!=Some(format!(".svm-transfer-{}",record.id).as_str()){
            return Err(refused("The interrupted conversion receipt is invalid."));
        }
        match fs::symlink_metadata(&record.directory) {
            Ok(_) => {}
            Err(e) if missing_stage(&e) => return fs::remove_file(journal).map_err(io_error),
            Err(e) => return Err(io_error(e)),
        }
        let parent=LocalFolder::open(record.directory.parent().ok_or_else(||bad("Missing conversion folder."))?).map_err(engine)?;
        Self{record,parent,journal:journal.to_owned()}.clean()
    }
}

fn missing_stage(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::NotFound { return true; }
    // A drive letter can outlive its removable volume.
    cfg!(windows) && matches!(error.raw_os_error(), Some(15 | 21 | 55 | 1167))
}

fn regular(path:&Path)->Result<bool,ApiError> {
    let metadata=fs::symlink_metadata(path).map_err(io_error)?;
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {return Ok(false);}
    }
    Ok(metadata.is_file() && !metadata.file_type().is_symlink())
}

enum Target {
    Import { machine:Value, bytes:u64 },
    Export { machine_id:String, file:PathBuf },
}

struct Pending {
    stage:Stage,
    target:Target,
    control:Arc<TransferControl>,
    worker:Option<JoinHandle<EngineResult<()>>>,
    _stage_handle:Option<LocalFolder>,
}
impl Pending {
    fn status(&self)->Value {
        let (kind,machine)=match &self.target {
            Target::Import{machine,..}=>("import",machine["id"].as_str().unwrap_or_default()),
            Target::Export{machine_id,..}=>("export",machine_id.as_str()),
        };
        json!({"id":self.stage.record.id,"kind":kind,"machineId":machine,
            "state":if self.control.cancelled(){"cancelling"}else{"running"},"percent":self.control.percent()})
    }
}
#[derive(Default)]
pub(super) struct Transfers { current:Option<Pending>, finished:Vec<Value> }

impl Transfers {
    pub(super) fn active(&self)->bool {self.current.is_some()}
    pub(super) fn owns_machine(&self,id:&str)->bool {
        matches!(self.current.as_ref().map(|p|&p.target),Some(Target::Export{machine_id,..}) if machine_id==id)
    }
}
impl Drop for Transfers {
    fn drop(&mut self) {
        if let Some(mut pending)=self.current.take(){
            pending.control.cancel();
            if let Some(worker)=pending.worker.take(){let _=worker.join();}
            drop(pending._stage_handle.take());
            let _=pending.stage.clean();
        }
    }
}

impl Machines {
    fn transfer_journal(&self)->PathBuf {self.library_dir.with_file_name("disk-transfer.json")}

    fn launch_transfer(&mut self,source:DiskSource,parent:LocalFolder,format:&str,target:Target)->Result<Reply,ApiError> {
        if source.path.parent()==Some(parent.path.as_path()) {
            return Err(bad("Choose a destination outside the source disk's folder."));
        }
        let id=next_id();
        let filename=match &target { Target::Export{file,..}=>file.file_name().and_then(|name|name.to_str()).map(str::to_owned),Target::Import{..}=>None };
        let stage=Stage::prepare(parent,self.transfer_journal(),&id,format,filename)?;
        let output=stage.output();
        let folder=match LocalFolder::open(&stage.record.directory) {
            Ok(folder)=>folder,Err(e)=>{stage.clean()?;return Err(engine(e));}
        };
        let control=Arc::new(TransferControl::default());
        let reporting=Arc::clone(&control);
        let kind=format.to_owned();
        let worker=thread::Builder::new().name("disk-conversion".into()).spawn(move||
            source.convert(&output,&kind,reporting));
        let worker=match worker {Ok(w)=>w,Err(e)=>{drop(folder);stage.clean()?;return Err(io_error(e));}};
        let pending=Pending{stage,target,control,worker:Some(worker),_stage_handle:Some(folder)};
        let status=pending.status();
        self.transfers.current=Some(pending);
        Ok(Reply::json_status(202,status))
    }

    pub(crate) fn transfer_route(&mut self,method:&str,parts:&[&str],body:&Value,networks:&[Network],events:&mut Events)->Result<Reply,ApiError>{
        self.finish_transfer(networks,events)?;
        match (method,parts) {
            ("GET",["transfers"])=>Ok(Reply::json(json!({"current":self.transfers.current.as_ref().map(Pending::status),
                "recent":self.transfers.finished}))),
            ("GET"|"DELETE",["transfers",id])=>{
                if let Some(p)=self.transfers.current.as_ref().filter(|p|p.stage.record.id==*id){
                    if method=="DELETE"{p.control.cancel();}
                    return Ok(Reply::json(p.status()));
                }
                self.transfers.finished.iter().find(|v|v["id"]==*id).cloned().map(Reply::json).ok_or_else(ApiError::missing)
            }
            ("POST",["transfers",action @ ("inspect"|"import"|"export")])=>{
                if self.converting(){return Err(refused("Another disk conversion or ready-image preparation is running. Wait for it or cancel it first."));}
                Stage::recover(&self.transfer_journal())?;
                match *action {
                    "inspect"=>{
                        let req:Inspect=parsed(body)?;
                        self.check_import_location(&req.path)?;
                        let info=self.qemu.disk_details(&req.path).map_err(engine)?;
                        self.check_import_size(info.bytes)?;
                        Ok(Reply::json(json!(info)))
                    }
                    "import"=>{
                        let req:Import=parsed(body)?;
                        self.check_import_location(&req.path)?;
                        if req.family==GuestFamily::Macos {return Err(bad("macOS guests require the Mac host."));}
                        let id=req.id.unwrap_or_else(next_id);self.ensure_identity(&id,&req.name)?;
                        if req.os.trim().is_empty() || req.os.len()>180{return Err(bad("Enter the guest operating system."));}
                        let (driver,format)=match req.firmware.as_str(){
                            "uefi"=>(EngineKind::HyperV,"vhdx"),"bios"=>(EngineKind::Qemu,"qcow2"),
                            _=>return Err(bad("Choose UEFI or legacy BIOS to match the installed x86 guest.")),
                        };
                        let source=self.qemu.disk_source(&req.path).map_err(engine)?;
                        let bytes=source.info.bytes;self.check_import_size(bytes)?;
                        let machine=json!({"id":id,"name":req.name,"os":req.os,"family":req.family,"engine":driver,
                            "net":"nat","vcpu":1,"ramGb":2,"secureBoot":false,"tpm":false});
                        let folder=LocalFolder::open(&self.library_dir).map_err(engine)?;
                        self.launch_transfer(source,folder,format,Target::Import{machine,bytes})
                    }
                    _=>self.export_disk(parsed(body)?,events),
                }
            }
            _=>Err(ApiError::missing()),
        }
    }
    fn check_import_location(&self,path:&Path)->Result<(),ApiError> {
        let parent=path.parent().ok_or_else(||bad("Select a local disk file."))?;
        let folder=LocalFolder::open(parent).map_err(engine)?;
        if folder.path==self.library_dir || self.library_dir.parent()==Some(folder.path.as_path()) {
            return Err(bad("Choose a source disk outside the service and library root folders."));
        }
        Ok(())
    }
    pub(super) fn recover_transfer(&mut self,events:&mut Events)->Result<(),ApiError> {
        if let Err(error)=Stage::recover(&self.transfer_journal()){
            events.record("disk transfer cleanup",&error.message)?;
        }
        Ok(())
    }
    fn check_import_size(&self,bytes:u64)->Result<(),ApiError>{
        if bytes==0 || bytes>(1_u64<<46){return Err(bad("Choose a disk up to 64 TiB with a positive virtual size."));}
        let cap=self.engine.capacity(&self.library_dir).map_err(engine)?;
        let free=cap["freeBytes"].as_u64().ok_or_else(||refused("The library drive's free space could not be measured."))?;
        if bytes>free{return Err(bad(format!("The disk's virtual size exceeds the library drive's {free} free bytes.")));}
        Ok(())
    }
    fn export_disk(&mut self,req:Export,events:&mut Events)->Result<Reply,ApiError>{
        if !matches!(req.format.as_str(),"vmdk"|"vdi"|"vhdx"|"qcow2"){return Err(bad("Choose VMDK, VDI, VHDX or qcow2."));}
        self.refresh_after(events,Some(&req.machine_id),None)?;
        let vm=self.vm(&req.machine_id)?;
        if (vm.throwaway && vm.state != VmState::Off) || self.throwaway_pending(&vm) {
            return Err(refused("Disk export is unavailable during a throwaway run."));
        }
        if vm.template.is_some() || vm.linked_from.is_some() {
            return Err(refused("Disk export is unavailable for templates and linked clones."));
        }
        self.available(&vm.id)?;
        if vm.state!=VmState::Off {return Err(refused("Power off the machine before exporting its disk."));}
        let bundle=self.library.bundle_path(&vm.id).map_err(store)?;
        if !self.driver_mut(vm.engine)?.list_snapshots(&vm.id).map_err(engine)?.is_empty() {
            return Err(refused("Merge all checkpoints before exporting this machine."));
        }
        let storage=self.driver(vm.engine)?.read_storage(&vm,&bundle).map_err(engine)?;
        let disks=storage["disks"].as_array().filter(|rows|rows.len()==1)
            .ok_or_else(||refused("Export requires exactly one attached, bundle-owned system disk."))?;
        let disk=disks[0]["path"].as_str().ok_or_else(||refused("The engine did not report a disk path."))?;
        let source=self.qemu.disk_source(Path::new(disk)).map_err(engine)?;
        if !source.path.starts_with(&bundle) {return Err(refused("The active disk is outside this machine's bundle."));}
        if !matches!((vm.engine,source.info.format.as_str()),(EngineKind::HyperV,"vhdx")|(EngineKind::Qemu,"qcow2")){
            return Err(refused("The active system disk is differencing or has an unexpected format. Merge checkpoints first."));
        }
        let folder=LocalFolder::open(&req.folder).map_err(engine)?;
        if folder.path.starts_with(self.library_dir.parent().unwrap_or(&self.library_dir)) {
            return Err(bad("Choose an export folder outside the service data and machine library."));
        }
        let name=req.file_name.unwrap_or_else(||format!("{}.{}",vm.id,req.format));
        validate_name(&name).map_err(store)?;
        if !Path::new(&name).extension().is_some_and(|e|e.eq_ignore_ascii_case(req.format.as_str())){
            return Err(bad("The export filename must end in the chosen disk format."));
        }
        let file=folder.path.join(name);
        if file.try_exists().map_err(io_error)? {return Err(refused("The export file already exists. Choose a new filename."));}
        self.launch_transfer(source,folder,&req.format,Target::Export{machine_id:vm.id,file})
    }
    pub(crate) fn finish_transfer(&mut self,networks:&[Network],events:&mut Events)->Result<(),ApiError>{
        if !self.transfers.current.as_ref().and_then(|p|p.worker.as_ref()).is_some_and(|w|w.is_finished()){return Ok(());}
        let mut p=self.transfers.current.take().expect("finished transfer");
        let mut status=p.status();
        let outcome=p.worker.take().expect("conversion worker").join().map_err(|_|refused("The disk converter stopped unexpectedly."))
            .and_then(|r|r.map_err(engine)).and_then(|()|{
                if p.control.cancelled(){return Err(refused("Disk conversion cancelled."));}
                match &p.target {
                    Target::Export{file,..}=>{
                        svm_qemu::publish_disk(&p.stage.output(),file).map_err(engine)?;
                        Ok(json!({"path":file}))
                    }
                    Target::Import{machine,bytes}=>{
                        self.engine.set_networks(networks);
                        let vm=self.create(parsed(machine)?,networks,events,Some((&p.stage.output(),*bytes)))?;
                        serde_json::from_slice(&vm.body).map_err(|_|refused("The new machine response could not be read."))
                    }
                }
            });
        drop(p._stage_handle.take());
        let cleanup=p.stage.clean();
        match outcome {
            Ok(v)=>{status["state"]=json!("completed");status["percent"]=json!(100);status["result"]=v;}
            Err(e)=>{status["state"]=json!(if p.control.cancelled(){"cancelled"}else{"failed"});status["message"]=json!(e.message);}
        }
        if let Err(e)=cleanup {status["cleanupMessage"]=json!(e.message);}
        if self.transfers.finished.len()>=16 {self.transfers.finished.remove(0);}
        self.transfers.finished.push(status);
        events.record("disk transfer",&format!("Disk transfer {} finished.",p.stage.record.id))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{networks::FakeSwitches, Service};
    use std::{
        io::Read, net::{Ipv4Addr, TcpListener, TcpStream},
        sync::{atomic::{AtomicBool, Ordering}, mpsc},
        time::Duration,
    };
    use svm_core::engine::FakeEngine;

    struct Fixture(PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn a_missing_stage_parent_does_not_block_the_next_transfer() {
        let home = Fixture(std::env::temp_dir().join(next_id()));
        fs::create_dir(&home.0).unwrap();
        let journal = home.0.join("disk-transfer.json");
        let id = next_id();
        let directory = home.0.join("offline").join(format!(".svm-transfer-{id}"));
        svm_core::write_json(&journal, &Receipt { id: id.clone(), directory, format: "vdi".into(), filename: None }).unwrap();
        Stage::recover(&journal).unwrap();
        assert!(!journal.exists());
        Stage::prepare(LocalFolder::open(&home.0).unwrap(), journal, &id, "vdi", None).unwrap().clean().unwrap();
    }

    #[test]
    fn transfer_finalization_error_stops_service_and_closes_console_sockets() {
        let path = std::env::temp_dir().join(next_id());
        fs::create_dir(&path).unwrap();
        let home = Fixture(path);
        let mut service = Service::open(&home.0, 0, Box::<FakeEngine>::default(), Box::<FakeSwitches>::default()).unwrap();
        let parent = LocalFolder::open(&home.0).unwrap();
        let machines = &mut service.worker.machines;
        let id = next_id();
        let stage = Stage::prepare(parent, machines.transfer_journal(), &id, "vdi", None).unwrap();
        machines.transfers.current = Some(Pending {
            stage,
            target: Target::Export { machine_id: "shutdown-fixture".into(), file: home.0.join("fixture.vdi") },
            control: Arc::new(TransferControl::default()),
            worker: Some(thread::spawn(|| Err(EngineError::Invalid("Discard the synthetic conversion.".into())))),
            _stage_handle: None,
        });
        // The finished conversion's event write is the failure observed by the service tick.
        service.worker.events.refuse_event_for_test("disk transfer");

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let console = service.worker.console.clone();
        console.register_test_socket(socket);

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let (send, done) = mpsc::channel();
        let task = thread::spawn(move || { let _ = send.send(service.run(worker_stop)); });
        let result = match done.recv_timeout(Duration::from_secs(4)) {
            Ok(result) => result,
            Err(error) => {
                stop.store(true, Ordering::Release);
                if done.recv_timeout(Duration::from_secs(2)).is_ok() {
                    task.join().unwrap();
                }
                panic!("the service must return on its own: {error}");
            }
        };
        task.join().unwrap();
        assert_eq!(result.unwrap_err().code, "test_event_write");
        assert!(stop.load(Ordering::Acquire));
        assert!(!home.0.join("disk-transfer.json").exists());
        assert!(!home.0.join("api-port").exists());
        peer.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
