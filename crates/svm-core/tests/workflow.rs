use std::{fs,io,net::Ipv4Addr,path::PathBuf,sync::atomic::{AtomicU64,Ordering}};
use svm_core::{
    capability::Capability,
    dhcp::{Config,LeaseTable},
    engine::{EngineDriver,FakeEngine},
    guard::{Decision,HostGuard},
    identity::allocate,
    library::Library,
    model::{EngineKind,GuestFamily,HostInfo,Network,NetworkMode,Vm,VmState},
};

struct Scratch(PathBuf);
impl Scratch {
    fn new()->Self {
        static NEXT:AtomicU64=AtomicU64::new(0);
        loop {
            let n=NEXT.fetch_add(1,Ordering::Relaxed);
            let path=std::env::temp_dir().join(format!("svm-workflow-{}-{n}",std::process::id()));
            match fs::create_dir(&path) {
                Ok(())=>return Self(path),
                Err(e) if e.kind()==io::ErrorKind::AlreadyExists=>continue,
                Err(e)=>panic!("Could not create the test directory: {e}"),
            }
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {let _=fs::remove_dir_all(&self.0);}
}

fn network()->Network {
    Network {
        bridge:None, id:"lab".into(),name:"Sample routed network".into(),mode:NetworkMode::Routed,
        subnet:"10.77.1.0/24".parse().unwrap(),gateway:Some(Ipv4Addr::new(10,77,1,1)),
        dhcp:true,note:String::new(),
    }
}
fn define(id:&str,name:&str,n:&Network,existing:&[Vm])->Vm {
    let identity=allocate(id,name,n,existing).unwrap();
    Vm {
        id:id.into(),name:name.into(),os:"Sample guest".into(),family:GuestFamily::Linux,
        architecture:Default::default(),engine:EngineKind::Qemu,accel:true,state:VmState::Off,vcpu:2,ram_gb:4,cores:Vec::new(),
        net:n.id.clone(),ip:identity.ip,mac:identity.mac,dns:identity.dns,snaps:0,share_clipboard:false,port_forwards:Vec::new(),template:None,linked_from:None,throwaway:false,isolated:false,
        disk_gb: None, disk_path: None, iso_path: None, secure_boot: None, tpm: None, ready: None,
    }
}

#[test]
fn define_start_checkpoint_and_reload() {
    let dir=Scratch::new();
    let library=Library::open(&dir.0).unwrap();
    let n=network();
    library.save_networks(std::slice::from_ref(&n),"10.77.9.0/24".parse().unwrap()).unwrap();
    let mut vm=define("vm-one","Sample guest",&n,&[]);
    library.create(&vm).unwrap();
    let leases=LeaseTable::new(Config {subnet:n.subnet,router:n.gateway,dns:n.gateway,lease_seconds:3600,boot_file:None}).unwrap();
    leases.reserve(vm.mac,vm.ip).unwrap();
    let lease_file=dir.0.join("leases.json");leases.save(&lease_file).unwrap();
    let host=HostInfo {logical:32,p_cores:[0,15],e_cores:[16,31],ram_gb:64};
    let mut engine=FakeEngine::default();engine.define(&vm).unwrap();
    assert!(engine.capabilities(&vm).has(Capability::Start));
    let Decision::Admit {cores}=HostGuard::default().admit(&host,&library.load_all().unwrap(),&vm) else {panic!("Expected admission");};
    engine.start(&vm.id).unwrap();vm.cores=cores;vm.state=engine.state(&vm.id).unwrap();
    let checkpoint=engine.snapshot(&vm.id,"First boot",true).unwrap();
    assert!(checkpoint.with_memory);
    vm.snaps=1;library.save(&vm).unwrap();
    let reopened=Library::open(&dir.0).unwrap();
    assert_eq!(reopened.load_all().unwrap(),vec![vm.clone()]);
    assert_eq!(reopened.load_networks().unwrap(),vec![n]);
    assert_eq!(LeaseTable::load(&lease_file).unwrap().reservation(vm.mac).unwrap().unwrap().ip,vm.ip);
}

#[test]
fn separate_library_handles_cannot_commit_the_same_identity() {
    let dir=Scratch::new();let n=network();let machine=define("vm-one","Lab",&n,&[]);
    let first=Library::open(&dir.0).unwrap();let second=Library::open(&dir.0).unwrap();
    let peer=machine.clone();
    let thread=std::thread::spawn(move || first.create(&peer));
    let result=second.create(&machine);
    let other=thread.join().unwrap();
    assert_ne!(result.is_ok(),other.is_ok());
    assert_eq!(second.load_all().unwrap(),vec![machine]);
}
