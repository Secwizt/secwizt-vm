#![cfg(windows)]
#![forbid(unsafe_code)]
#![deny(warnings)]

use serde_json::{json, Value};
use std::{
    error::Error, fs, io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use svm_core::{
    engine::{EngineDriver, EngineError},
    model::{Network, NetworkMode, Vm, VmState},
};
use svm_hyperv::{HyperV, WindowsPowerShell};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct LiveFixture {
    engine: HyperV<WindowsPowerShell>,
    network: Network,
    vm: Vm,
    temp: PathBuf,
    default_before: Value,
    switch_created: Option<String>,
    vm_armed: bool,
    cleaned: bool,
}

impl LiveFixture {
    fn new() -> Result<Self> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let id = format!("test-{}-{stamp}", std::process::id());
        let network = Network {
            bridge:None, id:"test".into(), name:"Test".into(), mode:NetworkMode::Routed,
            subnet:"10.77.8.0/24".parse()?, gateway:None, dhcp:false, note:String::new(),
        };
        let vm: Vm = serde_json::from_value(json!({
            "id":id, "name":"Live fixture", "os":"Empty firmware guest", "family":"other",
            "engine":"Hyper-V","accel":true,"state":"off","vcpu":1,"ramGb":1,"net":"test",
            "ip":"10.77.8.2","mac":"02:77:08:00:00:01","dns":"fixture.vm.lan"
        }))?;
        let mut engine = HyperV::new(WindowsPowerShell::default(), [network.clone()]);
        let default_before = engine.default_switch_info()?;
        match engine.state(&id) {
            Err(EngineError::Missing(_)) => {}
            Err(e) => return Err(e.into()),
            Ok(_) => return Err(io::Error::other("The disposable VM name is already in use.").into()),
        }
        let temp = std::env::temp_dir().join(format!("svm-{id}"));
        let bundle = temp.join("fixture.swvm");
        engine.register_bundle(&id, &bundle)?;
        fs::create_dir(&temp)?;
        // Arm directory cleanup before the first allocation inside it.
        let fixture = Self {
            engine, network, vm, temp, default_before,
            switch_created:None, vm_armed:false, cleaned:false,
        };
        fs::create_dir(&bundle)?;
        fs::write(bundle.join("vm.json"), serde_json::to_vec(&fixture.vm)?)?;
        Ok(fixture)
    }

    fn exercise(&mut self) -> Result<()> {
        let receipt = self.engine.ensure_switch(&self.network)?;
        if !receipt.created {
            return Err(io::Error::other("SVM-test already exists. The live test needs an unused switch name.").into());
        }
        self.switch_created = Some(receipt.guid);
        self.vm_armed = true;
        self.engine.define(&self.vm)?;
        let id = &self.vm.id;
        assert_eq!(self.engine.state(id)?, VmState::Off);
        self.engine.start(id)?;
        assert_eq!(self.engine.state(id)?, VmState::Running);
        let frame = self.engine.thumbnail(id)?;
        assert_eq!((frame.width,frame.height), (320,240));
        assert_eq!(frame.rgba.len(),320*240*4);
        let checkpoint = self.engine.snapshot(id,"Firmware checkpoint",true)?;
        self.engine.revert(id,&checkpoint.id)?;
        self.engine.delete_snapshot(id,&checkpoint.id)?;
        self.engine.pause(id)?;
        assert_eq!(self.engine.state(id)?,VmState::Paused);
        self.engine.resume(id)?;
        self.engine.stop(id)?;
        assert_eq!(self.engine.state(id)?,VmState::Off);
        assert!(self.engine.thumbnail(id).is_err());
        self.engine.remove(id)?;
        assert!(matches!(self.engine.state(id),Err(EngineError::Missing(_))));
        self.vm_armed = false;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned { return Ok(()); }
        if self.vm_armed {
            let id = &self.vm.id;
            match self.engine.state(id) {
                Err(EngineError::Missing(_)) => {}
                Err(e) => return Err(e.into()),
                Ok(state) => {
                    if state != VmState::Off { self.engine.stop(id)?; }
                    self.engine.remove(id)?;
                }
            }
            self.vm_armed = false;
        }
        if let Some(guid) = &self.switch_created {
            self.engine.remove_switch_if_same(&self.network, Some(guid))?;
            self.switch_created = None;
        }
        fs::remove_dir_all(&self.temp)?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for LiveFixture {
    fn drop(&mut self) {
        if self.cleaned { return; }
        if let Err(e) = self.cleanup() {
            eprintln!("Hyper-V fixture cleanup needs review for {}: {e}", self.vm.id);
        }
        match self.engine.default_switch_info() {
            Ok(after) if after == self.default_before => {}
            Ok(_) => eprintln!("Default Switch differs from its pre-test configuration."),
            Err(e) => eprintln!("Could not verify Default Switch after cleanup: {e}"),
        }
    }
}

#[test]
#[ignore = "requires a real Windows Hyper-V host and explicit live-test opt-in"]
fn owned_generation_two_lifecycle() -> Result<()> {
    if std::env::var("SVM_HYPERV_LIVE").as_deref() != Ok("1") { return Ok(()); }
    let mut fixture = LiveFixture::new()?;
    let run = fixture.exercise();
    let cleanup = fixture.cleanup();
    let after = fixture.engine.default_switch_info()?;
    assert_eq!(fixture.default_before, after, "Default Switch configuration changed");
    cleanup?;
    run
}
