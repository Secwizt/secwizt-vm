use super::*;

impl Machines {
    pub(crate) fn console_endpoint(&self, id: &str) -> Result<svm_qemu::ConsoleEndpoint, ApiError> {
        let vm = self.vm(id)?;
        if vm.engine != EngineKind::Qemu { return Err(refused("Use Windows’ viewer for this machine.")); }
        self.qemu.console_endpoint(&vm).map_err(engine)
    }

    pub(crate) fn qemu_settings(&mut self, method:&str, body:&Value)->Result<Reply,ApiError> {
        match method {
            "GET" => {}
            "PUT" => {
                if self.converting(){return Err(refused("Finish or cancel the disk conversion before changing QEMU."));}
                if let Some(value) = body.as_object().filter(|fields| fields.len() == 1)
                    .and_then(|fields| fields.get("openSeparateWindow")) {
                    let open = value.as_bool().ok_or_else(|| bad("Choose whether to open a separate QEMU window."))?;
                    self.qemu.set_separate_window(open).map_err(engine)?;
                    return Ok(Reply::json(self.qemu.prerequisites()));
                }
                let fields=body.as_object().filter(|f|f.len()==1 && f.contains_key("path"))
                    .ok_or_else(||bad("Supply the selected QEMU executable in path, or null to clear it."))?;
                let path=match &fields["path"] {
                    Value::Null=>None,
                    Value::String(path) if !path.is_empty()=>Some(Path::new(path)),
                    _=>return Err(bad("Choose an absolute path to qemu-system-x86_64.exe.")),
                };
                for vm in self.inventory.iter().filter(|v|v.engine==EngineKind::Qemu) {
                    match self.qemu.state(&vm.id) {
                        Ok(VmState::Off)|Err(EngineError::Missing(_))=>{},
                        _=>return Err(refused("Power off all QEMU machines and confirm their state before changing the executable.")),
                    }
                }
                self.qemu.set_executable(path).map_err(engine)?;
            }
            _=>return Err(ApiError::missing()),
        }
        Ok(Reply::json(self.qemu.prerequisites()))
    }
}

impl MachineEngine for Qemu {
    fn register(&mut self,id:&str,bundle:&Path)->EngineResult<()> { self.register_bundle(id,bundle) }
    fn set_networks(&mut self,_:&[Network]) {}
    fn profile(&self)->EngineResult<HostProfile> { Err(EngineError::Invalid("Host capacity is supplied by the host service.".into())) }
    fn configure(&mut self,vm:&Vm)->EngineResult<()> { self.guard_hardware_change(vm).map(drop) }
    fn clone_disk(&mut self,_:&Vm,_:&Path,_:&Vm,_:&Path)->EngineResult<bool> { Err(EngineError::Invalid("QEMU cloning is unavailable.".into())) }
    fn read_storage(&self,vm:&Vm,bundle:&Path)->EngineResult<Value> {
        let path=bundle.join("system.qcow2");
        let metadata=fs::symlink_metadata(&path).map_err(|_|EngineError::Invalid("The bundle-owned qcow2 disk is unavailable.".into()))?;
        if !metadata.is_file() || path.canonicalize().ok().as_ref()!=Some(&path) {
            return Err(EngineError::Invalid("The QEMU disk is linked or outside its bundle.".into()));
        }
        Ok(json!({"disks":[{"path":path,"hostBytes":metadata.len(),"maximumBytes":self.disk_bytes(&vm.id)?}],
            "isoPath":vm.iso_path,"originalInstaller":self.original_installer(&vm.id)?,
            "bootFirst":if vm.iso_path.is_some() {"image"} else {"disk"},
            "canEditBoot":false,"canEditMedia":vm.state==VmState::Off,
            "bootReason":if vm.iso_path.is_some() {"Remove the installer disc to boot from the virtual disk."} else {"The machine starts from its virtual disk."},
            "mediaReason":"Power off the QEMU machine before changing its installer disc."}))
    }
    fn removal_plan(&mut self,vm:&Vm)->EngineResult<RemovalPlan> {
        if self.state(&vm.id)?!=VmState::Off {return Err(EngineError::Invalid("The QEMU machine must be off before removal.".into()));}
        Ok(RemovalPlan {guid:vm.id.clone(),stamp:"off".into(),required:false})
    }
    fn unregister(&mut self,vm:&Vm,bundle:&Path,plan:&RemovalPlan,keep:bool)->EngineResult<RemovalReceipt> {
        if keep {return Err(EngineError::Invalid("QEMU retained exports are unavailable. Normal removal keeps the qcow2 disk in trash.".into()));}
        if plan.guid!=vm.id || self.state(&vm.id)?!=VmState::Off {return Err(EngineError::Invalid("The QEMU machine changed before removal.".into()));}
        let receipt=RemovalReceipt{id:vm.id.clone(),retained:None,bytes:None};
        // Publish before unregistering so an interrupted removal can resume with its disk intact.
        svm_core::write_json(&bundle.join("removal-complete.json"),&receipt).map_err(|_|EngineError::Engine("Could not save the QEMU removal receipt.".into()))?;
        self.remove(&vm.id)?;
        Ok(receipt)
    }
    fn trash_detached(&mut self,_id:&str,bundle:&Path)->EngineResult<()> {
        for name in ["qemu-vm.json","qemu-run.json"] {
            match fs::symlink_metadata(bundle.join(name)) {
                Err(e) if e.kind()==io::ErrorKind::NotFound=>{},
                _=>return Err(EngineError::Invalid("The QEMU disk is still registered or its supervision state is uncertain.".into())),
            }
        }
        Ok(())
    }
}
