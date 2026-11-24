use super::*;

#[derive(Serialize,Deserialize)]
pub(crate) struct Definition {
    pub(crate) id:String,
    #[serde(default)]
    pub(crate) architecture:GuestArchitecture,
    pub(crate) iso:Option<PathBuf>,
    pub(crate) gib:u32,
    #[serde(default)]
    pub(crate) imported_bytes:Option<u64>,
    #[serde(default)]
    pub(crate) legacy_windows:bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) linked_from: Option<String>,
}
impl Definition {
    pub(crate) fn bytes(&self)->u64 {self.imported_bytes.unwrap_or(u64::from(self.gib)<<30)}
}
pub(crate) fn validate(vm:&Vm,def:&Definition)->Result<()>{
    crate::validate_port_forwards(&vm.port_forwards)?;
    let imported=def.imported_bytes.is_some();
    let linked=def.linked_from.is_some();
    if vm.linked_from != def.linked_from || (linked && (!imported || vm.template.is_some() ||
        vm.iso_path.is_some() || def.iso.is_some() || vm.snaps != 0)) {
        return Err(err("The registered linked QEMU disk must match its machine and have no installer or checkpoints."));
    }
    if def.legacy_windows {
        crate::validate_legacy_windows_profile(vm.architecture,vm.family,vm.vcpu,vm.ram_gb)?;
        if !linked && ((!imported && def.iso.is_none()) || (imported && def.iso.is_some())) {
            return Err(err("Choose a local Windows installer ISO and a new virtual disk."));
        }
    } else {
        let imported_profile=imported && (!linked || vm.architecture==GuestArchitecture::X86_64);
        crate::validate_profile(vm.architecture,vm.family,imported_profile,vm.vcpu,vm.ram_gb)?;
    }
    if vm.architecture!=def.architecture {return Err(err("The selected architecture differs from the registered machine."));}
    if vm.engine!=EngineKind::Qemu || vm.net!="nat" || vm.secure_boot==Some(true) ||
        vm.tpm==Some(true) || vm.id!=def.id {
        return Err(err("QEMU machines require their registered identity, user-mode NAT, and Secure Boot and TPM off."));
    }
    if let Some(bytes)=def.imported_bytes {
        if !(1..=(1_u64<<46)).contains(&bytes) || vm.disk_path.as_deref()!=Some(Path::new("system.qcow2")) || vm.disk_gb.is_some() {
            return Err(err("An imported or linked machine must use its bundle-owned qcow2 disk."));
        }
    } else if vm.disk_gb!=Some(def.gib) || def.gib==0 || def.gib>65536 || vm.disk_path.is_some() {
        return Err(err("A new QEMU machine needs a bundle-owned qcow2 of the recorded size."));
    }
    if !imported && vm.family==GuestFamily::Android && def.iso.is_none() {
        return Err(err("Choose an Android installer ISO for a new Android machine."));
    }
    if def.iso.as_ref().is_some_and(|p|!p.extension().is_some_and(|e|e.eq_ignore_ascii_case("iso"))) {
        return Err(err("Choose a local installer ISO."));
    }
    if let Some(path)=vm.iso_path.as_deref() {
        if def.iso.as_deref()!=Some(&local(path,false)?) {return Err(err("Only the original installer disc can be reattached to this machine."));}
    }
    Ok(())
}

impl Qemu {
    pub fn define_import(&mut self,vm:&Vm,bytes:u64,legacy_windows:bool)->Result<()> {
        let bundle=self.bundle(&vm.id)?;
        let _lock=operation_lock(bundle)?;
        let arm = vm.architecture == GuestArchitecture::Aarch64;
        let mut def=Definition{id:vm.id.clone(),architecture:vm.architecture,iso:None,gib:0,imported_bytes:Some(bytes),legacy_windows,linked_from:None};
        if arm {
            let size = vm.disk_gb.filter(|size| u64::from(*size)<<30 == bytes).ok_or_else(||err("The Arm backup disk size does not match its machine."))?;
            let file = linked::hold_file(&bundle.join("uefi-vars.fd"), false)?;
            if file.metadata().map_err(io_error)?.len() != self.available()?.arm_tools()?.variables_size() { return Err(err("Invalid Arm backup firmware variables.")); }
            def.gib = size;
            def.imported_bytes = None;
        }
        validate(vm,&def)?;
        let disk=local(&bundle.join("system.qcow2"),false)?;
        self.available()?.inspect_disk(&disk,bytes)?;
        let registration=bundle.join("qemu-vm.json");
        if registration.try_exists().map_err(io_error)? {return Err(err("A QEMU registration already exists."));}
        save(&registration,&def)
    }
    pub fn disk_bytes(&self,id:&str)->Result<u64> {Ok(self.definition(id)?.1.bytes())}
    pub fn original_installer(&self,id:&str)->Result<Option<PathBuf>> {
        Ok(self.definition(id)?.1.iso)
    }

    /// Hold this guard through the library save so a competing start cannot use the old media.
    pub fn guard_hardware_change(&self,vm:&Vm)->Result<File> {
        let (bundle,def)=self.definition(&vm.id)?;
        let guard=operation_lock(bundle)?;
        if self.status(&vm.id)?!=VmState::Off {return Err(err("Power off the machine before changing its hardware."));}
        validate(vm,&def)?;
        Ok(guard)
    }

    pub fn guard_installer_change(&self,vm:&Vm)->Result<File> {
        let (bundle,mut def)=self.definition(&vm.id)?;
        let guard=operation_lock(bundle)?;
        if self.status(&vm.id)?!=VmState::Off {return Err(err("Power off the QEMU machine before changing the installer disc."));}
        // Record the first chosen disc before marking it attached in vm.json. An interrupted
        // save can leave a known disc ejected, and reattaching it safely completes the request.
        let first=!def.legacy_windows && def.iso.is_none() && vm.iso_path.is_some();
        if first {def.iso=vm.iso_path.clone();}
        validate(vm,&def)?;
        if first {save(&bundle.join("qemu-vm.json"),&def)?;}
        Ok(guard)
    }
}

impl Qemu {
    /// Provision a new BIOS PC from the caller's local Windows installer.
    pub fn define_legacy_windows(&mut self,vm:&Vm)->Result<()> {
        self.provision(vm,true)
    }

    pub(crate) fn provision(&self,vm:&Vm,legacy_windows:bool)->Result<()> {
        let tools=self.available()?;
        let bundle=self.bundle(&vm.id)?;
        let iso=vm.iso_path.as_deref().map(|path|local(path,false)).transpose()?;
        let gib=vm.disk_gb.ok_or_else(||err("Choose a size for a new standalone qcow2 disk."))?;
        let def=Definition{id:vm.id.clone(),architecture:vm.architecture,iso,gib,imported_bytes:None,legacy_windows,linked_from:None};
        validate(vm,&def)?;
        let disk=bundle.join("system.qcow2");
        let registration=bundle.join("qemu-vm.json");
        let _lock=operation_lock(bundle)?;
        if disk.try_exists().map_err(io_error)? || registration.try_exists().map_err(io_error)?{return Err(err("This QEMU registration or disk already exists."));}
        let stage=bundle.join(format!(".qemu-staging-{}",unique()));
        fs::create_dir(&stage).map_err(io_error)?;
        let staged_disk=stage.join("system.qcow2");
        let staged_vars=stage.join("uefi-vars.fd");
        let owned_vars=bundle.join("uefi-vars.fd");
        let mut vars_published=false;
        let mut published=false;
        let result=(|| {
            let _image=tools.image.verified()?;
            let mut c=tools::command(&tools.image.path);
            c.args(["create","-f","qcow2"]).arg(&staged_disk).arg(format!("{gib}G"));
            tools::run(c,20)?;
            local(&staged_disk,false)?;
            tools.inspect_disk(&staged_disk,def.bytes())?;
            if vm.architecture==GuestArchitecture::Aarch64 {
                use std::io::Seek;
                let arm=tools.arm_tools()?;
                let mut template=arm.template.verified()?;
                template.rewind().map_err(io_error)?;
                let mut vars=OpenOptions::new().create_new(true).write(true).open(&staged_vars).map_err(io_error)?;
                if std::io::copy(&mut template,&mut vars).map_err(io_error)?!=arm.variables_size() {
                    return Err(err("The Arm UEFI variables template could not be copied completely."));
                }
                vars.sync_all().map_err(io_error)?;
                drop(vars);
                fs::hard_link(&staged_vars,&owned_vars).map_err(io_error)?;
                vars_published=true;
            }
            fs::hard_link(&staged_disk,&disk).map_err(io_error)?;
            published=true;
            save(&registration,&def)
        })();
        if result.is_err() && published{let _=fs::remove_file(&disk);}
        if result.is_err() && vars_published{let _=fs::remove_file(owned_vars);}
        let _=fs::remove_file(staged_vars);
        let _=fs::remove_file(staged_disk);let _=fs::remove_dir(stage);
        result
    }
}
