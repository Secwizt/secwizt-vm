use std::{collections::BTreeSet, fs::{self,File,OpenOptions}, io, path::{Path,PathBuf}};
use crate::{identity::{validate_subnets,Subnet}, model::{Network,Vm}, storage::{read_json,unique_name,write_json},Error};

#[path = "library_trash.rs"]
mod trash;
pub use trash::TrashEntry;

#[derive(Debug, Clone)]
pub struct Library { root:PathBuf, stable_bundles:bool }

pub fn validate_name(name:&str)->Result<(),Error> {
    let bad = || Error::Invalid("Use a plain bundle name without separators, reserved device names or trailing spaces and dots.".into());
    if name.trim() != name || name.starts_with('.') || name.len() > 160 || !ordinary_file_name(name) {
        return Err(bad());
    }
    Ok(())
}

pub fn ordinary_file_name(name: &str) -> bool {
    if name.is_empty() || name.ends_with([' ', '.'])
        || name.chars().any(|c| c.is_control() || r#"\\/:*?"<>|"#.contains(c)) {
        return false;
    }
    let stem = name.split_once('.').map_or(name, |(first, _)| first).trim_end().to_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return false;
    }
    !["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|digit| matches!(digit, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"))
    })
}

fn direct_child(path:&Path,parent:&Path,dir:bool)->Result<(),Error> {
    let meta=fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || (dir && !meta.is_dir()) || (!dir && !meta.is_file())
        || path.canonicalize()?.parent()!=Some(parent) {
        return Err(Error::Invalid(format!("Unexpected file or linked path at {}.",path.display())));
    }
    Ok(())
}

fn exists(path:&Path)->Result<bool,Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),Err(e) if e.kind()==io::ErrorKind::NotFound => Ok(false),Err(e)=>Err(e.into()),
    }
}

impl Library {
    pub fn open(root:impl AsRef<Path>)->Result<Self,Error> {
        Self::open_mode(root.as_ref(), false)
    }
    /// Keep bundle paths fixed while display names are edited in the VM service.
    pub fn open_stable(root:impl AsRef<Path>)->Result<Self,Error> {
        Self::open_mode(root.as_ref(), true)
    }
    fn open_mode(root:&Path, stable_bundles:bool)->Result<Self,Error> {
        fs::create_dir_all(root)?;
        let lib=Self {root:root.canonicalize()?, stable_bundles};
        let _lock=lib.lock()?;
        let networks=lib.root.join("networks.json");
        if !exists(&networks)? {write_json(&networks,&Vec::<Network>::new())?;}
        else { direct_child(&networks,&lib.root,false)?; }
        Ok(lib)
    }
    fn lock(&self)->Result<File,Error> {
        let path=self.root.join(".library.lock");
        if exists(&path)? {direct_child(&path,&self.root,false)?;}
        let file=OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        file.lock()?;
        Ok(file)
    }
    fn bundle(&self,name:&str)->PathBuf {self.root.join(format!("{name}.swvm"))}
    fn machines(&self)->Result<Vec<Vm>,Error> { self.scan_machines(false) }
    fn scan_machines(&self,include_restoring:bool)->Result<Vec<Vm>,Error> {
        let mut out=Vec::new();
        let mut ids=BTreeSet::new();
        for entry in fs::read_dir(&self.root)? {
            let path=entry?.path();
            if path.extension().and_then(|e| e.to_str())!=Some("swvm") {continue;}
            let name=path.file_stem().and_then(|n|n.to_str()).ok_or_else(||Error::Invalid("Invalid bundle filename.".into()))?;
            validate_name(name)?;
            direct_child(&path,&self.root,true)?;
            if !include_restoring && exists(&path.join(trash::RESTORING))? {continue;}
            let json=path.join("vm.json");
            direct_child(&json,&path.canonicalize()?,false)?;
            let mut vm:Vm=read_json(&json)?;
            // A renamed directory is authoritative even if the host stopped before the JSON refresh.
            if self.stable_bundles { validate_name(&vm.name)?; } else { vm.name=name.into(); }
            if vm.id.trim().is_empty() || !ids.insert(vm.id.clone()) {return Err(Error::Invalid("Duplicate or empty machine ID on disk.".into()));}
            out.push(vm);
        }
        out.sort_by(|a,b|a.name.cmp(&b.name));
        Ok(out)
    }
    pub fn load_all(&self)->Result<Vec<Vm>,Error> {let _lock=self.lock()?;self.machines()}
    fn find(&self,id:&str)->Result<Vm,Error> {
        self.machines()?.into_iter().find(|v|v.id==id).ok_or_else(||Error::Missing(id.into()))
    }
    fn validate(&self,v:&Vm,all:&[Vm],updating:bool)->Result<(),Error> {
        validate_name(&v.name)?;
        if v.id.trim().is_empty() || v.vcpu==0 || v.ram_gb==0 || !v.mac.is_station() || v.dns.trim().is_empty() {
            return Err(Error::Invalid("Machine identity and resource fields must be valid.".into()));
        }
        for peer in all {
            if updating && peer.id==v.id {continue;}
            if peer.id==v.id || peer.name.to_lowercase()==v.name.to_lowercase() ||
                peer.mac==v.mac || peer.ip==v.ip || peer.dns.eq_ignore_ascii_case(&v.dns) {
                return Err(Error::Conflict(format!("Machine name, ID or network identity conflicts with {}.",peer.name)));
            }
        }
        Ok(())
    }
    pub fn create(&self,v:&Vm)->Result<(),Error> {
        let _lock=self.lock()?;
        self.validate(v,&self.scan_machines(true)?,false)?;
        let stem=if self.stable_bundles { &v.id } else { &v.name };
        validate_name(stem)?;
        let destination=self.bundle(stem);
        if exists(&destination)? {return Err(Error::Conflict(v.name.clone()));}
        let stage=loop {
            let dir=self.root.join(unique_name(".svm-new"));
            match fs::create_dir(&dir) {
                Ok(())=>break dir,Err(e) if e.kind()==io::ErrorKind::AlreadyExists=>continue,Err(e)=>return Err(e.into()),
            }
        };
        let json=stage.join("vm.json");
        let result=write_json(&json,v).and_then(|()|Ok(fs::rename(&stage,destination)?));
        if result.is_err() {let _=fs::remove_file(json);let _=fs::remove_dir(stage);}
        result
    }
    /// Publish a fully prepared new backup restore under the same lock as ordinary creation.
    pub fn publish_backup(&self, vm: &Vm) -> Result<PathBuf, Error> {
        let _lock = self.lock()?;
        validate_name(&vm.id)?;
        self.validate(vm, &self.scan_machines(true)?, false)?;
        let stage = self.root.join(format!(".svm-restore-{}", vm.id));
        direct_child(&stage, &self.root, true)?;
        let prepared = stage.join("prepared");
        direct_child(&prepared, &stage, true)?;
        let destination = self.bundle(&vm.id);
        if exists(&destination)? { return Err(Error::Conflict(vm.id.clone())); }
        write_json(&prepared.join("vm.json"), vm)?;
        fs::rename(prepared, &destination)?;
        Ok(destination)
    }
    /// Locate by persistent identity, also supporting existing display-name bundles.
    pub fn bundle_path(&self,id:&str)->Result<PathBuf,Error> {
        let _lock=self.lock()?;
        self.locate(id)
    }
    fn locate(&self,id:&str)->Result<PathBuf,Error> {
        for entry in fs::read_dir(&self.root)? {
            let path=entry?.path();
            if path.extension().and_then(|e|e.to_str())!=Some("swvm") {continue;}
            direct_child(&path,&self.root,true)?;
            let record=path.join("vm.json");
            direct_child(&record,&path.canonicalize()?,false)?;
            if read_json::<Vm>(&record)?.id==id {return Ok(path);}
        }
        Err(Error::Missing(id.into()))
    }
    pub fn save(&self,v:&Vm)->Result<(),Error> {
        let _lock=self.lock()?;
        let all=self.machines()?;
        let old=all.iter().find(|m|m.id==v.id).ok_or_else(||Error::Missing(v.id.clone()))?;
        if !self.stable_bundles && old.name!=v.name {return Err(Error::Invalid("Use rename to change a bundle name.".into()));}
        self.validate(v,&self.scan_machines(true)?,true)?;
        write_json(&self.locate(&v.id)?.join("vm.json"),v)
    }
    pub fn rename(&self,id:&str,new_name:&str)->Result<Vm,Error> {
        validate_name(new_name)?;
        let _lock=self.lock()?;
        let all=self.machines()?;
        let mut vm=all.iter().find(|m|m.id==id).cloned().ok_or_else(||Error::Missing(id.into()))?;
        if vm.name==new_name {return Ok(vm);}
        if self.stable_bundles {
            vm.name=new_name.into();
            self.validate(&vm,&self.scan_machines(true)?,true)?;
            write_json(&self.locate(id)?.join("vm.json"),&vm)?;
            return Ok(vm);
        }
        let old=self.bundle(&vm.name);
        let dest=self.bundle(new_name);
        vm.name=new_name.into();
        self.validate(&vm,&self.scan_machines(true)?,true)?;
        if exists(&dest)? && old.canonicalize()?!=dest.canonicalize()? {return Err(Error::Conflict(new_name.into()));}
        fs::rename(&old,&dest)?;
        if let Err(e)=write_json(&dest.join("vm.json"),&vm) {
            fs::rename(&dest,old)?;
            return Err(e);
        }
        Ok(vm)
    }
    pub fn delete(&self,id:&str)->Result<PathBuf,Error> {
        let _lock=self.lock()?;
        let vm=self.find(id)?;
        let trash=self.root.join("trash");
        if !exists(&trash)? {fs::create_dir(&trash)?;}
        direct_child(&trash,&self.root,true)?;
        let epoch=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        loop {
            let dest=trash.join(format!("{}-{epoch:x}-{}.swvm",vm.name,unique_name("deleted")));
            if !exists(&dest)? {fs::rename(self.locate(id)?,&dest)?;return Ok(dest);}
        }
    }
    pub fn load_networks(&self)->Result<Vec<Network>,Error> {
        let _lock=self.lock()?;
        let p=self.root.join("networks.json");direct_child(&p,&self.root,false)?;read_json(&p)
    }
    pub fn save_networks(&self,networks:&[Network],host_lan:Subnet)->Result<(),Error> {
        let _lock=self.lock()?;
        validate_subnets(networks,host_lan)?;
        let p=self.root.join("networks.json");direct_child(&p,&self.root,false)?;write_json(&p,networks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::sample,storage::{write_atomic,TestDir}};
    use std::io::Write;
    #[test]
    fn create_reload_rename_and_trash() {
        let d=TestDir::new();let lib=Library::open(&d.0).unwrap();let v=sample();
        lib.create(&v).unwrap();assert!(lib.create(&v).is_err());
        assert_eq!(Library::open(&d.0).unwrap().load_all().unwrap(),vec![v.clone()]);
        let mut changed=lib.rename(&v.id,"Renamed").unwrap();changed.ram_gb=6;lib.save(&changed).unwrap();
        assert_eq!(lib.load_all().unwrap(),vec![changed.clone()]);
        let trashed=lib.delete(&v.id).unwrap();assert!(trashed.starts_with(d.0.canonicalize().unwrap().join("trash")));
        assert_eq!(read_json::<Vm>(&trashed.join("vm.json")).unwrap(),changed);
        assert!(lib.load_all().unwrap().is_empty());
    }
    #[test]
    fn partial_save_preserves_old_definition() {
        let d=TestDir::new();let lib=Library::open(&d.0).unwrap();let v=sample();lib.create(&v).unwrap();
        let dest=lib.bundle(&v.name).join("vm.json");
        let result=write_atomic(&dest,|file| {file.write_all(b"incomplete")?;Err(Error::Invalid("Injected failure.".into()))});
        assert!(result.is_err());assert_eq!(lib.load_all().unwrap(),vec![v]);
    }
    #[test]
    fn rejects_traversal_and_device_names() {
        for n in ["..","../other",r"..\other",r"C:\escape","NUL","LPT1.log","name:alt","end.","A/B"] {
            assert!(validate_name(n).is_err(),"{n}");
        }
        let d=TestDir::new();let lib=Library::open(&d.0).unwrap();let mut v=sample();v.name="../escape".into();
        assert!(lib.create(&v).is_err());
    }

    #[test]
    fn restore_pending_is_retryable_and_keeps_the_guest_disk() {
        let dir=TestDir::new();let lib=Library::open_stable(&dir.0).unwrap();
        let vm=sample();lib.create(&vm).unwrap();
        let path=lib.bundle_path(&vm.id).unwrap();
        fs::write(path.join("system.vhdx"),b"installed guest").unwrap();
        lib.delete(&vm.id).unwrap();
        let entry=lib.list_trash().unwrap().pop().unwrap();
        assert!(lib.purge_trash(&entry.key,"another machine").is_err());
        assert_eq!(lib.prepare_restore(&entry.key).unwrap().path,path);
        let reopened=Library::open_stable(&dir.0).unwrap();
        assert!(reopened.load_all().unwrap().is_empty());
        assert!(reopened.list_trash().unwrap()[0].restoring);
        assert!(reopened.purge_trash(&entry.key,&vm.name).is_err());
        reopened.cancel_restore(&entry.key).unwrap();
        reopened.prepare_restore(&entry.key).unwrap();
        reopened.finish_restore(&entry.key).unwrap();
        assert_eq!(reopened.load_all().unwrap(),[vm]);
        assert!(reopened.list_trash().unwrap().is_empty());
        assert_eq!(fs::read(path.join("system.vhdx")).unwrap().as_slice(),b"installed guest");
    }

    #[test]
    fn permanent_delete_only_removes_the_selected_trashed_copy() {
        let dir=TestDir::new();let lib=Library::open_stable(&dir.0).unwrap();
        let vm=sample();lib.create(&vm).unwrap();let first=lib.delete(&vm.id).unwrap();
        let key=lib.list_trash().unwrap()[0].key.clone();
        lib.create(&vm).unwrap();
        assert!(lib.prepare_restore(&key).is_err());
        let second=lib.delete(&vm.id).unwrap();
        lib.purge_trash(&key,&vm.name).unwrap();
        assert!(!first.exists());
        assert!(second.join("vm.json").is_file());
        assert_eq!(lib.list_trash().unwrap().len(),1);
    }

    #[test]
    fn interrupted_final_delete_keeps_a_retryable_named_record() {
        let dir=TestDir::new();let lib=Library::open_stable(&dir.0).unwrap();
        let vm=sample();lib.create(&vm).unwrap();let path=lib.delete(&vm.id).unwrap();
        let key=lib.list_trash().unwrap()[0].key.clone();
        write_json(&path.join(".delete-pending.json"),&key).unwrap();
        fs::rename(path.join("vm.json"),path.with_extension("swvm.delete.json")).unwrap();
        let reopened=Library::open_stable(&dir.0).unwrap();
        assert!(reopened.list_trash().unwrap()[0].metadata_only);
        assert!(reopened.purge_trash(&key,"wrong").is_err());
        reopened.purge_trash(&key,&vm.name).unwrap();
        assert!(reopened.list_trash().unwrap().is_empty());
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn purge_waits_briefly_for_a_file_another_process_still_holds() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir=TestDir::new();let lib=Library::open_stable(&dir.0).unwrap();
        let vm=sample();lib.create(&vm).unwrap();let path=lib.delete(&vm.id).unwrap();
        fs::write(path.join("system.vhdx"),b"disk").unwrap();
        // Like a scanner opening the moved disk: no sharing at all, released after 600 ms.
        let held=fs::OpenOptions::new().read(true).share_mode(0).open(path.join("system.vhdx")).unwrap();
        let release=std::thread::spawn(move||{std::thread::sleep(std::time::Duration::from_millis(600));drop(held);});
        let key=lib.list_trash().unwrap()[0].key.clone();
        lib.purge_trash(&key,&vm.name).unwrap();
        release.join().unwrap();
        assert!(lib.list_trash().unwrap().is_empty());
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_purge_stopped_by_a_long_lock_keeps_its_records_for_the_retry() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir=TestDir::new();let lib=Library::open_stable(&dir.0).unwrap();
        let vm=sample();lib.create(&vm).unwrap();let path=lib.delete(&vm.id).unwrap();
        fs::write(path.join("system.qcow2"),b"disk").unwrap();
        fs::write(path.join("removal-complete.json"),b"{}").unwrap();
        let held=fs::OpenOptions::new().read(true).share_mode(0).open(path.join("system.qcow2")).unwrap();
        let key=lib.list_trash().unwrap()[0].key.clone();
        assert!(lib.purge_trash(&key,&vm.name).is_err(),"a disk held past the retry window stops the purge");
        assert!(path.join("removal-complete.json").is_file(),"the removal receipt survives for the retry");
        drop(held);
        lib.purge_trash(&key,&vm.name).unwrap();
        assert!(lib.list_trash().unwrap().is_empty());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn trash_refuses_nested_links_before_removing_any_files() {
        let dir=TestDir::new();let lib=Library::open_stable(&dir.0).unwrap();
        let vm=sample();lib.create(&vm).unwrap();let path=lib.delete(&vm.id).unwrap();
        std::os::unix::fs::symlink(&dir.0,path.join("outside")).unwrap();
        let key=lib.list_trash().unwrap()[0].key.clone();
        assert!(lib.prepare_restore(&key).is_err());
        assert!(lib.purge_trash(&key,&vm.name).is_err());
        assert!(path.join("vm.json").is_file());
    }

    #[test]
    fn stable_bundles_keep_the_registration_path_on_display_rename() {
        let dir=TestDir::new();
        let lib=Library::open_stable(&dir.0).unwrap();
        let guest=sample();
        lib.create(&guest).unwrap();
        let path=lib.bundle_path(&guest.id).unwrap();
        assert_eq!(path.file_stem().unwrap(),guest.id.as_str());
        let mut renamed=guest.clone();renamed.name="Another display name".into();
        lib.save(&renamed).unwrap();
        assert_eq!(lib.bundle_path(&guest.id).unwrap(),path);
        assert_eq!(lib.load_all().unwrap(),[renamed]);
    }
}
