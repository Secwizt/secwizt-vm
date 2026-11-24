use super::*;

pub(super) const RESTORING: &str = ".restore-pending.json";
const PURGING: &str = ".delete-pending.json";

/// A virus scanner or Hyper-V may hold a file of a just-moved bundle open for a moment.
/// Retry only sharing, lock and access errors, for about five seconds, before giving up.
fn settle<T>(mut op: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    for _ in 0..20 {
        match op() {
            Err(error) if matches!(error.raw_os_error(), Some(5 | 32 | 33)) => std::thread::sleep(std::time::Duration::from_millis(250)),
            other => return other,
        }
    }
    op()
}

#[derive(Debug, Clone)]
pub struct TrashEntry {
    pub key: String,
    pub machine: Vm,
    pub path: PathBuf,
    pub restoring: bool,
    pub purging: bool,
    pub metadata_only: bool,
    original: String,
}

fn invalid_trash() -> Error { Error::Invalid("The trash record has an unexpected path or identity.".into()) }

fn entry_key(name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(name.len()*2);
    for b in name.bytes() {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 15) as usize]));
    }
    out
}

fn checked_tree(root: &Path) -> Result<(), Error> {
    let mut folders = vec![root.to_owned()];
    while let Some(parent) = folders.pop() {
        for child in fs::read_dir(&parent)? {
            let path = child?.path();
            let meta = fs::symlink_metadata(&path)?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & 0x400 != 0 { return Err(invalid_trash()); }
            }
            direct_child(&path,&parent,meta.is_dir())?;
            if meta.is_dir() {folders.push(path);}
        }
    }
    Ok(())
}

impl Library {
    fn trash_entries(&self) -> Result<Vec<TrashEntry>, Error> {
        let trash = self.root.join("trash");
        let mut entries = Vec::new();
        for (parent,restoring) in [(&trash,false),(&self.root,true)] {
            if !exists(parent)? {continue;}
            if !restoring { direct_child(parent,&self.root,true)?; }
            for child in fs::read_dir(parent)? {
                let path = child?.path();
                if !restoring {
                    if let Some(original)=path.file_name().and_then(|x|x.to_str()).and_then(|x|x.strip_suffix(".delete.json")).filter(|x|x.ends_with(".swvm")) {
                        direct_child(&path,parent,false)?;
                        let machine:Vm=read_json(&path)?;
                        validate_name(&machine.name)?;
                        let old=parent.join(original);
                        if exists(&old)? {
                            direct_child(&old,parent,true)?;
                            if exists(&old.join("vm.json"))? {return Err(invalid_trash());}
                        }
                        entries.push(TrashEntry {key:entry_key(original),machine,path:old,restoring:false,purging:true,metadata_only:true,original:original.into()});
                        continue;
                    }
                }
                if path.extension().and_then(|x|x.to_str()) != Some("swvm") {continue;}
                direct_child(&path,parent,true)?;
                let marker = path.join(RESTORING);
                let original = if restoring {
                    if !exists(&marker)? {continue;}
                    direct_child(&marker,&path,false)?;
                    read_json::<String>(&marker)?
                } else {
                    path.file_name().and_then(|x|x.to_str()).ok_or_else(invalid_trash)?.into()
                };
                if Path::new(&original).file_name().and_then(|x|x.to_str()) != Some(original.as_str())
                    || !original.ends_with(".swvm") || original.contains(['/', '\\', ':']) {return Err(invalid_trash());}
                let record = path.join("vm.json");
                if !restoring && !exists(&record)? && exists(&parent.join(format!("{original}.delete.json")))? {continue;}
                direct_child(&record,&path,false)?;
                let machine: Vm = read_json(&record)?;
                validate_name(&machine.name)?;
                entries.push(TrashEntry {key:entry_key(&original),machine,restoring,metadata_only:false,purging:exists(&path.join(PURGING))?,path,original});
            }
        }
        entries.sort_by(|a,b|a.machine.name.cmp(&b.machine.name).then(a.key.cmp(&b.key)));
        Ok(entries)
    }
    fn trash_entry(&self,key:&str)->Result<TrashEntry,Error>{
        let mut found=self.trash_entries()?.into_iter().filter(|e|e.key==key);
        let entry=found.next().ok_or_else(||Error::Missing("trash entry".into()))?;
        if found.next().is_some() {return Err(invalid_trash());}
        Ok(entry)
    }
    pub fn list_trash(&self)->Result<Vec<TrashEntry>,Error>{let _lock=self.lock()?;self.trash_entries()}

    pub fn prepare_restore(&self,key:&str)->Result<TrashEntry,Error>{
        let _lock=self.lock()?;
        let mut entry=self.trash_entry(key)?;
        if entry.purging {return Err(Error::Conflict("Permanent deletion already started.".into()));}
        checked_tree(&entry.path)?;
        self.validate(&entry.machine,&self.scan_machines(true)?,entry.restoring)?;
        if entry.restoring {return Ok(entry);}
        let stem=if self.stable_bundles {&entry.machine.id} else {&entry.machine.name};
        validate_name(stem)?;
        let active=self.bundle(stem);
        if exists(&active)? {return Err(Error::Conflict("The original library location is occupied.".into()));}
        write_json(&entry.path.join(RESTORING),&entry.original)?;
        fs::rename(&entry.path,&active)?;
        entry.path=active;
        entry.restoring=true;
        Ok(entry)
    }

    pub fn finish_restore(&self,key:&str)->Result<(),Error>{
        let _lock=self.lock()?;
        let entry=self.trash_entry(key)?;
        if !entry.restoring {return Err(invalid_trash());}
        let receipt=entry.path.join("removal-complete.json");
        if exists(&receipt)? {
            direct_child(&receipt,&entry.path,false)?;
            fs::rename(&receipt,entry.path.join("last-restored-removal.json"))?;
        }
        fs::remove_file(entry.path.join(RESTORING))?;
        Ok(())
    }

    /// Only return files to trash after the engine confirms the registration is absent.
    pub fn cancel_restore(&self,key:&str)->Result<(),Error>{
        let _lock=self.lock()?;
        let entry=self.trash_entry(key)?;
        if !entry.restoring {return Ok(());}
        let parent=self.root.join("trash");
        direct_child(&parent,&self.root,true)?;
        let destination=parent.join(entry.original);
        if exists(&destination)? {return Err(Error::Conflict("The trash destination is already occupied.".into()));}
        let receipt=entry.path.join("removal-complete.json");
        let previous=entry.path.join("last-restored-removal.json");
        if !exists(&receipt)? && exists(&previous)? {
            direct_child(&previous,&entry.path,false)?;
            fs::rename(previous,receipt)?;
        }
        fs::rename(&entry.path,&destination)?;
        fs::remove_file(destination.join(RESTORING))?;
        Ok(())
    }

    pub fn purge_trash(&self,key:&str,confirm_name:&str)->Result<(),Error>{
        let _lock=self.lock()?;
        let entry=self.trash_entry(key)?;
        if entry.restoring || entry.machine.name!=confirm_name {return Err(Error::Conflict("The selected trash entry changed.".into()));}
        let terminal=self.root.join("trash").join(format!("{}.delete.json",entry.original));
        let marker=entry.path.join(PURGING);
        let finish=||->Result<(),Error>{
            if exists(&entry.path)? {
                direct_child(&entry.path,&self.root.join("trash"),true)?;
                if exists(&marker)? {
                    direct_child(&marker,&entry.path,false)?;
                    if read_json::<String>(&marker)?!=entry.key {return Err(invalid_trash());}
                    fs::remove_file(&marker)?;
                }
                settle(|| fs::remove_dir(&entry.path))?;
            }
            direct_child(&terminal,&self.root.join("trash"),false)?;
            fs::remove_file(&terminal)?;
            Ok(())
        };
        if entry.metadata_only {return finish();}
        checked_tree(&entry.path)?;
        if exists(&terminal)? {return Err(invalid_trash());}
        write_json(&marker,&entry.key)?;
        if let Some(template) = &entry.machine.template {
            let leaf = Path::new(&template.disk);
            let disk_file = leaf.extension().and_then(|suffix| suffix.to_str())
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case("qcow2") || suffix.eq_ignore_ascii_case("vhdx"));
            if leaf.components().count() != 1 || !disk_file {
                return Err(invalid_trash());
            }
            let disk = entry.path.join(leaf);
            if exists(&disk)? {
                direct_child(&disk, &entry.path, false)?;
                let mut permissions = fs::metadata(&disk)?.permissions();
                if permissions.readonly() {
                    permissions.set_readonly(false);
                    fs::set_permissions(&disk, permissions)?;
                }
            }
        }
        // Payload first, small JSON records last: a purge stopped by a locked disk keeps the
        // records a later purge needs, such as a QEMU removal receipt.
        let mut records=Vec::new();
        for child in fs::read_dir(&entry.path)? {
            let child=child?;
            let path=child.path();
            if child.file_name()=="vm.json" || path==marker {continue;}
            if child.file_type()?.is_dir() {settle(|| fs::remove_dir_all(&path))?;}
            else if path.extension().is_some_and(|suffix| suffix.eq_ignore_ascii_case("json")) {records.push(path);}
            else {settle(|| fs::remove_file(&path))?;}
        }
        for path in records {settle(|| fs::remove_file(&path))?;}
        // Keep the confirmed identity discoverable even if final directory cleanup fails.
        settle(|| fs::rename(entry.path.join("vm.json"),&terminal))?;
        finish()
    }
}
