use super::*;
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read};
use svm_core::model::TemplateDisk;

/// A template disk held open with a handle that denies writers.
pub(super) struct TemplateFile {
    folder: svm_qemu::LocalFolder,
    name: String,
    file: fs::File,
}

impl TemplateFile {
    fn open(bundle: &Path, disk: &Path) -> Result<Self, ApiError> {
        let folder = svm_qemu::LocalFolder::open(bundle).map_err(engine)?;
        let name = disk.file_name().and_then(|value| value.to_str())
            .filter(|value| !value.contains(['/', '\\', ':']))
            .ok_or_else(|| refused("The template disk must be a file in this machine's bundle."))?
            .to_owned();
        let path = folder.path.join(&name);
        if disk.canonicalize().map_err(io_error)? != path {
            return Err(refused("The template disk is outside this machine's bundle."));
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Data is read-only. This handle may also set the exact held file's read-only attribute.
            options.access_mode(0x8000_0000 | 0x100).share_mode(1).custom_flags(0x0020_0000);
        }
        let file = options.open(&path).map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(refused("A link cannot be used as the template disk."));
            }
        }
        if !metadata.is_file() || fs::symlink_metadata(&path).map_err(io_error)?.is_symlink()
            || path.canonicalize().map_err(io_error)? != path
        {
            return Err(refused("The template disk must be an ordinary file in this machine's bundle."));
        }
        Ok(Self { folder, name, file })
    }

    fn path(&self) -> PathBuf { self.folder.path.join(&self.name) }

    fn read_only(&self) -> Result<bool, ApiError> {
        Ok(self.file.metadata().map_err(io_error)?.permissions().readonly())
    }

    fn set_read_only(&self, enabled: bool) -> Result<(), ApiError> {
        let mut permissions = self.file.metadata().map_err(io_error)?.permissions();
        if permissions.readonly() != enabled {
            permissions.set_readonly(enabled);
            self.file.set_permissions(permissions.clone()).map_err(io_error)?;
            // Through a handle, an attribute value of 0 means "leave unchanged", so clearing the flag on
            // a file whose only attribute is read-only does nothing. The held handle denies rename and
            // delete, so the path still names this exact file.
            if self.read_only()? != enabled {
                fs::set_permissions(self.folder.path.join(&self.name), permissions).map_err(io_error)?;
            }
        }
        Ok(())
    }

    pub(super) fn sha256(&self) -> Result<String, ApiError> {
        let mut hash = Sha256::new();
        let mut input = BufReader::with_capacity(1024 * 1024, &self.file);
        let mut chunk = vec![0; 1024 * 1024];
        loop {
            let read = input.read(&mut chunk).map_err(io_error)?;
            if read == 0 { break; }
            hash.update(&chunk[..read]);
        }
        Ok(format!("{:x}", hash.finalize()))
    }

    fn verify(&self, expected: &TemplateDisk) -> Result<(), ApiError> {
        if expected.disk != self.name || self.sha256()? != expected.sha256 {
            return Err(refused("The template disk does not match its recorded SHA-256. The linked clone was refused."));
        }
        Ok(())
    }
}

impl Machines {
    pub(super) fn template_dependents(&self, id: &str) -> Result<Vec<String>, ApiError> {
        let mut names: Vec<_> = self.held_identities()?.into_iter()
            .filter(|v| v.linked_from.as_deref() == Some(id))
            .map(|v| v.name).collect();
        names.sort_unstable();
        names.dedup();
        Ok(names)
    }

    pub(super) fn require_no_linked_clones(&self, id: &str) -> Result<(), ApiError> {
        let names = self.template_dependents(id)?;
        if names.is_empty() { return Ok(()); }
        Err(refused(format!("Linked clones still use this template: {}. Permanently remove their bundles first.", names.join(", "))))
    }

    pub(super) fn template_eligibility(&self, vm: &Vm) -> Result<(), ApiError> {
        self.available(&vm.id)?;
        if vm.throwaway { return Err(refused("Turn off throwaway mode before making a template.")); }
        if !matches!(vm.engine, EngineKind::Qemu | EngineKind::HyperV)
            || vm.state != VmState::Off || vm.linked_from.is_some() || vm.snaps != 0 || vm.tpm == Some(true)
        {
            return Err(refused("Templates require a verified stopped QEMU or Hyper-V machine with a standalone disk, no checkpoints and no virtual TPM."));
        }
        Ok(())
    }

    fn template_file(&self, vm: &Vm) -> Result<TemplateFile, ApiError> {
        let bundle = self.library.bundle_path(&vm.id).map_err(store)?;
        let path = match vm.engine {
            EngineKind::Qemu => self.qemu.template_disk(&vm.id),
            EngineKind::HyperV => self.engine.template_disk(&vm.id),
            EngineKind::AppleVz => return Err(refused("Templates are unavailable for this engine.")),
        }.map_err(engine)?;
        TemplateFile::open(&bundle, &path)
    }

    pub(super) fn seal_template(&mut self, id: &str, networks: &[Network], events: &mut Events) -> Result<Reply, ApiError> {
        let vm = self.vm(id)?;
        self.template_eligibility(&vm)?;
        let _guard = (vm.engine == EngineKind::Qemu).then(|| self.qemu.guard_hardware_change(&vm)).transpose().map_err(engine)?;
        let file = self.template_file(&vm)?;
        if let Some(saved) = &vm.template {
            file.verify(saved)?;
            file.set_read_only(true)?;
            return Ok(Reply::json(self.published(&vm, networks)));
        }
        let digest = file.sha256()?;
        self.finish_seal(vm, &file, digest, networks, events)
    }

    /// Seal a ready-image disk whose SHA-256 the preparation worker computed through a handle that
    /// denied writers. The file must still be that file: it moved by rename into the bundle, so its
    /// size and last-write time are unchanged. Every linked clone re-checks the digest.
    pub(super) fn seal_template_with_digest(
        &mut self, id: &str, digest: &str, bytes: u64, modified: std::time::SystemTime,
        networks: &[Network], events: &mut Events,
    ) -> Result<Reply, ApiError> {
        let vm = self.vm(id)?;
        self.template_eligibility(&vm)?;
        if vm.template.is_some() { return Err(refused("This machine is already a template.")); }
        let _guard = (vm.engine == EngineKind::Qemu).then(|| self.qemu.guard_hardware_change(&vm)).transpose().map_err(engine)?;
        let file = self.template_file(&vm)?;
        let metadata = file.file.metadata().map_err(io_error)?;
        if metadata.len() != bytes || metadata.modified().map_err(io_error)? != modified || digest.len() != 64 {
            return Err(refused("The prepared disk changed after it was checked. Get the image again."));
        }
        self.finish_seal(vm, &file, digest.to_owned(), networks, events)
    }

    fn finish_seal(&mut self, mut vm: Vm, file: &TemplateFile, digest: String, networks: &[Network], events: &mut Events) -> Result<Reply, ApiError> {
        let old = vm.clone();
        let originally_read_only = file.read_only()?;
        vm.template = Some(TemplateDisk { disk: file.name.clone(), sha256: digest, originally_read_only });
        // Publish the write restriction first. Recovery can repeat the attribute change safely.
        self.save(&vm)?;
        if let Err(error) = file.set_read_only(true) {
            self.save(&old)?;
            return Err(error);
        }
        events.record("template sealed", &format!("The disk for {} was sealed as a read-only template.", vm.id))?;
        Ok(Reply::json(self.published(&vm, networks)))
    }

    /// Open a sealed template's disk so another thread can hash it. The handle denies writers for
    /// as long as it is held, so a digest taken through it still describes the file afterwards.
    pub(super) fn held_template(&self, id: &str) -> Result<(TemplateDisk, TemplateFile), ApiError> {
        let source = self.vm(id)?;
        self.template_eligibility(&source)?;
        let saved = source.template.clone().ok_or_else(|| refused("Make this machine a template before creating a linked clone."))?;
        let file = self.template_file(&source)?;
        if !file.read_only()? {
            return Err(refused("The template disk has lost its read-only protection. Verify the template before creating a linked clone."));
        }
        if file.name != saved.disk { return Err(refused("The recorded template disk is no longer attached to this machine.")); }
        Ok((saved, file))
    }

    pub(super) fn unseal_template(&mut self, id: &str, networks: &[Network], events: &mut Events) -> Result<Reply, ApiError> {
        let mut vm = self.vm(id)?;
        self.template_eligibility(&vm)?;
        let Some(saved) = vm.template.clone() else { return Ok(Reply::json(self.published(&vm, networks))); };
        self.require_no_linked_clones(id)?;
        let _guard = (vm.engine == EngineKind::Qemu).then(|| self.qemu.guard_hardware_change(&vm)).transpose().map_err(engine)?;
        let file = self.template_file(&vm)?;
        if saved.disk != file.name {
            return Err(refused("The recorded template disk is no longer attached to this machine."));
        }
        file.set_read_only(saved.originally_read_only)?;
        vm.template = None;
        if let Err(error) = self.save(&vm) {
            let _ = file.set_read_only(true);
            return Err(error);
        }
        events.record("template unsealed", &format!("The read-only template was removed from {id}."))?;
        Ok(Reply::json(self.published(&vm, networks)))
    }

    pub(super) fn recover_template_permissions(&self, events: &mut Events) -> Result<(), ApiError> {
        for vm in self.inventory.iter().filter(|v| v.template.is_some() && v.state == VmState::Off) {
            let Some(saved) = &vm.template else { continue; };
            let result = (|| {
                let bundle = self.library.bundle_path(&vm.id).map_err(store)?;
                let disk = Path::new(&saved.disk);
                if disk.components().count() != 1 || !matches!(disk.components().next(), Some(std::path::Component::Normal(_))) {
                    return Err(refused("The recorded template disk name is invalid."));
                }
                let present = TemplateFile::open(&bundle, &bundle.join(disk))?;
                if present.read_only()? { return Ok(false); }
                drop(present);
                self.template_eligibility(vm)?;
                let _guard = (vm.engine == EngineKind::Qemu).then(|| self.qemu.guard_hardware_change(vm)).transpose().map_err(engine)?;
                let file = self.template_file(vm)?;
                file.verify(saved)?;
                file.set_read_only(true)?;
                Ok(true)
            })();
            match result {
                Ok(true) => events.record("template recovered", &format!("Read-only protection was restored for {}.", vm.id))?,
                Ok(false) => {}
                Err(_) => events.record("template protection unavailable", &format!("Inspect {} before creating linked clones.", vm.id))?,
            }
        }
        Ok(())
    }

    /// `trusted_digest` is a SHA-256 the caller computed through a held handle that denied writers
    /// (see held_template); otherwise the disk is hashed here.
    pub(super) fn link_template(
        &mut self, id: &str, name: String, requested_id: Option<String>, trusted_digest: Option<&str>,
        networks: &[Network], events: &mut Events,
    ) -> Result<Reply, ApiError> {
        let source = self.vm(id)?;
        self.template_eligibility(&source)?;
        let saved = source.template.as_ref().ok_or_else(|| refused("Make this machine a template before creating a linked clone."))?;
        let parent = self.template_file(&source)?;
        if !parent.read_only()? {
            return Err(refused("The template disk has lost its read-only protection. Verify the template before creating a linked clone."));
        }
        match trusted_digest {
            Some(digest) if digest == saved.sha256 && parent.name == saved.disk => {}
            Some(_) => return Err(refused("The template disk does not match its recorded SHA-256. The linked clone was refused.")),
            None => parent.verify(saved)?,
        }
        let mut child = source.clone();
        child.id = requested_id.unwrap_or_else(next_id);
        child.name = name;
        self.ensure_identity(&child.id, &child.name)?;
        let net = network(networks, &child.net)?;
        let identity = identity::allocate(&child.id, &child.name, net, &self.held_identities()?).map_err(store)?;
        child.mac = identity.mac;
        child.ip = identity.ip;
        child.dns = identity.dns;
        child.cores.clear();
        child.disk_gb = None;
        child.disk_path = Some(PathBuf::from(match child.engine {
            EngineKind::Qemu => "system.qcow2",
            EngineKind::HyperV => "system.vhdx",
            EngineKind::AppleVz => return Err(refused("Linked clones are unavailable for this engine.")),
        }));
        child.iso_path = None;
        child.share_clipboard = false;
        child.port_forwards.clear();
        child.template = None;
        child.throwaway = false;
        child.linked_from = Some(source.id.clone());
        let bundle = self.stage(&child)?;
        let result = match child.engine {
            EngineKind::Qemu => self.qemu.create_linked_clone(&source, &child),
            _ => self.engine.create_linked(&source, &child, &parent.path()),
        };
        drop(parent);
        if let Err(error) = result {
            match self.driver_mut(child.engine)?.state(&child.id) {
                Err(EngineError::Missing(_)) => {
                    self.driver_mut(child.engine)?.trash_detached(&child.id, &bundle).map_err(engine)?;
                    if child.engine == EngineKind::Qemu {
                        let receipt = RemovalReceipt { id: child.id.clone(), retained: None, bytes: None };
                        svm_core::write_json(&bundle.join("removal-complete.json"), &receipt).map_err(store)?;
                    }
                    self.forget(&child.id)?;
                }
                Ok(VmState::Off) => { self.remove_incomplete_linked_clone(&child.id, events)?; }
                _ => events.record("linked clone incomplete", &format!("Inspect the registered copy of {} before retrying.", child.id))?,
            }
            return Err(engine(error));
        }
        events.record("linked clone created", &format!("{} uses the read-only template {}.", child.id, source.id))?;
        Ok(Reply::created(self.published(&child, networks)))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn clearing_read_only_works_when_it_is_the_only_attribute() {
        let root = std::env::temp_dir().join(next_id());
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let disk = root.join("system.vhdx");
        fs::write(&disk, b"synthetic template contents").unwrap();
        // Read-only as the only attribute (no archive bit): the case a handle cannot clear.
        let plain = disk.to_string_lossy().trim_start_matches(r"\\?\").to_owned();
        assert!(std::process::Command::new("attrib").args(["-A", "+R", &plain]).status().unwrap().success());
        let held = TemplateFile::open(&root, &disk).unwrap();
        assert!(held.read_only().unwrap());
        held.set_read_only(false).unwrap();
        assert!(!held.read_only().unwrap());
        drop(held);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn held_template_preserves_attributes_and_rejects_different_bytes() {
        let root = std::env::temp_dir().join(next_id());
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let disk = root.join("system.qcow2");
        fs::write(&disk, b"synthetic template contents").unwrap();

        let held = TemplateFile::open(&root, &disk).unwrap();
        let record = TemplateDisk {
            disk: held.name.clone(),
            sha256: held.sha256().unwrap(),
            originally_read_only: held.read_only().unwrap(),
        };
        held.set_read_only(true).unwrap();
        assert!(held.read_only().unwrap());
        held.set_read_only(record.originally_read_only).unwrap();
        assert!(!held.read_only().unwrap());
        drop(held);

        fs::write(&disk, b"synthetic Template contents").unwrap();
        let changed = TemplateFile::open(&root, &disk).unwrap();
        let error = changed.verify(&record).unwrap_err();
        assert!(error.message.contains("recorded SHA-256"));
        drop(changed);
        fs::remove_file(disk).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
