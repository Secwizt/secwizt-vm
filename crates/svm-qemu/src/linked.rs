//! A linked QEMU disk has exactly one approved, read-only standalone parent.

use crate::{err, io_error, local, record, save, tools, Definition, LocalFolder, Qemu, Result};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use svm_core::{
    library::{ordinary_file_name, Library},
    model::{GuestArchitecture, Vm, VmState},
};

pub(crate) const DISK: &str = "system.qcow2";
const BACKING_FORMAT_EXTENSION: u32 = 0xe279_2aca;
const EXTERNAL_DATA_EXTENSION: u32 = 0x4441_5441;

pub(crate) struct Parent {
    folder: LocalFolder,
    disk: PathBuf,
    _handle: File,
}

pub(crate) struct RuntimeBacking {
    parent: Parent,
    _child: File,
}

impl RuntimeBacking {
    pub(crate) fn path(&self) -> &Path { &self.parent.disk }
}

pub(crate) fn hold_file(path: &Path, allow_write: bool) -> Result<File> {
    let original = local(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(if allow_write { 3 } else { 1 }).custom_flags(0x0020_0000);
    }
    #[cfg(not(windows))]
    let _ = allow_write;
    let file = options.open(path).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(err("A QEMU disk path changed to a reparse point."));
        }
    }
    if !metadata.is_file() || local(path, false)? != original {
        return Err(err("The QEMU disk path changed."));
    }
    Ok(file)
}

fn be32(bytes: &[u8], range: std::ops::Range<usize>) -> u32 {
    u32::from_be_bytes(bytes[range].try_into().expect("four-byte qcow2 field"))
}

fn be64(bytes: &[u8], range: std::ops::Range<usize>) -> u64 {
    u64::from_be_bytes(bytes[range].try_into().expect("eight-byte qcow2 field"))
}

pub(crate) fn header(mut file: impl Read + Seek, size: u64, backing: Option<&str>) -> Result<()> {
    let invalid = || err("The QEMU disk does not match its approved qcow2 size and backing format.");
    let mut fixed = [0; 104];
    file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    file.read_exact(&mut fixed[..72]).map_err(io_error)?;
    let version = be32(&fixed, 4..8);
    if &fixed[..4] != b"QFI\xfb" || !matches!(version, 2 | 3) {
        return Err(invalid());
    }
    if version == 3 { file.read_exact(&mut fixed[72..]).map_err(io_error)?; }
    if be64(&fixed, 24..32) != size || be32(&fixed, 32..36) != 0 ||
        (version == 3 && be64(&fixed, 72..80) & 4 != 0) {
        return Err(invalid());
    }
    let start = be64(&fixed, 8..16);
    let length = u64::from(be32(&fixed, 16..20));
    let Some(expected) = backing else {
        return if start == 0 && length == 0 { Ok(()) } else { Err(invalid()) };
    };
    let bits = be32(&fixed, 20..24);
    if !(9..=21).contains(&bits) || length != expected.len() as u64 ||
        start.checked_add(length).is_none_or(|end| end > (1_u64 << bits)) {
        return Err(invalid());
    }
    let fixed_size = if version == 3 { 104 } else { 72 };
    let extensions = if version == 3 { u64::from(be32(&fixed, 100..104)) } else { fixed_size };
    if extensions < fixed_size || extensions > start {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start(extensions)).map_err(io_error)?;
    let mut bytes = vec![0; usize::try_from(start + length - extensions).map_err(io_error)?];
    file.read_exact(&mut bytes).map_err(io_error)?;
    let name = usize::try_from(start - extensions).map_err(io_error)?;
    if &bytes[name..] != expected.as_bytes() { return Err(invalid()); }

    let mut position = 0;
    let mut format_found = false;
    while position + 8 <= name {
        let kind = be32(&bytes, position..position + 4);
        let amount = usize::try_from(be32(&bytes, position + 4..position + 8)).map_err(io_error)?;
        position += 8;
        if kind == 0 { break; }
        let end = position.checked_add(amount).filter(|end| *end <= name).ok_or_else(invalid)?;
        if kind == EXTERNAL_DATA_EXTENSION { return Err(invalid()); }
        if kind == BACKING_FORMAT_EXTENSION {
            if format_found || &bytes[position..end] != b"qcow2" { return Err(invalid()); }
            format_found = true;
        }
        position = end.checked_add(7).ok_or_else(invalid)? & !7;
    }
    if format_found { Ok(()) } else { Err(invalid()) }
}

pub(crate) fn standalone_disk(path: &Path, size: u64) -> Result<File> {
    let handle = hold_file(path, false)?;
    header(&handle, size, None)?;
    Ok(handle)
}

fn relative_backing(parent: &Path, child: &Path) -> Result<String> {
    let name = parent.file_name().and_then(|name| name.to_str()).filter(|name| {
        ordinary_file_name(name) && name.ends_with(".swvm")
    });
    if parent == child || parent.parent() != child.parent() {
        return Err(err("A linked disk must use a different template bundle in the same library."));
    }
    let name = name.ok_or_else(|| err("The QEMU template bundle name is invalid."))?;
    Ok(format!("../{name}/{DISK}"))
}

fn parent_disk(home: &Path, path: &Path, id: &str) -> Result<(Vm, Definition, Parent)> {
    let library = local(&home.join("library"), true)?;
    let folder = LocalFolder::open(path)?;
    if folder.path.parent() != Some(library.as_path()) {
        return Err(err("The QEMU template is outside this service library."));
    }
    let _idle = crate::runtime_lock(&folder.path)?;
    let vm: Vm = record(&folder.path.join("vm.json"))?;
    let def: Definition = record(&folder.path.join("qemu-vm.json"))?;
    let template = vm.template.as_ref().ok_or_else(|| err("The linked parent is no longer a template."))?;
    if vm.id != id || vm.state != VmState::Off || vm.linked_from.is_some() || vm.snaps != 0 ||
        template.disk != DISK || template.sha256.len() != 64 ||
        !template.sha256.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(err("The linked parent is not the registered standalone QEMU template."));
    }
    crate::validate(&vm, &def)?;
    crate::snapshot::require_empty(&folder.path)?;
    let disk = local(&folder.path.join(DISK), false)?;
    let handle = standalone_disk(&disk, def.bytes())?;
    if !handle.metadata().map_err(io_error)?.permissions().readonly() {
        return Err(err("Restore the linked template’s read-only protection before using it."));
    }
    Ok((vm, def, Parent { folder, disk, _handle: handle }))
}

fn matching_profile(parent: &Vm, parent_def: &Definition, child: &Vm, child_def: &Definition) -> Result<()> {
    if parent.architecture != child.architecture || parent.family != child.family ||
        parent_def.bytes() != child_def.bytes() || parent_def.legacy_windows != child_def.legacy_windows {
        return Err(err("The linked disk does not match its template’s QEMU profile."));
    }
    Ok(())
}

pub(crate) fn runtime_parent(home: &Path, bundle: &Path, vm: &Vm, def: &Definition) -> Result<Option<RuntimeBacking>> {
    let Some(id) = def.linked_from.as_deref() else { return Ok(None); };
    let library = Library::open_stable(home.join("library")).map_err(|error| err(error.to_string()))?;
    let path = library.bundle_path(id).map_err(|_| err("The registered QEMU template could not be found."))?;
    let (source, source_def, parent) = parent_disk(home, &path, id)?;
    matching_profile(&source, &source_def, vm, def)?;
    let link = relative_backing(&parent.folder.path, bundle)?;
    let child = hold_file(&bundle.join(DISK), !vm.throwaway)?;
    header(&child, def.bytes(), Some(&link))?;
    Ok(Some(RuntimeBacking { parent, _child: child }))
}

pub(crate) fn append_block_devices(
    args: &mut Vec<String>, bundle: &Path, backing: Option<&Path>, overlay: Option<&Path>,
) -> Result<()> {
    if let Some(path) = backing {
        let file = json!({"driver":"file","node-name":"template-file","filename":path,"read-only":true});
        let disk = json!({"driver":"qcow2","node-name":"template-disk","file":"template-file","backing":null,"read-only":true});
        args.extend(["-blockdev".into(),file.to_string(),"-blockdev".into(),disk.to_string()]);
    }
    let disk = local(&bundle.join(DISK), false)?;
    let base = if overlay.is_some() { "persistent-system" } else { "system" };
    let file = json!({"driver":"file","node-name":"disk-file","filename":disk,"read-only":overlay.is_some()});
    let disk = json!({"driver":"qcow2","node-name":base,"file":"disk-file","backing":backing.map(|_| "template-disk"),"read-only":overlay.is_some()});
    args.extend(["-blockdev".into(),file.to_string(),"-blockdev".into(),disk.to_string()]);
    if let Some(overlay) = overlay {
        let file = json!({"driver":"file","node-name":"throwaway-file","filename":overlay});
        let disk = json!({"driver":"qcow2","node-name":"system","file":"throwaway-file","backing":base});
        args.extend(["-blockdev".into(),file.to_string(),"-blockdev".into(),disk.to_string()]);
    }
    Ok(())
}

impl Qemu {
    pub fn template_disk(&self, id: &str) -> Result<PathBuf> {
        // The service holds guard_hardware_change while sealing or unsealing the disk.
        // Reacquiring that operation lock would block the same transaction.
        let (bundle, def) = self.definition(id)?;
        if self.status(id)? != VmState::Off { return Err(err("Power off the QEMU machine before using its template disk.")); }
        let _idle = crate::runtime_lock(bundle)?;
        let vm: Vm = record(&bundle.join("vm.json"))?;
        crate::validate(&vm, &def)?;
        if vm.linked_from.is_some() || vm.snaps != 0 {
            return Err(err("A QEMU template needs a standalone disk with no checkpoints."));
        }
        crate::snapshot::require_empty(bundle)?;
        let disk = local(&bundle.join(DISK), false)?;
        let details = self.available()?.disk_info(&disk, def.bytes())?;
        if details["snapshots"].as_array().is_some_and(|rows| !rows.is_empty()) {
            return Err(err("Remove the QEMU disk’s native checkpoints before making it a template."));
        }
        Ok(disk)
    }

    pub fn create_linked_clone(&mut self, source: &Vm, target: &Vm) -> Result<()> {
        let tools = self.available()?;
        let parent_bundle = self.bundle(&source.id)?;
        let bundle = self.bundle(&target.id)?;
        if source.id == target.id || self.status(&source.id)? != VmState::Off ||
            target.state != VmState::Off || target.linked_from.as_deref() != Some(source.id.as_str()) {
            return Err(err("Choose a different stopped QEMU template and its new linked machine."));
        }
        let _source_operation = crate::operation_lock(parent_bundle)?;
        let (parent_vm, parent_def, parent) = parent_disk(&self.home, parent_bundle, &source.id)?;
        if parent_vm.template != source.template {
            return Err(err("The QEMU template record changed before its linked disk could be prepared."));
        }
        let folder = LocalFolder::open(bundle)?;
        let bundle = &folder.path;
        let _target_operation = crate::operation_lock(bundle)?;
        let _target_idle = crate::runtime_lock(bundle)?;
        let stored: Vm = record(&bundle.join("vm.json"))?;
        let def = Definition {
            id: target.id.clone(), architecture: parent_def.architecture, iso: None, gib: 0,
            imported_bytes: Some(parent_def.bytes()), legacy_windows: parent_def.legacy_windows,
            linked_from: target.linked_from.clone(),
        };
        crate::validate(target, &def)?;
        crate::validate(&stored, &def)?;
        matching_profile(&parent_vm, &parent_def, &stored, &def)?;
        let link = relative_backing(&parent.folder.path, bundle)?;
        let registration = bundle.join("qemu-vm.json");
        let disk = bundle.join(DISK);
        let vars = bundle.join("uefi-vars.fd");
        if registration.try_exists().map_err(io_error)? || disk.try_exists().map_err(io_error)? ||
            vars.try_exists().map_err(io_error)? {
            return Err(err("The linked machine already has QEMU storage."));
        }

        let stage = bundle.join(format!(".qemu-staging-{}", crate::unique()));
        fs::create_dir(&stage).map_err(io_error)?;
        let staged_disk = stage.join(DISK);
        let staged_vars = stage.join("uefi-vars.fd");
        let mut disk_published = false;
        let mut vars_published = false;
        let result = (|| {
            let _image = tools.image.verified()?;
            let mut command = tools::command(&tools.image.path);
            // The recorded sibling path is relative to the published disk, not this staging folder.
            // In metadata-only mode qemu-img does not open that future path.
            command.args(["create","-u","-f","qcow2","-F","qcow2","-b",&link])
                .arg(&staged_disk).arg(def.bytes().to_string());
            tools::run(command, 25)?;
            header(&hold_file(&staged_disk, false)?, def.bytes(), Some(&link))?;
            if target.architecture == GuestArchitecture::Aarch64 {
                let size = tools.arm_tools()?.variables_size();
                let mut initial = hold_file(&parent.folder.path.join("uefi-vars.fd"), false)?;
                if initial.metadata().map_err(io_error)?.len() != size {
                    return Err(err("The QEMU template’s Arm UEFI variables are incomplete."));
                }
                let mut output = OpenOptions::new().create_new(true).write(true).open(&staged_vars).map_err(io_error)?;
                if std::io::copy(&mut initial, &mut output).map_err(io_error)? != size {
                    return Err(err("The QEMU template’s Arm UEFI variables could not be copied completely."));
                }
                output.sync_all().map_err(io_error)?;
                drop(output);
                fs::hard_link(&staged_vars, &vars).map_err(io_error)?;
                vars_published = true;
            }
            fs::hard_link(&staged_disk, &disk).map_err(io_error)?;
            disk_published = true;
            let published = hold_file(&disk, false)?;
            header(&published, def.bytes(), Some(&link))?;
            save(&registration, &def)
        })();
        if result.is_err() && disk_published { let _ = fs::remove_file(&disk); }
        if result.is_err() && vars_published { let _ = fs::remove_file(&vars); }
        let _ = fs::remove_file(staged_vars);
        let _ = fs::remove_file(staged_disk);
        let _ = fs::remove_dir(stage);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{header, relative_backing, BACKING_FORMAT_EXTENSION};
    use std::{io::Cursor, path::Path};

    const BYTES: u64 = 8 << 30;
    const EXPECTED: &str = "../original template.swvm/system.qcow2";

    fn image(version: u32, backing: Option<&str>) -> Vec<u8> {
        let fixed_size = if version == 3 { 104 } else { 72 };
        let mut data = vec![0; fixed_size];
        data[..4].copy_from_slice(b"QFI\xfb");
        data[4..8].copy_from_slice(&version.to_be_bytes());
        data[20..24].copy_from_slice(&16_u32.to_be_bytes());
        data[24..32].copy_from_slice(&BYTES.to_be_bytes());
        if version == 3 { data[100..104].copy_from_slice(&104_u32.to_be_bytes()); }
        if let Some(backing) = backing {
            data.extend_from_slice(&BACKING_FORMAT_EXTENSION.to_be_bytes());
            data.extend_from_slice(&5_u32.to_be_bytes());
            data.extend_from_slice(b"qcow2\0\0\0");
            if version == 3 { data.extend_from_slice(&[0; 8]); }
            let offset = data.len() as u64;
            data[8..16].copy_from_slice(&offset.to_be_bytes());
            data[16..20].copy_from_slice(&(backing.len() as u32).to_be_bytes());
            data.extend_from_slice(backing.as_bytes());
        }
        data
    }

    #[test]
    fn the_managed_chain_must_match_the_exact_relative_name_and_format() {
        assert!(header(Cursor::new(image(2, None)), BYTES, None).is_ok());
        assert!(header(Cursor::new(image(2, Some(EXPECTED))), BYTES, Some(EXPECTED)).is_ok());
        assert!(header(Cursor::new(image(3, None)), BYTES, None).is_ok());
        assert!(header(Cursor::new(image(3, Some(EXPECTED))), BYTES, Some(EXPECTED)).is_ok());
        assert!(header(Cursor::new(image(2, None)), BYTES, Some(EXPECTED)).is_err());
        assert!(header(Cursor::new(image(3, Some(EXPECTED))), BYTES, None).is_err());
        assert!(header(Cursor::new(image(3, Some("../another file.swvm/system.qcow2"))), BYTES, Some(EXPECTED)).is_err());
        assert!(header(Cursor::new(image(3, Some(EXPECTED))), BYTES - 512, Some(EXPECTED)).is_err());
        let mut external = image(3, Some(EXPECTED));
        external[79] = 4;
        assert!(header(Cursor::new(external), BYTES, Some(EXPECTED)).is_err());
        let mut format = image(3, Some(EXPECTED));
        format[112..117].copy_from_slice(b"vmdk!");
        assert!(header(Cursor::new(format), BYTES, Some(EXPECTED)).is_err());
    }

    #[test]
    fn stored_backing_is_a_different_sibling_bundle() {
        let library = Path::new("owned-library");
        let parent = library.join("original template.swvm");
        assert_eq!(relative_backing(&parent, &library.join("new.swvm")).unwrap(), EXPECTED);
        assert!(relative_backing(&parent, &parent).is_err());
        assert!(relative_backing(&parent, &library.join("other").join("new.swvm")).is_err());
    }
}
