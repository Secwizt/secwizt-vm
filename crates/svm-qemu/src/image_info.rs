//! Inspection of a disk image chosen for import. Our own byte checks run first, so QEMU never
//! opens a file that could pull in a backing file, a parent, an extra extent or a remote path.
//! Only then does the pinned `qemu-img info` confirm the format and report the virtual size.

use crate::{err, local, tools::{self, Binary}, Result};
use serde_json::Value;
use std::{fs::File, io::{Read, Seek, SeekFrom}, path::Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageInfo {
    pub format: String,
    pub bytes: u64,
    pub firmware: Option<String>,
}

/// Enough for the MBR, the GPT header and 128 GPT entries at their usual place (LBA 2).
const HEAD: u64 = 64 * 1024;
const SECTOR: u64 = 512;
const MAX_DESCRIPTOR: u64 = 64 * 1024;
const NO_PARENT_CID: u64 = 0xffff_ffff;
/// VHDX region table and its size limit for the metadata region we read.
const VHDX_REGION_TABLES: [u64; 2] = [0x30000, 0x40000];
const VHDX_REGION_SIZE: usize = 64 * 1024;
const VHDX_MAX_METADATA: u64 = 4 * 1024 * 1024;
/// GUIDs in their on-disk (mixed-endian) byte order.
const GUID_VHDX_METADATA_REGION: [u8; 16] = [0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E];
const GUID_VHDX_PARENT_LOCATOR: [u8; 16] = [0x2D, 0x5F, 0xD3, 0xA8, 0x0B, 0xB3, 0x4D, 0x45, 0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C];
const GUID_VHDX_FILE_PARAMETERS: [u8; 16] = [0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B];
const GUID_EFI_SYSTEM_PARTITION: [u8; 16] = [0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind { Qcow2, Vmdk, Vdi, Vpc, Vhdx, Raw }

impl Kind {
    fn driver(self) -> &'static str {
        match self { Kind::Qcow2 => "qcow2", Kind::Vmdk => "vmdk", Kind::Vdi => "vdi", Kind::Vpc => "vpc", Kind::Vhdx => "vhdx", Kind::Raw => "raw" }
    }
}

/// Check an already opened Hyper-V disk without starting a platform tool.
pub fn check_standalone_vhdx(file: &mut File) -> Result<()> {
    let mut signature = [0; 8];
    file.seek(SeekFrom::Start(0)).and_then(|_| file.read_exact(&mut signature)).map_err(tools::io_error)?;
    if &signature != b"vhdxfile" { return Err(err("Choose a standalone VHDX disk.")); }
    let len = file.metadata().map_err(tools::io_error)?.len();
    vhdx_headers_without_log(file)?;
    check_vhdx_regions(file, len)?;
    file.seek(SeekFrom::Start(0)).map_err(tools::io_error)?;
    Ok(())
}

/// A VHDX header that names a log GUID has log entries that Hyper-V replays when it opens the disk, so
/// the disk could change after it was checked. Such a disk is refused. Returns whether a header exists.
fn vhdx_headers_without_log(mut file: &File) -> Result<bool> {
    let mut found_header = false;
    for offset in [0x10000, 0x20000] {
        file.seek(SeekFrom::Start(offset)).map_err(tools::io_error)?;
        let mut header = [0u8; 64];
        file.read_exact(&mut header).map_err(tools::io_error)?;
        if &header[..4] == b"head" {
            if header[48..64].iter().any(|b| *b != 0) {
                return Err(err("The VHDX has an active log. Shut down the machine that used it cleanly first."));
            }
            found_header = true;
        }
    }
    Ok(found_header)
}

/// Check the exact standalone format before a restored disk can be registered with either engine.
pub fn backup_disk_size(mut file: &File, engine: svm_core::model::EngineKind) -> Result<u64> {
    use svm_core::model::EngineKind;
    file.seek(SeekFrom::Start(0)).map_err(tools::io_error)?;
    let mut header = [0u8; 32];
    file.read_exact(&mut header).map_err(tools::io_error)?;
    match engine {
        EngineKind::HyperV if &header[..8] == b"vhdxfile" => {
            let len = file.metadata().map_err(tools::io_error)?.len();
            if !vhdx_headers_without_log(file)? { return Err(err("The VHDX has no recognizable header.")); }
            check_vhdx_regions(&mut file,len)?;
            Ok(len)
        }
        EngineKind::Qemu => {
            let bytes = u64::from_be_bytes(header[24..32].try_into().expect("fixed-size qcow2 field"));
            if !(1..=1_u64<<46).contains(&bytes) { return Err(err("Invalid backup disk size.")); }
            crate::linked::header(file,bytes,None)?;
            Ok(bytes)
        }
        _ => Err(err("The backup needs a standalone disk matching its machine engine.")),
    }
}

/// Inspects a local disk image for import. Never writes to the source.
pub(crate) fn inspect(image: &Binary, source: &Path) -> Result<ImageInfo> {
    let path = local(source, false)?;
    let ext = extension(&path)?;
    let mut file = File::open(&path).map_err(tools::io_error)?;
    let len = file.metadata().map_err(tools::io_error)?.len();
    if len < 2 * SECTOR { return Err(err("The selected file is too small to be a disk image.")); }
    let mut head = vec![0_u8; usize::try_from(HEAD.min(len)).map_err(tools::io_error)?];
    file.read_exact(&mut head).map_err(tools::io_error)?;
    let mut tail = [0_u8; 512];
    file.seek(SeekFrom::End(-512)).map_err(tools::io_error)?;
    file.read_exact(&mut tail).map_err(tools::io_error)?;
    let kind = detect(&head, &tail, &ext)?;
    if kind == Kind::Vmdk {
        let (offset, size) = vmdk_descriptor_span(&head, len)?;
        let mut text = vec![0_u8; usize::try_from(size).map_err(tools::io_error)?];
        file.seek(SeekFrom::Start(offset)).map_err(tools::io_error)?;
        file.read_exact(&mut text).map_err(tools::io_error)?;
        let own_name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        check_vmdk_descriptor(&String::from_utf8_lossy(&text), own_name)?;
        // QEMU searches a fixed 20-sector window for descriptor keys, wherever the header says the
        // descriptor ends. Refuse any such key outside the text that was just checked.
        for start in [SECTOR, offset] {
            let end = (start + 20 * SECTOR).min(len);
            let mut window = vec![0_u8; usize::try_from(end - start).map_err(tools::io_error)?];
            file.seek(SeekFrom::Start(start)).map_err(tools::io_error)?;
            file.read_exact(&mut window).map_err(tools::io_error)?;
            let (from, to) = (offset.clamp(start, end) - start, (offset + size).clamp(start, end) - start);
            let (from, to) = (usize::try_from(from).map_err(tools::io_error)?, usize::try_from(to).map_err(tools::io_error)?);
            if vmdk_stray_keys(&window, from, to) {
                return Err(err("This VMDK carries disk settings outside its descriptor. Convert it to a new monolithic VMDK first."));
            }
        }
    }
    if kind == Kind::Vhdx {
        check_vhdx_regions(&mut file, len)?;
    }
    drop(file);
    let _tool = image.verified()?;
    let mut c = tools::command(&image.path);
    c.args(["info", "--output=json", "-U", "-f", kind.driver()]).arg(&path);
    let info: Value = serde_json::from_str(&tools::run(c, 20)?).map_err(|_| err("qemu-img returned an unreadable description of the image."))?;
    let bytes = check_info(&info, kind)?;
    let firmware = if kind == Kind::Raw { firmware_hint(&head).map(str::to_owned) } else { None };
    Ok(ImageInfo { format: kind.driver().to_owned(), bytes, firmware })
}

fn extension(path: &Path) -> Result<String> {
    let ext = path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).unwrap_or_default();
    if ["vmdk", "vdi", "vhd", "vhdx", "qcow2", "img"].contains(&ext.as_str()) { Ok(ext) }
    else { Err(err("Choose a .vmdk, .vdi, .vhd, .vhdx, .qcow2 or raw .img disk image.")) }
}

fn be32(b: &[u8], at: usize) -> u32 { u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) }
fn be64(b: &[u8], at: usize) -> u64 { u64::from_be_bytes(b[at..at + 8].try_into().unwrap_or([0; 8])) }
fn le16(b: &[u8], at: usize) -> u16 { u16::from_le_bytes([b[at], b[at + 1]]) }
fn le32(b: &[u8], at: usize) -> u32 { u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) }
fn le64(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8])) }

/// Decides the format from the file's own bytes. The extension only allows raw for `.img`.
fn detect(head: &[u8], tail: &[u8; 512], ext: &str) -> Result<Kind> {
    if head.len() < 1024 { return Err(err("The selected file is too small to be a disk image.")); }
    if head.starts_with(b"QFI\xfb") {
        if !matches!(be32(head, 4), 2 | 3) { return Err(err("Only qcow2 version 2 or 3 images can be imported.")); }
        if be64(head, 8) != 0 { return Err(err("This qcow2 image depends on a backing file. Import a standalone image.")); }
        if be32(head, 32) != 0 { return Err(err("Encrypted qcow2 images cannot be imported.")); }
        // Version 3 incompatible feature bit 2: the guest data lives in an external file.
        if be32(head, 4) == 3 && be64(head, 72) & 0b100 != 0 {
            return Err(err("This qcow2 image keeps its data in an external file. Import a standalone image."));
        }
        return Ok(Kind::Qcow2);
    }
    if head.starts_with(b"KDMV") { return Ok(Kind::Vmdk); }
    if head.starts_with(b"COWD") { return Err(err("ESX COWD virtual disks are not supported. Export a monolithic VMDK instead.")); }
    if String::from_utf8_lossy(&head[..512]).contains("Disk DescriptorFile") {
        return Err(err("This VMDK is a descriptor for other files. Convert it to a single monolithic VMDK first."));
    }
    if head[0x40..0x44] == [0x7f, 0x10, 0xda, 0xbe] {
        // Image type: 1 normal, 2 fixed; 3 undo and 4 differencing need a parent image.
        return match le32(head, 0x4c) {
            1 | 2 => Ok(Kind::Vdi),
            3 | 4 => Err(err("This VDI depends on a parent image. Import a standalone VDI.")),
            _ => Err(err("This VDI has an unsupported image type.")),
        };
    }
    if head.starts_with(b"vhdxfile") { return Ok(Kind::Vhdx); }
    if tail.starts_with(b"conectix") {
        return match be32(tail, 60) {
            2 | 3 => Ok(Kind::Vpc),
            4 => Err(err("This VHD is a differencing disk that depends on a parent. Import a standalone VHD.")),
            _ => Err(err("This VHD has an unsupported disk type.")),
        };
    }
    if ext == "img" { Ok(Kind::Raw) } else { Err(err("The file's contents do not match a supported disk image format.")) }
}

/// Byte range of the descriptor embedded in a sparse VMDK header (offset, size in bytes).
fn vmdk_descriptor_span(head: &[u8], len: u64) -> Result<(u64, u64)> {
    // With a zero capacity QEMU reads the embedded text as a descriptor file and opens every extent
    // it names, including absolute and network paths. A real sparse disk always states its capacity.
    if le64(head, 12) == 0 {
        return Err(err("This VMDK header has no capacity, so it is not a self-contained disk. Import a monolithic sparse VMDK."));
    }
    let (offset, size) = (le64(head, 28), le64(head, 36));
    if offset == 0 || size == 0 {
        return Err(err("This file is one part of a split VMDK. Convert the disk to a single monolithic VMDK first."));
    }
    let (start, bytes) = (offset.checked_mul(SECTOR), size.checked_mul(SECTOR));
    match (start, bytes) {
        (Some(start), Some(bytes)) if bytes <= MAX_DESCRIPTOR && start.checked_add(bytes).is_some_and(|end| end <= len) => Ok((start, bytes)),
        _ => Err(err("The VMDK header points outside the file.")),
    }
}

/// True if a descriptor key QEMU acts on appears anywhere in `window` other than wholly inside the
/// checked descriptor at `from..to`. QEMU reads the window as one buffer, so a key that starts before
/// the descriptor or runs past its end counts as outside.
fn vmdk_stray_keys(window: &[u8], from: usize, to: usize) -> bool {
    let lower = window.to_ascii_lowercase();
    [&b"parentcid"[..], b"parentfilenamehint", b"createtype"].iter().any(|key| {
        lower.windows(key.len()).enumerate()
            .any(|(at, part)| part == *key && !(at >= from && at + key.len() <= to))
    })
}

/// A plain file name: no directory, drive, scheme, traversal, stream or control character.
fn plain_basename(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && name != "." && name != ".."
        && !name.chars().any(|c| matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control())
}

/// One self-contained sparse extent that names this very file, an explicit "no parent"
/// marker, and a single-file create type. `own_name` is the source file's name on disk.
fn check_vmdk_descriptor(text: &str, own_name: &str) -> Result<()> {
    let text = text.trim_end_matches('\0');
    // QEMU stops at the first NUL, searches the whole text for the first `createType` and for
    // `parentFileNameHint`, and splits extent fields on any whitespace. Anything this check and QEMU
    // could read differently is refused, so the two can never disagree about what gets opened.
    if text.contains('\0') { return Err(err("This VMDK descriptor contains unexpected binary data.")); }
    let whole = text.to_ascii_lowercase();
    if whole.matches("createtype").count() != 1 {
        return Err(err("This VMDK must state its type exactly once. Import a monolithic sparse VMDK."));
    }
    if whole.contains("parentfilenamehint") {
        return Err(err("This VMDK depends on a parent disk. Import a standalone VMDK."));
    }
    // QEMU also takes the first `parentCID` it finds anywhere, including inside a comment.
    if whole.matches("parentcid").count() > 1 {
        return Err(err("This VMDK states its parent more than once. Import a standalone VMDK."));
    }
    let mut extents = 0;
    let mut create_ok = false;
    let mut no_parent = false;
    for line in text.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        let first = lower.split_whitespace().next().unwrap_or_default();
        if let Some(value) = lower.strip_prefix("createtype=") {
            create_ok = matches!(value.trim_matches('"'), "monolithicsparse" | "streamoptimized");
        } else if let Some(value) = lower.strip_prefix("parentcid=") {
            if u64::from_str_radix(value.trim(), 16).ok() != Some(NO_PARENT_CID) { return Err(err("This VMDK depends on a parent disk. Import a standalone VMDK.")); }
            no_parent = true;
        } else if lower.starts_with("parentfilenamehint") {
            return Err(err("This VMDK depends on a parent disk. Import a standalone VMDK."));
        } else if matches!(first, "rw" | "rdonly" | "noaccess") {
            extents += 1;
            if lower.split_whitespace().nth(2) != Some("sparse") { return Err(err("This VMDK keeps its data in other files. Convert it to a single monolithic VMDK first.")); }
            // The quoted name comes from the original line (case kept), between the first and last quote.
            let (Some(open), Some(close)) = (line.find('"'), line.rfind('"')) else {
                return Err(err("This VMDK names its data file in an unreadable way."));
            };
            let named = if close > open { &line[open + 1..close] } else { "" };
            if !plain_basename(named) {
                return Err(err("This VMDK points to a data file in another place. Import only a self-contained VMDK."));
            }
            if !named.eq_ignore_ascii_case(own_name) {
                return Err(err(format!("This VMDK names its data file \"{named}\", not itself. Rename the file back to that name, or convert it to a new monolithic VMDK first.")));
            }
        }
    }
    if !create_ok { return Err(err("Only monolithic sparse or stream-optimized VMDK files can be imported.")); }
    if !no_parent { return Err(err("This VMDK does not state that it has no parent disk. Import a standalone VMDK.")); }
    if extents != 1 { return Err(err("This VMDK has more than one data extent. Convert it to a single monolithic VMDK first.")); }
    Ok(())
}

/// Check every table QEMU could recognize before giving it the file.
fn check_vhdx_regions(file: &mut (impl Read + Seek), len: u64) -> Result<()> {
    let mut region = vec![0_u8; VHDX_REGION_SIZE];
    if len < VHDX_REGION_TABLES[1] + VHDX_REGION_SIZE as u64 {
        return Err(err("This VHDX file is incomplete."));
    }
    let mut checked = false;
    for table_offset in VHDX_REGION_TABLES {
        file.seek(SeekFrom::Start(table_offset)).map_err(tools::io_error)?;
        file.read_exact(&mut region).map_err(tools::io_error)?;
        if !region.starts_with(b"regi") {
            continue;
        }
        let (offset, size) = vhdx_metadata_span(&region, len)?;
        let mut meta = vec![0_u8; usize::try_from(size).map_err(tools::io_error)?];
        file.seek(SeekFrom::Start(offset)).map_err(tools::io_error)?;
        file.read_exact(&mut meta).map_err(tools::io_error)?;
        check_vhdx_metadata(&meta)?;
        checked = true;
    }
    if checked { Ok(()) } else { Err(err("This VHDX file has no valid region table.")) }
}

/// Finds the metadata region in a VHDX region table (offset, length in bytes).
fn vhdx_metadata_span(region: &[u8], len: u64) -> Result<(u64, u64)> {
    if region.len() < 16 || &region[..4] != b"regi" { return Err(err("This VHDX file has no valid region table.")); }
    let count = usize::try_from(le32(region, 8)).unwrap_or(usize::MAX);
    if count == 0 || count > (region.len() - 16) / 32 { return Err(err("This VHDX region table is invalid.")); }
    let mut found = None;
    for i in 0..count {
        let e = &region[16 + 32 * i..16 + 32 * (i + 1)];
        if e[..16] == GUID_VHDX_METADATA_REGION {
            if found.is_some() { return Err(err("This VHDX region table is invalid.")); }
            found = Some((le64(e, 16), u64::from(le32(e, 24))));
        }
    }
    match found {
        Some((offset, size)) if size >= 32 && size <= VHDX_MAX_METADATA && offset.checked_add(size).is_some_and(|end| end <= len) => Ok((offset, size)),
        _ => Err(err("This VHDX metadata region is missing or outside the file.")),
    }
}

/// A VHDX with a parent locator, or with the HasParent flag, depends on another file.
fn check_vhdx_metadata(meta: &[u8]) -> Result<()> {
    if meta.len() < 32 || &meta[..8] != b"metadata" { return Err(err("This VHDX metadata table is invalid.")); }
    let count = usize::from(le16(meta, 10));
    if 32 + count.saturating_mul(32) > meta.len() { return Err(err("This VHDX metadata table is invalid.")); }
    let mut parameters = false;
    for i in 0..count {
        let e = &meta[32 + 32 * i..32 + 32 * (i + 1)];
        if e[..16] == GUID_VHDX_PARENT_LOCATOR {
            return Err(err("This VHDX is a differencing disk that depends on a parent. Import a standalone VHDX."));
        }
        if e[..16] == GUID_VHDX_FILE_PARAMETERS {
            let at = usize::try_from(le32(e, 16)).unwrap_or(usize::MAX);
            if at.checked_add(8).is_none_or(|end| end > meta.len()) { return Err(err("This VHDX metadata table is invalid.")); }
            if le32(meta, at + 4) & 0b10 != 0 {
                return Err(err("This VHDX is a differencing disk that depends on a parent. Import a standalone VHDX."));
            }
            parameters = true;
        }
    }
    if parameters { Ok(()) } else { Err(err("This VHDX metadata has no file parameters.")) }
}

fn absent(v: &Value) -> bool { v.is_null() }

/// The pinned qemu-img description must agree with our own byte check.
fn check_info(info: &Value, kind: Kind) -> Result<u64> {
    if info["format"] != kind.driver() { return Err(err("qemu-img read a different format than the file's header shows.")); }
    if !absent(&info["backing-filename"]) || !absent(&info["full-backing-filename"]) || !absent(&info["backing-filename-format"]) {
        return Err(err("This image depends on a backing file. Import a standalone image."));
    }
    if info["encrypted"] == true { return Err(err("Encrypted images cannot be imported.")); }
    let data = &info["format-specific"]["data"];
    if !absent(&data["data-file"]) { return Err(err("This image keeps its data in an external file. Import a standalone image.")); }
    if kind == Kind::Vmdk {
        if data["extents"].as_array().map_or(0, Vec::len) != 1 { return Err(err("This VMDK has more than one data extent.")); }
        // QEMU 11.1 reports the type as a string and, for these two single-file types, an empty
        // extent format. Anything missing, of another type or of another format is refused.
        if !matches!(data["create-type"].as_str(), Some("monolithicSparse" | "streamOptimized")) {
            return Err(err("Only monolithic sparse or stream-optimized VMDK files can be imported."));
        }
        if !data["extents"][0]["format"].as_str().is_some_and(|format| format.is_empty() || format.eq_ignore_ascii_case("SPARSE")) {
            return Err(err("This VMDK keeps its data in other files. Convert it to a single monolithic VMDK first."));
        }
        if data["parent-cid"].as_u64() != Some(NO_PARENT_CID) {
            return Err(err("This VMDK depends on a parent disk. Import a standalone VMDK."));
        }
        if let Some(parent) = data["parent-cid"].as_u64() {
            if parent != NO_PARENT_CID { return Err(err("This VMDK depends on a parent disk. Import a standalone VMDK.")); }
        }
    }
    info["virtual-size"].as_u64().filter(|b| *b > 0).ok_or_else(|| err("qemu-img did not report the disk's size."))
}

/// A confident hint for raw images only, from what the disk can actually boot:
/// an EFI System Partition (GPT type GUID, or MBR type 0xEF) means UEFI; an MBR with
/// boot code and an active legacy partition, and no EFI System Partition, means BIOS.
/// Anything else is left unknown, so the wizard asks.
/// Shared with the conversion module, which feeds it the first 64 KiB of a container disk's
/// guest data (read with `qemu-img dd` from the already verified format).
pub(crate) fn firmware_hint(disk: &[u8]) -> Option<&'static str> {
    if disk.len() < 1024 || disk[510..512] != [0x55, 0xaa] { return None; }
    let entry = |i: usize| &disk[446 + 16 * i..446 + 16 * (i + 1)];
    if (0..4).any(|i| entry(i)[4] == 0xef) { return Some("uefi"); }
    if &disk[512..520] == b"EFI PART" {
        let (lba, count, size) = (le64(disk, 512 + 72), le32(disk, 512 + 80), le32(disk, 512 + 84));
        let size = usize::try_from(size).unwrap_or(0);
        let start = lba.checked_mul(SECTOR).and_then(|v| usize::try_from(v).ok());
        let (Some(start), true) = (start, size >= 128) else { return None };
        // Every offset below comes from the disk: checked arithmetic, and a table that leaves
        // the bytes we read ends the search as unknown.
        for i in 0..usize::try_from(count.min(128)).unwrap_or(0) {
            let Some(at) = i.checked_mul(size).and_then(|o| start.checked_add(o)) else { return None };
            let Some(end) = at.checked_add(16) else { return None };
            let Some(guid) = disk.get(at..end) else { return None };
            if guid == GUID_EFI_SYSTEM_PARTITION { return Some("uefi"); }
        }
        return None;
    }
    let boot_code = disk[..440].iter().any(|b| *b != 0);
    let active_legacy = (0..4).any(|i| entry(i)[0] == 0x80 && !matches!(entry(i)[4], 0 | 0xee | 0xef));
    (boot_code && active_legacy).then_some("bios")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn head() -> Vec<u8> { vec![0_u8; 4096] }
    fn no_tail() -> [u8; 512] { [0_u8; 512] }

    fn qcow2(version: u32, backing: u64, crypt: u32) -> Vec<u8> {
        let mut h = head();
        h[..4].copy_from_slice(b"QFI\xfb");
        h[4..8].copy_from_slice(&version.to_be_bytes());
        h[8..16].copy_from_slice(&backing.to_be_bytes());
        h[32..36].copy_from_slice(&crypt.to_be_bytes());
        h
    }
    fn vhd_tail(kind: u32) -> [u8; 512] {
        let mut t = no_tail();
        t[..8].copy_from_slice(b"conectix");
        t[60..64].copy_from_slice(&kind.to_be_bytes());
        t
    }
    fn reason(r: Result<impl std::fmt::Debug>) -> String { r.err().map(|e| e.to_string()).unwrap_or_default() }

    #[test]
    fn detects_supported_formats_by_content_not_extension() {
        assert_eq!(detect(&qcow2(3, 0, 0), &no_tail(), "vmdk").ok(), Some(Kind::Qcow2));
        let mut v = head(); v[..4].copy_from_slice(b"KDMV");
        assert_eq!(detect(&v, &no_tail(), "vmdk").ok(), Some(Kind::Vmdk));
        let mut d = head(); d[0x40..0x44].copy_from_slice(&[0x7f, 0x10, 0xda, 0xbe]); d[0x4c] = 1;
        assert_eq!(detect(&d, &no_tail(), "vdi").ok(), Some(Kind::Vdi));
        let mut x = head(); x[..8].copy_from_slice(b"vhdxfile");
        assert_eq!(detect(&x, &no_tail(), "vhdx").ok(), Some(Kind::Vhdx));
        assert_eq!(detect(&head(), &vhd_tail(3), "vhd").ok(), Some(Kind::Vpc));
        assert_eq!(detect(&head(), &vhd_tail(2), "vhd").ok(), Some(Kind::Vpc));
        assert_eq!(detect(&head(), &no_tail(), "img").ok(), Some(Kind::Raw));
    }

    #[test]
    fn refuses_linked_encrypted_and_unknown_images_before_qemu() {
        assert!(reason(detect(&qcow2(3, 0x200, 0), &no_tail(), "qcow2")).contains("backing file"));
        assert!(reason(detect(&qcow2(3, 0, 1), &no_tail(), "qcow2")).contains("Encrypted"));
        assert!(reason(detect(&qcow2(1, 0, 0), &no_tail(), "qcow2")).contains("version"));
        assert!(reason(detect(&head(), &vhd_tail(4), "vhd")).contains("differencing"));
        let mut text = head(); text[..21].copy_from_slice(b"# Disk DescriptorFile");
        assert!(reason(detect(&text, &no_tail(), "vmdk")).contains("descriptor"));
        let mut cowd = head(); cowd[..4].copy_from_slice(b"COWD");
        assert!(detect(&cowd, &no_tail(), "vmdk").is_err());
        assert!(reason(detect(&head(), &no_tail(), "vmdk")).contains("do not match"), "raw is only for .img");
        assert!(detect(&head()[..600], &no_tail(), "img").is_err());
        assert!(extension(Path::new(r"C:\x\disk.iso")).is_err());
        assert_eq!(extension(Path::new(r"C:\x\Disk.VMDK")).ok().as_deref(), Some("vmdk"));
    }

    #[test]
    fn vmdk_must_be_one_self_contained_sparse_extent() {
        let good = "# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\ncreateType=\"monolithicSparse\"\n\nRW 41943040 SPARSE \"disk.vmdk\"\n\0\0";
        let check = |text: &str| check_vmdk_descriptor(text, "disk.vmdk");
        assert!(check(good).is_ok());
        assert!(check_vmdk_descriptor(good, "DISK.VMDK").is_ok(), "Windows names are case-insensitive");
        assert!(check(&good.replace("monolithicSparse", "streamOptimized")).is_ok());
        assert!(check(&good.replace("monolithicSparse", "twoGbMaxExtentSparse")).is_err());
        assert!(check(&good.replace("parentCID=ffffffff", "parentCID=0badc0de")).is_err());
        assert!(reason(check(&good.replace("parentCID=ffffffff\n", ""))).contains("does not state"), "explicit no-parent marker required");
        assert!(reason(check(&good.replace("version=1", "version=1\nparentFileNameHint=\"base.vmdk\""))).contains("parent disk"));
        assert!(check(&good.replace("SPARSE", "FLAT")).is_err());
        // QEMU splits extent fields on any whitespace, so a tab-separated flat extent is still an extent.
        let body = good.trim_end_matches('\0');
        let host_file = "RW\t2048\tFLAT\t\"C:\\Users\\Example\\.ssh\\id_ed25519\"\t0";
        assert!(reason(check(&format!("{body}\n{host_file}\n\0"))).contains("other files"), "a tab-separated extent naming a host file");
        assert!(reason(check(&format!("{body}\n# parentCID=0badc0de\n\0"))).contains("more than once"));
        assert!(check(&good.replace("RW 41943040 SPARSE \"disk.vmdk\"", "RW\t41943040\tSPARSE\t\"disk.vmdk\"")).is_ok(), "tabs alone are fine");
        assert!(reason(check(&format!("{body}\nRW\n2048\nFLAT\n\"C:\\secret\"\n\0"))).contains("other files"), "an extent spread over several lines");
        let window = b"..parentCID=ffffffff..createType=x..";
        let (first, last) = (2, window.len() - 2);
        assert!(!vmdk_stray_keys(window, first, last), "keys wholly inside the checked descriptor are fine");
        assert!(vmdk_stray_keys(window, 3, last), "a key that starts before the descriptor");
        assert!(vmdk_stray_keys(window, first, last - 6), "a key that runs past the descriptor's end");
        assert!(vmdk_stray_keys(b"..ParentCID=0badc0de", 0, 0) && !vmdk_stray_keys(b"..plain grain data", 0, 0));
        // QEMU uses the first createType it finds anywhere, so a second one (even in a comment) is refused.
        assert!(check(&good.replace("createType=\"monolithicSparse\"", "createType=\"monolithicFlat\"\ncreateType=\"monolithicSparse\"")).is_err());
        assert!(check(&good.replace("# Disk DescriptorFile", "# createType=\"monolithicFlat\"")).is_err());
        assert!(check(&good.replace("version=1", "# parentFileNameHint=\"base.vmdk\"")).is_err());
        assert!(check(&good.replace("version=1", "version=1\0junk")).is_err(), "QEMU stops reading at a NUL");
        assert!(check(&good.replace("RW 41943040 SPARSE \"disk.vmdk\"", "RW 1 SPARSE \"disk.vmdk\"\nRW 1 SPARSE \"disk.vmdk\"")).is_err());
        for bad in [r"..\disk.vmdk", r"C:\disk.vmdk", "sub/disk.vmdk", r"\\server\share\disk.vmdk", "disk.vmdk:stream",
                    "file://disk.vmdk", "..", "", "dis\u{1}k.vmdk"] {
            let line = good.replace("\"disk.vmdk\"", &format!("\"{bad}\""));
            assert!(reason(check(&line)).contains("another place"), "extent name {bad:?} must be refused");
        }
        assert!(reason(check(&good.replace("\"disk.vmdk\"", "\"other.vmdk\""))).contains("not itself"));
        assert!(check(&good.replace("\"disk.vmdk\"", "disk.vmdk")).is_err(), "unquoted name");
        let mut h = head();
        h[12..20].copy_from_slice(&2048_u64.to_le_bytes());
        assert!(reason(vmdk_descriptor_span(&h, 1 << 20)).contains("split"));
        let mut empty = h.clone();
        empty[12..20].copy_from_slice(&0_u64.to_le_bytes());
        empty[28..36].copy_from_slice(&1_u64.to_le_bytes());
        empty[36..44].copy_from_slice(&1_u64.to_le_bytes());
        assert!(reason(vmdk_descriptor_span(&empty, 1 << 20)).contains("no capacity"), "a zero capacity selects QEMU's descriptor-file mode");
        h[28..36].copy_from_slice(&1_u64.to_le_bytes()); h[36..44].copy_from_slice(&20_u64.to_le_bytes());
        assert_eq!(vmdk_descriptor_span(&h, 1 << 20).ok(), Some((512, 10240)));
        assert!(vmdk_descriptor_span(&h, 4096).is_err(), "descriptor beyond the end of the file");
        h[36..44].copy_from_slice(&1000_u64.to_le_bytes());
        assert!(vmdk_descriptor_span(&h, 1 << 30).is_err(), "descriptor larger than 64 KiB");
    }

    #[test]
    fn qemu_description_must_agree() {
        let ok = json!({"format":"qcow2","virtual-size":8589934592_u64,"format-specific":{"type":"qcow2","data":{"compat":"1.1"}}});
        assert_eq!(check_info(&ok, Kind::Qcow2).ok(), Some(8 << 30));
        assert!(check_info(&ok, Kind::Vdi).is_err());
        let mut b = ok.clone(); b["backing-filename"] = json!("base.qcow2");
        assert!(check_info(&b, Kind::Qcow2).is_err());
        let mut e = ok.clone(); e["encrypted"] = json!(true);
        assert!(check_info(&e, Kind::Qcow2).is_err());
        let mut f = ok.clone(); f["format-specific"]["data"]["data-file"] = json!("D:\\data.raw");
        assert!(check_info(&f, Kind::Qcow2).is_err());
        let mut z = ok.clone(); z["virtual-size"] = json!(0);
        assert!(check_info(&z, Kind::Qcow2).is_err());
        // Shape taken from the pinned qemu-img 11.1.0 for a file it created itself.
        let vmdk = json!({"format":"vmdk","virtual-size":8388608,"format-specific":{"type":"vmdk","data":{"cid":2678953834_u64,"parent-cid":4294967295_u64,
            "create-type":"monolithicSparse","extents":[{"virtual-size":8388608,"filename":"C:\\a.vmdk","cluster-size":65536,"format":""}]}}});
        let mut stream = vmdk.clone(); stream["format-specific"]["data"]["create-type"] = json!("streamOptimized");
        assert!(check_info(&stream, Kind::Vmdk).is_ok());
        for (field, value) in [("create-type", json!("monolithicFlat")), ("create-type", Value::Null), ("parent-cid", Value::Null)] {
            let mut bad = vmdk.clone(); bad["format-specific"]["data"][field] = value;
            assert!(check_info(&bad, Kind::Vmdk).is_err(), "{field} must be present and single-file sparse");
        }
        for format in [json!("FLAT"), json!("VMFS"), Value::Null, json!(1)] {
            let mut bad = vmdk.clone(); bad["format-specific"]["data"]["extents"][0]["format"] = format;
            assert!(check_info(&bad, Kind::Vmdk).is_err(), "only an empty or SPARSE extent format is a single-file disk");
        }
        assert!(check_info(&vmdk, Kind::Vmdk).is_ok());
        let mut two = vmdk.clone(); two["format-specific"]["data"]["extents"] = json!([{}, {}]);
        assert!(check_info(&two, Kind::Vmdk).is_err());
        let mut parent = vmdk.clone(); parent["format-specific"]["data"]["parent-cid"] = json!(7);
        assert!(check_info(&parent, Kind::Vmdk).is_err());
    }

    fn gpt(entries: &[[u8; 16]]) -> Vec<u8> {
        let mut d = vec![0_u8; 64 * 1024];
        d[510] = 0x55; d[511] = 0xaa; d[446 + 4] = 0xee; // protective MBR
        d[512..520].copy_from_slice(b"EFI PART");
        d[512 + 72..512 + 80].copy_from_slice(&2_u64.to_le_bytes());
        d[512 + 80..512 + 84].copy_from_slice(&128_u32.to_le_bytes());
        d[512 + 84..512 + 88].copy_from_slice(&128_u32.to_le_bytes());
        for (i, g) in entries.iter().enumerate() { d[1024 + 128 * i..1024 + 128 * i + 16].copy_from_slice(g); }
        d
    }

    #[test]
    fn firmware_hint_needs_a_real_boot_signal() {
        const LINUX_DATA: [u8; 16] = [0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4];
        assert_eq!(firmware_hint(&gpt(&[LINUX_DATA, GUID_EFI_SYSTEM_PARTITION])), Some("uefi"));
        assert_eq!(firmware_hint(&gpt(&[LINUX_DATA])), None, "GPT without an ESP may boot BIOS: unknown");
        for (lba, entry_size) in [(u64::MAX, 128_u32), (u64::MAX / 512, 128), (2, u32::MAX), (1 << 40, 128), (127, 128)] {
            let mut bad = gpt(&[]);
            bad[512 + 72..512 + 80].copy_from_slice(&lba.to_le_bytes());
            bad[512 + 84..512 + 88].copy_from_slice(&entry_size.to_le_bytes());
            assert_eq!(firmware_hint(&bad), None, "malformed table lba {lba} entry size {entry_size}");
        }
        let mut mbr = head(); mbr[510] = 0x55; mbr[511] = 0xaa; mbr[0] = 0xeb; mbr[446] = 0x80; mbr[446 + 4] = 0x83;
        assert_eq!(firmware_hint(&mbr), Some("bios"));
        let mut mbr_esp = mbr.clone(); mbr_esp[462 + 4] = 0xef;
        assert_eq!(firmware_hint(&mbr_esp), Some("uefi"), "an MBR EFI partition means UEFI");
        let mut no_code = mbr.clone(); no_code[0] = 0;
        assert_eq!(firmware_hint(&no_code), None, "no boot code");
        let mut not_active = mbr.clone(); not_active[446] = 0;
        assert_eq!(firmware_hint(&not_active), None, "no active partition");
        assert_eq!(firmware_hint(&head()), None);
    }

    #[test]
    fn vdi_and_qcow2_references_are_refused_from_the_header() {
        let mut d = head(); d[0x40..0x44].copy_from_slice(&[0x7f, 0x10, 0xda, 0xbe]);
        for (kind, ok) in [(1_u32, true), (2, true), (3, false), (4, false), (9, false)] {
            d[0x4c..0x50].copy_from_slice(&kind.to_le_bytes());
            assert_eq!(detect(&d, &no_tail(), "vdi").is_ok(), ok, "VDI type {kind}");
        }
        let mut q = qcow2(3, 0, 0); q[72..80].copy_from_slice(&4_u64.to_be_bytes());
        assert!(reason(detect(&q, &no_tail(), "qcow2")).contains("external file"));
    }

    fn vhdx_region(offset: u64, len: u32) -> Vec<u8> {
        let mut r = vec![0_u8; 4096];
        r[..4].copy_from_slice(b"regi");
        r[8..12].copy_from_slice(&1_u32.to_le_bytes());
        r[16..32].copy_from_slice(&GUID_VHDX_METADATA_REGION);
        r[32..40].copy_from_slice(&offset.to_le_bytes());
        r[40..44].copy_from_slice(&len.to_le_bytes());
        r
    }
    fn vhdx_meta(flags: u32, parent_locator: bool) -> Vec<u8> {
        let mut m = vec![0_u8; 65536];
        m[..8].copy_from_slice(b"metadata");
        let n: u16 = if parent_locator { 2 } else { 1 };
        m[10..12].copy_from_slice(&n.to_le_bytes());
        m[32..48].copy_from_slice(&GUID_VHDX_FILE_PARAMETERS);
        m[48..52].copy_from_slice(&65536_u32.saturating_sub(16).to_le_bytes());
        m[65536 - 16 + 4..65536 - 16 + 8].copy_from_slice(&flags.to_le_bytes());
        if parent_locator { m[64..80].copy_from_slice(&GUID_VHDX_PARENT_LOCATOR); }
        m
    }

    #[test]
    fn checks_parent_metadata_referenced_by_either_region_table() {
        use std::io::Cursor;
        const METADATA_OFFSETS: [usize; 2] = [0x100000, 0x200000];
        let mut disk = vec![0; 0x300000];
        for (table, metadata) in VHDX_REGION_TABLES.into_iter().zip(METADATA_OFFSETS) {
            let data = vhdx_meta(0, false);
            let region = vhdx_region(metadata as u64, data.len() as u32);
            disk[table as usize..table as usize + region.len()].copy_from_slice(&region);
            disk[metadata..metadata + data.len()].copy_from_slice(&data);
        }
        let len = disk.len() as u64;
        assert!(check_vhdx_regions(&mut Cursor::new(&disk), len).is_ok());
        for metadata in METADATA_OFFSETS {
            for (flags, locator) in [(0b10, false), (0, true)] {
                let data = vhdx_meta(flags, locator);
                disk[metadata..metadata + data.len()].copy_from_slice(&data);
                assert!(reason(check_vhdx_regions(&mut Cursor::new(&disk), len)).contains("parent"));
            }
            let valid = vhdx_meta(0, false);
            disk[metadata..metadata + valid.len()].copy_from_slice(&valid);
        }
    }

    #[test]
    fn vhdx_parents_are_refused_from_metadata() {
        assert_eq!(vhdx_metadata_span(&vhdx_region(0x200000, 0x100000), 0x400000).ok(), Some((0x200000, 0x100000)));
        assert!(vhdx_metadata_span(&vhdx_region(0x200000, 0x100000), 0x250000).is_err(), "outside the file");
        assert!(vhdx_metadata_span(&vhdx_region(0x200000, 0x1000000), 1 << 30).is_err(), "too large");
        assert!(vhdx_metadata_span(&[0_u8; 4096], 1 << 30).is_err(), "no signature");
        assert!(check_vhdx_metadata(&vhdx_meta(0, false)).is_ok());
        assert!(check_vhdx_metadata(&vhdx_meta(0b01, false)).is_ok(), "LeaveBlocksAllocated is fine");
        assert!(reason(check_vhdx_metadata(&vhdx_meta(0b10, false))).contains("parent"), "HasParent");
        assert!(reason(check_vhdx_metadata(&vhdx_meta(0, true))).contains("parent"), "parent locator");
        let mut none = vhdx_meta(0, false); none[32..48].fill(0);
        assert!(check_vhdx_metadata(&none).is_err(), "file parameters required");
    }
}
