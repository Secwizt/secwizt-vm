//! Unpack the one disk inside a publisher's 7z archive into the service's private staging folder.
//! The archive's own bytes were verified against the catalog before this code reads them.

use super::catalog::ArchiveMember;
use sevenz_rust2::{Archive, ArchiveReader, Password};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::atomic::{AtomicU8, Ordering},
};

/// The largest decoder memory accepted for one archive (Kali uses a 256 MiB dictionary).
const MEMORY_LIMIT_KB: usize = 320 * 1024;
const BLOCK: usize = 1 << 20;
pub(super) const CANCELLED: &str = "Preparing the image was cancelled.";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const UNIX_EXTENSION: u32 = 0x8000;
const UNIX_TYPE_MASK: u32 = 0o170_000;
const UNIX_REGULAR: u32 = 0o100_000;

/// A member name must be one ordinary file name: no folders, links, drive letters or streams.
fn safe_member_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', ':', '\0'])
        && svm_core::library::ordinary_file_name(name)
}

/// 7z method IDs accepted for the one block: stored (COPY) or LZMA2.
const METHOD_COPY: &[u8] = &[0x00];
const METHOD_LZMA2: &[u8] = &[0x21];
/// LZMA2 dictionary property 32 means 256 MiB; Kali's archive uses LZMA2:28 (256 MiB).
const MAX_LZMA2_PROPERTY: u8 = 32;

/// Allow exactly one block with one coder, so no filter chain or second dictionary can raise
/// memory use beyond the one LZMA2 dictionary checked here.
fn check_blocks(archive: &Archive) -> Result<(), String> {
    let refuse = |message: &str| Err(message.to_owned());
    let [block] = archive.blocks.as_slice() else {
        return refuse("The archive must hold its disk in exactly one compressed block.");
    };
    let [coder] = block.coders.as_slice() else {
        return refuse("The archive uses chained filters, which the service does not accept.");
    };
    match coder.encoder_method_id() {
        METHOD_COPY if coder.properties().is_empty() => Ok(()),
        METHOD_LZMA2 => match coder.properties() {
            [property] if *property <= MAX_LZMA2_PROPERTY => Ok(()),
            _ => refuse("The archive needs a larger LZMA2 dictionary than the service permits."),
        },
        _ => refuse("The archive uses a compression method the service does not accept."),
    }
}

fn check_entries(archive: &Archive, rule: &ArchiveMember) -> Result<(), String> {
    let refuse = |message: &str| Err(message.to_owned());
    if archive.files.len() != 1 {
        return refuse("The archive must hold exactly the one disk that the catalog names.");
    }
    let entry = &archive.files[0];
    if !safe_member_name(&entry.name) {
        return refuse("The archive names a file outside its own folder. The archive was refused.");
    }
    if entry.name != rule.member || entry.is_directory || !entry.has_stream || entry.is_anti_item {
        return refuse("The archive does not hold the disk that the catalog names.");
    }
    if entry.size != rule.bytes {
        return refuse("The disk in the archive does not have the size the catalog permits.");
    }
    if archive.is_file_encrypted(0) {
        return refuse("Encrypted archives are refused.");
    }
    if entry.has_windows_attributes {
        let attributes = entry.windows_attributes;
        let unix_type = (attributes >> 16) & UNIX_TYPE_MASK;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (attributes & UNIX_EXTENSION != 0 && unix_type != 0 && unix_type != UNIX_REGULAR)
        {
            return refuse("The archive marks the disk as a link or special file. The archive was refused.");
        }
    }
    Ok(())
}

fn describe(error: &sevenz_rust2::Error) -> String {
    match error {
        sevenz_rust2::Error::PasswordRequired | sevenz_rust2::Error::MaybeBadPassword(_) =>
            "Encrypted archives are refused.".into(),
        sevenz_rust2::Error::MaxMemLimited { .. } =>
            "The archive needs more decoder memory than the service permits.".into(),
        sevenz_rust2::Error::UnsupportedCompressionMethod(_) | sevenz_rust2::Error::Unsupported(_) =>
            "The archive uses a compression method the service does not accept.".into(),
        sevenz_rust2::Error::ChecksumVerificationFailed | sevenz_rust2::Error::NextHeaderCrcMismatch =>
            "The archive failed its internal checksum.".into(),
        _ => "The archive could not be read.".into(),
    }
}

/// Write the archive's single member to `destination` (a new file in a private folder), with a
/// hard size cap, and check it against the catalog's SHA-256 before returning. On any failure
/// the partial file is removed.
pub(super) fn unpack_member(
    archive: &Path, rule: &ArchiveMember, destination: &Path, percent: &AtomicU8, cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    let result = unpack(archive, rule, destination, percent, cancelled);
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn unpack(
    archive: &Path, rule: &ArchiveMember, destination: &Path, percent: &AtomicU8, cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    let source = OpenOptions::new().read(true).open(archive)
        .map_err(|_| "The verified archive could not be opened.".to_owned())?;
    let mut reader = ArchiveReader::new_with_memory_limit(source, Password::empty(), MEMORY_LIMIT_KB)
        .map_err(|error| describe(&error))?;
    // One decoder thread: the service keeps heavy work light on the host.
    reader.set_thread_count(1);
    check_entries(reader.archive(), rule)?;
    check_blocks(reader.archive())?;
    let mut output = OpenOptions::new().write(true).create_new(true).open(destination)
        .map_err(|_| "The private staging folder could not hold the unpacked disk.".to_owned())?;
    let mut hash = Sha256::new();
    let mut written = 0_u64;
    let mut failure: Option<String> = None;
    let walk = reader.for_each_entries(|entry, data| {
        if entry.name != rule.member {
            failure = Some("The archive does not hold the disk that the catalog names.".into());
            return Ok(false);
        }
        let mut buffer = vec![0_u8; BLOCK];
        loop {
            if cancelled() {
                failure = Some(CANCELLED.into());
                return Ok(false);
            }
            let count = data.read(&mut buffer)
                .map_err(|error| sevenz_rust2::Error::Io(error, "reading the archive member".into()))?;
            if count == 0 { break; }
            written = match written.checked_add(count as u64).filter(|next| *next <= rule.bytes) {
                Some(next) => next,
                None => {
                    failure = Some("The disk in the archive is larger than the catalog permits.".into());
                    return Ok(false);
                }
            };
            hash.update(&buffer[..count]);
            if output.write_all(&buffer[..count]).is_err() {
                failure = Some("The unpacked disk could not be written. Check the free space.".into());
                return Ok(false);
            }
            let done = written.saturating_mul(100) / rule.bytes.max(1);
            percent.store(u8::try_from(done.min(100)).unwrap_or(100), Ordering::Release);
        }
        Ok(true)
    });
    if let Some(message) = failure { return Err(message); }
    walk.map_err(|error| describe(&error))?;
    output.sync_all().map_err(|_| "The unpacked disk could not be saved.".to_owned())?;
    drop(output);
    if written != rule.bytes {
        return Err("The disk in the archive ended before the size the catalog names.".into());
    }
    let digest = format!("{:x}", hash.finalize());
    if digest != rule.sha256 {
        return Err("The unpacked disk does not match the catalog's SHA-256.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod};
    use std::{io::Cursor, path::PathBuf, sync::atomic::AtomicBool};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!("svm-ready-archive-{:032x}", u128::from_ne_bytes(random)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        archive_with(members, EncoderMethod::COPY)
    }

    fn archive_with(members: &[(&str, &[u8])], method: EncoderMethod) -> Vec<u8> {
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        writer.set_content_methods(vec![EncoderConfiguration::new(method)]);
        for (name, data) in members {
            writer.push_archive_entry(ArchiveEntry::new_file(name), Some(*data)).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn rule(member: &str, data: &[u8]) -> ArchiveMember {
        ArchiveMember { member: member.into(), bytes: data.len() as u64, sha256: format!("{:x}", Sha256::digest(data)) }
    }

    fn run(temp: &Temp, bytes: &[u8], rule: &ArchiveMember, cancel: &AtomicBool) -> (Result<(), String>, PathBuf) {
        let source = temp.0.join("image.7z");
        fs::write(&source, bytes).unwrap();
        let destination = temp.0.join("unpacked.qcow2");
        let percent = AtomicU8::new(0);
        let result = unpack_member(&source, rule, &destination, &percent, &|| cancel.load(Ordering::Acquire));
        (result, destination)
    }

    #[test]
    fn unpacks_the_named_member_and_checks_its_digest() {
        let temp = Temp::new();
        let data = b"QFI\xfbsynthetic disk bytes for the unpack test".repeat(4096);
        let rule = rule("disk.qcow2", &data);
        let (result, out) = run(&temp, &archive(&[("disk.qcow2", &data)]), &rule, &AtomicBool::new(false));
        result.unwrap();
        assert_eq!(fs::read(out).unwrap(), data);
    }

    #[test]
    fn refuses_wrong_size_digest_name_extra_members_and_cancel_leaving_nothing() {
        let temp = Temp::new();
        let data = b"synthetic disk".repeat(1000);
        let good = rule("disk.qcow2", &data);
        let cases: Vec<(Vec<u8>, ArchiveMember, &str)> = vec![
            (archive(&[("disk.qcow2", &data)]), ArchiveMember { sha256: "0".repeat(64), ..good.clone() }, "SHA-256"),
            (archive(&[("disk.qcow2", &data)]), ArchiveMember { bytes: good.bytes - 1, ..good.clone() }, "size"),
            (archive(&[("other.qcow2", &data)]), good.clone(), "catalog names"),
            (archive(&[("../disk.qcow2", &data)]), ArchiveMember { member: "../disk.qcow2".into(), ..good.clone() }, "outside"),
            (archive(&[("C:disk.qcow2", &data)]), ArchiveMember { member: "C:disk.qcow2".into(), ..good.clone() }, "outside"),
            (archive(&[("dir\\disk.qcow2", &data)]), ArchiveMember { member: "dir\\disk.qcow2".into(), ..good.clone() }, "outside"),
            (archive(&[("disk.qcow2", &data), ("extra.txt", b"x")]), good.clone(), "exactly the one disk"),
            (b"not an archive at all".to_vec(), good.clone(), "could not be read"),
        ];
        for (bytes, rule, expected) in cases {
            let (result, out) = run(&temp, &bytes, &rule, &AtomicBool::new(false));
            let message = result.unwrap_err();
            assert!(message.contains(expected), "{expected}: {message}");
            assert!(!out.exists(), "{expected}: partial disk left behind");
        }
        let (result, out) = run(&temp, &archive(&[("disk.qcow2", &data)]), &good, &AtomicBool::new(true));
        assert_eq!(result.unwrap_err(), CANCELLED);
        assert!(!out.exists());
    }

    #[test]
    fn accepts_lzma2_and_refuses_other_methods() {
        let temp = Temp::new();
        let data = b"compressible synthetic disk ".repeat(20_000);
        let good = rule("disk.qcow2", &data);
        let (result, out) = run(&temp, &archive_with(&[("disk.qcow2", &data)], EncoderMethod::LZMA2), &good, &AtomicBool::new(false));
        result.unwrap();
        assert_eq!(fs::read(&out).unwrap(), data);
        fs::remove_file(out).unwrap();
        let (result, out) = run(&temp, &archive_with(&[("disk.qcow2", &data)], EncoderMethod::LZMA), &good, &AtomicBool::new(false));
        assert!(result.unwrap_err().contains("compression method"));
        assert!(!out.exists());
    }

    #[test]
    fn member_names_must_be_single_ordinary_files() {
        for name in ["disk.qcow2", "kali-linux-2026.3-qemu-amd64.qcow2"] { assert!(safe_member_name(name), "{name}"); }
        for name in ["", ".", "..", "../x", "a/b", "a\\b", "C:x", "x:stream", "nul"] {
            assert!(!safe_member_name(name), "{name}");
        }
    }
}
