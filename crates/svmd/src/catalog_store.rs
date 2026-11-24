use super::{
    catalog::{ChecksumFormat, Entry, Phase, Status, lock_status, lower_hex},
    catalog_http::{ArtifactResponse, open_artifact},
    catalog_signature::{require_verifier, verify_freebsd_sha256, verify_sha256_list, verify_sha512},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::UNIX_EPOCH,
};
use svm_qemu::LocalFolder;

const PARTIAL: &str = "download.json";
const RECEIPT: &str = "verified.json";
const BLOCK: usize = 1024 * 1024;

pub(super) enum Failure { Cancelled, Failed(String) }
impl From<String> for Failure { fn from(message: String) -> Self { Self::Failed(message) } }
impl From<&str> for Failure { fn from(message: &str) -> Self { Self::Failed(message.to_owned()) } }

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Partial {
    id: String,
    sha256: String,
    total: u64,
    etag: Option<String>,
    resource: Option<String>,
}
impl Partial {
    fn new(entry: &Entry, etag: Option<String>, resource: Option<String>) -> Self {
        Self { id: entry.id.clone(), sha256: entry.sha256.clone(), total: entry.bytes, etag, resource }
    }

    fn matches(&self, entry: &Entry) -> bool {
        self.id == entry.id && self.sha256 == entry.sha256 && self.total == entry.bytes
            && self.etag.as_deref().is_none_or(strong_etag)
            && self.resource.as_deref().is_none_or(|digest| lower_hex(digest, 64))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    id: String,
    file_name: String,
    bytes: u64,
    sha256: String,
    modified_ns: u64,
    signature_verified: bool,
}
impl Receipt {
    fn matches(&self, entry: &Entry, file: &Metadata) -> bool {
        self.id == entry.id && self.file_name == entry.file_name && self.bytes == entry.bytes
            && file.len() == entry.bytes && self.sha256 == entry.sha256
            && file_timestamp(file).ok() == Some(self.modified_ns)
            && self.signature_verified == entry.signature_required()
    }
}

fn path_error() -> String {
    "The selected machine library could not safely store this installer.".into()
}

fn file_timestamp(file: &Metadata) -> Result<u64, String> {
    file.modified().ok().and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|time| time.as_nanos().try_into().ok()).ok_or_else(path_error)
}

fn present(path: &Path) -> Result<Option<Metadata>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 { return Err(path_error()); }
            }
            if metadata.file_type().is_symlink() { return Err(path_error()); }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(path_error()),
    }
}

fn regular(path: &Path) -> Result<Option<Metadata>, String> {
    match present(path)? {
        Some(file) if !file.is_file() => Err(path_error()),
        value => Ok(value),
    }
}

fn directory(path: &Path) -> Result<bool, String> {
    match present(path)? {
        Some(item) if !item.is_dir() => Err(path_error()),
        value => Ok(value.is_some()),
    }
}

fn record<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    let Some(metadata) = regular(path)? else { return Ok(None); };
    if metadata.len() > 8192 { return Err(path_error()); }
    let mut source = File::open(path).map_err(|_| path_error())?.take(8193);
    let mut contents = Vec::new();
    source.read_to_end(&mut contents).map_err(|_| path_error())?;
    if contents.len() > 8192 { return Err(path_error()); }
    serde_json::from_slice(&contents).map(Some).map_err(|_| path_error())
}

fn part_name(entry: &Entry) -> String { format!(".{}.partial", entry.id) }

fn staged_receipt(path: &Path, entry: &Entry, file: Option<&Metadata>) -> Result<Option<Partial>, String> {
    if let Some(metadata) = record::<Partial>(&path.join(PARTIAL))? {
        return if metadata.matches(entry) { Ok(Some(metadata)) } else { Err(path_error()) };
    }
    // A crash before the final directory rename may leave a complete, verified staged file.
    match record::<Receipt>(&path.join(RECEIPT))? {
        Some(receipt) if file.is_some_and(|meta| receipt.matches(entry, meta)) => Ok(Some(Partial::new(entry, None, None))),
        Some(_) => Err(path_error()),
        None => Ok(None),
    }
}

fn measure_status(base: &Path, entry: &Entry) -> Result<Status, String> {
    let mut status = Status::idle(entry);
    if !directory(base)? { return Ok(status); }
    let ready = base.join(&entry.id);
    if directory(&ready)? {
        let receipt: Receipt = record(&ready.join(RECEIPT))?.ok_or_else(path_error)?;
        let file = regular(&ready.join(&entry.file_name))?.ok_or_else(path_error)?;
        if !receipt.matches(entry, &file) { return Err("The published installer has changed or its receipt is invalid.".into()); }
        status.state = Phase::Verified;
        status.bytes = entry.bytes;
        status.sha256 = Some(receipt.sha256);
        status.signature_verified = Some(receipt.signature_verified);
    } else {
        let part = base.join(part_name(entry));
        if directory(&part)? {
            let file = regular(&part.join(&entry.file_name))?;
            let metadata = staged_receipt(&part, entry, file.as_ref())?;
            if let (Some(file), Some(metadata)) = (file, metadata) {
                status.bytes = file.len().min(entry.bytes);
                status.can_resume = resumable(file.len(), entry.bytes, metadata.etag.as_deref(), metadata.resource.as_deref());
                status.state = Phase::Paused;
            }
        }
    }
    Ok(status)
}

pub(super) fn observe(base: &Path, entry: &Entry) -> Status {
    measure_status(base, entry).unwrap_or_else(|message| {
        let mut status = Status::idle(entry);
        status.state = Phase::Failed;
        status.message = Some(message);
        status
    })
}

fn strong_etag(value: &str) -> bool {
    value.len() >= 2 && value.len() <= 256 && value.starts_with('"') && value.ends_with('"')
        && value.as_bytes()[1..value.len()-1].iter().all(|byte| (b'!'..=b'~').contains(byte) && *byte != b'"')
}

fn resumable(length: u64, total: u64, etag: Option<&str>, resource: Option<&str>) -> bool {
    length == total || (length > 0 && length < total && resource.is_some()
        && etag.is_some_and(strong_etag))
}

fn range_matches(value: &str, start: u64, total: u64) -> bool {
    let Some((window, size)) = value.strip_prefix("bytes ").and_then(|value| value.split_once('/')) else { return false; };
    let Some((first, last)) = window.split_once('-') else { return false; };
    first.parse::<u64>().ok() == Some(start) && last.parse::<u64>().ok() == total.checked_sub(1)
        && size.parse::<u64>().ok() == Some(total)
}

fn response_matches(reply: &ArtifactResponse, position: u64, total: u64, saved: &Partial) -> bool {
    if reply.content_length.is_some_and(|length| total.checked_sub(position) != Some(length)) {
        return false;
    }
    if position == 0 {
        reply.status == 200 && reply.content_range.is_none()
    } else {
        reply.status == 206 && reply.etag == saved.etag && Some(&reply.resource) == saved.resource.as_ref()
            && reply.content_range.as_deref().is_some_and(|raw| range_matches(raw, position, total))
    }
}

fn open_installers(base: &Path) -> Result<LocalFolder, String> {
    if directory(base)? { return LocalFolder::open(base).map_err(|_| path_error()); }
    let library = LocalFolder::open(base.parent().ok_or_else(path_error)?).map_err(|_| path_error())?;
    library.create_private_child("installers").map_err(|_| path_error())
}

fn open_partial(base: &LocalFolder, entry: &Entry) -> Result<(LocalFolder, Partial), String> {
    let name = part_name(entry);
    let path = base.path.join(&name);
    let part = if directory(&path)? {
        LocalFolder::open(&path)
    } else {
        base.create_private_child(&name)
    }.map_err(|_| path_error())?;
    let receipt_path = part.path.join(PARTIAL);
    let file = regular(&part.path.join(&entry.file_name))?;
    clear_interrupted_records(&part.path)?;
    let receipt = match staged_receipt(&part.path, entry, file.as_ref())? {
        Some(receipt) => receipt,
        None => {
            if fs::read_dir(&part.path).map_err(|_| path_error())?.next().is_some() { return Err(path_error()); }
            let receipt = Partial::new(entry, None, None);
            svm_core::write_json(&receipt_path, &receipt).map_err(|_| path_error())?;
            receipt
        }
    };
    Ok((part, receipt))
}

fn clear_interrupted_records(part: &Path) -> Result<(), String> {
    for entry in fs::read_dir(part).map_err(|_| path_error())? {
        let entry = entry.map_err(|_| path_error())?;
        let name = entry.file_name();
        let Some((pid, sequence)) = name.to_str()
            .and_then(|name| name.strip_prefix(".svm-write-"))
            .and_then(|name| name.split_once('-'))
        else { continue; };
        if pid.parse::<u32>().is_err() || sequence.parse::<u64>().is_err() { continue; }
        if !regular(&entry.path())?.is_some_and(|file| file.len() <= 8192) {
            return Err(path_error());
        }
        fs::remove_file(entry.path()).map_err(|_| path_error())?;
    }
    Ok(())
}

fn payload(path: &Path, writable: bool) -> Result<File, String> {
    regular(path)?;
    let mut opts = OpenOptions::new();
    opts.read(true).write(writable).create(writable).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(1).custom_flags(0x0020_0000);
    }
    let file = opts.open(path).map_err(|_| path_error())?;
    let metadata = file.metadata().map_err(|_| path_error())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { return Err(path_error()); }
    }
    if !metadata.is_file() { return Err(path_error()); }
    Ok(file)
}

pub(super) struct HeldInstaller {
    path: PathBuf,
    _file: File,
    _folder: LocalFolder,
}

impl HeldInstaller {
    pub(super) fn path(&self) -> &Path { &self.path }
}

pub(super) fn verified_installer(base: &Path, entry: &Entry) -> Result<HeldInstaller, String> {
    let folder = LocalFolder::open(&base.join(&entry.id))
        .map_err(|_| "Download and verify this installer in the OS catalog first.".to_owned())?;
    let path = folder.path.join(&entry.file_name);
    let mut file = payload(&path, false)?;
    let metadata = file.metadata().map_err(|_| path_error())?;
    let receipt: Receipt = record(&folder.path.join(RECEIPT))?
        .ok_or_else(|| "The selected installer has no verification receipt.".to_owned())?;
    if !receipt.matches(entry, &metadata) {
        return Err("The catalog installer or its verification receipt has changed.".into());
    }

    let signed_sha512 = entry.upstream.as_ref().and_then(|release| release.signed_sha512());
    let matches = if let Some(expected_sha512) = signed_sha512 {
        let (sha256, sha512) = digests(&mut file, &Mutex::new(Status::idle(entry))).map_err(|failure| match failure {
            Failure::Failed(message) => message,
            Failure::Cancelled => "Installer verification was interrupted.".into(),
        })?;
        sha256 == entry.sha256 && sha512 == expected_sha512
    } else {
        matches_digest::<Sha256>(&mut file, entry.bytes, &entry.sha256)?
    };
    if !matches {
        return Err("The catalog installer no longer matches its verified checksum.".into());
    }
    if let Some(release) = &entry.upstream {
        release.check_manifest(base)?;
        release.check_asset(base, &path, signed_sha512.unwrap_or_default(), &|| false)?;
    }
    Ok(HeldInstaller { path, _file: file, _folder: folder })
}

pub(super) fn local_installer(path: &Path, publisher_sha256: Option<&str>) -> Result<HeldInstaller, String> {
    let parent = path.parent().ok_or_else(path_error)?;
    let folder = LocalFolder::open(parent).map_err(|_| path_error())?;
    let path = folder.path.join(path.file_name().ok_or_else(path_error)?);
    let mut file = payload(&path, false)?;
    let bytes = file.metadata().map_err(|_| path_error())?.len();
    if bytes == 0 { return Err("Choose a nonempty local installer ISO.".into()); }
    if let Some(expected) = publisher_sha256 {
        if bytes > 128 * 1024 * 1024 * 1024 || !matches_digest::<Sha256>(&mut file, bytes, expected)? {
            return Err("The selected ISO does not match the SHA-256 published for this release and language.".into());
        }
    }
    Ok(HeldInstaller { path, _file: file, _folder: folder })
}

fn matches_digest<D: Digest>(file: &mut File, expected_bytes: u64, expected_digest: &str) -> Result<bool, String> {
    file.rewind().map_err(|_| path_error())?;
    let mut digest = D::new();
    let mut buffer = vec![0; BLOCK];
    let mut bytes = 0;
    loop {
        let count = file.read(&mut buffer).map_err(|_| path_error())?;
        if count == 0 { break; }
        bytes += count as u64;
        if bytes > expected_bytes { return Ok(false); }
        digest.update(&buffer[..count]);
    }
    let actual: String = digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(bytes == expected_bytes && actual == expected_digest)
}

fn receive(
    mut reply: ArtifactResponse, file: &mut File, mut bytes: u64, entry: &Entry, status: &Mutex<Status>,
) -> Result<(), Failure> {
    let mut buffer = vec![0; BLOCK];
    loop {
        lock_status(status).progress(bytes)?;
        let count = reply.body.read(&mut buffer)
            .map_err(|_| Failure::Failed("The publisher connection stopped before the installer finished.".into()))?;
        if count == 0 { break; }
        let next = bytes.checked_add(count as u64).filter(|next| *next <= entry.bytes);
        let Some(next) = next else {
            file.set_len(0).map_err(|_| path_error())?;
            return Err("The publisher sent more data than the catalog permits.".into());
        };
        file.write_all(&buffer[..count]).map_err(|_| path_error())?;
        bytes = next;
    }
    lock_status(status).progress(bytes)?;
    if bytes != entry.bytes { return Err("The publisher response ended before the expected installer length.".into()); }
    Ok(())
}

fn digests(file: &mut File, status: &Mutex<Status>) -> Result<(String, String), Failure> {
    file.seek(SeekFrom::Start(0)).map_err(|_| path_error())?;
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut buffer = vec![0; BLOCK];
    loop {
        lock_status(status).check_cancelled()?;
        let count = file.read(&mut buffer).map_err(|_| path_error())?;
        if count == 0 { break; }
        sha256.update(&buffer[..count]);
        sha512.update(&buffer[..count]);
    }
    Ok((format!("{:x}", sha256.finalize()), format!("{:x}", sha512.finalize())))
}

fn verify_vendor(entry: &Entry, base: &Path, sha256: &str, sha512: &str) -> Result<bool, Failure> {
    let Some(rule) = &entry.signed_checksum else { return Ok(false); };
    match rule.format {
        ChecksumFormat::DebianSha512 => {
            let (sums, signature): (&[u8], &[u8]) = match entry.file_name.as_str() {
                "debian-13.7.0-amd64-netinst.iso" => (
                    include_bytes!("../catalog/amd64.SHA512SUMS"),
                    include_bytes!("../catalog/amd64.SHA512SUMS.sign"),
                ),
                "debian-13.7.0-arm64-netinst.iso" => (
                    include_bytes!("../catalog/arm64.SHA512SUMS"),
                    include_bytes!("../catalog/arm64.SHA512SUMS.sign"),
                ),
                _ => return Err("The catalog is missing this Debian installer's signed checksum.".into()),
            };
            verify_sha512(base, include_bytes!("../catalog/debian-cd-keyring.gpg"), sums, signature,
                &rule.fingerprint, &entry.file_name, sha512)?;
        }
        ChecksumFormat::FreebsdSha256 => verify_freebsd_sha256(base,
            include_bytes!("../catalog/freebsd-release-keyring.gpg"),
            include_bytes!("../catalog/freebsd.SHA256SUMS.asc"),
            &rule.fingerprint, &entry.file_name, sha256)?,
        ChecksumFormat::Sha256Sums => {
            let (keyring, sums, signature) = bundled_sha256_list(&entry.file_name)
                .ok_or("The catalog is missing this image's signed checksum list.")?;
            verify_sha256_list(base, keyring, sums, signature, &rule.fingerprint, &entry.file_name, sha256)?;
        }
    }
    Ok(true)
}

/// The publisher keyring, SHA256SUMS list and detached signature shipped for a ready image.
fn bundled_sha256_list(file_name: &str) -> Option<(&'static [u8], &'static [u8], &'static [u8])> {
    match file_name {
        "kali-linux-2026.3-qemu-amd64.7z" => Some((
            include_bytes!("../catalog/kali-archive-keyring.gpg"),
            include_bytes!("../catalog/kali-2026.3.SHA256SUMS"),
            include_bytes!("../catalog/kali-2026.3.SHA256SUMS.gpg"),
        )),
        "ubuntu-26.04-server-cloudimg-amd64.img" => Some((
            include_bytes!("../catalog/ubuntu-cloudimage-keyring.gpg"),
            include_bytes!("../catalog/ubuntu-26.04-cloud.SHA256SUMS"),
            include_bytes!("../catalog/ubuntu-26.04-cloud.SHA256SUMS.gpg"),
        )),
        _ => None,
    }
}

pub(super) fn download(directory: &Path, entry: &Entry, status: &Mutex<Status>) -> Result<(), Failure> {
    download_from(directory, entry, status, open_artifact)
}

fn download_from(
    directory: &Path, entry: &Entry, status: &Mutex<Status>,
    mut fetch: impl FnMut(&str, &[String], Option<(u64, &str)>) -> Result<ArtifactResponse, String>,
) -> Result<(), Failure> {
    lock_status(status).progress(0)?;
    if entry.signature_required() { require_verifier()?; }
    let base = open_installers(directory)?;
    if let Some(release) = &entry.upstream { release.check_manifest(&base.path)?; }
    lock_status(status).check_cancelled()?;
    let destination = base.path.join(&entry.id);
    if present(&destination)?.is_some() { return Err("An installer already occupies the catalog destination.".into()); }
    let (part, record) = open_partial(&base, entry)?;
    let file_path = part.path.join(&entry.file_name);
    let mut file = payload(&file_path, true)?;
    let existing = file.metadata().map_err(|_| path_error())?.len();
    let start = if resumable(existing, entry.bytes, record.etag.as_deref(), record.resource.as_deref()) { existing } else { 0 };
    lock_status(status).progress(start)?;
    if start != entry.bytes {
        let resume = if start == 0 { None } else { record.etag.as_deref().map(|etag| (start, etag)) };
        let mut reply = fetch(&entry.url, &entry.official_hosts, resume)?;
        lock_status(status).progress(start)?;
        if matches!(reply.status, 404 | 410) {
            if let Some(archive) = &entry.archive_url {
                reply = fetch(archive, &entry.official_hosts, resume)?;
                lock_status(status).progress(start)?;
            }
        }
        if !response_matches(&reply, start, entry.bytes, &record) {
            if start > 0 && matches!(reply.status, 200 | 206 | 416) {
                file.set_len(0).map_err(|_| path_error())?;
                return Err("The publisher no longer matched the saved partial. Start a fresh download.".into());
            }
            return Err("The publisher did not return the installer with the expected length and range.".into());
        }
        let etag = reply.etag.as_deref().filter(|value| strong_etag(value)).map(str::to_owned);
        let metadata = Partial::new(entry, etag, Some(reply.resource.clone()));
        if start == 0 && existing != 0 {
            file.set_len(0).map_err(|_| path_error())?;
            file.sync_all().map_err(|_| path_error())?;
        }
        svm_core::write_json(&part.path.join(PARTIAL), &metadata).map_err(|_| path_error())?;
        file.seek(SeekFrom::Start(start)).map_err(|_| path_error())?;
        let result = receive(reply, &mut file, start, entry, status);
        file.sync_all().map_err(|_| path_error())?;
        result?;
    }
    drop(file);
    lock_status(status).verify(entry.bytes)?;
    let mut file = payload(&file_path, false)?;
    let (sha256, sha512) = digests(&mut file, status)?;
    lock_status(status).check_cancelled()?;
    if sha256 != entry.sha256 || !lower_hex(&sha512, 128) {
        drop(file);
        let invalid = payload(&file_path, true)?;
        invalid.set_len(0).map_err(|_| path_error())?;
        invalid.sync_all().map_err(|_| path_error())?;
        return Err("Installer checksum mismatch. A fresh download is required.".into());
    }
    let signature_verified = if let Some(release) = &entry.upstream {
        release.check_asset(&base.path, &file_path, &sha512, &|| lock_status(status).state == Phase::Cancelling)?;
        true
    } else {
        verify_vendor(entry, &base.path, &sha256, &sha512)?
    };
    lock_status(status).check_cancelled()?;
    let meta = file.metadata().map_err(|_| path_error())?;
    if meta.len() != entry.bytes { return Err("The installer changed during verification.".into()); }
    let receipt = Receipt {
        id: entry.id.clone(), file_name: entry.file_name.clone(), bytes: entry.bytes,
        sha256, modified_ns: file_timestamp(&meta)?, signature_verified,
    };
    svm_core::write_json(&part.path.join(RECEIPT), &receipt).map_err(|_| path_error())?;
    match fs::remove_file(part.path.join(PARTIAL)) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(path_error().into()),
    }
    drop(file);
    let source = part.path.clone();
    drop(part);
    if present(&destination)?.is_some() { return Err("The installer destination is already occupied.".into()); }
    lock_status(status).publish()?;
    fs::rename(source, &destination).map_err(|_| path_error())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resuming_requires_the_same_exact_range_and_strong_validator() {
        let resource = Some("resource");
        assert!(resumable(7, 16, Some("\"stable\""), resource));
        assert!(!resumable(7, 16, Some("\"stable\""), None));
        assert!(!resumable(7, 16, Some("W/\"weak\""), resource));
        assert!(!resumable(7, 16, Some("\"broken\nvalue\""), resource));
        assert!(!resumable(17, 16, Some("\"stable\""), resource));
        assert!(range_matches("bytes 7-15/16", 7, 16));
        assert!(!range_matches("bytes 0-15/16", 7, 16));
        assert!(!range_matches("bytes 7-16/16", 7, 16));
        assert!(!range_matches("bytes 7-15/*", 7, 16));
    }

    struct TempLibrary(PathBuf);
    impl TempLibrary {
        fn create() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!("svm-catalog-check-{:032x}", u128::from_ne_bytes(random)));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }
    impl Drop for TempLibrary {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    fn entry(download: &[u8]) -> Entry {
        serde_json::from_value(serde_json::json!({
            "id":"synthetic-test","name":"Synthetic installer","version":"1","edition":"Test",
            "architecture":"x86_64","engine":"Hyper-V","vcpu":1,"ramGb":2,"diskGb":8,
            "bytes":download.len(),"fileName":"synthetic.iso",
            "sha256":format!("{:x}", Sha256::digest(download)),
            "url":"https://publisher.example/synthetic.iso","officialHosts":["publisher.example"],
        })).unwrap()
    }

    fn response(status: u16, length: u64, range: Option<&str>, data: &[u8]) -> ArtifactResponse {
        ArtifactResponse {
            status, etag: Some("\"stable\"".into()), resource: "ab".repeat(32), content_length: Some(length),
            content_range: range.map(str::to_owned), gzip: false, body: Box::new(io::Cursor::new(data.to_vec())),
        }
    }

    fn downloading(entry: &Entry) -> Mutex<Status> {
        let mut status = Status::idle(entry);
        status.state = Phase::Downloading;
        Mutex::new(status)
    }

    #[test]
    fn a_short_download_recovers_and_publishes_one_verified_receipt() {
        let library = TempLibrary::create();
        let base = library.0.join("installers");
        let bytes = b"abcdefghijklmnop";
        let entry = entry(bytes);
        let first = download_from(&base, &entry, &downloading(&entry), |_, _, resume| {
            assert_eq!(resume, None);
            Ok(response(200, 16, None, &bytes[..7]))
        });
        assert!(matches!(first, Err(Failure::Failed(_))));
        let remaining = observe(&base, &entry);
        assert_eq!(remaining.state, Phase::Paused);
        assert_eq!(remaining.bytes, 7);
        assert!(remaining.can_resume);
        assert!(!base.join(&entry.id).exists());

        assert!(download_from(&base, &entry, &downloading(&entry), |_, _, resume| {
            assert_eq!(resume, Some((7, "\"stable\"")));
            Ok(response(206, 9, Some("bytes 7-15/16"), &bytes[7..]))
        }).is_ok());
        let published = base.join(&entry.id);
        assert_eq!(fs::read(published.join(&entry.file_name)).unwrap(), bytes);
        assert!(!published.join(PARTIAL).exists());
        assert_eq!(observe(&base, &entry).state, Phase::Verified);
    }

    #[test]
    fn interrupted_metadata_and_cancelled_response_leave_a_safe_retry() {
        let library = TempLibrary::create();
        let base = library.0.join("installers");
        let entry = entry(b"abcd");
        let part = base.join(part_name(&entry));
        fs::create_dir_all(&part).unwrap();
        fs::write(part.join(".svm-write-2026-0"), b"{").unwrap();

        let status = downloading(&entry);
        let result = download_from(&base, &entry, &status, |_, _, resume| {
            assert!(resume.is_none());
            lock_status(&status).state = Phase::Cancelling;
            Ok(response(200, 4, None, b"abcd"))
        });
        assert!(matches!(result, Err(Failure::Cancelled)));
        assert!(!part.join(".svm-write-2026-0").exists());
        assert!(!base.join(&entry.id).exists());
        assert_eq!(observe(&base, &entry).bytes, 0);

        assert!(download_from(&base, &entry, &downloading(&entry), |_, _, _| {
            Ok(response(200, 4, None, b"abcd"))
        }).is_ok());
        assert_eq!(observe(&base, &entry).state, Phase::Verified);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires the existing Windows OpenPGP verifier"]
    fn native_catalog_signatures_accept_the_three_pinned_publishers_files() {
        let library = TempLibrary::create();
        let rows = super::super::catalog::catalog().expect("valid catalog");
        for id in ["debian-13-7-amd64-netinst", "debian-13-7-arm64-netinst", "freebsd-15-1-amd64-disc1"] {
            let row = rows.iter().find(|row| row.id == id).expect("pinned signature fixture");
            let sha512 = match id {
                "debian-13-7-amd64-netinst" => concat!(
                    "ef04d0276850d70e4aaec0b55003628660e9631b26e35215a70ab3c8c707294a4b",
                    "12731bc73c75a932902f703a7c278310ca99df28d6b36fb06d5618d8d0f678",
                ),
                "debian-13-7-arm64-netinst" => concat!(
                    "cff08e2f29c2846f0503fe57ad1085b5067f29acab444acdf7cdf5b10f2a11140",
                    "a0e87828e4ffeb9828d188053690467ebe50151c142551d6053fc3288808b86",
                ),
                "freebsd-15-1-amd64-disc1" => "",
                _ => panic!("unexpected catalog fixture"),
            };
            assert!(row.signed_checksum.is_some());
            assert!(verify_vendor(row, &library.0, &row.sha256, sha512)
                .unwrap_or_else(|failure| match failure {
                    Failure::Failed(message) => panic!("{}: {message}", row.id),
                    Failure::Cancelled => panic!("{}: unexpected cancellation", row.id),
                }));
        }
        assert_eq!(fs::read_dir(&library.0).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires the existing Windows OpenPGP verifier"]
    fn native_signatures_accept_the_ready_image_lists_and_refuse_a_changed_digest() {
        let library = TempLibrary::create();
        let images = super::super::catalog::ready_images().expect("valid ready images");
        let mut signed = 0;
        for row in images.iter().filter(|row| row.signed_checksum.is_some()) {
            signed += 1;
            assert!(verify_vendor(row, &library.0, &row.sha256, "")
                .unwrap_or_else(|failure| match failure {
                    Failure::Failed(message) => panic!("{}: {message}", row.id),
                    Failure::Cancelled => panic!("{}: unexpected cancellation", row.id),
                }));
            let changed = format!("{}0", &row.sha256[..63]);
            assert!(verify_vendor(row, &library.0, &changed, "").is_err(), "{} accepted a changed digest", row.id);
        }
        assert_eq!(signed, 2);
        assert_eq!(fs::read_dir(&library.0).unwrap().count(), 0);
    }

    #[test]
    fn ready_image_lists_name_each_pinned_image_once() {
        let images = super::super::catalog::ready_images().expect("valid ready images");
        for row in images.iter().filter(|row| row.signed_checksum.is_some()) {
            let (keyring, sums, signature) = bundled_sha256_list(&row.file_name).expect("bundled list");
            assert!(!keyring.is_empty() && !signature.is_empty());
            let text = std::str::from_utf8(sums).unwrap();
            let records: Vec<_> = text.lines().filter(|line| line.ends_with(&format!(" {}", row.file_name))
                || line.ends_with(&format!("*{}", row.file_name))).collect();
            assert_eq!(records.len(), 1, "{}", row.id);
            assert!(records[0].starts_with(&row.sha256), "{}", row.id);
        }
        assert!(bundled_sha256_list("unlisted.7z").is_none());
    }

    #[test]
    fn create_reopens_verified_bytes_and_refuses_same_size_same_timestamp_changes() {
        let library = TempLibrary::create();
        let base = library.0.join("installers");
        let entry = entry(b"abcd");
        assert!(verified_installer(&base, &entry).is_err());
        assert!(download_from(&base, &entry, &downloading(&entry), |_, _, _| {
            Ok(response(200, 4, None, b"abcd"))
        }).is_ok());

        let held = verified_installer(&base, &entry).expect("verified installer");
        let verified_path = held.path().to_path_buf();
        assert_eq!(fs::read(&verified_path).unwrap(), b"abcd");
        #[cfg(windows)]
        {
            assert!(OpenOptions::new().write(true).open(&verified_path).is_err());
            assert!(fs::rename(held.path(), held.path().with_file_name("renamed.iso")).is_err());
        }
        drop(held);

        let modified = fs::metadata(&verified_path).unwrap().modified().unwrap();
        let mut altered = OpenOptions::new().write(true).open(&verified_path).unwrap();
        altered.write_all(b"wxyz").unwrap();
        altered.sync_all().unwrap();
        altered.set_times(fs::FileTimes::new().set_modified(modified)).unwrap();
        drop(altered);
        assert_eq!(observe(&base, &entry).state, Phase::Verified);
        assert!(matches!(verified_installer(&base, &entry), Err(message) if message.contains("verified checksum")));
    }


    #[cfg(windows)]
    #[test]
    #[ignore = "requires the existing Windows OpenPGP verifier"]
    fn native_publisher_verifier_authenticates_the_exact_small_artifact_handle() {
        use super::super::catalog_signature::{verified_publisher_manifest, verify_publisher_asset};
        let library = TempLibrary::create();
        let manifest = include_bytes!("../catalog/amd64.SHA512SUMS");
        let signature = include_bytes!("../catalog/amd64.SHA512SUMS.sign");
        let keyring = include_bytes!("../catalog/debian-cd-keyring.gpg");
        let pin = "DF9B9C49EAA9298432589D76DA87E80D6294BE9B";
        assert_eq!(verified_publisher_manifest(&library.0, keyring, manifest, Some(signature), pin)
            .expect("authentic publisher manifest"), manifest);
        let sample = library.0.join("signed-artifact.bin");
        fs::write(&sample, manifest).unwrap();
        assert!(verify_publisher_asset(&library.0, keyring, signature, pin, &sample, &|| false).is_ok());
        fs::write(&sample, b"altered artifact").unwrap();
        assert!(verify_publisher_asset(&library.0, keyring, signature, pin, &sample, &|| false).is_err());
        assert!(verify_publisher_asset(&library.0, keyring, signature, pin, &sample, &|| true).is_err());
    }

    #[test]
    fn user_supplied_media_checks_the_pin_when_the_publisher_provides_one() {
        let library = TempLibrary::create();
        let path = library.0.join("owned.iso");
        fs::write(&path, b"synthetic installer bytes").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"synthetic installer bytes"));
        let held = local_installer(&path, Some(&digest)).expect("matching publisher pin");
        assert_eq!(held.path(), path);
        drop(held);
        assert!(matches!(local_installer(&path, Some(&"0".repeat(64))), Err(message) if message.contains("published")));
        assert!(local_installer(&path, None).is_ok());
        assert!(!library.0.join(RECEIPT).exists());
    }

    #[test]
    fn checksum_mismatch_clears_the_partial_without_publishing() {
        let library = TempLibrary::create();
        let base = library.0.join("installers");
        let entry = entry(b"abcd");
        let result = download_from(&base, &entry, &downloading(&entry), |_, _, _| {
            Ok(response(200, 4, None, b"bad!"))
        });
        assert!(matches!(result, Err(Failure::Failed(message)) if message.contains("checksum mismatch")));
        assert!(!base.join(&entry.id).exists());
        assert!(!observe(&base, &entry).can_resume);
    }

}
