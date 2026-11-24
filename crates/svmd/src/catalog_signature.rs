use std::path::Path;

const MAX_KEYRING: usize = 256 * 1024;
const MAX_SUMS: usize = 64 * 1024;
const MAX_SIGNATURE: usize = 16 * 1024;
type Check<T> = Result<T, &'static str>;

/// Verify the exact Debian SHA-512 record and its detached signature with a binary
/// OpenPGP public keyring in the supplied owner-held application directory.
pub(super) fn verify_sha512(
    bundle_dir: &Path,
    keyring: &[u8],
    sums: &[u8],
    signature: &[u8],
    primary_fingerprint: &str,
    image_name: &str,
    image_sha512: &str,
) -> Result<(), String> {
    let document = SignedDocument::Detached { sums, signature };
    check_input(keyring, primary_fingerprint, document).map_err(str::to_owned)?;
    check_sha512(sums, image_name, image_sha512).map_err(str::to_owned)?;
    verify_signer(bundle_dir, keyring, document, primary_fingerprint)
        .map(|_| ()).map_err(str::to_owned)
}

/// Verify a standard SHA256SUMS list (`<digest>  <name>` or `<digest> *<name>` records) and its
/// detached signature, as Kali and the Ubuntu cloud images publish them.
pub(super) fn verify_sha256_list(
    bundle_dir: &Path,
    keyring: &[u8],
    sums: &[u8],
    signature: &[u8],
    primary_fingerprint: &str,
    image_name: &str,
    image_sha256: &str,
) -> Result<(), String> {
    let document = SignedDocument::Detached { sums, signature };
    check_input(keyring, primary_fingerprint, document).map_err(str::to_owned)?;
    check_manifest(sums, image_name, image_sha256, 64, sha256_record).map_err(str::to_owned)?;
    verify_signer(bundle_dir, keyring, document, primary_fingerprint)
        .map(|_| ()).map_err(str::to_owned)
}

/// Verify a FreeBSD clearsigned checksum document and read only the bytes that gpgv
/// authenticated. The installer must match the exact tagged SHA-256 record.
pub(super) fn verify_freebsd_sha256(
    bundle_dir: &Path,
    keyring: &[u8],
    signed_sums: &[u8],
    primary_fingerprint: &str,
    image_name: &str,
    image_sha256: &str,
) -> Result<(), String> {
    let document = SignedDocument::Cleartext(signed_sums);
    check_input(keyring, primary_fingerprint, document).map_err(str::to_owned)?;
    let verified = verify_signer(bundle_dir, keyring, document, primary_fingerprint)
        .map_err(str::to_owned)?
        .ok_or_else(|| "The FreeBSD signature verifier returned no signed text.".to_owned())?;
    check_manifest(&verified, image_name, image_sha256, 64, tagged_sha256_record).map_err(str::to_owned)
}

/// Return an authenticated publisher manifest. For a detached signature, return
/// the original bytes. For a clearsigned document, return only gpgv's signed text.
pub(super) fn verified_publisher_manifest(
    bundle_dir: &Path,
    keyring: &[u8],
    document: &[u8],
    signature: Option<&[u8]>,
    fingerprint: &str,
) -> Result<Vec<u8>, String> {
    let signed = match signature {
        Some(signature) => SignedDocument::Detached {
            sums: document,
            signature,
        },
        None => SignedDocument::Cleartext(document),
    };
    check_input(keyring, fingerprint, signed).map_err(str::to_owned)?;
    let verified = verify_signer(bundle_dir, keyring, signed, fingerprint).map_err(str::to_owned)?;
    match signature {
        Some(_) => Ok(document.to_vec()),
        None => verified.ok_or_else(|| "The publisher signature verifier returned no signed text.".to_owned()),
    }
}

/// Verify a detached binary signature. The caller holds the installer and its
/// directories in place through verification and subsequent publication.
pub(super) fn verify_publisher_asset(
    bundle_dir: &Path,
    keyring: &[u8],
    signature: &[u8],
    fingerprint: &str,
    file: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    if cancelled() {
        return Err(ASSET_CANCELLED.into());
    }
    let document = SignedDocument::Asset {
        signature,
        file,
        cancelled,
    };
    check_input(keyring, fingerprint, document).map_err(str::to_owned)?;
    verify_signer(bundle_dir, keyring, document, fingerprint)
        .map(|_| ())
        .map_err(str::to_owned)
}

#[derive(Clone, Copy)]
enum SignedDocument<'a> {
    Detached {
        sums: &'a [u8],
        signature: &'a [u8],
    },
    Cleartext(&'a [u8]),
    Asset {
        signature: &'a [u8],
        #[cfg_attr(not(windows), allow(dead_code))]
        file: &'a Path,
        #[cfg_attr(not(windows), allow(dead_code))]
        cancelled: &'a dyn Fn() -> bool,
    },
}

const ASSET_CANCELLED: &str = "Catalog download cancelled.";
const CLEAR_BEGIN: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNATURE_BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
const SIGNATURE_END: &str = "-----END PGP SIGNATURE-----";

fn check_input(keyring: &[u8], fingerprint: &str, document: SignedDocument<'_>) -> Check<()> {
    const INVALID: &str = "The catalog has invalid signature verification data.";
    if keyring.is_empty() || keyring.len() > MAX_KEYRING || !hex(fingerprint, 40) {
        return Err(INVALID);
    }
    match document {
        SignedDocument::Detached { sums, signature } => {
            if sums.is_empty() || sums.len() > MAX_SUMS || signature.is_empty() || signature.len() > MAX_SIGNATURE {
                return Err(INVALID);
            }
        }
        SignedDocument::Asset { signature, .. } => {
            if signature.is_empty() || signature.len() > MAX_SIGNATURE {
                return Err(INVALID);
            }
        }
        SignedDocument::Cleartext(signed) => {
            if signed.len() > MAX_SUMS + MAX_SIGNATURE { return Err(INVALID); }
            let text = std::str::from_utf8(signed).map_err(|_| INVALID)?;
            let mut lines = text.lines();
            if lines.next() != Some(CLEAR_BEGIN) {
                return Err(INVALID);
            }
            let mut opened = false;
            let mut closed = false;
            for line in lines.filter(|line| !line.is_empty()) {
                if closed || line == CLEAR_BEGIN { return Err(INVALID); }
                if line == SIGNATURE_BEGIN {
                    if opened { return Err(INVALID); }
                    opened = true;
                } else if line == SIGNATURE_END {
                    if !opened { return Err(INVALID); }
                    closed = true;
                }
            }
            if !closed { return Err(INVALID); }
        }
    }
    Ok(())
}

fn hex(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn checksum_record(line: &str) -> Option<(&str, &str)> {
    if let Some(tagged) = line.strip_prefix("SHA512 (") {
        return tagged.rsplit_once(") = ");
    }
    let (digest, marker_and_name) = (line.get(..128)?, line.get(128..)?);
    let name = marker_and_name.strip_prefix("  ").or_else(|| marker_and_name.strip_prefix(" *"))?;
    Some((name, digest))
}

fn sha256_record(line: &str) -> Option<(&str, &str)> {
    let (digest, marker_and_name) = (line.get(..64)?, line.get(64..)?);
    let name = marker_and_name.strip_prefix("  ").or_else(|| marker_and_name.strip_prefix(" *"))?;
    Some((name, digest))
}

fn tagged_sha256_record(line: &str) -> Option<(&str, &str)> {
    line.strip_prefix("SHA256 (")?.rsplit_once(") = ")
}

fn check_sha512(sums: &[u8], image_name: &str, image_sha512: &str) -> Check<()> {
    check_manifest(sums, image_name, image_sha512, 128, checksum_record)
}

fn check_manifest(
    sums: &[u8], image_name: &str, expected_digest: &str, length: usize,
    read_record: fn(&str) -> Option<(&str, &str)>,
) -> Check<()> {
    if !svm_core::library::ordinary_file_name(image_name) || !hex(expected_digest, length) {
        return Err("The catalog has an invalid image name or checksum.");
    }
    let text = std::str::from_utf8(sums).map_err(|_| "The signed checksum manifest is not UTF-8.")?;
    let mut match_digest = None;
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (name, digest) = read_record(line).ok_or("The signed checksum manifest has a malformed record.")?;
        if name.is_empty() || name.chars().any(char::is_control) || !hex(digest, length) {
            return Err("The signed checksum manifest has a malformed record.");
        }
        if name == image_name && match_digest.replace(digest).is_some() {
            return Err("The signed checksum manifest repeats the catalog image.");
        }
    }
    if !match_digest.is_some_and(|digest| digest.eq_ignore_ascii_case(expected_digest)) {
        return Err("The signed manifest does not match the catalog image's checksum.");
    }
    Ok(())
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
enum SignatureClass {
    DetachedManifest,
    Cleartext,
    BinaryAsset,
}

#[cfg(any(windows, test))]
fn check_status(status: &[u8], fingerprint: &str, class: SignatureClass) -> Check<()> {
    const INVALID: &str = "Publisher signature verification did not confirm the pinned signing key.";
    let cleartext = matches!(class, SignatureClass::Cleartext);
    let text = std::str::from_utf8(status).map_err(|_| INVALID)?;
    let mut good = false;
    let mut pinned = false;
    for line in text.lines() {
        let record = line.strip_prefix("[GNUPG:] ").ok_or(INVALID)?;
        let mut words = record.split_ascii_whitespace();
        match words.next().ok_or(INVALID)? {
            "NEWSIG" | "KEY_CONSIDERED" | "SIG_ID" | "TRUST_UNDEFINED"
            | "TRUST_MARGINAL" | "TRUST_FULLY" | "TRUST_ULTIMATE" => {}
            "PLAINTEXT" if cleartext && matches!(words.next(), Some("74" | "75"))
                && words.next().is_some_and(|stamp| stamp.parse::<u64>().is_ok()) => {}
            "PLAINTEXT_LENGTH" if cleartext && words.next()
                .and_then(|length| length.parse::<usize>().ok()).is_some_and(|length| length <= MAX_SUMS) => {}
            "GOODSIG" if !good && words.next().is_some_and(|key| hex(key, 16) || hex(key, 40)) => good = true,
            "VALIDSIG" if good && !pinned => {
                let fields: Vec<_> = words.collect();
                if !matches!(fields.len(), 9 | 10) {
                    return Err(INVALID);
                }
                let signer = fields[0];
                // GnuPG appends the primary key fingerprint when it knows it. Without
                // that field, only a signature made by the pinned primary itself qualifies.
                let primary = fields.get(9).copied().unwrap_or(signer);
                if !hex(signer, 40) || !hex(primary, 40) || !primary.eq_ignore_ascii_case(fingerprint)
                    || !matches!(fields[7], "8" | "9" | "10" | "11")
                    || !matches!(
                        (class, fields[8]),
                        (SignatureClass::DetachedManifest | SignatureClass::BinaryAsset, "00")
                            | (SignatureClass::DetachedManifest | SignatureClass::Cleartext, "01")
                    )
                {
                    return Err(INVALID);
                }
                pinned = true;
            }
            _ => return Err(INVALID),
        }
    }
    if pinned { Ok(()) } else { Err(INVALID) }
}

#[cfg(not(windows))]
fn verify_signer(_: &Path, _: &[u8], _: SignedDocument<'_>, _: &str) -> Check<Option<Vec<u8>>> {
    Err("The publisher signature verifier is unavailable on this host.")
}

#[cfg(not(windows))]
pub(super) fn require_verifier() -> Result<(), String> {
    Err("The publisher signature verifier is unavailable on this host.".into())
}

#[cfg(windows)]
pub(super) use windows::require_verifier;

#[cfg(windows)]
use windows::verify_signer;

#[cfg(windows)]
mod windows {
    use super::{ASSET_CANCELLED, Check, MAX_SUMS, SignatureClass, SignedDocument, check_status};
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Read, Write},
        os::windows::{fs::{MetadataExt, OpenOptionsExt}, process::CommandExt},
        path::{Component, Path, Prefix},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use svm_qemu::LocalFolder;

    const GPGV: &str = r"C:\Program Files\Git\usr\bin\gpgv.exe";
    const KEYRING: &str = "publisher.gpg";
    const MANIFEST: &str = "SHA512SUMS";
    const SIGNATURE: &str = "SHA512SUMS.sign";
    const CLEARSIGNED: &str = "checksums.asc";
    const SIGNED_TEXT: &str = "checksums.txt";
    const STATUS: &str = "status.txt";
    const MAX_STATUS: u64 = 32 * 1024;
    const UNAVAILABLE: &str = "The publisher signature verifier is unavailable on this host.";
    const STAGE_ERROR: &str = "The service could not prepare private publisher signature verification files.";
    const CLEAN_ERROR: &str = "The service could not clear its private publisher signature verification files.";
    const VERIFY_ERROR: &str = "Publisher signature verification failed.";

    struct Stage(Option<LocalFolder>);

    impl Stage {
        fn new(parent: &LocalFolder) -> Check<Self> {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|_| STAGE_ERROR)?;
            let label: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let folder = parent.create_private_child(&format!(".catalog-signature-{label}"))
                .map_err(|_| STAGE_ERROR)?;
            Ok(Self(Some(folder)))
        }

        fn path(&self) -> &Path {
            &self.0.as_ref().expect("private stage is open").path
        }

        fn clear(&mut self) -> Check<()> {
            let Some(folder) = &self.0 else { return Ok(()); };
            for name in [KEYRING, MANIFEST, SIGNATURE, CLEARSIGNED, SIGNED_TEXT, STATUS] {
                match fs::remove_file(folder.path.join(name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return Err(CLEAN_ERROR),
                }
            }
            let path = folder.path.clone();
            // Do not retry deleting children after relinquishing the held folder.
            drop(self.0.take());
            fs::remove_dir(path).map_err(|_| CLEAN_ERROR)
        }
    }

    impl Drop for Stage {
        fn drop(&mut self) { let _ = self.clear(); }
    }

    fn create_file(folder: &Path, name: &str) -> Check<File> {
        OpenOptions::new().write(true).create_new(true)
            .open(folder.join(name)).map_err(|_| STAGE_ERROR)
    }

    fn open_asset(path: &Path) -> Check<File> {
        const ASSET_ERROR: &str = "The installer could not be held read-only for signature verification.";
        if !path.is_absolute()
            || !matches!(path.components().next(), Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
            || !path.file_name().and_then(|name| name.to_str())
                .is_some_and(svm_core::library::ordinary_file_name)
        {
            return Err(ASSET_ERROR);
        }
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1) // FILE_SHARE_READ
            .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT
            .open(path)
            .map_err(|_| ASSET_ERROR)?;
        let metadata = file.metadata().map_err(|_| ASSET_ERROR)?;
        if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
            return Err(ASSET_ERROR);
        }
        Ok(file)
    }

    fn status_output(folder: &Path, exe: &Path, document: SignedDocument<'_>) -> Check<Vec<u8>> {
        let status = create_file(folder, STATUS)?;
        let path = folder.join(STATUS);
        let mut command = Command::new(exe);
        command.current_dir(folder)
            .args(["--homedir", ".", "--keyring", KEYRING, "--status-fd", "1"])
            .env_clear().env("LC_ALL", "C")
            .stdin(Stdio::null()).stdout(Stdio::from(status)).stderr(Stdio::null())
            .creation_flags(0x0800_0000);
        let cleartext = matches!(document, SignedDocument::Cleartext(_));
        let cancelled = match document {
            SignedDocument::Asset { file, cancelled, .. } => {
                if cancelled() {
                    return Err(ASSET_CANCELLED);
                }
                // Pass the read-only file handle instead of letting gpgv resolve a path.
                command.stdin(Stdio::from(open_asset(file)?)).args(["--", SIGNATURE, "-"]);
                Some(cancelled)
            }
            SignedDocument::Cleartext(_) => {
                command.args(["--output", SIGNED_TEXT, "--", CLEARSIGNED]);
                None
            }
            SignedDocument::Detached { .. } => {
                command.args(["--", SIGNATURE, MANIFEST]);
                None
            }
        };
        let signed_text = folder.join(SIGNED_TEXT);
        for name in ["SystemRoot", "WINDIR", "SystemDrive"] {
            if let Some(value) = std::env::var_os(name) { command.env(name, value); }
        }
        let mut child = command.spawn().map_err(|_| UNAVAILABLE)?;
        // A full installer may take substantially longer to hash than a manifest.
        let (timeout, poll_interval) = if cancelled.is_some() {
            (Duration::from_secs(15 * 60), Duration::from_millis(100))
        } else {
            (Duration::from_secs(10), Duration::from_millis(25))
        };
        let deadline = Instant::now() + timeout;
        let completion = loop {
            if cancelled.is_some_and(|check| check()) {
                break Err(ASSET_CANCELLED);
            }
            match child.try_wait() {
                Ok(Some(exit)) => break Ok(exit),
                Err(_) => break Err(VERIFY_ERROR),
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                break Err("Publisher signature verification timed out.");
            }
            match fs::metadata(&path) {
                Ok(meta) if meta.len() <= MAX_STATUS => {}
                _ => break Err(VERIFY_ERROR),
            }
            if cleartext {
                match fs::metadata(&signed_text) {
                    Ok(meta) if meta.len() <= MAX_SUMS as u64 => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    _ => break Err(VERIFY_ERROR),
                }
            }
            thread::sleep(poll_interval);
        };
        if completion.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if !completion?.success() { return Err(VERIFY_ERROR); }

        read_bounded(&path, MAX_STATUS)
    }

    fn read_bounded(path: &Path, max: u64) -> Check<Vec<u8>> {
        let mut output = Vec::new();
        File::open(path).map_err(|_| VERIFY_ERROR)?.take(max + 1)
            .read_to_end(&mut output).map_err(|_| VERIFY_ERROR)?;
        if output.len() as u64 > max { return Err(VERIFY_ERROR); }
        Ok(output)
    }

    fn executable() -> Check<&'static Path> {
        let exe = Path::new(GPGV);
        let meta = fs::symlink_metadata(exe).map_err(|_| UNAVAILABLE)?;
        if !meta.is_file() || meta.file_attributes() & 0x400 != 0 {
            return Err(UNAVAILABLE);
        }
        Ok(exe)
    }

    pub(in crate::machines) fn require_verifier() -> Result<(), String> {
        executable().map(|_| ()).map_err(str::to_owned)
    }

    pub(super) fn verify_signer(
        bundle_dir: &Path, keyring: &[u8], document: SignedDocument<'_>, fingerprint: &str,
    ) -> Check<Option<Vec<u8>>> {
        let exe = executable()?;
        let parent = LocalFolder::open(bundle_dir).map_err(|_| STAGE_ERROR)?;
        let mut stage = Stage::new(&parent)?;
        let result = (|| {
            create_file(stage.path(), KEYRING)?.write_all(keyring).map_err(|_| STAGE_ERROR)?;
            let class = match document {
                SignedDocument::Detached { sums, signature } => {
                    for (name, contents) in [(MANIFEST, sums), (SIGNATURE, signature)] {
                        create_file(stage.path(), name)?.write_all(contents).map_err(|_| STAGE_ERROR)?;
                    }
                    SignatureClass::DetachedManifest
                }
                SignedDocument::Cleartext(signed) => {
                    create_file(stage.path(), CLEARSIGNED)?.write_all(signed).map_err(|_| STAGE_ERROR)?;
                    SignatureClass::Cleartext
                }
                SignedDocument::Asset { signature, .. } => {
                    create_file(stage.path(), SIGNATURE)?.write_all(signature).map_err(|_| STAGE_ERROR)?;
                    SignatureClass::BinaryAsset
                }
            };
            check_status(&status_output(stage.path(), exe, document)?, fingerprint, class)?;
            if matches!(class, SignatureClass::Cleartext) {
                let text = read_bounded(&stage.path().join(SIGNED_TEXT), MAX_SUMS as u64)?;
                Ok(Some(text))
            } else {
                Ok(None)
            }
        })();
        stage.clear()?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnu_checksum_records_use_an_exact_unique_image_name() {
        let digest = "a4".repeat(64);
        let image = "debian-amd64-netinst.iso";
        let text = format!("{digest} *{image}\n{digest}  {image}.other\n");
        let tagged = format!("SHA512 ({image}) = {digest}\n");
        assert_eq!(check_sha512(text.as_bytes(), image, &digest), Ok(()));
        assert_eq!(check_sha512(tagged.as_bytes(), image, &digest), Ok(()));
        assert!(check_sha512(format!("{text}{tagged}").as_bytes(), image, &digest).is_err());
        assert!(check_sha512(text.as_bytes(), "Debian-amd64-netinst.iso", &digest).is_err());
        assert!(check_sha512(text.as_bytes(), image, &"c0".repeat(64)).is_err());
        assert!(check_sha512(format!("{digest} {image}\n").as_bytes(), image, &digest).is_err());
    }

    #[test]
    fn sha256_lists_accept_plain_and_binary_records_only() {
        let digest = "6a".repeat(32);
        let image = "kali-linux-2026.3-qemu-amd64.7z";
        let plain = format!("{digest}  {image}\n{digest}  {image}.torrent\n");
        let binary = format!("{digest} *{image}\n");
        assert_eq!(check_manifest(plain.as_bytes(), image, &digest, 64, sha256_record), Ok(()));
        assert_eq!(check_manifest(binary.as_bytes(), image, &digest, 64, sha256_record), Ok(()));
        assert!(check_manifest(format!("{plain}{binary}").as_bytes(), image, &digest, 64, sha256_record).is_err());
        assert!(check_manifest(format!("{digest} {image}\n").as_bytes(), image, &digest, 64, sha256_record).is_err());
        assert!(check_manifest(format!("SHA256 ({image}) = {digest}\n").as_bytes(), image, &digest, 64, sha256_record).is_err());
        assert!(check_manifest(plain.as_bytes(), image, &"0a".repeat(32), 64, sha256_record).is_err());
        assert!(check_manifest(plain.as_bytes(), "kali-linux-2026.3-qemu-amd64.7", &digest, 64, sha256_record).is_err());
    }

    #[test]
    fn freebsd_checksum_requires_tagged_records_and_one_signature_envelope() {
        let image = "FreeBSD-15.1-RELEASE-amd64-disc1.iso";
        let digest = "fa".repeat(32);
        let tagged = format!("SHA256 ({image}) = {digest}\n");
        let cleartext = format!("{CLEAR_BEGIN}\nHash: SHA512\n\n{tagged}{SIGNATURE_BEGIN}\npacket\n{SIGNATURE_END}\n");
        let primary = "82563B84D0620EDC0DFB86413897F2E22E65AD3F";
        assert_eq!(check_manifest(tagged.as_bytes(), image, &digest, 64, tagged_sha256_record), Ok(()));
        assert!(check_manifest(format!("{tagged}{tagged}").as_bytes(), image, &digest, 64, tagged_sha256_record).is_err());
        assert!(check_manifest(format!("{digest}  {image}").as_bytes(), image, &digest, 64, tagged_sha256_record).is_err());
        assert_eq!(check_input(b"keyring", primary, SignedDocument::Cleartext(cleartext.as_bytes())), Ok(()));
        let appended = format!("{cleartext}{tagged}");
        assert!(check_input(b"keyring", primary, SignedDocument::Cleartext(appended.as_bytes())).is_err());
    }

    #[test]
    fn gpgv_status_requires_the_pinned_primary_and_no_bad_status() {
        let primary = "DF9B9C49EAA9298432589D76DA87E80D6294BE9B";
        let signer = "B6ABAF940D3B67E7AA4602ACAD760ECD3D2FF001";
        let status = format!("[GNUPG:] GOODSIG AD760ECD3D2FF001 Debian CD\n\
            [GNUPG:] VALIDSIG {signer} 2026-11-19 1795050000 0 4 0 1 10 00 {primary}\n");
        use SignatureClass::{BinaryAsset, Cleartext, DetachedManifest};

        assert_eq!(check_status(status.as_bytes(), primary, DetachedManifest), Ok(()));
        assert_eq!(check_status(status.as_bytes(), primary, BinaryAsset), Ok(()));
        assert!(check_status(status.as_bytes(), primary, Cleartext).is_err());
        let text_signature = status.replace("10 00", "10 01");
        let cleartext = format!("[GNUPG:] PLAINTEXT 74 0 \n{text_signature}");
        assert_eq!(check_status(cleartext.as_bytes(), primary, Cleartext), Ok(()));
        assert!(check_status(cleartext.as_bytes(), primary, DetachedManifest).is_err());
        assert!(check_status(text_signature.as_bytes(), primary, BinaryAsset).is_err());
        assert!(check_status(status.as_bytes(), signer, DetachedManifest).is_err());
        assert!(check_status(status.replace("10 00", "2 00").as_bytes(), primary, DetachedManifest).is_err());
        assert!(check_status(format!("{status}[GNUPG:] BADSIG unexpected\n").as_bytes(), primary, DetachedManifest).is_err());
        assert!(check_status(format!("{status}{status}").as_bytes(), primary, DetachedManifest).is_err());
        assert!(check_status(b"[GNUPG:] GOODSIG AD760ECD3D2FF001 Debian CD\n", primary, DetachedManifest).is_err());
    }
}
