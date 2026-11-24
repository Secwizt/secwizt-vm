use crate::{agent::AgentCall, err, tools::io_error, ExecRequest, GuestAgentSession, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs::File, io::{Read, Seek, SeekFrom, Write}, time::{Duration, Instant}};
use svm_core::{engine::FileTransferUpdate, model::GuestFamily};

pub(crate) const CHUNK: usize = 1024 * 1024;
pub(crate) const ENCODED_CHUNK: usize = CHUNK.div_ceil(3) * 4;
const MAX_DOWNLOAD: u64 = 4 * 1024 * 1024 * 1024;
const DOWNLOAD_RESERVE: u64 = 64 * 1024 * 1024;
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);

fn check_download_size(total: u64, available: u64) -> Result<()> {
    if total > MAX_DOWNLOAD { return Err(err("QEMU guest downloads are limited to 4 GiB.")); }
    if total + DOWNLOAD_RESERVE > available {
        return Err(err("The destination volume needs enough free space for the file plus 64 MiB."));
    }
    Ok(())
}

fn check_download_time(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline { return Err(err("The QEMU file download exceeded its 15-minute limit.")); }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum FileCall {
    Open { path: String, write: bool },
    Read { handle: u64 },
    Write { handle: u64, data: String },
    Close { handle: u64 },
}

const LINUX_FILE: &str = r#"
set -eu
case "$1" in
    create)
        if [ -e "$3" ] || [ -L "$3" ]; then exit 1; fi
        umask 077
        mkdir -m 700 -- "$2"
        if ! ( : > "$2/data" ); then
            rmdir -- "$2"
            exit 1
        fi
        ;;
    size)
        [ -f "$2" ] || exit 1
        [ ! -L "$2" ] || exit 1
        stat -c %s -- "$2"
        ;;
    hash)
        [ -f "$2" ] || exit 1
        [ ! -L "$2" ] || exit 1
        sha256sum < "$2"
        ;;
    publish)
        [ -f "$2" ] || exit 1
        [ ! -L "$2" ] || exit 1
        ln -T -- "$2" "$3"
        ;;
    clean)
        [ ! -L "$2" ]
        if [ -d "$2" ]; then
            rm -f -- "$2/data"
            rmdir -- "$2"
        else
            [ ! -e "$2" ]
        fi
        ;;
    *) exit 1 ;;
esac
"#;

const WINDOWS_FILE: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
$r = [Console]::In.ReadToEnd() | ConvertFrom-Json
function Check-RegularFile([string]$path) {
    $attributes = [IO.File]::GetAttributes($path)
    $refused = [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint
    if ($attributes -band $refused) { throw 'A regular file is required.' }
}
switch ($r.action) {
    'create' {
        if ([IO.File]::Exists($r.target) -or [IO.Directory]::Exists($r.target)) { exit 1 }
        $file = [IO.File]::Open($r.path, 'CreateNew', 'Write', 'None')
        $file.Dispose()
    }
    'size' {
        Check-RegularFile $r.path
        $file = [IO.FileInfo]::new($r.path)
        [Console]::WriteLine($file.Length.ToString([Globalization.CultureInfo]::InvariantCulture))
    }
    'hash' {
        Check-RegularFile $r.path
        $file = [IO.File]::OpenRead($r.path)
        try {
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                [Console]::WriteLine([BitConverter]::ToString($sha.ComputeHash($file)).Replace('-', '').ToLowerInvariant())
            } finally { $sha.Dispose() }
        } finally { $file.Dispose() }
    }
    'publish' { [IO.File]::Move($r.path, $r.target) }
    'clean' { [IO.File]::Delete($r.path) }
    default { exit 1 }
}
"#;

struct Staging {
    root: String,
    data: String,
}

fn guest_path(family: GuestFamily, input: &str) -> Result<String> {
    let invalid = || err("Supply an absolute, regular file path inside the guest.");
    if input.is_empty() || input.len() > 4096 || input.contains('\0') {
        return Err(invalid());
    }
    match family {
        GuestFamily::Linux => {
            let tail = input.strip_prefix('/').ok_or_else(invalid)?;
            if tail.split('/').any(|part| part.is_empty() || matches!(part, "." | "..")) {
                return Err(invalid());
            }
            Ok(input.into())
        }
        GuestFamily::Windows => {
            let path = input.replace('/', "\\");
            let bytes = path.as_bytes();
            if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || &bytes[1..3] != b":\\" {
                return Err(invalid());
            }
            for part in path[3..].split('\\') {
                if part.is_empty() || part.ends_with(['.', ' '])
                    || part.chars().any(|character| character.is_control() || "<>:\"|?*".contains(character)) {
                    return Err(invalid());
                }
                let stem = part.split('.').next().unwrap_or_default().trim_end().to_ascii_uppercase();
                if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
                    || ["COM", "LPT"].into_iter().any(|prefix| {
                        matches!(stem.strip_prefix(prefix), Some("0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"))
                    }) {
                    return Err(invalid());
                }
            }
            Ok(path)
        }
        _ => Err(err("QEMU file transfers are available for Linux and Windows guests.")),
    }
}

impl GuestAgentSession {
    pub fn upload_file(
        &self, guest_path_input: &str, source: &mut File, progress: &mut dyn FnMut(FileTransferUpdate) -> Result<()>,
    ) -> Result<(u64, String)> {
        let path = guest_path(self.family, guest_path_input)?;
        let total = source.metadata().map_err(io_error)?.len();
        source.seek(SeekFrom::Start(0)).map_err(io_error)?;
        progress(FileTransferUpdate::Progress { bytes: 0, total: Some(total) })?;
        let staging = self.staging(&path)?;
        self.file_helper("create", &staging.root, Some(&path), None)?;
        let result = self.upload_staged(&staging, &path, source, total, progress);
        let cleanup = self.file_helper("clean", &staging.root, None, None);
        match (result, cleanup) {
            (result, Ok(_)) => result,
            (Ok(_), Err(_)) => Err(err("The guest file was published, but staging cleanup could not be confirmed.")),
            (Err(_), Err(_)) => Err(err("The guest did not confirm removal of the file transfer staging area.")),
        }
    }

    fn upload_staged(
        &self, staging: &Staging, path: &str, source: &mut File, total: u64, progress: &mut dyn FnMut(FileTransferUpdate) -> Result<()>,
    ) -> Result<(u64, String)> {
        let hash = self.with_guest_file(&staging.data, true, None, |handle| {
            let mut hash = Sha256::new();
            let mut bytes = 0;
            let mut buffer = vec![0; CHUNK];
            while bytes < total {
                let length = (total - bytes).min(CHUNK as u64) as usize;
                let chunk = &mut buffer[..length];
                source.read_exact(chunk).map_err(io_error)?;
                let response = self.transfer(FileCall::Write { handle, data: STANDARD.encode(&*chunk) }, None)?;
                if response["count"].as_u64() != Some(length as u64) {
                    return Err(err("The guest agent did not write the complete file chunk."));
                }
                hash.update(chunk);
                bytes += length as u64;
                progress(FileTransferUpdate::Progress { bytes, total: Some(total) })?;
            }
            if source.read(&mut [0; 1]).map_err(io_error)? != 0 {
                return Err(err("The host source changed size during the file transfer."));
            }
            Ok(format!("{:x}", hash.finalize()))
        })?;
        self.verify_hash(&staging.data, &hash, None)?;
        progress(FileTransferUpdate::Publish)?;
        self.file_helper("publish", &staging.data, Some(path), None)?;
        Ok((total, hash))
    }

    pub fn download_file(
        &self, guest_path_input: &str, destination: &mut File, available: u64, deadline: Instant,
        progress: &mut dyn FnMut(FileTransferUpdate) -> Result<()>,
    ) -> Result<(u64, String)> {
        let path = guest_path(self.family, guest_path_input)?;
        progress(FileTransferUpdate::Progress { bytes: 0, total: None })?;
        let total = self.file_helper("size", &path, None, Some(deadline))?.trim().parse::<u64>()
            .map_err(|_| err("The guest did not report a valid source file size."))?;
        check_download_size(total, available)?;
        check_download_time(deadline)?;
        progress(FileTransferUpdate::Progress { bytes: 0, total: Some(total) })?;
        destination.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let hash = self.with_guest_file(&path, false, Some(deadline), |handle| {
            let mut hash = Sha256::new();
            let mut bytes = 0;
            loop {
                let response = self.transfer(FileCall::Read { handle }, Some(deadline))?;
                check_download_time(deadline)?;
                let eof = response["eof"].as_bool()
                    .ok_or_else(|| err("The guest agent did not report the state of the open file."))?;
                let count = response["count"].as_u64().filter(|count| *count <= CHUNK as u64)
                    .ok_or_else(|| err("The guest agent did not report a valid file byte count."))?;
                let chunk = STANDARD.decode(response["buf-b64"].as_str().unwrap_or_default())
                    .map_err(|_| err("The guest agent returned invalid file data."))?;
                if count != chunk.len() as u64 || (count == 0 && !eof) {
                    return Err(err("The guest agent returned an incomplete file chunk."));
                }
                if count > total - bytes {
                    return Err(err("The guest source changed size during the file transfer."));
                }
                destination.write_all(&chunk).map_err(io_error)?;
                hash.update(&chunk);
                bytes += count;
                progress(FileTransferUpdate::Progress { bytes, total: Some(total) })?;
                if eof {
                    if bytes != total {
                        return Err(err("The guest source changed size during the file transfer."));
                    }
                    return Ok(format!("{:x}", hash.finalize()));
                }
            }
        })?;
        self.verify_hash(&path, &hash, Some(deadline))?;
        check_download_time(deadline)?;
        destination.flush().map_err(io_error)?;
        progress(FileTransferUpdate::Progress { bytes: total, total: Some(total) })?;
        Ok((total, hash))
    }

    fn staging(&self, destination: &str) -> Result<Staging> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| err("Could not name the guest file transfer staging area."))?;
        let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let separator = if self.family == GuestFamily::Windows { '\\' } else { '/' };
        let (parent, _) = destination.rsplit_once(separator).ok_or_else(|| err("The guest destination has no parent directory."))?;
        let root = format!("{parent}{separator}.svm-transfer-{id}");
        let data = if self.family == GuestFamily::Windows { root.clone() } else { format!("{root}/data") };
        Ok(Staging { root, data })
    }

    fn with_guest_file<T>(&self, path: &str, write: bool, deadline: Option<Instant>, perform: impl FnOnce(u64) -> Result<T>) -> Result<T> {
        let handle = self.transfer(FileCall::Open { path: path.to_owned(), write }, deadline)?
            .as_u64().ok_or_else(|| err("The guest agent did not return a file handle."))?;
        let result = perform(handle);
        self.transfer(FileCall::Close { handle }, None)
            .map_err(|_| err("The guest did not confirm closure of the file transfer handle."))?;
        result
    }

    fn transfer(&self, request: FileCall, deadline: Option<Instant>) -> Result<Value> {
        self.call_before(AgentCall::FileTransfer { request }, deadline)
    }

    fn verify_hash(&self, path: &str, expected: &str, deadline: Option<Instant>) -> Result<()> {
        let report = self.file_helper("hash", path, None, deadline)?;
        if report.split_ascii_whitespace().next() != Some(expected) {
            return Err(err("The host and guest file SHA-256 checksums did not match."));
        }
        Ok(())
    }

    fn file_helper(&self, action: &str, path: &str, target: Option<&str>, deadline: Option<Instant>) -> Result<String> {
        let (argv, stdin) = if self.family == GuestFamily::Windows {
            let encoded: Vec<u8> = WINDOWS_FILE.encode_utf16().flat_map(u16::to_le_bytes).collect();
            (vec![
                "powershell.exe".into(), "-NoProfile".into(), "-NonInteractive".into(),
                "-EncodedCommand".into(), STANDARD.encode(encoded),
            ], Some(json!({"action":action,"path":path,"target":target}).to_string()))
        } else {
            (vec![
                "/bin/sh".into(), "-c".into(), LINUX_FILE.into(), "svm-file-transfer".into(),
                action.into(), path.into(), target.unwrap_or_default().into(),
            ], None)
        };
        let timeout_sec = if action == "hash" { 30 } else { 5 };
        let request = ExecRequest { argv, timeout_sec, stdin };
        request.check()?;
        let response = self.call_before(AgentCall::Exec { request }, deadline)?;
        if response["exitCode"].as_i64() != Some(0) || response["stdoutTruncated"] == true {
            let failure = match action {
                "create" => "Could not create guest staging. Check the directory and whether the destination exists.",
                "publish" => "Could not publish the guest file without overwriting an existing file.",
                "size" | "hash" => "Could not read a regular guest file for verification.",
                _ => "Could not remove the guest file transfer staging area.",
            };
            return Err(err(failure));
        }
        response["stdout"].as_str().map(str::to_owned).ok_or_else(|| err("The guest file helper did not return valid output."))
    }
}

#[test]
fn qemu_download_enforces_size_space_and_time_limits() {
    assert!(check_download_size(MAX_DOWNLOAD, MAX_DOWNLOAD + DOWNLOAD_RESERVE).is_ok());
    assert!(check_download_size(MAX_DOWNLOAD + 1, u64::MAX).is_err());
    assert!(check_download_size(MAX_DOWNLOAD, MAX_DOWNLOAD + DOWNLOAD_RESERVE - 1).is_err());
    assert!(check_download_time(Instant::now()).is_err());
}
