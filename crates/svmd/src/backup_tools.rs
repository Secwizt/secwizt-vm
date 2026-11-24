//! Fixed restic operations. Only restic connects age's stdout to its repository password.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{BufRead, BufReader, Read, Write}, process::{Command, Stdio}};
use svm_qemu::LocalFolder;

pub(super) const BINARIES: [&str; 3] = ["restic.exe", "age.exe", "age-plugin-yubikey.exe"];
const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const EXCLUDES: &[&str] = &["*.tmp", "*.lock", ".throwaway-*", ".ga*", ".qemu-staging-*",
    "qemu-run.json", "qemu-throwaway.json", "hyperv-throwaway.json", "throwaway-protected.json",
    "removal-complete.json", ".delete-pending.json", "qemu-agent*.json", "qemu-console.json", "qemu-outcome.json",
    "installer-first-boot.json", "backup-publishing.json", "last-restored-removal.json", ".svm-throwaway*"];

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Paths {
    pub tools: PathBuf, pub repository: PathBuf, pub identity: PathBuf, pub encrypted_password: PathBuf,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Settings { pub paths: Paths, hashes: [String; 3] }

struct Held {
    _folders: Vec<LocalFolder>,
    _files: Vec<File>,
}

fn path_text(path: &Path) -> Result<&str, ApiError> {
    let s = path.to_str().ok_or_else(|| bad("Choose a local Unicode path."))?;
    if s.contains(['"', '\'']) || s.chars().any(char::is_control) || !path.is_absolute()
        || path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(bad("Choose absolute local paths without quotes or control characters."));
    }
    if path.components().any(|part| matches!(part, std::path::Component::Normal(name) if !name.to_str().is_some_and(svm_core::library::ordinary_file_name))) {
        return Err(bad("Choose ordinary file and folder names on a local drive."));
    }
    Ok(s.strip_prefix(r"\\?\").unwrap_or(s))
}

pub(super) fn ordinary(path: &Path) -> Result<File, ApiError> {
    let mut open = OpenOptions::new();
    open.read(true);
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        open.share_mode(1).custom_flags(0x0020_0000);
    }
    let file = open.open(path).map_err(|_| refused("A required backup file is missing or in use."))?;
    let meta = file.metadata().map_err(io_error)?;
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 { return Err(refused("Backup files cannot be links.")); }
    }
    if !meta.is_file() || fs::symlink_metadata(path).map_err(io_error)?.file_type().is_symlink() {
        return Err(refused("Choose an ordinary file for this backup operation."));
    }
    Ok(file)
}

fn file_hash(file: &mut File) -> Result<String,ApiError> {
    let mut digest = Sha256::new();
    std::io::copy(file,&mut digest).map_err(io_error)?;
    Ok(format!("{:x}",digest.finalize()))
}

fn check_contents(folder: &Path) -> Result<(),ApiError> {
    let entries = fs::read_dir(folder).map_err(io_error)?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let name = entry.map_err(io_error)?.file_name().into_string().map_err(|_|refused("Unexpected file in the pinned tools folder."))?;
        if !BINARIES.contains(&name.as_str()) { return Err(refused("Unexpected file in the pinned tools folder.")); }
        names.insert(name);
    }
    if names.len() != BINARIES.len() { return Err(refused("A pinned backup tool is missing.")); }
    Ok(())
}

fn tool_copy_name(name: &str) -> bool {
    let hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if let Some(hash) = name.strip_prefix("backup-tools-") { return hash.len() == 64 && hex(hash); }
    if let Some(id) = name.strip_prefix(".backup-install-vm-") {
        let parts: Vec<_> = id.split('-').collect();
        return parts.len() == 3 && parts.iter().all(|part| part.len() <= 32 && hex(part));
    }
    false
}

/// Only retire application-owned directories and known tool files. Leave unexpected contents for the owner.
pub(super) fn prune_tool_copies(home: &Path, active: Option<&Settings>) -> Result<(), ApiError> {
    let root = LocalFolder::hold(home).map_err(engine)?;
    let current = active.map(|settings| settings.private_path(&root.path));
    'folders: for entry in fs::read_dir(&root.path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let path = entry.path();
        if Some(&path) == current.as_ref() || !entry.file_name().to_str().is_some_and(tool_copy_name) { continue; }
        let Ok(folder) = LocalFolder::hold(&path) else { continue; };
        if folder.verify_private().is_err() { continue; }
        let mut files = Vec::new();
        for child in fs::read_dir(&folder.path).map_err(io_error)? {
            let child = child.map_err(io_error)?;
            if !child.file_name().to_str().is_some_and(|name| BINARIES.contains(&name)) || ordinary(&child.path()).is_err() {
                continue 'folders;
            }
            files.push(child.path());
        }
        for file in files { fs::remove_file(file).map_err(io_error)?; }
        drop(folder);
        fs::remove_dir(&path).map_err(io_error)?;
    }
    Ok(())
}

impl Settings {
    pub(super) fn select(paths: Paths, home: &Path) -> Result<Self, ApiError> {
        let (settings, _source_handles) = Self::inspect(paths, home)?;
        let root = LocalFolder::hold(home).map_err(engine)?;
        let destination = settings.private_path(&root.path);
        if !destination.try_exists().map_err(io_error)? {
            let temp = root.create_private_child(&format!(".backup-install-{}", next_id()))
                .map_err(|_| refused("Could not create a private backup tools folder for the owner and SYSTEM."))?;
            let staging_path = temp.path.clone();
            let copied = (|| {
                for (i,name) in BINARIES.iter().enumerate() {
                    let mut input = ordinary(&settings.paths.tools.join(name))?;
                    let target = temp.path.join(name);
                    super::copy_private(&mut input, &target)?;
                    if file_hash(&mut ordinary(&target)?)? != settings.hashes[i] {
                        return Err(refused("The selected tools changed during copying."));
                    }
                }
                check_contents(&temp.path)
            })();
            drop(temp);
            // Settings/startup cleanup reopens and verifies abandoned staging directories before deleting files.
            copied?;
            fs::rename(&staging_path,&destination).map_err(io_error)?;
        }
        settings.for_launch(&root.path)?;
        Ok(settings)
    }

    fn private_path(&self, home: &Path) -> PathBuf {
        let digest = Sha256::digest(self.hashes.join("\n").as_bytes());
        home.join(format!("backup-tools-{digest:x}"))
    }

    fn for_launch(&self, home: &Path) -> Result<(Self,Held),ApiError> {
        let mut paths = self.paths.clone();
        paths.tools = self.private_path(home);
        let (pinned, handles) = Self::inspect(paths,home)?;
        handles._folders[0].verify_private().map_err(|_| refused("The pinned backup tools folder must be private to its owner and SYSTEM."))?;
        if pinned.hashes != self.hashes {
            return Err(refused("A pinned backup tool has changed. Inspect the private tool folder."));
        }
        check_contents(&pinned.paths.tools)?;
        Ok((pinned,handles))
    }

    pub(super) fn details(&self) -> Value {
        let hashes: BTreeMap<_,_> = BINARIES.iter().zip(&self.hashes).collect();
        json!({"configured":true,"paths":self.paths,"hashes":hashes})
    }

    fn inspect(input: Paths, home: &Path) -> Result<(Self, Held), ApiError> {
        for path in [&input.tools, &input.repository, &input.identity, &input.encrypted_password] { path_text(path)?; }
        if path_text(&input.tools)?.contains(';') { return Err(bad("Choose a tools folder without a semicolon.")); }
        let tools = LocalFolder::open(&input.tools).map_err(engine)?;
        let repository = LocalFolder::open(&input.repository).map_err(engine)?;
        let home = home.canonicalize().map_err(io_error)?;
        if repository.path.starts_with(&home) || home.starts_with(&repository.path) {
            return Err(bad("Choose a backup repository separate from the service and its library."));
        }
        let mut paths = input;
        paths.tools = tools.path.clone();
        paths.repository = repository.path.clone();
        let mut held = Held { _folders: vec![tools, repository], _files: Vec::new() };
        for path in [&mut paths.identity, &mut paths.encrypted_password] {
            let name = path.file_name().and_then(|n| n.to_str()).filter(|n| svm_core::library::ordinary_file_name(n))
                .ok_or_else(|| bad("Choose the YubiKey identity and encrypted password files."))?;
            let dir = LocalFolder::open(path.parent().ok_or_else(|| bad("Choose a local file."))?).map_err(engine)?;
            let full = dir.path.join(name);
            if full.starts_with(&paths.repository) || full.starts_with(&home) {
                return Err(bad("Keep the identity and encrypted password outside the repository and service folder."));
            }
            held._files.push(ordinary(&full)?);
            held._folders.push(dir);
            *path = full;
        }
        if paths.identity == paths.encrypted_password { return Err(bad("Choose two different credential files.")); }
        let mut hashes = [String::new(), String::new(), String::new()];
        for (name, hash) in BINARIES.iter().zip(&mut hashes) {
            let mut file = ordinary(&paths.tools.join(name))?;
            *hash = file_hash(&mut file)?;
            held._files.push(file);
        }
        Ok((Self { paths, hashes }, held))
    }
}

#[derive(Serialize, Deserialize)]
pub(super) enum Operation {
    Backup { machine: String, disk: String },
    List,
    Restore { snapshot: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Launch { pub lease_id: String, pub op: Operation }

pub(super) fn bounded(mut input: impl Read, limit: usize) -> Result<Vec<u8>, ApiError> {
    let mut bytes = Vec::new();
    input.by_ref().take(limit as u64 + 1).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() > limit {
        std::io::copy(&mut input, &mut std::io::sink()).map_err(io_error)?;
        return Err(refused("Backup tool output exceeded its limit."));
    }
    Ok(bytes)
}

// Long-running backups may print many progress records. Keep only the last nonempty record.
fn last_record(input: impl Read, mut display: impl Write) -> Result<Vec<u8>, ApiError> {
    const MAX_RECORD: usize = 16384;
    let mut reader = BufReader::new(input);
    let mut line = Vec::new();
    let mut last = Vec::new();
    loop {
        let chunk = reader.fill_buf().map_err(io_error)?;
        if chunk.is_empty() { break; }
        let newline = chunk.iter().position(|b| *b == b'\n');
        let length = newline.unwrap_or(chunk.len());
        let keep = length.min((MAX_RECORD+1).saturating_sub(line.len()));
        line.extend_from_slice(&chunk[..keep]);
        if newline.is_some() {
            if !line.is_empty() && line != b"\r" { std::mem::swap(&mut line, &mut last); }
            line.clear();
        }
        let consumed = length + usize::from(newline.is_some());
        // A closed window must not prevent us from draining the child's pipe.
        let _ = display.write_all(&chunk[..consumed]);
        reader.consume(consumed);
    }
    if !line.is_empty() { last=line; }
    if last.len() > MAX_RECORD { return Err(bad("Backup summary exceeds its limit.")); }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_is_streamed_and_the_final_record_is_bounded() {
        let mut stream = vec![b'x'; OUTPUT_LIMIT+100];
        stream.extend_from_slice(b"\nsummary\r\n\r\n");
        assert_eq!(last_record(&stream[..], std::io::sink()).unwrap(), b"summary\r");
        assert!(last_record(&stream[..OUTPUT_LIMIT], std::io::sink()).is_err());
        assert!(bounded(&stream[..], OUTPUT_LIMIT).is_err());
    }

    #[test]
    fn classifies_only_structured_matching_fatal_records() {
        let error = br#"{"message_type":"exit_error","code":1,"message":"Fatal: Resolving password failed: private diagnostic"}"#;
        assert_eq!(failure(Some(1), error, None), Failure::KeyStep);
        assert_eq!(failure(Some(3), error, None), Failure::Unknown);
        assert_eq!(failure(Some(12), b"", None), Failure::Repository);
        assert_eq!(failure(Some(1), b"Fatal: Resolving password failed:", None), Failure::Unknown);
        let stream = [b"progress\n".as_slice(), error, b"\n"].concat();
        let mut display = Vec::new();
        assert_eq!(last_record(&stream[..], &mut display).unwrap(), error);
        assert_eq!(display, stream);
    }
}

fn local_env(command: &mut Command) {
    command.env_clear();
    for key in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(key) { command.env(key, value); }
    }
    command.env("GOMAXPROCS","1").env("NoDefaultCurrentDirectoryInExePath","1");
}

fn command(settings: &Settings) -> Result<Command, ApiError> {
    let p = &settings.paths;
    let arg = |path: &Path| -> Result<String, ApiError> { Ok(format!("\"{}\"", path_text(path)?.replace('\\', "/"))) };
    let password_command = format!("{} -d -i {} {}", arg(&p.tools.join("age.exe"))?, arg(&p.identity)?, arg(&p.encrypted_password)?);
    let mut cmd = Command::new(p.tools.join("restic.exe"));
    local_env(&mut cmd);
    cmd.env("PATH", path_text(&p.tools)?).env("PATHEXT",".EXE").current_dir(&p.tools)
        .args(["--repo", &format!("local:{}", path_text(&p.repository)?), "--password-command", &password_command, "--no-cache", "--json"]);
    Ok(cmd)
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Failure { KeyStep, Repository, Restore, Unknown }

impl Failure {
    pub(super) fn message(self, restoring: bool) -> &'static str {
        match self {
            Self::KeyStep if restoring => "The YubiKey step did not finish (PIN or touch). Nothing was restored. Try again.",
            Self::KeyStep => "The YubiKey step did not finish. Check the message in the backup console.",
            Self::Repository => "Restic could not open or lock the repository. Check the message in the backup console.",
            Self::Restore => "Restic opened the repository but could not finish restoring the files. Check the message in the backup console.",
            Self::Unknown => "Restic did not finish. Check the error in the backup console.",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ToolResult {
    pub exit_code: Option<i32>,
    pub result: Value,
    pub reason: Option<Failure>,
}

fn failure(code: Option<i32>, last: &[u8], target: Option<&Path>) -> Failure {
    #[derive(Deserialize)]
    struct ExitError { message_type: String, code: i32, message: String }
    if matches!(code, Some(10..=12)) { return Failure::Repository; }
    if let Ok(error) = serde_json::from_slice::<ExitError>(last) {
        if error.message_type == "exit_error" && Some(error.code) == code
            && error.message.starts_with("Fatal: Resolving password failed:") { return Failure::KeyStep; }
    }
    if target.and_then(|p| fs::read_dir(p).ok()).is_some_and(|mut entries| matches!(entries.next(), Some(Ok(_)))) {
        return Failure::Restore;
    }
    Failure::Unknown
}

// Release all pins and leases before publishing the result or waiting for the owner.
pub fn console() -> Result<(), ApiError> {
    let launch = serde_json::from_slice(&bounded(std::io::stdin(), 65536)?).map_err(|_| bad("Invalid backup request."))?;
    let result = run_console(launch)?;
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &result).map_err(|_| bad("Backup result unavailable."))?;
    writeln!(out).and_then(|_|out.flush()).map_err(io_error)?;
    #[cfg(windows)]
    if result.reason.is_some() {
        let mut display = OpenOptions::new().write(true).open("CONOUT$").map_err(io_error)?;
        writeln!(display, "\nPress Enter to close.").map_err(io_error)?;
        let input = File::open("CONIN$").map_err(io_error)?;
        BufReader::new(input).skip_until(b'\n').map_err(io_error)?;
    }
    Ok(())
}

// Run in our own console so age has an owner-visible terminal even when the service is hidden.
fn run_console(launch: Launch) -> Result<ToolResult, ApiError> {
    let home = LocalFolder::hold(&crate::data_home()?).map_err(engine)?;
    let library = home.path.join("library");
    let catalog = super::load_catalog(&home.path)?.ok_or_else(||refused("No saved backup tools."))?;
    let authority = super::Lease::read(&home.path)?.filter(|owner|owner.id == launch.lease_id)
        .ok_or_else(||refused("The backup console no longer has an active operation."))?;
    let (verified, _pins) = catalog.settings.for_launch(&home.path)?;
    let mut identity = String::new();
    ordinary(&verified.paths.identity)?.take(16385).read_to_string(&mut identity).map_err(|_| bad("Invalid YubiKey identity file."))?;
    let keys: Vec<_> = identity.lines().map(str::trim).filter(|s| !s.is_empty() && !s.starts_with('#')).collect();
    if identity.len() > 16384 || keys.len() != 1 || !keys[0].starts_with("AGE-PLUGIN-YUBIKEY-1") ||
        !keys[0].bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-') {
        return Err(bad("Choose a single age-plugin-yubikey identity file."));
    }
    let owner = super::lease_path(&home.path, &launch.lease_id)?;
    let lease = ordinary(&owner)?;
    if lease.metadata().map_err(io_error)?.len() != 0 { return Err(refused("Invalid backup lease.")); }
    let mut cmd = command(&verified)?;
    let _folder;
    let mut target = None;
    let _disk;
    cmd.stdin(Stdio::from(lease));
    match &launch.op {
        Operation::Backup { machine, disk } => {
            if authority.kind != "backup" || authority.machine.as_ref() != Some(machine) || !id_ok(machine) || !matches!(disk.as_str(), "system.qcow2"|"system.vhdx") { return Err(bad("Invalid backup machine.")); }
            let bundle = svm_core::library::Library::open_stable(&library).map_err(store)?.bundle_path(machine).map_err(store)?;
            _folder = LocalFolder::hold(&bundle).map_err(engine)?;
            cmd.current_dir(&_folder.path).args(["backup","--read-concurrency","1","--tag","secwiz-vm","--tag",&format!("machine:{machine}")]);
            for item in EXCLUDES { cmd.args(["--iexclude", item]); }
            // This read-only handle also prevents an external writer during an orphaned restic run.
            _disk = ordinary(&_folder.path.join(disk))?;
            cmd.arg(".");
        }
        Operation::List => {
            if authority.kind != "list" || authority.machine.is_some() { return Err(refused("Invalid backup list operation.")); }
            cmd.args(["snapshots","--tag","secwiz-vm"]);
        }
        Operation::Restore { snapshot } => {
            if authority.kind != "restore" || authority.snapshot.as_ref() != Some(snapshot) || !snapshot_id(snapshot) || !catalog.snapshots.iter().any(|s|s.id==*snapshot && Some(&s.machine_id)==authority.machine.as_ref()) { return Err(bad("Invalid backup identifier.")); }
            let (_, stage) = super::Stage::pending(&library)?.ok_or_else(||refused("Missing restore staging receipt."))?;
            _folder = LocalFolder::hold(&stage.path).map_err(engine)?;
            let data = &target.insert(LocalFolder::hold(&_folder.path.join("data")).map_err(engine)?).path;
            let lease = ordinary(&_folder.path.join("lease"))?;
            cmd.args(["restore",snapshot,"--target",path_text(&data)?,"--verify"]);
            for file in ["/vm.json","/system.qcow2","/system.vhdx","/uefi-vars.fd","/qemu-vm.json"] { cmd.args(["--include", file]); }
            cmd.stdin(Stdio::from(lease));
        }
    }
    #[cfg(windows)]
    let display = {
        let mut terminal = OpenOptions::new().write(true).open("CONOUT$").map_err(|_| refused("The backup console is unavailable."))?;
        let subject = match &launch.op {
            Operation::Backup { .. } => "Back up machine",
            Operation::Restore { .. } => "Restore machine",
            Operation::List => "List backups",
        };
        let id = authority.machine.as_deref().unwrap_or("");
        if !id.is_empty() && !id_ok(id) { return Err(bad("Invalid machine identifier.")); }
        writeln!(terminal,"Secwiz VM | {subject} {id}").map_err(io_error)?;
        writeln!(terminal,"Type your YubiKey PIN when asked. When the key blinks, touch it. Close this window to cancel.").map_err(io_error)?;
        terminal
    };
    #[cfg(not(windows))]
    let display = std::io::stderr();
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|_| refused("The backup tool could not start."))?;
    let mut stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (output, diagnostic) = std::thread::scope(|scope| {
        // age reads the PIN directly from CONIN$. Only restic's diagnostic stream is relayed.
        let reader = scope.spawn(move || last_record(stderr, display));
        let output = match &launch.op {
            Operation::Backup { .. } => last_record(stdout, std::io::sink()),
            Operation::List => bounded(stdout, OUTPUT_LIMIT),
            Operation::Restore { .. } => std::io::copy(&mut stdout, &mut std::io::sink()).map(|_|Vec::new()).map_err(io_error),
        };
        (output, reader.join().ok().and_then(Result::ok).unwrap_or_default())
    });
    let status = child.wait().map_err(io_error)?;
    if !status.success() {
        // Restic can store a partial snapshot before a read failure. Return only its validated ID so the service can exclude it.
        let partial = if matches!(launch.op,Operation::Backup{..}) {
            output.as_ref().ok().and_then(|bytes|backup_summary(bytes).ok()).unwrap_or(Value::Null)
        } else { Value::Null };
        let reason = failure(status.code(), &diagnostic, target.as_ref().map(|folder|folder.path.as_path()));
        return Ok(ToolResult { exit_code:status.code(), result:partial, reason:Some(reason) });
    }
    let output = output?;
    let result = match launch.op {
        Operation::List => serde_json::to_value(super::parse_snapshots(&output)?).map_err(|_| bad("Invalid backup list."))?,
        Operation::Backup { .. } => backup_summary(&output)?,
        Operation::Restore { .. } => json!(true),
    };
    Ok(ToolResult { exit_code:Some(0), result, reason:None })
}

fn backup_summary(output:&[u8]) -> Result<Value,ApiError> {
    #[derive(Deserialize)]
    struct Message { message_type: String, snapshot_id: Option<String>, backup_end: Option<String>, total_bytes_processed:u64 }
    let msg: Message = serde_json::from_slice(output).map_err(|_| bad("Invalid backup summary."))?;
    let id = msg.snapshot_id.filter(|s| snapshot_id(s)).ok_or_else(|| bad("Missing snapshot identifier."))?;
    let time = msg.backup_end.filter(|s| valid_time(s)).ok_or_else(|| bad("Missing snapshot time."))?;
    if msg.message_type != "summary" { return Err(bad("Missing backup summary.")); }
    Ok(json!({"id":id,"time":time,"bytes":msg.total_bytes_processed}))
}

pub(super) fn execute(helper: &Path, home: &Path, launch: &Launch) -> Result<ToolResult, ApiError> {
    let mut process = Command::new(helper);
    local_env(&mut process);
    process.env("SVM_HOME",home).current_dir(helper.parent().ok_or_else(|| bad("Invalid backup console location."))?);
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        process.creation_flags(0x0000_0010); // CREATE_NEW_CONSOLE for the owner's PIN and touch.
    }
    let mut child = process.arg("--backup-console").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| refused("The backup console could not start."))?;
    let mut input = child.stdin.take().unwrap();
    let request = serde_json::to_vec(launch).map_err(|_| bad("Invalid backup request."))?;
    let sent = input.write_all(&request);
    drop(input);
    let mut frame = Vec::new();
    let count = BufReader::new(child.stdout.take().unwrap()).take(OUTPUT_LIMIT as u64 + 1)
        .read_until(b'\n', &mut frame).map_err(io_error)?;
    if count == 0 || sent.is_err() { return Err(refused("The backup console closed before reporting a result. Check the key, files and pinned tools.")); }
    if count > OUTPUT_LIMIT || frame.last() != Some(&b'\n') { return Err(refused("The backup console returned an invalid result.")); }
    let result: ToolResult = serde_json::from_slice(&frame).map_err(|_| refused("The backup console returned an invalid result."))?;
    // After a failed tool run the owner may keep reading the console. It holds no operation resources.
    if result.reason.is_none() && !child.wait().map_err(io_error)?.success() {
        return Err(refused("The backup console closed unexpectedly."));
    }
    Ok(result)
}
