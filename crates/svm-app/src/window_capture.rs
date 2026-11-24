use serde::Deserialize;
use std::{
    env, fs::{File, OpenOptions}, io::Read,
    os::windows::{fs::{MetadataExt, OpenOptionsExt}, process::CommandExt},
    path::{Component, Path, PathBuf}, process::{Command, Stdio},
};

const REPARSE_POINT: u32 = 0x400;
const READ_ATTRIBUTES: u32 = 0x80;
const SHARE_READ: u32 = 1;
const SHARE_WRITE: u32 = 2;
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const BACKUP_SEMANTICS: u32 = 0x0200_0000;
const CAPTURE_UNAVAILABLE: &str = "The capture is no longer an ordinary file in this machine’s library bundle.";

pub enum Viewer { Wireshark, Explorer }

struct HeldPath {
    path: PathBuf,
    // Keep the checked file and directories from being overwritten or moved through process creation.
    _handles: Vec<File>,
}

pub fn capture_id(id: &str) -> bool {
    id.len() <= 100 && id.strip_prefix("capture-").is_some_and(|tail| {
        tail.as_bytes().first().is_some_and(u8::is_ascii_digit)
            && tail.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && tail.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    })
}

fn local_display(path: &Path) -> Option<&str> {
    let rendered = path.to_str()?;
    let display = rendered.strip_prefix(r"\\?\").unwrap_or(rendered);
    let bytes = display.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\'
        || display.chars().any(|c| c.is_control() || r#"/"*?<>|"#.contains(c))
        || display[3..].split('\\').any(|part| matches!(part, "." | "..") || part.contains(':')) {
        return None;
    }
    Some(display)
}

fn capture_location(home: &Path, returned: &Path, capture: &str) -> Option<(PathBuf, PathBuf)> {
    let library = home.join("library");
    let inside = Path::new(local_display(returned)?).strip_prefix(local_display(&library)?).ok()?;
    let file_name = format!("{capture}.pcap");
    let mut parts = inside.components();
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(Component::Normal(bundle)), Some(Component::Normal(folder)), Some(Component::Normal(file)), None)
            if Path::new(bundle).extension().is_some_and(|suffix| suffix == "swvm")
                && folder == "captures" && file == file_name.as_str() => {
            let bundle = library.join(bundle);
            let file = bundle.join("captures").join(file_name);
            Some((bundle, file))
        }
        _ => None,
    }
}

fn hold_directory(path: &Path) -> Option<File> {
    let handle = OpenOptions::new().access_mode(READ_ATTRIBUTES).share_mode(SHARE_READ | SHARE_WRITE)
        .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT).open(path).ok()?;
    let info = handle.metadata().ok()?;
    (info.is_dir() && info.file_attributes() & REPARSE_POINT == 0).then_some(handle)
}

fn hold_file(path: &Path) -> Option<File> {
    let handle = OpenOptions::new().read(true).share_mode(SHARE_READ)
        .custom_flags(OPEN_REPARSE_POINT).open(path).ok()?;
    let info = handle.metadata().ok()?;
    (info.is_file() && info.file_attributes() & REPARSE_POINT == 0).then_some(handle)
}

fn hold_path(path: PathBuf) -> Option<HeldPath> {
    local_display(&path)?;
    let directories: Vec<_> = path.parent()?.ancestors().collect();
    let mut handles = directories.into_iter().rev().map(hold_directory).collect::<Option<Vec<_>>>()?;
    handles.push(hold_file(&path)?);
    Some(HeldPath { path, _handles: handles })
}

#[derive(Deserialize)]
struct BundleIdentity {
    id: String,
    engine: String,
}

fn owned_bundle(record: impl Read, machine: &str) -> bool {
    serde_json::from_reader::<_, BundleIdentity>(record.take(128 * 1024))
        .is_ok_and(|info| info.id == machine && info.engine == "QEMU")
}

fn get_capture(home: &Path, machine: &str, capture: &str, path: &Path) -> Result<HeldPath, String> {
    let home = home.canonicalize().map_err(|_| CAPTURE_UNAVAILABLE)?;
    let (bundle, capture_path) = capture_location(&home, path, capture).ok_or(CAPTURE_UNAVAILABLE)?;
    let mut held = hold_path(capture_path).ok_or(CAPTURE_UNAVAILABLE)?;
    let identity = hold_file(&bundle.join("vm.json")).ok_or(CAPTURE_UNAVAILABLE)?;
    if !owned_bundle(&identity, machine) { return Err(CAPTURE_UNAVAILABLE.into()); }
    held._handles.push(identity);
    Ok(held)
}

fn wireshark() -> Option<HeldPath> {
    ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"].into_iter()
        .filter_map(env::var_os)
        .find_map(|root| hold_path(PathBuf::from(root).join("Wireshark").join("Wireshark.exe")))
}

pub fn available() -> bool { wireshark().is_some() }

pub fn open(home: &Path, machine: &str, capture: &str, path: &Path, viewer: Viewer) -> Result<(), String> {
    let checked = get_capture(home, machine, capture, path)?;
    let filename = local_display(&checked.path).ok_or(CAPTURE_UNAVAILABLE)?;
    let program = match viewer {
        Viewer::Wireshark => wireshark().ok_or("Wireshark is not installed in Program Files. Choose Show file.")?,
        Viewer::Explorer => env::var_os("SystemRoot").and_then(|root| hold_path(PathBuf::from(root).join("explorer.exe")))
            .ok_or("Windows Explorer is unavailable.")?,
    };
    let exe = local_display(&program.path).ok_or("The capture viewer is unavailable.")?;
    let mut command = Command::new(exe);
    command.current_dir(program.path.parent().ok_or("The capture viewer is unavailable.")?);
    match viewer {
        Viewer::Wireshark => { command.arg("-r").arg(&checked.path); }
        // Explorer parses the comma and quoted filename together. local_display rejects quotes and switches.
        Viewer::Explorer => { command.raw_arg(format!("/select,\"{filename}\"")); }
    }
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
        .map_err(|_| "Windows could not open this packet capture.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{capture_id, capture_location, local_display, owned_bundle};
    use std::path::Path;

    const CAPTURE: &str = "capture-1760000000000-42-1000-0-user";

    #[test]
    fn capture_ids_are_plain_generated_tokens() {
        assert!(capture_id(CAPTURE));
        for invalid in ["", "../capture-1", "capture-1.pcap", "capture-1/2", "capture-1%2f",
            "capture-1?extra", "capture-1-", "capture-1-END", "other-1"] {
            assert!(!capture_id(invalid), "{invalid}");
        }
        assert!(!capture_id(&format!("capture-{}", "1".repeat(100))));
    }

    #[test]
    fn capture_path_must_be_the_exact_file_inside_a_direct_library_bundle() {
        let home = Path::new(r"\\?\C:\service");
        for bundle in ["machine-id.swvm", "Original display name.swvm"] {
            let returned = format!(r"C:\service\library\{bundle}\captures\{CAPTURE}.pcap");
            let (owner, file) = capture_location(home, Path::new(&returned), CAPTURE).unwrap();
            assert_eq!(owner, home.join("library").join(bundle));
            assert_eq!(file, owner.join("captures").join(format!("{CAPTURE}.pcap")));
        }
        for bad in [
            format!(r"C:\other\library\vm.swvm\captures\{CAPTURE}.pcap"),
            format!(r"C:\service\library\trash\vm.swvm\captures\{CAPTURE}.pcap"),
            format!(r"C:\service\library\vm.swvm\captures\..\captures\{CAPTURE}.pcap"),
            format!(r"C:\service\library\vm.swvm\captures\{CAPTURE}.pcap:stream"),
            format!(r"C:\service\library\vm.swvm\captures\{CAPTURE}-copy.pcap"),
            format!(r"C:\service\library\vm.swvm\other\{CAPTURE}.pcap"),
            format!(r"\\?\UNC\server\share\vm.swvm\captures\{CAPTURE}.pcap"),
        ] {
            assert!(capture_location(home, Path::new(&bad), CAPTURE).is_none(), "{bad}");
        }
        assert!(local_display(Path::new(r#"C:\unsafe"argument\file.pcap"#)).is_none());
        assert!(local_display(Path::new(r"C:relative.pcap")).is_none());
    }

    #[test]
    fn the_bundle_record_must_identify_the_requested_qemu_machine() {
        let valid = br#"{"id":"machine-a","engine":"QEMU","name":"Original display name"}"#;
        assert!(owned_bundle(&valid[..], "machine-a"));
        assert!(!owned_bundle(&valid[..], "machine-b"));
        let wrong = br#"{"id":"machine-a","engine":"Hyper-V"}"#;
        assert!(!owned_bundle(&wrong[..], "machine-a"));
        let duplicate = br#"{"id":"machine-b","id":"machine-a","engine":"QEMU"}"#;
        assert!(!owned_bundle(&duplicate[..], "machine-a"));
    }
}
