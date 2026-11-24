//! Sound for the Android QEMU profile: an output-only Intel HD Audio device that plays on
//! the PC's default output device, or an honest silent plan. Planning never stops a start.

use crate::{tools::{self, Tools}, Result};
use serde_json::{json, Value};

pub(crate) struct AudioPlan {
    pub(crate) args: Vec<String>,
    pub(crate) status: Value,
}

pub(crate) const PROFILE_SILENT: &str = "Sound is off for the legacy BIOS guest profile.";
pub(crate) fn silent_reason(architecture:svm_core::model::GuestArchitecture)->&'static str {
    if architecture==svm_core::model::GuestArchitecture::Aarch64 {"Sound is off for Emulated Arm."} else {PROFILE_SILENT}
}
pub(crate) fn for_guest(tools:&Tools,family:svm_core::model::GuestFamily, architecture:svm_core::model::GuestArchitecture)->AudioPlan {
    if family==svm_core::model::GuestFamily::Android {plan(tools)}
    else {AudioPlan{args:Vec::new(),status:json!({"enabled":false,"message":silent_reason(architecture)})}}
}

const BACKEND: &str = "dsound";
const AUDIODEV_ID: &str = "svm-snd0";

pub(crate) const ENABLED_MESSAGE: &str = "Sound plays on this PC's default output device.";
pub(crate) const NO_BACKEND_MESSAGE: &str = "Sound is off: this QEMU build has no Windows sound output (dsound).";
pub(crate) const NO_DEVICE_MESSAGE: &str = "Sound is off: this PC has no default playback device.";
pub(crate) const BACKEND_PROBE_MESSAGE: &str = "Sound is off: the QEMU sound check did not complete.";
pub(crate) const DEVICE_PROBE_MESSAGE: &str = "Sound is off: the default playback device could not be opened.";

/// DirectSound result for "no sound driver / no default playback device".
const DSERR_NODRIVER: u32 = 0x8878_0078;

/// Probes the selected QEMU build and the default DirectSound playback device, then decides.
pub(crate) fn plan(tools: &Tools) -> AudioPlan {
    let backends = tools.system.unchanged().and_then(|()| {
        let mut c = tools::command(&tools.system.path);
        c.args(["-audiodev", "help"]);
        tools::run(c, 5)
    });
    // Probe the host only when QEMU can play sound at all.
    let device = match &backends {
        Ok(text) if has_backend(text) => default_playback(),
        _ => Ok(String::new()),
    };
    decide(backends, device)
}

/// Opens the default DirectSound playback device (the same device QEMU's dsound backend uses)
/// and releases it at once. Nothing is played, no buffer is created and no device name or ID is read.
/// The crate forbids unsafe Rust, so the native call runs in a short Windows PowerShell child,
/// as the worker CPU limit does. Output is one line: `hr=0x........`.
#[cfg(windows)]
fn default_playback() -> Result<String> {
    let root = std::env::var_os("SystemRoot").ok_or_else(|| crate::err("Windows system folder is unavailable."))?;
    let mut c = tools::command(&std::path::PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"));
    // No double quotes anywhere: Windows command-line parsing strips them from -Command text.
    let script = r#"$ErrorActionPreference='Stop'
$q=[char]34
Add-Type -Namespace SvmAudio -Name Probe -MemberDefinition ('[DllImport('+$q+'dsound.dll'+$q+')] public static extern int DirectSoundCreate8(IntPtr guid, out IntPtr ds, IntPtr outer);')
$ds=[IntPtr]::Zero
$hr=[SvmAudio.Probe]::DirectSoundCreate8([IntPtr]::Zero,[ref]$ds,[IntPtr]::Zero)
if ($ds -ne [IntPtr]::Zero) { [void][Runtime.InteropServices.Marshal]::Release($ds) }
'hr=0x{0:X8}' -f $hr"#;
    c.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    tools::run(c, 15)
}
#[cfg(not(windows))]
fn default_playback() -> Result<String> { Ok(String::new()) }

fn has_backend(help: &str) -> bool {
    help.lines().any(|line| line.trim() == BACKEND)
}

/// Reads the probe's `hr=0x........` line. `None` when the output is not a result line.
fn probe_result(output: &str) -> Option<u32> {
    let line = output.lines().map(str::trim).rfind(|l| !l.is_empty())?;
    let hex = line.strip_prefix("hr=0x")?;
    if hex.len() != 8 { return None; }
    u32::from_str_radix(hex, 16).ok()
}

fn silent(message: &str) -> AudioPlan {
    AudioPlan { args: Vec::new(), status: json!({"enabled": false, "message": message}) }
}

/// Pure decision from the two probe results, so it can be tested without QEMU or PowerShell.
fn decide(backends: Result<String>, device: Result<String>) -> AudioPlan {
    let Ok(help) = backends else { return silent(BACKEND_PROBE_MESSAGE) };
    if !has_backend(&help) { return silent(NO_BACKEND_MESSAGE); }
    let Ok(output) = device else { return silent(DEVICE_PROBE_MESSAGE) };
    match probe_result(&output) {
        Some(0) => {}
        Some(DSERR_NODRIVER) => return silent(NO_DEVICE_MESSAGE),
        _ => return silent(DEVICE_PROBE_MESSAGE),
    }
    AudioPlan {
        // Output only: no capture voices on the host side, and an output-only codec in the guest.
        args: ["-audiodev", &format!("{BACKEND},id={AUDIODEV_ID},in.voices=0"), "-device", "intel-hda",
            "-device", &format!("hda-output,audiodev={AUDIODEV_ID}")].iter().map(|s| s.to_string()).collect(),
        status: json!({"enabled": true, "message": ENABLED_MESSAGE}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELP: &str = "Available audio drivers:\nnone\ndbus\ndsound\njack\nsdl\nspice\nwav\n";
    const OK: &str = "hr=0x00000000\r\n";

    fn failed() -> Result<String> { Err(crate::err("probe failed")) }
    fn text(s: &str) -> Result<String> { Ok(s.to_string()) }

    #[test]
    fn plays_through_an_output_only_path_when_the_default_device_opens() {
        let p = decide(text(HELP), text(OK));
        assert_eq!(p.status["enabled"], true);
        assert_eq!(p.status["message"], ENABLED_MESSAGE);
        assert_eq!(p.args, ["-audiodev", "dsound,id=svm-snd0,in.voices=0", "-device", "intel-hda", "-device", "hda-output,audiodev=svm-snd0"]);
        assert!(!p.args.iter().any(|a| a.contains("duplex") || a.contains("micro")), "no microphone path");
    }

    #[test]
    fn stays_silent_with_an_honest_reason() {
        let cases = [
            (failed(), text(OK), BACKEND_PROBE_MESSAGE),
            (text("Available audio drivers:\nnone\nsdl\nwav\n"), text(OK), NO_BACKEND_MESSAGE),
            (text(HELP), failed(), DEVICE_PROBE_MESSAGE),
            (text(HELP), text("hr=0x88780078"), NO_DEVICE_MESSAGE),
            (text(HELP), text("hr=0x80070005"), DEVICE_PROBE_MESSAGE),
            (text(HELP), text(""), DEVICE_PROBE_MESSAGE),
            (text(HELP), text("Add-Type : something went wrong"), DEVICE_PROBE_MESSAGE),
        ];
        for (backends, device, message) in cases {
            let p = decide(backends, device);
            assert!(p.args.is_empty());
            assert_eq!(p.status["enabled"], false);
            assert_eq!(p.status["message"], message);
        }
    }

    #[test]
    fn parsing_is_strict() {
        assert!(!has_backend("Available audio drivers:\ndsound-legacy\n"));
        assert!(has_backend("  dsound  \n"));
        assert_eq!(probe_result("noise\nhr=0x00000000\n\n"), Some(0), "the last non-empty line counts");
        assert_eq!(probe_result("hr=0x88780078"), Some(DSERR_NODRIVER));
        assert_eq!(probe_result("hr=0x0"), None, "exactly eight hex digits");
        assert_eq!(probe_result("hr=0xZZZZZZZZ"), None);
        assert_eq!(probe_result("hr=0x00000000\nwarning"), None, "a trailing line is not a result");
    }
}
