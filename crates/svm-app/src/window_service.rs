use serde_json::Value;
use std::{
    env, os::windows::process::CommandExt, path::{Path, PathBuf}, process::{Child, Command, Stdio},
    sync::Mutex, thread, time::{Duration, Instant},
};
use svm::client::{Client, ClientError};

const HIDDEN: u32 = 0x0800_0000;

pub struct Service {
    home: PathBuf,
    // A timed-out startup may still be reconciling. A retry should observe that child.
    launched: Mutex<Option<Child>>,
    start_lock: Mutex<()>,
}

impl Service {
    pub fn new(home: PathBuf) -> Self {
        Self { home, launched: Mutex::new(None), start_lock: Mutex::new(()) }
    }
    pub fn home(&self) -> &Path { &self.home }

    fn healthy(&self) -> Result<bool, String> {
        let client = match Client::load(&self.home, None) {
            Ok(client) => client,
            Err(ClientError::Offline) => return Ok(false),
            Err(err) => return Err(err.to_string()),
        };
        match client.request_with_timeout("GET", "/v1/health", None, Duration::from_secs(2)) {
            Ok(r) if r.status == 200 => {
                let health: Value = serde_json::from_slice(&r.body)
                    .map_err(|_| "The service returned an unreadable health response.")?;
                Ok(health["status"] == "ok")
            }
            Ok(_) => Err("The service refused its health check. Verify the current account and service data folder.".into()),
            Err(ClientError::Offline) => Ok(false),
            Err(err) => Err(err.to_string()),
        }
    }

    pub fn start(&self) -> Result<(), String> {
        let _starting = self.start_lock.lock().map_err(|_| "Could not coordinate service startup.")?;
        if self.healthy()? { return Ok(()); }
        let mut child = self.launched.lock().map_err(|_| "Could not check the existing service process.")?;
        if let Some(process) = child.as_mut() {
            if process.try_wait().map_err(|_| "Could not inspect the service process.")?.is_some() { *child = None; }
        }
        if child.is_none() {
            let exe = env::current_exe().map_err(|_| "Cannot locate the desktop executable.")?.with_file_name("svmd.exe");
            if !exe.is_file() { return Err("Place svmd.exe beside svm-app.exe, then choose Start it.".into()); }
            *child = Some(Command::new(exe).env("SVM_HOME", &self.home).creation_flags(HIDDEN)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
                .map_err(|_| "Windows could not start svmd.exe. Check the installation and choose Start it.")?);
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.healthy()? { return Ok(()); }
            if let Some(process) = child.as_mut() {
                if let Some(status) = process.try_wait().map_err(|_| "Could not inspect the service process.")? {
                    *child = None;
                    // Another launcher may have acquired the data folder first.
                    if self.healthy()? { return Ok(()); }
                    return Err(format!("The service exited ({status}). Check the data folder and svmd.log, then choose Start it."));
                }
            }
            thread::sleep(Duration::from_millis(180));
        }
        Err("The service has not answered yet. Check svmd.log in the data folder, then choose Start it again.".into())
    }

    pub fn close_if_idle(&self) -> Result<(), String> {
        let client=match Client::load(&self.home,None) {
            Ok(client)=>client, Err(ClientError::Offline)=>return Ok(()), Err(e)=>return Err(e.to_string()),
        };
        let result=client.request("POST","/v1/shutdown",Some(&serde_json::json!({"ifIdle":true})));
        match result {
            Ok(reply) if reply.status==200=>Ok(()),
            Ok(reply) if reply.status==409 && serde_json::from_slice::<Value>(&reply.body)
                .is_ok_and(|v|v["error"]["code"]=="service_in_use")=>Ok(()),
            Err(ClientError::Offline)=>Ok(()),
            _=>Err("The service could not confirm it was idle and may still be running.".into()),
        }
    }
    pub fn stop_from_menu(&self) -> Result<(), String> {
        let r = Client::load(&self.home, None).map_err(|e| e.to_string())?
            .request("POST", "/v1/shutdown", None).map_err(|e| e.to_string())?;
        if (200..300).contains(&r.status) { Ok(()) } else { Err("The service declined the shutdown request.".into()) }
    }

    pub fn open_console(&self, id: &str, before_start: bool) -> Result<(), String> {
        // Treat the ID as a single URL segment. Its meaning belongs to the service.
        if !machine_id(id) { return Err("Choose a machine from the library.".into()); }
        let client = Client::load(&self.home, None).map_err(|e| e.to_string())?;
        let response = client.request_with_timeout("GET", &format!("/v1/machines/{id}/console"), None, Duration::from_secs(20))
            .map_err(|e| e.to_string())?;
        if client.contains_credential(&response.body) { return Err("The service returned console information that cannot be displayed.".into()); }
        let info: Value = serde_json::from_slice(&response.body).map_err(|_| "The console information was unreadable.")?;
        if !(200..300).contains(&response.status) {
            return Err(info["error"]["message"].as_str().unwrap_or("The console is unavailable.").to_owned());
        }
        let guid = console_target(&info, before_start)?;
        connect_viewer(guid)
    }

    pub fn capture_path(&self, machine: &str, capture: &str) -> Result<PathBuf, String> {
        if !machine_id(machine) || !crate::window_capture::capture_id(capture) {
            return Err("Choose a packet capture from its machine’s capture list.".into());
        }
        let unavailable = || "The service could not confirm this packet capture.".to_owned();
        let client = Client::load(&self.home, None).map_err(|_| unavailable())?;
        let route = format!("/v1/machines/{machine}/captures/{capture}/file");
        let reply = client.request_with_timeout("GET", &route, None, Duration::from_secs(5))
            .map_err(|_| unavailable())?;
        if reply.status != 200 || client.contains_credential(&reply.body) { return Err(unavailable()); }
        let info: Value = serde_json::from_slice(&reply.body).map_err(|_| unavailable())?;
        info["path"].as_str().map(PathBuf::from).ok_or_else(unavailable)
    }

    pub fn verify_clipboard(&self, id: &str) -> Result<(), String> {
        let unavailable = || "Clipboard copying requires a running QEMU console with sharing enabled.".to_owned();
        if !machine_id(id) { return Err(unavailable()); }
        let client = Client::load(&self.home, None).map_err(|_| unavailable())?;
        let reply = client.request_with_timeout("GET", &format!("/v1/machines/{id}"), None, Duration::from_secs(5))
            .map_err(|_| unavailable())?;
        if reply.status != 200 || client.contains_credential(&reply.body) { return Err(unavailable()); }
        let vm: Value = serde_json::from_slice(&reply.body).map_err(|_| unavailable())?;
        if vm["id"] != id || !active_clipboard(&vm) { return Err(unavailable()); }
        Ok(())
    }
}

fn machine_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256 && id != "." && !id.contains("..")
        && id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

fn active_clipboard(vm: &Value) -> bool {
    vm["engine"] == "QEMU" && vm["registration"] == "registered" && vm["shareClipboard"] == true
        && matches!(vm["state"].as_str(), Some("running" | "paused"))
}

fn console_target(info: &Value, before_start: bool) -> Result<&str, String> {
    let guid = info["hypervId"].as_str().filter(|s| canonical_guid(s))
        .ok_or("The service did not return a valid console identity.")?;
    match (info["state"].as_str(), before_start) {
        (Some("off" | "saved"), true) | (Some("running" | "paused"), false) => Ok(guid),
        (Some("off" | "saved"), false) => Err("The machine is stopped or saved. Choose Start and open console.".into()),
        (Some("running" | "paused"), true) => Err("The machine is already active. Choose Open console.".into()),
        _ => Err("The service could not verify the machine's power state.".into()),
    }
}

fn canonical_guid(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i,c)| {
        if matches!(i, 8 | 13 | 18 | 23) { c == b'-' } else { c.is_ascii_hexdigit() }
    })
}

// The helper receives only the system viewer path and a service-verified Hyper-V GUID.
// Attach to an existing viewer only when both its executable and local GUID arguments match.
const CONNECT_VIEWER: &str = r##"
$ErrorActionPreference = 'Stop'
$clock = [Diagnostics.Stopwatch]::StartNew()
$viewerPath = $env:SVM_VIEWER_PATH
$guid = ([guid]::ParseExact($env:SVM_VIEWER_GUID,'D')).ToString('D')
$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
$arguments = '^\s*(?:"[^"]+"|\S+)\s+"?localhost"?\s+-G\s+"?' + [regex]::Escape($guid) + '"?\s*$'
function Find-Viewer {
    if (-not [Diagnostics.Process]::GetProcessesByName('vmconnect').Length) { return }
    try {
        $rows = Get-CimInstance -ClassName Win32_Process -Filter "Name='vmconnect.exe' AND SessionId=$session" -Property ProcessId,ExecutablePath,CommandLine -OperationTimeoutSec 2
        foreach ($row in $rows) {
            if ($row.ExecutablePath -ieq $viewerPath -and $row.CommandLine -imatch $arguments) {
                try { return [Diagnostics.Process]::GetProcessById($row.ProcessId) } catch {}
            }
        }
    } catch { }
}
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SvmViewerWindow {
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] private static extern bool IsWindowEnabled(IntPtr window);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr window, System.Text.StringBuilder name, int length);
    public static bool IsViewerWindow(IntPtr window) {
        var name = new System.Text.StringBuilder(256);
        return IsWindowEnabled(window) && GetClassName(window,name,name.Capacity) > 0 && name.ToString() != "#32770";
    }
    [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr window, int state);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}
'@
    $process = Find-Viewer
    if ($clock.Elapsed.TotalSeconds -ge 12) { exit 4 }
    if (-not $process) {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $viewerPath
        $start.Arguments = 'localhost -G ' + $guid
        $start.UseShellExecute = $false
        $process = [Diagnostics.Process]::Start($start)
    }
    $hadWindow = $false
    while ($clock.Elapsed.TotalSeconds -lt 12) {
        $process.Refresh()
        if ($process.HasExited) {
            # Some viewer versions activate an existing instance and exit the new process.
            $process = Find-Viewer
            if (-not $process) { exit 3 }
        }
        $window = $process.MainWindowHandle
        if ($window -ne [IntPtr]::Zero -and $process.WaitForInputIdle(150) -and [SvmViewerWindow]::IsViewerWindow($window)) {
            $hadWindow = $true
            if ([SvmViewerWindow]::IsIconic($window)) { [void][SvmViewerWindow]::ShowWindowAsync($window,9) }
            if ([SvmViewerWindow]::GetForegroundWindow() -ne $window) { [void][SvmViewerWindow]::SetForegroundWindow($window) }
            if ([SvmViewerWindow]::GetForegroundWindow() -eq $window -and -not [SvmViewerWindow]::IsIconic($window)) { exit 0 }
        }
        Start-Sleep -Milliseconds 120
    }
    if ($hadWindow) { exit 5 }
    exit 4
} catch { exit 6 }
"##;

fn connect_viewer(guid: &str) -> Result<(),String> {
    let windows = PathBuf::from(env::var_os("SystemRoot").ok_or("Cannot locate the Windows system directory.")?);
    let viewer = windows.join(r"System32\vmconnect.exe");
    if !viewer.is_file() {
        return Err("Windows Virtual Machine Connection is unavailable. Check that Hyper-V Management Tools are installed.".into());
    }
    let mut helper = Command::new(windows.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", CONNECT_VIEWER])
        .env("SVM_VIEWER_PATH",viewer).env("SVM_VIEWER_GUID",guid).creation_flags(HIDDEN)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
        .map_err(|_| "Windows could not start the virtual machine viewer helper.")?;
    let status = svm_app::wait_for_viewer_helper(&mut helper, Duration::from_secs(16))
        .map_err(|_| "Windows could not check or close the virtual machine viewer helper.")?;
    match status.map(|status| status.code()) {
        None => Err("Windows did not confirm a ready console in time. Check the viewer before trying again.".into()),
        Some(Some(0)) => Ok(()),
        Some(Some(3)) => Err("Virtual Machine Connection closed before the console was ready. Check Hyper-V access and try again.".into()),
        Some(Some(5)) => Err("Windows opened the viewer but could not bring it to the front. Select its window, then try again.".into()),
        Some(Some(4)) => Err("The virtual machine viewer did not become ready in time. Check for an open viewer dialog and try again.".into()),
        _ => Err("Windows could not open or check this console. Check Hyper-V Management Tools and access to this machine.".into()),
    }
}

#[cfg(test)]
mod console_tests {
    use super::{active_clipboard, console_target};
    use serde_json::json;
    const GUID: &str = "01234567-89ab-cdef-0123-456789abcdef";

    #[test]
    fn pre_start_and_regular_viewer_require_the_expected_power_state() {
        for state in ["off", "saved", "running", "paused", "unknown"] {
            let info = json!({"hypervId":GUID,"state":state});
            assert_eq!(console_target(&info,true).ok(), matches!(state,"off"|"saved").then_some(GUID));
            assert_eq!(console_target(&info,false).ok(), matches!(state,"running"|"paused").then_some(GUID));
        }
    }
    #[test]
    fn clipboard_copy_requires_an_opted_in_active_qemu_registration() {
        let vm = json!({"engine":"QEMU","registration":"registered","state":"running","shareClipboard":true});
        assert!(active_clipboard(&vm));
        for (field, value) in [("engine", json!("Hyper-V")), ("registration", json!("unknown")),
            ("state", json!("off")), ("shareClipboard", json!(false)), ("shareClipboard", json!(null))] {
            let mut denied = vm.clone();
            denied[field] = value;
            assert!(!active_clipboard(&denied));
        }
    }

    #[test]
    fn viewer_rejects_unverified_arguments() {
        for invalid in ["", "Guest One", "01234567-89ab-cdef-0123-456789abcdex", "localhost -G guest"] {
            assert!(console_target(&json!({"hypervId":invalid,"state":"off"}),true).is_err());
        }
    }
}
