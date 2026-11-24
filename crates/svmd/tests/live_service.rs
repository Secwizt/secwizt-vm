#![cfg(windows)]
#![forbid(unsafe_code)]
#![deny(warnings)]

use serde_json::{json, Value};
use std::{
    error::Error, fs, io,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use svm::client::{Client, Response};
use svm_hyperv::{HyperV, WindowsPowerShell};

#[path = "../../../tests/support/test_service.rs"]
mod test_service;
#[path = "../../../tests/support/hyperv_cleanup.rs"]
mod hyperv_cleanup;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn fail(message: &str) -> Box<dyn Error> { io::Error::other(message).into() }

// Read-only inventory deliberately includes unmarked objects. Never clean up another run's fixture.
fn check_host_empty() -> Result<Vec<u8>> {
    const INSPECT: &str = r#"
$ErrorActionPreference = 'Stop'
$vm = @(Get-VM | Where-Object { $_.Name -like 'svm-test-*' })
$sw = @(Get-VMSwitch | Where-Object { $_.Name -like 'SVM-test*' })
if ($vm.Count -or $sw.Count) { [Console]::Error.WriteLine('A matching test VM or switch is present.'); exit 1 }
$addresses = @(Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 |
    Sort-Object IPAddress,PrefixLength | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength })
[Console]::Out.Write(($addresses -join ','))
"#;
    let system = std::env::var_os("SystemRoot").ok_or_else(|| fail("Windows system directory is unavailable."))?;
    let powershell = PathBuf::from(system).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let output = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", INSPECT])
        .stdin(Stdio::null()).output()?;
    if !output.status.success() || output.stdout.is_empty() { return Err(fail("Could not verify the host inventory and Default Switch address.")); }
    Ok(output.stdout)
}

fn checked(response: Response) -> Result<Response> {
    if (200..300).contains(&response.status) { return Ok(response); }
    let parsed = serde_json::from_slice::<Value>(&response.body).ok();
    let message = parsed.as_ref().and_then(|v| v["error"]["message"].as_str()).unwrap_or("Request failed.");
    Err(fail(&format!("HTTP {}: {message}", response.status)))
}

struct Fixture {
    dir: PathBuf,
    machine: String,
    network: String,
    service: test_service::TestService,
    client: Option<Client>,
    vm_requested: bool,
    net_requested: bool,
}

impl Fixture {
    fn launch() -> Result<Self> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        // Hyper-V repeats these names in its paging paths. Keep them short on deep worktrees.
        let suffix = format!("{:x}", stamp & 0x0000_ffff_ffff_ffff);
        let id = format!("test-{suffix}");
        let dir = std::env::temp_dir().canonicalize()?.join(format!("s-{suffix}"));
        fs::create_dir(&dir)?;
        let service = match test_service::TestService::spawn(std::path::Path::new(env!("CARGO_BIN_EXE_svmd")), &dir) {
            Ok(process) => process,
            Err(error) => { fs::remove_dir(&dir)?; return Err(error.into()); }
        };
        Ok(Self {
            dir, machine: format!("{id}-vm"), network: format!("{id}-net"), service,
            client: None, vm_requested: false, net_requested: false,
        })
    }

    fn ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(status) = self.service.child.try_wait()? {
                return Err(fail(&format!("The service exited during startup with {status}.")));
            }
            if self.dir.join("api-port").is_file() {
                if let Ok(client) = Client::load(&self.dir, None) {
                    if client.request_with_timeout("GET", "/v1/health", None, Duration::from_secs(3)).is_ok_and(|r| r.status == 200) {
                        self.client = Some(client);
                        return Ok(());
                    }
                }
            }
            if Instant::now() >= deadline { return Err(fail("The test service did not become ready.")); }
            thread::sleep(Duration::from_millis(150));
        }
    }

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Response> {
        let client = self.client.as_ref().ok_or_else(|| fail("The test service is unavailable."))?;
        Ok(client.request(method, path, body.as_ref())?)
    }

    fn json(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let response = checked(self.request(method, path, body)?)?;
        if response.body.is_empty() { return Ok(Value::Null); }
        Ok(serde_json::from_slice(&response.body)?)
    }

    fn exercise(&mut self) -> Result<()> {
        self.ready()?;
        self.vm_requested = true;
        let vm = self.json("POST", "/v1/machines", Some(json!({
            "id":self.machine, "name":"Service hardware fixture", "os":"Empty firmware guest",
            "family":"other", "vcpu":1, "ramGb":1, "net":"nat"
        })))?;
        assert_eq!(vm["id"].as_str(), Some(self.machine.as_str()));
        let path = format!("/v1/machines/{}", self.machine);
        self.json("POST", &format!("{path}/start"), Some(json!({})))?;
        let frame = checked(self.request("GET", &format!("{path}/thumbnail"), None)?)?;
        assert_eq!(frame.headers.get("content-type").map(String::as_str), Some("application/octet-stream"));
        assert_eq!(frame.headers.get("x-pixel-format").map(String::as_str), Some("RGBA8"));
        assert_eq!(frame.headers["x-width"], "320");
        assert_eq!(frame.headers["x-height"], "240");
        assert_eq!(frame.body.len(), 320 * 240 * 4);
        let snap = self.json("POST", &format!("{path}/snapshots"), Some(json!({"name":"Firmware","withMemory":true})))?;
        let sid = snap["id"].as_str().ok_or_else(|| fail("The service did not return a checkpoint ID."))?;
        let snapshot = format!("{path}/snapshots/{sid}");
        self.json("POST", &format!("{snapshot}/revert"), Some(json!({})))?;
        self.json("DELETE", &snapshot, None)?;
        self.json("POST", &format!("{path}/stop"), Some(json!({})))?;
        self.json("DELETE", &path, None)?;
        self.vm_requested = false;
        self.net_requested = true;
        let net = self.json("POST", "/v1/networks", Some(json!({
            "id":self.network, "name":"Service routed fixture", "mode":"Routed"
        })))?;
        assert_eq!(net["id"].as_str(), Some(self.network.as_str()));
        assert_eq!(net["dhcp"], "waiting for setup");
        self.json("DELETE", &format!("/v1/networks/{}", self.network), None)?;
        self.net_requested = false;
        Ok(())
    }

    fn wire_offer(&mut self) -> Result<()> {
        self.ready()?;
        self.net_requested = true;
        self.json("POST", "/v1/networks", Some(json!({
            "id":self.network, "name":"Firmware DHCP fixture", "mode":"Link-local"
        })))?;
        let refresh = format!("/v1/networks/{}/refresh", self.network);
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let row = self.json("POST", &refresh, Some(json!({})))?;
            if row["dhcp"] == "serving" { break; }
            if Instant::now() >= deadline {
                return Err(fail(&format!("Link-local DHCP did not start: {}", row["dhcp"])));
            }
            thread::sleep(Duration::from_secs(2));
        }
        let read_traffic = |fixture: &Fixture| -> Result<(u64, Value)> {
            let rows = fixture.json("GET", "/v1/networks", None)?;
            let row = rows.as_array().and_then(|rows| rows.iter().find(|row| row["id"] == fixture.network))
                .ok_or_else(|| fail("The DHCP fixture network disappeared."))?;
            let traffic = &row["dhcpTraffic"];
            let offers = traffic["zeroSourceOffers"].as_u64()
                .ok_or_else(|| fail("The service did not report its zero-source DHCP offer count."))?;
            Ok((offers, traffic.clone()))
        };
        let (before, _) = read_traffic(self)?;
        self.vm_requested = true;
        self.json("POST", "/v1/machines", Some(json!({
            "id":self.machine, "name":"Firmware DHCP probe", "os":"Empty firmware guest",
            "family":"other", "vcpu":1, "ramGb":1, "secureBoot":false, "net":self.network
        })))?;
        self.json("POST", &format!("/v1/machines/{}/start", self.machine), Some(json!({})))?;
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            // Only a successful socket send for a DISCOVER from 0.0.0.0:68 increments this count.
            let (offers, traffic) = read_traffic(self)?;
            if offers > before { return Ok(()); }
            if Instant::now() >= deadline {
                return Err(fail(&format!("No new OFFER for a DISCOVER from 0.0.0.0:68. Counters: {traffic}")));
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        let mut problems = Vec::new();
        // The exercise can fail before startup publishes api-port. Finish startup so even
        // that case follows the ordinary authenticated shutdown path.
        if self.client.is_none() && self.service.child.try_wait()?.is_none() {
            if let Err(error) = self.ready() { problems.push(error.to_string()); }
        }
        let reachable = self.client.is_some() && self.service.child.try_wait()?.is_none();
        if !reachable && (self.vm_requested || self.net_requested) { problems.push("The fixture service exited before releasing its guest resources.".into()); }
        if reachable {
            if self.vm_requested {
                let path = format!("/v1/machines/{}", self.machine);
                if let Err(error) = (|| -> Result<()> {
                    let probe = self.request("GET", &path, None)?;
                    if probe.status == 404 { return Ok(()); }
                    let vm: Value = serde_json::from_slice(&checked(probe)?.body)?;
                    if vm["state"] != "off" { self.json("POST", &format!("{path}/stop"), Some(json!({})))?; }
                    let snapshots = self.json("GET", &format!("{path}/snapshots"), None)?;
                    for snapshot in snapshots.as_array().ok_or_else(|| fail("Invalid checkpoint inventory."))? {
                        let id = snapshot["id"].as_str().filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
                            .ok_or_else(|| fail("Unexpected fixture checkpoint ID."))?;
                        self.json("DELETE", &format!("{path}/snapshots/{id}"), None)?;
                    }
                    self.json("DELETE", &path, None)?;
                    Ok(())
                })() { problems.push(format!("Machine {}: {error}", self.machine)); }
            }
            if self.net_requested {
                if let Err(error) = self.request("DELETE", &format!("/v1/networks/{}", self.network), None)
                    .and_then(|r| if r.status == 404 { Ok(()) } else { checked(r).map(drop) }) {
                    problems.push(format!("Network {}: {error}", self.network));
                }
            }
            if let Err(e) = self.json("POST", "/v1/shutdown", Some(json!({}))) {
                problems.push(format!("Shutdown: {e}"));
            }
        }
        if let Err(error) = self.service.finish(Duration::from_secs(20)) { problems.push(error.to_string()); }
        if !problems.is_empty() {
            hyperv_cleanup::remove_owned(&self.dir, self.vm_requested.then_some(self.machine.as_str()),
                self.net_requested.then_some(self.network.as_str()))?;
        }
        fs::remove_dir_all(&self.dir)?;
        if problems.is_empty() { Ok(()) } else { Err(fail(&problems.join(" "))) }
    }
}

#[test]
#[ignore = "requires a real Hyper-V host and SVM_SERVICE_LIVE=1"]
fn owned_service_lifecycle() -> Result<()> {
    if std::env::var("SVM_SERVICE_LIVE").as_deref() != Ok("1") { return Ok(()); }
    run_live_fixture(Fixture::exercise)
}

#[test]
#[ignore = "requires a real Hyper-V firmware guest and SVM_DHCP_LIVE=1"]
fn link_local_firmware_discover_from_zero_gets_an_offer() -> Result<()> {
    if std::env::var("SVM_DHCP_LIVE").as_deref() != Ok("1") {
        return Err(fail("Set SVM_DHCP_LIVE=1 to run this Hyper-V DHCP test."));
    }
    run_live_fixture(Fixture::wire_offer)
}

#[test]
#[ignore = "requires a real Hyper-V host and SVM_STORAGE_LIVE=1"]
fn owned_storage_put_agrees_with_native_firmware_and_dvd() -> Result<()> {
    if std::env::var("SVM_STORAGE_LIVE").as_deref() != Ok("1") {
        return Err(fail("Set SVM_STORAGE_LIVE=1 to run this Hyper-V storage test."));
    }
    run_live_fixture(|fixture| {
        fixture.ready()?;
        let iso = fixture.dir.join("fixture.iso");
        let system = std::env::var_os("SystemRoot").ok_or_else(|| fail("Windows system directory is unavailable."))?;
        let powershell = PathBuf::from(system).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        let run = |script: &str| -> Result<Vec<u8>> {
            let output = Command::new(&powershell)
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .env("SVM_FIXTURE_ISO", &iso).env("SVM_FIXTURE_ID", &fixture.machine)
                .stdin(Stdio::null()).output()?;
            if !output.status.success() { return Err(fail(&String::from_utf8_lossy(&output.stderr))); }
            Ok(output.stdout)
        };
        // Windows' image writer makes a valid empty ISO without an installer or network access.
        run(r#"
$ErrorActionPreference = 'Stop'
$image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$image.FileSystemsToCreate = 1
$image.VolumeName = 'FIXTURE'
$image.Root.AddDirectory('EMPTY')
$result = $image.CreateResultImage()
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices.ComTypes;
public static class FixtureImage {
    public static void Save(object source, Stream output, int blocks, int blockSize) {
        IStream input = (IStream)source;
        byte[] sector = new byte[blockSize];
        for (int i=0; i<blocks; i++) {
            input.Read(sector, sector.Length, IntPtr.Zero);
            output.Write(sector, 0, sector.Length);
        }
    }
}
'@
$file = [IO.File]::Open($env:SVM_FIXTURE_ISO, 'CreateNew')
try { [FixtureImage]::Save($result.ImageStream, $file, $result.TotalBlocks, $result.BlockSize) } finally { $file.Dispose() }
"#)?;
        fixture.vm_requested = true;
        fixture.json("POST", "/v1/machines", Some(json!({
            "id":fixture.machine, "name":"Storage readback fixture", "vcpu":1, "ramGb":1,
            "net":"nat", "family":"other", "diskGb":1, "isoPath":iso
        })))?;
        let path = format!("/v1/machines/{}/storage", fixture.machine);
        let native = || -> Result<Value> {
            let bytes = run(r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$name = 'svm-' + $env:SVM_FIXTURE_ID
$vm = @(Get-VM -Name $name)
if ($vm.Count -ne 1 -or $vm[0].Name -cne $name -or $vm[0].Notes -cne ('secwiz-vm:' + $env:SVM_FIXTURE_ID)) { throw 'Unexpected fixture registration.' }
$dvd = @(Get-VMDvdDrive -VM $vm[0])
if ($dvd.Count -ne 1) { throw 'Expected exactly one fixture DVD slot.' }
$order = (Get-VMFirmware -VM $vm[0]).BootOrder
$media = $null
if (![string]::IsNullOrWhiteSpace([string]$dvd[0].Path)) { $media = [string]$dvd[0].Path }
[Console]::Out.Write((@{first=$order[0].Device.GetType().Name; media=$media} | ConvertTo-Json -Compress))
"#)?;
            Ok(serde_json::from_slice(&bytes)?)
        };
        for (edit, expected, mounted) in [
            (json!({"bootFirst":"disk"}), "disk", true),
            (json!({"bootFirst":"image"}), "image", true),
            (json!({"bootFirst":"disk"}), "disk", true),
            (json!({"isoPath":null}), "disk", false),
            (json!({"isoPath":null}), "disk", false),
        ] {
            let reply = fixture.json("PUT", &path, Some(edit))?;
            let observed = native()?;
            assert_eq!(observed["first"], if expected == "disk" { "HardDiskDrive" } else { "DvdDrive" });
            assert_eq!(reply["bootFirst"], expected);
            for (source, media) in [("native DVD", observed.get("media")), ("service", reply.get("isoPath"))] {
                if mounted {
                    let path = media.and_then(Value::as_str).ok_or_else(|| fail("Mounted media path missing."))?;
                    assert_eq!(PathBuf::from(path).canonicalize()?, iso.canonicalize()?);
                } else {
                    assert_eq!(media, Some(&Value::Null), "{source} must report empty media after eject");
                }
            }
        }
        Ok(())
    })
}


#[test]
#[ignore = "requires a real Hyper-V host, SVM_INSTALLED_LIVE=1 and SVM_INSTALLED_DISK"]
fn owned_installed_guest_storage_address_and_graceful_controls() -> Result<()> {
    if std::env::var("SVM_INSTALLED_LIVE").as_deref() != Ok("1") {
        return Err(fail("Set SVM_INSTALLED_LIVE=1 and select an installed Debian test disk."));
    }
    run_live_fixture(|fixture| {
        let source = PathBuf::from(std::env::var_os("SVM_INSTALLED_DISK").ok_or_else(|| fail("Select an installed Debian disk."))?).canonicalize()?;
        let source_before = fs::metadata(&source)?;
        fixture.ready()?;
        fixture.vm_requested = true;
        fixture.json("POST", "/v1/machines", Some(json!({
            "id":fixture.machine, "name":"Installed Debian fixture", "os":"Debian 13", "family":"linux",
            "vcpu":2, "ramGb":2, "secureBoot":true, "net":"nat", "diskPath":source
        })))?;
        let path = format!("/v1/machines/{}", fixture.machine);
        let storage = format!("{path}/storage");
        let disk = fixture.json("GET", &storage, None)?;
        let attached = PathBuf::from(disk["disks"][0]["path"].as_str().ok_or_else(|| fail("Missing disk attachment."))?).canonicalize()?;
        assert_ne!(attached, source);
        assert!(attached.starts_with(fixture.dir.join("library").canonicalize()?));

        // Each observation gets a new process. A long-lived Hyper-V reader can keep the pre-edit object.
        let powershell = |script: &str| -> Result<Value> {
            let root = std::env::var_os("SystemRoot").ok_or_else(|| fail("Windows system directory is unavailable."))?;
            let cmd = PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
            let output = Command::new(cmd).args(["-NoProfile","-NonInteractive","-Command",script])
                .env("SVM_FIXTURE_ID",&fixture.machine).stdin(Stdio::null()).output()?;
            if !output.status.success() { return Err(fail(&String::from_utf8_lossy(&output.stderr))); }
            Ok(serde_json::from_slice(&output.stdout)?)
        };
        let native = || powershell(r#"
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$v=Get-VM -Name ('svm-'+$env:SVM_FIXTURE_ID)
if ($v.Notes -cne ('secwiz-vm:'+$env:SVM_FIXTURE_ID)) { throw 'Fixture identity changed.' }
$entries=@((Get-VMFirmware -VM $v).BootOrder)
$nic=@(Get-VMNetworkAdapter -VM $v)
if ($nic.Count -ne 1) { throw 'Expected a single fixture NIC.' }
$result=@{type=[string]$entries[0].BootType; description=[string]$entries[0].Description;
    files=@($entries|Where-Object BootType -eq File|ForEach-Object { [string]$_.FirmwarePath });
    ips=@($nic[0].IPAddresses|Where-Object { $_ }); state=[string]$v.State}
[Console]::Out.Write((ConvertTo-Json $result -Compress))
"#);
        fixture.json("POST", &format!("{path}/start"), Some(json!({})))?;
        let ready = || -> Result<()> {
            let deadline = Instant::now()+Duration::from_secs(150);
            loop {
                let caps = fixture.json("GET",&format!("{path}/capabilities"),None)?;
                if caps["Shutdown"]["available"] == true && caps["Restart"]["available"] == true { return Ok(()); }
                if Instant::now() >= deadline { return Err(fail(&format!("Guest integration unavailable: {}",caps["Shutdown"]["reason"]))); }
                thread::sleep(Duration::from_secs(2));
            }
        };
        ready()?;
        let address_deadline = Instant::now() + Duration::from_secs(35);
        loop {
            let observed = native()?;
            let row = fixture.json("GET",&path,None)?;
            let guest_ips: Vec<std::net::Ipv4Addr> = observed["ips"].as_array().into_iter().flatten()
                .filter_map(|a| a.as_str()?.parse::<std::net::Ipv4Addr>().ok())
                .filter(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()).collect();
            let agrees = row["ip"].as_str().and_then(|ip| ip.parse().ok()).is_some_and(|ip| guest_ips.contains(&ip));
            if agrees {
                assert_eq!(row["addressSource"],"reported by the guest");
                eprintln!("Guest-reported IPv4 confirmed by a fresh native read.");
                break;
            }
            if Instant::now() >= address_deadline {
                assert!(guest_ips.is_empty() && row["ip"].is_null(), "Native and API IPv4 observations did not converge.");
                assert_eq!(row["addressSource"],"not reported by the guest");
                eprintln!("Hyper-V returned no guest IPv4 address; the API reported that absence.");
                break;
            }
            thread::sleep(Duration::from_secs(2));
        }
        let sent = fixture.json("POST", &format!("{path}/keys"), Some(json!({"keys":["Enter"]})))?;
        assert_eq!(sent["sent"],1);
        fixture.json("POST",&format!("{path}/restart"),Some(json!({})))?;
        // A guest restart can leave the VM object running throughout. Wait for its integration to return.
        thread::sleep(Duration::from_secs(10));
        ready()?;
        fixture.json("POST",&format!("{path}/shutdown"),Some(json!({})))?;
        assert_eq!(native()?["state"],"Off");
        assert_eq!(fixture.json("GET",&path,None)?["state"],"off");

        let before = native()?;
        let row = fixture.json("GET",&storage,None)?;
        if before["type"] == "File" {
            assert_eq!(row["bootFirst"],"system");
            assert_eq!(row["bootDescription"],before["description"]);
        }
        eprintln!("Installed disk native first boot type: {}. Preserved firmware file entries: {}.",
            before["type"],before["files"].as_array().map_or(0,Vec::len));
        let edited = fixture.json("PUT",&storage,Some(json!({"bootFirst":"disk"})))?;
        assert_eq!(edited["bootFirst"],"disk");
        assert_eq!(native()?["files"],before["files"]);
        if let Some(iso) = std::env::var_os("SVM_INSTALLED_ISO") {
            fixture.json("PUT",&storage,Some(json!({"isoPath":PathBuf::from(iso)})))?;
            assert_eq!(fixture.json("PUT",&storage,Some(json!({"bootFirst":"image"})))?["bootFirst"],"image");
            assert_eq!(native()?["files"],before["files"]);
        }
        let source_after=fs::metadata(source)?;
        assert_eq!(source_before.len(),source_after.len());
        assert_eq!(source_before.modified()?,source_after.modified()?);
        Ok(())
    })
}

fn run_live_fixture(exercise: fn(&mut Fixture) -> Result<()>) -> Result<()> {
    let addresses_before = check_host_empty()?;
    let verifier = HyperV::new(WindowsPowerShell::default(), []);
    let default_before = verifier.default_switch_info()?;
    let mut fixture = Fixture::launch()?;
    // A failed assertion still runs cleanup before rethrowing the test failure.
    let exercised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exercise(&mut fixture)));
    let cleanup = fixture.cleanup();
    let default_after = verifier.default_switch_info()?;
    assert_eq!(default_before, default_after, "Default Switch configuration changed");
    cleanup?;
    assert!(addresses_before == check_host_empty()?, "Default Switch IPv4 configuration changed");
    match exercised { Ok(result) => result, Err(panic) => std::panic::resume_unwind(panic) }
}
