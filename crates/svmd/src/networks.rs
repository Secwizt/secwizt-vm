#[path = "network_io.rs"]
mod network_io;

use crate::{ApiError, Events, Reply};
use network_io::{Activity, Listener};
use crate::dns_io::DnsListener;
use std::sync::{Arc,RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet}, fs::{self, OpenOptions}, io::{self, Write},
    net::Ipv4Addr, path::{Path, PathBuf}, time::{Duration, Instant},
};
use svm_core::{
    dhcp::{Config, LeaseState, LeaseTable}, engine::EngineError,
    identity::Subnet, model::{Network, NetworkMode, Vm},
};
use svm_hyperv::{HyperV, PsRunner, Script, WindowsPowerShell};
use sha2::{Digest, Sha256};

const SETUP: &str = r"Paste the command into Windows PowerShell opened as administrator, then refresh the network. It checks setup\svm-admin-setup.ps1 against this build, copies it to a folder only administrators can change, and runs that copy.";
/// The administrator script this build was made with. The setup command pins its SHA-256, so a script
/// that is missing, changed or planted beside svmd.exe (a folder the user's own programs can write)
/// is refused before anything runs elevated.
const ADMIN_SETUP: &[u8] = include_bytes!("../../../setup/svm-admin-setup.ps1");
const NAT: &str = "nat";
const ROUTED_RANGE: &str = "10.77.0.0/16";

#[derive(Clone, Deserialize)]
pub struct NatRule {
    pub name: String,
    pub prefix: String,
}

impl NatRule {
    fn matches_shared_config(&self) -> bool {
        self.prefix == ROUTED_RANGE && self.name.strip_prefix("SVM-Routed-").is_some_and(|id| {
            id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Interface {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub alias: String,
    pub switch_guid: Option<String>,
    pub preferred: bool,
    #[serde(default)]
    pub resolvers:Vec<Ipv4Addr>,
    #[serde(default)]
    pub nat_rules: Option<Vec<NatRule>>,
}
impl Interface {
    fn overlaps(&self, network: Subnet) -> bool {
        let host = u32::from(self.address);
        let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix.min(32))).unwrap_or(0);
        (host & mask) <= u32::from(network.broadcast()) && (host | !mask) >= u32::from(network.base())
    }
}

pub trait Switches: Send {
    fn addresses(&self) -> Result<Vec<Interface>, ApiError>;
    fn bridges(&self) -> Result<Value,ApiError> {Ok(json!({"adapters":[]}))}
    fn resolve_bridge(&self,_:&Network)->Result<Value,ApiError> {Err(ApiError::invalid("A wired external switch is required."))}
    fn ensure(&mut self, network: &Network) -> Result<(String, bool), ApiError>;
    fn remove(&mut self, network: &Network, guid: &str) -> Result<(), ApiError>;
}

pub struct HyperSwitches { driver: HyperV<WindowsPowerShell> }
impl HyperSwitches {
    pub fn new() -> Self { Self { driver: HyperV::new(WindowsPowerShell::default(), []) } }
}
fn switch_error(operation: &str, e: EngineError) -> ApiError {
    let status = match &e { EngineError::Permission(_) => 403, EngineError::Invalid(_) => 409, _ => 503 };
    ApiError::new(status, "switch_operation", format!("The service could not {operation}. {e}"))
}
impl Switches for HyperSwitches {
    fn bridges(&self)->Result<Value,ApiError> {
        self.driver.bridge_adapters().map_err(|e|switch_error("list wired bridge adapters",e))
    }
    fn resolve_bridge(&self,n:&Network)->Result<Value,ApiError> {
        self.driver.resolve_bridge(n).map_err(|e|switch_error("validate the external switch",e))
    }
    fn addresses(&self) -> Result<Vec<Interface>, ApiError> {
        let data = WindowsPowerShell::default().run(Script::NetworkAddresses, &json!({}))
            .map_err(|e| switch_error("read the host IPv4 interfaces", e))?;
        serde_json::from_value(data).map_err(|_| ApiError::new(503, "host_addresses", "Windows returned unreadable interface addresses."))
    }
    fn ensure(&mut self, network: &Network) -> Result<(String, bool), ApiError> {
        let receipt = self.driver.ensure_switch(network).map_err(|e| switch_error("create the internal switch", e))?;
        Ok((receipt.guid, receipt.created))
    }
    fn remove(&mut self, network: &Network, guid: &str) -> Result<(), ApiError> {
        match self.driver.remove_switch_if_same(network, Some(guid)) {
            Ok(()) | Err(EngineError::Missing(_)) => Ok(()),
            Err(e) => Err(switch_error("remove the recorded switch", e)),
        }
    }
}

#[derive(Default)]
pub struct FakeSwitches {
    switches: BTreeMap<String, String>,
    pub interfaces: Vec<Interface>,
}
impl Switches for FakeSwitches {
    fn bridges(&self)->Result<Value,ApiError> {
        Ok(json!({"adapters":[{"id":"aabbccdd-0000-4000-8000-123456789abc","name":"Lab Ethernet","available":true,"bound":true,"reasons":[],"switchGuid":"aabbccdd-0000-4000-8000-098765432abc","switchName":"Shared Ethernet"}]}))
    }
    fn resolve_bridge(&self,n:&Network)->Result<Value,ApiError> {
        let link=n.bridge.as_ref().ok_or_else(ApiError::missing)?;
        Ok(json!({"guid":link.switch_guid,"name":"Shared Ethernet","owned":false}))
    }
    fn addresses(&self) -> Result<Vec<Interface>, ApiError> { Ok(self.interfaces.clone()) }
    fn ensure(&mut self, n: &Network) -> Result<(String, bool), ApiError> {
        let created = !self.switches.contains_key(&n.id);
        let guid = self.switches.entry(n.id.clone()).or_insert_with(|| format!("test-{}", n.id));
        Ok((guid.clone(), created))
    }
    fn remove(&mut self, n: &Network, guid: &str) -> Result<(), ApiError> {
        if self.switches.get(&n.id).is_some_and(|current| current != guid) {
            return Err(ApiError::new(409, "ownership", "The switch registration has changed."));
        }
        self.switches.remove(&n.id);
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Saved {
    #[serde(flatten)]
    network: Network,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    switch_guid: Option<String>,
}

struct Runtime {
    saved: Saved,
    table: Option<Arc<LeaseTable>>,
    activity: Arc<Activity>,
    listener: Option<Listener>,
    dns:Option<DnsListener>,
    dns_address:Option<Ipv4Addr>,
    host_address:Option<Ipv4Addr>,
    upstream:Vec<Ipv4Addr>,
    dns_status:String,
    nat_status:String,
    bridge_reasons:Vec<String>,
    nat_state: &'static str,
    status: String,
    dirty: bool,
}

fn lease_path(home: &Path, id: &str) -> PathBuf { home.join(format!("leases-{id}.json")) }
fn valid_id(id: &str) -> bool {
    id.len() <= 80 && id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) && !id.ends_with('.')
}
fn valid_guid(s:&str)->bool {
    s.len()==36 && s.bytes().enumerate().all(|(i,c)|if matches!(i,8|13|18|23) {c==b'-'} else {c.is_ascii_hexdigit()})
}
fn managed(mode: NetworkMode) -> bool {
    matches!(mode, NetworkMode::Routed | NetworkMode::HostOnly | NetworkMode::Isolated | NetworkMode::LinkLocal)
}
fn contains(parent: Subnet, child: Subnet) -> bool {
    parent.base() <= child.base() && child.broadcast() <= parent.broadcast()
}

fn aggregate_conflict(rows: &BTreeMap<String, Runtime>, interfaces: &[Interface], range: Subnet) -> Option<String> {
    for row in rows.values() {
        let net = &row.saved.network;
        if managed(net.mode) && net.subnet.overlaps(range)
            && (net.mode != NetworkMode::Routed || !contains(range, net.subnet)) {
            return Some(format!("Saved network {} ({}) overlaps the shared routed range. Its addresses are unchanged.", net.id, String::from(net.subnet)));
        }
    }
    for nic in interfaces.iter().filter(|i| i.overlaps(range)) {
        let owned_gateway = rows.values().any(|row| {
            let net = &row.saved.network;
            net.mode == NetworkMode::Routed && contains(range, net.subnet) && net.gateway == Some(nic.address)
                && u32::from(nic.prefix) == u32::from(net.subnet.mask()).count_ones()
                && nic.alias == format!("vEthernet (SVM-{})", net.id) && nic.switch_guid.is_some()
                && nic.switch_guid.as_ref().zip(row.saved.switch_guid.as_ref()).is_some_and(|(a,b)| a.eq_ignore_ascii_case(b))
        });
        if !owned_gateway {
            return Some(format!("Host interface {} ({}/{}) overlaps the shared routed range.", nic.alias, nic.address, nic.prefix));
        }
    }
    None
}

fn nat_status(subnet: Subnet, range: Subnet, conflict: Option<&str>, rules: Option<&[NatRule]>,
    gateway_ready: bool) -> (&'static str, String) {
    if !subnet.overlaps(range) {
        return ("outside-range", format!("Local network. The app supplies no internet outside {ROUTED_RANGE}."));
    }
    if let Some(reason) = conflict { return ("conflict", format!("Shared routed internet is unavailable. {reason}")); }
    match rules {
        None => ("unknown", "No app-provided internet has been verified. Windows NAT settings could not be read.".into()),
        Some([]) => ("needs-setup", "No app-provided internet. Run administrator setup to configure the shared Windows NAT and gateway.".into()),
        Some([rule]) if rule.matches_shared_config() && gateway_ready =>
            ("matching", format!("Windows reports the expected NAT for {ROUTED_RANGE} and the switch gateway is configured. Guest internet has not been tested.")),
        Some([rule]) if rule.matches_shared_config() =>
            ("needs-setup", "No app-provided internet yet. The shared Windows NAT exists, but the switch gateway is missing or unverified.".into()),
        Some(_) => ("conflict", "Another or older Windows NAT configuration is present. The shared configuration could not be verified. Existing NAT settings are preserved.".into()),
    }
}

fn bad_lease(e: svm_core::Error) -> ApiError {
    ApiError::new(500, "lease_table", format!("The service could not read or save the guest reservations. {e}"))
}
fn nat() -> Result<Saved, ApiError> {
    // This range is used for stable library identities only. Windows allocates the real NAT addresses.
    let subnet = "192.0.2.0/24".parse().map_err(bad_lease)?;
    Ok(Saved { network: Network { bridge:None, id: NAT.into(), name: "NAT".into(), mode: NetworkMode::Nat,
        subnet, gateway: Some(Ipv4Addr::new(192,0,2,1)), dhcp: true,
        note: "Windows assigns the address on the Default Switch.".into() }, switch_guid: None })
}
fn runtime(home: &Path, saved: Saved) -> Result<Runtime, ApiError> {
    let n = &saved.network;
    if !valid_id(&n.id) || (n.mode == NetworkMode::Nat && n.id != NAT)
        || (n.id == NAT && n.mode != NetworkMode::Nat) || (!matches!(n.mode,NetworkMode::Nat|NetworkMode::Bridged) && !managed(n.mode))
        || (n.mode==NetworkMode::Bridged)!=n.bridge.is_some() {
        return Err(ApiError::new(500, "network_record", "The saved network definition is invalid."));
    }
    let mut table = None;
    if managed(n.mode) {
        let path = lease_path(home, &n.id);
        let range: Subnet = ROUTED_RANGE.parse().map_err(bad_lease)?;
        let inside_range = contains(range, n.subnet);
        let router = if n.mode == NetworkMode::Routed && inside_range { n.gateway } else { None };
        let leases = if path.try_exists().map_err(ApiError::storage)? {
            let leases = LeaseTable::load(&path).map_err(bad_lease)?;
            let config = leases.config().map_err(bad_lease)?;
            // Older Routed networks outside the shared range may have a manual route in use.
            let legacy_router = n.mode == NetworkMode::Routed && !inside_range && config.router == n.gateway;
            if config.subnet != n.subnet || (config.router != router && !legacy_router) {
                return Err(ApiError::new(409, "lease_subnet", "Saved leases belong to a different network configuration."));
            }
            leases
        } else {
            LeaseTable::new(Config { subnet: n.subnet, router, dns: None, lease_seconds: 3600, boot_file: None }).map_err(bad_lease)?
        };
        table = Some(Arc::new(leases));
    }
    let status = if managed(n.mode) { "waiting for setup" } else if n.mode==NetworkMode::Bridged { "awaiting bridge verification" } else { "managed by Windows" }.into();
    Ok(Runtime { saved, table, activity: Arc::default(), listener:None,dns:None,dns_address:None,host_address:None,upstream:Vec::new(),dns_status:"waiting for host address".into(),nat_status:"No app-provided internet has been verified.".into(),nat_state:"unknown",bridge_reasons:Vec::new(),status,dirty:false })
}

pub struct Networks {
    home: PathBuf,
    switches: Box<dyn Switches>,
    rows: BTreeMap<String, Runtime>,
    names:Arc<RwLock<BTreeMap<String,Ipv4Addr>>>,
    next_refresh: Instant,
}

impl Networks {
    pub fn open(home: &Path, switches: Box<dyn Switches>, events: &mut Events) -> Result<Self, ApiError> {
        let path = home.join("networks.json");
        let mut saved: Vec<Saved> = match fs::read(path) {
            Ok(data) => serde_json::from_slice(&data).map_err(|_| ApiError::new(500,"network_record","The saved network definitions are unreadable."))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(ApiError::storage(e)),
        };
        let missing_nat = !saved.iter().any(|s| s.network.id == NAT);
        if missing_nat { saved.push(nat()?); }
        let mut rows = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for item in saved {
            if !ids.insert(item.network.id.to_ascii_lowercase()) {
                return Err(ApiError::new(500, "network_record", "Network IDs in the saved library are duplicated."));
            }
            rows.insert(item.network.id.clone(), runtime(home, item)?);
        }
        let mut networks = Self { home: home.into(), switches, rows, names:Arc::new(RwLock::new(BTreeMap::new())), next_refresh: Instant::now() };
        if missing_nat { networks.save()?; }
        networks.refresh(events)?;
        let bridges:Vec<_>=networks.rows.iter().filter(|(_,r)|r.saved.network.bridge.is_some()).map(|(id,_)|id.clone()).collect();
        for id in bridges {let _=networks.refresh_bridge(&id);}
        Ok(networks)
    }

    fn save(&self) -> Result<(), ApiError> {
        let path = self.home.join("networks.json");
        let rows: Vec<_> = self.rows.values().map(|r| &r.saved).collect();
        let data = serde_json::to_vec_pretty(&rows).map_err(|_| ApiError::new(500,"network_record","Could not encode the network definitions."))?;
        let mut attempt = 0u64;
        let (temp, mut file) = loop {
            let temp = self.home.join(format!(".networks.{}.{attempt}.tmp", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).open(&temp) {
                Ok(file) => break (temp, file),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => { attempt += 1; },
                Err(e) => return Err(ApiError::storage(e)),
            }
        };
        let result = file.write_all(&data).and_then(|()| file.sync_all());
        drop(file);
        if let Err(e) = result.and_then(|()| fs::rename(&temp, &path)) {
            let _ = fs::remove_file(&temp);
            return Err(ApiError::storage(e));
        }
        Ok(())
    }

    pub fn definitions(&self) -> Vec<Network> {
        self.rows.values().map(|row|{
            let mut n=row.saved.network.clone();
            if n.mode==NetworkMode::LinkLocal {n.gateway=row.host_address; }
            if row.status!="router DHCP" {if let Some(link)=n.bridge.as_mut() {link.switch_guid=None;}}
            n
        }).collect()
    }

    pub fn sync_guests(&mut self, guests: &[Vm]) -> Result<(), ApiError> {
        let mut names=BTreeMap::new();
        for vm in guests {
            let name=vm.dns.trim_end_matches('.').to_ascii_lowercase();
            if name.ends_with(".vm.lan") && self.rows.get(&vm.net).is_some_and(|r|managed(r.saved.network.mode)) {
                names.insert(name,vm.ip);
            }
        }
        *self.names.write().map_err(|_|ApiError::new(500,"dns_table","The guest name table is unavailable."))?=names;
        for (id, row) in &mut self.rows {
            let Some(table) = &row.table else { continue };
            let desired = guests.iter().filter(|v| &v.net == id).map(|v| (v.mac,v.ip)).collect();
            if table.sync_reservations(&desired).map_err(bad_lease)? { row.dirty = true; }
            if row.dirty {
                table.save(&lease_path(&self.home, id)).map_err(bad_lease)?;
                row.dirty = false;
            }
        }
        Ok(())
    }

    /// One line for an elevated Windows PowerShell. It reads the script once, checks those bytes against
    /// the pinned SHA-256, writes them into `%ProgramFiles%\SecwizVM Setup` (created with the
    /// Administrators-and-SYSTEM-only ACL that the script itself requires) and runs that copy with no
    /// profile. Nothing in a user-writable folder runs elevated, even if it changes after the check.
    /// Folder paths come from the Windows API, not from environment variables the user can set.
    fn setup_command(with_service:bool) -> String {
        let executable = std::env::current_exe().ok();
        let script = executable.as_deref().and_then(Path::parent).map(|bin| {
            let sibling = bin.join("setup").join("svm-admin-setup.ps1");
            if sibling.is_file() { sibling } else {
                // Cargo's target/<profile>/svmd.exe and a portable deployment have different roots.
                bin.ancestors().find(|p| p.file_name().is_some_and(|name| name == "target"))
                    .and_then(Path::parent).map_or(sibling, |p| p.join("setup").join("svm-admin-setup.ps1"))
            }
        });
        let source = script.as_deref().map_or_else(|| r"'.\setup\svm-admin-setup.ps1'".to_owned(), ps_quote);
        let digest: String = Sha256::digest(ADMIN_SETUP).iter().map(|byte| format!("{byte:02X}")).collect();
        let mut command = format!(concat!(
            "$src = {source}; $dir = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SecwizVM Setup'; ",
            "$dst = Join-Path $dir 'svm-admin-setup.ps1'; $bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $src).ProviderPath); ",
            "$sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', ''); ",
            "if ($sha -ne '{digest}') {{ throw 'This svm-admin-setup.ps1 is not the one this Secwizt VM build expects.' }}; ",
            "$acl = [Security.AccessControl.DirectorySecurity]::new(); $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544'); ",
            "$acl.SetAccessRuleProtection($true, $false); foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {{ ",
            "$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$sid, ",
            "'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')) }}; ",
            "[void][IO.Directory]::CreateDirectory($dir, $acl); [IO.File]::WriteAllBytes($dst, $bytes); ",
            "& (Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\\v1.0\\powershell.exe') ",
            "-NoProfile -ExecutionPolicy Bypass -File $dst"), source = source, digest = digest);
        if with_service {
            let service = executable.as_deref().map_or_else(
                || "(Get-Command svmd.exe -CommandType Application -ErrorAction Stop).Source".to_owned(), ps_quote);
            command.push_str(&format!(" -ServiceExe {service}"));
        }
        command
    }

    fn view(row: &Runtime) -> Value {
        let n = &row.saved.network;
        let mut wire = json!({"id":n.id,"name":n.name,"mode":n.mode,"dhcp":row.status,"note":n.note});
        if n.mode==NetworkMode::Routed && n.note=="The administrator setup enables IPv4 forwarding. The upstream router needs a route to the guest subnet." {
            wire["note"]=json!("The one-time administrator setup can provide outbound connections through Windows NAT.");
        }
        if let Some(bridge)=&n.bridge {
            let ready=row.status=="router DHCP";
            wire["addressSource"]=json!("Router DHCP");
            wire["ready"]=json!(ready);
            wire["adapterId"]=json!(bridge.adapter_id);
            wire["bridgeOwned"]=json!(bridge.owned);
            let can_setup=bridge.owned && bridge.switch_guid.is_none() && row.status=="waiting for bridge setup" && row.bridge_reasons.is_empty();
            wire["bridgeCanSetup"]=json!(can_setup);
            wire["bridgeReasons"]=json!(row.bridge_reasons);
            if bridge.owned {
                let command=Self::setup_command(false);
                if bridge.switch_guid.is_some() {
                    wire["removeCommand"]=json!(format!("{command} -Remove -BridgeId '{}'",n.id));
                }
                if can_setup {
                    wire["setupCommand"]=json!(format!("{command} -BridgeId '{}' -AdapterGuid '{}'",n.id,bridge.adapter_id));
                    wire["setupInstruction"]=json!("Run the bridge setup as the same administrator account. Ethernet may briefly disconnect.");
                }
            }
        } else if n.mode == NetworkMode::Nat {
            wire["addressSource"] = json!("Windows DHCP");
        } else {
            if n.mode == NetworkMode::Routed {
                wire["natState"] = json!(row.nat_state);
                wire["natStatus"] = json!(row.nat_status);
                wire["natRange"] = json!(ROUTED_RANGE);
                if row.nat_state == "outside-range" {
                    wire["note"] = json!("The host and guests can use this network locally.");
                }
            }
            wire["dnsStatus"]=json!(row.dns_status);
            wire["dnsAddress"]=json!(row.dns_address);
            wire["addressSource"]=json!("Permanent reservation");
            wire["dhcpTraffic"]=json!(row.activity.traffic());
            wire["subnet"] = json!(n.subnet);
            wire["gateway"] = json!(if n.mode==NetworkMode::LinkLocal {None} else {n.gateway});
            if n.mode==NetworkMode::LinkLocal {wire["hostAddress"]=json!(row.host_address);}
        }
        if n.mode!=NetworkMode::LinkLocal && managed(n.mode) && (row.status == "waiting for setup"
            || (n.mode==NetworkMode::Routed && row.nat_state=="needs-setup")) {
            wire["setupInstruction"] = json!(SETUP);
            wire["setupCommand"] = json!(Self::setup_command(true));
        }
        wire
    }

    fn refresh(&mut self, events: &mut Events) -> Result<(), ApiError> {
        self.next_refresh = Instant::now() + Duration::from_secs(30);
        if !self.rows.values().any(|r| managed(r.saved.network.mode)) { return Ok(()); }
        let inventory = self.switches.addresses();
        let range: Subnet = ROUTED_RANGE.parse().map_err(bad_lease)?;
        let shared_conflict = aggregate_conflict(&self.rows, inventory.as_deref().unwrap_or_default(), range);
        let rules = inventory.as_ref().ok().and_then(|interfaces| interfaces.iter().find_map(|i| i.nat_rules.as_deref()));
        let local:BTreeSet<_>=inventory.as_ref().map(|rows|rows.iter().map(|a|a.address).collect()).unwrap_or_default();
        let resolvers:Vec<_>=inventory.as_ref().map(|rows|{
            let mut seen=BTreeSet::new();
            rows.iter().filter(|a|a.preferred && a.switch_guid.is_none()).flat_map(|a|a.resolvers.iter().copied())
                .filter(|ip|!local.contains(ip) && !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && seen.insert(*ip)).collect()
        }).unwrap_or_default();
        for (id, row) in &mut self.rows {
            let n = &row.saved.network;
            if !managed(n.mode) { continue; }
            let selected = inventory.as_ref().ok().and_then(|interfaces| interfaces.iter().find(|a| {
                a.alias == format!("vEthernet (SVM-{id})") && a.preferred
                    && a.switch_guid.as_ref().zip(row.saved.switch_guid.as_ref()).is_some_and(|(live,saved)| live.eq_ignore_ascii_case(saved))
                    && n.subnet.usable(a.address) && (if n.mode==NetworkMode::LinkLocal {a.address.is_link_local()} else {Some(a.address)==n.gateway})
            }));
            let ambiguous = selected.is_some_and(|owned| inventory.as_ref().is_ok_and(|interfaces| {
                interfaces.iter().any(|other| other.address == owned.address
                    && (other.alias != owned.alias || other.switch_guid != owned.switch_guid))
            }));
            let address = selected.filter(|_| !ambiguous).map(|a| a.address);
            if n.mode == NetworkMode::Routed {
                let gateway_ready = address.is_some() && selected.is_some_and(|i| u32::from(i.prefix) == u32::from(n.subnet.mask()).count_ones());
                let (state, message) = nat_status(n.subnet, range, shared_conflict.as_deref(), rules, gateway_ready);
                if row.nat_state != state || row.nat_status != message {
                    events.record("nat", &format!("Network {id}: {message}"))?;
                    row.nat_state = state;
                    row.nat_status = message;
                }
            }
            row.host_address=address;
            if row.listener.as_ref().is_some_and(|l| Some(l.address) != address || l.finished()) { row.listener = None; }
            let table=row.table.as_ref().ok_or_else(||ApiError::invalid("Missing reservation table."))?;
            let upstream = if n.mode == NetworkMode::Routed && table.config().map_err(bad_lease)?.router.is_some() {
                resolvers.clone()
            } else { Vec::new() };
            if row.dns_address!=address || row.upstream!=upstream || row.dns.as_ref().is_some_and(DnsListener::finished) {
                row.dns=None;row.dns_address=None;
            }
            let reserved=address.is_some_and(|ip|table.reservations().map_or(true,|entries|entries.values().any(|r|r.ip==ip)));
            let mut bind_error=None;
            let dns_status=if reserved {
                row.listener=None;row.dns=None;row.dns_address=None;
                "Host address conflicts with a guest reservation. Shut down the guest before changing its address.".to_owned()
            } else if let Some(ip)=address {
                if row.dns.is_none() {
                    match DnsListener::start(ip,upstream.clone(),Arc::clone(&self.names),n.subnet) {
                        Ok(listener)=>{row.dns=Some(listener);row.dns_address=Some(ip);row.upstream=upstream.clone();}
                        Err(e)=>{bind_error=Some(format!("Cannot bind DNS on {ip}: {e}"));}
                    }
                }
                if let Some(listener)=&row.dns {
                    if listener.can_forward() {"serving local names and forwarding".into()} else {"serving local names".into()}
                } else {bind_error.unwrap_or_else(||"DNS is unavailable.".into())}
            } else if ambiguous { "The host address is assigned to more than one interface.".into() }
            else {"waiting for host address".into()};
            if table.set_dns(row.dns_address).map_err(bad_lease)? {row.dirty=true;}
            if row.dns_status!=dns_status {events.record("dns",&format!("Network {id}: {dns_status}."))?;row.dns_status=dns_status;}
            let status = if reserved { "host address conflicts with a guest reservation".into() } else if let Err(e) = &inventory {
                format!("unavailable: {}", e.message)
            } else if let Some(ip) = address {
                if row.listener.is_none() {
                    match Listener::start(id, ip, Arc::clone(table), lease_path(&self.home, id), Arc::clone(&row.activity)) {
                        Ok(listener) => { row.listener = Some(listener); "serving".into() }
                        Err(e) => format!("The DHCP socket could not bind on the switch. {e}"),
                    }
                } else { "serving".into() }
            } else if ambiguous {"The host address is assigned to more than one interface.".into()}
            else if n.mode==NetworkMode::LinkLocal {"waiting for Windows link-local address".into()} else { "waiting for setup".into() };
            if row.status != status {
                events.record("dhcp", &format!("Network {id}: {status}."))?;
                row.status = status;
            }
        }
        Ok(())
    }

    fn record_activity(&mut self, events: &mut Events) -> Result<(), ApiError> {
        for (id, row) in &mut self.rows {
            if let Some(message) = row.listener.as_ref().and_then(Listener::take_failure) {
                row.listener = None;
                row.status = format!("The DHCP listener stopped. {message}");
                events.record("dhcp", &format!("Network {id}: {}", row.status))?;
            }
            let (changes, dropped) = row.activity.drain_changes();
            if dropped > 0 {
                events.record("dhcp", &format!("Network {id} exceeded its event buffer. {dropped} older lease transitions were omitted."))?;
            }
            for (mac, entry) in changes {
                let kind = if entry.state == LeaseState::Active { "lease given" } else { "lease changed" };
                events.record(kind, &format!("Network {id} assigned {} to {mac} ({:?}).", entry.ip, entry.state))?;
            }
        }
        Ok(())
    }

    pub fn tick(&mut self, events: &mut Events) -> Result<(), ApiError> {
        self.record_activity(events)?;
        if Instant::now() >= self.next_refresh { self.refresh(events)?; }
        Ok(())
    }

    pub fn shutdown(&mut self, events: &mut Events) -> Result<(), ApiError> {
        for row in self.rows.values_mut() { row.listener = None;row.dns=None; }
        for (id, row) in &self.rows {
            if let Some(table) = &row.table { table.save(&lease_path(&self.home,id)).map_err(bad_lease)?; }
        }
        self.record_activity(events)
    }

    fn create(&mut self, body: &Value, events: &mut Events) -> Result<Reply, ApiError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields,rename_all="camelCase")]
        struct NewNetwork { id: Option<String>, name: String, mode: NetworkMode, subnet: Option<Subnet>, gateway: Option<Ipv4Addr>, adapter_id:Option<String>,confirm_disconnect:Option<bool> }
        let input: NewNetwork = serde_json::from_value(body.clone())
            .map_err(|_| ApiError::invalid("Enter a network name, mode and an optional aligned IPv4 subnet."))?;
        if input.mode!=NetworkMode::Bridged && !managed(input.mode) {
            return Err(ApiError::invalid("Choose Routed, Host-only or Isolated segment. NAT already uses the Default Switch."));
        }
        if input.name.trim().is_empty() || input.name.len() > 160 || input.name.chars().any(char::is_control) {
            return Err(ApiError::invalid("Enter a network name of at most 160 printable characters."));
        }
        let id = match input.id {
            Some(id) => id,
            None => (1..=u32::MAX).map(|i| format!("net-{i}")).find(|id| !self.rows.contains_key(id))
                .ok_or_else(|| ApiError::new(409,"network_ids","No network IDs remain."))?,
        };
        if !valid_id(&id) { return Err(ApiError::invalid("Use a short alphanumeric network ID with optional dashes, underscores or dots.")); }
        if self.rows.keys().any(|existing| existing.eq_ignore_ascii_case(&id)) {
            return Err(ApiError::new(409,"network_exists","This network ID is already in use."));
        }
        if input.mode==NetworkMode::Bridged {
            if input.subnet.is_some() || input.gateway.is_some() || input.confirm_disconnect!=Some(true) {return Err(ApiError::invalid("Acknowledge the Ethernet interruption. The router supplies the subnet and gateway."));}
            let adapter=input.adapter_id.ok_or_else(||ApiError::invalid("Select a wired Ethernet adapter."))?;
            return self.create_bridge(id,input.name,&adapter,events);
        }
        if input.adapter_id.is_some() || input.confirm_disconnect.is_some() {return Err(ApiError::invalid("Only external networks take a physical adapter."));}
        if input.mode==NetworkMode::LinkLocal && (input.subnet.is_some() || input.gateway.is_some() || self.rows.values().any(|row|row.saved.network.mode==NetworkMode::LinkLocal)) {
            return Err(ApiError::invalid("Use one Link-local network per library with its automatic subnet."));
        }
        let interfaces = self.switches.addresses()?;
        let range: Subnet = ROUTED_RANGE.parse().map_err(bad_lease)?;
        let pool = if input.mode == NetworkMode::Routed { 77 } else { 78 };
        let available = |s: Subnet| !self.rows.values().any(|r| r.saved.network.subnet.overlaps(s))
            && !interfaces.iter().any(|i| i.overlaps(s));
        let subnet = if input.mode==NetworkMode::LinkLocal {"169.254.0.0/16".parse().map_err(bad_lease)?} else {match input.subnet {
            Some(subnet) => subnet,
            None => (0..=255u16).filter_map(|i| format!("10.{pool}.{i}.0/24").parse().ok())
                .find(|s| available(*s)).ok_or_else(|| ApiError::new(409,"subnet_pool","The automatic address pool is full. Choose a free private subnet."))?,
        }};
        if input.mode!=NetworkMode::LinkLocal && (!subnet.base().is_private() || !subnet.broadcast().is_private()) {
            return Err(ApiError::invalid("Choose a private IPv4 subnet for this internal network."));
        }
        if subnet.overlaps(range) && input.mode != NetworkMode::Routed {
            return Err(ApiError::new(409, "routed_range", format!("Local-only networks need a subnet outside {ROUTED_RANGE}.")));
        }
        if subnet.overlaps(range) && !contains(range, subnet) {
            return Err(ApiError::invalid(&format!("Choose a subnet wholly inside or wholly outside {ROUTED_RANGE}.")));
        }
        if input.mode!=NetworkMode::LinkLocal && !available(subnet) {
            return Err(ApiError::new(409,"subnet_overlap","This subnet overlaps the host or another network."));
        }
        let gateway = input.gateway.unwrap_or_else(|| Ipv4Addr::from(u32::from(subnet.base()) + 1));
        if !subnet.usable(gateway) { return Err(ApiError::invalid("The host-side address must be usable in the selected subnet.")); }
        let network = Network { bridge:None, id: id.clone(), name: input.name, mode: input.mode, subnet, gateway: (input.mode!=NetworkMode::LinkLocal).then_some(gateway), dhcp: true,
            note: match input.mode {
                NetworkMode::Routed if contains(range, subnet) => "Administrator setup can provide outbound connections through the shared Windows NAT.",
                NetworkMode::Routed => "The host and guests can use this network locally.",
                NetworkMode::LinkLocal => "Permanent local addresses for this host and its guests. No internet or administrator setup.",
                NetworkMode::HostOnly => "This internal switch connects guests and their host.",
                _ => "Guests share an internal switch with host-side DHCP. Guest-only isolation is not enforced in this phase.",
            }.into() };
        let (guid, created) = self.switches.ensure(&network)?;
        if !created { return Err(ApiError::new(409,"switch_exists","A switch with this ID exists outside this library. Choose another ID.")); }
        let saved = Saved { network: network.clone(), switch_guid: Some(guid.clone()) };
        let inserted = runtime(&self.home, saved).and_then(|row| {
            self.rows.insert(id.clone(), row);
            self.save()
        });
        if let Err(error) = inserted {
            self.rows.remove(&id);
            if self.switches.remove(&network, &guid).is_err() {
                return Err(ApiError::new(500,"network_rollback",format!("Saving the network failed. Check the retained switch SVM-{id} before retrying.")));
            }
            return Err(error);
        }
        events.record("network created",&format!("Created internal network {id}."))?;
        self.refresh(events)?;
        let row = self.rows.get(&id).ok_or_else(ApiError::missing)?;
        Ok(Reply::created(Self::view(row)))
    }

    fn create_bridge(&mut self,id:String,name:String,adapter:&str,events:&mut Events)->Result<Reply,ApiError> {
        let adapters=self.switches.bridges()?;
        let a=adapters["adapters"].as_array().and_then(|rows|rows.iter().find(|r|r["id"].as_str().is_some_and(|x|x.eq_ignore_ascii_case(adapter))))
            .ok_or_else(||ApiError::invalid("Choose a detected wired adapter."))?;
        if a["available"]!=true {return Err(ApiError::invalid(a["reason"].as_str().unwrap_or("This adapter cannot be bridged.")));}
        if !valid_guid(adapter) {return Err(ApiError::invalid("Invalid adapter identity."));}
        if self.rows.values().any(|r|r.saved.network.bridge.as_ref().is_some_and(|b|b.adapter_id.eq_ignore_ascii_case(adapter))) {
            return Err(ApiError::new(409,"bridge_exists","This adapter already has a network in the library."));
        }
        let guid=a["switchGuid"].as_str().map(str::to_owned);
        if guid.as_deref().is_some_and(|g|!valid_guid(g)) {return Err(ApiError::invalid("The external switch identity is invalid."));}
        let mut network=nat()?.network;
        network.id=id.clone();network.name=name;network.mode=NetworkMode::Bridged;network.gateway=None;
        network.note="The physical LAN router supplies the guest address. A bridge uses a wired adapter shared with the host.".into();
        network.bridge=Some(svm_core::model::BridgeLink{adapter_id:adapter.to_owned(),owned:guid.is_none(),switch_guid:guid.clone()});
        let checked=self.switches.resolve_bridge(&network)?;
        if let Some(expected)=guid.as_deref() {
            if !checked["guid"].as_str().is_some_and(|found|found.eq_ignore_ascii_case(expected)) {
                return Err(ApiError::new(409,"bridge_changed","The selected external switch changed. Refresh the physical adapter list."));
            }
        } else if checked["canSetup"]!=true {
            let reasons=checked["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(" ");
            return Err(ApiError::new(409,"bridge_changed",if reasons.is_empty() {"The adapter changed. Refresh the physical adapter list.".into()} else {reasons}));
        }
        let mut row=runtime(&self.home,Saved{network,switch_guid:None})?;
        row.status=if guid.is_some() {"router DHCP"} else {"waiting for bridge setup"}.into();
        self.rows.insert(id.clone(),row);
        if let Err(e)=self.save() {self.rows.remove(&id);return Err(e);}
        events.record("network created",&format!("Registered wired bridge {id}."))?;
        Ok(Reply::created(Self::view(&self.rows[&id])))
    }
    fn refresh_bridge(&mut self,id:&str)->Result<Reply,ApiError> {
        let mut n=self.rows.get(id).ok_or_else(ApiError::missing)?.saved.network.clone();
        let result=self.switches.resolve_bridge(&n);
        let link=n.bridge.as_mut().ok_or_else(||ApiError::invalid("Select a bridged network."))?;
        let row=self.rows.get_mut(id).ok_or_else(ApiError::missing)?;
        row.bridge_reasons.clear();
        let checked=match result {Ok(value)=>value, Err(error)=>{
            row.status="bridge unavailable".into();row.bridge_reasons.push(error.message);
            return Ok(Reply::json(Self::view(row)));
        }};
        if checked["guid"].is_null() {
            let available=checked["canSetup"]==true && link.owned && link.switch_guid.is_none();
            row.status=if available {"waiting for bridge setup"} else {"bridge unavailable"}.into();
            if let Some(reasons)=checked["reasons"].as_array() {
                row.bridge_reasons=reasons.iter().filter_map(|r|r.as_str().map(str::to_owned)).collect();
            }
            if !available && row.bridge_reasons.is_empty() {row.bridge_reasons.push("The recorded external switch could not be verified.".into());}
            return Ok(Reply::json(Self::view(row)));
        }
        let guid=checked["guid"].as_str().filter(|g|valid_guid(g)).ok_or_else(||ApiError::invalid("The external switch identity was unavailable."))?;
        if link.switch_guid.as_deref().is_some_and(|old|!old.eq_ignore_ascii_case(guid)) || (link.owned && checked["owned"]!=true) {
            row.status="bridge unavailable".into();row.bridge_reasons.push("The original external switch could not be verified.".into());
            return Ok(Reply::json(Self::view(row)));
        }
        let changed=link.switch_guid.is_none();
        link.switch_guid=Some(guid.to_owned());
        let before=row.saved.network.clone();
        row.saved.network=n;row.status="router DHCP".into();
        if changed {if let Err(e)=self.save() {let row=self.rows.get_mut(id).ok_or_else(ApiError::missing)?;row.saved.network=before;row.status="awaiting bridge verification".into();return Err(e);}}
        Ok(Reply::json(Self::view(&self.rows[id])))
    }
    pub fn route(&mut self, method: &str, parts: &[&str], body: &Value, attached: bool, events: &mut Events) -> Result<Reply,ApiError> {
        match (method, parts) {
            ("GET", ["networks","bridge-adapters"])=>Ok(Reply::json(self.switches.bridges()?)),
            ("POST", ["networks",id,"refresh"])=>{
                let row=self.rows.get(*id).ok_or_else(ApiError::missing)?;
                if row.saved.network.mode==NetworkMode::Bridged {
                    let reply=self.refresh_bridge(id)?;
                    events.record("bridge checked",&format!("Checked wired bridge {id}."))?;
                    Ok(reply)
                } else if managed(row.saved.network.mode) {
                    self.refresh(events)?;
                    Ok(Reply::json(Self::view(&self.rows[*id])))
                } else {Err(ApiError::invalid("Windows manages the Default Switch."))}
            }
            ("GET", ["networks"]) => Ok(Reply::json(Value::Array(self.rows.values().map(Self::view).collect()))),
            ("POST", ["networks"]) => self.create(body,events),
            ("GET", ["networks",id,"leases"]) => {
                let row = self.rows.get(*id).ok_or_else(ApiError::missing)?;
                let leases = match &row.table {
                    Some(table) => table.reservations().map_err(bad_lease)?.into_iter()
                        .map(|(mac,r)| json!({"mac":mac,"ip":r.ip,"state":r.state})).collect(),
                    None => Vec::new(),
                };
                Ok(Reply::json(Value::Array(leases)))
            }
            ("DELETE", ["networks",id]) => {
                let row = self.rows.get(*id).ok_or_else(ApiError::missing)?;
                if *id == NAT { return Err(ApiError::new(409,"default_switch","Windows owns the Default Switch.")); }
                if attached { return Err(ApiError::new(409,"network_in_use","Move or delete the attached machines before removing this network.")); }
                if let Some(bridge)=&row.saved.network.bridge {
                    if bridge.owned {
                        let adapters=self.switches.bridges()?;
                        let adapter=adapters["adapters"].as_array().and_then(|list|list.iter().find(|r|r["id"].as_str().is_some_and(|id|id.eq_ignore_ascii_case(&bridge.adapter_id))))
                            .ok_or_else(||ApiError::new(409,"ownership","Reconnect the adapter so its switch can be verified."))?;
                        if adapter["bound"]!=false || !adapter["switchGuid"].is_null() {return Err(ApiError::new(409,"bridge_in_use","Run the recorded bridge undo before removing its library entry."));}
                    }
                    let prior=self.rows.remove(*id).ok_or_else(ApiError::missing)?;
                    if let Err(e)=self.save(){self.rows.insert((*id).to_owned(),prior);return Err(e);}
                    events.record("network deleted",&format!("Forgot wired bridge {id}."))?;
                    return Ok(Reply::json(json!({"deleted":id})));
                }
                let guid = row.saved.switch_guid.as_deref().ok_or_else(|| ApiError::new(409,"ownership","The recorded switch identity is missing."))?;
                self.switches.remove(&row.saved.network,guid)?;
                let mut removed = self.rows.remove(*id).ok_or_else(ApiError::missing)?;
                removed.listener = None;removed.dns=None;
                if let Err(e) = self.save() {
                    self.rows.insert((*id).into(), removed);
                    return Err(e);
                }
                match fs::remove_file(lease_path(&self.home,id)) {
                    Ok(()) => {},
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {},
                    Err(e) => return Err(ApiError::storage(e)),
                }
                events.record("network deleted", &format!("Removed internal network {id}."))?;
                Ok(Reply::json(json!({"deleted":id})))
            }
            _ => Err(ApiError::missing()),
        }
    }
}

/// A PowerShell single-quoted string. PowerShell also ends a single-quoted string at the typographic
/// quotes U+2018 to U+201B, so each of them is doubled like an ASCII quote.
fn ps_quote(path: &Path) -> String {
    let mut quoted = String::from("'");
    for c in path.to_string_lossy().chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') { quoted.push(c); }
        quoted.push(c);
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::UdpSocket, sync::atomic::{AtomicU64, Ordering}};
    use svm_core::identity::MacAddr;

    struct TestHome(PathBuf);

    #[test]
    fn admin_setup_command_runs_only_a_pinned_copy_from_a_protected_folder() {
        let digest: String = Sha256::digest(ADMIN_SETUP).iter().map(|byte| format!("{byte:02X}")).collect();
        let command = Networks::setup_command(true);
        assert!(command.contains(&format!("if ($sha -ne '{digest}') {{ throw")), "{command}");
        assert!(command.contains("GetFolderPath('ProgramFiles')") && !command.contains("$env:"), "{command}");
        assert!(command.contains("SetAccessRuleProtection($true, $false)") && command.contains("'S-1-5-32-544', 'S-1-5-18'"));
        assert!(command.contains("[IO.File]::WriteAllBytes($dst, $bytes); & (Join-Path"));
        assert!(command.contains("-NoProfile -ExecutionPolicy Bypass -File $dst -ServiceExe '"), "{command}");
        // The source script is read once and never run from its own, user-writable folder.
        assert_eq!(command.matches("$src").count(), 2);
        assert!(!Networks::setup_command(false).contains("-ServiceExe"));
        assert_eq!(ps_quote(Path::new("C:\\it's\u{2019}\u{2018}x")), "'C:\\it''s\u{2019}\u{2019}\u{2018}\u{2018}x'");
        assert!(SETUP.contains("svm-admin-setup.ps1"));
    }

    #[test]
    fn existing_bridge_loses_setup_command_when_the_adapter_is_refused() {
        const ADAPTER:&str="aabbccdd-0000-4000-8000-123456789abc";
        struct BridgeFixture(Arc<std::sync::atomic::AtomicBool>);
        impl Switches for BridgeFixture {
            fn addresses(&self)->Result<Vec<Interface>,ApiError>{Ok(Vec::new())}
            fn bridges(&self)->Result<Value,ApiError>{
                Ok(json!({"adapters":[{"id":ADAPTER,"available":!self.0.load(Ordering::Relaxed),"bound":false}]}))
            }
            fn resolve_bridge(&self,_:&Network)->Result<Value,ApiError>{
                if self.0.load(Ordering::Relaxed) {
                    Ok(json!({"guid":null,"canSetup":false,"reasons":["Static DNS.","IPv6 is not bound."]}))
                } else {Ok(json!({"guid":null,"canSetup":true,"reasons":[]}))}
            }
            fn ensure(&mut self,_:&Network)->Result<(String,bool),ApiError>{unreachable!()}
            fn remove(&mut self,_:&Network,_:&str)->Result<(),ApiError>{unreachable!()}
        }
        let temp=TestHome::new();
        let mut events=Events::open(&temp.0).unwrap();
        let refused=Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut nets=Networks::open(&temp.0,Box::new(BridgeFixture(Arc::clone(&refused))),&mut events).unwrap();
        let before=nets.create_bridge("wired".into(),"Wired".into(),ADAPTER,&mut events).unwrap();
        let before:Value=serde_json::from_slice(&before.body).unwrap();
        assert!(before["setupCommand"].is_string());
        refused.store(true,Ordering::Relaxed);
        let after=nets.refresh_bridge("wired").unwrap();
        let after:Value=serde_json::from_slice(&after.body).unwrap();
        assert_eq!(after["bridgeCanSetup"],false);
        assert!(after.get("setupCommand").is_none());
        assert!(after.get("removeCommand").is_none());
        assert_eq!(after["bridgeReasons"],json!(["Static DNS.","IPv6 is not bound."]));
        assert!(nets.route("DELETE",&["networks","wired"],&Value::Null,false,&mut events).is_ok());
    }

    impl TestHome {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            loop {
                let dir = std::env::temp_dir().join(format!("svmd-net-test-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
                match fs::create_dir(&dir) {
                    Ok(()) => return Self(dir),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create test folder: {error}"),
                }
            }
        }
    }
    impl Drop for TestHome { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

    #[test]
    fn addresses_behind_small_prefixes_block_overlapping_creates() {
        let temp = TestHome::new();
        let mut events = Events::open(&temp.0).unwrap();
        let mut fake = FakeSwitches::default();
        fake.interfaces.push(Interface { address: Ipv4Addr::new(10,77,0,14), prefix:32,
            alias:"host".into(), switch_guid:None, preferred:true,resolvers:Vec::new(),nat_rules:None });
        let mut networks = Networks::open(&temp.0,Box::new(fake),&mut events).unwrap();
        let explicit = json!({"id":"sample","name":"Sample","mode":"Routed","subnet":"10.77.0.0/24"});
        let outcome = networks.create(&explicit,&mut events);
        assert!(matches!(outcome,Err(ApiError { status:409,.. })));
        let automatic = json!({"id":"sample","name":"Sample","mode":"Routed"});
        let reply = networks.create(&automatic,&mut events).unwrap();
        let row: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(row["subnet"],"10.77.1.0/24");
        assert_eq!(row["natState"],"conflict");
        assert!(row["natStatus"].as_str().unwrap().contains("10.77.0.14/32"));
        assert_eq!(row["dhcp"],"waiting for setup");
        assert!(row["setupInstruction"].as_str().unwrap().contains("svm-admin-setup.ps1"));
        assert!(matches!(networks.route("DELETE",&["networks","sample"],&Value::Null,true,&mut events),
            Err(ApiError { status:409,.. })));
        assert!(matches!(networks.route("DELETE",&["networks","nat"],&Value::Null,false,&mut events),
            Err(ApiError { status:409,.. })));
        networks.route("DELETE",&["networks","sample"],&Value::Null,false,&mut events).unwrap();
        assert_eq!(networks.definitions().len(),1);
    }

    #[test]
    fn managed_network_creation_uses_separate_pools_and_reports_custom_local_only_networks() {
        let temp = TestHome::new();
        let mut events = Events::open(&temp.0).unwrap();
        let mut networks = Networks::open(&temp.0, Box::new(FakeSwitches::default()), &mut events).unwrap();
        for (id, mode, expected) in [("r1","Routed","10.77.0.0/24"), ("local","Host-only","10.78.0.0/24"),
            ("r2","Routed","10.77.1.0/24"), ("isolated","Isolated segment","10.78.1.0/24")] {
            let response = networks.create(&json!({"id":id,"name":id,"mode":mode}), &mut events).unwrap();
            let row: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(row["subnet"], expected);
        }
        for (mode, cidr) in [("Host-only","10.77.250.0/24"), ("Isolated segment","10.76.0.0/15"),
            ("Routed","10.76.0.0/15"), ("Routed","10.77.0.128/25")] {
            assert!(networks.create(&json!({"id":"bad","name":"bad","mode":mode,"subnet":cidr}), &mut events).is_err());
        }
        let custom = json!({"id":"custom","name":"Custom","mode":"Routed","subnet":"192.168.210.0/24"});
        networks.create(&custom, &mut events).unwrap();
        let reply = networks.route("GET", &["networks"], &Value::Null, false, &mut events).unwrap();
        let rows: Vec<Value> = serde_json::from_slice(&reply.body).unwrap();
        let outside = rows.iter().find(|row| row["id"] == "custom").unwrap();
        assert_eq!(outside["natState"], "outside-range");
        assert_eq!(outside["natRange"], ROUTED_RANGE);
        assert!(outside["natStatus"].as_str().unwrap().contains("no internet outside"));
        assert!(networks.rows["custom"].table.as_ref().unwrap().config().unwrap().router.is_none());
        assert_eq!(rows.iter().find(|r| r["id"] == "r1").unwrap()["natState"], "unknown");
    }

    #[test]
    fn missing_nat_and_unreadable_windows_inventory_have_distinct_api_states() {
        for (rules, expected) in [(json!([]), "needs-setup"), (Value::Null, "unknown"),
            (json!([{"name":"foreign","prefix":"10.77.0.0/16"}]), "conflict")] {
            let temp = TestHome::new();
            let mut events = Events::open(&temp.0).unwrap();
            let mut fake = FakeSwitches::default();
            fake.interfaces = serde_json::from_value(json!([{"address":"192.0.2.14","prefix":24,
                "alias":"test-adapter","switchGuid":null,"preferred":true,"resolvers":[],"natRules":rules}])).unwrap();
            let mut networks = Networks::open(&temp.0, Box::new(fake), &mut events).unwrap();
            let response = networks.create(&json!({"id":"r","name":"Routed","mode":"Routed"}), &mut events).unwrap();
            let row: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(row["natState"], expected);
            if expected == "needs-setup" { assert!(row["natStatus"].as_str().unwrap().contains("No app-provided internet")); }
        }
    }

    #[test]
    fn one_expected_nat_can_cover_several_verified_gateways_but_not_another_configuration() {
        let parent: Subnet = ROUTED_RANGE.parse().unwrap();
        let expected = NatRule { name: format!("SVM-Routed-{}", "a8".repeat(16)), prefix: ROUTED_RANGE.into() };
        let expected = [expected];
        for child in ["10.77.0.0/24", "10.77.255.0/24"] {
            let subnet: Subnet = child.parse().unwrap();
            assert_eq!(nat_status(subnet, parent, None, Some(&expected), true).0, "matching");
            assert_eq!(nat_status(subnet, parent, None, Some(&expected), false).0, "needs-setup");
            assert_eq!(nat_status(subnet, parent, None, Some(&[]), true).0, "needs-setup");
            assert_eq!(nat_status(subnet, parent, None, None, true).0, "unknown");
            assert_eq!(nat_status(subnet, parent, Some("foreign interface"), Some(&expected), true).0, "conflict");
        }
        let overlapping = "10.77.3.0/24".parse().unwrap();
        for (name,prefix) in [("Foreign".into(), ROUTED_RANGE), ("SVM-Routed-abc".into(), ROUTED_RANGE),
            (format!("SVM-Routed-{}", "AA".repeat(16)), ROUTED_RANGE), (expected[0].name.clone(), "10.77.3.0/24")] {
            let wrong = NatRule { name, prefix: prefix.into() };
            assert_eq!(nat_status(overlapping, parent, None, Some(&[wrong.clone()]), true).0, "conflict");
            assert_eq!(nat_status(overlapping, parent, None, Some(&[expected[0].clone(), wrong]), true).0, "conflict");
        }
    }

    #[test]
    fn saved_networks_and_reservations_survive_shared_range_conflicts() {
        let temp = TestHome::new();
        let mut events = Events::open(&temp.0).unwrap();
        let manifest = json!([
            {"id":"legacy","name":"Existing local-only","mode":"Host-only","subnet":"10.77.9.0/24","gateway":"10.77.9.1","dhcp":true,"note":"","switchGuid":"test-legacy"},
            {"id":"r1","name":"Routed","mode":"Routed","subnet":"10.77.1.0/24","gateway":"10.77.1.1","dhcp":true,"note":"","switchGuid":"test-r1"},
            {"id":"manual","name":"Prior custom routed","mode":"Routed","subnet":"192.168.210.0/24","gateway":"192.168.210.1","dhcp":true,"note":"","switchGuid":"test-manual"}
        ]);
        fs::write(temp.0.join("networks.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        let leases = json!({"config":{"subnet":"192.168.210.0/24","router":"192.168.210.1","dns":null,"leaseSeconds":3600,"bootFile":null},
            "entries":{"02:77:00:00:00:01":{"ip":"192.168.210.9","state":"Active"}}});
        fs::write(lease_path(&temp.0,"manual"), serde_json::to_vec(&leases).unwrap()).unwrap();
        let networks = Networks::open(&temp.0, Box::new(FakeSwitches::default()), &mut events).unwrap();
        assert_eq!(networks.rows["r1"].nat_state, "conflict");
        assert!(networks.rows["r1"].nat_status.contains("legacy"));
        assert_eq!(String::from(networks.rows["legacy"].saved.network.subnet), "10.77.9.0/24");
        assert_eq!(networks.rows["manual"].nat_state, "outside-range");
        let table = networks.rows["manual"].table.as_ref().unwrap();
        assert_eq!(table.config().unwrap().router, Some(Ipv4Addr::new(192,168,210,1)));
        let lease = table.reservation("02:77:00:00:00:01".parse().unwrap()).unwrap().unwrap();
        assert_eq!((lease.ip, lease.state), (Ipv4Addr::new(192,168,210,9), LeaseState::Active));
    }

    #[test]
    fn shared_range_accepts_only_matching_owned_gateway_address_and_prefix() {
        let temp = TestHome::new();
        let mut events = Events::open(&temp.0).unwrap();
        let mut networks = Networks::open(&temp.0, Box::new(FakeSwitches::default()), &mut events).unwrap();
        for id in ["a","b"] {
            networks.create(&json!({"id":id,"name":id,"mode":"Routed"}), &mut events).unwrap();
        }
        let make = |index: u8, id: &str| Interface { address: Ipv4Addr::new(10,77,index,1), prefix:24,
            alias: format!("vEthernet (SVM-{id})"), switch_guid: Some(format!("test-{id}")), preferred: true,
            resolvers: Vec::new(), nat_rules: Some(Vec::new()) };
        let a = make(0,"a");
        let b = make(1,"b");
        let range: Subnet = ROUTED_RANGE.parse().unwrap();
        let conflict = |rows: &[Interface]| aggregate_conflict(&networks.rows, rows, range);
        assert!(conflict(&[a.clone(),b.clone()]).is_none());
        let mut wrong = b.clone();
        wrong.prefix = 23;
        assert!(conflict(&[a.clone(),wrong]).is_some());
        let mut wrong = b.clone();
        wrong.address = Ipv4Addr::new(10,77,1,3);
        assert!(conflict(&[a.clone(),wrong]).is_some());
        let mut wrong = b;
        wrong.switch_guid = None;
        wrong.alias = "Foreign adapter".into();
        assert!(conflict(&[a,wrong]).unwrap().contains("Foreign adapter"));
    }

    #[test]
    fn duplicate_address_on_an_unowned_interface_prevents_listener_binding() {
        let temp = TestHome::new();
        let mut events = Events::open(&temp.0).unwrap();
        let shared = Ipv4Addr::new(169,254,40,1);
        let mut fake = FakeSwitches::default();
        for (alias, guid) in [("vEthernet (SVM-probe)", Some("test-probe")), ("unowned", None)] {
            fake.interfaces.push(Interface { address: shared, prefix: 16, alias: alias.into(),
                switch_guid: guid.map(str::to_owned), preferred: true, resolvers: Vec::new(), nat_rules: None });
        }
        let mut networks = Networks::open(&temp.0, Box::new(fake), &mut events).unwrap();
        let reply = networks.create(&json!({"id":"probe","name":"Probe","mode":"Link-local"}), &mut events).unwrap();
        let network: Value = serde_json::from_slice(&reply.body).unwrap();
        assert!(network["dhcp"].as_str().unwrap().contains("more than one interface"));
        assert!(network["hostAddress"].is_null());
        assert!(networks.rows["probe"].listener.is_none());
    }

    #[test]
    fn owner_acknowledges_a_real_datagram_and_reloads_the_active_lease_and_event() {
        let temp = TestHome::new();
        let mut events = Events::open(&temp.0).unwrap();
        let mut networks = Networks::open(&temp.0,Box::new(FakeSwitches::default()),&mut events).unwrap();
        let server = Ipv4Addr::LOCALHOST;
        let guest = Ipv4Addr::new(127,0,0,5);
        let mac = MacAddr::from_bytes([2,1,2,3,4,5]);
        let record = Saved { network: Network { bridge:None, id:"loop".into(),name:"Loopback".into(),mode:NetworkMode::Routed,
            subnet:"127.0.0.0/24".parse().unwrap(),gateway:Some(server),dhcp:true,note:String::new() },switch_guid:Some("fixture".into()) };
        let mut row = runtime(&temp.0,record).unwrap();
        row.table.as_ref().unwrap().reserve(mac,guest).unwrap();
        let client = UdpSocket::bind((server,0)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let (listener,endpoint) = Listener::loopback("loop", client.local_addr().unwrap().port(),
            Arc::clone(row.table.as_ref().unwrap()), lease_path(&temp.0, "loop"), Arc::clone(&row.activity)).unwrap();
        row.listener = Some(listener);
        networks.rows.insert("loop".into(),row);
        networks.save().unwrap();
        let mut packet = vec![0;240];
        packet[..3].copy_from_slice(&[1,1,6]); packet[28..34].copy_from_slice(&mac.octets());
        packet[236..240].copy_from_slice(&[99,130,83,99]);
        packet.extend_from_slice(&[53,1,1,255]);
        let mut buf = [0;512];
        // No worker tick until both replies arrive. A slow Hyper-V operation must not stall DHCP.
        client.send_to(&packet,endpoint).unwrap();
        let (size, source) = client.recv_from(&mut buf).unwrap();
        assert_eq!(source, endpoint);
        assert!(size >= 243);
        assert_eq!(buf[242], 2);
        assert_eq!(&buf[16..20], &guest.octets());
        packet.truncate(240);
        packet.extend_from_slice(&[53,1,3,50,4,127,0,0,5,255]);
        client.send_to(&packet,endpoint).unwrap();
        let (_, source) = client.recv_from(&mut buf).unwrap();
        assert_eq!(source, endpoint);
        assert_eq!(buf[242], 5);
        assert_eq!(LeaseTable::load(&lease_path(&temp.0, "loop")).unwrap().reservation(mac).unwrap().unwrap().state, LeaseState::Active);
        networks.shutdown(&mut events).unwrap();
        let listed = networks.route("GET", &["networks"], &Value::Null, false, &mut events).unwrap();
        let listed: Vec<Value> = serde_json::from_slice(&listed.body).unwrap();
        let traffic = &listed.iter().find(|row| row["id"] == "loop").unwrap()["dhcpTraffic"];
        assert_eq!(traffic, &json!({"discovers":1,"offers":1,"zeroSourceOffers":0,"requests":1,"acks":1,"sendErrors":0}));
        drop(networks);
        drop(events);
        let mut events = Events::open(&temp.0).unwrap();
        assert!(events.reader().since(0).unwrap().iter().any(|e| e.kind=="lease given"));
        let mut networks = Networks::open(&temp.0,Box::new(FakeSwitches::default()),&mut events).unwrap();
        let reply = networks.route("GET",&["networks","loop","leases"],&Value::Null,false,&mut events).unwrap();
        let leases: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(leases[0]["state"],"Active");
        assert_eq!(leases[0]["ip"],"127.0.0.5");
    }
}
