use crate::identity::{MacAddr, Subnet};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmState { Off, Running, Paused, Saved }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestFamily { Windows, Linux, Android, Bsd, Macos, Dos, Other }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestArchitecture {
    #[default]
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineKind {
    #[serde(rename = "Hyper-V", alias = "hyperv")]
    HyperV,
    #[serde(rename = "QEMU", alias = "qemu")]
    Qemu,
    #[serde(rename = "Apple VZ", alias = "applevz")]
    AppleVz,
}

// Definitions predating engine selection were created by the Hyper-V driver.
fn hyperv_engine() -> EngineKind { EngineKind::HyperV }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    Routed, Bridged,
    #[serde(rename="Link-local")]
    LinkLocal,
    #[serde(rename = "NAT")]
    Nat,
    #[serde(rename = "Host-only")]
    HostOnly,
    #[serde(rename = "Isolated segment")]
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortForwardProtocol { Tcp, Udp }

impl PortForwardProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortForward {
    pub protocol: PortForwardProtocol,
    pub host_port: u16,
    pub guest_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateDisk {
    pub disk: String,
    pub sha256: String,
    pub originally_read_only: bool,
}

/// A template or machine made from a bundled ready-to-run image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadyOrigin {
    /// The bundled catalog ID of the ready image.
    pub image: String,
    /// The publisher's public default user. While set, the machine still uses the publisher's
    /// default password, so the service refuses port forwards for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_login: Option<String>,
    /// QEMU only: attach the machine's private first-boot settings volume (label CIDATA).
    #[serde(default)]
    pub seed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm {
    pub id: String,
    pub name: String,
    pub os: String,
    pub family: GuestFamily,
    #[serde(default)]
    pub architecture: GuestArchitecture,
    #[serde(default = "hyperv_engine")]
    pub engine: EngineKind,
    pub accel: bool,
    pub state: VmState,
    pub vcpu: u16,
    pub ram_gb: u32,
    #[serde(default)]
    pub cores: Vec<u16>,
    pub net: String,
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub dns: String,
    #[serde(default)]
    pub snaps: u32,
    #[serde(default)]
    pub share_clipboard: bool,
    #[serde(default)]
    pub port_forwards: Vec<PortForward>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<TemplateDisk>,
    #[serde(default)]
    pub throwaway: bool,
    /// QEMU only: the guest network cannot reach this PC (including its loopback services) or the
    /// internet; only the machine's own TCP port forwards work.
    #[serde(default)]
    pub isolated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_path: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso_path: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<ReadyOrigin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase")]
pub struct BridgeLink {
    pub adapter_id: String,
    pub switch_guid: Option<String>,
    pub owned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub bridge: Option<BridgeLink>,
    pub id: String,
    pub name: String,
    pub mode: NetworkMode,
    pub subnet: Subnet,
    pub gateway: Option<Ipv4Addr>,
    pub dhcp: bool,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotConsistency { GuestQuiesced, CrashConsistent, HypervProduction, Standard, Unverified }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub id: String,
    pub name: String,
    pub parent: Option<String>,
    pub with_memory: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency: Option<SnapshotConsistency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    pub logical: u16,
    pub p_cores: [u16; 2],
    pub e_cores: [u16; 2],
    pub ram_gb: u32,
}

#[cfg(test)]
pub(crate) fn sample() -> Vm {
    Vm {
        id: "vm-a".into(), name: "Sample A".into(), os: "Sample Linux".into(),
        family: GuestFamily::Linux, architecture: GuestArchitecture::X86_64, engine: EngineKind::HyperV, accel: true,
        state: VmState::Off, vcpu: 2, ram_gb: 4, cores: Vec::new(),
        net: "lab".into(), ip: Ipv4Addr::new(10,77,1,10),
        mac: MacAddr::from_bytes([2, 119, 0, 0, 0, 1]), dns: "sample-a.vm.lan".into(), snaps: 0, share_clipboard: false,
        port_forwards: Vec::new(), template: None, linked_from: None, throwaway: false, isolated: false,
        disk_gb: None, disk_path: None, iso_path: None, secure_boot: None, tpm: None, ready: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_ui_fields_and_values() {
        let vm = sample();
        let json = serde_json::to_value(&vm).unwrap();
        assert_eq!(json["ramGb"], 4);
        assert_eq!(json["engine"], "Hyper-V");
        assert_eq!(json["state"], "off");
        assert_eq!(json["mac"], "02:77:00:00:00:01");
        assert_eq!(json["shareClipboard"], false);
        assert_eq!(json["portForwards"], serde_json::json!([]));
        let mut old = json.clone();
        let old_fields = old.as_object_mut().unwrap();
        old_fields.remove("shareClipboard");
        old_fields.remove("portForwards");
        assert_eq!(serde_json::from_value::<Vm>(old).unwrap(), vm);
        assert_eq!(serde_json::from_value::<Vm>(json).unwrap(), vm);
    }

    #[test]
    fn ready_origin_is_optional_and_strict() {
        let mut vm = sample();
        assert!(serde_json::to_value(&vm).unwrap().get("ready").is_none());
        vm.ready = Some(ReadyOrigin { image: "kali-2026-3-qemu".into(), default_login: Some("kali".into()), seed: false });
        let json = serde_json::to_value(&vm).unwrap();
        assert_eq!(json["ready"], serde_json::json!({"image":"kali-2026-3-qemu","defaultLogin":"kali","seed":false}));
        assert_eq!(serde_json::from_value::<Vm>(json.clone()).unwrap(), vm);
        let mut unknown = json;
        unknown["ready"]["password"] = serde_json::json!("never stored");
        assert!(serde_json::from_value::<Vm>(unknown).is_err());
    }
}
