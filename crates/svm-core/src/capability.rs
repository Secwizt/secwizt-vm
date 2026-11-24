use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Capability {
    Start, Stop, Pause, Resume, Snapshot, SnapshotWithMemory, Clone, UsbPassthrough,
    OwnLanAddress, Accelerated, Console, Thumbnail, Delete, RevertSnapshot, DeleteSnapshot,
    Shutdown, Restart, SendKeys, EnhancedSession,
}

impl Capability {
    pub const ALL: [Self;19] = [Self::Start,Self::Stop,Self::Pause,Self::Resume,
        Self::Snapshot,Self::SnapshotWithMemory,Self::Clone,Self::UsbPassthrough,
        Self::OwnLanAddress,Self::Accelerated,Self::Console,Self::Thumbnail,
        Self::Delete,Self::RevertSnapshot,Self::DeleteSnapshot,Self::Shutdown,Self::Restart,Self::SendKeys,Self::EnhancedSession];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySet { missing: BTreeMap<Capability,String> }

impl CapabilitySet {
    pub fn unavailable(reason: &str) -> Self {
        let mut out=Self { missing:BTreeMap::new() };
        for cap in Capability::ALL { out.deny(cap,reason); }
        out
    }
    pub fn allow(&mut self, cap: Capability) { self.missing.remove(&cap); }
    pub fn deny(&mut self, cap: Capability, reason: &str) {
        let reason=if reason.trim().is_empty() { "This engine cannot provide this control." } else { reason };
        self.missing.insert(cap,reason.into());
    }
    pub fn has(&self, cap: Capability) -> bool { !self.missing.contains_key(&cap) }
    pub fn reason(&self, cap: Capability) -> Option<&str> { self.missing.get(&cap).map(String::as_str) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_missing_control_has_a_reason() {
        let mut caps=CapabilitySet::unavailable("");
        caps.allow(Capability::Start);
        for c in Capability::ALL {
            assert_eq!(caps.has(c),c==Capability::Start);
            assert_eq!(caps.reason(c).is_some_and(|s| !s.is_empty()),c!=Capability::Start);
        }
    }
}
