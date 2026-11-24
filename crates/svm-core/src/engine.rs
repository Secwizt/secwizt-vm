use std::collections::BTreeMap;
use thiserror::Error;
use crate::{capability::{Capability,CapabilitySet},model::{Snapshot,Vm,VmState}};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EngineError {
    #[error("No machine or checkpoint matches {0}.")]
    Missing(String),
    #[error("{0}")]
    Invalid(String),
    #[error("The fake engine failed the requested call: {0}.")]
    Injected(String),
    #[error("{0}")]
    Permission(String),
    #[error("The engine did not finish within {seconds} seconds. Check its state before retrying.")]
    Timeout { seconds: u64 },
    #[error("The guest did not confirm the power request within 25 seconds. Check its state before choosing Power off.")]
    GuestPowerTimeout,
    #[error("{0}")]
    Engine(String),
}

pub type EngineResult<T> = Result<T,EngineError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTransferUpdate {
    Progress { bytes: u64, total: Option<u64> },
    Publish,
}

/// Literal process arguments for one command inside an owned guest.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestExecRequest {
    pub argv: Vec<String>,
    pub timeout_sec: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
}

impl GuestExecRequest {
    pub fn check(&self) -> EngineResult<()> {
        if self.argv.is_empty() || self.argv[0].trim().is_empty() || self.argv.len() > 256
            || self.argv.iter().any(|arg| arg.len() > 8192 || arg.contains('\0')) {
            return Err(EngineError::Invalid("Supply an executable and a bounded argument array.".into()));
        }
        if !(1..=120).contains(&self.timeout_sec) {
            return Err(EngineError::Invalid("The guest command timeout must be between 1 and 120 seconds.".into()));
        }
        if self.stdin.as_ref().is_some_and(|stdin| stdin.len() > 128 * 1024) {
            return Err(EngineError::Invalid("Guest command input is too large.".into()));
        }
        Ok(())
    }
}


/// One US keyboard stroke. Zero uses Hyper-V's dedicated Ctrl+Alt+Del method.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct GuestStroke {
    pub code: u8,
    pub shift: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct GuestKeyReport {
    pub sent: usize,
    pub retried: bool,
    pub error: Option<String>,
}

// US keyboard punctuation: unshifted character, shifted character, Windows virtual key.
const US_KEY_PAIRS: &[(char, char, u8)] = &[
    ('1','!',0x31), ('2','@',0x32), ('3','#',0x33), ('4','$',0x34), ('5','%',0x35),
    ('6','^',0x36), ('7','&',0x37), ('8','*',0x38), ('9','(',0x39), ('0',')',0x30),
    ('`','~',0xc0), ('-','_',0xbd), ('=','+',0xbb), ('[','{',0xdb), (']','}',0xdd),
    ('\\','|',0xdc), (';',':',0xba), ('\'','"',0xde), (',','<',0xbc), ('.','>',0xbe), ('/','?',0xbf),
];

#[derive(Debug)]
pub struct GuestKeys(Vec<GuestStroke>);
impl GuestKeys {
    pub fn strokes(&self) -> &[GuestStroke] { &self.0 }
    pub fn from_text(text: &str) -> EngineResult<Self> { Self::from_text_with_enter(text, false) }
    pub fn from_text_with_enter(text: &str, append_enter: bool) -> EngineResult<Self> {
        let mut keys = Vec::new();
        for ch in text.chars() {
            let (code, shift) = if ch.is_ascii_alphabetic() {
                (ch.to_ascii_uppercase() as u8, ch.is_ascii_uppercase())
            } else if ch == ' ' {
                (0x20, false)
            } else if let Some(&(plain, _, vk)) = US_KEY_PAIRS.iter().find(|&&(plain, upper, _)| plain == ch || upper == ch) {
                (vk, ch != plain)
            } else {
                return Err(EngineError::Invalid(format!("Unsupported character {ch:?} (U+{:04X}). Use printable US-ASCII.", u32::from(ch))));
            };
            if keys.len() == 64 { return Err(EngineError::Invalid("Send at most 64 characters including an appended Enter.".into())); }
            keys.push(GuestStroke { code, shift });
        }
        if keys.is_empty() { return Err(EngineError::Invalid("Send at least one printable US-ASCII character.".into())); }
        if append_enter {
            if keys.len() == 64 { return Err(EngineError::Invalid("Send at most 64 characters including an appended Enter.".into())); }
            keys.push(GuestStroke { code: 13, shift: false });
        }
        Ok(Self(keys))
    }
    pub fn from_names(names: &[String]) -> EngineResult<Self> {
        if !(1..=64).contains(&names.len()) { return Err(EngineError::Invalid("Send 1 to 64 named keys.".into())); }
        let mut codes = Vec::with_capacity(names.len());
        for name in names {
            let name = name.to_ascii_lowercase();
            let code = match name.as_str() {
                "ctrl+alt+del" | "ctrlaltdel" => 0, "backspace" => 8, "tab" => 9, "enter" | "return" => 13,
                "escape" | "esc" => 27, "space" => 32, "pageup" => 33, "pagedown" => 34,
                "end" => 35, "home" => 36, "left" | "arrowleft" => 37, "up" | "arrowup" => 38,
                "right" | "arrowright" => 39, "down" | "arrowdown" => 40, "insert" => 45, "delete" | "del" => 46,
                other => {
                    let number = other.strip_prefix('f').and_then(|n|n.parse::<u8>().ok()).filter(|n|(1..=12).contains(n));
                    111 + number.ok_or_else(|| EngineError::Invalid("Unsupported guest key. Use a navigation key, F1 to F12, Enter, Tab, Space, Backspace, Escape, Delete or Ctrl+Alt+Del.".into()))?
                }
            };
            codes.push(GuestStroke { code, shift: false });
        }
        Ok(Self(codes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thumbnail { pub width:u16, pub height:u16, pub rgba:Vec<u8> }

pub trait EngineDriver {
    fn capabilities(&self, vm:&Vm) -> CapabilitySet;
    fn define(&mut self, vm:&Vm) -> EngineResult<()>;
    fn start(&mut self, id:&str) -> EngineResult<()>;
    fn stop(&mut self, id:&str) -> EngineResult<()>;
    fn shutdown(&mut self, id:&str) -> EngineResult<()>;
    fn restart(&mut self, id:&str) -> EngineResult<()>;
    fn send_keys(&mut self, id:&str, keys:&GuestKeys) -> EngineResult<GuestKeyReport>;
    fn pause(&mut self, id:&str) -> EngineResult<()>;
    fn resume(&mut self, id:&str) -> EngineResult<()>;
    fn list_snapshots(&mut self, _id:&str) -> EngineResult<Vec<Snapshot>> {
        Err(EngineError::Invalid("This engine cannot list checkpoints.".into()))
    }
    fn snapshot(&mut self, id:&str, name:&str, with_memory:bool) -> EngineResult<Snapshot>;
    fn revert(&mut self, id:&str, snapshot_id:&str) -> EngineResult<()>;
    fn delete_snapshot(&mut self, id:&str, snapshot_id:&str) -> EngineResult<()>;
    fn remove(&mut self, id:&str) -> EngineResult<()>;
    fn state(&mut self, id:&str) -> EngineResult<VmState>;
    fn thumbnail(&mut self, id:&str) -> EngineResult<Thumbnail>;
}

#[derive(serde::Serialize,serde::Deserialize)]
struct Machine {
    state:VmState,
    head:Option<String>,
    next:u64,
    snapshots:BTreeMap<String,(Snapshot,VmState)>,
}

#[derive(Default)]
pub struct FakeEngine { machines:BTreeMap<String,Machine>, failure:Option<String> }

impl FakeEngine {
    pub fn archive_registration(&mut self,id:&str)->EngineResult<serde_json::Value> {
        serde_json::to_value(self.machine(id)?).map_err(|_|EngineError::Invalid("Invalid test guest state.".into()))
    }
    pub fn import_registration(&mut self,vm:&Vm,archive:&serde_json::Value)->EngineResult<()> {
        if self.machines.contains_key(&vm.id) {return Err(EngineError::Invalid("The registration already exists.".into()));}
        let err=||EngineError::Invalid("The saved test registration could not be verified.".into());
        let record:Vm=serde_json::from_value(archive["vm"].clone()).map_err(|_|err())?;
        if record.id!=vm.id {return Err(err());}
        let machine:Machine=if let Some(saved)=archive.get("registration") {
            serde_json::from_value(saved.clone()).map_err(|_|err())?
        } else {
            let rows:Vec<Snapshot>=serde_json::from_value(archive["snapshots"].clone()).map_err(|_|err())?;
            let mut m=Machine {state:record.state,head:None,next:1,snapshots:BTreeMap::new()};
            for snap in rows {
                let n=snap.id.strip_prefix("snapshot-").and_then(|s|s.parse::<u64>().ok()).and_then(|n|n.checked_add(1)).ok_or_else(err)?;
                m.next=m.next.max(n);
                let state=if snap.with_memory {VmState::Running} else {VmState::Off};
                m.head=Some(snap.id.clone());m.snapshots.insert(snap.id.clone(),(snap,state));
            }
            m
        };
        self.machines.insert(vm.id.clone(),machine);
        Ok(())
    }
    pub fn unregister_saved(&mut self,id:&str)->EngineResult<()> {
        self.check("remove")?;
        if self.machine(id)?.state!=VmState::Saved {return Err(EngineError::Invalid("A saved registration was expected.".into()));}
        self.machines.remove(id);
        Ok(())
    }
    pub fn fail_next(&mut self, call:&str) { self.failure=Some(call.into()); }
    fn check(&mut self, call:&str) -> EngineResult<()> {
        if self.failure.as_deref()==Some(call) {
            self.failure=None;
            return Err(EngineError::Injected(call.into()));
        }
        Ok(())
    }
    fn machine(&mut self, id:&str) -> EngineResult<&mut Machine> {
        self.machines.get_mut(id).ok_or_else(||EngineError::Missing(id.into()))
    }
    fn transition(&mut self,id:&str,call:&str,from:&[VmState],to:VmState) -> EngineResult<()> {
        self.check(call)?;
        let machine=self.machine(id)?;
        if !from.contains(&machine.state) {
            return Err(EngineError::Invalid(format!("Cannot {call} this machine in its current state.")));
        }
        machine.state=to;
        Ok(())
    }
}
impl EngineDriver for FakeEngine {
    fn capabilities(&self,vm:&Vm)->CapabilitySet {
        use Capability::*;
        let mut caps=CapabilitySet::unavailable("The test engine does not provide this feature.");
        if let Some(m)=self.machines.get(&vm.id) {
            for cap in [Snapshot, RevertSnapshot, DeleteSnapshot] { caps.allow(cap); }
            if matches!(m.state, VmState::Off | VmState::Saved) { caps.allow(Delete); }
            if m.state==VmState::Off {caps.allow(Clone); }
            match m.state {
                VmState::Off => caps.allow(Start),
                VmState::Saved => { caps.allow(Start); caps.allow(Stop); }
                VmState::Running | VmState::Paused => {
                    caps.allow(if m.state==VmState::Running {Pause} else {Resume});
                    if m.state==VmState::Running { for cap in [Shutdown,Restart,SendKeys] {caps.allow(cap);} }
                    for c in [Stop,Thumbnail,SnapshotWithMemory] { caps.allow(c); }
                }
            }
        }
        caps
    }
    fn define(&mut self,vm:&Vm)->EngineResult<()> {
        self.check("define")?;
        if vm.id.trim().is_empty() || self.machines.contains_key(&vm.id) {
            return Err(EngineError::Invalid("A new machine requires a unique nonempty ID.".into()));
        }
        self.machines.insert(vm.id.clone(),Machine {state:vm.state,head:None,next:1,snapshots:BTreeMap::new()});
        Ok(())
    }
    fn start(&mut self,id:&str)->EngineResult<()> {self.transition(id,"start",&[VmState::Off,VmState::Saved],VmState::Running)}
    fn stop(&mut self,id:&str)->EngineResult<()> {self.transition(id,"stop",&[VmState::Running,VmState::Paused,VmState::Saved],VmState::Off)}
    fn shutdown(&mut self,id:&str)->EngineResult<()> {self.transition(id,"shutdown",&[VmState::Running],VmState::Off)}
    fn restart(&mut self,id:&str)->EngineResult<()> {self.transition(id,"restart",&[VmState::Running],VmState::Running)}
    fn send_keys(&mut self,id:&str,keys:&GuestKeys)->EngineResult<GuestKeyReport> {
        self.transition(id,"keys",&[VmState::Running],VmState::Running)?;
        Ok(GuestKeyReport { sent: keys.strokes().len(), retried: false, error: None })
    }
    fn pause(&mut self,id:&str)->EngineResult<()> {self.transition(id,"pause",&[VmState::Running],VmState::Paused)}
    fn resume(&mut self,id:&str)->EngineResult<()> {self.transition(id,"resume",&[VmState::Paused],VmState::Running)}
    fn list_snapshots(&mut self,id:&str)->EngineResult<Vec<Snapshot>> {
        self.check("list_snapshots")?;
        Ok(self.machine(id)?.snapshots.values().map(|(snap,_)|snap.clone()).collect())
    }
    fn snapshot(&mut self,id:&str,name:&str,with_memory:bool)->EngineResult<Snapshot> {
        self.check("snapshot")?;
        let m=self.machine(id)?;
        if name.trim().is_empty() || (with_memory && !matches!(m.state,VmState::Paused|VmState::Running)) {
            return Err(EngineError::Invalid("A checkpoint needs a name and memory capture needs an active guest.".into()));
        }
        let snap=Snapshot {id:format!("snapshot-{}",m.next),name:name.into(),parent:m.head.clone(),with_memory,consistency:None};
        m.next=m.next.checked_add(1).ok_or_else(||EngineError::Invalid("Checkpoint IDs exhausted.".into()))?;
        m.head=Some(snap.id.clone());m.snapshots.insert(snap.id.clone(),(snap.clone(),m.state));
        Ok(snap)
    }
    fn revert(&mut self,id:&str,snapshot_id:&str)->EngineResult<()> {
        self.check("revert")?;
        let m=self.machine(id)?;
        let (snap,saved)=m.snapshots.get(snapshot_id).ok_or_else(||EngineError::Missing(snapshot_id.into()))?;
        if snap.with_memory { m.state=*saved; }
        m.head=Some(snap.id.clone());Ok(())
    }
    fn delete_snapshot(&mut self,id:&str,snapshot_id:&str)->EngineResult<()> {
        self.check("delete_snapshot")?;
        let m=self.machine(id)?;
        let (snap,_)=m.snapshots.remove(snapshot_id).ok_or_else(||EngineError::Missing(snapshot_id.into()))?;
        for (child,_) in m.snapshots.values_mut() {
            if child.parent.as_deref()==Some(snapshot_id) {child.parent=snap.parent.clone();}
        }
        if m.head.as_deref()==Some(snapshot_id) {m.head=snap.parent;}
        Ok(())
    }
    fn remove(&mut self,id:&str)->EngineResult<()> {
        self.check("remove")?;
        if self.machine(id)?.state!=VmState::Off {return Err(EngineError::Invalid("The machine must be off to remove it.".into()));}
        self.machines.remove(id);Ok(())
    }
    fn state(&mut self,id:&str)->EngineResult<VmState> {
        self.check("state")?;Ok(self.machine(id)?.state)
    }
    fn thumbnail(&mut self,id:&str)->EngineResult<Thumbnail> {
        self.check("thumbnail")?;
        let rgba=match self.machine(id)?.state {
            VmState::Running=>vec![8,32,64,255], VmState::Paused=>vec![64,48,8,255],
            _=>return Err(EngineError::Invalid("A machine without an active display has no thumbnail.".into())),
        };
        Ok(Thumbnail {width:1,height:1,rgba})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sample;
    #[test]
    fn transitions_and_failures_are_deterministic() {
        let mut e=FakeEngine::default();let v=sample();e.define(&v).unwrap();
        assert!(e.capabilities(&v).has(Capability::Start));
        e.fail_next("start");assert_eq!(e.start(&v.id),Err(EngineError::Injected("start".into())));
        assert_eq!(e.state(&v.id).unwrap(),VmState::Off);
        e.start(&v.id).unwrap();e.pause(&v.id).unwrap();e.resume(&v.id).unwrap();
        let snap=e.snapshot(&v.id,"Boot",true).unwrap();
        e.stop(&v.id).unwrap();e.revert(&v.id,&snap.id).unwrap();
        assert_eq!(e.state(&v.id).unwrap(),VmState::Running);
        assert_eq!(e.thumbnail(&v.id).unwrap().rgba.len(),4);
        e.delete_snapshot(&v.id,&snap.id).unwrap();assert!(e.revert(&v.id,&snap.id).is_err());
        e.stop(&v.id).unwrap();e.remove(&v.id).unwrap();assert!(e.state(&v.id).is_err());
    }
}
