use crate::{model::{HostInfo, Vm, VmState}, Error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug,PartialEq,Eq)]
pub enum Decision { Admit { cores:Vec<u16> }, Refuse { reason:String } }

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(default,rename_all="camelCase",deny_unknown_fields)]
pub struct HostGuard {
    pub enabled: bool,
    pub budget_pct: u8,
    pub reserve_gb: u32,
    pub max_running: Option<usize>,
    pub preferred_cores: Vec<u16>,
}
impl Default for HostGuard {
    fn default() -> Self {
        Self { enabled:false, budget_pct:100, reserve_gb:0, max_running:None, preferred_cores:Vec::new() }
    }
}

fn invalid(message:&str)->Error { Error::Invalid(message.into()) }

pub fn thread_budget(host:&HostInfo,percent:u8)->Result<u16,Error> {
    if host.logical==0 || !(1..=100).contains(&percent) {
        return Err(invalid("Choose a CPU budget between 1 and 100 percent on a host with logical processors."));
    }
    let threads = (u32::from(host.logical) * u32::from(percent) / 100) as u16;
    if threads == 0 { return Err(invalid("Choose a CPU budget that allows at least one whole thread.")); }
    Ok(threads)
}

pub fn check_budget_change(host:&HostInfo,percent:u8,machines:&[Vm])->Result<(),Error> {
    let limit=thread_budget(host,percent)?;
    let used:u64=machines.iter().filter(|v| v.state==VmState::Running).map(|v| u64::from(v.vcpu)).sum();
    if used>u64::from(limit) {
        return Err(Error::Invalid(format!("Running machines already use {used} threads. The proposed budget allows {limit}.")));
    }
    Ok(())
}

impl HostGuard {
    pub fn check_configuration(&self, host:&HostInfo, machines:&[Vm]) -> Result<(),Error> {
        if !(1..=100).contains(&self.budget_pct) { return Err(invalid("Choose a CPU budget between 1 and 100 percent.")); }
        if self.max_running == Some(0) { return Err(invalid("Set a positive machine limit or leave it unlimited.")); }
        let preferred: BTreeSet<_> = self.preferred_cores.iter().copied().collect();
        if preferred.len() != self.preferred_cores.len() || (self.enabled && preferred.iter().any(|c| *c >= host.logical)) {
            return Err(invalid("Choose distinct preferred logical cores that exist on this host."));
        }
        if !self.enabled { return Ok(()); }
        check_budget_change(host,self.budget_pct,machines)?;
        let running=machines.iter().filter(|v| v.state==VmState::Running).count();
        if self.max_running.is_some_and(|max| running > max) {
            return Err(invalid("More machines are already running than the proposed limit."));
        }
        let held:u64=machines.iter().filter(|v| matches!(v.state,VmState::Paused|VmState::Running)).map(|v| u64::from(v.ram_gb)).sum();
        if held+u64::from(self.reserve_gb) > u64::from(host.ram_gb) {
            return Err(invalid("The proposed host memory reserve exceeds the memory available alongside the active machines."));
        }
        Ok(())
    }

    pub fn advisory(&self,host:&HostInfo,machines:&[Vm],candidate:&Vm)->Vec<u16> {
        let mut seen=BTreeSet::new();
        let saved=candidate.cores.iter().copied().collect::<BTreeSet<_>>();
        if candidate.state==VmState::Paused && saved.len()==usize::from(candidate.vcpu)
            && saved.len()==candidate.cores.len() && saved.iter().all(|&c| c<host.logical) {
            return candidate.cores.clone();
        }
        let auto=[host.e_cores,host.p_cores].into_iter().flat_map(|[first,last]| first..=last);
        let preferred=self.preferred_cores.iter().copied().filter(|_| self.enabled);
        let slots:Vec<_>=preferred.chain(auto).chain(0..host.logical).filter(|&c| c<host.logical && seen.insert(c)).collect();
        let used:BTreeSet<_>=machines.iter().filter(|o|o.id!=candidate.id && matches!(o.state,VmState::Running|VmState::Paused))
            .flat_map(|o|o.cores.iter().copied()).collect();
        slots.iter().copied().filter(|c| !used.contains(c)).chain(slots.iter().copied().filter(|c| used.contains(c)))
            .take(usize::from(candidate.vcpu)).collect()
    }

    pub fn admit(&self,host:&HostInfo,machines:&[Vm],candidate:&Vm)->Decision {
        if self.enabled {
            if let Err(error)=self.check_start(host,machines,candidate) { return Decision::Refuse {reason:error.to_string()}; }
        }
        Decision::Admit {cores:self.advisory(host,machines,candidate)}
    }
    fn check_start(&self,host:&HostInfo,machines:&[Vm],v:&Vm)->Result<(),Error> {
        let limit=thread_budget(host,self.budget_pct)?;
        if v.id.trim().is_empty() || v.vcpu==0 || v.ram_gb==0 {
            return Err(invalid("A machine needs an ID, at least one processor thread and some memory."));
        }
        if v.state==VmState::Running { return Err(invalid("This machine is already running.")); }
        let mut ram=u64::from(self.reserve_gb)+u64::from(v.ram_gb);
        let mut threads=u64::from(v.vcpu);
        let mut running=0;
        for other in machines.iter().filter(|o| o.id!=v.id && matches!(o.state,VmState::Running|VmState::Paused)) {
            ram+=u64::from(other.ram_gb);
            if other.state==VmState::Running { threads+=u64::from(other.vcpu); running+=1; }
        }
        if threads>u64::from(limit) {
            return Err(Error::Invalid(format!("Starting this machine needs {threads} total threads. The {} percent budget allows {limit}.",self.budget_pct)));
        }
        if ram>u64::from(host.ram_gb) {
            return Err(Error::Invalid(format!("Starting this machine needs {ram} GB including the {} GB host reserve. The host has {} GB.",self.reserve_gb,host.ram_gb)));
        }
        if self.max_running.is_some_and(|max|running>=max) { return Err(invalid("The host has reached its configured limit of running machines.")); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sample;
    fn protection(percent:u8)->HostGuard { HostGuard { enabled:true,budget_pct:percent,max_running:Some(2),reserve_gb:12,preferred_cores:vec![] } }
    fn host()->HostInfo {HostInfo {logical:32,p_cores:[0,15],e_cores:[16,31],ram_gb:64}}
    #[test]
    fn disabled_policy_does_not_refuse_when_all_host_capacity_is_used() {
        let host=HostInfo {logical:2,p_cores:[0,1],e_cores:[1,0],ram_gb:8};
        let mut v=sample();v.vcpu=5;v.ram_gb=40;
        let mut running=v.clone();running.id="other".into();running.state=VmState::Running;running.cores=vec![0,1];
        assert_eq!(HostGuard::default().admit(&host,&[running],&v),Decision::Admit{cores:vec![0,1]});
    }
    #[test]
    fn percent_and_e_core_placement() {
        let mut a=sample();let mut b=a.clone();b.id="vm-b".into();
        assert_eq!(thread_budget(&host(),25).unwrap(),8);
        assert_eq!(protection(25).admit(&host(),&[],&a),Decision::Admit{cores:vec![16,17]});
        a.state=VmState::Running;a.cores=vec![16,17];
        assert_eq!(protection(25).admit(&host(),&[a],&b),Decision::Admit{cores:vec![18,19]});
    }
    #[test]
    fn cpu_and_memory_are_independent() {
        let mut a=sample();a.vcpu=9;
        assert!(matches!(protection(25).admit(&host(),&[],&a),Decision::Refuse{reason} if reason.contains("threads")));
        a.vcpu=1;a.ram_gb=53;
        assert!(matches!(protection(25).admit(&host(),&[],&a),Decision::Refuse{reason} if reason.contains("GB")));
    }
    #[test]
    fn budget_cannot_drop_below_running_allocation() {
        let mut a=sample();a.state=VmState::Running;a.vcpu=8;
        assert!(check_budget_change(&host(),24,std::slice::from_ref(&a)).is_err());
        assert!(check_budget_change(&host(),25,&[a]).is_ok());
    }
    #[test]
    fn paused_guest_retains_memory_and_cores_on_resume() {
        let mut a=sample();a.state=VmState::Paused;a.ram_gb=50;a.cores=vec![18,19];
        assert_eq!(protection(25).admit(&host(),std::slice::from_ref(&a),&a),Decision::Admit{cores:vec![18,19]});
        let mut b=sample();b.id="vm-b".into();
        assert!(matches!(protection(25).admit(&host(),&[a],&b),Decision::Refuse{..}));
    }
    #[test]
    fn running_job_limit_and_fallback_to_performance_cores() {
        let mut a=sample();a.state=VmState::Running;a.cores=vec![16,17];
        let mut b=a.clone();b.id="vm-b".into();b.cores=vec![18,19];
        let mut c=sample();c.id="vm-c".into();
        assert!(matches!(protection(25).admit(&host(),&[a.clone(),b],&c),Decision::Refuse{reason} if reason.contains("running machines")));
        let small=HostInfo {logical:6,p_cores:[0,3],e_cores:[4,5],ram_gb:64};
        a.cores=vec![4,5];
        assert_eq!(protection(100).admit(&small,&[a],&c),Decision::Admit{cores:vec![0,1]});
    }
}
