use crate::{model::{Network, Vm}, Error};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, net::Ipv4Addr, str::FromStr};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const fn from_bytes(bytes: [u8; 6]) -> Self { Self(bytes) }
    pub const fn octets(self) -> [u8; 6] { self.0 }
    pub fn is_station(self) -> bool { self.0[0] & 1 == 0 && self.0 != [0; 6] }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a,b,c,d,e,g] = self.0;
        write!(f, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
    }
}
impl From<MacAddr> for String {
    fn from(value: MacAddr) -> Self { value.to_string() }
}
impl TryFrom<String> for MacAddr {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> { s.parse() }
}
impl FromStr for MacAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let invalid = || Error::Invalid("Enter six hexadecimal MAC octets separated by colons.".into());
        let mut iter = s.split(':');
        let mut bytes = [0; 6];
        for b in &mut bytes {
            let part = iter.next().ok_or_else(invalid)?;
            if part.len()!=2 || !part.bytes().all(|c| c.is_ascii_hexdigit()) { return Err(invalid()); }
            *b = u8::from_str_radix(part,16).map_err(|_| invalid())?;
        }
        if iter.next().is_some() { return Err(invalid()); }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Subnet { base: Ipv4Addr, prefix: u8 }

impl FromStr for Subnet {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let invalid = || Error::Invalid("Use an aligned IPv4 subnet with at least two usable host addresses.".into());
        let (addr, bits) = s.split_once('/').ok_or_else(invalid)?;
        let base = addr.parse::<Ipv4Addr>().map_err(|_| invalid())?;
        let prefix = bits.parse::<u8>().map_err(|_| invalid())?;
        if prefix > 30 { return Err(invalid()); }
        let net = Self { base, prefix };
        if u32::from(base) & !u32::from(net.mask()) != 0 { return Err(invalid()); }
        Ok(net)
    }
}
impl From<Subnet> for String {
    fn from(n: Subnet) -> Self { format!("{}/{}", n.base, n.prefix) }
}
impl TryFrom<String> for Subnet {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> { value.parse() }
}
impl Subnet {
    pub fn base(self) -> Ipv4Addr { self.base }
    pub fn mask(self) -> Ipv4Addr {
        Ipv4Addr::from(if self.prefix == 0 { 0 } else { u32::MAX << (32-self.prefix) })
    }
    pub fn broadcast(self) -> Ipv4Addr { Ipv4Addr::from(u32::from(self.base) | !u32::from(self.mask())) }
    pub fn usable(self, ip: Ipv4Addr) -> bool { self.base < ip && ip < self.broadcast() }
    pub fn overlaps(self, other: Self) -> bool { self.base <= other.broadcast() && other.base <= self.broadcast() }
}

pub fn validate_subnets(networks: &[Network], host_lan: Subnet) -> Result<(), Error> {
    for (i,n) in networks.iter().enumerate() {
        if n.id.trim().is_empty() || networks[..i].iter().any(|p| p.id == n.id) {
            return Err(Error::Invalid("Each network needs a unique nonempty ID.".into()));
        }
        if n.gateway.is_some_and(|ip| !n.subnet.usable(ip)) {
            return Err(Error::Invalid(format!("The gateway for {} is outside its usable range.",n.name)));
        }
        if n.subnet.overlaps(host_lan) || networks[..i].iter().any(|p| p.subnet.overlaps(n.subnet)) {
            return Err(Error::Invalid(format!("The subnet for {} overlaps the host LAN or another network.", n.name)));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity { pub mac: MacAddr, pub ip: Ipv4Addr, pub dns: String }

pub fn allocate_mac(used: &BTreeSet<MacAddr>) -> Result<MacAddr, Error> {
    for i in 1..=0xff_ffffu32 {
        let [_,a,b,c] = i.to_be_bytes();
        let mac = MacAddr([0x02,0x77,0,a,b,c]);
        if !used.contains(&mac) { return Ok(mac); }
    }
    Err(Error::Invalid("The local MAC address pool is full.".into()))
}

fn dns_name(name: &str, vms: &[Vm]) -> String {
    let mut stem = String::new();
    for c in name.bytes() {
        if c.is_ascii_alphanumeric() { stem.push(char::from(c.to_ascii_lowercase())); }
        else if !stem.is_empty() && !stem.ends_with('-') { stem.push('-'); }
        if stem.len() == 40 { break; }
    }
    let stem = stem.trim_end_matches('-');
    let stem = if stem.is_empty() { "machine" } else { stem };
    let mut candidate = format!("{stem}.vm.lan");
    let mut suffix = 2usize;
    while vms.iter().any(|v| v.dns.eq_ignore_ascii_case(&candidate)) {
        candidate = format!("{stem}-{suffix}.vm.lan");
        suffix += 1;
    }
    candidate
}

pub fn allocate(id: &str, name: &str, net: &Network, vms: &[Vm]) -> Result<Identity, Error> {
    if id.trim().is_empty() || name.trim().is_empty() { return Err(Error::Invalid("A machine ID and name are required.".into())); }
    if let Some(vm) = vms.iter().find(|v| v.id == id) {
        if vm.net != net.id || !net.subnet.usable(vm.ip) || net.gateway == Some(vm.ip) {
            return Err(Error::Invalid("The saved reservation does not fit this network.".into()));
        }
        return Ok(Identity { mac:vm.mac, ip:vm.ip, dns:vm.dns.clone() });
    }
    let used = vms.iter().map(|v| v.ip).collect::<BTreeSet<_>>();
    let range = (u32::from(net.subnet.base())+1)..u32::from(net.subnet.broadcast());
    let ip = range.map(Ipv4Addr::from).find(|ip| Some(*ip)!=net.gateway && !used.contains(ip)
        && (net.mode!=crate::model::NetworkMode::LinkLocal || (1..255).contains(&ip.octets()[2])))
        .ok_or_else(|| Error::Invalid("No free IPv4 reservation remains in this subnet.".into()))?;
    let mac = allocate_mac(&vms.iter().map(|v| v.mac).collect())?;
    Ok(Identity { mac, ip, dns:dns_name(name,vms) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{sample,NetworkMode};
    fn net() -> Network {
        Network { bridge:None, id:"lab".into(),name:"Lab".into(),mode:NetworkMode::Routed,subnet:"10.77.1.0/24".parse().unwrap(),
            gateway:Some(Ipv4Addr::new(10,77,1,1)),dhcp:true,note:String::new() }
    }
    #[test]
    fn thousand_unique_local_macs() {
        let mut used=BTreeSet::new();
        for _ in 0..1000 {
            let mac=allocate_mac(&used).unwrap();
            assert_eq!(mac.octets()[0]&3,2);
            assert!(used.insert(mac));
        }
    }
    #[test]
    fn clone_and_repeat() {
        let v=sample(); let all=std::slice::from_ref(&v);
        let a=allocate(&v.id,&v.name,&net(),all).unwrap();
        assert_eq!((a.mac,a.ip),(v.mac,v.ip));
        let b=allocate("vm-b",&v.name,&net(),all).unwrap();
        assert_ne!(a.mac,b.mac); assert_ne!(a.ip,b.ip); assert_eq!(b.dns,"sample-a-2.vm.lan");
    }
    #[test]
    fn overlapping_networks_and_lan_are_refused() {
        let n=net(); let host="10.77.0.0/24".parse().unwrap();
        assert!(validate_subnets(std::slice::from_ref(&n),host).is_ok());
        let mut other=n.clone();other.id="other".into();other.subnet="10.77.1.0/25".parse().unwrap();
        assert!(validate_subnets(&[n.clone(),other],host).is_err());
        assert!(validate_subnets(std::slice::from_ref(&n),n.subnet).is_err());
        assert!("10.77.1.1/24".parse::<Subnet>().is_err());
    }
    #[test]
    fn exhausted_subnet_preserves_existing_reservations() {
        let mut n=net();n.subnet="10.77.1.0/30".parse().unwrap();
        let mut v=sample();let first=allocate(&v.id,&v.name,&n,&[]).unwrap();
        v.ip=first.ip;v.mac=first.mac;v.dns=first.dns;
        assert_eq!(v.ip,Ipv4Addr::new(10,77,1,2));
        assert!(allocate("new-id","Another",&n,std::slice::from_ref(&v)).is_err());
        assert_eq!(allocate(&v.id,&v.name,&n,std::slice::from_ref(&v)).unwrap().ip,v.ip);
    }
}
