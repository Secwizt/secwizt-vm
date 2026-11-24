use crate::{identity::{MacAddr,Subnet},storage::{read_json,write_json},Error};
use serde::{Deserialize,Serialize};
use std::{collections::{BTreeMap,BTreeSet},io,net::{Ipv4Addr,SocketAddr,SocketAddrV4,UdpSocket},path::Path,sync::Mutex,time::{Duration,Instant}};

const COOKIE:[u8;4]=[99,130,83,99];
const DISCOVER:u8=1;
const OFFER:u8=2;
const REQUEST:u8=3;
const DECLINE:u8=4;
const ACK:u8=5;
const NAK:u8=6;
const RELEASE:u8=7;
const INFORM:u8=8;
const LEASE_CHANGE_WINDOW: Duration = Duration::from_secs(10);
const MAX_LEASE_CHANGES: u8 = 4;
const DECLINE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase")]
pub struct Config {
    pub subnet:Subnet,
    pub router:Option<Ipv4Addr>,
    pub dns:Option<Ipv4Addr>,
    pub lease_seconds:u32,
    pub boot_file:Option<String>,
}

#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub enum LeaseState { Reserved,Active,Declined }
#[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
pub struct Reservation {pub ip:Ipv4Addr,pub state:LeaseState}
#[derive(Debug,Serialize,Deserialize)]
struct TableData {
    config: Config,
    entries: BTreeMap<MacAddr, Reservation>,
    #[serde(skip)]
    recent_changes: BTreeMap<MacAddr, (Instant, u8)>,
    #[serde(skip)]
    declines: BTreeMap<MacAddr, Instant>,
}
#[derive(Debug)]
pub struct LeaseTable {data:Mutex<TableData>}

impl TableData {
    fn with_entries(config: Config, entries: BTreeMap<MacAddr, Reservation>) -> Self {
        Self { config, entries, recent_changes: BTreeMap::new(), declines: BTreeMap::new() }
    }

    fn visible(&self, mac: &MacAddr, mut entry: Reservation, now: Instant) -> Reservation {
        if entry.state == LeaseState::Declined && self.declines.get(mac).is_none_or(|until| *until <= now) {
            entry.state = LeaseState::Reserved;
        }
        entry
    }

    fn validate(&self)->Result<(),Error> {
        let c=&self.config;
        if c.lease_seconds==0 || c.router.is_some_and(|ip|!c.subnet.usable(ip)) ||
            c.boot_file.as_ref().is_some_and(|s| s.is_empty() || s.len()>127 || !s.bytes().all(|b|b.is_ascii_graphic()||b==b' ')) {
            return Err(Error::Invalid("The DHCP router, lease duration or boot filename is invalid.".into()));
        }
        let mut ips=BTreeSet::new();
        for (mac,r) in &self.entries {
            if !mac.is_station() || !c.subnet.usable(r.ip) || Some(r.ip)==c.router || Some(r.ip)==c.dns || !ips.insert(r.ip) {
                return Err(Error::Invalid("DHCP reservations need valid station MACs and unique usable host addresses.".into()));
            }
        }
        Ok(())
    }
}
impl LeaseTable {
    pub fn new(config:Config)->Result<Self,Error> {
        let data=TableData::with_entries(config,BTreeMap::new());data.validate()?;Ok(Self{data:Mutex::new(data)})
    }
    fn lock(&self)->Result<std::sync::MutexGuard<'_,TableData>,Error> {
        self.data.lock().map_err(|_|Error::Invalid("The lease table is unavailable.".into()))
    }
    pub fn reserve(&self,mac:MacAddr,ip:Ipv4Addr)->Result<(),Error> {
        let mut data=self.lock()?;
        if let Some(r)=data.entries.get(&mac) {
            if r.ip==ip {return Ok(());}
            return Err(Error::Conflict(format!("A reservation already exists for {mac}.")));
        }
        if !mac.is_station() || !data.config.subnet.usable(ip) || Some(ip)==data.config.router ||
            Some(ip)==data.config.dns || data.entries.values().any(|r|r.ip==ip) {
            return Err(Error::Invalid("Choose an unused host address and a valid unicast MAC.".into()));
        }
        data.entries.insert(mac,Reservation{ip,state:LeaseState::Reserved});Ok(())
    }
    pub fn reservation(&self,mac:MacAddr)->Result<Option<Reservation>,Error> {
        let data=self.lock()?;
        Ok(data.entries.get(&mac).map(|&entry| data.visible(&mac, entry, Instant::now())))
    }
    pub fn reservations(&self) -> Result<BTreeMap<MacAddr, Reservation>, Error> {
        let data=self.lock()?;
        let now=Instant::now();
        Ok(data.entries.iter().map(|(mac, &entry)| (*mac, data.visible(mac, entry, now))).collect())
    }

    /// Keep existing active and declined bindings for unchanged guest identities.
    pub fn sync_reservations(&self, desired: &BTreeMap<MacAddr, Ipv4Addr>) -> Result<bool, Error> {
        let mut data = self.lock()?;
        let entries = desired.iter().map(|(&mac, &ip)| {
            let existing = data.entries.get(&mac).copied().filter(|binding| binding.ip == ip);
            (mac, existing.unwrap_or(Reservation { ip, state: LeaseState::Reserved }))
        }).collect();
        let updated = TableData::with_entries(data.config.clone(), entries);
        updated.validate()?;
        if updated.entries == data.entries { return Ok(false); }
        let TableData {entries,recent_changes,declines,..}=&mut *data;
        let unchanged = |mac: &MacAddr| entries.get(mac).zip(updated.entries.get(mac))
            .is_some_and(|(old, new)| old.ip == new.ip);
        recent_changes.retain(|mac, _| unchanged(mac));
        declines.retain(|mac, _| unchanged(mac));
        *entries = updated.entries;
        Ok(true)
    }

    /// Update only the advertised DNS endpoint. Preserve the state of every existing reservation.
    pub fn set_dns(&self,address:Option<Ipv4Addr>)->Result<bool,Error> {
        let mut data=self.lock()?;
        if address.is_some_and(|ip|!data.config.subnet.usable(ip) || data.entries.values().any(|r|r.ip==ip)) {
            return Err(Error::Conflict("The DNS endpoint must be a free host address.".into()));
        }
        if data.config.dns==address {return Ok(false);}
        data.config.dns=address;
        Ok(true)
    }
    pub fn config(&self) -> Result<Config, Error> { Ok(self.lock()?.config.clone()) }

    pub fn clear_decline(&self,mac:MacAddr)->Result<(),Error> {
        let mut d=self.lock()?;
        let r=d.entries.get_mut(&mac).ok_or_else(||Error::Missing(mac.to_string()))?;
        if r.state==LeaseState::Declined {r.state=LeaseState::Reserved;}
        d.declines.remove(&mac);
        Ok(())
    }
    pub fn save(&self,path:&Path)->Result<(),Error> {
        let d=self.lock()?;write_json(path,&*d)
    }
    pub fn load(path:&Path)->Result<Self,Error> {
        let mut data:TableData=read_json(path)?;
        data.validate()?;
        for binding in data.entries.values_mut() {
            if binding.state == LeaseState::Declined { binding.state = LeaseState::Reserved; }
        }
        Ok(Self{data:Mutex::new(data)})
    }
}

#[derive(Default)]
struct Options {msg:Option<u8>,requested:Option<Ipv4Addr>,server:Option<Ipv4Addr>}
fn address(bytes:&[u8])->Option<Ipv4Addr> {
    let octets:[u8;4]=bytes.try_into().ok()?;Some(Ipv4Addr::from(octets))
}
fn parse_options(mut tail:&[u8])->Option<Options> {
    let mut options=Options::default();
    while let Some((&tag,rest))=tail.split_first() {
        tail=rest;
        match tag {
            0=>continue,
            255=>return Some(options),
            _=>{}
        }
        let (&len,rest)=tail.split_first()?;
        let (value,rest)=rest.split_at_checked(usize::from(len))?;
        tail=rest;
        match tag {
            53 if options.msg.is_none() && value.len()==1 => options.msg=Some(value[0]),
            50 if options.requested.is_none() => options.requested=Some(address(value)?),
            54 if options.server.is_none() => options.server=Some(address(value)?),
            53|50|54=>return None,
            _=>{}
        }
    }
    None
}
fn ip_option(reply:&mut Vec<u8>,code:u8,ip:Ipv4Addr) {
    reply.extend_from_slice(&[code,4]);reply.extend_from_slice(&ip.octets());
}
fn reply(packet:&[u8],response:u8,ip:Ipv4Addr,server:Ipv4Addr,config:&Config,inform:bool)->Vec<u8> {
    let mut out=vec![0;240];
    out[..3].copy_from_slice(&[2,1,6]);
    out[4..8].copy_from_slice(&packet[4..8]);
    out[10..12].copy_from_slice(&packet[10..12]);
    out[28..44].copy_from_slice(&packet[28..44]);
    out[236..240].copy_from_slice(&COOKIE);
    out.extend_from_slice(&[53,1,response]);
    ip_option(&mut out,54,server);
    if response!=NAK {
        if !inform {
            out[16..20].copy_from_slice(&ip.octets());
            out[20..24].copy_from_slice(&server.octets());
            out.extend_from_slice(&[51,4]);out.extend_from_slice(&config.lease_seconds.to_be_bytes());
        }
        ip_option(&mut out,1,config.subnet.mask());
        if let Some(ip)=config.router {ip_option(&mut out,3,ip);}
        if let Some(ip)=config.dns {
            ip_option(&mut out,6,ip);
            if ip==server {out.extend_from_slice(&[15,6]);out.extend_from_slice(b"vm.lan");}
        }
        if let Some(name)=&config.boot_file {
            let data=name.as_bytes();
            out[108..108+data.len()].copy_from_slice(data);
            out.extend_from_slice(&[67,data.len() as u8]);out.extend_from_slice(data);
        }
    }
    out.push(255);
    if out.len()<300 {out.resize(300,0);}
    out
}

pub fn handle(packet:&[u8],table:&LeaseTable,server_ip:Ipv4Addr)->Option<Vec<u8>> {
    process(packet, table, server_ip)?.response
}

/// A recognized transaction for a reservation on this server. Lease changes are captured under the table lock.
pub struct Exchange {
    pub message: u8,
    pub response: Option<Vec<u8>>,
    pub changed: Option<(MacAddr, Reservation)>,
}

pub fn process(packet: &[u8], table: &LeaseTable, server_ip: Ipv4Addr) -> Option<Exchange> {
    process_at(packet, table, server_ip, Instant::now())
}

fn allow_change(changes: &mut BTreeMap<MacAddr, (Instant, u8)>, mac: MacAddr, now: Instant) -> bool {
    let (since, count) = changes.entry(mac).or_insert((now, 0));
    if now.duration_since(*since) >= LEASE_CHANGE_WINDOW { (*since, *count) = (now, 0); }
    if *count >= MAX_LEASE_CHANGES { return false; }
    *count += 1;
    true
}

fn process_at(packet: &[u8], table: &LeaseTable, server_ip: Ipv4Addr, now: Instant) -> Option<Exchange> {
    if packet.len()<240 || packet[..3]!=[1,1,6] || packet[236..240]!=COOKIE || packet[24..28]!=[0;4] {return None;}
    let options=parse_options(&packet[240..])?;
    if options.server.is_some_and(|ip|ip!=server_ip) {return None;}
    let mac=MacAddr::from_bytes(packet[28..34].try_into().ok()?);
    let ciaddr=address(&packet[12..16])?;
    let mut guard=table.lock().ok()?;
    let TableData {config,entries,recent_changes,declines}=&mut *guard;
    if !config.subnet.usable(server_ip) {return None;}
    let binding=entries.get_mut(&mac)?;
    if binding.ip==server_ip {return None;}
    if binding.state == LeaseState::Declined && declines.get(&mac).is_none_or(|until| *until <= now) {
        binding.state = LeaseState::Reserved;
        declines.remove(&mac);
    }
    let message=options.msg?;
    let before = *binding;
    let response=match message {
        RELEASE => {
            if ciaddr==binding.ip && binding.state==LeaseState::Active {binding.state=LeaseState::Reserved;}
            None
        }
        DECLINE => {
            if options.requested==Some(binding.ip) && options.server==Some(server_ip) {binding.state=LeaseState::Declined;}
            None
        }
        DISCOVER if binding.state!=LeaseState::Declined && ciaddr.is_unspecified()=>Some(OFFER),
        REQUEST => {
            let requested=options.requested.or_else(||(!ciaddr.is_unspecified()).then_some(ciaddr))?;
            if requested!=binding.ip || (!ciaddr.is_unspecified() && ciaddr!=binding.ip) || binding.state==LeaseState::Declined {Some(NAK)}
            else {binding.state=LeaseState::Active;Some(ACK)}
        }
        INFORM if ciaddr==binding.ip && binding.state!=LeaseState::Declined=>Some(ACK),
        _=>return None,
    };
    if before != *binding {
        if !allow_change(recent_changes, mac, now) {
            *binding = before;
            return Some(Exchange { message, response: None, changed: None });
        }
        if binding.state == LeaseState::Declined {
            declines.insert(mac, now + DECLINE_TTL);
        }
    }
    Some(Exchange {
        message,
        response: response.map(|kind| reply(packet,kind,binding.ip,server_ip,config,message==INFORM)),
        changed: (before != *binding).then_some((mac, *binding)),
    })
}

/// Dispatch one DHCP datagram. Alternative ports and unicast replies are confined to loopback tests.
pub fn serve_one_with(
    socket: &UdpSocket, server_ip: Ipv4Addr, client_port: u16,
    process: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> io::Result<bool> {
    receive_one(socket, server_ip, client_port, |packet, _, send| {
        if let Some(reply) = process(packet) { send(&reply)?; }
        Ok(())
    })
}

/// The three datagram operations used by the wire path. Tests can supply the IPv4
/// source address a physical client uses before it owns an address.
pub trait DatagramSocket {
    fn local_endpoint(&self) -> io::Result<SocketAddr>;
    fn receive(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn transmit(&self, packet: &[u8], to: SocketAddr) -> io::Result<usize>;
}

impl DatagramSocket for UdpSocket {
    fn local_endpoint(&self) -> io::Result<SocketAddr> { self.local_addr() }
    fn receive(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> { self.recv_from(buf) }
    fn transmit(&self, packet: &[u8], to: SocketAddr) -> io::Result<usize> { self.send_to(packet, to) }
}

/// Receive on the address-specific socket and use that same socket and port for the response.
pub fn receive_one(
    socket: &impl DatagramSocket, server_ip: Ipv4Addr, client_port: u16,
    process: impl FnOnce(&[u8], SocketAddr, &dyn Fn(&[u8]) -> io::Result<()>) -> io::Result<()>,
) -> io::Result<bool> {
    let local = socket.local_endpoint()?;
    let test_ports = server_ip.is_loopback() && local.port() >= 1024 && client_port >= 1024;
    if local.ip() != server_ip || server_ip.is_unspecified()
        || (!test_ports && (local.port() != 67 || client_port != 68)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Use the serving interface and the DHCP server and client ports."));
    }
    let mut buf = [0u8; 65535];
    let (n, src) = match socket.receive(&mut buf) {
        Ok(packet) => packet,
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(false),
        Err(e) if transient_datagram_error(&e) => return Ok(true),
        Err(e) => return Err(e),
    };
    if src.port() != client_port || n < 240 || (test_ports && !src.ip().is_loopback()) { return Ok(true); }
    let packet = &buf[..n];
    process(packet, src, &|data| {
        let destination = if test_ports { src } else { reply_destination(packet, data) };
        let size = socket.transmit(data, destination)?;
        if size == data.len() { Ok(()) } else { Err(io::Error::new(io::ErrorKind::WriteZero, "Incomplete DHCP reply.")) }
    })?;
    Ok(true)
}

fn transient_datagram_error(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused)
        || (cfg!(windows) && error.raw_os_error() == Some(10040))
}

/// Select the RFC 2131 client endpoint from a validated BOOTP header and reply.
fn reply_destination(packet: &[u8], reply: &[u8]) -> SocketAddr {
    let ciaddr = packet.get(12..16).and_then(address).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let broadcast = reply.get(242) == Some(&NAK) || ciaddr.is_unspecified()
        || packet.get(10).is_some_and(|flags| flags & 0x80 != 0);
    SocketAddr::V4(SocketAddrV4::new(if broadcast { Ipv4Addr::BROADCAST } else { ciaddr }, 68))
}

/// Serve a caller-bound IPv4 interface. A read timeout returns control to the caller.
pub fn serve(socket: &UdpSocket, table: &LeaseTable, server_ip: Ipv4Addr) -> io::Result<()> {
    if socket.local_addr()? != SocketAddr::V4(SocketAddrV4::new(server_ip, 67)) || server_ip.is_unspecified() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Bind the DHCP socket to the serving IPv4 address on port 67."));
    }
    {
        let guard = table.lock().map_err(io::Error::other)?;
        if !guard.config.subnet.usable(server_ip) || guard.entries.values().any(|r| r.ip == server_ip) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "The server needs its own usable and unreserved address on this subnet."));
        }
    }
    socket.set_broadcast(true)?;
    while serve_one_with(socket, server_ip, 68, |packet| handle(packet, table, server_ip))? {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::TestDir;
    const MAC:MacAddr=MacAddr::from_bytes([2,119,0,0,0,1]);
    const IP:Ipv4Addr=Ipv4Addr::new(10,77,1,50);
    const SERVER:Ipv4Addr=Ipv4Addr::new(10,77,1,1);
    fn table()->LeaseTable {
        let t=LeaseTable::new(Config{subnet:"10.77.1.0/24".parse().unwrap(),router:Some(SERVER),dns:Some(SERVER),
            lease_seconds:3600,boot_file:Some("proof.efi".into())}).unwrap();
        t.reserve(MAC,IP).unwrap();t
    }
    fn packet(msg:u8,options:&[u8])->Vec<u8> {
        let mut p=vec![0;240];p[..3].copy_from_slice(&[1,1,6]);p[4..8].copy_from_slice(&[1,2,3,4]);p[10]=128;
        p[28..34].copy_from_slice(&MAC.octets());p[236..240].copy_from_slice(&COOKIE);
        p.extend_from_slice(&[53,1,msg]);p.extend_from_slice(options);p.push(255);p
    }
    #[test]
    fn transient_receive_error_leaves_dhcp_ready_for_the_next_datagram() {
        struct TemporarilyUnavailable;
        impl DatagramSocket for TemporarilyUnavailable {
            fn local_endpoint(&self) -> io::Result<SocketAddr> { Ok((SERVER, 67).into()) }
            fn receive(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                Err(io::ErrorKind::ConnectionReset.into())
            }
            fn transmit(&self, _: &[u8], _: SocketAddr) -> io::Result<usize> { unreachable!() }
        }
        assert!(receive_one(&TemporarilyUnavailable, SERVER, 68, |_, _, _| unreachable!()).unwrap());
    }

    #[test]
    fn discover_returns_exact_proof_offer() {
        let p=packet(DISCOVER,&[]);let actual=handle(&p,&table(),SERVER).unwrap();
        let mut expected=vec![0;300];expected[..3].copy_from_slice(&[2,1,6]);expected[4..8].copy_from_slice(&[1,2,3,4]);
        expected[10]=128;expected[16..20].copy_from_slice(&[10,77,1,50]);expected[20..24].copy_from_slice(&[10,77,1,1]);
        expected[28..34].copy_from_slice(&[2,119,0,0,0,1]);expected[108..117].copy_from_slice(b"proof.efi");
        let opt=[99,130,83,99,53,1,2,54,4,10,77,1,1,51,4,0,0,14,16,1,4,255,255,255,0,
            3,4,10,77,1,1,6,4,10,77,1,1,15,6,b'v',b'm',b'.',b'l',b'a',b'n',67,9,b'p',b'r',b'o',b'o',b'f',b'.',b'e',b'f',b'i',255];
        expected[236..236+opt.len()].copy_from_slice(&opt);assert_eq!(actual,expected);
    }
    #[test]
    fn request_matches_registered_mac_address_and_server() {
        let t=table();let p=packet(REQUEST,&[50,4,10,77,1,50,54,4,10,77,1,1]);
        assert_eq!(handle(&p,&t,SERVER).unwrap()[242],ACK);
        let mut foreign=p.clone();foreign[33]=7;assert!(handle(&foreign,&t,SERVER).is_none());
        assert_eq!(handle(&packet(REQUEST,&[50,4,10,77,1,49]),&t,SERVER).unwrap()[242],NAK);
        assert!(handle(&packet(REQUEST,&[50,4,10,77,1,50,54,4,10,77,1,2]),&t,SERVER).is_none());
    }
    #[test]
    fn release_decline_inform_and_persistence() {
        let t=table();let mut p=packet(REQUEST,&[]);p[12..16].copy_from_slice(&IP.octets());
        assert_eq!(handle(&p,&t,SERVER).unwrap()[242],ACK);
        p[242]=RELEASE;assert!(handle(&p,&t,SERVER).is_none());
        assert_eq!(t.reservation(MAC).unwrap().unwrap().state,LeaseState::Reserved);
        p[242]=INFORM;let inform=handle(&p,&t,SERVER).unwrap();assert_eq!(inform[242],ACK);
        assert_eq!(&inform[16..20],&[0;4]);assert_eq!(inform[249],1);
        assert!(handle(&packet(DECLINE,&[50,4,10,77,1,50,54,4,10,77,1,1]),&t,SERVER).is_none());
        assert!(handle(&packet(DISCOVER,&[]),&t,SERVER).is_none());
        let d=TestDir::new();let file=d.0.join("leases.json");t.save(&file).unwrap();
        let t=LeaseTable::load(&file).unwrap();assert_eq!(t.reservation(MAC).unwrap().unwrap().state,LeaseState::Reserved);
        assert!(handle(&packet(DISCOVER,&[]),&t,SERVER).is_some());
        assert!(handle(&packet(DECLINE,&[50,4,10,77,1,50,54,4,10,77,1,1]),&t,SERVER).is_none());
        t.clear_decline(MAC).unwrap();assert!(handle(&packet(DISCOVER,&[]),&t,SERVER).is_some());
    }
    #[test]
    fn one_machines_lease_changes_are_limited_without_affecting_other_machines() {
        let t = table();
        let other = MacAddr::from_bytes([2, 119, 0, 0, 0, 2]);
        t.reserve(other, Ipv4Addr::new(10, 77, 1, 51)).unwrap();
        let now = Instant::now();
        let mut request = packet(REQUEST, &[]);
        request[12..16].copy_from_slice(&IP.octets());
        let mut release = request.clone();
        release[242] = RELEASE;
        for index in 0..MAX_LEASE_CHANGES {
            let message = if index % 2 == 0 { &request } else { &release };
            assert!(process_at(message, &t, SERVER, now).unwrap().changed.is_some());
        }
        let refused = process_at(&request, &t, SERVER, now).unwrap();
        assert!(refused.changed.is_none() && refused.response.is_none());
        let mut other_request = request.clone();
        other_request[28..34].copy_from_slice(&other.octets());
        other_request[15] = 51;
        assert!(process_at(&other_request, &t, SERVER, now).unwrap().changed.is_some());
        assert!(process_at(&request, &t, SERVER, now + LEASE_CHANGE_WINDOW).unwrap().changed.is_some());
    }
    #[test]
    fn a_decline_expires_without_being_extended_by_duplicates() {
        let t = table();
        let now = Instant::now();
        let decline = packet(DECLINE, &[50,4,10,77,1,50,54,4,10,77,1,1]);
        let discover = packet(DISCOVER, &[]);
        assert!(process_at(&decline, &t, SERVER, now).unwrap().changed.is_some());
        assert!(process_at(&decline, &t, SERVER, now + Duration::from_secs(1)).unwrap().changed.is_none());
        assert!(process_at(&discover, &t, SERVER, now + DECLINE_TTL - Duration::from_millis(1)).is_none());
        assert_eq!(process_at(&discover, &t, SERVER, now + DECLINE_TTL).unwrap().response.unwrap()[242], OFFER);
    }
    #[test]
    fn truncated_or_malformed_options_are_silent() {
        let t=table();let p=packet(REQUEST,&[50,4,10,77,1,50,54,4,10,77,1,1]);
        for end in 0..p.len() {assert!(handle(&p[..end],&t,SERVER).is_none());}
        for bad in [vec![50,255,1],vec![53,1,DISCOVER],vec![54,1,1]] {
            assert!(handle(&packet(REQUEST,&bad),&t,SERVER).is_none());
        }
    }
}
