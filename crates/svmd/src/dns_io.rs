use std::{
    collections::{hash_map::RandomState, BTreeMap, BTreeSet}, hash::BuildHasher, io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc, Mutex, RwLock},
    thread::{self, JoinHandle}, time::{Duration, Instant},
};
use svm_core::{dns::{answer, Answer}, identity::Subnet};

type Records = Arc<RwLock<BTreeMap<String, Ipv4Addr>>>;
const MAX_WIRE: usize = 1232;
const TICK: Duration = Duration::from_millis(120);
const LOOKUP: Duration = Duration::from_millis(750);
static LOCAL: Mutex<BTreeSet<SocketAddrV4>> = Mutex::new(BTreeSet::new());

struct Binding(SocketAddrV4);
impl Binding {
    fn register(address: SocketAddrV4) -> io::Result<Self> {
        if !LOCAL.lock().map_err(|_| io::Error::other("DNS address registry is unavailable"))?.insert(address) {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "the DNS listener already exists"));
        }
        Ok(Self(address))
    }
}
impl Drop for Binding {
    fn drop(&mut self) { if let Ok(mut active) = LOCAL.lock() { active.remove(&self.0); } }
}

struct Lookup { from: SocketAddrV4, query: Vec<u8>, received: Instant }
pub(super) struct DnsListener {
    done: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    forwarder: Option<JoinHandle<()>>,
    can_forward:bool,
    _binding: Binding,
}

impl DnsListener {
    pub(super) fn start(ip: Ipv4Addr, resolvers: Vec<Ipv4Addr>, records: Records, subnet: Subnet) -> io::Result<Self> {
        let managed = (subnet.base().is_private() && subnet.broadcast().is_private())
            || (subnet.base().is_link_local() && subnet.broadcast().is_link_local());
        if !managed || !subnet.usable(ip) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS requires a specific managed gateway or link-local address"));
        }
        let mut upstreams = Vec::new();
        if !ip.is_link_local() {
            for host in resolvers {
                let addr = SocketAddrV4::new(host,53);
                if host.is_unspecified() || host.is_multicast() || host.is_broadcast() || host.is_link_local()
                    || host == subnet.base() || host == subnet.broadcast() || subnet.usable(host) || upstreams.contains(&addr) {
                    continue;
                }
                upstreams.push(addr);
                if upstreams.len() == 2 { break; }
            }
        }
        Self::with_socket(UdpSocket::bind((ip,53))?, upstreams, records, subnet)
    }

    fn with_socket(socket: UdpSocket, upstreams: Vec<SocketAddrV4>, records: Records, subnet: Subnet) -> io::Result<Self> {
        let SocketAddr::V4(address) = socket.local_addr()? else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,"an IPv4 listener is required"));
        };
        let binding = Binding::register(address)?;
        socket.set_read_timeout(Some(TICK))?;
        socket.set_write_timeout(Some(TICK))?;
        let replies = socket.try_clone()?;
        let can_forward=!upstreams.is_empty();
        let (queue, requests) = mpsc::sync_channel::<Lookup>(16);
        let done = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&done);
        let forwarder = thread::Builder::new().name("svm-dns-forward".into()).spawn(move || {
            let key = RandomState::new();
            let mut serial = 0u64;
            while !stopping.load(Ordering::Acquire) {
                let job = match requests.recv_timeout(TICK) {
                    Ok(job) => job,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                serial = serial.wrapping_add(1);
                let id = (key.hash_one((serial,job.from)) as u16).to_be_bytes();
                let upstream = if job.received.elapsed() <= LOOKUP * 2 {
                    forward(&job.query,&upstreams,id,&stopping)
                } else { None };
                let reply = upstream.or_else(|| header_reply(&job.query,2,false));
                if !stopping.load(Ordering::Acquire) {
                    if let Some(bytes) = reply { let _ = replies.send_to(&bytes,job.from); }
                }
            }
        })?;
        let stopping = Arc::clone(&done);
        let reader = thread::Builder::new().name("svm-dns".into()).spawn(move || {
            let mut buf = [0; MAX_WIRE + 1];
            while !stopping.load(Ordering::Acquire) {
                let (len,from) = match socket.recv_from(&mut buf) {
                    Ok((len,SocketAddr::V4(peer))) if len <= MAX_WIRE && subnet.usable(*peer.ip()) && peer.port() != 0 => (len,peer),
                    Ok(_) => continue,
                    Err(e) if transient(&e) => continue,
                    Err(_) => break,
                };
                let query = &buf[..len];
                let env=envelope(query);
                if let Some(info)=env.filter(|e|e.version.is_some_and(|v|v!=0)) {
                    if let Some(bytes)=bounded_header(query,info,16,false,false) {let _=socket.send_to(&bytes,from);}
                    continue;
                }
                let response = match records.try_read() {
                    Ok(table) => match answer(query,&table) {
                        Answer::Reply(bytes) => match env {
                            Some(info)=>local_reply(query,info,&table,bytes),
                            None if bytes.len()==12 && matches!(bytes[3]&15,1|4)=>Some(bytes),
                            None=>None,
                        },
                        Answer::Drop => None,
                        Answer::Forward if env.is_none() => None,
                        Answer::Forward if query[2] & 1 == 0 => header_reply(query,5,false),
                        Answer::Forward => match queue.try_send(Lookup {from,query:query.to_vec(),received:Instant::now()}) {
                            Ok(()) => None,
                            Err(_) => header_reply(query,2,false),
                        },
                    },
                    Err(_) => env.and_then(|info|bounded_header(query,info,2,false,false)),
                };
                if let Some(bytes) = response { let _ = socket.send_to(&bytes,from); }
            }
        });
        match reader {
            Ok(reader) => Ok(Self {done,reader:Some(reader),forwarder:Some(forwarder),can_forward,_binding:binding}),
            Err(error) => { done.store(true,Ordering::Release); let _ = forwarder.join(); Err(error) }
        }
    }

    pub(super) fn can_forward(&self)->bool {self.can_forward}

    pub(super) fn finished(&self) -> bool {
        self.reader.as_ref().is_none_or(JoinHandle::is_finished) || self.forwarder.as_ref().is_none_or(JoinHandle::is_finished)
    }
}
impl Drop for DnsListener {
    fn drop(&mut self) {
        self.done.store(true,Ordering::Release);
        if let Some(worker) = self.reader.take() { let _ = worker.join(); }
        if let Some(worker) = self.forwarder.take() { let _ = worker.join(); }
    }
}

fn transient(error: &io::Error) -> bool {
    if matches!(error.kind(),io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
        | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused) { return true; }
    // Windows reports a datagram larger than the receive buffer as WSAEMSGSIZE.
    #[cfg(windows)]
    if error.raw_os_error() == Some(10040) { return true; }
    false
}

fn word(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(buf.get(at..at+2)?.try_into().ok()?))
}
// A single ordinary question fits without compression: there is no earlier name to reference.
fn question_end(buf: &[u8]) -> Option<usize> {
    if word(buf,4)? != 1 { return None; }
    let mut end = 12;
    loop {
        let length = usize::from(*buf.get(end)?);
        end += 1;
        if length > 63 || end + length - 12 > 255 { return None; }
        if length == 0 { break; }
        buf.get(end..end+length)?;
        end += length;
    }
    buf.get(end..end+4)?;
    Some(end+4)
}

#[derive(Clone,Copy)]
struct Envelope { limit:usize, version:Option<u8>, dnssec:bool }

fn envelope(query:&[u8])->Option<Envelope> {
    if query.len()>MAX_WIRE {return None;}
    let end=question_end(query)?;
    if query[2]&0xfe!=0 || query[3]&!0x30!=0 || word(query,6)?!=0 || word(query,8)?!=0
        || word(query,end-4)?==0 || word(query,end-2)?==0 {return None;}
    match word(query,10)? {
        0 if end==query.len()=>Some(Envelope{limit:512,version:None,dnssec:false}),
        1 if query.get(end)==Some(&0) && word(query,end+1)?==41=>{
            if *query.get(end+5)?!=0 || end+11+usize::from(word(query,end+9)?)!=query.len(){return None;}
            // OPT RDATA is a series of complete option-code, option-length, and option-data tuples.
            let mut pos=end+11;
            while pos<query.len() {
                let len=usize::from(word(query,pos+2)?);
                pos+=4+len;
                if pos>query.len(){return None;}
            }
            Some(Envelope{limit:usize::from(word(query,end+3)?).clamp(512,MAX_WIRE),
                version:Some(query[end+6]),dnssec:word(query,end+7)?&0x8000!=0})
        }
        _=>None,
    }
}

fn udp_limit(query:&[u8])->Option<usize> {
    let env=envelope(query)?;
    (env.version.unwrap_or(0)==0).then_some(env.limit)
}

// Header and original question, plus an OPT record when the client used EDNS.
// BADVERS is extended RCODE 16, carried in the high byte of the OPT TTL.
fn bounded_header(query:&[u8],env:Envelope,rcode:u8,truncated:bool,authoritative:bool)->Option<Vec<u8>> {
    let mut reply=header_reply(query,rcode&15,truncated)?;
    if authoritative {reply[2]|=4;}
    if env.version.is_some() {
        reply[11]=1;
        reply.extend_from_slice(&[0,0,41]);
        reply.extend_from_slice(&(MAX_WIRE as u16).to_be_bytes());
        reply.extend_from_slice(&[rcode>>4,0,if env.dnssec {128} else {0},0,0,0]);
    }
    Some(reply)
}

fn ptr_address(query:&[u8])->Option<Ipv4Addr> {
    let end=question_end(query)?;
    if !matches!(word(query,end-4)?,12|255) {return None;}
    let mut ip=[0u8;4];
    let mut pos=12;
    for octet in ip.iter_mut().rev() {
        let len=usize::from(*query.get(pos)?);pos+=1;
        let label=query.get(pos..pos+len)?;pos+=len;
        if label.is_empty() || len>3 || (len>1 && label[0]==b'0') || !label.iter().all(u8::is_ascii_digit) {return None;}
        *octet=std::str::from_utf8(label).ok()?.parse().ok()?;
    }
    query.get(pos..end-4)?.eq_ignore_ascii_case(b"\x07in-addr\x04arpa\0").then_some(Ipv4Addr::from(ip))
}

fn local_reply(query:&[u8],env:Envelope,names:&BTreeMap<String,Ipv4Addr>,mut reply:Vec<u8>)->Option<Vec<u8>> {
    // A local PTR RRset can contain many aliases. If the core hit its own ceiling, send TC
    // as well: an incomplete RRset must not be presented as complete even at the EDNS limit.
    let count=usize::from(word(&reply,6)?);
    let missing_alias=reply.len()>MAX_WIRE-(255+12+11) && count>0 && ptr_address(query).is_some_and(|ip|{
        names.iter().filter(|(name,addr)|**addr==ip && name.len()<=253 && name.split('.').all(|label|
            !label.is_empty() && label.len()<=63 && label.bytes().all(|b|b.is_ascii_alphanumeric() || matches!(b,b'-'|b'_'))))
            .take(count+1).count()>count
    });
    if reply.len()>env.limit || missing_alias {return bounded_header(query,env,0,true,reply[2]&4!=0);}
    reply[3]|=query[3]&0x10;
    // The core emits an empty OPT in responses to EDNS; preserve the request's DO bit.
    if env.dnssec && word(&reply,10)==Some(1) && reply.len()>=11 {
        let flags=reply.len()-4;reply[flags]|=0x80;
    }
    Some(reply)
}

fn header_reply(query: &[u8], rcode: u8, truncated: bool) -> Option<Vec<u8>> {
    let mut reply = query.get(..question_end(query)?)?.to_vec();
    reply[2] = 0x80 | (query[2] & 1) | (u8::from(truncated) << 1);
    reply[3] = 0x80 | (query[3] & 0x10) | rcode;
    reply[6..12].fill(0);
    Some(reply)
}

fn matches_question(query: &[u8], reply: &[u8], id: [u8;2]) -> bool {
    let Some(end) = question_end(reply) else { return false };
    if reply.get(..2) != Some(&id[..]) || reply[2] & 0xf8 != 0x80 || question_end(query) != Some(end) {
        return false;
    }
    reply[12..end-4].eq_ignore_ascii_case(&query[12..end-4]) && reply[end-4..end] == query[end-4..end]
}

fn forward(query: &[u8], upstreams: &[SocketAddrV4], id: [u8;2], done: &AtomicBool) -> Option<Vec<u8>> {
    let limit = udp_limit(query)?;
    let mut outgoing = query.to_vec();
    outgoing[..2].copy_from_slice(&id);
    if word(query,10) == Some(1) {
        let size_at = question_end(query)? + 3;
        outgoing[size_at..size_at+2].copy_from_slice(&(limit as u16).to_be_bytes());
    }
    let mut buf = [0;MAX_WIRE+1];
    for upstream in upstreams {
        if done.load(Ordering::Acquire) { return None; }
        if LOCAL.lock().ok()?.contains(upstream) { continue; }
        // A fresh source port and forwarded transaction ID isolate each outstanding lookup.
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED,0)) else { continue };
        if socket.connect(upstream).is_err() || socket.set_read_timeout(Some(TICK)).is_err()
            || socket.set_write_timeout(Some(TICK)).is_err() || socket.send(&outgoing).is_err() { continue; }
        let until = Instant::now()+LOOKUP;
        let mut discarded = 0;
        while !done.load(Ordering::Acquire) && Instant::now() < until && discarded < 4 {
            match socket.recv_from(&mut buf) {
                Ok((len,peer)) if peer == SocketAddr::V4(*upstream) && matches_question(query,&buf[..len],id) => {
                    if len > limit { return bounded_header(query,envelope(query)?,0,true,buf[2]&4!=0); }
                    let mut reply = buf[..len].to_vec();
                    reply[..2].copy_from_slice(&query[..2]);
                    return Some(reply);
                }
                Ok(_) => discarded += 1,
                Err(err) if matches!(err.kind(),io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {},
                Err(_) => break,
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut q = vec![0x12,0x34,1,0,0,1,0,0,0,0,0,0];
        for label in name.split('.') { q.push(label.len() as u8); q.extend_from_slice(label.as_bytes()); }
        q.push(0); q.extend_from_slice(&kind.to_be_bytes()); q.extend_from_slice(&1u16.to_be_bytes());
        q
    }
    fn bind() -> UdpSocket {
        let s=UdpSocket::bind((Ipv4Addr::LOCALHOST,0)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s
    }
    fn address(socket: &UdpSocket) -> SocketAddrV4 {
        match socket.local_addr().unwrap() { SocketAddr::V4(v) => v, _ => unreachable!() }
    }

    #[test]
    fn loopback_guest_resolves_name_and_misses_public_lookup_without_a_resolver() {
        let server=bind(); let dest=address(&server); let client=bind();
        let guest=Ipv4Addr::new(10,77,1,2);
        let records=Arc::new(RwLock::new(BTreeMap::from([("guest.vm.lan".into(),guest)])));
        let listener=DnsListener::with_socket(server,Vec::new(),records,"127.0.0.0/24".parse().unwrap()).unwrap();
        assert!(!listener.finished());
        let mut buf=[0;512];
        client.send_to(&query("guest.vm.lan",1),dest).unwrap();
        let (n,from)=client.recv_from(&mut buf).unwrap();
        assert_eq!(from,SocketAddr::V4(dest));
        assert_eq!(word(&buf[..n],6),Some(1));
        assert!(buf[..n].ends_with(&guest.octets()));
        client.send_to(&query("outside.example",1),dest).unwrap();
        let (n,_)=client.recv_from(&mut buf).unwrap();
        assert!(n>12);
        assert_eq!(buf[3]&15,2);
    }

    #[test]
    fn listener_discards_datagrams_from_outside_its_subnet() {
        let server=bind(); let dest=address(&server); let client=bind();
        client.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let _listener=DnsListener::with_socket(server,Vec::new(),Arc::default(),"10.77.1.0/24".parse().unwrap()).unwrap();
        client.send_to(&query("guest.vm.lan",1),dest).unwrap();
        assert!(transient(&client.recv_from(&mut [0;512]).unwrap_err()));
        assert!(DnsListener::start(Ipv4Addr::UNSPECIFIED,Vec::new(),Arc::default(),"0.0.0.0/0".parse().unwrap()).is_err());
    }

    #[test]
    fn forwarder_checks_peer_id_and_full_question_then_restores_the_guest_id() {
        let upstream=bind(); let addr=address(&upstream);
        let q=query("outside.example",1); let expected=q.clone();
        let sender=thread::spawn(move || {
            let mut packet=[0;512];
            let (n,peer)=upstream.recv_from(&mut packet).unwrap();
            let mut good=packet[..n].to_vec();
            assert_eq!(&good[..2],&[0x98,0x76]);
            assert_eq!(good[2..],expected[2..]);
            good[2]|=0x80;
            let other=bind(); let mut forged=good.clone(); forged[3]=0x85;
            other.send_to(&forged,peer).unwrap();
            let mut wrong_id=forged.clone(); wrong_id[0]^=1; upstream.send_to(&wrong_id,peer).unwrap();
            forged[13]=b'z'; upstream.send_to(&forged,peer).unwrap();
            upstream.send_to(&good,peer).unwrap();
        });
        let result=forward(&q,&[addr],[0x98,0x76],&AtomicBool::new(false)).unwrap();
        sender.join().unwrap();
        assert_eq!(&result[..2],&q[..2]);
        assert_eq!(result[3]&15,0);
        assert_eq!(&result[12..],&q[12..]);
    }

    fn edns(mut q:Vec<u8>,limit:u16,version:u8,options:&[u8])->Vec<u8>{
        q[11]=1;
        q.extend_from_slice(&[0,0,41]);q.extend_from_slice(&limit.to_be_bytes());
        q.extend_from_slice(&[0,version,0x80,0]);q.extend_from_slice(&(options.len() as u16).to_be_bytes());
        q.extend_from_slice(options);q
    }

    #[test]
    fn edns_requires_complete_option_tuples_before_forwarding(){
        let q=query("outside.example",1);
        let good=edns(q.clone(),1400,0,&[0,12,0,2,0,0,0,42,0,0]);
        assert_eq!(udp_limit(&good),Some(MAX_WIRE));
        for options in [&[0,12,0][..],&[0,12,0,2,0],&[0,12,0,0,1]]{
            assert!(envelope(&edns(q.clone(),1232,0,options)).is_none());
        }
        let mut trailing=q.clone();trailing.push(0);
        assert!(envelope(&trailing).is_none());
        let mut invalid=q.clone();let class=invalid.len()-2;invalid[class..].fill(0);
        assert!(envelope(&invalid).is_none());
    }

    #[test]
    fn unsupported_edns_version_returns_badvers_without_recursion(){
        let q=edns(query("external.example",1),4096,1,&[]);
        let info=envelope(&q).unwrap();
        assert_eq!(info.version,Some(1));assert!(udp_limit(&q).is_none());
        let r=bounded_header(&q,info,16,false,false).unwrap();
        let end=question_end(&r).unwrap();
        assert_eq!(r[3]&15,0);assert_eq!(r[end+5],1);assert_eq!(r[end+6],0);
        assert_eq!(r[end+7],0x80);assert_eq!(word(&r,10),Some(1));
    }

    #[test]
    fn ptr_reply_respects_legacy_edns_and_complete_rrset_limits(){
        let ip=Ipv4Addr::new(10,77,0,9);
        let aliases:BTreeMap<_,_>=(0..200).map(|i|(format!("long-alias-for-guest-{i:03}.vm.lan"),ip)).collect();
        let question=query("9.0.77.10.in-addr.arpa",12);
        for q in [question.clone(),edns(question.clone(),640,0,&[]),edns(question.clone(),4096,0,&[])]{
            let info=envelope(&q).unwrap();assert_eq!(ptr_address(&q),Some(ip));
            let Answer::Reply(full)=answer(&q,&aliases) else {panic!("local reply expected")};
            let r=local_reply(&q,info,&aliases,full).unwrap();
            assert!(r.len()<=info.limit);assert_ne!(r[2]&2,0);assert_ne!(r[2]&4,0);
            assert_eq!(word(&r,6),Some(0));assert_eq!(word(&r,10),Some(u16::from(info.version.is_some())));
        }
        let one=BTreeMap::from([("guest.vm.lan".into(),ip)]);
        let mut q=edns(question,512,0,&[]);q[3]|=0x10;
        let Answer::Reply(full)=answer(&q,&one) else {panic!("local reply expected")};
        let r=local_reply(&q,envelope(&q).unwrap(),&one,full).unwrap();
        assert_eq!(r[2]&2,0);assert_eq!(word(&r,6),Some(1));assert_eq!(r[3]&0x10,0x10);assert_eq!(r[r.len()-4]&0x80,0x80);
    }

    #[test]
    fn edns_bounds_and_question_types_are_checked_and_own_listener_is_never_an_upstream() {
        let q=query("outside.example",65);
        let mut reply=q.clone(); reply[2]|=0x80;
        let kind=reply.len()-3; reply[kind]=97;
        assert!(!matches_question(&q,&reply,[0x12,0x34]));
        let mut extended=q.clone(); extended[11]=1;
        extended.extend_from_slice(&[0,0,41,0x10,0,0,0,0,0,0,0]);
        assert_eq!(udp_limit(&extended),Some(MAX_WIRE));
        extended.pop(); assert_eq!(udp_limit(&extended),None);
        let socket=bind(); let addr=address(&socket); let _entry=Binding::register(addr).unwrap();
        assert!(forward(&q,&[addr],[0x98,0x76],&AtomicBool::new(false)).is_none());
    }
}
