use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque, io, net::{Ipv4Addr, SocketAddr, UdpSocket}, path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}},
    thread::{self, JoinHandle}, time::Duration,
};
use svm_core::{dhcp::{self, LeaseTable, Reservation}, identity::MacAddr};

#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Traffic {
    discovers: u64,
    offers: u64,
    zero_source_offers: u64,
    requests: u64,
    acks: u64,
    send_errors: u64,
}

const MAX_PENDING_EVENTS: usize = 512;

#[derive(Default)]
struct Observations {
    traffic: Traffic,
    changes: VecDeque<(MacAddr, Reservation)>,
    dropped_events: u64,
}

impl Observations {
    fn push_change(&mut self, change: (MacAddr, Reservation)) {
        if self.changes.len() == MAX_PENDING_EVENTS {
            self.changes.pop_front();
            self.dropped_events += 1;
        }
        self.changes.push_back(change);
    }
}

#[derive(Default)]
pub(super) struct Activity {
    observed: Mutex<Observations>,
    needs_save: AtomicBool,
}

impl Activity {
    fn observed(&self) -> std::sync::MutexGuard<'_, Observations> {
        self.observed.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn traffic(&self) -> Traffic { self.observed().traffic }

    pub(super) fn drain_changes(&self) -> (VecDeque<(MacAddr, Reservation)>, u64) {
        let mut observed = self.observed();
        (std::mem::take(&mut observed.changes), std::mem::take(&mut observed.dropped_events))
    }

    fn serve_one(&self, socket: &impl dhcp::DatagramSocket, table: &LeaseTable, path: &Path,
        server: Ipv4Addr, client_port: u16) -> io::Result<bool> {
        dhcp::receive_one(socket, server, client_port, |packet, peer, send| {
            self.respond(table, path, server, packet, peer, send)
        })
    }

    // Runs on the interface's socket thread. Hyper-V and HTTP work cannot delay an OFFER.
    fn respond(
        &self, table: &LeaseTable, path: &Path, server: Ipv4Addr, packet: &[u8], peer: SocketAddr,
        send: &dyn Fn(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let Some(exchange) = dhcp::process(packet, table, server) else { return Ok(()); };
        {
            let mut observed = self.observed();
            match exchange.message {
                1 => observed.traffic.discovers += 1,
                3 => observed.traffic.requests += 1,
                _ => {}
            }
            if let Some((mac, entry)) = exchange.changed {
                observed.push_change((mac, entry));
                self.needs_save.store(true, Ordering::Release);
            }
        }
        // Keep REQUEST/RELEASE/DECLINE durable even if the main worker is in a long host call.
        // Each network has exactly one receiving thread, including during a rebind.
        if self.needs_save.load(Ordering::Acquire) {
            table.save(path).map_err(io::Error::other)?;
            self.needs_save.store(false, Ordering::Release);
        }
        if let Some(reply) = exchange.response {
            let sent = send(&reply);
            let mut observed = self.observed();
            if sent.is_err() {
                observed.traffic.send_errors += 1;
            } else if exchange.message == 1 && reply.get(242) == Some(&2) {
                observed.traffic.offers += 1;
                if peer == SocketAddr::from((Ipv4Addr::UNSPECIFIED, 68)) {
                    observed.traffic.zero_source_offers += 1;
                }
            } else if exchange.message == 3 && reply.get(242) == Some(&5) {
                observed.traffic.acks += 1;
            }
        }
        Ok(())
    }
}

fn shared_udp() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    Ok(socket)
}

fn bind(server: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    if server.is_unspecified() || server.is_multicast() || server.is_broadcast() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "A configured host-side address is required."));
    }
    let socket = shared_udp()?;
    socket.bind(&SocketAddr::from((server, port)).into())?;
    socket.set_read_timeout(Some(Duration::from_millis(150)))?;
    Ok(socket.into())
}

pub(super) struct Listener {
    pub(super) address: Ipv4Addr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl Listener {
    pub(super) fn start(id: &str, server: Ipv4Addr, table: Arc<LeaseTable>, path: PathBuf,
        activity: Arc<Activity>) -> io::Result<Self> {
        let socket = bind(server, 67)?;
        Self::with_socket(id, server, socket, 68, table, path, activity)
    }

    fn with_socket(id: &str, server: Ipv4Addr, socket: UdpSocket, client_port: u16,
        table: Arc<LeaseTable>, path: PathBuf, activity: Arc<Activity>) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&stop);
        let failure = Arc::new(Mutex::new(None));
        let thread_failure = Arc::clone(&failure);
        let thread = thread::Builder::new().name(format!("dhcp-{id}")).spawn(move || {
            while !done.load(Ordering::Acquire) {
                let result = activity.serve_one(&socket, &table, &path, server, client_port);
                if let Err(error) = result {
                    *thread_failure.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error.to_string());
                    break;
                }
            }
        })?;
        Ok(Self { address: server, stop, thread: Some(thread), failure })
    }

    #[cfg(test)]
    pub(super) fn loopback(id: &str, client_port: u16, table: Arc<LeaseTable>, path: PathBuf,
        activity: Arc<Activity>) -> io::Result<(Self, SocketAddr)> {
        let ip = Ipv4Addr::LOCALHOST;
        let socket = bind(ip, 0)?;
        let address = socket.local_addr()?;
        Ok((Self::with_socket(id, ip, socket, client_port, table, path, activity)?, address))
    }

    pub(super) fn take_failure(&self) -> Option<String> {
        self.failure.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
    }

    pub(super) fn finished(&self) -> bool { self.thread.as_ref().is_none_or(JoinHandle::is_finished) }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.thread.take() { let _ = worker.join(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svm_core::dhcp::{Config, LeaseState};

    #[test]
    fn production_socket_has_address_sharing_before_bind() {
        assert!(shared_udp().unwrap().reuse_address().unwrap());
    }

    #[test]
    fn lease_events_keep_order_and_account_for_overflow_while_host_is_busy() {
        let mut observed = Observations::default();
        let mac = MacAddr::from_bytes([2,1,2,3,4,5]);
        let mut lease = Reservation { ip: Ipv4Addr::new(169,254,1,0), state: LeaseState::Reserved };
        for _ in 0..MAX_PENDING_EVENTS {
            observed.push_change((mac, lease));
        }
        lease.state = LeaseState::Active;
        observed.push_change((mac, lease));
        lease.state = LeaseState::Reserved;
        observed.push_change((mac, lease));
        assert_eq!(observed.dropped_events, 2);
        assert_eq!(observed.changes.len(), MAX_PENDING_EVENTS);
        assert_eq!(observed.changes[MAX_PENDING_EVENTS - 2].1.state, LeaseState::Active);
        assert_eq!(observed.changes[MAX_PENDING_EVENTS - 1].1.state, LeaseState::Reserved);
    }

    #[test]
    fn bootstrap_discover_from_zero_address_sends_offer_to_broadcast() {
        let server = Ipv4Addr::new(169, 254, 40, 1);
        let guest = Ipv4Addr::new(169, 254, 1, 0);
        let mac = MacAddr::from_bytes([2, 1, 2, 3, 4, 5]);
        let table = LeaseTable::new(Config { subnet: "169.254.0.0/16".parse().unwrap(), router: None,
            dns: Some(server), lease_seconds: 3600, boot_file: None }).unwrap();
        table.reserve(mac, guest).unwrap();
        let mut packet = vec![0; 240];
        packet[..3].copy_from_slice(&[1, 1, 6]);
        packet[4..8].copy_from_slice(&[10, 20, 30, 40]);
        packet[28..34].copy_from_slice(&mac.octets());
        packet[236..240].copy_from_slice(&[99, 130, 83, 99]);
        packet.extend_from_slice(&[53, 1, 1, 255]);
        let activity = Activity::default();
        struct Wire {
            server: Ipv4Addr, peer: SocketAddr, packet: Vec<u8>, fail_send: bool,
            sent: std::cell::RefCell<Vec<(SocketAddr, Vec<u8>)>>,
        }
        impl dhcp::DatagramSocket for Wire {
            fn local_endpoint(&self) -> io::Result<SocketAddr> { Ok((self.server, 67).into()) }
            fn receive(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                buffer[..self.packet.len()].copy_from_slice(&self.packet);
                Ok((self.packet.len(), self.peer))
            }
            fn transmit(&self, reply: &[u8], to: SocketAddr) -> io::Result<usize> {
                if self.fail_send { return Err(io::Error::other("send failed")); }
                self.sent.borrow_mut().push((to, reply.to_vec()));
                Ok(reply.len())
            }
        }
        let mut wire = Wire { server, peer: (Ipv4Addr::UNSPECIFIED, 68).into(), packet,
            fail_send: false, sent: Default::default() };
        let path = Path::new("unused-for-discover");
        let receive = |wire: &Wire| activity.serve_one(wire, &table, path, server, 68).unwrap();
        assert!(receive(&wire));
        let (to, reply) = wire.sent.borrow_mut().pop().unwrap();
        assert_eq!(to, SocketAddr::from((Ipv4Addr::BROADCAST, 68)));
        assert_eq!(&reply[4..8], &wire.packet[4..8]);
        assert_eq!(&reply[16..20], &guest.octets());
        assert_eq!(&reply[20..24], &server.octets());
        assert_eq!(reply[242], 2);
        assert_eq!(activity.traffic().zero_source_offers, 1);
        assert_eq!(table.reservation(mac).unwrap().unwrap().state, LeaseState::Reserved);
        wire.fail_send = true;
        assert!(receive(&wire));
        wire.fail_send = false;
        wire.peer.set_port(69);
        assert!(receive(&wire));
        wire.peer.set_port(68);
        wire.packet[33] = 99;
        assert!(receive(&wire));
        assert!(wire.sent.borrow().is_empty());
        let traffic = activity.traffic();
        assert_eq!((traffic.discovers, traffic.offers, traffic.zero_source_offers, traffic.send_errors), (2,1,1,1));
    }
}
