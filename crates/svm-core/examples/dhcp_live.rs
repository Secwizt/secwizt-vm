//! Live check for the build host: run the real `svm_core::dhcp` server on one interface for a few seconds and
//! print what happened to the reservation. Used against a real Hyper-V machine booting from the network.
//! Usage: dhcp_live <bind-ip> <subnet-cidr> <mac> <lease-ip> <seconds>
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};
use svm_core::dhcp::{Config, LeaseTable};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 6 {
        return Err("usage: dhcp_live <bind-ip> <subnet-cidr> <mac> <lease-ip> <seconds>".into());
    }
    let bind: Ipv4Addr = a[1].parse()?;
    let table = LeaseTable::new(Config { subnet: a[2].parse()?, router: None, dns: None, lease_seconds: 3600, boot_file: Some("proof.efi".into()) })?;
    let mac = a[3].parse()?;
    table.reserve(mac, a[4].parse()?)?;
    // Another program may already hold port 67 on 0.0.0.0, so the address must be shared.
    let s2 = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    s2.set_reuse_address(true)?;
    s2.bind(&std::net::SocketAddr::from((bind, 67)).into())?;
    let socket: UdpSocket = s2.into();
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    println!("serving on {bind}:67, reservation before: {:?}", table.reservation(mac)?);
    let end = Instant::now() + Duration::from_secs(a[5].parse()?);
    while Instant::now() < end {
        svm_core::dhcp::serve(&socket, &table, bind)?;
    }
    println!("reservation after: {:?}", table.reservation(mac)?);
    Ok(())
}
