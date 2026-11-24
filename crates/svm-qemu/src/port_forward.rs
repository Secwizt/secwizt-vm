use crate::{err, Result};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use svm_core::model::{PortForward, PortForwardProtocol};

const MAX_PORT_FORWARDS: usize = 16;
pub const PORT_FORWARD_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

pub fn validate_port_forwards(forwards: &[PortForward]) -> Result<()> {
    if forwards.len() > MAX_PORT_FORWARDS {
        return Err(err("A QEMU machine can have up to 16 port forwards."));
    }
    for (index, forward) in forwards.iter().enumerate() {
        if forward.host_port == 0 || forward.guest_port == 0 {
            return Err(err("Host and guest port numbers must be between 1 and 65535."));
        }
        if forwards[..index].iter().any(|previous| {
            (previous.protocol, previous.host_port) == (forward.protocol, forward.host_port)
        }) {
            return Err(err(format!(
                "The {} host port {} is already listed for this machine.",
                forward.protocol.as_str().to_ascii_uppercase(), forward.host_port,
            )));
        }
    }
    Ok(())
}

/// QEMU's user network maps the guest-visible host address (10.0.2.2) to this PC's loopback, so a
/// guest can reach every local-only service here. `restrict=on` cuts the guest off from the host and
/// from outside networks; the machine's own TCP port forwards keep working (UDP replies are dropped).
pub(crate) fn user_network(forwards: &[PortForward], isolated: bool) -> Result<String> {
    validate_port_forwards(forwards)?;
    let mut options = String::from(if isolated { "user,id=nat0,restrict=on" } else { "user,id=nat0" });
    for forward in forwards {
        options.push_str(&format!(
            ",hostfwd={}:{PORT_FORWARD_HOST}:{}-:{}",
            forward.protocol.as_str(), forward.host_port, forward.guest_port,
        ));
    }
    Ok(options)
}

pub(crate) fn check_available(forwards: &[PortForward]) -> Result<()> {
    // This probe can explain a conflict early. QEMU owns the final bind.
    for forward in forwards {
        let address = (PORT_FORWARD_HOST, forward.host_port);
        let result = match forward.protocol {
            PortForwardProtocol::Tcp => TcpListener::bind(address).map(drop),
            PortForwardProtocol::Udp => UdpSocket::bind(address).map(drop),
        };
        result.map_err(|error| err(format!(
            "The {} port forward cannot bind {PORT_FORWARD_HOST}:{} ({error}).",
            forward.protocol.as_str().to_ascii_uppercase(), forward.host_port,
        )))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(protocol: PortForwardProtocol, host_port: u16, guest_port: u16) -> PortForward {
        PortForward { protocol, host_port, guest_port }
    }

    #[test]
    fn user_network_preserves_default_nat_and_uses_only_ipv4_loopback() {
        use PortForwardProtocol::{Tcp, Udp};

        assert_eq!(user_network(&[], false).unwrap(), "user,id=nat0");
        assert_eq!(user_network(&[], true).unwrap(), "user,id=nat0,restrict=on");
        assert_eq!(user_network(&[rule(Tcp, 2222, 22)], true).unwrap(), "user,id=nat0,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22");
        assert_eq!(
            user_network(&[rule(Tcp, 2222, 22), rule(Udp, 2222, 65000)], false).unwrap(),
            "user,id=nat0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=udp:127.0.0.1:2222-:65000",
        );
    }

    #[test]
    fn invalid_rules_are_refused_before_argument_assembly() {
        use PortForwardProtocol::{Tcp, Udp};

        assert!(user_network(&[rule(Tcp, 0, 22)], false).is_err());
        assert!(user_network(&[rule(Udp, 53, 0)], false).is_err());
        assert!(user_network(&[rule(Tcp, 2222, 22), rule(Tcp, 2222, 23)], false).is_err());
        let many: Vec<_> = (1..=17).map(|port| rule(Tcp, port, 65535)).collect();
        assert!(user_network(&many[..16], false).is_ok());
        assert!(user_network(&many, false).is_err());
    }
}
