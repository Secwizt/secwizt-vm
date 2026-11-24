//! Mutual authentication for one request on a native loopback connection.

use ring::{hmac, rand::{SecureRandom, SystemRandom}};
use std::{io::{self, Read, Write}, net::{Ipv4Addr, TcpStream}, time::Instant};

/// The loopback address for the service's API, the console relay, QEMU supervisors and QEMU displays.
/// QEMU's user-mode network sends a guest's connections to 10.0.2.2 (and the rest of 10.0.2.0/24)
/// to 127.0.0.1 only, so a guest without isolation cannot reach anything listening here. User-facing
/// port forwards stay on 127.0.0.1.
pub const SERVICE_HOST: Ipv4Addr = Ipv4Addr::new(127, 77, 0, 1);

const PREFACE: &[u8; 12] = b"\0SVM-AUTH/1\n";
const NONCE_SIZE: usize = 32;
const TAG_SIZE: usize = 32;

fn invalid_proof() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Local service authentication failed")
}

fn time_left(deadline: Instant) -> io::Result<std::time::Duration> {
    deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
}

fn read_frame(stream: &mut TcpStream, mut frame: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !frame.is_empty() {
        stream.set_read_timeout(Some(time_left(deadline)?))?;
        match stream.read(frame) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => frame = &mut frame[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_frame(stream: &mut TcpStream, frame: &[u8], deadline: Instant) -> io::Result<()> {
    stream.set_write_timeout(Some(time_left(deadline)?))?;
    stream.write_all(frame)
}

fn nonce() -> io::Result<[u8; NONCE_SIZE]> {
    let mut bytes = [0; NONCE_SIZE];
    SystemRandom::new().fill(&mut bytes).map_err(|_| io::Error::other("Cannot generate an authentication nonce"))?;
    Ok(bytes)
}

fn transcript(client: &[u8], server: &[u8], port: u16, purpose: u8) -> [u8; 79] {
    let mut message = [0; 79];
    message[..32].copy_from_slice(client);
    message[32..64].copy_from_slice(server);
    message[64..76].copy_from_slice(PREFACE);
    message[76..78].copy_from_slice(&port.to_be_bytes());
    message[78] = purpose;
    message
}

/// Send only a public nonce until the peer proves knowledge of the token.
pub fn client(stream: &mut TcpStream, token: &str, port: u16, deadline: Instant) -> io::Result<()> {
    let mut hello = [0; PREFACE.len() + NONCE_SIZE];
    hello[..PREFACE.len()].copy_from_slice(PREFACE);
    let client = nonce()?;
    hello[PREFACE.len()..].copy_from_slice(&client);
    write_frame(stream, &hello, deadline)?;

    let mut challenge = [0; NONCE_SIZE + TAG_SIZE];
    read_frame(stream, &mut challenge, deadline)?;
    let (server, proof) = challenge.split_at(NONCE_SIZE);
    let key = hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes());
    hmac::verify(&key, &transcript(&client, server, port, b'S'), proof).map_err(|_| invalid_proof())?;
    let proof = hmac::sign(&key, &transcript(&client, server, port, b'C'));
    write_frame(stream, proof.as_ref(), deadline)
}

/// Authenticate a native peer before its HTTP request is processed.
pub fn server(stream: &mut TcpStream, token: &str, port: u16, deadline: Instant) -> io::Result<()> {
    let mut hello = [0; PREFACE.len() + NONCE_SIZE];
    read_frame(stream, &mut hello, deadline)?;
    let (preface, client) = hello.split_at(PREFACE.len());
    if preface != PREFACE { return Err(invalid_proof()); }

    let server = nonce()?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes());
    let mut challenge = [0; NONCE_SIZE + TAG_SIZE];
    challenge[..NONCE_SIZE].copy_from_slice(&server);
    challenge[NONCE_SIZE..].copy_from_slice(hmac::sign(&key, &transcript(client, &server, port, b'S')).as_ref());
    write_frame(stream, &challenge, deadline)?;

    let mut proof = [0; TAG_SIZE];
    read_frame(stream, &mut proof, deadline)?;
    hmac::verify(&key, &transcript(client, &server, port, b'C'), &proof).map_err(|_| invalid_proof())
}
