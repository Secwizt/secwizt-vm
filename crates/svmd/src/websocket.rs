use crate::{console, http, ApiError};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha1::{Digest, Sha1};
use std::{
    io::{self, Read, Write}, net::{Shutdown, TcpStream}, sync::Mutex,
    thread, time::{Duration, Instant},
};

const FRAME_LIMIT: u64 = 1024 * 1024;
const IO_LIMIT: Duration = Duration::from_secs(5);
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub(crate) struct Upgrade {
    pub id: String,
    pub ticket: String,
    pub key: String,
}

impl Upgrade {
    pub(crate) fn parse<'a>(method: &str, id: &str, port: u16, headers: impl Iterator<Item = &'a str>) -> Result<Self, ApiError> {
        let error = || ApiError::invalid("Send a valid binary WebSocket console upgrade.");
        if method != "GET" || !console::machine_id(id) { return Err(error()); }
        let (mut host, mut origin, mut upgrade, mut connection, mut version, mut key, mut protocols) =
            (None, None, None, None, None, None, None);
        let mut length = None;
        for line in headers {
            let (name, value) = http::header(line)?;
            let field = match name.as_str() {
                "host" => &mut host,
                "origin" => &mut origin,
                "upgrade" => &mut upgrade,
                "connection" => &mut connection,
                "sec-websocket-version" => &mut version,
                "sec-websocket-key" => &mut key,
                "sec-websocket-protocol" => &mut protocols,
                "content-length" => &mut length,
                "authorization" | "transfer-encoding" | "expect" => return Err(error()),
                _ => continue,
            };
            if field.replace(value).is_some() { return Err(error()); }
        }
        if host != Some(format!("{}:{port}", svm_core::local_auth::SERVICE_HOST).as_str()) || origin != Some(console::ORIGIN) {
            return Err(ApiError::new(403, "console_origin", "Open the local console inside the desktop app."));
        }
        if !upgrade.is_some_and(|v: &str| v.eq_ignore_ascii_case("websocket")) || version != Some("13")
            || !connection.is_some_and(|v: &str| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
            || !matches!(length, None | Some("0")) {
            return Err(error());
        }
        let key = key.filter(|v| v.len() == 24 && STANDARD.decode(v).is_ok_and(|k| k.len() == 16)).ok_or_else(error)?;
        let mut offers = protocols.unwrap_or("").split(',').map(str::trim);
        let ticket_error = || ApiError::new(401, "console_ticket", "Reconnect to obtain a fresh console ticket.");
        if offers.next() != Some("binary") { return Err(ticket_error()); }
        let ticket = offers.next().filter(|candidate| candidate.len() == 43).ok_or_else(ticket_error)?;
        if offers.next().is_some() { return Err(ticket_error()); }
        Ok(Self { id: id.to_owned(), key: key.to_owned(), ticket: ticket.to_owned() })
    }
}

fn accept(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(WEBSOCKET_GUID);
    STANDARD.encode(digest.finalize())
}

pub(crate) fn relay(mut browser: TcpStream, mut rfb: TcpStream, key: &str) -> io::Result<()> {
    browser.set_write_timeout(Some(IO_LIMIT))?;
    rfb.set_write_timeout(Some(IO_LIMIT))?;
    rfb.set_read_timeout(None)?;
    browser.set_read_timeout(None)?;
    write!(browser,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
        accept(key))?;
    let output = Mutex::new(browser.try_clone()?);
    let mut rfb_write = rfb.try_clone()?;
    thread::scope(|scope| {
        scope.spawn(|| {
            let _ = from_browser(&mut browser, &mut rfb_write, &output);
            let _ = browser.shutdown(Shutdown::Both);
            let _ = rfb_write.shutdown(Shutdown::Both);
        });
        let result = to_browser(&mut rfb, &output);
        let _ = rfb.shutdown(Shutdown::Both);
        if let Ok(socket) = output.lock() { let _ = socket.shutdown(Shutdown::Both); }
        result
    })
}

fn invalid() -> io::Error { io::Error::new(io::ErrorKind::InvalidData, "Invalid console WebSocket frame") }
fn write_frame(socket: &Mutex<TcpStream>, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut socket = socket.lock().map_err(|_| io::Error::other("The console socket is unavailable"))?;
    let len = payload.len();
    if len < 126 {
        socket.write_all(&[0x80 | opcode, len as u8])?;
    } else {
        let len = u16::try_from(len).map_err(|_| invalid())?.to_be_bytes();
        socket.write_all(&[0x80 | opcode, 126, len[0], len[1]])?;
    }
    socket.write_all(payload)
}

fn to_browser(rfb: &mut TcpStream, browser: &Mutex<TcpStream>) -> io::Result<()> {
    let mut data = [0; 16 * 1024];
    loop {
        let length = rfb.read(&mut data)?;
        if length == 0 { return Ok(()); }
        write_frame(browser, 2, &data[..length])?;
    }
}

fn read_part(socket: &mut TcpStream, mut dest: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !dest.is_empty() {
        let left = deadline.checked_duration_since(Instant::now()).filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "The console frame timed out"))?;
        socket.set_read_timeout(Some(left))?;
        let count = socket.read(dest)?;
        if count == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
        dest = &mut dest[count..];
    }
    Ok(())
}

fn from_browser(browser: &mut TcpStream, rfb: &mut TcpStream, output: &Mutex<TcpStream>) -> io::Result<()> {
    let mut fragmented = false;
    loop {
        browser.set_read_timeout(None)?;
        let mut first = [0; 1];
        browser.read_exact(&mut first)?;
        let deadline = Instant::now() + IO_LIMIT;
        let mut second = [0; 1];
        read_part(browser, &mut second, deadline)?;
        let fin = first[0] & 0x80 != 0;
        let opcode = first[0] & 0x0f;
        if first[0] & 0x70 != 0 || second[0] & 0x80 == 0 { return Err(invalid()); }
        let short = second[0] & 0x7f;
        if opcode >= 8 && (!fin || short > 125) { return Err(invalid()); }
        let len = match short {
            126 => {
                let mut extended = [0; 2];
                read_part(browser, &mut extended, deadline)?;
                let value = u16::from_be_bytes(extended);
                if value < 126 { return Err(invalid()); }
                u64::from(value)
            }
            127 => {
                let mut extended = [0; 8];
                read_part(browser, &mut extended, deadline)?;
                let value = u64::from_be_bytes(extended);
                if value < 65536 { return Err(invalid()); }
                value
            }
            n => u64::from(n),
        };
        if len > FRAME_LIMIT || !matches!((opcode, fragmented), (2, false) | (0, true) | (8..=10, _)) {
            return Err(invalid());
        }
        let mut mask = [0; 4];
        read_part(browser, &mut mask, deadline)?;
        let mut payload = vec![0; len as usize];
        read_part(browser, &mut payload, deadline)?;
        for (i, byte) in payload.iter_mut().enumerate() { *byte ^= mask[i % 4]; }
        match opcode {
            0 | 2 => {
                fragmented = !fin;
                rfb.write_all(&payload)?;
            }
            8 => {
                if payload.len() == 1 || (payload.len() >= 2 && std::str::from_utf8(&payload[2..]).is_err()) {
                    return Err(invalid());
                }
                return write_frame(output, 8, &payload);
            }
            9 => write_frame(output, 10, &payload)?,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_matches_rfc_example_and_rejects_cross_origin_or_missing_ticket() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert_eq!(accept(key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        let ticket = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let header = format!("Sec-WebSocket-Protocol: binary, {ticket}");
        let mut headers = [
            "Host: 127.77.0.1:45000", "Origin: https://svm.localhost", "Upgrade: websocket",
            "Connection: Upgrade", "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", &header,
        ];
        let parse = |headers| Upgrade::parse("GET", "vm", 45000, headers);
        assert_eq!(parse(headers.into_iter()).ok().unwrap().ticket, ticket);
        // 127.0.0.1 is the address a guest without isolation can reach; the console is not there.
        headers[0] = "Host: 127.0.0.1:45000";
        assert_eq!(parse(headers.into_iter()).err().unwrap().status, 403);
        headers[0] = "Host: 127.77.0.1:45000";
        headers[1] = "Origin: https://svm.app";
        assert_eq!(parse(headers.into_iter()).err().unwrap().status, 403);
        headers[1] = "Origin: https://svm.localhost.attacker.invalid";
        assert_eq!(parse(headers.into_iter()).err().unwrap().status, 403);
        headers[1] = "Origin: https://svm.localhost";
        headers[6] = "Sec-WebSocket-Protocol: binary";
        assert_eq!(parse(headers.into_iter()).err().unwrap().status, 401);
    }
}
