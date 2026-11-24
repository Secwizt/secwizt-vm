use crate::{websocket::Upgrade, ApiError, Reply};
use serde_json::Value;
use std::{io::{self, Read, Write}, net::TcpStream, time::{Duration, Instant}};

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 256 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(2);
const PRE_AUTH_TIMEOUT: Duration = Duration::from_millis(500);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct Request {
    pub method: String,
    pub target: String,
    pub body: Value,
}

pub(crate) enum Incoming {
    Api(Request),
    Console(Upgrade),
}

pub(crate) fn header(line: &str) -> Result<(String, &str), ApiError> {
    let malformed = || ApiError::invalid("Send one complete HTTP/1.1 request.");
    let (name, value) = line.split_once(':').ok_or_else(malformed)?;
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || value.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f) { return Err(malformed()); }
    Ok((name.to_ascii_lowercase(), value.trim_matches([' ', '\t'])))
}

fn remaining(deadline: Instant) -> Result<Duration, ApiError> {
    deadline.checked_duration_since(Instant::now()).filter(|v| !v.is_zero())
        .ok_or_else(|| ApiError::new(408, "timeout", "The request took too long."))
}

fn receive(stream: &mut TcpStream, deadline: Instant, buf: &mut [u8]) -> Result<usize, ApiError> {
    stream.set_read_timeout(Some(remaining(deadline)?)).map_err(ApiError::storage)?;
    stream.read(buf).map_err(|_| ApiError::new(408, "incomplete_request", "The request did not arrive in time."))
}

pub(crate) fn read(stream: &mut TcpStream, port: u16, token: &str, authenticated: impl FnOnce()) -> Result<Incoming, ApiError> {
    let started = Instant::now();
    let deadline = started + PRE_AUTH_TIMEOUT;
    stream.set_read_timeout(Some(remaining(deadline)?)).map_err(ApiError::storage)?;
    let mut preface = [0u8; 1];
    let native = stream.peek(&mut preface)
        .map_err(|_| ApiError::new(408, "incomplete_request", "The request did not arrive in time."))? == 1
        && preface[0] == 0;
    if native {
        svm_core::local_auth::server(stream, token, port, deadline)
            .map_err(|_| unauthorized())?;
        authenticated();
    }
    let started = Instant::now();
    let header = if native { started + HEADER_TIMEOUT } else { deadline };
    read_with_deadlines(stream, port, native, header, started + REQUEST_TIMEOUT)
}

fn unauthorized() -> ApiError { ApiError::new(401, "unauthorized", "Unauthorized.") }

fn read_with_deadlines(stream: &mut TcpStream, port: u16, authenticated: bool, header_deadline: Instant, deadline: Instant) -> Result<Incoming, ApiError> {
    let malformed = || ApiError::invalid("Send one complete HTTP/1.1 request.");
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 2048];
    let mut scanned = 0usize;
    let end = loop {
        if let Some(i) = bytes[scanned..].windows(4).position(|w| w == b"\r\n\r\n") { break scanned + i + 4; }
        if bytes.len() >= MAX_HEAD { return Err(ApiError::new(431, "headers_too_large", "The request headers are too large.")); }
        scanned = bytes.len().saturating_sub(3);
        let n = receive(stream, header_deadline, &mut chunk)?;
        if n == 0 { return Err(malformed()); }
        bytes.extend_from_slice(&chunk[..n]);
    };
    if end > MAX_HEAD { return Err(ApiError::new(431, "headers_too_large", "The request headers are too large.")); }
    let head = std::str::from_utf8(&bytes[..end - 4]).map_err(|_| malformed())?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().ok_or_else(malformed)?.split(' ');
    let method = first.next().ok_or_else(malformed)?.to_owned();
    let target = first.next().ok_or_else(malformed)?.to_owned();
    if first.next() != Some("HTTP/1.1") || first.next().is_some()
        || !target.bytes().all(|b| b.is_ascii_graphic() && !b"#%\\".contains(&b)) { return Err(malformed()); }
    if let Some(id) = target.strip_prefix("/console/") {
        if authenticated || bytes.len() != end { return Err(malformed()); }
        return Upgrade::parse(&method, id, port, lines).map(Incoming::Console);
    }
    if !target.starts_with("/v1/") { return Err(malformed()); }
    let (mut host, mut credential, mut length, mut content_type) = (None, None, None, None);
    let mut expectation = None;
    let mut origin = false;
    for line in lines {
        let (name, val) = header(line)?;
        match name.as_str() {
            "host" if host.replace(val).is_some() => return Err(malformed()),
            "authorization" if credential.replace(val).is_some() => return Err(malformed()),
            "content-length" if length.replace(val).is_some() => return Err(malformed()),
            "content-type" if content_type.replace(val).is_some() => return Err(malformed()),
            "origin" => origin = true,
            "expect" if expectation.replace(val).is_some() => return Err(malformed()),
            "transfer-encoding" => return Err(malformed()),
            _ => {}
        }
    }
    if !authenticated || credential.is_some() { return Err(unauthorized()); }
    if origin || !host.is_some_and(|h| h == format!("{}:{port}", svm_core::local_auth::SERVICE_HOST)) {
        return Err(ApiError::new(403, "forbidden", "This request is not allowed."));
    }
    let too_large = || ApiError::new(413, "body_too_large", "The JSON request is too large.");
    let length = match length {
        Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => value.parse::<usize>().map_err(|_| too_large())?,
        Some(_) => return Err(malformed()),
        None => 0,
    };
    if length > MAX_BODY { return Err(too_large()); }
    if length > 0 && !content_type.is_some_and(|t| t.split(';').next().is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))) {
        return Err(ApiError::new(415, "content_type", "Send the request as application/json."));
    }
    let mut received = bytes.len() - end;
    if received > length { return Err(malformed()); }
    if let Some(expect) = expectation {
        if !expect.eq_ignore_ascii_case("100-continue") {
            return Err(ApiError::new(417, "unsupported_expectation", "Only Expect: 100-continue is supported."));
        }
        if received < length {
            stream.set_write_timeout(Some(remaining(deadline)?)).map_err(ApiError::storage)?;
            stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .map_err(|_| ApiError::new(408, "incomplete_request", "The client did not receive permission to send the body."))?;
        }
    }
    bytes.resize(end + length, 0);
    while received < length {
        let n = receive(stream, deadline, &mut bytes[end + received..])?;
        if n == 0 { return Err(malformed()); }
        received += n;
    }
    let body = if length == 0 { serde_json::json!({}) } else {
        let value: Value = serde_json::from_slice(&bytes[end..]).map_err(|_| ApiError::invalid("The request body must be a JSON object."))?;
        if !value.is_object() { return Err(ApiError::invalid("The request body must be a JSON object.")); }
        value
    };
    Ok(Incoming::Api(Request { method, target, body }))
}

pub(crate) fn send(stream: &mut TcpStream, reply: &Reply) -> io::Result<()> {
    let reason = match reply.status {
        200 => "OK", 201 => "Created", 202 => "Accepted", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden",
        404 => "Not Found", 405 => "Method Not Allowed", 408 => "Request Timeout", 409 => "Conflict",
        413 => "Content Too Large", 415 => "Unsupported Media Type", 417 => "Expectation Failed", 431 => "Request Header Fields Too Large",
        500 => "Internal Server Error", 502 => "Bad Gateway", 503 => "Service Unavailable", 504 => "Gateway Timeout", _ => "Response",
    };
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(stream, "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n", reply.status, reason, reply.content_type, reply.body.len())?;
    if let Some((width, height)) = reply.width_height {
        write!(stream, "X-Width: {width}\r\nX-Height: {height}\r\nX-Pixel-Format: RGBA8\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&reply.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn idle_connections_have_a_shorter_deadline_before_authentication() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let started = Instant::now();
        let error = read(&mut stream, addr.port(), "fixture", || panic!("an idle peer authenticated"))
            .err().expect("the idle peer must time out");
        assert_eq!(error.status, 408);
        assert!(started.elapsed() < HEADER_TIMEOUT);
    }

    #[test]
    fn an_expired_header_deadline_returns_timeout_without_waiting_for_input() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let started = Instant::now();
        let deadline = started.checked_sub(Duration::from_millis(1)).unwrap();
        let error = read_with_deadlines(&mut stream, addr.port(), false, deadline, started + REQUEST_TIMEOUT)
            .err().expect("the expired header should be refused");
        assert_eq!(error.status, 408);
        assert_eq!(error.code, "timeout");
        assert!(started.elapsed() < HEADER_TIMEOUT);
    }
}
