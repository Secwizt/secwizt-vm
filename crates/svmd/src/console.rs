use crate::{auth, http, ApiError, Reply};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    net::{Shutdown, TcpStream},
    sync::{Arc, Mutex}, thread, time::{Duration, Instant},
};
use svm_qemu::ConsoleEndpoint;

const TTL: Duration = Duration::from_secs(30);
const MAX_TICKETS: usize = 32;
const MAX_PER_MACHINE: usize = 2;
const MAX_CONNECTIONS: usize = 4;
pub(crate) const ORIGIN: &str = "https://svm.localhost";

type Asset = (&'static str, &'static str, &'static [u8]);
const ASSETS: &[Asset] = include!(concat!(env!("OUT_DIR"), "/console-assets.rs"));
const ASSET_PREFIX: &str = "/v1/console/assets/";

pub(crate) fn asset(request: &http::Request) -> Option<Reply> {
    let path = request.target.strip_prefix(ASSET_PREFIX)?;
    let result = match (request.method.as_str(), ASSETS.iter().find(|(name, _, _)| *name == path)) {
        ("GET", Some((_, content_type, bytes))) => Reply {
            status: 200, content_type, width_height: None, body: bytes.to_vec(),
        },
        _ => Reply::error(ApiError::missing()),
    };
    Some(result)
}

pub(crate) fn machine_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 80 && !matches!(id, "." | "..")
        && id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

fn unauthorized() -> ApiError { ApiError::new(401, "console_ticket", "The console ticket is unavailable. Reconnect to get a fresh ticket.") }
fn unavailable() -> ApiError { ApiError::new(503, "console_unavailable", "The local console is unavailable. Try again shortly.") }

struct Ticket<T> {
    digest: [u8; 32],
    expires: Instant,
    id: String,
    origin: &'static str,
    endpoint: T,
}

struct Connection {
    serial: u64,
    id: String,
    stream: TcpStream,
}

struct State<T> {
    tickets: Vec<Ticket<T>>,
    connections: Vec<Connection>,
    next: u64,
    closed: bool,
}

impl<T> State<T> {
    fn new() -> Self {
        Self { tickets: Vec::new(), connections: Vec::new(), next: 0, closed: false }
    }

    fn issue(&mut self, id: &str, endpoint: T, now: Instant) -> Result<String, ApiError> {
        if self.closed { return Err(unavailable()); }
        self.tickets.retain(|ticket| ticket.expires > now);
        if self.tickets.len() >= MAX_TICKETS {
            return Err(ApiError::new(503, "console_tickets_busy", "Too many console tickets are pending. Try again in 30 seconds."));
        }
        let mut secret = [0; 32];
        getrandom::fill(&mut secret).map_err(|_| unavailable())?;
        let digest = Sha256::digest(secret).into();
        let answer = URL_SAFE_NO_PAD.encode(secret);
        self.tickets.push(Ticket { digest, id: id.to_owned(), expires: now + TTL, origin: ORIGIN, endpoint });
        Ok(answer)
    }

    fn check_capacity(&self, id: &str) -> Result<(), ApiError> {
        if self.connections.len() >= MAX_CONNECTIONS
            || self.connections.iter().filter(|bridge| bridge.id == id).count() >= MAX_PER_MACHINE {
            return Err(ApiError::new(503, "console_busy", "Close another console before reconnecting. Each machine allows two consoles and the app allows four in total."));
        }
        Ok(())
    }

    fn admit(&mut self, id: &str, origin: &str, encoded: &str, stream: &TcpStream, now: Instant) -> Result<(u64, T), ApiError> {
        if self.closed { return Err(unavailable()); }
        let mut secret = [0; 32];
        if encoded.len() != 43 || URL_SAFE_NO_PAD.decode_slice(encoded, &mut secret).ok() != Some(secret.len()) {
            return Err(unauthorized());
        }
        let digest = Sha256::digest(secret);
        self.tickets.retain(|ticket| ticket.expires > now);
        let index = self.tickets.iter().position(|ticket|
            auth::accepts(&ticket.digest, &digest) && ticket.id == id && ticket.origin == origin).ok_or_else(unauthorized)?;
        // A valid presentation consumes the ticket even if the browser must retry.
        let endpoint = self.tickets.swap_remove(index).endpoint;
        self.check_capacity(id)?;
        let serial = self.next;
        self.next = self.next.wrapping_add(1);
        self.connections.push(Connection { serial, id: id.to_owned(), stream: stream.try_clone().map_err(|_| unavailable())? });
        Ok((serial, endpoint))
    }
}

pub(crate) struct Console {
    port: u16,
    state: Mutex<State<ConsoleEndpoint>>,
}

impl Console {
    pub(crate) fn new(port: u16) -> Self {
        Self { port, state: Mutex::new(State::new()) }
    }

    pub(crate) fn issue(&self, id: &str, endpoint: ConsoleEndpoint) -> Result<Reply, ApiError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        state.check_capacity(id)?;
        let ticket = state.issue(id, endpoint, Instant::now())?;
        Ok(Reply::json(json!({"ticket":ticket,"port":self.port})))
    }

    pub(crate) fn upgrade(self: &Arc<Self>, mut stream: TcpStream, upgrade: super::websocket::Upgrade) {
        let admission = self.state.lock().map_err(|_| unavailable())
            .and_then(|mut state| state.admit(&upgrade.id, ORIGIN, &upgrade.ticket, &stream, Instant::now()));
        let (serial, endpoint) = match admission {
            Ok(accepted) => accepted,
            Err(error) => { let _ = http::send(&mut stream, &Reply::error(error)); return; }
        };
        let permit = Permit { console: Arc::clone(self), serial };
        let _ = thread::Builder::new().name("qemu-console".into()).spawn(move || {
            let _permit = permit;
            let rfb = match endpoint.connect() {
                Ok(stream) => stream,
                Err(_) => {
                    let error = ApiError::new(409, "console_run", "The QEMU console changed or is unavailable. Reconnect to the current run.");
                    let _ = http::send(&mut stream, &Reply::error(error));
                    return;
                }
            };
            let _ = super::websocket::relay(stream, rfb, &upgrade.key);
        });
    }

    #[cfg(test)]
    pub(crate) fn register_test_socket(&self, stream: TcpStream) {
        self.state.lock().unwrap().connections.push(Connection {
            serial: 0, id: "shutdown-fixture".into(), stream,
        });
    }

    pub(crate) fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.tickets.clear();
            for bridge in &state.connections { let _ = bridge.stream.shutdown(Shutdown::Both); }
        }
    }
}

struct Permit {
    console: Arc<Console>,
    serial: u64,
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.console.state.lock() {
            state.connections.retain(|connection| connection.serial != self.serial);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn tickets_bind_origin_machine_and_run_and_are_single_use() {
        let mut state = State::new();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let now = Instant::now();
        let ticket = state.issue("vm", "owned-run-one", now).unwrap();
        for (id, origin, candidate) in [("other", ORIGIN, ticket.as_str()), ("vm", "https://other.test", ticket.as_str()), ("vm", ORIGIN, "")] {
            assert_eq!(state.admit(id, origin, candidate, &stream, now).unwrap_err().status, 401);
        }
        let current_run = "owned-run-two";
        let (_, bound_run) = state.admit("vm", ORIGIN, &ticket, &stream, now).unwrap();
        assert_eq!(bound_run, "owned-run-one");
        assert_ne!(bound_run, current_run);
        assert_eq!(state.admit("vm", ORIGIN, &ticket, &stream, now).unwrap_err().status, 401);
        let expired = state.issue("vm", current_run, now).unwrap();
        assert_eq!(state.admit("vm", ORIGIN, &expired, &stream, now + TTL).unwrap_err().status, 401);
    }

    #[test]
    fn console_capacity_enforces_both_limits() {
        let mut state = State::new();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let now = Instant::now();
        let mut admit = |id| {
            let ticket = state.issue(id, (), now).unwrap();
            state.admit(id, ORIGIN, &ticket, &stream, now)
        };
        assert!(admit("first").is_ok());
        assert!(admit("first").is_ok());
        assert_eq!(admit("first").unwrap_err().code, "console_busy");
        assert!(admit("second").is_ok());
        assert!(admit("second").is_ok());
        assert_eq!(admit("third").unwrap_err().code, "console_busy");
    }
}
