use serde_json::Value;
use std::{
    collections::BTreeMap, env, fmt, fs::{self, OpenOptions, TryLockError},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 16 * 1024 * 1024;
const START: &str = "The local service is not running. Start it with: svmd";

#[derive(Debug)]
pub enum ClientError { Offline, Other(String) }

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offline => f.write_str(START),
            Self::Other(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for ClientError {}

pub struct Client { port: u16, token: String }

pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

fn other(message: &str) -> ClientError { ClientError::Other(message.to_owned()) }

fn port_number(text: &str) -> Result<u16, ClientError> {
    text.trim().parse().ok().filter(|p| *p > 0)
        .ok_or_else(|| other("Choose a local service port between 1 and 65535."))
}

pub fn data_home() -> Result<PathBuf, ClientError> {
    if let Some(folder) = env::var_os("SVM_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(folder));
    }
    env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty())
        .map(|folder| PathBuf::from(folder).join("SecwizVM"))
        .ok_or_else(|| other("Set SVM_HOME to the local service data folder."))
}

impl Client {
    /// Reads only the service discovery files, never the VM library.
    pub fn load(folder: &Path, override_port: Option<u16>) -> Result<Self, ClientError> {
        let owner = match OpenOptions::new().read(true).write(true).open(folder.join("service.lock")) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ClientError::Offline),
            Err(_) => return Err(other("Cannot check local service ownership.")),
        };
        match owner.try_lock_shared() {
            Ok(()) => return Err(ClientError::Offline),
            Err(TryLockError::WouldBlock) => {}
            Err(_) => return Err(other("Cannot check local service ownership.")),
        }
        let token = match fs::read_to_string(folder.join("api-token")) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ClientError::Offline),
            Err(_) => return Err(other("Cannot read the local service credential.")),
        };
        let token = token.trim();
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(other("The local service credential has an invalid format."));
        }
        let port = match override_port {
            Some(0) => return Err(other("Choose a local service port between 1 and 65535.")),
            Some(number) => number,
            None => match fs::read_to_string(folder.join("api-port")) {
                Ok(text) => port_number(&text)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ClientError::Offline),
                Err(_) => return Err(other("Cannot read the local service port.")),
            },
        };
        Ok(Self { port, token: token.to_owned() })
    }

    /// Detect a credential echoed by a peer without exposing it to the caller.
    pub fn contains_credential(&self, bytes: &[u8]) -> bool {
        bytes.windows(self.token.len()).any(|value| value == self.token.as_bytes())
    }

    pub fn from_environment() -> Result<Self, ClientError> {
        let port = match env::var("SVM_PORT") {
            Ok(value) => Some(port_number(&value)?),
            Err(env::VarError::NotPresent) => None,
            Err(_) => return Err(other("The service port must be a number.")),
        };
        Self::load(&data_home()?, port)
    }

    pub fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Response, ClientError> {
        // A retained Hyper-V export gets up to two hours plus final unregister and trash.
        let timeout = if (method == "DELETE" && path.starts_with("/v1/machines/") && path.split('/').count() == 4)
            || (method == "POST" && path.starts_with("/v1/trash/") && path.ends_with("/restore"))
            || (method == "POST" && path == "/v1/machines" && body.and_then(|value| value["catalogId"].as_str()).is_some()) {
            Duration::from_secs(7_500)
        } else { Duration::from_secs(300) };
        self.request_with_timeout(method, path, body, timeout)
    }

    pub fn request_with_timeout(&self, method: &str, path: &str, body: Option<&Value>, read_timeout: Duration) -> Result<Response, ClientError> {
        let start = Instant::now();
        let time_left = || read_timeout.checked_sub(start.elapsed()).filter(|t| !t.is_zero())
            .ok_or_else(|| other("The service request timed out."));
        if !matches!(method, "GET" | "POST" | "PATCH" | "PUT" | "DELETE")
            || !path.starts_with("/v1/") || !path.bytes().all(|b| b.is_ascii_graphic() && b != b'#') {
            return Err(other("The local API request is invalid."));
        }
        let host = svm_core::local_auth::SERVICE_HOST;
        let address = SocketAddr::from((host, self.port));
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3).min(time_left()?))
            .map_err(|e| match e.kind() {
                io::ErrorKind::ConnectionRefused => ClientError::Offline,
                _ => other("Cannot connect to the local service."),
            })?;
        let io_error = |_| other("The service did not finish the request; check its status before retrying.");
        let auth_deadline = Instant::now() + Duration::from_secs(2).min(time_left()?);
        svm_core::local_auth::client(&mut stream, &self.token, self.port, auth_deadline)
            .map_err(|_| other("Cannot authenticate the local service connection."))?;
        stream.set_write_timeout(Some(Duration::from_secs(10).min(time_left()?))).map_err(io_error)?;
        let content = match body {
            Some(value) => serde_json::to_vec(value).map_err(|_| other("Cannot encode the request as JSON."))?,
            None => Vec::new(),
        };
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: {host}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", self.port, content.len()).map_err(io_error)?;
        stream.write_all(&content).map_err(io_error)?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            stream.set_read_timeout(Some(time_left()?)).map_err(io_error)?;
            let count = stream.read(&mut buffer).map_err(io_error)?;
            if count == 0 { break; }
            if bytes.len() + count > MAX_HEADER + MAX_BODY {
                return Err(other("The service response exceeds the client size limit."));
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        decode(&bytes)
    }
}

fn decode(bytes: &[u8]) -> Result<Response, ClientError> {
    let separator = bytes.windows(4).take(MAX_HEADER).position(|s| s == b"\r\n\r\n")
        .ok_or_else(|| other("The service returned incomplete HTTP headers."))?;
    let header = std::str::from_utf8(&bytes[..separator])
        .map_err(|_| other("The service returned invalid HTTP headers."))?;
    let mut lines = header.split("\r\n");
    let mut start = lines.next().unwrap_or_default().split_whitespace();
    if !matches!(start.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(other("The service returned an invalid HTTP version."));
    }
    let status = start.next().and_then(|s| s.parse::<u16>().ok()).filter(|n| (100..=599).contains(n))
        .ok_or_else(|| other("The service returned an invalid HTTP status."))?;
    let mut headers = BTreeMap::new();
    for line in lines {
        let (key, value) = line.split_once(':').ok_or_else(|| other("The service returned an invalid header."))?;
        if headers.insert(key.to_ascii_lowercase(), value.trim().to_owned()).is_some() {
            return Err(other("The service returned duplicate headers."));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(other("The service returned an unsupported transfer encoding."));
    }
    let data = &bytes[separator + 4..];
    if data.len() > MAX_BODY { return Err(other("The service response exceeds the client size limit.")); }
    if let Some(field) = headers.get("content-length") {
        if field.parse::<usize>().ok() != Some(data.len()) {
            return Err(other("The service response has an incorrect length."));
        }
    }
    Ok(Response { status, headers, body: data.to_vec() })
}
