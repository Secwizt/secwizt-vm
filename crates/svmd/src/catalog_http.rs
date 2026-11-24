use sha2::{Digest, Sha256};
use std::{io, time::Duration};
use ureq::{
    http::{header, HeaderMap, HeaderName},
    unversioned::{
        resolver::DefaultResolver,
        transport::{time, Buffers, ConnectionDetails, Connector, DefaultConnector, NextTimeout, Transport},
    },
    Agent,
};
use url::{Host, Url};

const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const HEADER_TIMEOUT: Duration = Duration::from_secs(20);
const READ_IDLE_TIMEOUT: time::Duration = time::Duration::from_secs(15);
const INVALID_HEADERS: &str = "The official source returned invalid download headers.";
const UNOFFICIAL_URL: &str = "The download URL or redirect is outside the approved official HTTPS hosts.";

pub(super) struct ArtifactResponse {
    pub status: u16,
    pub etag: Option<String>,
    pub resource: String,
    pub content_length: Option<u64>,
    pub content_range: Option<String>,
    pub gzip: bool,
    pub body: Box<dyn io::Read + Send>,
}

fn official_url(raw: &str, base: Option<&Url>, official_hosts: &[String]) -> Result<Url, String> {
    if raw.is_empty() || raw.len() > 8192 || raw.trim() != raw
        || raw.bytes().any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(UNOFFICIAL_URL.into());
    }

    // The URL parser can normalize an empty userinfo component away. Check it before parsing.
    if let Some(authority) = raw.strip_prefix("//").or_else(|| raw.split_once("://").map(|(_, tail)| tail)) {
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(UNOFFICIAL_URL.into());
        }
    }

    let url = match base {
        Some(base) => base.join(raw),
        None => Url::parse(raw),
    }.map_err(|_| UNOFFICIAL_URL.to_owned())?;

    let allowed_host = matches!(url.host(), Some(Host::Domain(host)) if official_hosts.iter().any(|allowed| host == allowed));
    if url.scheme() != "https" || url.port_or_known_default() != Some(443) || !allowed_host
        || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
    {
        return Err(UNOFFICIAL_URL.into());
    }
    Ok(url)
}

pub(super) fn official_destination(url: &str, hosts: &[String]) -> bool {
    official_url(url, None, hosts).is_ok()
}

fn one_header(headers: &HeaderMap, name: HeaderName) -> Result<Option<&str>, String> {
    let values = headers.get_all(name);
    let mut values = values.iter();
    let Some(value) = values.next() else { return Ok(None); };
    if values.next().is_some() { return Err(INVALID_HEADERS.into()); }
    value.to_str().map(Some).map_err(|_| INVALID_HEADERS.into())
}

fn strong_etag(etag: &str) -> bool {
    etag.len() <= 1024 && etag.strip_prefix('"').and_then(|value| value.strip_suffix('"')).is_some_and(|opaque| {
        opaque.bytes().all(|byte| byte == b'!' || (b'#'..=b'~').contains(&byte))
    })
}

pub(super) fn open_artifact(
    url: &str, official_hosts: &[String], resume: Option<(u64, &str)>,
) -> Result<ArtifactResponse, String> {
    open(url, official_hosts, resume, false, None, false)
}

// Only small publisher metadata may arrive gzip-encoded (some publishers ignore `identity`); installers never.
fn open(
    url: &str, official_hosts: &[String], resume: Option<(u64, &str)>, head: bool, deadline: Option<Duration>,
    allow_gzip: bool,
) -> Result<ArtifactResponse, String> {
    let mut target = official_url(url, None, official_hosts)?;
    if resume.is_some_and(|(_, etag)| !strong_etag(etag)) {
        return Err("The saved download has no valid resume validator.".into());
    }

    let config = Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .timeout_global(deadline)
        .timeout_resolve(Some(CONNECT_TIMEOUT))
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_send_request(Some(CONNECT_TIMEOUT))
        .timeout_recv_response(Some(HEADER_TIMEOUT))
        .build();
    let agent = Agent::with_parts(config, IdleConnector::default(), DefaultResolver::default());
    for hop in 0..=MAX_REDIRECTS {
        let request = if head { agent.head(target.as_str()) } else { agent.get(target.as_str()) };
        let mut request = request.header(header::ACCEPT_ENCODING, "identity");
        if let Some((offset, etag)) = resume {
            request = request.header(header::RANGE, format!("bytes={offset}-")).header(header::IF_RANGE, etag);
        }
        let response = request.call().map_err(|error| match error {
            ureq::Error::Timeout(_) => "The official source took too long to respond.".to_owned(),
            _ => "Could not open an HTTPS connection to the official download source.".to_owned(),
        })?;
        let status = response.status().as_u16();
        let headers = response.headers();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if hop == MAX_REDIRECTS { return Err("The official source redirected the download too many times.".into()); }
            let location = one_header(headers, header::LOCATION)?
                .ok_or_else(|| "The official source returned a redirect without a destination.".to_owned())?;
            target = official_url(location, Some(&target), official_hosts)?;
            continue;
        }
        let gzip = match one_header(headers, header::CONTENT_ENCODING)? {
            None => false,
            Some(encoding) if encoding.eq_ignore_ascii_case("identity") => false,
            Some(encoding) if allow_gzip && encoding.eq_ignore_ascii_case("gzip") => true,
            Some(_) => return Err("The official source returned an unexpected content encoding.".into()),
        };
        let content_length = one_header(headers, header::CONTENT_LENGTH)?.map(|value| {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(INVALID_HEADERS.to_owned());
            }
            value.parse::<u64>().map_err(|_| INVALID_HEADERS.to_owned())
        }).transpose()?;
        let etag = one_header(headers, header::ETAG)?.map(str::to_owned);
        let content_range = one_header(headers, header::CONTENT_RANGE)?.map(str::to_owned);
        return Ok(ArtifactResponse {
            status, etag, content_length, content_range, gzip,
            resource: format!("{:x}", Sha256::digest(target.as_str().as_bytes())),
            body: Box::new(CleanBody(response.into_body().into_reader())),
        });
    }
    unreachable!("every redirect is bounded or returns an error");
}

pub(super) fn metadata(url: &str, hosts: &[String], limit: usize) -> Result<Vec<u8>, String> {
    use io::Read;
    let reply = open(url, hosts, None, false, Some(Duration::from_secs(30)), true)?;
    if reply.status != 200 || reply.content_range.is_some()
        || reply.content_length.is_some_and(|size| size > limit as u64)
    {
        return Err("The publisher metadata was unavailable or exceeded its size limit.".into());
    }
    let mut bytes = Vec::new();
    reply.body.take(limit as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| "The publisher metadata response was interrupted.".to_owned())?;
    if bytes.is_empty() || bytes.len() > limit || reply.content_length.is_some_and(|size| size != bytes.len() as u64) {
        return Err("The publisher metadata did not have the expected length.".into());
    }
    if reply.gzip { gunzip(&bytes, limit) } else { Ok(bytes) }
}

/// Decode one complete gzip member held in memory. The decoded text has the same size limit as plain
/// metadata, and trailing bytes after the member are refused. Signatures are still checked afterwards.
fn gunzip(compressed: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    use io::Read;
    const INVALID_GZIP: &str = "The publisher metadata was not valid compressed text.";
    let mut decoder = flate2::bufread::GzDecoder::new(compressed);
    let mut text = Vec::new();
    (&mut decoder).take(limit as u64 + 1).read_to_end(&mut text).map_err(|_| INVALID_GZIP.to_owned())?;
    if text.is_empty() || text.len() > limit || !decoder.into_inner().is_empty() {
        return Err(INVALID_GZIP.into());
    }
    Ok(text)
}

pub(super) fn media_size(url: &str, hosts: &[String]) -> Result<u64, String> {
    let reply = open(url, hosts, None, true, Some(Duration::from_secs(24)), false)?;
    if reply.status != 200 || reply.content_range.is_some() {
        return Err("The publisher did not report the installer length.".into());
    }
    reply.content_length.filter(|size| (1..=128 * 1024 * 1024 * 1024).contains(size))
        .ok_or_else(|| "The publisher did not report a supported installer length.".into())
}

struct CleanBody<R>(R);
impl<R: io::Read> io::Read for CleanBody<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer).map_err(|error| io::Error::new(error.kind(), "Could not read the official download stream."))
    }
}

// This caps I/O inactivity without imposing a deadline on the whole ISO.
#[derive(Debug, Default)]
struct IdleConnector(DefaultConnector);
impl Connector for IdleConnector {
    type Out = IdleTransport;

    fn connect(&self, details: &ConnectionDetails, chained: Option<()>) -> Result<Option<Self::Out>, ureq::Error> {
        self.0.connect(details, chained).map(|transport| transport.map(IdleTransport))
    }
}

#[derive(Debug)]
struct IdleTransport(Box<dyn Transport>);
impl Transport for IdleTransport {
    fn buffers(&mut self) -> &mut dyn Buffers { self.0.buffers() }

    fn transmit_output(&mut self, amount: usize, mut timeout: NextTimeout) -> Result<(), ureq::Error> {
        timeout.after = timeout.after.min(READ_IDLE_TIMEOUT);
        self.0.transmit_output(amount, timeout)
    }

    fn await_input(&mut self, mut timeout: NextTimeout) -> Result<bool, ureq::Error> {
        timeout.after = timeout.after.min(READ_IDLE_TIMEOUT);
        self.0.await_input(timeout)
    }

    fn is_open(&mut self) -> bool { self.0.is_open() }
    fn is_tls(&self) -> bool { self.0.is_tls() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_destinations_use_exact_official_https_origins() {
        let hosts = ["images.example.org".to_owned(), "cdn.example.org".to_owned()];
        let base = official_url("https://images.example.org:443/release/image.iso?private=value", None, &hosts).unwrap();
        assert!(official_url("image2.iso", Some(&base), &hosts).is_ok());
        assert!(official_url("//cdn.example.org/files/image.iso", Some(&base), &hosts).is_ok());
        for invalid in [
            "http://images.example.org/file",
            "https://images.example.org:444/file",
            "https://images.example.org.evil.example/file",
            "https://images.example.org./file",
            "//unknown.example.org/file",
            "https://@images.example.org/file",
            "https://user:secret@images.example.org/file",
            "https://images.example.org/file#fragment",
        ] {
            assert_eq!(official_url(invalid, Some(&base), &hosts).unwrap_err(), UNOFFICIAL_URL);
        }
    }

    #[test]
    fn resume_only_uses_a_strong_entity_tag() {
        assert!(strong_etag("\"immutable-release\""));
        assert!(!strong_etag("W/\"immutable-release\""));
        assert!(!strong_etag("\"value\"\r\n"));
        assert!(!strong_etag("\"value\", \"different\""));
    }

    fn gzip(text: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(text).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn gzip_metadata_decodes_within_its_limit() {
        let index = b"<a href=\"22.3/\">22.3/</a>
<a href=\"23/\">23/</a>
";
        assert_eq!(gunzip(&gzip(index), 1024).unwrap(), index.to_vec());
    }

    #[test]
    fn gzip_metadata_refuses_bombs_trailing_bytes_and_damage() {
        let large = vec![b'a'; 64 * 1024];
        assert!(gunzip(&gzip(&large), 1024).is_err(), "decoded text above the limit");
        let mut trailing = gzip(b"checksums");
        trailing.extend_from_slice(b"extra");
        assert!(gunzip(&trailing, 1024).is_err(), "bytes after the gzip member");
        let mut damaged = gzip(b"checksums");
        let middle = damaged.len() / 2;
        damaged[middle] ^= 0xff;
        assert!(gunzip(&damaged, 1024).is_err(), "corrupted stream");
        assert!(gunzip(b"not gzip at all", 1024).is_err(), "plain bytes");
        assert!(gunzip(&gzip(b""), 1024).is_err(), "empty text");
    }
}
