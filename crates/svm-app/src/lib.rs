#![forbid(unsafe_code)]
#![deny(warnings)]

#[cfg(windows)]
mod viewer_process;
#[cfg(windows)]
pub use viewer_process::wait_for_viewer_helper;

use serde_json::{json, Value};
use std::path::Path;
use svm::client::{Client, ClientError, Response};

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws://127.77.0.1:*; base-uri 'none'; form-action 'none'";
type Asset = (&'static str, &'static str, &'static [u8]);
const ASSETS: &[Asset] = include!(concat!(env!("OUT_DIR"), "/assets.rs"));

pub struct PageResponse { pub status: u16, pub headers: Vec<(String, String)>, pub body: Vec<u8> }

impl PageResponse {
    fn new(status: u16, mime: &str, body: Vec<u8>) -> Self {
        Self { status, headers: vec![
            ("Content-Type".into(), mime.into()), ("Content-Security-Policy".into(), CSP.into()),
            ("X-Content-Type-Options".into(),"nosniff".into()), ("Cache-Control".into(),"no-store".into()),
            ("Referrer-Policy".into(),"no-referrer".into()),
        ], body }
    }
    fn error(status: u16, code: &str, message: &str) -> Self {
        Self::new(status,"application/json",json!({"error":{"code":code,"message":message}}).to_string().into_bytes())
    }
}

fn bad() -> PageResponse { PageResponse::error(400,"invalid_request","This request is not allowed.") }
fn unavailable() -> PageResponse { PageResponse::error(503,"service_offline","The service is not running. Start it to continue.") }
fn transport(error: ClientError) -> PageResponse {
    match error {
        ClientError::Offline => unavailable(),
        ClientError::Other(_) => PageResponse::error(502,"service_unavailable","The service did not complete the request. Check its status before retrying."),
    }
}

fn safe_target(s: &str) -> bool {
    s.starts_with('/') && s.len() <= 8192 && !s.contains("..") && !s.contains("//")
        && s.bytes().all(|b| b.is_ascii_graphic() && !matches!(b,b'%'|b'\\'|b'#'))
}

fn asset(path: &str) -> PageResponse {
    if path == "/favicon.ico" { return PageResponse::new(204,"image/x-icon",Vec::new()); }
    if path == "/notices.txt" {
        return PageResponse::new(200,"text/plain; charset=utf-8",include_bytes!(concat!(env!("OUT_DIR"),"/notices.txt")).to_vec());
    }
    let path = if path == "/" { "/index.html" } else { path };
    ASSETS.iter().find(|(name,_,_)| *name == path)
        .map(|(_,mime,data)| PageResponse::new(200,mime,data.to_vec()))
        .unwrap_or_else(|| PageResponse::error(404,"not_found","The requested page was not found."))
}

pub fn handle(home: &Path, method: &str, target: &str, content_type: Option<&str>, body: &[u8]) -> PageResponse {
    if !safe_target(target) || target == "/api" { return bad(); }
    if target.starts_with("/console/assets/") {
        if method != "GET" || !body.is_empty() || target.contains('?') { return bad(); }
        let client = match Client::load(home, None) { Ok(c) => c, Err(e) => return transport(e) };
        let result = match client.request("GET", &format!("/v1{target}"), None) {
            Ok(reply) => reply, Err(e) => return transport(e),
        };
        if result.status != 200 || client.contains_credential(&result.body) {
            return PageResponse::error(404, "console_asset", "The requested console file was not found.");
        }
        return match result.headers.get("content-type").map(String::as_str) {
            Some("text/javascript; charset=utf-8") => PageResponse::new(200, "text/javascript; charset=utf-8", result.body),
            Some("text/plain; charset=utf-8") => PageResponse::new(200, "text/plain; charset=utf-8", result.body),
            _ => PageResponse::error(502, "console_asset", "The requested console file was unavailable."),
        };
    }
    if !target.starts_with("/api/") {
        return if method == "GET" && body.is_empty() { asset(target) } else { bad() };
    }
    let path = &target[4..];
    let resource = path.split('?').next().unwrap_or("");
    if !resource.starts_with("/v1/") || resource.len() <= 4 || resource.ends_with('/')
        || resource.split('/').any(|p| p == ".") || resource.eq_ignore_ascii_case("/v1/shutdown")
        || !matches!(method, "GET" | "POST" | "PUT" | "PATCH" | "DELETE") || body.len() > 256 * 1024 {
        return bad();
    }
    let payload: Option<Value> = if body.is_empty() { None } else {
        if method == "GET" || !content_type.and_then(|s| s.split(';').next()).is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json")) { return bad(); }
        match serde_json::from_slice(body) { Ok(v @ Value::Object(_)) => Some(v), _ => return bad() }
    };
    let client = match Client::load(home, None) { Ok(c) => c, Err(e) => return transport(e) };
    let result = match client.request(method, path, payload.as_ref()) { Ok(r) => r, Err(e) => return transport(e) };
    if client.contains_credential(&result.body) {
        return PageResponse::error(502,"invalid_reply","The service returned a response that cannot be displayed.");
    }
    page_reply(path, result)
}

fn page_reply(path: &str, result: Response) -> PageResponse {
    let invalid = || PageResponse::error(502,"invalid_reply","The service returned an unreadable response.");
    let mime = result.headers.get("content-type").and_then(|s| s.split(';').next()).map(str::trim);
    if mime == Some("application/json") && serde_json::from_slice::<Value>(&result.body).is_ok() {
        return PageResponse::new(result.status, "application/json", result.body);
    }
    if result.status != 200 || !path.ends_with("/thumbnail") || mime != Some("application/octet-stream")
        || !result.headers.get("x-pixel-format").is_some_and(|s| s == "RGBA8") { return invalid(); }
    let dimension = |key| result.headers.get(key).and_then(|s| s.parse::<u16>().ok()).filter(|n| *n != 0);
    let (Some(w),Some(h)) = (dimension("x-width"), dimension("x-height")) else { return invalid() };
    if usize::from(w).checked_mul(usize::from(h)).and_then(|n| n.checked_mul(4)) != Some(result.body.len()) { return invalid(); }
    let mut response = PageResponse::new(200, "application/octet-stream", result.body);
    response.headers.extend([("X-Width".into(),w.to_string()),("X-Height".into(),h.to_string()),("X-Pixel-Format".into(),"RGBA8".into())]);
    response
}

#[cfg(test)]
mod tests;
