use std::{path::PathBuf, sync::{mpsc, Arc, Mutex}, thread};
use svm_app::{PageResponse, CSP};
use wry::{http::{Request, Response, Uri}, RequestAsyncResponder};

pub const HOME_PAGE: &str = "https://svm.localhost/index.html";
pub const START_PAGE: &str = "svm://localhost/shell/start";

const START_HTML: &str = r#"<!doctype html>
<html lang="en" data-mode="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secwizt Virtual Machine</title>
<link rel="stylesheet" href="/core/tokens.css"><link rel="stylesheet" href="/core/app.css"></head>
<body><main class="main" style="max-width:48rem;padding:3rem"><h1>Secwizt Virtual Machine</h1>
<p id="status" role="status">Starting the local service…</p><button type="button" id="retry" hidden>Start it</button></main>
<script src="/shell/start.js"></script></body></html>"#;

const START_JS: &str = r#"'use strict';
const statusText = document.getElementById('status');
const retry = document.getElementById('retry');
let seq = 0;
function call(action) { window.ipc.postMessage(JSON.stringify({requestId:++seq, action})); }
function failed(text) { statusText.textContent = text; retry.hidden = false; retry.disabled = false; }
window.addEventListener('svm-native-result', event => {
  const r = event.detail;
  if (!r.ok) failed(r.error);
  else if (r.value && r.value.startupError) failed(r.value.startupError);
});
window.addEventListener('svm-startup-error', event => failed(event.detail));
retry.addEventListener('click', () => { retry.disabled = true; statusText.textContent = 'Starting the local service…'; call('startService'); });
call('appInfo');
"#;

// Wry presents the custom scheme to this handler. WebView2 presents the corresponding
// HTTPS origin to navigation and IPC callbacks. Match the entire authority in both cases.
pub fn trusted_document(uri: &Uri) -> bool {
    matches!(uri.scheme_str(), Some("https")) && uri.authority().is_some_and(|a| a.as_str() == "svm.localhost")
        && uri.query().is_none() && matches!(uri.path(), "/index.html" | "/shell/start")
}

fn standard(status: u16, content_type: &str, body: Vec<u8>) -> Response<Vec<u8>> {
    to_http(PageResponse { status, headers: vec![
        ("Content-Type".into(),content_type.into()),("Content-Security-Policy".into(),CSP.into()),
        ("Cache-Control".into(),"no-store".into()),("X-Content-Type-Options".into(),"nosniff".into()),
    ], body })
}

fn refused(status: u16, message: &str) -> Response<Vec<u8>> {
    standard(status, "application/json", serde_json::json!({"error":{"code":"desktop_request","message":message}}).to_string().into_bytes())
}

fn to_http(reply: PageResponse) -> Response<Vec<u8>> {
    let mut response = Response::builder().status(reply.status);
    for (k,v) in reply.headers { response = response.header(k,v); }
    response.body(reply.body).unwrap_or_else(|_| {
        let mut error = Response::new(Vec::new());
        *error.status_mut() = wry::http::StatusCode::INTERNAL_SERVER_ERROR;
        error
    })
}

struct Job { request: Request<Vec<u8>>, responder: RequestAsyncResponder }

pub struct Protocol { work: mpsc::SyncSender<Job>, console_assets: mpsc::SyncSender<Job>, home: PathBuf }

fn request_queue(home: &std::path::Path, name: &str, depth: usize, workers: usize) -> Result<mpsc::SyncSender<Job>, String> {
    let (send, receive) = mpsc::sync_channel::<Job>(depth);
    let receive = Arc::new(Mutex::new(receive));
    for _ in 0..workers {
        let inbox = Arc::clone(&receive);
        let dir = home.to_path_buf();
        thread::Builder::new().name(name.into()).spawn(move || loop {
            let job = match inbox.lock() {
                Ok(queue) => queue.recv(),
                Err(_) => break,
            };
            let Ok(Job { request, responder }) = job else { break };
            responder.respond(to_http(resolve(&dir, &request)));
        }).map_err(|_| "Windows could not initialize the service connection.")?;
    }
    Ok(send)
}

impl Protocol {
    pub fn new(home: PathBuf) -> Result<Self,String> {
        let work = request_queue(&home, "desktop-proxy", 24, 4)?;
        // The bundled noVNC graph may request more than 24 distinct modules at once.
        let console_assets = request_queue(&home, "console-assets", 64, 2)?;
        Ok(Self { work, console_assets, home })
    }

    pub fn serve(&self, request: Request<Vec<u8>>, responder: RequestAsyncResponder) {
        let uri = request.uri();
        if uri.scheme_str() != Some("svm") || !uri.authority().is_some_and(|a| a.as_str() == "localhost") {
            responder.respond(refused(400, "This desktop address is unavailable.")); return;
        }
        let queue = if uri.path().starts_with("/api/") { Some(&self.work) }
            else if uri.path().starts_with("/console/assets/") { Some(&self.console_assets) }
            else { None };
        if let Some(queue) = queue {
            if let Err(e) = queue.try_send(Job { request, responder }) {
                let job = match e { mpsc::TrySendError::Full(j) | mpsc::TrySendError::Disconnected(j) => j };
                job.responder.respond(refused(503, "The desktop connection is busy. Try again."));
            }
            return;
        }
        if uri.query().is_none() && request.method() == "GET" && request.body().is_empty() {
            let page = match uri.path() {
                "/shell/start" => Some(("text/html; charset=utf-8", START_HTML)),
                "/shell/start.js" => Some(("text/javascript; charset=utf-8", START_JS)),
                _ => None,
            };
            if let Some((mime, content)) = page {
                responder.respond(standard(200, mime, content.as_bytes().to_vec())); return;
            }
        }
        responder.respond(to_http(resolve(&self.home, &request)));
    }
}

fn resolve(home: &std::path::Path, req: &Request<Vec<u8>>) -> PageResponse {
    let target = req.uri().path_and_query().map_or("", |p| p.as_str());
    let content_type = req.headers().get("content-type").and_then(|v| v.to_str().ok());
    svm_app::handle(home, req.method().as_str(), target, content_type, req.body())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_privileges_require_the_exact_embedded_document_even_after_hash_navigation() {
        for url in ["https://svm.localhost/index.html", "https://svm.localhost/index.html#machine/guest", "https://svm.localhost/shell/start"] {
            assert!(trusted_document(&url.parse().unwrap()));
        }
        for url in ["https://svm.app/index.html", "https://svm.localhost.evil/index.html", "https://svm.localhost:443/index.html",
            "http://svm.localhost/index.html", "https://svm.localhost/api/v1/health", "https://svm.localhost/index.html?other", "https://svm.localhost/shell/start.js"] {
            assert!(!trusted_document(&url.parse().unwrap()));
        }
    }
}
