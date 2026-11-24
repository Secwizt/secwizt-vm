//! Runs the shipped console in a real WebView2 against a disposable fixture service.
#![forbid(unsafe_code)]

#[cfg(windows)]
#[allow(dead_code)]
#[path = "../src/window_protocol.rs"]
mod window_protocol;

#[cfg(not(windows))]
fn main() {
    eprintln!("The native console fixture needs Windows WebView2.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use serde_json::Value;
    use std::{env, fs, path::PathBuf, time::{Duration, Instant}};
    use tao::{
        dpi::PhysicalSize, event::Event, event_loop::{ControlFlow, EventLoopBuilder},
        platform::{run_return::EventLoopExtRunReturn, windows::EventLoopBuilderExtWindows},
        window::WindowBuilder,
    };
    use window_protocol::{trusted_document, Protocol};
    use wry::{NewWindowResponse, PermissionResponse, WebContext, WebViewBuilder, WebViewBuilderExtWindows};

    let home = PathBuf::from(env::var_os("SVM_3E_FIXTURE_HOME").ok_or("Missing isolated fixture home")?);
    let id = env::var("SVM_3E_FIXTURE_ID")?;
    let receipt = PathBuf::from(env::var_os("SVM_3E_FIXTURE_RECEIPT").ok_or("Missing console test receipt path")?);
    let clipboard_enabled = match env::var("SVM_3F_CLIPBOARD_MODE").ok().as_deref() {
        None => None,
        Some("on") => Some(true),
        Some("off") => Some(false),
        _ => return Err("Invalid clipboard fixture mode.".into()),
    };
    let prefix = if clipboard_enabled.is_some() { "a3f-" } else { "a3e-" };
    if !id.starts_with(prefix) || id.len() > 72 || !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !home.canonicalize()?.starts_with(env::temp_dir().canonicalize()?) {
        return Err("Use an owned QEMU console fixture in the temporary directory.".into());
    }
    let mut events = EventLoopBuilder::<Value>::with_user_event().with_any_thread(true).build();
    let window = WindowBuilder::new().with_title("Disposable console verification")
        .with_inner_size(PhysicalSize::new(1100, 900)).with_focused(false).build(&events)?;
    let receiver = events.create_proxy();
    let protocol = Protocol::new(home.clone())?;
    let mut context = WebContext::new(Some(home.join("console-proof-webview")));
    let script = match clipboard_enabled {
        Some(enabled) => include_str!("embedded_clipboard_webview.js").replace("__CLIPBOARD_ENABLED__", if enabled { "true" } else { "false" }),
        None => include_str!("embedded_console_webview.js").to_owned(),
    }.replace("__FIXTURE_ID__", &serde_json::to_string(&id)?);
    let _view = WebViewBuilder::new_with_web_context(&mut context)
        .with_focused(false)
        .with_https_scheme(true)
        .with_asynchronous_custom_protocol("svm".into(), move |_, request, response| protocol.serve(request, response))
        .with_navigation_handler(|url| url.split('#').next().is_some_and(|page| page.parse().is_ok_and(|uri| trusted_document(&uri))))
        .with_permission_handler(|_| PermissionResponse::Deny)
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .with_devtools(false)
        .with_additional_browser_args("--disable-background-networking --disable-component-update --disable-sync")
        .with_initialization_script(&script)
        .with_ipc_handler(move |request| {
            if trusted_document(request.uri()) && request.body().len() < 4096 {
                if let Ok(value) = serde_json::from_str::<Value>(request.body()) {
                    if value.get("consoleFixture").is_some() { let _ = receiver.send_event(value); }
                }
            }
        })
        .with_url("svm://localhost/index.html")
        .build(&window)?;
    let deadline = Instant::now() + Duration::from_secs(35);
    let mut outcome = None;
    let mut readiness = Ok(());
    events.run_return(|event, _, flow| {
        *flow = ControlFlow::WaitUntil(deadline);
        if let Event::UserEvent(value) = event {
            match value["consoleFixture"].as_str() {
                Some("resize") => { window.set_inner_size(PhysicalSize::new(850, 690)); }
                Some("clipboard-ready") if clipboard_enabled.is_some() => {
                    readiness = fs::write(receipt.with_extension("ready"), value.to_string());
                    if readiness.is_err() { *flow = ControlFlow::Exit; }
                }
                Some("done" | "failed") => {
                    outcome = Some(value);
                    *flow = ControlFlow::Exit;
                }
                _ => {}
            }
        }
        if Instant::now() >= deadline { *flow = ControlFlow::Exit; }
    });
    readiness?;
    let result = outcome.ok_or("No console proof arrived from WebView2.")?;
    fs::write(receipt, serde_json::to_vec_pretty(&result)?)?;
    if result["consoleFixture"] != "done" {
        return Err("The console fixture did not complete. See the local receipt.".into());
    }
    Ok(())
}
