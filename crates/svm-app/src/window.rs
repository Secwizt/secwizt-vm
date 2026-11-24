use super::{window_native as native, window_protocol::{self, Protocol}, window_service::Service};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions}, io::{self, Write}, path::{Component, Path, PathBuf, Prefix},
    sync::Arc, thread, time::{Duration, Instant},
};
use tao::{
    dpi::{LogicalSize, PhysicalPosition, PhysicalSize}, event::{ElementState, Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy}, keyboard::Key,
    platform::windows::{IconExtWindows, WindowBuilderExtWindows, WindowExtWindows}, window::{Icon, Window, WindowBuilder},
};
use wry::{NewWindowResponse, PermissionResponse, WebContext, WebView, WebViewBuilder, WebViewBuilderExtWindows};

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct Preferences {
    width: u32, height: u32, x: Option<i32>, y: Option<i32>, maximized: bool, skip_close_notice: bool,
    layout_checked: bool, interface_size: Option<u16>,
}

impl Preferences {
    fn load(home: &Path) -> Self {
        fs::read(home.join("window.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }
    fn size_percent(&self) -> u16 {
        self.interface_size.filter(|v| matches!(*v, 85 | 100 | 115 | 130)).unwrap_or(100)
    }
    fn set_interface_size(&mut self, view: &WebView, home: &Path, value: Option<&str>) -> Result<Value,String> {
        let size = value.and_then(|v| v.parse::<u16>().ok())
            .filter(|v| matches!(*v, 85 | 100 | 115 | 130)).ok_or("Choose one of the available interface sizes.")?;
        let old = self.size_percent();
        view.zoom(f64::from(size) / 100.0).map_err(|_| "The interface size could not be changed.")?;
        self.interface_size = Some(size);
        if let Err(reason) = self.save(home) {
            if view.zoom(f64::from(old) / 100.0).is_ok() { self.interface_size = Some(old); }
            return Err(reason);
        }
        Ok(json!(size))
    }
    fn geometry(&mut self, window: &Window) {
        if window.is_minimized() { return; }
        self.maximized = window.is_maximized();
        if self.maximized { return; }
        let size = window.inner_size();
        if size.width >= 320 && size.height >= 200 { self.width = size.width; self.height = size.height; }
        if let Ok(pos) = window.outer_position() { self.x = Some(pos.x); self.y = Some(pos.y); }
    }
    fn save(&self, home: &Path) -> Result<(), String> {
        let data = serde_json::to_vec(self).map_err(|_| "Could not encode window settings.")?;
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let temp = home.join(format!("window-{}-{stamp}.pending", std::process::id()));
        let mut file = File::create_new(&temp).map_err(|_| "Could not create the window settings file.")?;
        let result = file.write_all(&data).and_then(|()| file.sync_all());
        drop(file);
        let result = result.and_then(|()| fs::rename(&temp, home.join("window.json")));
        if result.is_err() { let _ = fs::remove_file(temp); }
        result.map_err(|_| "Could not save the window settings.".to_owned())
    }
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct NativeRequest {
    request_id: u64, action: String, id: Option<String>, text: Option<String>,
}

enum Message {
    Request(NativeRequest),
    Started(Option<u64>, Result<(),String>),
    Action(u64, Result<Value,String>),
    Closed(Result<String,String>),
    FinishedClosing(Result<(),String>),
}

fn dispatch(view: &WebView, name: &str, detail: &Value) {
    // The event names are constants and every value is serialized as a JSON literal.
    let js = format!("window.dispatchEvent(new CustomEvent('{name}',{{detail:{detail}}}));");
    let _ = view.evaluate_script(&js);
}
fn respond(view: &WebView, id: u64, result: Result<Value,String>) {
    let data = match result {
        Ok(value) => json!({"requestId":id,"ok":true,"value":value}),
        Err(error) => json!({"requestId":id,"ok":false,"error":error}),
    };
    dispatch(view, "svm-native-result", &data);
}

fn finish_close(service: Arc<Service>, events: EventLoopProxy<Message>) {
    thread::spawn(move || {let _=events.send_event(Message::FinishedClosing(service.close_if_idle()));});
}

fn start(service: Arc<Service>, events: EventLoopProxy<Message>, id: Option<u64>) {
    thread::spawn(move || { let _ = events.send_event(Message::Started(id,service.start())); });
}

// A second process never constructs a WebView or starts the service.
fn instance(home: &Path) -> Result<Option<File>,String> {
    fs::create_dir_all(home).map_err(|_| "Could not create the application data folder.")?;
    let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(home.join("window.lock")).map_err(|_| "Could not open the application lock.")?;
    match lock.try_lock() {
        Ok(()) => Ok(Some(lock)),
        Err(std::fs::TryLockError::WouldBlock) => {
            // Create a signal only. An already pending request also wakes the first window.
            match File::create_new(home.join("window.focus")) {
                Ok(_) => {},
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {},
                Err(_) => return Err("The existing window could not be notified.".into()),
            }
            Ok(None)
        }
        Err(_) => Err("The application data folder does not support instance locking.".into()),
    }
}

fn local_drive_path(path: &Path) -> bool {
    path.is_absolute() && matches!(path.components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
}

fn guest_download_name(name: &str) -> Option<&str> {
    if name.is_empty() || name.len() > 255 || name.ends_with([' ', '.'])
        || name.chars().any(|c| c.is_control() || r#"\/:*?"<>|"#.contains(c)) {
        return None;
    }
    let stem = name.split('.').next()?.trim_end().to_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|digit| matches!(digit, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")) {
        return None;
    }
    Some(name)
}

fn action(req: NativeRequest, service: &Service, owner: isize) -> Result<Value,String> {
    match req.action.as_str() {
        "pickGuestUpload" | "pickGuestDownload" => {
            let upload = req.action == "pickGuestUpload";
            let proposed = req.text.as_deref().and_then(guest_download_name).unwrap_or("");
            let kind = if upload && req.text.as_deref() == Some("backup") { "backup-file" } else if upload { "guest-upload" } else { "guest-download" };
            let name = native::dialog(kind, owner, if upload { "" } else { proposed })?;
            if name.is_empty() { return Ok(Value::Null); }
            let path = PathBuf::from(name);
            if !local_drive_path(&path) {
                return Err("Choose a file on a local drive.".into());
            }
            Ok(json!(path))
        }
        "pickDisk" | "pickExportFolder" => {
            let directory=req.action=="pickExportFolder";
            let kind=if directory && req.text.as_deref()==Some("backup") {"backup-folder"} else if directory {"folder"} else {"disk"};
            let chosen=native::dialog(kind,owner,"")?;
            if chosen.is_empty() {return Ok(Value::Null);}
            let chosen=PathBuf::from(chosen);
            if !chosen.is_absolute() || (directory && !chosen.is_dir()) || (!directory && !chosen.is_file()) {
                return Err("Choose an existing disk file or export folder.".into());
            }
            Ok(json!(chosen))
        }
        "pickIso" | "pickQemu" => {
            let qemu = req.action == "pickQemu";
            let directory = req.text.as_deref().filter(|s| s.len()>=3 && s.len()<4096 &&
                s.as_bytes()[0].is_ascii_alphabetic() && s.as_bytes()[1]==b':' && matches!(s.as_bytes()[2], b'\\'|b'/'))
                .filter(|s| !s.contains('\0') && Path::new(s).is_dir()).unwrap_or("");
            let path = native::dialog(if qemu { "qemu" } else { "iso" }, owner, directory)?;
            if path.is_empty() { return Ok(Value::Null); }
            let path = PathBuf::from(path);
            if qemu {
                if !local_drive_path(&path) || !path.file_name().is_some_and(|name| name.eq_ignore_ascii_case("qemu-system-x86_64.exe")) {
                    return Err("Choose the local qemu-system-x86_64.exe executable.".into());
                }
            } else if !path.is_absolute() || !path.extension().is_some_and(|e| e.eq_ignore_ascii_case("iso")) {
                return Err("Choose an ISO installer image.".into());
            }
            Ok(json!(path))
        }
        "openFolder" => { native::open_folder(service.home())?; Ok(Value::Null) }
        "openTrash" => { native::open_trash(service.home())?; Ok(Value::Null) }
        "openCaptureInWireshark" | "showCaptureFile" => {
            use crate::window_capture::{self, Viewer};
            let (Some(machine), Some(capture)) = (req.id.as_deref(), req.text.as_deref()) else {
                return Err("Choose a packet capture from its machine’s capture list.".into());
            };
            let path = service.capture_path(machine, capture)?;
            let viewer = if req.action == "openCaptureInWireshark" { Viewer::Wireshark } else { Viewer::Explorer };
            window_capture::open(service.home(), machine, capture, &path, viewer)?;
            Ok(Value::Null)
        }
        "openConsole" => {
            service.open_console(req.id.as_deref().ok_or("Choose a machine from the library.")?,
                req.text.as_deref() == Some("beforeStart"))?;
            Ok(Value::Null)
        }
        "copyConsoleText" => {
            let id = req.id.as_deref().ok_or("Choose an open QEMU console.")?;
            service.verify_clipboard(id)?;
            native::copy_console_text(req.text.ok_or("Choose the text to copy.")?)?;
            Ok(Value::Null)
        }
        "copyText" => {
            let text = req.text.as_deref().filter(|s| !s.is_empty() && s.len() <= 4096 && !s.contains('\0'))
                .ok_or("Choose a short command to copy.")?;
            native::dialog("copy", owner, text)?;
            Ok(Value::Null)
        }
        "appMenu" => {
            // A page can show the menu. Only the separate native menu and confirmation produce this result.
            if native::dialog("menu", owner, "")? == "stop" { service.stop_from_menu()?; }
            Ok(Value::Null)
        }
        _ => Err("This action is unavailable.".into()),
    }
}

pub fn run() -> Result<(),String> {
    let home = svm::client::data_home().map_err(|e| e.to_string())?;
    let Some(lock) = instance(&home)? else { return Ok(()) };
    let home = fs::canonicalize(home).map_err(|_| "Could not locate the data folder.")?;
    let mut prefs = Preferences::load(&home);
    let events = EventLoopBuilder::<Message>::with_user_event().build();
    let mut builder = WindowBuilder::new().with_title("Secwizt Virtual Machine")
        .with_inner_size(LogicalSize::new(1366,800)).with_min_inner_size(LogicalSize::new(640,420));
    // Resource 1 is the app icon linked into the exe by build.rs (assets/svm.rc).
    if let Ok(icon) = Icon::from_resource(1, None) { builder = builder.with_window_icon(Some(icon)); }
    if let Ok(icon) = Icon::from_resource(1, None) { builder = builder.with_taskbar_icon(Some(icon)); }
    if (320..=32768).contains(&prefs.width) && (200..=32768).contains(&prefs.height) {
        builder = builder.with_inner_size(PhysicalSize::new(prefs.width,prefs.height));
    }
    if let (Some(x),Some(y)) = (prefs.x,prefs.y) {
        let visible = events.available_monitors().any(|m| {
            let p=m.position(); let size=m.size();
            let inside = |v:i32, start:i32, extent:u32| i64::from(v) >= i64::from(start)-8 && i64::from(v)+40 < i64::from(start)+i64::from(extent);
            inside(x,p.x,size.width) && inside(y,p.y,size.height)
        });
        if visible { builder=builder.with_position(PhysicalPosition::new(x,y)); }
    }
    let window = builder.with_maximized(prefs.maximized).build(&events)
        .map_err(|_| "Windows could not create the desktop window.")?;
    let owner = window.hwnd();
    let proxy = events.create_proxy();
    let inbox = proxy.clone();
    let protocol = Protocol::new(home.clone())?;
    let mut context = WebContext::new(Some(home.join("webview")));
    let view = WebViewBuilder::new_with_web_context(&mut context)
        .with_https_scheme(true)
        .with_asynchronous_custom_protocol("svm".into(), move |_,req,res| protocol.serve(req,res))
        .with_navigation_handler(|url| {
            let page = url.split('#').next().unwrap_or("");
            page.parse().is_ok_and(|uri| window_protocol::trusted_document(&uri))
        })
        .with_new_window_req_handler(|_,_| NewWindowResponse::Deny)
        .with_permission_handler(|_| PermissionResponse::Deny)
        .with_download_started_handler(|_,_| false).with_drag_drop_handler(|_| true)
        .with_clipboard(false).with_general_autofill_enabled(false).with_browser_extensions_enabled(false)
        .with_browser_accelerator_keys(false).with_default_context_menus(false).with_devtools(false)
        .with_back_forward_navigation_gestures(false)
        .with_additional_browser_args("--disable-background-networking --disable-component-update --disable-sync")
        .with_ipc_handler(move |req| {
            const IPC_LIMIT: usize = 16384;
            const CLIPBOARD_IPC_LIMIT: usize = 6 * native::CLIPBOARD_TEXT_LIMIT + 1024;
            let bytes = req.body().len();
            if !window_protocol::trusted_document(req.uri()) || bytes > CLIPBOARD_IPC_LIMIT { return; }
            if let Ok(parsed) = serde_json::from_str::<NativeRequest>(req.body()) {
                if bytes > IPC_LIMIT && parsed.action != "copyConsoleText" { return; }
                if parsed.request_id <= (1u64 << 53)-1 { let _ = inbox.send_event(Message::Request(parsed)); }
            }
        })
        .with_url(window_protocol::START_PAGE).build(&window)
        .map_err(|_| "The desktop window could not open its system WebView2 runtime. Check the runtime and data-folder permissions.")?;
    let mut apply_saved_size = true;
    let service = Arc::new(Service::new(home.clone()));
    let mut starting = true;
    let mut closing = false;
    let mut startup_error: Option<String> = None;
    let mut in_main = false;
    let mut modal = false;
    let mut last_focus_check = Instant::now();
    start(Arc::clone(&service),proxy.clone(),None);

    events.run(move |event,_,flow| {
        let _keep_instance = &lock;
        let _keep_profile = &context;
        *flow = ControlFlow::WaitUntil(Instant::now()+Duration::from_millis(350));
        match event {
            Event::UserEvent(Message::Started(id,result)) => {
                starting = false;
                if closing {finish_close(Arc::clone(&service),proxy.clone()); return;}
                startup_error = result.as_ref().err().cloned();
                if let Some(id) = id { respond(&view,id,result.as_ref().map(|_|Value::Null).map_err(Clone::clone)); }
                match result {
                    Ok(()) if !in_main => {
                        if view.load_url(window_protocol::HOME_PAGE).is_ok() { in_main=true; }
                        else {
                            let reason = "The interface could not be loaded. Choose Start it to retry.";
                            startup_error=Some(reason.into()); dispatch(&view,"svm-startup-error",&json!(reason));
                        }
                    }
                    Err(reason) if !in_main => dispatch(&view,"svm-startup-error",&json!(reason)),
                    _ => {}
                }
            }
            Event::UserEvent(Message::Request(request)) => {
                if closing {return;}
                let id=request.request_id;
                match request.action.as_str() {
                    "appInfo" => {
                        if let Some(width) = request.text.as_deref().and_then(|v| v.parse::<u32>().ok()).filter(|v| *v > 0) {
                            if !prefs.layout_checked {
                                prefs.layout_checked = true;
                                if width < 1000 { window.set_maximized(true); }
                            }
                            if apply_saved_size {
                                apply_saved_size = false;
                                let size = prefs.size_percent();
                                if size != 100 && view.zoom(f64::from(size) / 100.0).is_err() {
                                    prefs.interface_size = Some(100);
                                    native::show_error("The saved interface size could not be applied. The window will use the system size.");
                                }
                            }
                        }
                        respond(&view,id,Ok(json!({"dataFolder":service.home(),"version":env!("CARGO_PKG_VERSION"),
                            "startupError":startup_error,"interfaceSize":prefs.size_percent()})));
                    }
                    "setInterfaceSize" => respond(&view,id,prefs.set_interface_size(&view,&home,request.text.as_deref())),
                    "startService" if !starting => {
                        starting=true; start(Arc::clone(&service),proxy.clone(),Some(id));
                    }
                    "startService" => respond(&view,id,Err("The service is already starting.".into())),
                    "captureViewerAvailable" if request.id.is_none() && request.text.is_none() => {
                        respond(&view, id, Ok(json!(crate::window_capture::available())));
                    }
                    "appMenu" if modal => respond(&view,id,Ok(Value::Null)),
                    "appMenu" | "pickIso" | "pickQemu" | "pickDisk" | "pickExportFolder" | "pickGuestUpload" | "pickGuestDownload" | "openConsole" | "openFolder" | "openTrash" | "copyText" | "copyConsoleText"
                    | "openCaptureInWireshark" | "showCaptureFile" if !modal => {
                        modal=true; let s=Arc::clone(&service); let tx=proxy.clone();
                        thread::spawn(move || { let _=tx.send_event(Message::Action(id,action(request,&s,owner))); });
                    }
                    _ => respond(&view,id,Err("This desktop action is unavailable or another dialog is open.".into())),
                }
            }
            Event::UserEvent(Message::Action(id,result)) => {
                modal=false;
                if id==0 { if let Err(reason)=result {native::show_error(&reason);} } else { respond(&view,id,result); }
            }
            Event::WindowEvent { event: WindowEvent::KeyboardInput { event, .. }, .. }
                if event.logical_key == Key::F10 && event.state==ElementState::Pressed && !event.repeat && !modal => {
                let request=NativeRequest {request_id:0,action:"appMenu".into(),id:None,text:None};
                let _=proxy.send_event(Message::Request(request));
            }
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } if !modal => {
                modal=true;
                if prefs.skip_close_notice {
                    let _=proxy.send_event(Message::Closed(Ok("close".into())));
                } else {
                    modal=true; let tx=proxy.clone();
                    thread::spawn(move || { let _=tx.send_event(Message::Closed(native::dialog("close",owner,""))); });
                }
            }
            Event::UserEvent(Message::Closed(result)) => {
                modal=false;
                match result {
                    Ok(choice) if matches!(choice.as_str(),"close"|"always") => {
                        if choice=="always" { prefs.skip_close_notice=true; }
                        prefs.geometry(&window);
                        if let Err(e)=prefs.save(&home) { native::show_error(&e); }
                        closing=true;
                        modal=true;
                        if !starting {finish_close(Arc::clone(&service),proxy.clone());}
                    }
                    Err(e) => { native::show_error(&e); },
                    _ => {},
                }
            }
            Event::UserEvent(Message::FinishedClosing(result)) => {
                if let Err(reason)=result {native::show_error(&reason);}
                *flow=ControlFlow::Exit;
            }
            Event::WindowEvent { event:WindowEvent::Resized(_) | WindowEvent::Moved(_), .. } => prefs.geometry(&window),
            Event::MainEventsCleared if last_focus_check.elapsed()>=Duration::from_millis(250) => {
                last_focus_check=Instant::now();
                if fs::remove_file(home.join("window.focus")).is_ok() {
                    window.set_minimized(false); window.set_visible(true); window.set_focus(); let _ = view.focus();
                }
            }
            _ => {},
        }
    });
}
