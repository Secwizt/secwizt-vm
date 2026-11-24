#![forbid(unsafe_code)]
#![deny(warnings)]

mod auth;
mod console;
mod websocket;
mod dns_io;
mod events;
mod http;
pub mod machines;
pub mod networks;
mod types;
pub use events::Events;
pub use types::{ApiError, Reply};

use machines::{MachineCompletion, MachineEngine, Machines};
use networks::{Networks, Switches};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions}, io::{self, Write}, net::TcpListener,
    path::{Path, PathBuf}, sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc, Arc},
    thread, time::{Duration, Instant},
};

pub fn data_home() -> Result<PathBuf, ApiError> {
    if let Some(path) = std::env::var_os("SVM_HOME") {
        if !path.is_empty() { return Ok(PathBuf::from(path)); }
    }
    std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("SecwizVM"))
        .ok_or_else(|| ApiError::invalid("Set SVM_HOME to a private data folder on this platform."))
}

/// The usual port. If another program already holds it, the service takes any free port instead;
/// clients always read the real port from `api-port`.
const DEFAULT_PORT: u16 = 47800;

pub fn configured_port() -> Result<u16, ApiError> {
    match std::env::var("SVM_PORT") {
        Ok(value) => value.parse().map_err(|_| ApiError::invalid("SVM_PORT must be a number between 0 and 65535.")),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_PORT),
        Err(_) => Err(ApiError::invalid("SVM_PORT must contain a port number.")),
    }
}

struct Worker {
    machines: Machines,
    networks: Networks,
    events: Events,
    console: Arc<console::Console>,
}
struct BackgroundJob {
    work: thread::JoinHandle<MachineCompletion>,
    reply: Option<mpsc::Sender<Reply>>,
}

impl Worker {
    fn finish_background(&mut self, job: BackgroundJob) {
        self.machines.track_background(None);
        let completed = job.work.join().map_err(|_| ApiError::new(500,"machine_job","The background machine operation ended unexpectedly."));
        let result = completed.and_then(|finish| {
            let networks = self.networks.definitions();
            let result = finish(&mut self.machines, &networks, &mut self.events);
            self.networks.sync_guests(self.machines.inventory())?;
            result
        });
        if let Some(reply) = job.reply { let _ = reply.send(result.unwrap_or_else(Reply::error)); }
    }

    fn dispatch(&mut self, request: http::Request) -> Result<Reply, ApiError> {
        let (path, query) = request.target.split_once('?').map_or((request.target.as_str(), None), |(p,q)| (p,Some(q)));
        let parts: Vec<_> = path.strip_prefix("/v1/").ok_or_else(ApiError::missing)?.split('/').collect();
        if parts.iter().any(|v| v.is_empty() || *v == ".." || *v == ".") { return Err(ApiError::missing()); }
        let method = request.method.as_str();
        if query.is_some() && parts != ["events"] && !(method == "GET" && parts == ["backups"]) { return Err(ApiError::invalid("This resource does not accept a query.")); }
        if method == "GET" && parts.starts_with(&["catalog", "apps"]) {
            return self.machines.app_catalog_route(&parts, &self.networks.definitions());
        }
        if let ("GET", ["machines", id, "apps"]) = (method, parts.as_slice()) {
            return self.machines.app_job(id);
        }
        if parts.first() == Some(&"catalog") {
            return self.machines.catalog_route(method, &parts, &request.body);
        }
        if parts.first() == Some(&"ready") {
            let networks = self.networks.definitions();
            let result = self.machines.ready_route(method, &parts, &request.body, &networks, &mut self.events);
            self.networks.sync_guests(self.machines.inventory())?;
            return result;
        }
        if matches!(parts.as_slice(), ["machines", _, "files", ..]) {
            return self.machines.file_route(method, &parts, &request.body, &self.networks.definitions(), &mut self.events);
        }
        if self.machines.background_busy() {
            let hyperv = self.machines.background_hyperv();
            let checkpoint = self.machines.background_checkpoint();
            let app_operation = self.machines.background_app_operation();
            // Native management reads share the same lock as a long Hyper-V command.
            let wait = match (method, parts.as_slice()) {
                ("GET", ["networks", "bridge-adapters"]) => hyperv,
                ("GET", ["machines", _, "snapshots"]) if checkpoint => false,
                ("GET", ["machines", id, ..]) if parts.len() > 2 => (hyperv && self.machines.uses_hyperv(id)) || (checkpoint && self.machines.background_owns(id)),
                ("GET", _) => false,
                (_, ["transfers", ..]) => hyperv || checkpoint,
                (_, ["networks" | "trash" | "settings", ..] | ["machines"]) => hyperv,
                (_, ["machines", _, "start" | "resume"]) if hyperv => true,
                ("POST", ["machines", id, "stop"]) if !hyperv && !((checkpoint || app_operation) && self.machines.background_owns(id)) => false,
                (_, ["machines", id, ..]) => self.machines.background_owns(id) || (hyperv && self.machines.uses_hyperv(id)),
                _ => false,
            };
            if wait {
                let message = if app_operation { "Wait for the current app operation to finish." }
                    else if hyperv { "Wait for the current Hyper-V operation to finish." }
                    else if checkpoint { "Wait for the checkpoint operation to finish." }
                    else { "Wait for this machine’s guest-agent request to finish." };
                return Err(ApiError::new(409,"machine_operation_in_progress",message));
            }
        }
        match (method, parts.as_slice()) {
            ("GET", ["health"]) => Ok(Reply::json(json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}))),
            ("POST", ["shutdown"]) => {
                if self.machines.background_busy() {
                    let message = if self.machines.background_hyperv() { "Finish the current Hyper-V operation before stopping the service." }
                        else if self.machines.background_checkpoint() { "Finish the checkpoint operation before stopping the service." }
                        else { "Finish the guest-agent request before stopping the service." };
                    return Err(ApiError::new(409,"service_in_use",message));
                }
                if self.machines.converting(){return Err(ApiError::new(409,"service_in_use","Finish or cancel the disk conversion before stopping the service."));}
                if self.machines.file_transfer_busy() || self.machines.catalog_busy() {
                    return Err(ApiError::new(409, "service_in_use", "Finish or cancel the file or installer transfer before stopping the service."));
                }
                if let Some(fields)=request.body.as_object() {
                    if fields.keys().any(|key|key!="ifIdle") || fields.get("ifIdle").is_some_and(|v|!v.is_boolean()) {
                        return Err(ApiError::invalid("Use a boolean ifIdle shutdown condition."));
                    }
                }
                if request.body["ifIdle"] == true && !self.machines.may_close_service(&mut self.events)? {
                    return Err(ApiError::new(409,"service_in_use","Running, paused or unverified machines keep the service open."));
                }
                self.networks.shutdown(&mut self.events)?;
                self.events.record("shutdown", "The service is shutting down.")?;
                Ok(Reply::json(json!({"status":"stopping"})))
            }
            (_, ["networks", ..]) => {
                let attached = parts.get(1).is_some_and(|id| self.machines.uses_network(id));
                self.networks.route(method, &parts, &request.body, attached, &mut self.events)
            }
            (_, ["transfers",..]) => {
                if method == "POST" && (self.machines.file_transfer_busy() || self.machines.catalog_busy()) {
                    return Err(ApiError::new(409, "busy", "Finish or cancel the guest file transfer or installer download first."));
                }
                let was_converting=self.machines.converting();
                let result=self.machines.transfer_route(method,&parts,&request.body,&self.networks.definitions(),&mut self.events);
                if was_converting && !self.machines.converting(){self.networks.sync_guests(self.machines.inventory())?;}
                result
            }
            ("GET" | "POST", ["machines", id, "file-guest-service"]) => self.machines.file_service_route(id, method, &request.body),
            ("POST", ["machines", id, "console-ticket"]) => {
                if !request.body.as_object().is_some_and(|body| body.is_empty()) {
                    return Err(ApiError::invalid("Open the console for the selected machine without extra fields."));
                }
                let endpoint = self.machines.console_endpoint(id)?;
                self.console.issue(id, endpoint)
            }
            (_, ["backups", ..] | ["settings","backup"]) => self.machines.backup_route(method, &parts, query, &request.body, &mut self.events),
            (_, ["settings","qemu"]) => self.machines.qemu_settings(method,&request.body),
            (_, ["machines" | "host" | "guard" | "trash", ..]) => {
                let result = self.machines.route(method, &parts, &request.body, &self.networks.definitions(), &mut self.events);
                if method != "GET" { self.networks.sync_guests(self.machines.inventory())?; }
                result
            }
            _ => Err(ApiError::missing()),
        }
    }
}

type Job = (http::Request, mpsc::Sender<Reply>);
const CONNECTION_WORKERS: usize = 12;
const PRE_AUTH_LIMIT: usize = 6;
const REQUEST_QUEUE: usize = 8;

#[derive(Default)]
struct PreAuth(AtomicUsize);

impl PreAuth {
    fn admit(&self) -> Option<PendingAuth<'_>> {
        if self.0.fetch_add(1, Ordering::Relaxed) >= PRE_AUTH_LIMIT {
            self.0.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(PendingAuth(self))
    }
}

struct PendingAuth<'a>(&'a PreAuth);
impl Drop for PendingAuth<'_> {
    fn drop(&mut self) { self.0.0.fetch_sub(1, Ordering::Relaxed); }
}

#[test]
fn admissions_limit_pending_authentication_and_reuse_a_released_slot() {
    let gate = PreAuth::default();
    let mut admitted: Vec<_> = (0..PRE_AUTH_LIMIT).map(|_| gate.admit().unwrap()).collect();
    assert!(gate.admit().is_none());
    drop(admitted.pop());
    assert!(gate.admit().is_some());
}

fn read_events(reader: &events::EventReader, query: &str) -> Result<Reply, ApiError> {
    let cursor = if query.is_empty() { 0 } else {
        query.strip_prefix("since=").filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| ApiError::invalid("Use a nonnegative event number for since."))?
    };
    Ok(Reply::json(json!(reader.since(cursor)?)))
}

fn receive_clients(listener: &TcpListener, port: u16, token: &str, events: &events::EventReader, refresh_requested: &AtomicBool, send: mpsc::SyncSender<Job>, stop: &AtomicBool, console: &Arc<console::Console>, pre_auth: &PreAuth) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, peer)) if peer.ip().is_loopback() => {
                let Some(permit) = pre_auth.admit() else {
                    drop(stream);
                    thread::sleep(Duration::from_millis(10));
                    continue;
                };
                // Windows: a socket accepted from a non-blocking listener is itself non-blocking. http::read and
                // http::send assume a blocking socket with timeouts; without this line a read that arrives a moment
                // early returns WouldBlock, the request is answered 408 or not at all, and the client sees a closed
                // connection (found on the real build host: 11 of 18 test runs failed before this line).
                if stream.set_nonblocking(false).is_err() { continue; }
                let mut pending = Some(permit);
                let incoming = http::read(&mut stream, port, token, || drop(pending.take()));
                let reply = match incoming {
                    Err(error) => Reply::error(error),
                    Ok(http::Incoming::Console(upgrade)) => {
                        console.upgrade(stream, upgrade);
                        continue;
                    }
                    Ok(http::Incoming::Api(request)) => {
                        if let Some(reply) = console::asset(&request) {
                            let _ = http::send(&mut stream, &reply);
                            continue;
                        }
                        let (path, query) = request.target.split_once('?').unwrap_or((&request.target, ""));
                        if request.method == "GET" && path == "/v1/events" {
                            // A watching client also requests the shorter inventory refresh interval.
                            refresh_requested.store(true, Ordering::Release);
                            let response = read_events(events, query).unwrap_or_else(Reply::error);
                            let _ = http::send(&mut stream, &response);
                            continue;
                        }
                        let (tx, rx) = mpsc::channel();
                        match send.try_send((request, tx)) {
                            Ok(()) => match rx.recv() { Ok(reply) => reply, Err(_) => break },
                            Err(mpsc::TrySendError::Full(_)) => Reply::error(ApiError::new(503, "busy", "The request queue is full. Try again shortly.")),
                            Err(mpsc::TrySendError::Disconnected(_)) => break,
                        }
                    }
                };
                drop(pending);
                let _ = http::send(&mut stream, &reply);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            _ => thread::sleep(Duration::from_millis(20)),
        }
    }
}

pub struct Service {
    home: PathBuf,
    listener: TcpListener,
    port: u16,
    token: String,
    worker: Worker,
    _owner: File,
}
impl Service {
    pub fn open(home: &Path, port: u16, engine: Box<dyn MachineEngine>, switches: Box<dyn Switches>) -> Result<Self, ApiError> {
        let supervisor=std::env::current_exe().map_err(ApiError::storage)?;
        Self::open_with_supervisor(home,port,engine,switches,&supervisor)
    }
    pub fn open_with_supervisor(home:&Path,port:u16,engine:Box<dyn MachineEngine>,switches:Box<dyn Switches>,supervisor:&Path)->Result<Self,ApiError> {
        fs::create_dir_all(home).map_err(ApiError::storage)?;
        let home = fs::canonicalize(home).map_err(ApiError::storage)?;
        let owner = OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .open(home.join("service.lock")).map_err(ApiError::storage)?;
        owner.try_lock().map_err(|_| ApiError::new(409, "already_running", "Another service owns this data folder, or the folder cannot be locked."))?;
        match fs::remove_file(home.join("api-port")) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(ApiError::storage(e)),
        }
        let host = svm_core::local_auth::SERVICE_HOST;
        let listener = TcpListener::bind((host, port))
            .or_else(|error| if port == DEFAULT_PORT { TcpListener::bind((host, 0)) } else { Err(error) })
            .map_err(|_| ApiError::new(503, "port_unavailable", "The service could not bind its loopback port. Check whether it is already in use."))?;
        listener.set_nonblocking(true).map_err(ApiError::storage)?;
        let port = listener.local_addr().map_err(ApiError::storage)?.port();
        let token = auth::token(&home)?;
        let mut events = Events::open(&home)?;
        let mut networks = Networks::open(&home, switches, &mut events)?;
        let machines = Machines::open_with_supervisor(&home,engine,&networks.definitions(),&mut events,supervisor)?;
        networks.sync_guests(machines.inventory())?;
        events.record("ready", "The service loaded its library and networks.")?;
        // Publish only after reconciliation, socket binding and authentication are ready.
        let next = home.join("api-port.pending");
        let mut file = File::create(&next).map_err(ApiError::storage)?;
        writeln!(file, "{port}").and_then(|()| file.sync_all()).map_err(ApiError::storage)?;
        drop(file);
        fs::rename(next, home.join("api-port")).map_err(ApiError::storage)?;
        Ok(Self { _owner: owner, home, listener, token, port, worker: Worker { machines, networks, events, console: Arc::new(console::Console::new(port)) } })
    }
    pub fn port(&self) -> u16 { self.port }
    pub fn run(mut self, stop: Arc<AtomicBool>) -> Result<(), ApiError> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(REQUEST_QUEUE);
        let event_reader = self.worker.events.reader();
        let refresh_requested = AtomicBool::new(false);
        let pre_auth = PreAuth::default();
        let worker = &mut self.worker;
        let console = &worker.console.clone();
        let outcome = thread::scope(|scope| {
            for _ in 0..CONNECTION_WORKERS {
                let (listener, token, port, sender, flag) = (&self.listener, &self.token, self.port, sender.clone(), &*stop);
                let events = &event_reader;
                let refresh = &refresh_requested;
                let pre_auth = &pre_auth;
                scope.spawn(move || receive_clients(listener, port, token, events, refresh, sender, flag, console, pre_auth));
            }
            drop(sender);
            let mut last_tick = Instant::now();
            let mut by_api = false;
            let mut background: Option<BackgroundJob> = None;
            let result = loop {
                if background.as_ref().is_some_and(|job| job.work.is_finished()) {
                    if let Some(job) = background.take() { worker.finish_background(job); }
                }
                if stop.load(Ordering::Acquire) { break Ok(()); }
                match receiver.recv_timeout(Duration::from_millis(50)) {
                    Ok((request, return_to)) => {
                        match worker.machines.prepare_background(&request, &worker.networks.definitions(), &mut worker.events) {
                            Ok(Some(mut task)) => {
                                worker.machines.track_background(Some(&task));
                                let accepted = task.accepted.take();
                                background = Some(BackgroundJob {
                                    work: thread::spawn(move || task.run()),
                                    reply: if let Some(accepted) = accepted {
                                        let _ = return_to.send(accepted);
                                        None
                                    } else { Some(return_to) },
                                });
                            }
                            Ok(None) => {
                                let shutdown = request.method == "POST" && request.target == "/v1/shutdown";
                                let reply = worker.dispatch(request);
                                by_api = shutdown && reply.is_ok();
                                let _ = return_to.send(reply.unwrap_or_else(Reply::error));
                                if by_api { break Ok(()); }
                            }
                            Err(error) => { let _ = return_to.send(Reply::error(error)); }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break Ok(()),
                }
                if last_tick.elapsed() >= Duration::from_millis(50) {
                    if let Err(error) = worker.networks.tick(&mut worker.events) { break Err(error); }
                    match worker.machines.finish_backup(&worker.networks.definitions(), &mut worker.events) {
                        Ok(true) => if let Err(error) = worker.networks.sync_guests(worker.machines.inventory()) { break Err(error); },
                        Ok(false) => {}
                        Err(error) => break Err(error),
                    }
                    let was_converting=worker.machines.converting();
                    // Ready images: finish a prepared image and start Get requests whose download is verified.
                    if let Err(error) = worker.machines.finish_ready(&worker.networks.definitions(), &mut worker.events) {
                        break Err(error);
                    }
                    if was_converting {
                        if let Err(error) = worker.machines.finish_transfer(&worker.networks.definitions(), &mut worker.events) {
                            break Err(error);
                        }
                        if !worker.machines.converting() {
                            if let Err(error) = worker.networks.sync_guests(worker.machines.inventory()) {
                                break Err(error);
                            }
                        }
                    }
                    let interested = refresh_requested.swap(false, Ordering::AcqRel);
                    if let Err(error) = worker.machines.tick(&mut worker.events, interested) { break Err(error); }
                    last_tick = Instant::now();
                }
            };
            stop.store(true, Ordering::Release);
            console.close();
            drop(receiver);
            worker.machines.stop_file_transfers();
            worker.machines.stop_catalog_downloads();
            if let Some(job) = background.take() { worker.finish_background(job); }
            if !by_api {
                worker.networks.shutdown(&mut worker.events)?;
                worker.events.record("shutdown", "The service closed its DHCP listeners and left guest power unchanged.")?;
            }
            result
        });
        match fs::remove_file(self.home.join("api-port")) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(ApiError::storage(e)),
            _ => {}
        }
        outcome
    }
}
