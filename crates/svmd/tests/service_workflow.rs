#![forbid(unsafe_code)]
#![deny(warnings)]

use serde_json::{json, Value};
use std::{
    fs, path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}},
    thread::{self, JoinHandle}, time::{SystemTime, UNIX_EPOCH},
};
use svm::client::{Client, Response};
use svm_core::{engine::{EngineDriver, FakeEngine}, library::Library, model::{Vm, VmState}};
use svmd::{networks::FakeSwitches, Service};

#[path = "support/vhdx.rs"]
mod vhdx;

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        static NUMBER: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("svmd-http-{}-{stamp}-{}", std::process::id(), NUMBER.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

struct Server {
    client: Client,
    flag: Arc<AtomicBool>,
    runner: Option<JoinHandle<Result<(), svmd::ApiError>>>,
}
impl Server {
    fn start(folder: &Path, engine: FakeEngine) -> Self {
        Self::using_engine(folder, Box::new(engine))
    }

    fn using_engine(folder: &Path, engine: Box<dyn svmd::machines::MachineEngine>) -> Self {
        let service = Service::open(folder, 0, engine, Box::new(FakeSwitches::default())).unwrap();
        let client = Client::load(folder, None).unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&flag);
        let runner = thread::spawn(move || service.run(shutdown));
        Self { client, flag, runner: Some(runner) }
    }

    fn raw(&self, method: &str, path: &str, body: Value) -> Response {
        self.client.request(method, path, if body.is_null() { None } else { Some(&body) }).unwrap()
    }

    fn json(&self, method: &str, path: &str, body: Value) -> Value {
        let result = self.raw(method, path, body);
        assert!((200..300).contains(&result.status), "{method} {path} returned {}: {}", result.status, String::from_utf8_lossy(&result.body));
        if result.body.is_empty() { Value::Null } else { serde_json::from_slice(&result.body).unwrap() }
    }

    fn refused(&self, method: &str, path: &str, body: Value, status: u16) -> String {
        let result = self.raw(method, path, body);
        assert_eq!(result.status, status, "{method} {path}: {}", String::from_utf8_lossy(&result.body));
        let response: Value = serde_json::from_slice(&result.body).unwrap();
        assert!(response["error"]["code"].as_str().is_some_and(|s| !s.is_empty()));
        response["error"]["message"].as_str().unwrap().to_owned()
    }

    fn stop(mut self) {
        self.json("POST", "/v1/shutdown", json!({}));
        self.runner.take().unwrap().join().unwrap().unwrap();
    }

    fn machine(&self, id: &str, network: &str, cpu: u16, ram: u32) -> Value {
        self.json("POST", "/v1/machines", json!({
            "id":id,"name":id,"os":"Synthetic guest","net":network,"vcpu":cpu,"ramGb":ram
        }))
    }

    fn network(&self) -> Value {
        self.json("POST", "/v1/networks", json!({"id":"lab","name":"Lab","mode":"Routed"}))
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = self.runner.take() {
            self.flag.store(true, Ordering::Release);
            let _ = task.join();
        }
    }
}

#[test]
fn guest_power_and_keyboard_routes_follow_observed_capabilities() {
    let home=Home::new();
    let server=Server::start(&home.0,FakeEngine::default());
    server.machine("guest","nat",1,1);
    let path="/v1/machines/guest";
    let caps=server.json("GET",&format!("{path}/capabilities"),Value::Null);
    for name in ["Shutdown","Restart","SendKeys"] {
        assert_eq!(caps[name]["available"],false);
        assert!(caps[name]["reason"].is_string());
    }
    server.refused("POST",&format!("{path}/keys"),json!({"keys":["Ctrl+Alt+Del"]}),409);
    server.json("POST",&format!("{path}/start"),json!({}));
    let caps=server.json("GET",&format!("{path}/capabilities"),Value::Null);
    for name in ["Shutdown","Restart","SendKeys"] { assert_eq!(caps[name]["available"],true); }
    let keys=format!("{path}/keys");
    assert_eq!(server.json("POST",&keys,json!({"text":"ab 12"}))["sent"],5);
    assert_eq!(server.json("POST",&keys,json!({"keys":["Tab","Enter","Ctrl+Alt+Del"]}))["sent"],3);
    let reported=server.json("POST",&keys,json!({"text":"Aa/?-", "appendEnter":true}));
    assert_eq!(reported,json!({"sent":6,"retried":false,"layout":"us","message":"6 of 6 keys sent to the machine."}));
    assert_eq!(server.json("POST",&keys,json!({"text":"a".repeat(63),"appendEnter":true}))["sent"],64);
    for (text,expected) in [("\n","U+000A"),("ä","U+00E4"),("🦀","U+1F980")] {
        assert!(server.refused("POST",&keys,json!({"text":text}),400).contains(expected));
    }
    for invalid in [json!({"text":"a".repeat(65)}),json!({"text":"a".repeat(64),"appendEnter":true}),
        json!({"keys":["unknown"]}),json!({"keys":[]}),json!({"text":"a","keys":["Enter"]}),
        json!({"keys":["Enter"],"appendEnter":true}),json!({"text":"a","appendEnter":1})] {
        server.refused("POST",&keys,invalid,400);
    }
    let restarted=server.json("POST",&format!("{path}/restart"),json!({}));
    assert_eq!(restarted["guestPowerStatus"],"restart_requested");
    assert_eq!(restarted["state"],"running");
    assert_eq!(server.json("POST",&format!("{path}/shutdown"),json!({}))["state"],"off");
    server.refused("POST",&format!("{path}/restart"),json!({}),409);
    server.stop();
}

#[test]
fn machine_network_checkpoints_full_clone_and_trash_over_http() {
    let home = Home::new();
    let service = Server::start(&home.0, FakeEngine::default());
    assert_eq!(service.json("GET", "/v1/health", Value::Null)["status"], "ok");
    let networks = service.json("GET", "/v1/networks", Value::Null);
    assert!(networks.as_array().unwrap().iter().any(|item| item["id"] == "nat"));
    let net = service.network();
    assert_eq!(net["dhcp"], "waiting for setup");
    assert!(net["setupInstruction"].as_str().unwrap().contains("svm-admin-setup.ps1"));
    let vm = service.json("POST", "/v1/machines", json!({
        "id":"test-guest","name":"Test guest","os":"Synthetic guest","net":"lab","vcpu":1,"ramGb":1,"diskGb":1
    }));
    let library = Library::open_stable(home.0.join("library")).unwrap();
    // The fake driver has no VHDX format. Ordinary bytes prove a full, independent copy.
    let source_disk = library.bundle_path("test-guest").unwrap().join("system.vhdx");
    fs::write(&source_disk, b"fixture disk").unwrap();
    let path = "/v1/machines/test-guest";
    assert_eq!(service.json("GET", "/v1/machines", Value::Null)[0]["id"], vm["id"]);
    let changed = service.json("PATCH", path, json!({"name":"Renamed test guest"}));
    assert_eq!(changed["name"], "Renamed test guest");
    assert_eq!(service.json("GET", path, Value::Null)["name"], changed["name"]);
    service.refused("DELETE", "/v1/networks/lab", Value::Null, 409);
    let started = service.json("POST", &format!("{path}/start"), json!({}));
    assert_eq!(started["state"], "running");
    assert_eq!(started["cores"].as_array().unwrap().len(), 1);
    let frame = service.raw("GET", &format!("{path}/thumbnail"), Value::Null);
    assert_eq!(frame.status, 200);
    assert_eq!(frame.headers["x-pixel-format"], "RGBA8");
    assert_eq!(frame.body, [8,32,64,255]);
    let caps = service.json("GET", &format!("{path}/capabilities"), Value::Null);
    assert!(caps.to_string().contains("UsbPassthrough"));
    assert!(caps.to_string().contains("reason"));
    service.refused("POST", &format!("{path}/clone"), json!({"name":"Running copy"}), 409);
    let checkpoints = format!("{path}/snapshots");
    let snap = service.json("POST", &checkpoints, json!({"name":"Point A","withMemory":true}));
    let snap_url = format!("{checkpoints}/{}", snap["id"].as_str().unwrap());
    assert_eq!(service.json("GET", &checkpoints, Value::Null)[0]["id"], snap["id"]);
    assert_eq!(service.json("POST", &format!("{path}/pause"), json!({}))["state"], "paused");
    assert_eq!(service.json("POST", &format!("{path}/resume"), json!({}))["state"], "running");
    service.json("POST", &format!("{snap_url}/revert"), json!({}));
    service.json("DELETE", &snap_url, Value::Null);
    assert_eq!(service.json("GET", &checkpoints, Value::Null), json!([]));
    assert_eq!(service.json("POST", &format!("{path}/stop"), json!({}))["state"], "off");
    let clone = service.json("POST", &format!("{path}/clone"), json!({"name":"Full copy"}));
    for key in ["id","mac","ip","dns"] { assert_ne!(clone[key], vm[key], "{key} reused"); }
    let clone_id = clone["id"].as_str().unwrap();
    let disk = library.bundle_path(clone_id).unwrap().join("system.vhdx");
    assert_eq!(fs::read(&disk).unwrap(), b"fixture disk");
    fs::write(&disk, b"changed copy").unwrap();
    assert_eq!(fs::read(&source_disk).unwrap(), b"fixture disk");
    assert_eq!(service.json("GET", "/v1/networks/lab/leases", Value::Null).as_array().unwrap().len(), 2);
    service.json("POST", &format!("/v1/machines/{clone_id}/snapshots"), json!({"name":"Keep this point","withMemory":false}));
    let kept = service.json("DELETE", &format!("/v1/machines/{clone_id}"), json!({"keepCopy":false}));
    assert_eq!(kept["removalPath"], "retained-copy");
    let retained = Path::new(kept["retainedPath"].as_str().unwrap());
    assert!(retained.is_absolute() && retained.exists());
    let archived = Path::new(kept["trashPath"].as_str().unwrap());
    assert!(archived.is_dir() && retained.starts_with(archived));
    assert!(kept["retainedBytes"].is_u64());
    let simple = service.json("DELETE", path, Value::Null);
    assert_eq!(simple["removalPath"], "bundle-only");
    assert!(simple["retainedPath"].is_null());
    let trashed = Path::new(simple["trashPath"].as_str().unwrap());
    assert!(trashed.join("vm.json").is_file());
    assert_eq!(trashed.parent().unwrap(), archived.parent().unwrap());
    assert_eq!(service.json("GET", "/v1/machines", Value::Null), json!([]));
    assert_eq!(fs::read_dir(home.0.join("library/trash")).unwrap().count(), 2);
    assert_eq!(service.json("GET", "/v1/networks/lab/leases", Value::Null), json!([]));
    service.json("DELETE", "/v1/networks/lab", Value::Null);
    service.stop();
}

#[test]
fn guard_refuses_cpu_memory_and_lower_budget_and_records_reasons() {
    let home = Home::new();
    let service = Server::start(&home.0, FakeEngine::default());
    let host = service.json("GET", "/v1/host", Value::Null);
    assert_eq!(host["placement"], "advisory");
    assert_eq!(service.json("GET","/v1/guard",Value::Null)["enabled"],false);
    service.json("PUT","/v1/guard",json!({"enabled":true,"budgetPct":25,"maxRunning":2,"reserveGb":12}));
    for (id,cpu,ram,phrase) in [("thread-heavy",9,1,"threads"),("ram-heavy",1,53,"GB")] {
        service.machine(id,"nat",cpu,ram);
        let reason = service.refused("POST",&format!("/v1/machines/{id}/start"),json!({}),409);
        assert!(reason.contains(phrase));
        let events = service.json("GET","/v1/events",Value::Null);
        assert!(events.as_array().unwrap().iter().any(|e| e["kind"] == "refused"
            && e["message"].as_str().is_some_and(|s|s.contains(reason.as_str()))));
        assert_eq!(service.json("GET", &format!("/v1/machines/{id}"), Value::Null)["state"], "off");
    }
    service.machine("fits","nat",8,1);
    service.json("POST","/v1/machines/fits/start",json!({}));
    let reason = service.refused("PUT","/v1/guard",json!({"budgetPct":24}),409);
    assert!(reason.contains("threads"));
    service.json("POST","/v1/machines/fits/stop",json!({}));
    assert_eq!(service.json("PUT","/v1/guard",json!({"budgetPct":24}))["budgetPct"],24);
    service.stop();
}

#[test]
fn failed_engine_call_has_a_plain_error_and_service_remains_usable() {
    let home = Home::new();
    let mut engine = FakeEngine::default();
    engine.fail_next("start");
    let service = Server::start(&home.0,engine);
    service.machine("unlucky","nat",1,1);
    let reason = service.refused("POST","/v1/machines/unlucky/start",json!({}),502);
    assert!(reason.starts_with("The engine could not complete the operation."));
    assert_eq!(service.json("GET","/v1/machines/unlucky",Value::Null)["state"],"off");
    assert_eq!(service.json("POST","/v1/machines/unlucky/start",json!({}))["state"],"running");
    service.stop();
}

struct RecoveryRunner { running: AtomicBool }

impl svm_hyperv::PsRunner for RecoveryRunner {
    fn run(&self, _: svm_hyperv::Script, request: &Value) -> svm_core::engine::EngineResult<Value> {
        use svm_core::engine::EngineError;
        let running = self.running.load(Ordering::Relaxed);
        match request["op"].as_str() {
            Some("host") => Ok(json!({"cpu":"Fixture","logical":8,"pCores":[0,4],"eCores":[4,4],"ramGb":32})),
            Some("inspect") => Ok(json!({"name":"svm-recovery","notes":"secwiz-vm:recovery","guid":"01234567-89ab-cdef-0123-456789abcdef",
                "state":if running {2} else {3},"stateName":if running {"Running"} else {"Off"},"ownLink":false})),
            Some("stop") => { self.running.store(false, Ordering::Relaxed); Ok(json!(true)) }
            Some("throwawayRecover") => Err(EngineError::Invalid("Fixture disk is still held".into())),
            op => Err(EngineError::Invalid(format!("Unsupported fixture operation {op:?}"))),
        }
    }
}

#[test]
fn hyperv_stop_reports_off_while_recovery_is_retried_and_deduplicated() {
    let home = Home::new();
    let initial = Server::start(&home.0, FakeEngine::default());
    initial.machine("recovery", "nat", 1, 1);
    initial.stop();
    let library = Library::open_stable(home.0.join("library")).unwrap();
    let mut vm = library.load_all().unwrap().pop().unwrap();
    vm.throwaway = true;
    library.save(&vm).unwrap();
    let bundle = library.bundle_path(&vm.id).unwrap();
    fs::write(bundle.join("system.vhdx"), b"fixture").unwrap();
    let journal = bundle.join("hyperv-throwaway.json");

    let runner = RecoveryRunner { running: AtomicBool::new(true) };
    let server = Server::using_engine(&home.0, Box::new(svm_hyperv::HyperV::new(runner, [])));
    let path = "/v1/machines/recovery";
    fs::write(&journal, b"fixture journal").unwrap();
    let stopped = server.json("POST", &format!("{path}/stop"), json!({}));
    assert_eq!(stopped["state"], "off");
    assert_eq!(stopped["registration"], "registered");
    let failures = || server.json("GET", "/v1/events", Value::Null).as_array().unwrap().iter()
        .filter(|e| e["kind"] == "throwaway recovery failed" && e["message"].as_str().unwrap().contains("Fixture disk is still held")).count();
    assert!(server.refused("PATCH", path, json!({"throwaway":false}), 409).contains("still being recovered"));
    assert!(server.refused("POST", &format!("{path}/start"), json!({}), 409).contains("still being recovered"));
    assert!(server.refused("POST", "/v1/transfers/export", json!({"machineId":"recovery","folder":home.0,"format":"vdi"}), 409).contains("throwaway run"));
    assert_eq!(failures(), 1);

    fs::remove_file(&journal).unwrap();
    assert_eq!(server.json("GET", path, Value::Null)["state"], "off");
    fs::write(&journal, b"second fixture journal").unwrap();
    assert_eq!(server.json("GET", path, Value::Null)["registration"], "registered");
    assert_eq!(failures(), 2);
    fs::remove_file(&journal).unwrap();
    assert_eq!(server.json("PATCH", path, json!({"throwaway":false}))["throwaway"], false);
    server.stop();
}

#[test]
fn restart_preserves_inventory_reservations_events_and_reconciles_engine_state() {
    let home = Home::new();
    let first = Server::start(&home.0,FakeEngine::default());
    first.network();
    first.machine("persist","lab",1,1);
    first.json("POST","/v1/machines/persist/start",json!({}));
    let networks = first.json("GET","/v1/networks",Value::Null);
    let leases = first.json("GET","/v1/networks/lab/leases",Value::Null);
    assert_eq!(leases.as_array().unwrap().len(),1);
    let saved_events = first.json("GET","/v1/events",Value::Null);
    let saved_events = saved_events.as_array().unwrap();
    let cursor = saved_events.last().unwrap()["id"].as_u64().unwrap();
    first.stop();
    let library = Library::open_stable(home.0.join("library")).unwrap();
    let mut vm: Vm = library.load_all().unwrap().pop().unwrap();
    assert_eq!(vm.state, VmState::Running, "service shutdown must leave the guest running");
    // Simulate the operator powering off the guest between service sessions.
    let mut actual = FakeEngine::default();
    vm.state = VmState::Off;
    actual.define(&vm).unwrap();
    let second = Server::start(&home.0,actual);
    let reconciled = second.json("GET","/v1/machines/persist",Value::Null);
    assert_eq!(reconciled["state"],"off");
    assert_eq!(reconciled["cores"], json!([]));
    assert_eq!(second.json("GET","/v1/networks",Value::Null),networks);
    assert_eq!(second.json("GET","/v1/networks/lab/leases",Value::Null),leases);
    let events = second.json("GET","/v1/events",Value::Null);
    assert!(events.as_array().unwrap().starts_with(saved_events));
    let new_events = second.json("GET",&format!("/v1/events?since={cursor}"),Value::Null);
    assert!(new_events.as_array().unwrap().iter().any(|e|e["kind"]=="reconciled"
        && e["message"].as_str().is_some_and(|message|message.contains("persist"))));
    second.stop();
}

#[test]
fn host_protection_is_optional_and_preferences_persist_outside_the_machine_library() {
    let home=Home::new();
    let service=Server::start(&home.0,FakeEngine::default());
    let host=service.json("GET","/v1/host",Value::Null);
    assert_eq!(host["enabled"],false);assert!(host["maxRunning"].is_null());assert_eq!(host["reserveGb"],0);
    for id in ["first","second","third"] {
        service.machine(id,"nat",16,22);
        let path=format!("/v1/machines/{id}");
        assert_eq!(service.json("GET",&format!("{path}/capabilities"),Value::Null)["Start"]["available"],true);
        service.json("POST",&format!("{path}/start"),json!({}));
    }
    service.refused("PUT","/v1/guard",json!({"enabled":true,"budgetPct":50}),409);
    for id in ["first","second","third"] {service.json("POST",&format!("/v1/machines/{id}/stop"),json!({}));}
    let settings=service.json("PUT","/v1/guard",json!({"enabled":true,"budgetPct":75,"maxRunning":3,"reserveGb":7,"preferredCores":[3,2]}));
    assert_eq!(settings["preferredCores"],json!([3,2]));
    assert!(!home.0.join("library/guard.json").exists());
    let running=service.json("POST","/v1/machines/first/start",json!({}));
    assert_eq!(&running["cores"].as_array().unwrap()[..2],&[json!(3),json!(2)]);
    service.stop();
    let reopened=Server::start(&home.0,FakeEngine::default());
    let saved=reopened.json("GET","/v1/guard",Value::Null);
    assert_eq!(saved["enabled"],true);assert_eq!(saved["reserveGb"],7);assert_eq!(saved["maxRunning"],3);
    reopened.json("PUT","/v1/guard",json!({"enabled":false}));
    reopened.stop();
    let other=Home::new();
    let service=Server::start(&other.0,FakeEngine::default());
    assert_eq!(service.json("GET","/v1/guard",Value::Null)["enabled"],false);
    service.stop();
}

#[test]
fn concurrent_starts_share_one_host_budget() {
    let home = Home::new();
    let service = Server::start(&home.0, FakeEngine::default());
    service.json("PUT","/v1/guard",json!({"enabled":true,"budgetPct":25}));
    for id in ["first", "second"] { service.machine(id, "nat", 5, 1); }
    let barrier = std::sync::Barrier::new(2);
    let fire = |id: &str| {
        barrier.wait();
        service.raw("POST", &format!("/v1/machines/{id}/start"), json!({})).status
    };
    let statuses = thread::scope(|scope| {
        let other = scope.spawn(|| fire("second"));
        let first = fire("first");
        [first, other.join().unwrap()]
    });
    assert!(statuses.contains(&200) && statuses.contains(&409));
    let host = service.json("GET", "/v1/host", Value::Null);
    assert_eq!(host["usedThreads"], 5);
    service.stop();
}

#[test]
fn guard_requires_one_whole_thread_and_accepts_only_percentages() {
    let home = Home::new();
    fs::write(home.0.join("guard.json"), b"1").unwrap();
    let service = Server::start(&home.0, FakeEngine::default());
    // The old unbound percentage can travel with a copied service home.
    let guard = service.json("GET", "/v1/guard", Value::Null);
    assert_eq!(guard["enabled"],false);
    assert_eq!(guard["threadBudget"],32);
    assert_eq!(guard["budgetPct"],100);
    let reason = service.refused("PUT", "/v1/guard", json!({"budgetPct":1}), 409);
    assert!(reason.contains("at least one whole thread"));
    for percent in [0, 101, 500] {
        let reason = service.refused("PUT", "/v1/guard", json!({"budgetPct":percent}), 400);
        assert!(reason.contains("between 1 and 100"));
    }
    assert_eq!(service.json("GET", "/v1/guard", Value::Null)["enabled"],false);
    let explicit=service.json("PUT", "/v1/guard", json!({"budgetPct":100}));
    assert_eq!(explicit["enabled"],true); assert_eq!(explicit["budgetPct"],100);
    service.stop();
}

#[test]
fn nat_discloses_windows_assignment_without_a_placeholder_address() {
    let home = Home::new();
    let service = Server::start(&home.0, FakeEngine::default());
    let guest = service.machine("assigned-by-host", "nat", 1, 1);
    let networks = service.json("GET", "/v1/networks", Value::Null);
    let nat = networks.as_array().unwrap().iter().find(|n| n["id"] == "nat").unwrap();
    assert_eq!(nat["addressSource"], "Windows DHCP");
    assert_eq!(guest["addressSource"], "not reported by the guest");
    assert!(guest["ip"].is_null());
    assert!(guest.get("reservationIp").is_none());
    assert!(nat.get("subnet").is_none() && nat.get("gateway").is_none());
    assert_eq!(service.json("GET", "/v1/networks/nat/leases", Value::Null), json!([]));
    let routed = service.network();
    assert!(routed["subnet"].is_string() && routed["gateway"].is_string());
    assert!(routed["setupCommand"].as_str().unwrap().contains("-ServiceExe"));
    let managed = service.machine("assigned-by-service", "lab", 1, 1);
    assert!(managed["ip"].is_string());
    service.stop();
}

#[test]
fn service_power_and_checkpoint_changes_do_not_emit_reconciliation_events() {
    let home = Home::new();
    let service = Server::start(&home.0, FakeEngine::default());
    service.machine("event-check", "nat", 1, 1);
    let path = "/v1/machines/event-check";
    for command in ["start", "pause", "resume"] {
        service.json("POST", &format!("{path}/{command}"), json!({}));
    }
    let checkpoint = service.json("POST", &format!("{path}/snapshots"), json!({"name":"Active guest","withMemory":true}));
    service.json("POST", &format!("{path}/stop"), json!({}));
    let sid = checkpoint["id"].as_str().unwrap();
    service.json("POST", &format!("{path}/snapshots/{sid}/revert"), json!({}));
    let events = service.json("GET", "/v1/events", Value::Null);
    let events = events.as_array().unwrap();
    for kind in ["started", "paused", "resumed", "stopped", "reverted"] {
        assert!(events.iter().any(|e| e["kind"] == kind));
    }
    assert!(!events.iter().any(|e| e["kind"] == "reconciled"));
    service.stop();
}

#[test]
fn machine_identity_round_trips_without_building_an_id_from_the_name() {
    let home = Home::new();
    let service = Server::start(&home.0, FakeEngine::default());
    let guest = service.json("POST", "/v1/machines", json!({"name":"First display name"}));
    let id = guest["id"].as_str().unwrap();
    assert!(!id.is_empty());
    let path = format!("/v1/machines/{id}");
    let renamed = service.json("PATCH", &path, json!({"name":"Changed display name"}));
    assert_eq!(renamed["id"], id);
    assert_eq!(service.json("GET", &path, Value::Null)["name"], "Changed display name");
    let cloned = service.json("POST", &format!("{path}/clone"), json!({"name":"Independent copy"}));
    let other = cloned["id"].as_str().unwrap();
    assert_ne!(other, id);
    assert_eq!(service.json("GET", &format!("/v1/machines/{other}"), Value::Null)["id"], other);
    let caps = service.json("GET", &format!("{path}/capabilities"), Value::Null);
    assert_eq!(caps["Delete"]["available"], true);
    assert_eq!(caps["Console"]["available"], false);
    service.refused("GET", &format!("{path}/console"), Value::Null, 409);
    service.json("POST", &format!("{path}/start"), json!({}));
    assert_eq!(service.json("GET", &format!("{path}/capabilities"), Value::Null)["Delete"]["available"], false);
    service.stop();
}

#[test]
fn resume_is_readmitted_and_keeps_the_guest_paused_when_the_cpu_budget_is_full() {
    let home = Home::new();
    let service = Server::start(&home.0, FakeEngine::default());
    service.json("PUT","/v1/guard",json!({"enabled":true,"budgetPct":25}));
    service.machine("paused-guest", "nat", 2, 1);
    service.machine("other-guest", "nat", 8, 1);
    let path = "/v1/machines/paused-guest";
    let running = service.json("POST", &format!("{path}/start"), json!({}));
    service.json("POST", &format!("{path}/pause"), json!({}));
    service.json("POST", "/v1/machines/other-guest/start", json!({}));

    let caps = service.json("GET", &format!("{path}/capabilities"), Value::Null);
    assert_eq!(caps["Resume"]["available"], false);
    let reason = service.refused("POST", &format!("{path}/resume"), json!({}), 409);
    assert_eq!(caps["Resume"]["reason"].as_str(), Some(reason.as_str()));
    let still_paused = service.json("GET", path, Value::Null);
    assert_eq!(still_paused["state"], "paused");
    assert_eq!(still_paused["cores"], running["cores"]);
    let host = service.json("GET", "/v1/host", Value::Null);
    assert_eq!(host["usedThreads"], 8);
    assert_eq!(host["usedRamGb"], 2);
    let events = service.json("GET", "/v1/events", Value::Null);
    assert!(events.as_array().unwrap().iter().any(|e| e["kind"] == "refused"
        && e["message"].as_str().is_some_and(|text| text.contains(&reason[..]))));
    assert!(!events.as_array().unwrap().iter().any(|e| e["kind"] == "resumed"));

    service.json("POST", "/v1/machines/other-guest/stop", json!({}));
    let resumed = service.json("POST", &format!("{path}/resume"), json!({}));
    assert_eq!(resumed["state"], "running");
    assert_eq!(resumed["cores"], running["cores"]);
    service.stop();
}

#[test]
fn oversized_disk_requests_leave_the_library_empty() {
    let home = Home::new();
    let service = Server::start(&home.0, FakeEngine::default());
    let host = service.json("GET", "/v1/host", Value::Null);
    assert_eq!(host["maxDiskGb"], 160);
    assert_eq!(host["freeRamGb"], 32);
    let low=service.refused("POST","/v1/machines",json!({"name":"Too large for volume","diskGb":161}),400);
    assert!(low.contains("160 GiB"));
    let message = service.refused("POST", "/v1/machines",
        json!({"name":"Oversized guest","diskGb":65_537}), 400);
    assert!(message.contains("64 TiB"));
    assert_eq!(service.json("GET", "/v1/machines", Value::Null), json!([]));
    service.stop();
}

#[test]
fn installer_boot_is_a_one_time_choice_for_fresh_windows_disks() {
    let home=Home::new();
    let server=Server::start(&home.0,FakeEngine::default());
    let iso=home.0.join("windows.iso");
    fs::write(&iso,b"installer").unwrap();
    for id in ["default","opt-out","disk-first"] {
        server.json("POST","/v1/machines",json!({"id":id,"name":id,"family":"windows","diskGb":4,"isoPath":iso}));
        let path=format!("/v1/machines/{id}");
        let start=format!("{path}/start");
        let caps=format!("{path}/capabilities");
        assert_eq!(server.json("GET",&caps,Value::Null)["PressKeyAtBoot"]["available"],true);
        let input=match id {
            "default"=>json!({}),
            "opt-out"=>json!({"pressKeyAtBoot":false}),
            _=>{
                server.json("PUT",&format!("{path}/storage"),json!({"bootFirst":"disk"}));
                assert_eq!(server.json("GET",&caps,Value::Null)["PressKeyAtBoot"]["available"],false);
                server.refused("POST",&start,json!({"pressKeyAtBoot":true}),409);
                json!({})
            }
        };
        let result=server.json("POST",&start,input);
        assert_eq!(result["state"],"running");
        assert_eq!(result["bootKey"]["sent"].is_number(),id=="default");
        server.json("POST",&format!("{path}/stop"),json!({}));
        server.refused("POST",&start,json!({"pressKeyAtBoot":true}),409);
        assert_eq!(server.json("GET",&caps,Value::Null)["PressKeyAtBoot"]["available"],false);
    }
    let existing=home.0.join("existing.vhdx");
    let standalone = vhdx::standalone();
    let mut differencing = standalone.clone();
    differencing[0x50000 + 128 + 4] = 2;
    fs::write(&existing, &differencing).unwrap();
    let create = json!({"id":"imported","name":"Imported","family":"windows","diskPath":existing,"isoPath":iso});
    let refusal = server.refused("POST", "/v1/machines", create.clone(), 400);
    assert!(refusal.contains("depends on a parent"));
    assert_eq!(fs::read(&existing).unwrap(), differencing);
    fs::write(&existing, standalone).unwrap();
    server.json("POST", "/v1/machines", create);
    server.refused("POST","/v1/machines/imported/start",json!({"pressKeyAtBoot":true}),409);
    server.stop();
}

#[test]
fn installer_storage_and_idle_shutdown_follow_machine_state() {
    let home=Home::new();
    let mut server=Server::start(&home.0,FakeEngine::default());
    let iso=home.0.join("installer.iso");
    fs::write(&iso,b"local fixture").unwrap();
    server.json("POST","/v1/machines",json!({"id":"install","name":"Install","diskGb":20,"isoPath":iso}));
    let path="/v1/machines/install/storage";
    let initial=server.json("GET",path,Value::Null);
    assert_eq!(initial["bootFirst"],"image");
    assert_eq!(initial["disks"][0]["maximumBytes"],20u64<<30);
    for first in ["disk","image","disk"] {
        assert_eq!(server.json("PUT",path,json!({"bootFirst":first}))["bootFirst"],first);
        assert_eq!(server.json("GET",path,Value::Null)["bootFirst"],first);
    }
    let reply=server.json("PATCH","/v1/machines/install",json!({"vcpu":2,"ramGb":2}));
    assert_eq!(reply["vcpu"],2);
    server.json("POST","/v1/machines/install/start",json!({}));
    server.refused("POST","/v1/shutdown",json!({"ifIdle":true}),409);
    server.refused("PUT",path,json!({"bootFirst":"image"}),409);
    server.refused("PATCH","/v1/machines/install",json!({"ramGb":4}),409);
    for _ in 0..2 {
        assert_eq!(server.json("PUT",path,json!({"isoPath":null})).get("isoPath"),Some(&Value::Null));
        let storage=server.json("GET",path,Value::Null);
        assert_eq!(storage.get("isoPath"),Some(&Value::Null));
        assert_eq!(storage["bootFirst"],"disk");
    }
    assert!(server.json("PUT",path,json!({"isoPath":iso}))["isoPath"].is_string());
    server.json("POST","/v1/machines/install/pause",json!({}));
    server.refused("POST","/v1/shutdown",json!({"ifIdle":true}),409);
    server.json("POST","/v1/machines/install/stop",json!({}));
    assert_eq!(server.json("POST","/v1/shutdown",json!({"ifIdle":true}))["status"],"stopping");
    server.runner.take().unwrap().join().unwrap().unwrap();
}

#[test]
fn borrowed_wired_bridge_is_forgotten_without_router_leases_or_switch_removal() {
    let home=Home::new();
    let server=Server::start(&home.0,FakeEngine::default());
    let adapters=server.json("GET","/v1/networks/bridge-adapters",Value::Null);
    let adapter=&adapters["adapters"][0]["id"];
    let mut body=json!({"id":"wired","name":"Wired","mode":"Bridged","adapterId":adapter});
    server.refused("POST","/v1/networks",body.clone(),400);
    body["confirmDisconnect"]=json!(true);
    let wired=server.json("POST","/v1/networks",body);
    assert_eq!(wired["ready"],true);assert_eq!(wired["bridgeOwned"],false);
    assert_eq!(wired["addressSource"],"Router DHCP");assert!(wired.get("subnet").is_none());
    let guest=server.machine("on-lan","wired",1,1);
    assert!(guest["ip"].is_null());assert_eq!(guest["addressSource"],"not reported by the guest");
    server.refused("DELETE","/v1/networks/wired",json!({}),409);
    server.json("DELETE","/v1/machines/on-lan",json!({}));
    server.json("DELETE","/v1/networks/wired",json!({}));
    assert_eq!(server.json("GET","/v1/networks/bridge-adapters",Value::Null),adapters);
    server.stop();
}

#[test]
fn permanent_reservations_are_editable_unique_and_retained_across_rename_and_clone() {
    let home=Home::new();let server=Server::start(&home.0,FakeEngine::default());
    let local=server.json("POST","/v1/networks",json!({"id":"wireless-free","name":"Local","mode":"Link-local"}));
    assert_eq!(local["subnet"],"169.254.0.0/16");assert!(local["gateway"].is_null());assert!(local["setupCommand"].is_null());
    server.refused("POST","/v1/networks",json!({"id":"another","name":"Duplicate range","mode":"Link-local"}),400);
    let guest=server.machine("local-guest","wireless-free",1,1);
    let path="/v1/machines/local-guest";
    assert_eq!(guest["ip"],"169.254.1.0");
    assert_eq!(server.json("PATCH",path,json!({"ip":"169.254.16.12"}))["ip"],"169.254.16.12");
    let other=server.machine("sibling","wireless-free",1,1);
    server.refused("PATCH",path,json!({"ip":other["ip"]}),409);
    server.refused("PATCH",path,json!({"ip":"169.254.255.88"}),400);
    let renamed=server.json("PATCH",path,json!({"name":"Renamed"}));
    assert_eq!(renamed["ip"],"169.254.16.12");assert_eq!(renamed["dns"],guest["dns"]);
    let copy=server.json("POST","/v1/machines/local-guest/clone",json!({"id":"copy","name":"Copy"}));
    assert_ne!(copy["ip"],renamed["ip"]);assert_ne!(copy["dns"],renamed["dns"]);
    let leases=server.json("GET","/v1/networks/wireless-free/leases",Value::Null);
    assert!(leases.as_array().unwrap().iter().any(|a|a["ip"]=="169.254.16.12"));
    server.json("POST","/v1/machines/local-guest/start",json!({}));
    server.refused("PATCH",path,json!({"ip":"169.254.32.9"}),409);
    server.stop();
}

#[test]
fn discarded_guest_keeps_reservations_until_permanent_removal() {
    let home=Home::new(); let server=Server::start(&home.0,FakeEngine::default());
    server.network();
    let original=server.machine("original","lab",1,1);
    server.json("DELETE","/v1/machines/original",json!({}));
    let newer=server.machine("newer","lab",1,1);
    for field in ["ip","mac","dns"] {assert_ne!(newer[field],original[field]);}
    server.refused("PATCH","/v1/machines/newer",json!({"ip":original["ip"]}),409);
    let entries=server.json("GET","/v1/trash",Value::Null);
    let item=entries[0]["key"].as_str().unwrap();
    let restored=server.json("POST",&format!("/v1/trash/{item}/restore"),json!({}));
    for field in ["ip","mac","dns"] {assert_eq!(restored[field],original[field]);}
    server.stop();
}

#[derive(Clone)]
struct GatedHyperv {
    live: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
    active: Arc<AtomicBool>,
    entered: std::sync::mpsc::Sender<String>,
    release: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<bool>>>,
}

impl GatedHyperv {
    fn hold(&self, operation: &str) -> svm_core::engine::EngineResult<()> {
        assert!(!self.active.swap(true, Ordering::AcqRel));
        self.entered.send(operation.to_owned()).unwrap();
        let result = self.release.lock().unwrap().recv_timeout(std::time::Duration::from_secs(8));
        self.active.store(false, Ordering::Release);
        match result {
            Ok(true) => Ok(()),
            _ => Err(svm_core::engine::EngineError::Engine("Fixture operation stopped before changing data.".into())),
        }
    }
}

impl svm_hyperv::PsRunner for GatedHyperv {
    fn background(&self) -> Option<Box<dyn svm_hyperv::PsRunner + Send>> {
        Some(Box::new(self.clone()))
    }

    fn run(&self, _: svm_hyperv::Script, request: &Value) -> svm_core::engine::EngineResult<Value> {
        use svm_core::engine::EngineError;

        assert!(!self.active.load(Ordering::Acquire), "The service entered a native provider during held work");
        let id = request["id"].as_str().unwrap_or_default();
        let guid = "01234567-89ab-cdef-0123-456789abcdef";
        let registered = || self.live.lock().unwrap().contains(id);
        match request["op"].as_str() {
            Some("host") => Ok(json!({"cpu":"Mock","hostKey":"synthetic-background-fixture","logical":8,"pCores":[0,4],"eCores":[4,4],"ramGb":32})),
            Some("capacity") => Ok(json!({"freeBytes":50_u64 << 30,"freeRamGb":24})),
            Some("inspect") if registered() => Ok(json!({"name":format!("svm-{id}"),"notes":format!("secwiz-vm:{id}"),"guid":guid,"state":3,"stateName":"Off","ownLink":false})),
            Some("inspect") => Err(EngineError::Missing(id.to_owned())),
            Some("storage") => Ok(json!({"isoPath":null,"bootFirst":"disk"})),
            Some("define") => {
                self.live.lock().unwrap().insert(id.to_owned());
                Ok(json!({"guid":guid}))
            }
            Some("copyDisk") => {
                self.hold("copyDisk")?;
                Ok(json!({"copied":false}))
            }
            Some("removePlan") => Ok(json!({"guid":guid,"stamp":"fixture","required":true})),
            Some("remove") => {
                self.hold("remove")?;
                let bundle = PathBuf::from(request["bundle"].as_str().unwrap());
                let retained = "retained/fixture";
                fs::create_dir_all(bundle.join(retained)).unwrap();
                fs::write(bundle.join(retained).join("guest-config"), b"fixture").unwrap();
                let receipt = json!({"id":id,"retained":retained,"bytes":7});
                svm_core::write_json(&bundle.join("removal-complete.json"), &receipt).unwrap();
                self.live.lock().unwrap().remove(id);
                Ok(receipt)
            }
            Some("restoreRegistration") => Ok(json!(registered())),
            Some("trashDetached") if !registered() => Ok(json!({"ok":true})),
            Some("importRetained") => {
                self.hold("importRetained")?;
                self.live.lock().unwrap().insert(id.to_owned());
                Ok(json!({"ok":true}))
            }
            Some("snapshots") => Ok(json!({"items":[]})),
            other => Err(EngineError::Engine(format!("Unexpected fixture operation {other:?}."))),
        }
    }
}

#[test]
fn hyperv_disk_jobs_free_the_request_worker_and_publish_only_after_completion() {
    use std::{sync::{mpsc, Mutex}, time::{Duration, Instant}};

    let home = Home::new();
    let initial = Server::start(&home.0, FakeEngine::default());
    initial.machine("source", "nat", 1, 1);
    initial.stop();

    let (entered_send, entered) = mpsc::channel();
    let (release, release_recv) = mpsc::channel();
    let fixture = GatedHyperv {
        live: Arc::new(Mutex::new(["source".to_owned()].into_iter().collect())),
        active: Arc::new(AtomicBool::new(false)),
        entered: entered_send,
        release: Arc::new(Mutex::new(release_recv)),
    };
    let server = Server::using_engine(&home.0, Box::new(svm_hyperv::HyperV::new(fixture, [])));
    let begin = |method: &'static str, route: String, body: Value, operation: &str| {
        let client = Client::load(&home.0, None).unwrap();
        let pending = thread::spawn(move || client.request(method, &route, Some(&body)).unwrap());
        assert_eq!(entered.recv_timeout(Duration::from_secs(4)).unwrap(), operation);
        let time = Instant::now();
        assert_eq!(server.json("GET", "/v1/health", Value::Null)["status"], "ok");
        assert!(server.json("GET", "/v1/networks", Value::Null).is_array());
        assert!(server.json("GET", "/v1/host", Value::Null).is_object());
        assert!(time.elapsed() < Duration::from_secs(3));
        server.refused("POST", "/v1/shutdown", json!({}), 409);
        pending
    };
    let machines = || server.json("GET", "/v1/machines", Value::Null);
    let clone = begin("POST", "/v1/machines/source/clone".into(), json!({"id":"destination","name":"Destination"}), "copyDisk");
    assert_eq!(machines().as_array().unwrap().len(), 1);
    server.refused("PATCH", "/v1/machines/source", json!({"name":"Busy"}), 409);
    release.send(true).unwrap();
    assert_eq!(clone.join().unwrap().status, 201);
    assert_eq!(machines().as_array().unwrap().len(), 2);

    let bad_remove = begin("DELETE", "/v1/machines/source".into(), json!({"keepCopy":true}), "remove");
    release.send(false).unwrap();
    assert_eq!(bad_remove.join().unwrap().status, 502);
    assert_eq!(machines().as_array().unwrap().len(), 2);

    let remove = begin("DELETE", "/v1/machines/source".into(), json!({"keepCopy":true}), "remove");
    assert_eq!(machines().as_array().unwrap().len(), 2);
    release.send(true).unwrap();
    let removed = remove.join().unwrap();
    assert_eq!(removed.status, 200);
    assert_eq!(machines().as_array().unwrap().len(), 1);
    let trash = server.json("GET", "/v1/trash", Value::Null);
    let key = trash[0]["key"].as_str().unwrap();
    let restore = begin("POST", format!("/v1/trash/{key}/restore"), json!({}), "importRetained");
    assert_eq!(machines().as_array().unwrap().len(), 1);
    release.send(true).unwrap();
    assert_eq!(restore.join().unwrap().status, 200);
    assert_eq!(machines().as_array().unwrap().len(), 2);
    assert_eq!(server.json("GET", "/v1/trash", Value::Null), json!([]));
    server.stop();
}


#[derive(Clone)]
struct GuestSecretRunner {
    entered: std::sync::mpsc::Sender<()>,
    release: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
}

impl svm_hyperv::PsRunner for GuestSecretRunner {
    fn background(&self) -> Option<Box<dyn svm_hyperv::PsRunner + Send>> { Some(Box::new(self.clone())) }

    fn run(&self, script: svm_hyperv::Script, request: &Value) -> svm_core::engine::EngineResult<Value> {
        assert_ne!(script, svm_hyperv::Script::GuestExec);
        assert!(!request.to_string().contains("synthetic-guest-canary"));
        let id = request["id"].as_str().unwrap_or_default();
        match request["op"].as_str() {
            Some("host") => Ok(json!({"cpu":"Fixture","hostKey":"guest-command-fixture","logical":8,"pCores":[0,4],"eCores":[4,4],"ramGb":32})),
            Some("capacity") => Ok(json!({"freeBytes":50_u64 << 30,"freeRamGb":24})),
            Some("inspect") if id=="guest-cmd" => Ok(json!({"name":"svm-guest-cmd","notes":"secwiz-vm:guest-cmd",
                "guid":"01234567-89ab-cdef-0123-456789abcdef","state":2,"stateName":"Running","ownLink":false})),
            _ => Err(svm_core::engine::EngineError::Invalid("Unavailable fixture operation.".into())),
        }
    }

    fn run_guest_exec(&self, request: &Value, _: std::time::Duration) -> svm_core::engine::EngineResult<Value> {
        assert!(request["username"]=="synthetic-guest-canary-user" && request["password"]=="synthetic-guest-canary-password");
        assert_eq!(request["guid"],"01234567-89ab-cdef-0123-456789abcdef");
        assert!(request["command"]["password"].is_null());
        if request["command"]["argv"][0] == "powershell.exe" {
            let script = request["command"]["argv"][5].as_str().unwrap();
            assert!(script.contains("https://cdn.winget.microsoft.com/cache"));
            assert!(!script.contains("synthetic-guest-canary"));
            if script.contains("'install --id Git.Git --exact --source winget") {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv_timeout(std::time::Duration::from_secs(8)).unwrap();
                return Ok(json!({"exitCode":87,"stdoutB64":"", "stderrB64":"Z3Vlc3QgZmFpbGVkCg=="}));
            }
            if script.contains("'uninstall --id Git.Git --exact --source winget") {
                return Ok(json!({"exitCode":0,"stdoutB64":"cmVtb3ZlZAo=", "stderrB64":""}));
            }
            assert!(script.contains("Microsoft community repository verified."));
            return Ok(json!({"exitCode":0,"stdoutB64":"dmVyaWZpZWQK","stderrB64":""}));
        }
        assert_eq!(request["command"]["argv"][1],"a literal \"quoted\" argument");
        match request["command"]["argv"][0].as_str().unwrap() {
            "fixture-success.exe" => {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv_timeout(std::time::Duration::from_secs(8)).unwrap();
                Ok(json!({"exitCode":0,"stdoutB64":"Z3Vlc3QK","stderrB64":""}))
            }
            "fixture-timeout.exe" => Ok(json!({"timeout":true})),
            _ => Ok(json!({"error":"synthetic-guest-canary-password"})),
        }
    }
}

#[test]
fn hyperv_guest_credentials_remain_on_the_private_command_channel() {
    let home=Home::new();
    let initial=Server::start(&home.0,FakeEngine::default());
    initial.json("POST", "/v1/machines", json!({"id":"guest-cmd","name":"Guest command fixture",
        "os":"Windows 10 fixture","family":"windows","vcpu":1,"ramGb":1,"net":"nat"}));
    initial.stop();
    let (created, entered) = std::sync::mpsc::channel();
    let (release, resumed) = std::sync::mpsc::channel();
    let runner = GuestSecretRunner { entered: created, release: Arc::new(std::sync::Mutex::new(resumed)) };
    let server=Server::using_engine(&home.0,Box::new(svm_hyperv::HyperV::new(runner, [])));
    let request=|program|json!({"argv":[program,"a literal \"quoted\" argument"],"timeoutSec":1,
        "credentials":{"username":"synthetic-guest-canary-user","password":"synthetic-guest-canary-password"}});
    let path="/v1/machines/guest-cmd/exec";
    let client = Client::load(&home.0, None).unwrap();
    let command = request("fixture-success.exe");
    let pending = thread::spawn(move || client.request("POST",path,Some(&command)).unwrap());
    entered.recv_timeout(std::time::Duration::from_secs(4)).unwrap();
    assert_eq!(server.json("GET","/v1/health",Value::Null)["status"],"ok");
    server.refused("PATCH","/v1/machines/guest-cmd",json!({"name":"Rename while busy"}),409);
    server.refused("DELETE","/v1/machines/guest-cmd",json!({"keepCopy":false}),409);
    release.send(()).unwrap();
    let reply = pending.join().unwrap();
    assert_eq!(reply.status,200);
    let report: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(report["channel"],"powershell-direct");
    assert_eq!(report["stdout"],"guest\n");
    assert_eq!(report["exitCode"],0);
    let error=server.refused("POST",path,request("fixture-error.exe"),409);
    assert!(!error.contains("synthetic-guest-canary"));
    let message=server.refused("POST",path,request("fixture-timeout.exe"),504);
    assert!(message.contains("may still be running inside the guest"));
    let invalid=server.refused("POST",path,json!({"argv":["hostname.exe"],"timeoutSec":1,
        "credentials":"synthetic-guest-canary-password"}),400);
    assert!(!invalid.contains("synthetic-guest-canary"));
    let events=server.json("GET","/v1/events",Value::Null);
    assert!(!events.to_string().contains("synthetic-guest-canary"));
    server.stop();
    let bundle=Library::open_stable(home.0.join("library")).unwrap().bundle_path("guest-cmd").unwrap();
    for file in [home.0.join("svmd.log"),bundle.join("vm.json")] {
        assert!(!fs::read_to_string(file).unwrap().contains("synthetic-guest-canary"));
    }
}

#[test]
fn app_marketplace_requires_confirmation_and_streams_step_results_over_http() {
    let home = Home::new();
    let initial = Server::start(&home.0, FakeEngine::default());
    initial.json("POST", "/v1/machines", json!({"id":"guest-cmd","name":"Guest app fixture",
        "os":"Windows fixture","family":"windows","vcpu":1,"ramGb":1,"net":"nat"}));
    assert_eq!(initial.json("GET", "/v1/catalog/apps/git/machines", Value::Null), json!([]));
    initial.stop();

    let (created, entered) = std::sync::mpsc::channel();
    let (release, resumed) = std::sync::mpsc::channel();
    let runner = GuestSecretRunner { entered: created, release: Arc::new(std::sync::Mutex::new(resumed)) };
    let server = Server::using_engine(&home.0, Box::new(svm_hyperv::HyperV::new(runner, [])));
    let access = json!({"credentials":{"username":"synthetic-guest-canary-user","password":"synthetic-guest-canary-password"}});
    let preview_route = "/v1/machines/guest-cmd/apps/git/preview";
    let run_route = "/v1/machines/guest-cmd/apps/git/run";
    let job_route = "/v1/machines/guest-cmd/apps";
    assert!(server.json("GET", "/v1/catalog/apps", Value::Null).as_array().unwrap().len() >= 15);
    assert_eq!(server.json("GET", "/v1/catalog/apps/git/machines", Value::Null)[0]["id"], "guest-cmd");
    assert_eq!(server.json("GET", job_route, Value::Null), Value::Null);
    server.refused("POST", run_route, json!({"previewId":"unknown","access":access}), 409);
    server.refused("POST", preview_route, json!({"action":"install","access":access,"argv":["forged"]}), 400);
    let preview = server.json("POST", preview_route, json!({"action":"install","access":access}));
    assert_eq!(preview["steps"].as_array().unwrap().len(), 2);
    assert!(preview["steps"][1]["argv"][5].as_str().unwrap().contains("install --id Git.Git --exact --source winget"));
    assert!(!preview.to_string().contains("synthetic-guest-canary"));
    assert!(entered.try_recv().is_err());
    let confirmation = json!({"previewId":preview["previewId"],"access":access});
    let accepted = server.raw("POST", run_route, confirmation.clone());
    assert_eq!(accepted.status, 202);
    entered.recv_timeout(std::time::Duration::from_secs(4)).unwrap();
    let progress = server.json("GET", job_route, Value::Null);
    assert_eq!(progress["state"], "running");
    assert_eq!(progress["log"][0]["state"], "succeeded");
    assert_eq!(progress["log"][1]["state"], "running");
    server.refused("POST", run_route, confirmation.clone(), 409);
    server.refused("POST", "/v1/machines/guest-cmd/stop", json!({}), 409);
    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    loop {
        let progress = server.json("GET", job_route, Value::Null);
        if progress["state"] == "failed" {
            assert_eq!(progress["log"][1]["output"]["stderr"], "guest failed\n");
            assert!(progress["message"].as_str().unwrap().contains("Step 2 failed"));
            assert!(!progress.to_string().contains("synthetic-guest-canary"));
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        thread::sleep(std::time::Duration::from_millis(20));
    }
    server.refused("POST", run_route, confirmation, 409);
    let preview = server.json("POST", preview_route, json!({"action":"uninstall","access":access}));
    assert!(preview["steps"][1]["argv"][5].as_str().unwrap().contains("'uninstall --id Git.Git --exact --source winget"));
    let accepted = server.raw("POST", run_route, json!({"previewId":preview["previewId"],"access":access}));
    assert_eq!(accepted.status, 202);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    loop {
        let progress = server.json("GET", job_route, Value::Null);
        if progress["state"] == "succeeded" {
            assert_eq!(progress["action"], "uninstall");
            assert_eq!(progress["log"][1]["output"]["stdout"], "removed\n");
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        thread::sleep(std::time::Duration::from_millis(20));
    }
}
