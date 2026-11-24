use super::*;
use std::{cell::RefCell, collections::VecDeque};

#[derive(Default)]
struct Mock {
    retained_calls: std::cell::Cell<usize>,
    calls: RefCell<Vec<Value>>,
    replies: RefCell<VecDeque<EngineResult<Value>>>,
}

impl Mock {
    fn reply(&self, value: Value) { self.replies.borrow_mut().push_back(Ok(value)); }
    fn error(&self, error: EngineError) { self.replies.borrow_mut().push_back(Err(error)); }
}

impl PsRunner for Mock {
    fn run_retained(&self,script:Script,data:&Value)->EngineResult<Value> {
        self.retained_calls.set(self.retained_calls.get()+1);
        self.run(script,data)
    }
    fn run(&self, script: Script, data: &Value) -> EngineResult<Value> {
        assert_eq!(script, match data["op"].as_str() {
            Some("define") => Script::Definition,
            Some("throwawayStart" | "throwawayRecover") => Script::Throwaway,
            Some("installerBootStatus" | "installerStart") => Script::InstallerBoot,
            Some("trashDetached" | "restoreRegistration" | "importRetained") => Script::Trash,
            Some("bridgeAdapters" | "resolveBridge") => Script::Bridge,
            Some("storage" | "setStorage" | "confirmStorage" | "capacity") => Script::Storage,
            Some("guestStatus" | "shutdown" | "restart" | "keys") => Script::Guest,
            Some("fileGuestService" | "setFileGuestService") => Script::FileGuestService,
            Some("host") => Script::Host,
            Some("snapshot") => Script::Checkpoint,
            Some("snapshots" | "configure" | "copyDisk" | "removePlan" | "remove") => Script::Service,
            _ => Script::Management,
        });
        self.calls.borrow_mut().push(data.clone());
        self.replies.borrow_mut().pop_front().expect("missing recorded reply")
    }
}

const ID: &str = "test-unit";
const GUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const DISPLAY: &str = "x'; Remove-VM *; '";

fn guest() -> Vm {
    serde_json::from_value(json!({
        "id":ID,"name":DISPLAY,"os":"Test","family":"linux","engine":"Hyper-V",
        "accel":true,"state":"off","vcpu":1,"ramGb":1,"net":"test",
        "ip":"10.77.1.2","mac":"02:77:00:00:00:01","dns":"test.vm.lan"
    })).unwrap()
}

fn net(mode: NetworkMode) -> Network {
    Network { bridge:None, id:"test".into(), name:"Test".into(), mode, subnet:"10.77.1.0/24".parse().unwrap(),
        gateway:None, dhcp:true, note:String::new() }
}

fn driver(mode: NetworkMode) -> HyperV<Mock> {
    let mut d = HyperV::new(Mock::default(), [net(mode)]);
    d.register_bundle(ID, std::env::temp_dir().join("unit.swvm")).unwrap();
    d
}

fn info() -> Value {
    json!({"name":"svm-test-unit","notes":"secwiz-vm:test-unit","guid":GUID,"state":2,"stateName":"Running","ownLink":true})
}
fn answer(d: &HyperV<Mock>, value: Value) {
    d.runner.reply(info());
    d.runner.reply(value);
}

#[test]
fn legacy_definition_and_untrusted_display_name_are_data() {
    let mut d = driver(NetworkMode::Nat);
    let mut vm = guest();
    assert_eq!((vm.disk_gb, vm.secure_boot, vm.tpm), (None, None, None));
    assert!(serde_json::to_value(&vm).unwrap().get("diskPath").is_none());
    vm.disk_gb = Some(2);
    vm.iso_path = Some("install.iso".into());
    vm.tpm = Some(true);
    d.runner.reply(json!({"guid":GUID}));
    d.define(&vm).unwrap();
    let calls = d.runner.calls.borrow();
    assert_eq!(calls[0], json!({
        "op":"define","id":ID,"displayName":DISPLAY,"bundle":d.bundle(ID).unwrap(),
        "vcpu":1,"ramGb":1,"mac":"027700000001","networkId":"test","networkMode":"NAT",
        "diskGb":2,"diskPath":null,"isoPath":"install.iso","secureBoot":true,
        "template":"MicrosoftUEFICertificateAuthority","tpm":true
    }));
    assert!(!Script::Management.source().contains(DISPLAY));
}

#[test]
fn respects_optional_boot_and_disk_configuration() {
    let mut d = driver(NetworkMode::HostOnly);
    let mut vm = guest();
    vm.family = GuestFamily::Windows;
    vm.disk_path = Some("guest.vhdx".into());
    vm.secure_boot = Some(false);
    d.runner.reply(json!({"guid":GUID}));
    d.define(&vm).unwrap();
    {
        let log = d.runner.calls.borrow();
        assert_eq!(log[0]["template"], "MicrosoftWindows");
        assert_eq!(log[0]["secureBoot"], false);
        assert_eq!(log[0]["diskPath"], "guest.vhdx");
    }
    vm.disk_gb = Some(1);
    assert!(d.define(&vm).is_err());
    vm.disk_gb = None;
    vm.family = GuestFamily::Bsd;
    vm.secure_boot = None;
    d.runner.reply(json!({"guid":GUID}));
    d.define(&vm).unwrap();
    assert_eq!(d.runner.calls.borrow()[1]["secureBoot"], false);
}

#[test]
fn bridged_and_unmanaged_switch_modes_are_refused_before_dispatch() {
    let mut d = driver(NetworkMode::Bridged);
    assert!(d.define(&guest()).is_err());
    assert!(d.ensure_switch(&net(NetworkMode::Bridged)).is_err());
    assert!(d.remove_switch(&net(NetworkMode::Nat)).is_err());
    assert!(d.runner.calls.borrow().is_empty());
}

#[test]
fn capabilities_follow_observed_attachment() {
    let d = driver(NetworkMode::Routed);
    for linked in [true,false] {
        let mut found = info();
        found["ownLink"] = json!(linked);
        d.runner.reply(found);
        d.runner.reply(json!({"powerReason":null,"keyReason":null}));
        let caps = d.capabilities(&guest());
        for c in [Capability::Start,Capability::Stop,Capability::Pause,Capability::Resume,
            Capability::Snapshot,Capability::SnapshotWithMemory,Capability::Accelerated,
            Capability::Thumbnail,Capability::Console,Capability::Clone] { assert!(caps.has(c)); }
        assert_eq!(caps.has(Capability::OwnLanAddress), linked);
        assert!(caps.reason(Capability::UsbPassthrough).unwrap().contains("no USB passthrough"));
    }
}

#[test]
fn name_and_marker_are_each_required_before_mutation() {
    let mut d = driver(NetworkMode::Nat);
    for (key, value) in [("notes",""),("notes","secwiz-vm:another"),("name","other")] {
        let mut foreign = info();
        foreign[key] = json!(value);
        d.runner.reply(foreign);
        assert!(matches!(d.stop(ID), Err(EngineError::Invalid(_))));
    }
    assert!(d.runner.calls.borrow().iter().all(|r|r["op"]=="inspect"));
}

#[test]
fn power_and_removal_pin_the_inspected_registration() {
    let mut d = driver(NetworkMode::Routed);
    for op in ["start","pause","resume","stop","remove"] {
        answer(&d, json!({"ok":true}));
        match op {
            "start" => d.start(ID), "pause" => d.pause(ID), "resume" => d.resume(ID),
            "stop" => d.stop(ID), _ => d.remove(ID),
        }.unwrap();
        let calls = d.runner.calls.borrow();
        let request = calls.last().unwrap();
        assert_eq!(request["op"], op);
        assert_eq!(request["id"], ID);
        assert_eq!(request["guid"], GUID);
        if matches!(op, "remove" | "start") { assert_eq!(request["bundle"], json!(d.bundle(ID).unwrap())); }
    }
}

#[test]
fn checkpoints_round_trip_ids_and_labels() {
    let mut d = driver(NetworkMode::Routed);
    for memory in [true,false] {
        answer(&d,json!({"Id":"checkpoint","Name":DISPLAY,"ParentSnapshotId":"previous","SnapshotType":0}));
        let s = d.snapshot(ID,DISPLAY,memory).unwrap();
        assert_eq!(s.parent.as_deref(),Some("previous"));
        assert_eq!(s.with_memory,memory);
        let req = d.runner.calls.borrow().last().unwrap().clone();
        assert_eq!(req["label"],DISPLAY);
        assert_eq!(req["withMemory"],memory);
        answer(&d,json!({})); d.revert(ID,&s.id).unwrap();
        answer(&d,json!({})); d.delete_snapshot(ID,&s.id).unwrap();
        for req in d.runner.calls.borrow().iter().filter(|r|r["op"]=="revert" || r["op"]=="deleteSnapshot") {
            assert_eq!(req["snapshotId"],"checkpoint"); assert_eq!(req["guid"],GUID);
        }
    }
}

#[test]
fn known_states_and_unknown_state_through_driver() {
    let mut d = driver(NetworkMode::Routed);
    for (expected, names) in [
        (VmState::Off, "Off OffCritical"),
        (VmState::Paused, "Paused PausedCritical"),
        (VmState::Saved, "Saved SavedCritical FastSaved FastSavedCritical Hibernated"),
        (VmState::Running, "Running RunningCritical Starting StartingCritical Stopping StoppingCritical Reset ResetCritical Saving SavingCritical FastSaving FastSavingCritical Pausing PausingCritical Resuming ResumingCritical ForceShutdown ForceReboot ComponentServicing"),
    ] {
        for name in names.split_whitespace() {
            assert_eq!(map_state(name).unwrap(), expected, "{name}");
        }
    }
    for name in ["Other","UnexpectedState"] { assert!(map_state(name).is_err()); }
    let mut unknown=info(); unknown["state"]=json!(123456); unknown["stateName"]=json!("123456");
    d.runner.reply(unknown); assert!(d.state(ID).is_err());
}

#[test]
fn thumbnail_converts_only_complete_rgb565_frames() {
    let mut d = driver(NetworkMode::Routed);
    answer(&d,json!({"returnValue":0,"width":3,"height":1,"pixels":"00F8E0071F0001020304"}));
    let t = d.thumbnail(ID).unwrap();
    assert_eq!(t.rgba,[255,0,0,255,0,255,0,255,0,0,255,255]);
    assert!(rgb565_to_rgba(2,1,&[0,0]).is_err());
    assert!(state::decode_frame(1,1,"G000").is_err());
    answer(&d,json!({"returnValue":0,"width":1,"height":1,"pixels":""}));
    assert!(d.thumbnail(ID).is_err());
    d.runner.reply(info()); d.runner.error(invalid("The machine has no active display."));
    assert!(d.thumbnail(ID).unwrap_err().to_string().contains("no active display"));
}

#[test]
fn switch_helpers_select_only_the_project_network_id() {
    let mut d = driver(NetworkMode::Isolated);
    let n = net(NetworkMode::Isolated);
    d.runner.reply(json!({"guid":GUID,"created":true}));
    let receipt = d.ensure_switch(&n).unwrap();
    assert!(receipt.created);
    d.runner.reply(json!({"Name":"SVM-test","SwitchType":1,"Notes":"secwiz-switch:test"}));
    assert_eq!(d.list_our_switches().unwrap(),["SVM-test"]);
    d.runner.reply(json!({"ok":true}));
    d.remove_switch_if_same(&n,Some(&receipt.guid)).unwrap();
    assert_eq!(d.runner.calls.borrow()[2],json!({"op":"removeSwitch","networkId":"test","guid":GUID}));
}

#[test]
fn timeout_and_permission_errors_survive_trait_boundary() {
    let mut d = driver(NetworkMode::Routed);
    d.runner.reply(info());
    d.runner.error(EngineError::Timeout {seconds:120});
    assert_eq!(d.start(ID), Err(EngineError::Timeout {seconds:120}));
    let denied = runner::diagnostic("You do not have the required permission to complete this task.");
    assert!(matches!(&denied,EngineError::Permission(s) if s.contains("Hyper-V Administrators") && s.contains("Sign out")));
    d.runner.error(denied);
    assert!(matches!(d.state(ID),Err(EngineError::Permission(_))));
    assert!(matches!(runner::diagnostic("SVM_TPM_PERMISSION: access denied"),EngineError::Permission(s) if s.contains("virtual TPM without elevation")));
    // An unreadable differencing parent is reported by Hyper-V as an access problem.
    let chain = runner::diagnostic("SVM_PERMISSION: 'svm-test' failed to start. Failed to Power on with Error 'The chain of virtual hard disks is inaccessible. The process has not been granted access rights to the parent virtual hard disk for the differencing disk.'. 'Access is denied.' (0x80070005).");
    assert!(matches!(&chain,EngineError::Invalid(s) if s.contains("virtual disk chain") && !s.contains("Administrators")));
    assert_eq!(WindowsPowerShell::default().timeout().as_secs(),120);
}

#[cfg(not(windows))]
#[test]
fn real_runner_reports_windows_requirement() {
    let error = WindowsPowerShell::default().run(Script::Management,&json!({})).unwrap_err();
    assert!(error.to_string().contains("only on Windows"));
}

fn recordings() -> &'static Value {
    static DATA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("../tests/fixtures/hyperv.json")).unwrap())
}

#[test]
fn replay_recorded_machine_lifecycle_and_snapshot() {
    let f = recordings();
    let mut d = driver(NetworkMode::Routed);
    let mut vm = guest();
    vm.name = f["hostile-name"]["params"]["name"].as_str().unwrap().into();
    assert_eq!(f["hostile-name"]["stdout"]["ourVmStillThere"], true);
    d.runner.reply(f["define"]["stdout"].clone());
    d.define(&vm).unwrap();
    assert_eq!(d.runner.calls.borrow()[0]["displayName"], vm.name);
    for (capture, expected) in [
        ("define",VmState::Off), ("state-off",VmState::Off), ("start",VmState::Running),
        ("pause",VmState::Paused), ("resume",VmState::Running), ("revert",VmState::Running),
        ("stop-guest",VmState::Off), ("turnoff",VmState::Off),
    ] {
        let native = &f[capture]["stdout"];
        let mut owned = info();
        owned["state"] = native["State"].clone();
        owned["stateName"] = Value::Null;
        d.runner.reply(owned);
        assert_eq!(d.state(ID).unwrap(), expected, "{capture}");
    }
    // The proof's Notes and name used different suffixes. Keep that real negative case.
    let native = &f["define"]["stdout"];
    let actual_id = native["Name"].as_str().unwrap().strip_prefix("svm-").unwrap();
    let mut mismatched = info();
    mismatched["name"] = native["Name"].clone();
    mismatched["notes"] = native["Notes"].clone();
    d.runner.reply(mismatched);
    assert!(matches!(d.start(actual_id),Err(EngineError::Invalid(_))));

    let recorded = &f["snapshot-memory"]["stdout"];
    answer(&d, recorded.clone());
    let snap = d.snapshot(ID, recorded["Name"].as_str().unwrap(), true).unwrap();
    assert_eq!(snap.id, recorded["Id"].as_str().unwrap());
    assert!(snap.parent.is_none() && snap.with_memory);
    answer(&d,f["revert"]["stdout"].clone()); d.revert(ID,&snap.id).unwrap();
    answer(&d,f["snapshot-delete"]["stdout"].clone()); d.delete_snapshot(ID,&snap.id).unwrap();
    answer(&d,f["remove"]["stdout"].clone()); d.remove(ID).unwrap();
    let missing = &f["missing-vm"];
    assert_eq!(missing["exit"],3);
    d.runner.error(runner::diagnostic(&missing["stderr"].to_string()));
    assert!(matches!(d.state(ID),Err(EngineError::Missing(_))));
}

#[test]
fn replay_switch_shapes_without_adopting_a_foreign_switch() {
    let f = recordings();
    let mut d = driver(NetworkMode::Routed);
    d.runner.reply(f["switch-list"]["stdout"].clone());
    assert!(d.list_our_switches().unwrap().is_empty());
    let mut marked = f["switch-create"]["stdout"].clone();
    marked["Notes"] = json!("secwiz-switch:test");
    d.runner.reply(marked.clone());
    assert_eq!(d.list_our_switches().unwrap(), ["SVM-test"]);
    d.runner.reply(json!({"created":true,"guid":marked["Id"]}));
    let n = net(NetworkMode::Routed);
    let receipt = d.ensure_switch(&n).unwrap();
    d.runner.reply(f["switch-remove"]["stdout"].clone());
    d.remove_switch_if_same(&n,Some(&receipt.guid)).unwrap();
}

#[test]
fn replay_thumbnail_result_codes_and_measured_buffer_size() {
    let f = recordings();
    let mut d = driver(NetworkMode::Routed);
    let capture = &f["thumbnail"];
    let w = capture["params"]["w"].as_u64().unwrap() as u16;
    let h = capture["params"]["h"].as_u64().unwrap() as u16;
    let observed = &capture["stdout"];
    let bytes = observed["bytes"].as_u64().unwrap() as usize;
    assert_eq!(bytes,usize::from(w)*usize::from(h)*2+4);
    // The capture stored a prefix and size, not a full frame. Add synthetic remaining pixels.
    answer(&d,json!({"returnValue":observed["returnValue"],"width":w,"height":h,"pixels":"00".repeat(bytes)}));
    assert_eq!(d.thumbnail(ID).unwrap().rgba.len(),usize::from(w)*usize::from(h)*4);
    answer(&d,f["thumbnail-off"]["stdout"].clone());
    assert!(d.thumbnail(ID).unwrap_err().to_string().contains("no active display"));
}

#[test]
fn throwaway_start_pins_the_registration_and_refuses_ineligible_machines() {
    let d = driver(NetworkMode::Nat);
    let mut vm = guest();
    vm.throwaway = true;
    answer(&d, json!({"started":true}));
    let parents = [d.bundle(ID).unwrap().join("system.vhdx")];
    d.start_throwaway(&vm, &parents).unwrap();
    {
        let calls = d.runner.calls.borrow();
        assert_eq!(calls[0]["op"], "inspect");
        assert_eq!(calls[1]["op"], "throwawayStart");
        assert!(calls[1]["id"] == ID && calls[1]["guid"] == GUID && calls[1]["templateDisk"].is_null());
        assert_eq!(calls[1]["parents"], json!(parents));
        assert!(calls[1]["bundle"].as_str().is_some_and(|path| path.ends_with("unit.swvm")));
    }
    // Hyper-V has to confirm the start itself.
    answer(&d, json!({"started":false}));
    assert!(d.start_throwaway(&vm, &parents).is_err());

    let sent = d.runner.calls.borrow().len();
    let mut normal = vm.clone();
    normal.throwaway = false;
    let mut running = vm.clone();
    running.state = VmState::Running;
    let mut sealed = vm.clone();
    sealed.tpm = Some(true);
    let mut other_engine = vm.clone();
    other_engine.engine = EngineKind::Qemu;
    for refused in [normal, running, sealed, other_engine] {
        assert!(matches!(d.start_throwaway(&refused, &parents), Err(EngineError::Invalid(_))));
    }
    assert_eq!(d.runner.calls.borrow().len(), sent, "an ineligible machine never reaches PowerShell");
}

#[test]
fn throwaway_base_is_read_only_while_the_mode_is_on_and_after_recovery() {
    let mut d = driver(NetworkMode::Nat);
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let bundle = std::env::temp_dir().join(format!("svm-throwaway-base-{}-{unique}.swvm", std::process::id()));
    std::fs::create_dir(&bundle).unwrap();
    let base = bundle.join("system.vhdx");
    std::fs::write(&base, b"persistent").unwrap();
    d.register_bundle(ID, &bundle).unwrap();
    let read_only = |path: &Path| std::fs::metadata(path).unwrap().permissions().readonly();

    d.protect_throwaway_base(ID, true).unwrap();
    assert!(read_only(&base));
    assert!(bundle.join("throwaway-protected.json").is_file(), "throwaway mode records that it owns the flag");
    d.protect_throwaway_base(ID, true).unwrap();
    assert!(read_only(&base), "repeating is harmless");
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let held = std::fs::OpenOptions::new().read(true).share_mode(0).open(bundle.join("throwaway-protected.json")).unwrap();
        assert!(d.protect_throwaway_base(ID, false).is_err(), "an unreadable record is an error, never a guess");
        assert!(read_only(&base));
        drop(held);
    }

    // The script lifts the flag only for the reattach. If it dies there, the driver puts it back.
    std::fs::write(bundle.join("hyperv-throwaway.json"), b"{}").unwrap();
    d.protect_throwaway_base(ID, false).unwrap();
    d.runner.reply(info());
    d.runner.error(invalid("Fixture recovery failure."));
    assert!(d.recover_throwaway(ID).is_err());
    assert!(read_only(&base), "a failed recovery leaves the base protected");
    answer(&d, json!({"recovered":true}));
    assert_eq!(d.recover_throwaway(ID), Ok(true));
    assert!(read_only(&base));

    d.protect_throwaway_base(ID, false).unwrap();
    assert!(!read_only(&base));
    assert!(!bundle.join("throwaway-protected.json").exists());
    assert_eq!(std::fs::read(&base).unwrap(), b"persistent");

    // A flag that throwaway mode never set is left alone in both directions.
    let mut user = std::fs::metadata(&base).unwrap().permissions();
    user.set_readonly(true);
    std::fs::set_permissions(&base, user.clone()).unwrap();
    d.protect_throwaway_base(ID, true).unwrap();
    assert!(!bundle.join("throwaway-protected.json").exists(), "an already read-only disk is not taken over");
    d.protect_throwaway_base(ID, false).unwrap();
    assert!(read_only(&base), "a read-only flag the mode did not set is never lifted");
    std::fs::write(bundle.join("throwaway-protected.json"), b"\"another-machine\"").unwrap();
    d.protect_throwaway_base(ID, false).unwrap();
    assert!(read_only(&base), "a stale record from another machine does not grant ownership");
    std::fs::remove_file(bundle.join("throwaway-protected.json")).unwrap();
    user.set_readonly(false);
    std::fs::set_permissions(&base, user).unwrap();
    std::fs::remove_dir_all(bundle).unwrap();
}

#[test]
fn throwaway_disk_check_asks_hyper_v_for_the_only_attachment() {
    let d = driver(NetworkMode::Nat);
    answer(&d, json!({"ok":true}));
    assert_eq!(d.verify_throwaway_disk(ID), Ok(()));
    {
        let calls = d.runner.calls.borrow();
        assert_eq!(calls[1]["op"], "throwawayDisk");
        assert_eq!(calls[1]["bundle"], json!(d.bundle(ID).unwrap()));
    }
    d.runner.reply(info());
    d.runner.error(invalid("Throwaway mode needs the bundle system.vhdx as the only disk."));
    assert!(d.verify_throwaway_disk(ID).is_err());
}

#[test]
fn throwaway_recovery_runs_only_when_a_record_exists() {
    let mut d = driver(NetworkMode::Nat);
    assert_eq!(d.recover_throwaway(ID), Ok(false));
    assert!(d.runner.calls.borrow().is_empty(), "no record means no PowerShell call");

    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let bundle = std::env::temp_dir().join(format!("svm-throwaway-unit-{}-{unique}.swvm", std::process::id()));
    std::fs::create_dir(&bundle).unwrap();
    std::fs::write(bundle.join("hyperv-throwaway.json"), b"{}").unwrap();
    std::fs::write(bundle.join("system.vhdx"), b"persistent").unwrap();
    d.register_bundle(ID, &bundle).unwrap();
    answer(&d, json!({"recovered":true}));
    assert_eq!(d.recover_throwaway(ID), Ok(true));
    answer(&d, json!({"recovered":false}));
    assert_eq!(d.recover_throwaway(ID), Ok(false));
    {
        let calls = d.runner.calls.borrow();
        assert_eq!(calls[1]["op"], "throwawayRecover");
        assert!(calls[1]["id"] == ID && calls[1]["guid"] == GUID);
    }
    let mut writable = std::fs::metadata(bundle.join("system.vhdx")).unwrap().permissions();
    writable.set_readonly(false);
    std::fs::set_permissions(bundle.join("system.vhdx"), writable).unwrap();
    std::fs::remove_dir_all(bundle).unwrap();
}

#[cfg(windows)]
#[test]
fn throwaway_disk_swap_restores_and_rolls_back() {
    run_control_fixture(include_str!("../tests/throwaway_controls.ps1"), "SVM_THROWAWAY_SOURCE", concat!(env!("CARGO_MANIFEST_DIR"), "/src/throwaway.ps1"));
}

#[cfg(windows)]
#[test]
fn chain_access_grants_only_on_listed_parents_inside_the_library() {
    let fixture = format!("{}\n{}", scripts::FIXTURE_PATHS, include_str!("../tests/chain_access_controls.ps1"));
    run_control_fixture(&fixture, "SVM_CHAIN_SOURCE", concat!(env!("CARGO_MANIFEST_DIR"), "/src/chain_access.ps1"));
}

#[test]
fn fixed_commands_fit_windows_and_use_distinct_encodings() {
    assert_eq!(runner::base64("é".as_bytes()),"w6k=");
    let wide: Vec<u8> = "é".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(runner::base64(&wide),"6QA=");
    for script in [Script::Trash,Script::Definition,Script::LinkedDisk,Script::Throwaway,Script::Management,Script::Checkpoint,Script::Service,Script::Bridge,Script::Storage,Script::Guest,Script::FileGuestService,Script::GuestCopy,Script::GuestExec,Script::GuestUpload,Script::InstallerBoot,Script::Host] {
        let bytes: Vec<u8> = script.source().encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = runner::base64(&bytes).len();
        if matches!(script, Script::Management | Script::Throwaway) { println!("{script:?}: {encoded} encoded characters"); }
        assert!(encoded < 31000, "{script:?} exceeds the command limit");
        if matches!(script, Script::GuestExec | Script::GuestUpload) {
            assert!(script.source().contains("[Console]::In.ReadToEnd()"));
            assert!(!script.source().contains("$env:SVM_PARAMS"));
        } else {
            assert!(script.source().contains("$env:SVM_PARAMS"));
        }
        assert!(!script.source().contains(DISPLAY));
    }
}


#[test]
fn retained_restore_uses_the_bundle_and_long_deadline() {
    let d=driver(NetworkMode::Nat);
    d.runner.reply(json!(false));
    assert!(!d.restored_registration(ID).unwrap());
    d.runner.reply(json!({"ok":true}));
    d.import_retained(ID,"retained/fixture").unwrap();
    let calls=d.runner.calls.borrow();
    assert_eq!(calls[1]["bundle"],calls[0]["bundle"]);
    assert_eq!(calls[1]["retained"],"retained/fixture");
    assert_eq!(d.runner.retained_calls.get(),1);
}

#[test]
fn retained_copy_cannot_be_disabled_by_a_caller() {
    let d=driver(NetworkMode::Nat);
    let plan=RemovalPlan {guid:GUID.into(),stamp:"Saved|False|".into(),required:true};
    d.runner.reply(json!({"id":ID,"retained":"retained/fixture","bytes":123}));
    let receipt=d.finish_removal(ID,&plan,false).unwrap();
    assert_eq!(receipt.bytes,Some(123));
    let calls=d.runner.calls.borrow();
    assert_eq!(calls[0]["keepCopy"],true);
    assert_eq!(calls[0]["guid"],GUID);
    assert_eq!(calls[0]["stamp"],plan.stamp);
    assert_eq!(d.runner.retained_calls.get(),1);
}

#[test]
fn powered_off_guest_without_protected_data_uses_normal_deadline() {
    let d=driver(NetworkMode::Nat);
    answer(&d,json!({"guid":GUID,"stamp":"Off|False|","required":false}));
    let plan=d.removal_plan(ID).unwrap();
    d.runner.reply(json!({"id":ID,"retained":null,"bytes":null}));
    let receipt=d.finish_removal(ID,&plan,false).unwrap();
    assert!(receipt.retained.is_none());
    assert_eq!(d.runner.retained_calls.get(),0);
}

// Found by the live service test: a successful script that uses auto-loaded networking cmdlets still
// writes CLIXML progress records to stderr. The shapes below match what Windows PowerShell 5.1 produces.
#[test]
fn progress_only_stderr_is_not_a_failure_but_real_errors_are() {
    let progress = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">\
<Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T></TN>\
<MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\"><AV>Preparing modules for first use.</AV></PR></MS></Obj>\
<Obj S=\"progress\" RefId=\"1\"><TNRef RefId=\"0\" /><MS><I64 N=\"SourceId\">2</I64></MS></Obj></Objs>";
    assert!(runner::only_progress(progress));
    assert!(runner::only_progress(&format!("\u{feff}  {progress}\r\n")));

    let with_error = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">\
<Obj S=\"progress\" RefId=\"0\"><MS><I64 N=\"SourceId\">1</I64></MS></Obj>\
<S S=\"Error\">Get-VM : Hyper-V was unable to find a virtual machine with name \"x\"._x000D__x000A_</S></Objs>";
    // An error line is an <S S="Error"> element, not a progress object. Mixed with progress it is still a failure.
    assert!(!runner::only_progress(with_error));
    assert!(!runner::only_progress("#< CLIXML\r\n<Objs><S S=\"warning\">careful</S></Objs>"));
    assert!(!runner::only_progress("#< CLIXML\r\n<Objs><Obj S=\"Error\" RefId=\"0\"></Obj></Objs>"));
    assert!(!runner::only_progress("plain text on stderr"));
    assert!(!runner::only_progress(""));
    assert!(!runner::only_progress("#< CLIXML\r\n<Objs></Objs>"));
    assert!(!runner::only_progress("{\"error\":\"boom\",\"id\":\"X\"}"));

    let plain = runner::plain_stderr(with_error);
    assert!(plain.contains("Hyper-V was unable to find a virtual machine"), "{plain}");
    assert!(!plain.contains('<') && !plain.contains("CLIXML") && !plain.contains("_x000D_"), "{plain}");
    assert_eq!(runner::plain_stderr("  already plain  "), "already plain");
    assert!(matches!(runner::diagnostic(&plain), EngineError::Missing(_)));
}

#[test]
fn console_uses_only_a_valid_owned_hyperv_registration_guid() {
    let driver = driver(NetworkMode::Nat);
    driver.runner.reply(info());
    assert_eq!(driver.console_guid(ID).unwrap(), GUID);
    for (key, value) in [("notes", "other"), ("guid", "invalid-viewer-argument"), ("guid", "00000000-0000-0000-0000-000000000000")] {
        let mut invalid = info();
        invalid[key] = json!(value);
        driver.runner.reply(invalid);
        assert!(driver.console_guid(ID).is_err());
    }
    assert!(driver.runner.calls.borrow().iter().all(|r| r["op"] == "inspect"));
}

#[cfg(windows)]
#[test]
fn installer_window_requires_the_original_blank_disk_and_consumes_first_start() {
    run_control_fixture(include_str!("../tests/installer_controls.ps1"), "SVM_INSTALLER_SOURCE", concat!(env!("CARGO_MANIFEST_DIR"), "/src/installer_boot.ps1"));
}

#[cfg(windows)]
#[test]
fn storage_controls_confirm_native_boot_order_and_empty_media() {
    run_control_fixture(include_str!("../tests/storage_controls.ps1"), "SVM_STORAGE_SOURCE", concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage.ps1"));
}

#[cfg(windows)]
#[test]
fn bridge_discovery_collects_every_refusal_and_preserves_existing_switches() {
    run_control_fixture(include_str!("../tests/bridge_controls.ps1"), "SVM_BRIDGE_SOURCE", concat!(env!("CARGO_MANIFEST_DIR"), "/src/bridge.ps1"));
}

#[cfg(windows)]
fn run_control_fixture(script: &str, variable: &str, source: &str) {
    use std::os::windows::process::CommandExt;
    let root = std::env::var_os("SystemRoot").expect("Windows system directory");
    let powershell = std::path::PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    // A file rather than -EncodedCommand: a fixture may outgrow Windows' 32,767-character command line.
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let file = std::env::temp_dir().join(format!("svm-fixture-{}-{unique}.ps1", std::process::id()));
    // Windows PowerShell 5.1 reads a file without a byte-order mark as ANSI.
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(script.as_bytes());
    std::fs::write(&file, bytes).expect("write the control fixture");
    let output = std::process::Command::new(powershell)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&file)
        .env(variable, source)
        .creation_flags(0x08000000)
        .output();
    let _ = std::fs::remove_file(&file);
    let output = output.expect("run fixture with mocked Hyper-V commands");
    assert!(output.status.success(), "{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

#[test]
fn storage_verifies_in_fresh_runner_calls_without_repeating_the_mutation() {
    let d = driver(NetworkMode::Nat);
    let confirmed = json!({"isoPath":null,"bootFirst":"disk"});
    answer(&d, json!(true));
    d.runner.reply(json!({"confirmed":false,"storage":{"isoPath":"old.iso"}}));
    d.runner.reply(json!({"confirmed":true,"storage":confirmed}));
    assert_eq!(d.set_storage(ID, "isoPath", &Value::Null).unwrap(), confirmed);
    let calls = d.runner.calls.borrow();
    let ops: Vec<_> = calls.iter().map(|p| p["op"].as_str().unwrap()).collect();
    assert_eq!(ops, ["inspect", "setStorage", "confirmStorage", "confirmStorage"]);
    assert!(calls[1..].iter().all(|p| p["guid"] == GUID && p["id"] == ID && p["value"].is_null()));
}

#[test]
fn storage_preserves_setter_errors_and_refuses_unconfirmed_native_state() {
    let d = driver(NetworkMode::Nat);
    d.runner.reply(info());
    d.runner.error(invalid("Native setter refused."));
    assert!(d.set_storage(ID, "bootFirst", &json!("disk")).unwrap_err().to_string().contains("Native setter refused."));
    assert_eq!(d.runner.calls.borrow().len(), 2);

    answer(&d, json!(true));
    for _ in 0..3 { d.runner.reply(json!({"confirmed":false,"storage":{"bootFirst":"image"}})); }
    let error = d.set_storage(ID, "bootFirst", &json!("disk")).unwrap_err().to_string();
    assert!(error.contains("did not confirm the selected first boot device"), "{error}");
    let calls = d.runner.calls.borrow();
    assert_eq!(calls[2..].iter().filter(|p| p["op"] == "setStorage").count(), 1);
    assert_eq!(calls[2..].iter().filter(|p| p["op"] == "confirmStorage").count(), 3);
}

#[test]
fn graceful_timeout_does_not_force_off_or_repeat_the_guest_request() {
    let mut d=driver(NetworkMode::Nat);
    answer(&d,json!({"power":"timeout"}));
    assert_eq!(d.shutdown(ID),Err(EngineError::GuestPowerTimeout));
    let calls=d.runner.calls.borrow();
    assert_eq!(calls.len(),2);
    assert_eq!(calls[1],json!({"op":"shutdown","id":ID,"guid":GUID}));
}

#[test]
fn us_text_maps_every_printable_character_and_keeps_confirmed_partial_counts() {
    for c in 32u8..=126 {
        let text=char::from(c).to_string();
        assert_eq!(GuestKeys::from_text(&text).unwrap().strokes().len(),1);
    }
    let keys=GuestKeys::from_text_with_enter("aA/?-!~",true).unwrap();
    let strokes: Vec<_>=keys.strokes().iter().map(|s|(s.code,s.shift)).collect();
    assert_eq!(strokes,[(65,false),(65,true),(191,false),(191,true),(189,false),(49,true),(192,true),(13,false)]);
    let mut d=driver(NetworkMode::Nat);
    answer(&d,json!({"sent":2,"retried":true,"error":"Keyboard did not become ready."}));
    let result=d.send_keys(ID,&keys).unwrap();
    assert_eq!(result.sent,2);
    assert!(result.retried && result.error.is_some());
    answer(&d,json!({"sent":2,"retried":false,"error":null}));
    assert!(d.send_keys(ID,&keys).is_err());
}

#[test]
fn file_guest_service_reads_and_changes_only_the_verified_registration() {
    let driver = driver(NetworkMode::Nat);
    let vm = guest();
    answer(&driver, json!({"available":true,"enabled":false,"canChange":true}));
    assert_eq!(driver.file_guest_service(&vm, None).unwrap()["enabled"], false);
    answer(&driver, json!({"available":true,"enabled":true,"canChange":true}));
    assert_eq!(driver.file_guest_service(&vm, Some(true)).unwrap()["enabled"], true);
    let calls = driver.runner.calls.borrow();
    assert_eq!(calls[1], json!({"op":"fileGuestService","id":ID,"guid":GUID}));
    assert_eq!(calls[3], json!({"op":"setFileGuestService","id":ID,"guid":GUID,"enabled":true}));
}

#[test]
fn guest_integration_and_keyboard_advertise_their_own_native_status() {
    let d=driver(NetworkMode::Nat);
    answer(&d,json!({"powerReason":"No contact with the guest service.","keyReason":null}));
    let caps=d.capabilities(&guest());
    for op in [Capability::Shutdown,Capability::Restart] {
        assert!(!caps.has(op));
        assert_eq!(caps.reason(op),Some("No contact with the guest service."));
    }
    assert!(caps.has(Capability::SendKeys));
    assert!(caps.has(Capability::Stop));
}

#[test]
fn enhanced_session_uses_native_state_and_preserves_vmconnect() {
    for (state, reason) in [
        (Some(2), None),
        (Some(3), Some("Hyper-V does not allow Enhanced Session for this machine.")),
        (Some(6), Some("Enhanced Session is currently unavailable in this guest.")),
        (Some(99), Some("Hyper-V could not confirm this guest’s Enhanced Session availability.")),
        (None, Some("Hyper-V could not confirm this guest’s Enhanced Session availability.")),
    ] {
        let d = driver(NetworkMode::Nat);
        let mut reply = json!({"powerReason":null,"keyReason":null});
        if let Some(state) = state { reply["enhancedSessionModeState"] = json!(state); }
        answer(&d, reply);
        let caps = d.capabilities(&guest());
        assert_eq!(caps.has(Capability::EnhancedSession), reason.is_none());
        assert_eq!(caps.reason(Capability::EnhancedSession), reason);
        assert!(caps.has(Capability::Console));
        assert_eq!(d.runner.calls.borrow()[1], json!({"op":"guestStatus","id":ID,"guid":GUID}));
    }

    let d = driver(NetworkMode::Nat);
    let mut off = info();
    off["state"] = json!(3);
    off["stateName"] = json!("Off");
    d.runner.reply(off);
    let caps = d.capabilities(&guest());
    assert_eq!(caps.reason(Capability::EnhancedSession), Some("Start or resume this guest to check Enhanced Session."));
    assert!(caps.has(Capability::Console));
    assert_eq!(d.runner.calls.borrow().len(), 1);
}

#[cfg(windows)]
#[test]
fn guest_controls_use_native_non_forced_methods_and_individual_virtual_keys() {
    use std::os::windows::process::CommandExt;
    let root = std::env::var_os("SystemRoot").expect("Windows system directory");
    let powershell = std::path::PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let fixture: Vec<u8> = include_str!("../tests/guest_controls.ps1")
        .encode_utf16().flat_map(u16::to_le_bytes).collect();
    let output = std::process::Command::new(powershell)
        .args(["-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand"]).arg(runner::base64(&fixture))
        .env("SVM_GUEST_SOURCE",concat!(env!("CARGO_MANIFEST_DIR"),"/src/guest.ps1"))
        .creation_flags(0x08000000).output().expect("run guest commands against isolated CIM fixtures");
    assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
    let ready:Value=serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(ready,json!({"powerReason":null,"keyReason":null,"enhancedSessionModeState":null}));
}

#[test]
fn observed_guest_addresses_are_ipv4_values_from_the_registered_external_guest() {
    let vm = guest();
    for mode in [NetworkMode::Nat, NetworkMode::Bridged, NetworkMode::Routed] {
        let d = driver(mode);
        let mut record = info();
        record["addresses"] = json!(["fe80::1", "not an address", "127.0.0.1", "255.255.255.255", "239.1.1.1", "169.254.2.3", "172.20.1.8"]);
        d.runner.reply(record.clone());
        let expected = if mode == NetworkMode::Routed { None } else { Some(std::net::Ipv4Addr::new(172,20,1,8)) };
        assert_eq!(d.observe_guest(&vm).unwrap(), (VmState::Running, expected));
        assert_eq!(d.runner.calls.borrow()[0]["addressMac"].as_str(), expected.map(|_| "027700000001"));
        record["state"] = json!(3);
        record["stateName"] = json!("Off");
        d.runner.reply(record);
        assert_eq!(d.observe_guest(&vm).unwrap(), (VmState::Off, None));
    }
}

#[test]
fn removal_receipt_is_flushed_and_closed_before_publish() {
    let (_, removal) = Script::Service.source().split_once("function RemoveOwned").unwrap();
    let (removal, _) = removal.split_once("function CopyDisk").unwrap();
    let write = removal.find("$stream.Write($bytes,0,$bytes.Length)").unwrap();
    let flush = removal.find("$stream.Flush($true)").unwrap();
    let close = removal.find("$stream.Dispose()").unwrap();
    let publish = removal.find("[IO.File]::Replace($temp,$marker,$null)").unwrap();
    assert!(write < flush && flush < close && close < publish);
}
