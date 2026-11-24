#![cfg(windows)]
#![deny(warnings)]
#![forbid(unsafe_code)]

use std::{error::Error, fs, io, path::{Path, PathBuf}, process::Command,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, thread, time::{Duration, Instant}};
use serde_json::{json, Value};
use svm::client::Client;
use svm_core::engine::FakeEngine;
use svmd::{Service, networks::FakeSwitches};

#[path = "support/vhdx.rs"]
mod vhdx;
use vhdx::standalone as sample_disk;

type Result<T> = std::result::Result<T,Box<dyn Error>>;
const SOURCE: &str = "backup-source";
const SNAP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
struct Fixture { stop: Arc<AtomicBool>, thread: Option<thread::JoinHandle<std::result::Result<(),svmd::ApiError>>>, client: Client }
impl Fixture {
    fn open(home: &Path) -> Result<Self> { Self::with_engine(home,FakeEngine::default()) }
    fn with_engine(home: &Path,engine:FakeEngine) -> Result<Self> {
        let svc = Service::open_with_supervisor(home, 0, Box::new(engine), Box::<FakeSwitches>::default(), Path::new(env!("CARGO_BIN_EXE_svmd")))?;
        let client = Client::load(home,None)?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        Ok(Self {client, stop, thread:Some(thread::spawn(move||svc.run(flag)))})
    }
    fn call(&self, method:&str, path:&str, body:Value, status:u16) -> Result<Value> {
        let res = self.client.request_with_timeout(method,path,(!body.is_null()).then_some(&body),Duration::from_secs(60))?;
        let v:Value = serde_json::from_slice(&res.body)?;
        if res.status!=status { return Err(io::Error::other(format!("{method} {path} expected {status}, got {} ({})",res.status,v["error"]["message"])).into()); }
        Ok(v)
    }
    fn get(&self,path:&str)->Result<Value> { self.call("GET",path,Value::Null,200) }
    fn prompt_ready(&self)->Result<()> {
        let deadline=Instant::now()+Duration::from_secs(10);
        while self.get("/v1/backups")?["cooldownSeconds"].as_u64().unwrap_or(0)>0 {
            if Instant::now()>=deadline {return Err("Prompt cooldown did not finish.".into());}
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }
    fn wait(&self)->Result<Value> {
        let deadline = Instant::now()+Duration::from_secs(65);
        loop {
            let state = self.get("/v1/backups")?;
            if state["current"].is_null() {return Ok(state["last"].clone());}
            if Instant::now()>deadline {return Err("Backup task timed out".into());}
            thread::sleep(Duration::from_millis(100));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {self.stop.store(true,Ordering::Release); if let Some(t)=self.thread.take(){let _=t.join();}}
}
fn build_tools(folder:&Path)->Result<()> {
    let bin=folder.join("restic.exe");
    let source=Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_backup.rs");
    let built=Command::new(std::env::var_os("RUSTC").unwrap_or_else(||"rustc".into())).args(["--edition=2021","-C","debuginfo=0","-C","codegen-units=1"])
        .arg(source).arg("-o").arg(&bin).current_dir(folder).output()?;
    if !built.status.success(){return Err(io::Error::other(String::from_utf8_lossy(&built.stderr)).into());}
    for name in ["age.exe","age-plugin-yubikey.exe"] {fs::copy(&bin,folder.join(name))?;}
    Ok(())
}
fn new_root()->Result<PathBuf>{
    let temp=std::env::temp_dir().canonicalize()?;
    let nonce=getrandom::u64()?;
    let root=temp.join(format!("svm-backup-test-{nonce:x}"));
    fs::create_dir(&root)?;
    Ok(root)
}
fn qemu_roundtrips(server:&Fixture, root:&Path, home:&Path)->Result<()> {
    let folder=root.join("simulated qemu");fs::create_dir(&folder)?;
    let exe=folder.join("qemu-system-x86_64.exe");
    let src=Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_qemu.rs");
    let built=Command::new(std::env::var_os("RUSTC").unwrap_or_else(||"rustc".into())).args(["--edition=2021","-C","debuginfo=0","-C","codegen-units=1"]).arg(src).arg("-o").arg(&exe).current_dir(&folder).output()?;
    if !built.status.success(){return Err("Simulated QEMU did not compile.".into());}
    for file in ["qemu-img.exe","qemu-system-aarch64.exe"] {fs::copy(&exe,folder.join(file))?;}
    let fw=folder.join("share");fs::create_dir(&fw)?;
    for file in ["edk2-arm-vars.fd","edk2-aarch64-code.fd"] {
        fs::File::create_new(fw.join(file))?.set_len(64<<20)?;
    }
    assert_eq!(server.call("PUT","/v1/settings/qemu",json!({"path":exe}),200)?["armAvailable"],true);
    let iso=root.join("fixture.iso");fs::write(&iso,b"fake media")?;
    for (id,arch) in [("restore-pc","x86_64"),("restore-arm","aarch64"),("restore-bios","x86_64")] {
        let request=if id=="restore-bios" { json!({"id":id,"name":id,"catalogId":"windows-xp","isoPath":iso}) }
            else {json!({"id":id,"name":id,"engine":"QEMU","family":"linux","architecture":arch,"diskGb":1})};
        let mut request=request;
        if id=="restore-pc" { request["isoPath"]=json!(iso); }
        let original=server.call("POST","/v1/machines",request,201)?;
        if id=="restore-pc" {
            let route=format!("/v1/machines/{id}");
            let changed=server.call("PATCH",&route,json!({"shareClipboard":true,"portForwards":[{"protocol":"tcp","hostPort":32222,"guestPort":2222}],"throwaway":true,"isolated":false}),200)?;
            assert_eq!(changed["shareClipboard"],true);assert_eq!(changed["throwaway"],true);
            assert_eq!(changed["portForwards"].as_array().unwrap().len(),1);assert!(original["isoPath"].is_string());
        }
        let isolated=id!="restore-pc";
        if isolated { server.call("PATCH",&format!("/v1/machines/{id}"),json!({"isolated":true}),200)?; }
        server.call("POST","/v1/backups",json!({"machineId":id}),202)?;
        let result=server.wait()?;assert_eq!(result["state"],"completed","{result}");
        server.call("POST","/v1/backups/restore",json!({"snapshotId":SNAP,"name":format!("{id} copy")}),202)?;
        let result=server.wait()?;assert_eq!(result["state"],"completed","{result}");
        let new_id=result["newId"].as_str().ok_or("Missing restored machine id")?;
        let restored=server.get(&format!("/v1/machines/{new_id}"))?;
        assert_ne!(restored["mac"],original["mac"]);assert_eq!(restored["registration"],"registered");assert_eq!(restored["architecture"],arch);assert_eq!(restored["isolated"],isolated);
        assert_eq!(restored["net"],"nat");assert_eq!(restored["shareClipboard"],false);assert_eq!(restored["throwaway"],false);
        assert_eq!(restored["portForwards"],json!([]));assert!(restored["isoPath"].is_null());
        let bundle=home.join("library").join(format!("{new_id}.swvm"));
        let def:Value=serde_json::from_slice(&fs::read(bundle.join("qemu-vm.json"))?)?;assert_eq!(def["id"],new_id);assert_eq!(def["legacy_windows"],id=="restore-bios");
        assert_eq!(bundle.join("uefi-vars.fd").exists(),arch=="aarch64");assert!(!bundle.join("qemu-run.json").exists());
    }
    Ok(())
}
fn restore_into_empty_library(root: &Path, settings: &Value, source: &Value) -> Result<()> {
    let destination = Fixture::open(&root.join("fresh-destination"))?;
    assert_eq!(destination.get("/v1/machines")?, json!([]));
    destination.call("POST", "/v1/networks", json!({"id":"closed","name":"Closed","mode":"Isolated segment"}), 201)?;
    destination.call("PUT", "/v1/settings/backup", settings.clone(), 200)?;
    destination.call("POST", "/v1/backups/refresh", json!({}), 202)?;
    assert_eq!(destination.wait()?["state"], "completed");
    // This distinct display name normally gets the same DNS label as "Backup fixture".
    let name = "Backup-fixture";
    destination.call("POST", "/v1/backups/restore", json!({"snapshotId":SNAP,"name":name}), 202)?;
    let job = destination.wait()?;
    assert_eq!(job["state"], "completed", "{job}");
    let id = job["newId"].as_str().ok_or("Missing restored ID")?;
    let restored = destination.get(&format!("/v1/machines/{id}"))?;
    assert_eq!(restored["name"], name);
    assert_eq!(restored["registration"], "registered");
    for field in ["mac", "ip", "dns", "id", "name"] {
        assert_ne!(restored[field], source[field], "empty-library restore reused {field}");
    }
    Ok(())
}

fn exercise(root:&Path)->Result<()> {
    let home=root.join("service"); let repo=root.join("backup repo"); let tools=root.join("verified tools");
    for dir in [&home,&repo,&tools] {fs::create_dir(dir)?;}
    build_tools(&tools)?;
    let credentials=root.join("credentials");fs::create_dir(&credentials)?;
    let identity=credentials.join("identity fixture.txt"); let cipher=credentials.join("simulated ciphertext.age");
    for name in ["age-plugin-yubikey.com","winscard.dll"] {fs::write(tools.join(name),b"inert test data")?;}
    fs::write(&identity,"AGE-PLUGIN-YUBIKEY-1FIXTURE")?;
    let canary=format!("{:016x}{:016x}",getrandom::u64()?,getrandom::u64()?);
    fs::write(&cipher,&canary)?;
    let server=Fixture::open(&home)?;
    let settings=json!({"tools":tools,"repository":repo,"identity":identity,"encryptedPassword":cipher});
    for path in [home.clone(),home.join("library"),root.to_owned(),PathBuf::from(r"\\server\share")] {
        let mut bad=settings.clone();bad["repository"]=json!(path);
        let r=server.client.request("PUT","/v1/settings/backup",Some(&bad))?;
        assert!((400..500).contains(&r.status), "invalid repository accepted or internal error");
    }
    assert_eq!(server.get("/v1/settings/backup")?["configured"],false);
    let saved=server.call("PUT","/v1/settings/backup",settings.clone(),200)?;
    assert_eq!(saved["hashes"].as_object().unwrap().len(),3);
    assert_eq!(server.get("/v1/settings/backup")?["hashes"],saved["hashes"]);
    let private_tools=fs::read_dir(&home)?.filter_map(|e|e.ok()).find(|e|e.file_name().to_string_lossy().starts_with("backup-tools-")).ok_or("Missing private tool copy")?.path();
    assert_eq!(fs::read_dir(&private_tools)?.count(),3);
    let private = svm_qemu::LocalFolder::hold(&private_tools)?;
    private.verify_private()?;
    drop(private);
    let service_home = svm_qemu::LocalFolder::hold(&home)?;
    let interrupted_tools = service_home.create_private_child(".backup-install-vm-1234-a-2")?;
    fs::write(interrupted_tools.path.join("restic.exe"), b"inert partial copy")?;
    let orphan_tools = interrupted_tools.path.clone();
    assert!(service_home.create_private_child(".backup-install-vm-1234-a-2").is_err());
    drop(interrupted_tools);
    let unrelated = home.join(".backup-install-personal");fs::create_dir(&unrelated)?;
    let source_tool = tools.join("restic.exe");
    let original_bytes = fs::read(&source_tool)?;
    use std::io::Write;
    fs::OpenOptions::new().append(true).open(&source_tool)?.write_all(b"test tool rotation")?;
    let changed = server.call("PUT","/v1/settings/backup",settings.clone(),200)?;
    assert_ne!(changed["hashes"],saved["hashes"]);
    assert!(!private_tools.exists());assert!(!orphan_tools.exists());assert!(unrelated.is_dir());
    fs::write(&source_tool,original_bytes)?;
    server.call("PUT","/v1/settings/backup",settings.clone(),200)?;
    assert_eq!(fs::read_dir(&home)?.filter_map(|e|e.ok()).filter(|e|e.file_name().to_string_lossy().starts_with("backup-tools-")).count(),1);
    assert!(private_tools.is_dir());drop(service_home);
    for name in ["age-plugin-yubikey.com","winscard.dll"] {assert!(!private_tools.join(name).exists());}
    server.call("POST","/v1/networks",json!({"id":"closed","name":"Closed","mode":"Isolated segment"}),201)?;
    let original=server.call("POST","/v1/machines",json!({"id":SOURCE,"name":"Backup fixture","family":"linux","diskGb":2,"net":"closed"}),201)?;
    let bundle=home.join("library").join(format!("{SOURCE}.swvm"));
    let disk=sample_disk();fs::write(bundle.join("system.vhdx"),&disk)?;
    let backup=json!({"machineId":SOURCE});
    let start=format!("/v1/machines/{SOURCE}/start"); let stop=format!("/v1/machines/{SOURCE}/stop");
    server.call("POST",&start,json!({}),200)?;
    server.call("POST","/v1/backups",backup.clone(),409)?;
    server.call("POST",&stop,json!({}),200)?;
    let stale=bundle.join("hyperv-throwaway.json");fs::write(&stale,"{}")?;
    server.call("POST","/v1/backups",backup.clone(),409)?;fs::remove_file(stale)?;
    fs::write(repo.join("wait"),"")?;
    server.call("POST","/v1/backups",backup.clone(),202)?;
    server.call("POST",&start,json!({}),409)?;
    server.call("PUT","/v1/settings/backup",settings.clone(),409)?;
    fs::remove_file(repo.join("wait"))?;
    let result=server.wait()?;assert_eq!(result["state"],"completed","{result}");assert_eq!(result["exitCode"],0);
    let args=fs::read_to_string(repo.join("arguments"))?;
    let lines:Vec<_>=args.lines().collect();
    let path_text=|p:&Path|p.to_string_lossy().trim_start_matches(r"\\?\").replace('\\',"/");
    let password_command=format!("\"{}\" -d -i \"{}\" \"{}\"",path_text(&private_tools.join("age.exe")),path_text(&identity),path_text(&cipher));
    assert_eq!(lines[0],"--repo"); assert!(lines[1].starts_with("local:"));assert_eq!(lines[2],"--password-command");
    assert!(lines[3]==password_command);
    assert_eq!(&lines[4..13],["--no-cache","--json","backup","--read-concurrency","1","--tag","secwiz-vm","--tag","machine:backup-source"]);
    assert_eq!(lines.last(),Some(&"."));
    for exclude in ["*.tmp","*.lock",".throwaway-*",".ga*","qemu-run.json","hyperv-throwaway.json"] {assert!(lines[13..].windows(2).any(|p|p==["--iexclude",exclude]));}
    let environment=fs::read_to_string(repo.join("environment"))?;
    assert!(environment.lines().all(|k| ["GOMAXPROCS","NODEFAULTCURRENTDIRECTORYINEXEPATH","PATH","PATHEXT","SYSTEMROOT","TEMP","TMP","WINDIR"].contains(&k.to_ascii_uppercase().as_str())));
    server.call("POST","/v1/backups/refresh",json!({}),202)?; assert_eq!(server.wait()?["state"],"completed");
    assert!(fs::read_to_string(repo.join("arguments"))?.ends_with("snapshots\n--tag\nsecwiz-vm"));
    let rows=server.get("/v1/backups?machineId=backup-source")?;assert_eq!(rows["snapshots"].as_array().unwrap().len(),1);assert_eq!(rows["snapshots"][0]["id"],SNAP);
    assert_eq!(server.get("/v1/backups?machineId=elsewhere")?["snapshots"],json!([]));
    restore_into_empty_library(root, &settings, &original)?;
    let restore=json!({"snapshotId":SNAP,"name":"Recovered fixture"});
    server.call("POST","/v1/backups/restore",restore.clone(),202)?;
    let result=server.wait()?;assert_eq!(result["state"],"completed","{result}");
    let id=result["newId"].as_str().ok_or("missing new id")?; assert_ne!(id,SOURCE);
    let restored=server.get(&format!("/v1/machines/{id}"))?;
    assert_eq!(restored["name"],"Recovered fixture");assert_eq!(restored["throwaway"],false);assert_eq!(restored["registration"],"registered");
    assert_ne!(restored["mac"],original["mac"]);assert_eq!(restored["net"],"closed");assert_eq!(fs::read(bundle.join("system.vhdx"))?,disk);
    let restore_args=fs::read_to_string(repo.join("arguments"))?;
    let restore_argv:Vec<_>=restore_args.lines().collect();
    assert_eq!(&restore_argv[6..9],["restore",SNAP,"--target"]);assert_eq!(Path::new(restore_argv[9]).file_name().unwrap(),"data");
    assert_eq!(&restore_argv[10..],["--verify","--include","/vm.json","--include","/system.qcow2","--include","/system.vhdx","--include","/uefi-vars.fd","--include","/qemu-vm.json"]);
    assert_eq!(fs::read(home.join("library").join(format!("{id}.swvm")).join("system.vhdx"))?,disk);
    server.call("POST","/v1/backups/restore",restore,409)?;
    let canceled = credentials.join("cancel-key-prompt");
    for (marker, code, reason, message) in [
        (canceled, 1, "key_step", "YubiKey step did not finish"),
        (repo.join("fail"), 12, "repository", "open or lock the repository"),
        (repo.join("restore-error"), 1, "restore", "could not finish restoring the files"),
    ] {
        server.prompt_ready()?;
        fs::write(&marker, [])?;
        server.call("POST","/v1/backups/restore",json!({"snapshotId":SNAP,"name":"Diagnostic fixture"}),202)?;
        let last = server.wait()?;
        assert_eq!(last["state"], "failed");
        assert_eq!(last["exitCode"], code);
        assert_eq!(last["reason"], reason);
        assert!(last["message"].as_str().unwrap().contains(message));
        assert!(!last.to_string().contains("private fixture detail"));
        assert!(last["newId"].is_null());
        assert!(!home.join("backup-owner.json").exists() && !home.join("backup-restore.json").exists());
        fs::remove_file(marker)?;
    }
    server.prompt_ready()?;
    let sentinel=repo.join("sentinel-dir");fs::create_dir(&sentinel)?;fs::write(sentinel.join("keep"),b"keep")?;
    fs::write(repo.join("link-mode"),"")?;
    server.call("POST","/v1/backups/restore",json!({"snapshotId":SNAP,"name":"Link fixture"}),202)?;
    let result=server.wait()?;assert_eq!(result["state"],"failed");assert_eq!(result["exitCode"],0);
    assert_eq!(fs::read(sentinel.join("keep"))?,b"keep");assert!(!home.join("backup-restore.json").exists());
    fs::remove_file(repo.join("link-mode"))?;
    for mode in ["extra","wrong-case","directory","file-link"] {
        fs::write(repo.join("fixture-tree"),mode)?;server.prompt_ready()?;
        server.call("POST","/v1/backups/restore",json!({"snapshotId":SNAP,"name":"Rejected tree"}),202)?;
        let job=server.wait()?;assert_eq!(job["state"],"failed","{mode}");assert_eq!(job["exitCode"],0,"{mode}");
        assert!(!home.join("backup-restore.json").exists());assert_eq!(fs::read(sentinel.join("keep"))?,b"keep");
    }
    fs::remove_file(repo.join("fixture-tree"))?;
    let record=repo.join("vm.json");let saved=fs::read(&record)?;
    for (field,value,message) in [("id","other-source","tag"),("net","gone","network")] {
        let mut change:Value=serde_json::from_slice(&saved)?;change[field]=json!(value);
        fs::write(&record,serde_json::to_vec(&change)?)?;server.prompt_ready()?;
        server.call("POST","/v1/backups/restore",json!({"snapshotId":SNAP,"name":"Unusable guest"}),202)?;
        let result=server.wait()?;assert_eq!(result["state"],"failed");
        assert!(result["message"].as_str().unwrap().contains(message),"{result}");
    }
    fs::write(&record,saved)?;
    server.prompt_ready()?;fs::write(repo.join("wait-restore"),[])?;
    server.call("POST","/v1/backups/restore",json!({"snapshotId":SNAP,"name":"Contested copy"}),202)?;
    server.call("POST","/v1/machines",json!({"id":"collision-winner","name":"Contested copy"}),201)?;
    fs::remove_file(repo.join("wait-restore"))?;
    let conflict=server.wait()?;assert_eq!(conflict["state"],"failed");assert_eq!(server.get("/v1/machines/collision-winner")?["name"],"Contested copy");
    let size_file=repo.join("size");let saved_size=fs::read(&size_file)?;
    for declared in ["18446744073709551615","8"] {
        fs::write(&size_file,declared)?;server.prompt_ready()?;
        server.call("POST","/v1/backups/refresh",json!({}),202)?;assert_eq!(server.wait()?["state"],"completed");
        let req=json!({"snapshotId":SNAP,"name":"Space fixture"});
        if declared=="8" {
            server.call("POST","/v1/backups/restore",req,202)?;
            let result=server.wait()?;assert!(result["message"].as_str().unwrap().contains("size"));
        } else {
            let refusal=server.call("POST","/v1/backups/restore",req,409)?;
            assert!(refusal["error"]["message"].as_str().unwrap().contains("256 MiB"));
        }
    }
    fs::write(size_file,saved_size)?;
    server.prompt_ready()?;
    qemu_roundtrips(&server,root,&home)?;
    fs::write(repo.join("fail"),"")?;
    server.call("POST","/v1/backups/refresh",json!({}),202)?;assert_eq!(server.wait()?["exitCode"],12);
    fs::remove_file(repo.join("fail"))?;
    let previous=server.get("/v1/backups")?["snapshots"].clone();
    server.call("POST","/v1/backups/refresh",json!({}),409)?;server.prompt_ready()?;
    let cancel=credentials.join("cancel-key-prompt"); fs::write(&cancel,[])?;
    server.call("POST","/v1/backups",backup.clone(),202)?;
    let rejected=server.wait()?;assert_eq!(rejected["state"],"failed");assert_eq!(rejected["exitCode"],1);assert_eq!(rejected["reason"],"key_step");
    server.call("POST",&start,json!({}),200)?;server.call("POST",&stop,json!({}),200)?;
    assert_eq!(server.get("/v1/backups")?["snapshots"],previous);
    fs::remove_file(cancel)?;
    server.prompt_ready()?;
    fs::write(repo.join("partial"),[])?;server.call("POST","/v1/backups",backup,202)?;
    let partial=server.wait()?;assert_eq!(partial["exitCode"],3);assert_eq!(partial["state"],"failed");
    fs::remove_file(repo.join("partial"))?;server.prompt_ready()?;
    server.call("POST","/v1/backups/refresh",json!({}),202)?;assert_eq!(server.wait()?["state"],"completed");
    assert!(!server.get("/v1/backups")?["snapshots"].as_array().unwrap().iter().any(|row|row["id"]=="f".repeat(64)));
    fs::write(private_tools.join("unexpected.txt"),b"inert")?;
    server.call("POST","/v1/backups/refresh",json!({}),202)?;assert_eq!(server.wait()?["state"],"failed");
    fs::remove_file(private_tools.join("unexpected.txt"))?;server.prompt_ready()?;
    fs::write(private_tools.join("age-plugin-yubikey.exe"),b"changed fake binary")?;
    server.call("POST","/v1/backups/refresh",json!({}),202)?;let result=server.wait()?;
    assert_eq!(result["state"],"failed");assert!(result["exitCode"].is_null());
    for value in [server.get("/v1/events?since=0")?.to_string(),rows.to_string(),args,environment,
        fs::read_to_string(home.join("backup-settings.json"))?,result.to_string()] {assert!(!value.contains(&canary));}
    drop(server);
    let orphan=home.join("library/.svm-restore-vm-1234-1-1");
    fs::create_dir(&orphan)?;fs::write(orphan.join("lease"),"")?;fs::write(orphan.join("partial"),"partial data")?;
    fs::write(home.join("backup-restore.json"),r#""vm-1234-1-1""#)?;
    let restarted=Fixture::open(&home)?;
    assert!(!orphan.exists());assert!(!home.join("backup-restore.json").exists());
    drop(restarted);
    let journal=home.join("backup-restore.json");
    let published=home.join("library").join(format!("{id}.swvm")).join("backup-publishing.json");
    let route = format!("/v1/machines/{id}");
    let check_blocked = |fixture: &Fixture| -> Result<()> {
        let row=fixture.get(&route)?;
        assert_eq!(row["registration"],"restore incomplete");assert!(row["state"].is_null());
        let caps=fixture.get(&format!("{route}/capabilities"))?;
        assert_eq!(caps["Start"]["available"],false);assert_eq!(caps["Delete"]["available"],true);
        assert!(fixture.call("POST",&format!("{route}/start"),json!({}),409)?["error"]["message"].as_str().unwrap().contains("Restore incomplete"));
        Ok(())
    };
    for (phase,success) in [("Prepared",true),("Defining",false),("Failed",false)] {
        fs::write(&journal,serde_json::to_vec(id)?)?;
        fs::write(&published,serde_json::to_vec(&json!({"id":id,"legacy_windows":false,"phase":phase}))?)?;
        let mut engine=FakeEngine::default();
        if !success {
            use svm_core::engine::EngineDriver;
            let vm=serde_json::from_slice(&fs::read(published.with_file_name("vm.json"))?)?;
            engine.define(&vm)?;
        }
        let recovering=Fixture::with_engine(&home,engine)?;
        assert_eq!(published.exists(),!success);assert!(!journal.exists());
        if success {assert_eq!(recovering.get(&format!("/v1/machines/{id}"))?["registration"],"registered");}
        else {
            let last=recovering.get("/v1/backups")?["last"].clone();assert_eq!(last["newId"],id);assert_eq!(last["state"],"failed");
            check_blocked(&recovering)?;
        }
        drop(recovering);
        if !success {
            // The stage journal is gone. The bundle marker alone must still prevent a start after another restart.
            let again=Fixture::open(&home)?;check_blocked(&again)?;drop(again);
        }
    }
    fs::write(&journal,serde_json::to_vec(id)?)?;
    fs::write(&published,serde_json::to_vec(&json!({"id":id,"legacy_windows":false,"phase":"Defined"}))?)?;
    {
        use std::os::windows::fs::OpenOptionsExt;
        use svm_core::engine::EngineDriver;
        let mut defined=FakeEngine::default();
        defined.define(&serde_json::from_slice(&fs::read(published.with_file_name("vm.json"))?)?)?;
        let held=fs::OpenOptions::new().read(true).share_mode(1).open(&published)?;
        let recovering=Fixture::with_engine(&home,defined)?;
        check_blocked(&recovering)?;
        assert_eq!(recovering.get("/v1/backups")?["last"]["state"],"pending");
        assert!(journal.exists());drop(held);
        let end=Instant::now()+Duration::from_secs(14);
        while recovering.get("/v1/backups")?["last"]["state"]=="pending" {
            if Instant::now()>=end {return Err("Defined restore marker did not retire".into());}
            thread::sleep(Duration::from_millis(120));
        }
        assert_eq!(recovering.get("/v1/backups")?["last"]["state"],"completed");
        assert_eq!(recovering.get(&route)?["registration"],"registered");
        assert!(!journal.exists());assert!(!published.exists());
    }
    fs::write(&journal,serde_json::to_vec(id)?)?;
    fs::write(&published,serde_json::to_vec(&json!({"id":id,"legacy_windows":false,"phase":"Prepared"}))?)?;
    let mut faulty=FakeEngine::default();faulty.fail_next("define");
    let recovering=Fixture::with_engine(&home,faulty)?;
    let failure=recovering.get("/v1/backups")?["last"].clone();
    assert_eq!(failure["newId"],id);
    assert!(failure["message"].as_str().unwrap().contains("library trash"));
    drop(recovering);
    for name in ["backup-owner.json","backup-restore.json"] {
        let path=home.join(name);fs::write(&path,b"bad receipt")?;
        let recovering=Fixture::open(&home)?;
        let response=recovering.call("POST","/v1/backups/refresh",json!({}),409)?;
        assert!(response["error"]["message"].as_str().unwrap().contains(name));
        drop(recovering);fs::remove_file(path)?;
    }
    // A restarted service must wait for a still-open console, then recover without another request.
    let lease_id="vm-9876-1-2";
    let lease_path=home.join(format!(".backup-{lease_id}.lock"));
    fs::write(&lease_path,[])?;
    use std::os::windows::fs::OpenOptionsExt;
    let held=fs::OpenOptions::new().read(true).share_mode(1).open(&lease_path)?;
    fs::write(home.join("backup-owner.json"),serde_json::to_vec(&json!({"id":lease_id,"machine":SOURCE}))?)?;
    let recovering=Fixture::open(&home)?;
    assert_eq!(recovering.get("/v1/backups")?["current"]["kind"],"previous console");
    recovering.call("POST",&start,json!({}),409)?;
    drop(held);
    let end=Instant::now()+Duration::from_secs(12);
    while home.join("backup-owner.json").exists() {
        if Instant::now()>=end {return Err("Orphaned backup lease did not retire".into());}
        thread::sleep(Duration::from_millis(150));
    }
    assert!(!lease_path.exists());drop(recovering);

    let service_home=svm_qemu::LocalFolder::hold(&home)?;
    let stale=service_home.create_private_child(".backup-install-vm-ab-ff-2")?;
    let stale_dir=stale.path.clone();fs::write(stale.path.join("age.exe"),b"inert interrupted install")?;
    drop(stale);drop(service_home);
    fs::write(bundle.join("backup-publishing.json"),b"unreadable fixture marker")?;
    let recovering=Fixture::open(&home)?;
    assert!(!stale_dir.exists());assert!(private_tools.is_dir());
    let source_route=format!("/v1/machines/{SOURCE}");
    assert_eq!(recovering.get(&source_route)?["registration"],"restore incomplete");
    let removed=recovering.call("DELETE",&source_route,json!({"keepCopy":false}),200)?;
    assert_eq!(removed["trashed"],true);
    assert!(Path::new(removed["trashPath"].as_str().unwrap()).join("system.vhdx").is_file());
    drop(recovering);Ok(())
}
#[test]
fn backup_disk_requires_standalone_data_and_clean_vhdx_log() -> Result<()> {
    use svm_core::model::EngineKind;
    let root=new_root()?;
    let file=root.join("header-fixture");
    let check=|data:&[u8],kind| -> Result<bool> {
        fs::write(&file,data)?;
        Ok(svm_qemu::backup_disk_size(&fs::File::open(&file)?,kind).is_ok())
    };
    let base=sample_disk();
    assert!(check(&base,EngineKind::HyperV)?);
    for offset in [0x10000+48,0x20000+48,0x50000+128+4] {
        let mut dirty=base.clone();dirty[offset]=2;
        assert!(!check(&dirty,EngineKind::HyperV)?);
    }
    let mut qcow=[0u8;104];qcow[..4].copy_from_slice(b"QFI\xfb");qcow[7]=3;qcow[20..24].copy_from_slice(&16u32.to_be_bytes());qcow[24..32].copy_from_slice(&(1u64<<30).to_be_bytes());
    assert!(check(&qcow,EngineKind::Qemu)?);
    for (offset,flag) in [(15,1),(79,4),(35,1)] {
        let mut unsupported=qcow;unsupported[offset]=flag;assert!(!check(&unsupported,EngineKind::Qemu)?);
    }
    fs::remove_file(file)?;fs::remove_dir(root)?;Ok(())
}
#[test]
fn encrypted_backup_restore_and_recovery() -> Result<()> {
    let root=new_root()?;
    let result=exercise(&root);
    if root.parent()==Some(std::env::temp_dir().canonicalize()?.as_path()) && root.file_name().unwrap().to_string_lossy().starts_with("svm-backup-test-") { fs::remove_dir_all(&root)?; }
    result
}
