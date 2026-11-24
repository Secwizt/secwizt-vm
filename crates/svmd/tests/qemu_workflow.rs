#![cfg(windows)]
#![deny(warnings)]
#![forbid(unsafe_code)]

use serde_json::{json, Value};
use std::{
    error::Error, fs, io, path::{Path,PathBuf}, process::Command,
    sync::{Arc,atomic::{AtomicBool,Ordering}}, thread::{self,JoinHandle},
    time::{Duration,Instant,SystemTime,UNIX_EPOCH},
};
use svm::client::Client;
use svm_core::{engine::FakeEngine, library::Library};
use svmd::{networks::FakeSwitches,Service};

type Result<T> = std::result::Result<T,Box<dyn Error>>;
fn fail(s:&str)->Box<dyn Error> { io::Error::other(s).into() }

struct Server { client:Client, stop:Arc<AtomicBool>, task:Option<JoinHandle<std::result::Result<(),svmd::ApiError>>> }

impl Server {
    fn open(home:&Path)->Result<Self> {
        let server=Service::open_with_supervisor(home,0,Box::new(FakeEngine::default()),
            Box::<FakeSwitches>::default(),Path::new(env!("CARGO_BIN_EXE_svmd")))?;
        let client=Client::load(home,None)?;
        let stop=Arc::new(AtomicBool::new(false));
        let flag=stop.clone();
        Ok(Self{client,stop,task:Some(thread::spawn(move||server.run(flag)))})
    }
    fn call(&self,method:&str,path:&str,body:Option<Value>,expected:u16)->Result<Value> {
        let reply=self.client.request_with_timeout(method,path,body.as_ref(),Duration::from_secs(45))?;
        let parsed:Value=serde_json::from_slice(&reply.body)?;
        if reply.status!=expected {
            return Err(fail(&format!("{method} {path}: expected {expected}, received {}: {}",reply.status,parsed["error"]["message"])));
        }
        Ok(parsed)
    }
    fn stop_server(&mut self)->Result<()> {
        self.stop.store(true,Ordering::Release);
        if let Some(task)=self.task.take(){task.join().map_err(|_|fail("Fixture service panicked."))??;}
        Ok(())
    }
}
impl Drop for Server { fn drop(&mut self){let _=self.stop_server();} }

fn fake_tools(folder:&Path)->Result<PathBuf> {
    let binary=folder.join("qemu-system-x86_64.exe");
    let source=Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_qemu.rs");
    let compiler=std::env::var_os("RUSTC").unwrap_or_else(||"rustc".into());
    let built=Command::new(compiler).arg("--edition=2021").args(["-C","debuginfo=0","-C","codegen-units=1"])
        .arg(&source).arg("-o").arg(&binary).current_dir(folder).output()?;
    if !built.status.success(){return Err(fail(&String::from_utf8_lossy(&built.stderr)));}
    fs::copy(&binary,folder.join("qemu-img.exe"))?;
    Ok(binary)
}

fn wait_transfer(server:&Server,job:&Value)->Result<Value>{
    let path=format!("/v1/transfers/{}",job["id"].as_str().ok_or("Missing job ID")?);
    let end=Instant::now()+Duration::from_secs(30);
    loop {
        let row=server.call("GET",&path,None,200)?;
        if !matches!(row["state"].as_str(),Some("running"|"cancelling")) {return Ok(row);}
        if Instant::now()>=end{return Err(fail("Transfer did not finish."));}
        thread::sleep(Duration::from_millis(70));
    }
}
fn transfers(home:&Path,server:&Server)->Result<()>{
    let inputs=home.join("inputs");fs::create_dir(&inputs)?;
    let input=inputs.join("cancel.img");
    let mut raw=vec![0u8;65536];raw[0]=0xeb;raw[446]=0x80;raw[450]=0x83;raw[510]=0x55;raw[511]=0xaa;
    fs::write(&input,&raw)?;
    let before=fs::metadata(&input)?.modified()?;
    let info=server.call("POST","/v1/transfers/inspect",Some(json!({"path":input})),200)?;
    assert_eq!(info["format"],"raw");assert_eq!(info["firmware"],"bios");
    let checkpoint_vm="export-checkpoint";
    server.call("POST","/v1/machines",Some(json!({"id":checkpoint_vm,"name":"Export checkpoint","family":"linux"})),201)?;
    server.call("POST","/v1/machines/export-checkpoint/snapshots",Some(json!({"name":"kept","withMemory":false})),201)?;
    let blocked=server.call("POST","/v1/transfers/export",Some(json!({"machineId":checkpoint_vm,"folder":home,"format":"vdi"})),409)?;
    assert!(blocked["error"]["message"].as_str().is_some_and(|msg|msg.contains("checkpoints")));
    let start=|id:&str,path:&Path|server.call("POST","/v1/transfers/import",Some(json!({"path":path,
        "id":id,"name":id,"os":"Linux","family":"linux","firmware":"bios"})),202);
    let cancelled=start("cancelled-import",&input)?;
    let id=cancelled["id"].as_str().unwrap();
    let end=Instant::now()+Duration::from_secs(12);
    while server.call("GET",&format!("/v1/transfers/{id}"),None,200)?["percent"]==0 {
        if Instant::now()>end{return Err(fail("No conversion progress arrived."));}
        thread::sleep(Duration::from_millis(80));
    }
    server.call("POST","/v1/shutdown",Some(json!({"ifIdle":true})),409)?;
    server.call("DELETE",&format!("/v1/transfers/{id}"),None,200)?;
    assert_eq!(wait_transfer(server,&cancelled)?["state"],"cancelled");
    server.call("GET","/v1/machines/cancelled-import",None,404)?;
    assert!(!home.join("disk-transfer.json").exists());
    assert!(!fs::read_dir(home.join("library"))?.filter_map(|e|e.ok()).any(|e|e.file_name().to_string_lossy().starts_with(".svm-transfer-")));
    assert_eq!(fs::read(&input)?,raw);assert_eq!(fs::metadata(&input)?.modified()?,before);
    let source=inputs.join("source.img");fs::copy(&input,&source)?;
    let efi=server.call("POST","/v1/transfers/import",Some(json!({"path":source,"id":"imported-efi",
        "name":"Imported EFI","os":"Linux","family":"linux","firmware":"uefi"})),202)?;
    let installed=wait_transfer(server,&efi)?;
    assert_eq!(installed["state"],"completed","{installed}");
    assert_eq!(installed["result"]["engine"],"Hyper-V");
    let bundle=Library::open_stable(home.join("library"))?.bundle_path("imported-efi")?;
    assert_eq!(svm_core::read_json::<String>(&bundle.join("boot-order.json"))?,"disk");
    let completed=wait_transfer(server,&start("imported-bios",&source)?)?;
    assert_eq!(completed["state"],"completed","{completed}");
    assert_eq!(completed["result"]["engine"],"QEMU");
    let vm="/v1/machines/imported-bios";
    server.call("POST",&format!("{vm}/start"),Some(json!({})),200)?;
    let export_dir=home.parent().unwrap().join(format!("{}-export",home.file_name().unwrap().to_string_lossy()));
    fs::create_dir(&export_dir)?;
    let result=(|| -> Result<()> {
        let body=json!({"machineId":"imported-bios","folder":export_dir,"format":"vdi"});
        server.call("POST","/v1/transfers/export",Some(body.clone()),409)?;
        server.call("POST",&format!("{vm}/stop"),Some(json!({})),200)?;
        let bundle=Library::open_stable(home.join("library"))?.bundle_path("imported-bios")?;
        let disk=bundle.join("system.qcow2");
        let old=fs::metadata(&disk)?.modified()?;let contents=fs::read(&disk)?;
        let export=server.call("POST","/v1/transfers/export",Some(body.clone()),202)?;
        let done=wait_transfer(server,&export)?;
        assert_eq!(done["state"],"completed","{done}");
        server.call("POST","/v1/transfers/export",Some(body),409)?;
        let output=export_dir.join("imported-bios.vdi");
        let disguised=export_dir.join("different-name.vhd");
        fs::rename(&output,&disguised)?;
        assert_eq!(server.call("POST","/v1/transfers/inspect",Some(json!({"path":disguised})),200)?["format"],"vdi");
        assert_eq!(fs::metadata(&disk)?.modified()?,old);assert_eq!(fs::read(&disk)?,contents);
        let mut invalid=contents.clone();invalid[15]=32;
        let linked=inputs.join("linked.qcow2");fs::write(&linked,&invalid)?;
        server.call("POST","/v1/transfers/inspect",Some(json!({"path":linked})),409)?;
        invalid[15]=0;invalid[24..32].copy_from_slice(&(200u64<<30).to_be_bytes());fs::write(&linked,invalid)?;
        server.call("POST","/v1/transfers/inspect",Some(json!({"path":linked})),400)?;
        fs::remove_file(disguised)?;
        Ok(())
    })();
    if let Err(e)=fs::remove_dir(&export_dir){if result.is_ok(){return Err(e.into());}}
    result
}

fn legacy_x86(server:&Server,home:&Path,iso:&Path)->Result<()> {
    for (id,extra) in [
        ("bad-cpu",json!({"vcpu":5})),("bad-ram",json!({"ramGb":9})),("bad-family",json!({"family":"windows"})),
        ("bad-secure",json!({"secureBoot":true})),("bad-tpm",json!({"tpm":true})),
    ] {
        let mut request=json!({"id":id,"name":id,"family":"linux","engine":"QEMU"});
        for (key,val) in extra.as_object().unwrap(){request[key]=val.clone();}
        server.call("POST","/v1/machines",Some(request),400)?;
    }
    for (id,family) in [("bios-bsd","bsd"),("bios-other","other")] {
        let vm=server.call("POST","/v1/machines",Some(json!({"id":id,"name":id,"engine":"QEMU","family":family,"diskGb":1})),201)?;
        assert!(vm["isoPath"].is_null());
    }
    let vm=server.call("POST","/v1/machines",Some(json!({"id":"legacy-linux","name":"Legacy Linux","family":"linux",
        "engine":"QEMU","vcpu":2,"ramGb":3,"diskGb":1})),201)?;
    assert_eq!(vm["state"],"off");
    assert_eq!(vm["shareClipboard"], false);
    let route="/v1/machines/legacy-linux";
    let storage=format!("{route}/storage");
    let original=server.call("GET",&storage,None,200)?;
    assert!(original["originalInstaller"].is_null());assert_eq!(original["canEditMedia"],true);
    let disc=server.call("PUT",&storage,Some(json!({"isoPath":iso})),200)?;
    assert!(disc["originalInstaller"].is_string());
    let bundle=Library::open_stable(home.join("library"))?.bundle_path("legacy-linux")?;
    server.call("POST",&format!("{route}/start"),Some(json!({})),200)?;
    let args:Vec<String>=serde_json::from_slice(&fs::read(bundle.join("fake-arguments.json"))?)?;
    for pair in [["-smp","2"],["-m","3072"],["-accel","whpx"],["-machine","pc,i8042=off"],["-device","usb-kbd"],
        ["-device","usb-tablet"],["-device","virtio-vga"],["-display","none"],["-vnc","127.77.0.1:0,to=99,password=on"],["-boot","order=c,once=d"]] {
        assert!(args.windows(2).any(|p|p==pair),"{pair:?}");
    }
    assert!(!args.iter().any(|a|a.contains("tcg")||a.contains("hda-")||a=="-audiodev"));
    assert!(!args.iter().any(|arg| arg.contains("com.redhat.spice.0")));
    server.call("PATCH",route,Some(json!({"shareClipboard":true})),409)?;
    let live=server.call("GET",&format!("{route}/capabilities"),None,200)?;
    assert_eq!(live["AudioOutput"]["available"],false);
    assert!(live["AudioOutput"]["message"].as_str().unwrap().contains("legacy BIOS"));
    server.call("PATCH",route,Some(json!({"vcpu":1})),409)?;
    server.call("PUT",&storage,Some(json!({"isoPath":null})),409)?;
    server.call("POST",&format!("{route}/stop"),Some(json!({})),200)?;
    server.call("PATCH",route,Some(json!({"ramGb":9})),409)?;
    let updated = server.call("PATCH",route,Some(json!({"vcpu":1,"ramGb":1,"shareClipboard":true})),200)?;
    assert_eq!(updated["shareClipboard"], true);
    server.call("PUT",&storage,Some(json!({"isoPath":null})),200)?;
    let wrong=home.join("other-fixture.iso");fs::write(&wrong,b"fixture")?;
    server.call("PUT",&storage,Some(json!({"isoPath":wrong})),409)?;
    server.call("PUT",&storage,Some(json!({"isoPath":iso})),200)?;
    server.call("PUT",&storage,Some(json!({"isoPath":null})),200)?;
    server.call("POST",&format!("{route}/start"),Some(json!({})),200)?;
    let disk_only:Vec<String>=serde_json::from_slice(&fs::read(bundle.join("fake-arguments.json"))?)?;
    assert!(disk_only.windows(2).any(|p|p==["-boot","order=c"]));
    assert!(!disk_only.iter().any(|p|p.contains("ide-cd")));
    assert!(disk_only.windows(2).any(|p| p==["-chardev", "qemu-vdagent,id=svm-clipboard,clipboard=on,mouse=off"]));
    assert!(disk_only.iter().any(|arg| arg.contains("name=com.redhat.spice.0")));
    assert_eq!(disk_only.iter().filter(|arg| arg.as_str()=="virtio-serial-pci,id=svm-agent-bus").count(),1);
    server.call("PATCH",route,Some(json!({"shareClipboard":false})),409)?;
    server.call("POST",&format!("{route}/stop"),Some(json!({})),200)?;
    Ok(())
}

fn emulated_arm(server:&Server,home:&Path,tools:&Path,iso:&Path)->Result<()> {
    use std::io::{Read,Write};
    let settings="/v1/settings/qemu";
    let create=json!({"id":"arm-linux","name":"Arm Linux","engine":"QEMU","architecture":"aarch64","family":"linux","diskGb":2,"isoPath":iso});
    server.call("POST","/v1/machines",Some(create.clone()),409)?;
    for (field,value) in [("vcpu",json!(3)),("ramGb",json!(5)),("family",json!("android")),("engine",json!("Hyper-V")),("architecture",json!("unknown"))] {
        let mut request=create.clone();request[field]=value;
        server.call("POST","/v1/machines",Some(request),400)?;
    }
    let arm=tools.with_file_name("qemu-system-aarch64.exe");
    fs::copy(tools,&arm)?;
    let mismatch=home.join("fixture-arm-version");
    fs::write(&mismatch,b"other version")?;
    let select=||server.call("PUT",settings,Some(json!({"path":tools})),200);
    let unavailable=select()?;
    assert_eq!(unavailable["available"],true);assert_eq!(unavailable["armAvailable"],false);
    assert!(unavailable["armReason"].as_str().unwrap().contains("different QEMU versions"));
    fs::remove_file(mismatch)?;
    let share=home.join("share");fs::create_dir(&share)?;
    let template=share.join("edk2-arm-vars.fd");
    for path in [&template,&share.join("edk2-aarch64-code.fd")] {
        let mut f=fs::File::create_new(path)?;f.write_all(b"fixture")?;f.set_len(64<<20)?;
    }
    assert_eq!(select()?["armAvailable"],true);
    let vm=server.call("POST","/v1/machines",Some(create),201)?;
    assert_eq!(vm["architecture"],"aarch64");assert_eq!(vm["accel"],false);
    let route="/v1/machines/arm-linux";
    let caps=server.call("GET",&format!("{route}/capabilities"),None,200)?;
    assert_eq!(caps["Start"]["available"],true);assert_eq!(caps["Accelerated"]["available"],false);
    assert_eq!(caps["AudioOutput"]["available"],false);
    let bundle=Library::open_stable(home.join("library"))?.bundle_path("arm-linux")?;
    let vars=bundle.join("uefi-vars.fd");
    let mut marker=[0;7];
    fs::File::open(&vars)?.read_exact(&mut marker)?;assert_eq!(&marker,b"fixture");
    fs::OpenOptions::new().write(true).open(&vars)?.write_all(b"changed")?;
    fs::File::open(&template)?.read_exact(&mut marker)?;assert_eq!(&marker,b"fixture");
    for disc in [true,false] {
        if !disc {server.call("PUT",&format!("{route}/storage"),Some(json!({"isoPath":null})),200)?;}
        server.call("POST",&format!("{route}/start"),Some(json!({})),200)?;
        let args:Vec<String>=serde_json::from_slice(&fs::read(bundle.join("fake-arguments.json"))?)?;
        assert_eq!(fs::read_to_string(bundle.join("fake-system-name"))?,"qemu-system-aarch64");
        assert!(args.windows(2).any(|pair|pair[0]=="-accel" && pair[1].split(',').next()==Some("tcg")));
        assert!(args.windows(2).any(|pair|pair[0]=="-machine" && pair[1].split(',').any(|s|s=="virt"||s=="type=virt")));
        assert!(args.iter().any(|arg|arg.contains("cortex-a72")));
        for device in ["usb-kbd","usb-tablet","virtio-net","virtio","edk2-aarch64-code.fd","uefi-vars.fd"] {
            assert!(args.iter().any(|arg|arg.contains(device)),"Missing {device}");
        }
        assert!(!args.iter().any(|s|s.contains("whpx")||s.contains("hda-")||s=="-audiodev"));
        assert_eq!(args.iter().any(|arg|arg.contains("android-fixture.iso")),disc);
        server.call("POST",&format!("{route}/stop"),Some(json!({})),200)?;
    }
    server.call("PUT",&format!("{route}/storage"),Some(json!({"isoPath":iso})),200)?;
    fs::File::open(&vars)?.read_exact(&mut marker)?;assert_eq!(&marker,b"changed");
    fs::OpenOptions::new().append(true).open(&arm)?.write_all(b"changed binary")?;
    let changed=server.call("GET",settings,None,200)?;
    assert_eq!(changed["armAvailable"],false);assert_eq!(changed["available"],true);
    let caps=server.call("GET",&format!("{route}/capabilities"),None,200)?;
    assert_eq!(caps["Start"]["available"],false);
    Ok(())
}

fn purge_qemu_checkpoint(server: &Server, home: &Path) -> Result<()> {
    const ID: &str = "purge-qemu-checkpoint";
    const NAME: &str = "QEMU Checkpoint Fixture";
    const MACHINE: &str = "/v1/machines/purge-qemu-checkpoint";
    const SNAPSHOTS: &str = "/v1/machines/purge-qemu-checkpoint/snapshots";
    server.call("POST", "/v1/machines", Some(json!({
        "id": ID, "name": NAME, "family": "linux", "engine": "QEMU", "diskGb": 1,
    })), 201)?;

    let library = Library::open_stable(home.join("library"))?;
    let bundle = library.bundle_path(ID)?;
    let checkpoint = json!({
        "id": "svm-cp-1", "name": "Disk checkpoint", "parent": null,
        "withMemory": false, "consistency": "crash-consistent",
    });
    let book = json!({"head": checkpoint["id"], "rows": [checkpoint.clone()]});
    svm_core::write_json(&bundle.join("qemu-snapshots.json"), &book)?;
    assert_eq!(server.call("GET", SNAPSHOTS, None, 200)?, json!([checkpoint]));

    let removed = server.call("DELETE", MACHINE, Some(json!({"keepCopy": false})), 200)?;
    assert_eq!(removed["removalPath"], "bundle-only");
    assert!(!bundle.try_exists()?);
    let mut entry = library.list_trash()?.into_iter().find(|row| row.machine.id == ID)
        .ok_or_else(|| fail("The QEMU bundle did not reach trash."))?;
    // The fake qemu-img cannot capture a native checkpoint. Persist the checkpoint
    // count that a completed capture would have put in the machine record.
    entry.machine.snaps = 1;
    svm_core::write_json(&entry.path.join("vm.json"), &entry.machine)?;
    let disk = entry.path.join("system.qcow2");
    let checkpoint_book = entry.path.join("qemu-snapshots.json");
    let trashed_disk = fs::read(&disk)?;
    assert_eq!(svm_core::read_json::<Value>(&checkpoint_book)?, book);

    let trash_route = format!("/v1/trash/{}", entry.key);
    let wrong = server.call("DELETE", &trash_route, Some(json!({"confirmName": NAME.to_ascii_lowercase()})), 409)?;
    assert!(wrong["error"]["message"].as_str().is_some_and(|message| message.contains("confirmName")));
    assert_eq!(fs::read(&disk)?, trashed_disk);
    assert_eq!(svm_core::read_json::<Value>(&checkpoint_book)?, book);

    let purged = server.call("DELETE", &trash_route, Some(json!({"confirmName": NAME})), 200)?;
    assert_eq!(purged["deleted"], true);
    assert!(!entry.path.try_exists()?);
    assert!(!disk.try_exists()?);
    assert!(!checkpoint_book.try_exists()?);
    assert!(!library.list_trash()?.iter().any(|row| row.key == entry.key));
    server.call("GET", SNAPSHOTS, None, 404)?;
    Ok(())
}

fn throwaway(server: Server, home: &Path) -> Result<Server> {
    const ID: &str = "throwaway-fixture";
    const P: &str = "/v1/machines/throwaway-fixture";
    let mut server = server;
    server.call("POST", "/v1/machines", Some(json!({
        "id": ID, "name": "Throwaway fixture", "family": "linux", "engine": "QEMU", "diskGb": 1,
    })), 201)?;
    let library = Library::open_stable(home.join("library"))?;
    let bundle = library.bundle_path(ID)?;
    let disk = bundle.join("system.qcow2");
    let persistent = fs::read(&disk)?;
    let journal = bundle.join("qemu-throwaway.json");
    let overlays = |bundle: &Path| -> Result<Vec<PathBuf>> {
        let mut found = Vec::new();
        for entry in fs::read_dir(bundle)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(".throwaway-") { found.push(entry.path()); }
        }
        Ok(found)
    };
    let refusal = |reply: Value| reply["error"]["message"].as_str().unwrap_or_default().to_owned();

    // Throwaway mode is a stopped-machine setting, and it excludes checkpoints and templates.
    assert_eq!(server.call("GET", &format!("{P}/capabilities"), None, 200)?["EditThrowaway"]["available"], true);
    let enabled = server.call("PATCH", P, Some(json!({"throwaway": true})), 200)?;
    assert_eq!(enabled["throwaway"], true);
    assert_eq!(enabled["isolated"], true, "a throwaway QEMU machine is cut off from this PC by default");
    let checkpoint = json!({"name": "kept", "withMemory": false});
    assert!(refusal(server.call("POST", &format!("{P}/snapshots"), Some(checkpoint.clone()), 409)?).contains("throwaway mode"));
    assert!(refusal(server.call("POST", &format!("{P}/template"), Some(json!({})), 409)?).contains("throwaway mode"));
    assert_eq!(server.call("GET", &format!("{P}/capabilities"), None, 200)?["Snapshot"]["available"], false);

    // A run writes only to its private overlay. The persistent disk is opened read-only.
    server.call("POST", &format!("{P}/start"), Some(json!({})), 200)?;
    assert!(journal.is_file());
    let running = overlays(&bundle)?;
    assert_eq!(running.len(), 1);
    assert!(running[0].join("system.qcow2").is_file());
    let args: Vec<String> = serde_json::from_slice(&fs::read(bundle.join("fake-arguments.json"))?)?;
    assert!(args.windows(2).any(|pair| pair[0] == "-netdev" && pair[1] == "user,id=nat0,restrict=on"),
        "an isolated machine starts with a restricted user network");
    let nodes: Vec<Value> = args.windows(2).filter(|pair| pair[0] == "-blockdev")
        .map(|pair| serde_json::from_str(&pair[1])).collect::<std::result::Result<_, _>>()?;
    let node = |name: &str| nodes.iter().find(|node| node["node-name"] == name).cloned()
        .ok_or_else(|| fail("A throwaway block node is missing."));
    assert_eq!(node("disk-file")?["read-only"], true);
    assert_eq!(node("persistent-system")?["read-only"], true);
    let overlay = node("system")?;
    assert_eq!(overlay["backing"], "persistent-system");
    assert!(overlay.get("read-only").is_none());
    assert!(node("throwaway-file")?["filename"].as_str().is_some_and(|name| name.contains(".throwaway-")));

    // The run cannot be checkpointed, exported, trashed or switched to normal mode.
    assert!(refusal(server.call("POST", &format!("{P}/snapshots"), Some(checkpoint), 409)?).contains("throwaway mode"));
    assert!(refusal(server.call("PATCH", P, Some(json!({"throwaway": false})), 409)?).contains("stopped"));
    let export = json!({"machineId": ID, "folder": home, "format": "vdi"});
    assert!(refusal(server.call("POST", "/v1/transfers/export", Some(export), 409)?).contains("throwaway run"));
    assert!(refusal(server.call("DELETE", P, Some(json!({"keepCopy": false})), 409)?).contains("Turn off throwaway mode"));

    // Power-off discards the overlay and leaves the persistent disk byte for byte.
    server.call("POST", &format!("{P}/stop"), Some(json!({})), 200)?;
    assert_eq!(server.call("GET", P, None, 200)?["state"], "off");
    assert!(!journal.exists() && overlays(&bundle)?.is_empty() && !bundle.join("qemu-run.json").exists());
    assert_eq!(fs::read(&disk)?, persistent);

    // An interrupted run leaves its record and overlay behind. The next service start discards
    // both, together with a stale disk-transfer stage, before anything else uses the machine.
    server.stop_server()?;
    let ticket = "0a1b-2c3d-4e5f";
    svm_core::write_json(&journal, &json!({"id": ID, "ticket": ticket}))?;
    let leftover = bundle.join(format!(".throwaway-{ticket}"));
    fs::create_dir(&leftover)?;
    fs::write(leftover.join("system.qcow2"), b"discarded guest writes")?;
    let stage_parent = home.join("interrupted-export");
    fs::create_dir(&stage_parent)?;
    let stage = stage_parent.join(".svm-transfer-stale1");
    fs::create_dir(&stage)?;
    fs::write(stage.join("owner"), "stale1")?;
    let transfer_journal = home.join("disk-transfer.json");
    svm_core::write_json(&transfer_journal, &json!({"id": "stale1", "directory": stage, "format": "qcow2"}))?;
    let server = Server::open(home)?;
    assert!(!journal.exists() && !leftover.exists(), "the interrupted throwaway run was discarded");
    assert!(!stage.exists() && !transfer_journal.exists(), "the stale transfer stage was cleaned");
    assert_eq!(fs::read(&disk)?, persistent);
    let events = server.call("GET", "/v1/events", None, 200)?;
    let recovered = events.as_array().ok_or_else(|| fail("The event list is missing."))?.iter().filter(|event| {
        event["kind"] == "throwaway disk discarded"
            && event["message"].as_str().is_some_and(|text| text.contains(ID) && text.contains("interrupted run"))
    }).count();
    assert_eq!(recovered, 1);

    // A record that recovery cannot match stays in place, and the mode cannot change until it is resolved.
    let server = { let mut server = server; server.stop_server()?;
        svm_core::write_json(&journal, &json!({"id": "someone-else", "ticket": ticket}))?;
        Server::open(home)? };
    assert!(journal.exists(), "an unverifiable record is kept");
    let stopped = server.call("GET", P, None, 200)?;
    assert_eq!(stopped["state"], "off");
    assert_eq!(stopped["registration"], "registered");
    assert!(refusal(server.call("PATCH", P, Some(json!({"throwaway": false})), 409)?).contains("still being recovered"));
    assert!(refusal(server.call("POST", &format!("{P}/start"), Some(json!({})), 409)?).contains("still being recovered"));
    let stuck = server.call("GET", "/v1/events", None, 200)?;
    assert_eq!(stuck.as_array().ok_or_else(|| fail("The event list is missing."))?.iter().filter(|event|
        event["kind"] == "throwaway recovery failed" && event["message"].as_str().is_some_and(|text| text.contains(ID))
    ).count(), 1);
    assert_eq!(server.call("GET", &format!("{P}/capabilities"), None, 200)?["EditThrowaway"]["available"], false);
    let export = json!({"machineId": ID, "folder": home, "format": "vdi"});
    assert!(refusal(server.call("POST", "/v1/transfers/export", Some(export), 409)?).contains("throwaway run"));
    fs::remove_file(&journal)?;

    // The machine is usable again: one more throwaway run, then normal mode and removal.
    server.call("POST", &format!("{P}/start"), Some(json!({})), 200)?;
    server.call("POST", &format!("{P}/stop"), Some(json!({})), 200)?;
    assert!(!journal.exists() && overlays(&bundle)?.is_empty());
    assert_eq!(fs::read(&disk)?, persistent);
    let normal = server.call("PATCH", P, Some(json!({"throwaway": false})), 200)?;
    assert_eq!(normal["throwaway"], false);
    assert_eq!(normal["isolated"], true, "isolation stays until the owner turns it off");
    assert_eq!(server.call("PATCH", P, Some(json!({"isolated": false})), 200)?["isolated"], false);
    assert!(refusal(server.call("PATCH", "/v1/machines/primary", Some(json!({"isolated": true})), 409)?).contains("QEMU machine setting"));
    server.call("DELETE", P, Some(json!({"keepCopy": false})), 200)?;

    // A purge that removed the removal receipt and then stopped (for example on a disk a scanner
    // held past the retry window) can still be finished: its own record proves the check passed.
    let entry = library.list_trash()?.into_iter().find(|row| row.machine.id == ID)
        .ok_or_else(|| fail("The throwaway machine is not in the trash."))?;
    svm_core::write_json(&entry.path.join(".delete-pending.json"), &entry.key)?;
    fs::remove_file(entry.path.join("removal-complete.json"))?;
    server.call("DELETE", &format!("/v1/trash/{}", entry.key), Some(json!({"confirmName": entry.machine.name})), 200)?;
    assert!(!library.list_trash()?.iter().any(|row| row.machine.id == ID));
    Ok(server)
}

fn configure_fixture_forward(server: &Server, path: &str) -> Result<(Value, u16)> {
    let held = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let port = held.local_addr()?.port();
    let rule = json!({"protocol":"tcp","hostPort":port,"guestPort":2222});
    let rules = json!([rule.clone()]);
    let update = json!({"portForwards":rules.clone()});
    let mut zero = rule.clone();
    zero["guestPort"] = json!(0);
    let mut wildcard = rule.clone();
    wildcard["hostAddress"] = json!("0.0.0.0");
    for invalid in [json!([zero]), json!([wildcard]), json!([rule.clone(),rule])] {
        server.call("PATCH", path, Some(json!({"portForwards":invalid})), 400)?;
    }
    let saved = server.call("PATCH", path, Some(update.clone()), 200)?;
    assert_eq!(saved["portForwards"], rules);
    assert_eq!(saved["portForwardAddress"], "127.0.0.1");
    let conflict = server.call("PATCH", "/v1/machines/legacy-linux", Some(update.clone()), 409)?;
    assert!(conflict["error"]["message"].as_str().unwrap().contains("Android fixture"));
    server.call("PATCH", "/v1/machines/primary", Some(update), 409)?;
    let blocked = server.call("POST", &format!("{path}/start"), Some(json!({})), 409)?;
    let message = blocked["error"]["message"].as_str().unwrap();
    assert!(message.contains("127.0.0.1") && message.contains(&port.to_string()));
    assert_eq!(server.call("GET", path, None, 200)?["state"], "off");
    drop(held);
    Ok((rules, port))
}

fn exercise(home:&Path,tools:&Path)->Result<()> {
    let iso=home.join("android-fixture.iso");
    fs::write(&iso,b"fixture, read only")?;
    let src=fs::metadata(&iso)?.modified()?;
    let mut server=Server::open(home)?;
    let get=server.call("GET","/v1/settings/qemu",None,200)?;
    assert_eq!(get["available"],false);
    let selected=server.call("PUT","/v1/settings/qemu",Some(json!({"path":tools})),200)?;
    assert_eq!(selected["available"],true);
    assert_eq!(selected["armAvailable"],false);
    assert_eq!(selected["openSeparateWindow"],false);
    emulated_arm(&server,home,tools,&iso)?;
    legacy_x86(&server,home,&iso)?;
    let preference=server.call("PUT","/v1/settings/qemu",Some(json!({"openSeparateWindow":true})),200)?;
    assert_eq!(preference["openSeparateWindow"],true);
    let oversized=server.call("POST","/v1/machines",Some(json!({"id":"oversized","name":"Oversized Android",
        "os":"Android-x86","family":"android","engine":"QEMU","diskGb":161,"isoPath":iso})),400)?;
    assert_eq!(oversized["error"]["message"],"The library currently has space for at most 160 GiB.");
    server.call("GET","/v1/machines/oversized",None,404)?;
    const P:&str="/v1/machines/qatest";
    let row=server.call("POST","/v1/machines",Some(json!({"id":"qatest","name":"Android fixture","os":"Android-x86",
        "family":"android","engine":"QEMU","vcpu":1,"ramGb":2,"net":"nat","isoPath":iso})),201)?;
    assert_eq!(row["engine"],"QEMU");
    assert_eq!(row["diskGb"],8);
    let lib=Library::open_stable(home.join("library"))?;
    let bundle=lib.bundle_path("qatest")?;
    assert!(bundle.join("system.qcow2").is_file());
    let caps=server.call("GET",&format!("{P}/capabilities"),None,200)?;
    assert_eq!(caps["Start"]["available"],true);
    for name in ["SnapshotWithMemory","Clone"] {
        assert!(caps[name]["available"]==false && caps[name]["reason"].as_str().is_some_and(|s|!s.is_empty()));
    }
    server.call("POST","/v1/machines",Some(json!({"id":"primary","name":"Primary fixture","os":"Other","net":"nat"})),201)?;
    let hyper=lib.bundle_path("primary")?;
    server.call("PATCH","/v1/machines/primary",Some(json!({"shareClipboard":true})),409)?;
    server.call("POST","/v1/machines/primary/start",Some(json!({})),200)?;
    server.call("POST","/v1/machines/primary/stop",Some(json!({})),200)?;
    assert!(!hyper.join("fake-starts").exists() && !bundle.join("fake-starts").exists());
    let (rules, host_port) = configure_fixture_forward(&server, P)?;
    assert!(!bundle.join("fake-starts").exists());
    server.call("POST","/v1/machines/qatest/start",Some(json!({})),200)?;
    server.call("PATCH",P,Some(json!({"portForwards":[]})),409)?;
    let first_pid=fs::read_to_string(bundle.join("fake-last-pid"))?;
    let args:Vec<String>=serde_json::from_slice(&fs::read(bundle.join("fake-arguments.json"))?)?;
    assert!(args.windows(2).any(|p|p==["-accel","whpx"]));
    assert!(!args.iter().any(|arg|arg.contains("tcg")));
    for pair in [["-machine","pc,i8042=off"],["-device","usb-kbd"],["-device","usb-tablet"],["-display","gtk,grab-on-hover=off"]] {
        assert!(args.windows(2).any(|p|p==pair));
    }
    assert!(args.windows(2).any(|p|p==["-qmp","stdio"]));
    let nat = format!("user,id=nat0,hostfwd=tcp:127.0.0.1:{host_port}-:2222");
    assert!(args.windows(2).any(|p| p[0]=="-netdev" && p[1]==nat));
    assert!(args.windows(2).filter(|p|p[0]=="-blockdev").all(|p|!p[1].contains("\"locking\":\"on\"")));
    let caps=server.call("GET",&format!("{P}/capabilities"),None,200)?;
    assert!(caps["AudioOutput"]["message"].as_str().is_some_and(|text|!text.is_empty()));
    if caps["AudioOutput"]["available"]==true {
        assert!(args.iter().any(|a|a.starts_with("hda-output,")));
        assert!(args.iter().any(|a|a.starts_with("dsound,")||a.starts_with("sdl,")));
    } else {
        assert!(!args.iter().any(|a|a.starts_with("hda-output,")));
    }
    assert!(args.windows(2).any(|p|p==["-boot","order=c,once=d"]));
    assert!(args.iter().any(|a|a.starts_with("ide-cd,drive=installer")));
    server.call("PUT",&format!("{P}/storage"),Some(json!({"isoPath":null})),409)?;
    assert_eq!(server.call("GET",P,None,200)?["state"],"running");
    let refusal=server.call("POST","/v1/shutdown",Some(json!({"ifIdle":true})),409)?;
    assert_eq!(refusal["error"]["code"],"service_in_use");
    server.stop_server()?;
    let server=Server::open(home)?;
    assert_eq!(server.call("GET",P,None,200)?["state"],"running");
    assert_eq!(server.call("GET", P, None, 200)?["portForwards"], rules);
    let retained=server.call("GET","/v1/settings/qemu",None,200)?;
    assert_eq!(retained["openSeparateWindow"],true);
    assert_eq!(fs::read_to_string(bundle.join("fake-last-pid"))?,first_pid);
    assert_eq!(fs::read_to_string(bundle.join("fake-starts"))?.lines().count(),1);
    fs::write(bundle.join("fixture-monitor-error"),b"refuse status")?;
    let reply=server.call("GET",P,None,200)?;
    assert_eq!(reply["registration"],"unknown");
    let caps=server.call("GET",&format!("{P}/capabilities"),None,200)?;
    assert_eq!(caps["Stop"]["available"],true);
    assert_eq!(caps["Start"]["available"],false);
    server.call("POST","/v1/shutdown",Some(json!({"ifIdle":true})),409)?;
    fs::remove_file(bundle.join("fixture-monitor-error"))?;
    server.call("POST",&format!("{P}/stop"),Some(json!({})),200)?;
    assert_eq!(server.call("GET",P,None,200)?["state"],"off");
    assert_eq!(server.call("PATCH", P, Some(json!({"portForwards":[]})), 200)?["portForwards"], json!([]));
    let storage=format!("{P}/storage");
    let disc=server.call("PUT",&storage,Some(json!({"isoPath":null})),200)?;
    assert_eq!(disc["bootFirst"],"disk");
    assert!(disc["isoPath"].is_null());
    server.call("PUT",&storage,Some(json!({"isoPath":iso})),200)?;
    assert_eq!(server.call("GET",&storage,None,200)?["bootFirst"],"image");
    server.call("PUT",&storage,Some(json!({"isoPath":null})),200)?;
    let moved=iso.with_extension("offline");
    fs::rename(&iso,&moved)?;
    fs::write(bundle.join("fixture-audio-error"),b"unavailable playback")?;
    server.call("POST",&format!("{P}/start"),Some(json!({})),200)?;
    let silent=server.call("GET",&format!("{P}/capabilities"),None,200)?;
    assert_eq!(silent["AudioOutput"]["available"],false);
    let disk_only:Vec<String>=serde_json::from_slice(&fs::read(bundle.join("fake-arguments.json"))?)?;
    assert!(disk_only.windows(2).any(|p|p==["-boot","order=c"]));
    assert!(!disk_only.iter().any(|a|a.contains("ide-cd")||a.contains("iso-file")||a.contains("once=d")));
    fs::rename(moved,&iso)?;
    fs::write(bundle.join("fixture-simulate-crash"),b"exit")?;
    let until=Instant::now()+Duration::from_secs(20);
    while server.call("GET",P,None,200)?["state"]!="off" {
        if Instant::now()>until{return Err(fail("An exited QEMU worker was still reported as running."));}
        thread::sleep(Duration::from_millis(100));
    }
    fs::remove_file(bundle.join("fixture-simulate-crash"))?;
    assert_eq!(fs::read_to_string(bundle.join("fake-starts"))?.lines().count(),2);
    assert!(!bundle.join("qemu-run.json").exists());
    assert_eq!(fs::metadata(iso)?.modified()?,src);
    let receipt=bundle.join("qemu-run.json");
    fs::write(&receipt,br#"{"ticket":"invalid","port":1,"tag":"invalid"}"#)?;
    assert_eq!(server.call("GET",P,None,200)?["registration"],"unknown");
    let caps=server.call("GET",&format!("{P}/capabilities"),None,200)?;
    assert_eq!(caps["Stop"]["available"],false);
    assert_eq!(caps["Start"]["available"],false);
    server.call("POST",&format!("{P}/stop"),Some(json!({})),409)?;
    fs::remove_file(receipt)?;
    assert_eq!(server.call("GET",P,None,200)?["state"],"off");
    transfers(home,&server)?;
    purge_qemu_checkpoint(&server,home)?;
    let server=throwaway(server,home)?;
    server.call("POST","/v1/shutdown",Some(json!({"ifIdle":true})),200)?;
    Ok(())
}

#[test]
fn owned_qemu_process_survives_service_restart_and_reports_crash()->Result<()> {
    let stamp=SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let home=std::env::temp_dir().canonicalize()?.join(format!("sq-{:x}",stamp as u64));
    fs::create_dir(&home)?;
    let result=std::panic::catch_unwind(|| -> Result<()> {
        let tools=fake_tools(&home)?;
        exercise(&home,&tools)
    });
    // If an assertion interrupts a running fixture, tell that exact simulated worker
    // to exit itself. The fake's control file exists only inside this test's bundle.
    if let Ok(bundle)=Library::open_stable(home.join("library")).and_then(|l|l.bundle_path("qatest")) {
        if bundle.join("fake-starts").exists(){
            fs::write(bundle.join("fixture-simulate-crash"),b"exit")?;
            let lock=fs::OpenOptions::new().read(true).write(true).open(bundle.join("fake-worker.lock"))?;
            let end=Instant::now()+Duration::from_secs(10);
            while lock.try_lock().is_err(){
                if Instant::now()>=end{return Err(fail("The simulated worker did not exit after its fixture cleanup request."));}
                thread::sleep(Duration::from_millis(60));
            }
        }
    }
    let deadline=Instant::now()+Duration::from_secs(15);
    loop {
        match fs::remove_dir_all(&home) {
            Ok(())=>break,
            Err(e) if Instant::now()>=deadline=>return Err(e.into()),
            Err(_)=>thread::sleep(Duration::from_millis(120)),
        }
    }
    match result {Ok(value)=>value,Err(panic)=>std::panic::resume_unwind(panic)}
}
