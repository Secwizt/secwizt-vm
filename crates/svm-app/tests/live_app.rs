#![cfg(windows)]
#![forbid(unsafe_code)]
#![deny(warnings)]

use serde_json::{json, Value};
use std::{error::Error, fs, io, os::windows::process::CommandExt, path::{Path,PathBuf},
    process::{Child,Command,Stdio}, thread, time::{Duration,Instant,SystemTime,UNIX_EPOCH}};
#[path = "../../../tests/support/test_service.rs"]
mod test_service;
#[path = "../../../tests/support/hyperv_cleanup.rs"]
mod hyperv_cleanup;

use svm::client::Client;
use svm_app::{handle,PageResponse};
use svm_hyperv::{HyperV,WindowsPowerShell};

type Result<T> = std::result::Result<T,Box<dyn Error>>;
fn problem(message: &str) -> Box<dyn Error> { io::Error::other(message).into() }

fn inventory() -> Result<Vec<u8>> {
    let windows = std::env::var_os("SystemRoot").ok_or_else(||problem("Cannot find the Windows folder."))?;
    let script = r#"$ErrorActionPreference='Stop'
$machines=@(Get-VM | Where-Object { $_.Notes -like 'secwiz-vm:*' } | ForEach-Object { $_.VMId.ToString() } | Sort-Object)
$switches=@(Get-VMSwitch | ForEach-Object { $_.Id.ToString() } | Sort-Object)
$addresses=@(Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 | ForEach-Object { $_.IPAddress+'/'+$_.PrefixLength } | Sort-Object)
[Console]::Write((@{machines=$machines;switches=$switches;addresses=$addresses} | ConvertTo-Json -Compress))"#;
    let out = Command::new(PathBuf::from(windows).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile","-NonInteractive","-Command",script]).creation_flags(0x08000000)
        .stdin(Stdio::null()).output()?;
    if !out.status.success() { return Err(problem("The host inventory could not be verified.")); }
    Ok(out.stdout)
}

fn request(home:&Path,method:&str,path:&str,body:Option<Value>) -> Result<PageResponse> {
    let bytes = body.map(|v| serde_json::to_vec(&v)).transpose()?.unwrap_or_default();
    let response = handle(home,method,&format!("/api{path}"),Some("application/json"),&bytes);
    if !(200..300).contains(&response.status) {
        let value:Value = serde_json::from_slice(&response.body)?;
        return Err(problem(value["error"]["message"].as_str().unwrap_or("The proxy returned an error.")));
    }
    Ok(response)
}
fn json_request(home:&Path,method:&str,path:&str,body:Option<Value>) -> Result<Value> {
    Ok(serde_json::from_slice(&request(home,method,path,body)?.body)?)
}
fn id_from(vm:&Value) -> Result<&str> {
    vm["id"].as_str().filter(|s| !s.is_empty() && !s.contains(['/', '\\', '%', '?', '#']))
        .ok_or_else(||problem("The fixture has no usable service identifier."))
}
fn exercise(home:&Path, id:&str) -> Result<()> {
    let created = json_request(home,"POST","/v1/machines",Some(json!({
        "id":id,"name":"Desktop proxy fixture","os":"Empty firmware guest","family":"other","vcpu":1,"ramGb":1,"net":"nat"
    })))?;
    let route = format!("/v1/machines/{}",id_from(&created)?);
    json_request(home,"POST",&format!("{route}/start"),Some(json!({})))?;
    let frame = request(home,"GET",&format!("{route}/thumbnail"),None)?;
    assert!(frame.headers.contains(&("X-Pixel-Format".into(),"RGBA8".into())));
    assert_eq!(frame.body.len(),320*240*4);
    json_request(home,"POST",&format!("{route}/stop"),Some(json!({})))?;
    let removed = json_request(home,"DELETE",&route,None)?;
    assert_eq!(removed["trashed"],true);
    assert_eq!(removed["removalPath"],"bundle-only");
    Ok(())
}

fn ready(home:&Path,child:&mut Child) -> Result<()> {
    let deadline = Instant::now()+Duration::from_secs(90);
    while Instant::now()<deadline {
        if child.try_wait()?.is_some() { return Err(problem("The fixture service exited before becoming ready.")); }
        if handle(home,"GET","/api/v1/health",None,&[]).status == 200 { return Ok(()); }
        thread::sleep(Duration::from_millis(150));
    }
    Err(problem("The fixture service did not become ready."))
}
fn cleanup(home:&Path,service:&mut test_service::TestService) -> Result<()> {
    let result = (|| -> Result<()> {
        let guests = json_request(home,"GET","/v1/machines",None)?;
        for vm in guests.as_array().ok_or_else(||problem("Invalid fixture inventory."))? {
            if vm["name"]!="Desktop proxy fixture" { return Err(problem("An unexpected guest exists in the private fixture.")); }
            let path = format!("/v1/machines/{}",id_from(vm)?);
            if vm["state"]!="off" { json_request(home,"POST",&format!("{path}/stop"),Some(json!({})))?; }
            json_request(home,"DELETE",&path,None)?;
        }
        Ok(())
    })();
    let shutdown = (|| -> Result<()> {
        if service.child.try_wait()?.is_none() {
            let client = Client::load(home,None)?;
            if client.request_with_timeout("POST","/v1/shutdown",Some(&json!({})),Duration::from_secs(15))?.status!=200 {
                return Err(problem("The fixture service could not shut down."));
            }
        }
        Ok(())
    })();
    let exit = service.finish(Duration::from_secs(20));
    result?;
    shutdown?;
    Ok(exit?)
}

#[test]
#[ignore = "requires Hyper-V and SVM_APP_LIVE=1"]
fn desktop_proxy_lifecycle() -> Result<()> {
    if std::env::var("SVM_APP_LIVE").as_deref()!=Ok("1") { return Ok(()); }
    let before:Value = serde_json::from_slice(&inventory()?)?;
    let engine = HyperV::new(WindowsPowerShell::default(),[]);
    let default = engine.default_switch_info()?;
    let test = std::env::current_exe()?;
    let daemon = test.parent().and_then(Path::parent).ok_or_else(||problem("Build the workspace binaries first."))?.join("svmd.exe");
    if !daemon.is_file(){return Err(problem("Build svmd.exe in the same target profile before running this test."));}
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let home = std::env::temp_dir().canonicalize()?.join(format!("svm-app-{}-{stamp}",std::process::id()));
    fs::create_dir(&home)?;
    let mut service = match test_service::TestService::spawn(&daemon,&home) {
        Ok(service)=>service, Err(error)=>{ fs::remove_dir(&home)?; return Err(error.into()); }
    };
    let id = format!("test-desktop-{:x}",stamp as u64);
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
        ready(&home,&mut service.child)?; exercise(&home,&id)
    }));
    let cleaned=cleanup(&home,&mut service);
    if cleaned.is_err(){hyperv_cleanup::remove_owned(&home,Some(&id),None)?;}
    fs::remove_dir_all(&home)?;
    cleaned?;
    if before!=serde_json::from_slice::<Value>(&inventory()?)? || default!=engine.default_switch_info()?{
        return Err(problem("Host inventory changed during the desktop check."));
    }
    match run {Ok(result)=>result,Err(panic)=>std::panic::resume_unwind(panic)}
}
