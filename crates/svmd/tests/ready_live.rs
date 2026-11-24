#![cfg(windows)]
#![forbid(unsafe_code)]
#![deny(warnings)]

//! Live check of ready-to-run images against the real service and real QEMU.
//! Opt-in only: it downloads the official images (about 5.2 GB in total), prepares their
//! templates and boots one machine from each. Set:
//!   SVM_READY_LIVE=1
//!   SVM_READY_HOME=<empty or earlier test folder for the service; never the owner's data folder>
//!   SVM_READY_QEMU=<path of qemu-system-x86_64.exe>
//!   SVM_READY_IMAGES=<optional comma list of catalog IDs>

use serde_json::{json, Value};
use std::{
    error::Error, fs, io, path::{Path, PathBuf}, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use svm::client::Client;

#[path = "../../../tests/support/test_service.rs"]
mod test_service;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn fail(message: impl Into<String>) -> Box<dyn Error> { io::Error::other(message.into()).into() }

struct Live { client: Client, started: Instant, port: u16 }

impl Live {
    fn log(&self, line: &str) { eprintln!("[ready-live {:>5}s] {line}", self.started.elapsed().as_secs()); }

    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<(u16, Value)> {
        let response = self.client.request_with_timeout(method, path, body.as_ref(), Duration::from_secs(900))?;
        Ok((response.status, serde_json::from_slice(&response.body).unwrap_or(Value::Null)))
    }

    fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let (status, value) = self.call(method, path, body)?;
        if !(200..300).contains(&status) {
            return Err(fail(format!("{method} {path}: HTTP {status}: {}", value["error"]["message"])));
        }
        Ok(value)
    }

    fn wait<T>(&self, what: &str, limit: Duration, mut step: impl FnMut() -> Result<Option<T>>) -> Result<T> {
        let start = Instant::now();
        loop {
            if let Some(value) = step()? { return Ok(value); }
            if start.elapsed() > limit { return Err(fail(format!("timed out after {}s waiting for {what}", limit.as_secs()))); }
            thread::sleep(Duration::from_secs(3));
        }
    }

    fn image(&self, id: &str) -> Result<Value> {
        let list = self.ok("GET", "/v1/ready", None)?;
        list["images"].as_array().and_then(|images| images.iter().find(|image| image["id"] == id)).cloned()
            .ok_or_else(|| fail(format!("{id} is not a bundled ready image")))
    }

    fn exec(&self, machine: &str, argv: &[&str], stdin: Option<&str>) -> Result<Value> {
        let mut body = json!({"argv": argv, "timeoutSec": 60});
        if let Some(text) = stdin { body["stdin"] = json!(text); }
        self.ok("POST", &format!("/v1/machines/{machine}/exec"), Some(body))
    }
}

fn suffix() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|time| time.as_secs() % 100_000).unwrap_or(0) }

fn get_and_prepare(live: &Live, id: &str) -> Result<Value> {
    let image = live.image(id)?;
    if !image["template"].is_null() { live.log(&format!("{id}: template already prepared")); return Ok(image); }
    // One Get, as in the interface: the service starts (or resumes) the verified download and
    // prepares the image from its own queue once the download is verified.
    if image["download"]["state"] != "verified" {
        live.log(&format!("{id}: Get downloads {} bytes from {}", image["bytes"], image["sourceHost"]));
    }
    live.ok("POST", &format!("/v1/ready/{id}/prepare"), Some(json!({})))?;
    let mut last = String::new();
    live.wait("the prepared template", Duration::from_secs(9000), || {
        let image = live.image(id)?;
        if !image["template"].is_null() { return Ok(Some(())); }
        if !image["outcome"].is_null() { return Err(fail(format!("Get {id}: {}", image["outcome"]))); }
        let progress = if image["preparing"].is_object() {
            format!("{} {}%", image["preparing"]["stage"], image["preparing"]["percent"].as_u64().unwrap_or(0) / 20 * 20)
        } else {
            let download = &image["download"];
            let percent = download["bytes"].as_u64().unwrap_or(0) * 100 / download["totalBytes"].as_u64().unwrap_or(1).max(1);
            let queued = if image["queued"] == true { ", queued" } else { "" };
            format!("download {} {}%{queued}", download["state"], percent / 25 * 25)
        };
        if progress != last { live.log(&format!("{id}: {progress}")); last = progress; }
        Ok(None)
    })?;
    let status = live.ok("GET", &format!("/v1/catalog/{id}/download"), None)?;
    live.log(&format!("{id}: download verified, signature verified = {}", status["signatureVerified"]));
    let image = live.image(id)?;
    let template = live.ok("GET", &format!("/v1/machines/{}", image["template"]["id"].as_str().unwrap_or_default()), None)?;
    if template["template"].is_null() || template["ready"]["image"] != id {
        return Err(fail(format!("{id}: the template is not sealed or not marked as this image")));
    }
    live.log(&format!("{id}: sealed template {} (disk SHA-256 {})", template["name"], template["template"]["sha256"]));
    Ok(image)
}

/// Stop, delete and purge one test machine. Used after every check and for leftovers.
fn remove_machine(live: &Live, machine: &str, name: &str) -> Result<()> {
    let state = live.ok("GET", &format!("/v1/machines/{machine}"), None)?;
    if state["state"] != "off" {
        live.ok("POST", &format!("/v1/machines/{machine}/stop"), Some(json!({})))?;
        live.wait("power off", Duration::from_secs(120), || {
            let state = live.ok("GET", &format!("/v1/machines/{machine}"), None)?;
            Ok((state["state"] == "off").then_some(()))
        })?;
    }
    live.ok("DELETE", &format!("/v1/machines/{machine}"), Some(json!({"keepCopy": false})))?;
    let trash = live.wait("the trash entry", Duration::from_secs(300), || {
        let list = live.ok("GET", "/v1/trash", None)?;
        Ok(list.as_array().and_then(|rows| rows.iter().find(|row| row["id"] == machine).cloned()))
    })?;
    let key = trash["key"].as_str().ok_or_else(|| fail("trash entry has no key"))?;
    live.ok("DELETE", &format!("/v1/trash/{key}"), Some(json!({"confirmName": name})))?;
    Ok(())
}

/// Machines this test made in an earlier, interrupted run. QEMU machines keep running when the
/// service stops, by design.
fn remove_leftovers(live: &Live) -> Result<()> {
    let machines = live.ok("GET", "/v1/machines", None)?;
    for vm in machines.as_array().into_iter().flatten() {
        let name = vm["name"].as_str().unwrap_or_default();
        if name.starts_with("Live ") && vm["linkedFrom"].is_string() && vm["ready"].is_object() {
            let id = vm["id"].as_str().unwrap_or_default();
            live.log(&format!("removing a leftover test machine: {name}"));
            remove_machine(live, id, name)?;
        }
    }
    Ok(())
}

fn launch_and_check(live: &Live, id: &str, image: &Value) -> Result<()> {
    let cloud = image["firstBoot"] == "cloud-init";
    let name = format!("Live {} {}", image["name"].as_str().unwrap_or("image"), suffix());
    let body = if cloud { json!({"name": name, "user": "labuser", "generatePassword": true}) } else { json!({"name": name}) };
    let started = Instant::now();
    let launched = live.ok("POST", &format!("/v1/ready/{id}/launch"), Some(body))?;
    let machine = launched["machine"]["id"].as_str().ok_or_else(|| fail("launch returned no machine"))?.to_owned();
    live.log(&format!("{id}: launched {name} ({machine}) in {} ms", started.elapsed().as_millis()));
    let checks = check_machine(live, id, cloud, &machine, &launched);
    let cleanup = remove_machine(live, &machine, &name);
    checks?;
    cleanup?;
    live.log(&format!("{id}: machine stopped and deleted permanently"));
    Ok(())
}

fn check_machine(live: &Live, id: &str, cloud: bool, machine: &str, launched: &Value) -> Result<()> {
    let template = launched["machine"]["linkedFrom"].as_str().ok_or_else(|| fail("the machine is not a linked clone"))?.to_owned();
    if cloud {
        let (status, refusal) = live.call("POST", &format!("/v1/machines/{template}/linked-clones"), Some(json!({"name": format!("Plain copy {}", suffix())})))?;
        if status != 409 || !refusal["error"]["message"].as_str().unwrap_or_default().contains("first-boot settings") {
            return Err(fail(format!("a plain linked clone of a cloud template was not refused: HTTP {status} {refusal}")));
        }
        live.log(&format!("{id}: a plain linked clone of the cloud template is refused"));
    }
    if cloud {
        let password = launched["password"].as_str().ok_or_else(|| fail("no generated password"))?;
        if password.len() != 20 { return Err(fail("the generated password has the wrong length")); }
        if launched["machine"]["ready"]["seed"] != true { return Err(fail("the cloud machine has no first-boot seed")); }
    } else {
        if !launched["password"].is_null() { return Err(fail("a default-login image returned a password")); }
        let (status, refusal) = live.call("PATCH", &format!("/v1/machines/{machine}"),
            Some(json!({"portForwards": [{"protocol": "tcp", "hostPort": 42222, "guestPort": 22}]})))?;
        if status != 409 || !refusal["error"]["message"].as_str().unwrap_or_default().contains("default password") {
            return Err(fail(format!("port forwards were not refused for the default login: HTTP {status} {refusal}")));
        }
        live.log(&format!("{id}: port forwards refused while the default login is in use"));
        live.ok("PATCH", &format!("/v1/machines/{machine}"), Some(json!({"throwaway": true})))?;
        let (status, refusal) = live.call("POST", &format!("/v1/machines/{machine}/default-login"), Some(json!({"changed": true})))?;
        if status != 409 || !refusal["error"]["message"].as_str().unwrap_or_default().contains("throwaway") {
            return Err(fail(format!("a throwaway machine accepted a default-login confirmation: HTTP {status} {refusal}")));
        }
        live.ok("PATCH", &format!("/v1/machines/{machine}"), Some(json!({"throwaway": false})))?;
        live.log(&format!("{id}: a throwaway machine cannot confirm a changed password"));
    }
    live.ok("POST", &format!("/v1/machines/{machine}/start"), Some(json!({})))?;
    let boot = Instant::now();
    let agent = live.wait("the guest agent", Duration::from_secs(if cloud { 900 } else { 420 }), || {
        let (status, value) = live.call("GET", &format!("/v1/machines/{machine}/agent"), None)?;
        Ok((status == 200 && value["present"] == true).then_some(value))
    });
    match &agent {
        Ok(value) => live.log(&format!("{id}: guest agent answered after {}s ({})", boot.elapsed().as_secs(), value["version"])),
        Err(error) => live.log(&format!("{id}: guest agent did not answer: {error}")),
    }
    if cloud {
        agent?;
        let user = live.exec(machine, &["/usr/bin/id", "labuser"], None)?;
        if user["exitCode"] != 0 || !user["stdout"].as_str().unwrap_or_default().contains("(sudo)") {
            return Err(fail(format!("labuser was not created as a sudo user: {user}")));
        }
        let shadow = live.exec(machine, &["/usr/bin/getent", "shadow", "labuser"], None)?;
        if !shadow["stdout"].as_str().unwrap_or_default().starts_with("labuser:$6$") {
            return Err(fail("labuser has no SHA-512-crypt password"));
        }
        let ssh = live.exec(machine, &["/usr/sbin/sshd", "-T"], None)?;
        if ssh["stdout"].as_str().unwrap_or_default().lines().any(|line| line.trim() == "passwordauthentication yes") {
            return Err(fail("SSH password sign-in is on"));
        }
        let instance = live.exec(machine, &["/usr/bin/cloud-init", "query", "v1.instance_id"], None)?;
        if instance["stdout"].as_str().unwrap_or_default().trim() != machine {
            return Err(fail(format!("cloud-init did not use this machine's settings volume: {instance}")));
        }
        let size = live.exec(machine, &["/usr/bin/df", "--output=size", "-B1", "/"], None)?;
        let bytes: u64 = size["stdout"].as_str().unwrap_or_default().lines().nth(1).and_then(|line| line.trim().parse().ok()).unwrap_or(0);
        if bytes < 15_000_000_000 { return Err(fail(format!("the root file system did not grow: {bytes} bytes"))); }
        let host = live.exec(machine, &["/usr/bin/hostname"], None)?;
        live.log(&format!("{id}: labuser is a sudo user with a $6$ hash; SSH passwords off; instance ID matches; root file system {:.1} GB; host name {}",
            bytes as f64 / 1e9, host["stdout"].as_str().unwrap_or_default().trim()));
        // A guest without isolation reaches the host's 127.0.0.1 through 10.0.2.2. The service, QEMU
        // supervisors and QEMU displays listen on another loopback address, which it must not reach.
        let decoy = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let probe = |port: u16| -> Result<String> {
            let script = format!("timeout 5 bash -c '</dev/tcp/10.0.2.2/{port}' 2>/dev/null && echo reachable || echo refused");
            let result = live.exec(machine, &["/bin/bash", "-c", &script], None)?;
            Ok(result["stdout"].as_str().unwrap_or_default().trim().to_owned())
        };
        let (control, service) = (probe(decoy.local_addr()?.port())?, probe(live.port)?);
        if control != "reachable" || service != "refused" {
            return Err(fail(format!("guest reachability: a host 127.0.0.1 port is {control}, the service port is {service}")));
        }
        live.log(&format!("{id}: the guest reaches a test port on the host's 127.0.0.1 but not the service port {}", live.port));
    } else if agent.is_ok() {
        let new_password = format!("Live-{}-Check", suffix());
        let changed = live.exec(machine, &["/usr/sbin/chpasswd"], Some(&format!("kali:{new_password}\n")))?;
        if changed["exitCode"] != 0 { return Err(fail(format!("chpasswd failed: {changed}"))); }
        let cleared = live.ok("POST", &format!("/v1/machines/{machine}/default-login"), Some(json!({"changed": true})))?;
        if !cleared["ready"]["defaultLogin"].is_null() { return Err(fail("the default-login flag was not cleared")); }
        let desktop = live.exec(machine, &["/usr/bin/systemctl", "is-active", "lightdm"], None)?;
        live.log(&format!("{id}: password changed through the guest agent; default-login flag cleared; display manager {}",
            desktop["stdout"].as_str().unwrap_or_default().trim()));
    } else {
        thread::sleep(Duration::from_secs(30));
        let state = live.ok("GET", &format!("/v1/machines/{machine}"), None)?;
        if state["state"] != "running" { return Err(fail("the desktop image stopped running")); }
        live.log(&format!("{id}: still running after the agent wait; this image has no guest agent, so its screen must be checked by eye"));
    }
    Ok(())
}

#[test]
#[ignore = "downloads official images (about 5.2 GB), prepares templates and boots real QEMU guests"]
fn ready_images_get_prepare_launch_and_boot() -> Result<()> {
    if std::env::var("SVM_READY_LIVE").as_deref() != Ok("1") { return Err(fail("Set SVM_READY_LIVE=1 to run this live check.")); }
    let home = PathBuf::from(std::env::var_os("SVM_READY_HOME").ok_or_else(|| fail("Set SVM_READY_HOME to a test folder."))?);
    let qemu = PathBuf::from(std::env::var_os("SVM_READY_QEMU").ok_or_else(|| fail("Set SVM_READY_QEMU to qemu-system-x86_64.exe."))?);
    let images: Vec<String> = std::env::var("SVM_READY_IMAGES").ok().filter(|text| !text.trim().is_empty())
        .map_or_else(|| vec!["debian-13-20261123-cloud-amd64".into(), "ubuntu-26-04-20261108-cloud-amd64".into(), "kali-2026-3-qemu-amd64".into()],
            |text| text.split(',').map(|id| id.trim().to_owned()).collect());
    fs::create_dir_all(&home)?;
    let mut service = test_service::TestService::spawn(Path::new(env!("CARGO_BIN_EXE_svmd")), &home)?;
    let started = Instant::now();
    let client = loop {
        if let Ok(client) = Client::load(&home, None) {
            if client.request("GET", "/v1/health", None).is_ok_and(|response| response.status == 200) { break client; }
        }
        if started.elapsed() > Duration::from_secs(60) { return Err(fail("the test service did not start")); }
        thread::sleep(Duration::from_millis(500));
    };
    let port = fs::read_to_string(home.join("api-port"))?.trim().parse()?;
    let live = Live { client, started, port };
    let result = (|| -> Result<()> {
        // The setting is kept in the test folder; QEMU cannot be changed while a machine runs.
        if live.ok("GET", "/v1/settings/qemu", None)?["available"] != true {
            live.ok("PUT", "/v1/settings/qemu", Some(json!({"path": qemu})))?;
        }
        remove_leftovers(&live)?;
        for id in &images {
            let image = get_and_prepare(&live, id)?;
            launch_and_check(&live, id, &image)?;
        }
        Ok(())
    })();
    if let Err(error) = &result { live.log(&format!("FAILED: {error}")); }
    let _ = live.call("POST", "/v1/shutdown", Some(json!({})));
    let _ = service.finish(Duration::from_secs(60));
    result
}
