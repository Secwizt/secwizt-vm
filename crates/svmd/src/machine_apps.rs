use super::*;
use super::{agent::GuestCommand, app_catalog::{self, Action, App, Step, Target}};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PREVIEW_LIFETIME: Duration = Duration::from_secs(300);
const LOG_BYTES: usize = 8192;

#[derive(Default)]
pub(super) struct GuestApps {
    previews: BTreeMap<String, Preview>,
    jobs: BTreeMap<String, Arc<Mutex<Progress>>>,
}

struct Preview {
    id: String,
    app: String,
    action: Action,
    target: Target,
    expires: Instant,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    action: Action,
    access: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RunRequest {
    preview_id: String,
    access: Value,
}

struct Progress {
    id: String,
    app: String,
    action: Action,
    state: &'static str,
    step: Option<usize>,
    message: String,
    log: Vec<Value>,
}

impl Progress {
    fn wire(&self) -> Value {
        json!({"id": self.id, "app": self.app, "action": self.action, "state": self.state,
            "step": self.step, "message": self.message, "log": self.log})
    }
}

impl GuestApps {
    pub(super) fn forget(&mut self, id: &str) {
        self.previews.remove(id);
        self.jobs.remove(id);
    }
}

fn entries() -> Result<&'static [App], ApiError> {
    app_catalog::entries().map_err(|message| ApiError::new(500, "app_catalog", message))
}

fn entry(id: &str) -> Result<&'static App, ApiError> {
    entries()?.iter().find(|app| app.id == id).ok_or_else(ApiError::missing)
}

fn windows(vm: &Vm) -> bool { vm.family == GuestFamily::Windows }

fn eligible(vm: &Vm, networks: &[Network], app: &App) -> Result<(), ApiError> {
    if vm.state != VmState::Running {
        return Err(refused("Start the machine before using the app catalog."));
    }
    if vm.isolated || !networks.iter().any(|net| net.id == vm.net &&
        matches!(net.mode, NetworkMode::Nat | NetworkMode::Routed | NetworkMode::Bridged))
    {
        return Err(refused(if vm.throwaway { "This isolated throwaway machine cannot reach package sources." }
            else { "This machine has no network that can reach package sources." }));
    }
    if !matches!((vm.engine, vm.family), (EngineKind::Qemu | EngineKind::HyperV, GuestFamily::Linux)
        | (EngineKind::HyperV, GuestFamily::Windows))
        || !app.may_use(windows(vm))
    {
        return Err(refused("This app has no install recipe for this guest and command channel."));
    }
    Ok(())
}

fn checked_target(run: &GuestCommand, windows: bool) -> Result<Target, ApiError> {
    let result = run(app_catalog::probe(windows))?;
    target_result(windows, &result)
}

fn target_result(windows: bool, result: &Value) -> Result<Target, ApiError> {
    if result["exitCode"] != 0 || result["stdoutTruncated"] == true {
        return Err(refused(if windows {
            "PowerShell Direct must be able to run Microsoft App Installer and verify the winget source for this account."
        } else { "The guest command channel could not read the Linux distribution. Check the guest agent or SSH access." }));
    }
    Target::from_probe(windows, result["stdout"].as_str().unwrap_or_default())
        .ok_or_else(|| refused("This Linux distribution or release has no app recipe."))
}

fn limited_text(result: &Value, field: &str, cut: &str) -> String {
    let output = result[field].as_str().unwrap_or_default();
    if output.len() <= LOG_BYTES && result[cut] != true { return output.to_owned(); }
    let mut end = output.len().min(LOG_BYTES);
    while !output.is_char_boundary(end) { end -= 1; }
    format!("{}\n[Output truncated]", &output[..end])
}

fn change_progress(progress: &Mutex<Progress>, change: impl FnOnce(&mut Progress)) {
    change(&mut progress.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
}

fn execute_job(progress: &Mutex<Progress>, steps: Vec<Step>, target: Target, windows: bool, run: &GuestCommand) {
    for (index, step) in steps.into_iter().enumerate() {
        let number = index + 1;
        change_progress(progress, |job| {
            job.step = Some(number);
            job.message = step.title.to_owned();
            job.log.push(json!({"step": number, "title": step.title, "state": "running"}));
        });
        let result = run(step.command);
        let (output, failure) = match result {
            Ok(report) => {
                let failure = if report["exitCode"] != 0 {
                    let detail = if let Some(code) = report["exitCode"].as_i64() { format!("exit code {code}") }
                        else if let Some(signal) = report["signal"].as_i64() { format!("signal {signal}") }
                        else { "the guest did not return an exit code".into() };
                    Some(detail)
                } else if index == 0 && target_result(windows, &report).ok() != Some(target) {
                    Some("the guest profile changed after the preview".into())
                } else { None };
                (json!({"stdout": limited_text(&report, "stdout", "stdoutTruncated"),
                    "stderr": limited_text(&report, "stderr", "stderrTruncated")}), failure)
            }
            Err(error) => (Value::Null, Some(error.message)),
        };
        change_progress(progress, |job| {
            job.log[number - 1] = json!({"step": number, "title": step.title,
                "state": if failure.is_some() { "failed" } else { "succeeded" }, "output": output});
            if let Some(detail) = &failure {
                job.state = "failed";
                job.message = format!("Step {number} failed. {} ({detail})", step.title);
            }
        });
        if failure.is_some() { return; }
    }
    change_progress(progress, |job| {
        job.state = "succeeded";
        job.message = if job.action == Action::Install { "Install completed." } else { "Uninstall completed." }.into();
    });
}

impl Machines {
    pub(crate) fn app_catalog_route(&self, parts: &[&str], networks: &[Network]) -> Result<Reply, ApiError> {
        match parts {
            ["catalog", "apps"] => Ok(Reply::json(json!(entries()?.iter().map(App::public).collect::<Vec<_>>()))),
            ["catalog", "apps", app_id, "machines"] => {
                let app = entry(app_id)?;
                let machines: Vec<_> = self.inventory.iter().filter(|vm| vm.state == VmState::Running
                    && self.available(&vm.id).is_ok() && app.may_use(windows(vm))
                    && matches!((vm.engine, vm.family), (EngineKind::Qemu | EngineKind::HyperV, GuestFamily::Linux)
                        | (EngineKind::HyperV, GuestFamily::Windows)))
                    .map(|vm| json!({"id": vm.id, "name": vm.name, "family": vm.family, "engine": vm.engine,
                        "reason": eligible(vm, networks, app).err().map(|error| error.message)})).collect();
                Ok(Reply::json(json!(machines)))
            }
            _ => Err(ApiError::missing()),
        }
    }

    pub(crate) fn app_job(&self, id: &str) -> Result<Reply, ApiError> {
        self.vm(id)?;
        let status = self.guest_apps.jobs.get(id).map(|job| {
            job.lock().unwrap_or_else(std::sync::PoisonError::into_inner).wire()
        });
        Ok(Reply::json(json!(status)))
    }

    pub(super) fn prepare_app(
        &mut self, method: &str, parts: &[&str], body: &Value, networks: &[Network], events: &mut Events,
    ) -> Result<Option<BackgroundTask>, ApiError> {
        let ("POST", ["machines", id, "apps", app_id, route @ ("preview" | "run")]) = (method, parts)
            else { return Ok(None); };
        if self.background_busy() || self.converting() {
            return Err(refused("Wait for the current guest or machine operation to finish."));
        }
        let app = entry(app_id)?;
        self.refresh_after(events, Some(id), None)?;
        let vm = self.vm(id)?;
        self.available(id)?;
        eligible(&vm, networks, app)?;
        let windows = windows(&vm);
        let hyperv = vm.engine == EngineKind::HyperV;
        let machine = vm.id.clone();

        let (accepted, run): (_, Box<dyn FnOnce() -> MachineCompletion + Send>) = if *route == "preview" {
            let request: PreviewRequest = parsed(body)?;
            let channel = self.app_guest_channel(vm, &request.access)?;
            self.guest_apps.previews.remove(*id);
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).map_err(|_| ApiError::new(500, "app_preview", "Could not create a confirmation for this preview."))?;
            let preview_id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let run = move || -> MachineCompletion {
                let result = (|| {
                    let target = checked_target(&channel, windows)?;
                    let steps = app.plan(target, request.action)
                        .ok_or_else(|| refused("This app has no recipe for the guest's Linux distribution."))?;
                    if app.needs_docker(target) && channel(app_catalog::docker_probe().command)?["exitCode"] != 0 {
                        return Err(refused("Docker must already be installed and running inside this machine."));
                    }
                    Ok(Preview { id: preview_id, app: app.id.clone(), action: request.action,
                        target, expires: Instant::now() + PREVIEW_LIFETIME, steps })
                })();
                Box::new(move |machines, _, _| {
                    let preview = result?;
                    let reply = Reply::json(json!({"previewId": preview.id,
                        "steps": preview.steps.iter().map(Step::preview).collect::<Vec<_>>()}));
                    machines.guest_apps.previews.insert(machine, preview);
                    Ok(reply)
                })
            };
            (None, Box::new(run))
        } else {
            let request: RunRequest = parsed(body)?;
            let preview = self.guest_apps.previews.get(*id).filter(|preview|
                preview.id == request.preview_id && preview.app == app.id && preview.expires > Instant::now())
                .ok_or_else(|| refused("Check this machine and review a fresh command preview before continuing."))?;
            let channel = self.app_guest_channel(vm, &request.access)?;
            let progress = Arc::new(Mutex::new(Progress { id: preview.id.clone(), app: app.name.clone(),
                action: preview.action, state: "running", step: None, message: "Starting guest app operation.".into(),
                log: Vec::new() }));
            let reply = Reply::json_status(202, json!({"id": preview.id}));
            let preview = self.guest_apps.previews.remove(*id).expect("preview was validated on this worker");
            self.guest_apps.jobs.insert(machine, progress.clone());
            let run = move || -> MachineCompletion {
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                    execute_job(&progress, preview.steps, preview.target, windows, &channel))).is_err()
                {
                    change_progress(&progress, |job| {
                        job.state = "failed";
                        job.message = "The guest app operation ended unexpectedly. Check the guest before retrying.".into();
                    });
                }
                Box::new(|_, _, _| Ok(Reply::json(Value::Null)))
            };
            (Some(reply), Box::new(run))
        };
        Ok(Some(BackgroundTask { machines: vec![id.to_string()], reserved: None, hyperv,
            qemu_checkpoint: false, catalog_io: false, accepted, run }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marketplace_refuses_stopped_isolated_and_incompatible_machines() {
        let app = entry("git").unwrap();
        let mut vm: Vm = serde_json::from_value(json!({"id":"vm-fixture","name":"Fixture","os":"Debian",
            "family":"linux","engine":"QEMU","accel":true,"state":"off","vcpu":1,"ramGb":1,
            "net":"nat","ip":"192.0.2.10","mac":"02:77:00:00:00:01","dns":"fixture.vm.lan"})).unwrap();
        let network = Network { bridge: None, id: "nat".into(), name: "NAT".into(), mode: NetworkMode::Nat,
            subnet: "192.0.2.0/24".parse().unwrap(), gateway: None, dhcp: true, note: String::new() };
        let mut networks = [network];
        assert!(eligible(&vm, &networks, app).unwrap_err().message.contains("Start the machine"));
        vm.state = VmState::Running;
        assert!(eligible(&vm, &networks, app).is_ok());
        vm.throwaway = true;
        vm.isolated = true;
        assert!(eligible(&vm, &networks, app).unwrap_err().message.contains("isolated throwaway"));
        vm.isolated = false;
        networks[0].mode = NetworkMode::HostOnly;
        assert!(eligible(&vm, &networks, app).is_err());
        networks[0].mode = NetworkMode::Nat;
        vm.family = GuestFamily::Bsd;
        assert!(eligible(&vm, &networks, app).unwrap_err().message.contains("no install recipe"));
    }

    #[test]
    fn changed_guest_fails_before_any_package_command() {
        let target = Target::from_probe(false, "ID=debian\nVERSION_CODENAME=trixie\nSVM_MARKET_ARCH=x86_64").unwrap();
        let steps = entry("git").unwrap().plan(target, Action::Install).unwrap();
        let job = Mutex::new(Progress { id: "fixture".into(), app: "Git".into(), action: Action::Install,
            state: "running", step: None, message: String::new(), log: Vec::new() });
        let channel: GuestCommand = Box::new(|command| {
            assert_eq!(command.timeout_sec, 18);
            Ok(json!({"exitCode":0,"stdout":"ID=fedora\nSVM_MARKET_ARCH=x86_64\n"}))
        });
        execute_job(&job, steps, target, false, &channel);
        let job = job.into_inner().unwrap();
        assert_eq!(job.state, "failed");
        assert_eq!(job.step, Some(1));
        assert_eq!(job.log.len(), 1);
        assert!(job.message.contains("guest profile changed"));
    }
}
