use super::*;

use svm_core::engine::GuestExecRequest;
use svm_hyperv::{LinuxSshAccess, WindowsGuestCredentials};

fn exec_error(error: EngineError) -> ApiError {
    match error {
        EngineError::Timeout { .. } => ApiError::new(504, "guest_exec_timeout",
            "The guest command timed out. The command may still be running inside the guest."),
        other => engine(other),
    }
}

fn command(fields: &serde_json::Map<String, Value>) -> Result<GuestExecRequest, ApiError> {
    let input = fields.iter().filter(|(key, _)| !matches!(key.as_str(), "credentials" | "ssh"))
        .map(|(key,value)| (key.clone(),value.clone())).collect();
    let command: GuestExecRequest = serde_json::from_value(Value::Object(input))
        .map_err(|_| bad("Use argv, timeoutSec and optional stdin for the guest command."))?;
    command.check().map_err(|error| bad(error.to_string()))?;
    Ok(command)
}

enum HyperVAccess {
    Windows(WindowsGuestCredentials),
    Linux(LinuxSshAccess),
}

impl HyperVAccess {
    fn parse(vm: &Vm, fields: &serde_json::Map<String, Value>) -> Result<Self, ApiError> {
        match vm.family {
            GuestFamily::Windows if !fields.contains_key("ssh") => {
                let error = || bad("Enter the Windows guest username and password for this run.");
                let access: WindowsGuestCredentials = serde_json::from_value(fields.get("credentials").cloned().ok_or_else(error)?)
                    .map_err(|_|error())?;
                access.check().map_err(|_|error())?;
                Ok(Self::Windows(access))
            }
            GuestFamily::Linux if !fields.contains_key("credentials") => {
                let error = || bad("Supply a Linux guest username and its SSH host key.");
                let access: LinuxSshAccess = serde_json::from_value(fields.get("ssh").cloned().ok_or_else(error)?)
                    .map_err(|_|error())?;
                access.check().map_err(|error|bad(error.to_string()))?;
                Ok(Self::Linux(access))
            }
            _ => Err(refused("This Hyper-V guest cannot use the requested command channel.")),
        }
    }

    fn run(&self, driver: &dyn MachineEngine, vm: &Vm, command: GuestExecRequest) -> Result<Value, ApiError> {
        match self {
            Self::Windows(access) => driver.windows_guest_exec(vm, command, access.clone()),
            Self::Linux(access) => driver.linux_guest_exec(vm, command, access.clone()),
        }.map_err(exec_error)
    }
}

pub(super) type GuestCommand = Box<dyn Fn(GuestExecRequest) -> Result<Value, ApiError> + Send>;

impl Machines {
    pub(super) fn app_guest_channel(&self, vm: Vm, access: &Value) -> Result<GuestCommand, ApiError> {
        let fields = access.as_object().ok_or_else(|| bad("Supply a guest access object."))?;
        match vm.engine {
            EngineKind::HyperV if fields.len() == 1 => {
                let access = HyperVAccess::parse(&vm, fields)?;
                let driver = self.engine.background_driver()
                    .ok_or_else(|| refused("This host cannot run Hyper-V guest commands."))?;
                Ok(Box::new(move |command| access.run(&*driver, &vm, command)))
            }
            EngineKind::Qemu if fields.is_empty() => {
                let agent = self.qemu.guest_agent(&vm).map_err(engine)?;
                Ok(Box::new(move |command| agent.execute(command).map_err(exec_error)))
            }
            _ => Err(bad("Use the existing guest command channel for this machine.")),
        }
    }
}

fn ipv4_from_agent(interfaces: &Value) -> Option<std::net::Ipv4Addr> {
    interfaces.as_array()?.iter()
        .filter_map(|interface|interface["ip-addresses"].as_array())
        .flatten()
        .filter(|address|address["ip-address-type"] == "ipv4")
        .filter_map(|address|address["ip-address"].as_str()?.parse::<std::net::Ipv4Addr>().ok())
        .filter(|ip|!ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast())
        .min_by_key(std::net::Ipv4Addr::is_link_local)
}

impl Machines {
    pub(super) fn prepare_agent(
        &mut self, method: &str, parts: &[&str], body: &Value, events: &mut Events,
    ) -> Result<Option<BackgroundTask>, ApiError> {
        let (id, route) = match (method, parts) {
            ("GET", ["machines", id, "agent"]) => (*id, "agent"),
            ("POST", ["machines", id, route @ ("exec" | "ssh-key")]) => (*id, *route),
            _ => return Ok(None),
        };
        let vm = self.vm(id)?;
        if vm.family == GuestFamily::Android {
            return Err(refused("Android guests have no guest agent."));
        }
        if self.background_busy() || self.converting() {
            return Err(refused("Wait for the current machine or disk operation to finish."));
        }
        if vm.engine == EngineKind::HyperV {
            if route == "agent" { return Err(refused("This engine has no guest-agent status channel.")); }
            let fields = body.as_object().ok_or_else(|| bad("Supply a guest command object."))?;
            let task = if route == "exec" {
                Some((command(fields)?, HyperVAccess::parse(&vm, fields)?))
            } else if vm.family == GuestFamily::Linux && fields.is_empty() {
                None
            } else {
                return Err(refused("SSH key enrollment is available for Hyper-V Linux guests."));
            };
            let driver = self.engine.background_driver().ok_or_else(|| refused("This host cannot run Hyper-V guest commands."))?;
            self.available(id)?;
            let run = move || -> MachineCompletion {
                let result = match task {
                    Some((command, access)) => access.run(&*driver, &vm, command),
                    None => driver.guest_ssh_key(&vm).map(|key|json!({"publicKey":key})).map_err(exec_error),
                };
                Box::new(move |_, _, _| result.map(Reply::json))
            };
            return Ok(Some(BackgroundTask { machines: vec![id.to_owned()], reserved: None, hyperv: false, qemu_checkpoint: false, catalog_io: false, accepted: None, run: Box::new(run) }));
        }
        if vm.engine != EngineKind::Qemu || route == "ssh-key" {
            return Err(refused("This engine has no requested guest command channel."));
        }
        let input = if route == "exec" {
            let input: GuestExecRequest = serde_json::from_value(body.clone())
                .map_err(|_| bad("Use argv, timeoutSec and optional stdin for the guest command."))?;
            input.check().map_err(|error| bad(error.to_string()))?;
            Some(input)
        } else { None };
        self.refresh_after(events, Some(id), None)?;
        let vm = self.vm(id)?;
        self.available(id)?;
        let agent = self.qemu.guest_agent(&vm).map_err(engine)?;
        let id = id.to_owned();
        let run = move || -> MachineCompletion {
            match input {
                Some(input) => {
                    let result = agent.execute(input).map_err(exec_error);
                    Box::new(move |_, _, _| result.map(Reply::json))
                }
                None => {
                    let mut status = agent.status();
                    let ip = if status["present"] == true {
                        agent.interfaces().ok().as_ref().and_then(ipv4_from_agent)
                    } else { None };
                    status["ip"] = json!(ip);
                    status["addressSource"] = if ip.is_some() { json!("guest agent") } else { Value::Null };
                    Box::new(move |machines, _, _| {
                        if machines.vm(&id)?.state != VmState::Running || machines.available(&id).is_err() {
                            return Err(refused("The machine stopped or could no longer be verified during the guest-agent check."));
                        }
                        if let Some(ip) = ip { machines.agent_ipv4.insert(id, ip); }
                        else { machines.agent_ipv4.remove(&id); }
                        Ok(Reply::json(status))
                    })
                }
            }
        };
        Ok(Some(BackgroundTask { machines: vec![vm.id], reserved: None, hyperv: false, qemu_checkpoint: false, catalog_io: false, accepted: None, run: Box::new(run) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_ip_is_taken_only_from_a_usable_ipv4_address() {
        let interfaces = json!([
            {"ip-addresses":[{"ip-address-type":"ipv4","ip-address":"127.0.0.1"}]},
            {"ip-addresses":[{"ip-address-type":"ipv4","ip-address":"169.254.9.8"},
                {"ip-address-type":"ipv6","ip-address":"::1"},
                {"ip-address-type":"ipv4","ip-address":"10.0.2.15"}]}
        ]);
        assert_eq!(ipv4_from_agent(&interfaces).unwrap().to_string(), "10.0.2.15");
        assert!(ipv4_from_agent(&json!([])).is_none());
    }
}
