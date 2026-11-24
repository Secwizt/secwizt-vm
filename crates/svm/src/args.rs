use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub(crate) const USAGE: &str = "Secwizt Virtual Machine by Secwizt Private Limited. Use svm list, show, create, start, shutdown, restart, power-off, pause, resume, snapshot, snapshots, revert, clone, delete, trash, net, guard, host, events, why, or service.";

#[derive(Debug, PartialEq)]
pub struct Command {
    pub method: &'static str,
    pub path: String,
    pub body: Option<Value>,
    pub json: bool,
}

struct Options<'a>(BTreeMap<&'a str, &'a str>);

impl<'a> Options<'a> {
    fn parse(args: &[&'a str], valued: &[&str], flags: &[&str]) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let mut iter = args.iter().copied();
        while let Some(key) = iter.next() {
            let value = if flags.contains(&key) {
                ""
            } else if valued.contains(&key) {
                iter.next().filter(|v| !v.starts_with("--") && !v.trim().is_empty())
                    .ok_or_else(|| format!("Supply a value for {key}."))?
            } else {
                return Err(format!("Unrecognized option {key}."));
            };
            if values.insert(key, value).is_some() {
                return Err(format!("Supply {key} only once."));
            }
        }
        Ok(Self(values))
    }

    fn get(&self, key: &str) -> Option<&str> { self.0.get(key).copied() }

    fn required(&self, key: &str) -> Result<&str, String> {
        self.get(key).ok_or_else(|| format!("Supply {key} for this command."))
    }
}

fn segment(id: &str) -> Result<&str, String> {
    if id.len() <= 80 && id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        Ok(id)
    } else {
        Err("Use a valid project ID from the list.".into())
    }
}

fn trash_key(key: &str) -> Result<&str, String> {
    // Each filename byte becomes two hex digits, so keys may exceed the machine ID limit.
    if !key.is_empty() && key.len() <= 2048 && key.len() % 2 == 0
        && key.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(key)
    } else { Err("Use the complete trash key from svm trash list.".into()) }
}

fn positive(value: &str, option: &str) -> Result<u32, String> {
    value.parse::<u32>().ok().filter(|n| *n > 0)
        .ok_or_else(|| format!("{option} needs a positive whole number."))
}

fn create_machine(args: &[&str]) -> Result<Value, String> {
    let opts = Options::parse(args, &["--name", "--os", "--vcpu", "--ram", "--disk", "--iso", "--net"], &[])?;
    let mut body = Map::new();
    body.insert("name".into(), json!(opts.required("--name")?));
    body.insert("os".into(), json!(opts.required("--os")?));
    for (flag, field) in [("--vcpu", "vcpu"), ("--ram", "ramGb")] {
        if let Some(value) = opts.get(flag) { body.insert(field.into(), json!(positive(value, flag)?)); }
    }
    if let Some(disk) = opts.get("--disk") {
        if disk.to_ascii_lowercase().ends_with(".vhdx") {
            body.insert("diskPath".into(), json!(disk));
        } else {
            body.insert("diskGb".into(), json!(positive(disk, "--disk")?));
        }
    }
    if let Some(iso) = opts.get("--iso") { body.insert("isoPath".into(), json!(iso)); }
    if let Some(net) = opts.get("--net") { body.insert("net".into(), json!(segment(net)?)); }
    Ok(Value::Object(body))
}

fn create_network(args: &[&str]) -> Result<Value, String> {
    let opts = Options::parse(args, &["--name", "--id", "--mode", "--subnet", "--gateway"], &[])?;
    let mut body = json!({"name": opts.required("--name")?, "mode": match opts.required("--mode")?.to_ascii_lowercase().as_str() {
        "routed" => "Routed",
        "host-only" => "Host-only",
        "isolated" | "isolated segment" => "Isolated segment",
        _ => return Err("Choose Routed, Host-only or Isolated for the network mode.".into()),
    }});
    if let Some(id) = opts.get("--id") { body["id"] = json!(segment(id)?); }
    if let Some(subnet) = opts.get("--subnet") { body["subnet"] = json!(subnet); }
    if let Some(gateway) = opts.get("--gateway") { body["gateway"] = json!(gateway); }
    Ok(body)
}

pub fn parse(arguments: &[String]) -> Result<Command, String> {
    let json = arguments.iter().any(|s| s == "--json");
    let args: Vec<&str> = arguments.iter().map(String::as_str).filter(|s| *s != "--json").collect();
    let (method, path, body) = match args.as_slice() {
        ["list"] => ("GET", "/v1/machines".into(), None),
        ["show", id] => ("GET", format!("/v1/machines/{}", segment(id)?), None),
        ["create", rest @ ..] => ("POST", "/v1/machines".into(), Some(create_machine(rest)?)),
        [action @ ("start" | "stop" | "shutdown" | "restart" | "pause" | "resume"), id] =>
            ("POST", format!("/v1/machines/{}/{action}", segment(id)?), Some(json!({}))),
        ["power-off", id] => ("POST", format!("/v1/machines/{}/stop", segment(id)?), Some(json!({}))),
        ["trash", "list"] => ("GET", "/v1/trash".into(), None),
        ["trash", "restore", key] => ("POST", format!("/v1/trash/{}/restore", trash_key(key)?), Some(json!({}))),
        ["trash", "delete", key, rest @ ..] => {
            let name = match rest {
                ["--confirm-name", name] if !name.starts_with("--") => Some(*name),
                [option] => option.strip_prefix("--confirm-name="),
                _ => None,
            }.filter(|name| !name.trim().is_empty()).ok_or_else(|| "Supply --confirm-name with the exact machine name from svm trash list.".to_owned())?;
            ("DELETE", format!("/v1/trash/{}", trash_key(key)?), Some(json!({"confirmName":name})))
        }
        ["trash", ..] => return Err("Use svm trash list, svm trash restore <key>, or svm trash delete <key> --confirm-name <name>.".into()),
        ["delete", id, rest @ ..] => {
            let opts = Options::parse(rest, &[], &["--keep-copy"])?;
            let body = opts.get("--keep-copy").map(|_| json!({"keepCopy":true}));
            ("DELETE", format!("/v1/machines/{}", segment(id)?), body)
        }
        ["why", id] => ("GET", format!("/v1/machines/{}/capabilities", segment(id)?), None),
        ["snapshots", id] => ("GET", format!("/v1/machines/{}/snapshots", segment(id)?), None),
        ["snapshot", id, rest @ ..] => {
            let opts = Options::parse(rest, &["--name"], &["--no-memory"])?;
            let mut body = json!({});
            if opts.get("--no-memory").is_some() { body["withMemory"] = json!(false); }
            if let Some(name) = opts.get("--name") { body["name"] = json!(name); }
            ("POST", format!("/v1/machines/{}/snapshots", segment(id)?), Some(body))
        }
        ["revert", id, sid] =>
            ("POST", format!("/v1/machines/{}/snapshots/{}/revert", segment(id)?, segment(sid)?), Some(json!({}))),
        ["clone", id, rest @ ..] => {
            let opts = Options::parse(rest, &["--name"], &[])?;
            ("POST", format!("/v1/machines/{}/clone", segment(id)?), Some(json!({"name": opts.required("--name")?})))
        }
        ["net", "list"] => ("GET", "/v1/networks".into(), None),
        ["net", "create", rest @ ..] => ("POST", "/v1/networks".into(), Some(create_network(rest)?)),
        ["net", "delete", id] => ("DELETE", format!("/v1/networks/{}", segment(id)?), None),
        ["net", "leases", id] => ("GET", format!("/v1/networks/{}/leases", segment(id)?), None),
        ["guard"] => ("GET", "/v1/guard".into(), None),
        ["guard", "--set", pct] => ("PUT", "/v1/guard".into(), Some(json!({"budgetPct": positive(pct, "--set")?}))),
        ["host"] => ("GET", "/v1/host".into(), None),
        ["events"] => ("GET", "/v1/events".into(), None),
        ["events", "--since", value] => {
            let seq: u64 = value.parse().map_err(|_| "--since needs a non-negative whole number.".to_owned())?;
            ("GET", format!("/v1/events?since={seq}"), None)
        }
        ["service", "status"] => ("GET", "/v1/health".into(), None),
        ["service", "stop"] => ("POST", "/v1/shutdown".into(), Some(json!({}))),
        _ => return Err(USAGE.into()),
    };
    Ok(Command { method, path, body, json })
}
