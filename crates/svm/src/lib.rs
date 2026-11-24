#![forbid(unsafe_code)]
#![deny(warnings)]

pub mod args;
pub mod client;

use args::Command;
use client::{Client, ClientError, Response};
use serde_json::{json, Value};

pub struct Output { pub code: u8, pub text: String }

fn clean(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn cell(value: &Value) -> String {
    match value {
        Value::String(s) => clean(s),
        Value::Null => "-".into(),
        _ => value.to_string(),
    }
}

fn table(value: &Value) -> String {
    match value {
        Value::Array(items) if items.is_empty() => "No entries.".into(),
        Value::Array(items) if items.iter().all(Value::is_object) => {
            let preferred = ["key", "id", "name", "state", "net", "os", "mode", "subnet", "dhcp",
                             "ip", "addressSource", "mac", "dns", "restoreReason", "capability", "allowed", "reason", "seq", "kind", "message"];
            let mut columns: Vec<&str> = preferred.into_iter()
                .filter(|k| items.iter().any(|row| row.get(*k).is_some())).collect();
            if columns.is_empty() {
                if let Some(row) = items.first().and_then(Value::as_object) {
                    columns.extend(row.keys().map(String::as_str));
                }
            }
            let mut rows = vec![columns.iter().map(|key| clean(key)).collect::<Vec<_>>().join("\t")];
            rows.extend(items.iter().map(|row| columns.iter().map(|key| cell(&row[*key])).collect::<Vec<_>>().join("\t")));
            rows.join("\n")
        }
        Value::Array(items) => items.iter().map(cell).collect::<Vec<_>>().join("\n"),
        Value::Object(fields) if !fields.is_empty() && fields.values().all(|v| v["available"].is_boolean() && v.get("reason").is_some()) => {
            let mut rows = vec!["capability\tavailable\treason".to_owned()];
            rows.extend(fields.iter().map(|(key, v)| format!("{}\t{}\t{}", clean(key), cell(&v["available"]), cell(&v["reason"]))));
            rows.join("\n")
        }
        Value::Object(fields) => fields.iter().map(|(key, v)| format!("{}\t{}", clean(key), cell(v))).collect::<Vec<_>>().join("\n"),
        Value::Null => "OK".into(),
        scalar => cell(scalar),
    }
}

fn failure(code: u8, kind: &str, message: &str, json_output: bool) -> Output {
    let text = if json_output {
        json!({"error":{"code":kind,"message":message}}).to_string()
    } else {
        clean(message)
    };
    Output { code, text }
}

fn finish(response: Result<Response, ClientError>, json_output: bool) -> Output {
    let response = match response {
        Ok(resp) => resp,
        Err(e @ ClientError::Offline) => return failure(3, "service_offline", &e.to_string(), json_output),
        Err(e) => return failure(1, "client_error", &e.to_string(), json_output),
    };
    if !(200..300).contains(&response.status) {
        let parsed = serde_json::from_slice::<Value>(&response.body).ok();
        let details = parsed.as_ref().and_then(|v| v.get("error"));
        let code = details.and_then(|e| e["code"].as_str()).unwrap_or("service_error");
        let message = details.and_then(|e| e["message"].as_str()).unwrap_or(
            if response.status == 401 { "The service refused the local credential." } else { "The service could not complete this request." }
        );
        return failure(if (400..500).contains(&response.status) { 2 } else { 1 }, code, message, json_output);
    }
    let value = if response.body.is_empty() { Value::Null } else {
        match serde_json::from_slice(&response.body) {
            Ok(value) => value,
            Err(_) => return failure(1, "invalid_response", "The service returned invalid JSON.", json_output),
        }
    };
    Output { code: 0, text: if json_output { value.to_string() } else { table(&value) } }
}

pub fn run(arguments: &[String], connect: impl FnOnce() -> Result<Client, ClientError>) -> Output {
    if let [argument] = arguments {
        match argument.as_str() {
            "--help" | "-h" => return Output { code: 0, text: args::USAGE.into() },
            "--version" | "-V" => return Output { code: 0, text: format!(
                "Secwizt Virtual Machine {} by Secwizt Private Limited", env!("CARGO_PKG_VERSION")) },
            _ => {}
        }
    }
    let cmd: Command = match args::parse(arguments) {
        Ok(command) => command,
        Err(error) => return failure(1, "invalid_arguments", &error, arguments.iter().any(|arg| arg == "--json")),
    };
    finish(connect().and_then(|c| c.request(cmd.method, &cmd.path, cmd.body.as_ref())), cmd.json)
}

#[cfg(test)]
mod tests;
