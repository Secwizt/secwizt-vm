//! Opt-in Hyper-V checks that need a real Windows host with Hyper-V.
//!   hyperv_checks foreign <id>          -> the driver must REFUSE to act on a machine named svm-<id> that lacks our marker
//!   hyperv_checks frame <out.rgba>      -> full lifecycle of our own machine; writes one real thumbnail as raw RGBA
use serde_json::json;
use std::{error::Error, fs, path::PathBuf};
use svm_core::{engine::EngineDriver, model::{Network, NetworkMode, Vm}};
use svm_hyperv::{HyperV, WindowsPowerShell};

fn network() -> Result<Network, Box<dyn Error>> {
    Ok(Network { bridge:None, id: "test".into(), name: "Test".into(), mode: NetworkMode::Routed, subnet: "10.77.8.0/24".parse()?, gateway: None, dhcp: false, note: String::new() })
}

fn main() -> Result<(), Box<dyn Error>> {
    let a: Vec<String> = std::env::args().collect();
    let net = network()?;
    let mut engine = HyperV::new(WindowsPowerShell::default(), [net.clone()]);
    match a.get(1).map(String::as_str) {
        Some("foreign") => {
            let id = a.get(2).ok_or("id missing")?;
            println!("state    -> {:?}", engine.state(id));
            println!("start    -> {:?}", engine.start(id));
            println!("stop     -> {:?}", engine.stop(id));
            println!("snapshot -> {:?}", engine.snapshot(id, "x", false).map(|s| s.id));
            println!("remove   -> {:?}", engine.remove(id));
        }
        Some("frame") => {
            let out = PathBuf::from(a.get(2).ok_or("output path missing")?);
            let id = format!("test-check-{}", std::process::id());
            let temp = std::env::temp_dir().join(format!("svm-{id}"));
            let bundle = temp.join("fixture.swvm");
            engine.register_bundle(&id, &bundle)?;
            fs::create_dir_all(&bundle)?;
            let vm: Vm = serde_json::from_value(json!({
                "id": id, "name": "Frame check", "os": "Empty firmware guest", "family": "other", "engine": "Hyper-V",
                "accel": true, "state": "off", "vcpu": 1, "ramGb": 1, "net": "test", "ip": "10.77.8.3", "mac": "02:77:08:00:00:02", "dns": "frame.vm.lan"
            }))?;
            fs::write(bundle.join("vm.json"), serde_json::to_vec(&vm)?)?;
            let receipt = engine.ensure_switch(&net)?;
            println!("switch created: {}", receipt.created);
            let result = (|| -> Result<(), Box<dyn Error>> {
                engine.define(&vm)?;
                engine.start(&id)?;
                std::thread::sleep(std::time::Duration::from_secs(12)); // let the firmware draw its screen
                let f = engine.thumbnail(&id)?;
                println!("frame {}x{} rgba bytes {}", f.width, f.height, f.rgba.len());
                fs::write(&out, &f.rgba)?;
                engine.stop(&id)?;
                println!("remove -> {:?}", engine.remove(&id));
                Ok(())
            })();
            if result.is_err() { let _ = engine.stop(&id); let _ = engine.remove(&id); }
            if receipt.created { println!("switch removed -> {:?}", engine.remove_switch_if_same(&net, Some(&receipt.guid))); }
            let _ = fs::remove_dir_all(&temp);
            result?;
        }
        _ => return Err("usage: hyperv_checks foreign <id> | frame <out.rgba>".into()),
    }
    Ok(())
}
