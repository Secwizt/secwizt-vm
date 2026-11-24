//! Device layout for an explicitly selected 64-bit Arm software-emulated machine.
use crate::{local, Result};
use serde_json::json;
use std::path::Path;
use svm_core::model::Vm;

fn block_device(args: &mut Vec<String>, name: &str, format: &str, path: &Path, read_only: bool) -> Result<()> {
    let file = format!("{name}-file");
    let host = json!({"driver":"file", "node-name":file, "filename":local(path, false)?, "read-only":read_only});
    let image = json!({"driver":format, "node-name":name, "file":file, "read-only":read_only});
    args.extend(["-blockdev".into(),host.to_string(),"-blockdev".into(),image.to_string()]);
    Ok(())
}

pub(crate) fn arguments(
    bundle: &Path, vm: &Vm, code: &Path, backing: Option<&Path>, throwaway: Option<&crate::throwaway::Disk>,
) -> Result<Vec<String>> {
    let network = crate::port_forward::user_network(&vm.port_forwards, vm.isolated)?;
    let mut args:Vec<String> = [
        "-no-user-config", "-nodefaults", "-machine", "virt,pflash0=firmware,pflash1=nvram",
        "-cpu", "cortex-a72", "-accel", "tcg", "-smp", &vm.vcpu.to_string(),
        "-m", &(u64::from(vm.ram_gb)*1024).to_string(), "-name", &format!("svm-{}",vm.id),
        "-qmp", "stdio", "-monitor", "none", "-serial", "none",
        "-device", "virtio-gpu-pci", "-device", "qemu-xhci", "-device", "usb-kbd", "-device", "usb-tablet",
        "-netdev", &network, "-device", &format!("virtio-net-pci,netdev=nat0,mac={}",vm.mac)
    ].iter().map(|arg|arg.to_string()).collect();
    block_device(&mut args,"firmware","raw",code,true)?;
    let original_vars = bundle.join("uefi-vars.fd");
    let vars = throwaway.and_then(|run| run.vars.as_deref()).unwrap_or(&original_vars);
    block_device(&mut args,"nvram","raw",vars,false)?;
    crate::linked::append_block_devices(&mut args, bundle, backing, throwaway.map(|run| run.disk.as_path()))?;
    let priority=if let Some(iso)=&vm.iso_path {
        block_device(&mut args,"installer","raw",iso,true)?;
        args.extend(["-device","virtio-scsi-pci,id=scsi","-device","scsi-cd,bus=scsi.0,drive=installer,bootindex=1"].map(str::to_owned));
        2
    } else { 1 };
    args.extend(["-device".into(),format!("virtio-blk-pci,drive=system,bootindex={priority}")]);
    Ok(args)
}
