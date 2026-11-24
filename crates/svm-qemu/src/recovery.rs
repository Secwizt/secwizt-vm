//! After a crash or power cut the supervisor is gone, but its run receipt remains and the machine
//! could never be verified again. Retire that receipt once nothing owns the machine any more.

use crate::{agent_transport, control, io_error, Qemu, Result};
use std::{fs, io, path::Path};
use svm_core::model::Vm;

const RECEIPT: &str = "qemu-run.json";
const DISK: &str = "system.qcow2";

/// True when no process has the disk open. A running or orphaned emulator keeps its disk open,
/// so an exclusive open succeeds only after it is gone.
#[cfg(windows)]
fn unused(path: &Path) -> Result<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    let path = crate::local(path, false)?;
    match fs::OpenOptions::new().read(true).share_mode(0).open(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io_error(error)),
        Err(_) => Ok(false),
    }
}

/// Other platforms have no mandatory sharing rules to prove the emulator is gone.
#[cfg(not(windows))]
fn unused(_: &Path) -> Result<bool> { Ok(false) }

impl Qemu {
    /// Returns true when a stale run receipt was retired. A live supervisor holds the lifetime lock
    /// and an orphaned emulator holds the disk. Either one leaves everything in place.
    pub fn recover_interrupted_run(&self, vm: &Vm) -> Result<bool> {
        let bundle = self.bundle(&vm.id)?;
        match fs::symlink_metadata(bundle.join(RECEIPT)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(io_error(error)),
            Ok(_) => {}
        }
        let Ok(_idle) = crate::runtime_lock(bundle) else { return Ok(false); };
        let Ok(_operation) = crate::operation_lock(bundle) else { return Ok(false); };
        let key = control::machine_key(&self.home, &vm.id, bundle)?;
        // An unreadable or forged receipt stays in place for the owner to inspect.
        let Ok(Some(run)) = control::read_run(bundle, &key) else { return Ok(false); };
        if !unused(&bundle.join(DISK))? { return Ok(false); }
        agent_transport::discard_stale(bundle, &run.ticket)?;
        fs::remove_file(bundle.join(RECEIPT)).map_err(io_error)?;
        Ok(true)
    }
}

#[cfg(test)]
pub(super) mod fixture {
    use super::*;
    use crate::{control::Run, save};
    use std::path::PathBuf;

    const ID: &str = "interrupted";
    pub(crate) const TICKET: &str = "0a1b-2c3d-4e5f";

    pub(crate) struct Home(pub(crate) PathBuf);
    impl Home {
        pub(crate) fn new(tag: &str) -> Self {
            let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().canonicalize().unwrap()
                .join(format!("svm-recovery-{tag}-{}-{unique}", std::process::id()));
            fs::create_dir(&path).unwrap();
            fs::write(path.join("api-token"), "a".repeat(64)).unwrap();
            fs::write(path.join("machine-key"), "b".repeat(64)).unwrap();
            Self(path)
        }
        /// A registered QEMU machine with a disk and, optionally, a receipt for a finished run.
        pub(crate) fn machine(&self, receipt_port: Option<u16>) -> (Qemu, Vm, PathBuf) {
            let bundle = self.0.join("interrupted.swvm");
            fs::create_dir(&bundle).unwrap();
            let vm: Vm = serde_json::from_value(serde_json::json!({
                "id":ID,"name":"Interrupted","os":"Test","family":"linux","engine":"QEMU",
                "accel":true,"state":"running","vcpu":1,"ramGb":1,"net":"nat",
                "ip":"10.77.1.2","mac":"02:77:00:00:00:01","dns":"interrupted.vm.lan"
            })).unwrap();
            save(&bundle.join("vm.json"), &vm).unwrap();
            fs::write(bundle.join(DISK), b"persistent").unwrap();
            let mut qemu = Qemu::new(&self.0, Path::new("unused-supervisor.exe"));
            qemu.register_bundle(ID, &bundle).unwrap();
            if let Some(port) = receipt_port {
                let registered = qemu.bundle(ID).unwrap().to_owned();
                let key = control::machine_key(&self.0, ID, &registered).unwrap();
                save(&bundle.join(RECEIPT), &Run::new(&key, TICKET.into(), port)).unwrap();
            }
            (qemu, vm, bundle)
        }
    }
    impl Drop for Home {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use super::fixture::{Home, TICKET};

    #[test]
    fn a_stale_receipt_is_retired_once_nothing_owns_the_machine() {
        for port in [0, 5900] {
            let home = Home::new("stale");
            let (qemu, vm, bundle) = home.machine(Some(port));
            let sockets = agent_transport::directory(&bundle, TICKET);
            fs::create_dir(&sockets).unwrap();
            fs::write(sockets.join("q"), b"").unwrap();

            assert!(qemu.recover_interrupted_run(&vm).unwrap(), "port {port}");
            assert!(!bundle.join(RECEIPT).exists());
            assert!(!sockets.exists(), "the run's private socket folder goes with it");
            assert_eq!(fs::read(bundle.join(DISK)).unwrap(), b"persistent");
            assert!(!qemu.recover_interrupted_run(&vm).unwrap(), "nothing is left to recover");
        }
    }

    #[test]
    fn a_live_supervisor_or_an_open_disk_keeps_the_receipt() {
        let home = Home::new("owned");
        let (qemu, vm, bundle) = home.machine(Some(5900));

        let supervisor = crate::runtime_lock(&bundle).unwrap();
        assert!(!qemu.recover_interrupted_run(&vm).unwrap(), "a supervisor still holds the lifetime lock");
        drop(supervisor);

        let emulator = fs::File::open(bundle.join(DISK)).unwrap();
        assert!(!qemu.recover_interrupted_run(&vm).unwrap(), "an emulator still has the disk open");
        assert!(bundle.join(RECEIPT).exists());
        drop(emulator);

        assert!(qemu.recover_interrupted_run(&vm).unwrap());
    }

    #[test]
    fn a_forged_receipt_and_a_clean_machine_are_left_alone() {
        let home = Home::new("forged");
        let (qemu, vm, bundle) = home.machine(None);
        assert!(!qemu.recover_interrupted_run(&vm).unwrap(), "no receipt, nothing to do");

        let forged = br#"{"ticket":"invalid","port":1,"tag":"invalid"}"#;
        fs::write(bundle.join(RECEIPT), forged).unwrap();
        assert!(!qemu.recover_interrupted_run(&vm).unwrap());
        assert_eq!(fs::read(bundle.join(RECEIPT)).unwrap(), forged, "an unverified receipt is kept");
    }
}
