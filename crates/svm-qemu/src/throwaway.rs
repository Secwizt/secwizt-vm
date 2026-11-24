//! One writable disk for one throwaway run. The recorded ticket scopes recovery.

use crate::{control, err, io_error, linked, local, record, save, tools, Definition, Qemu, Result};
use serde::{Deserialize, Serialize};
use std::{fs::{self, File, OpenOptions}, io, path::{Path, PathBuf}};
use svm_core::model::{GuestArchitecture, Vm};

const JOURNAL: &str = "qemu-throwaway.json";
const DISK: &str = "system.qcow2";
const VARS: &str = "uefi-vars.fd";
const BACKING: &str = "../system.qcow2";

#[derive(Deserialize, Serialize)]
struct Journal {
    id: String,
    ticket: String,
}

impl Journal {
    fn directory(&self, bundle: &Path) -> PathBuf {
        bundle.join(format!(".throwaway-{}", self.ticket))
    }

    fn read(bundle: &Path, id: &str) -> Result<Self> {
        let journal: Self = record(&bundle.join(JOURNAL))?;
        let pieces: Vec<_> = journal.ticket.split('-').collect();
        if journal.id != id || pieces.len() != 3 || pieces.iter().any(|part| {
            part.is_empty() || part.len() > 32 || !part.bytes().all(|c| c.is_ascii_hexdigit())
        }) {
            return Err(err("The throwaway disk record does not identify this run."));
        }
        Ok(journal)
    }
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(error)),
    }
}

pub(crate) fn reserve(bundle: &Path, id: &str, ticket: &str) -> Result<()> {
    let journal = Journal { id: id.to_owned(), ticket: ticket.to_owned() };
    if exists(&bundle.join(JOURNAL))? || exists(&journal.directory(bundle))? {
        return Err(err("Recover the earlier throwaway disk before starting this machine."));
    }
    save(&bundle.join(JOURNAL), &journal)
}

pub(crate) struct Disk {
    pub disk: PathBuf,
    pub vars: Option<PathBuf>,
    _base: File,
    _leaf: File,
}

pub(crate) fn prepare(bundle: &Path, vm: &Vm, def: &Definition, input: &crate::supervisor::Launch) -> Result<Disk> {
    let journal = Journal::read(bundle, &vm.id)?;
    if journal.ticket != input.ticket {
        return Err(err("The throwaway disk belongs to a different QEMU run."));
    }
    let directory = journal.directory(bundle);
    let base = bundle.join(DISK);
    let held = if def.linked_from.is_some() {
        linked::hold_file(&base, false)?
    } else {
        linked::standalone_disk(&base, def.bytes())?
    };
    fs::create_dir(&directory).map_err(io_error)?;
    let directory = local(&directory, true)?;
    let disk = directory.join(DISK);
    let _image = input.tools.image.verified()?;
    let mut command = tools::command(&input.tools.image.path);
    command.args(["create", "-u", "-f", "qcow2", "-F", "qcow2", "-b", BACKING])
        .arg(&disk).arg(def.bytes().to_string());
    tools::run(command, 25)?;
    let leaf = linked::hold_file(&disk, true)?;
    linked::header(&leaf, def.bytes(), Some(BACKING))?;
    let vars = if vm.architecture == GuestArchitecture::Aarch64 {
        let path = directory.join(VARS);
        let mut original = linked::hold_file(&bundle.join(VARS), false)?;
        let mut copy = OpenOptions::new().create_new(true).write(true).open(&path).map_err(io_error)?;
        if io::copy(&mut original, &mut copy).map_err(io_error)? != input.tools.arm_tools()?.variables_size() {
            return Err(err("The Arm firmware variables could not be copied completely."));
        }
        copy.sync_all().map_err(io_error)?;
        Some(path)
    } else {
        None
    };
    Ok(Disk { disk, vars, _base: held, _leaf: leaf })
}

fn remove_files(bundle: &Path, journal: &Journal) -> Result<()> {
    let directory = journal.directory(bundle);
    if !exists(&directory)? {
        return Ok(());
    }
    {
        // Holding the folder and its ancestors stops anyone swapping the folder for a link while
        // its files are removed by name.
        let held = crate::transfer::LocalFolder::hold(&directory)?;
        for name in [DISK, VARS] {
            let path = held.path.join(name);
            if !exists(&path)? {
                continue;
            }
            // Delete the exact object at this name in the held folder: opened exclusively (an
            // emulator still holding it blocks cleanup, even after a supervisor crash), never through
            // a link, and removed when this only handle closes.
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // A scanner may open the file for a moment right after the emulator closes it, so retry
                // sharing and lock violations for about a second. An emulator that really still holds
                // the file keeps failing after that, so the safety check does not change.
                let open = || OpenOptions::new().access_mode(0x0001_0000 | 0x8000_0000).share_mode(0)
                    .custom_flags(0x0400_0000 | 0x0020_0000).open(&path);
                let mut attempt = open();
                for _ in 0..20 {
                    match &attempt {
                        Err(error) if matches!(error.raw_os_error(), Some(32 | 33)) => {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            attempt = open();
                        }
                        _ => break,
                    }
                }
                let doomed = attempt.map_err(io_error)?;
                drop(doomed);
                if exists(&path)? {
                    return Err(err("The temporary QEMU disk could not be removed."));
                }
            }
            #[cfg(not(windows))]
            {
                let path = local(&path, false)?;
                let stopped = OpenOptions::new().read(true).open(&path).map_err(io_error)?;
                stopped.try_lock_shared().map_err(io_error)?;
                drop(stopped);
                fs::remove_file(path).map_err(io_error)?;
            }
        }
    }
    // By name, never resolved: remove_dir removes only an empty folder, or a link itself.
    fs::remove_dir(&directory).map_err(io_error)
}

pub(crate) fn finish(bundle: &Path, id: &str, ticket: &str) -> Result<()> {
    let journal = Journal::read(bundle, id)?;
    if journal.ticket != ticket {
        return Err(err("The throwaway disk belongs to a different QEMU run."));
    }
    remove_files(bundle, &journal)?;
    // The run receipt goes last, so its absence always means the run is fully cleaned up.
    fs::remove_file(bundle.join(JOURNAL)).map_err(io_error)?;
    fs::remove_file(bundle.join("qemu-run.json")).map_err(io_error)
}

impl Qemu {
    /// A running supervisor holds the lifetime lock even across a service restart.
    /// A throwaway run needs a checkpoint book with no checkpoints and no unfinished change.
    pub fn throwaway_ready(&self, vm: &Vm) -> Result<()> {
        crate::snapshot::require_empty(self.bundle(&vm.id)?)
    }

    pub fn recover_throwaway(&self, vm: &Vm) -> Result<bool> {
        let bundle = self.bundle(&vm.id)?;
        if !exists(&bundle.join(JOURNAL))? {
            return Ok(false);
        }
        let Ok(_operation) = crate::operation_lock(bundle) else { return Ok(false); };
        let Ok(_idle) = crate::runtime_lock(bundle) else { return Ok(false); };
        let journal = Journal::read(bundle, &vm.id)?;
        let key = control::machine_key(&self.home, &vm.id, bundle)?;
        let receipt = control::read_run(bundle, &key)?;
        if receipt.as_ref().is_some_and(|run| run.ticket != journal.ticket) {
            return Err(err("The throwaway record and the QEMU supervisor receipt disagree."));
        }
        remove_files(bundle, &journal)?;
        // A crash or power cut leaves the run's private guest-agent sockets behind.
        crate::agent_transport::discard_stale(bundle, &journal.ticket)?;
        fs::remove_file(bundle.join(JOURNAL)).map_err(io_error)?;
        if receipt.is_some() {
            fs::remove_file(bundle.join("qemu-run.json")).map_err(io_error)?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::recovery::fixture::{Home, TICKET};

    struct Bundle(PathBuf);
    impl Bundle {
        fn new(tag: &str) -> Self {
            let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().join(format!("svm-throwaway-{tag}-{}-{unique}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Bundle {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    fn journal(bundle: &Path, id: &str, ticket: &str) {
        save(&bundle.join(JOURNAL), &Journal { id: id.into(), ticket: ticket.into() }).unwrap();
    }

    fn leftover(bundle: &Path, with_files: bool) -> PathBuf {
        let directory = bundle.join(format!(".throwaway-{TICKET}"));
        fs::create_dir(&directory).unwrap();
        if with_files {
            fs::write(directory.join(DISK), b"overlay").unwrap();
            fs::write(directory.join(VARS), b"vars").unwrap();
        }
        directory
    }

    #[test]
    fn the_journal_only_identifies_its_own_run() {
        let bundle = Bundle::new("journal");
        journal(&bundle.0, "lab", TICKET);
        assert!(Journal::read(&bundle.0, "lab").is_ok());
        assert!(Journal::read(&bundle.0, "other").is_err(), "a different machine");
        for ticket in ["", "0a1b-2c3d", "0a1b-2c3d-zz", "0a1b-2c3d-4e5f-6a7b", "../x-1-2"] {
            journal(&bundle.0, "lab", ticket);
            assert!(Journal::read(&bundle.0, "lab").is_err(), "ticket {ticket:?} must be refused");
        }
    }

    #[test]
    fn a_new_run_is_refused_while_an_earlier_throwaway_disk_remains() {
        let bundle = Bundle::new("reserve");
        reserve(&bundle.0, "lab", TICKET).unwrap();
        assert!(Journal::read(&bundle.0, "lab").is_ok(), "the journal is written before any overlay exists");
        assert!(reserve(&bundle.0, "lab", "1111-2222-3333").is_err(), "a second run while the journal remains");

        // A leftover overlay folder without its journal also blocks the same ticket.
        let other = Bundle::new("reserve-folder");
        leftover(&other.0, false);
        assert!(reserve(&other.0, "lab", TICKET).is_err());
    }

    #[test]
    fn finishing_removes_the_overlay_receipt_and_journal_for_the_same_ticket_only() {
        let bundle = Bundle::new("finish");
        journal(&bundle.0, "lab", TICKET);
        let directory = leftover(&bundle.0, true);
        fs::write(bundle.0.join("qemu-run.json"), b"{}").unwrap();
        fs::write(bundle.0.join(DISK), b"persistent").unwrap();

        assert!(finish(&bundle.0, "lab", "ffff-ffff-ffff").is_err(), "another run's ticket");
        assert!(exists(&directory.join(DISK)).unwrap(), "nothing is removed for a different ticket");

        finish(&bundle.0, "lab", TICKET).unwrap();
        assert!(!exists(&directory).unwrap());
        assert!(!exists(&bundle.0.join(JOURNAL)).unwrap());
        assert!(!exists(&bundle.0.join("qemu-run.json")).unwrap());
        assert_eq!(fs::read(bundle.0.join(DISK)).unwrap(), b"persistent", "the persistent disk is untouched");
    }

    #[cfg(windows)]
    #[test]
    fn an_emulator_still_holding_the_overlay_blocks_cleanup_until_it_lets_go() {
        let bundle = Bundle::new("held");
        journal(&bundle.0, "lab", TICKET);
        let directory = leftover(&bundle.0, true);
        fs::write(bundle.0.join("qemu-run.json"), b"{}").unwrap();
        let held = fs::File::open(directory.join(DISK)).unwrap();
        assert!(finish(&bundle.0, "lab", TICKET).is_err(), "an open overlay is never deleted");
        assert!(exists(&directory.join(DISK)).unwrap());
        assert!(exists(&bundle.0.join("qemu-run.json")).unwrap(), "the run stays recorded for a later cleanup");
        drop(held);
        finish(&bundle.0, "lab", TICKET).unwrap();
        assert!(!exists(&directory).unwrap());
    }

    #[test]
    fn recovering_a_different_ticket_preserves_the_overlay_and_both_records() {
        let home = Home::new("throwaway-mismatch");
        let (qemu, vm, bundle) = home.machine(None);
        journal(&bundle, &vm.id, TICKET);
        let directory = leftover(&bundle, true);
        let key = control::machine_key(&home.0, &vm.id, qemu.bundle(&vm.id).unwrap()).unwrap();
        let receipt = bundle.join("qemu-run.json");
        save(&receipt, &control::Run::new(&key, "1111-2222-3333".into(), 0)).unwrap();
        let original = fs::read(&receipt).unwrap();

        let error = qemu.recover_throwaway(&vm).unwrap_err();
        assert!(error.to_string().contains("disagree"));
        assert_eq!(fs::read(&receipt).unwrap(), original);
        assert_eq!(Journal::read(&bundle, &vm.id).unwrap().ticket, TICKET);
        assert_eq!(fs::read(directory.join(DISK)).unwrap(), b"overlay");
        assert_eq!(fs::read(directory.join(VARS)).unwrap(), b"vars");
    }

    #[test]
    fn recovery_discards_only_the_matching_throwaway_run() {
        let home = Home::new("throwaway-match");
        let (qemu, vm, bundle) = home.machine(Some(0));
        journal(&bundle, &vm.id, TICKET);
        let directory = leftover(&bundle, true);
        assert!(qemu.recover_throwaway(&vm).unwrap());
        assert!(!directory.exists() && !bundle.join(JOURNAL).exists() && !bundle.join("qemu-run.json").exists());
        assert_eq!(fs::read(bundle.join(DISK)).unwrap(), b"persistent");
        assert!(!qemu.recover_throwaway(&vm).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn recovery_waits_for_the_open_overlay_and_keeps_its_records() {
        let home = Home::new("throwaway-open");
        let (qemu, vm, bundle) = home.machine(Some(0));
        journal(&bundle, &vm.id, TICKET);
        let directory = leftover(&bundle, true);
        let held = File::open(directory.join(DISK)).unwrap();
        assert!(qemu.recover_throwaway(&vm).is_err());
        assert!(directory.join(DISK).exists() && directory.join(VARS).exists());
        assert!(bundle.join(JOURNAL).exists() && bundle.join("qemu-run.json").exists());
        drop(held);
        assert!(qemu.recover_throwaway(&vm).unwrap());
        assert_eq!(fs::read(bundle.join(DISK)).unwrap(), b"persistent");
    }

    #[test]
    fn finishing_tolerates_an_overlay_that_is_already_gone() {
        let bundle = Bundle::new("gone");
        journal(&bundle.0, "lab", TICKET);
        let directory = leftover(&bundle.0, false);
        fs::write(bundle.0.join("qemu-run.json"), b"{}").unwrap();
        finish(&bundle.0, "lab", TICKET).unwrap();
        assert!(!exists(&directory).unwrap());
        assert!(!exists(&bundle.0.join(JOURNAL)).unwrap());

        // With the folder itself missing too (power cut right after the journal write).
        journal(&bundle.0, "lab", TICKET);
        fs::write(bundle.0.join("qemu-run.json"), b"{}").unwrap();
        finish(&bundle.0, "lab", TICKET).unwrap();
        assert!(!exists(&bundle.0.join(JOURNAL)).unwrap());
    }
}
