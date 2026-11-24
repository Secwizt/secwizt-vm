use super::*;
use crate::agent::AgentCall;
use svm_core::model::SnapshotConsistency;

const BOOK: &str = "qemu-snapshots.json";

#[derive(Default, Serialize, Deserialize)]
struct Book {
    #[serde(default)]
    head: Option<String>,
    #[serde(default)]
    rows: Vec<Snapshot>,
    #[serde(default)]
    pending: Option<Pending>,
}

#[derive(Serialize, Deserialize)]
enum Pending {
    Create { row: Snapshot, ticket: String },
    Apply { id: String },
    Delete { id: String },
}

impl Book {
    fn read(bundle: &Path) -> Result<Self> {
        let path = bundle.join(BOOK);
        match fs::symlink_metadata(&path) {
            Ok(_) => svm_core::read_json(&local(&path, false)?).map_err(io_error),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(io_error(error)),
        }
    }

    fn save(&self, bundle: &Path) -> Result<()> {
        save(&bundle.join(BOOK), self)
    }

    fn created(&mut self, mut row: Snapshot, consistency: SnapshotConsistency) -> Snapshot {
        row.consistency = Some(consistency);
        self.head = Some(row.id.clone());
        self.rows.push(row.clone());
        self.pending = None;
        row
    }

    fn removed(&mut self, id: &str) -> Result<()> {
        let before = self.rows.iter().find(|row| row.id == id)
            .ok_or_else(|| err("The pending checkpoint record is missing."))?.parent.clone();
        self.rows.retain(|row| row.id != id);
        for child in &mut self.rows {
            if child.parent.as_deref() == Some(id) { child.parent = before.clone(); }
        }
        if self.head.as_deref() == Some(id) { self.head = before; }
        self.pending = None;
        Ok(())
    }
}

fn tag(id: &str) -> Result<&str> {
    let valid = id.strip_prefix("svm-cp-").is_some_and(|tail| {
        (1..=65).contains(&tail.len()) && tail.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    });
    if valid { Ok(id) } else { Err(err("The QEMU checkpoint identity is invalid.")) }
}

fn image_tool(bins: &Tools, disk: &Path, arguments: &[&str]) -> Result<String> {
    let _tool = bins.image.verified()?;
    let mut command = tools::command(&bins.image.path);
    command.args(arguments).arg(disk);
    tools::run_with_limit(command, 45, 1024 * 1024)
}

fn native_tags(image: &Value) -> std::collections::BTreeSet<&str> {
    image["snapshots"].as_array().into_iter().flatten().filter_map(|row| row["name"].as_str()).collect()
}

fn finish_offline(bundle: &Path, bins: &Tools, bytes: u64, book: &mut Book) -> Result<()> {
    let Some(pending) = book.pending.take() else { return Ok(()); };
    let disk = local(&bundle.join("system.qcow2"), false)?;
    let image = bins.disk_info(&disk, bytes)?;
    let native = native_tags(&image);
    match pending {
        Pending::Create { row, .. } => {
            if native.contains(tag(&row.id)?) { book.created(row, SnapshotConsistency::Unverified); }
        }
        Pending::Apply { id } => {
            let id = tag(&id)?;
            if native.contains(id) {
                image_tool(bins, &disk, &["snapshot", "-a", id])?;
                book.head = Some(id.to_owned());
            } else {
                // The native tag was removed while this disk was offline. Clear the abandoned intent.
                book.removed(id)?;
                book.head = None;
            }
        }
        Pending::Delete { id } => {
            let id = tag(&id)?;
            if native.contains(id) { image_tool(bins, &disk, &["snapshot", "-d", id])?; }
            book.removed(id)?;
        }
    }
    book.save(bundle)
}

/// Called with the operation lock held after verifying that the supervisor is gone.
pub(crate) fn recover_before_start(bundle: &Path, bins: &Tools, bytes: u64, linked: bool) -> Result<()> {
    let _idle = runtime_lock(bundle)?;
    if linked { require_empty(bundle) } else { finish_offline(bundle, bins, bytes, &mut Book::read(bundle)?) }
}

pub(crate) fn require_empty(bundle: &Path) -> Result<()> {
    let book=Book::read(bundle)?;
    if book.pending.is_some() || !book.rows.is_empty() || book.head.is_some() {
        return Err(err("QEMU templates, linked disks and throwaway machines cannot have checkpoints or pending checkpoint changes."));
    }
    Ok(())
}

fn allow_changes(bundle: &Path) -> Result<()> {
    let vm: Vm=record(&bundle.join("vm.json"))?;
    if vm.template.is_some() || vm.linked_from.is_some() {
        return Err(err("Checkpoints are unavailable for QEMU templates and linked disks."));
    }
    Ok(())
}

pub(crate) fn list(bundle: &Path) -> Result<Vec<Snapshot>> { Ok(Book::read(bundle)?.rows) }

impl Qemu {
    pub(super) fn take_snapshot(&self, id: &str, name: &str, with_memory: bool) -> Result<Snapshot> {
        if with_memory { return Err(err("QEMU checkpoints capture the disk only.")); }
        if name.trim().is_empty() || name.len() > 180 { return Err(err("Use a checkpoint name of one to 180 bytes.")); }
        let (bundle, _) = self.definition(id)?;
        let _operation = operation_lock(bundle)?;
        allow_changes(bundle)?;
        if self.status(id)? != VmState::Running { return Err(err("Start the QEMU machine before taking a checkpoint.")); }
        let key = machine_key(&self.home, id, bundle)?;
        let running = read_run(bundle, &key)?.filter(|run| run.port != 0)
            .ok_or_else(|| err("The QEMU supervisor could not be verified."))?;
        let report = request(&key, &running, "probe")?;
        if report["owned"] != true || report["checkpoints"] != true {
            return Err(err("Restart this QEMU machine to enable its checkpoint support."));
        }
        let mut book = Book::read(bundle)?;
        if book.pending.is_some() {
            return Err(err("Power off the machine before recovering its interrupted checkpoint operation."));
        }
        let row = Snapshot { id: format!("svm-cp-{}", unique()), name: name.to_owned(), parent: book.head.clone(),
            with_memory: false, consistency: None };
        book.pending = Some(Pending::Create { row, ticket: running.ticket.clone() });
        book.save(bundle)?;
        let result = request(&key, &running, "snapshot")?;
        serde_json::from_value(result).map_err(io_error)
    }

    pub(super) fn edit_snapshot(&self, id: &str, snapshot: &str, delete: bool) -> Result<()> {
        tag(snapshot)?;
        let (bundle, definition) = self.definition(id)?;
        let bins = self.available()?;
        let _operation = operation_lock(bundle)?;
        allow_changes(bundle)?;
        if self.status(id)? != VmState::Off { return Err(err("Power off this QEMU machine before changing its checkpoints.")); }
        let _idle = runtime_lock(bundle)?;
        let mut book = Book::read(bundle)?;
        finish_offline(bundle, bins, definition.bytes(), &mut book)?;
        if !book.rows.iter().any(|row| row.id == snapshot) {
            return Err(EngineError::Missing(snapshot.to_owned()));
        }
        if !delete {
            let disk = local(&bundle.join("system.qcow2"), false)?;
            let image = bins.disk_info(&disk, definition.bytes())?;
            if !native_tags(&image).contains(snapshot) {
                book.removed(snapshot)?;
                book.save(bundle)?;
                return Err(EngineError::Missing(snapshot.to_owned()));
            }
        }
        book.pending = Some(if delete { Pending::Delete {id: snapshot.to_owned()} }
            else { Pending::Apply {id: snapshot.to_owned()} });
        book.save(bundle)?;
        finish_offline(bundle, bins, definition.bytes(), &mut book)
    }
}

pub(crate) fn capture_pending(
    bundle: &Path, active: &Run, mut call: impl FnMut(AgentCall) -> Result<Value>,
    checkpoint: impl FnOnce(&str) -> Result<()>,
) -> Result<Value> {
    let mut book = Book::read(bundle)?;
    let Some(Pending::Create { row, ticket }) = book.pending.take() else {
        return Err(err("No checkpoint request belongs to this QEMU run."));
    };
    if ticket != active.ticket { return Err(err("The checkpoint request belongs to another QEMU run.")); }
    let id = tag(&row.id)?;
    let consistency = capture(&mut call, || checkpoint(id))?;
    serde_json::to_value(book.created(row, consistency)).map_err(io_error).and_then(|result| {
        book.save(bundle)?;
        Ok(result)
    })
}

fn capture(
    call: &mut impl FnMut(AgentCall) -> Result<Value>, checkpoint: impl FnOnce() -> Result<()>,
) -> Result<SnapshotConsistency> {
    let probe = match call(AgentCall::SnapshotProbe) {
        Ok(probe) => probe,
        Err(EngineError::Invalid(reason)) if reason == "The guest agent is not running in this machine." => Value::Null,
        Err(error) => return Err(error),
    };
    if probe.is_null() {
        checkpoint()?;
        return Ok(SnapshotConsistency::CrashConsistent);
    }
    if probe != "thawed" { return Err(err("The guest agent did not confirm writable filesystems before the checkpoint.")); }
    let frozen = call(AgentCall::Freeze).and_then(|reply| reply.as_u64().filter(|count| *count > 0)
        .ok_or_else(|| err("The guest agent did not confirm freezing a filesystem.")));
    let captured = frozen.and_then(|frozen| checkpoint().map(|()| frozen));
    let thawed = call(AgentCall::Thaw).and_then(|reply| reply.as_u64()
        .ok_or_else(|| err("The guest agent returned an invalid thaw report.")));
    let thawed = thawed.map_err(|_| err("The guest did not confirm thawing its filesystems within ten seconds."))?;
    if thawed != captured? {
        return Err(err("The guest’s frozen and thawed filesystem counts differed. Check its state before retrying."));
    }
    Ok(SnapshotConsistency::GuestQuiesced)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_freeze_or_checkpoint_always_attempts_to_thaw() {
        for freeze_fails in [true, false] {
            let mut sequence = Vec::new();
            let mut agent = |call| {
                match call {
                    AgentCall::SnapshotProbe => { sequence.push("probe"); Ok(json!("thawed")) }
                    AgentCall::Freeze => {
                        sequence.push("freeze");
                        if freeze_fails { Err(err("freeze failed")) } else { Ok(json!(2)) }
                    }
                    AgentCall::Thaw => { sequence.push("thaw"); Ok(json!(2)) }
                    _ => panic!("Unexpected test request"),
                }
            };
            let mut checkpoint_attempted = false;
            assert!(capture(&mut agent, || {checkpoint_attempted=true;Err(err("checkpoint failed"))}).is_err());
            assert_eq!(sequence, ["probe","freeze","thaw"]);
            assert_eq!(checkpoint_attempted,!freeze_fails);
        }
    }

    #[test]
    fn a_missing_agent_creates_a_crash_consistent_checkpoint() {
        let mut absent = |call| {
            assert!(matches!(call, AgentCall::SnapshotProbe));
            Err(err("The guest agent is not running in this machine."))
        };
        assert_eq!(capture(&mut absent, || Ok(())).unwrap(), SnapshotConsistency::CrashConsistent);
    }
}
