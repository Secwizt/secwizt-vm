use crate::ApiError;
use serde::{Deserialize, Serialize};
use std::{fs::{self, File, OpenOptions}, io::{Read, Seek, SeekFrom, Write}, path::{Path, PathBuf}, sync::{Arc, RwLock}, time::{SystemTime, UNIX_EPOCH}};

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: u64,
    pub kind: String,
    pub message: String,
    pub timestamp: u64,
}

#[derive(Clone)]
pub(crate) struct EventReader(Arc<RwLock<Vec<Event>>>);
impl EventReader {
    pub(crate) fn since(&self, cursor: u64) -> Result<Vec<Event>, ApiError> {
        let entries = self.0.read().map_err(|_| ApiError::new(500, "event_log", "The event log is unavailable."))?;
        let offset = entries.partition_point(|entry| entry.id <= cursor);
        Ok(entries[offset..].to_vec())
    }
}

pub struct Events {
    file: File,
    path: PathBuf,
    bytes: u64,
    limit: u64,
    first_id: u64,
    reader: EventReader,
    next_id: u64,
    writable: bool,
    #[cfg(test)]
    rejected_kind: Option<&'static str>,
}
enum Recovery {
    TruncatedTail,
    CorruptedLog,
}

struct Scan {
    entries: Vec<Event>,
    bytes: Vec<u8>,
    trimmed: bool,
    valid_bytes: usize,
    recovery: Option<Recovery>,
}

fn scan(file: &mut File, limit: u64, expected: Option<u64>) -> Result<Scan, ApiError> {
    let length = file.metadata().map_err(ApiError::storage)?.len();
    let start = length.saturating_sub(limit);
    let mut bytes = Vec::new();
    file.seek(SeekFrom::Start(start)).and_then(|_| file.take(limit).read_to_end(&mut bytes)).map_err(ApiError::storage)?;
    let trimmed = start > 0;
    if trimmed {
        let partial = bytes.iter().position(|&byte| byte == b'\n').map_or(bytes.len(), |index| index + 1);
        bytes.drain(..partial);
    }
    let mut entries = Vec::new();
    let mut valid_bytes = 0;
    let mut next = if trimmed { None } else { expected };
    let mut recovery = None;
    for line in bytes.split_inclusive(|&byte| byte == b'\n') {
        if line.last() != Some(&b'\n') {
            recovery = Some(Recovery::TruncatedTail);
            break;
        }
        match serde_json::from_slice::<Event>(line) {
            Ok(event) if (1..u64::MAX).contains(&event.id) && next.is_none_or(|id| id == event.id) => {
                next = Some(event.id + 1);
                entries.push(event);
                valid_bytes += line.len();
            }
            _ => {
                recovery = Some(Recovery::CorruptedLog);
                break;
            }
        }
    }
    Ok(Scan { entries, bytes, trimmed, valid_bytes, recovery })
}

fn open_current(path: &Path) -> Result<File, ApiError> {
    OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).map_err(ApiError::storage)
}

fn replace_log(path: &Path, bytes: &[u8]) -> Result<(), ApiError> {
    let pending = path.with_file_name("svmd.log.pending");
    let mut file = File::create(&pending).map_err(ApiError::storage)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    result.and_then(|()| fs::rename(pending, path)).map_err(ApiError::storage)
}

impl Events {
    pub fn open(home: &Path) -> Result<Self, ApiError> {
        Self::open_with_limit(home, MAX_LOG_BYTES)
    }

    fn open_with_limit(home: &Path, limit: u64) -> Result<Self, ApiError> {
        let path = home.join("svmd.log");
        let archive = home.join("svmd.log.1");
        let mut entries = match File::open(&archive) {
            Ok(mut file) => scan(&mut file, limit, None)?.entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(ApiError::storage(error)),
        };
        let expected = entries.last().map_or(1, |event| event.id + 1);
        let mut file = open_current(&path)?;
        let mut current = scan(&mut file, limit, Some(expected))?;
        let had_truncated_tail = matches!(current.recovery, Some(Recovery::TruncatedTail));
        let message = if matches!(current.recovery, Some(Recovery::CorruptedLog)) {
            let damaged = home.join("svmd.log.corrupt-last");
            drop(file);
            if current.trimmed { replace_log(&path, &current.bytes)?; }
            fs::rename(&path, damaged).map_err(ApiError::storage)?;
            file = open_current(&path)?;
            current.entries.clear();
            current.valid_bytes = 0;
            Some("Archived a damaged event log as svmd.log.corrupt-last.")
        } else if current.trimmed {
            drop(file);
            // Older releases could leave an arbitrarily large active log. Retain its bounded tail
            // as the previous log so the first retained event need not start at ID 1.
            if !current.entries.is_empty() {
                replace_log(&archive, &current.bytes[..current.valid_bytes])?;
                entries = std::mem::take(&mut current.entries);
            }
            replace_log(&path, &[])?;
            file = open_current(&path)?;
            current.valid_bytes = 0;
            Some("Trimmed the old event log to its most recent entries.")
        } else if had_truncated_tail {
            file.set_len(current.valid_bytes as u64).map_err(ApiError::storage)?;
            Some("Removed an incomplete final entry from the event log.")
        } else {
            None
        };
        file.seek(SeekFrom::End(0)).map_err(ApiError::storage)?;
        let first_id = current.entries.first().map_or_else(
            || entries.last().map_or(1, |event| event.id + 1), |event| event.id,
        );
        entries.extend(current.entries);
        let mut events = Self {
            file, path, first_id, limit, bytes: current.valid_bytes as u64,
            next_id: entries.last().map_or(1, |event| event.id + 1),
            reader: EventReader(Arc::new(RwLock::new(entries))),
            writable: true,
            #[cfg(test)]
            rejected_kind: None,
        };
        if let Some(message) = message {
            events.record("event log recovered", &message)?;
        }
        Ok(events)
    }
    pub fn record(&mut self, kind: &str, message: &str) -> Result<(), ApiError> {
        #[cfg(test)]
        if self.rejected_kind == Some(kind) {
            return Err(ApiError::new(500, "test_event_write", "The fixture rejected its transfer event."));
        }
        if !self.writable { return Err(ApiError::new(503, "event_log", "Restart the service after fixing its event log.")); }
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let event = Event { id: self.next_id, kind: kind.to_owned(), message: message.to_owned(), timestamp };
        let mut bytes = serde_json::to_vec(&event).map_err(|_| ApiError::new(500, "event_log", "The event could not be recorded."))?;
        bytes.push(b'\n');
        let size = bytes.len() as u64;
        if size > self.limit || self.next_id == u64::MAX {
            return Err(ApiError::new(500, "event_log", "The event could not be recorded."));
        }
        let rotated = self.bytes + size > self.limit;
        let previous_first = self.first_id;
        if rotated {
            let rotation = fs::rename(&self.path, self.path.with_file_name("svmd.log.1"))
                .map_err(ApiError::storage).and_then(|()| open_current(&self.path));
            match rotation {
                Ok(file) => self.file = file,
                Err(error) => { self.writable = false; return Err(error); }
            }
            self.bytes = 0;
            self.first_id = event.id;
        }
        if let Err(e) = self.file.write_all(&bytes).and_then(|()| self.file.sync_data()) {
            self.writable = false;
            return Err(ApiError::storage(e));
        }
        self.bytes += size;
        let mut entries = self.reader.0.write().map_err(|_| ApiError::new(500, "event_log", "The event log is unavailable."))?;
        if rotated {
            let retained = entries.partition_point(|entry| entry.id < previous_first);
            entries.drain(..retained);
        }
        entries.push(event);
        self.next_id += 1;
        Ok(())
    }
    pub(crate) fn reader(&self) -> EventReader { self.reader.clone() }

    #[cfg(test)]
    pub(crate) fn refuse_event_for_test(&mut self, kind: &'static str) {
        self.rejected_kind = Some(kind);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EventHome(PathBuf);

    impl EventHome {
        fn new() -> Self {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let home = std::env::temp_dir().join(format!("svm-events-{}-{timestamp}", std::process::id()));
            fs::create_dir(&home).unwrap();
            Self(home)
        }
    }

    impl Drop for EventHome {
        fn drop(&mut self) {
            for entry in fs::read_dir(&self.0).into_iter().flatten().flatten() {
                let _ = fs::remove_file(entry.path());
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn rotation_bounds_the_journal_and_preserves_event_ids_after_restart() {
        let home = EventHome::new();
        let limit = 384;
        let mut events = Events::open_with_limit(&home.0, limit).unwrap();
        for _ in 0..20 { events.record("test", &"x".repeat(72)).unwrap(); }
        let archive = home.0.join("svmd.log.1");
        assert!(archive.is_file());
        for file in [home.0.join("svmd.log"), archive.clone()] {
            assert!(fs::metadata(file).unwrap().len() <= limit);
        }
        let ids = |events: &Events, cursor| events.reader().since(cursor).unwrap()
            .into_iter().map(|entry| entry.id).collect::<Vec<_>>();
        let latest = ids(&events, 0);
        assert!(latest[0] > 1);
        assert_eq!(ids(&events, 18), [19, 20]);
        drop(events);
        let mut reopened = Events::open_with_limit(&home.0, limit).unwrap();
        assert_eq!(ids(&reopened, 0), latest);
        reopened.record("test", "after restart").unwrap();
        assert_eq!(ids(&reopened, 20), [21]);
    }

    #[test]
    fn startup_bounds_a_legacy_journal_and_keeps_its_newest_events() {
        let home = EventHome::new();
        let mut original = Events::open(&home.0).unwrap();
        for _ in 0..20 { original.record("test", "legacy fixture entry").unwrap(); }
        drop(original);
        let mut reopened = Events::open_with_limit(&home.0, 384).unwrap();
        assert_eq!(reopened.reader().since(19).unwrap().iter().map(|entry| entry.id).collect::<Vec<_>>(), [20, 21]);
        reopened.record("test", "fresh entry").unwrap();
        drop(reopened);
        let again = Events::open_with_limit(&home.0, 384).unwrap();
        assert_eq!(again.reader().since(21).unwrap()[0].id, 22);
    }

    #[test]
    fn incomplete_final_entry_recovers_and_is_reported_only_once() {
        let home = EventHome::new();
        let mut events = Events::open(&home.0).unwrap();
        events.record("test", "complete entry").unwrap();
        drop(events);
        let mut file = OpenOptions::new().append(true).open(home.0.join("svmd.log")).unwrap();
        file.write_all(b"{\"id\":2,\"kind\":\"cut").unwrap();
        drop(file);

        let mut recovered = Events::open(&home.0).unwrap();
        let entries = recovered.reader().since(0).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "complete entry");
        assert_eq!(entries[1].id, 2);
        assert_eq!(entries[1].kind, "event log recovered");
        recovered.record("test", "new event after recovery").unwrap();
        drop(recovered);

        let reopened = Events::open(&home.0).unwrap();
        let entries = reopened.reader().since(0).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].id, 3);
        assert_eq!(entries[2].message, "new event after recovery");
    }

    #[test]
    fn damaged_complete_entries_and_sequence_gaps_are_archived() {
        for damage in [
            b"not a JSON entry\n".as_slice(),
            b"{\"id\":3,\"kind\":\"test\",\"message\":\"bad sequence\",\"timestamp\":0}\n".as_slice(),
        ] {
            let home = EventHome::new();
            let path = home.0.join("svmd.log");
            fs::write(&path, damage).unwrap();
            let events = Events::open(&home.0).unwrap();
            let entries = events.reader().since(0).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].id, 1);
            assert_eq!(entries[0].kind, "event log recovered");
            let archived: Vec<_> = fs::read_dir(&home.0).unwrap()
                .map(|entry| entry.unwrap())
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("svmd.log.corrupt-"))
                .collect();
            assert_eq!(archived.len(), 1);
            assert_eq!(fs::read(archived[0].path()).unwrap(), damage);
        }
    }
}
