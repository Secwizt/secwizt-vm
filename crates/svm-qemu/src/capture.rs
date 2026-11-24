use crate::{control, err, io_error, local, machine_key, operation_lock, read_run, runtime_lock, LocalFolder, Qemu, Result};
use crate::capture_space::{SpaceWatch, FREE_SPACE_RESERVE};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, ErrorKind, Read, Seek},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const DIRECTORY: &str = "captures";
const SNAPLEN: u32 = 1514;
const MIB: u64 = 1024 * 1024;
const MAX_LIMIT: u16 = 512;
const HEADER: u64 = 24;
const PACKET_HEADER: u64 = 16;
pub(crate) const FILTER_ID: &str = "svm-packet-capture";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopReason {
    Limit,
    LowDiskSpace,
    Stopped,
    MachineStopped,
}

impl StopReason {
    fn label(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::LowDiskSpace => "low-disk-space",
            Self::Stopped => "stopped",
            Self::MachineStopped => "machine-stopped",
        }
    }
}

fn valid_limit(mib: u16) -> bool {
    (1..=MAX_LIMIT).contains(&mib)
}

pub(crate) fn start_limit(operation: &str) -> Option<u16> {
    let digits = operation.strip_prefix("capture-start:")?;
    if digits.is_empty() || digits.len() > 3 || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    digits.parse::<u16>().ok().filter(|mib| valid_limit(*mib))
}

fn reason_for_id(id: &str) -> Option<&'static str> {
    if id.len() > 100 {
        return None;
    }
    let id = id.strip_prefix("capture-")?;
    let mut parts = id.splitn(5, '-');
    let stamp = parts.next()?;
    if stamp.is_empty() || stamp.len() > 20 || !stamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    for maximum in [8, 32, 16] {
        let field = parts.next()?;
        if field.is_empty() || field.len() > maximum
            || !field.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
    }
    match parts.next()? {
        "limit" => Some("limit"),
        "low-disk-space" => Some("low-disk-space"),
        "stopped" => Some("stopped"),
        "machine-stopped" => Some("machine-stopped"),
        _ => None,
    }
}

fn capture_folder(bundle: &Path) -> Result<Option<PathBuf>> {
    let path = bundle.join(DIRECTORY);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_error(e)),
        Ok(_) => local(&path, true).map(Some),
    }
}

fn read_header(input: &mut impl Read) -> Result<()> {
    let mut header = [0; HEADER as usize];
    input.read_exact(&mut header).map_err(io_error)?;
    if header[..8] != [0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0]
        || header[16..20] != SNAPLEN.to_le_bytes()
        || header[20..24] != 1_u32.to_le_bytes()
    {
        return Err(err("The QEMU capture does not have a supported PCAP header."));
    }
    Ok(())
}

fn complete_length<R: Read + Seek>(input: &mut BufReader<R>, end: u64) -> Result<u64> {
    read_header(input)?;
    let mut length = HEADER;
    while length + PACKET_HEADER <= end {
        let mut packet = [0; PACKET_HEADER as usize];
        input.read_exact(&mut packet).map_err(io_error)?;
        let caplen = u32::from_le_bytes(packet[8..12].try_into().expect("packet length field"));
        let wirelen = u32::from_le_bytes(packet[12..16].try_into().expect("packet length field"));
        if caplen > SNAPLEN || caplen > wirelen {
            return Err(err("The QEMU capture contains an invalid packet record."));
        }
        let next = length + PACKET_HEADER + u64::from(caplen);
        if next > end {
            break;
        }
        input.seek_relative(i64::from(caplen)).map_err(io_error)?;
        length = next;
    }
    Ok(length)
}

fn automatic_stop(bytes: Option<u64>, cap: u64, free_space: Option<u64>) -> Option<StopReason> {
    if free_space.is_some_and(|bytes| bytes < FREE_SPACE_RESERVE) {
        Some(StopReason::LowDiskSpace)
    } else if bytes.is_some_and(|bytes| bytes >= cap) {
        Some(StopReason::Limit)
    } else if free_space.is_none() || bytes.is_none() {
        Some(StopReason::Stopped)
    } else {
        None
    }
}

pub(crate) struct Capture {
    directory: LocalFolder,
    stem: String,
    leaf: String,
    file: File,
    limit: u64,
    space: SpaceWatch,
}

impl Capture {
    pub(crate) fn prepare(bundle: &Path, limit_mib: u16) -> Result<Self> {
        if !valid_limit(limit_mib) {
            return Err(err("Capture size must be between 1 and 512 MiB."));
        }
        let space = SpaceWatch::start(bundle)?;
        space.check_initial_space()?;
        let directory = match capture_folder(bundle)? {
            Some(path) => LocalFolder::open(&path)?,
            None => LocalFolder::open(bundle)?.create_private_child(DIRECTORY)?,
        };
        space.check_initial_space()?;
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        let stem = format!("capture-{stamp}-{}", control::unique());
        let leaf = format!(".{stem}.partial");
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(windows)] {
            use std::os::windows::fs::OpenOptionsExt;
            // QEMU can open this file for writing, but its name cannot move while held.
            options.share_mode(3).custom_flags(0x0020_0000);
        }
        let file = options.open(directory.path.join(&leaf)).map_err(io_error)?;
        Ok(Self { directory, stem, leaf, file, limit: u64::from(limit_mib) * MIB, space })
    }

    pub(crate) fn arguments(&self) -> Value {
        json!({"qom-type":"filter-dump","id":FILTER_ID,"netdev":"nat0",
            "file":format!("{DIRECTORY}/{}", self.leaf),"maxlen":SNAPLEN})
    }

    pub(crate) fn stop_reason(&self) -> Option<StopReason> {
        let bytes = self.file.metadata().ok().map(|metadata| metadata.len());
        automatic_stop(bytes, self.limit, self.space.available())
    }

    pub(crate) fn discard(self) {
        let path = self.directory.path.join(&self.leaf);
        drop(self.file);
        let _ = fs::remove_file(path);
    }

    pub(crate) fn finish(self, reason: StopReason) -> Result<()> {
        let Self { directory, stem, leaf, file, limit, space } = self;
        let free_space = space.available();
        drop(space);
        let path = directory.path.join(&leaf);
        let destination = (|| {
            let size = file.metadata().map_err(io_error)?.len();
            let reason = match automatic_stop(Some(size), limit, free_space) {
                Some(StopReason::LowDiskSpace) => StopReason::LowDiskSpace,
                Some(StopReason::Limit) if reason != StopReason::LowDiskSpace => StopReason::Limit,
                _ => reason,
            };
            let mut input = BufReader::new(&file);
            let length = complete_length(&mut input, size.min(limit))?;
            file.set_len(length).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            Ok::<_, crate::EngineError>(directory.path.join(format!("{stem}-{}.pcap", reason.label())))
        })();
        drop(file);
        let result = destination.and_then(|to| crate::publish_disk(&path, &to));
        if result.is_err() {
            let _ = fs::remove_file(&path);
        }
        result
    }
}

fn finalized_file(path: &Path) -> Result<(PathBuf, u64)> {
    let verified = local(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)] {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        options.share_mode(1).custom_flags(0x0020_0000);
        let file = options.open(&verified).map_err(io_error)?;
        if file.metadata().map_err(io_error)?.file_attributes() & 0x400 != 0 {
            return Err(err("The selected capture path changed."));
        }
        return checked_final(file, path, verified);
    }
    #[cfg(not(windows))]
    checked_final(options.open(&verified).map_err(io_error)?, path, verified)
}

fn checked_final(mut file: File, path: &Path, verified: PathBuf) -> Result<(PathBuf, u64)> {
    let info = file.metadata().map_err(io_error)?;
    if !info.is_file() || !(HEADER..=u64::from(MAX_LIMIT)*MIB).contains(&info.len())
        || local(path, false)? != verified
    {
        return Err(err("The selected capture is not a completed PCAP file."));
    }
    read_header(&mut file)?;
    Ok((verified, info.len()))
}

impl Qemu {
    pub fn capture_list(&self, id: &str) -> Result<Value> {
        let (bundle, _) = self.definition(id)?;
        let active = self.capture_request(id, "capture-status")?
            .map(|value| value["active"].as_bool().ok_or_else(|| err("Invalid QEMU capture status.")))
            .transpose()?.unwrap_or(false);
        let mut captures = Vec::new();
        if let Some(folder) = capture_folder(bundle)? {
            for entry in fs::read_dir(folder).map_err(io_error)? {
                let entry = entry.map_err(io_error)?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let Some(capture) = name.strip_suffix(".pcap") else { continue };
                let Some(reason) = reason_for_id(capture) else { continue };
                if let Ok((_, bytes)) = finalized_file(&entry.path()) {
                    captures.push((capture.to_owned(), json!({
                        "id":capture,"name":name,"bytes":bytes,"stoppedBecause":reason,
                    })));
                }
            }
        }
        captures.sort_unstable_by(|a,b| b.0.cmp(&a.0));
        Ok(json!({"active":active,"captures":captures.into_iter().map(|(_,capture)|capture).collect::<Vec<_>>()}))
    }

    pub fn start_capture(&self, id: &str, limit_mib: u16) -> Result<Value> {
        if !valid_limit(limit_mib) {
            return Err(err("Capture size must be between 1 and 512 MiB."));
        }
        let (bundle, _) = self.definition(id)?;
        let _operation = operation_lock(bundle)?;
        self.capture_request(id, &format!("capture-start:{limit_mib}"))?
            .ok_or_else(|| err("Start the QEMU machine before capturing packets."))
    }

    pub fn stop_capture(&self, id: &str) -> Result<Value> {
        let (bundle, _) = self.definition(id)?;
        let _operation = operation_lock(bundle)?;
        Ok(self.capture_request(id, "capture-stop")?.unwrap_or_else(|| json!({"active":false})))
    }

    pub fn capture_path(&self, id: &str, capture: &str) -> Result<PathBuf> {
        let (bundle, _) = self.definition(id)?;
        let folder = capture_folder(bundle)?.ok_or_else(|| err("The capture is unavailable."))?;
        reason_for_id(capture).ok_or_else(|| err("Choose a completed QEMU capture."))?;
        finalized_file(&folder.join(format!("{capture}.pcap"))).map(|(path, _)| path)
    }

    pub fn delete_capture(&self, id: &str, capture: &str) -> Result<()> {
        let (bundle, _) = self.definition(id)?;
        let _operation = operation_lock(bundle)?;
        let path = self.capture_path(id, capture)?;
        let folder = LocalFolder::open(path.parent().ok_or_else(|| err("The capture folder is unavailable."))?)?;
        let name = path.file_name().ok_or_else(|| err("The capture name is unavailable."))?;
        let (path, _) = finalized_file(&folder.path.join(name))?;
        fs::remove_file(path).map_err(io_error)
    }

    fn capture_request(&self, id: &str, operation: &str) -> Result<Option<Value>> {
        let (bundle, _) = self.definition(id)?;
        let key = machine_key(&self.home, id, bundle)?;
        let Some(run) = read_run(bundle, &key)? else {
            let _idle = runtime_lock(bundle)?;
            return Ok(None);
        };
        if run.port == 0 {
            return Err(err("Wait for the QEMU machine to finish starting."));
        }
        control::request(&key, &run, operation).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn validates_capture_operation_and_file_identity() {
        assert_eq!(start_limit("capture-start:512"), Some(512));
        for invalid in ["capture-start:0", "capture-start:513", "capture-start:01", "capture-start:1/path"] {
            assert_eq!(start_limit(invalid), None);
        }
        assert_eq!(reason_for_id("capture-123-ab-abc-1-machine-stopped"), Some("machine-stopped"));
        assert_eq!(reason_for_id("capture-123-ab-abc-1-low-disk-space"), Some("low-disk-space"));
        for invalid in ["../capture-123-ab-abc-1-stopped", "capture-123-ab-abc-1-stopped.pcap", "capture-123-ab-abc-1-unknown"] {
            assert_eq!(reason_for_id(invalid), None);
        }
    }

    #[test]
    fn capture_stops_for_low_space_before_the_packet_limit() {
        assert_eq!(automatic_stop(Some(MIB - 1), MIB, Some(FREE_SPACE_RESERVE)), None);
        assert_eq!(automatic_stop(Some(MIB - 1), MIB, Some(FREE_SPACE_RESERVE - 1)), Some(StopReason::LowDiskSpace));
        assert_eq!(automatic_stop(Some(MIB), MIB, Some(FREE_SPACE_RESERVE - 1)), Some(StopReason::LowDiskSpace));
        assert_eq!(automatic_stop(Some(MIB), MIB, Some(FREE_SPACE_RESERVE)), Some(StopReason::Limit));
        assert_eq!(automatic_stop(Some(MIB - 1), MIB, None), Some(StopReason::Stopped));
    }

    #[test]
    fn capture_cap_keeps_only_whole_pcap_records() {
        let mut data = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        data.extend([0; 8]);
        data.extend(SNAPLEN.to_le_bytes());
        data.extend(1_u32.to_le_bytes());
        for bytes in [10_u32, 12] {
            data.extend([0; 8]);
            data.extend(bytes.to_le_bytes());
            data.extend(bytes.to_le_bytes());
            data.extend(vec![0; bytes as usize]);
        }
        let size = data.len() as u64;
        let mut reader = BufReader::new(Cursor::new(&data));
        assert_eq!(complete_length(&mut reader, size - 1).unwrap(), HEADER + PACKET_HEADER + 10);
        let mut reader = BufReader::new(Cursor::new(&data));
        assert_eq!(complete_length(&mut reader, size).unwrap(), size);
        data[0] = 0;
        let mut reader = BufReader::new(Cursor::new(&data));
        assert!(complete_length(&mut reader, size).is_err());
    }
}
