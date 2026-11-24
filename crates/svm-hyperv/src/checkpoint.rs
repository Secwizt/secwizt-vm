use super::*;
use svm_core::model::SnapshotConsistency;

impl<R: PsRunner> HyperV<R> {
    pub(super) fn checkpoint_labels(&self, id: &str) -> EngineResult<BTreeMap<String, SnapshotConsistency>> {
        let Some(bundle) = self.bundles.get(id) else { return Ok(BTreeMap::new()); };
        let path = bundle.join("hyperv-snapshot-labels.json");
        let error = || EngineError::Engine("The machine’s checkpoint consistency metadata could not be read.".into());
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x400 != 0 { return Err(error()); }
                }
                svm_core::read_json(&path).map_err(|_| error())
            }
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            _ => Err(error()),
        }
    }

    pub(super) fn record_checkpoint_label(&self, id: &str, row: &Snapshot, mut entries: BTreeMap<String, SnapshotConsistency>) -> EngineResult<()> {
        let (Some(bundle), Some(label)) = (self.bundles.get(id), row.consistency) else { return Ok(()); };
        entries.insert(row.id.clone(), label);
        svm_core::write_json(&bundle.join("hyperv-snapshot-labels.json"), &entries).map_err(|_| {
            EngineError::Engine("The checkpoint exists, but its consistency label could not be saved.".into())
        })
    }
}
