use serde::{de::DeserializeOwned, Serialize};
use std::{fs::{self, File, OpenOptions}, io::{self, BufReader, Write}, path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("An entry already exists: {0}")]
    Conflict(String),
    #[error("No such entry: {0}")]
    Missing(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

pub fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<(), Error> {
    write_atomic(path, |file| {
        serde_json::to_writer_pretty(&mut *file, value)?;
        file.write_all(b"\n")?;
        Ok(())
    })
}

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

pub(crate) fn write_atomic(path: &Path, write: impl FnOnce(&mut File) -> Result<(), Error>) -> Result<(), Error> {
    let parent = path.parent().ok_or_else(|| Error::Invalid("A destination folder is required.".into()))?;
    let (temp, mut file) = loop {
        let name = parent.join(unique_name(".svm-write"));
        match OpenOptions::new().write(true).create_new(true).open(&name) {
            Ok(file) => break (Temp(name), file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    };
    let result = write(&mut file).and_then(|()| Ok(file.sync_all()?));
    drop(file);
    result?;
    fs::rename(&temp.0, path)?;
    Ok(())
}

#[cfg(test)]
pub(crate) struct TestDir(pub PathBuf);

#[cfg(test)]
impl TestDir {
    pub fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(unique_name("svm-test"));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("test directory: {e}"),
            }
        }
    }
}
#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
