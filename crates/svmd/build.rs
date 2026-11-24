#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{env, fs, io, path::{Path, PathBuf}};

fn embed(root: &Path, folder: &Path, entries: &mut Vec<String>) -> io::Result<()> {
    let mut children = fs::read_dir(folder)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            embed(root, &path, entries)?;
        } else if kind.is_file() {
            let name = path.strip_prefix(root).map_err(io::Error::other)?
                .to_str().ok_or_else(|| io::Error::other("noVNC paths must be UTF-8"))?.replace('\\', "/");
            let mime = if path.extension().is_some_and(|e| e == "js") {
                "text/javascript; charset=utf-8"
            } else if name == "LICENSE.txt" || name == "vendor/pako/LICENSE" || name.starts_with("docs/LICENSE.") {
                "text/plain; charset=utf-8"
            } else {
                return Err(io::Error::other("Unexpected noVNC runtime file"));
            };
            entries.push(format!("({name:?}, {mime:?}, include_bytes!({path:?})),"));
        } else {
            return Err(io::Error::other("Only regular files can be embedded"));
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| io::Error::other("Missing manifest folder"))?);
    let root = manifest.join("vendor/novnc").canonicalize()?;
    println!("cargo:rerun-if-changed={}", root.display());
    let mut entries = Vec::new();
    embed(&root, &root, &mut entries)?;
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("Missing build folder"))?);
    fs::write(out.join("console-assets.rs"), format!("&[\n{}\n]", entries.join("\n")))
}
