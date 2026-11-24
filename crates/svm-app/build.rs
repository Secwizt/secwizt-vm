#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{env, fs, io, path::{Path, PathBuf}};

fn embed(root: &Path, dir: &Path, entries: &mut Vec<String>) -> io::Result<()> {
    let mut children = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            // ui/tools holds development checks; they are not part of the app.
            if dir == root && entry.file_name() == "tools" { continue; }
            embed(root, &path, entries)?;
        }
        else if kind.is_file() {
            let relative = path.strip_prefix(root).map_err(io::Error::other)?.to_str()
                .ok_or_else(|| io::Error::other("UI filenames must be UTF-8."))?.replace('\\', "/");
            let mime = match path.extension().and_then(|s| s.to_str()) {
                Some("js" | "mjs") => "text/javascript; charset=utf-8",
                Some("html") => "text/html; charset=utf-8", Some("css") => "text/css; charset=utf-8",
                Some("svg") => "image/svg+xml", Some("png") => "image/png",
                Some("json") => "application/json", Some("txt" | "md") => "text/plain; charset=utf-8",
                _ => return Err(io::Error::other(format!("Unknown UI file type: {relative}"))),
            };
            entries.push(format!("({:?}, {:?}, include_bytes!({:?})),", format!("/{relative}"), mime, path));
        } else { return Err(io::Error::other("Only regular files can be embedded.")); }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| io::Error::other("Missing manifest folder."))?);
    let root = manifest.join("../../ui").canonicalize()?;
    let inventory = manifest.join("../../DOWNLOADS.md");
    println!("cargo:rerun-if-changed={}", root.display());
    println!("cargo:rerun-if-changed={}", inventory.display());
    // App icon: link the precompiled resource (assets/svm.rc explains how to rebuild it).
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") && env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let icon = manifest.join("assets").join("svm.res");
        println!("cargo:rerun-if-changed={}", icon.display());
        println!("cargo:rustc-link-arg-bins={}", icon.display());
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("Missing build folder."))?);
    let mut entries = Vec::new();
    embed(&root, &root, &mut entries)?;
    fs::write(out.join("assets.rs"), format!("&[\n{}\n]", entries.join("\n")))?;
    // Embed the component tables from DOWNLOADS.md for Settings > About.
    let mut notices = String::from("Secwizt Virtual Machine © 2026 Secwizt Private Limited.\n\nThird-party components\n\n");
    let mut shipped = true;
    for line in fs::read_to_string(inventory)?.lines() {
        if line.starts_with('#') { shipped = !line.starts_with("### Other targets in Cargo.lock"); }
        if !shipped || !line.starts_with('|') { continue; }
        let fields: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
        if fields.iter().all(|s| s.chars().all(|c| matches!(c, '-' | ':' | ' '))) { continue; }
        notices.push_str(&fields.join("  ·  "));
        notices.push('\n');
    }
    fs::write(out.join("notices.txt"), notices)
}
