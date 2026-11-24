//! Stand-ins for restic and age. Only the simulated restic receives the simulated credential.
use std::{env, fs, path::{Path, PathBuf}, process::Command, time::Duration};

const SNAP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TIME: &str = "2026-11-20T18:00:00Z";

fn value<'a>(args: &'a [String], name: &str) -> &'a str {
    &args[args.iter().position(|v| v == name).expect("required option") + 1]
}

// A simulated owner acknowledges this fake tool's failure in its own isolated console.
fn fail(code: i32) -> ! {
    let shell = PathBuf::from(env::var_os("SystemRoot").unwrap()).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let input = fs::OpenOptions::new().read(true).write(true).open("CONIN$").unwrap();
    let status = Command::new(shell).args(["-NoProfile", "-NonInteractive", "-Command", include_str!("acknowledge_backup.ps1")])
        .stdin(input).status().unwrap();
    assert!(status.success());
    std::process::exit(code)
}

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let exe = env::current_exe().unwrap();
    if exe.file_name().unwrap() == "age.exe" {
        assert_eq!(&args[..2], ["-d", "-i"]);
        assert_eq!(args.len(), 4);
        assert!(Path::new(&args[2]).is_file());
        if Path::new(&args[3]).with_file_name("cancel-key-prompt").exists() { std::process::exit(1); }
        let canary = fs::read_to_string(&args[3]).unwrap();
        print!("{canary}");
        return;
    }
    let repo = PathBuf::from(value(&args, "--repo").strip_prefix("local:").unwrap());
    let password_command = value(&args, "--password-command");
    let quoted: Vec<_> = password_command.split('"').collect();
    assert_eq!(quoted.len(), 7);
    assert_eq!([quoted[0],quoted[2],quoted[4],quoted[6]], [""," -d -i "," ",""]);
    let age = Path::new(quoted[1]);
    assert_eq!(age.canonicalize().unwrap(), exe.with_file_name("age.exe").canonicalize().unwrap());
    let output = Command::new(age).args(["-d","-i",quoted[3],quoted[5]]).output().unwrap();
    if !output.status.success() {
        eprintln!(r#"{{"message_type":"exit_error","code":1,"message":"Fatal: Resolving password failed: private fixture detail"}}"#);
        fail(1);
    }
    assert_eq!(output.stdout.len(), 32);
    assert!(output.stdout.iter().all(u8::is_ascii_hexdigit));
    // Record paths and the names of environment variables only.
    fs::write(repo.join("arguments"), args.join("\n")).unwrap();
    fs::write(repo.join("environment"),env::vars_os().map(|(k,_)|k.to_string_lossy().into_owned()).collect::<Vec<_>>().join("\n")).unwrap();
    assert_eq!(env::var("GOMAXPROCS").unwrap(), "1");
    assert_eq!(env::var("PATHEXT").unwrap(), ".EXE");
    assert_eq!(env::var_os("PATH").map(PathBuf::from).unwrap().canonicalize().unwrap(), exe.parent().unwrap().canonicalize().unwrap());
    if repo.join("fail").exists() { fail(12); }
    if args.iter().any(|v| v=="backup") {
        if repo.join("partial").exists() {
            let id="f".repeat(64);
            fs::write(repo.join("partial-index"),[]).unwrap();
            println!(r#"{{"message_type":"summary","snapshot_id":"{id}","backup_end":"{TIME}","total_bytes_processed":1}}"#);
            fail(3);
        }
        assert_eq!(args.last().unwrap(), ".");
        for _ in 0..150 {
            if !repo.join("wait").exists() { break; }
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut bytes=0;
        for name in ["vm.json","system.vhdx","system.qcow2","uefi-vars.fd","qemu-vm.json"] {
            let stored=repo.join(name);
            if Path::new(name).exists() { bytes+=fs::copy(name, stored).unwrap(); }
            else if stored.exists() { fs::remove_file(stored).unwrap(); }
        }
        fs::write(repo.join("size"),bytes.to_string()).unwrap();
        println!(r#"{{"message_type":"summary","snapshot_id":"{SNAP}","backup_end":"{TIME}","total_bytes_processed":{bytes}}}"#);
    } else if args.iter().any(|v| v=="snapshots") {
        let size=fs::read_to_string(repo.join("size")).unwrap();
        let id="f".repeat(64);
        let partial=if repo.join("partial-index").exists() {format!(r#",{{"id":"{id}","time":"{TIME}","tags":["secwiz-vm","machine:backup-source"]}}"#)}else{String::new()};
        println!(r#"[{{"id":"{SNAP}","time":"{TIME}","summary":{{"total_bytes_processed":{size}}},"tags":["secwiz-vm","machine:backup-source"]}},{{"id":"unrelated","time":"","tags":["other"]}}{partial}]"#);
    } else {
        assert_eq!(value(&args,"restore"),SNAP);
        let target=Path::new(value(&args,"--target"));
        for _ in 0..200 {
            if !repo.join("wait-restore").exists() {break;}
            std::thread::sleep(Duration::from_millis(50));
        }
        for name in ["vm.json","system.vhdx","system.qcow2","uefi-vars.fd","qemu-vm.json"] {
            if repo.join(name).exists() { fs::copy(repo.join(name),target.join(name)).unwrap(); }
        }
        if repo.join("restore-error").exists() { fail(1); }
        match fs::read_to_string(repo.join("fixture-tree")).unwrap_or_default().as_str() {
            "extra" => fs::write(target.join("extra.txt"),b"fixture").unwrap(),
            "wrong-case" => {
                fs::rename(target.join("vm.json"),target.join("case-stage")).unwrap();
                fs::rename(target.join("case-stage"),target.join("VM.json")).unwrap();
            }
            "directory" => fs::create_dir(target.join("uefi-vars.fd")).unwrap(),
            #[cfg(windows)]
            "file-link" => std::os::windows::fs::symlink_file(repo.join("sentinel-dir/keep"),target.join("uefi-vars.fd")).unwrap(),
            _ => {}
        }
        if repo.join("link-mode").exists() {
            #[cfg(windows)] {
                let cmd=PathBuf::from(env::var_os("SystemRoot").unwrap()).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
                assert!(Command::new(cmd).args(["-NoProfile","-NonInteractive","-Command",
                    "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:FAKE_LINK -Target $env:FAKE_TARGET | Out-Null"])
                    .env("FAKE_LINK",target.join("uefi-vars.fd")).env("FAKE_TARGET",repo.join("sentinel-dir")).status().unwrap().success());
            }
        }
        println!("{{}}");
    }
}
