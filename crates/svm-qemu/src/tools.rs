use crate::{err, local, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions}, io::{self, Read}, path::{Path, PathBuf}, process::{Command, Stdio},
    sync::mpsc, thread, time::{Duration, Instant, UNIX_EPOCH},
};

pub(crate) fn command(exe: &Path) -> Command {
    let mut cmd=Command::new(exe);
    cmd.env_clear();
    for name in ["SystemRoot","WINDIR","SystemDrive","TEMP","TMP","LOCALAPPDATA","USERPROFILE","LANG"] {
        if let Some(value)=std::env::var_os(name) {cmd.env(name,value);}
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    cmd
}

pub(crate) fn io_error(e: impl std::fmt::Display) -> svm_core::engine::EngineError { err(e.to_string()) }

pub(crate) fn drain(mut input: impl Read + Send + 'static, cap: usize) -> mpsc::Receiver<Vec<u8>> {
    let (send,recv)=mpsc::channel();
    thread::spawn(move || {
        let mut kept=Vec::new();
        let mut buf=[0_u8;4096];
        while let Ok(n)=input.read(&mut buf) {
            if n==0 {break;}
            let take=n.min(cap.saturating_sub(kept.len()));
            kept.extend_from_slice(&buf[..take]);
        }
        let _=send.send(kept);
    });
    recv
}

pub(crate) fn run(cmd: Command, seconds: u64) -> Result<String> {
    run_with_limit(cmd, seconds, 16384)
}

pub(crate) fn run_with_limit(mut cmd: Command, seconds: u64, limit: usize) -> Result<String> {
    let mut child=cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(io_error)?;
    let stdout=drain(child.stdout.take().expect("piped stdout"),limit+1);
    let stderr=drain(child.stderr.take().expect("piped stderr"),2048);
    let until=Instant::now()+Duration::from_secs(seconds);
    let status=loop {
        if let Some(status)=child.try_wait().map_err(io_error)? {break status;}
        if Instant::now()>=until {
            let _=child.kill(); let _=child.wait();
            return Err(err("The selected QEMU tool timed out."));
        }
        thread::sleep(Duration::from_millis(25));
    };
    let output=stdout.recv_timeout(Duration::from_secs(1)).map_err(|_|err("The tool did not close its output."))?;
    let details=stderr.recv_timeout(Duration::from_secs(1)).map_err(|_|err("The tool did not close its error output."))?;
    if !status.success() {return Err(err(format!("QEMU exited with {status}. {}",String::from_utf8_lossy(&details).trim())));}
    if output.len()>limit {return Err(err("The selected tool returned too much output."));}
    String::from_utf8(output).map_err(|_|err("The selected tool returned invalid text."))
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Binary {
    pub path:PathBuf, length:u64, modified:u64, hash:String,
}

fn stamp(path:&Path)->Result<(u64,u64)> {
    let m=fs::metadata(path).map_err(io_error)?;
    let ns=m.modified().map_err(io_error)?.duration_since(UNIX_EPOCH).map_err(io_error)?.as_nanos();
    Ok((m.len(),u64::try_from(ns).map_err(io_error)?))
}

fn open_binary(path:&Path)->Result<File> {
    let mut open=OpenOptions::new();open.read(true);
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        open.share_mode(1);
    }
    open.open(path).map_err(io_error)
}

fn fingerprint(file:&mut File)->Result<String> {
    let mut digest=Sha256::new();
    io::copy(file,&mut digest).map_err(io_error)?;
    Ok(format!("{:x}",digest.finalize()))
}

impl Binary {
    fn capture(path:&Path)->Result<(Self,File)> {
        let path=local(path,false)?;
        let mut handle=open_binary(&path)?;
        let (length,modified)=stamp(&path)?;
        let hash=fingerprint(&mut handle)?;
        Ok((Self{path,length,modified,hash},handle))
    }
    pub fn unchanged(&self)->Result<()> {
        if local(&self.path,false)?!=self.path || stamp(&self.path)?!=(self.length,self.modified) {return Err(err("The selected QEMU installation changed. Select the executable again in Settings."));}
        Ok(())
    }
    pub fn verified(&self)->Result<File> {
        let mut file=open_binary(&self.path)?;
        self.unchanged()?;
        if fingerprint(&mut file)?!=self.hash {return Err(err("The selected QEMU executable changed. Verify it again in Settings."));}
        Ok(file)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Tools {
    pub system: Binary, pub image: Binary, pub version: String,
    #[serde(default)] pub arm: Option<ArmTools>,
    #[serde(default)] pub arm_reason: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ArmTools {
    pub system: Binary,
    pub code: Binary,
    pub template: Binary,
}

impl ArmTools {
    fn capture(system: &Binary, expected_version: &str) -> Result<Self> {
        let exe = system.path.with_file_name("qemu-system-aarch64.exe");
        let share = system.path.with_file_name("share");
        let (arm, _system_handle) = Binary::capture(&exe)?;
        if version(&arm, "QEMU emulator version ")? != expected_version {
            return Err(err("The Arm executable and the selected x86 executable have different QEMU versions."));
        }
        let mut help = command(&arm.path);
        help.args(["-accel", "help"]);
        if !run(help, 5)?.lines().any(|line| line.trim() == "tcg") {
            return Err(err("The Arm executable does not provide software emulation (TCG)."));
        }
        let (code, _code_handle) = Binary::capture(&share.join("edk2-aarch64-code.fd"))?;
        let (template, _template_handle) = Binary::capture(&share.join("edk2-arm-vars.fd"))?;
        if code.length != 64 << 20 || template.length != 64 << 20 {
            return Err(err("The Arm virt machine requires two 64 MiB UEFI flash images."));
        }
        Ok(Self { system: arm, code, template })
    }

    pub fn variables_size(&self) -> u64 { self.template.length }
}

fn version(bin:&Binary,prefix:&str)->Result<String> {
    let mut c=command(&bin.path); c.arg("--version");
    let output=run(c,5)?;
    let value=output.lines().next().and_then(|line|line.strip_prefix(prefix)).and_then(|s|s.split_whitespace().next()).unwrap_or_default();
    let fields:Vec<_>=value.split('.').collect();
    if fields.len()!=3 || fields.iter().any(|s|s.is_empty() || !s.bytes().all(|b|b.is_ascii_digit())) {return Err(err("The selected executable did not report the expected QEMU version."));}
    Ok(value.into())
}

impl Tools {
    pub fn select(path:&Path)->Result<Self> {
        if !path.file_name().is_some_and(|n|n.eq_ignore_ascii_case("qemu-system-x86_64.exe")) {return Err(err("Choose qemu-system-x86_64.exe from the installed QEMU folder."));}
        let (system,_sys_handle)=Binary::capture(path)?;
        let (image,_img_handle)=Binary::capture(&system.path.with_file_name("qemu-img.exe"))?;
        let ver=version(&system,"QEMU emulator version ")?;
        if version(&image,"qemu-img version ")?!=ver {return Err(err("The QEMU system and disk tools report different versions."));}
        let mut help=command(&system.path);help.args(["-accel","help"]);
        if !run(help,5)?.lines().any(|l|l.trim()=="whpx") {return Err(err("This QEMU build does not provide the Windows Hypervisor Platform accelerator (WHPX)."));}
        let mut tools=Self{system,image,version:ver,arm:None,arm_reason:None};
        tools.detect_arm();
        Ok(tools)
    }
    pub fn unchanged(&self)->Result<()> {
        self.system.unchanged()?;self.image.unchanged()
    }
    pub fn detect_arm(&mut self) {
        match ArmTools::capture(&self.system, &self.version) {
            Ok(arm) => { self.arm=Some(arm); self.arm_reason=None; }
            Err(error) => { self.arm=None; self.arm_reason=Some(format!("Emulated Arm is unavailable. {error} Verify the matching QEMU Arm executable and firmware in Settings.")); }
        }
    }

    pub fn arm_tools(&self) -> Result<&ArmTools> {
        let arm=self.arm.as_ref().ok_or_else(||err(self.arm_reason.as_deref().unwrap_or("Select QEMU again in Settings to verify the Arm executable and firmware.")))?;
        let share=self.system.path.with_file_name("share");
        if arm.system.path!=self.system.path.with_file_name("qemu-system-aarch64.exe") ||
            arm.code.path!=share.join("edk2-aarch64-code.fd") || arm.template.path!=share.join("edk2-arm-vars.fd") {
            return Err(err("The Arm executable and firmware must belong to the selected QEMU installation."));
        }
        arm.system.unchanged()?;
        arm.code.unchanged()?;
        arm.template.unchanged()?;
        Ok(arm)
    }
    pub fn inspect_disk(&self,disk:&Path,size:u64)->Result<()> {
        self.disk_info(disk,size).map(drop)
    }
    pub(crate) fn disk_info(&self,disk:&Path,size:u64)->Result<serde_json::Value> {
        // Check the disk header before the external tool can interpret any storage reference.
        let _disk=crate::linked::standalone_disk(disk,size)?;
        let _handle=self.image.verified()?;
        let mut c=command(&self.image.path);
        c.args(["info","--output=json","-f","qcow2"]).arg(disk);
        let info:serde_json::Value=serde_json::from_str(&run_with_limit(c,10,1024*1024)?).map_err(io_error)?;
        if info["format"]!="qcow2" || info["virtual-size"].as_u64()!=Some(size)
            || !info["backing-filename"].is_null() || !info["full-backing-filename"].is_null()
            || info.pointer("/format-specific/data/data-file").is_some_and(|v|!v.is_null())
            || info["encrypted"]==true {
            return Err(err("The owned disk must be one standalone qcow2 of the recorded size."));
        }
        Ok(info)
    }
}
