use crate::{err, image_info, local, tools, Qemu, Result};
use std::{
    fs::{self, File, OpenOptions}, io::{self, Read}, path::{Path, PathBuf},
    process::Stdio, sync::{Arc, atomic::{AtomicBool, AtomicU8, Ordering}},
    thread, time::{Duration, Instant},
};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct DiskInfo {
    pub format: String,
    pub bytes: u64,
    pub firmware: Option<String>,
}

pub struct LocalFolder {
    pub path: PathBuf,
    _handles: Vec<File>,
}

impl LocalFolder {
    pub fn open(folder: &Path) -> Result<Self> {
        #[cfg(windows)] {
            use std::path::{Component, Prefix};
            if !folder.is_absolute() || !matches!(folder.components().next(), Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))) {
                return Err(err("Choose an ordinary local disk path."));
            }
            let root=folder.ancestors().last().ok_or_else(||err("Choose a local disk volume."))?;
            let mut check=powershell()?;
            let drive=root.to_string_lossy().trim_start_matches(r"\\?\").to_owned();
            check.args(["-NoProfile","-NonInteractive","-Command",
                "if(([IO.DriveInfo]::new($env:SVM_DISK_ROOT)).DriveType -notin 'Fixed','Removable','Ram'){exit 1}"])
                .env("SVM_DISK_ROOT",drive);
            tools::run(check,8).map_err(|_|err("Select a local disk volume. Network drives are unavailable."))?;
        }
        Self::hold(folder)
    }

    /// Hold a folder already known to be on a local disk, such as one inside a machine bundle,
    /// without the drive check. That check starts PowerShell, which is too slow for the exit path
    /// of a supervisor that must confirm the guest off within seconds.
    pub fn hold(folder: &Path) -> Result<Self> {
        #[cfg(windows)] {
            use std::path::{Component, Prefix};
            if !folder.is_absolute() || !matches!(folder.components().next(), Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))) {
                return Err(err("Choose an ordinary local disk path."));
            }
        }
        let path=local(folder,true)?;
        let mut handles=Vec::new();
        #[cfg(windows)] {
            use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
            for ancestor in folder.ancestors().collect::<Vec<_>>().into_iter().rev() {
                // Open the directory itself, never its reparse target, and deny renaming while in use.
                let handle=OpenOptions::new().read(true).share_mode(3)
                    .custom_flags(0x0200_0000|0x0020_0000).open(ancestor).map_err(tools::io_error)?;
                if handle.metadata().map_err(tools::io_error)?.file_attributes() & 0x400 != 0 {
                    return Err(err("The disk path crosses a link or junction."));
                }
                handles.push(handle);
            }
        }
        #[cfg(not(windows))]
        handles.push(File::open(&path).map_err(tools::io_error)?);
        if local(folder,true)?!=path {return Err(err("The selected folder changed. Choose it again."));}
        Ok(Self{path,_handles:handles})
    }

    pub fn verify_private(&self) -> Result<()> {
        #[cfg(windows)] { crate::agent_transport::directory_acl(&self.path,"check")?; }
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            if self.path.metadata().map_err(tools::io_error)?.permissions().mode() & 0o077 != 0 {
                return Err(err("The private tools directory allows other users."));
            }
        }
        Ok(())
    }

    pub fn create_private_child(&self, name: &str) -> Result<Self> {
        if !svm_core::library::ordinary_file_name(name) {
            return Err(err("The temporary folder name is invalid."));
        }
        let path = self.path.join(name);
        #[cfg(windows)]
        crate::agent_transport::directory_acl(&path, "new")?;
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path).map_err(tools::io_error)?;
        }
        let folder = Self::open(&path)?;
        folder.verify_private()?;
        Ok(folder)
    }
}

#[cfg(windows)]
fn powershell() -> Result<std::process::Command> {
    let root=std::env::var_os("SystemRoot").ok_or_else(||err("Windows system folder is unavailable."))?;
    Ok(tools::command(&PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe")))
}

/// Both paths are inside held directories. Publish only if the named destination is still free.
pub fn publish_disk(from:&Path,to:&Path)->Result<()> {
    #[cfg(windows)] {
        let mut cmd=powershell()?;
        cmd.args(["-NoProfile","-NonInteractive","-Command",
            "$ErrorActionPreference='Stop';[IO.File]::Move($env:SVM_DISK_FROM,$env:SVM_DISK_TO)"])
            .env("SVM_DISK_FROM",from).env("SVM_DISK_TO",to);
        tools::run(cmd,15).map_err(|_|err("The destination already exists or Windows could not publish the converted disk."))?;
    }
    #[cfg(not(windows))] {
        fs::hard_link(from,to).map_err(tools::io_error)?;
        fs::remove_file(from).map_err(tools::io_error)?;
    }
    Ok(())
}

pub struct DiskSource {
    pub path:PathBuf,
    pub info:DiskInfo,
    tool:tools::Binary,
    _folder:LocalFolder,
    _handle:File,
}

impl Qemu {
    pub fn disk_details(&self,path:&Path)->Result<DiskInfo> {
        let mut source=self.disk_source(path)?;
        if source.info.format=="raw" || source.info.bytes<65536 {return Ok(source.info);}
        let work=LocalFolder::open(&self.home)?;
        let workdir=work.path.join(format!(".disk-hint-{}",crate::unique()));
        fs::create_dir(&workdir).map_err(tools::io_error)?;
        let output=workdir.join("partition-table.bin");
        let read=(||->Result<Option<String>>{
            let _tool=source.tool.verified()?;
            let mut cmd=tools::command(&source.tool.path);
            cmd.args(["dd","-f",&source.info.format,"-O","raw","bs=65536","count=1"]);
            let mut input=std::ffi::OsString::from("if=");input.push(&source.path);
            let mut target=std::ffi::OsString::from("of=");target.push(&output);
            cmd.arg(input).arg(target);
            tools::run(cmd,12)?;
            let file=File::open(&output).map_err(tools::io_error)?;
            let mut bytes=Vec::new();
            file.take(65537).read_to_end(&mut bytes).map_err(tools::io_error)?;
            Ok((bytes.len()==65536).then(||image_info::firmware_hint(&bytes)).flatten().map(str::to_owned))
        })();
        if output.try_exists().map_err(tools::io_error)? {fs::remove_file(output).map_err(tools::io_error)?;}
        fs::remove_dir(workdir).map_err(tools::io_error)?;
        source.info.firmware=read.unwrap_or(None);
        Ok(source.info)
    }
    pub fn disk_source(&self,source:&Path)->Result<DiskSource> {
        self.image_tool()?.disk_source(source)
    }

    /// The verified disk tool of the selected QEMU, for disk work on a worker thread.
    pub fn image_tool(&self)->Result<ImageTool> {
        Ok(ImageTool{tool:self.available()?.image.clone()})
    }
}

/// The selected QEMU's disk tool. Every use re-verifies the executable first.
#[derive(Clone)]
pub struct ImageTool { tool:tools::Binary }

impl ImageTool {
    pub fn disk_source(&self,source:&Path)->Result<DiskSource> {
        let tool=self.tool.clone();
        let folder=LocalFolder::open(source.parent().ok_or_else(||err("Select a disk file."))?)?;
        let candidate=folder.path.join(source.file_name().ok_or_else(||err("Select a regular disk file."))?);
        let source=local(&candidate,false)?;
        let mut options=OpenOptions::new();
        options.read(true);
        #[cfg(windows)] {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(1).custom_flags(0x0020_0000);
        }
        let file=options.open(&candidate).map_err(|_|err("The disk is in use or could not be opened read-only."))?;
        if local(&candidate,false)?!=source {return Err(err("The selected disk changed. Choose it again."));}
        let report=image_info::inspect(&tool,&source)?;
        Ok(DiskSource{path:source,info:DiskInfo{format:report.format,bytes:report.bytes,firmware:report.firmware},
            tool,_folder:folder,_handle:file})
    }

    /// Grow a standalone qcow2 that this service wrote to exactly `bytes` of virtual size.
    /// The disk is never shrunk. The result is checked with an explicit format.
    pub fn grow_qcow2(&self,disk:&Path,bytes:u64)->Result<()> {
        let check=|expected:Option<u64>|->Result<u64> {
            let _verified=self.tool.verified()?;
            let mut info=tools::command(&self.tool.path);
            info.args(["info","--output=json","-f","qcow2"]).arg(disk);
            let report:serde_json::Value=serde_json::from_str(&tools::run(info,15)?).map_err(tools::io_error)?;
            let size=report["virtual-size"].as_u64().ok_or_else(||err("The disk tool did not report the disk size."))?;
            if report["format"]!="qcow2" || !report["backing-filename"].is_null() || report["encrypted"]==true
                || report.pointer("/format-specific/data/data-file").is_some_and(|value|!value.is_null())
                || expected.is_some_and(|expected|expected!=size) {
                return Err(err("The prepared disk is not one standalone qcow2 of the expected size."));
            }
            Ok(size)
        };
        let current=check(None)?;
        if current>bytes {return Err(err("The prepared disk is larger than its catalog size."));}
        if current<bytes {
            let _verified=self.tool.verified()?;
            let mut resize=tools::command(&self.tool.path);
            resize.args(["resize","-f","qcow2"]).arg(disk).arg(bytes.to_string());
            tools::run(resize,60)?;
        }
        check(Some(bytes)).map(drop)
    }
}

#[derive(Default)]
pub struct TransferControl {
    percent:AtomicU8,
    cancel:AtomicBool,
}
impl TransferControl {
    pub fn percent(&self)->u8 {self.percent.load(Ordering::Acquire)}
    pub fn cancel(&self){self.cancel.store(true,Ordering::Release);}
    pub fn cancelled(&self)->bool {self.cancel.load(Ordering::Acquire)}
}

fn progress(mut pipe:impl Read,control:Arc<TransferControl>,base:u8,span:u8)->io::Result<()> {
    let mut bytes=[0_u8;256];
    let mut line=Vec::with_capacity(48);
    loop {
        let n=pipe.read(&mut bytes)?;
        if n==0{break;}
        for &byte in &bytes[..n] {
            if byte==b'(' {line.clear();}
            if byte==b'/' {
                if let Ok(text)=std::str::from_utf8(&line) {
                    if let Ok(p)=text.trim_start_matches('(').trim().parse::<f64>() {
                        if p.is_finite() && (0.0..=100.0).contains(&p) {
                            control.percent.fetch_max(base+((p*f64::from(span)/100.0) as u8),Ordering::Release);
                        }
                    }
                }
            }
            if line.len()<64 {line.push(byte);}
        }
    }
    Ok(())
}

#[cfg(windows)]
fn ordinary_vhdx(path:&Path)->Result<bool> {
    use std::os::windows::fs::MetadataExt;
    let attributes=fs::metadata(path).map_err(tools::io_error)?.file_attributes();
    Ok(attributes & (0x200|0x800|0x4000)==0)
}

#[cfg(windows)]
fn prepare_hyperv_disk(to:&Path,control:&Arc<TransferControl>)->Result<()> {
    if ordinary_vhdx(to)? {return Ok(());}
    let staging=to.with_file_name("qemu-output.tmp");
    publish_disk(to,&staging)?;
    // QEMU makes the Windows file sparse even when the guest container is dynamic.
    // Hyper-V requires an ordinary Windows file. Copy only the container's bytes.
    let script=r#"$ErrorActionPreference='Stop'
$inputFile=[IO.File]::Open($env:SVM_DISK_FROM,'Open','Read','Read')
try {
    $outputFile=[IO.File]::Open($env:SVM_DISK_TO,'CreateNew','Write','None')
    try {
        $buffer=[byte[]]::new(1048576)
        $last=-1
        while(($count=$inputFile.Read($buffer,0,$buffer.Length)) -gt 0){
            $outputFile.Write($buffer,0,$count)
            $percent=[int][math]::Floor(100.0*$inputFile.Position/$inputFile.Length)
            if($percent -gt $last){[Console]::WriteLine(('('+[string]$percent+'/100%)'));$last=$percent}
        }
        $outputFile.Flush($true)
    } finally {$outputFile.Dispose()}
} finally {$inputFile.Dispose()}"#;
    let mut cmd=powershell()?;
    cmd.args(["-NoProfile","-NonInteractive","-Command",script]).env("SVM_DISK_FROM",&staging).env("SVM_DISK_TO",to);
    run_conversion(cmd,control,85,14)?;
    if !ordinary_vhdx(to)? {return Err(err("Hyper-V requires an uncompressed, unencrypted local folder for this disk."));}
    fs::remove_file(staging).map_err(tools::io_error)
}

fn run_conversion(mut cmd:std::process::Command,control:&Arc<TransferControl>,base:u8,span:u8)->Result<()> {
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000|0x0000_4000);
    }
    let mut child=cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(tools::io_error)?;
    let stdout=child.stdout.take().expect("piped stdout");
    let updates=Arc::clone(control);
    let reporter=thread::spawn(move||progress(stdout,updates,base,span));
    let errors=tools::drain(child.stderr.take().expect("piped stderr"),2048);
    let started=Instant::now();
    let result=loop {
        if control.cancelled() || started.elapsed()>Duration::from_secs(24*3600) {
            break Err(err(if control.cancelled(){"Disk conversion cancelled."}else{"Disk conversion timed out."}));
        }
        match child.try_wait() {
            Ok(Some(status))=>break if status.success(){Ok(())}else{
                let detail=errors.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
                Err(err(format!("Disk conversion failed. {}",String::from_utf8_lossy(&detail).trim())))
            },
            Ok(None)=>thread::sleep(Duration::from_millis(60)),
            Err(e)=>break Err(tools::io_error(e)),
        }
    };
    if result.is_err(){let _=child.kill();let _=child.wait();}
    let _=reporter.join();
    result
}

impl DiskSource {
    pub fn convert(self,to:&Path,format:&str,control:Arc<TransferControl>)->Result<()> {
        if !matches!(format,"qcow2"|"vhdx"|"vmdk"|"vdi"){return Err(err("Unsupported conversion target."));}
        if control.cancelled(){return Err(err("Disk conversion cancelled."));}
        let _verified=self.tool.verified()?;
        let mut cmd=tools::command(&self.tool.path);
        cmd.args(["convert","-p","-m","1","-f",&self.info.format,"-O",format]);
        if format=="vmdk" {cmd.args(["-o","subformat=monolithicSparse"]);}
        cmd.arg(&self.path).arg(to);
        let span=if cfg!(windows) && format=="vhdx"{85}else{99};
        run_conversion(cmd,&control,0,span)?;
        #[cfg(windows)]
        if format=="vhdx"{prepare_hyperv_disk(to,&control)?;}
        // Verify the container we just wrote using its explicit format before it becomes visible.
        let mut check=tools::command(&self.tool.path);
        check.args(["info","--output=json","-f",format]).arg(to);
        let info:serde_json::Value=serde_json::from_str(&tools::run(check,15)?).map_err(tools::io_error)?;
        if info["format"]!=format || info["virtual-size"].as_u64()!=Some(self.info.bytes) {
            return Err(err("The converted disk's format or capacity did not match the source."));
        }
        fs::OpenOptions::new().write(true).open(to).and_then(|file|file.sync_all()).map_err(tools::io_error)
    }
}
