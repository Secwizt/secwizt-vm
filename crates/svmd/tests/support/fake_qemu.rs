#![forbid(unsafe_code)]
#![deny(warnings)]

// Compiled only by qemu_workflow. The two filenames implement the small protocols
// exercised by the driver. All disk and worker data stays in the test directory.
use std::{env, fs, io::{self, BufRead, Write}, path::{Path, PathBuf}, process, thread, time::Duration};

fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn qcow2_header(size: u64) -> [u8; 72] {
    let mut header = [0; 72];
    header[..4].copy_from_slice(b"QFI\xfb");
    header[4..8].copy_from_slice(&2u32.to_be_bytes());
    header[20..24].copy_from_slice(&16u32.to_be_bytes());
    header[24..32].copy_from_slice(&size.to_be_bytes());
    header
}

fn image_tool(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("create") if args.len() >= 3 => {
            let size = args.last().unwrap();
            // A plain number is a byte count. The provisioner passes whole gibibytes with a G suffix.
            let bytes: u64 = match size.strip_suffix(['G','g']) {
                Some(gib) => gib.parse::<u64>()? << 30,
                None => size.parse()?,
            };
            let path = Path::new(&args[args.len()-2]);
            let mut image = qcow2_header(bytes).to_vec();
            if let Some(backing) = args.windows(2).find(|pair| pair[0] == "-b").map(|pair| pair[1].as_str()) {
                // The backing format extension and the backing name, laid out as qemu-img writes them.
                image.extend_from_slice(&0xe279_2aca_u32.to_be_bytes());
                image.extend_from_slice(&5_u32.to_be_bytes());
                image.extend_from_slice(b"qcow2\0\0\0");
                let offset = image.len() as u64;
                image[8..16].copy_from_slice(&offset.to_be_bytes());
                image[16..20].copy_from_slice(&(backing.len() as u32).to_be_bytes());
                image.extend_from_slice(backing.as_bytes());
            }
            fs::OpenOptions::new().write(true).create_new(true).open(path)?.write_all(&image)?;
        }
        Some("convert") => {
            let from=Path::new(&args[args.len()-2]);
            let to=Path::new(&args[args.len()-1]);
            let read=fs::read(from)?;
            let fmt=args.windows(2).find(|p|p[0]=="-O").ok_or("Missing output format")?[1].as_str();
            let size=if read.starts_with(b"QFI\xfb") {u64::from_be_bytes(read[24..32].try_into()?)}else{read.len() as u64};
            let mut data=vec![0u8;65536];
            match fmt {
                "qcow2" => data[..72].copy_from_slice(&qcow2_header(size)),
                "vhdx"=>data[..8].copy_from_slice(b"vhdxfile"),
                "vdi"=>{data[64..68].copy_from_slice(&0xbeda107fu32.to_le_bytes());data[76..80].copy_from_slice(&1u32.to_le_bytes());}
                _=>return Err("Unsupported test conversion format".into()),
            }
            let mut dest=fs::OpenOptions::new().write(true).create_new(true).open(to)?;
            dest.write_all(&data)?;
            print!("(35.00/100%)\r");io::stdout().flush()?;
            thread::sleep(Duration::from_millis(if from.file_name().is_some_and(|n|n=="cancel.img"){4500}else{180}));
        }
        Some("dd")=>return Err("No partition hint in this simulated container".into()),
        Some("info") => {
            let data=fs::read(args.last().unwrap())?;
            let (format, bytes) = if data.starts_with(b"QFI\xfb") {
                ("qcow2", u64::from_be_bytes(data[24..32].try_into()?))
            } else if data.starts_with(b"vhdxfile") {
                ("vhdx", data.len() as u64)
            } else if data.get(64..68) == Some(&0xbeda107fu32.to_le_bytes()) {
                ("vdi", data.len() as u64)
            } else {
                ("raw", data.len() as u64)
            };
            println!("{{\"format\":\"{format}\",\"virtual-size\":{bytes}}}");
        }
        _ => return Err("Unknown fixture disk-tool operation".into()),
    }
    Ok(())
}

fn response_id(line: &str) -> &str {
    let Some((_, after)) = line.split_once("\"id\"") else { return "null"; };
    let value=after.trim_start().strip_prefix(':').unwrap_or("").trim_start();
    if let Some(text)=value.strip_prefix('"') {
        return text.find('"').map_or("null",|n|&value[..n+2]);
    }
    value.split([',','}']).next().unwrap_or("null").trim()
}

fn worker(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let folder=env::current_dir()?;
    let lease=fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(folder.join("fake-worker.lock"))?;
    lease.try_lock()?;
    if folder.join("fixture-audio-error").is_file() && args.iter().any(|s|s.starts_with("hda-output,")) {
        return Err("audio: default playback unavailable".into());
    }
    let pid=process::id();
    fs::write(folder.join("fake-system-name"),env::current_exe()?.file_stem().unwrap().to_string_lossy().as_bytes())?;
    fs::write(folder.join("fake-last-pid"),pid.to_string())?;
    let mut log=fs::OpenOptions::new().create(true).append(true).open(folder.join("fake-starts"))?;
    writeln!(log,"{pid}")?;
    fs::write(folder.join("fake-arguments.json"),format!("[{}]",args.iter().map(|s|quoted(s)).collect::<Vec<_>>().join(",")))?;
    let trigger=folder.join("fixture-simulate-crash");
    thread::spawn(move||loop{
        if trigger.exists(){process::exit(17);}
        thread::sleep(Duration::from_millis(40));
    });
    println!("{{\"QMP\":{{\"version\":{{}},\"capabilities\":[]}}}}");
    io::stdout().flush()?;
    let mut running=!args.iter().any(|arg|arg=="-S");
    for line in io::stdin().lock().lines() {
        let line=line?;
        let id=response_id(&line);
        if line.contains("query-status") && folder.join("fixture-monitor-error").is_file() {
            println!("{{\"error\":{{\"desc\":\"fixture monitor failure\"}},\"id\":{id}}}");
            io::stdout().flush()?;
            continue;
        }
        let result=if line.contains("\"qmp_capabilities\"") || line.contains("\"quit\"") { "{}" }
            else if line.contains("\"query-vnc-servers\"") {
                r#"[{"auth":"vnc","server":[{"auth":"vnc","family":"ipv4","host":"127.77.0.1","service":"5900","websocket":false}]}]"#
            }
            else if line.contains("\"set_password\"") { "{}" }
            else if line.contains("\"cont\"") { running=true; "{}" }
            else if line.contains("\"query-status\"") && !running { "{\"status\":\"prelaunch\",\"running\":false}" }
            else if line.contains("\"query-status\"") { "{\"status\":\"running\",\"running\":true}" }
            else { return Err("Unexpected fixture QMP operation".into()); };
        println!("{{\"return\":{result},\"id\":{id}}}");
        io::stdout().flush()?;
        if line.contains("\"quit\"") { break; }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args:Vec<String>=env::args().skip(1).collect();
    let exe:PathBuf=env::current_exe()?;
    let img=exe.file_stem().and_then(|s|s.to_str())==Some("qemu-img");
    let arm=exe.file_stem().and_then(|s|s.to_str())==Some("qemu-system-aarch64");
    if args==["--version"] && arm && exe.with_file_name("fixture-arm-version").exists(){println!("QEMU emulator version 8.0.0");return Ok(());}
    if args==["--version"] {
        println!("{} version 11.1.0",if img {"qemu-img"} else {"QEMU emulator"});
        return Ok(());
    }
    if img { return image_tool(&args); }
    if args==["-accel","help"] { println!("Accelerators supported in QEMU binary:\nwhpx\ntcg"); return Ok(()); }
    if args==["-audiodev","help"] { println!("Available audio drivers:\nnone\ndsound"); return Ok(()); }
    if args==["-display","help"] { println!("Available display backend types:\ngtk\nsdl"); return Ok(()); }
    worker(&args)
}
