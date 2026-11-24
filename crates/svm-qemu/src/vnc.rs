use crate::{err, io_error, Result};
use serde_json::Value;
use std::{
    io::{self, Read, Write}, net::{Shutdown, SocketAddr, TcpStream},
    sync::atomic::{AtomicBool, Ordering}, thread, time::{Duration, Instant},
};
use svm_core::local_auth::SERVICE_HOST;

/// QEMU's display listens on the service loopback address (svm_core::local_auth::SERVICE_HOST), which
/// the guest's user-mode network cannot reach, so a guest cannot even try the display password.
pub(crate) const ARGUMENT: &str = "127.77.0.1:0,to=99,password=on";
const VERSION: &[u8; 12] = b"RFB 003.008\n";
const HANDSHAKE: Duration = Duration::from_secs(8);

pub(crate) struct Vnc {
    port: u16,
    password: [u8; 8],
    closing: AtomicBool,
}

impl Vnc {
    pub(crate) fn new(servers: &Value) -> Result<Self> {
        let error = || err("QEMU did not confirm one password-protected loopback display.");
        let [display] = servers.as_array().map(Vec::as_slice).ok_or_else(error)? else { return Err(error()); };
        let [listener] = display["server"].as_array().map(Vec::as_slice).ok_or_else(error)? else { return Err(error()); };
        let port = listener["service"].as_str().and_then(|s| s.parse::<u16>().ok())
            .filter(|p| (5900..=5999).contains(p)).ok_or_else(error)?;
        if display["auth"] != "vnc" || listener["auth"] != "vnc" || listener["family"] != "ipv4"
            || listener["host"] != SERVICE_HOST.to_string().as_str() || listener["websocket"] != false {
            return Err(error());
        }
        let mut password = [0; 8];
        getrandom::fill(&mut password).map_err(|_| err("Windows could not generate a display password."))?;
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for byte in &mut password { *byte = alphabet[usize::from(*byte & 63)]; }
        Ok(Self { port, password, closing: AtomicBool::new(false) })
    }

    pub(crate) fn password(&self) -> &str {
        std::str::from_utf8(&self.password).expect("ASCII display password")
    }

    pub(crate) fn serve(&self, mut downstream: TcpStream) -> Result<()> {
        let mut upstream = self.connect()?;
        let deadline = Instant::now() + HANDSHAKE;
        downstream.set_write_timeout(Some(HANDSHAKE)).map_err(io_error)?;
        downstream.write_all(VERSION).map_err(io_error)?;
        if read::<12>(&mut downstream, deadline)? != *VERSION {
            return Err(err("The console did not negotiate RFB 3.8."));
        }
        // The private downstream peer has already authenticated with the supervisor.
        downstream.write_all(&[1, 1]).map_err(io_error)?;
        if read::<1>(&mut downstream, deadline)? != [1] {
            return Err(err("The authenticated console did not select its local security type."));
        }
        downstream.write_all(&[0; 4]).map_err(io_error)?;
        relay(downstream, upstream.try_clone().map_err(io_error)?, &mut upstream)
    }

    pub(crate) fn close(&self) {
        self.closing.store(true, Ordering::Release);
    }

    fn connect(&self) -> Result<TcpStream> {
        if self.closing.load(Ordering::Acquire) { return Err(err("The QEMU display is closing.")); }
        let target = SocketAddr::from((SERVICE_HOST, self.port));
        let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(2)).map_err(io_error)?;
        stream.set_write_timeout(Some(HANDSHAKE)).map_err(io_error)?;
        let deadline = Instant::now() + HANDSHAKE;
        if read::<12>(&mut stream, deadline)? != *VERSION {
            return Err(err("The owned QEMU display did not negotiate RFB 3.8."));
        }
        stream.write_all(VERSION).map_err(io_error)?;
        let count = usize::from(read::<1>(&mut stream, deadline)?[0]);
        if count != 1 || read::<1>(&mut stream, deadline)? != [2] {
            return Err(err("The owned QEMU display did not require its password."));
        }
        stream.write_all(&[2]).map_err(io_error)?;
        let challenge = read::<16>(&mut stream, deadline)?;
        let response = encrypt(self.password.map(u8::reverse_bits), challenge, &self.closing)?;
        stream.write_all(&response).map_err(io_error)?;
        if read::<4>(&mut stream, deadline)? != [0; 4] {
            return Err(err("The owned QEMU display refused the private bridge."));
        }
        Ok(stream)
    }
}

fn read<const N: usize>(stream: &mut TcpStream, deadline: Instant) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    let mut rest = bytes.as_mut_slice();
    while !rest.is_empty() {
        let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
            .ok_or_else(|| err("The QEMU display handshake timed out."))?;
        stream.set_read_timeout(Some(left)).map_err(io_error)?;
        let size = stream.read(rest).map_err(io_error)?;
        if size == 0 { return Err(err("The QEMU display closed its handshake.")); }
        rest = &mut rest[size..];
    }
    Ok(bytes)
}

fn relay(mut downstream: TcpStream, mut up_write: TcpStream, upstream: &mut TcpStream) -> Result<()> {
    let mut down_read = downstream.try_clone().map_err(io_error)?;
    downstream.set_read_timeout(None).map_err(io_error)?;
    upstream.set_read_timeout(None).map_err(io_error)?;
    thread::scope(|scope| {
        scope.spawn(move || {
            let _ = io::copy(&mut down_read, &mut up_write);
            let _ = down_read.shutdown(Shutdown::Both);
            let _ = up_write.shutdown(Shutdown::Both);
        });
        let _ = io::copy(upstream, &mut downstream);
        let _ = upstream.shutdown(Shutdown::Both);
        let _ = downstream.shutdown(Shutdown::Both);
    });
    Ok(())
}

#[cfg(windows)]
fn encrypt(key: [u8; 8], challenge: [u8; 16], closing: &AtomicBool) -> Result<[u8; 16]> {
    use std::{path::PathBuf, process::Stdio};
    let unavailable = || err("Windows could not authenticate to the owned VNC display. Check the host cryptography policy or open a separate window on the next start.");
    let windows = std::env::var_os("SystemRoot").ok_or_else(unavailable)?;
    if closing.load(Ordering::Acquire) { return Err(unavailable()); }
    let windows = PathBuf::from(windows);
    let exe = windows.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut child = crate::tools::command(&exe)
        .current_dir(&windows)
        .args(["-NoProfile", "-NonInteractive", "-Command", include_str!("vnc-challenge.ps1")])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| unavailable())?;
    let deadline = Instant::now() + Duration::from_secs(4);
    let output = crate::tools::drain(child.stdout.take().expect("private helper output"), 17);
    let result = (|| {
        let mut input = child.stdin.take().expect("private helper input");
        input.write_all(&key).and_then(|()| input.write_all(&challenge)).map_err(|_| unavailable())?;
        drop(input);
        loop {
            if let Some(status) = child.try_wait().map_err(|_| unavailable())? {
                if !status.success() { return Err(unavailable()); }
                return output.recv_timeout(Duration::from_millis(250)).map_err(|_| unavailable())?
                    .try_into().map_err(|_| unavailable());
            }
            if closing.load(Ordering::Acquire) || Instant::now() >= deadline { return Err(unavailable()); }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() && child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(not(windows))]
fn encrypt(_: [u8; 8], _: [u8; 16], _: &AtomicBool) -> Result<[u8; 16]> {
    Err(err("The QEMU display bridge requires Windows host cryptography."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn requires_exactly_one_private_password_listener() {
        let info = json!([{"auth":"vnc","server":[
            {"host":"127.77.0.1","service":"5901","family":"ipv4","websocket":false,"auth":"vnc"}
        ]}]);
        let vnc = Vnc::new(&info).unwrap();
        assert_eq!(vnc.port, 5901);
        assert_eq!(vnc.password().len(), 8);
        assert!(ARGUMENT.starts_with(&format!("{SERVICE_HOST}:0,")));
        // 127.0.0.1 is reachable from a guest without isolation, so a display there is refused.
        for (field, invalid) in [("host", json!("0.0.0.0")), ("host", json!("127.0.0.1")), ("auth", json!("none")), ("websocket", json!(true))] {
            let mut changed = info.clone();
            changed[0]["server"][0][field] = invalid;
            assert!(Vnc::new(&changed).is_err());
        }
    }
}
