use crate::{err, tools::io_error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::{
    fs::{self,File},io::{Read,Write},net::{SocketAddrV4,TcpStream},path::Path,
    sync::atomic::{AtomicU64,Ordering},time::{Duration,Instant,SystemTime,UNIX_EPOCH},
};

pub(crate) fn unique()->String {
    static SERIAL:AtomicU64=AtomicU64::new(1);
    format!("{:x}-{:x}-{:x}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),SERIAL.fetch_add(1,Ordering::Relaxed))
}
// HMAC-SHA256. Every domain and field is length-prefixed, including both peer nonces.
fn mac(key:&[u8],fields:&[&str])->String {
    let mut ipad=[0x36;64];let mut opad=[0x5c;64];
    for (i,b) in key.iter().enumerate(){ipad[i]^=b;opad[i]^=b;}
    let mut inner=Sha256::new();inner.update(ipad);
    for f in fields {inner.update((f.len() as u64).to_be_bytes());inner.update(f.as_bytes());}
    let mut outer=Sha256::new();outer.update(opad);outer.update(inner.finalize());
    format!("{:x}",outer.finalize())
}
fn equal(a:&str,b:&str)->bool {
    a.len()==b.len() && std::hint::black_box(a.bytes().zip(b.bytes()).fold(0u8,|d,(x,y)| d|std::hint::black_box(x^y)))==0
}
pub(crate) fn machine_key(home:&Path,id:&str,bundle:&Path)->Result<String> {
    // The service rotates api-token at every start; supervisors that outlive a restart need this stable key.
    let file=crate::local(&home.join("machine-key"),false)?;
    let mut secret=String::new();
    File::open(file).map_err(io_error)?.take(65).read_to_string(&mut secret).map_err(io_error)?;
    if secret.len()!=64 || !secret.bytes().all(|v|v.is_ascii_hexdigit()){return Err(err("The service identity is unavailable."));}
    Ok(mac(secret.as_bytes(),&["svm-qemu-machine-v1",id,&bundle.to_string_lossy()]))
}

#[derive(Clone,Serialize,Deserialize)]
pub(crate) struct Run {pub ticket:String,pub port:u16,tag:String}
impl Run {
    pub fn new(key:&str,ticket:String,port:u16)->Self {
        let tag=mac(key.as_bytes(),&["run",&ticket,&port.to_string()]);Self{ticket,port,tag}
    }
    pub fn valid(&self,key:&str)->bool {
        equal(&self.tag,&mac(key.as_bytes(),&["run",&self.ticket,&self.port.to_string()]))
    }
}
pub(crate) fn read_run(bundle:&Path,key:&str)->Result<Option<Run>> {
    let path=bundle.join("qemu-run.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),
        Err(e)=>return Err(io_error(e)),Ok(_)=>{}
    }
    let r:Run=crate::record(&path)?;
    if !r.valid(key){return Err(err("The saved QEMU supervisor identity could not be verified."));}
    Ok(Some(r))
}

fn line(stream:&mut TcpStream,deadline:Instant)->Result<Value> {
    let mut bytes=Vec::new();
    loop{
        let left=deadline.checked_duration_since(Instant::now()).filter(|d|!d.is_zero()).ok_or_else(||err("The QEMU supervisor did not answer in time."))?;
        stream.set_read_timeout(Some(left)).map_err(io_error)?;
        let mut b=[0u8;1];stream.read_exact(&mut b).map_err(io_error)?;
        match b[0]{b'\n'=>break,v if bytes.len()<8192=>bytes.push(v),_=>return Err(err("The QEMU control response was too large."))}
    }
    serde_json::from_slice(&bytes).map_err(|_|err("The QEMU control response was invalid."))
}
fn send(stream:&mut TcpStream,value:&Value)->Result<()>{
    serde_json::to_writer(&mut *stream,value).map_err(io_error)?;stream.write_all(b"\n").map_err(io_error)
}
fn field<'a>(v:&'a Value,k:&str)->Result<&'a str>{
    v[k].as_str().filter(|s|!s.is_empty() && s.len()<=256).ok_or_else(||err("Invalid QEMU control message."))
}

pub(crate) fn request(key:&str,run:&Run,op:&str)->Result<Value> {
    request_with_stream(key,run,op).map(|(value,_)|value)
}

pub(crate) fn request_with_stream(key:&str,run:&Run,op:&str)->Result<(Value,TcpStream)> {
    let addr=SocketAddrV4::new(svm_core::local_auth::SERVICE_HOST,run.port);
    let mut stream=TcpStream::connect_timeout(&addr.into(),Duration::from_secs(2)).map_err(|_|err("The recorded QEMU supervisor is unreachable. Check the machine before retrying."))?;
    stream.set_write_timeout(Some(Duration::from_secs(2))).map_err(io_error)?;
    let seconds=if op=="snapshot" {40}
        else if matches!(op,"stop"|"capture-stop") || crate::capture::start_limit(op).is_some() {35}
        else {12};
    let deadline=Instant::now()+Duration::from_secs(seconds);
    let client=unique();
    send(&mut stream,&json!({"nonce":client,"op":op}))?;
    let challenge=line(&mut stream,deadline)?;
    let server=field(&challenge,"nonce")?;
    let fields=[op,run.ticket.as_str(),&client,server];
    let proof=|domain:&str,extra:&str|mac(key.as_bytes(),&[domain,fields[0],fields[1],fields[2],fields[3],extra]);
    if !equal(field(&challenge,"proof")?,&proof("server","")){return Err(err("The QEMU endpoint did not prove its identity."));}
    send(&mut stream,&json!({"proof":proof("client","")}))?;
    let response=line(&mut stream,deadline)?;
    let result=&response["result"];
    if !equal(field(&response,"proof")?,&proof("result",&result.to_string())){return Err(err("The QEMU reply could not be verified."));}
    if let Some(e)=result["error"].as_str(){return Err(err(e));}
    Ok((result.clone(),stream))
}

pub(crate) fn serve(mut stream:TcpStream,key:&str,run:&Run,act:impl FnOnce(&str)->Result<Value>)->Result<Option<TcpStream>>{
    stream.set_nonblocking(false).map_err(io_error)?;
    stream.set_write_timeout(Some(Duration::from_secs(2))).map_err(io_error)?;
    let deadline=Instant::now()+Duration::from_secs(2);
    let hello=line(&mut stream,deadline)?;
    let op=field(&hello,"op")?;
    if !matches!(op,"state"|"stop"|"probe"|"snapshot"|"console"|"capture-status"|"capture-stop")
        && crate::capture::start_limit(op).is_none()
    {
        return Err(err("Unknown QEMU operation."));
    }
    let client=field(&hello,"nonce")?;let server=unique();
    let proof=|domain:&str,extra:&str|mac(key.as_bytes(),&[domain,op,&run.ticket,client,&server,extra]);
    send(&mut stream,&json!({"nonce":server,"proof":proof("server","")}))?;
    let response=line(&mut stream,deadline)?;
    if !equal(field(&response,"proof")?,&proof("client","")){return Err(err("QEMU control authentication failed."));}
    let result=act(op).unwrap_or_else(|e|json!({"error":e.to_string()}));
    let takeover = op == "console" && result["ready"] == true;
    send(&mut stream,&json!({"proof":proof("result",&result.to_string()),"result":result}))?;
    Ok(takeover.then_some(stream))
}
