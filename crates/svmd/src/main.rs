#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{sync::{atomic::{AtomicBool, Ordering}, Arc}, thread};
use svm_hyperv::{HyperV, WindowsPowerShell};
use svmd::{configured_port, data_home, networks::HyperSwitches, ApiError, Service};

fn serve() -> Result<(), ApiError> {
    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    // enable_all, not enable_io: with only the "rt" and "signal" features, enable_io does not exist on Windows
    // (it needs the "net" feature). enable_all turns on exactly the drivers the enabled features provide.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(|_| ApiError::new(500, "console_signal", "The service could not initialize its console signal handler."))?;
    thread::Builder::new().name("console-signal".into()).spawn(move || {
        if runtime.block_on(tokio::signal::ctrl_c()).is_err() { eprintln!("The console signal handler failed."); }
        signal.store(true, Ordering::Release);
    }).map_err(ApiError::storage)?;
    let machine_engine = HyperV::new(WindowsPowerShell::default(), []);
    Service::open(&data_home()?, configured_port()?, Box::new(machine_engine), Box::new(HyperSwitches::new()))?.run(stop)
}

fn main() -> std::process::ExitCode {
    let mut args=std::env::args_os().skip(1);
    if let Some(command)=args.next() {
        if command=="--backup-console" {
            return if args.next().is_none() && svmd::machines::backup_console().is_ok() { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::FAILURE };
        }
        if command=="--qemu-agent-relay" {
            return if args.next().is_none() && svm_qemu::relay_call().is_ok() { std::process::ExitCode::SUCCESS }
                else { std::process::ExitCode::FAILURE };
        }
        if command=="--qemu-supervisor" {
            if let Some(bundle)=args.next().filter(|_|args.next().is_none()) {
                return match svm_qemu::supervise(std::path::Path::new(&bundle)) {
                    Ok(())=>std::process::ExitCode::SUCCESS,
                    Err(e)=>{ eprintln!("{e}"); std::process::ExitCode::FAILURE }
                };
            }
            return std::process::ExitCode::FAILURE;
        }
    }
    match serve() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => { eprintln!("{error}"); std::process::ExitCode::FAILURE }
    }
}
