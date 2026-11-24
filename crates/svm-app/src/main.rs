#![forbid(unsafe_code)]
#![deny(warnings)]
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod window;
#[cfg(windows)]
mod window_capture;
#[cfg(windows)]
mod window_native;
#[cfg(windows)]
mod window_protocol;
#[cfg(windows)]
mod window_service;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    if let Err(reason) = window::run() {
        window_native::show_error(&reason);
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("This program runs on Windows.");
    std::process::ExitCode::FAILURE
}
