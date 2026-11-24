#![forbid(unsafe_code)]
#![deny(warnings)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = Vec::new();
    for argument in std::env::args_os().skip(1) {
        match argument.into_string() {
            Ok(value) => args.push(value),
            Err(_) => { eprintln!("The command contains text that cannot be represented as Unicode."); return ExitCode::from(1); }
        }
    }
    let output = svm::run(&args, svm::client::Client::from_environment);
    if output.code == 0 { println!("{}", output.text); }
    else { eprintln!("{}", output.text); }
    ExitCode::from(output.code)
}
