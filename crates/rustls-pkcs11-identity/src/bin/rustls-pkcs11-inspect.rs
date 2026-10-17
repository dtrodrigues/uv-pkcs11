//! Report what a PKCS#11 module exposes and whether identity detection would
//! succeed, using the same rules as `Pkcs11ClientIdentity::from_uri`.

use std::env;
use std::io;
use std::process::ExitCode;

use rustls_pkcs11_identity::cli::{self, Invocation};

fn main() -> ExitCode {
    let invocation = Invocation {
        program: "rustls-pkcs11-inspect",
        version: env!("CARGO_PKG_VERSION"),
    };
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let mut stdout = io::stdout().lock();
    match cli::run(&invocation, &arguments, &mut stdout) {
        Ok(status) => ExitCode::from(status),
        Err(error) => {
            eprintln!("rustls-pkcs11-inspect: {error}");
            ExitCode::from(cli::EXIT_NOT_USABLE)
        }
    }
}
