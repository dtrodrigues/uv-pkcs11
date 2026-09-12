//! Report what a PKCS#11 module exposes and whether uv would select exactly
//! one client identity from an `SSL_CLIENT_CERT` `pkcs11:` URI.
//!
//! This is the `rustls-pkcs11-inspect` command of `rustls-pkcs11-identity`,
//! shipped in the uv-pkcs11 wheel next to `uv` and `uvx`.

use std::env;
use std::io;
use std::process::ExitCode;

use rustls_pkcs11_identity::cli::{self, Invocation};

#[expect(clippy::print_stderr)]
fn main() -> ExitCode {
    let invocation = Invocation {
        program: "uv-pkcs11-inspect",
        version: uv_version::version(),
    };
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let mut stdout = io::stdout().lock();
    match cli::run(&invocation, &arguments, &mut stdout) {
        Ok(status) => ExitCode::from(status),
        Err(error) => {
            eprintln!("uv-pkcs11-inspect: {error}");
            ExitCode::from(cli::EXIT_NOT_USABLE)
        }
    }
}
