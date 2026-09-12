//! The `rustls-pkcs11-inspect` command: report what a PKCS#11 module exposes
//! and whether identity detection would succeed, using the same rules as
//! [`Pkcs11ClientIdentity::from_uri`].
//!
//! The command is shipped under more than one name (the crate's own
//! `rustls-pkcs11-inspect`, and `uv-pkcs11-inspect` in the uv-pkcs11 wheel),
//! so the binaries are thin wrappers around [`run`].

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::inspect::{Inspection, TokenReport};
use crate::{Pkcs11ClientIdentity, Pkcs11Uri};

/// The name and version the command reports about itself.
#[derive(Debug, Clone, Copy)]
pub struct Invocation<'a> {
    /// The command name, as used in the usage text.
    pub program: &'a str,
    /// The version printed by `--version`.
    pub version: &'a str,
}

/// Exit status when exactly one identity would be selected.
pub const EXIT_OK: u8 = 0;
/// Exit status when no identity or more than one would be selected, or the
/// module could not be inspected.
pub const EXIT_NOT_USABLE: u8 = 1;
/// Exit status for invalid command-line arguments.
pub const EXIT_USAGE: u8 = 2;

fn usage(program: &str) -> String {
    format!(
        "\
Usage: {program} [MODULE_PATH | PKCS11_URI]

Lists the tokens, certificates, and private keys a PKCS#11 module exposes
without login, and reports whether exactly one usable identity is present.

Arguments:
  MODULE_PATH    Path of the PKCS#11 module to inspect (unlike the URI's
                 `module-path`, a direct argument may be a relative path)
  PKCS11_URI     A `pkcs11:` URI (RFC 7512 subset), as passed to uv in
                 SSL_CLIENT_CERT: the `token`, `serial`, `id`, `object`, and
                 `type=cert` attributes restrict the match, and the
                 `module-path` query attribute names the module as an
                 absolute path

Options:
  -h, --help     Print this help and exit
  -V, --version  Print the version and exit

With no argument (or a URI without `module-path`), the p11-kit proxy module
is inspected.

Exit status is 0 when exactly one identity would be selected, 1 otherwise.
"
    )
}

/// Run the command with `arguments` (excluding the program name), writing
/// the report to `output`, and return the exit status.
///
/// Usage errors are reported on `output` too, followed by the usage text,
/// with status [`EXIT_USAGE`].
pub fn run(
    invocation: &Invocation<'_>,
    arguments: &[OsString],
    output: &mut dyn Write,
) -> io::Result<u8> {
    let program = invocation.program;
    let mut positional = None;
    for argument in arguments {
        match argument.to_str() {
            Some("-h" | "--help") => {
                write!(output, "{}", usage(program))?;
                return Ok(EXIT_OK);
            }
            Some("-V" | "--version") => {
                writeln!(output, "{program} {}", invocation.version)?;
                return Ok(EXIT_OK);
            }
            Some(option) if option.starts_with('-') && option != "-" => {
                write!(
                    output,
                    "{program}: unrecognized option `{option}`\n\n{}",
                    usage(program)
                )?;
                return Ok(EXIT_USAGE);
            }
            _ => {
                if positional.replace(argument).is_some() {
                    write!(
                        output,
                        "{program}: too many arguments\n\n{}",
                        usage(program)
                    )?;
                    return Ok(EXIT_USAGE);
                }
            }
        }
    }

    let argument = positional.map(|argument| argument.to_string_lossy().into_owned());
    let uri = match argument.as_deref() {
        Some(argument) if argument.starts_with("pkcs11:") => match Pkcs11Uri::parse(argument) {
            Ok(uri) => uri,
            Err(error) => {
                writeln!(output, "{program}: {error}")?;
                return Ok(EXIT_USAGE);
            }
        },
        _ => match Pkcs11Uri::parse("pkcs11:") {
            Ok(uri) => uri,
            Err(error) => {
                writeln!(output, "{program}: {error}")?;
                return Ok(EXIT_USAGE);
            }
        },
    };
    let module = match (&argument, uri.module_path()) {
        (_, Some(path)) => path.to_path_buf(),
        (Some(argument), None) if !argument.starts_with("pkcs11:") => PathBuf::from(argument),
        _ => PathBuf::from(Pkcs11ClientIdentity::P11_KIT_PROXY),
    };

    let inspection = match Inspection::load(&module) {
        Ok(inspection) => inspection,
        Err(error) => {
            writeln!(
                output,
                "{program}: failed to inspect `{}`: {error}",
                module.display()
            )?;
            return Ok(EXIT_NOT_USABLE);
        }
    };

    writeln!(output, "Module: {}", module.display())?;
    if inspection.tokens.is_empty() {
        writeln!(output, "No initialized tokens.")?;
    }
    for token in &inspection.tokens {
        write_token(output, token)?;
    }

    writeln!(output)?;
    let identities = inspection.identities(&uri);
    let scope = if uri.has_filters() {
        "matching the URI"
    } else {
        "across all tokens"
    };
    match identities.as_slice() {
        [identity] => {
            writeln!(
                output,
                "OK: exactly one usable identity {scope}: token `{}`, CKA_ID {}.",
                identity.token.label,
                hex(identity.id)
            )?;
            Ok(EXIT_OK)
        }
        [] => {
            writeln!(
                output,
                "NOT USABLE: no certificate/RSA signing key pair found {scope}."
            )?;
            write_hints(output, &inspection)?;
            Ok(EXIT_NOT_USABLE)
        }
        many => {
            writeln!(
                output,
                "AMBIGUOUS: {} usable identities {scope}:",
                many.len()
            )?;
            for identity in many {
                writeln!(
                    output,
                    "  token `{}`, CKA_ID {}",
                    identity.token.label,
                    hex(identity.id)
                )?;
            }
            writeln!(
                output,
                "Add an `id=`, `token=`, or `object=` attribute to the `pkcs11:` URI to choose one."
            )?;
            Ok(EXIT_NOT_USABLE)
        }
    }
}

fn write_token(output: &mut dyn Write, token: &TokenReport) -> io::Result<()> {
    writeln!(output)?;
    writeln!(output, "Token `{}` (slot {})", token.label, token.slot)?;
    if token.supported_schemes.is_empty() {
        writeln!(output, "  Signing: no supported RSA signature mechanisms")?;
    } else {
        writeln!(output, "  Signing: {}", schemes(&token.supported_schemes))?;
    }
    writeln!(output, "  Certificates: {}", token.certificates.len())?;
    for certificate in &token.certificates {
        let status = match certificate.problem {
            Some(problem) => format!("  {problem}"),
            None => String::new(),
        };
        writeln!(
            output,
            "    CKA_ID {:<12} label `{}`{status}",
            hex(&certificate.id),
            certificate.label
        )?;
    }
    writeln!(output, "  Private keys: {}", token.private_keys.len())?;
    for key in &token.private_keys {
        let status = if !key.rsa {
            "not RSA".to_string()
        } else if !key.sign {
            "CKA_SIGN=false".to_string()
        } else if key.schemes.is_empty() {
            "no usable mechanism".to_string()
        } else {
            schemes(&key.schemes)
        };
        writeln!(
            output,
            "    CKA_ID {:<12} label `{}`  {status}",
            hex(&key.id),
            key.label
        )?;
    }
    Ok(())
}

fn write_hints(output: &mut dyn Write, inspection: &Inspection) -> io::Result<()> {
    let keys = inspection
        .tokens
        .iter()
        .flat_map(|token| &token.private_keys)
        .count();
    let certificates = inspection
        .tokens
        .iter()
        .flat_map(|token| &token.certificates)
        .count();
    if keys == 0 && certificates == 0 {
        writeln!(
            output,
            "No objects are visible without login; the provider may require a PIN, which this client does not present."
        )
    } else if keys == 0 {
        writeln!(
            output,
            "Certificates are visible but no private keys are; the keys may be hidden until login."
        )
    } else if certificates == 0 {
        writeln!(
            output,
            "Private keys are visible but no certificates are stored on the token."
        )
    } else {
        writeln!(
            output,
            "Check that a certificate and an RSA signing key share the same non-empty CKA_ID."
        )
    }
}

fn schemes(schemes: &[rustls::SignatureScheme]) -> String {
    schemes
        .iter()
        .map(|scheme| format!("{scheme:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(empty)".to_string();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVOCATION: Invocation<'static> = Invocation {
        program: "inspect-test",
        version: "1.2.3",
    };

    fn run_with(arguments: &[&str]) -> (u8, String) {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        let mut output = Vec::new();
        let status = run(&INVOCATION, &arguments, &mut output).unwrap();
        (status, String::from_utf8(output).unwrap())
    }

    #[test]
    fn prints_help_and_version_with_the_program_name() {
        let (status, output) = run_with(&["--help"]);
        assert_eq!(status, EXIT_OK);
        assert!(
            output.starts_with("Usage: inspect-test [MODULE_PATH | PKCS11_URI]"),
            "{output}"
        );

        let (status, output) = run_with(&["--version"]);
        assert_eq!(status, EXIT_OK);
        assert_eq!(output, "inspect-test 1.2.3\n");
    }

    #[test]
    fn rejects_bad_arguments() {
        let (status, output) = run_with(&["a", "b"]);
        assert_eq!(status, EXIT_USAGE);
        assert!(
            output.starts_with("inspect-test: too many arguments"),
            "{output}"
        );

        let (status, output) = run_with(&["--bogus"]);
        assert_eq!(status, EXIT_USAGE);
        assert!(
            output.starts_with("inspect-test: unrecognized option `--bogus`"),
            "{output}"
        );

        let (status, output) = run_with(&["pkcs11:id=%zz"]);
        assert_eq!(status, EXIT_USAGE);
        assert!(
            output.starts_with("inspect-test: invalid PKCS#11 URI"),
            "{output}"
        );
    }

    #[test]
    fn reports_a_module_that_cannot_be_loaded() {
        let (status, output) = run_with(&["/nonexistent/pkcs11-module.so"]);
        assert_eq!(status, EXIT_NOT_USABLE);
        assert!(
            output.starts_with("inspect-test: failed to inspect `/nonexistent/pkcs11-module.so`: "),
            "{output}"
        );
    }
}
