//! Report what a PKCS#11 module exposes and whether identity detection would
//! succeed, using the same rules as `Pkcs11ClientIdentity::from_uri`.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use rustls_pkcs11_identity::inspect::{Inspection, TokenReport};
use rustls_pkcs11_identity::{Pkcs11ClientIdentity, Pkcs11Uri};

const USAGE: &str = "\
Usage: rustls-pkcs11-inspect [MODULE_PATH | PKCS11_URI]

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

With no argument (or a URI without `module-path`), the p11-kit proxy module
is inspected.

Exit status is 0 when exactly one identity would be selected, 1 otherwise.
";

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| argument == "-h" || argument == "--help")
    {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if arguments.len() > 1 {
        eprintln!("rustls-pkcs11-inspect: too many arguments\n\n{USAGE}");
        return ExitCode::FAILURE;
    }

    let argument = arguments.into_iter().next();
    let uri = match argument.as_deref() {
        Some(argument) if argument.starts_with("pkcs11:") => match Pkcs11Uri::parse(argument) {
            Ok(uri) => uri,
            Err(error) => {
                eprintln!("rustls-pkcs11-inspect: {error}");
                return ExitCode::FAILURE;
            }
        },
        _ => Pkcs11Uri::parse("pkcs11:").expect("empty URI parses"),
    };
    let module = match (&argument, uri.module_path()) {
        (_, Some(path)) => path.to_path_buf(),
        (Some(argument), None) if !argument.starts_with("pkcs11:") => PathBuf::from(argument),
        _ => PathBuf::from(Pkcs11ClientIdentity::P11_KIT_PROXY),
    };

    let inspection = match Inspection::load(&module) {
        Ok(inspection) => inspection,
        Err(error) => {
            eprintln!(
                "rustls-pkcs11-inspect: failed to inspect `{}`: {error}",
                module.display()
            );
            return ExitCode::FAILURE;
        }
    };

    println!("Module: {}", module.display());
    if inspection.tokens.is_empty() {
        println!("No initialized tokens.");
    }
    for token in &inspection.tokens {
        print_token(token);
    }

    println!();
    let identities = inspection.identities(&uri);
    let scope = if uri.has_filters() {
        "matching the URI"
    } else {
        "across all tokens"
    };
    match identities.as_slice() {
        [identity] => {
            println!(
                "OK: exactly one usable identity {scope}: token `{}`, CKA_ID {}.",
                identity.token.label,
                hex(identity.id)
            );
            ExitCode::SUCCESS
        }
        [] => {
            println!("NOT USABLE: no certificate/RSA signing key pair found {scope}.");
            print_hints(&inspection);
            ExitCode::FAILURE
        }
        many => {
            println!("AMBIGUOUS: {} usable identities {scope}:", many.len());
            for identity in many {
                println!(
                    "  token `{}`, CKA_ID {}",
                    identity.token.label,
                    hex(identity.id)
                );
            }
            println!(
                "Add an `id=`, `token=`, or `object=` attribute to the `pkcs11:` URI to choose one."
            );
            ExitCode::FAILURE
        }
    }
}

fn print_token(token: &TokenReport) {
    println!();
    println!("Token `{}` (slot {})", token.label, token.slot);
    if token.supported_schemes.is_empty() {
        println!("  Signing: no supported RSA signature mechanisms");
    } else {
        println!("  Signing: {}", schemes(&token.supported_schemes));
    }
    println!("  Certificates: {}", token.certificates.len());
    for certificate in &token.certificates {
        let status = match certificate.problem {
            Some(problem) => format!("  {problem}"),
            None => String::new(),
        };
        println!(
            "    CKA_ID {:<12} label `{}`{status}",
            hex(&certificate.id),
            certificate.label
        );
    }
    println!("  Private keys: {}", token.private_keys.len());
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
        println!(
            "    CKA_ID {:<12} label `{}`  {status}",
            hex(&key.id),
            key.label
        );
    }
}

fn print_hints(inspection: &Inspection) {
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
        println!(
            "No objects are visible without login; the provider may require a PIN, which this client does not present."
        );
    } else if keys == 0 {
        println!(
            "Certificates are visible but no private keys are; the keys may be hidden until login."
        );
    } else if certificates == 0 {
        println!("Private keys are visible but no certificates are stored on the token.");
    } else {
        println!(
            "Check that a certificate and an RSA signing key share the same non-empty CKA_ID."
        );
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
