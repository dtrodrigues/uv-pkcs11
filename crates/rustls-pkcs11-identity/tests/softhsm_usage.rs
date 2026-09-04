mod common;

use common::{KeySpec, TokenSpec, Usage};
use rustls_pkcs11_identity::{ClientCertificateProblem, Pkcs11ClientIdentity, Pkcs11IdentityError};

/// Only certificates that can sign as a TLS client are identities: a key
/// encipherment certificate (RSA key exchange) and a server-only certificate
/// are passed over, so the client certificate is found unambiguously and
/// selecting a rejected one says why.
#[test]
fn certificates_must_allow_client_signing() {
    let Some(fixture) = common::provision(
        "usage",
        &[TokenSpec {
            label: "usage",
            keys: vec![
                KeySpec {
                    id: 1,
                    with_certificate: true,
                    usage: Usage::KeyEncipherment,
                },
                KeySpec {
                    id: 2,
                    with_certificate: true,
                    usage: Usage::ClientAuth,
                },
                KeySpec {
                    id: 3,
                    with_certificate: true,
                    usage: Usage::ServerAuth,
                },
            ],
            store_root: false,
        }],
    ) else {
        return;
    };

    let identity = Pkcs11ClientIdentity::load(&fixture.module, None).unwrap();
    assert_eq!(common::handshake(&fixture, &identity), 1);

    let error = Pkcs11ClientIdentity::load(&fixture.module, Some(&[1])).unwrap_err();
    assert!(
        matches!(
            error,
            Pkcs11IdentityError::UnusableCertificate(ClientCertificateProblem::NoDigitalSignature)
        ),
        "{error}"
    );
    let error = Pkcs11ClientIdentity::load(&fixture.module, Some(&[3])).unwrap_err();
    assert!(
        matches!(
            error,
            Pkcs11IdentityError::UnusableCertificate(ClientCertificateProblem::NoClientAuth)
        ),
        "{error}"
    );

    // The inspect command applies the same rules and names the problems.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rustls-pkcs11-inspect"))
        .arg(&fixture.module)
        .output()
        .unwrap();
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success()
            && report.contains("OK: exactly one usable identity")
            && report.contains("keyUsage lacks digitalSignature")
            && report.contains("extendedKeyUsage lacks clientAuth"),
        "{report}"
    );
}
