mod common;

use common::{KeySpec, TokenSpec, Usage};
use cryptoki::mechanism::MechanismType;
use rustls_pkcs11_identity::Pkcs11ClientIdentity;

/// A key whose `CKA_ALLOWED_MECHANISMS` permits only `CKM_SHA256_RSA_PKCS`
/// advertises just `RSA_PKCS1_SHA256`, even though the token offers every RSA
/// mechanism: the key restriction narrows the token's list. That leaves TLS
/// 1.2 usable and TLS 1.3, which requires RSA-PSS for client certificates,
/// without a scheme.
#[test]
fn allowed_mechanisms_restrict_a_key() {
    let Some(fixture) = common::provision(
        "allowed",
        &[TokenSpec {
            label: "allowed",
            keys: vec![KeySpec {
                id: 1,
                with_certificate: true,
                usage: Usage::ClientAuth,
                allowed_mechanisms: Some(vec![MechanismType::SHA256_RSA_PKCS]),
            }],
            store_root: false,
        }],
    ) else {
        return;
    };

    let identity = Pkcs11ClientIdentity::load(&fixture.module, None).unwrap();
    assert_eq!(
        common::try_handshake(&fixture, &identity, &[&rustls::version::TLS12]),
        Ok(1)
    );
    // Without a usable scheme the client sends no certificate and the server
    // rejects the connection.
    let error = common::try_handshake(&fixture, &identity, &[&rustls::version::TLS13]).unwrap_err();
    assert!(error.contains("CertificateRequired"), "{error}");

    // The inspect command reports the token's full mechanism list but only the
    // scheme the key itself allows.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rustls-pkcs11-inspect"))
        .arg(&fixture.module)
        .output()
        .unwrap();
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success()
            && report.contains(
                "  Signing: RSA_PSS_SHA512, RSA_PSS_SHA384, RSA_PSS_SHA256, RSA_PKCS1_SHA512, RSA_PKCS1_SHA384, RSA_PKCS1_SHA256"
            )
            && report.contains("CKA_ID 01           label ``  RSA_PKCS1_SHA256"),
        "{report}"
    );
}
