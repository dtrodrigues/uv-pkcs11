mod common;

use common::{KeySpec, TokenSpec};
use rustls_pkcs11_identity::Pkcs11ClientIdentity;

/// A token offering only the raw `CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS`
/// mechanisms, as providers without hash-and-sign mechanisms do, still
/// completes client-authenticated handshakes: the transcript is hashed in
/// process and the token pads and signs the digest.
#[test]
fn raw_mechanisms_complete_handshake() {
    let Some(fixture) = common::provision_with_mechanisms(
        "raw",
        "-CKM_SHA256_RSA_PKCS,CKM_SHA384_RSA_PKCS,CKM_SHA512_RSA_PKCS,CKM_SHA256_RSA_PKCS_PSS,CKM_SHA384_RSA_PKCS_PSS,CKM_SHA512_RSA_PKCS_PSS",
        &[TokenSpec {
            label: "raw",
            keys: vec![KeySpec {
                id: 1,
                with_certificate: true,
            }],
            store_root: false,
        }],
    ) else {
        return;
    };

    let identity = Pkcs11ClientIdentity::from_uri(&format!(
        "pkcs11:?module-path={}",
        fixture.module.display()
    ))
    .unwrap();
    assert!(identity.resolver().has_certs());
    // TLS 1.3 requires RSA-PSS for client authentication.
    assert_eq!(common::handshake(&fixture, &identity), 1);
    assert_eq!(
        common::try_handshake(&fixture, &identity, &[&rustls::version::TLS12]),
        Ok(1)
    );

    // The inspect command reports the schemes the raw mechanisms produce.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rustls-pkcs11-inspect"))
        .arg(&fixture.module)
        .output()
        .unwrap();
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success()
            && report.contains(
                "RSA_PSS_SHA512, RSA_PSS_SHA384, RSA_PSS_SHA256, RSA_PKCS1_SHA512, RSA_PKCS1_SHA384, RSA_PKCS1_SHA256"
            ),
        "{report}"
    );
}
