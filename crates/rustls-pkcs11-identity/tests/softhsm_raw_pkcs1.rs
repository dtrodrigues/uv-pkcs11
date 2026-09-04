mod common;

use common::{KeySpec, TokenSpec, Usage};
use rustls_pkcs11_identity::Pkcs11ClientIdentity;

/// A token whose only signing mechanism is the raw `CKM_RSA_PKCS` can
/// authenticate over TLS 1.2 with a `DigestInfo` computed in process, but not
/// over TLS 1.3, which requires RSA-PSS for client certificates.
#[test]
fn pkcs1_only_token_needs_tls12() {
    let Some(fixture) = common::provision_with_mechanisms(
        "raw-pkcs1",
        "-CKM_SHA256_RSA_PKCS,CKM_SHA384_RSA_PKCS,CKM_SHA512_RSA_PKCS,CKM_SHA256_RSA_PKCS_PSS,CKM_SHA384_RSA_PKCS_PSS,CKM_SHA512_RSA_PKCS_PSS,CKM_RSA_PKCS_PSS",
        &[TokenSpec {
            label: "pkcs1",
            keys: vec![KeySpec {
                id: 1,
                with_certificate: true,
                usage: Usage::ClientAuth,
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
}
