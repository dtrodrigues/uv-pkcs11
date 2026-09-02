mod common;

use common::{KeySpec, TokenSpec};
use rustls_pkcs11_identity::Pkcs11ClientIdentity;

/// An RSA identity is detected across tokens (one of which is empty), loaded
/// from a `pkcs11:` URI, and completes a client-authenticated handshake.
#[test]
fn rsa_identity_completes_handshake() {
    let Some(fixture) = common::provision(
        "rsa",
        &[
            TokenSpec {
                label: "empty",
                keys: vec![],
                store_root: false,
            },
            TokenSpec {
                label: "identity",
                keys: vec![KeySpec {
                    id: 1,
                    with_certificate: true,
                }],
                store_root: true,
            },
        ],
    ) else {
        return;
    };

    let identity = Pkcs11ClientIdentity::from_uri(&format!(
        "pkcs11:?module-path={}",
        fixture.module.display()
    ))
    .unwrap();
    assert!(identity.resolver().has_certs());
    assert_eq!(common::handshake(&fixture, &identity), 1);
    // Loading again reuses the initialised module.
    let again = Pkcs11ClientIdentity::load(&fixture.module, None).unwrap();
    assert_eq!(common::handshake(&fixture, &again), 1);
}
