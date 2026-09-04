mod common;

use common::{KeySpec, TokenSpec, Usage};
use rustls_pkcs11_identity::{Pkcs11ClientIdentity, Pkcs11IdentityError};

/// A key without a certificate and a CA certificate without a key do not
/// form an identity.
#[test]
fn no_identity_is_reported() {
    let Some(fixture) = common::provision(
        "none",
        &[TokenSpec {
            label: "partial",
            keys: vec![KeySpec {
                id: 1,
                with_certificate: false,
                usage: Usage::ClientAuth,
            }],
            store_root: true,
        }],
    ) else {
        return;
    };
    let error = Pkcs11ClientIdentity::load(&fixture.module, None).unwrap_err();
    assert!(
        matches!(error, Pkcs11IdentityError::NoUsableSigningIdentity),
        "{error}"
    );
}
