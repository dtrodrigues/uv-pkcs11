mod common;

use common::{KeySpec, TokenSpec};
use rustls_pkcs11_identity::{Pkcs11ClientIdentity, Pkcs11IdentityError};

/// `pkcs11:` URI attributes select identities the same way the loader does.
#[test]
fn uri_attributes_select_identities() {
    let Some(fixture) = common::provision(
        "uri",
        &[
            TokenSpec {
                label: "first",
                keys: vec![KeySpec {
                    id: 1,
                    with_certificate: true,
                }],
                store_root: false,
            },
            TokenSpec {
                label: "second",
                keys: vec![KeySpec {
                    id: 2,
                    with_certificate: true,
                }],
                store_root: false,
            },
        ],
    ) else {
        return;
    };
    let module = fixture.module.to_str().unwrap();

    // With no filter attributes, two identities are ambiguous.
    let error =
        Pkcs11ClientIdentity::from_uri(&format!("pkcs11:?module-path={module}")).unwrap_err();
    assert!(
        matches!(
            error,
            Pkcs11IdentityError::MultipleUsableSigningIdentities(2)
        ),
        "{error}"
    );

    // A token label narrows to one identity.
    let identity =
        Pkcs11ClientIdentity::from_uri(&format!("pkcs11:token=first?module-path={module}"))
            .unwrap();
    assert_eq!(common::handshake(&fixture, &identity), 1);

    // So does a CKA_ID, percent-encoded.
    let identity =
        Pkcs11ClientIdentity::from_uri(&format!("pkcs11:id=%02?module-path={module}")).unwrap();
    assert_eq!(common::handshake(&fixture, &identity), 1);

    // The certificate label (`object`) applies per token.
    let identity = Pkcs11ClientIdentity::from_uri(&format!(
        "pkcs11:token=second;object=cert-0?module-path={module}"
    ))
    .unwrap();
    assert_eq!(common::handshake(&fixture, &identity), 1);

    // Filters combine conjunctively: a token/ID mismatch selects nothing.
    let error =
        Pkcs11ClientIdentity::from_uri(&format!("pkcs11:token=first;id=%02?module-path={module}"))
            .unwrap_err();
    assert!(
        matches!(error, Pkcs11IdentityError::NoUsableSigningIdentity),
        "{error}"
    );

    // An unknown token label selects nothing.
    let error =
        Pkcs11ClientIdentity::from_uri(&format!("pkcs11:token=missing?module-path={module}"))
            .unwrap_err();
    assert!(
        matches!(error, Pkcs11IdentityError::NoUsableSigningIdentity),
        "{error}"
    );
}
