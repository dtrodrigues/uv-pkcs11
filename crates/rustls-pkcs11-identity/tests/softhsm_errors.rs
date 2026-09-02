mod common;

use common::{KeySpec, TokenSpec};
use rustls_pkcs11_identity::{Pkcs11ClientIdentity, Pkcs11IdentityError};

/// Two identities across two tokens is ambiguous.
#[test]
fn ambiguity_is_reported() {
    let Some(fixture) = common::provision(
        "errors",
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
    let error = Pkcs11ClientIdentity::load(&fixture.module, None).unwrap_err();
    assert!(
        matches!(
            error,
            Pkcs11IdentityError::MultipleUsableSigningIdentities(2)
        ),
        "{error}"
    );

    // A CKA_ID selects one of them, and an unknown ID selects nothing.
    let identity = Pkcs11ClientIdentity::load(&fixture.module, Some(&[2])).unwrap();
    assert_eq!(common::handshake(&fixture, &identity), 1);
    let error = Pkcs11ClientIdentity::load(&fixture.module, Some(&[9])).unwrap_err();
    assert!(
        matches!(error, Pkcs11IdentityError::NoUsableSigningIdentity),
        "{error}"
    );

    // The same selection through a URI, and a malformed id is rejected.
    let identity = Pkcs11ClientIdentity::from_uri(&format!(
        "pkcs11:id=%01?module-path={}",
        fixture.module.display()
    ))
    .unwrap();
    assert_eq!(common::handshake(&fixture, &identity), 1);
    assert!(matches!(
        Pkcs11ClientIdentity::from_uri("pkcs11:id=%zz"),
        Err(Pkcs11IdentityError::InvalidUri(_))
    ));

    // The inspect command applies the same rules.
    let inspect = |id: Option<&str>| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_rustls-pkcs11-inspect"));
        match id {
            Some(id) => command.arg(format!(
                "pkcs11:id={id}?module-path={}",
                fixture.module.display()
            )),
            None => command.arg(&fixture.module),
        };
        let output = command.output().unwrap();
        (
            output.status.success(),
            String::from_utf8(output.stdout).unwrap(),
        )
    };
    let (ok, report) = inspect(None);
    assert!(
        !ok && report.contains("AMBIGUOUS: 2 usable identities"),
        "{report}"
    );
    let (ok, report) = inspect(Some("%02"));
    assert!(
        ok && report.contains("OK: exactly one usable identity"),
        "{report}"
    );
    let (ok, report) = inspect(Some("%09"));
    assert!(!ok && report.contains("NOT USABLE"), "{report}");
}
