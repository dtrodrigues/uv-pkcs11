//! Provision a SoftHSM token with a public-session-visible RSA identity, for
//! smoke tests: import an RSA private key (PKCS#1 or PKCS#8 DER) and X.509
//! certificate as public objects (`CKA_PRIVATE=false`) sharing one `CKA_ID`,
//! so the PIN-less client can use them.
//!
//! Usage: provision-softhsm <module> <token-label> <pin> <key.der> <cert.der> <id-hex>

// A test tool reading fixture files; the workspace's fs-err mandate is for
// production code.
#![allow(clippy::disallowed_methods)]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

/// Split one DER TLV off the front of `data`: `(tlv, rest)`.
fn der_split(data: &[u8]) -> (&[u8], &[u8]) {
    let (header, length) = if data[1] < 0x80 {
        (2, usize::from(data[1]))
    } else {
        let count = usize::from(data[1] & 0x7F);
        let length = data[2..2 + count]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (2 + count, length)
    };
    data.split_at(header + length)
}

fn der_contents(tlv: &[u8]) -> &[u8] {
    let header = if tlv[1] < 0x80 {
        2
    } else {
        2 + usize::from(tlv[1] & 0x7F)
    };
    &tlv[header..]
}

/// The nine INTEGERs of a PKCS#1 `RSAPrivateKey`, without leading zero pads.
///
/// A PKCS#8 `PrivateKeyInfo` envelope is unwrapped first: OpenSSL 3 writes
/// PKCS#8 by default where earlier versions wrote PKCS#1.
fn rsa_private_key_integers(der: &[u8]) -> Vec<Vec<u8>> {
    let (sequence, _) = der_split(der);
    let mut body = der_contents(sequence);
    let (_version, rest) = der_split(body);
    let (second, after_second) = der_split(rest);
    if second[0] == 0x30 {
        // version INTEGER, then AlgorithmIdentifier SEQUENCE: this is
        // PKCS#8; the RSAPrivateKey is inside the privateKey OCTET STRING.
        let (octet_string, _) = der_split(after_second);
        assert_eq!(
            octet_string[0], 0x04,
            "expected OCTET STRING in PrivateKeyInfo"
        );
        return rsa_private_key_integers(der_contents(octet_string));
    }
    let mut integers = Vec::new();
    while !body.is_empty() {
        let (tlv, rest) = der_split(body);
        assert_eq!(tlv[0], 0x02, "expected INTEGER in RSAPrivateKey");
        let mut value = der_contents(tlv);
        while value.len() > 1 && value[0] == 0 {
            value = &value[1..];
        }
        integers.push(value.to_vec());
        body = rest;
    }
    assert_eq!(integers.len(), 9, "expected 9 RSAPrivateKey INTEGERs");
    integers
}

/// The DER `subject` Name of a certificate (needed for `CKA_SUBJECT`).
fn certificate_subject(certificate: &[u8]) -> Vec<u8> {
    let (cert, _) = der_split(certificate);
    let (tbs, _) = der_split(der_contents(cert));
    let mut body = der_contents(tbs);
    if body[0] == 0xA0 {
        body = der_split(body).1; // version
    }
    for _ in 0..4 {
        body = der_split(body).1; // serial, signature algorithm, issuer, validity
    }
    der_split(body).0.to_vec()
}

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("id must be hex"))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, module, token_label, pin, key_path, cert_path, id_hex] = args.as_slice() else {
        eprintln!(
            "usage: provision-softhsm <module> <token-label> <pin> <key.pkcs1.der> <cert.der> <id-hex>"
        );
        std::process::exit(2);
    };
    let id = unhex(id_hex);
    let key_der = std::fs::read(key_path).unwrap();
    let cert_der = std::fs::read(cert_path).unwrap();
    let integers = rsa_private_key_integers(&key_der);
    let [_version, n, e, d, p, q, dmp1, dmq1, iqmp] = integers.as_slice() else {
        unreachable!()
    };
    let subject = certificate_subject(&cert_der);

    let pkcs11 = Pkcs11::new(module).unwrap();
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    let slot = pkcs11
        .get_slots_with_initialized_token()
        .unwrap()
        .into_iter()
        .find(|slot| {
            pkcs11.get_token_info(*slot).unwrap().label().trim_end() == token_label.as_str()
        })
        .expect("token not found");
    let session = pkcs11.open_rw_session(slot).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new(pin.clone().into())))
        .unwrap();
    session
        .create_object(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Id(id.clone()),
            Attribute::Label(b"smoke-key".to_vec()),
            Attribute::Modulus(n.clone()),
            Attribute::PublicExponent(e.clone()),
            Attribute::PrivateExponent(d.clone()),
            Attribute::Prime1(p.clone()),
            Attribute::Prime2(q.clone()),
            Attribute::Exponent1(dmp1.clone()),
            Attribute::Exponent2(dmq1.clone()),
            Attribute::Coefficient(iqmp.clone()),
        ])
        .unwrap();
    session
        .create_object(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(id.clone()),
            Attribute::Label(b"smoke-cert".to_vec()),
            Attribute::Subject(subject),
            Attribute::Value(cert_der),
        ])
        .unwrap();
    session.logout().unwrap();
    println!("provisioned token `{token_label}` with a public RSA identity (CKA_ID {id_hex})");
}
