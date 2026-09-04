//! Diagnostic view of what a PKCS#11 module exposes, using the same rules as
//! identity detection, for the `rustls-pkcs11-inspect` command.

use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass};
use cryptoki::session::Session;
use rustls::SignatureScheme;

use crate::{Pkcs11IdentityError, Pkcs11Uri, attribute, load_module, signing_schemes};

/// Everything relevant to identity detection that a module exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// One entry per initialized token, in slot order.
    pub tokens: Vec<TokenReport>,
}

/// A token and the objects visible on it without login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenReport {
    /// The slot identifier.
    pub slot: u64,
    /// The token label.
    pub label: String,
    /// The token serial number.
    pub serial: String,
    /// TLS signature schemes the token's mechanisms can produce.
    pub supported_schemes: Vec<SignatureScheme>,
    /// X.509 certificate objects.
    pub certificates: Vec<CertificateReport>,
    /// Private key objects.
    pub private_keys: Vec<KeyReport>,
}

/// A certificate object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateReport {
    /// `CKA_ID` (may be empty).
    pub id: Vec<u8>,
    /// `CKA_LABEL`.
    pub label: String,
}

/// A private key object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyReport {
    /// `CKA_ID` (may be empty).
    pub id: Vec<u8>,
    /// `CKA_LABEL`.
    pub label: String,
    /// Whether the key is RSA.
    pub rsa: bool,
    /// `CKA_SIGN`.
    pub sign: bool,
    /// TLS signature schemes this key can produce on this token (empty if it
    /// is not a usable RSA signing key).
    pub schemes: Vec<SignatureScheme>,
}

/// A usable certificate/key pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity<'a> {
    /// The token holding the pair.
    pub token: &'a TokenReport,
    /// The shared `CKA_ID`.
    pub id: &'a [u8],
    /// The certificate of the pair.
    pub certificate: &'a CertificateReport,
}

impl TokenReport {
    /// The usable identities on this token: certificates whose non-empty
    /// `CKA_ID` matches exactly one usable RSA signing key.
    pub fn identities(&self) -> Vec<Identity<'_>> {
        self.certificates
            .iter()
            .filter(|certificate| !certificate.id.is_empty())
            .filter(|certificate| {
                let keys = self
                    .private_keys
                    .iter()
                    .filter(|key| key.id == certificate.id && !key.schemes.is_empty())
                    .count();
                keys == 1
            })
            .map(|certificate| Identity {
                token: self,
                id: &certificate.id,
                certificate,
            })
            .collect()
    }
}

impl Inspection {
    /// Inspect the module at `path`.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, Pkcs11IdentityError> {
        let pkcs11 = load_module(path.as_ref())?;
        let mut tokens = Vec::new();
        for slot in pkcs11.get_slots_with_initialized_token()? {
            let info = pkcs11.get_token_info(slot)?;
            let mechanisms = pkcs11.get_mechanism_list(slot)?;
            let session = pkcs11.open_ro_session(slot)?;
            tokens.push(TokenReport {
                slot: slot.id(),
                label: info.label().to_string(),
                serial: info.serial_number().to_string(),
                supported_schemes: signing_schemes(&mechanisms),
                certificates: certificates(&session)?,
                private_keys: private_keys(&session, &mechanisms)?,
            });
        }
        Ok(Self { tokens })
    }

    /// All usable identities across tokens, restricted by the URI's `token`,
    /// `serial`, `id`, and `object` attributes — the same rules
    /// [`crate::Pkcs11ClientIdentity::from_uri`] applies.
    pub fn identities(&self, uri: &Pkcs11Uri) -> Vec<Identity<'_>> {
        let selector = &uri.selector;
        self.tokens
            .iter()
            .filter(|token| {
                selector
                    .token
                    .as_deref()
                    .is_none_or(|wanted| token.label.trim_end() == wanted)
                    && selector
                        .serial
                        .as_deref()
                        .is_none_or(|wanted| token.serial.trim_end() == wanted)
            })
            .flat_map(TokenReport::identities)
            .filter(|identity| {
                selector
                    .id
                    .as_deref()
                    .is_none_or(|wanted| identity.id == wanted)
            })
            .filter(|identity| {
                selector
                    .object
                    .as_deref()
                    .is_none_or(|wanted| identity.certificate.label == wanted)
            })
            .collect()
    }
}

fn certificates(session: &Session) -> Result<Vec<CertificateReport>, Pkcs11IdentityError> {
    let handles = session.find_objects(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
    ])?;
    handles
        .into_iter()
        .map(|handle| {
            Ok(CertificateReport {
                id: attribute(session, handle, AttributeType::Id, id_attribute)?
                    .unwrap_or_default(),
                label: attribute(session, handle, AttributeType::Label, label_attribute)?
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn private_keys(
    session: &Session,
    mechanisms: &[MechanismType],
) -> Result<Vec<KeyReport>, Pkcs11IdentityError> {
    let handles = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])?;
    handles
        .into_iter()
        .map(|handle| {
            let rsa = attribute(
                session,
                handle,
                AttributeType::KeyType,
                |attribute| match attribute {
                    Attribute::KeyType(key_type) => Some(key_type == KeyType::RSA),
                    _ => None,
                },
            )?
            .unwrap_or(false);
            let sign = attribute(
                session,
                handle,
                AttributeType::Sign,
                |attribute| match attribute {
                    Attribute::Sign(sign) => Some(sign),
                    _ => None,
                },
            )?
            .unwrap_or(false);
            let schemes = if rsa && sign {
                signing_schemes(mechanisms)
            } else {
                Vec::new()
            };
            Ok(KeyReport {
                id: attribute(session, handle, AttributeType::Id, id_attribute)?
                    .unwrap_or_default(),
                label: attribute(session, handle, AttributeType::Label, label_attribute)?
                    .unwrap_or_default(),
                rsa,
                sign,
                schemes,
            })
        })
        .collect()
}

fn id_attribute(attribute: Attribute) -> Option<Vec<u8>> {
    match attribute {
        Attribute::Id(id) => Some(id),
        _ => None,
    }
}

fn label_attribute(attribute: Attribute) -> Option<String> {
    match attribute {
        Attribute::Label(label) => Some(String::from_utf8_lossy(&label).into_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(certificates: &[(&[u8], &str)], keys: &[(&[u8], bool)]) -> TokenReport {
        TokenReport {
            slot: 0,
            label: "t".into(),
            serial: "0000".into(),
            supported_schemes: vec![SignatureScheme::RSA_PSS_SHA256],
            certificates: certificates
                .iter()
                .map(|(id, label)| CertificateReport {
                    id: id.to_vec(),
                    label: (*label).to_string(),
                })
                .collect(),
            private_keys: keys
                .iter()
                .map(|(id, usable)| KeyReport {
                    id: id.to_vec(),
                    label: String::new(),
                    rsa: true,
                    sign: *usable,
                    schemes: if *usable {
                        vec![SignatureScheme::RSA_PSS_SHA256]
                    } else {
                        vec![]
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn pairs_by_id_like_detection() {
        // Cert 1 has a usable key; cert 2's key cannot sign; cert 3 has two
        // keys; cert with empty ID is ignored; key 4 has no cert.
        let token = token(
            &[(b"\x01", ""), (b"\x02", ""), (b"\x03", ""), (b"", "")],
            &[
                (b"\x01", true),
                (b"\x02", false),
                (b"\x03", true),
                (b"\x03", true),
                (b"\x04", true),
            ],
        );
        let ids = token
            .identities()
            .into_iter()
            .map(|identity| identity.id.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![vec![1]]);
    }

    #[test]
    fn filters_by_uri_attributes() {
        let inspection = Inspection {
            tokens: vec![
                token(&[(b"\x01", "")], &[(b"\x01", true)]),
                token(&[(b"\x02", "")], &[(b"\x02", true)]),
            ],
        };
        let uri = |uri: &str| Pkcs11Uri::parse(uri).unwrap();
        assert_eq!(inspection.identities(&uri("pkcs11:")).len(), 2);
        assert_eq!(inspection.identities(&uri("pkcs11:id=%02")).len(), 1);
        assert!(inspection.identities(&uri("pkcs11:id=%09")).is_empty());
        assert_eq!(inspection.identities(&uri("pkcs11:token=t")).len(), 2);
        assert!(inspection.identities(&uri("pkcs11:token=u")).is_empty());
        assert_eq!(inspection.identities(&uri("pkcs11:serial=0000")).len(), 2);
        assert!(inspection.identities(&uri("pkcs11:serial=1111")).is_empty());
        assert!(
            inspection
                .identities(&uri("pkcs11:object=missing"))
                .is_empty()
        );
    }

    #[test]
    fn object_filter_applies_to_the_specific_certificate() {
        // `object=` must select by the certificate's own label when two
        // certificates share a CKA_ID.
        let inspection = Inspection {
            tokens: vec![token(&[(b"\x01", "a"), (b"\x01", "b")], &[(b"\x01", true)])],
        };
        let uri = |uri: &str| Pkcs11Uri::parse(uri).unwrap();
        assert_eq!(inspection.identities(&uri("pkcs11:")).len(), 2);
        let identities = inspection.identities(&uri("pkcs11:object=a"));
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].certificate.label, "a");
    }
}
