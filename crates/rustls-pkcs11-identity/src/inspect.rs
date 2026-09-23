//! Diagnostic view of what a PKCS#11 module exposes, using the same rules as
//! identity detection, for the `rustls-pkcs11-inspect` command.

use std::path::Path;

use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass};
use cryptoki::session::Session;
use rustls::SignatureScheme;

use crate::{
    ClientCertificateProblem, Pkcs11IdentityError, Pkcs11Uri, attribute,
    client_certificate_problem, key_allowed_mechanisms, load_module, percent_encode,
    signing_schemes,
};

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
    /// TLS signature schemes the token's mechanisms can produce, before any
    /// per-key `CKA_ALLOWED_MECHANISMS` restriction.
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
    /// Why the certificate cannot identify a TLS client, if it cannot.
    pub problem: Option<ClientCertificateProblem>,
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
    /// TLS signature schemes this key can produce on this token, honouring the
    /// key's `CKA_ALLOWED_MECHANISMS` (empty if it is not a usable RSA signing
    /// key).
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
    /// The usable identities on this token: client-capable certificates whose
    /// non-empty `CKA_ID` matches exactly one usable RSA signing key.
    pub fn identities(&self) -> Vec<Identity<'_>> {
        self.certificates
            .iter()
            .filter(|certificate| !certificate.id.is_empty() && certificate.problem.is_none())
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
                supported_schemes: signing_schemes(&mechanisms, None),
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

    /// A `pkcs11:` URI that selects `identity` and nothing else, in the form
    /// [`crate::Pkcs11ClientIdentity::from_uri`] reads.
    ///
    /// The URI names the token label and the certificate's `CKA_ID`, adding
    /// the token's serial number when the label is empty or shared with
    /// another token, and the certificate's label as `object` when another
    /// identity on the same token shares the `CKA_ID`. `module_path`, which
    /// RFC 7512 requires to be absolute, becomes the `module-path` query
    /// attribute; without it the URI names no module and so resolves through
    /// the p11-kit proxy.
    #[must_use]
    pub fn uri(&self, identity: &Identity<'_>, module_path: Option<&Path>) -> String {
        let label = identity.token.label.trim_end();
        let shared_label = self
            .tokens
            .iter()
            .filter(|token| token.label.trim_end() == label)
            .count()
            > 1;
        let shared_id = identity
            .token
            .identities()
            .iter()
            .filter(|other| other.id == identity.id)
            .count()
            > 1;
        identity_uri(identity, shared_label, shared_id, module_path)
    }
}

/// Build the `pkcs11:` URI that selects `identity` on `module_path`.
///
/// `shared_label` says whether another token carries the same label, and
/// `shared_id` whether another identity on the same token carries the same
/// `CKA_ID`; either one pulls a further attribute into the URI.
fn identity_uri(
    identity: &Identity<'_>,
    shared_label: bool,
    shared_id: bool,
    module_path: Option<&Path>,
) -> String {
    let token = identity.token;
    let label = token.label.trim_end();
    let mut attributes = Vec::new();
    if !label.is_empty() {
        attributes.push(format!("token={}", percent_encode(label.as_bytes(), b"")));
    }
    if label.is_empty() || shared_label {
        attributes.push(format!(
            "serial={}",
            percent_encode(token.serial.trim_end().as_bytes(), b"")
        ));
    }
    attributes.push(format!("id={}", percent_encode(identity.id, b"")));
    if shared_id && !identity.certificate.label.is_empty() {
        attributes.push(format!(
            "object={}",
            percent_encode(identity.certificate.label.as_bytes(), b"")
        ));
    }
    let mut uri = format!("pkcs11:{}", attributes.join(";"));
    if let Some(path) = module_path {
        // `/` needs no encoding in the query part, so paths stay readable.
        let path = percent_encode(path.to_string_lossy().as_bytes(), b"/");
        uri.push_str(&format!("?module-path={path}"));
    }
    uri
}

fn certificates(session: &Session) -> Result<Vec<CertificateReport>, Pkcs11IdentityError> {
    let handles = session.find_objects(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
    ])?;
    handles
        .into_iter()
        .map(|handle| {
            let value = attribute(
                session,
                handle,
                AttributeType::Value,
                |attribute| match attribute {
                    Attribute::Value(value) => Some(value),
                    _ => None,
                },
            )?;
            Ok(CertificateReport {
                id: attribute(session, handle, AttributeType::Id, id_attribute)?
                    .unwrap_or_default(),
                label: attribute(session, handle, AttributeType::Label, label_attribute)?
                    .unwrap_or_default(),
                problem: match value {
                    Some(value) => client_certificate_problem(&value),
                    None => Some(ClientCertificateProblem::Malformed),
                },
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
                signing_schemes(
                    mechanisms,
                    key_allowed_mechanisms(session, handle)?.as_deref(),
                )
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
                    problem: None,
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
    fn uris_name_the_token_and_the_id() {
        let inspection = Inspection {
            tokens: vec![token(&[(b"\x01", "leaf")], &[(b"\x01", true)])],
        };
        let identities = inspection.identities(&Pkcs11Uri::parse("pkcs11:").unwrap());
        assert_eq!(
            inspection.uri(&identities[0], None),
            "pkcs11:token=t;id=%01"
        );
        assert_eq!(
            inspection.uri(&identities[0], Some(Path::new("/opt/x y.so"))),
            "pkcs11:token=t;id=%01?module-path=/opt/x%20y.so"
        );
    }

    #[test]
    fn uris_disambiguate_shared_labels_and_ids() {
        // Two tokens carry the same label, and two certificates on the second
        // share a CKA_ID, so the serial number and the certificate label are
        // both needed to name one identity.
        let mut second = token(&[(b"\x02", "a"), (b"\x02", "b")], &[(b"\x02", true)]);
        second.serial = "1111".to_string();
        let inspection = Inspection {
            tokens: vec![token(&[(b"\x01", "leaf")], &[(b"\x01", true)]), second],
        };
        let identities = inspection.identities(&Pkcs11Uri::parse("pkcs11:").unwrap());
        let uris = identities
            .iter()
            .map(|identity| inspection.uri(identity, None))
            .collect::<Vec<_>>();
        assert_eq!(
            uris,
            [
                "pkcs11:token=t;serial=0000;id=%01",
                "pkcs11:token=t;serial=1111;id=%02;object=a",
                "pkcs11:token=t;serial=1111;id=%02;object=b",
            ]
        );
        // Each URI selects the one identity it was built for.
        for (uri, identity) in uris.iter().zip(&identities) {
            let selected = inspection.identities(&Pkcs11Uri::parse(uri).unwrap());
            assert_eq!(selected.len(), 1, "{uri}");
            assert_eq!(selected[0].certificate, identity.certificate, "{uri}");
        }
    }

    #[test]
    fn uris_name_an_unlabeled_token_by_serial() {
        let mut unlabeled = token(&[(b"\x01", "leaf")], &[(b"\x01", true)]);
        unlabeled.label = String::new();
        let inspection = Inspection {
            tokens: vec![unlabeled],
        };
        let identities = inspection.identities(&Pkcs11Uri::parse("pkcs11:").unwrap());
        assert_eq!(
            inspection.uri(&identities[0], None),
            "pkcs11:serial=0000;id=%01"
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
