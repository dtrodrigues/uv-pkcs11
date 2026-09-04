//! PKCS#11-backed client identities for rustls.
//!
//! [`Pkcs11ClientIdentity::load`] locates a certificate and matching
//! private key on a PKCS#11 token and exposes them as a rustls
//! [`ResolvesClientCert`], so TLS client authentication can use keys that never
//! leave the token.
//!
//! # Blocking
//!
//! Signing happens synchronously inside rustls' handshake, on whichever thread
//! drives the connection, while holding a lock on the token session. For local
//! tokens this takes milliseconds; for network HSMs it can block that thread
//! for the duration of a round trip. Async runtimes that drive many
//! connections on a small worker pool should account for this.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::Session;
use cryptoki::slot::Slot;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub mod inspect;

/// A rustls client identity backed by a PKCS#11 certificate and private key.
#[derive(Clone, Debug)]
pub struct Pkcs11ClientIdentity {
    resolver: Arc<dyn ResolvesClientCert>,
}

impl Pkcs11ClientIdentity {
    /// The p11-kit proxy module, loaded by soname when no module is named.
    #[cfg(not(target_os = "macos"))]
    pub const P11_KIT_PROXY: &'static str = "p11-kit-proxy.so";
    /// The p11-kit proxy module, loaded by soname when no module is named.
    #[cfg(target_os = "macos")]
    pub const P11_KIT_PROXY: &'static str = "p11-kit-proxy.dylib";

    /// Load the identity named by an RFC 7512 `pkcs11:` URI.
    ///
    /// The path attributes `token`, `serial`, `id`, and `object` restrict
    /// which certificate/key pairs are considered; the query attribute
    /// `module-path` names the PKCS#11 module by absolute path (native code
    /// that must be trusted), defaulting to the p11-kit proxy
    /// ([`Self::P11_KIT_PROXY`]) when absent. Exactly one identity must
    /// match; the URI naming nothing is an error. `pin-value` and
    /// `pin-source` are rejected: objects are read from public sessions
    /// without login, as described on [`Self::load`].
    pub fn from_uri(uri: &str) -> Result<Self, Pkcs11IdentityError> {
        let Pkcs11Uri {
            selector,
            module_path,
        } = Pkcs11Uri::parse(uri)?;
        let pkcs11 = match &module_path {
            Some(path) => load_module(path)?,
            None => load_proxy()?,
        };
        Self::single_identity(&pkcs11, &selector)
    }

    /// Load the single usable identity found on any token of a PKCS#11 module.
    ///
    /// Detection pairs each X.509 certificate on each initialized token with
    /// the signing-capable RSA private key sharing its `CKA_ID`, as PKCS#11
    /// providers conventionally arrange. When `id` is given, only objects with
    /// that `CKA_ID` are considered. Exactly one usable pair must exist across
    /// all tokens. Only the certificate itself is sent; any intermediates must
    /// be known to the server.
    ///
    /// No PIN is presented and no login is performed: whatever the provider
    /// exposes in a public session is used. Providers that are unlocked out
    /// of band (or that do not require login at all) work as-is; tokens that
    /// hide their keys until login will not yield an identity.
    pub fn load(module: impl AsRef<Path>, id: Option<&[u8]>) -> Result<Self, Pkcs11IdentityError> {
        let pkcs11 = load_module(module.as_ref())?;
        let selector = Selector {
            id: id.map(<[u8]>::to_vec),
            ..Selector::default()
        };
        Self::single_identity(&pkcs11, &selector)
    }

    /// The exactly-one identity matching `selector`, or an error.
    fn single_identity(pkcs11: &Pkcs11, selector: &Selector) -> Result<Self, Pkcs11IdentityError> {
        let (identities, found_supported_token) = find_identities(pkcs11, selector)?;
        if identities.is_empty() && !found_supported_token {
            return Err(Pkcs11IdentityError::NoSupportedSignatureMechanisms);
        }
        Ok(Self::from_discovered(select_discovered_identity(
            identities,
        )?))
    }

    fn from_discovered(identity: DiscoveredIdentity) -> Self {
        let signing_key = Arc::new(Pkcs11SigningKey {
            session: identity.session,
            private_key: identity.private_key,
            supported_schemes: identity.supported_schemes,
        });
        let certified_key = CertifiedKey::new(
            vec![CertificateDer::from(identity.certificate)],
            signing_key,
        );
        Self {
            resolver: Arc::new(SingleCertAndKey::from(certified_key)),
        }
    }

    /// Return the resolver for use with `ClientConfig::with_client_cert_resolver`.
    #[must_use]
    pub fn resolver(&self) -> Arc<dyn ResolvesClientCert> {
        self.resolver.clone()
    }
}

/// Loaded PKCS#11 modules, keyed by path.
///
/// A module must be initialised once per process and stays loaded for the
/// life of the process: unloading a still-initialised module (or finalising
/// one that other code is using) is unsafe with many providers.
static MODULES: LazyLock<Mutex<HashMap<PathBuf, Pkcs11>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn load_module(path: &Path) -> Result<Pkcs11, Pkcs11IdentityError> {
    let mut modules = MODULES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(pkcs11) = modules.get(path) {
        return Ok(pkcs11.clone());
    }

    let pkcs11 = Pkcs11::new(path)?;
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(())
        | Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, Function::Initialize)) => {
        }
        Err(error) => return Err(error.into()),
    }
    modules.insert(path.to_path_buf(), pkcs11.clone());
    Ok(pkcs11)
}

fn load_proxy() -> Result<Pkcs11, Pkcs11IdentityError> {
    load_module(Path::new(Pkcs11ClientIdentity::P11_KIT_PROXY))
        .map_err(|error| Pkcs11IdentityError::ProxyUnavailable(Box::new(error)))
}

/// Which certificate/key pairs to consider, per RFC 7512 attribute.
#[derive(Debug, Default)]
struct Selector {
    token: Option<String>,
    serial: Option<String>,
    id: Option<Vec<u8>>,
    object: Option<String>,
}

/// The identities matching `selector` across all initialized tokens, and
/// whether any token supported the required signature mechanisms at all.
fn find_identities(
    pkcs11: &Pkcs11,
    selector: &Selector,
) -> Result<(Vec<DiscoveredIdentity>, bool), Pkcs11IdentityError> {
    let mut identities = Vec::new();
    let mut found_supported_token = false;
    for slot in pkcs11.get_slots_with_initialized_token()? {
        let token_mechanisms = pkcs11.get_mechanism_list(slot)?;
        if signing_schemes(&token_mechanisms).is_empty() {
            continue;
        }
        found_supported_token = true;
        if selector.token.is_some() || selector.serial.is_some() {
            let info = pkcs11.get_token_info(slot)?;
            if selector
                .token
                .as_deref()
                .is_some_and(|token| info.label().trim_end() != token)
            {
                continue;
            }
            if selector
                .serial
                .as_deref()
                .is_some_and(|serial| info.serial_number().trim_end() != serial)
            {
                continue;
            }
        }
        identities.extend(discover_on_token(
            pkcs11,
            slot,
            selector,
            &token_mechanisms,
        )?);
    }
    Ok((identities, found_supported_token))
}

/// The parsed subset of an RFC 7512 `pkcs11:` URI, as described on
/// [`Pkcs11ClientIdentity::from_uri`].
#[derive(Debug)]
pub struct Pkcs11Uri {
    selector: Selector,
    module_path: Option<PathBuf>,
}

impl Pkcs11Uri {
    /// Parse a `pkcs11:` URI, accepting the `token`, `serial`, `id`,
    /// `object`, and `type=cert` path attributes and the `module-path` query
    /// attribute, and rejecting everything else (including
    /// `pin-value`/`pin-source`). Per RFC 7512, `module-path` must be
    /// absolute so it cannot resolve against the working directory.
    pub fn parse(uri: &str) -> Result<Self, Pkcs11IdentityError> {
        let Some(rest) = uri.strip_prefix("pkcs11:") else {
            return Err(invalid_uri("it must begin with `pkcs11:`"));
        };
        let (path_part, query_part) = match rest.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (rest, None),
        };

        let mut selector = Selector::default();
        let mut object_type: Option<String> = None;
        let mut module_path: Option<PathBuf> = None;
        for (name, value) in attributes(path_part, ';')? {
            match name {
                "token" => set_once(name, &mut selector.token, decode_string(name, value)?)?,
                "serial" => set_once(name, &mut selector.serial, decode_string(name, value)?)?,
                "object" => set_once(name, &mut selector.object, decode_string(name, value)?)?,
                "id" => set_once(name, &mut selector.id, decode_bytes(value)?)?,
                "type" => {
                    let object_type_value = decode_string(name, value)?;
                    if object_type_value != "cert" {
                        return Err(invalid_uri(format!(
                            "`type={object_type_value}` is not supported; only `type=cert` is accepted"
                        )));
                    }
                    set_once(name, &mut object_type, object_type_value)?;
                }
                "module-path" => {
                    return Err(invalid_uri(
                        "`module-path` belongs after `?`, as in `pkcs11:?module-path=/path/to/module.so`",
                    ));
                }
                _ => return Err(unsupported_attribute(name)),
            }
        }
        for (name, value) in attributes(query_part.unwrap_or(""), '&')? {
            match name {
                "module-path" => {
                    let path = PathBuf::from(decode_string(name, value)?);
                    if !path.is_absolute() {
                        return Err(invalid_uri(format!(
                            "`module-path` must be an absolute path, got `{}`",
                            path.display()
                        )));
                    }
                    set_once(name, &mut module_path, path)?;
                }
                _ => return Err(unsupported_attribute(name)),
            }
        }
        Ok(Self {
            selector,
            module_path,
        })
    }

    /// The `module-path` query attribute, when present.
    #[must_use]
    pub fn module_path(&self) -> Option<&Path> {
        self.module_path.as_deref()
    }

    /// Whether any identity-filtering attribute (`token`, `serial`, `id`,
    /// `object`) is present.
    #[must_use]
    pub fn has_filters(&self) -> bool {
        let Selector {
            token,
            serial,
            id,
            object,
        } = &self.selector;
        token.is_some() || serial.is_some() || id.is_some() || object.is_some()
    }
}

fn attributes(part: &str, separator: char) -> Result<Vec<(&str, &str)>, Pkcs11IdentityError> {
    part.split(separator)
        .filter(|attribute| !attribute.is_empty())
        .map(|attribute| {
            attribute
                .split_once('=')
                .ok_or_else(|| invalid_uri(format!("attribute `{attribute}` has no `=`")))
        })
        .collect()
}

fn unsupported_attribute(name: &str) -> Pkcs11IdentityError {
    if matches!(name, "pin-value" | "pin-source") {
        invalid_uri(
            "PIN attributes are not supported; objects are read from public sessions without login",
        )
    } else {
        invalid_uri(format!("unsupported attribute `{name}`"))
    }
}

fn set_once<T>(name: &str, slot: &mut Option<T>, value: T) -> Result<(), Pkcs11IdentityError> {
    if slot.replace(value).is_some() {
        return Err(invalid_uri(format!("duplicate attribute `{name}`")));
    }
    Ok(())
}

fn decode_bytes(value: &str) -> Result<Vec<u8>, Pkcs11IdentityError> {
    let raw = value.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' {
            let byte = raw
                .get(index + 1..index + 3)
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .ok_or_else(|| invalid_uri(format!("invalid percent-encoding in `{value}`")))?;
            bytes.push(byte);
            index += 3;
        } else {
            bytes.push(raw[index]);
            index += 1;
        }
    }
    Ok(bytes)
}

fn decode_string(name: &str, value: &str) -> Result<String, Pkcs11IdentityError> {
    String::from_utf8(decode_bytes(value)?)
        .map_err(|_| invalid_uri(format!("`{name}` is not valid UTF-8")))
}

fn invalid_uri(message: impl Into<String>) -> Pkcs11IdentityError {
    Pkcs11IdentityError::InvalidUri(message.into())
}

struct DiscoveredIdentity {
    session: Arc<Mutex<Session>>,
    private_key: ObjectHandle,
    supported_schemes: Vec<(SignatureScheme, SigningMethod)>,
    certificate: Vec<u8>,
}

struct TokenCertificate {
    id: Vec<u8>,
    value: Vec<u8>,
}

fn discover_on_token(
    pkcs11: &Pkcs11,
    slot: Slot,
    selector: &Selector,
    token_mechanisms: &[MechanismType],
) -> Result<Vec<DiscoveredIdentity>, Pkcs11IdentityError> {
    let session = pkcs11.open_ro_session(slot)?;
    let mut identities = Vec::new();
    for certificate in load_certificates(&session, selector)? {
        if certificate.id.is_empty() {
            continue;
        }

        let private_keys = session.find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Token(true),
            Attribute::Sign(true),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Id(certificate.id.clone()),
        ])?;
        let private_key = match private_keys.as_slice() {
            [private_key] => *private_key,
            [] => continue,
            _ => return Err(Pkcs11IdentityError::MultipleObjects("private key")),
        };

        let supported_schemes = signing_methods(token_mechanisms);
        if supported_schemes.is_empty() {
            continue;
        }

        identities.push((private_key, supported_schemes, certificate.value));
    }

    let session = Arc::new(Mutex::new(session));
    Ok(identities
        .into_iter()
        .map(
            |(private_key, supported_schemes, certificate)| DiscoveredIdentity {
                session: session.clone(),
                private_key,
                supported_schemes,
                certificate,
            },
        )
        .collect())
}

fn load_certificates(
    session: &Session,
    selector: &Selector,
) -> Result<Vec<TokenCertificate>, Pkcs11IdentityError> {
    let mut template = vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
    ];
    if let Some(id) = &selector.id {
        template.push(Attribute::Id(id.clone()));
    }
    if let Some(object) = &selector.object {
        template.push(Attribute::Label(object.clone().into_bytes()));
    }
    let mut certificates = Vec::new();
    for handle in session.find_objects(&template)? {
        let mut id = Vec::new();
        let mut value = None;
        for attribute in
            session.get_attributes(handle, &[AttributeType::Id, AttributeType::Value])?
        {
            match attribute {
                Attribute::Id(found) => id = found,
                Attribute::Value(found) => value = Some(found),
                _ => {}
            }
        }
        let value = value.ok_or(Pkcs11IdentityError::MissingCertificateValue)?;
        certificates.push(TokenCertificate { id, value });
    }
    Ok(certificates)
}

fn select_discovered_identity<T>(mut identities: Vec<T>) -> Result<T, Pkcs11IdentityError> {
    match identities.len() {
        0 => Err(Pkcs11IdentityError::NoUsableSigningIdentity),
        1 => Ok(identities.remove(0)),
        count => Err(Pkcs11IdentityError::MultipleUsableSigningIdentities(count)),
    }
}

fn attribute<T>(
    session: &Session,
    object: ObjectHandle,
    attribute_type: AttributeType,
    extract: impl Fn(Attribute) -> Option<T>,
) -> Result<Option<T>, Pkcs11IdentityError> {
    Ok(session
        .get_attributes(object, &[attribute_type])?
        .into_iter()
        .find_map(extract))
}

#[derive(Debug)]
struct Pkcs11SigningKey {
    session: Arc<Mutex<Session>>,
    private_key: ObjectHandle,
    supported_schemes: Vec<(SignatureScheme, SigningMethod)>,
}

impl SigningKey for Pkcs11SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.supported_schemes
            .iter()
            .copied()
            .find(|(scheme, _)| offered.contains(scheme))
            .map(|(scheme, method)| {
                Box::new(Pkcs11Signer {
                    session: self.session.clone(),
                    private_key: self.private_key,
                    scheme,
                    method,
                }) as Box<dyn Signer>
            })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
struct Pkcs11Signer {
    session: Arc<Mutex<Session>>,
    private_key: ObjectHandle,
    scheme: SignatureScheme,
    method: SigningMethod,
}

impl Signer for Pkcs11Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        let unsupported = || {
            RustlsError::General(format!(
                "unsupported PKCS#11 signature scheme: {:?}",
                self.scheme
            ))
        };
        let mechanism = mechanism_for(self.scheme, self.method).ok_or_else(unsupported)?;
        let input = signing_input(self.scheme, self.method, message).ok_or_else(unsupported)?;
        self.session
            .lock()
            .map_err(|_| RustlsError::General("PKCS#11 session lock is poisoned".to_string()))?
            .sign(&mechanism, self.private_key, &input)
            .map_err(|err| RustlsError::General(format!("PKCS#11 signing failed: {err}")))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// How a TLS signature scheme is produced on a token, in preference order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SigningMethod {
    /// The token hashes and signs the handshake transcript
    /// (`CKM_SHA*_RSA_PKCS` and `CKM_SHA*_RSA_PKCS_PSS`).
    HashOnToken,
    /// The transcript is hashed here and the token pads and signs the digest
    /// (`CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS`), for providers that only
    /// expose the raw RSA mechanisms.
    HashInProcess,
}

impl SigningMethod {
    const PREFERENCE: [Self; 2] = [Self::HashOnToken, Self::HashInProcess];
}

/// A TLS signature scheme and the PKCS#11 mechanisms that produce it.
struct SchemeMechanisms {
    scheme: SignatureScheme,
    /// The hash-and-sign mechanism ([`SigningMethod::HashOnToken`]).
    hashed: MechanismType,
    /// The mechanism that signs a digest ([`SigningMethod::HashInProcess`]).
    raw: MechanismType,
}

impl SchemeMechanisms {
    fn mechanism(&self, method: SigningMethod) -> MechanismType {
        match method {
            SigningMethod::HashOnToken => self.hashed,
            SigningMethod::HashInProcess => self.raw,
        }
    }
}

/// TLS signature schemes and their PKCS#11 mechanisms, in preference order.
const SCHEME_MECHANISMS: [SchemeMechanisms; 6] = [
    SchemeMechanisms {
        scheme: SignatureScheme::RSA_PSS_SHA512,
        hashed: MechanismType::SHA512_RSA_PKCS_PSS,
        raw: MechanismType::RSA_PKCS_PSS,
    },
    SchemeMechanisms {
        scheme: SignatureScheme::RSA_PSS_SHA384,
        hashed: MechanismType::SHA384_RSA_PKCS_PSS,
        raw: MechanismType::RSA_PKCS_PSS,
    },
    SchemeMechanisms {
        scheme: SignatureScheme::RSA_PSS_SHA256,
        hashed: MechanismType::SHA256_RSA_PKCS_PSS,
        raw: MechanismType::RSA_PKCS_PSS,
    },
    SchemeMechanisms {
        scheme: SignatureScheme::RSA_PKCS1_SHA512,
        hashed: MechanismType::SHA512_RSA_PKCS,
        raw: MechanismType::RSA_PKCS,
    },
    SchemeMechanisms {
        scheme: SignatureScheme::RSA_PKCS1_SHA384,
        hashed: MechanismType::SHA384_RSA_PKCS,
        raw: MechanismType::RSA_PKCS,
    },
    SchemeMechanisms {
        scheme: SignatureScheme::RSA_PKCS1_SHA256,
        hashed: MechanismType::SHA256_RSA_PKCS,
        raw: MechanismType::RSA_PKCS,
    },
];

/// The TLS signature schemes producible through `token_mechanisms`, each
/// with the preferred [`SigningMethod`] the token supports for it, in
/// preference order.
///
/// Per-key `CKA_ALLOWED_MECHANISMS` restrictions are not consulted: cryptoki
/// 0.12 decodes that attribute with its byte length as the element count and
/// reads past the buffer, so a key carrying it fails in `C_Sign` instead.
fn signing_methods(token_mechanisms: &[MechanismType]) -> Vec<(SignatureScheme, SigningMethod)> {
    SCHEME_MECHANISMS
        .iter()
        .filter_map(|entry| {
            SigningMethod::PREFERENCE
                .into_iter()
                .find(|method| token_mechanisms.contains(&entry.mechanism(*method)))
                .map(|method| (entry.scheme, method))
        })
        .collect()
}

/// The TLS signature schemes producible through `token_mechanisms`, as
/// [`signing_methods`] without the method.
fn signing_schemes(token_mechanisms: &[MechanismType]) -> Vec<SignatureScheme> {
    signing_methods(token_mechanisms)
        .into_iter()
        .map(|(scheme, _)| scheme)
        .collect()
}

/// The PSS parameters of an RSA-PSS scheme.
fn pss_params(scheme: SignatureScheme) -> Option<PkcsPssParams> {
    let params = match scheme {
        SignatureScheme::RSA_PSS_SHA256 => PkcsPssParams {
            hash_alg: MechanismType::SHA256,
            mgf: PkcsMgfType::MGF1_SHA256,
            s_len: 32.into(),
        },
        SignatureScheme::RSA_PSS_SHA384 => PkcsPssParams {
            hash_alg: MechanismType::SHA384,
            mgf: PkcsMgfType::MGF1_SHA384,
            s_len: 48.into(),
        },
        SignatureScheme::RSA_PSS_SHA512 => PkcsPssParams {
            hash_alg: MechanismType::SHA512,
            mgf: PkcsMgfType::MGF1_SHA512,
            s_len: 64.into(),
        },
        _ => return None,
    };
    Some(params)
}

/// The PKCS#11 mechanism that produces `scheme` by `method`.
fn mechanism_for(scheme: SignatureScheme, method: SigningMethod) -> Option<Mechanism<'static>> {
    let mechanism = match (scheme, method) {
        (SignatureScheme::RSA_PSS_SHA256, SigningMethod::HashOnToken) => {
            Mechanism::Sha256RsaPkcsPss(pss_params(scheme)?)
        }
        (SignatureScheme::RSA_PSS_SHA384, SigningMethod::HashOnToken) => {
            Mechanism::Sha384RsaPkcsPss(pss_params(scheme)?)
        }
        (SignatureScheme::RSA_PSS_SHA512, SigningMethod::HashOnToken) => {
            Mechanism::Sha512RsaPkcsPss(pss_params(scheme)?)
        }
        (
            SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512,
            SigningMethod::HashInProcess,
        ) => Mechanism::RsaPkcsPss(pss_params(scheme)?),
        (SignatureScheme::RSA_PKCS1_SHA256, SigningMethod::HashOnToken) => Mechanism::Sha256RsaPkcs,
        (SignatureScheme::RSA_PKCS1_SHA384, SigningMethod::HashOnToken) => Mechanism::Sha384RsaPkcs,
        (SignatureScheme::RSA_PKCS1_SHA512, SigningMethod::HashOnToken) => Mechanism::Sha512RsaPkcs,
        (
            SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512,
            SigningMethod::HashInProcess,
        ) => Mechanism::RsaPkcs,
        _ => return None,
    };
    Some(mechanism)
}

/// The `DigestInfo` prefixes that PKCS#1 v1.5 signatures place before the
/// digest (RFC 8017, section 9.2, note 1), which `CKM_RSA_PKCS` expects the
/// caller to supply.
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// The data passed to `C_Sign` for `message`: the message itself when the
/// token hashes, otherwise its digest, wrapped in a `DigestInfo` for the
/// PKCS#1 v1.5 schemes (`CKM_RSA_PKCS_PSS` takes the bare digest and learns
/// the hash from its parameters).
fn signing_input<'a>(
    scheme: SignatureScheme,
    method: SigningMethod,
    message: &'a [u8],
) -> Option<Cow<'a, [u8]>> {
    match method {
        SigningMethod::HashOnToken => Some(Cow::Borrowed(message)),
        SigningMethod::HashInProcess => {
            let input = match scheme {
                SignatureScheme::RSA_PSS_SHA256 => Sha256::digest(message).to_vec(),
                SignatureScheme::RSA_PSS_SHA384 => Sha384::digest(message).to_vec(),
                SignatureScheme::RSA_PSS_SHA512 => Sha512::digest(message).to_vec(),
                SignatureScheme::RSA_PKCS1_SHA256 => {
                    [DIGEST_INFO_SHA256, &Sha256::digest(message)].concat()
                }
                SignatureScheme::RSA_PKCS1_SHA384 => {
                    [DIGEST_INFO_SHA384, &Sha384::digest(message)].concat()
                }
                SignatureScheme::RSA_PKCS1_SHA512 => {
                    [DIGEST_INFO_SHA512, &Sha512::digest(message)].concat()
                }
                _ => return None,
            };
            Some(Cow::Owned(input))
        }
    }
}

/// Errors produced while loading a PKCS#11 client identity.
#[derive(Debug, thiserror::Error)]
pub enum Pkcs11IdentityError {
    /// No supported signing mechanism is available on the selected tokens.
    #[error("PKCS#11 tokens support none of the required RSA signature mechanisms")]
    NoSupportedSignatureMechanisms,
    /// No signing-capable key has a unique matching certificate.
    #[error("PKCS#11 tokens have no usable signing identity")]
    NoUsableSigningIdentity,
    /// Automatic discovery found more than one usable identity.
    #[error(
        "PKCS#11 tokens hold {0} usable signing identities; select one with a `pkcs11:` URI attribute (`id`, `token`, `object`)"
    )]
    MultipleUsableSigningIdentities(usize),
    /// The `pkcs11:` URI could not be parsed or uses unsupported attributes.
    #[error("invalid PKCS#11 URI: {0}")]
    InvalidUri(String),
    /// The p11-kit proxy module could not be loaded.
    #[error(
        "the p11-kit proxy module `{}` is unavailable; install p11-kit or name a module with the `module-path` URI attribute",
        Pkcs11ClientIdentity::P11_KIT_PROXY
    )]
    ProxyUnavailable(#[source] Box<Pkcs11IdentityError>),
    /// More than one object matched a selector that must be unique.
    #[error("multiple PKCS#11 {0} objects share one CKA_ID")]
    MultipleObjects(&'static str),
    /// The certificate object has no `CKA_VALUE`.
    #[error("PKCS#11 certificate has no value")]
    MissingCertificateValue,
    /// The PKCS#11 provider returned an error.
    #[error(transparent)]
    Cryptoki(#[from] cryptoki::error::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_unsupported_signature_schemes() {
        let token_mechanisms = [
            MechanismType::SHA256_RSA_PKCS_PSS,
            MechanismType::SHA256_RSA_PKCS,
        ];
        assert_eq!(
            signing_methods(&token_mechanisms),
            vec![
                (SignatureScheme::RSA_PSS_SHA256, SigningMethod::HashOnToken),
                (
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SigningMethod::HashOnToken
                ),
            ]
        );
        assert_eq!(
            signing_schemes(&[MechanismType::SHA256_RSA_PKCS]),
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        );
    }

    #[test]
    fn falls_back_to_raw_mechanisms() {
        // A sign-only token offers every scheme, hashed in process.
        let raw_only = [MechanismType::RSA_PKCS_PSS, MechanismType::RSA_PKCS];
        assert_eq!(
            signing_methods(&raw_only),
            vec![
                (
                    SignatureScheme::RSA_PSS_SHA512,
                    SigningMethod::HashInProcess
                ),
                (
                    SignatureScheme::RSA_PSS_SHA384,
                    SigningMethod::HashInProcess
                ),
                (
                    SignatureScheme::RSA_PSS_SHA256,
                    SigningMethod::HashInProcess
                ),
                (
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SigningMethod::HashInProcess
                ),
                (
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SigningMethod::HashInProcess
                ),
                (
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SigningMethod::HashInProcess
                ),
            ]
        );
        // Hashing on the token is preferred where available, per scheme.
        let mixed = [MechanismType::SHA256_RSA_PKCS, MechanismType::RSA_PKCS];
        assert_eq!(
            signing_methods(&mixed),
            vec![
                (
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SigningMethod::HashInProcess
                ),
                (
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SigningMethod::HashInProcess
                ),
                (
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SigningMethod::HashOnToken
                ),
            ]
        );
    }

    #[test]
    fn hashes_in_process_for_raw_mechanisms() {
        let message = b"handshake transcript";
        assert_eq!(
            signing_input(
                SignatureScheme::RSA_PSS_SHA256,
                SigningMethod::HashOnToken,
                message
            )
            .as_deref(),
            Some(&message[..])
        );
        assert_eq!(
            signing_input(
                SignatureScheme::RSA_PSS_SHA384,
                SigningMethod::HashInProcess,
                message
            )
            .as_deref(),
            Some(&Sha384::digest(message)[..])
        );
        // PKCS#1 v1.5 wraps the digest in a `DigestInfo`.
        let input = signing_input(
            SignatureScheme::RSA_PKCS1_SHA256,
            SigningMethod::HashInProcess,
            message,
        )
        .unwrap();
        assert_eq!(&input[..DIGEST_INFO_SHA256.len()], DIGEST_INFO_SHA256);
        assert_eq!(
            &input[DIGEST_INFO_SHA256.len()..],
            &Sha256::digest(message)[..]
        );
        assert_eq!(input.len(), 0x33);
        assert!(
            signing_input(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SigningMethod::HashInProcess,
                message
            )
            .is_none()
        );
    }

    #[test]
    fn discovery_requires_exactly_one_usable_identity() {
        assert!(matches!(
            select_discovered_identity::<u8>(vec![]),
            Err(Pkcs11IdentityError::NoUsableSigningIdentity)
        ));
        assert_eq!(select_discovered_identity(vec![7]).unwrap(), 7);
        assert!(matches!(
            select_discovered_identity(vec![7, 8]),
            Err(Pkcs11IdentityError::MultipleUsableSigningIdentities(2))
        ));
    }

    #[test]
    fn parses_pkcs11_uris() {
        let uri = Pkcs11Uri::parse("pkcs11:").unwrap();
        assert!(uri.module_path.is_none());
        assert!(uri.selector.token.is_none() && uri.selector.id.is_none());

        let uri = Pkcs11Uri::parse(
            "pkcs11:token=my%20token;serial=0123;id=%01%a2;object=leaf?module-path=/opt/x/y.so",
        )
        .unwrap();
        assert_eq!(uri.selector.token.as_deref(), Some("my token"));
        assert_eq!(uri.selector.serial.as_deref(), Some("0123"));
        assert_eq!(uri.selector.id.as_deref(), Some(&[0x01, 0xA2][..]));
        assert_eq!(uri.selector.object.as_deref(), Some("leaf"));
        assert_eq!(uri.module_path.as_deref(), Some(Path::new("/opt/x/y.so")));

        let uri = Pkcs11Uri::parse("pkcs11:type=cert?module-path=/usr/lib64/pkcs11/libsofthsm2.so")
            .unwrap();
        assert!(uri.selector.id.is_none());
        assert_eq!(
            uri.module_path.as_deref(),
            Some(Path::new("/usr/lib64/pkcs11/libsofthsm2.so"))
        );
    }

    #[test]
    fn rejects_malformed_pkcs11_uris() {
        for uri in [
            "pkcs12:",
            "pkcs11:id",
            "pkcs11:id=%1",
            "pkcs11:id=%zz",
            "pkcs11:id=%01;id=%02",
            "pkcs11:module-path=/x.so",
            "pkcs11:slot-id=4",
            "pkcs11:type=private",
            "pkcs11:type=cert;type=cert",
            "pkcs11:?pin-value=1234",
            "pkcs11:pin-source=file:/pin",
            "pkcs11:?token=x",
            "pkcs11:?module-path=module.so",
            "pkcs11:?module-path=./x.so",
            "pkcs11:?module-path=../x/y.so",
            "pkcs11:?module-path=",
        ] {
            assert!(
                matches!(
                    Pkcs11Uri::parse(uri),
                    Err(Pkcs11IdentityError::InvalidUri(_))
                ),
                "{uri}"
            );
        }
    }

    #[test]
    fn maps_schemes_to_mechanisms() {
        assert!(matches!(
            mechanism_for(SignatureScheme::RSA_PSS_SHA256, SigningMethod::HashOnToken),
            Some(Mechanism::Sha256RsaPkcsPss(_))
        ));
        assert!(matches!(
            mechanism_for(
                SignatureScheme::RSA_PSS_SHA256,
                SigningMethod::HashInProcess
            ),
            Some(Mechanism::RsaPkcsPss(_))
        ));
        assert!(matches!(
            mechanism_for(
                SignatureScheme::RSA_PKCS1_SHA512,
                SigningMethod::HashInProcess
            ),
            Some(Mechanism::RsaPkcs)
        ));
        assert!(
            mechanism_for(
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SigningMethod::HashOnToken
            )
            .is_none()
        );
    }
}
