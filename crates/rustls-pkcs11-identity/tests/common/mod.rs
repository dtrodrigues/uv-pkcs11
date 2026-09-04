//! Shared SoftHSM provisioning for the integration tests.
//!
//! Each scenario lives in its own test binary (and therefore its own
//! process), because a SoftHSM configuration is process-global and the crate
//! auto-detects across every token the module exposes.
//!
//! Scenarios are skipped when `softhsm2-util`, `openssl`, or the SoftHSM
//! module is not available. Set `RUSTLS_PKCS11_SOFTHSM_MODULE` to override
//! the module path.

#![allow(dead_code)]
// Test fixtures write scratch files; the workspace's fs-err mandate is for
// production code.
#![allow(clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    SupportedProtocolVersion,
};
use rustls_pkcs11_identity::Pkcs11ClientIdentity;

const PIN: &str = "1234";

pub struct Material {
    pub key: PathBuf,
    pub key_der: Vec<u8>,
    pub certificate_pem: PathBuf,
    pub certificate: Vec<u8>,
}

/// Certificate authorities and the server identity, held in software.
pub struct Pki {
    pub root: Material,
    pub server: Material,
}

/// An RSA key pair generated on the token as public objects (the crate never
/// logs in, and SoftHSM hides private objects until login), with a
/// certificate issued by the PKI root.
pub struct KeySpec {
    pub id: u8,
    /// Whether to store the key's certificate (under the same `CKA_ID`).
    pub with_certificate: bool,
}

pub struct TokenSpec<'a> {
    pub label: &'a str,
    pub keys: Vec<KeySpec>,
    /// Whether to also store the root certificate (under an unrelated ID).
    pub store_root: bool,
}

pub struct Fixture {
    pub module: PathBuf,
    pub pki: Pki,
}

/// Provision a scratch SoftHSM configuration, or `None` to skip the test.
pub fn provision(name: &str, tokens: &[TokenSpec<'_>]) -> Option<Fixture> {
    provision_with_mechanisms(name, "ALL", tokens)
}

/// [`provision`] with SoftHSM's `slots.mechanisms` setting, which edits what
/// `C_GetMechanismList` reports (`ALL`, or `-CKM_X,CKM_Y` to hide some).
pub fn provision_with_mechanisms(
    name: &str,
    mechanisms: &str,
    tokens: &[TokenSpec<'_>],
) -> Option<Fixture> {
    let Some(module) = find_module() else {
        eprintln!("skipping: SoftHSM module not found");
        return None;
    };
    if !tool_available("openssl") || !tool_available("softhsm2-util") {
        eprintln!("skipping: openssl or softhsm2-util not available");
        return None;
    }

    let dir = std::env::temp_dir().join(format!(
        "rustls-pkcs11-identity-{name}-{}",
        std::process::id()
    ));
    let token_dir = dir.join("tokens");
    std::fs::create_dir_all(&token_dir).unwrap();
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.mechanisms = {mechanisms}\n",
            token_dir.display()
        ),
    )
    .unwrap();
    // SAFETY: called once, before any PKCS#11 module is loaded, and no other
    // thread reads the environment concurrently.
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };

    let pki = build_pki(&dir);
    for spec in tokens {
        softhsm(
            &conf,
            &[
                "--init-token",
                "--free",
                "--label",
                spec.label,
                "--so-pin",
                PIN,
                "--pin",
                PIN,
            ],
        );
    }

    let pkcs11 = Pkcs11::new(&module).unwrap();
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();
    for spec in tokens {
        populate_token(&pkcs11, &dir, &pki, spec);
    }
    // The crate keeps modules initialised for the process lifetime;
    // finalising here would break its later sessions.
    std::mem::forget(pkcs11);

    Some(Fixture { module, pki })
}

fn populate_token(pkcs11: &Pkcs11, dir: &Path, pki: &Pki, spec: &TokenSpec<'_>) {
    let slot = pkcs11
        .get_slots_with_initialized_token()
        .unwrap()
        .into_iter()
        .find(|slot| pkcs11.get_token_info(*slot).unwrap().label() == spec.label)
        .expect("token exists");
    let session = pkcs11.open_rw_session(slot).unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new(PIN.into())))
        .unwrap();

    let mut certificates = Vec::new();
    for key in &spec.keys {
        let name = format!("{}-{:02x}", spec.label, key.id);
        let public_template = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Id(vec![key.id]),
            Attribute::Verify(true),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![1, 0, 1]),
        ];
        let private_template = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Sensitive(true),
            Attribute::Id(vec![key.id]),
            Attribute::Sign(true),
        ];
        let (public_key, _) = session
            .generate_key_pair(
                &Mechanism::RsaPkcsKeyPairGen,
                &public_template,
                &private_template,
            )
            .unwrap();
        let modulus = match session
            .get_attributes(public_key, &[AttributeType::Modulus])
            .unwrap()
            .pop()
        {
            Some(Attribute::Modulus(modulus)) => modulus,
            other => panic!("unexpected attribute {other:?}"),
        };
        let certificate = issue_for_public_key(dir, &name, &rsa_spki(&modulus), &pki.root);
        if key.with_certificate {
            certificates.push((certificate, vec![key.id]));
        }
    }
    if spec.store_root {
        certificates.push((pki.root.certificate.clone(), vec![0x80]));
    }

    for (index, (certificate, id)) in certificates.into_iter().enumerate() {
        let subject = certificate_subject(&certificate);
        session
            .create_object(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Id(id),
                Attribute::Label(format!("cert-{index}").into_bytes()),
                Attribute::Subject(subject),
                Attribute::Value(certificate),
            ])
            .unwrap();
    }
    session.logout().unwrap();
}

/// Split one DER TLV off the front of `data`: `(header_len, contents, rest)`.
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
    let (tlv, rest) = data.split_at(header + length);
    (tlv, rest)
}

fn der_contents(tlv: &[u8]) -> &[u8] {
    let header = if tlv[1] < 0x80 {
        2
    } else {
        2 + usize::from(tlv[1] & 0x7F)
    };
    &tlv[header..]
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

// Minimal DER writers for a SubjectPublicKeyInfo, so openssl can issue a
// certificate for a key that only exists on the token.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let significant = &bytes[bytes.iter().position(|&b| b != 0).unwrap()..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(contents);
    out
}

fn integer(value: &[u8]) -> Vec<u8> {
    let mut contents = Vec::with_capacity(value.len() + 1);
    if value.first().is_some_and(|first| first & 0x80 != 0) {
        contents.push(0);
    }
    contents.extend_from_slice(value);
    tlv(0x02, &contents)
}

fn bit_string(contents: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0u8], contents].concat())
}

fn rsa_spki(modulus: &[u8]) -> Vec<u8> {
    const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    let algorithm = tlv(
        0x30,
        &[tlv(0x06, OID_RSA_ENCRYPTION), tlv(0x05, &[])].concat(),
    );
    let key = tlv(0x30, &[integer(modulus), integer(&[1, 0, 1])].concat());
    tlv(0x30, &[algorithm, bit_string(&key)].concat())
}

/// Issue a client certificate for a public key we hold no private key for:
/// a throwaway key signs the request and `-force_pubkey` swaps in the token's.
fn issue_for_public_key(dir: &Path, name: &str, spki: &[u8], issuer: &Material) -> Vec<u8> {
    let spki_path = dir.join(format!("{name}.spki.der"));
    std::fs::write(&spki_path, spki).unwrap();
    let pubkey_pem = dir.join(format!("{name}.pub"));
    openssl(&[
        "pkey",
        "-pubin",
        "-inform",
        "DER",
        "-in",
        spki_path.to_str().unwrap(),
        "-out",
        pubkey_pem.to_str().unwrap(),
    ]);
    let throwaway = generate_key(dir, &format!("{name}-throwaway"), "EC");
    let csr = dir.join(format!("{name}.csr"));
    let ext = dir.join(format!("{name}.ext"));
    let pem = dir.join(format!("{name}.pem"));
    let der_path = dir.join(format!("{name}.der"));
    std::fs::write(&ext, CLIENT_EXTENSIONS).unwrap();
    openssl(&[
        "req",
        "-new",
        "-key",
        throwaway.to_str().unwrap(),
        "-subj",
        &format!("/CN={name}"),
        "-out",
        csr.to_str().unwrap(),
    ]);
    openssl(&[
        "x509",
        "-req",
        "-in",
        csr.to_str().unwrap(),
        "-force_pubkey",
        pubkey_pem.to_str().unwrap(),
        "-CA",
        issuer.certificate_pem.to_str().unwrap(),
        "-CAkey",
        issuer.key.to_str().unwrap(),
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        ext.to_str().unwrap(),
        "-extensions",
        "v3",
        "-out",
        pem.to_str().unwrap(),
    ]);
    openssl(&[
        "x509",
        "-in",
        pem.to_str().unwrap(),
        "-outform",
        "DER",
        "-out",
        der_path.to_str().unwrap(),
    ]);
    std::fs::read(der_path).unwrap()
}

fn find_module() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("RUSTLS_PKCS11_SOFTHSM_MODULE") {
        return Some(PathBuf::from(path));
    }
    [
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn build_pki(dir: &Path) -> Pki {
    let root = make_ca(dir, "root", None);
    let server = {
        let key = generate_key(dir, "server", "EC");
        sign_request(dir, "server", &key, None, SERVER_EXTENSIONS);
        finish_material(dir, "server", key)
    };
    Pki { root, server }
}

fn openssl(args: &[&str]) {
    let output = Command::new("openssl").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn softhsm(conf: &Path, args: &[&str]) {
    let output = Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", conf)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "softhsm2-util {args:?} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn generate_key(dir: &Path, name: &str, algorithm: &str) -> PathBuf {
    let key = dir.join(format!("{name}.key"));
    let mut args = vec![
        "genpkey",
        "-algorithm",
        algorithm,
        "-out",
        key.to_str().unwrap(),
    ];
    match algorithm {
        "RSA" => args.extend(["-pkeyopt", "rsa_keygen_bits:2048"]),
        "EC" => args.extend(["-pkeyopt", "ec_paramgen_curve:P-256"]),
        _ => unreachable!(),
    }
    openssl(&args);
    key
}

fn finish_material(dir: &Path, name: &str, key: PathBuf) -> Material {
    let certificate_pem = dir.join(format!("{name}.pem"));
    let der = dir.join(format!("{name}.der"));
    openssl(&[
        "x509",
        "-in",
        certificate_pem.to_str().unwrap(),
        "-outform",
        "DER",
        "-out",
        der.to_str().unwrap(),
    ]);
    let key_der = dir.join(format!("{name}.key.der"));
    openssl(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        key.to_str().unwrap(),
        "-outform",
        "DER",
        "-out",
        key_der.to_str().unwrap(),
    ]);
    Material {
        key,
        key_der: std::fs::read(key_der).unwrap(),
        certificate: std::fs::read(der).unwrap(),
        certificate_pem,
    }
}

fn sign_request(dir: &Path, name: &str, key: &Path, issuer: Option<&Material>, extensions: &str) {
    let csr = dir.join(format!("{name}.csr"));
    let ext = dir.join(format!("{name}.ext"));
    let pem = dir.join(format!("{name}.pem"));
    std::fs::write(&ext, extensions).unwrap();
    let subject = format!("/CN={name}");
    let key = key.to_str().unwrap();
    match issuer {
        None => openssl(&[
            "req",
            "-x509",
            "-new",
            "-key",
            key,
            "-subj",
            &subject,
            "-days",
            "2",
            "-extensions",
            "v3",
            "-config",
            ext.to_str().unwrap(),
            "-out",
            pem.to_str().unwrap(),
        ]),
        Some(issuer) => {
            openssl(&[
                "req",
                "-new",
                "-key",
                key,
                "-subj",
                &subject,
                "-out",
                csr.to_str().unwrap(),
            ]);
            openssl(&[
                "x509",
                "-req",
                "-in",
                csr.to_str().unwrap(),
                "-CA",
                issuer.certificate_pem.to_str().unwrap(),
                "-CAkey",
                issuer.key.to_str().unwrap(),
                "-CAcreateserial",
                "-days",
                "2",
                "-extfile",
                ext.to_str().unwrap(),
                "-extensions",
                "v3",
                "-out",
                pem.to_str().unwrap(),
            ]);
        }
    }
}

const CA_EXTENSIONS: &str = "[req]\ndistinguished_name=dn\n[dn]\n[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n";
const CLIENT_EXTENSIONS: &str =
    "[v3]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n";
const SERVER_EXTENSIONS: &str = "[req]\ndistinguished_name=dn\n[dn]\n[v3]\nbasicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n";

fn make_ca(dir: &Path, name: &str, issuer: Option<&Material>) -> Material {
    let key = generate_key(dir, name, "RSA");
    sign_request(dir, name, &key, issuer, CA_EXTENSIONS);
    finish_material(dir, name, key)
}

/// Run one client-authenticated TLS exchange against an in-process rustls
/// server that trusts the PKI root, and return the number of certificates
/// the server received from the client.
pub fn handshake(fixture: &Fixture, identity: &Pkcs11ClientIdentity) -> usize {
    try_handshake(fixture, identity, rustls::DEFAULT_VERSIONS).unwrap()
}

/// [`handshake`] with the client limited to `versions`, returning the error
/// of whichever side failed first instead of panicking.
pub fn try_handshake(
    fixture: &Fixture,
    identity: &Pkcs11ClientIdentity,
    versions: &[&'static SupportedProtocolVersion],
) -> Result<usize, String> {
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(fixture.pki.root.certificate.clone()))
        .unwrap();
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .unwrap();
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(fixture.pki.server.certificate.clone())],
            PrivateKeyDer::Pkcs8(fixture.pki.server.key_der.clone().into()),
        )
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || -> Result<usize, String> {
        let (mut tcp, _) = listener.accept().unwrap();
        let mut connection = ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut stream = rustls::Stream::new(&mut connection, &mut tcp);
        let mut request = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut request)
            .map_err(|error| format!("server: {error}"))?;
        assert_eq!(request, "ping\n");
        stream
            .write_all(b"pong\n")
            .map_err(|error| format!("server: {error}"))?;
        stream.conn.send_close_notify();
        stream
            .conn
            .complete_io(stream.sock)
            .map_err(|error| format!("server: {error}"))?;
        Ok(connection
            .peer_certificates()
            .map_or(0, |certs| certs.len()))
    });

    let mut server_roots = RootCertStore::empty();
    server_roots
        .add(CertificateDer::from(fixture.pki.server.certificate.clone()))
        .unwrap();
    let client_config = ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(server_roots)
        .with_client_cert_resolver(identity.resolver());
    let mut connection = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tcp = TcpStream::connect(address).unwrap();
    let mut stream = rustls::Stream::new(&mut connection, &mut tcp);
    let client = stream
        .write_all(b"ping\n")
        .and_then(|()| {
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            assert_eq!(response, "pong\n");
            Ok(())
        })
        .map_err(|error| format!("client: {error}"));

    let received = server.join().unwrap();
    client.and(received)
}
