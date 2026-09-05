# rustls-pkcs11-identity

`rustls-pkcs11-identity` provides a PKCS#11-backed client-certificate resolver
for rustls. The certificate chain is read from the token, while TLS signatures
are delegated to the matching non-extractable private key. No login is ever
performed, so the identity must be usable without a PIN; PIN-protected devices
that require `C_Login` before private-key use are not supported.

```rust
use rustls_pkcs11_identity::Pkcs11ClientIdentity;

// From a `pkcs11:` URI (RFC 7512 subset):
let identity =
    Pkcs11ClientIdentity::from_uri("pkcs11:id=%01?module-path=/path/to/pkcs11-module.so")?;
// Or name the module and `CKA_ID` directly:
let identity = Pkcs11ClientIdentity::load("/path/to/pkcs11-module.so", Some(&[0x01]))?;

let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_client_cert_resolver(identity.resolver());
```

## Detection

The crate opens every initialized token the module exposes and pairs each
X.509 certificate with the signing-capable RSA private key sharing its
`CKA_ID`, the pairing convention PKCS#11 providers use. Exactly one such pair
must exist across all tokens; otherwise an ambiguity (or "no identity") error
is returned rather than depending on enumeration order.

Pairing trusts `CKA_ID` alone: the certificate's public key is not compared
against the private key, so a stale or mispaired certificate sharing the
key's `CKA_ID` is selected and fails only when the server verifies the TLS
handshake signature.

When a token holds several identities, the URI's `id` attribute selects one
by its `CKA_ID` (percent-encoded, e.g. `id=%01`), and `token`, `serial`, and
`object` narrow further. `CKA_ID` is the portable selector: every provider
supports searching by it, and it is stable across sessions, unlike slot
numbers or object handles.

Only the certificate itself is sent to the server; any intermediate CA
certificates must already be known to the server.

## PKCS#11 URIs

`Pkcs11ClientIdentity::from_uri` accepts an RFC 7512 subset:

```text
pkcs11:token=…;serial=…;id=%01;object=…?module-path=/path/to/module.so
```

The path attributes (`token`, `serial`, `id`, `object`, and the no-op
`type=cert`) are optional filters that combine conjunctively; exactly one
identity must match. Other RFC 7512 attributes are rejected rather than
ignored. `module-path` must be an absolute path — the module is native code
loaded into the process and must be trusted. Without `module-path`, the
p11-kit proxy is loaded by soname (`p11-kit-proxy.so`; `p11-kit-proxy.dylib`
on macOS).
`pin-value` and `pin-source` are rejected: no login is ever performed.

No PIN is presented and no login is performed: whatever the provider exposes
in a public session is used. This suits providers that are unlocked out of
band or need no login; tokens that hide their keys until login will not yield
an identity.

## Algorithms

RSA PKCS#1 v1.5 and RSA-PSS with SHA-256, SHA-384, and SHA-512. The token's
`CKM_SHAxxx_RSA_PKCS[_PSS]` mechanisms are preferred; when only the raw
`CKM_RSA_PKCS` and `CKM_RSA_PKCS_PSS` mechanisms are listed, the handshake
transcript is hashed in process and the token pads and signs the digest.
Per-mechanism `CKF_SIGN` flags and key-size ranges from `C_GetMechanismInfo`
are not checked, so a mechanism the token lists but cannot use with the
selected key fails in `C_Sign` at handshake time.

## Operational notes

- Signing runs synchronously inside the rustls handshake while holding a lock
  on the token session. Local tokens sign in milliseconds; network HSMs will
  block the calling thread for a round trip.
- Modules are initialized once per process and kept loaded for its lifetime.
  Loading the same module twice reuses the initialized module.

## Inspecting a module

`rustls-pkcs11-inspect` (built by default, no extra dependencies) lists the
tokens, certificates, and private keys a module exposes without login and
applies the same detection rules as the client, so its verdict is what
`from_uri` will do. It takes a module path or the same `pkcs11:` URI the
client uses (with no argument, the p11-kit proxy is inspected), and exits 0
when exactly one identity would be selected:

```console
$ rustls-pkcs11-inspect /path/to/pkcs11-module.so
Module: /path/to/pkcs11-module.so

Token `MyToken` (slot 1)
  Signing: RSA_PSS_SHA512, RSA_PSS_SHA384, RSA_PSS_SHA256, RSA_PKCS1_SHA512, ...
  Certificates: 1
    CKA_ID 3f9a…         label `My Certificate`
  Private keys: 1
    CKA_ID 3f9a…         label `My Key`  RSA_PSS_SHA512, RSA_PSS_SHA384, ...

OK: exactly one usable identity across all tokens: token `MyToken`, CKA_ID 3f9a….
```

With several identities it prints `AMBIGUOUS` and their `CKA_ID`s; add an
`id=`, `token=`, or `object=` attribute to the URI to check a specific one.
With none it prints `NOT USABLE` and a hint (for example that nothing is
visible without login).

## Testing

`cargo test` runs end-to-end scenarios against SoftHSM when `softhsm2-util`,
`openssl`, and the SoftHSM module are available (set
`RUSTLS_PKCS11_SOFTHSM_MODULE` to point at a non-standard module path). Each
scenario is its own test binary because a SoftHSM configuration is
process-global: it provisions a scratch token directory, generates RSA key
pairs on the token as public objects, issues certificates for them with a
software CA, and completes client-authenticated TLS handshakes against an
in-process rustls server. Without SoftHSM the scenarios are skipped.
