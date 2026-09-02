# uv-pkcs11

**An unofficial fork of [uv](https://github.com/astral-sh/uv)** — the
extremely fast Python package and project manager — with PKCS#11
client-certificate (mTLS) support, so uv can authenticate to package indexes
with keys held in PKCS#11 providers that never expose the private key.

The fork never logs in to a token, so it works with providers whose
certificate and key are usable **without a PIN**: software HSMs, network HSMs
unlocked out of band, and p11-kit-proxied providers configured for loginless
use. Ordinary PIN-protected smart cards and tokens that require `C_Login`
before private-key use are **not supported**. The PKCS#11 support itself is
new (beta): tested end to end against SoftHSM, with limited real-world
provider mileage so far.

This project is not affiliated with or endorsed by Astral. The fork lives at
[github.com/dtrodrigues/uv-pkcs11](https://github.com/dtrodrigues/uv-pkcs11);
for everything except the PKCS#11 additions, see the [upstream
documentation](https://docs.astral.sh/uv).

## Usage

Client-certificate behavior is controlled entirely by `SSL_CLIENT_CERT`:

- **A `pkcs11:` URI** (an RFC 7512 subset) selects a PKCS#11 identity:

  ```console
  $ export SSL_CLIENT_CERT='pkcs11:?module-path=/path/to/pkcs11-module.so'
  $ uv pip install --index-url https://my-mtls-index.example.com/simple/ some-package
  ```

  The path attributes `token`, `serial`, `id` (percent-encoded `CKA_ID`), and
  `object` (certificate label) narrow the match when tokens hold more than
  one identity, for example `pkcs11:id=%01` or `pkcs11:token=MyToken`;
  `type=cert` is accepted, other attributes are rejected. The `module-path`
  query attribute must be an absolute path, and the named module is native
  code loaded into the process — only point it at a module you trust.
  Without a `module-path` query attribute, the p11-kit proxy
  (`p11-kit-proxy.so`; `p11-kit-proxy.dylib` on macOS) is loaded, picking up
  any module registered with
  [p11-kit](https://p11-glue.github.io/p11-glue/p11-kit.html). Exactly one
  identity must match, otherwise uv reports an error naming the candidates.

- **A file path** is a PEM client certificate and key, exactly as in
  upstream uv.

- **Unset** means no client certificate — stock uv behavior. PKCS#11 is
  never activated implicitly.

Notes:

- No PIN is presented and no login is performed: the certificate/key pair
  must be visible in a public session (providers unlocked out of band work
  as-is; PIN-protected devices requiring login will not).
  `pin-value`/`pin-source` URI attributes are rejected.
- RSA only (PKCS#1 v1.5 and PSS with SHA-256/384/512); the identity applies
  only to verified HTTPS connections, never to hosts marked
  `--allow-insecure-host`.
- Only the leaf certificate is sent; intermediates must be known to the
  server.

Known limitations (kept simple on purpose; both surface as TLS handshake
failures rather than discovery-time errors):

- Pairing trusts the provider's `CKA_ID` convention: the certificate's
  public key is not compared against the private key, so a stale or
  mispaired certificate sharing the key's `CKA_ID` is selected and fails
  when the server verifies the handshake signature. Re-provision the token
  so certificate and key match.
- Signature schemes are offered based on `C_GetMechanismList` alone:
  per-mechanism `CKF_SIGN` flags and key-size ranges from
  `C_GetMechanismInfo` are not checked, so a token that lists an RSA
  mechanism it cannot use with the selected key (for example a key outside
  the mechanism's supported size range) fails in `C_Sign` during the
  handshake.

## Installation

```console
$ pip install uv-pkcs11
```

Wheels are built for Linux (x86_64 and aarch64) and macOS (Apple Silicon);
other platforms build from the sdist. The distribution installs the `uv` and
`uvx` commands and therefore **must not be installed alongside the official
`uv` distribution** in the same environment — install one or the other.

## Versioning

Wheel versions mirror the upstream uv release the fork is built from (e.g.
`0.12.9`); `.postN` marks a fork-side re-release of the same upstream base.
`uv self update` support is intentionally not built in — it would replace
this fork with official uv binaries.
