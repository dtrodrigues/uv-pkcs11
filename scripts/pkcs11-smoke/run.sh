#!/usr/bin/env bash
# PKCS#11 smoke test for the built uv-pkcs11 wheel: provision a SoftHSM token
# with a public-session-visible RSA identity, serve the built wheel from a
# local mTLS package index, and verify that the installed uv presents the
# token identity via an SSL_CLIENT_CERT pkcs11: URI.
#
# Requires: softhsm2-util + the SoftHSM module, openssl, python3, cargo, and
# the uv under test on PATH (override with UV=/path/to/uv). Wheels are served
# from ./dist (override with DIST=...).
set -euo pipefail

UV=${UV:-uv}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
DIST=${DIST:-$REPO_ROOT/dist}

MODULE=""
for candidate in /usr/lib/softhsm/libsofthsm2.so \
                 /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
                 /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so \
                 /usr/lib64/pkcs11/libsofthsm2.so \
                 /usr/local/lib/softhsm/libsofthsm2.so \
                 /opt/homebrew/lib/softhsm/libsofthsm2.so; do
  if [ -e "$candidate" ]; then MODULE=$candidate; break; fi
done
[ -n "$MODULE" ] || { echo "SoftHSM module not found" >&2; exit 1; }

WORK=$(mktemp -d)
SERVER_PID=""
trap '[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"' EXIT

mkdir "$WORK/tokens"
export SOFTHSM2_CONF=$WORK/softhsm2.conf
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
  "$WORK/tokens" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label smoke --so-pin 1234 --pin 1234 >/dev/null

# PKI: a root CA, a server certificate for localhost, and a client identity.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/ca.key" 2>/dev/null
openssl req -x509 -new -key "$WORK/ca.key" -subj /CN=smoke-ca -days 2 -out "$WORK/ca.crt"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/server.key" 2>/dev/null
openssl req -new -key "$WORK/server.key" -subj /CN=localhost -out "$WORK/server.csr"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$WORK/server.ext"
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
  -CAcreateserial -days 2 -extfile "$WORK/server.ext" -out "$WORK/server.crt" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/client.key" 2>/dev/null
openssl req -new -key "$WORK/client.key" -subj /CN=smoke-client -out "$WORK/client.csr"
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > "$WORK/client.ext"
openssl x509 -req -in "$WORK/client.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
  -CAcreateserial -days 2 -extfile "$WORK/client.ext" -out "$WORK/client.crt" 2>/dev/null
# PKCS#1 from OpenSSL 1.x/LibreSSL, PKCS#8 from OpenSSL 3; the provisioning
# example accepts both.
openssl rsa -in "$WORK/client.key" -outform DER -out "$WORK/client.key.der" 2>/dev/null
openssl x509 -in "$WORK/client.crt" -outform DER -out "$WORK/client.der"

cargo run -q -p rustls-pkcs11-identity --example provision-softhsm -- \
  "$MODULE" smoke 1234 "$WORK/client.key.der" "$WORK/client.der" 01

python3 "$SCRIPT_DIR/index_server.py" \
  --packages "$DIST" --cert "$WORK/server.crt" --key "$WORK/server.key" \
  --client-ca "$WORK/ca.crt" --port-file "$WORK/port" \
  > "$WORK/index-server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 100); do
  [ -s "$WORK/port" ] && break
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
  sleep 0.2
done
if [ ! -s "$WORK/port" ]; then
  echo "index server did not start:" >&2
  cat "$WORK/index-server.log" >&2
  exit 1
fi
INDEX="https://localhost:$(cat "$WORK/port")/simple/"

# Run uv from the scratch directory so it does not pick up this repository's
# own [tool.uv] configuration (exclude-newer would filter the dateless wheel).
cd "$WORK"

"$UV" venv -q "$WORK/venv"

echo "--- without a client identity, the handshake must be refused"
set +e
output=$(env -u SSL_CLIENT_CERT SSL_CERT_FILE="$WORK/ca.crt" \
  "$UV" pip install -p "$WORK/venv" --no-cache --index-url "$INDEX" uv-pkcs11 2>&1)
status=$?
set -e
if [ "$status" -eq 0 ]; then
  echo "expected the install to fail without a client certificate" >&2
  exit 1
fi
if ! grep -q "CertificateRequired" <<<"$output"; then
  printf '%s\n' "$output" >&2
  echo "expected a CertificateRequired alert" >&2
  exit 1
fi

echo "--- with the token identity, the install must succeed"
env SSL_CERT_FILE="$WORK/ca.crt" \
  SSL_CLIENT_CERT="pkcs11:token=smoke?module-path=$MODULE" \
  "$UV" pip install -p "$WORK/venv" --no-cache --index-url "$INDEX" uv-pkcs11

echo "PKCS#11 smoke test passed"
