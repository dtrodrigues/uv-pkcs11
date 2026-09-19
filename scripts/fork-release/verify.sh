#!/usr/bin/env bash
# Check the fork's own changes on the current checkout: formatting, clippy,
# the SoftHSM-backed helper tests, the uv-client unit tests, and the README
# symlink GitHub renders. These are the checks Fork CI runs, so a tree that
# passes here should pass there.
#
# Usage: verify.sh [--full]
#
#   --full  Also check that Cargo.lock is consistent and that the whole
#           workspace compiles. After a rebase this is what finds upstream
#           code that no longer handles the fork's additions, such as a new
#           exhaustive `match` over an enum the fork extends.
#
# Requires: cargo with rustfmt and clippy, softhsm2-util with the SoftHSM
# module, and openssl. The helper tests skip silently when a tool is missing,
# so a skipped scenario is treated as a failure. Nothing is built with the
# release profile.
set -euo pipefail

FULL=false
while [ $# -gt 0 ]; do
  case "$1" in
    --full)
      FULL=true
      shift
      ;;
    -h | --help)
      sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "verify: unknown argument \`$1\` (see --help)" >&2
      exit 1
      ;;
  esac
done

cd "$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

# Run one named check, stopping at the first failure.
step() {
  local name=$1
  shift
  echo "--- $name"
  if ! "$@"; then
    echo "verify: FAILED: $name" >&2
    exit 1
  fi
}

tools_present() {
  softhsm2-util --version >/dev/null && openssl version >/dev/null
}

helper_tests() {
  # The log lives outside the checkout so it can never be committed. `step`
  # calls this from an `if`, where `set -e` is suspended, so the pipeline's
  # status is checked explicitly.
  if ! cargo test --locked -p rustls-pkcs11-identity -- --nocapture 2>&1 | tee "$LOG"; then
    return 1
  fi
  if grep -q "skipping:" "$LOG"; then
    echo "SoftHSM scenarios were skipped; a required tool is missing" >&2
    return 1
  fi
}

lock_consistent() {
  cargo metadata --locked --format-version 1 >/dev/null
}

readme_symlink() {
  [ -L .github/README.md ] && [ "$(readlink .github/README.md)" = "../README_PKCS11.md" ]
}

step "SoftHSM and OpenSSL are available" tools_present
if $FULL; then
  step "Cargo.lock is consistent" lock_consistent
  step "Workspace compiles" cargo check --locked --workspace --all-targets
fi
step "Format" cargo fmt -p rustls-pkcs11-identity -p uv-client -p uv -- --check
step "Clippy" cargo clippy --locked -p rustls-pkcs11-identity -p uv-client --all-targets -- -D warnings
step "Clippy (uv-pkcs11-inspect)" cargo clippy --locked -p uv --bin uv-pkcs11-inspect -- -D warnings
step "Helper crate tests (SoftHSM)" helper_tests
step "uv-client unit tests" cargo test --locked -p uv-client --lib
step ".github/README.md links to ../README_PKCS11.md" readme_symlink

echo "verify: all checks passed"
