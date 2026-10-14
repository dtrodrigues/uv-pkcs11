#!/usr/bin/env bash
# Rebuild the fork's commit series on top of an upstream tag, one commit per
# concern, from a finished tree. After a rebase (and any fixes committed on
# top of it), this folds follow-up commits into the group that owns the code
# and splits cross-cutting changes by path, then proves that the rebuilt
# series has exactly the content of the tree it started from.
#
# Usage: regroup.sh --tag <upstream-tag> [--final <rev>] [--update-branch]
#                   [--clippy] [--print-table]
#
#   --tag <upstream-tag>  The upstream release the series sits on.
#   --final <rev>         The finished tree to regroup (default: HEAD).
#   --update-branch       Move the checked-out branch to the rebuilt series
#                         (it must be $FORK_RELEASE_BRANCH, default pkcs11,
#                         clean, and at the finished tree).
#   --clippy              Also run clippy at each commit the table marks with
#                         `clippy=<package>`.
#   --print-table         Print the group table as markdown and exit.
#
# The rebuilt series is left at refs/fork-release/regrouped. Nothing is
# fetched, pushed or tagged.
#
# The work happens in a scratch worktree, never in the checkout this script
# lives in: detaching that checkout at the upstream tag would delete
# scripts/fork-release/ while bash is still reading this file.
#
# Requires: git and cargo (for `cargo metadata`; nothing is built unless
# --clippy is given).
set -euo pipefail

# One record per commit, in order: message|flags|paths. Paths are files or
# directories relative to the repository root, separated by spaces. Flags are
# separated by commas:
#   lock          the group changes manifests, so Cargo.lock is resynchronised
#                 before committing
#   pin-lock      Cargo.lock is taken verbatim from the finished tree; this
#                 belongs on the last group that touches it
#   clippy=<pkg>  the commit is code-bearing and must pass clippy for <pkg>
#                 under --clippy
# Cargo.lock is the one file several groups touch, which is why it is handled
# by flags rather than listed as a path.
FORK_RELEASE_GROUPS=(
  "Add rustls-pkcs11-identity crate|lock,clippy=rustls-pkcs11-identity|Cargo.toml crates/rustls-pkcs11-identity"
  "Select PKCS#11 identities with SSL_CLIENT_CERT pkcs11: URIs|lock,clippy=uv-client|crates/uv-client"
  "Identify the fork in version and help output||crates/uv-cli crates/uv-static/src/env_vars.rs crates/uv/tests/it"
  "Add SoftHSM smoke test for built wheels||scripts/pkcs11-smoke"
  "Document PKCS#11 support||README_PKCS11.md .github/README.md"
  "Package as uv-pkcs11|lock,pin-lock|.github/workflows/build-pkcs11-wheel.yml crates/uv/Cargo.toml crates/uv/src/bin/uv-pkcs11-inspect.rs pyproject.toml uv.lock"
  "Add fork CI and workflow linting||.github/workflows/fork-ci.yml .github/workflows/zizmor.yml"
  "Add fork release tooling||scripts/fork-release"
)

BRANCH=${FORK_RELEASE_BRANCH:-pkcs11}

die() {
  echo "regroup: $*" >&2
  exit 1
}

group_message() { printf '%s' "${1%%|*}"; }
group_flags() {
  local rest=${1#*|}
  printf '%s' "${rest%%|*}"
}
group_paths() { printf '%s' "${1##*|}"; }

has_flag() {
  case ",$1," in
    *",$2,"*) return 0 ;;
    *) return 1 ;;
  esac
}

# The package named by a `clippy=<pkg>` flag, or nothing.
clippy_package() {
  local flag
  local IFS=,
  for flag in $1; do
    case "$flag" in
      clippy=*) printf '%s' "${flag#clippy=}" ;;
    esac
  done
}

# Whether path $1 is one of the space-separated entries in $2 or sits under
# one of them.
path_in() {
  local entry
  for entry in $2; do
    if [ "$1" = "$entry" ]; then return 0; fi
    case "$1" in
      "$entry"/*) return 0 ;;
    esac
  done
  return 1
}

validate_table() {
  local group rest flags last_lock="" pin_count=0 pin_group=""
  for group in "${FORK_RELEASE_GROUPS[@]}"; do
    rest=${group#*|}
    case "${rest#*|}" in
      *"|"*) die "malformed table record (expected message|flags|paths): $group" ;;
    esac
    [ -n "$(group_message "$group")" ] || die "table record without a message: $group"
    [ -n "$(group_paths "$group")" ] || die "table record without paths: $group"
    flags=$(group_flags "$group")
    if has_flag "$flags" lock; then last_lock=$group; fi
    if has_flag "$flags" pin-lock; then
      pin_count=$((pin_count + 1))
      pin_group=$group
    fi
  done
  [ "$pin_count" -eq 1 ] || die "exactly one group must carry pin-lock, found $pin_count"
  [ "$pin_group" = "$last_lock" ] ||
    die "pin-lock must be on the last group that carries lock, so every later commit keeps the final Cargo.lock"
}

print_table() {
  local group path cell index=0
  echo "| Group | Paths |"
  echo "| --- | --- |"
  for group in "${FORK_RELEASE_GROUPS[@]}"; do
    index=$((index + 1))
    cell=""
    for path in $(group_paths "$group"); do
      if [ "$(git cat-file -t "HEAD:$path" 2>/dev/null)" = tree ]; then path="$path/"; fi
      cell="${cell:+$cell, }\`$path\`"
    done
    echo "| $index. $(group_message "$group") | $cell |"
  done
}

TAG=""
FINAL=HEAD
UPDATE_BRANCH=false
CLIPPY=false
PRINT_TABLE=false
while [ $# -gt 0 ]; do
  case "$1" in
    --tag)
      [ $# -ge 2 ] || die "--tag needs a value"
      TAG=$2
      shift 2
      ;;
    --final)
      [ $# -ge 2 ] || die "--final needs a value"
      FINAL=$2
      shift 2
      ;;
    --update-branch)
      UPDATE_BRANCH=true
      shift
      ;;
    --clippy)
      CLIPPY=true
      shift
      ;;
    --print-table)
      PRINT_TABLE=true
      shift
      ;;
    -h | --help)
      sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "unknown argument \`$1\` (see --help)" ;;
  esac
done

REPO_ROOT=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
cd "$REPO_ROOT"

validate_table
if $PRINT_TABLE; then
  print_table
  exit 0
fi

[ -n "$TAG" ] || die "--tag <upstream-tag> is required (see --help)"
TAG_SHA=$(git rev-parse -q --verify "$TAG^{commit}") || die "\`$TAG\` is not a commit"
FINAL_SHA=$(git rev-parse -q --verify "$FINAL^{commit}") || die "\`$FINAL\` is not a commit"
git merge-base --is-ancestor "$TAG_SHA" "$FINAL_SHA" ||
  die "\`$TAG\` is not an ancestor of \`$FINAL\`; rebase onto it first"

ALL_PATHS=""
for group in "${FORK_RELEASE_GROUPS[@]}"; do
  ALL_PATHS="$ALL_PATHS $(group_paths "$group")"
done

# Every path the fork changes must belong to a group: the series is rebuilt
# from the table alone, so an unlisted path would silently vanish.
unmapped=""
while IFS= read -r path; do
  [ -n "$path" ] || continue
  [ "$path" = Cargo.lock ] && continue
  path_in "$path" "$ALL_PATHS" || unmapped="$unmapped  $path"$'\n'
done <<EOF_PATHS
$(git diff --name-only "$TAG_SHA" "$FINAL_SHA")
EOF_PATHS
if [ -n "$unmapped" ]; then
  echo "regroup: these paths differ from $TAG but belong to no group:" >&2
  printf '%s' "$unmapped" >&2
  die "add them to FORK_RELEASE_GROUPS in $0 (and to the table in release.md)"
fi

WORK=$(mktemp -d)
TREE=$WORK/tree
cleanup() {
  git -C "$REPO_ROOT" worktree remove --force "$TREE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
git worktree add -q --detach "$TREE" "$TAG_SHA"

# Resynchronise Cargo.lock with the manifests staged so far. Seeding it with
# the finished tree's lockfile makes cargo keep those exact versions and only
# prune the packages this commit does not reach yet, so the intermediate
# lockfiles never drift to whatever the registry offers today.
sync_lock() {
  git -C "$TREE" checkout -q "$FINAL_SHA" -- Cargo.lock
  (cd "$TREE" && { cargo metadata --offline --format-version 1 >/dev/null 2>&1 ||
    cargo metadata --format-version 1 >/dev/null; }) ||
    die "cargo metadata failed while resynchronising Cargo.lock"
}

echo "Regrouping $(git rev-parse --short "$FINAL_SHA") onto $TAG"
for group in "${FORK_RELEASE_GROUPS[@]}"; do
  message=$(group_message "$group")
  flags=$(group_flags "$group")
  paths=$(group_paths "$group")

  # `git checkout <tree> -- <path>` never removes files, so deletions the
  # fork makes are staged explicitly.
  # shellcheck disable=SC2086
  git -C "$TREE" diff --name-only --diff-filter=D "$TAG_SHA" "$FINAL_SHA" -- $paths |
    while IFS= read -r deleted; do
      git -C "$TREE" rm -q --ignore-unmatch -- "$deleted"
    done

  present=""
  for path in $paths; do
    if git cat-file -e "$FINAL_SHA:$path" 2>/dev/null; then
      present="$present $path"
    elif [ -z "$(git diff --name-only "$TAG_SHA" "$FINAL_SHA" -- "$path")" ]; then
      echo "regroup: warning: table path \`$path\` matches nothing" >&2
    fi
  done
  if [ -n "$present" ]; then
    # shellcheck disable=SC2086
    git -C "$TREE" checkout -q "$FINAL_SHA" -- $present
  fi

  if has_flag "$flags" lock; then sync_lock; fi
  if has_flag "$flags" pin-lock; then
    git -C "$TREE" checkout -q "$FINAL_SHA" -- Cargo.lock
  fi
  git -C "$TREE" add -A

  allowed=$paths
  if has_flag "$flags" lock; then allowed="$allowed Cargo.lock"; fi
  while IFS= read -r staged; do
    [ -n "$staged" ] || continue
    path_in "$staged" "$allowed" ||
      die "\`$staged\` was staged for \"$message\" but is not one of its paths"
  done <<EOF_STAGED
$(git -C "$TREE" diff --cached --name-only)
EOF_STAGED

  git -C "$TREE" diff --cached --quiet && die "nothing to commit for \"$message\""
  git -C "$TREE" commit -q -m "$message"
  echo "  $(git -C "$TREE" rev-parse --short HEAD) $message"
done
NEW_SHA=$(git -C "$TREE" rev-parse HEAD)

# The rebuild must be content-preserving.
if ! git diff --quiet "$FINAL_SHA" "$NEW_SHA"; then
  git --no-pager diff --stat "$FINAL_SHA" "$NEW_SHA" >&2
  die "the regrouped series differs from $FINAL (see above)"
fi
[ "$(git rev-parse "$FINAL_SHA^{tree}")" = "$(git rev-parse "$NEW_SHA^{tree}")" ] ||
  die "tree hashes differ between $FINAL and the regrouped series"

expected=""
for group in "${FORK_RELEASE_GROUPS[@]}"; do
  expected="$expected$(group_message "$group")"$'\n'
done
actual=$(git log --reverse --format=%s "$TAG_SHA..$NEW_SHA")$'\n'
[ "$expected" = "$actual" ] || die "the regrouped commit subjects do not match the table"

# Every commit must stand on its own, so bisect works.
echo "Checking each commit"
for commit in $(git rev-list --reverse "$TAG_SHA..$NEW_SHA"); do
  git -C "$TREE" checkout -q --detach "$commit"
  subject=$(git log -1 --format='%h %s' "$commit")
  (cd "$TREE" && cargo metadata --offline --locked --format-version 1 >/dev/null 2>&1) ||
    die "Cargo.lock is stale at $subject"
  echo "  lock ok  $subject"
done
if $CLIPPY; then
  index=0
  for commit in $(git rev-list --reverse "$TAG_SHA..$NEW_SHA"); do
    package=$(clippy_package "$(group_flags "${FORK_RELEASE_GROUPS[$index]}")")
    index=$((index + 1))
    [ -n "$package" ] || continue
    git -C "$TREE" checkout -q --detach "$commit"
    subject=$(git log -1 --format='%h %s' "$commit")
    echo "  clippy -p $package at $subject"
    # Share the main checkout's build cache rather than rebuilding uv.
    (cd "$TREE" && CARGO_TARGET_DIR="$REPO_ROOT/target" \
      cargo clippy --locked -p "$package" --all-targets -- -D warnings) ||
      die "clippy failed for $package at $subject"
  done
fi

git update-ref refs/fork-release/regrouped "$NEW_SHA"
echo "Regrouped series: refs/fork-release/regrouped ($(git rev-parse --short "$NEW_SHA")), identical in content to $FINAL"

if $UPDATE_BRANCH; then
  [ "$(git symbolic-ref -q --short HEAD)" = "$BRANCH" ] ||
    die "--update-branch needs \`$BRANCH\` checked out"
  if ! git diff --quiet || ! git diff --cached --quiet; then
    die "--update-branch needs a clean working tree"
  fi
  [ "$(git rev-parse "HEAD^{tree}")" = "$(git rev-parse "$NEW_SHA^{tree}")" ] ||
    die "--update-branch needs \`$BRANCH\` to be at the finished tree"
  git reset -q --hard "$NEW_SHA"
  echo "Moved $BRANCH to $(git rev-parse --short "$NEW_SHA")"
else
  echo "To adopt it:  git reset --hard $(git rev-parse --short "$NEW_SHA")    (on $BRANCH, with a clean tree)"
fi
