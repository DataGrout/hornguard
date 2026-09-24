#!/bin/sh
# Make the release tag for VERSION after checking everything that has to
# agree first. Pushing the tag is left to you; the release workflow does the
# rest. Usage: tools/tag.sh 0.1.0 [--quick]   (--quick skips the full suite)
set -eu
V="${1:?usage: tools/tag.sh VERSION [--quick]}"
QUICK="${2:-}"
cd "$(dirname "$0")/.."

fail() { echo "tag: $*" >&2; exit 1; }

case "$V" in *[!0-9.]*|"") fail "version must look like 0.1.0, got '$V'";; esac
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || fail "not on main"
[ -z "$(git status --porcelain)" ] || fail "working tree is not clean"
git rev-parse -q --verify "refs/tags/v$V" >/dev/null && fail "tag v$V exists"

pack=$(sed -n "s/^version('\([0-9.]*\)')\./\1/p" pack.pl)
crate=$(sed -n 's/^version = "\([0-9.]*\)"/\1/p' crates/hornguard/Cargo.toml | head -1)
[ "$pack" = "$V" ]  || fail "pack.pl says $pack, not $V"
[ "$crate" = "$V" ] || fail "crates/hornguard/Cargo.toml says $crate, not $V"
grep -q "^## $V\b" CHANGELOG.md || fail "CHANGELOG.md has no '## $V' section"

if [ "$QUICK" = "--quick" ]; then
  make check test-fixtures test-policy
else
  make test
fi

if git config --get user.signingkey >/dev/null 2>&1; then
  git tag -s "v$V" -m "hornguard $V"
  echo "signed tag v$V made"
else
  git tag -a "v$V" -m "hornguard $V"
  echo "annotated tag v$V made (no signing key configured; set user.signingkey to sign)"
fi
echo "next: git push origin v$V   (the release workflow publishes the release)"
