#!/usr/bin/env bash
# Build the Linux native test package from a COMMITTED source (never from a dirty tree).
# Usage: build-package.sh <commit-ish> <out-dir>      (run from a clone/worktree of the repository, networkless ok:
#        dependencies are vendored from the local Cargo cache with --offline)
# Produces <out-dir>/build8-linux-native-test-<commit12>/ and a deterministic .tar.gz with its sha256.
# The package is the source tree (git archive), a per-root vendored dependency cache (the declared,
# pinned offline cache; sources are exactly the crates in each Cargo.lock), PACKAGE-MANIFEST.sha256
# (every file) and PACKAGE-IDENTITY.json. The identified runner is
# package/linux-native-test/run-linux-native-tests.sh.
# Vendored roots: consensus, node, crypto-v2, transport-v2 and, when the commit contains it, wallet-core.
# desktop and release-signer are Windows/host components: they are in the source tree (git archive) but are
# NOT vendored (vendoring the desktop would pull the GUI and Windows crates into a Linux package); their
# lockfile hashes are recorded for information. The import identity of those trees is checked against the
# repository history here, at build time (build/check-import-provenance.sh); the check aborts the build.
# The Linux source-path check (build/check-source-paths.pl) runs on the extracted tree, in file-system mode (exactly the
# files the package ships), before vendoring; a finding aborts the build, since such a package could not build or test on
# Linux. PACKAGE-IDENTITY.json names the checker, its sha256 and the result; the runner repeats it as step g0-source-paths.
set -eu
set -o pipefail
umask 077
COMMIT=${1:?commit-ish}; OUT=${2:?out dir}
REPO=$(git rev-parse --show-toplevel)
FULL=$(git -C "$REPO" rev-parse "$COMMIT^{commit}")
TREE=$(git -C "$REPO" rev-parse "$FULL^{tree}")
NAME=build8-linux-native-test-${FULL:0:12}
PKG="$OUT/$NAME"
[ ! -e "$PKG" ] || { echo "refusing to overwrite $PKG" >&2; exit 2; }
mkdir -p "$OUT"
mkdir -m 0700 "$PKG"
git -C "$REPO" archive --format=tar "$FULL" | tar -x -C "$PKG"
# Private machine-identifying evidence must never be in the package.
if find "$PKG" \( -iname 'NODE-A-*' -o -iname '*LIVE-TPM*' -o -iname '*.sqlite*' -o -iname '*.wallet' -o -iname '*.test-value-backup' \) | grep -q .; then
  echo "ABORT: private or generated evidence present in the archive" >&2; exit 3
fi
# Import identity: the wallet and release-signer trees and the public fixture must equal their identity-verified
# imports (or carry an explicit, recorded edit). Checked against the repository history, not just the archive.
PROV="not-checked: this commit has no build/check-import-provenance.sh"
if [ -f "$PKG/build/check-import-provenance.sh" ]; then
  GITDIR=$(cd "$REPO" && cd "$(git rev-parse --git-common-dir)" && pwd)
  PROVOUT="$OUT/$NAME.import-provenance.txt"
  if BUILD8_PROVENANCE_GIT_DIR="$GITDIR" bash "$PKG/build/check-import-provenance.sh" > "$PROVOUT" 2>&1; then
    PROV="passed against the repository history at build time ($(grep '^RESULT' "$PROVOUT"))"
  else
    echo "ABORT: import provenance check failed for $FULL (see $PROVOUT)" >&2; exit 8
  fi
fi
# Linux source-path portability of exactly the files the package ships (file-system mode: the package has no .git).
SPATHS="not-checked: this commit has no build/check-source-paths.pl"; SPSHA="absent"
if [ -f "$PKG/build/check-source-paths.pl" ]; then
  SPSHA=$(sha256sum "$PKG/build/check-source-paths.pl" | cut -c1-64)
  SPOUT="$OUT/$NAME.source-paths.txt"
  if perl "$PKG/build/check-source-paths.pl" --root "$PKG" > "$SPOUT" 2>&1; then
    SPATHS="passed on the extracted package at build time ($(tr -d '\r' < "$SPOUT" | grep '^check-source-paths: ' | sed 's/^check-source-paths: //; s/;.*//'))"
  else
    echo "ABORT: the Linux source-path check failed for $FULL (see $SPOUT)" >&2; exit 9
  fi
elif grep -q 'check-source-paths' "$PKG/package/linux-native-test/run-linux-native-tests.sh"; then
  echo "ABORT: the runner of $FULL runs build/check-source-paths.pl but the archive does not contain it" >&2; exit 9
fi
# Vendor each root's locked dependencies from the local cache (declared offline cache).
ROOTS="consensus node crypto-v2 transport-v2"
WC=false
if [ -f "$PKG/wallet-core/Cargo.toml" ]; then ROOTS="$ROOTS wallet-core"; WC=true
else echo "NOTE: $FULL has no wallet-core/ (phase 1 not merged): the package has no wallet-core and its runner reports an incomplete campaign" >&2; fi
for r in $ROOTS; do
  ( cd "$PKG/$r" && cargo vendor --locked --offline --versioned-dirs "../vendor/$r" > "../vendor-$r.config.txt" )
  mkdir -p "$PKG/$r/.cargo"
  printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "../vendor/%s"\n\n[net]\noffline = true\n' "$r" > "$PKG/$r/.cargo/config.toml"
done
# Identity and manifest (the manifest lists every file except itself).
CRATES=0; for r in $ROOTS; do CRATES=$((CRATES + $(ls "$PKG/vendor/$r" | wc -l))); done
RUNNER=$(sha256sum "$PKG/package/linux-native-test/run-linux-native-tests.sh" | cut -c1-64)
{
  printf '{\n  "package": "%s",\n  "source_commit": "%s",\n  "source_tree": "%s",\n' "$NAME" "$FULL" "$TREE"
  printf '  "toolchain": "rustc 1.98.1 (pinned by rust-toolchain.toml); install offline before running",\n'
  printf '  "target": "x86_64-unknown-linux-gnu (the runner refuses any other host)",\n'
  printf '  "runner": "package/linux-native-test/run-linux-native-tests.sh",\n  "runner_sha256": "%s",\n' "$RUNNER"
  printf '  "source_path_checker": "build/check-source-paths.pl",\n  "source_path_checker_sha256": "%s",\n  "source_paths_at_build": "%s",\n' "$SPSHA" "$SPATHS"
  printf '  "wallet_core_included": %s,\n  "vendored_roots": "%s",\n' "$WC" "$ROOTS"
  printf '  "lockfiles": {\n'
  first=1; for r in $ROOTS; do
    [ $first = 1 ] || printf ',\n'; first=0
    printf '    "%s/Cargo.lock": "%s"' "$r" "$(sha256sum "$PKG/$r/Cargo.lock" | cut -c1-64)"
  done; printf '\n  },\n'
  printf '  "not_vendored_lockfiles_for_information": {\n    "desktop/Cargo.lock": "%s",\n    "release-signer/Cargo.lock": "%s"\n  },\n' "$(sha256sum "$PKG/desktop/Cargo.lock" | cut -c1-64)" "$(sha256sum "$PKG/release-signer/Cargo.lock" | cut -c1-64)"
  printf '  "import_provenance_at_build": "%s",\n' "$PROV"
  printf '  "offline_dependency_cache": "vendor/<root> (cargo vendor --locked --offline --versioned-dirs), %s vendored crate directories in total; no git dependencies",\n' "$CRATES"
  printf '  "private_fixtures_included": false,\n'
  printf '  "evidence_class": "NATIVE PASS (offline, TEST-VALUE) at most; see docs/EVIDENCE-CLASSES-V1.md",\n'
  printf '  "not_established": "physical clock qualification, real-TPM evidence, production readiness, release lock"\n}\n'
} > "$PKG/PACKAGE-IDENTITY.json"
( cd "$PKG" && find . -type f ! -name PACKAGE-MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > PACKAGE-MANIFEST.sha256 )
perl "$PKG/build/package-tree.pl" manifest "$PKG"
FILES=$(wc -l < "$PKG/PACKAGE-MANIFEST.sha256")
# Deterministic tarball.
TS=$(git -C "$REPO" show -s --format=%ct "$FULL")
( cd "$OUT" && tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$TS" -cf - "$NAME" | gzip -n -9 > "$NAME.tar.gz" )
( cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )
echo "package: $PKG ($FILES files, $CRATES vendored crates)"
echo "tarball: $OUT/$NAME.tar.gz  $(cut -c1-64 "$OUT/$NAME.tar.gz.sha256")"
echo "manifest sha256: $(sha256sum "$PKG/PACKAGE-MANIFEST.sha256" | cut -c1-64)"
