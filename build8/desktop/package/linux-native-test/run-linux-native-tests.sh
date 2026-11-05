#!/usr/bin/env bash
# Build 8 Linux native test runner (offline, software-only). Every pass it records is at most
# "NATIVE PASS (offline, TEST-VALUE)" (docs/EVIDENCE-CLASSES-V1.md). Tests that need private or
# physical evidence are #[ignore]d and are listed as SKIPPED-PHYSICAL, never counted as passed.
# This is NOT physical clock qualification, a real-TPM result, production readiness or release lock.
#
# Safety: refuses root; runs in a SEPARATE workspace (nothing is written into the package); uses an
# EMPTY CARGO_HOME; blocks sudo/ssh/scp/sftp/pkexec and every tpm2_* tool with tripwire shims that
# record any attempt (the run FAILS if one is recorded); never touches custody, never clears or
# provisions a TPM, never installs a service, never initialises Genesis. An inherited BUILD8_ONLY
# environment variable is IGNORED (and recorded); a focused rerun needs the explicit --only option and
# is then reported as an incomplete campaign.
#
# Components: consensus, node, crypto-v2, transport-v2 and, once phase 1 has created it, wallet-core
# (compile gates, debug and release suites and the release check; plus the NON-SHIPPING
# test-value-signing rehearsal steps, labelled as such). The Windows wallet (desktop) and the release
# signer are Windows/host components and are NOT run here (see package/windows-wallet-test). If wallet-core/
# is absent from the source, its steps are not declared and the campaign is reported as incomplete.
# The first step, g0-source-paths, runs build/check-source-paths.pl over the package: Linux (POSIX) path semantics for
# every #[path], include!/include_str!/include_bytes!, mod declaration, Cargo.toml path and build-script input (exact
# case, no lexical `..`), CRLF scripts and case-colliding names. It is recorded like every step (a finding fails the
# campaign) but does not gate the compile steps g1-g9, which stay the authoritative compile gate.
#
# Usage: run-linux-native-tests.sh [--dry-run] [--allow-non-linux] [--debug-only] [--release-only]
#                                  [--only "step names"]
# Environment: BUILD8_WORKSPACE (default $HOME/build8-linux-test-<UTC stamp>; must not exist),
#              BUILD8_TEST_THREADS (default 4), BUILD8_ARCHIVE_SHA256 (recorded).
set -u
set -o pipefail
umask 077
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC=${BUILD8_SRC:-$(cd "$HERE/../.." && pwd)}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WS=${BUILD8_WORKSPACE:-$HOME/build8-linux-test-$STAMP}
OUT="$WS/evidence"; TARGET="$WS/target"; export CARGO_HOME="$WS/cargo-home"
THREADS=${BUILD8_TEST_THREADS:-4}
WANT_RUSTC=1.98.1
INHERITED_ONLY="${BUILD8_ONLY:-}"; unset BUILD8_ONLY
DRY=0; ALLOW_NON_LINUX=0; DO_DEBUG=1; DO_RELEASE=1; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --allow-non-linux) ALLOW_NON_LINUX=1 ;;
    --debug-only) DO_RELEASE=0 ;;
    --release-only) DO_DEBUG=0 ;;
    --only) shift; ONLY="${1:-}" ;;
    *) echo "unknown option $1" >&2; exit 64 ;;
  esac; shift
done
[ "$(id -u)" != 0 ] || { echo "ABORT: refusing to run as root" >&2; exit 2; }
[ ! -e "$WS" ] || { echo "ABORT: workspace $WS already exists (a fresh, separate workspace is required)" >&2; exit 65; }
# Create only this owned workspace; never reuse or repair existing ancestors.
case "$WS" in /*) ;; *) echo "ABORT: workspace must be an absolute path" >&2; exit 65 ;; esac
case "/$WS/" in */../*|*/./*) echo "ABORT: workspace cannot contain dot path components" >&2; exit 65 ;; esac
SRC_REAL=$(cd "$SRC" && pwd -P) || exit 65
WS_PARENT_REAL=$(cd "$(dirname "$WS")" && pwd -P) || exit 65
case "$WS_PARENT_REAL/$(basename "$WS")/" in "$SRC_REAL/"*) echo "ABORT: workspace cannot be inside source/package" >&2; exit 65 ;; esac
mkdir -m 0700 "$WS" || exit 65
mkdir -m 0700 "$OUT" "$TARGET" "$CARGO_HOME" "$WS/tmp" || exit 65
export TMPDIR="$WS/tmp"
if [ "$(uname -s)" != Linux ] && command -v cygpath >/dev/null 2>&1; then
  export TMP="$(cygpath -w "$TMPDIR")" TEMP="$(cygpath -w "$TMPDIR")"
fi
ANCESTORS="$OUT/ancestors.txt"
: > "$ANCESTORS"
if [ "$(uname -s)" = Linux ]; then
  source "$SRC/build/check-test-ancestors.sh"
  check_ancestors "$WS" workspace "$ANCESTORS" || exit 65
  # Package ancestor failures are diagnostics; tests write only below workspace TMPDIR.
  check_ancestors "$SRC" package "$ANCESTORS" >> "$OUT/package-ancestor-diagnostics.log" 2>&1 || true
else
  printf 'Unix owner/mode preflight NOT VERIFIED on non-Linux host\n' >> "$ANCESTORS"
fi
RUNNER_SHA=$(sha256sum "${BASH_SOURCE[0]}" | cut -c1-64)
RES="$OUT/results.tsv"
printf 'step\tprofile\tclass\texit\tseconds\tlog_sha256\n' > "$RES"
say() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
FAILS=0
COMPLETE=1
if [ -n "$ONLY" ] || [ "$DO_DEBUG" = 0 ] || [ "$DO_RELEASE" = 0 ]; then COMPLETE=0; fi
[ -z "$INHERITED_ONLY" ] || say "NOTE: inherited BUILD8_ONLY='$INHERITED_ONLY' was IGNORED and unset (use --only for a focused rerun)"

# ---- preconditions ---------------------------------------------------------------------------
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  if [ "$ALLOW_NON_LINUX" = 1 ]; then say "WARNING: not Linux x86_64; results are NOT Linux evidence"
  else say "ABORT: this runner requires Linux x86_64 (use --allow-non-linux only to test the script itself)"; exit 2; fi
fi
CCBIN=""
for c in cc gcc clang; do
  if command -v "$c" >/dev/null 2>&1; then CCBIN=$c; break; fi
done
if [ -z "$CCBIN" ]; then
  if [ "$ALLOW_NON_LINUX" = 1 ]; then say "WARNING: no cc/gcc/clang on PATH; a host compiler (for example MSVC) is assumed because this is the --allow-non-linux self-test"; CCBIN=cc
  else say "ABORT: no C compiler (cc, gcc or clang) found: the crypto and sqlite build scripts need one"; exit 6; fi
fi
for t in ar sha256sum grep sed awk tr date uname tee perl; do
  if ! command -v "$t" >/dev/null 2>&1; then
    if [ "$t" = ar ] && [ "$ALLOW_NON_LINUX" = 1 ]; then say "WARNING: 'ar' not on PATH (--allow-non-linux self-test only)"
    else say "ABORT: required tool '$t' missing"; exit 6; fi
  fi
done
RUSTC_V=$(cd "$SRC" && rustc -V 2>&1 | head -1)
case "$RUSTC_V" in *"$WANT_RUSTC"*) ;; *) say "ABORT: rustc $WANT_RUSTC required (rust-toolchain.toml pin), found: $RUSTC_V"; exit 3 ;; esac
[ -z "$(ls -A "$CARGO_HOME" 2>/dev/null)" ] || { say "ABORT: CARGO_HOME $CARGO_HOME is not empty"; exit 7; }
ROOTS="consensus node crypto-v2 transport-v2"
# wallet-core/ is created by phase 1. When it is part of the source its steps are declared and REQUIRED; when it is
# absent the campaign says so and can never be reported complete (a package built before phase 1 has no wallet-core evidence).
WC=0
if [ -e "$SRC/wallet-core" ]; then WC=1; ROOTS="$ROOTS wallet-core"
else say "NOTE: wallet-core/ is absent from this source (phase 1 not merged): its steps are NOT declared and this campaign cannot be complete"; COMPLETE=0; fi
for r in $ROOTS; do
  [ -f "$SRC/$r/Cargo.lock" ] || { say "ABORT: $r/Cargo.lock missing"; exit 5; }
  if [ -f "$SRC/PACKAGE-IDENTITY.json" ]; then
    [ -f "$SRC/$r/.cargo/config.toml" ] || { say "ABORT: $r/.cargo/config.toml (vendored-source replacement) missing"; exit 5; }
  fi
done
# Manifest verification (the archive hash is verified by the operator BEFORE extraction).
MANIFEST_OK="not-present"
if [ -f "$SRC/PACKAGE-MANIFEST.sha256" ]; then
  if perl "$SRC/build/package-tree.pl" manifest "$SRC" >> "$OUT/run.log" 2>&1; then
    MANIFEST_OK="verified-before-run"; say "package manifest verified"
  else say "ABORT: package manifest verification failed"; exit 4; fi
else say "NOTE: no PACKAGE-MANIFEST.sha256 beside the sources (running from a plain checkout)"; fi
[ -f "$SRC/PACKAGE-IDENTITY.json" ] && cp "$SRC/PACKAGE-IDENTITY.json" "$OUT/"
ARCHIVE_SHA="${BUILD8_ARCHIVE_SHA256:-unrecorded}"
perl "$SRC/build/package-tree.pl" snapshot "$SRC" > "$OUT/package-tree-before.txt" || exit 4
# Every rustc subprocess inherits remapping, including shipping checks. Preserve
# caller flag arguments and include native Windows spellings in package-form tests.
append_remap() {
  local from=$1 to=$2
  [ -n "$from" ] || return 0
  local native="$from"
  if command -v cygpath >/dev/null 2>&1; then native=$(cygpath -m "$from"); fi
  CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS:+$CARGO_ENCODED_RUSTFLAGS$'\x1f'}--remap-path-prefix=$from=$to"
  if [ "$native" != "$from" ]; then CARGO_ENCODED_RUSTFLAGS+=$'\x1f'"--remap-path-prefix=$native=$to"; fi
}
if [ -n "${RUSTFLAGS:-}" ]; then
  say "ABORT: inherited RUSTFLAGS requires explicit encoded arguments; use CARGO_ENCODED_RUSTFLAGS to preserve exact argument boundaries"; exit 64
fi
append_remap "${HOME:-}" /build8/home
append_remap "${USERPROFILE:-}" /build8/home
append_remap "$WS" /build8/workspace
append_remap "$SRC" /build8/source
export CARGO_ENCODED_RUSTFLAGS
if [ "$(uname -s)" = Linux ]; then
  export CFLAGS="${CFLAGS:-} -ffile-prefix-map=$SRC=/build8/source -ffile-prefix-map=$WS=/build8/workspace -ffile-prefix-map=$HOME=/build8/home"
fi

# ---- environment record ----------------------------------------------------------------------
{
  echo "utc $(date -u +%FT%TZ)"; echo "runner_sha256 $RUNNER_SHA"; echo "archive_sha256 $ARCHIVE_SHA"
  echo "umask $(umask)"; echo "TMPDIR $TMPDIR"; cat "$ANCESTORS";
  echo "path_remapping source=/build8/source workspace=/build8/workspace home=/build8/home"
  echo "src $SRC"; echo "workspace $WS"; echo "threads $THREADS"; echo "user $(id -un) uid=$(id -u) groups=$(id -Gn)"
  echo "wallet_core $( [ "$WC" = 1 ] && echo present || echo ABSENT )"
  echo "--- uname"; uname -a; echo "--- os-release"; cat /etc/os-release 2>/dev/null
  echo "--- toolchain"; (cd "$SRC" && rustc -Vv; cargo -V; command -v rustup >/dev/null 2>&1 && rustup show active-toolchain)
  echo "--- C toolchain"; "$CCBIN" --version | head -1; ar --version 2>&1 | head -1; ld --version 2>&1 | head -1; ldd --version 2>&1 | head -1
  echo "--- bash and sha256sum"; bash --version | head -1; sha256sum --version | head -1
  echo "--- resources"; nproc 2>&1; free -m 2>&1; df -Pk "$WS" 2>&1
  echo "--- TPM device nodes and this user's access (the tests never open them; recorded only)"; ls -l /dev/tpm0 /dev/tpmrm0 2>&1
  echo "--- environment names that influence the build (values omitted)"
  env | grep -E '^(RUSTUP_|CARGO_|RUSTFLAGS|BUILD8_|MUTINYD_|NATIVE_)' | sed -E 's/=.*/=<value omitted>/' | sort
} > "$OUT/environment.txt" 2>&1
export CARGO_NET_OFFLINE=true CARGO_TERM_COLOR=never

# ---- tripwires: any attempt to use ssh/sudo/TPM tools is blocked and recorded ------------------
TRIP="$OUT/tripwire-bin"; export BUILD8_TRIPWIRE_LOG="$OUT/tripwire.log"; mkdir -p "$TRIP"; : > "$BUILD8_TRIPWIRE_LOG"
for t in sudo ssh scp sftp pkexec doas su tpm2 tpm2_clear tpm2_startup tpm2_shutdown tpm2_createprimary tpm2_create tpm2_load tpm2_evictcontrol tpm2_nvdefine tpm2_nvwrite tpm2_nvread tpm2_nvundefine tpm2_nvincrement tpm2_hierarchycontrol tpm2_changeauth tpm2_dictionarylockout tpm2_sign tpm2_quote tpm2_certify tpm2_activatecredential tpm2_makecredential tpm2_getrandom tpm2_pcrread tpm2_pcrextend tpm2_flushcontext tpm2_unseal tpm2_getcap; do
  {
    echo '#!/bin/sh'
    echo 'printf "%s tripwire: %s %s\n" "$(date -u +%FT%TZ)" "$(basename "$0")" "$*" >> "${BUILD8_TRIPWIRE_LOG:-/dev/null}"'
    echo "echo 'BUILD8 TRIPWIRE: $t is blocked during the software-only TEST-VALUE campaign' >&2"
    echo 'exit 126'
  } > "$TRIP/$t"
  chmod +x "$TRIP/$t"
done
export PATH="$TRIP:$PATH"
if [ "$DRY" = 1 ]; then say "dry run: preconditions ok (rustc: $RUSTC_V; cc: $CCBIN); steps not executed"; exit 0; fi

# ---- step runner -----------------------------------------------------------------------------
ALL_STEPS=""
step() {
  local name=$1 profile=$2 dir=$3; shift 3
  ALL_STEPS="$ALL_STEPS $name"
  if [ -n "$ONLY" ] && [[ " $ONLY " != *" $name "* ]]; then return 0; fi
  local log="$OUT/$name.log" t0 t1 rc
  t0=$(date +%s)
  ( cd "$SRC/$dir" && CARGO_TARGET_DIR="$TARGET/$profile" "$@" ) > "$log" 2>&1
  rc=$?; t1=$(date +%s)
  local cls="NATIVE PASS (offline, TEST-VALUE)"
  # The rehearsal configuration is NON-SHIPPING and is labelled as such in the evidence.
  case "$name" in *test-value*) cls="NATIVE PASS (offline, TEST-VALUE) [NON-SHIPPING feature test-value-signing]" ;; esac
  if [ "$rc" -ne 0 ]; then cls="FAIL"; FAILS=$((FAILS+1)); fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$profile" "$cls" "$rc" "$((t1-t0))" "$(sha256sum "$log" | cut -c1-64)" >> "$RES"
  say "$name [$profile] exit $rc"
}
# Vector-export tests panic without a fresh, empty evidence directory.
ev() { local d="$OUT/vectors-$1"; rm -rf "$d"; mkdir -p "$d"; export NATIVE_TRADING_EVIDENCE_DIR="$d"; }
noev() { unset NATIVE_TRADING_EVIDENCE_DIR; }
# Keep each shipping build's binary for the forbidden-string check (the second build overwrites the first).
copy_bin() {
  local b
  for b in "$TARGET/release/release/mutinyd-v8" "$TARGET/release/release/mutinyd-v8.exe"; do
    if [ -f "$b" ]; then cp "$b" "$OUT/bin-$1${b##*mutinyd-v8}"; fi
  done
}
ran() { [ -z "$ONLY" ] || [[ " $ONLY " == *" $1 "* ]]; }
CT="--locked --offline"
SVC="trading-service,mutiny-crypto-v2/wallet-custody"
FIX="dividend-test-fixtures,legacy-v0-test-fixtures"

# ---- source-path portability (static, seconds; the first step) --------------------------------
step g0-source-paths check . perl build/check-source-paths.pl

# ---- compile gate ----------------------------------------------------------------------------
step g1-consensus debug consensus cargo test $CT --no-run
step g2-consensus-fixtures debug consensus cargo test $CT --no-run --features $FIX --lib --test dividends_v1 --test trading_license_dividends_v1 --test voter --test treasury_rehearsal_rotation_v1 --test treasury_rehearsal_rotation_v3
step g3-node debug node cargo test $CT --no-run
step g4-node-service debug node cargo test $CT --no-run --lib --features $SVC
step g5-crypto-v2 debug crypto-v2 cargo test $CT --no-run
step g6-crypto-v2-custody debug crypto-v2 cargo test $CT --no-run --features wallet-custody
step g7-transport-v2 debug transport-v2 cargo test $CT --no-run
if [ "$WC" = 1 ]; then
  step g8-wallet-core debug wallet-core cargo test $CT --no-run
  # NON-SHIPPING rehearsal configuration (test-value-signing); never a shipping graph.
  step g9-wallet-core-test-value debug wallet-core cargo test $CT --no-run --features test-value-signing
fi
GATE_FAILED=0
if grep -Eq "^g[1-9].*FAIL" "$RES"; then GATE_FAILED=1; say "COMPILE GATE FAILED; later steps are not run"; COMPLETE=0; fi

if [ "$GATE_FAILED" = 0 ]; then
  # ---- debug profile -------------------------------------------------------------------------
  if [ "$DO_DEBUG" = 1 ]; then
    ev d-consensus; step d-consensus debug consensus cargo test $CT --no-fail-fast -- --test-threads=$THREADS
    ev d-consensus-fix; step d-consensus-fixtures debug consensus cargo test $CT --no-fail-fast --features $FIX --lib --test dividends_v1 --test trading_license_dividends_v1 --test voter --test treasury_rehearsal_rotation_v1 --test treasury_rehearsal_rotation_v3 -- --test-threads=1
    noev; step d-crypto-v2 debug crypto-v2 cargo test $CT --no-fail-fast
    step d-crypto-v2-custody debug crypto-v2 cargo test $CT --no-fail-fast --features wallet-custody
    step d-transport-v2 debug transport-v2 cargo test $CT --no-fail-fast
    ev d-node; step d-node debug node cargo test $CT --no-fail-fast -- --test-threads=$THREADS
    ev d-node-svc; step d-node-service debug node cargo test $CT --no-fail-fast --lib --features $SVC -- --test-threads=$THREADS
    noev
    if [ "$WC" = 1 ]; then
      step d-wallet-core debug wallet-core cargo test $CT --no-fail-fast -- --test-threads=$THREADS
      step d-wallet-core-test-value debug wallet-core cargo test $CT --no-fail-fast --features test-value-signing -- --test-threads=$THREADS
    fi
  fi
  # ---- release profile -----------------------------------------------------------------------
  if [ "$DO_RELEASE" = 1 ]; then
    noev; step r-chain release consensus cargo test $CT --release --test integrated_chain -- --ignored --nocapture --test-threads=1
    ev r-consensus; step r-consensus release consensus cargo test $CT --release --no-fail-fast
    ev r-consensus-fix; step r-consensus-fixtures release consensus cargo test $CT --release --no-fail-fast --features $FIX --lib --test dividends_v1 --test trading_license_dividends_v1 --test voter --test treasury_rehearsal_rotation_v1 --test treasury_rehearsal_rotation_v3 -- --test-threads=1
    noev; step r-crypto-v2 release crypto-v2 cargo test $CT --release --no-fail-fast
    step r-transport-v2 release transport-v2 cargo test $CT --release --no-fail-fast
    ev r-node; step r-node release node cargo test $CT --release --no-fail-fast -- --test-threads=$THREADS
    ev r-node-svc; step r-node-service release node cargo test $CT --release --no-fail-fast --lib --features $SVC -- --test-threads=$THREADS
    noev
    if [ "$WC" = 1 ]; then step r-wallet-core release wallet-core cargo test $CT --release --no-fail-fast -- --test-threads=$THREADS; fi
    # production dependency graph (shipping configurations; never --all-features)
    step p1-node-build release node cargo build $CT --release
    if ran p1-node-build; then copy_bin default; fi
    step p1b-node-service-build release node cargo build $CT --release --features trading-service
    if ran p1b-node-service-build; then copy_bin trading-service; fi
    step p2-node-tree release node cargo tree $CT --edges normal,build -e features --prefix none
    step p3-consensus-check release consensus cargo check $CT --release --lib
    step p3-crypto-v2-check release crypto-v2 cargo check $CT --release --lib
    step p3-transport-v2-check release transport-v2 cargo check $CT --release --lib
    if [ "$WC" = 1 ]; then
      # shipping configuration of wallet-core: default features only, release profile. (Its rlib is not scanned for
      # strings: rustc records cfg-stripped item names in an rlib's metadata, so a default-feature rlib legitimately
      # contains the name of a gated item. The marker strings are checked in linked executables.)
      step p5-wallet-core-check release wallet-core cargo check $CT --release --lib
    fi
    # Expected artifacts, not a glob of whichever builds happened to succeed.
    # Missing either configuration must fail the linked exclusion step.
    export BUILD8_BINARIES="$OUT/bin-default $OUT/bin-trading-service"
    # Full exclusion checks (including the -D unexpected_cfgs compile checks of every configuration), own target dir.
    step x-exclusion-checks xcheck . bash build/check-shipping-config.sh
  fi
fi

# ---- skipped physical / private-evidence tests: listed, never counted as passed ---------------
if [ -z "$ONLY" ]; then
  SPECS="consensus node"; [ "$WC" = 1 ] && SPECS="$SPECS wallet-core"
  for spec in $SPECS; do
    ( cd "$SRC/$spec" && CARGO_TARGET_DIR="$TARGET/debug" cargo test $CT -- --list --ignored 2>/dev/null | grep ': test$' | sed 's/: test$//' ) > "$OUT/skipped-physical-$spec.txt" 2>/dev/null
    # wallet-core has NO physical-evidence tests: its ignored tests are golden-text printers and a fixture generator
    # (run by hand to regenerate a committed file), reported as IGNORED, not as SKIPPED-PHYSICAL.
    cls="SKIPPED-PHYSICAL (evidence not supplied)"
    [ "$spec" = wallet-core ] && cls="IGNORED (golden-text printer or fixture generator, not a physical-evidence test)"
    while IFS= read -r t; do
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "ignored:$spec:$t" n/a "$cls" - 0 - >> "$RES"
    done < "$OUT/skipped-physical-$spec.txt"
  done
fi

# ---- completeness, tripwire, package integrity, summary --------------------------------------
MISSING=""
if [ "$COMPLETE" = 1 ]; then
  for s in $ALL_STEPS; do
    awk -F'\t' -v s="$s" '$1==s{f=1} END{exit !f}' "$RES" || MISSING="$MISSING $s"
  done
  if [ -n "$MISSING" ]; then say "FAIL: expected steps missing from the results:$MISSING"; FAILS=$((FAILS+1)); fi
fi
TRIPS=$(wc -l < "$BUILD8_TRIPWIRE_LOG" | tr -d ' ')
if [ "$TRIPS" != 0 ]; then say "FAIL: $TRIPS tripwire hit(s); see tripwire.log"; FAILS=$((FAILS+1)); fi
PKG_AFTER="not-checked"
if perl "$SRC/build/package-tree.pl" snapshot "$SRC" > "$OUT/package-tree-after.txt" &&
   cmp -s "$OUT/package-tree-before.txt" "$OUT/package-tree-after.txt"; then
  say "whole package tree unchanged: files/hashes, additions, removals, directories and links"
else
  PKG_AFTER="CHANGED"; FAILS=$((FAILS+1))
  diff -u "$OUT/package-tree-before.txt" "$OUT/package-tree-after.txt" > "$OUT/package-tree.diff" || true
  say "FAIL: package tree additions/removals/changes; see package-tree.diff"
fi
if [ -f "$SRC/PACKAGE-MANIFEST.sha256" ]; then
  if perl "$SRC/build/package-tree.pl" manifest "$SRC" >> "$OUT/run.log" 2>&1; then [ "$PKG_AFTER" = CHANGED ] || PKG_AFTER="unchanged"
  else PKG_AFTER="CHANGED"; FAILS=$((FAILS+1)); say "FAIL: the package no longer matches its manifest after the run"; fi
fi
CH_LEFT=$(ls -A "$CARGO_HOME" 2>/dev/null | tr '\n' ' ')
PASSED=$(grep -c 'NATIVE PASS' "$RES"); SKIPPED=$(grep -c 'SKIPPED-PHYSICAL' "$RES")
COMPLETE_TXT=false; if [ "$COMPLETE" = 1 ]; then COMPLETE_TXT=true; fi
WC_TXT=false; if [ "$WC" = 1 ]; then WC_TXT=true; fi
{
  printf '{\n  "runner_sha256": "%s",\n  "archive_sha256": "%s",\n  "rustc": "%s",\n  "host": "%s",\n' "$RUNNER_SHA" "$ARCHIVE_SHA" "$RUSTC_V" "$(uname -sm)"
  printf '  "complete_campaign": %s,\n  "wallet_core_present": %s,\n  "focus_filter": "%s",\n  "inherited_BUILD8_ONLY_ignored": "%s",\n' "$COMPLETE_TXT" "$WC_TXT" "$ONLY" "$INHERITED_ONLY"
  printf '  "steps_declared": "%s",\n  "steps_missing": "%s",\n' "$(echo $ALL_STEPS)" "$(echo $MISSING)"
  printf '  "steps_native_pass": %s,\n  "steps_failed": %s,\n  "ignored_tests_skipped_physical": %s,\n' "$PASSED" "$FAILS" "$SKIPPED"
  printf '  "tripwire_hits": %s,\n  "package_manifest_before": "%s",\n  "package_after_run": "%s",\n  "cargo_home_after_run": "%s",\n' "$TRIPS" "$MANIFEST_OK" "$PKG_AFTER" "$CH_LEFT"
  printf '  "evidence_class": "NATIVE PASS (offline, TEST-VALUE) only; NOT physical clock qualification, NOT real-TPM evidence, NOT production readiness, NOT release lock",\n'
  printf '  "results_tsv_sha256": "%s"\n}\n' "$(sha256sum "$RES" | cut -c1-64)"
} > "$OUT/summary.json"
RUNNER_EXIT=1; if [ "$FAILS" -eq 0 ] && [ "$COMPLETE" = 1 ]; then RUNNER_EXIT=0; fi
say "done: $PASSED native pass, $FAILS failed, $SKIPPED skipped-physical, complete_campaign=$COMPLETE_TXT; runner_exit=$RUNNER_EXIT; evidence in $OUT"
# Final log write above. Never append to finalized evidence after this point.
( cd "$OUT" && find . -type f ! -name evidence.sha256 -print0 | sort -z | xargs -0 sha256sum > evidence.sha256 ) || exit 74
( cd "$OUT" && sha256sum --check --quiet evidence.sha256 ) || exit 74
printf 'runner_exit=%s\n' "$RUNNER_EXIT" > "$WS/finished.txt"
exit "$RUNNER_EXIT"
