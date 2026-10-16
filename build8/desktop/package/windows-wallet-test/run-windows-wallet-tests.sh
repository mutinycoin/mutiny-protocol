#!/usr/bin/env bash
# Build 8 Windows wallet native test runner (offline, software-only). Run it from Git Bash on Windows 10/11 x86_64
# (MSVC toolchain). Every pass it records is at most "Windows-native NATIVE PASS (offline, TEST-VALUE)"
# (docs/EVIDENCE-CLASSES-V1.md): software correctness of the exact source commit on this Windows host. It is NOT
# Linux evidence, NOT physical clock or TPM qualification, NOT a real wallet or real key, NOT production readiness and
# NOT release lock. No real wallet is created or touched; no network is used; no TPM is opened.
#
# What it builds and tests, in this order, each as its own recorded step:
#   g0-source-paths: build/check-source-paths.pl, Linux path semantics of the source (static; the same check the
#                    Linux runner runs first; run when this source contains it)
#   release-signer  (host/offline component)   compile gate, debug suite, release suite, release build
#   desktop         (the Windows wallet)       compile gate, debug suite, release suite, release build
#   wallet-core     (UI-free library; phase 1) the same, plus the NON-SHIPPING test-value-signing rehearsal steps
#   x-exclusion-checks: build/check-shipping-config.sh over the built binaries (per-binary string rules, the
#                       pdb is scanned too) together with the graph, manifest and import-provenance checks
# A component whose compile gate fails has its test steps recorded as NOT RUN (never silently dropped), so the
# campaign is reported honestly. Today (before phase 0C) the desktop's tests do not compile: admission.rs include_str!s
# private NODE-A evidence that is deliberately not imported. The runner reports that as a failed gate with a named
# known blocker and still runs everything else; the shipping desktop build is attempted independently.
#
# Safety: refuses an elevated (Administrator) shell and non-Windows hosts; runs in a SEPARATE workspace (nothing is written
# into the source tree; cargo writes only to the target directory); redirects LOCALAPPDATA, TEMP and TMP into the
# workspace so tests cannot touch the operator's profile; CARGO_NET_OFFLINE=true with --locked --offline everywhere;
# blocks sudo/ssh/scp/sftp and every tpm2_* tool with tripwire shims for anything launched through bash (the run FAILS if one
# is recorded; native Windows programs spawned by tests resolve names themselves and are covered by the source review:
# the only external program a test spawns is powershell.exe, in release-signer storage_io, and the test executable itself);
# ignores an inherited BUILD8_ONLY (a focused rerun needs --only and is then an incomplete campaign).
# Unlike the Linux runner it uses the host's own offline Cargo cache (CARGO_HOME) instead of an empty one: there is no
# vendored Windows package. The cache must already contain every locked crate (see the README); the runner never fetches.
#
# Usage: run-windows-wallet-tests.sh [--dry-run] [--skip-desktop] [--debug-only] [--release-only] [--only "step names"]
#                                    [--allow-non-windows] [--allow-elevated]   (the last two only to test the script itself)
# Environment: BUILD8_WORKSPACE (default $HOME/build8-windows-wallet-test-<UTC stamp>; must not exist),
#              BUILD8_TARGET_DIR (cargo target directory for every step; default <workspace>/target),
#              BUILD8_TEST_THREADS (default 4), BUILD8_ARCHIVE_SHA256 (recorded), BUILD8_SRC (default: the tree
#              containing this script). RUSTUP_TOOLCHAIN may select the host toolchain whose rustc is 1.98.1.
set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC=${BUILD8_SRC:-$(cd "$HERE/../.." && pwd)}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WS=${BUILD8_WORKSPACE:-$HOME/build8-windows-wallet-test-$STAMP}
OUT="$WS/evidence"
TARGET=${BUILD8_TARGET_DIR:-$WS/target}
THREADS=${BUILD8_TEST_THREADS:-4}
WANT_RUSTC=1.98.1
INHERITED_ONLY="${BUILD8_ONLY:-}"; unset BUILD8_ONLY
DRY=0; ALLOW_NON_WINDOWS=0; ALLOW_ELEVATED=0; SKIP_DESKTOP=0; DO_DEBUG=1; DO_RELEASE=1; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --allow-non-windows) ALLOW_NON_WINDOWS=1 ;;
    --allow-elevated) ALLOW_ELEVATED=1 ;;
    --skip-desktop) SKIP_DESKTOP=1 ;;
    --debug-only) DO_RELEASE=0 ;;
    --release-only) DO_DEBUG=0 ;;
    --only) shift; ONLY="${1:-}" ;;
    *) echo "unknown option $1" >&2; exit 64 ;;
  esac; shift
done
[ ! -e "$WS" ] || { echo "ABORT: workspace $WS already exists (a fresh, separate workspace is required)" >&2; exit 65; }
mkdir -p "$OUT" "$WS/localappdata" "$WS/tmp" || exit 65
[ -e "$TARGET" ] || mkdir -p "$TARGET" || exit 65
RUNNER_SHA=$(sha256sum "${BASH_SOURCE[0]}" | cut -c1-64)
RES="$OUT/results.tsv"
printf 'step\tprofile\tclass\texit\tseconds\tlog_sha256\n' > "$RES"
say() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
FAILS=0; NOTRUN=0
COMPLETE=1
if [ -n "$ONLY" ] || [ "$DO_DEBUG" = 0 ] || [ "$DO_RELEASE" = 0 ] || [ "$SKIP_DESKTOP" = 1 ]; then COMPLETE=0; fi
[ -z "$INHERITED_ONLY" ] || say "NOTE: inherited BUILD8_ONLY='$INHERITED_ONLY' was IGNORED and unset (use --only for a focused rerun)"

# ---- preconditions ---------------------------------------------------------------------------
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) IS_WIN=1 ;; *) IS_WIN=0 ;; esac
if [ "$IS_WIN" != 1 ] || [ "$(uname -m)" != "x86_64" ]; then
  if [ "$ALLOW_NON_WINDOWS" = 1 ]; then say "WARNING: not Windows x86_64 (Git Bash); results are NOT Windows evidence"
  else say "ABORT: this runner requires Windows x86_64 from Git Bash (use --allow-non-windows only to test the script itself)"; exit 2; fi
fi
ELEVATED=0; if net session >/dev/null 2>&1; then ELEVATED=1; fi
if [ "$ELEVATED" = 1 ]; then
  if [ "$ALLOW_ELEVATED" = 1 ]; then say "WARNING: running elevated (Administrator); this is not a valid campaign shell (--allow-elevated was given to test the script)"
  else say "ABORT: refusing to run in an elevated (Administrator) shell; open an ordinary Git Bash"; exit 2; fi
fi
for t in sha256sum grep sed awk tr date uname tee find cp perl; do
  command -v "$t" >/dev/null 2>&1 || { say "ABORT: required tool '$t' missing"; exit 6; }
done
RUSTC_V=$(cd "$SRC" && rustc -V 2>&1 | head -1)
case "$RUSTC_V" in *"$WANT_RUSTC"*) ;; *) say "ABORT: rustc $WANT_RUSTC required (rust-toolchain.toml pin), found: $RUSTC_V (on a host whose toolchain is named 'stable' set RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-msvc)"; exit 3 ;; esac
HOST_TRIPLE=$(cd "$SRC" && rustc -vV 2>&1 | sed -n 's/^host: *//p' | tr -d '\r')
if [ "$HOST_TRIPLE" != "x86_64-pc-windows-msvc" ]; then
  if [ "$ALLOW_NON_WINDOWS" = 1 ]; then say "WARNING: rustc host is $HOST_TRIPLE, not x86_64-pc-windows-msvc"
  else say "ABORT: rustc host triple is '$HOST_TRIPLE', expected x86_64-pc-windows-msvc"; exit 3; fi
fi
COMPONENTS="release-signer"
[ "$SKIP_DESKTOP" = 1 ] || COMPONENTS="$COMPONENTS desktop"
# wallet-core/ is created by phase 1. When present its steps are declared and REQUIRED; when absent the campaign says
# so and is never complete.
WC=0
if [ -e "$SRC/wallet-core" ]; then WC=1; COMPONENTS="$COMPONENTS wallet-core"
else say "NOTE: wallet-core/ is absent from this source (phase 1 not merged): its steps are NOT declared and this campaign cannot be complete"; COMPLETE=0; fi
if [ "$SKIP_DESKTOP" = 1 ]; then say "NOTE: --skip-desktop: the desktop steps are not declared; this campaign cannot be complete"; fi
for c in $COMPONENTS; do
  [ -f "$SRC/$c/Cargo.toml" ] || { say "ABORT: $c/Cargo.toml missing"; exit 5; }
  [ -f "$SRC/$c/Cargo.lock" ] || { say "ABORT: $c/Cargo.lock missing"; exit 5; }
done
# The fixture the release-signer tests include must be present (identity-verified import).
[ -f "$SRC/qualification/release-policy-public-fixture-v1.json" ] || { say "ABORT: qualification/release-policy-public-fixture-v1.json missing (the release-signer tests include it)"; exit 5; }
# Offline cache: every locked crate of every component must already be in the host cache; the runner never fetches.
export CARGO_NET_OFFLINE=true CARGO_TERM_COLOR=never
for c in $COMPONENTS; do
  if ! ( cd "$SRC/$c" && CARGO_TARGET_DIR="$TARGET" cargo metadata --locked --offline --format-version 1 >/dev/null 2> "$OUT/precondition-metadata-$c.log" ); then
    say "ABORT: $c: cargo metadata --locked --offline failed (see precondition-metadata-$c.log): the offline Cargo cache is incomplete or Cargo.lock is out of date. Populate the cache once, online, with 'cargo fetch --locked' in $c (the runner never fetches)."; exit 7
  fi
done
# Source identity: a package manifest if present (verified before and after), else the git commit and dirtiness.
MANIFEST_OK="not-present"
if [ -f "$SRC/PACKAGE-MANIFEST.sha256" ]; then
  if (cd "$SRC" && sha256sum --check --quiet PACKAGE-MANIFEST.sha256) >> "$OUT/run.log" 2>&1; then MANIFEST_OK="verified-before-run"; say "package manifest verified"
  else say "ABORT: package manifest verification failed"; exit 4; fi
else say "NOTE: no PACKAGE-MANIFEST.sha256 beside the sources (running from a checkout)"; fi
[ -f "$SRC/PACKAGE-IDENTITY.json" ] && cp "$SRC/PACKAGE-IDENTITY.json" "$OUT/"
SRC_COMMIT="unknown"; SRC_DIRTY="unknown"
if [ -e "$SRC/.git" ]; then
  SRC_COMMIT=$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)
  SRC_DIRTY=$(git -C "$SRC" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
  [ "$SRC_DIRTY" = 0 ] || say "NOTE: the source tree has $SRC_DIRTY uncommitted change(s); the evidence names the commit but the run used the working tree"
fi
ARCHIVE_SHA="${BUILD8_ARCHIVE_SHA256:-unrecorded}"

# ---- environment record ----------------------------------------------------------------------
{
  echo "utc $(date -u +%FT%TZ)"; echo "runner_sha256 $RUNNER_SHA"; echo "archive_sha256 $ARCHIVE_SHA"
  echo "src $SRC"; echo "source_commit $SRC_COMMIT"; echo "source_dirty_files $SRC_DIRTY"
  echo "workspace $WS"; echo "target_dir $TARGET"; echo "threads $THREADS"; echo "user $(id -un) elevated=$ELEVATED"
  echo "components $COMPONENTS"; echo "wallet_core $( [ "$WC" = 1 ] && echo present || echo ABSENT )"
  echo "--- uname"; uname -a; echo "--- Windows"; cmd //c ver 2>&1 | tr -d '\r'; echo "PROCESSOR_ARCHITECTURE=${PROCESSOR_ARCHITECTURE:-}"
  echo "--- toolchain"; (cd "$SRC" && rustc -Vv; cargo -V; command -v rustup >/dev/null 2>&1 && rustup show active-toolchain)
  echo "--- MSVC (the cc crate locates it through vswhere itself; informational)"; where cl 2>&1 | head -2; where link 2>&1 | head -2
  echo "--- bash and sha256sum"; bash --version | head -1; sha256sum --version | head -1
  echo "--- resources"; nproc 2>&1; df -k "$WS" 2>&1
  echo "--- cargo cache (the host's own offline cache is used; it is not empty and not isolated)"; echo "CARGO_HOME=${CARGO_HOME:-<default: %USERPROFILE%\\.cargo>}"
  echo "--- environment names that influence the build (values omitted)"
  env | grep -E '^(RUSTUP_|CARGO_|RUSTFLAGS|BUILD8_|NATIVE_)' | sed -E 's/=.*/=<value omitted>/' | sort
} > "$OUT/environment.txt" 2>&1
# Isolation: tests that use the local profile or the temp directory stay inside the workspace.
export LOCALAPPDATA="$(winpath "$WS/localappdata")" TEMP="$(winpath "$WS/tmp")" TMP="$(winpath "$WS/tmp")"

# ---- tripwires: any attempt to use ssh/sudo/TPM tools from bash is blocked and recorded --------
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
if [ "$DRY" = 1 ]; then say "dry run: preconditions ok (rustc: $RUSTC_V; host $HOST_TRIPLE; components: $COMPONENTS; offline cache resolves every component); steps not executed"; exit 0; fi

# ---- step runner -----------------------------------------------------------------------------
ALL_STEPS=""
CLS_PASS="Windows-native NATIVE PASS (offline, TEST-VALUE)"
step() {
  local name=$1 profile=$2 dir=$3; shift 3
  ALL_STEPS="$ALL_STEPS $name"
  if [ -n "$ONLY" ] && [[ " $ONLY " != *" $name "* ]]; then return 0; fi
  local log="$OUT/$name.log" t0 t1 rc
  t0=$(date +%s)
  ( cd "$SRC/$dir" && CARGO_TARGET_DIR="$TARGET" "$@" ) > "$log" 2>&1
  rc=$?; t1=$(date +%s)
  local cls="$CLS_PASS"
  # The rehearsal configuration is NON-SHIPPING and is labelled as such in the evidence.
  case "$name" in *test-value*) cls="$CLS_PASS [NON-SHIPPING feature test-value-signing]" ;; esac
  if [ "$rc" -ne 0 ]; then cls="FAIL"; FAILS=$((FAILS+1)); fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$profile" "$cls" "$rc" "$((t1-t0))" "$(sha256sum "$log" | cut -c1-64)" >> "$RES"
  say "$name [$profile] exit $rc"
}
# A step that cannot run because its compile gate failed is recorded (never dropped) and makes the campaign incomplete.
not_run() { # name profile reason
  ALL_STEPS="$ALL_STEPS $1"
  if [ -n "$ONLY" ] && [[ " $ONLY " != *" $1 "* ]]; then return 0; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "NOT RUN ($3)" - 0 - >> "$RES"
  NOTRUN=$((NOTRUN+1)); COMPLETE=0
  say "$1 [$2] NOT RUN ($3)"
}
gate_ok() { awk -F'\t' -v s="g-$1" '$1==s && $4==0 {f=1} END{exit !f}' "$RES"; }
ran() { [ -z "$ONLY" ] || [[ " $ONLY " == *" $1 "* ]]; }
copy_exe() { # cargo-bin-name: the release exe and its pdb (symbol names live in the pdb on Windows)
  local exe="$TARGET/release/$1.exe" pdb="$TARGET/release/$(printf '%s' "$1" | tr '-' '_').pdb"
  [ -f "$exe" ] && cp "$exe" "$OUT/"
  [ -f "$pdb" ] && cp "$pdb" "$OUT/"
}
CT="--locked --offline"
KNOWN=""

# ---- source-path portability (static, seconds; the same check the Linux runner runs first) ------
if [ -f "$SRC/build/check-source-paths.pl" ]; then step g0-source-paths check . perl build/check-source-paths.pl
else say "NOTE: build/check-source-paths.pl is not in this source; the source-path check is not run"; fi

# ---- provenance of the imported sources (cheap; recorded as a step) ----------------------------
if [ -f "$SRC/build/check-import-provenance.sh" ]; then step p0-import-provenance check . bash build/check-import-provenance.sh
else say "NOTE: build/check-import-provenance.sh is not in this source; the import identity is not checked"; fi

# ---- compile gates, one per component --------------------------------------------------------
for c in $COMPONENTS; do step "g-$c" debug "$c" cargo test $CT --no-run; done
if [ "$WC" = 1 ]; then
  # NON-SHIPPING rehearsal configuration (test-value-signing); never a shipping graph.
  step g-wallet-core-test-value debug wallet-core cargo test $CT --no-run --features test-value-signing
fi
if ! gate_ok desktop && [ "$SKIP_DESKTOP" = 0 ] && [ -f "$OUT/g-desktop.log" ] && grep -q 'NODE-A-NATIVE-TPM-PUBLIC-FIXTURE' "$OUT/g-desktop.log"; then
  KNOWN="desktop tests do not compile: desktop/src/admission.rs include_str!s qualification/NODE-A-NATIVE-TPM-PUBLIC-FIXTURE.json, private machine-identifying evidence that is deliberately not imported; phase 0C retires or reworks it"
  say "KNOWN BLOCKER: $KNOWN"
fi

# ---- debug and release suites, per component (skipped, and recorded as NOT RUN, behind a failed gate) --
for c in $COMPONENTS; do
  if gate_ok "$c" || ! ran "g-$c"; then
    if [ "$DO_DEBUG" = 1 ]; then step "d-$c" debug "$c" cargo test $CT --no-fail-fast -- --test-threads=$THREADS; fi
    if [ "$c" = wallet-core ] && [ "$DO_DEBUG" = 1 ]; then step d-wallet-core-test-value debug wallet-core cargo test $CT --no-fail-fast --features test-value-signing -- --test-threads=$THREADS; fi
    if [ "$DO_RELEASE" = 1 ]; then step "r-$c" release "$c" cargo test $CT --release --no-fail-fast -- --test-threads=$THREADS; fi
  else
    [ "$DO_DEBUG" = 1 ] && not_run "d-$c" debug "compile gate g-$c failed"
    [ "$DO_DEBUG" = 1 ] && [ "$c" = wallet-core ] && not_run d-wallet-core-test-value debug "compile gate g-$c failed"
    [ "$DO_RELEASE" = 1 ] && not_run "r-$c" release "compile gate g-$c failed"
  fi
done

# ---- shipping builds and the exclusion checks --------------------------------------------------
if [ "$DO_RELEASE" = 1 ]; then
  step p-release-signer-build release release-signer cargo build $CT --release
  if ran p-release-signer-build; then copy_exe mutiny-offline-release-signer; fi
  if [ "$SKIP_DESKTOP" = 0 ]; then
    step p-desktop-build release desktop cargo build $CT --release
    if ran p-desktop-build; then copy_exe mutiny-wallet-v8; fi
  fi
  if [ "$WC" = 1 ]; then
    # shipping configuration of wallet-core: default features only, release profile
    # (not scanned for strings: an rlib's metadata carries cfg-stripped item names; the markers are checked in the linked exe)
    step p-wallet-core-build release wallet-core cargo build $CT --release --lib
  fi
  # Explicit platform artifact set: failed/missing builds cannot disappear from
  # the exclusion check. The checker also requires each matching Windows PDB.
  export BUILD8_BINARIES="$OUT/mutiny-offline-release-signer.exe"
  if [ "$SKIP_DESKTOP" = 0 ]; then
    export BUILD8_BINARIES="$BUILD8_BINARIES $OUT/mutiny-wallet-v8.exe"
  fi
  # Full exclusion checks (graphs for the Windows target, manifests, guards, import provenance, -D unexpected_cfgs
  # compile checks of every configuration that compiles here, and the per-binary string rules over the binaries above).
  step x-exclusion-checks check . bash build/check-shipping-config.sh
fi

# ---- completeness, tripwire, source integrity, summary ---------------------------------------
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
if [ -f "$SRC/PACKAGE-MANIFEST.sha256" ]; then
  if (cd "$SRC" && sha256sum --check --quiet PACKAGE-MANIFEST.sha256) >> "$OUT/run.log" 2>&1; then PKG_AFTER="unchanged"
  else PKG_AFTER="CHANGED"; FAILS=$((FAILS+1)); say "FAIL: the package no longer matches its manifest after the run"; fi
fi
SRC_DIRTY_AFTER="unknown"; [ -e "$SRC/.git" ] && SRC_DIRTY_AFTER=$(git -C "$SRC" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
comp_status() { # component -> passed | failed | not-run | not-declared
  local c="$1" st
  case " $COMPONENTS " in *" $c "*) ;; *) echo "not-declared"; return ;; esac
  st=$(awk -F'\t' -v c="$c" 'NR>1 && ($1 ~ ("-" c "$") || $1 ~ ("-" c "-")) { if ($3 ~ /^FAIL/) f=1; else if ($3 ~ /^NOT RUN/) n=1; else p=1 } END { if (f) print "failed"; else if (n) print "not-run"; else if (p) print "passed"; else print "not-run" }' "$RES")
  echo "$st"
}
PASSED=$(grep -c 'NATIVE PASS' "$RES")
COMPLETE_TXT=false; if [ "$COMPLETE" = 1 ]; then COMPLETE_TXT=true; fi
{
  printf '{\n  "runner_sha256": "%s",\n  "archive_sha256": "%s",\n  "rustc": "%s",\n  "host": "%s (%s)",\n' "$RUNNER_SHA" "$ARCHIVE_SHA" "$RUSTC_V" "$(uname -sm)" "$HOST_TRIPLE"
  printf '  "source_commit": "%s",\n  "source_dirty_files_before": "%s",\n  "source_dirty_files_after": "%s",\n' "$SRC_COMMIT" "$SRC_DIRTY" "$SRC_DIRTY_AFTER"
  printf '  "complete_campaign": %s,\n  "focus_filter": "%s",\n  "inherited_BUILD8_ONLY_ignored": "%s",\n' "$COMPLETE_TXT" "$ONLY" "$INHERITED_ONLY"
  printf '  "components": "%s",\n  "release_signer": "%s",\n  "desktop": "%s",\n  "wallet_core": "%s",\n' "$COMPONENTS" "$(comp_status release-signer)" "$(comp_status desktop)" "$( [ "$WC" = 1 ] && comp_status wallet-core || echo absent )"
  printf '  "known_blockers": "%s",\n' "$KNOWN"
  printf '  "steps_declared": "%s",\n  "steps_missing": "%s",\n' "$(echo $ALL_STEPS)" "$(echo $MISSING)"
  printf '  "steps_native_pass": %s,\n  "steps_failed": %s,\n  "steps_not_run": %s,\n' "$PASSED" "$FAILS" "$NOTRUN"
  printf '  "tripwire_hits": %s,\n  "package_manifest_before": "%s",\n  "package_after_run": "%s",\n  "elevated": %s,\n' "$TRIPS" "$MANIFEST_OK" "$PKG_AFTER" "$( [ "$ELEVATED" = 1 ] && echo true || echo false )"
  printf '  "evidence_class": "Windows-native NATIVE PASS (offline, TEST-VALUE) only; NOT Linux evidence, NOT physical clock or TPM qualification, NOT a real wallet or key, NOT production readiness, NOT release lock",\n'
  printf '  "results_tsv_sha256": "%s"\n}\n' "$(sha256sum "$RES" | cut -c1-64)"
} > "$OUT/summary.json"
( cd "$OUT" && find . -type f ! -name evidence.sha256 ! -path './tripwire-bin/*' -print0 | sort -z | xargs -0 sha256sum > evidence.sha256 )
say "done: $PASSED native pass, $FAILS failed, $NOTRUN not run; release-signer=$(comp_status release-signer) desktop=$(comp_status desktop) wallet-core=$( [ "$WC" = 1 ] && comp_status wallet-core || echo absent ); complete_campaign=$COMPLETE_TXT; evidence in $OUT"
[ "$FAILS" -eq 0 ] && [ "$COMPLETE" = 1 ]
