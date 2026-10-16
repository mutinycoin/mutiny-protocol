#!/usr/bin/env bash
# Negative controls for the production-exclusion checks (build/check-shipping-config.sh) and the import-provenance
# check (build/check-import-provenance.sh): a demonstration that each check FAILS when the forbidden thing is injected.
#
# It NEVER touches the real tree. It clones the committed tree (git clone --no-hardlinks) into a scratch directory
# (--with-working-tree first overlays the modified and untracked files of the real tree and commits them there), requires
# the unmodified scratch tree to PASS (a positive control, so that a failure can only come from the injection), then for
# each control: injects one forbidden thing, runs the check, requires a non-zero exit AND the expected FAIL message(s),
# and restores the scratch tree. Controls that need wallet-core build a minimal stub in the scratch copy while the real
# crate does not exist yet (it uses the real one when it does) and record its lockfile hash exactly as the integrator
# will. Exit status 0 only if the baselines passed and every control was DETECTED.
#
# Requires bash 4+ (mapfile), git and perl. Usage: build/negative-controls.sh [--with-working-tree] [--keep] [--list] [--only name[,name...]]
# Env:   CARGO_TARGET_DIR (set it outside the repository), PATH with cargo (RUSTUP_TOOLCHAIN as for the checks).
# Runtime: each shipping-config control runs the whole check (about a minute on a Windows host).
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OVERLAY=0; KEEP=0; LIST=0; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --with-working-tree) OVERLAY=1 ;;
    --keep) KEEP=1 ;;
    --list) LIST=1 ;;
    --only) shift; ONLY="${1:-}" ;;
    *) echo "unknown option $1" >&2; exit 64 ;;
  esac; shift
done
[ -e "$ROOT/.git" ] || { echo "negative-controls.sh needs a git work tree (it clones it)" >&2; exit 2; }
WORK="$(mktemp -d)" || exit 2
C="$WORK/t"
cleanup() {
  if [ "$KEEP" = 1 ]; then echo "scratch tree kept at $WORK"; return; fi
  chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"
}
trap cleanup EXIT
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$WORK/target}"

NDET=0; NMISS=0; NBASE=0; SUMMARY=""
OUT=""; RC=0
run() { OUT="$(cd "$C" && "$@" 2>&1)"; RC=$?; }
BASE=""
commit_all() { git -C "$C" add -A >/dev/null 2>&1; git -C "$C" commit -qm "${1:-scratch}" >/dev/null 2>&1 || true; }
reset() { git -C "$C" reset -q --hard "$BASE" >/dev/null 2>&1; git -C "$C" clean -fdq >/dev/null 2>&1; }
fails() { echo "$OUT" | tr -d '\r' | grep -E 'FAIL'; }
# ef <control> <patterns joined by '|||'> <command...>: the command must exit non-zero and EVERY pattern must match a FAIL line.
ef() {
  local name="$1" pats="$2" p miss="" shown; shift 2
  local -a PATARR
  [ "${NOCOMMIT:-0}" = 1 ] || commit_all "injection: $name"
  run "$@"
  if [ "$RC" = 0 ]; then
    echo "NEGATIVE CONTROL $name: NOT DETECTED (the check exited 0)"; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  NOT DETECTED  $name"; reset; return
  fi
  mapfile -t PATARR < <(echo "$pats" | sed 's/|||/\n/g')
  for p in "${PATARR[@]}"; do
    fails | grep -qE "$p" || miss="$miss [$p]"
  done
  if [ -n "$miss" ]; then
    echo "NEGATIVE CONTROL $name: FAILED BUT NOT FOR THE EXPECTED REASON (exit $RC); missing patterns:$miss"
    fails | head -8 | sed 's/^/    /'
    NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  WRONG REASON  $name"
  else
    echo "NEGATIVE CONTROL $name: DETECTED (exit $RC, $(fails | wc -l | tr -d ' ') FAIL line(s)); expected message(s):"
    for p in "${PATARR[@]}"; do
      fails | grep -E "$p" | head -3 | sed 's/^ */    /'
    done
    NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      $name"
  fi
  reset
}
# pass_expected <name> <pattern> <command...>: positive control; exit 0 and the PASS pattern present.
pe() {
  local name="$1" pat="$2"; shift 2
  [ "${NOCOMMIT:-0}" = 1 ] || commit_all "positive control: $name"
  run "$@"
  if [ "$RC" = 0 ] && echo "$OUT" | tr -d '\r' | grep -qE "$pat"; then
    [ "${NC_VERBOSE:-0}" = 1 ] && echo "$OUT" | tr -d '\r' | sed 's/^/    | /'
    echo "POSITIVE CONTROL $name: PASSED as expected"; NBASE=$((NBASE+1)); SUMMARY="$SUMMARY
  PASSED        $name (positive control)"
  else
    echo "POSITIVE CONTROL $name: UNEXPECTED RESULT (exit $RC)"; echo "$OUT" | tr -d '\r' | grep -E 'FAIL|RESULT' | head -10 | sed 's/^/    /'
    NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  UNEXPECTED    $name (positive control)"
  fi
  reset
}

# ---- helpers: manifests, lockfiles, the wallet-core stub ----------------------------------------------------------------
CUR=""
setup_failed() { echo "  (setup) $1"; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  SETUP FAILED  $CUR: $1"; }
cargo_sync() { # dir: add what a manifest edit needs to that root's lockfile, offline, never --locked
  ( cd "$C/$1" && cargo metadata --offline --format-version 1 >/dev/null 2>&1 ) || { setup_failed "cargo metadata --offline failed in $1"; return 1; }
}
sync_wc() { # record wallet-core's lockfile hash in the JSON and the docs, as the integrator will
  local h p
  h="$(sha256sum "$C/wallet-core/Cargo.lock" | cut -c1-64)"; p="${h:0:12}"
  perl -pi -e 'BEGIN { $h = shift; } if (/"path": "wallet-core\/Cargo\.lock"/) { s/"sha256": (null|"[0-9a-f]*")/"sha256": "$h"/; s/, "pending": "[^"]*"//; }' "$h" "$C/build/shipping-configurations-v1.json"
  perl -pi -e 'BEGIN { $p = shift; } s/^(\| wallet-core\/Cargo\.lock \| )[^|]*\|\s*$/$1$p |\n/' "$p" "$C/docs/BUILD-CONFIGURATIONS-V1.md"
  commit_all "wallet-core lock recorded"
}
stub_wc() { # a minimal valid wallet-core (what phase 1 must look like to the checks); no-op if the real crate exists
  [ -e "$C/wallet-core" ] && { return 0; }
  mkdir -p "$C/wallet-core/src"
  cat > "$C/wallet-core/Cargo.toml" <<'STUBEOF'
[package]
name = "mutiny-wallet-core-v8"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
mutiny-crypto-v2 = { path = "../crypto-v2", features = ["wallet-custody"] }
mutiny-consensus-v8 = { path = "../consensus" }
zeroize = { version = "=1.9.0", features = ["derive"] }

[features]
default = []
test-value-signing = []

[patch.crates-io]
hkdf = { path = "../qualification/crypto-v2-sources/kdf-custody-v1/hkdf" }
hmac = { path = "../qualification/crypto-v2-sources/kdf-custody-v1/hmac" }
sha2 = { path = "../qualification/crypto-v2-sources/kdf-custody-v1/sha2" }
block-buffer = { path = "../qualification/crypto-v2-sources/kdf-custody-v1/block-buffer" }
pbkdf2 = { path = "../qualification/crypto-v2-sources/kdf-custody-v1/pbkdf2" }
argon2 = { path = "../qualification/crypto-v2-sources/kdf-custody-v1/argon2" }
blake2 = { path = "../qualification/crypto-v2-sources/kdf-custody-v1/blake2" }

[profile.dev.package."*"]
opt-level = 3

[profile.release]
opt-level = 3
overflow-checks = true
debug-assertions = false
codegen-units = 1
strip = "none"
lto = false
panic = "unwind"
STUBEOF
  cat > "$C/wallet-core/src/lib.rs" <<'STUBEOF'
const _: () = assert!(!mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED);
const _: () = assert!(!mutiny_crypto_v2::RECEIPT_QUALIFICATION_ENABLED);
const _: () = assert!(!mutiny_consensus_v8::DIVIDEND_TEST_FIXTURES_ENABLED);
const _: () = assert!(!mutiny_consensus_v8::LEGACY_V0_TEST_FIXTURES_ENABLED);
#[cfg(feature = "test-value-signing")]
pub struct TestValueGate;
pub fn marker() -> u8 {
    1
}
#[cfg(test)]
mod tests {
    #[test]
    fn env_in_tests_is_allowed() {
        let _ = std::env::var("X");
    }
}
STUBEOF
  ( cd "$C/wallet-core" && cargo generate-lockfile --offline >/dev/null 2>&1 ) || { setup_failed "cargo generate-lockfile --offline failed for the stub"; return 1; }
  sync_wc
}
wc_dep() { # a dependency line for wallet-core, then re-lock and re-record
  perl -pi -e 'BEGIN { $d = shift; } $_ .= "$d\n" if /^\[dependencies\]/' "$1" "$C/wallet-core/Cargo.toml"
  cp "$C/desktop/Cargo.lock" "$C/wallet-core/Cargo.lock"
  cargo_sync wallet-core && sync_wc
}
stub_crate() { # name: a local path crate with that name (no registry needed)
  mkdir -p "$C/stubs/$1/src"
  printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n' "$1" > "$C/stubs/$1/Cargo.toml"
  printf 'pub fn stub() {}\n' > "$C/stubs/$1/src/lib.rs"
}
SHIP=(bash build/check-shipping-config.sh --fast)
PROV=(bash build/check-import-provenance.sh)

selected() { [ -z "$ONLY" ] || [[ ",$ONLY," == *",$1,"* ]]; }
CONTROLS="
base_ship base_ship_wc base_prov base_pkg
prov_altered_file prov_deleted_file prov_added_file prov_manifest_altered prov_fixture_altered prov_record_stale prov_record_ok prov_forbidden_artifact prov_commit_missing prov_record_hash_wrong prov_pkg_altered prov_pkg_target prov_pkg_stray_sqlite prov_pkg_test_output prov_pkg_test_output_node_a prov_pkg_unlisted_file runner_tree_mutation
ship_import_altered
ship_desktop_release_custody ship_desktop_qualification ship_desktop_consensus_fixture ship_desktop_trading_service ship_desktop_feature_added ship_signer_wallet_custody ship_signer_consensus ship_signer_walletcore
ship_wc_eframe ship_wc_bitcoin_stub ship_wc_bitcoin_hashes ship_wc_bip39 ship_wc_secp256k1 ship_wc_network ship_wc_windows_sys ship_wc_v1_bip32 ship_wc_test_value_default ship_wc_test_value_forwarded ship_wc_crypto_extra ship_desktop_test_value
ship_desktop_no_wallet_core ship_desktop_wallet_core_build_table ship_desktop_dev_extra ship_json_wallet_core
ship_lock_json ship_lock_file ship_wc_pending_but_present ship_wc_absent_no_pending ship_wc_hash_wrong ship_doc_hash ship_json_crypto
ship_pending_unlisted ship_pending_stale ship_profile_extra
ship_guard_desktop ship_guard_desktop_test_value ship_guard_desktop_test_value_cfg ship_guard_signer ship_profile_signer ship_profile_dev_desktop ship_wc_profile ship_wc_guard ship_wc_env ship_wc_cfg
ship_host_g0 ship_host_g1 ship_host_g2 ship_host_g3 ship_host_g4 ship_host_g5 ship_host_g6 ship_host_g6b ship_host_g7 ship_host_g8 ship_host_g9 ship_host_selftest ship_host_stale_allow
ship_sign_r1 ship_sign_r2 ship_sign_r3 ship_sign_c15 ship_sign_c16 ship_sign_c17 ship_sign_c18 ship_sign_selftest ship_sign_stale_allow
ship_binaries ship_binaries_default_search
w15_base w15_default w15_forward w15_missing_required w15_source w15_test_literal w15_shipping_path w15_any_test_path w15_shipping_guard w15_runner w15_binaries w15_node_edge w15_node_shipping w15_treasury_graph w15_treasury_import
ship_actor_timer_normal ship_actor_timer_default ship_actor_timer_dev_extra
"

# Source-path controls (build/check-source-paths.pl; docs/BUILD-CONFIGURATIONS-V1.md 6.1).
CONTROLS="$CONTROLS paths_base paths_selftest paths_inline_path paths_include_case paths_path_case paths_cargo_case paths_crlf_script paths_case_collision paths_untracked paths_pkg_mode paths_shipping"

if [ "$LIST" = 1 ]; then echo $CONTROLS | tr ' ' '\n'; exit 0; fi

# ---- scratch clone ------------------------------------------------------------------------------------------------
git clone -q --no-hardlinks "$ROOT" "$C" || { echo "clone failed" >&2; exit 2; }
git -C "$C" config user.name negative-controls; git -C "$C" config user.email nc@example.invalid
git -C "$C" config core.autocrlf false; git -C "$C" config core.safecrlf false
if [ "$OVERLAY" = 1 ]; then
  while IFS= read -r -d '' f; do mkdir -p "$C/$(dirname "$f")"; cp "$ROOT/$f" "$C/$f"; done < <({ git -C "$ROOT" ls-files -m -o --exclude-standard -z; git -C "$ROOT" diff --cached --name-only --diff-filter=AMR -z; })
  while IFS= read -r -d '' f; do rm -f "$C/$f"; done < <({ git -C "$ROOT" ls-files -d -z; git -C "$ROOT" diff --cached --name-only --diff-filter=D -z; })
  git -C "$C" add -A >/dev/null 2>&1
  git -C "$C" commit -qm "overlay of the working tree" >/dev/null 2>&1 || true
elif [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then
  echo "NOTE: the real tree has uncommitted changes; they are NOT in the scratch copy (use --with-working-tree to include them)"
fi
BASE="$(git -C "$C" rev-parse HEAD)"
echo "scratch tree: $C (commit $(git -C "$C" rev-parse --short HEAD)); real tree untouched"
HAVE_REAL_WC=0; [ -e "$C/wallet-core" ] && HAVE_REAL_WC=1
echo "wallet-core: $( [ "$HAVE_REAL_WC" = 1 ] && echo 'the real crate is present' || echo 'absent in the real tree; a minimal stub is built in the scratch copy for the controls that need it' )"

# ---- the controls ------------------------------------------------------------------------------------------------
# baselines (positive controls) -----------------------------------------------------------------------------------
c_base_ship()    { pe "base_ship (the unmodified scratch tree passes build/check-shipping-config.sh --fast)" '^RESULT: [0-9]+ passed, 0 failed' "${SHIP[@]}"; }
c_base_ship_wc() { stub_wc || return; pe "base_ship_wc (with wallet-core present and recorded, all wallet-core checks apply and pass)" '^RESULT: [0-9]+ passed, 0 failed' "${SHIP[@]}"; }
c_base_prov()    { pe "base_prov (the unmodified tree passes build/check-import-provenance.sh)" '^RESULT: [0-9]+ passed, 0 failed' "${PROV[@]}"; }
c_base_pkg() {
  rm -rf "$WORK/pkg"; mkdir -p "$WORK/pkg"; git -C "$C" archive --format=tar HEAD | tar -x -C "$WORK/pkg"
  OUT="$(cd "$WORK/pkg" && "${PROV[@]}" 2>&1)"; RC=$?
  if [ "$RC" = 0 ] && echo "$OUT" | grep -q 'mode: package'; then echo "POSITIVE CONTROL base_pkg (extracted package, no .git: provenance passes, commit comparison is an explicit SKIP): PASSED as expected"; NBASE=$((NBASE+1)); SUMMARY="$SUMMARY
  PASSED        base_pkg (positive control)"
  else echo "POSITIVE CONTROL base_pkg: UNEXPECTED RESULT (exit $RC)"; echo "$OUT" | grep -E 'FAIL|RESULT' | head | sed 's/^/    /'; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  UNEXPECTED    base_pkg"; fi
}

# import provenance ---------------------------------------------------------------------------------------------
c_prov_altered_file() { printf '\n// injected\n' >> "$C/desktop/src/proofs.rs"; ef "prov_altered_file (an imported file is altered)" 'desktop/src/proofs.rs: differs from the import' "${PROV[@]}"; }
c_prov_deleted_file() { rm -f "$C/desktop/src/payment.rs"; ef "prov_deleted_file (an imported file is deleted)" 'desktop/src/payment.rs: listed by .* but missing from the tree' "${PROV[@]}"; }
c_prov_added_file()   { printf 'fn x() {}\n' > "$C/desktop/src/extra_module.rs"; ef "prov_added_file (an unlisted file appears under desktop/)" 'desktop/src/extra_module.rs: a file under an imported tree that is in no import manifest' "${PROV[@]}"; }
c_prov_manifest_altered() {
  perl -pi -e 's/^(.)/$1 eq "a" ? "b" : "a"/e if /desktop\/src\/proofs\.rs/' "$C/build/imports/IMPORT-MANIFEST-WALLET-RELEASE-SIGNER-V1.sha256"
  ef "prov_manifest_altered (a manifest line is altered)" 'manifest sha256 .* != recorded .* \(the manifest was altered\)|manifest blob at .* hashes to' "${PROV[@]}"
}
c_prov_fixture_altered() {
  perl -pi -e 's/"production_authorized": false/"production_authorized": true/' "$C/qualification/release-policy-public-fixture-v1.json"
  ef "prov_fixture_altered (the fixture now claims production_authorized true)" 'release-policy-public-fixture-v1.json: differs from the import|production_authorized' "${PROV[@]}"
}
c_prov_record_stale() {
  # A record entry for an imported desktop file that is still byte-identical to its import. The file is taken from
  # the tree (the first such file in manifest order), because later phases keep editing desktop files: wallet.rs
  # until phase 0C, store_v2.rs until phase 7 and wallet_host_fixture_tpm.rs until the TPM admission merge are now
  # 'removed' or 'edited' records.
  local p="" h="" mh mf
  while read -r mh mf; do
    case "$mf" in desktop/*) ;; *) continue ;; esac
    grep -q "	$mf	" "$C/build/imports/EDITED-AFTER-IMPORT-V1.tsv" && continue
    if [ -f "$C/$mf" ] && [ "$(sha256sum "$C/$mf" | cut -c1-64)" = "$mh" ]; then p="$mf"; h="$mh"; break; fi
  done < "$C/build/imports/IMPORT-MANIFEST-WALLET-RELEASE-SIGNER-V1.sha256"
  [ -n "$p" ] || { setup_failed "no imported desktop file is byte-identical to its import"; return; }
  printf 'edited\t%s\t%s\t%s\tstale entry for an unchanged file\n' "$p" "$h" "$h" >> "$C/build/imports/EDITED-AFTER-IMPORT-V1.tsv"
  ef "prov_record_stale (a record entry for a file that equals its import)" "stale 'edited' entry for '$p'" "${PROV[@]}"
}
c_prov_record_ok() {
  local p=desktop/src/proofs.rs h c; h="$(grep " $p\$" "$C/build/imports/IMPORT-MANIFEST-WALLET-RELEASE-SIGNER-V1.sha256" | cut -c1-64)"
  printf '\n// a legitimate, recorded edit\n' >> "$C/$p"; c="$(sha256sum "$C/$p" | cut -c1-64)"
  printf 'edited\t%s\t%s\t%s\tnegative control: a recorded edit is tolerated\n' "$p" "$h" "$c" >> "$C/build/imports/EDITED-AFTER-IMPORT-V1.tsv"
  local n; n="$(grep -c '^edited' "$C/build/imports/EDITED-AFTER-IMPORT-V1.tsv")"
  pe "prov_record_ok (the same kind of edit WITH an explicit record line is tolerated)" "$n edited \(recorded\)" "${PROV[@]}"
}
c_prov_forbidden_artifact() {
  printf 'x\n' > "$C/desktop/src/live-tpm-quote.txt"
  ef "prov_forbidden_artifact (a *LIVE-TPM* file under desktop/)" 'live-tpm-quote.txt: private or generated evidence' "${PROV[@]}"
}
c_prov_commit_missing() {
  perl -pi -e 's/\t121479b04356d5c61fb0597dd063821d7f2bc429/\t1111111111111111111111111111111111111111/' "$C/build/imports/IMPORT-COMMITS-V1.tsv"
  ef "prov_commit_missing (the recorded import commit does not exist)" 'import commit 111111111111 is not available' "${PROV[@]}"
}
c_prov_record_hash_wrong() {
  perl -pi -e 's/\tf1d6398448a7/\tf1d6398448a8/' "$C/build/imports/IMPORT-COMMITS-V1.tsv"
  ef "prov_record_hash_wrong (the recorded manifest hash is wrong)" 'manifest sha256 .* != recorded' "${PROV[@]}"
}
c_prov_pkg_altered() {
  rm -rf "$WORK/pkg"; mkdir -p "$WORK/pkg"; git -C "$C" archive --format=tar HEAD | tar -x -C "$WORK/pkg"
  printf '\n// injected\n' >> "$WORK/pkg/release-signer/src/lib.rs"
  OUT="$(cd "$WORK/pkg" && "${PROV[@]}" 2>&1)"; RC=$?
  if [ "$RC" != 0 ] && echo "$OUT" | grep -qE 'FAIL  release-signer/src/lib.rs: differs from the import'; then
    echo "NEGATIVE CONTROL prov_pkg_altered (extracted package, an imported file is altered): DETECTED (exit $RC)"; echo "$OUT" | grep -E 'FAIL  release-signer/src/lib.rs' | head -1 | sed 's/^ */    /'
    NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      prov_pkg_altered"
  else echo "NEGATIVE CONTROL prov_pkg_altered: NOT DETECTED (exit $RC)"; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  NOT DETECTED  prov_pkg_altered"; fi
}
c_prov_pkg_target() {
  rm -rf "$WORK/pkg"; mkdir -p "$WORK/pkg"; git -C "$C" archive --format=tar HEAD | tar -x -C "$WORK/pkg"
  mkdir -p "$WORK/pkg/desktop/target/release"; printf 'x' > "$WORK/pkg/desktop/target/release/leftover.bin"
  OUT="$(cd "$WORK/pkg" && "${PROV[@]}" 2>&1)"; RC=$?
  if [ "$RC" != 0 ] && echo "$OUT" | grep -qE 'FAIL  desktop/target/release/leftover.bin: build output'; then
    echo "NEGATIVE CONTROL prov_pkg_target (extracted package containing desktop/target/): DETECTED (exit $RC)"; echo "$OUT" | grep -E 'FAIL  desktop/target' | head -1 | sed 's/^ */    /'
    NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      prov_pkg_target"
  else echo "NEGATIVE CONTROL prov_pkg_target: NOT DETECTED (exit $RC)"; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  NOT DETECTED  prov_pkg_target"; fi
}

# Successor tests write outside the source tree. Previously tolerated databases are now forbidden.
c_prov_pkg_stray_sqlite() {
  rm -rf "$WORK/pkg"; mkdir -p "$WORK/pkg"; git -C "$C" archive --format=tar HEAD | tar -x -C "$WORK/pkg"
  printf 'x' > "$WORK/pkg/qualification/stray-evidence.sqlite"
  OUT="$(cd "$WORK/pkg" && "${PROV[@]}" 2>&1)"; RC=$?
  if [ "$RC" != 0 ] && echo "$OUT" | grep -qE 'FAIL  qualification/stray-evidence.sqlite: private or generated evidence'; then
    echo "NEGATIVE CONTROL prov_pkg_stray_sqlite (extracted package, a database directly under qualification/): DETECTED (exit $RC)"
    NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      prov_pkg_stray_sqlite"
  else echo "NEGATIVE CONTROL prov_pkg_stray_sqlite: NOT DETECTED (exit $RC)"; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  NOT DETECTED  prov_pkg_stray_sqlite"; fi
}
c_prov_pkg_test_output() {
  rm -rf "$WORK/pkg"; mkdir -p "$WORK/pkg"; git -C "$C" archive --format=tar HEAD | tar -x -C "$WORK/pkg"
  mkdir -p "$WORK/pkg/qualification/transport-object-tests/1-2" "$WORK/pkg/qualification/continuity-custody-tests/3-4"
  printf 'x' > "$WORK/pkg/qualification/transport-object-tests/1-2/recv.sqlite"
  printf 'x' > "$WORK/pkg/qualification/continuity-custody-tests/3-4/snapshot.sqlite"
  OUT="$(cd "$WORK/pkg" && "${PROV[@]}" 2>&1)"; RC=$?
  if [ "$RC" != 0 ] && echo "$OUT" | grep -qE 'FAIL  qualification/(transport-object-tests/1-2/recv|continuity-custody-tests/3-4/snapshot).sqlite: private or generated evidence'; then
    echo "NEGATIVE CONTROL prov_pkg_test_output (formerly tolerated source-tree databases are refused): DETECTED (exit $RC)"
    NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      prov_pkg_test_output"
  else echo "POSITIVE CONTROL prov_pkg_test_output: UNEXPECTED RESULT (exit $RC)"; echo "$OUT" | grep -E 'FAIL|RESULT' | head -5 | sed 's/^/    /'; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  UNEXPECTED    prov_pkg_test_output"; fi
}
c_prov_pkg_test_output_node_a() {
  rm -rf "$WORK/pkg"; mkdir -p "$WORK/pkg"; git -C "$C" archive --format=tar HEAD | tar -x -C "$WORK/pkg"
  mkdir -p "$WORK/pkg/qualification/transport-object-tests/1-3"; printf 'x' > "$WORK/pkg/qualification/transport-object-tests/1-3/node-a-quote.txt"
  OUT="$(cd "$WORK/pkg" && "${PROV[@]}" 2>&1)"; RC=$?
  if [ "$RC" != 0 ] && echo "$OUT" | grep -qE 'FAIL  qualification/transport-object-tests/1-3/node-a-quote.txt: private or generated evidence'; then
    echo "NEGATIVE CONTROL prov_pkg_test_output_node_a (a NODE-A name inside a test output directory is still refused): DETECTED (exit $RC)"
    NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      prov_pkg_test_output_node_a"
  else echo "NEGATIVE CONTROL prov_pkg_test_output_node_a: NOT DETECTED (exit $RC)"; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  NOT DETECTED  prov_pkg_test_output_node_a"; fi
}

c_prov_pkg_unlisted_file() {
  rm -rf "$WORK/pkg"; mkdir -p "$WORK/pkg"; git -C "$C" archive --format=tar HEAD | tar -x -C "$WORK/pkg"
  ( cd "$WORK/pkg" && find . -type f ! -name PACKAGE-MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > PACKAGE-MANIFEST.sha256 )
  printf 'generated\n' > "$WORK/pkg/consensus/accidental-output.txt"
  OUT="$(cd "$WORK/pkg" && "${PROV[@]}" 2>&1)"; RC=$?
  if [ "$RC" != 0 ] && echo "$OUT" | grep -q 'FAIL  consensus/accidental-output.txt: unlisted package file'; then
    echo "NEGATIVE CONTROL prov_pkg_unlisted_file: DETECTED (exit $RC)"
    NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      prov_pkg_unlisted_file"
  else echo "NEGATIVE CONTROL prov_pkg_unlisted_file: NOT DETECTED (exit $RC)"; NMISS=$((NMISS+1)); fi
}
c_runner_tree_mutation() {
  rm -rf "$WORK/pkg"; mkdir -p "$WORK/pkg"; git -C "$C" archive --format=tar HEAD | tar -x -C "$WORK/pkg"
  perl "$C/build/package-tree.pl" snapshot "$WORK/pkg" > "$WORK/before.txt" || { setup_failed snapshot; return; }
  # Represents a step writing into the package after the runner's pre-run snapshot.
  printf 'step output\n' > "$WORK/pkg/consensus/step-output.txt"
  perl "$C/build/package-tree.pl" snapshot "$WORK/pkg" > "$WORK/after.txt" || { setup_failed snapshot; return; }
  if ! cmp -s "$WORK/before.txt" "$WORK/after.txt" && grep -q 'consensus/step-output.txt' "$WORK/after.txt"; then
    echo "NEGATIVE CONTROL runner_tree_mutation: DETECTED (addition after initial snapshot)"
    NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      runner_tree_mutation"
  else echo "NEGATIVE CONTROL runner_tree_mutation: NOT DETECTED"; NMISS=$((NMISS+1)); fi
}

# shipping configuration: imported files and the parent script ----------------------------------------------------
c_ship_import_altered() { printf '\n// injected\n' >> "$C/desktop/src/wallet_v2.rs"; ef "ship_import_altered (an imported file is altered, seen through the shipping check)" 'FAIL  import provenance|desktop/src/wallet_v2.rs: differs from the import' "${SHIP[@]}"; }
# manifests: forbidden crypto-v2 / consensus / node features ------------------------------------------------------
c_ship_desktop_release_custody() {
  perl -pi -e 's/features = \["wallet-custody"\]/features = ["wallet-custody", "release-custody"]/' "$C/desktop/Cargo.toml"
  ef "ship_desktop_release_custody (release-custody injected into the desktop)" 'desktop: mutiny-crypto-v2 dependency enables \[release-custody,wallet-custody\]|wallet-desktop \[x86_64-pc-windows-msvc\]: mutiny-crypto-v2 features = \[release-custody,wallet-custody\], expected \[wallet-custody\]' "${SHIP[@]}"
}
c_ship_desktop_qualification() {
  perl -pi -e 's/features = \["wallet-custody"\]/features = ["wallet-custody", "qualification"]/' "$C/desktop/Cargo.toml"
  ef "ship_desktop_qualification (crypto-v2 qualification injected into the desktop)" 'desktop: mutiny-crypto-v2 dependency enables|wallet-desktop \[x86_64-pc-windows-msvc\]: mutiny-crypto-v2 features' "${SHIP[@]}"
}
c_ship_desktop_consensus_fixture() {
  perl -pi -e 's/^mutiny-consensus-v8 = \{ path = "..\/consensus" \}/mutiny-consensus-v8 = { path = "..\/consensus", features = ["dividend-test-fixtures"] }/' "$C/desktop/Cargo.toml"
  ef "ship_desktop_consensus_fixture (a consensus fixture feature enabled through the desktop)" 'desktop: mutiny-consensus-v8 dependency enables features|forbidden consensus feature in graph|mutiny-consensus-v8 features' "${SHIP[@]}"
}
c_ship_actor_timer_normal() {
  perl -pi -e 's/^mutiny-consensus-v8 = \{ path = "\.\.\/consensus" \}/mutiny-consensus-v8 = { path = "..\/consensus", features = ["actor-timer-test-fixtures"] }/' "$C/node/Cargo.toml"
  ef "ship_actor_timer_normal (controlled timer on a normal NODE edge)" 'node enables a consensus feature through its normal dependency|forbidden consensus feature in graph' "${SHIP[@]}"
}
c_ship_actor_timer_default() {
  perl -pi -e 's/^default=\[\]/default=["actor-timer-test-fixtures"]/' "$C/consensus/Cargo.toml"
  ef "ship_actor_timer_default (controlled timer made default)" 'forbidden consensus feature in graph|mutiny-consensus-v8 features' "${SHIP[@]}"
}
c_ship_actor_timer_dev_extra() {
  perl -pi -e 's/features = \["actor-timer-test-fixtures"\]/features = ["actor-timer-test-fixtures", "dividend-test-fixtures"]/' "$C/node/Cargo.toml"
  ef "ship_actor_timer_dev_extra (timer DEV edge forwards an extra feature)" 'node consensus dev edge must enable exactly actor-timer-test-fixtures' "${SHIP[@]}"
}
c_ship_desktop_trading_service() {
  perl -pi -e 's/^mutinyd-v8 = \{ path = "..\/node" \}/mutinyd-v8 = { path = "..\/node", features = ["trading-service"] }/' "$C/desktop/Cargo.toml"
  ef "ship_desktop_trading_service (the node trading-service feature enabled through the desktop)" 'desktop: mutinyd-v8 dependency enables features|mutinyd-v8 features = \[default,trading-service\], expected \[default\]' "${SHIP[@]}"
}
c_ship_desktop_feature_added() {
  printf '\n[features]\nextra = []\n' >> "$C/desktop/Cargo.toml"
  ef "ship_desktop_feature_added (the desktop declares an extra feature)" 'desktop \[features\] = .*extra' "${SHIP[@]}"
}

# W15 explicit non-shipping window. These static controls do not claim binary or UI behavior;
# shipping Cargo graph and linked artifact scans remain independent gates.
c_w15_base() { pe "w15_base" '^PASS W15 shipping executable rejects feature in every profile' perl build/check-testvalue-window.pl .; }
c_w15_default() {
  perl -pi -e 's/^testvalue-window =/default = ["testvalue-window"]\ntestvalue-window =/' "$C/desktop/Cargo.toml"
  ef "w15_default" '^FAIL W15 feature has one exact forward and no default' perl build/check-testvalue-window.pl .
}
c_w15_forward() {
  perl -pi -e 's@mutiny-wallet-core-v8/test-value-signing@mutiny-wallet-core-v8/test-value-signing", "mutiny-crypto-v2/release-custody@' "$C/desktop/Cargo.toml"
  ef "w15_forward" '^FAIL W15 feature has one exact forward and no default' perl build/check-testvalue-window.pl .
}
c_w15_missing_required() {
  perl -ni -e 'print unless /^required-features/' "$C/desktop/Cargo.toml"
  ef "w15_missing_required" '^FAIL W15 test executables require explicit feature' perl build/check-testvalue-window.pl .
}
c_w15_source() {
  printf '\n#[cfg(feature = "testvalue-window")] fn w15_injected() {}\n' >> "$C/desktop/src/payment.rs"
  ef "w15_source" '^FAIL W15 feature source-site count desktop/src/payment.rs' perl build/check-testvalue-window.pl .
}
c_w15_test_literal() {
  printf '\n#[cfg(test)] const W15_EXCLUDED_ROOT: &str = "testvalue/app.rs";\n' >> "$C/desktop/src/payment.rs"
  pe "w15_test_literal (TEST-only guard may name excluded root)" '^PASS W15 shipping module exclusion desktop/src/payment.rs' perl build/check-testvalue-window.pl .
}
c_w15_shipping_path() {
  printf '\n#[path = "testvalue/app.rs"] mod w15_injected;\n' >> "$C/desktop/src/payment.rs"
  ef "w15_shipping_path (ordinary path still reaches excluded root)" '^FAIL W15 shipping module exclusion desktop/src/payment.rs' perl build/check-testvalue-window.pl .
}
c_w15_any_test_path() {
  printf '\n#[cfg(any(test, feature = "unreviewed"))] #[path = "testvalue/app.rs"] mod w15_injected;\n' >> "$C/desktop/src/payment.rs"
  ef "w15_any_test_path (mixed TEST cfg remains shipping)" '^FAIL W15 shipping module exclusion desktop/src/payment.rs' perl build/check-testvalue-window.pl .
}
c_w15_shipping_guard() {
  perl -pi -e 's/!TEST_VALUE_WINDOW/TEST_VALUE_WINDOW/' "$C/desktop/src/main.rs"
  ef "w15_shipping_guard" '^FAIL W15 shipping executable rejects feature in every profile' perl build/check-testvalue-window.pl .
}
c_w15_runner() {
  printf '\n# Injected shipping command: cargo build --features testvalue-window\n' >> "$C/package/windows-wallet-test/run-windows-wallet-tests.sh"
  ef "w15_runner" '^FAIL W15 shipping runner excludes rehearsal targets' perl build/check-testvalue-window.pl .
}
c_w15_node_shipping() {
  perl -pi -e 's/^\[dev-dependencies\]/[dependencies]/' "$C/wallet-core/Cargo.toml"
  ef "w15_node_shipping" '^FAIL W15 NODE fixture edge is exact dev-only with defaults disabled' perl build/check-testvalue-window.pl .
}
c_w15_node_edge() {
  perl -pi -e 's/^mutinyd-v8 = .*$/mutinyd-v8 = { path = "..\/node", features = ["trading-service"] }/' "$C/wallet-core/Cargo.toml"
  ef "w15_node_edge" '^FAIL W15 NODE fixture edge is exact dev-only with defaults disabled' perl build/check-testvalue-window.pl .
}
c_w15_treasury_graph() {
  printf '\npub mod treasury_rehearsal_v1;\n' >> "$C/consensus/src/lib.rs"
  ef "w15_treasury_graph" '^FAIL W15 normal Treasury module graph exports only identified V3 ceremony' perl build/check-testvalue-window.pl .
}
c_w15_treasury_import() {
  printf '\npub use mutiny_consensus_v8::treasury_admission_v1::CeremonyStore as FrozenStore;\n' >> "$C/desktop/src/payment.rs"
  ef "w15_treasury_import" '^FAIL W15 current Treasury import graph desktop/src/payment.rs' perl build/check-testvalue-window.pl .
}
c_w15_binaries() {
  local TD="$WORK/w15-binary-injection"; mkdir -p "$TD/release"
  printf 'MZ synthetic W15 nonshipping target' > "$TD/release/mutiny-wallet-v8-testvalue.exe"
  printf 'MZ synthetic W15 nonshipping Treasury target' > "$TD/release/mutiny-treasury-v8-testvalue.exe"
  printf 'MZ MUTINY-WALLET-V8-TESTVALUE-WINDOW-V1' > "$TD/release/mutiny-wallet-v8.exe"
  ef "w15_binaries" "FAIL  mutiny-wallet-v8-testvalue.exe: NON-SHIPPING W15 executable|||FAIL  mutiny-treasury-v8-testvalue.exe: NON-SHIPPING W15 executable|||FAIL  mutiny-wallet-v8.exe contains 'MUTINY-WALLET-V8-TESTVALUE-WINDOW-V1'" env -u BUILD8_BINARIES CARGO_TARGET_DIR="$TD" "${SHIP[@]}"
}
c_ship_signer_wallet_custody() {
  perl -pi -e 's/features = \["release-custody"\]/features = ["release-custody", "wallet-custody"]/' "$C/release-signer/Cargo.toml"
  ef "ship_signer_wallet_custody (wallet-custody injected into the release signer)" 'release-signer: mutiny-crypto-v2 dependency enables \[release-custody,wallet-custody\]|release-signer \[x86_64-unknown-linux-gnu\]: mutiny-crypto-v2 features = \[release-custody,wallet-custody\]' "${SHIP[@]}"
}
c_ship_signer_consensus() {
  perl -pi -e 'BEGIN { $d = q(mutiny-consensus-v8 = { path = "../consensus" }); } $_ .= "$d\r\n" if /^\[dependencies\]/' "$C/release-signer/Cargo.toml"
  cargo_sync release-signer
  ef "ship_signer_consensus (the release signer links consensus)" 'release-signer: forbidden dependency name\(s\): .*mutiny-consensus-v8|release-signer \[x86_64-unknown-linux-gnu\]: mutiny-consensus-v8 is in the graph' "${SHIP[@]}"
}
c_ship_signer_walletcore() {
  stub_wc || return
  perl -pi -e 'BEGIN { $d = q(mutiny-wallet-core-v8 = { path = "../wallet-core" }); } $_ .= "$d\r\n" if /^\[dependencies\]/' "$C/release-signer/Cargo.toml"
  cargo_sync release-signer
  ef "ship_signer_walletcore (wallet-core, and with it its signing code, reachable from the release signer)" 'release-signer: forbidden dependency name\(s\): .*mutiny-wallet-core-v8|release-signer \[x86_64-unknown-linux-gnu\]: mutiny-wallet-core-v8 is in the graph' "${SHIP[@]}"
}
# wallet-core ----------------------------------------------------------------------------------------------------
c_ship_wc_eframe() {
  stub_wc || return; wc_dep 'eframe = { version = "=0.36.2", default-features = false, features = ["default_fonts", "glow"] }' || return
  ef "ship_wc_eframe (eframe added to wallet-core)" 'wallet-core: forbidden dependency name\(s\) in its manifest: .*eframe|wallet-core \[x86_64-unknown-linux-gnu\]: forbidden GUI/windowing .*eframe' "${SHIP[@]}"
}
c_ship_wc_bitcoin_stub() {
  stub_wc || return; stub_crate bitcoin; wc_dep 'bitcoin = { path = "../stubs/bitcoin" }' || return
  ef "ship_wc_bitcoin_stub (a crate named bitcoin added to wallet-core)" "wallet-core: forbidden dependency name\(s\) in its manifest: .*bitcoin|Bitcoin-ecosystem crate 'bitcoin' is in the graph" "${SHIP[@]}"
}
c_ship_wc_bitcoin_hashes() {
  stub_wc || return; wc_dep 'bitcoin_hashes = { version = "=0.14.101", default-features = false }' || return
  ef "ship_wc_bitcoin_hashes (bitcoin_hashes as a DIRECT dependency: the exemption is narrow)" 'wallet-core: forbidden dependency name\(s\) in its manifest: .*bitcoin_hashes|bitcoin_hashes is reached through \[bip39 mutiny-wallet-core-v8\], only bip39 is accepted' "${SHIP[@]}"
}
c_ship_wc_bip39() {
  stub_wc || return; wc_dep 'bip39 = "=3.0.0"' || return
  ef "ship_wc_bip39 (a direct bip39 dependency in wallet-core)" "wallet-core: forbidden dependency name\(s\) in its manifest: .*bip39|bip39 is reached through 'mutiny-wallet-core-v8'" "${SHIP[@]}"
}
c_ship_wc_secp256k1() {
  stub_wc || return; stub_crate secp256k1; wc_dep 'secp256k1 = { path = "../stubs/secp256k1" }' || return
  ef "ship_wc_secp256k1 (a crate named secp256k1 added to wallet-core)" "wallet-core: forbidden dependency name\(s\) in its manifest: .*secp256k1|Bitcoin-ecosystem crate 'secp256k1' is in the graph" "${SHIP[@]}"
}
c_ship_wc_network() {
  stub_wc || return; stub_crate tokio; wc_dep 'tokio = { path = "../stubs/tokio" }' || return
  ef "ship_wc_network (a network crate, tokio, added to wallet-core)" 'wallet-core: forbidden dependency name\(s\) in its manifest: .*tokio|forbidden network crate\(s\) in the graph: tokio' "${SHIP[@]}"
}
c_ship_wc_windows_sys() {
  stub_wc || return; wc_dep 'windows-sys = "=0.61.2"' || return
  ef "ship_wc_windows_sys (windows-sys added to wallet-core)" 'wallet-core: forbidden dependency name\(s\) in its manifest: .*windows-sys|forbidden OS-binding/V1-key \(windows-sys, ed25519-dalek-bip32\) crate\(s\) in the graph: windows-sys' "${SHIP[@]}"
}
c_ship_wc_v1_bip32() {
  stub_wc || return; wc_dep 'ed25519-dalek-bip32 = "=0.3.0"' || return
  ef "ship_wc_v1_bip32 (ed25519-dalek-bip32 added to wallet-core)" 'wallet-core: forbidden dependency name\(s\) in its manifest: .*ed25519-dalek-bip32|forbidden OS-binding/V1-key .* crate\(s\) in the graph: .*ed25519-dalek-bip32' "${SHIP[@]}"
}
c_ship_wc_test_value_default() {
  stub_wc || return; perl -pi -e 's/^default = \[\]/default = ["test-value-signing"]/' "$C/wallet-core/Cargo.toml"; cargo_sync wallet-core; sync_wc
  ef "ship_wc_test_value_default (test-value-signing made a default feature)" 'wallet-core: default must be exactly \[\]|mutiny-wallet-core-v8 features = \[default,test-value-signing\], expected \[default\]' "${SHIP[@]}"
}
c_ship_wc_test_value_forwarded() {
  stub_wc || return; perl -pi -e 's/^test-value-signing = \[\]/test-value-signing = []\nrehearsal = ["test-value-signing"]/' "$C/wallet-core/Cargo.toml"; cargo_sync wallet-core; sync_wc
  ef "ship_wc_test_value_forwarded (another feature forwards test-value-signing)" 'wallet-core: another feature forwards test-value-signing|wallet-core \[features\] = default rehearsal test-value-signing' "${SHIP[@]}"
}
c_ship_wc_crypto_extra() {
  stub_wc || return; perl -pi -e 's/features = \["wallet-custody"\]/features = ["wallet-custody", "release-custody"]/' "$C/wallet-core/Cargo.toml"; cargo_sync wallet-core; sync_wc
  ef "ship_wc_crypto_extra (release-custody injected into wallet-core)" 'wallet-core: mutiny-crypto-v2 dependency enables \[release-custody,wallet-custody\]|wallet-core \[x86_64-unknown-linux-gnu\]: mutiny-crypto-v2 features = \[release-custody,wallet-custody\]' "${SHIP[@]}"
}
c_ship_desktop_test_value() {
  stub_wc || return
  # Since phase 7 the desktop depends on wallet-core (default features) and enables the NON-SHIPPING feature only in its
  # [dev-dependencies] line (tests). Turn the feature on in the NORMAL dependency line, which a shipping build uses.
  perl -pi -e 's/^mutiny-wallet-core-v8 = \{ path = "\.\.\/wallet-core" \}/mutiny-wallet-core-v8 = { path = "..\/wallet-core", features = ["test-value-signing"] }/' "$C/desktop/Cargo.toml"
  [ "$(tr -d '\r' < "$C/desktop/Cargo.toml" | grep -c '^mutiny-wallet-core-v8 = { path = "../wallet-core", features = \["test-value-signing"\] }$')" = 2 ] || { setup_failed "the desktop's normal wallet-core line was not found"; return; }
  cargo_sync desktop
  ef "ship_desktop_test_value (the desktop enables wallet-core test-value-signing)" 'desktop: enables wallet-core test-value-signing|wallet-desktop \[x86_64-pc-windows-msvc\]: mutiny-wallet-core-v8 features = \[default,test-value-signing\], expected \[default\]' "${SHIP[@]}"
}
c_ship_desktop_no_wallet_core() {
  # The desktop without its normal wallet-core dependency (a shell that no longer links the core).
  perl -ni -e 'print unless /^mutiny-wallet-core-v8 = \{ path = "\.\.\/wallet-core" \}/' "$C/desktop/Cargo.toml"
  ef "ship_desktop_no_wallet_core (the desktop's wallet-core dependency is removed)" 'desktop: no wallet-core dependency in \[dependencies\]' "${SHIP[@]}"
}
c_ship_desktop_wallet_core_build_table() {
  # wallet-core in another dependencies table of the desktop (build dependencies).
  printf '\r\n[build-dependencies]\r\nmutiny-wallet-core-v8 = { path = "../wallet-core" }\r\n' >> "$C/desktop/Cargo.toml"
  cargo_sync desktop
  ef "ship_desktop_wallet_core_build_table (wallet-core in another dependencies table of the desktop)" 'desktop: wallet-core in another dependencies table: \[build-dependencies\]' "${SHIP[@]}"
}
c_ship_desktop_dev_extra() {
  # The test-only dev-dependency turns off wallet-core's default features as well: refused (exactly one feature, no more).
  perl -pi -e 's/^(mutiny-wallet-core-v8 = \{ path = "\.\.\/wallet-core", )(features = \["test-value-signing"\] \})/$1default-features = false, $2/' "$C/desktop/Cargo.toml"
  ef "ship_desktop_dev_extra (the wallet-core dev-dependency changes more than the test feature)" 'desktop: the wallet-core dev-dependency must enable exactly test-value-signing and nothing else' "${SHIP[@]}"
}
c_ship_json_wallet_core() {
  perl -pi -e 's/("mutiny-wallet-core-v8": \{ "default_features": true, "features": )\[\]/$1["test-value-signing"]/' "$C/build/shipping-configurations-v1.json"
  ef "ship_json_wallet_core (the JSON records test-value-signing for the desktop's wallet-core edge)" 'the JSON crypto-v2 feature record disagrees with the enforced policy for: .*wallet-desktop\(mutiny-wallet-core-v8\)' "${SHIP[@]}"
}
# lockfile hashes -----------------------------------------------------------------------------------------------
c_ship_lock_json() {
  local h w; h="$(sha256sum "$C/desktop/Cargo.lock" | cut -c1-64)"; w="${h:0:63}$( [ "${h:63:1}" = 0 ] && echo 1 || echo 0 )"
  perl -pi -e 'BEGIN { ($h, $w) = splice(@ARGV, 0, 2); } s/\Q$h\E/$w/g' "$h" "$w" "$C/build/shipping-configurations-v1.json"
  grep -qF "$w" "$C/build/shipping-configurations-v1.json" || { setup_failed "the desktop lock hash $h is not recorded in the JSON"; return; }
  ef "ship_lock_json (a recorded lockfile hash is changed in the JSON)" "desktop/Cargo.lock sha256 \[${h:0:12}.*\] != recorded \[$w" "${SHIP[@]}"
}
c_ship_lock_file() {
  printf '# injected\n' >> "$C/desktop/Cargo.lock"; NOCOMMIT=1
  ef "ship_lock_file (a lockfile itself is altered)" 'desktop/Cargo.lock sha256 \[.*\] != recorded|desktop: Cargo.lock differs from index|desktop: cargo metadata --locked failed' "${SHIP[@]}"
}
c_ship_wc_pending_but_present() {
  stub_wc || return
  perl -pi -e 's/"path": "wallet-core\/Cargo\.lock", "sha256": "[0-9a-f]{64}"/"path": "wallet-core\/Cargo.lock", "sha256": null, "pending": "created by phase 1"/' "$C/build/shipping-configurations-v1.json"
  ef "ship_wc_pending_but_present (wallet-core/ exists while its lock entry is still pending)" 'wallet-core/ exists but build/shipping-configurations-v1.json has no lockfile sha256' "${SHIP[@]}"
}
c_ship_wc_absent_no_pending() {
  [ "$HAVE_REAL_WC" = 1 ] && { echo "NEGATIVE CONTROL ship_wc_absent_no_pending: SKIPPED (the real wallet-core exists)"; return; }
  perl -pi -e 's/"sha256": null, "pending": "created by phase 1"/"sha256": "0000000000000000000000000000000000000000000000000000000000000000"/' "$C/build/shipping-configurations-v1.json"
  ef "ship_wc_absent_no_pending (wallet-core/ is absent but its lock entry is not the pending marker)" 'wallet-core/ is absent but its lockfile entry is not the pending marker' "${SHIP[@]}"
}
c_ship_wc_hash_wrong() {
  stub_wc || return
  perl -pi -e 'if (/"path": "wallet-core\/Cargo\.lock"/) { s/("sha256": ")([0-9a-f])/$1 . ($2 eq "a" ? "b" : "a")/e }' "$C/build/shipping-configurations-v1.json"
  ef "ship_wc_hash_wrong (wallet-core's recorded lock hash does not match its lockfile)" 'wallet-core/Cargo.lock sha256 \[.*\] != recorded' "${SHIP[@]}"
}
c_ship_doc_hash() {
  local p q; p="$(sha256sum "$C/desktop/Cargo.lock" | cut -c1-12)"; q="${p:0:11}$( [ "${p:11:1}" = 0 ] && echo 1 || echo 0 )"
  perl -pi -e 'BEGIN { ($p, $q) = splice(@ARGV, 0, 2); } s/\Q$p\E/$q/g' "$p" "$q" "$C/docs/BUILD-CONFIGURATIONS-V1.md"
  ef "ship_doc_hash (the documentation table names a wrong lockfile hash)" 'docs/BUILD-CONFIGURATIONS-V1.md does not list the current lockfile hash of: .*desktop' "${SHIP[@]}"
}
c_ship_json_crypto() {
  perl -pi -e 'if (/"mutiny-crypto-v2": \{ "default_features": true, "features": \["wallet-custody"\] \}/ && ++$n == 2) { s/\["wallet-custody"\]/["wallet-custody", "release-custody"]/ }' "$C/build/shipping-configurations-v1.json"
  ef "ship_json_crypto (the JSON records release-custody for the desktop: the record disagrees with the enforced policy)" 'the JSON crypto-v2 feature record disagrees with the enforced policy for: .*wallet-desktop' "${SHIP[@]}"
}
# V1 dependencies recorded as pending removal (the list can only shrink) ----------------------------------------------
c_ship_pending_unlisted() {
  # Phase 0C removed the V1 crates and emptied the list; put ed25519-dalek-bip32 back into the desktop without recording it.
  perl -pi -e 'BEGIN { $d = q(ed25519-dalek-bip32 = "=0.3.0"); } $_ .= "$d\r\n" if /^\[dependencies\]/' "$C/desktop/Cargo.toml"
  cargo_sync desktop || return
  ef "ship_pending_unlisted (the V1 crate ed25519-dalek-bip32 is present in the desktop but not recorded as pending)" 'ed25519-dalek-bip32 is present and is not recorded in known_pending_removals of wallet-desktop' "${SHIP[@]}"
}
c_ship_pending_stale() {
  # ed25519-dalek-bip32 is gone from the desktop (phase 0C); record it as pending anyway.
  perl -pi -e 's/"known_pending_removals": \[\]/"known_pending_removals": ["ed25519-dalek-bip32"]/' "$C/build/shipping-configurations-v1.json"
  grep -qF '"known_pending_removals": ["ed25519-dalek-bip32"]' "$C/build/shipping-configurations-v1.json" || { setup_failed "known_pending_removals is not the empty list"; return; }
  ef "ship_pending_stale (ed25519-dalek-bip32 is gone from the desktop but recorded as pending)" "'ed25519-dalek-bip32' is listed in known_pending_removals of wallet-desktop but .* is already gone" "${SHIP[@]}"
}
c_ship_profile_extra() {
  perl -pi -e 'BEGIN { $d = q(rpath = true); } $_ .= "$d\r\n" if /^\[profile\.release\]/' "$C/release-signer/Cargo.toml"
  ef "ship_profile_extra (an extra key in the shared release profile of the release signer)" 'release-signer: \[profile.release\] keys are \[.*rpath' "${SHIP[@]}"
}
# guards, profile tables, wallet-core sources ---------------------------------------------------------------------
c_ship_guard_desktop() {
  perl -ni -e 'print unless /RELEASE_CUSTODY_ENABLED|Desktop wallet must not include private firmware-release custody/' "$C/desktop/src/main.rs"
  ef "ship_guard_desktop (the desktop bin guard against release-custody is removed)" 'desktop bin static guard \(no release-custody\) missing/changed' "${SHIP[@]}"
}
c_ship_guard_desktop_test_value() {
  perl -ni -e 'print unless /!mutiny_wallet_core_v8::TEST_VALUE_SIGNING_ENABLED/' "$C/desktop/src/main.rs"
  ef "ship_guard_desktop_test_value (the desktop bin guard against wallet-core's TEST-VALUE gate is removed)" 'desktop bin static guard \(no wallet-core TEST-VALUE gate\) missing/changed' "${SHIP[@]}"
}
c_ship_guard_desktop_test_value_cfg() {
  # The guard kept, but behind a cfg that never holds: it would never be evaluated.
  perl -pi -e 's/^#\[cfg\(all\(not\(test\), not\(debug_assertions\)\)\)\]/#[cfg(any())]/' "$C/desktop/src/main.rs"
  ef "ship_guard_desktop_test_value_cfg (the guard's cfg is changed so that it never applies)" 'desktop bin static guard \(no wallet-core TEST-VALUE gate\) missing/changed' "${SHIP[@]}"
}
c_ship_guard_signer() {
  perl -ni -e 'print unless /WALLET_CUSTODY_ENABLED|Release signer executables must not enable wallet private custody/' "$C/release-signer/src/main.rs"
  ef "ship_guard_signer (the release-signer bin guard against wallet-custody is removed)" 'release-signer bin static guard \(no wallet-custody\) missing/changed' "${SHIP[@]}"
}
c_ship_profile_signer() {
  perl -ni -e 'print unless /^panic = "unwind"/' "$C/release-signer/Cargo.toml"
  ef "ship_profile_signer (the release profile loses panic = unwind in the release signer)" 'release-signer: \[profile.release\] lacks .panic = "unwind".' "${SHIP[@]}"
}
c_ship_profile_dev_desktop() {
  perl -ni -e 'print unless /^\[profile\.dev\.package\."\*"\]/ || (/^opt-level = 3/ && $seen++ == 0)' "$C/desktop/Cargo.toml"
  ef "ship_profile_dev_desktop (the dev-profile dependency optimisation is removed from the desktop)" 'desktop: no \[profile.dev.package."\*"\] opt-level = 3' "${SHIP[@]}"
}
c_ship_wc_profile() {
  stub_wc || return; perl -ni -e 'print unless /^strip = "none"/' "$C/wallet-core/Cargo.toml"; cargo_sync wallet-core; sync_wc
  ef "ship_wc_profile (wallet-core without the shared release profile)" 'wallet-core: \[profile.release\] lacks .strip = "none".' "${SHIP[@]}"
}
c_ship_wc_guard() {
  stub_wc || return; perl -ni -e 'print unless /RECEIPT_QUALIFICATION_ENABLED/' "$C/wallet-core/src/lib.rs"
  ef "ship_wc_guard (wallet-core without its receipt-qualification compile-time guard)" 'wallet-core guard missing: .*RECEIPT_QUALIFICATION_ENABLED' "${SHIP[@]}"
}
c_ship_wc_env() {
  stub_wc || return; printf 'pub fn home() -> Option<String> { std::env::var("HOME").ok() }\n' | cat - "$C/wallet-core/src/lib.rs" > "$C/wallet-core/src/lib.rs.new"; mv "$C/wallet-core/src/lib.rs.new" "$C/wallet-core/src/lib.rs"
  ef "ship_wc_env (an environment read in non-test wallet-core code)" 'wallet-core/src: environment read outside tests' "${SHIP[@]}"
}
c_ship_wc_cfg() {
  stub_wc || return; printf '#[cfg(feature = "rehearsal")]\npub fn r() {}\n' >> "$C/wallet-core/src/lib.rs"
  ef "ship_wc_cfg (a feature cfg other than test-value-signing in wallet-core)" 'wallet-core: unexpected feature cfg' "${SHIP[@]}"
}
# host independence (docs/BUILD-CONFIGURATIONS-V1.md section 13): the review's probe spellings -----------------------------
# hi_probe <id> <patterns>: inject probe <id> of build/host-independence-probes.txt (the shared corpus, read from the
# scratch clone) as a new file node/src/guard_probe.rs, or appended to the file the probe names (@file).
hi_probe() {
  local id="$1" pats="$2" corpus="$C/build/host-independence-probes.txt" text target
  text="$(awk -v id="$id" '/^=== /{ on = ($2 == id); next } on' "$corpus")"
  target="$(awk -v id="$id" '/^=== / && $2 == id && $4 ~ /^@/ { print substr($4, 2) }' "$corpus")"
  [ -n "$text" ] || { setup_failed "probe $id is not in build/host-independence-probes.txt"; return; }
  if [ -n "$target" ]; then printf '%s\n' "$text" >> "$C/$target"; else target=node/src/guard_probe.rs; printf '%s\n' "$text" > "$C/$target"; fi
  ef "ship_host_${id,,} (probe $id injected into $target)" "$pats" "${SHIP[@]}"
}
c_ship_host_g0()  { hi_probe G0  'host independence: node/src/guard_probe.rs:1: env'; }
c_ship_host_g1()  { hi_probe G1  'host independence: node/src/guard_probe.rs:1: host'; }
c_ship_host_g2()  { hi_probe G2  'host independence: node/src/guard_probe.rs:1: env'; }
c_ship_host_g3()  { hi_probe G3  'host independence: node/src/guard_probe.rs:1: host|||host independence: node/src/guard_probe.rs:1: assembly'; }
c_ship_host_g4()  { hi_probe G4  'host independence: node/src/guard_probe.rs:2: env'; }
c_ship_host_g6()  { hi_probe G6  'host independence: node/src/guard_probe.rs:2: env'; }
c_ship_host_g6b() { hi_probe G6b 'host independence: node/src/main.rs:[0-9]+: env'; }
c_ship_host_g7()  { hi_probe G7  'host independence: node/src/guard_probe.rs:1: host'; }
c_ship_host_g8()  { hi_probe G8  'host independence: node/src/guard_probe.rs:1: host|||host independence: node/src/guard_probe.rs:1: env'; }
c_ship_host_g9()  { hi_probe G9  'host independence: node/src/guard_probe.rs:1: env'; }
c_ship_host_g5() {
  # A developer host alias (the review's G5); the string is taken from the script's own list, not repeated here.
  local h; h="$(sed -n 's/^HOST_STRINGS="\([^ "]*\).*/\1/p' "$C/build/check-shipping-config.sh")"
  [ -n "$h" ] || { setup_failed "HOST_STRINGS not found in build/check-shipping-config.sh"; return; }
  printf 'pub const PROBE: &str = "%s";\n' "$h" > "$C/node/src/guard_probe.rs"
  ef "ship_host_g5 (a developer host alias in a shipped source)" "host-specific strings in shipped sources/config: \\[$h: " "${SHIP[@]}"
}
c_ship_host_selftest() {
  perl -pi -e 's/^=== G0 FAIL /=== G0 PASS /' "$C/build/host-independence-probes.txt"
  grep -q '^=== G0 PASS ' "$C/build/host-independence-probes.txt" || { setup_failed "probe G0 header not found"; return; }
  ef "ship_host_selftest (a probe expectation is wrong: the scanner self-test must fail)" 'host-independence tripwire self-test: .*G0 expected PASS got FAIL MISMATCH' "${SHIP[@]}"
}
c_ship_host_stale_allow() {
  printf 'allow node/src/main.rs std::env::var("NO_SUCH_SITE")\n' >> "$C/build/host-independence-rules.txt"
  ef "ship_host_stale_allow (an allow-list entry that no line needs)" 'host independence: build/host-independence-rules.txt: stale allow entry' "${SHIP[@]}"
}
# signing calls (docs/BUILD-CONFIGURATIONS-V1.md section 14): the independent wallet review's MAJOR-2 probes R1-R3 (appended
# to wallet-core/src/ops/payment.rs, as the review did), a count excess in an allowed function, a Domain:: path in the one
# allowed raw signature, two desktop call sites, a wrong self-test expectation and a stale allow entry.
# sc_probe <id> <patterns>: append probe <id> of build/signing-call-probes.txt (the shared corpus, read from the scratch
# clone) to the file the probe names (@file), by default wallet-core/src/ops/payment.rs.
sc_probe() {
  local id="$1" pats="$2" corpus="$C/build/signing-call-probes.txt" text target
  text="$(awk -v id="$id" '/^=== /{ on = ($2 == id); next } on' "$corpus")"
  target="$(awk -v id="$id" '/^=== / && $2 == id && $4 ~ /^@/ { print substr($4, 2) }' "$corpus")"
  [ -n "$text" ] || { setup_failed "probe $id is not in build/signing-call-probes.txt"; return; }
  [ -n "$target" ] || target=wallet-core/src/ops/payment.rs
  [ -f "$C/$target" ] || { setup_failed "$target is not in the scratch tree"; return; }
  printf '%s\n' "$text" >> "$C/$target"
  ef "ship_sign_${id,,} (probe $id appended to $target)" "$pats" "${SHIP[@]}"
}
c_ship_sign_r1()  { sc_probe R1  "signing calls: wallet-core/src/ops/payment\\.rs:[0-9]+: signing call 'sign' \\(method\\) in fn review_probe_receiver_named_signer: 1 in this function, the allow-list permits 0|||signing calls: wallet-core/src/ops/payment\\.rs:[0-9]+: a Domain:: path inside the arguments of the signing call 'sign' in fn review_probe_receiver_named_signer"; }
c_ship_sign_r2()  { sc_probe R2  "signing calls: wallet-core/src/ops/payment\\.rs:[0-9]+: signing call 'sign' \\(path\\) in fn review_probe_path_call: 1 in this function, the allow-list permits 0|||signing calls: wallet-core/src/ops/payment\\.rs:[0-9]+: a Domain:: path inside the arguments of the signing call 'sign' in fn review_probe_path_call"; }
c_ship_sign_r3()  { sc_probe R3  "signing calls: wallet-core/src/ops/payment\\.rs:[0-9]+: signing call 'approve' \\(method\\) in fn review_probe_consensus_approve: 1 in this function, the allow-list permits 0"; }
c_ship_sign_c15() { sc_probe C15 "signing calls: wallet-core/src/ops/payment\\.rs:[0-9]+: signing call 'sign_input' \\(method\\) in fn sign: 3 in this function, the allow-list permits 1"; }
c_ship_sign_c16() { sc_probe C16 "signing calls: wallet-core/src/authorize\\.rs:[0-9]+: a Domain:: path inside the arguments of the signing call 'sign' in fn sign"; }
c_ship_sign_c17() { sc_probe C17 "signing calls: desktop/src/wallet_v2\\.rs:[0-9]+: signing call 'sign' \\(method\\) in fn sign_for_host: 1 in this function, the allow-list permits 0"; }
c_ship_sign_c18() { sc_probe C18 "signing calls: desktop/src/wallet_controller_v2\\.rs:[0-9]+: signing call 'approve' \\(method\\) in fn co_sign: 1 in this function, the allow-list permits 0"; }
c_ship_sign_selftest() {
  perl -pi -e 's/^=== R1 FAIL /=== R1 PASS /' "$C/build/signing-call-probes.txt"
  grep -q '^=== R1 PASS ' "$C/build/signing-call-probes.txt" || { setup_failed "probe R1 header not found"; return; }
  ef "ship_sign_selftest (a probe expectation is wrong: the tripwire self-test must fail)" 'signing-call tripwire self-test: .*R1 expected PASS got FAIL MISMATCH' "${SHIP[@]}"
}
c_ship_sign_stale_allow() {
  printf 'allow wallet-core/src/ops/payment.rs no_such_fn sign 1\n' >> "$C/build/signing-call-rules.txt"
  ef "ship_sign_stale_allow (an allow-list entry that no call needs)" 'signing calls: build/signing-call-rules\.txt: stale allow entry \(wallet-core/src/ops/payment\.rs fn no_such_fn callee sign permits 1, 0 found\)' "${SHIP[@]}"
}
# binaries: synthetic files (no build needed) -----------------------------------------------------------------------
c_ship_binaries() {
  local B="$WORK/bins"; rm -rf "$B"; mkdir -p "$B/ok" "$B/forb" "$B/forbpdb" "$B/norequired" "$B/wcust" "$B/wmark" "$B/wcmark" "$B/wphrase" "$B/wold" "$B/nphrase" "$B/nrcpt" "$B/ntimer"
  local pad="MZ synthetic binary padding"
  printf '%s' "$pad" > "$B/ok/mutiny-offline-release-signer.exe";               printf 'CustodianSession %s' "$pad" > "$B/ok/mutiny_offline_release_signer.pdb"
  printf '%s wallet_restore' "$pad" > "$B/forb/mutiny-offline-release-signer.exe"; printf 'CustodianSession' > "$B/forb/mutiny_offline_release_signer.pdb"
  printf '%s' "$pad" > "$B/forbpdb/mutiny-offline-release-signer.exe";           printf 'CustodianSession mutiny_consensus_v8' > "$B/forbpdb/mutiny_offline_release_signer.pdb"
  printf '%s' "$pad" > "$B/norequired/mutiny-offline-release-signer.exe";        printf 'nothing' > "$B/norequired/mutiny_offline_release_signer.pdb"
  printf '%s CustodianSession' "$pad" > "$B/wcust/mutiny-wallet-v8.exe"
  printf '%s TestValueGate' "$pad" > "$B/wmark/mutiny-wallet-v8.exe"
  printf '%s MUTINY-WALLET-CORE-TEST-VALUE-GATE-V1' "$pad" > "$B/wcmark/mutiny-wallet-v8.exe"
  printf '%s create_wallet_phrase wallet_restore' "$pad" > "$B/wphrase/mutiny-wallet-v8.exe"
  # Order W8: the retired name of the wallet executable is refused outright (a stale artefact, never shipped).
  printf '%s create_wallet_phrase' "$pad" > "$B/wold/mutiny-desktop-v8-ceremony.exe"
  printf '%s create_wallet_phrase' "$pad" > "$B/nphrase/mutinyd-v8.exe"
  printf '%s MUTINY-BUILD8-QUAL-RECEIPT-ADAPTER-V1' "$pad" > "$B/nrcpt/mutinyd-v8.exe"
  printf '%s MonotonicTimer' "$pad" > "$B/ntimer/mutinyd-v8.exe"
  local all="" d; for d in ok forb forbpdb norequired wcust wmark wcmark wphrase wold nphrase nrcpt ntimer; do all="$all $(ls "$B/$d"/*.exe)"; done
  # one run, twelve synthetic binaries; the Windows paths are passed as they are
  OUT="$(cd "$C" && BUILD8_BINARIES="$all" "${SHIP[@]}" 2>&1)"; RC=$?
  local o; o="$(echo "$OUT" | tr -d '\r')"
  chk() { # name expect(FAIL|PASS) pattern
    local name="$1" want="$2" pat="$3" line
    line="$(echo "$o" | grep -E "$pat" | head -1 | sed 's/^ *//')"
    if [ "$want" = FAIL ]; then
      if echo "$line" | grep -q '^FAIL'; then echo "NEGATIVE CONTROL $name: DETECTED"; echo "    $line"; NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      $name"
      else echo "NEGATIVE CONTROL $name: NOT DETECTED (line: ${line:-none})"; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  NOT DETECTED  $name"; fi
    else
      if echo "$line" | grep -q '^PASS'; then echo "POSITIVE CONTROL $name: PASSED as expected"; echo "    $line"; NBASE=$((NBASE+1)); SUMMARY="$SUMMARY
  PASSED        $name (positive control)"
      else echo "POSITIVE CONTROL $name: UNEXPECTED (line: ${line:-none})"; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  UNEXPECTED    $name"; fi
    fi
  }
  chk "bin_signer_ok (a signer binary whose pdb holds CustodianSession passes)" PASS 'mutiny-offline-release-signer.exe: none of the forbidden signer strings present, required'
  chk "bin_signer_forbidden_in_exe (wallet_restore inside the signer exe)" FAIL "FAIL  mutiny-offline-release-signer.exe contains 'wallet_restore'"
  chk "bin_signer_forbidden_in_pdb (mutiny_consensus only in the signer's pdb)" FAIL "FAIL  mutiny_offline_release_signer.pdb contains 'mutiny_consensus'"
  chk "bin_signer_missing_required (the signer lacks the required CustodianSession)" FAIL "FAIL  mutiny-offline-release-signer.exe \(signer\) lacks the required string 'CustodianSession'"
  chk "bin_wallet_custodian (release custody, CustodianSession, inside the wallet exe)" FAIL "FAIL  mutiny-wallet-v8.exe contains 'CustodianSession'"
  chk "bin_wallet_test_value_marker (the test-value-signing marker TestValueGate in the wallet exe)" FAIL "FAIL  mutiny-wallet-v8.exe contains 'TestValueGate'"
  chk "bin_wallet_core_gate_marker (wallet-core's own test-gate marker MUTINY-WALLET-CORE-TEST-VALUE-GATE-V1 in the wallet exe)" FAIL "FAIL  mutiny-wallet-v8.exe contains 'MUTINY-WALLET-CORE-TEST-VALUE-GATE-V1'"
  chk "bin_wallet_create_phrase_ok (create_wallet_phrase/wallet_restore in the wallet exe are legitimate)" PASS 'mutiny-wallet-v8.exe: none of the forbidden wallet strings present'
  chk "bin_wallet_retired_name (Order W8: a binary under the retired name mutiny-desktop-v8-ceremony is refused, never scanned as a node)" FAIL "FAIL  mutiny-desktop-v8-ceremony.exe: retired wallet executable name"
  chk "bin_node_create_phrase (create_wallet_phrase in a node binary: the original rule still applies)" FAIL "FAIL  mutinyd-v8.exe contains 'create_wallet_phrase'"
  chk "bin_node_receipt_adapter (the receipt adapter marker in a node binary: the original rule still applies)" FAIL "FAIL  mutinyd-v8.exe contains 'MUTINY-BUILD8-QUAL-RECEIPT-ADAPTER-V1'"
  chk "bin_node_actor_timer (controlled clock trait in a shipping node binary)" FAIL "FAIL  mutinyd-v8.exe contains 'MonotonicTimer'"
}

# Order W8: the check's DEFAULT binary search (no BUILD8_BINARIES) must find the wallet executable under its current name
# in CARGO_TARGET_DIR/release. The synthetic exe lives in a scratch target folder of its own (never a real one).
c_ship_binaries_default_search() {
  local TD="$WORK/default-search-target"; rm -rf "$TD"; mkdir -p "$TD/release"
  printf 'MZ synthetic binary padding TestValueGate' > "$TD/release/mutiny-wallet-v8.exe"
  ef "ship_binaries_default_search (Order W8: without BUILD8_BINARIES the check finds and scans mutiny-wallet-v8.exe in CARGO_TARGET_DIR/release)" "FAIL  mutiny-wallet-v8\.exe contains 'TestValueGate'" env -u BUILD8_BINARIES CARGO_TARGET_DIR="$TD" "${SHIP[@]}"
}

# source paths: Linux (POSIX) path semantics (build/check-source-paths.pl) --------------------------------------------
# sp_check runs the checker in the scratch tree (git mode: the INDEX is the tree) and prefixes each finding
# (`path:line: message`) with FAIL so that ef() can match it; the summary line keeps its form. Each injection below
# compiles on Windows (lexical `..`, case-insensitive names) and would fail on Linux.
sp_check() { local o rc; o="$(perl build/check-source-paths.pl "$@" 2>&1)"; rc=$?; printf '%s\n' "$o" | sed -E 's/^([^ :]+:[0-9]+: )/FAIL  \1/'; return $rc; }
NC_INLINE='
#[cfg(test)]
mod nc_inline_path {
    #[path = "../../../tests/support/software_tpm.rs"]
    mod nc_tpm;
}'
c_paths_base()     { pe "paths_base (the unmodified scratch tree passes build/check-source-paths.pl)" '^check-source-paths: 0 failing finding' sp_check; }
c_paths_selftest() { pe "paths_selftest (build/check-source-paths.pl --selftest: every finding class is reported and a clean tree passes)" '^SELFTEST PASSED' perl build/check-source-paths.pl --selftest; }
c_paths_inline_path() {
  printf '%s\n' "$NC_INLINE" >> "$C/consensus/src/join.rs"
  ef "paths_inline_path (an inline-module #[path] with '..': Windows compiles it, Linux fails with ENOENT)" 'FAIL  consensus/src/join\.rs:[0-9]+: #\[path = "\.\./\.\./\.\./tests/support/software_tpm\.rs"\] inside inline module .nc_inline_path. resolves from consensus/src/join/nc_inline_path/.*consensus/src/join. does not exist' sp_check
}
c_paths_include_case() {
  perl -pi -e 's/ROTATION-TEST-VALUE-FIXTURE-V1\.json/Rotation-Test-Value-Fixture-V1.json/' "$C/consensus/src/rotation.rs"
  ef "paths_include_case (an include_str! path with the wrong case: Windows opens the file, Linux does not)" 'FAIL  consensus/src/rotation\.rs:[0-9]+: include_str!\("\.\./\.\./qualification/Rotation-Test-Value-Fixture-V1\.json"\): .*the case differs' sp_check
}
c_paths_path_case() {
  perl -pi -e 's/#\[path = "body_assembler_tests\.rs"\]/#[path = "Body_assembler_tests.rs"]/' "$C/node/src/body_assembler.rs"
  ef "paths_path_case (a #[path] with the wrong case)" 'FAIL  node/src/body_assembler\.rs:[0-9]+: #\[path = "Body_assembler_tests\.rs"\]: .*the case differs' sp_check
}
c_paths_cargo_case() {
  perl -pi -e 's{^mutiny-crypto-v2 = \{ path = "\.\./crypto-v2" \}}{mutiny-crypto-v2 = { path = "../Crypto-v2" }}' "$C/consensus/Cargo.toml"
  ef "paths_cargo_case (a Cargo path dependency with the wrong case)" 'FAIL  consensus/Cargo\.toml:[0-9]+: path = "\.\./Crypto-v2" .*the case differs' sp_check
}
c_paths_crlf_script() {
  perl -pi -e 's/\n/\r\n/' "$C/build/check-import-provenance.sh"
  ef "paths_crlf_script (a CRLF shell script: bash on Linux fails with \$'\\r': command not found)" 'FAIL  build/check-import-provenance\.sh:1: carriage return' sp_check
}
c_paths_case_collision() {
  local blob
  blob="$(git -C "$C" hash-object -w README.md)" && git -C "$C" update-index --add --cacheinfo "100644,$blob,Readme.md" \
    || { setup_failed "could not add Readme.md to the scratch index"; return; }
  NOCOMMIT=1
  ef "paths_case_collision (README.md and Readme.md both tracked: a case-insensitive checkout cannot hold both)" 'FAIL  Readme\.md:1: differs only by case from .README\.md.' sp_check
}
c_paths_untracked() {
  printf 'x\n' > "$C/consensus/src/nc_untracked.txt"
  printf '\n#[cfg(test)]\nconst NC_UNTRACKED: &str = include_str!("nc_untracked.txt");\n' >> "$C/consensus/src/lib.rs"
  NOCOMMIT=1
  ef "paths_untracked (include_str! of a file that is in the working tree but untracked: a clone and the package lack it)" 'FAIL  consensus/src/lib\.rs:[0-9]+: include_str!\("nc_untracked\.txt"\): .*untracked' sp_check
}
c_paths_pkg_mode() {
  rm -rf "$WORK/pkg"; mkdir -p "$WORK/pkg"; git -C "$C" archive --format=tar HEAD | tar -x -C "$WORK/pkg"
  OUT="$(cd "$WORK/pkg" && sp_check 2>&1)"; RC=$?
  if [ "$RC" = 0 ] && echo "$OUT" | tr -d '\r' | grep -q '^check-source-paths: 0 failing finding.*; fs mode'; then
    echo "POSITIVE CONTROL paths_pkg_mode_base (extracted package without .git: the extracted files are the tree, and it passes): PASSED as expected"
    NBASE=$((NBASE+1)); SUMMARY="$SUMMARY
  PASSED        paths_pkg_mode_base (positive control)"
  else
    echo "POSITIVE CONTROL paths_pkg_mode_base: UNEXPECTED RESULT (exit $RC)"; echo "$OUT" | grep -E 'FAIL|check-source-paths' | head | sed 's/^/    /'
    NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  UNEXPECTED    paths_pkg_mode_base"
  fi
  printf '%s\n' "$NC_INLINE" >> "$WORK/pkg/consensus/src/join.rs"
  OUT="$(cd "$WORK/pkg" && sp_check 2>&1)"; RC=$?
  if [ "$RC" != 0 ] && echo "$OUT" | tr -d '\r' | grep -qE 'FAIL  consensus/src/join\.rs:[0-9]+: .*inside inline module .nc_inline_path.'; then
    echo "NEGATIVE CONTROL paths_pkg_mode (extracted package, the inline #[path] injected): DETECTED (exit $RC)"
    echo "$OUT" | grep -E 'FAIL  consensus/src/join' | head -1 | cut -c1-160 | sed 's/^ */    /'
    NDET=$((NDET+1)); SUMMARY="$SUMMARY
  DETECTED      paths_pkg_mode"
  else
    echo "NEGATIVE CONTROL paths_pkg_mode: NOT DETECTED (exit $RC)"; NMISS=$((NMISS+1)); SUMMARY="$SUMMARY
  NOT DETECTED  paths_pkg_mode"
  fi
}
c_paths_shipping() {
  printf '%s\n' "$NC_INLINE" >> "$C/consensus/src/join.rs"
  ef "paths_shipping (the same inline #[path], seen through build/check-shipping-config.sh)" 'FAIL  source paths: build/check-source-paths\.pl exit 1' "${SHIP[@]}"
}

for name in $CONTROLS; do
  selected "$name" || continue
  echo
  echo "---- $name"
  reset; NOCOMMIT=0; CUR="$name"
  "c_$name"
done

echo
echo "================ NEGATIVE CONTROL SUMMARY ================"
echo "$SUMMARY" | sed '/^$/d'
echo "negative controls detected: $NDET; positive controls passed: $NBASE; problems: $NMISS"
[ "$NMISS" = 0 ] && [ "$NDET" -gt 0 ]
