#!/usr/bin/env bash
# Production-exclusion checks for the Mutiny Build 8 shipping configurations
# (build/shipping-configurations-v1.json, docs/BUILD-CONFIGURATIONS-V1.md).
# Checks each DELIBERATE configuration. It never uses --all-features and never treats a
# default-feature build as a substitute for the explicit configuration lists.
#
# Components checked: the node validator (two variants), wallet-core (UI-free library, Linux and
# Windows; its checks switch on when wallet-core/ exists, until then it must be recorded as pending),
# the Windows wallet (desktop; Windows target only), the release signer (host/offline), and the shared
# libraries. Plus the identity checks of the imports (build/check-import-provenance.sh).
#
# Usage:  build/check-shipping-config.sh [--fast]
#   --fast  skip the `-D unexpected_cfgs` compile checks (graph/grep/guard checks only).
# Env:    CARGO_TARGET_DIR (recommended, outside the repo). RUSTUP_TOOLCHAIN may override the
#         rust-toolchain.toml pin ONLY on a host that lacks that exact toolchain name (record it).
#         BUILD8_BINARIES: space-separated built release binaries to inspect (see the last section).
# Negative controls (a demonstration that each check FAILS when the forbidden thing is injected, run on a
# scratch copy, never on the committed tree): build/negative-controls.sh.
# Implemented != Qualified; this is an offline source/graph check, not a physical qualification.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAST=0; [ "${1:-}" = "--fast" ] && FAST=1
CARGO_FLAGS="--offline --locked"
LINUX="x86_64-unknown-linux-gnu"
WINDOWS="x86_64-pc-windows-msvc"
FAIL=0; PASS=0; SKIP=0; WARN=0
pass() { PASS=$((PASS+1)); echo "  PASS  $*"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $*"; }
skip() { SKIP=$((SKIP+1)); echo "  SKIP  $*"; }
warn() { WARN=$((WARN+1)); echo "  WARN  $*"; }

# Mode: inside a git work tree (a .git entry at the tree root) use git; in an extracted package (no .git) use plain
# grep and the package files. A .git entry is required so that a package extracted INSIDE some other repository is not
# mistaken for a work tree.
MODE=package
if [ -e "$ROOT/.git" ] && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then MODE=git; fi
# wallet-core/ is created by phase 1. While the directory is absent its checks are skipped and the JSON must say
# "pending"; as soon as it exists every wallet-core check applies and a real lockfile entry is required.
HAVE_WC=0; [ -e "$ROOT/wallet-core" ] && HAVE_WC=1
JSON="$ROOT/build/shipping-configurations-v1.json"
DOC="$ROOT/docs/BUILD-CONFIGURATIONS-V1.md"

# "<package>|<features>" lines, one per distinct package/feature set, no dev-dependencies.
tree_pkgs() { # dir pkg target [cargo feature args...]
  local dir="$1" pkg="$2" target="$3"; shift 3
  ( cd "$ROOT/$dir" && cargo tree $CARGO_FLAGS -p "$pkg" --target "$target" -e normal,build \
      --prefix none --no-dedupe -f '{p}|{f}' "$@" 2>/dev/null ) \
    | tr -d '\r' | sed -E 's/ \(\*\)$//; s/ v[0-9][^ |]*( \([^)]*\))?\|/|/' | sort -u
}
features_of() { # tree-output package-name -> ';'-joined distinct feature sets
  echo "$1" | awk -F'|' -v p="$2" '$1==p {print $2}' | sort -u | tr '\n' ';' | sed 's/;$//'
}
expect_features() { # label tree pkg expected
  local got; got="$(features_of "$2" "$3")"
  if [ "$got" = "$4" ]; then pass "$1: $3 features = [$4]"; else fail "$1: $3 features = [$got], expected [$4]"; fi
}

check_graph() { # label dir pkg expected_pkg_features [cargo feature args...]
  local label="$1" dir="$2" pkg="$3" pkg_f="$4"; shift 4
  local out; out="$(tree_pkgs "$dir" "$pkg" "$LINUX" "$@")"
  if [ -z "$out" ]; then fail "$label: cargo tree produced no output"; return; fi
  expect_features "$label" "$out" "$pkg" "$pkg_f"
  expect_features "$label" "$out" mutiny-consensus-v8 "default"
  expect_features "$label" "$out" mutiny-crypto-v2 ""
  expect_features "$label" "$out" mutiny-transport-v2 ""
  if echo "$out" | grep -E 'mutiny-crypto-v2.*(wallet-custody|release-custody|receipt-qualification|qualification)' >/dev/null; then
    fail "$label: forbidden crypto-v2 feature in graph"; else pass "$label: no wallet/release/receipt/qualification crypto feature"; fi
  if echo "$out" | grep -E 'mutiny-consensus-v8.*(dividend-test-fixtures|legacy-v0-test-fixtures|actor-timer-test-fixtures|a2-local-fixture-generator|trading-)' >/dev/null; then
    fail "$label: forbidden consensus feature in graph"; else pass "$label: no consensus fixture/trading feature"; fi
  case " $* " in *all-features*) fail "$label: --all-features used";; esac
}

list_features() { # manifest -> sorted feature names, one per line
  sed -n '/^\[features\]/,/^\[/p' "$1" | tr -d '\r' | grep -E '^[A-Za-z]' | cut -d= -f1 | tr -d ' ' | sort
}

# ---- helpers for the component checks (wallet-core, desktop, release-signer) ---------------------------------------
# Forbidden crate families, matched against package NAMES in the resolved graph.
BTC_RE='^(bitcoin[-_a-z0-9]*|secp256k1[-_a-z0-9]*|bdk[-_a-z0-9]*|miniscript|psbt|bitcoincore-rpc|rust-bitcoin|electrum[-_a-z0-9]*|esplora[-_a-z0-9]*)$'
GUI_RE='^(eframe|egui|egui[-_a-z0-9]*|epaint[-_a-z0-9]*|emath|ecolor|winit|glutin[-_a-z0-9]*|glow|arboard|raw-window-handle)$'
OS_RE='^(windows-sys|windows|windows-core|winapi|winapi-[-a-z0-9]+|ed25519-dalek-bip32)$'
NET_RE='^(tokio|tokio-[-a-z0-9]+|mio|socket2|reqwest|hyper|hyper-[-a-z0-9]+|h2|http|http-body|http-body-util|ureq|curl|curl-sys|isahc|surf|attohttpc|axum|warp|actix-[-a-z0-9]+|tungstenite|async-std|smol|rustls|rustls-[-a-z0-9]+|native-tls|openssl|openssl-sys|webpki|webpki-[-a-z0-9]+|quinn|quinn-[-a-z0-9]+|libp2p|libp2p-[-a-z0-9]+|tonic|tower|tower-[-a-z0-9]+|hickory-[-a-z0-9]+|trust-dns-[-a-z0-9]+)$'
# One-fact-per-line JSON readers (the record is formatted so grep/awk can read it; no JSON parser is required).
json_block() { # component id -> that component's lines
  tr -d '\r' < "$JSON" | awk -v id="$1" '/^[[:space:]]*"id": *"/ { c=$0; sub(/^[^:]*: *"/,"",c); sub(/".*$/,"",c) } c==id { print }'
}
json_dep_features() { # component dep -> sorted comma-joined features recorded for that dependency, or <absent>
  local l; l="$(json_block "$1" | grep -F "\"$2\": {" | head -1)"
  [ -n "$l" ] || { echo "<absent>"; return; }
  echo "$l" | sed -n 's/.*"features": *\[\([^]]*\)\].*/\1/p' | tr -d '" ' | tr ',' '\n' | sed '/^$/d' | sort | paste -sd, -
}
json_list() { # component key -> items of that one-line string array, one per line
  json_block "$1" | grep -F "\"$2\": [" | head -1 | sed -n 's/.*\[\(.*\)\].*/\1/p' | tr -d '"' | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed '/^$/d'
}
line_features() { # a dependency line -> sorted comma-joined `features = [..]` of that line ("" if none)
  echo "$1" | sed -n 's/.*[^-_a-z]features *= *\[\([^]]*\)\].*/\1/p' | tr -d '" ' | tr ',' '\n' | sed '/^$/d' | sort | paste -sd, -
}
dep_line() { tr -d '\r' < "$1" | grep -E "^$2 *=" | head -1; }
manifest_deps() { # manifest -> every dependency name in every dependencies table (normal, dev, build, target-specific)
  tr -d '\r' < "$1" | awk '
    /^\[/ { indep=0
            if ($0 ~ /^\[(target\..*\.)?(dev-|build-)?dependencies\]/) { indep=1 }
            else if ($0 ~ /^\[(target\..*\.)?(dev-|build-)?dependencies\.[^]]+\]/) { n=$0; sub(/^.*dependencies\./,"",n); sub(/\]$/,"",n); gsub(/"/,"",n); print n }
            next }
    indep && /^[A-Za-z0-9_-]+[[:space:]]*=/ { k=$0; sub(/[[:space:]]*=.*/,"",k); print k }'
}
table_lines() { # manifest table-header (exact text, e.g. [profile.release]) -> the assignment lines of that table
  tr -d '\r' < "$1" | awk -v h="$2" '$0 == h { f=1; next } /^\[/ { f=0 } f && /^[A-Za-z]/ { print }'
}
can_resolve() { # does cargo resolve this root offline here? git work tree: yes; package: vendored sources, else a probe of the host's cache
  [ "$MODE" = git ] && return 0
  [ -f "$ROOT/$1/.cargo/config.toml" ] && return 0
  local v="RESOLVE_PROBE_${1//-/_}" cur
  eval "cur=\${$v:-}"
  if [ -z "$cur" ]; then
    if ( cd "$ROOT/$1" && cargo metadata $CARGO_FLAGS --format-version 1 >/dev/null 2>&1 ); then cur=1; else cur=0; fi
    eval "$v=$cur"
  fi
  [ "$cur" = 1 ]
}
expect_spec() { # label tree pkg spec   (spec: ABSENT | OPT:<features> | REQ:<features>)
  local label="$1" tree="$2" pkg="$3" spec="$4" present got
  present="$(echo "$tree" | awk -F'|' -v p="$pkg" '$1==p {f=1} END {print f+0}')"
  got="$(features_of "$tree" "$pkg")"
  case "$spec" in
    ABSENT) if [ "$present" = 0 ]; then pass "$label: $pkg is not in the graph"; else fail "$label: $pkg is in the graph (features [$got]) but must not be"; fi ;;
    OPT:*)  if [ "$present" = 0 ]; then pass "$label: $pkg is not in the graph (optional)"
            elif [ "$got" = "${spec#OPT:}" ]; then pass "$label: $pkg features = [$got]"
            else fail "$label: $pkg features = [$got], expected [${spec#OPT:}] (or absent)"; fi ;;
    REQ:*)  if [ "$present" = 0 ]; then fail "$label: $pkg is not in the graph, expected features [${spec#REQ:}]"
            elif [ "$got" = "${spec#REQ:}" ]; then pass "$label: $pkg features = [$got]"
            else fail "$label: $pkg features = [$got], expected [${spec#REQ:}]"; fi ;;
  esac
}
forbid_re() { # label tree regex what
  local hit; hit="$(echo "$2" | cut -d'|' -f1 | sort -u | grep -E "$3" | tr '\n' ' ' | sed 's/ $//')"
  if [ -z "$hit" ]; then pass "$1: no $4 crate in the graph"; else fail "$1: forbidden $4 crate(s) in the graph: $hit"; fi
}
dependents_of() { # dir pkg target spec -> direct dependents of spec in pkg's normal+build graph (space separated)
  ( cd "$ROOT/$1" && cargo tree $CARGO_FLAGS -p "$2" --target "$3" -e normal,build -i "$4" --depth 1 --prefix none 2>/dev/null ) \
    | tr -d '\r' | sed -n '2,$p' | grep -v '^\[' | sed -E 's/ v[0-9].*$//' | sort -u | tr '\n' ' ' | sed 's/ $//'
}
# The Bitcoin boundary. No Bitcoin-ecosystem crate may be in the graph, with ONE narrow exemption that cannot be
# avoided: crypto-v2 depends on bip39 (the 24-word wallet phrase), and bip39 depends on bitcoin_hashes (hash
# functions only: no keys, scripts or transactions), so bitcoin_hashes is in every graph that links crypto-v2,
# the node validator included. It is accepted only when it is reached through bip39 and nothing else, and bip39 only
# through the allowed parents (mutiny-crypto-v2; a wallet-core or signer must not depend on bip39 itself).
bitcoin_boundary() { # label dir pkg target tree "allowed bip39 parents"
  local label="$1" dir="$2" pkg="$3" target="$4" tree="$5" allowed="$6" names hits p dep d bad=0
  names="$(echo "$tree" | cut -d'|' -f1 | sort -u)"
  hits="$(echo "$names" | grep -E "$BTC_RE" | tr '\n' ' ')"
  for p in $hits; do
    if [ "$p" = bitcoin_hashes ]; then
      dep="$(dependents_of "$dir" "$pkg" "$target" bitcoin_hashes)"
      if [ "$dep" != "bip39" ]; then fail "$label: bitcoin_hashes is reached through [$dep], only bip39 is accepted"; bad=1; fi
    else fail "$label: Bitcoin-ecosystem crate '$p' is in the graph"; bad=1; fi
  done
  if echo "$names" | grep -qx bip39; then
    dep="$(dependents_of "$dir" "$pkg" "$target" bip39)"
    for d in $dep; do
      case " $allowed " in *" $d "*) ;; *) fail "$label: bip39 is reached through '$d' (allowed: $allowed)"; bad=1 ;; esac
    done
  fi
  if [ "$bad" = 0 ]; then pass "$label: no Bitcoin-ecosystem crate (bitcoin_hashes only via bip39; bip39 only via [$allowed])"; fi
}
# One resolved-graph check of a component for one target; sets GRAPH for the extra checks that follow.
GRAPH=""
graph_component() { # label dir pkg target pkg_spec crypto_spec consensus_spec node_spec transport_spec wallet_core_spec
  local label="$1" dir="$2" pkg="$3" target="$4"
  GRAPH="$(tree_pkgs "$dir" "$pkg" "$target")"
  if [ -z "$GRAPH" ]; then fail "$label: cargo tree produced no output (target $target)"; return 1; fi
  expect_spec "$label" "$GRAPH" "$pkg" "$5"
  expect_spec "$label" "$GRAPH" mutiny-crypto-v2 "$6"
  expect_spec "$label" "$GRAPH" mutiny-consensus-v8 "$7"
  expect_spec "$label" "$GRAPH" mutinyd-v8 "$8"
  expect_spec "$label" "$GRAPH" mutiny-transport-v2 "$9"
  [ "$pkg" = mutiny-wallet-core-v8 ] || expect_spec "$label" "$GRAPH" mutiny-wallet-core-v8 "${10}"
  if echo "$GRAPH" | grep -E 'mutiny-consensus-v8.*(dividend-test-fixtures|legacy-v0-test-fixtures|actor-timer-test-fixtures|a2-local-fixture-generator|trading-)' >/dev/null; then
    fail "$label: forbidden consensus feature in graph"; else pass "$label: no consensus fixture/trading feature"; fi
  return 0
}
# While V1 (Ed25519/BIP32) code is still compiled into the imported desktop, its two dependencies are recorded in the
# JSON as pending removal (phase 0C). Present-and-listed is a WARN, present-and-unlisted and listed-but-gone are FAILs.
pending_check() { # label component present(0/1) item description
  local label="$1" comp="$2" present="$3" item="$4" what="$5" listed=0
  json_list "$comp" known_pending_removals | grep -qx "$item" && listed=1
  if   [ "$present" = 1 ] && [ "$listed" = 1 ]; then warn "$label: $what is still present (V1; recorded as pending removal, phase 0C)"
  elif [ "$present" = 1 ] && [ "$listed" = 0 ]; then fail "$label: $what is present and is not recorded in known_pending_removals of $comp"
  elif [ "$present" = 0 ] && [ "$listed" = 1 ]; then fail "$label: '$item' is listed in known_pending_removals of $comp but $what is already gone; remove the entry"
  else pass "$label: $what is absent"; fi
}

if bash "$ROOT/build/check-treasury-application-shipping.sh"; then pass "Treasury ordinary shipping graph"; else fail "Treasury ordinary shipping graph"; fi
echo "== Toolchain and manifests"
if grep -q '^channel *= *"1\.98\.1"' "$ROOT/rust-toolchain.toml"; then pass "rust-toolchain.toml pins 1.98.1"; else fail "rust-toolchain.toml missing exact pin"; fi
ROOTS="consensus node crypto-v2 transport-v2 desktop release-signer treasury-application"
[ "$HAVE_WC" = 1 ] && ROOTS="$ROOTS wallet-core"
for c in $ROOTS; do
  m="$ROOT/$c/Cargo.toml"
  if [ ! -f "$m" ]; then fail "$c: Cargo.toml is missing"; continue; fi
  if grep -q '^\[profile.release\]' "$m"; then pass "$c: explicit [profile.release]"; else fail "$c: no [profile.release]"; fi
  for kv in 'opt-level = 3' 'overflow-checks = true' 'debug-assertions = false' 'codegen-units = 1' 'strip = "none"' 'lto = false' 'panic = "unwind"'; do
    sed -n '/^\[profile\.release\]/,$p' "$m" | tr -d '\r' | grep -qx "$kv" || fail "$c: [profile.release] lacks '$kv'"
  done
  # The table is the SAME table in every shipped root: exactly these seven keys, no extra key (no inherits, rpath, ...).
  extra="$(table_lines "$m" '[profile.release]' | sed 's/ *=.*//' | sort | tr '\n' ' ')"
  if [ "$extra" = "codegen-units debug-assertions lto opt-level overflow-checks panic strip " ]; then pass "$c: [profile.release] has exactly the seven shared keys"; else fail "$c: [profile.release] keys are [$extra], expected exactly opt-level overflow-checks debug-assertions codegen-units strip lto panic"; fi
done
if [ "$HAVE_WC" = 0 ]; then skip "wallet-core: profile tables not checked (pending: created by phase 1; they are required as soon as wallet-core/ exists)"; fi
# Dev profile: dependencies optimised at opt-level 3 (FN-DSA/KDF/C crypto are too slow at opt-level 0 in tests).
DEVROOTS="consensus desktop release-signer"; [ "$HAVE_WC" = 1 ] && DEVROOTS="$DEVROOTS wallet-core"
for c in $DEVROOTS; do
  if table_lines "$ROOT/$c/Cargo.toml" '[profile.dev.package."*"]' | grep -qx 'opt-level = 3'; then pass "$c: [profile.dev.package.\"*\"] opt-level = 3"; else fail "$c: no [profile.dev.package.\"*\"] opt-level = 3 (FN-DSA/KDF code is too slow at opt-level 0 in tests)"; fi
done
# The JSON lists which manifests carry the release table (first present_in_manifests) and the dev table (second).
rp="$(tr -d '\r' < "$JSON" | grep -F '"present_in_manifests"' | sed -n 1p)"; dp="$(tr -d '\r' < "$JSON" | grep -F '"present_in_manifests"' | sed -n 2p)"
pmiss=""; for mfst in consensus node crypto-v2 transport-v2 desktop release-signer wallet-core treasury-application; do echo "$rp" | grep -qF "\"$mfst/Cargo.toml\"" || pmiss="$pmiss $mfst"; done
dmiss=""; for mfst in consensus desktop release-signer wallet-core; do echo "$dp" | grep -qF "\"$mfst/Cargo.toml\"" || dmiss="$dmiss $mfst"; done
if [ -z "$pmiss$dmiss" ]; then pass "the JSON lists every manifest that carries the release profile (8) and the dev profile (4)"; else fail "the JSON present_in_manifests lists miss: release[$pmiss ] dev[$dmiss ]"; fi
# Mode: inside a git work tree use git grep; in an extracted package (no .git) use plain grep over the same
# file types (vendored sources, build output and historical records excluded). A search ERROR is a failure,
# never a silent pass: the previous form treated "git: not a repository" as "no matches".
if [ "$MODE" = git ]; then
  hits="$(cd "$ROOT" && git grep -nE 'trading-(candidate|qualification|license-hook)' -- '*.toml' '*.sh' '*.ps1' '*.yml' '*.yaml' ':!qualification/nonce-20261002' ':!build/check-shipping-config.sh'; echo "rc=$?")"
else
  hits="$(cd "$ROOT" && grep -rnE --include='*.toml' --include='*.sh' --include='*.ps1' --include='*.yml' --include='*.yaml' --exclude-dir=vendor --exclude-dir=target --exclude-dir=nonce-20261002 --exclude=check-shipping-config.sh 'trading-(candidate|qualification|license-hook)' . ; echo "rc=$?")"
fi
echo "  mode: $MODE (git work tree = git; extracted package without .git = package)"
rc="${hits##*rc=}"; hits="${hits%rc=*}"
if [ "$rc" = 0 ]; then fail "removed trading-* consensus features still referenced by a manifest or script"; echo "$hits"
elif [ "$rc" = 1 ]; then pass "no manifest/script references removed trading-* features (searched in $MODE mode)"
else fail "reference search failed (rc=$rc, mode $MODE): cannot claim there are no references"; fi
got="$(list_features "$ROOT/consensus/Cargo.toml" | tr '\n' ' ')"
if [ "$got" = "a2-local-fixture-generator actor-timer-test-fixtures default dividend-test-fixtures legacy-v0-test-fixtures " ]; then pass "consensus declares only default + four test-fixture features"; else fail "consensus [features] = $got"; fi
if tr -d '\r' < "$ROOT/consensus/Cargo.toml" | grep -qx 'actor-timer-test-fixtures = \[\]'; then pass "actor timer test feature forwards nothing"; else fail "actor timer test feature must be exactly []"; fi
if command -v python3 >/dev/null 2>&1 && [ -f "$ROOT/build/check-a2-local-fixture.py" ]; then
  a2out="$(python3 -I -B "$ROOT/build/check-a2-local-fixture.py" "$ROOT" 2>&1)"; a2rc=$?
  printf '%s\n' "$a2out" | sed 's/^/    | /'
  if [ "$a2rc" = 0 ]; then pass "A2 local generator source exclusion tripwire"; else fail "A2 local generator source exclusion tripwire (rc=$a2rc)"; fi
else fail "A2 local generator exclusion requires python3 with tomllib and build/check-a2-local-fixture.py"; fi
got="$(list_features "$ROOT/node/Cargo.toml" | tr '\n' ' ')"
if [ "$got" = "default trading-service " ]; then pass "node declares only default + trading-service"; else fail "node [features] = $got"; fi
if tr -d '\r' < "$ROOT/node/Cargo.toml" | grep -qx 'trading-service=\[\]'; then pass "node trading-service forwards nothing"; else fail "node trading-service must be exactly []"; fi
node_consensus_lines="$(tr -d '\r' < "$ROOT/node/Cargo.toml" | awk '/^\[/ { t=$0; next } /^mutiny-consensus-v8[[:space:]]*=/ { print t "\t" $0 }')"
node_consensus_normal="$(echo "$node_consensus_lines" | awk -F'\t' '$1=="[dependencies]" { print $2 }')"
node_consensus_dev="$(echo "$node_consensus_lines" | awk -F'\t' '$1=="[dev-dependencies]" { print $2 }')"
node_consensus_other="$(echo "$node_consensus_lines" | awk -F'\t' '$0 != "" && $1!="[dependencies]" && $1!="[dev-dependencies]" {print $1}')"
if [ "$(echo "$node_consensus_normal" | wc -l | tr -d ' ')" = 1 ] && [ -n "$node_consensus_normal" ] && ! echo "$node_consensus_normal" | grep -q 'features'; then pass "node dependency on consensus enables no features"; else fail "node enables a consensus feature through its normal dependency"; fi
if [ -z "$node_consensus_other" ] && [ "$(echo "$node_consensus_dev" | wc -l | tr -d ' ')" = 1 ] && [ "$(line_features "$node_consensus_dev")" = actor-timer-test-fixtures ] && ! echo "$node_consensus_dev" | grep -q 'default-features'; then pass "node consensus dev edge enables only actor-timer-test-fixtures"; else fail "node consensus dev edge must enable exactly actor-timer-test-fixtures in dev-dependencies only"; fi

echo "== Component manifests (desktop, release-signer, wallet-core): features and dependency names"
# desktop: crypto-v2 wallet-custody ONLY; every other Build 8 dependency at its default features; no [features] table.
dm="$ROOT/desktop/Cargo.toml"
got="$(line_features "$(dep_line "$dm" mutiny-crypto-v2)")"
if [ "$got" = "wallet-custody" ]; then pass "desktop: mutiny-crypto-v2 dependency enables exactly [wallet-custody]"; else fail "desktop: mutiny-crypto-v2 dependency enables [$got], expected exactly [wallet-custody] (no release-custody, receipt-qualification or qualification)"; fi
for d in mutiny-consensus-v8 mutinyd-v8 mutiny-transport-v2; do
  l="$(dep_line "$dm" "$d")"
  if [ -z "$l" ]; then fail "desktop: no $d dependency line"
  elif echo "$l" | grep -q 'features'; then fail "desktop: $d dependency enables features or changes default-features: $l"
  else pass "desktop: $d dependency at default features"; fi
done
got="$(list_features "$dm" | tr '\n' ' ')"
if [ "$got" = "testvalue-window " ]; then pass "desktop declares only the explicit NON-SHIPPING W15 feature"; else fail "desktop [features] = $got (expected only testvalue-window)"; fi
if command -v perl >/dev/null 2>&1 && perl "$ROOT/build/check-testvalue-window.pl" "$ROOT"; then pass "W15 explicit target/feature/source/runner exclusions"; else fail "W15 target/feature/source/runner exclusion failed"; fi
# Since phase 7 the desktop is a shell over wallet-core: exactly one wallet-core line in [dependencies], at default
# features; the NON-SHIPPING test-value-signing feature only in [dev-dependencies] (tests; Cargo never unifies a
# dev-dependency feature into `cargo build --release`); wallet-core in no other dependencies table.
wc_lines="$(tr -d '\r' < "$dm" | awk '/^\[/ { t=$0; next } /^mutiny-wallet-core-v8[[:space:]]*=/ { print t "\t" $0 }')"
wc_normal="$(echo "$wc_lines" | awk -F'\t' '$1=="[dependencies]" { print $2 }')"
if [ -z "$wc_normal" ]; then fail "desktop: no wallet-core dependency in [dependencies] (the desktop is a shell over wallet-core since phase 7)"
elif [ "$(echo "$wc_normal" | wc -l | tr -d ' ')" != 1 ]; then fail "desktop: more than one wallet-core line in [dependencies]"
elif echo "$wc_normal" | grep -q 'test-value-signing'; then fail "desktop: enables wallet-core test-value-signing (non-shipping) in [dependencies]"
elif echo "$wc_normal" | grep -q 'features'; then fail "desktop: wallet-core dependency enables features or changes default-features: $wc_normal"
else pass "desktop: wallet-core dependency in [dependencies] at default features (test-value-signing not enabled)"; fi
wc_other="$(echo "$wc_lines" | awk -F'\t' '$0 != "" && $1!="[dependencies]" && $1!="[dev-dependencies]" { print $1 }' | tr '\n' ' ')"
if [ -z "$wc_other" ]; then pass "desktop: wallet-core appears only in [dependencies] and [dev-dependencies]"; else fail "desktop: wallet-core in another dependencies table: $wc_other"; fi
wc_dev="$(echo "$wc_lines" | awk -F'\t' '$1=="[dev-dependencies]" { print $2 }')"
if [ -z "$wc_dev" ] || { [ "$(echo "$wc_dev" | wc -l | tr -d ' ')" = 1 ] && [ "$(line_features "$wc_dev")" = "test-value-signing" ] && ! echo "$wc_dev" | grep -q 'default-features'; }; then
  pass "desktop: the wallet-core dev-dependency (tests only) enables exactly test-value-signing, or is absent"
else fail "desktop: the wallet-core dev-dependency must enable exactly test-value-signing and nothing else: $wc_dev"; fi
# release-signer: crypto-v2 release-custody ONLY; no consensus/node/transport/GUI/sqlite/V1-key dependency in any table.
sm="$ROOT/release-signer/Cargo.toml"
got="$(line_features "$(dep_line "$sm" mutiny-crypto-v2)")"
if [ "$got" = "release-custody" ]; then pass "release-signer: mutiny-crypto-v2 dependency enables exactly [release-custody]"; else fail "release-signer: mutiny-crypto-v2 dependency enables [$got], expected exactly [release-custody] (no wallet-custody, receipt-qualification or qualification)"; fi
got="$(list_features "$sm" | tr '\n' ' ')"
if [ -z "$got" ]; then pass "release-signer declares no [features]"; else fail "release-signer [features] = $got (the signer declares none)"; fi
bad="$(manifest_deps "$sm" | grep -E '^(mutiny-consensus-v8|mutinyd-v8|mutiny-transport-v2|mutiny-wallet-core-v8|eframe|egui.*|winit|rusqlite|bip39|ed25519-dalek-bip32|bitcoin.*|secp256k1.*)$' | tr '\n' ' ')"
if [ -z "$bad" ]; then pass "release-signer: no consensus, node, transport, wallet-core, GUI, sqlite, bip39, V1-key or Bitcoin dependency in any dependencies table"; else fail "release-signer: forbidden dependency name(s): $bad"; fi
# wallet-core.
if [ "$HAVE_WC" = 1 ]; then
  wm="$ROOT/wallet-core/Cargo.toml"
  if [ ! -f "$wm" ]; then fail "wallet-core/ exists but wallet-core/Cargo.toml does not"
  else
    got="$(line_features "$(dep_line "$wm" mutiny-crypto-v2)")"
    if [ "$got" = "wallet-custody" ]; then pass "wallet-core: mutiny-crypto-v2 dependency enables exactly [wallet-custody]"; else fail "wallet-core: mutiny-crypto-v2 dependency enables [$got], expected exactly [wallet-custody]"; fi
    for d in mutiny-consensus-v8 mutiny-transport-v2; do
      l="$(dep_line "$wm" "$d")"
      if echo "$l" | grep -q 'features'; then fail "wallet-core: $d dependency enables features or changes default-features: $l"; fi
    done
    got="$(list_features "$wm" | tr '\n' ' ')"
    if [ "$got" = "default test-value-signing " ]; then pass "wallet-core declares exactly default + test-value-signing"; else fail "wallet-core [features] = $got, expected exactly 'default test-value-signing'"; fi
    feat="$(tr -d '\r ' < "$wm" | sed -n '/^\[features\]/,/^\[/p')"
    if echo "$feat" | grep -qx 'default=\[\]'; then pass "wallet-core: default = [] (test-value-signing is not a default feature)"; else fail "wallet-core: default must be exactly [] (test-value-signing must never be default)"; fi
    if echo "$feat" | grep -qx 'test-value-signing=\[\]'; then pass "wallet-core: test-value-signing = [] (forwards nothing)"; else fail "wallet-core: test-value-signing must be exactly []"; fi
    if echo "$feat" | grep -v '^test-value-signing=' | grep -q 'test-value-signing'; then fail "wallet-core: another feature forwards test-value-signing"; else pass "wallet-core: no other feature forwards test-value-signing"; fi
    bad="$(manifest_deps "$wm" | grep -E "$GUI_RE|$OS_RE|$BTC_RE|$NET_RE|^bip39$" | tr '\n' ' ')"
    if [ -z "$bad" ]; then pass "wallet-core: no GUI, OS, V1-key, bip39, Bitcoin or network dependency in any dependencies table (normal, dev, build, target)"; else fail "wallet-core: forbidden dependency name(s) in its manifest: $bad"; fi
  fi
else
  skip "wallet-core: manifest checks not run (pending: wallet-core/ is created by phase 1; they apply as soon as it exists)"
fi

echo "== Source greps (forbidden cfg)"
if grep -rnE 'feature *= *"trading-(candidate|qualification|license-hook)"' "$ROOT/consensus/src" "$ROOT/consensus/tests" "$ROOT/consensus/examples" "$ROOT/node/src" "$ROOT/node/tests" "$ROOT/crypto-v2/src" "$ROOT/transport-v2/src" 2>/dev/null; then
  fail "removed trading-* feature referenced in source"; else pass "no trading-candidate/qualification/license-hook cfg anywhere"; fi
bad="$(grep -rnE 'cfg(_attr)?!?\(.*feature *= *"' "$ROOT/consensus/src" | grep -vE '"(dividend-test-fixtures|legacy-v0-test-fixtures|actor-timer-test-fixtures|a2-local-fixture-generator)"' || true)"
if [ -z "$bad" ]; then pass "consensus/src: only test-fixture feature cfgs"; else fail "consensus/src: unexpected feature cfg"; echo "$bad"; fi
bad="$(grep -rnE 'cfg(_attr)?!?\(.*feature *= *"' "$ROOT/node/src" | grep -vE '"(trading-service|trading-local-storage-candidate|trading-bitcoin-candidate)"' || true)"
if [ -z "$bad" ]; then pass "node/src: only trading-service (+2 staged-only overlay cfgs) feature cfgs"; else fail "node/src: unexpected feature cfg"; echo "$bad"; fi
cnt="$(grep -rn 'feature *= *"trading-service"' "$ROOT/node/src" | wc -l | tr -d ' ')"
if [ "$cnt" = "2" ]; then pass "trading-service gates exactly 2 sites (lib.rs module, HybridRuntime::preview_trading)"; else fail "trading-service gate count = $cnt (expected 2)"; fi
for d in release-signer/src; do
  bad="$(grep -rnE 'cfg(_attr)?!?\(.*feature *= *"' "$ROOT/$d" 2>/dev/null | tr -d '\r' || true)"
  if [ -z "$bad" ]; then pass "$d: no feature cfg (the crate declares no features)"; else fail "$d: feature cfg in a crate that declares no features"; echo "$bad"; fi
done
if [ "$HAVE_WC" = 1 ]; then
  bad="$(grep -rnE 'cfg(_attr)?!?\(.*feature *= *"' "$ROOT/wallet-core/src" "$ROOT/wallet-core/tests" "$ROOT/wallet-core/examples" "$ROOT/wallet-core/benches" 2>/dev/null | tr -d '\r' | grep -vE '"test-value-signing"' || true)"
  if [ -z "$bad" ]; then pass "wallet-core: only the declared test-value-signing feature is used in cfgs"; else fail "wallet-core: unexpected feature cfg"; echo "$bad"; fi
  envbad=""
  while IFS= read -r f; do
    first="$(grep -n '^#\[cfg(test)\]' "$f" | head -1 | cut -d: -f1)"
    while IFS=: read -r ln rest; do
      [ -z "$ln" ] && continue
      if [ -z "$first" ] || [ "$ln" -lt "$first" ]; then envbad="$envbad $f:$ln"; fi
    done < <(grep -nE 'env::var|option_env!' "$f")
  done < <(find "$ROOT/wallet-core/src" -name '*.rs' ! -name '*_tests.rs' 2>/dev/null)
  if [ -z "$envbad" ]; then pass "wallet-core/src: every environment read is inside a test module"; else fail "wallet-core/src: environment read outside tests (the UI-free core is hermetic):$envbad"; fi
else
  skip "wallet-core: source greps not run (pending: wallet-core/ is created by phase 1)"
fi
# Host independence (TPM admission package, docs/BUILD-CONFIGURATIONS-V1.md section 13). No developer
# host alias, helper path or the former ambient profile pin in any shipped crate source (tests
# included) or shipping configuration record; historical records and docs are out of scope.
HOST_STRINGS="mutiny-node2 mutinyadmin tpm_signer.py linux_tpm_signing_helper serve-qualification MUTINYD_PHYSICAL_PROFILE_COMMITMENT"
hostbad=""
for s in $HOST_STRINGS; do
  hits="$(grep -rlF -- "$s" "$ROOT/consensus/src" "$ROOT/node/src" "$ROOT/crypto-v2/src" "$ROOT/transport-v2/src" "$ROOT/build/shipping-configurations-v1.json" 2>/dev/null | tr '\n' ' ')"
  [ -n "$hits" ] && hostbad="$hostbad [$s: $hits]"
done
if [ -z "$hostbad" ]; then pass "shipped crate sources and shipping config name no developer host alias or helper"; else fail "host-specific strings in shipped sources/config:$hostbad"; fi
if grep -rnE 'examples/support|external_helper_bridge|tpm_bridge' "$ROOT/consensus/src" "$ROOT/node/src" "$ROOT/crypto-v2/src" "$ROOT/transport-v2/src" 2>/dev/null; then
  fail "shipped source references the qualification-only external helper bridge"; else pass "qualification-only external helper bridge unreachable from shipped source"; fi
# Host-identity, process-environment and string-assembly spellings in NON-TEST consensus/src and node/src
# code: build/check-host-independence.pl, a TRIPWIRE (not a proof) that applies the rules and the explicit
# allow-list of build/host-independence-rules.txt with the same model of test code (brace/bracket-tracked
# #[cfg(test)] items, code after them on the same line counts as shipped, transitive #[path] test files) as
# consensus/tests/host_independence_guard.rs. Its self-test runs build/host-independence-probes.txt.
if command -v perl >/dev/null 2>&1; then
  hiout="$(perl "$ROOT/build/check-host-independence.pl" --root "$ROOT" 2>&1)"; hirc=$?
  hiout="$(printf '%s\n' "$hiout" | tr -d '\r')"
  if [ "$hirc" = 0 ]; then pass "host independence (tripwire): $(printf '%s\n' "$hiout" | sed -n 's/^SUMMARY //p')"
  else
    hin=0
    while IFS= read -r l; do hin=$((hin+1)); fail "host independence: ${l#FINDING }"; done < <(printf '%s\n' "$hiout" | grep '^FINDING ')
    [ "$hin" = 0 ] && fail "host independence: the scanner failed (rc=$hirc): $(printf '%s\n' "$hiout" | tail -3 | tr '\n' ' ')"
  fi
  stout="$(perl "$ROOT/build/check-host-independence.pl" --root "$ROOT" --selftest 2>&1)"; strc=$?
  stout="$(printf '%s\n' "$stout" | tr -d '\r')"
  if [ "$strc" = 0 ]; then pass "host-independence tripwire self-test: $(printf '%s\n' "$stout" | sed -n 's/^SELFTEST //p') (build/host-independence-probes.txt)"
  else fail "host-independence tripwire self-test: $(printf '%s\n' "$stout" | grep -E 'MISMATCH|^SELFTEST' | tr '\n' ' ')"; fi
else
  fail "host independence: perl is required to run build/check-host-independence.pl"
fi
# Signing calls in NON-TEST wallet-core/src and desktop/src code (fixes of the independent wallet review, MAJOR-2;
# docs/BUILD-CONFIGURATIONS-V1.md section 14): build/check-signing-calls.pl, a TRIPWIRE (not the property: the type
# system is, with the crate-private KindSigner and the single-use Approval only the review gate constructs). Same lexer
# and test-code model as the host-independence tripwire (build/rust-source-model.pl); every call of a signing name
# (build/signing-call-rules.txt: sign, approve, sign_*; method, path or bare syntax) must be on the EXACT allow-list
# (file, enclosing fn, callee, count), and a Domain:: path inside a signing call's arguments is a finding of its own.
# Its self-test runs build/signing-call-probes.txt (the review's three probes among them).
if [ "$HAVE_WC" = 1 ] && command -v perl >/dev/null 2>&1; then
  scout="$(perl "$ROOT/build/check-signing-calls.pl" --root "$ROOT" 2>&1)"; scrc=$?
  scout="$(printf '%s\n' "$scout" | tr -d '\r')"
  if [ "$scrc" = 0 ]; then pass "signing calls (tripwire): $(printf '%s\n' "$scout" | sed -n 's/^SUMMARY //p')"
  else
    scn=0
    while IFS= read -r l; do scn=$((scn+1)); fail "signing calls: ${l#FINDING }"; done < <(printf '%s\n' "$scout" | grep '^FINDING ')
    [ "$scn" = 0 ] && fail "signing calls: the scanner failed (rc=$scrc): $(printf '%s\n' "$scout" | tail -3 | tr '\n' ' ')"
  fi
  scst="$(perl "$ROOT/build/check-signing-calls.pl" --root "$ROOT" --selftest 2>&1)"; scstrc=$?
  scst="$(printf '%s\n' "$scst" | tr -d '\r')"
  if [ "$scstrc" = 0 ]; then pass "signing-call tripwire self-test: $(printf '%s\n' "$scst" | sed -n 's/^SELFTEST //p') (build/signing-call-probes.txt)"
  else fail "signing-call tripwire self-test: $(printf '%s\n' "$scst" | grep -E 'MISMATCH|^SELFTEST' | tr '\n' ' ')"; fi
elif [ "$HAVE_WC" = 1 ]; then
  fail "signing calls: perl is required to run build/check-signing-calls.pl"
else
  skip "signing calls: wallet-core/ is absent (the tripwire scans wallet-core/src and desktop/src)"
fi

echo "== Static guards"
head -8 "$ROOT/node/src/main.rs" | tr -d '\r' > "${TMPDIR:-/tmp}/mutiny-guard-head.$$"
if grep -q '!mutiny_crypto_v2::RECEIPT_QUALIFICATION_ENABLED' "${TMPDIR:-/tmp}/mutiny-guard-head.$$" \
   && grep -q '!mutiny_crypto_v2::WALLET_CUSTODY_ENABLED && !mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED' "${TMPDIR:-/tmp}/mutiny-guard-head.$$"; then
  pass "node bin guard present (receipt-qualification, wallet-custody, release-custody)"; else fail "node bin static guard missing/changed"; fi
rm -f "${TMPDIR:-/tmp}/mutiny-guard-head.$$"
for k in RECEIPT_QUALIFICATION_ENABLED DIVIDEND_TEST_FIXTURES_ENABLED LEGACY_V0_TEST_FIXTURES_ENABLED; do
  if head -20 "$ROOT/node/src/lib.rs" | grep -q "!mutiny_.*$k"; then pass "node lib guard present: $k"; else fail "node lib guard missing: $k"; fi
done
if grep -qE '^pub const DIVIDEND_TEST_FIXTURES_ENABLED' "$ROOT/consensus/src/lib.rs" && grep -qE '^pub const LEGACY_V0_TEST_FIXTURES_ENABLED' "$ROOT/consensus/src/lib.rs"; then
  pass "consensus exports fixture-feature constants"; else fail "consensus fixture constants missing"; fi
if head -8 "$ROOT/desktop/src/main.rs" | tr -d '\r' | grep -q '!mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED'; then pass "desktop bin guard present (no release-custody)"; else fail "desktop bin static guard (no release-custody) missing/changed"; fi
# Phase 7: the desktop bin asserts wallet-core's TEST-VALUE gate is absent from every build with the shipping profile
# (debug-assertions = false, required of the release table above): the exact three lines, near the top of main.rs.
if head -24 "$ROOT/desktop/src/main.rs" | tr -d '\r' | awk 'p2 && $0=="    !mutiny_wallet_core_v8::TEST_VALUE_SIGNING_ENABLED," {ok=1} {p2=(p1 && $0=="const _: () = assert!("); p1=($0=="#[cfg(all(not(test), not(debug_assertions)))]")} END {exit !ok}'; then
  pass "desktop bin guard present (no wallet-core TEST-VALUE gate in a shipping-profile build)"
else fail "desktop bin static guard (no wallet-core TEST-VALUE gate) missing/changed"; fi
if head -8 "$ROOT/release-signer/src/main.rs" | tr -d '\r' | grep -q '!mutiny_crypto_v2::WALLET_CUSTODY_ENABLED'; then pass "release-signer bin guard present (no wallet-custody)"; else fail "release-signer bin static guard (no wallet-custody) missing/changed"; fi
if [ "$HAVE_WC" = 1 ]; then
  for k in RELEASE_CUSTODY_ENABLED RECEIPT_QUALIFICATION_ENABLED DIVIDEND_TEST_FIXTURES_ENABLED LEGACY_V0_TEST_FIXTURES_ENABLED; do
    if grep -rhE "^[^/]*![a-z0-9_]*(mutiny_)[a-z0-9_]*::$k" "$ROOT/wallet-core/src" 2>/dev/null | grep -q .; then pass "wallet-core guard present: !$k"; else fail "wallet-core guard missing: a compile-time assert of !mutiny_*::$k in wallet-core/src"; fi
  done
else skip "wallet-core: static guards not checked (pending: wallet-core/ is created by phase 1)"; fi

echo "== Source paths under Linux (POSIX) semantics (build/check-source-paths.pl)"
# Static, a few seconds: every #[path] (from rustc's inline-module base directory), include!/include_str!/include_bytes!,
# mod declaration, Cargo.toml path and build-script input resolved component by component with exact case and `..` only
# through directories that exist (Windows collapses `..` lexically and ignores case, Linux does not); CRLF scripts;
# case-colliding or Windows-reserved names. Git work tree: the index is the tree; extracted package: the extracted files.
# Findings that only concern the Windows-only desktop are a WARN. Negative controls: build/negative-controls.sh paths_*.
SPC="$ROOT/build/check-source-paths.pl"
if [ ! -f "$SPC" ]; then fail "build/check-source-paths.pl is missing"
elif ! command -v perl >/dev/null 2>&1; then fail "source paths: perl is not on PATH (build/check-source-paths.pl needs it)"
else
  spout="$(perl "$SPC" --root "$ROOT" 2>&1)"; sprc=$?
  spout="$(printf '%s\n' "$spout" | tr -d '\r')"
  spsum="$(printf '%s\n' "$spout" | grep '^check-source-paths: ' | tail -1)"
  if [ "$sprc" = 0 ] && [ -n "$spsum" ]; then pass "source paths (Linux semantics, $MODE mode): ${spsum#check-source-paths: }"
  else
    printf '%s\n' "$spout" | grep -v '^check-source-paths: ' | grep -v ': windows-only: ' | sed 's/^/    | /'
    fail "source paths: build/check-source-paths.pl exit $sprc: ${spsum#check-source-paths: }"
  fi
  spwin="$(printf '%s\n' "$spout" | grep -c ': windows-only: ')"
  if [ "$spwin" != 0 ]; then
    printf '%s\n' "$spout" | grep ': windows-only: ' | sed 's/^/    | /'
    warn "source paths: $spwin windows-only finding(s) (desktop or cfg(windows) code; not built on Linux)"
  fi
fi

echo "== Resolved feature graph (node: target $LINUX; wallet-core: both targets; desktop: $WINDOWS; release-signer: both; normal+build edges only; no --all-features)"
check_graph "node-validator"                 node mutinyd-v8 ""                --no-default-features
check_graph "node-validator+trading-service" node mutinyd-v8 "trading-service" --no-default-features --features trading-service
# test-value-signing / wallet-core must not be reachable from a validator at all.
for variant in "node-validator|--no-default-features" "node-validator+trading-service|--no-default-features --features trading-service"; do
  vl="${variant%%|*}"; va="${variant#*|}"
  vt="$(tree_pkgs node mutinyd-v8 "$LINUX" $va)"
  if [ -n "$vt" ]; then expect_spec "$vl" "$vt" mutiny-wallet-core-v8 ABSENT; fi
done
# wallet-core (library; Linux and Windows): crypto-v2 wallet-custody ONLY; consensus/node/transport default only if present;
# default feature set only (test-value-signing off); no GUI/OS/V1-key/network crate; Bitcoin boundary.
if [ "$HAVE_WC" = 1 ]; then
  for T in $LINUX $WINDOWS; do
    L="wallet-core [$T]"
    if ! can_resolve wallet-core; then skip "$L: cannot resolve offline here (no vendored sources)"; continue; fi
    if graph_component "$L" wallet-core mutiny-wallet-core-v8 "$T" "REQ:default" "REQ:wallet-custody" "OPT:default" "OPT:default" "OPT:" "ABSENT"; then
      forbid_re "$L" "$GRAPH" "$GUI_RE" "GUI/windowing (eframe, egui, winit, glutin, glow, arboard)"
      forbid_re "$L" "$GRAPH" "$OS_RE" "OS-binding/V1-key (windows-sys, ed25519-dalek-bip32)"
      forbid_re "$L" "$GRAPH" "$NET_RE" "network"
      bitcoin_boundary "$L" wallet-core mutiny-wallet-core-v8 "$T" "$GRAPH" "mutiny-crypto-v2"
    fi
  done
else
  skip "wallet-core: graph checks not run (pending: wallet-core/ is created by phase 1)"
fi
# desktop (Windows target only: it does not build on Linux; cargo tree resolves, it does not compile).
if can_resolve desktop; then
  L="wallet-desktop [$WINDOWS]"
  # Since phase 7 wallet-core is REQUIRED in the desktop graph, at its default features only (no test-value-signing).
  if graph_component "$L" desktop mutiny-desktop-v8 "$WINDOWS" "REQ:" "REQ:wallet-custody" "REQ:default" "REQ:default" "REQ:" "REQ:default"; then
    expect_spec "$L" "$GRAPH" eframe "REQ:default_fonts,glow"
    forbid_re "$L" "$GRAPH" "$NET_RE" "network"
    pend=0; echo "$GRAPH" | cut -d'|' -f1 | grep -qx ed25519-dalek-bip32 && pend=1
    pending_check "$L" wallet-desktop "$pend" ed25519-dalek-bip32 "the V1 key-derivation crate ed25519-dalek-bip32"
    b39=0; case " $(dependents_of desktop mutiny-desktop-v8 "$WINDOWS" bip39) " in *" mutiny-desktop-v8 "*) b39=1 ;; esac
    pending_check "$L" wallet-desktop "$b39" bip39-direct "the direct (V1) bip39 dependency"
    allowed="mutiny-crypto-v2"; [ "$b39" = 1 ] && allowed="mutiny-crypto-v2 mutiny-desktop-v8"
    bitcoin_boundary "$L" desktop mutiny-desktop-v8 "$WINDOWS" "$GRAPH" "$allowed"
  fi
else
  skip "wallet-desktop: resolved-graph checks not run (not vendored in this package; cargo cannot resolve it offline here). The manifest checks above and the lock hash below still apply; the graph checks run in the repository and on the Windows runner."
fi
# release-signer (host/offline; both targets): crypto-v2 release-custody ONLY; no consensus/node/transport/wallet-core.
if can_resolve release-signer; then
  for T in $LINUX $WINDOWS; do
    L="release-signer [$T]"
    if graph_component "$L" release-signer mutiny-offline-release-signer "$T" "REQ:" "REQ:release-custody" "ABSENT" "ABSENT" "ABSENT" "ABSENT"; then
      forbid_re "$L" "$GRAPH" "$GUI_RE" "GUI/windowing"
      forbid_re "$L" "$GRAPH" '^(rusqlite|libsqlite3-sys|ed25519-dalek-bip32)$' "sqlite/V1-key"
      bitcoin_boundary "$L" release-signer mutiny-offline-release-signer "$T" "$GRAPH" "mutiny-crypto-v2"
    fi
  done
else
  skip "release-signer: resolved-graph checks not run (not vendored in this package; cargo cannot resolve it offline here). The manifest checks above and the lock hash below still apply; the graph checks run in the repository and on the Windows runner."
fi

echo "== Lockfiles and recorded hashes"
LOCKROOTS="consensus node crypto-v2 transport-v2 desktop release-signer treasury-application"
for c in $LOCKROOTS; do
  vend=1; if [ "$MODE" = package ] && [ ! -f "$ROOT/$c/.cargo/config.toml" ]; then vend=0; fi
  if can_resolve "$c"; then
    if ( cd "$ROOT/$c" && cargo metadata $CARGO_FLAGS --format-version 1 >/dev/null 2>&1 ); then pass "$c: cargo metadata --locked ok"; else fail "$c: cargo metadata --locked failed"; fi
  else
    skip "$c: cargo metadata --locked not run (not vendored in this package and the host's offline cache cannot resolve it); the lock hash is compared with the recorded value below and PACKAGE-MANIFEST.sha256 covers the file"
  fi
  if [ "$MODE" = git ]; then
    if git -C "$ROOT" ls-files --error-unmatch "$c/Cargo.lock" >/dev/null 2>&1; then
      if git -C "$ROOT" diff --quiet -- "$c/Cargo.lock"; then pass "$c: Cargo.lock unmodified vs index"; else fail "$c: Cargo.lock differs from index"; fi
    else fail "$c: Cargo.lock is not tracked"; fi
  elif [ "$vend" = 0 ]; then
    :  # a root that is not vendored in a package has no PACKAGE-IDENTITY entry: its identity is the recorded value below plus PACKAGE-MANIFEST.sha256
  elif [ -f "$ROOT/PACKAGE-IDENTITY.json" ]; then
    pk="$(tr -d '\r' < "$ROOT/PACKAGE-IDENTITY.json" | grep -F "\"$c/Cargo.lock\"" | head -1 | sed -E 's/.*: *"([0-9a-f]{64})".*/\1/')"
    if [ "$pk" = "$(sha256sum "$ROOT/$c/Cargo.lock" | cut -d' ' -f1)" ]; then pass "$c: Cargo.lock equals the PACKAGE-IDENTITY.json value (package mode)"; else fail "$c: Cargo.lock differs from PACKAGE-IDENTITY.json [$pk]"; fi
  else fail "$c: no git index and no PACKAGE-IDENTITY.json: lockfile identity cannot be checked"; fi
done
# Recorded sha256 values (JSON) vs the lockfiles. A checkout with CRLF conversion is accepted.
for c in $LOCKROOTS; do
  want="$(tr -d '\r' < "$JSON" | grep -F "\"path\": \"$c/Cargo.lock\"" | head -1 | sed -E 's/.*"sha256": *"([0-9a-f]{64})".*/\1/')"
  raw="$(sha256sum "$ROOT/$c/Cargo.lock" | cut -d' ' -f1)"
  lf="$(tr -d '\r' < "$ROOT/$c/Cargo.lock" | sha256sum | cut -d' ' -f1)"
  if [ "$want" = "$raw" ] || [ "$want" = "$lf" ]; then pass "$c/Cargo.lock sha256 matches the recorded value"; else fail "$c/Cargo.lock sha256 [$raw] != recorded [$want]"; fi
done
# wallet-core: pending ONLY while wallet-core/ is absent; a real, matching entry is required as soon as it exists.
wl="$(tr -d '\r' < "$JSON" | grep -F '"path": "wallet-core/Cargo.lock"' | head -1)"
if [ -z "$wl" ]; then fail "build/shipping-configurations-v1.json has no lockfile entry for wallet-core/Cargo.lock"
elif [ "$HAVE_WC" = 0 ]; then
  if echo "$wl" | grep -qE '"sha256": *null' && echo "$wl" | grep -qE '"pending": *"created by phase 1"'; then pass "wallet-core/Cargo.lock is recorded as pending (created by phase 1) while wallet-core/ is absent"
  else fail "wallet-core/ is absent but its lockfile entry is not the pending marker (sha256 null + \"pending\": \"created by phase 1\")"; fi
else
  want="$(echo "$wl" | sed -n -E 's/.*"sha256": *"([0-9a-f]{64})".*/\1/p')"
  if [ -z "$want" ]; then fail "wallet-core/ exists but build/shipping-configurations-v1.json has no lockfile sha256 for it (a pending entry is tolerated only while wallet-core/ is absent)"
  elif echo "$wl" | grep -q '"pending"'; then fail "wallet-core/ exists: the lockfile entry still carries a pending marker; remove it"
  elif [ ! -f "$ROOT/wallet-core/Cargo.lock" ]; then fail "wallet-core/Cargo.lock does not exist (wallet-core/ is present)"
  else
    raw="$(sha256sum "$ROOT/wallet-core/Cargo.lock" | cut -d' ' -f1)"
    lf="$(tr -d '\r' < "$ROOT/wallet-core/Cargo.lock" | sha256sum | cut -d' ' -f1)"
    if [ "$want" = "$raw" ] || [ "$want" = "$lf" ]; then pass "wallet-core/Cargo.lock sha256 matches the recorded value"; else fail "wallet-core/Cargo.lock sha256 [$raw] != recorded [$want]"; fi
    if can_resolve wallet-core; then
      if ( cd "$ROOT/wallet-core" && cargo metadata $CARGO_FLAGS --format-version 1 >/dev/null 2>&1 ); then pass "wallet-core: cargo metadata --locked ok"; else fail "wallet-core: cargo metadata --locked failed"; fi
    else skip "wallet-core: cargo metadata not checked (no vendored sources)"; fi
    if [ "$MODE" = git ]; then
      if git -C "$ROOT" ls-files --error-unmatch wallet-core/Cargo.lock >/dev/null 2>&1; then
        if git -C "$ROOT" diff --quiet -- wallet-core/Cargo.lock; then pass "wallet-core: Cargo.lock unmodified vs index"; else fail "wallet-core: Cargo.lock differs from index"; fi
      else fail "wallet-core: Cargo.lock is not tracked"; fi
    elif [ -f "$ROOT/PACKAGE-IDENTITY.json" ]; then
      pk="$(tr -d '\r' < "$ROOT/PACKAGE-IDENTITY.json" | grep -F '"wallet-core/Cargo.lock"' | head -1 | sed -E 's/.*: *"([0-9a-f]{64})".*/\1/')"
      if [ "$pk" = "$raw" ]; then pass "wallet-core: Cargo.lock equals the PACKAGE-IDENTITY.json value (package mode)"; else fail "wallet-core: Cargo.lock differs from PACKAGE-IDENTITY.json [$pk]"; fi
    else fail "wallet-core: no git index and no PACKAGE-IDENTITY.json: lockfile identity cannot be checked"; fi
  fi
fi
# The documentation table repeats the lock hashes (first 12 hex digits); it must agree with the real files.
if [ -f "$DOC" ]; then
  dbad=""
  for c in $LOCKROOTS; do
    raw="$(sha256sum "$ROOT/$c/Cargo.lock" | cut -d' ' -f1)"
    grep -qF "${raw:0:12}" "$DOC" || dbad="$dbad $c"
  done
  if [ "$HAVE_WC" = 1 ] && [ -f "$ROOT/wallet-core/Cargo.lock" ]; then
    raw="$(sha256sum "$ROOT/wallet-core/Cargo.lock" | cut -d' ' -f1)"; grep -qF "${raw:0:12}" "$DOC" || dbad="$dbad wallet-core"
  elif [ "$HAVE_WC" = 0 ]; then grep -q 'wallet-core/Cargo.lock.*pending' "$DOC" || dbad="$dbad wallet-core(pending)"; fi
  if [ -z "$dbad" ]; then pass "docs/BUILD-CONFIGURATIONS-V1.md lists the current lockfile hashes (12-digit prefixes)"; else fail "docs/BUILD-CONFIGURATIONS-V1.md does not list the current lockfile hash of:$dbad"; fi
else fail "docs/BUILD-CONFIGURATIONS-V1.md is missing"; fi
# The JSON records the import commits that the provenance record names, and the crypto-v2 features the graph checks enforce.
ibad=""
if [ -f "$ROOT/build/imports/IMPORT-COMMITS-V1.tsv" ]; then
  while IFS=$'\t' read -r mf msha mcommit extra; do
    case "$mf" in ''|'#'*) continue ;; esac
    tr -d '\r' < "$JSON" | grep -qF "$mcommit" || ibad="$ibad $mf"
  done < <(tr -d '\r' < "$ROOT/build/imports/IMPORT-COMMITS-V1.tsv")
fi
if [ -z "$ibad" ]; then pass "the JSON import_provenance names every import commit recorded in build/imports/IMPORT-COMMITS-V1.tsv"; else fail "the JSON import_provenance does not name the import commit of:$ibad"; fi
jbad=""
[ "$(json_dep_features wallet-desktop mutiny-crypto-v2)" = "wallet-custody" ] || jbad="$jbad wallet-desktop"
[ "$(json_dep_features release-signer mutiny-crypto-v2)" = "release-custody" ] || jbad="$jbad release-signer"
[ "$(json_dep_features wallet-core mutiny-crypto-v2)" = "wallet-custody" ] || jbad="$jbad wallet-core"
# Phase 7: the JSON records the desktop's wallet-core edge at default features (no test-value-signing).
[ "$(json_dep_features wallet-desktop mutiny-wallet-core-v8)" = "" ] || jbad="$jbad wallet-desktop(mutiny-wallet-core-v8)"
if [ -z "$jbad" ]; then pass "the JSON records crypto-v2 features wallet-custody (wallet-core, wallet-desktop) and release-custody (release-signer), and the desktop's wallet-core edge at default features, as enforced above"; else fail "the JSON crypto-v2 feature record disagrees with the enforced policy for:$jbad"; fi

echo "== Import provenance (build/check-import-provenance.sh)"
if [ -f "$ROOT/build/check-import-provenance.sh" ]; then
  prov="$(bash "$ROOT/build/check-import-provenance.sh" 2>&1)"; prc=$?
  echo "$prov" | sed 's/^/    | /'
  if [ "$prc" = 0 ]; then pass "import provenance: $(echo "$prov" | grep '^RESULT')"; else fail "import provenance: $(echo "$prov" | grep '^RESULT')"; fi
else fail "build/check-import-provenance.sh is missing"; fi

if [ "$FAST" = 0 ]; then
  echo "== -D unexpected_cfgs compile checks (no --all-features)"
  export RUSTFLAGS="-D unexpected_cfgs"
  cc() { # label dir cargo-args...
    local label="$1" dir="$2"; shift 2
    if ( cd "$ROOT/$dir" && cargo check $CARGO_FLAGS "$@" 2>&1 | tail -3 ) | grep -q Finished; then pass "$label"; else fail "$label"; fi
  }
  cc "consensus lib (default) -D unexpected_cfgs" consensus --lib
  cc "consensus lib +dividend-test-fixtures (CI test config) -D unexpected_cfgs" consensus --lib --features dividend-test-fixtures
  cc "consensus lib +legacy-v0-test-fixtures (CI test config) -D unexpected_cfgs" consensus --lib --features legacy-v0-test-fixtures
  cc "crypto-v2 lib (default) -D unexpected_cfgs" crypto-v2 --lib
  cc "transport-v2 lib -D unexpected_cfgs" transport-v2 --lib
  cc "node validator -D unexpected_cfgs" node --lib --bins --no-default-features
  cc "node validator+trading-service -D unexpected_cfgs" node --lib --bins --no-default-features --features trading-service
  if can_resolve release-signer; then cc "release-signer lib+bins -D unexpected_cfgs" release-signer --lib --bins; else skip "release-signer: -D unexpected_cfgs compile check not run (not vendored in this package)"; fi
  if [ "$HAVE_WC" = 1 ]; then
    cc "wallet-core lib (default) -D unexpected_cfgs" wallet-core --lib
    cc "wallet-core lib +test-value-signing (NON-SHIPPING CI config) -D unexpected_cfgs" wallet-core --lib --features test-value-signing
  else skip "wallet-core: -D unexpected_cfgs compile checks not run (pending: wallet-core/ is created by phase 1)"; fi
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      if can_resolve desktop; then cc "desktop bins (Windows host) -D unexpected_cfgs" desktop --bins
      else skip "desktop: -D unexpected_cfgs compile check not run (not vendored in this package: its dependency tree cannot be resolved offline here)"; fi ;;
    *) skip "desktop: -D unexpected_cfgs compile check needs a Windows host (eframe/winit/windows-sys); it runs on the Windows runner" ;;
  esac
  unset RUSTFLAGS
fi

echo "== Release binary string checks (every built shipping binary)"
# BUILD8_BINARIES: space-separated release binaries to inspect (the Linux runner passes the default and
# the trading-service builds; the Windows runner passes the wallet and the signer). The rule set is chosen
# from the file name: mutinyd-v8* = node (the original list, unchanged); mutiny-wallet-v8* = wallet (Order W8,
# candidate 3: formerly mutiny-desktop-v8-ceremony; a binary under a retired mutiny-desktop-v8* name FAILS: it is a stale
# artefact, never a shipping binary of this source);
# mutiny-offline-release-signer = signer; bin-default and bin-trading-service are the Linux runner's node copies.
# Unknown names fail rather than selecting another component's rules. Library artefacts (rlib) are NOT scanned:
# rustc records cfg-stripped item names in an rlib's metadata, so a default-feature rlib legitimately contains the name of
# an item gated by test-value-signing (observed). The test-value markers are checked in linked executables only. On Windows the exe holds no Rust symbol names, so the sibling
# .pdb (same name with _ for -) is scanned too; a REQUIRED string must be in the binary or its pdb.
# Without BUILD8_BINARIES the default target folder is searched as before (and now also for the wallet and signer).
BINS="${BUILD8_BINARIES:-}"
if [ "${BUILD8_BINARIES+x}" != x ]; then
  TD="${CARGO_TARGET_DIR:-$ROOT/node/target}"
  for cand in "$TD/release/mutinyd-v8" "$TD/release/mutinyd-v8.exe"; do [ -f "$cand" ] && BINS="$cand"; done
  # (MSYS reports an extension-less name as existing when only the .exe does; scan each binary once.)
  for b in mutiny-wallet-v8 mutiny-offline-release-signer mutiny-wallet-v8-testvalue mutiny-treasury-v8-testvalue; do
    if [ -f "$TD/release/$b.exe" ]; then BINS="$BINS $TD/release/$b.exe"; elif [ -f "$TD/release/$b" ]; then BINS="$BINS $TD/release/$b"; fi
  done
fi
A2_FIXTURE_FORBIDDEN="generate_protected_local_synthetic_a2_native_fixture BUILD8_A2_LOCAL_SOFTWARE_FIXTURE"
NODE_FORBIDDEN="MUTINY-BUILD8-QUAL-RECEIPT-ADAPTER-V1 DurableVoter fixture_suspend fixture_revoke fixture_advance_dividends MonotonicTimer BUILD8_SYNTHETIC_ TRADING_COMPLETION_CRASH TRADING_STORAGE_CRASH RECOVERY_CRASH_PHASE BUILD8_EXPORT_SYNTHETIC create_wallet_phrase qualification_wallet_entropy_provider MUTINY-WALLET-V8-TESTVALUE-WINDOW-V1 $A2_FIXTURE_FORBIDDEN $HOST_STRINGS"
# The wallet legitimately links create_wallet_phrase, so it is not forbidden there; CustodianSession is release custody.
# MUTINY-WALLET-CORE-TEST-VALUE-GATE-V1 is the marker wallet-core embeds when its TEST-VALUE gate is compiled in
# (wallet-core/src/authorize.rs TEST_VALUE_GATE_MARKER, referenced by SigningGate::test_value()).
WALLET_FORBIDDEN="MUTINY-BUILD8-QUAL-RECEIPT-ADAPTER-V1 DurableVoter fixture_suspend fixture_revoke fixture_advance_dividends MonotonicTimer BUILD8_SYNTHETIC_ TRADING_COMPLETION_CRASH TRADING_STORAGE_CRASH RECOVERY_CRASH_PHASE BUILD8_EXPORT_SYNTHETIC qualification_wallet_entropy_provider CustodianSession TestValueGate MUTINY-BUILD8-TEST-VALUE-SIGNING MUTINY-WALLET-CORE-TEST-VALUE-GATE-V1 MUTINY-WALLET-V8-TESTVALUE-WINDOW-V1 $A2_FIXTURE_FORBIDDEN $HOST_STRINGS"
SIGNER_FORBIDDEN="$NODE_FORBIDDEN wallet_restore MUTINY-BUILD8-DESKTOP-WALLET-CUSTODY-V2 mutiny_consensus WalletCustodyV2"
SIGNER_REQUIRED="CustodianSession"
if [ -n "$BINS" ]; then
  BIN_ITEMS=0
  for BIN in $BINS; do
    BIN_ITEMS=$((BIN_ITEMS+1))
    if [ ! -f "$BIN" ]; then echo "  FAIL  binary $BIN not found"; FAIL=$((FAIL+1)); continue; fi
    base="$(basename "$BIN")"; kind=node; forb="$NODE_FORBIDDEN"; req=""
    case "$base" in
      mutiny-wallet-v8-testvalue*|mutiny-treasury-v8-testvalue*) echo "  FAIL  $base: NON-SHIPPING W15 executable in shipping artifact set"; FAIL=$((FAIL+1)); continue ;;
      mutiny-desktop-v8*) echo "  FAIL  $base: retired wallet executable name (renamed to mutiny-wallet-v8 in candidate 3, Order W8); a stale artefact is not a shipping binary"; FAIL=$((FAIL+1)); continue ;;
    esac
    case "$base" in
      mutinyd-v8|mutinyd-v8.exe|bin-default|bin-default.exe|bin-trading-service|bin-trading-service.exe) ;;
      mutiny-wallet-v8|mutiny-wallet-v8.exe) kind=wallet; forb="$WALLET_FORBIDDEN" ;;
      mutiny-offline-release-signer|mutiny-offline-release-signer.exe) kind=signer; forb="$SIGNER_FORBIDDEN"; req="$SIGNER_REQUIRED" ;;
      *) fail "$base: unknown shipping component artifact name"; continue ;;
    esac
    files="$BIN"; stem="${BIN%.exe}"; pdb="$(dirname "$BIN")/$(basename "$stem" | tr '-' '_').pdb"
    if [[ "$BIN" == *.exe ]]; then
      if [ ! -f "$pdb" ]; then fail "$base: required Windows PDB not found: $pdb"; continue; fi
      files="$files $pdb"
    fi
    hit=0
    if ! command -v python3 >/dev/null 2>&1; then
      echo "  FAIL  $base: Python3 required for ASCII/UTF-16LE A2 linked-artifact scan"; hit=1
    elif ! python3 -I -B "$ROOT/build/check-a2-linked-artifacts.py" $files; then
      echo "  FAIL  $base: A2 linked-artifact exclusion"; hit=1
    fi
    for s in $forb; do
      for f in $files; do
        if grep -aqF "$s" "$f"; then echo "  FAIL  $(basename "$f") contains '$s'"; hit=1; fi
      done
    done
    for s in $req; do
      found=0; for f in $files; do grep -aqF "$s" "$f" && found=1; done
      if [ "$found" = 0 ]; then echo "  FAIL  $base ($kind) lacks the required string '$s' (in the binary or its pdb)"; hit=1; fi
    done
    if [ "$hit" = 0 ]; then
      if [ "$kind" = node ]; then pass "$base: none of the forbidden strings present"
      else pass "$base: none of the forbidden $kind strings present$( [ -n "$req" ] && echo ", required string(s) [$req] present" ) (scanned: $(echo $files | sed 's#[^ ]*/##g'))"; fi
    else FAIL=$((FAIL+1)); fi
  done
  if [ "$BIN_ITEMS" = 0 ]; then fail "release artifact list has no path tokens; linked exclusion is incomplete"; fi
else
  fail "no release binary supplied or found; linked artifact exclusion is incomplete"
fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
if [ "$SKIP" != 0 ] || [ "$WARN" != 0 ]; then echo "NOTE: $SKIP check(s) skipped (each reason is printed above), $WARN warning(s) (recorded pending items)"; fi
[ "$FAIL" = 0 ]
