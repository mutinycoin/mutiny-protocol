#!/usr/bin/env bash
# Ordinary Treasury root graph gate. No compilation, fixture or custody action.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/treasury-application"
test -f "$APP/Cargo.toml"
test -f "$APP/Cargo.lock"
test -f "$ROOT/treasury-sqlite-provider/Cargo.toml"
GRAPH="$(cd "$APP" && cargo tree --offline --locked --target x86_64-unknown-linux-gnu -e normal,build --prefix none --no-dedupe -f '{p}|{f}')"
test -n "$GRAPH"
if printf '%s\n' "$GRAPH" | grep -E 'mutiny-consensus-v8.*(dividend-test-fixtures|legacy-v0-test-fixtures|actor-timer-test-fixtures|a2-local-fixture-generator)' >/dev/null; then
  echo 'FAIL Treasury NORMAL graph contains a consensus fixture feature'; exit 1
fi
if printf '%s\n' "$GRAPH" | grep -E 'mutiny-crypto-v2.*(release-custody|receipt-qualification|qualification)' >/dev/null; then
  echo 'FAIL Treasury NORMAL graph contains release/qualification custody'; exit 1
fi
# Transport authentication unsealing needs the existing wallet-custody software
# feature; opened material is restricted to Role::Transport by the exact entry.
printf '%s\n' "$GRAPH" | grep -E '^mutiny-crypto-v2 .*\|.*wallet-custody' >/dev/null
printf '%s\n' "$GRAPH" | grep -E '^libsqlite3-sys .*treasury-sqlite-provider' >/dev/null
test "$(printf '%s\n' "$GRAPH" | grep -E '^libsqlite3-sys ' | sort -u | wc -l)" -eq 1
if printf '%s\n' "$GRAPH" | grep -E '^(bitcoin[-_a-z0-9]*|secp256k1[-_a-z0-9]*|bdk[-_a-z0-9]*|miniscript|psbt|bitcoincore-rpc|rust-bitcoin|electrum[-_a-z0-9]*|esplora[-_a-z0-9]*) ' >/dev/null; then
  echo 'FAIL Treasury graph contains protocol BTC custody dependency'; exit 1
fi
grep -F 'static INSTALLED:Option<InstalledSelection>=None;' "$APP/src/treasury_application_enrollment_v1.rs" >/dev/null
grep -F 'compile_error!("reviewed application projection is Linux-only")' "$APP/src/treasury_application_modules_v1.rs" >/dev/null
echo 'PASS Treasury ordinary root NORMAL graph, single native SQLite provider and missing production enrollment'
