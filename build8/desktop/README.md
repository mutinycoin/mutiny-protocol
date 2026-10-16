# Mutiny Build8

Fresh source history begun after Build7 operational absence verification.
Desktop Wallet V8 is the first deliverable. Genesis, consensus, nodes, miners and
LoRa implementation remain gated by the authorized sequence.

Build on Windows with Rust/MSVC (Rust 1.98.1, pinned by `rust-toolchain.toml`; every cargo call uses `--locked --offline` and never
`--all-features`; run from the repository root):

```powershell
cd desktop
cargo build --locked --offline --release
.\target\release\mutiny-wallet-v8.exe
```

The wallet executable is `mutiny-wallet-v8` (`[[bin]]` in `desktop/Cargo.toml`; the package keeps the name `mutiny-desktop-v8`).
Candidate 3 renamed it from `mutiny-desktop-v8-ceremony` (Order W8), a name that predated phase 0C's retirement of the V1
ceremony; the rename does not redefine the scope or branding of the wider Desktop product. The pinned toolchain is the `minimal` profile and carries no clippy.

**Current state of the desktop (read before using it).** In a non-test build the wallet is closed by two gates: `App::new` refuses
unconditionally and `wallet_v2::ready()` refuses while `mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED` is false, and the release
exe contains no custody code. Phase 0C (commit e34bd2c) retired the V1 Ed25519/BIP32 wallet: its identity, store, replica,
Genesis-binding, admission and firmware modules are gone, its payment draft too (`payment.rs` keeps only the amount parser), Windows
DPAPI moved into `desktop/src/dpapi_v2.rs`, and the GUI shell, which opens only in a test build, shows one closed-gate notice; it
creates, restores, unlocks and signs nothing and displays no recovery material. With `admission.rs` the
private NODE-A include left too, so `cargo test` for the desktop compiles again. The wallet and release-signer sources were imported
exactly as found (`build/imports/`); every later edit is recorded in `build/imports/EDITED-AFTER-IMPORT-V1.tsv`. The Windows build is
on `x86_64-pc-windows-msvc` only and does **not** build on Linux. The UI-free wallet library `wallet-core/` (phase 1: ordinary MUT
payments end to end with TEST-VALUE keys; production signing closed) is not linked by the desktop yet. How the wallet is built, what
it must and must not link, how it is tested and how the imports are verified:

* `docs/BUILD-CONFIGURATIONS-V1.md` and `build/shipping-configurations-v1.json`: the shipping configurations (node validator,
  wallet-core, Windows wallet, release signer), their production exclusion lists, lockfile hashes and the release profile.
* `bash build/check-shipping-config.sh [--fast]`: the exclusion checks; `bash build/check-import-provenance.sh`: the import identity
  check; `bash build/negative-controls.sh`: demonstrations that those checks fail when a forbidden thing is injected (scratch copy only).
* `package/windows-wallet-test/` (Windows, release signer + wallet) and `package/linux-native-test/` (Linux, validator libraries and
  wallet-core): offline TEST-VALUE test runners. A pass is at most NATIVE PASS (offline, TEST-VALUE), never a qualification.

The V1 create/restore ceremony this README used to describe (**CREATE NEW WALLET**, the written 24 words and their
confirmation, **Start clean restore qualification**, local data under `%LOCALAPPDATA%\Mutiny Build8` with
`restore-qualification.json`) was retired by phase 0C and is no longer in this tree. No real wallet exists merely from
building or running tests. Never send recovery words or passwords to Codex or any other assistant.

[spec/WALLET-V1.md](spec/WALLET-V1.md) specifies the retired V1 wallet (derivation, encryption and limitations) and is kept for
provenance under a status banner. `spec/verify_public_test_vector.py` independently reproduces that V1 known-public zero-entropy
fixture using Python cryptography; it never takes a real phrase as input. Never use that public fixture as a real wallet. The
active V2 custody is crypto-v2 `wallet-custody` (hybrid Ed448 + FN-DSA-1024): `desktop/src/wallet_v2.rs` and `wallet-core/`,
behind closed production gates.

Payment controls are deliberately unavailable until the locked Genesis and node
gates. No balances, transaction confirmations or network status are fabricated.
