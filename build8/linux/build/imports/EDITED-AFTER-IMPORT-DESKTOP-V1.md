# EDITED-AFTER-IMPORT-DESKTOP-V1
#
# Every change made to the desktop sources after the explicit import commit 121479b (the as-found
# originals; their hashes are in build/imports/IMPORT-MANIFEST-WALLET-RELEASE-SIGNER-V1.sha256).
# Branch wallet/p0c-desktop, phase 0C (desktop hygiene). Desktop files NOT listed below are
# byte-identical to that import.
# The machine-checked record of these edits is build/imports/EDITED-AFTER-IMPORT-V1.tsv (read by
# build/check-import-provenance.sh, which fails on any unrecorded difference); this file is the human narrative.
#
# Record lines: path<TAB>sha256-or-REMOVED<TAB>reason   (fields separated by one TAB character)
#   path    repository-relative, forward slashes
#   sha256  lowercase hex of the file bytes as committed ("* -text" is set, so no line-ending
#           conversion applies), or the word REMOVED when the file no longer exists
#   reason  one line; an added file's reason starts with "ADDED:"
# Lines starting with '#' and blank lines are not records.
#
# Notes:
#  * desktop/Cargo.toml: refreshed at the integration merge 6ebe63f (branch integ/p0b). The recorded
#    hash is the merged file: 0C's dependency edit plus the profile tables appended by phase 0B.
#  * Every removed source stays recoverable byte-for-byte: git show 121479b:<path>.
#
desktop/Cargo.toml	bb0f0dfeaf90c1640a7b3900c0418696cc337383d08235f839b9d35805ce6337	dependency lines only: removed bip39, ed25519-dalek-bip32, ed25519-dalek, getrandom and argon2 (each used only by the retired V1 modules); no profile table, [patch] or [[bin]] edit by 0C; the hash is the merged file, which also carries the [profile.dev.package."*"] and [profile.release] tables appended by phase 0B (commits 24dfb05, e7bacc5)
desktop/Cargo.lock	9579cd4dce1f376eaf4145d6741b060afddb9148ed007192d7f88c8342bd138c	regenerated offline after the manifest change (removals only, no version changed): packages ed25519-dalek-bip32 and derivation-path dropped; the desktop package lost five dependency edges and ed25519-dalek its rand_core edge
desktop/src/main.rs	3dbf077b42d2d9ceec703db3f0e70fbd4e3165fb815e267997d5a24342cab042	V1 ceremony GUI screens, App state, --qualify flow and hard-coded D: paths removed; minimal closed-gate GUI shell kept; binary guards byte-identical; scoped clippy allows for as-found V2 lints; guard, hygiene and ignored release-refusal tests added
desktop/src/payment.rs	e09703a25e510f6f5480fff0f0d363169ea00c60b1565f8c93ad433c3f43bc64	V1 Ed25519 payment Draft removed; the neutral parse_amount is kept for the V2 amount-entry screen, with added boundary tests
desktop/src/wallet_v2.rs	ac2cf03d12bb879380463ac4230d70507efddbe825c3c83232876931a357eed8	two dpapi call sites now use dpapi_v2; ready() evaluates the new pure gate_closed(); compile-time pins and a production-gate test added; nothing else changed
desktop/src/dpapi_v2.rs	61a57d3a28f07373c7ece1d74c4e100a7b416c1dd54d4964ef4ad0b908800d0c	ADDED: Windows DPAPI protect/unprotect moved out of the V1 wallet module so V2 no longer reaches into V1; non-Windows stub refuses; bound, entropy-binding and corruption tests added
desktop/src/wallet.rs	REMOVED	V1 Ed25519/BIP32 identity, BIP39 handling, Argon2+DPAPI seal/unseal and dpapi(); dpapi() moved to dpapi_v2, the rest superseded by the V2 hybrid wallet and retired
desktop/src/store.rs	REMOVED	V1 SQLite wallet row and transaction lifecycle store (BIP39 entropy under DPAPI); superseded by store_v2 and the mempool_v2 outbox
desktop/src/verified_sync.rs	REMOVED	V1 replica and JSON peer backend over the V1 canonical store; superseded by verified_sync_v2
desktop/src/bindings.rs	REMOVED	V1 Genesis worker-binding request (twelve pinned hardware MAC addresses, Ed25519 BindWorker); authorization was already refused by the as-found code
desktop/src/admission.rs	REMOVED	V1 physical-admission request review and UI (Ed25519, original-checkout paths, test read the git-ignored machine-identifying NODE-A fixture); authorization was already refused
desktop/src/firmware.rs	REMOVED	V1 firmware-update signing fixture (cfg(test) only, Ed25519); firmware release authority is the separate 2-of-3 offline release signer

## TPM admission merge fallout (two one-line edits, recorded in the .tsv)

`desktop/src/wallet_host_fixture_tpm.rs` (`provenance: None` in the Legacy/Test version-1 profile it builds) and `desktop/src/wallet_host_v2_tests.rs` (`AdmissionClass::LegacyTest` passed to `membership_v2::Book::genesis`): the TPM admission branch changed those consensus APIs; the desktop test code only had to follow them.

## Phase 7 (branch wallet/p7-desktop: the desktop as a thin shell over wallet-core; recorded in the .tsv)

The hashes in the record lines above are phase 0C's. Phase 7 edited `desktop/Cargo.toml`, `desktop/Cargo.lock`, `desktop/src/main.rs`, `payment.rs`, `wallet_v2.rs`, `custody_acl_v2.rs`, `store_v2.rs`, `verified_sync_v2.rs`, `wallet_controller_v2.rs`, `wallet_host_v2.rs`, `wallet_host_v2_tests.rs`, `wallet_host_service_v2.rs` and `wallet_host_service_v2_tests.rs`; added `custody_seal.rs`, `operation_outbox.rs`, `operation_screens.rs`, `plan_review.rs`, `preimage_store.rs`, `test_support.rs` (tests only) and `desktop/docs/PHASE-7-DESKTOP.md`; and removed `payment_v2.rs` and `payment_review_v2.rs` (the desktop's own payment pipeline, replaced by wallet-core's). The current hash and the reason of each are in the .tsv, one line per path (`wallet_host_v2_tests.rs` carries both phase 7's port and the TPM admission line above); `desktop/docs/PHASE-7-DESKTOP.md` describes the change.
