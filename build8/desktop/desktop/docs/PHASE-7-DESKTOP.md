# PHASE-7-DESKTOP: the Windows desktop as a thin shell over wallet-core

Evidence label: **NATIVE PASS (offline, TEST-VALUE)** at most, on Windows only. Implemented is not
Qualified; offline is not physical; simulated is not physical. Every key used is a public TEST-VALUE
key (the BIP-39 test vectors) or a fresh random maker key a test creates and discards. Signing exists
only in test builds, behind wallet-core's non-shipping TEST-VALUE gate; the production gate
(`mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED == false`) is untouched and closed in every
shipping binary. Nothing here was run on Linux (the desktop does not build there by design).

Branch `wallet/p7-desktop`, from integration commit `feef0bf`, brought up to `integration/self-contained-2`
three times, never rebased: to `8aee644` (wallet-core phases 1, 2, 3, 4 and 5A; a fast-forward, the
branch had no commit yet), then by merge commits to `c68c22e` (phase 5B: License DvP, fiat lock and
release, maker offers) and to `67e2463` (phase 6: the Treasury profile; the actor-halt and TPM
admission packages, whose two one-line desktop test edits merged cleanly). The desktop takes the
Treasury profile only from this machine's runtime declaration (section 2); no screen offers a Treasury
kind.

## 1. Files

| File | What |
|---|---|
| `Cargo.toml`, `Cargo.lock` | the edge desktop -> `mutiny-wallet-core-v8` at default features; `test-value-signing` for tests only through `[dev-dependencies]`; the lock gained one package entry and one edge (no version changed) |
| `src/main.rs` | module list; compile-time guard `!mutiny_wallet_core_v8::TEST_VALUE_SIGNING_ENABLED` in every shipping-profile build (section 9); every phase 0C guard and the start-up path byte-identical; the as-found clippy allows removed |
| `src/wallet_controller_v2.rs` | rewritten: the UI-FREE controller (section 2) |
| `src/plan_review.rs` (new) | the review widget over `Review::rows()` (section 3) |
| `src/operation_outbox.rs` (new) | the protected durable outbox of signed operations (section 4) |
| `src/preimage_store.rs` (new) | the sealed preimage store (section 5) |
| `src/custody_seal.rs` (new) | DPAPI sealing and the strict record encoding shared by the two stores |
| `src/store_v2.rs` | vault schema version 3 and the vault replacement (section 6) |
| `src/wallet_v2.rs` | the vault session hands its key to wallet-core (`into_signer`, `into_rotation_signer`); `RestoredKey` (clean restore); `restore_rotated`; `envelope_identity`; the old desktop payment signer removed |
| `src/operation_screens.rs` (new) | the request forms and the composed screens `WalletUi` (section 7) |
| `src/verified_sync_v2.rs` | the replica as the source of every `ChainView`; queueing of authorized payments; the old drafting removed |
| `src/wallet_host_v2.rs`, `src/wallet_host_service_v2.rs` | balances count both queues; plan commands; clippy findings fixed |
| `src/custody_acl_v2.rs` | allow-list of the three custody file names |
| `src/payment.rs` | the amount parser delegates to wallet-core's `units::parse_mut` (one parser for the wallet) |
| `src/test_support.rs` (new, tests only) | wallet-core's public test fixtures included read-only; the bond fixture world; a headless egui driver |
| `src/payment_v2.rs`, `src/payment_review_v2.rs` | REMOVED: the desktop's own payment `Draft`/`Review` and egui `Panel`/`Approval` (replaced by wallet-core; their tests ported, section 8) |

## 2. Architecture

```text
 request forms (operation_screens) --OperationRequest-->+
 review widget (plan_review) --ReviewInput------------->|  Service thread (commands, events)
                 <-- ReviewScreen (Review + GateStatus) +--> Controller (UI-free, single owner)
                                                              |  wallet-core: plan(), Review, PlanSession,
                                                              |  ReviewGate, KeySigner / RotationSigner,
                                                              |  Outbox contract, PartialApproval, offers
                                                              |  desktop: vault (store_v2, DPAPI, ACL),
                                                              |  replica (verified chain), payment pool,
                                                              |  operation outbox, preimage store
```

* **The only path to a signature**: the vault session's key MOVES into wallet-core's `KeySigner`
  at unlock (`Session::into_signer`; the session is consumed, so the key exists only in the signer,
  which erases it on lock, idle expiry and drop). The controller holds one `ActivePlan` (wallet-core's
  `PlanSession` with its `ReviewGate`). `ReviewInput::Authorize` runs `ReviewGate::approve` (every typed
  destination check, every acknowledgement, the phrase of a high-risk review, a fresh review at the
  current head), `Signer::authorize` (independent verification through consensus code) and the
  durable queue in ONE step; the approval never leaves the controller and no approval crosses the
  service's command queue. The desktop has no "sign these bytes" API and chooses no domain.
* **The gate**: `signing_gate()` is wallet-core's `SigningGate::production()` in every non-test build
  (refuses while unqualified; and `wallet_v2::ready()` refuses before that) and wallet-core's
  TEST-VALUE gate in test builds only (it exists in the desktop only through the dev-dependency).
* **Every `ChainView`** comes from the LOCALLY replayed canonical store: `HeadInfo::new(anchor, the
  head block's timestamp, the store's t0 from its Genesis execution parent, the authenticated state
  root)`, `ChainView::verified` (the root is recomputed), `reserved` = the payment pool's
  reservations plus `Outbox::reserved()` of the operation outbox, and the store's confirmation index
  attached. Never a peer's claim.
* **Q2, re-review at every new head**: every controller command first runs `PlanSession::on_head`
  against the current verified head. A plan that went back to `Planned` is reviewed again at the new
  head with every confirmation cleared (a new digest, a notice says so); a plan whose window closed
  (single-block operations at the next block) is invalidated and must be requested again. History
  ingress (`accept_history`, `accept_recovery_history`) cancels the review on screen outright, valid or
  not, as the phase-0 desktop did.
* **Lock**: `lock()` (and the 300 s idle limit, and a failed replacement unlock) erases the key
  (`KeySigner::lock`), erases both keys of a rotation in progress, and clears the plan's gate, which
  WITHDRAWS every approval it issued (wallet-core then refuses such an approval with
  `APPROVAL_REVOKED`; tested by taking an approval out through a test hook and using it after the
  idle lock). The signer keeps its own idle clock as well; since the wallet review fixes the
  service's `UserActivity` refreshes it (`Controller::touch_signer`), and a signer that already
  locked itself locks the whole session (fail-closed). The retirement of the previous identity is
  refused while the verified chain does not show the new one as current (tested since the review).
* **Queues**: ordinary payments go to the consensus transaction pool (`mempool_v2`, the existing
  durable queue and transport); every other kind goes to the protected operation outbox (Q1: queued and
  exportable, no delivery claim). A returned id means "queued on this computer", never delivered or
  settled.
* **Partial operations (Q12, public data only)**: `export(id)` gives a complete operation's signed
  bytes or, for a partial one, wallet-core's checksummed `PartialApproval` container;
  `explain_partial` (read-only counterparty review, same digest) and `adopt_partial` (plan this
  wallet's part, then the generic review) serve every multi-party kind. Completion signs nothing:
  `complete_conditional` (hash lock: wallet-core's `conditional::complete` with the maker's fill) and
  `complete_trade` (License sale, fiat lock and release: `offers::attach_fill_proof` for the maker's
  fill, then `offers::combine`, which verifies every signature and runs consensus' `prepare_batch`).
  Since the wallet review fixes (MINOR-1) both queue the complete operation IN PLACE OF this wallet's
  own open partial record in ONE transaction (`OperationOutbox::replace_partial`, section 4): the
  outbox verifies through wallet-core's `outbox::admit_replacement_record` that the record named (for a
  hash lock the caller names it, the partial having an identifier of its own; a phase 5B part shares
  the operation identifier) is an open partial of exactly that operation, the complete record takes
  over its reservations, a wrong identifier is refused and changes nothing, and a crash at any step
  leaves the partial or the complete record, never neither. `complete_trade` queues a new record when
  this wallet holds no record of the operation and leaves a settled one as it is; the complete bytes
  are returned for export either way. Exchange is by file of these bytes only; the desktop opens no
  channel for them.
* **Treasury profile (Q5)**: never selectable from the UI. The controller is constructed with this
  machine's `Option<TreasuryDeclaration>` (explicit runtime configuration; never a UI control, never
  inferred from a key). wallet-core's `profile::declare` checks it against the verified chain at
  unlock (a declaration that does not hold refuses the unlock: the session and its key are dropped)
  and again at every new verified head (when it no longer holds, the wallet locks: key erased,
  approvals withdrawn); only then does the signer carry `WalletProfile::Treasury`, as the very
  identity `declare` returned (with the roles it checked: since the wallet review fixes each
  Treasury kind checks its own role, and the vault session refuses an identity that is not its own).
  Without it the Genesis Treasury authority cannot spend (`TREASURY_PROFILE_REQUIRED`). The rotation
  signer carries the identity the unlocked signer holds (R1). No form offers a Treasury kind (R2
  rotation, offer freeze); a host may pass one to the UI-free controller, and wallet-core refuses it
  without the profile and the role and re-checks the identity at every use (these kinds were not
  exercised through the desktop). wallet-core's labelling is crate-private since the wallet review
  fixes (its CR-6-3): `declare` is the only way to the profile.
* **The vault root**: explicit only (`VaultRoot::from_args`: exactly `--vault-root <absolute path>`;
  no default, no environment fallback). Every store lives in its fixed file under
  `<root>\WalletCustodyV2\` (owner-and-SYSTEM protected DACL, single link, no reparse point, leased).

## 3. The review widget (`plan_review.rs`)

A thin renderer: the grid draws exactly `Review::rows()` under their section headings with each row's
emphasis marker (its text equals `Review::render_text()`, pinned against wallet-core's golden payment
and bond-creation files); typed destination checks (last eight hex characters); one checkbox per
`Review.acknowledgements()` (the Destination one only after the typed checks); the confirmation phrase
of a high-risk review; Cancel; Authorize, enabled only when the controller's `GateStatus` says
`ReviewGate::is_ready` at the current head; a block countdown from the verified head (never the OS
clock: "valid until block X, N block(s) left (approximate duration)", or for single-block operations
"valid only in block H"). It returns `ReviewInput`s and decides nothing. `is_ready` does not check the
review's age (`MAX_REVIEW_AGE`); `approve` does, so an Authorize after ten minutes is refused even
though the button was enabled.

Headless tests (`egui::Context::run_ui`, no window) drive the REAL widget with synthetic pointer and
keyboard events and apply what it returns to a REAL `ActivePlan`: rendering alone returns nothing,
also once the review is ready; clicking the disabled Authorize does nothing; every acknowledgement is
required; a wrong typed ending is refused; a head change clears the gate; cancel; single use; the
phrase of a high-risk review.

## 4. Protection at rest: the operation outbox (`operation_outbox.rs`)

Phase 5A found that a queued hash-lock CLAIM carries its preimage in clear until inclusion. wallet-core's
`SqliteOutbox` stores signed bytes in clear, so the desktop implements wallet-core's `Outbox` trait
itself, with `SqliteOutbox`'s semantics (exact bytes committed in one transaction before success, every
commit re-verified through consensus code with metadata DERIVED from the bytes by
`outbox::admit_record`, idempotent per identifier while open, one open record per coin or resource,
open-only limits, `forget` releases without revoking, reconciliation through `outbox::settle`, settled
history trimmed, bound to one chain, and, since the wallet review fixes, `replace_partial`: the open
partial's row is deleted and the complete record's row inserted in one write transaction after
`outbox::admit_replacement_record` verified the completion, tested at three kill points) and seals
every record:

* each record is two values sealed with **Windows DPAPI (CurrentUser)**: the signed bytes, and the
  metadata (kind, identifier, status, validity, reservations, missing signatures, wallet-core's
  record checksum); each bound (DPAPI "optional entropy") to `SHA-512(domain, field, chain, the file's
  random identifier, the record identifier)`. In clear are only the record identifier (a public hash)
  and an insertion sequence;
* a probe sealed at creation is opened on every open: a file this account cannot unseal is refused
  before anything is read; every record read back is rebuilt and re-verified with wallet-core's
  checksum; the exact schema is compared on every open; `secure_delete` is on; the file is in the
  custody directory under the custody ACL and lease.

What this PROTECTS: the file read by another Windows account (the ACL denies it, and the sealed values
need this account's DPAPI master key), copied off the machine (disk image, backup, synchronised folder),
or edited (any changed byte, a value moved to another record, field or file is refused).

What it does NOT protect: any process running as the same Windows user (it can ask DPAPI to unseal);
administrators and SYSTEM; the process memory while the wallet runs; the deletion of a row or of the
file; the replacement of the file by an older copy of itself (rollback); the size and count of queued
operations; residue of SEALED pages in the filesystem (the rollback journal is deleted after each
transaction, not wiped; its content is ciphertext). The refusal under another account or on another
machine follows from DPAPI and the ACL; it was not demonstrated by a test (one account, one machine).

Why not a key derived from the unlocked vault session: crypto-v2 exposes no general AEAD or KDF (its
custody module is private and seals only a `HybridKey`), the desktop may add no dependency but the
wallet-core edge, and deriving a key by signing with the wallet key would be a signing path outside
the gates. Change request CR-W7-1 asks for a sealing hook. Consequence accepted and documented: the
outbox is readable (for reconciliation and export) while the wallet is locked, by this Windows user.

Tests: no plaintext preimage, signed bytes or reservation in the file or its journal after a claim is
queued; the full `SqliteOutbox` contract across a restart; tampering (bit flips of each sealed value,
values moved between records and fields, an edited identifier) refused; another key (another file
identifier) refused, for an empty and a non-empty file; a child process killed after signing but before
the commit, inside the commit's transaction, and right after the commit: on reopen exactly the signed
bytes or nothing.

## 5. The preimage store (`preimage_store.rs`)

wallet-core's `PreimageStore`: `create()` takes 32 fresh bytes from the operating system (never derived
from the wallet phrase or any key: the store has no other input); each entry (condition and preimage)
is one DPAPI-sealed value bound to the file and its row, so the file does not even say which locks this
wallet can claim; lookup by the lock's condition opens and compares; `erase` is the person's explicit
act and nothing else deletes; plaintext lives only in zeroizing buffers and wallet-core's redacted
`Preimage`. `insert(Preimage)` is refused: wallet-core lets only itself read a `Preimage`'s bytes, so a
`Preimage` value cannot be stored durably (CR-W7-2); a disclosed preimage is recorded from its raw
bytes with `insert_disclosed`. The same protection statement as section 4 applies. A controller test
takes a claim's preimage from this store (`claim_request`), signs the claim and queues it sealed.

## 6. Wallet rotation and the vault replacement (P6)

* **The two-key session**: `begin_rotation(password, typed new phrase, expected descriptor)`: the vault
  password opens the CURRENT key a second time; the typed-back new phrase is restored
  (`RestoredKey::restore`, the clean-restore check: it must give exactly the descriptor of the
  generation step when one is given); both keys move into wallet-core's `RotationSigner` (both erased
  together on lock, cancel, idle expiry and after signing); the plan binds the restore evidence (the
  descriptor fingerprint); the high-risk review follows the generic flow. `generate_rotation_phrase`
  makes the phrase for display (crypto-v2's wallet entropy); it is not exercised by the tests (it would
  reach the TPM entropy source).
* **The vault replacement** (`store_v2`, schema version 3): the vault holds the ACTIVE identity record,
  at most one other record (a STAGED replacement or the SUPERSEDED previous identity) and ONE pointer
  row naming the active record, with a compare-and-swap revision. `replace_vault(password, phrase)`:
  (a) the verified chain must show the rotation (the authority's current descriptor is the next
  generation of the active identity) and the phrase must restore exactly that descriptor (the
  clean-restore check, also the evidence phase 2 asks for); (b) `stage_replacement` seals the new
  identity with the vault password, reads it back through both layers and writes it NEXT TO the active
  record; (c) `activate_replacement` reads the staged record back from disk, opens it again, checks the
  confirmed descriptor and only then flips the single pointer; (d) the previous record is kept,
  superseded, until `retire_previous_identity`, which the person must ask for and which is refused
  until the active identity is the chain's current authority; (e) each step is one SQLite transaction
  (rollback journal, synchronous FULL) needing the vault password and the current revision. A version-2
  vault file is refused, never migrated (none can exist outside test directories: the shell never
  opened a vault outside tests). An interrupted replacement (a staged record of exactly the confirmed
  identity) is resumed; `abandon_vault_replacement` deletes a staged record that never became active.
* **Crash safety**: a child process is killed inside and right after each of stage, activate and retire;
  on reopen the vault is exactly at the last commit, every invariant holds, and unlock opens the
  identity the pointer names.
* **End to end**: the desktop signs a funded rotation with the two-key session; consensus
  `Transaction::verify` accepts the exported bytes; consensus' `WalletBook::apply` applies exactly that
  rotation; over the resulting verified chain the old key is refused (`STALE_AUTHORITY`), the
  replacement makes the vault hold the new identity, the new identity signs a payment, and the old
  record goes only by the explicit retirement.

## 7. Screens (`operation_screens.rs`)

One request form per kind with a wallet-core handler on this branch: payment; dividend claim; bond
creation (a fresh random non-zero nonce per request), unbond and withdrawal; hash lock (an imported
maker offer as hex, recipient, amount, condition, refund height, optional opaque trade and contract
commitments), claim (the lock only: the controller takes the preimage from its sealed store) and refund
(the protocol's one cancellation); License sale by DvP (the imported offer, the License, both
commitments, which consensus requires non-zero, an optional payment destination and the seller's
public descriptor when the wallet book cannot name the seller); fiat lock (offer, buyer, amount,
payment-terms commitment, optional commitments and buyer descriptor); fiat release (the lock, the
seller's descriptor when needed). A form checks syntax only; every rule is wallet-core's. Another
kind's form starts empty: nothing typed for one operation carries over into another. The wallet
rotation is its own flow (section 6). `WalletUi` composes a form, the generic review and the outcome
over the controller; a headless test takes a payment from its form to the queue through synthetic
clicks and keystrokes. The window shell itself is unchanged: it still shows the closed-gate notice
(its start-up is byte-identical and `App::new` refuses outside tests), so mounting `WalletUi` in the
window belongs to the action that opens the gates.

## 8. Tests

The suite (`cargo test --offline --locked`, debug): 62 passed, 0 failed, 1 ignored; release (`--release`): 62 passed, 0 failed, 1 ignored;
the ignored test is `non_test_binary_refuses_to_start`, run against the release exe (section 9).

Ported from the phase-0 desktop (each asserts the same property through the new path):

| Old test | New test(s) |
|---|---|
| `payment_v2::dust_prefix_cannot_hide_funding_and_equal_values_have_stable_order` | wallet-core's selection tests (`unit_payment`, the phase 1 port of exactly this test); the desktop now plans through it (`verified_sync_v2`, `wallet_controller_v2` tests) |
| `payment_v2::immutable_review_hybrid_signatures_conservation_and_head_binding` | `verified_sync_v2::approved_payment_is_durable_before_transport_and_conflicts_fail_closed` (signed bytes verify, a changed plan is refused), `plan_review::every_acknowledgement_is_required_and_the_widget_drives_the_real_gate` (head binding, single use), the rotation end to end (a rotated authority signs with the new key; the old one is `STALE_AUTHORITY`) |
| `payment_review_v2::exact_review_change_head_change_cancel_and_single_consumption` | `plan_review::every_acknowledgement_is_required_and_the_widget_drives_the_real_gate` |
| `payment_review_v2::render_without_explicit_input_cannot_approve` | `plan_review::render_without_explicit_input_cannot_approve`, `plan_review::rendering_alone_cannot_approve_and_a_disabled_authorize_cannot_be_clicked` |
| `verified_sync_v2::approved_payment_is_durable_before_transport_and_conflicts_fail_closed` | the same name, through wallet-core's plan, gate and signer |
| `verified_sync_v2::public_hybrid_chain_drives_balance_and_rejects_forged_confirmation` | the same name; its drafts are wallet-core plans |
| `wallet_controller_v2::unlock_expiry_review_invalidation_and_durable_submission_are_composed` | the same name, through review inputs and Authorize |
| host and service tests (`wallet_host_*`, `service_*`) | the same names; the retired synthetic approval replaced by the review inputs and Authorize |
| `store_v2::*` (four tests) | the same names on schema version 3 (lookalike schemas, corrupt records, the crash child, password CAS) |

New: `plan_review` (rendering alone cannot approve, every acknowledgement through real clicks, the
high-risk phrase and the single-block countdown, golden payment and bond texts drawn exactly as
wallet-core renders them); `operation_outbox` and `preimage_store` (section 4 and 5); `store_v2`
(the replacement and its crash test at six kill points); `wallet_controller_v2` (the idle lock withdraws
an issued approval, a new head clears the gate, every acknowledgement and typed check, the rotation and
vault replacement end to end, locking erases both rotation keys, the vault root is explicit, a hash lock
exchanged between two wallets as public partials, a claim from the sealed preimage store, a fiat lock
signed by two wallets and completed with the maker's fill, a fiat release planned by the buyer and
co-signed by the seller, the Treasury profile only from a runtime declaration that holds); `operation_screens` (offered kinds and never a Treasury kind, exact request
mapping, every form reaches its own wallet-core handler, the composed screens from form to queue);
`main` (the wallet-core TEST-VALUE gate reaches test builds only).

Mutation checks (each mutant applied alone in the worktree, the named tests run, the file restored and
the tree verified clean before the next):

| Mutant | Killed by |
|---|---|
| M1 the controller reports "ready" for any fresh review (`ready: fresh`) | four `plan_review` tests; `approval_needs_every_acknowledgement_and_every_typed_check` |
| M2 the widget enables Authorize for any fresh review | four `plan_review` tests (`rendering_alone_cannot_approve_and_a_disabled_authorize_cannot_be_clicked` among them) |
| M3 a new verified head is not passed to the plan session | `a_new_head_clears_the_gate_and_the_review_starts_again`; `every_acknowledgement_is_required_and_the_widget_drives_the_real_gate` |
| M4 the outbox reports success without its durable commit | `the_durable_outbox_contract_holds_across_a_restart`; `a_kill_between_sign_and_commit_leaves_exact_bytes_or_nothing`; `tampering_and_a_wrong_key_are_refused`; `a_queued_claim_leaves_no_plaintext_preimage_in_the_file` |
| M5 activation without the confirmed-descriptor check | `the_vault_replacement_stages_flips_one_pointer_and_keeps_the_old_record` |
| M6 the single pointer flipped to the wrong record | the replacement test; `the_vault_replacement_is_crash_safe_at_every_step`; the rotation and vault replacement end to end |
| M7 locking keeps the plan on screen and its gate | `the_idle_lock_clears_pending_approvals_and_withdraws_issued_ones`; `locking_erases_both_keys_of_a_rotation_in_progress`; `unlock_expiry_review_invalidation_and_durable_submission_are_composed` |
| M8 a new verified head does not re-check the Treasury declaration | `the_treasury_profile_comes_only_from_a_runtime_declaration_that_holds` |
| M9 the unlock gives the Treasury profile without `profile::declare` | `the_treasury_profile_comes_only_from_a_runtime_declaration_that_holds` |

All nine were killed; none survived. Not covered by a mutant (known weak spots): the idle limit at
exactly 300 s (`>=` against `>`), and the head check in `refresh()` (the head moves only through
history ingress, which cancels the review anyway).

## 9. Build records

`build/imports/EDITED-AFTER-IMPORT-V1.tsv` records every desktop file phase 7 edited, added or removed
(one line per path; earlier phase 0B/0C reasons kept). `build/shipping-configurations-v1.json` records
the new lock hash, the wallet-core edge, the static guard, the role and the capability status;
`docs/BUILD-CONFIGURATIONS-V1.md` revision 4. `build/check-shipping-config.sh` REQUIRES wallet-core in
the desktop's resolved graph at `[default]`, exactly one wallet-core line in `[dependencies]` at
default features, `test-value-signing` only in `[dev-dependencies]`, and the guard in `main.rs` with its
exact cfg; the negative controls were updated with the same intent and extended.

The guard is `#[cfg(all(not(test), not(debug_assertions)))] const _: () =
assert!(!mutiny_wallet_core_v8::TEST_VALUE_SIGNING_ENABLED);`. A plain `#[cfg(not(test))]` fails
`cargo clippy --all-targets`: Cargo checks the non-test binary in the same invocation as the tests and
unifies the dev-dependency's feature into it (that dev-profile binary is never shipped). The shipping
profile pins `debug-assertions = false`, which the script checks, so every shipping build evaluates the
guard; `cargo build --release` passes it.

Runs (Windows test host): `cargo test --offline --locked` (debug) 62 passed, 0 failed, 1 ignored; `--release` the same;
`cargo clippy --all-targets -- -D warnings` clean; `cargo build --release --offline --locked`
succeeds: at `5b78aaa` `mutiny-desktop-v8-ceremony.exe` is 147,968 bytes, sha256
`8f0cb42a8d26b7da47f7348e3747aa6c2a1d9c14aa8b0c91f726b5534d3f1ca7`, and neither it nor its pdb contains a
forbidden wallet string, wallet-core's gate marker or any wallet-core item name (the code is
dead-stripped behind the closed gates); it exits 1 with the "under qualification" text and opens no
window (the ignored test run against it); `build/check-import-provenance.sh` 16 passed, 0 failed;
`build/check-shipping-config.sh --fast` 158 passed, 0 failed, and the full run 169 passed, 0 failed with that exe;
the desktop-relevant subset of the negative controls (`--only`): 33 injections detected, 5 positive controls passed, 0 problems.
(Renamed to `mutiny-wallet-v8` in candidate 3, Order W8: the figures above were observed under the old name.)

## 10. Findings, open questions, change requests

* CR-W7-1 (wallet-core): an `Outbox` sealing hook, or public `describe` / record encoding accessors,
  so a protected outbox need not mirror `SqliteOutbox`'s semantics.
* CR-W7-2 (wallet-core): access to a `Preimage`'s bytes for a durable store, or a sealed-storage hook.
* CR-W7-3 (wallet-core, the same as phase 5B change request 1): let an outbox replace an OPEN partial
  by its strictly more complete version, so the completing wallet can queue the complete phase 5B
  operation. MET: wallet-core's `Outbox::replace_partial` (phase 8) and, since the wallet review fixes,
  the desktop's sealed `OperationOutbox::replace_partial`, used by every completion path.
* CR-W7-4 (wallet-core): dedicated refusal codes for a damaged or misplaced preimage store (today
  `MALFORMED` and `INVALID_REQUEST`).
* Observation for the consensus owners (no change requested): a state whose only native records carry
  no chain context (an `Applied` receipt) while its License book is non-empty cannot be rooted
  (`trading_host_v1::records` falls back to a zero Genesis). Real chains always keep the offer's
  single-fill record next to a lock, so this was met only by a hand-made test state, which now carries
  that record.
* wallet-core CR-6-3 (from phase 6): MET by the wallet review fixes (the labelling is crate-private;
  the desktop takes the identity `profile::declare` returns).
* Open decisions (proposals in the phase report): protection at rest beyond DPAPI; retirement of the
  previous identity stays manual; the vault root from the command line only; partial exchange by files
  only; rotations are queued for export although a funded rotation is a transaction with a pool path;
  the binary was still called `mutiny-desktop-v8-ceremony` (settled by Order W8: renamed to `mutiny-wallet-v8` in
  candidate 3).
