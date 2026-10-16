# mutiny-wallet-core-v8

UI-free, network-free, Bitcoin-free core of the Build 8 wallet: it CONSTRUCTS, REVIEWS and AUTHORIZES
operations. Nothing here draws a window, opens a socket or touches Windows. `desktop/` (phase 7) is
meant to become a thin Windows shell over this crate (DPAPI vault, widgets, peer service).

**Evidence status (read this first).** Phases 1 to 6 of the wallet plan, the phase-8 consolidation
(phase 7, the desktop shell, lives in `desktop/`) and the candidate-3 hardening of lane W1 (the
Order's W2 to W6, W9 and W19 to W23). NATIVE PASS (offline, TEST-VALUE) on Windows at most:
Implemented is not Qualified; offline is not physical; simulated is not physical. Production signing is
unavailable while `mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED` is `false`, which this crate
neither flips nor works around. Every one of the 14 operation kinds has a handler
(`ops::implemented_kinds()` lists all 14; see "Which kinds exist"); `NOT_IMPLEMENTED` remains the
refusal of a build that lacks a kind. The consolidated, per-kind operations document is
`docs/WALLET-OPERATIONS-V1.md`; each phase's own record is `docs/PHASE-*.md`.

## The pipeline

```text
 OperationRequest --plan()-->  OperationPlan  --review()-->  Review  --ReviewGate-->  Approval
        |                           |   ^                        |                       |
  adopt(raw bytes) -----------------'   '--- explain(raw) ------'           (single use, bound to
  (offline signer, counterparty)                                              digest + head + scope)
                                    |                                                    |
                                    '------------ Signer::authorize(plan, approval, view)
                                                                  |
                                          SignedOperation::{Complete, Partial}  --Outbox--> export
```

* **Plan** (`plan.rs`): an immutable `OperationPlan` holds the UNSIGNED bytes of every object that
  will be signed, who must sign what, which coins it consumes, its validity and the head it was built
  against. Only an operation handler can construct one. `plan()` is deterministic in (request, view,
  signer). A cancellation request maps to the one operation the protocol permits (hash-lock refund)
  or is refused with `CANCEL_NOT_AVAILABLE` (Q3).
* **Review** (`review.rs`): a `Review` is a PURE FUNCTION of the unsigned bytes and the verified
  `ChainView`. It has private fields and only `review()` / `explain()` can make one, so a UI cannot
  show one thing and bind another. It always carries destinations (with the typed re-entry text),
  amount, fee (rule, size, payer), change, conditions, timing, effects (irreversible ones marked),
  warnings, the typed acknowledgements a person must give (derived from the rows, so a risk cannot be
  shown without its acknowledgement) and the binding digest
  `SHA-256(domain || kind || schema || unsigned objects || anchor || state root)`. `render_text()` is
  a stable plain-text rendering (pinned by a golden snapshot); `rows()` is what a widget draws.
* **Approval** (`authorize.rs`): `ReviewGate` collects the typed address checks and acknowledgements
  (and, for high-risk operations, a confirmation phrase derived from the digest) and only then issues
  an `Approval`: not `Clone`, private fields, consumed by move, bound to the review digest, the head,
  the state root and the exact set of acknowledgements and the wallet and profile they were given
  for. A gate has at most one live approval: a new head, an expired review, a lock or cancel
  (`clear`), putting anything new on screen, or issuing another approval WITHDRAWS every approval it
  issued before, even one a caller still holds; `authorize` then refuses it with `APPROVAL_REVOKED`.
  An approval is also refused when it is older than `MAX_APPROVAL_AGE` or stamped in the future.
  `Approval::binding()` is the public description of what an approval was given for (kind, schema,
  review digest, scope, anchor, state root), for the outbox (Order W6).
* **Authorize** (`authorize.rs`): `Signer::authorize(plan, approval, view)` is the ONLY way to a
  signature. There is no "sign these bytes" API: the tripwire `build/check-signing-calls.pl` (run by
  `build/check-shipping-config.sh`; docs/BUILD-CONFIGURATIONS-V1.md section 14) parses the non-test
  code of this crate and of the desktop and holds every signing call, by its syntax and its enclosing
  function, to an exact allow-list, and `build_independence` pins the public ways to an approval, a
  gate and a signer. Order of checks: the signer's lock (a locked signer, or one past its idle
  limit, is `LOCKED` before anything else), gate, approval not withdrawn, approval age, head, signer
  identity, current authority on the verified chain, plan binding (digest recomputed from the
  unsigned bytes and the CURRENT view, which also re-runs the kind's pre-signing validation),
  per-slot authority through `WalletBook::authorize` exactly as consensus resolves it, signing, then
  a check that the signed bytes equal the reviewed unsigned bytes plus signatures, independent
  verification through consensus code (`Transfer::verify` for payments), and a check that the
  metadata attached to the result (identifier, validity, reserved coins) is what the bytes say.
  Signing never takes a caller-supplied
  domain, and no code outside `capability.rs` reaches a key (Order W4): keys are held sealed, and a
  handler is lent a `capability::KindSigner` for its kind, from which it obtains only the typed
  capabilities that kind holds (`TransferSpend`, `BondAuthorization`, `ClaimAuthorization`,
  `TradeApproval`, `RotationProofs`, `TreasuryFreeze`; anything else is `CAPABILITY_NOT_PERMITTED`).
  Each signs one consensus object of its kind through the consensus-owned builder, under the domain
  consensus uses for it or the one `domain_for` returns (17 (kind, purpose) pairs). No function
  returns a key or signs caller-chosen bytes: `compile_fail` doctests in `capability.rs` prove it
  for a host and for the handler modules, and the tripwire and `build_independence` remain as
  additional regression checks.
* **Outbox** (`outbox.rs`, `outbox_sqlite.rs`): the signed bytes are re-verified and committed with
  their input reservations before success is reported. The record's identifier, completeness,
  missing signatures, validity and reserved coins are DERIVED from the bytes by the kind's handler
  (`describe`); a `SignedOperation` whose fields disagree is refused, so a wrong `reserved` cannot
  free a coin for a second plan. Success means "queued locally", never "delivered" or "settled" (Q1).
  There is no revoke: `forget` only releases the local reservations. Only OPEN records count against
  the limits and hold reservations; settled records are history, trimmed to the newest
  `DEFAULT_MAX_SETTLED` by every reconciliation or on demand (`prune_settled`). An outbox belongs to
  one chain, and a view older than the head a record was queued at says nothing about it.
  `resource_key(namespace, id)` gives a non-coin resource (a License on offer, a claim, a bond lot)
  a reservation key that can never equal a coin's outpoint. `SignedOperation::import(raw, view)`
  accepts bytes signed elsewhere (an offline signer) after the same checks. A queued PARTIAL record
  (a multi-party operation still missing signatures) is completed with `replace_partial`: the
  complete operation takes its place and its reservations in one atomic step (forget-then-commit
  leaves a window with neither); `commit` is unchanged. `pending()` re-checks only the unkeyed
  checksum: it is NOT authentication and not for delivery. `export_verified(id, view)` is the export
  for delivery (Order W6): before it releases a record's bytes it re-verifies them, the record's
  status from verified state (a stale view, a confirmed, expired, conflicting, stranded or forgotten
  record is `NOT_DELIVERABLE`), the approval binding `commit_approved` recorded with them, and every
  signature through consensus code.

## Module map and the frozen interface

| File | Frozen contract |
|---|---|
| `lib.rs` | const-assert guards (receipt-qualification, release-custody, dividend and legacy-v0 fixtures all OFF; `wallet-custody` required and allowed only in wallet roots); `#![forbid(unsafe_code)]`; re-exports |
| `context.rs` | `HeadInfo`, `ChainView` (head, state, reserved inputs, optional `ConfirmationSource`), `ChainClass` (TestValue / Production / Undeclared from the Treasury record), Treasury and reserve-backing helpers |
| `refusal.rs` | `Refusal` with stable machine codes (`Refusal::code`, `CATALOG`); every refusal changes no state and yields no signed bytes |
| `address_format.rs` | the checksummed, class-distinguishing address text (Order W2, PROPOSED, `docs/ADDRESS-FORMAT-V1.md`): `encode`, `decode`, `decode_for`, `AddressError`, the legacy hex path |
| `capability.rs` | sealed keys and the typed signing capabilities (Order W4): `KindSigner`, `KeySlot`, `Capability`, `capabilities(kind)`, `TransferSpend`, `BondAuthorization`, `ClaimAuthorization`, `TradeApproval`, `RotationProofs`, `TreasuryFreeze` |
| `export.rs` | the view-verified export of queued operations (Order W6): `ApprovalBinding`, `ApprovalEvidence`, `DeliveryStatus`, `VerifiedExport`, `verify_record` |
| `rotation_signer.rs` | the two-key `RotationSigner` (keys sealed; exported as `ops::rotation::RotationSigner`) |
| `review.rs` | `Review`, `Row`, `Section`, `Party`, `Destination`, `Fee`, `Timing`, `Condition`, `Effect`, `Warning`, `AckKind`, `ReviewDigest`, `binding_digest`, `review()`, `explain()` |
| `plan.rs` | `OperationKind` (all 14), every `*Request`, `OperationRequest`, `OperationPlan`, `Planner`/`StandardPlanner`, `plan()`, `adopt()`, `PlanSession` (the plan state machine) |
| `authorize.rs` | `SignerIdentity`, `WalletProfile`, `SigningGate`, `ReviewGate`, `Approval`, `Signer`, `KeySigner`, `SignedOperation`, `Purpose`, `domain_for` |
| `partial.rs` | `PartialApproval`: public, canonical, checksummed, bounded container (export/import), counterparty `explain_for` / `adopt_for` |
| `outbox.rs`, `outbox_sqlite.rs` | `Outbox` trait (`commit`, `replace_partial` (phase 8, with a default), `commit_approved` and `export_verified` (candidate 3, W6, with defaults), `records`, `get`, `reconcile`, `forget`, `prune_settled`, `reserved`, `pending`), `MemoryOutbox`, durable `SqliteOutbox`, `resource_key`, `DEFAULT_MAX_SETTLED` |
| `ops/mod.rs` | the closed registry: `handler(kind)` (crate-private), `recognizing(raw)`, `implemented_kinds()` |
| `ops/payment.rs` | ordinary MUT payments (phase 1) |
| `ops/rotation.rs` | wallet-authority rotation, the funded `Transaction::Rotate` (phase 2): `RotationSigner` (current and new key; defined in `rotation_signer.rs`), `combine` of a co-funded rotation, restore evidence, `rotation_resource` |
| `ops/dividend.rs`, `discovery/dividends.rs`, `discovery/licenses.rs` | dividend claims (phase 3): entitlements and claimability from verified state, partial claims and the per-(award, License) claim sequence |
| `ops/bond.rs`, `discovery/bonds.rs` | bond creation (funding bundle), unbond and withdrawal (phase 4): `CreateBundle`, `export_unsigned`, `lot_resource`, `stranded_escrow` |
| `ops/conditional.rs`, `discovery/locks.rs` | conditional MUT (phase 5A): hash lock, claim and refund, `complete` of the parts, `PreimageStore`, lock discovery and finality |
| `ops/license_dvp.rs`, `ops/fiat.rs`, `offers.rs` | License sale by delivery versus payment, fiat lock and fiat release (phase 5B); maker offers and fill proofs imported and verified, never created (Q7) |
| `ops/treasury.rs`, `profile.rs` | the Treasury profile (phase 6): `profile::declare` (identity-checked, non-default), the trading Treasury destination rotation (R2) and the offer-freeze authorization |
| `ops/select.rs` | shared coin selection (reserved, immature, foreign and excluded coins left out; top candidates kept with a stable order; totals over all) and the Treasury-profile guard; `context::require_reserve_backing` is the reserve hook |
| `secret.rs` | `Preimage`: fresh OS-random hash-lock preimage, redacted `Debug`, never derived from a wallet key (Q13) |
| `units.rs` | amount parsing and formatting (integers only), approximate block-time text (always labelled approximate, Q11) |

## Which kinds exist

`ops::implemented_kinds()` returns all 14 kinds of `OperationKind::ALL`, each registered once in
`ops/mod.rs`:

| Kind | Handler | Phase |
|---|---|---|
| `Payment` | `ops/payment.rs` | 1 |
| `WalletRotation` | `ops/rotation.rs` | 2 |
| `DividendClaim` | `ops/dividend.rs` | 3 |
| `BondCreate`, `BondUnbond`, `BondWithdraw` | `ops/bond.rs` | 4 |
| `HashLock`, `ConditionalClaim`, `ConditionalRefund` | `ops/conditional.rs` | 5A |
| `LicenseDvp` | `ops/license_dvp.rs` | 5B |
| `FiatLock`, `FiatRelease` | `ops/fiat.rs` | 5B |
| `TreasuryRotate`, `TreasuryFreezeOffer` | `ops/treasury.rs` | 6 |

Request structs are `#[non_exhaustive]`: the phase that owns a kind may add fields (and their
`with_*` builders) to the request struct of that kind. That is the ONE permitted edit to the shared
`plan.rs`; everything else in the table above is frozen, and a phase that needs another change asks
for it. Candidate 3 (lane W1, by the Order's decisions) added the modules `address_format`,
`capability`, `export` and `rotation_signer`, the outbox methods `commit_approved` and
`export_verified` (with default implementations), the diagnostic variants `Stranded`, made the
public enums that may gain variants `#[non_exhaustive]`, and changed one request field:
`LicenseDvpRequest::validity_blocks` is an `Option<u64>` that must stay `None` (W22).

## What the gates are, and what they are not

The approval step enforces an ORDER and a BINDING: nothing is signed that was not reviewed at the
current head, and a user interface that skipped, reordered or confused steps cannot obtain a
signature. It is not a proof that a human was present: the typed checks and acknowledgements are
ordinary calls, so a malicious HOST PROCESS that holds the key could drive them programmatically, or
sign without this crate at all. The boundary against such a process is the host process itself, the
vault and the platform, never this library. The typed destination check (the last 8 hex characters,
32 bits) defeats carelessness and look-alike addresses, not a determined grinder; it is an interim
human-error aid, not a checksum and not address authentication, kept on top of the checksummed
address text of `address_format.rs` (Order W2; `docs/ADDRESS-FORMAT-V1.md`, PROPOSED). The outbox
checksums catch accidental damage and careless edits; someone who can rewrite the outbox file can
recompute them, so `pending()` is not authentication. What protects against that person is that
queued bytes are already signed and cannot be altered into another valid operation, that `commit`
and `export_verified` re-verify them through consensus code against the verified view (the export
also checks the approval binding recorded with them, which is unkeyed too: bytes validly signed for
another record can still be substituted together with their binding), and that the chain rejects
anything invalid.

## Adding an operation (phases 2 to 6)

A phase ADDS files; the shared types above do not change.

1. Add `src/ops/<kind>.rs` with a unit struct implementing the crate-private `OperationHandler`
   (`plan`, `adopt`, `validate`, `review`, `explain`, `sign`, `unsigned_form`, `describe`,
   `check_signed`, `reconcile`, `recognizes`, and optionally `check_requirements`, which overrides the
   default per-slot authority check for a kind that introduces a key not yet registered, such as
   wallet rotation). Follow `ops/payment.rs`; spend coins through `ops/select.rs`. `describe(raw)`
   returns what the bytes commit to (identifier, complete or not, signatures still missing, validity,
   and every coin or `resource_key` resource the operation consumes); the outbox stores exactly that
   and refuses a caller's metadata that disagrees. `validate` must include the Treasury-profile guard
   (`select::require_profile_for_treasury`) for any kind that can spend Treasury coins, so a plan that
   arrives through `adopt` is held to the same rule as one built by `plan`.
2. Registration is PRE-WIRED: `ops/mod.rs` already names `ops/<kind>.rs` for every kind and
   `lib.rs` already names `discovery/*`; each placeholder file exports `handler(kind) -> Option<&'static
   dyn OperationHandler>` returning `None`. REPLACE THE CONTENT OF YOUR OWN FILE and return
   `Some(&HANDLER)` for your kinds; `mod.rs` and `lib.rs` do not change. `OperationRequest`,
   `OperationKind`, the refusals and the signing domains for every kind already exist.
3. Build the review through `ReviewDraft` (including `extra_acks`, `high_risk` for the highest-risk
   operations, `AddressLabel`s and `Warning`s with attached acknowledgements). Never hand-write rows.
4. Sign only through the typed capabilities of `capability.rs`: ask the lent `KindSigner` for a
   capability the kind holds (`transfer_spend(KeySlot::Primary)`, `trade_approval()`, ...) and let
   it sign the consensus object. A kind that needs another capability adds it to `capability.rs`
   with `capabilities(kind)`, `domain_for`, the tripwire rules and the compile_fail evidence. A
   two-key signer (wallet rotation) wraps `authorize::run_authorization` with its own `KeyRing`
   (`rotation_signer.rs`).
5. `check_signed` must verify through the public consensus API; for partial results it verifies each
   provided approval and reports the missing `Requirement`s.
6. Tests: reuse `tests/support/{rig,synthetic,flow,tempdir}.rs`, mirror `e2e_payment.rs` (real
   certified blocks, differential checks against consensus), `refusals_core.rs` and
   `review_completeness_payment.rs` (mutate every field; a hidden field is a failure). Since phase 8
   the shared rig's `Harness` carries block operations (`step_with`, `try_step_with`, `step_at_with`,
   `try_step_at`), has a Genesis hook (`with_genesis`), assembles without installing (`prepare`) and
   executes a candidate body over any state (`execute_on`); the per-phase rigs are adapters over it,
   and `flow.rs` types the confirmation phrase of a high-risk review.

## Host integration (what the desktop shell does)

* Build a `ChainView` from the LOCALLY replayed canonical store: `HeadInfo::new(anchor, head
  timestamp, t0, state root)`, the `State`, and `reserved` = the union of the transaction pool's
  reservations and `Outbox::reserved()`. Never build it from a peer's claim. A transaction does
  not commit to the VALUE of its inputs, so the fee and change a review shows are exactly as truthful
  as the coins in the view: use `ChainView::verified` (it recomputes the state root) unless the state
  came straight from an authenticated store. Re-create it on every new
  verified head and call `PlanSession::on_head`. `commit` and `reconcile` trust the view to be the
  host's CURRENT verified head. A `ChainView` is not `Sync` (it may hold a `dyn ConfirmationSource`):
  build one per thread from the shared verified state.
* Payments: `plan()` a `PaymentRequest`, `PlanSession::present` (or `review()` + `ReviewGate`), have
  the person enter each typed destination check (`Review::destinations_needing_check`), give every
  acknowledgement, `approve`, `authorize`, `Outbox::commit`, then submit. `Refusal::code()` is the
  stable key for UI text; `Refusal`'s `Display` is human text. To keep the approval with the queued
  bytes, take `Approval::binding()` before `authorize` and queue with `Outbox::commit_approved`;
  hand queued bytes to a transport only through `Outbox::export_verified(id, view)` at the current
  verified head (W6).
* Offline signing: an online machine plans with a public `SignerIdentity` (no key needed) and
  exports `plan.objects()[0].bytes`; the offline machine calls `adopt(bytes, view, identity)` against
  its own verified view of the same head, reviews, approves and signs. The review digest is the same on
  both machines.
* Counterparty review: `explain(bytes, view, me)` or `PartialApproval::explain_for`. The digest binds
  the UNSIGNED form, so signed bytes explain to the same digest as the plan that produced them. To
  explain a record that is already queued, use a view whose `reserved` does not count that record's
  own coins.
* Lock: `KeySigner::lock()` and `PlanSession::lock()`. Locking a session clears its gate, which
  withdraws the approval it issued; a plan that is already `Signed` stays `Signed` (its bytes exist and
  cannot be recalled). A `KeySigner` also locks itself after its idle limit (at most
  `DEFAULT_IDLE_LIMIT`); input at or after the limit cannot revive it.
* The Treasury profile: only `profile::declare` gives it (the labelling is crate-private since the
  wallet review fixes), and the identity carries exactly the ROLE SET `declare` checked against the
  verified chain (`SignerIdentity::treasury_roles`). Spending Genesis Treasury coins and rotating the
  Genesis Treasury authority (R1) need the `Authority` role, and spend only above the dividend
  reserve (`RESERVE_BACKING_VIOLATION`, differentially tested against consensus block execution); the
  rotation of a trading Treasury (R2) and the freeze of an offer to it need the `Destination` role for
  exactly that TreasuryID. An ordinary profile gets `TREASURY_PROFILE_REQUIRED`, a missing role
  `TREASURY_ROLE_NOT_DECLARED`, whether the plan was built by `plan()` or came in through `adopt()`.
  The profile and the roles are part of the identity an approval is bound to.
* Durable outbox: `SqliteOutbox::open(path, context)` takes a regular file at a real path (the empty
  name, `:memory:` and `file:` names are refused with `OUTBOX_LOCATION`; so is a path that cannot be
  opened). Another process holding the file is `OUTBOX_BUSY` (retry); a full disk is `OUTBOX_FULL`;
  anything irregular in the file is `OUTBOX_INTEGRITY`.

## Build, features and gates

* `default = []`. `test-value-signing = []` is NON-SHIPPING: it adds the TEST-VALUE signing gate
  (`SigningGate::test_value()`, `KeySigner::for_test`, `Approval::for_review_for_test`, ...). It is
  never default and no shipping root enables it. This crate's own tests get it through a dev-dependency
  on itself (`mutiny-wallet-core-v8 = { path = ".", features = ["test-value-signing"] }`); Cargo's
  resolver does not unify dev-dependency features into a normal or release build, so
  `cargo build --release` and `cargo tree -e normal` never see it. Exclusion checks must therefore use
  `cargo build --release` / `cargo tree -e normal,build`, NOT `--all-targets` or `cargo test`. Every
  shipping binary should add `const _: () = assert!(!mutiny_wallet_core_v8::TEST_VALUE_SIGNING_ENABLED);`.
  The unique string `MUTINY-WALLET-CORE-TEST-VALUE-GATE-V1` appears in a binary only if the gate is
  compiled in and may be used as a forbidden string in release-artifact checks (the test
  `build_independence` proves the library really embeds it, and that every item of the gate sits
  behind the non-shipping cfg). The explicit-clock and explicit-limit entry points
  (`ReviewGate::with_limits`, `present_at`, `approve_at`, `KeySigner::authorize_at`,
  `RotationSigner::authorize_at`) exist only in test builds too, so a shipping host cannot move time
  or widen the review or approval age limits. The one limit a host chooses is a signer's idle limit
  (`KeySigner::with_identity`, `RotationSigner::new`), and it can only SHORTEN it: anything above
  `DEFAULT_IDLE_LIMIT` (300 s) is clamped to it (since the wallet review fixes).
* The production gate is `SigningGate::production()`, which returns `GATE_CLOSED` while
  `PRODUCTION_SECURITY_QUALIFIED` is false. No `KeySigner` can be constructed without a gate.
* Commands (each in `wallet-core/`, with the usual `--offline --locked`):
  `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo build --release`,
  `cargo tree -e normal,build --prefix none`, and `cargo doc --no-deps` with
  `RUSTDOCFLAGS="-D warnings"`. Never `--all-features`.
* Dependencies: consensus (default features), crypto-v2 (`wallet-custody` only), minicbor 2.3.0, sha2,
  hex, zeroize, rusqlite (bundled), all locked to the same versions as the other roots. No GUI,
  window-system, OS-binding, network or Bitcoin crate. The release profile and the dev-dependency
  optimisation table are copied from the other roots; the `[patch.crates-io]` table equals node's.
* `tests/build_independence.rs` pins all of this (allow-list of dependencies, features, profiles,
  patches, lock versions, guards, forbidden source patterns, the resolved graph). It reads the sibling
  manifests `../consensus`, `../node`, `../desktop`, `../release-signer` and `../node/Cargo.lock` as
  text: a source package built for a runner must contain them.

## Safety properties and where they are tested

| Property | Test |
|---|---|
| plan to review to authorize to `Transfer::verify` to a real certified block | `e2e_payment` |
| fee is the exact signed size (fixed point), change and no-change boundaries, 16 KiB limit, dust prefix, rotation | `unit_payment` |
| every refusal that applies to payments (and the registry and cancellation refusals) | `refusals_core` |
| review completeness; no byte of the unsigned operation can change unnoticed; golden text | `review_completeness_payment` |
| single use, plan binding, head binding, expiry, future-stamped approvals, lock, withdrawal of an issued approval, typed acknowledgements, plan state machine, approval scope | `approval_flow` |
| independent verification on commit, metadata derived from the bytes, reservations, open-only capacity and history trimming, chain binding, stale views, integrity, reconciliation, import, partial container | `partial_and_outbox` |
| exact bytes survive a process kill; damaged, foreign or non-file locations refused; the same contract as the in-memory outbox | `outbox_sqlite` |
| unsigned proposals adopted for offline or co-signing; the Treasury profile through `adopt` and in the approval scope | `adopt_offline` |
| no secret in any `Debug` output | `debug_no_secret` |
| build independence: dependency allow-list, features, guards, no signing API over bytes, the public ways to an approval, a gate and a signer, every test-gate item behind the non-shipping cfg, the gate marker really embedded by the library | `build_independence` |
| randomised payment planner properties; threading contract of the public types | `payment_properties` |
| wallet rotation end to end on a real chain; every refusal; review completeness (golden); fee and size against an independent model, the outbox, co-funded parts | `e2e_rotation`, `refusals_rotation`, `review_completeness_rotation`, `rotation_outbox_and_properties` |
| dividend claims end to end (awards reached by stepping blocks); every refusal; review completeness | `e2e_dividend`, `refusals_dividend`, `review_completeness_dividend` |
| bond creation, unbond and withdrawal at the floor on a real chain; every refusal; review completeness | `e2e_bond`, `refusals_bond`, `review_completeness_bond` |
| hash lock, claim and refund on a real chain; every refusal; review completeness; fee fixed point, hostile decoding, preimage store, discovery | `e2e_conditional`, `refusals_conditional`, `review_completeness_conditional`, `unit_conditional` |
| License DvP, fiat lock and release on a real chain; offer import and hostile decoding; every refusal; review completeness | `e2e_license_dvp`, `e2e_fiat`, `offers_dvp`, `refusals_dvp`, `review_completeness_dvp` |
| the Treasury profile (R1, R2, offer freeze) on a real chain; every refusal; review completeness; outbox and reconciliation | `e2e_treasury`, `refusals_treasury`, `review_completeness_treasury`, `treasury_outbox_and_properties` |
| the Bitcoin custody boundary: no Bitcoin type, key, script or custody path; BTC terms are integer data only | `btc_boundary` |
| atomic replacement of an open partial record by its completion (memory and SQLite), refusals, a process killed between the steps leaves the partial or the complete record | `outbox_replace` |
| ONE real chain running every kind in a realistic order through the full pipeline, wallet and consensus agreeing at every step, with wrong-order, stale-head and double-reservation negatives | `e2e_matrix` |
| the checksummed address text: round trip, class prefixes, one typed error per rejection class, single substitutions and adjacent transpositions, the check order, the BIP-350/BIP-173 strings, the public vectors (W2) | `address_format` unit tests, `address_format_vectors` |
| typed signing capabilities: raw signing is a compile error (compile_fail doctests with controls), the capability table, kind and identity checks (W4) | `capability` doctests and unit tests, `build_independence` |
| one live approval per gate, withdrawal on re-presentation, binding to the exact bytes and verified state (W5) | `approval_flow` |
| view-verified export: bytes, signatures, approval binding, chain context, stale, expired, confirmed, conflicting and forgotten records, a rewritten store; the stranded diagnostic (W6, W9) | `outbox_export`, `e2e_bond` |
| one offer check: the same refusal code for every failure from every handler and entry point (W19) | `offer_checks` |
| opaque commitments: a Caution with the Conditions acknowledgement on every kind (W23) | `opaque_commitments` |

## The defaults Q1 to Q17 (settled by the Order)

The wallet plan assumed seventeen defaults; the Order settled each one individually (W1), and
temporary limitations are not the final product's scope. What the core applies now: Q1 signed
non-Transfer operations are queued locally and exported as bytes after a view-verified check
(`export_verified`, W6), no delivery claim (interim until P4 delivery); Q2 consent model (a):
re-review at every new head (`PlanSession::on_head`; interim until P4); Q3 only the hash-lock
refund exists as a cancellation, every other cancel is an explicit tested refusal; Q4 bond unbond
and withdraw carry no fee (`FeeRule::None`), an explicit, narrow decision for those two operations
only; Q5 both Treasury rotations (R1 and R2) only behind an identity-checked, non-default Treasury
profile; Q6 signing is available only under `cfg(test)` or the non-shipping `test-value-signing`
while the production gate is closed; Q7 offers and fill proofs are imported and verified, not
created (interim); Q8 trade and contract commitments are shown as opaque, with a Caution that
requires the Conditions acknowledgement (W23); Q9 a License sale does not bind the remaining
dividend entitlements: the review shows it and requires an acknowledgement (binding them is P5,
Lane P's); Q10 the checksummed address text (W2, PROPOSED) with the legacy hex, and the typed
last-eight-characters check as an interim aid; Q11 heights and epochs with approximate durations
labelled approximate; Q12 file or QR exchange of public partial operations; Q13 preimages are fresh
OS-random values in their own record, never derived from the wallet phrase; Q14 "License purchase"
means a sale of an existing License by delivery versus payment; Q15 Treasury spending is refused
below the dividend reserve; Q16 bonds only for nodes this wallet owns, read from verified state; Q17
a fresh Worker assignment after a sale is stated in the review, not built (the Order does not waive
it: a later stage). Where the code applies each one: `docs/WALLET-OPERATIONS-V1.md`, section 4.7;
the status of each against the Order: section 6 there.

## Findings and limits

* `bitcoin_hashes` (v0.14, the hash-function library used by `bip39`, which crypto-v2 links in every
  root) and its encoding dependency `hex-conservative` are in this crate's resolved graph
  (`cargo tree -e normal,build`). Neither contains key, script, transaction or custody code, and no
  wallet-core source names either. An exclusion rule of the form `^bitcoin` would flag every root;
  the allow-list in `build_independence.rs` names exactly this package and pins its only parent chain
  (bip39 under crypto-v2). The Order (W3) keeps these narrowly pinned bip39-to-crypto-v2 hash
  dependencies. A library name does not authorize Bitcoin custody/signing or another wallet stack.
* `PlanObject` bytes are NOT zeroized on drop (phase 8 decided to document rather than implement):
  a conditional claim's plan holds the hash-lock preimage in clear, but so do the claim's signed
  bytes, its outbox record, the consensus structures that decode it and every clone of the plan
  (`PlanObject` is `Clone` and its `bytes` field is public, so a `Drop` would also break code that
  moves the bytes out), and the claim publishes the preimage at inclusion. The preimage's own record
  (`secret::Preimage`) is zeroized; a host keeps plans and the outbox file as protected as the
  preimage store until the claim is included.
* `AckKind`, `Settlement`, `OutboxStatus` and the other public enums that may gain variants are
  `#[non_exhaustive]` since candidate 3 (Order W9; the desktop got wildcard arms). Reconciliation
  reports `Settlement::Stranded(h)` when a bond creation's funding payment was included without the
  creation (`ops::bond::stranded_escrow` tells a host the same): a DIAGNOSTIC of an old or test
  failure, which does not replace atomic bond funding (Lane P, stage 2). Phase 4's optional
  acknowledgement kind for the coupling was not added: the coupling is acknowledged through the
  `ESCROW_COUPLING` warning (Danger, requiring `AckKind::Irreversible`).
* A payment can carry about four inputs: each signed hybrid input is roughly 3.4 KB and a transaction is
  capped at 16 KiB. The planner refuses with a typed `SIZE_LIMIT` that says to consolidate (send coins
  to yourself); `TOO_MANY_INPUTS` is reachable only for many tiny coins.
* `Outbox` reconciliation recognises a confirmed payment from the host's confirmation index or from
  one of its output coins; inputs that vanished without such evidence are `InputsSpent`, not confirmed.
* No submission path exists for non-Transfer operations in this protocol version (Q1): the core can
  build, review, sign, queue and export them, nothing more.
