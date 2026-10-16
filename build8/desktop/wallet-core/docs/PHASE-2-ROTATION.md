# PHASE-2-ROTATION: native wallet-authority rotation (`WalletRotation`)

Evidence status: at most NATIVE PASS (offline, TEST-VALUE). Implemented is not Qualified; offline is
not physical; simulated is not physical. Signing exists only behind the non-shipping TEST-VALUE gate
while `mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED` is false (Q6); nothing here was run on Linux,
on a production chain, or with a real key.

Files: `src/ops/rotation.rs` (handler, two-key session, `combine`, and unit tests for two
defence-in-depth checks no public path reaches: the plan's evidence object, and the handler's own
current-authority check), `src/plan.rs` (the one permitted shared edit: `RotationRequest`), tests
`e2e_rotation.rs`, `refusals_rotation.rs`, `review_completeness_rotation.rs`,
`rotation_outbox_and_properties.rs` (an extra file named for this phase), and the golden snapshot
`golden/rotation_review.txt`.

## 1. The operation, as consensus defines it

A FUNDED `hybrid_transaction_v2::Transaction::Rotate { rotation, transfer }`, encoded
`[2, 21, rotation_bytes, transfer_bytes]`. Rules read from the code (not taken from the analysis):

| Rule | Where |
|---|---|
| both descriptors `WalletOwner`; proposed generation = current + 1 (`WrongGeneration`) | `wallet_rotation_v1.rs` `Rotation::unsigned` |
| neither the Ed448 nor the FN-DSA component reused (`Duplicate`) | same |
| network = `NETWORK_ID` (`WrongNetwork`); Genesis, fingerprint, authority non-zero and window `expiry - created <= 10,080` (`Codec`) | same |
| authorization by the current key over `unsigned()` in `Domain::WalletRotate`; possession by the proposed key in `Domain::WalletRotatePossession` | `Rotation::sign` / `Rotation::verify` |
| Genesis/fingerprint (`WrongGenesis`, `WrongFingerprint`), `authority` and `current` equal the committed current descriptor (`WrongGeneration`), inclusion height inside the window (`StaleSequence`) | `Rotation::verify` |
| a generation-one authority the book does not know is REGISTERED first (its address must be the authority); then `WalletBook::apply`: unknown authority (`UnknownSigner`), new address already registered (`Duplicate`), capacity | `hybrid_transaction_v2.rs` `Transaction::verify`, `wallet_authority_v1.rs` `apply` |
| the rotation is applied FIRST; the transfer is verified against the UPDATED book: every coin of the rotating authority (old addresses and the new address) is spent by the NEW descriptor | `Transaction::verify` |
| rotation and transfer share network/Genesis/fingerprint (`Binding`); envelope <= 16 KiB (`Bounds`) | `Transaction::encode` |
| fee >= encoded length of the WHOLE envelope (`Fee`); conservation, maturity, missing input, owner, input signatures as for any transfer | `Transaction::verify`, `transactions_v2.rs` |
| one pending rotation per authority | the hybrid MEMPOOL (`mempool_v2.rs` `rotations_v2`), not consensus validity |
| old addresses keep their coins and resolve to the new descriptor; the old key loses authority at inclusion | `WalletBook::authorize` |

Corrections and additions to the analysis (G-wallet 3.2):

1. **The signatures do not bind the rotation to its funding.** The rotation's two signatures cover
   `Rotation::unsigned()` only; each funding input's signature covers the transfer only
   (`Transfer::signing_payload`). Pinned on the real rig (`e2e_rotation::the_rotation_signatures_do_not_bind_the_funding_as_the_reviews_say`):
   (a) another wallet's funding transfer is a valid plain transfer ON ITS OWN, so a block producer
   can include it without the rotation (the payer pays the fee, no rotation happens); (b) a signed
   rotation is accepted with a THIRD wallet's funding; (c) after that, the rotating wallet's own
   funding transfer (signed by the new key) is valid on its own. Every review says so
   (`FUNDING_NOT_BOUND`), and reconciliation never takes "the book shows the new key" as proof that
   THIS transaction was included.
2. "One pending rotation per authority in the outbox (`mempool_v2.rs:419-428`)" is the mempool's
   rule; the wallet adds it to its own outbox as the reservation key `rotation_resource(authority)`.
   The pool's `reserved_inputs()` does NOT expose pending rotations, so a host cannot merge another
   device's pending rotation into `ChainView::reserved` (see section 9).
3. Size: one funding input gives a 10,202-byte envelope with the wallet's field widths (spec example
   10,198); two inputs fit; three exceed 16 KiB (`refusals_rotation`, `rotation_outbox_and_properties`).
4. A rotation for another Genesis/fingerprint fails `Transaction::verify` as `Signature` (the
   rotation is applied before the transfer's binding check); the precise reason is
   `Rotation::verify`'s `WrongGenesis`/`WrongFingerprint`.

## 2. Request (`RotationRequest`)

| Field | Meaning |
|---|---|
| `proposed_descriptor: Blob` | public descriptor of the new key at generation current + 1 |
| `fee_source: FeeSource` | `RotatingAuthority` (its coins, spent by the NEW key; change to the new address) or `OtherWallet(identity)` (that wallet's coins and change; it signs its own inputs) |
| `new_key_restore_verified: bool` | the HOST's statement that a clean restore of the new phrase was performed |
| `restore_verified_fingerprint: Option<Hash>` (new) | `ops::rotation::descriptor_fingerprint` of the descriptor that restore produced |
| `validity_blocks: u64` | 1..=10,080, default 144 |

Builders (new): `with_restore_verified(fingerprint)` (sets both evidence fields), `with_validity_blocks`.
`descriptor_fingerprint` is consensus `trading_v1::descriptor_hash` (the protocol's own descriptor
hash, the value a Treasury destination rotation records).

## 3. Plan

* Objects: `rotate` = the unsigned envelope (placeholder signatures, so its length is the signed
  length); `restore-evidence` = canonical CBOR `[EVIDENCE_TAG, true, fingerprint]` for the proposed
  descriptor. Both are in the review digest, so every approval and confirmation phrase is bound to
  the restore statement for exactly the descriptor that gets signed. `unsigned_form` and `explain`
  rebuild the same evidence object from the bytes (a valid plan can only carry the evidence of its
  own proposed descriptor), so a counterparty's digest equals the proposer's.
* Requirements: `RotationAuthorization` (wallet = authority), `RotationPossession` (wallet = new
  address), `Input(i)` (wallet = coin owner); `ThisWallet` / `Counterparty` / `Provided` by perspective.
* Inputs (reservations): the funding coins and `rotation_resource(authority)`. Validity: the heights
  at which the rotation AND the funding are valid (equal windows for wallet-built plans).
* Funding: `select::candidates` (largest first), the fee fixed point over the WHOLE envelope with
  exactly one change output (positive), at most what fits in 16 KiB (in practice two inputs). Too
  many small coins: `SIZE_LIMIT` with the consolidation hint; too little value: `INSUFFICIENT_FUNDS`
  (`available` = all spendable, `requested` = the least fee of the largest shape tried).

## 4. Review rows (always through `ReviewDraft`)

Rotating wallet (current or proposed key of the authority): title "Rotate wallet key" ("Rotate the
Treasury wallet key" for R1); `high_risk` (typed confirmation phrase); destination 0 = the new key's
address with its typed re-entry check (label `External` because the verified chain does not know it
before inclusion; a condition row says so); conditions "Wallet authority", "Key generation" (g to
g+1), "Current key fingerprint", "New key fingerprint", "New key address", "New key restore check"
(from the bound evidence object; from raw bytes: "not shown by these bytes" plus a
`RESTORE_NOT_SHOWN` warning), "Validity window" (both windows when they differ), "One pending
rotation", "Funding", "Fee rule" (whole-envelope size), "Maturity"; effects: the exact irreversible
statement `IRREVERSIBLE_KEY_LOSS`, the generation change (irreversible), "Old addresses keep their
coins", funding coins spent, change, fee, no revocation; warnings `TEST_VALUE_CHAIN`, `KEY_ROTATION`
(requires `KeyLoss`), `FUNDING_NOT_BOUND`, `COUNTERPARTY_FUNDED`, `TREASURY_ROTATION` and
`TREASURY_FUNDS` (require `TreasuryAuthority`), `FEE_ABOVE_MINIMUM`, `EXPIRES_SOON`, `BAD_SIGNATURE`;
extra acknowledgement `Conditions`. Amount `None` (no principal moves); fee with rule, payer and size.

Payer ("Pay the fee of a wallet key rotation"): its change is `Change`/this wallet, the restore check
is "asserted by the rotating wallet's host", `ROTATION_OF_ANOTHER_WALLET`, and `FUNDING_NOT_BOUND`
says its funding is valid on its own. Observer: "Key rotation of another wallet", signs nothing.
Change returned to ANOTHER funder is listed under effects, not as a destination the reader must
type-check. Golden text: `tests/golden/rotation_review.txt`.

## 5. Authorization

* `RotationSigner` (public): holds the current and the new `HybridKey` (zeroizing, erased together
  on `lock`, idle expiry, poisoned lock and drop; `Debug` prints `<redacted>`); needs a
  `SigningGate`; authorizes `WalletRotation` plans only (`REASON_SESSION_KIND`); runs
  `authorize::run_authorization` with `KeyRing { primary: current, secondary: Some(new) }`.
  Test-only constructors `for_test` / `authorize_at` are behind the non-shipping cfg.
* Keys are reached only through `KindSigner`: `(WalletRotation, RotateAuthorization)` ->
  `Domain::WalletRotate`, `(WalletRotation, RotatePossession)` -> `Domain::WalletRotatePossession`,
  `(WalletRotation, Spend)` for `Transfer::sign_input` (consensus selects `Domain::Transaction`). All
  three pairs are already listed by `domain_for`; no new pair, no caller-chosen domain.
* `check_requirements` (overridden): the rotation slots require the plan's signer to be the
  authority's CURRENT key on the CURRENT book (`check_current`, stale refuses); a funding input of the
  rotating authority requires the new descriptor and the rotating signer; any other input requires
  the signer's own descriptor, authorized in the current book and in the book after the rotation.
  `sign` also checks the session holds exactly the plan's two keys (`NotRequiredSigner`).
* Other wallet pays: the rotating wallet's result is `Partial` (missing `Input(i)`); the payer
  adopts the bytes (or `PartialApproval::adopt_for`), reviews the same digest, signs its inputs with
  an ordinary `KeySigner` (`Partial`, missing the rotation slots); `ops::rotation::combine(a, b, view)`
  joins them. `combine` holds no key: every taken signature must verify and the result is verified
  again before it is returned. The rotating wallet never adopts rotation bytes (`REASON_ADOPT_ROTATION`):
  its plan needs the restore evidence and is built where both keys are.

## 6. Verification through public consensus code

* Complete: `hybrid_transaction_v2::Transaction::verify(genesis, fingerprint, next_height, coins,
  wallets)` after checking both halves of all signatures are present (BOTH_REQUIRED).
* Partial: `wallet_rotation_v1::Rotation::verify` when both rotation signatures are present;
  otherwise each present signature with `mutiny_crypto_v2::PublicKey::verify` over the consensus
  payloads `Rotation::unsigned()` / `Transfer::signing_payload(i)`.
* Every case also runs the full signature-free mirror (`check`): context, key rules, windows,
  committed current key, new address not registered (`WalletBook::records` + `address_key`), funding
  against the book after the rotation, conservation, whole-envelope fee, reserve rule.
* Treasury reserve: `State::treasury_owner_set` plus the new address when the Treasury itself
  rotates, backing as `DividendState::backing` over the post-block coins; differentially checked
  against block execution at the exact boundary (`e2e_rotation`).

## 7. Refusals (each: no signature, nothing queued; consensus checked where it has a rule)

| Case | Wallet refusal | Consensus | Test |
|---|---|---|---|
| Ed448 reused | `INVALID_REQUEST` `REASON_REUSED_ED448` | `unsigned` `Duplicate` | refusals_rotation |
| FN-DSA reused | `INVALID_REQUEST` `REASON_REUSED_FNDSA` | `Duplicate` | refusals_rotation |
| generation not +1 | `INVALID_REQUEST` `REASON_WRONG_GENERATION` | `WrongGeneration` | refusals_rotation |
| window 0 or > 10,080 | `INVALID_VALIDITY` | `Codec` (span) | refusals_rotation |
| window not open / closed | `WINDOW_NOT_OPEN` / `WINDOW_CLOSED` | `StaleSequence` | refusals_rotation |
| stale or foreign authority | `STALE_AUTHORITY` | `WrongGeneration` -> `Signature` | refusals_rotation, e2e |
| pending rotation | `RESERVED_INPUT` (slot) | mempool `Conflict` | refusals_rotation, e2e |
| no / too little funding | `NOTHING_SPENDABLE` / `INSUFFICIENT_FUNDS` | `Fee` | refusals_rotation, properties |
| 16 KiB | `SIZE_LIMIT` (consolidation hint) | `encode` `Bounds` | refusals_rotation, properties |
| fee below envelope | `FEE_BELOW_MINIMUM` | `Fee` | refusals_rotation |
| conservation, missing input, old key on the funding, immature | `CONSERVATION`, `INPUT_UNAVAILABLE`, `STALE_AUTHORITY`, `IMMATURE_INPUT` | `Conservation`, `MissingInput`, `Owner`, `Immature` | refusals_rotation |
| Genesis / fingerprint / network | `WRONG_CONTEXT` (field) | `WrongGenesis`/`WrongFingerprint` -> `Signature`; `WrongNetwork`; split parts `Binding` | refusals_rotation |
| new address registered | `INVALID_REQUEST` `REASON_NEW_ADDRESS_REGISTERED` | `apply` `Duplicate` | refusals_rotation |
| restore evidence missing / other descriptor | `INVALID_REQUEST` `REASON_RESTORE_NOT_VERIFIED` / `..._OTHER_DESCRIPTOR` | none (wallet precondition; consensus accepts) | refusals_rotation |
| payer approval missing / tampered | `VERIFICATION_FAILED` / `COUNTERPARTY_APPROVAL_INVALID` | `Signature` | refusals_rotation |
| Treasury without the profile (rotating or paying) | `TREASURY_PROFILE_REQUIRED` | none (profile is a wallet rule) | refusals_rotation, e2e |
| Treasury reserve | `RESERVE_BACKING_VIOLATION` | block execution refuses | e2e_rotation |
| payer = rotating authority | `INVALID_REQUEST` `REASON_PAYER_IS_ROTATING` | n/a | refusals_rotation |
| session: wrong new key, single key, other kind, locked, idle | `NOT_REQUIRED_SIGNER`, `INVALID_REQUEST` `REASON_SESSION_KIND`, `LOCKED` | n/a | refusals_rotation |

Not mirrored: `WalletBook` capacity (10,000,000 records; no cheap public accessor).

## 8. Outbox and reconciliation

`describe` reports the identifier (`Transaction::id`, the same for unsigned, partial and complete
bytes), completeness, the missing slots (`Counterparty`; inputs name their descriptor's address), the
common window and the reservations (coins + `rotation_resource`). Bytes with no signature at all are
refused (a proposal is not a signed operation). `reconcile`: confirmation index -> `Confirmed(h)`; an
output coin of THIS transaction -> `Confirmed(created_height)`; past the window -> `Expired`; a funding
coin gone -> `InputsSpent`; otherwise `Pending`, also when the book shows the new key (the same
rotation may have been funded by someone else, and this record's funding transfer then stays valid
on its own until it expires, so its coins stay reserved). A queued partial settles with the complete
transaction (same identifier).

## 9. Change requests (not made; shared files are frozen)

* **CR-1** `tests/partial_and_outbox.rs` (phase 1) asserts that a payment's bytes labelled
  `WalletRotation` are refused as `NOT_IMPLEMENTED`. With this phase the kind has a handler and the
  refusal is `MALFORMED`, so that test FAILS on this branch. Replace the assertion (lines 131-134):

  ```rust
  let refusal = outbox.commit(&foreign, &view).unwrap_err();
  if ops::implemented_kinds().contains(&OperationKind::WalletRotation) {
      assert!(matches!(refusal, Refusal::Malformed(_)), "{refusal:?}");
  } else {
      assert_eq!(refusal, Refusal::NotImplemented(OperationKind::WalletRotation));
  }
  ```
* **CR-2** `review.rs`: an `AddressLabel::NewKey` ("this wallet's new key, not yet known to the
  chain", `needs_typed_check() == true`) so the new address is not rendered "an external address".
* **CR-3** `refusal.rs`: dedicated codes instead of `INVALID_REQUEST` reasons and `RESERVED_INPUT`:
  `ROTATION_KEY_REUSED`, `ROTATION_GENERATION`, `RESTORE_NOT_VERIFIED`, `ROTATION_PENDING`,
  `ROTATION_ADDRESS_TAKEN` (each with a `CATALOG` line and `Display` text).
* **CR-4** `outbox.rs` / `outbox_sqlite.rs`: let a `Complete` record replace an OPEN `Partial` record
  with the same identifier and the same unsigned form. Today the complete co-funded rotation is
  refused with `OUTBOX_INTEGRITY` until the part is forgotten and pruned (pinned by tests).
* **CR-5** `README.md`: rows for the rotation tests in "Safety properties" and the kind in the
  module map (the lead consolidates the README).

Missing consensus accessors (workarounds in place): `WalletBook` lookup of one address (today
`records()` builds the whole map on every validation); the hybrid mempool's pending rotation
authorities (`rotations_v2`) for `ChainView::reserved`.

## 10. Defaults assumed and open questions

Defaults: Q1 (queued and exportable, no delivery claim; rotations do have a mempool path), Q5 (R1 =
this operation under the Treasury profile, either fee source), Q6, Q10 (hex and typed last eight
characters), Q11, Q12 (public partial exchange), Q15 (reserve-aware).

Open questions (proposals):
1. Restore-check evidence: today a boolean plus the descriptor fingerprint, bound into the plan.
   Proposal: the host builds the `RotationSigner`'s NEW key from the restore of the written-down
   phrase (never from the generation step), compares its descriptor with the proposal and passes
   the fingerprint; the possession signature is then itself made by the restored key. A host record
   of the restore (time, method) belongs to phase 7.
2. Offline signing: proposal: plan, review and sign on the offline machine that holds both keys
   and performs the restore check, from a verified view of the head; the online machine relays
   bytes. If online planning is wanted, add a rotation-specific adoption that takes the restore
   evidence (own file only).
3. Funding not bound (section 1): accept as protocol behaviour (current reviews warn), or bind the
   funding transfer identifier into the rotation body in a later protocol version.

## 11. Not done here

Phase 6 owns the Treasury gating tests (here: profile guard, reserve rule, one R1 e2e). No desktop
vault replacement, no restore implementation (phase 7). No Linux run. Rotation records were
exercised through `MemoryOutbox` only; `SqliteOutbox` shares the admission and settlement code
(`admit_record`, `settle`) but no rotation record was written to it here.
