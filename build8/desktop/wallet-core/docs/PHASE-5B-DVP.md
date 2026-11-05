# Phase 5B: License purchase and transfer by DvP, fiat lock and release, maker offers

Kinds: `LicenseDvp`, `FiatLock`, `FiatRelease`. Files: `src/ops/license_dvp.rs`, `src/ops/fiat.rs`,
`src/offers.rs`, the request fields of these three kinds in `src/plan.rs`; tests
`tests/e2e_license_dvp.rs`, `tests/e2e_fiat.rs`, `tests/refusals_dvp.rs`,
`tests/review_completeness_dvp.rs`, `tests/offers_dvp.rs`, support `tests/support/trading_5b.rs` and
`tests/support/trading_rig_5b.rs`, golden snapshots `tests/golden/dvp_buyer_review.txt` and
`tests/golden/dvp_seller_review.txt`.

**Evidence status.** NATIVE PASS (offline, TEST-VALUE) at most: Windows, simulated TEST-VALUE chains
(the consensus block-driver rig with real hybrid certificates, and synthetic states checked with
`trading_v1::prepare_batch`), public test keys and random transport keys. Implemented is not
Qualified; offline is not physical. Signing exists only behind the non-shipping TEST-VALUE gate; the
production gate stays closed.

## 1. Protocol rules mirrored (checked against `consensus/src/trading_v1.rs`)

`apply_one` order for every native trading operation at inclusion height `H`: context; operation
window `created <= H <= expiry` and `expiry - created <= 10,080`; `fee >= max(240, wire length)`; not
already applied (`Applied` record); approval slot set exactly `expected_slots()`; `verify_offer(H)`
(context, offer id and maker binding, offer window against `H` and against the operation window,
exact terms, offer signature, fill signature over the exact body; an offer proof on an action that
fills no offer is refused); then the action:

* **LicenseDvp**: `price > 0`, `seller != buyer`, `effective_height == H`; the License exists, has
  the context's Genesis and is owned by exactly `seller`; the generation the last native transfer
  recorded (1 when never transferred, `license_generation`) equals `license_generation` and that
  buyer's rights have started; slot 0 authorized for `seller` and slot 1 for `buyer` against the
  PARENT wallet book (`verify_approval`); `Book::transfer_candidate`: no pending Worker assignment,
  non-zero TradeID and ContractHash, current assignment sequence; `debit`: at least one input, every
  input a coin of exactly the buyer address, created before `H`, mature if coinbase, inputs equal
  `price + change + fee`; `consume`: the single-fill record. Effects: price to the SIGNED
  `payment_destination` (output 0), change to the buyer (output 1), owner and native generation and
  assignment sequence change at `H`, the Worker is detached, rights from `H + 1`.
* **FiatLock**: `amount > 0`, `seller != buyer`; slots 0 seller, 1 buyer; the seller funds
  `amount + change + fee`; the amount becomes a lock record at `output_id(0)` (kind `Fiat { terms }`),
  change to the seller (output 1); the offer is consumed.
* **FiatRelease**: bound to the lock (context, TradeID, ContractHash, generation, amount, created
  before `H`), kind `Fiat` with the same terms, recipient = buyer, sender = seller; slots 0 buyer,
  1 seller; NO offer proof; the buyer pays `0 + change + fee` from its own coins; the locked amount
  is paid to the buyer (output 0), change to the buyer (output 1), the lock record is removed.
* A claim or a refund of a fiat lock returns `FiatRecoveryUnspecified`: there is no timeout, refund
  or unilateral release.

Facts the analysis did not state and the code does (verified): the License book refuses a transfer
whose TradeID or ContractHash is zero (`transfer_candidate`, surfaced as `LicenseLocked`); consensus
ACCEPTS a zero `payment_destination` (it credits the zero address; pinned by
`a_zero_payment_destination_is_refused_by_the_wallet_although_consensus_would_pay_it`); `debit`
requires inputs owned by exactly the payer AddressID (not merely controlled by its key); a License
offer, once filled, is refused on reuse by the generation rule before the single-fill rule (the sale
that consumed it moved the generation on), so the single-fill rule is isolated with a fiat offer;
`price == 0` cannot be reached past the exact-terms rule because an offer of price zero does not
encode.

## 2. Parties and the placeholder form

Three parties sign a License sale: the seller (approval slot 0), the buyer (slot 1) and the maker
(the fill: a `Role::Transport` signature under `Domain::TransportInitiator` the wallet never
produces; Q7). A fiat lock has the same three; a fiat release only the two wallets (slot 0 buyer,
slot 1 seller).

A trading operation of this wallet always carries EVERY approval slot and, for an offer-bearing
action, the offer proof; a signature not yet present is an all-zero placeholder of the fixed hybrid
width (descriptors are the signers' CURRENT descriptors, so their lengths are exact). Therefore the
placeholder form has exactly the length of the completed operation (pinned:
`complete.len() == planned.len()`), and the fee is fixed once, before anyone signs, as the smallest
fixed point `fee >= max(240, length)` (fee and change widths can only raise it). Every later step
re-checks the fee against the same canonical length, so a part whose fee became too low is refused,
never signed short. The UNSIGNED form (every approval signature and the fill zeroed; the maker's
OFFER signature kept) is the plan object, what each party reviews and what the review digest binds:
the buyer's review, the seller's explanation of the buyer's part and anybody's explanation of the
completed operation share one digest at one head.

The flow (License sale; the fiat lock is the same with the seller planning):

1. Buyer: `plan(LicenseDvpRequest)` imports and verifies the offer, reads the License, its generation
   and the seller's current descriptor from verified state, selects coins of exactly its current
   address (largest first, at most 16 = `trading_v1::MAX_INPUTS`, sorted by `native_input_id` with
   the locators in the same order), fixes the fee and change, and binds the plan to the next block
   (`created = expiry = effective_height = head + 1`). Review, approve (high risk: typed phrase),
   `authorize` signs slot 1 only, verifies it with `verify_approval` and returns
   `SignedOperation::Partial`; the buyer may queue it (reservations) and exports it as a
   `PartialApproval` (Q12).
2. Maker: signs the fill over the exact body; `offers::attach_fill_proof` verifies it
   (`verify_offer`) and places it.
3. Seller: `PartialApproval::import` / `explain_for` (seller-specific review, counterparty
   signatures shown as provided and verified, invalid ones as a Danger warning), `adopt_for` (refuses
   a rotated-away identity, bytes the seller has nothing left to sign in, and any counterparty
   signature that does not verify), review, approve, `authorize` signs slot 0 only.
4. Anyone: `offers::combine(parts, view)` merges parts of the same unsigned form after verifying
   every signature, then runs the kind's `check_signed`: `verify_approval` per approval,
   `verify_offer` for the fill, and for a complete operation `trading_v1::prepare_batch(state,
   anchor, state_root, [bytes], CandidatePolicy::native_denomination_locked())`.

Each wallet signs only its own slot over the unsigned plan; there is no path in which one wallet's
`authorize` adds another party's signature. `combine` takes no key and signs nothing.

## 3. Request fields (the one permitted edit of `plan.rs`)

| Request | Field | Meaning |
|---|---|---|
| `LicenseDvpRequest` | `offer` | the maker offer in the container `offers::encode_offer` produces |
| | `license` | the License; must equal the offer's |
| | `payment_destination` | default the seller's address; any other value is flagged |
| | `validity_blocks` | NOT used: a License sale is valid in exactly one block |
| | `trade`, `contract` (new) | opaque TradeID and ContractHash (Q8); must be non-zero |
| | `seller_descriptor` (new) | empty = read from the wallet book; needed only for an unregistered generation-one seller |
| `FiatLockRequest` | `offer`, `buyer`, `amount_atoms`, `payment_terms` | the amount and terms must restate the offer's |
| | `trade`, `contract`, `validity_blocks` | window `head+1 .. head+1+validity`, clamped to the offer's expiry |
| | `buyer_descriptor` (new) | as `seller_descriptor` |
| `FiatReleaseRequest` | `lock` | the lock output identifier (`output_id(0)` of the lock) |
| | `validity_blocks` | window from the next block |
| | `seller_descriptor` (new) | as above |

Builders: `with_payment_destination`, `with_commitments`, `with_seller_descriptor`,
`with_buyer_descriptor`, `with_validity_blocks` (fiat).

## 4. Plans, signing and verification

* Plan object: one, label `native-operation`, the unsigned placeholder bytes; schema 1.
* Requirements: `Approval(n)` for each slot (`ThisWallet` for the planner's slot, `Counterparty`
  otherwise), `OfferSignature` (`Provided`) and `FillSignature` (`Maker`) for offer-bearing kinds.
* `inputs()`: the coins AND the resource keys the outbox will reserve.
* Validity: the meta window; `valid_only_at = Some(effective_height)` for a License sale.
* `sign`: for each `ThisWallet` approval slot, `KindSigner::sign(Primary, Spend, signing_payload)`
  (domain `Transaction` from `domain_for`), then `verify_approval` at once.
* `check_signed`: identifier from the bytes, chain context, every unsigned rule against the current
  view (reservations not counted), every present signature (`verify_approval`, `verify_offer`),
  completeness claim equals the bytes, both halves of every signature present, then `prepare_batch`
  for a complete operation. `prepare_batch` also checks that the view's state hashes to the head's
  state root, which the wallet's own mirrors never read: a complete operation is therefore refused
  (`VERIFICATION_FAILED`) on a view whose state is not the authenticated one.

## 5. Reviews (all through `ReviewDraft`, all `high_risk`)

License sale, every view: License id, index, issue height, CURRENT native generation, owner, current
Worker, assignment sequence, dividend status; the inclusion rule ("Valid ONLY if included in block
H") as a condition, a `Valid only in block` timing row and a Danger warning requiring
`SingleBlockWindow`; the offer (id, maker identity, terms, maker side, window with the approximate
duration labelled approximate, single fill); TradeID, ContractHash and the trade operation
generation as opaque commitments with the Q8 warning (requires `Conditions`); the approvals still
missing; the payment destination (flagged when it is not the seller's address); the fee rule
(`max(240, signed size)`, payer the buyer); the buyer's inputs; the pending-assignment rule;
unclaimed dividend awards read from `state.dividends.ledger()` with the statement that the sale does
NOT bind them (Q9; `UnboundDividends` acknowledgement when any award has a remaining entitlement);
irreversible effects: ownership and generation change at H, the Worker cleared, rights from H+1, the
consumed offer, spent coins, the price paid, the fee, no revoke; the fresh Worker assignment the
buyer must authorize afterwards (Q17, stated, out of scope).

* Buyer view: "Buy License ...", change returned, total leaving the wallet.
* Seller view: "Sell License ...", "This wallet receives the price ... at X" (when X is its own),
  "This wallet loses License ..., its remaining dividend entitlements and its mining rights", "The
  reward of block H is still attributed to this wallet"; the unclaimed-award warning is Danger and
  says to claim before the sale; a destination elsewhere is a Danger warning with the typed check.
* Observer view: "License sale between other wallets".
* Fiat lock: the locked amount for the buyer, the payment-terms commitment (opaque), the
  `NO_UNILATERAL_EXIT` Danger warning requiring `NoUnilateralExit`, `FIAT_NOT_VERIFIED` requiring
  `ExternalEvidence` ("this wallet verifies no fiat or Bitcoin settlement").
* Fiat release: the lock, the release rule (both wallets, no offer proof), the payout to the buyer;
  for the seller "Approve only after the fiat payment has reached you" (Danger) and "This wallet
  gives up the locked amount for good".

Golden snapshots pin the buyer and seller texts; the four values derived from the random maker key
(offer id, maker identity, digest, confirmation phrase) are tokenised.

## 6. Refusals (each tested; consensus verdict from `prepare_batch` on the same state)

| Situation | Wallet | Consensus |
|---|---|---|
| License generation stale | `LICENSE_GENERATION_STALE` | `Conflict` |
| pending Worker assignment | `PENDING_ASSIGNMENT_OR_LOCK` | `LicenseLocked` |
| License not owned by the seller | `LICENSE_NOT_OWNED` | `Authority` |
| seller == buyer | `INVALID_REQUEST` | `Bounds` |
| price other than the offer's (zero included) | `OFFER_PROOF_INVALID` | `Candidate(OfferBinding)` |
| zero payment destination | `INVALID_RECIPIENT` | accepted (wallet stricter, pinned) |
| effective height ahead / behind | `NOT_YET_ELIGIBLE` / `WINDOW_CLOSED` | `Bounds` |
| offer consumed (fiat offer reused) | `OFFER_CONSUMED` | `Duplicate` |
| offer expired / not yet valid | `WINDOW_CLOSED` / `WINDOW_NOT_OPEN` (offer heights) | `Candidate(Expired)` / `Candidate(Time)` |
| fill invalid / missing / no offer proof | `OFFER_PROOF_INVALID` / part stays `Partial` / `MALFORMED` | `Candidate(Signature)` / `Candidate(Signature)` / `Candidate(OfferBinding)` |
| fill for another body, offer of another maker | `OFFER_PROOF_INVALID` | `Candidate(Signature)` / `Candidate(OfferBinding)` |
| counterparty approval missing / tampered | `Partial` (a "complete" claim is refused) / `COUNTERPARTY_APPROVAL_INVALID` | `Authority` |
| seller or buyer key rotated away | `STALE_AUTHORITY` | `Authority` |
| fee below `max(240, length)`, also a part signed elsewhere | `FEE_BELOW_MINIMUM` | `Fee` |
| inputs unsorted / unbalanced / not the buyer's | `UNKNOWN_OPERATION` (not canonical) / `CONSERVATION` / `INVALID_REQUEST` | refused at decoding / `Conservation` / `Authority` |
| immature coinbase or too-new coin | `IMMATURE_INPUT` | `Immature` |
| foreign network, Genesis, fingerprint | `WRONG_CONTEXT(field)` | `Context` |
| zero TradeID or ContractHash | `INVALID_REQUEST` | `LicenseLocked` |
| Treasury purchase below the dividend reserve | `RESERVE_BACKING_VIOLATION` | `Record` (state-root invariant) |
| replayed operation | `REPLAY` | `Duplicate` |
| offer proof on a fiat release | `OFFER_PROOF_INVALID` | `Candidate(OfferBinding)` |
| claim or refund of a fiat lock | (5A kinds; cancel is `CANCEL_NOT_AVAILABLE`) | `FiatRecoveryUnspecified` |
| release planned by the seller, unknown lock, mismatched release | `NOT_REQUIRED_SIGNER` / `INVALID_REQUEST` | refused |

Also tested: `NOTHING_SPENDABLE`, `INSUFFICIENT_FUNDS` (exact totals), `TOO_MANY_INPUTS` (16),
`RESERVED_INPUT` (coins, License, offer), `TREASURY_PROFILE_REQUIRED`, `NOT_REQUIRED_SIGNER`,
`GATE_CLOSED`, `LOCKED`, `EXPIRED`, `STALE_HEAD`, `PLAN_CHANGED`, `APPROVAL_REVOKED`,
`CONFIRMATION_PHRASE_MISSING`, `CHAIN_CLASS_MISMATCH`, `CANCEL_NOT_AVAILABLE`. `SIZE_LIMIT` is
unreachable for these kinds: 16 inputs give about 13.2 KB, under the 16 KiB bound. An offer outside
its window is reported with the generic window codes (no dedicated code exists; see the change
requests).

## 7. Outbox and reconciliation

`describe` derives from the bytes: id = the OPERATION identifier (`Operation::id`, the body hash, so a
part and the completed operation share it); complete when every slot and the fill are present; the
missing requirements; the validity; reserved = the inputs plus `resource_key("license", license)` and
`resource_key("offer", offer)` (sale), `resource_key("offer", offer)` (fiat lock),
`resource_key("lock", lock)` (release). Bytes without any wallet approval are refused (nothing signed
to queue).

The shared outbox keeps one byte string per identifier while a record exists: a wallet that queued
its part cannot queue the completed operation under the same identifier (`OUTBOX_INTEGRITY`; tested),
even after `forget`. The recommended flow is therefore: each wallet queues what it signed; the party
that completes the operation queues the complete bytes; a queued part settles as confirmed when the
completed operation is included, because reconciliation matches the operation identifier.

`reconcile`: `trading_v1::reconcile(state, raw)` (the `Applied` receipt record) gives
`Confirmed(height)`; if the receipt belongs to another signed version of the same body
(`Conflict`), the `Applied` record's height is used; then the host's confirmation index; then
`Expired` once the next height passes the validity window; `InputsSpent` when an input coin is gone,
the offer was consumed by another operation, the License changed owner or generation (sale), or the
lock vanished (release); otherwise `Pending`.

## 8. Assumed defaults (none weakens security)

Q1 queued locally, exportable, no delivery claim. Q2 consent model (a): a sale is valid in one block,
the plan expires at the next head and every party reviews again. Q3 no cancellation of a signed sale
or of a fiat lock (`CANCEL_NOT_AVAILABLE`). Q6 signing only behind the TEST-VALUE gate. Q7 offers and
fill proofs imported and verified, never created; the wallet never holds a transport key. Q8 TradeID
and ContractHash opaque with a warning. Q9 unclaimed awards shown, not bound, typed acknowledgement.
Q10 hex addresses with the typed last-eight check. Q11 heights with approximate durations labelled
approximate. Q12 parts exchanged as public `PartialApproval` files. Q14 "License purchase" = DvP of an
existing License. Q17 the fresh Worker assignment is stated, not built.

## 9. Open questions

* Q2 re-planning: a three-party signature set must be collected within one block interval (about 60
  s at the target). Should the buyer's wallet re-plan automatically at a new head while keeping the
  same offer and counterparties (still requiring every party to review and sign again)? Proposal: no
  automatic re-plan in the core; the host may offer "rebuild for the next block" as an explicit user
  action that produces a NEW plan and new reviews. Real use probably needs windowed validity in the
  protocol (Q2 option c) or a coordinated signing session.
* What the seller needs of the buyer's inputs: the seller's review shows them (outpoints, values,
  conservation) because a sale funded by spent or immature coins can never be included; the seller
  does not need them for its own safety (consensus enforces the price to the signed destination).
* The offer container: the protocol has no wire format for a bare signed offer; this wallet defines
  `[label, body, ed448, fndsa]`. A canonical maker-offer object should come from the trading spec.
* Treasury as seller: the Treasury-profile guard applies to any plan the Treasury authority signs,
  including selling a License (conservative).

## 10. Change requests (not made)

1. Outbox: allow replacing an OPEN partial record by a strictly more complete version of the same
   unsigned form (same operation identifier, every signature of the old bytes kept), so a wallet can
   upgrade its queued part to the completed operation.
2. Refusals: dedicated `OFFER_EXPIRED` and `OFFER_NOT_YET_VALID` codes instead of the generic window
   codes with the offer's heights.
3. `tests/support/rig.rs`: a `Harness::step_with(operations)`; phase 5B includes the consensus rig in
   its own support file to put operations into blocks.
4. Consensus (read-only): `WalletBook::authority_of(address)` / `current_for(address)`; the wallet
   decodes `WalletBook::records()` to find the authority of a later-generation address.
