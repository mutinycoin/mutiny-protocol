# Phase 5A: conditional MUT funding (hash lock, claim, refund, the permitted cancellation)

Evidence label: **NATIVE PASS (offline, TEST-VALUE)** at most. Implemented is not Qualified;
offline is not physical; simulated is not physical. Every key used by the tests is a public test
key (BIP-39 test vectors) or a fresh random maker key created and discarded by a test. Production
signing stays unavailable (`SigningGate::production()` refuses while
`PRODUCTION_SECURITY_QUALIFIED` is false); nothing here changes that.

Owned files: `src/ops/conditional.rs`, `src/discovery/locks.rs`, `tests/e2e_conditional.rs`,
`tests/refusals_conditional.rs`, `tests/review_completeness_conditional.rs`,
`tests/unit_conditional.rs`, `tests/support/conditional_rig.rs`, `tests/support/conditional_kit.rs`,
`tests/golden/{conditional_offer.hex,hash_lock_review.txt,hash_lock_recipient_review.txt,claim_review.txt,refund_review.txt}`,
this file. Shared edit (the one permitted kind): fields and `with_*` builders of
`HashLockRequest`, `ClaimRequest`, `RefundRequest` in `src/plan.rs`.

## 1. What the protocol does (read from `consensus/src/trading_v1.rs`, not from the analysis)

The three kinds are `trading_v1::NativeOperation { operation: Operation { meta, action, approvals,
offer_proof }, inputs }`. `apply_one` checks, in this order: canonical decoding; context; window
(`created <= H <= expiry`, `expiry - created <= 10,080`); `fee >= max(240, wire length)`; no
`Applied` receipt for the operation id; the approval slot set equals `expected_slots()`;
`verify_offer(H)`; then per action:

| Action | Bounds | Authorizations | Debit (payer, principal) | Effects |
|---|---|---|---|---|
| HashLock | amount > 0, sender != recipient, `refund_height > H`, `expiry < refund_height` | slot 0 sender, slot 1 recipient | sender, amount | consumes the single-fill offer; lock record at `output_id(0)`; change coin `(op id, 1)` to the sender |
| Claim | lock exists with the claim's context/trade/contract/generation/amount, created before H; hash lock only; recipient == lock recipient; `SHA256(preimage) == condition`; `H < refund_height` | slot 0 recipient | recipient, 0 | lock removed; principal `(op id, 0)` and change `(op id, 1)` to the recipient |
| Refund | same lock checks; hash lock only; owner == lock sender; `H >= refund_height` | slot 0 owner | owner, 0 | lock removed; principal and change to the owner |

`debit` requires at least one input, every input a coin whose owner IS the paying address (an
address comparison, not a wallet-authority resolution), created before H, mature, and
`inputs == principal + change + fee` exactly. `meta.inputs` are `native_input_id` (= `utxo_key`)
values, strictly increasing; `NativeOperation.inputs` follow the same order. Each approval signs
`[NAMESPACE, body, slot, descriptor]` under `Domain::Transaction`; the maker's offer proof carries the
offer signature and a FILL signature over the body (`Domain::TransportInitiator`). No signature signs
another signature.

## 2. Requests (fields added in `plan.rs`)

* `HashLockRequest { offer, recipient, amount_atoms, condition, refund_height, trade, contract,
  validity_blocks, generation, sender }` with `with_trade`, `with_contract`, `with_generation`,
  `with_validity_blocks`, `with_sender`.
  * `offer`: the maker's signed offer as imported: the consensus `OfferProof` encoding with an
    ALL-ZERO fill signature (there is no consensus encoding of a `SignedOffer` alone; the fill can
    only exist once the operation exists). A non-zero fill, another chain, non-hash-linked terms or
    a bad offer signature are refused (`OFFER_PROOF_INVALID` / `WRONG_CONTEXT`).
  * `amount_atoms` must equal the offer's amount; `condition` is `SHA-256(preimage)` supplied by
    whoever holds the preimage; `trade` / `contract` are opaque (Q8; default zero);
    `generation` is `Meta::generation` (default 1, never 0); `sender` pins the funding address
    (default: the current-generation address first, then the other controlled addresses by
    spendable value).
  * The window is `created = H` and `expiry = min(H + validity_blocks, refund_height - 1,
    offer.expiry)`: it only ever shrinks, so the operation can never outlive its refund height or
    its offer.
* `ClaimRequest { lock, preimage, validity_blocks }` + `with_validity_blocks`. `expiry =
  min(H + validity_blocks, refund_height - 1)`. `ops::conditional::claim_request(store, lock,
  view)` builds it with the preimage this wallet's store holds for the lock's condition.
* `RefundRequest { lock, validity_blocks }` + `with_validity_blocks`.
* Cancellation (Q3): `CancelTarget::HashLockRefund(lock)` is mapped by `plan()` (phase 1) to
  `RefundRequest::new(lock)`; the resulting plan is byte-identical to a direct refund plan (tested).
  Every other target is `CANCEL_NOT_AVAILABLE` (tested for all seven).

## 3. The multi-party flow and the unsigned form

A plan holds, and every review binds, the operation with NO approvals and an all-zero fill
signature; the maker's signed offer stays in it (it is reviewed and verified). The binding digest is
therefore the same for the sender, the recipient and anyone else at the same head, whatever
signatures the bytes they hold already carry.

1. Sender: `plan(HashLock)` -> review (high risk: typed phrase) -> approve -> `authorize` ->
   `SignedOperation::Partial` (missing: slot 1 Counterparty, FillSignature Maker). Queue it
   (`Outbox::commit`) to reserve its coins and the offer; export it (`PartialApproval`, Q12).
2. Recipient: `PartialApproval::import` -> `explain_for` (same digest) -> `adopt_for` -> review ->
   approve -> `authorize` -> its own partial (slot 1 only: a signer adds only its own approvals).
3. Maker (outside this wallet, Q7): signs the fill over the body of either partial and returns an
   `OfferProof` encoding.
4. Anyone: `ops::conditional::complete(&[sender_partial, recipient_partial], Some(fill), view)`
   verifies every approval (`verify_approval`) and the fill (`verify_offer`), merges them and imports
   the result through `SignedOperation::import` (consensus verification with `prepare_batch`). It
   signs nothing. The sender then `forget`s its partial and `commit`s the complete operation.

Claims and refunds have one slot and no offer: the signer's result is `Complete` at once.

## 4. Fee, change and inputs

`fee >= max(240, length of the COMPLETE signed wire)`. The plan computes the length with
zero-signature placeholders for missing approvals: hybrid signatures are fixed width, and the
descriptor width of a missing approval is that of the slot address's CURRENT authority in the view
(the descriptor encodes its generation as a variable-width integer: the wallet reads the generation
from the wallet book, generation 1 for an address no rotation touched). The fill signature has a
fixed width whether zero or not. The fee is a fixed point, only ever rising to the largest size seen
(tests: equal to the completed length, at most 8 atoms above it, across every integer width of the
change). Whenever an approval or the fill arrives the fee is checked again against the real length
(`examine` in `explain`, `adopt`, `complete`, `check_signed`): a short fee is
`FEE_BELOW_MINIMUM`, never signed into a complete operation. Coins are the fewest largest
eligible coins of exactly the paying address (at most 16), then sorted by native input identifier.

## 5. Review rows

Built only through `ReviewDraft`. Hash lock: destinations (`Locks` to the recipient with its label
and the typed check; `Returns to this wallet` change), amount, fee (rule `TradingMinimum{240}`,
payer, signed size), total leaving, inputs; conditions: hash condition (opaque), claim window
(before block R, approximate time), refund height (refund eligibility does not execute a refund),
offer (id, window, maker side, single fill), offer terms (the external terms as integer data, not
verified), maker (trade identity, not an address; fill status), finality, trade commitments (Q8),
trade generation, validity window, inputs, fee rule, approvals still required; effects (irreversible
marked: spends, locks, consumes the offer, fee, cannot be revoked); warnings
`EXTERNAL_LEG_NOT_VERIFIED` (ack `ExternalEvidence`), `NOT_FINAL_UNTIL_CERTIFIED`,
`OPAQUE_TRADE_COMMITMENTS`, `SHORT_CLAIM_WINDOW`, `SELF_LOCK`, `FEE_ABOVE_MINIMUM`,
`EXPIRES_SOON`, `TREASURY_FUNDS` (ack `TreasuryAuthority`); extra ack `Conditions`; `high_risk`.
Claim: `The protocol pays` the whole principal, fee coins of the recipient address, claim deadline,
`preimage supplied externally; Bitcoin settlement not verified by this wallet`, irreversible
disclosure (`DISCLOSES_PREIMAGE`, Danger, ack `DisclosesPreimage`; `PREIMAGE_SUPPLIED_EXTERNALLY`,
ack `ExternalEvidence`); `high_risk`. Refund: principal back, refund height reached (earliest height
row), exclusivity; not high risk. The preimage itself is never shown. Golden snapshots pin all three
plus the recipient's view of a hash lock.

## 6. Refusals (each tested: no outbox row, no signature; consensus verdict pinned)

| Case | Wallet | Consensus (`prepare_batch`) |
|---|---|---|
| amount zero | `INVALID_AMOUNT` | `Candidate(OfferBinding)` |
| sender == recipient | `INVALID_RECIPIENT` | `Bounds` |
| refund height not above H | `INVALID_REQUEST` | `Bounds` |
| expiry not below the refund height | `INVALID_REQUEST` | `Bounds` |
| wrong preimage | `PREIMAGE_MISMATCH` | `Authority` |
| wrong recipient | `NOT_REQUIRED_SIGNER` (plan) / `INVALID_RECIPIENT` (bytes) | `Authority` |
| claim at or after R | `WINDOW_CLOSED {expiry: R-1}` | `Time` |
| refund before R | `NOT_YET_ELIGIBLE {height: R}` | `Time` |
| missing counterparty approval | `COUNTERPARTY_APPROVAL_INVALID` | `Authority` |
| tampered counterparty approval | `COUNTERPARTY_APPROVAL_INVALID` | `Authority` |
| missing / invalid offer proof or fill | `OFFER_PROOF_INVALID` | `Candidate(OfferBinding / Signature)` |
| offer proof on a claim or refund | `OFFER_PROOF_INVALID` | `Candidate(OfferBinding)` |
| offer consumed | `OFFER_CONSUMED` | `Duplicate` |
| lock not found (or already spent) | `INPUT_UNAVAILABLE` | `Missing` |
| stale authority | `STALE_AUTHORITY` | `Authority` |
| fee below max(240, wire length) | `FEE_BELOW_MINIMUM` | `Fee` |
| inputs not sorted | undecodable (`UNKNOWN_OPERATION`) | undecodable |
| inputs != principal + change + fee | `CONSERVATION` | `Conservation` |
| input not a coin of the paying address | `INVALID_REQUEST` | `Authority` |
| input coin missing | `INPUT_UNAVAILABLE` | `Missing` |
| immature coinbase input | `IMMATURE_INPUT` | `Immature` |
| refund owner is not the lock sender | `INVALID_REQUEST` | `Authority` |
| operation outside its validity window | `WINDOW_CLOSED` / `WINDOW_NOT_OPEN` | `Time` |
| Treasury lock below the dividend reserve | `RESERVE_BACKING_VIOLATION` | `Record` (post-block state invalid) |
| wrong network / Genesis / fingerprint | `WRONG_CONTEXT` | `Context` |
| already applied | `REPLAY` | `Duplicate` |
| fiat lock claimed / refunded | `INVALID_REQUEST` / `CANCEL_NOT_AVAILABLE(FiatLock)` | `FiatRecoveryUnspecified` |
| cancellation other than the refund | `CANCEL_NOT_AVAILABLE` | n/a |
| offer / lock / coin reserved by another plan | `RESERVED_INPUT` | n/a (wallet policy) |
| Treasury authority on an ordinary profile | `TREASURY_PROFILE_REQUIRED` | n/a (wallet policy) |
| request out of range | `INVALID_VALIDITY` / `INVALID_REQUEST` / `WINDOW_NOT_OPEN` / `WINDOW_CLOSED` | n/a |
| funding | `NOTHING_SPENDABLE` / `INSUFFICIENT_FUNDS` / `TOO_MANY_INPUTS {16}` | n/a |

## 7. Verification through public consensus code

`trading_v1::verify_approval` (each approval present), `Operation::verify_offer` and
`SignedOffer::verify` (offer and fill), `trading_v1::prepare_batch(state, anchor, root, [raw],
&CandidatePolicy::native_denomination_locked())` (every complete operation, after signing, on
import, on commit), `trading_v1::locked` (locks), `trading_v1::reconcile` and the `Applied` record
(receipts), `trading_v1::verify_lock_proof` (`discovery::locks::lock_from_proof`).

## 8. Outbox and reconciliation

* Identifiers: a complete operation is its consensus operation id (the key of its `Applied`
  receipt); a partial one is `domain_hash("MUTINY-BUILD8-WALLET-CONDITIONAL-PARTIAL-ID-V1", bytes)`.
  An outbox never accepts other bytes under an existing id, so the completed operation needs its
  own id: use the outbox's atomic `replace_partial` operation to replace the exact partial with
  the complete operation while preserving its reservations.
* Reserved: the coin inputs plus `resource_key("trade-offer", offer id)` (hash lock) or
  `resource_key("hash-lock", lock id)` (claim and refund share it).
* Reconcile: `Confirmed(h)` requires this host's own replay-derived inclusion index for the
  operation id (including another valid completion of the same authenticated body). An `Applied`
  record alone does not confirm an operation;
  `Expired` after the window; `InputsSpent` when a coin input is gone, the offer was consumed by
  another operation (hash lock) or the lock is gone (claim, refund); otherwise `Pending`.

## 9. Finality of the native reservation

The hash lock is the native reservation that must precede any external value movement. The wallet
reports it as final only when its own replay-derived inclusion index confirms the operation
(`Confirmed` in the outbox; `discovery::locks::finality` additionally requires the `Applied`
receipt height to match that index). "Queued" is local storage only. Authenticated native
submission and peer acknowledgement are not confirmation; inclusion in a proposed, uncertified
block is not finality. Every conditional review says so (`Finality`
condition, `NOT_FINAL_UNTIL_CERTIFIED` warning).

## 10. Preimages (Q13)

`PreimageStore` (trait) with `MemoryPreimageStore`: `create()` makes a fresh OS-random
`Preimage` and returns its condition; `insert`, `preimage(condition)`, `erase`, `conditions`.
Keyed by the public condition; never derived from a key; `Debug` prints only a count; every value
is zeroized on drop. No Bitcoin type exists anywhere in this phase.

## 11. Discovery (`discovery::locks`)

`hash_locks(view, me)` walks `state.protocol_records` (`is_candidate_record`,
`NativeRecord::decode`, stored under `record_key(0, id)`), keeps hash locks of this chain whose
sender or recipient this key controls, with `LockPhase::ClaimWindow { last_claim_height }` or
`RefundWindow { since }` and `may_claim` / `may_refund`. `hash_lock(view, id, me)` reads one lock
(`trading_v1::locked`). Fiat locks are not listed (phase 5B).

## 12. Defaults applied

Q1 (queued locally, exportable, no delivery claim), Q3 (refund is the only cancellation), Q7
(offers and fills imported and verified, never created), Q8 (TradeID/ContractHash opaque with a
warning), Q10 (typed last-8 check on the recipient), Q11 (heights plus approximate durations,
labelled), Q12 (public partials exchanged as `PartialApproval` files), Q13 (fresh OS-random
preimages in their own store).

## 13. Findings (analysis versus code) and open questions

* `debit` compares the coin's owner address with the payer address; it does not resolve wallet
  authority. A rotated wallet can fund a lock only from coins of one address, and a claimant or
  refunder must hold fee coins at exactly the lock's recipient or sender address.
* The "fixed widths" of placeholder approvals hold per generation width class only: the descriptor
  encodes its generation as a variable-width integer. The wallet reads the generation of the slot
  address's current authority from the wallet book; consensus exposes no address-to-authority
  lookup, so the wallet uses the public `WalletBook::records()` and `wallet_authority_v1::address_key`
  for addresses of a later generation.
* There is no consensus encoding of a bare `SignedOffer`; the wallet imports offers as an
  `OfferProof` with an all-zero fill.
* `OfferBody::maker_side` is not checked by consensus; the review shows it.
* `apply_one` still writes the 240 floor as a literal; `native_units_v1::MINIMUM_TRADE_FEE_STRIKES`
  is the same value (a test pins it).
* `trading_v1::reconcile` refuses a receipt whose wire hash differs (another completion of the same
  body): the wallet also reads the `Applied` record by operation id.
* Open: how the host shows a proposer's candidate inclusion (proposal: not at all; finality only);
  what the host persists besides the outbox and the preimage store (proposal: the imported offer
  bytes, the counterparty's partial and the maker's fill until completion, and the outbox file
  protected like the preimage store because a queued claim carries the preimage in clear until
  inclusion).
