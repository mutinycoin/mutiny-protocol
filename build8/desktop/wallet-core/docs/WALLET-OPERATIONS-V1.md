# Wallet operations V1: the fourteen operation kinds of the wallet core

Phase id `PHASE-8-MATRIX`. The consolidated, Architect-facing description of what
`mutiny-wallet-core-v8` does for each operation kind, who must sign what, what a person is shown and
must acknowledge, what is refused, and what consensus code verifies the result.

**Evidence status.** Implemented is not Qualified. Every statement here is backed by code and by
tests that ran offline on Windows with public TEST-VALUE keys: NATIVE PASS (offline, TEST-VALUE) at
most. Nothing is physical, production or Linux evidence. The production signing gate is closed
(4.2); TEST-VALUE signing exists only in test builds (4.3).

**How to read the citations.** `path:line` is relative to `wallet-core/` (`consensus/...` is the
sibling consensus crate). Every citation was checked against the source of the phase-8 branch
(`wallet/p8-matrix`) when this document was written; the claims come from the code, not from the
phase documents, and where a phase document says otherwise (for example `docs/PHASE-6-TREASURY.md`
still lists the `INVALID_REQUEST` reasons that phase 8 replaced with dedicated codes) this document
is the current one.

**Candidate 3.** The Order's wallet decisions of lane W1 (W2, W3, W4, W5, W6, W9 and W19 to W23;
branch `cand3/wallet-core`) changed the code after those citations were checked. Every statement
they touch was rewritten against the candidate-3 source and names the item, and the test that
proves it, instead of a line; a `path:line` citation elsewhere is the phase-8 line and may have
moved by the lines candidate 3 inserted above it (the named function or item is authoritative).
Section 6 gives the status of every Order decision, W1 to W23 and Q1 to Q17. Evidence class
unchanged: NATIVE PASS (offline, TEST-VALUE) on Windows at most.

## 1. The pipeline (every kind)

`plan(request, view, signer)` builds an immutable `OperationPlan` of UNSIGNED objects
(src/plan.rs); `review(plan, view)` derives a `Review` from those bytes and the verified view only,
with the acknowledgements derived from its own rows (src/review.rs:1205) and a binding digest over
the kind, the schema, every unsigned object, the anchor and the state root (src/review.rs:573);
`ReviewGate` collects the typed destination checks, the acknowledgements and, for a high-risk
review, the confirmation phrase, and issues one single-use `Approval` (4.1);
`Signer::authorize(plan, approval, view)` is the ONLY way to a signature (no "sign these bytes"
API, no caller-chosen domain: `domain_for` in src/authorize.rs lists the 17 permitted (kind,
purpose) pairs, and a handler signs only through the typed capabilities of its kind,
src/capability.rs, 4.12) and re-verifies the result through consensus code; `Outbox::commit` queues
the exact bytes with their reservations, `Outbox::commit_approved` also keeps the binding of the
approval they were authorized with, and `Outbox::export_verified` re-verifies a queued record
against the current verified view before its bytes go to a transport (4.4); a real certified block
includes them; the outbox reconciles from verified state. The fourteen kinds are
`OperationKind::ALL` (src/plan.rs:71); every one has a handler (`ops::implemented_kinds`,
src/ops/mod.rs:74).

The review's sections are always the same (`Section`, src/review.rs:142): Summary, Chain, Signing
wallet, Required authorizations, Parties, Money, Conditions, Timing, Effects (irreversible ones
marked), Warnings, You must acknowledge, Binding. Acknowledgements are derived, never chosen by a
handler alone: Destination when a destination needs the typed check (every label except this
wallet's own address), Amount, Fee, Irreversible when an effect is irreversible, plus the
acknowledgement every warning requires and the handler's extra acknowledgements. Every structured
address row (signing address, wallet authority, required wallet authorizations, parties,
destinations, fee payer) shows the checksummed address text of the view's verified class first and
the legacy hex after it (Order W2, 4.11); a maker is named by its trade identity, which is not an
address, and stays hexadecimal.

## 2. Authorization matrix (operation, slot, required wallet authority)

"Current key" means the descriptor `WalletBook::authorize(address, descriptor)` accepts for that
address, exactly as consensus resolves it. The maker of an offer is a `Role::Transport` key this
wallet never holds: it imports and verifies the maker's offer signature and fill signature, it
never creates them (Q7).

| Kind | Slot | Who signs | Required authority |
|---|---|---|---|
| Payment | `Input(i)` | each coin's owner | current key of the coin owner's authority |
| WalletRotation | `RotationAuthorization` | the rotating authority | its committed current key (generation g) |
| WalletRotation | `RotationPossession` | the new key | the proposed descriptor at g + 1, address not yet registered |
| WalletRotation | `Input(i)` | each funder | the rotating authority's coins: the NEW key; another funder: its current key |
| DividendClaim | `Claim` | the License owner | current key of the owner's authority |
| LicenseDvp | `Approval(0)` / `Approval(1)` | seller / buyer | current key of each address; the Genesis Treasury wallet (a Treasury-owned License) only under the Treasury profile with the `Authority` role (W21) |
| LicenseDvp | offer, fill | the maker | imported and verified; never this wallet |
| HashLock | `Approval(0)` / `Approval(1)` | sender / recipient | current key of each address |
| HashLock | offer, fill | the maker | imported and verified; never this wallet |
| ConditionalClaim | `Approval(0)` | the lock's recipient | current key; fee coins at exactly that address |
| ConditionalRefund | `Approval(0)` | the lock's sender | current key; fee coins at exactly that address |
| FiatLock | `Approval(0)` / `Approval(1)` | seller (funds the lock) / buyer | current key of each address |
| FiatLock | offer, fill | the maker | imported and verified; never this wallet |
| FiatRelease | `Approval(0)` / `Approval(1)` | buyer (pays the fee) / seller | current key of each address; no maker |
| BondCreate | `Input(i)` | the funding coins' owner | current key |
| BondCreate | `BondOwner` | the node's admitted owner | current key of the admitted owner's authority |
| BondUnbond, BondWithdraw | `BondOwner` | the lot's owner | current key of the lot owner's authority |
| TreasuryRotate | `Approval(0)` | the trading Treasury's active destination | its current key, under the Treasury profile |
| TreasuryFreezeOffer | `TreasuryFreeze` | the destination wallet named in the freeze | its current key, under the Treasury profile |

Each wallet signs only its own slots; parts signed separately are merged without a key
(`offers::combine`, `conditional::complete`, `rotation::combine`) and verified through consensus
code. An approval binds the kind, so it never authorizes a plan of another kind, and the bytes of
one kind labelled as another are refused (`tests/cross_kind.rs`).

## 3. The kinds

### 3.1 Payment

* **Purpose.** An ordinary MUT payment: coins selected, the minimal fee fixed, change returned to
  the signer's current-generation address, signed and re-verified through consensus
  (src/ops/payment.rs:1).
* **Request.** `PaymentRequest { recipient, amount_atoms, validity_blocks }` (src/plan.rs:513-525);
  `validity_blocks` defaults to `DEFAULT_VALIDITY_BLOCKS` = 144 (src/plan.rs:439). A zero amount
  and the all-zero recipient are refused (src/ops/payment.rs:144-149).
* **Who signs.** Slot `Input(i)` for every input: the coin owner's current key
  (src/ops/payment.rs:829-833); every input descriptor must be the signer's (src/ops/payment.rs:912-916)
  and `WalletBook::authorize(owner, descriptor)` must hold (src/ops/payment.rs:366-369). Signed
  through the `TransferSpend` capability, which calls consensus' `Transfer::sign_input`
  (Domain::Transaction; 4.12).
* **Fee.** One atom per encoded byte, a fixed point of the signed size (`fit_outputs`,
  src/ops/payment.rs:274-313; `FeeRule::OneAtomPerEncodedByte`, src/ops/payment.rs:577); paid by
  this wallet when it owns an input (src/ops/payment.rs:564-574); it goes to the block producer.
* **Conditions and timing.** Valid in the next block and the `validity_blocks` = N blocks after it:
  N + 1 blocks, expiry = next + N, N in 1..=10,080 (src/ops/payment.rs:150-160; the same for every
  kind, `DEFAULT_VALIDITY_BLOCKS`, src/plan.rs:439); the window is checked at the next height
  (src/ops/payment.rs:340-351); immature coinbase coins are refused.
* **Irreversible effects.** Spends the coins; pays the recipient with no recall; pays the fee;
  once signed it stays valid until included or expired (src/ops/payment.rs:629-674).
* **Review.** Titles "Send MUT", "Move MUT within this wallet", "Payment between other wallets"
  (src/ops/payment.rs:754-777); destinations `Payment` and `Change` (src/ops/payment.rs:515-519);
  warnings `SELF_PAYMENT`, `DUST_CHANGE`, `TREASURY_DESTINATION`, `FEE_ABOVE_MINIMUM`,
  `EXPIRES_SOON`, `TEST_VALUE_CHAIN`, `BAD_SIGNATURE` (no acknowledgement) and `TREASURY_FUNDS`
  (TreasuryAuthority, src/ops/payment.rs:743); not high risk (src/ops/payment.rs:806).
* **Refusals.** `INVALID_AMOUNT`, `INVALID_RECIPIENT`, `INVALID_VALIDITY`, `NOTHING_SPENDABLE`,
  `INSUFFICIENT_FUNDS`, `TOO_MANY_INPUTS`, `SIZE_LIMIT`, `INPUT_UNAVAILABLE`, `RESERVED_INPUT`,
  `IMMATURE_INPUT`, `STALE_AUTHORITY`, `CONSERVATION`, `FEE_BELOW_MINIMUM`, `WINDOW_NOT_OPEN`,
  `WINDOW_CLOSED`, `WRONG_CONTEXT`, `NOT_REQUIRED_SIGNER`, `RESERVE_BACKING_VIOLATION`,
  `TREASURY_PROFILE_REQUIRED`, `TREASURY_ROLE_NOT_DECLARED` (the Genesis Treasury without the
  declared Authority role), `VERIFICATION_FAILED`.
* **Consensus verification.** `Transfer::verify(genesis, fingerprint, next, coins, wallets)` after a
  check that both signature halves are present (src/ops/payment.rs:1042-1043).
* **Tests.** tests/e2e_payment.rs, tests/unit_payment.rs, tests/review_completeness_payment.rs
  (golden snapshot), tests/payment_properties.rs, tests/refusals_core.rs, tests/e2e_matrix.rs.

### 3.2 WalletRotation

* **Purpose.** Move a wallet authority (named by its generation-one AddressID) from its current key
  at generation g to a new key at g + 1, as ONE funded `Transaction::Rotate { rotation, transfer }`
  whose transfer pays the fee (src/ops/rotation.rs:1-9).
* **Request.** `RotationRequest { proposed_descriptor, fee_source, new_key_restore_verified,
  validity_blocks, restore_verified_fingerprint }` (src/plan.rs:551-565); `fee_source` is
  `RotatingAuthority` (the NEW key spends the authority's coins) or `OtherWallet(identity)`
  (src/plan.rs:544-549). The restore check is required: without `with_restore_verified` and a
  fingerprint equal to the proposed descriptor's, planning refuses `RESTORE_NOT_VERIFIED`
  (src/ops/rotation.rs:948-957); the evidence is bound into the plan as its second object.
* **Who signs.** `RotationAuthorization`: the authority's committed CURRENT key
  (src/ops/rotation.rs:1202-1210); `RotationPossession`: the PROPOSED key, generation exactly g + 1,
  no component reused, its address not yet registered (src/ops/rotation.rs:1211-1219, 323-331,
  477-479); `Input(i)`: coins of the rotating authority are spent by the NEW key, another wallet's
  coins by that wallet's current key (src/ops/rotation.rs:1237-1245). Domains WalletRotate,
  WalletRotatePossession and Transaction (src/authorize.rs). The two-key `RotationSigner`
  (src/rotation_signer.rs since candidate 3, still exported as `ops::rotation::RotationSigner`)
  signs rotations only, through the `RotationProofs` and `TransferSpend` capabilities (4.12), holds
  both keys sealed and erases them on lock or idle.
* **Fee.** One atom per byte of the whole envelope, with its four rotation signature halves
  (src/ops/rotation.rs:26-27; fixed point `fit`, src/ops/rotation.rs:992-1015); paid by the funder.
* **Funding as net flows (wallet review fixes, BLOCKER-1).** The inputs of a co-funded rotation are
  pooled, so every reader computes, per party (the rotating authority, each other funder by its
  input descriptor), what its coins put in and what the outputs give back: each output first
  returns its holder's own contribution, whatever a party gets beyond that is a PAYMENT out of the
  pooled coins (`flows`, src/ops/rotation.rs:689). This wallet's net debit above the declared fee
  is refused (`ROTATION_FUNDING`, `REASON_NET_DEBIT_ABOVE_FEE`), and so is an output to the zero
  address or to an address that is neither a funder nor the rotating authority
  (`REASON_OUTPUT_ZERO`, `REASON_OUTPUT_NOT_FUNDER`, src/ops/rotation.rs:126-128), for every reader
  and for the plans this wallet builds. Payments to others are Payment destinations with the typed
  check, the Amount acknowledgement and the Danger warning `FUNDING_PAYS_ANOTHER_PARTY`; the summary
  and `FUNDING_NOT_BOUND` state this wallet's NET debit or gain.
* **Conditions and timing.** Window from the next height for `validity_blocks` = N (N + 1 blocks,
  N in 1..=10,080), the intersection of both parts; a co-funding payer's queued record instead
  lives as long as its funding transfer can still be included alone, its own window
  (`validity_of`, src/ops/rotation.rs:852-885; wallet review fixes, MINOR-4); ONE pending rotation per authority
  (reservation `rotation_resource`, src/ops/rotation.rs:159-161; `ROTATION_PENDING`,
  src/ops/rotation.rs:490).
* **Irreversible effects.** The old key loses all authority at inclusion and the funds are
  controlled only by the new key and its backup; generation g + 1 becomes current; the funding
  coins are spent; the fee is paid; once signed it cannot be revoked (src/ops/rotation.rs:1626-1707).
* **Review.** Titles "Rotate wallet key", "Rotate the Treasury wallet key", "Pay the fee of a wallet
  key rotation", "Receive MUT from the funding of a wallet key rotation" (a funder that gains, wallet
  review fixes), "Key rotation of another wallet" (src/ops/rotation.rs:1866-1890); the new key's
  address is listed as `AddressLabel::NewKey` with the typed check (src/ops/rotation.rs:1431-1436);
  warnings `KEY_ROTATION` (Danger, KeyLoss, src/ops/rotation.rs:1720), `RESTORE_NOT_SHOWN`
  (KeyLoss), `FUNDING_NOT_BOUND` (src/ops/rotation.rs:1744), `FUNDING_PAYS_ANOTHER_PARTY` (Danger,
  Amount, src/ops/rotation.rs:1788), `TREASURY_ROTATION` and
  `TREASURY_FUNDS` (TreasuryAuthority), `COUNTERPARTY_FUNDED`, `EXPIRES_SOON`; high risk for the
  rotating wallet (src/ops/rotation.rs:1921).
* **Refusals.** `ROTATION_GENERATION`, `ROTATION_KEY_REUSED`, `RESTORE_NOT_VERIFIED`,
  `ROTATION_PENDING`, `ROTATION_ADDRESS_TAKEN`, `ROTATION_FUNDING`, `STALE_AUTHORITY`,
  `COUNTERPARTY_APPROVAL_INVALID`,
  `INVALID_REQUEST` (payer is the rotating authority, a session of another kind), `LOCKED`, and the
  payment refusals of the funding (inputs, fee, window, reserve, Treasury profile and role).
* **Consensus verification.** `Transaction::verify` of the complete envelope
  (src/ops/rotation.rs:2238-2240); `Rotation::verify` of the rotation part
  (src/ops/rotation.rs:768-769).
* **Tests.** tests/e2e_rotation.rs, tests/refusals_rotation.rs, tests/review_completeness_rotation.rs
  (golden), tests/rotation_outbox_and_properties.rs, tests/outbox_replace.rs (a co-funded rotation
  replaced in place), tests/e2e_matrix.rs.

### 3.3 DividendClaim

* **Purpose.** Claim part or all of one License's dividend entitlement for one award: a fee-exempt
  `SignedClaim` (consensus operation kind 23) signed by the License owner's current key; the
  protocol pays from the Treasury reserve (src/ops/dividend.rs:1-11).
* **Request.** `DividendClaimRequest { license, award_epoch, amount_atoms, destination,
  validity_blocks }` (src/plan.rs:591-602); the claim sequence is derived from confirmed state, never
  supplied (src/ops/dividend.rs:435-440).
* **Who signs.** One slot, `Claim`: the current key of the License owner's authority, checked with
  `WalletBook::authorize(owner, descriptor)` (src/ops/dividend.rs:321-324; refusals
  `NOT_REQUIRED_SIGNER(Claim)` or `STALE_AUTHORITY`, src/ops/dividend.rs:161-172). A rotated wallet
  still controls Licenses recorded under its older addresses. Signed through the
  `ClaimAuthorization` capability (consensus `SignedClaim::sign`). An ordinary claim needs its
  owner's signature and nothing else, no Treasury co-signature and no Treasury acknowledgement
  (Order W20; `tests/refusals_dividend.rs`,
  `an_ordinary_claim_needs_only_its_owner_and_no_treasury_signature`, where consensus admits the
  owner-signed claim). The Genesis Treasury claims for an eligible License it owns under its checked
  profile with the `Authority` role and the normal claimant rules: an ordinary identity is
  `TREASURY_PROFILE_REQUIRED`, the profiled claim carries `TREASURY_CLAIMANT` and the
  TreasuryAuthority acknowledgement, and consensus admits it
  (`the_treasury_wallet_claims_only_through_the_treasury_profile`).
* **Fee.** None: `FeeRule::Exempt`, payer the protocol (src/ops/dividend.rs:586-592); the net debit
  of the claimant is zero.
* **Conditions and timing.** Height window from the next height (1..=10,080 blocks; the signed
  height window is a separate rule, its stage-2 form is Lane P's P4); every epoch rule is judged at
  the head's epoch, a lower bound of the including block's: an award after the head's epoch, or a
  later award that does not exist yet, is `AWARD_NOT_YET_OPEN`
  (`an_award_not_yet_reached_is_refused_like_consensus`), a window that has closed is
  `AWARD_EXPIRED` (`an_expired_award_is_refused_like_consensus`), an epoch that is no award of this
  License is `NOT_ENTITLED` (`absent_award` in src/ops/dividend.rs); the window is consensus'
  `E <= block epoch < E + CLAIM_WINDOW_EPOCHS` (65,536); ONE outstanding claim per (award, License)
  (reservation `claim_slot`, src/discovery/dividends.rs:33-41).
* **Why "at most" (Order W20, verified).** The epoch of a block is `mining_epoch(timestamp, t0) =
  (timestamp - t0) / 60` (consensus/src/pow.rs, applied to the block in
  consensus/src/execution_v2.rs), and consensus' timestamp rule `pow::validate_timestamp` requires
  every timestamp to be above the median of its ancestors AND not below its parent's, with no
  wall-clock bound in either direction. Along the chain that extends the verified head, timestamps
  therefore never decrease, the floor division keeps that order, and the including block's epoch is
  at least the head's, with no upper bound. So the epochs left at inclusion are AT MOST those left
  at the head, and the "Time left" row says exactly that: "At most N epochs after the verified
  block's epoch (H) remain before the window closes at epoch C (approximate duration)", with the
  verified epoch H and the actual deadline C shown as numbers. The earlier median-only rule, under
  which a timestamp could fall below its parent's and epochs could regress, would not have justified
  the wording; `tests/refusals_dividend.rs`,
  `the_at_most_wording_rests_on_consensus_refusing_a_regressing_timestamp`, fails if consensus
  drops the parent rule. The near-deadline warning `CLAIM_WINDOW_CLOSING` starts at
  `review::CLAIM_DEADLINE_WARNING_EPOCHS` = 1,440 epochs left (about one day; kept as
  `ops::dividend::NEAR_DEADLINE_EPOCHS` for hosts) or when the window may close within the claim's
  own validity window: a display threshold ONLY, not a claim time-to-live, not a validity rule and
  not a consensus constant (the same test pins that it is not `CLAIM_WINDOW_EPOCHS`).
* **Irreversible effects.** The protocol pays the destination from the reserve with no recall; the
  remaining entitlement falls and the claim sequence advances; once signed it stays valid until
  included, superseded, the License changes owner, the window closes or it expires
  (src/ops/dividend.rs:735-769).
* **Review.** Titles "Claim a dividend", "Dividend claim by another wallet"
  (src/ops/dividend.rs:854-867); destination `ProtocolPayout`; the "Owner at inclusion" condition
  states the stale-owner risk of a sale in the same block (src/ops/dividend.rs:695-700); warnings
  `CLAIM_WINDOW_CLOSING` (Conditions), `TREASURY_CLAIMANT` (TreasuryAuthority), `FULL_CLAIM`,
  `DESTINATION_NOT_OWNER`, `TREASURY_DESTINATION`, `NOT_THIS_WALLET`; extra acknowledgement
  Conditions; not high risk (src/ops/dividend.rs:900-901).
* **Refusals.** `AWARD_NOT_YET_OPEN`, `AWARD_EXPIRED`, `NOT_ENTITLED`, `INVALID_AMOUNT`,
  `LICENSE_SUSPENDED_OR_REVOKED`, `REPLAY`, `WRONG_SEQUENCE`, `OVERDRAWN`, `DIVIDEND_INACTIVE`,
  `INVALID_RECIPIENT` (the all-zero destination: wallet policy, stricter than consensus, which would
  admit it and destroy the dividend; refused at planning, adoption, explanation and import,
  `a_claim_to_the_zero_address_is_refused_by_wallet_policy`), `RESERVED_INPUT`,
  `NOT_REQUIRED_SIGNER`, `STALE_AUTHORITY`, `RESERVE_BACKING_VIOLATION`,
  `TREASURY_PROFILE_REQUIRED`, `TREASURY_ROLE_NOT_DECLARED`, the window refusals.
* **Consensus verification.** `Ledger::check_claim` at the head's epoch, `dividend_claim_v1::admit`
  of the unsigned claim stopping exactly at the signature (src/ops/dividend.rs:331-343),
  `plan_spend`; for signed bytes `SignedClaim::verify_signature` and `admit` at the next height
  (src/ops/dividend.rs:1055-1069).
* **Tests.** tests/e2e_dividend.rs (awards reached by stepping blocks; a License sold by DvP makes
  the seller's claim stale for both), tests/refusals_dividend.rs, tests/review_completeness_dividend.rs,
  tests/e2e_matrix.rs.

### 3.4 LicenseDvp

* **Purpose.** Move a License from seller to buyer against a price credited to the payment
  destination the seller signs, atomically, filling the maker's License offer
  (src/ops/license_dvp.rs:1-18). "License purchase" means this sale of an existing License (Q14).
* **Request.** `LicenseDvpRequest { offer, license, payment_destination, validity_blocks, trade,
  contract, seller_descriptor }` (src/plan.rs); TradeID and ContractHash must be non-zero
  (src/ops/license_dvp.rs). `validity_blocks` is an `Option<u64>` that must stay `None` (Order W22):
  a sale is valid in exactly one block, and a request that sets a window is refused with
  `VALIDITY_WINDOW_UNSUPPORTED`, naming P4, until Lane P's signed validity windows exist (stage 2);
  it is never silently ignored (`tests/refusals_dvp.rs`,
  `a_license_sale_request_with_a_validity_window_is_refused_until_p4`).
* **Who signs.** `Approval(0)` the seller, `Approval(1)` the buyer (consensus/src/trading_v1.rs:691):
  the buyer plans and signs slot 1 (and slot 0 too when the seller is an address of the same,
  rotated, wallet: `planner_slots`, src/ops/license_dvp.rs:1237; the review's "this wallet signs"
  names exactly these slots, `my_slots`, src/ops/license_dvp.rs:1220), the seller explains the
  buyer's part, adopts it and co-signs slot 0 only; each slot needs the current key of its address
  (`check_slot_authority`,
  src/offers.rs:877-887). The maker's offer signature is imported and verified and its fill
  signature is attached (`offers::attach_fill_proof`); this wallet never signs as the maker. Each
  approval is signed through the `TradeApproval` capability (4.12). A License the Genesis Treasury
  wallet owns is sold only under the Treasury profile with the declared `Authority` role (Order W21;
  `select::require_profile_for_treasury` in the sale's planning and validation, so also through
  `adopt` and at authorization): an ordinary identity is `TREASURY_PROFILE_REQUIRED`, a Treasury
  identity declared without that role `TREASURY_ROLE_NOT_DECLARED` (`tests/refusals_dvp.rs`,
  `selling_a_treasury_owned_license_needs_the_treasury_profile`, which also completes the profiled
  sale and has consensus accept it).
* **Fee.** max(240, encoded length of the placeholder form, which is the complete length)
  (src/offers.rs:719-732), paid by the buyer (consensus `fee_payer`, consensus/src/trading_v1.rs:715).
* **Conditions and timing.** Valid in exactly one block: created = expiry = the next height and the
  effective height equals it (src/ops/license_dvp.rs:269-285, `valid_only_at`); one block earlier
  `NOT_YET_ELIGIBLE`, one later `WINDOW_CLOSED` (src/ops/license_dvp.rs:416-427), as consensus
  requires (consensus/src/trading_v1.rs:2637-2639). The offer's own window at the next block
  (`OFFER_NOT_YET_VALID`, `OFFER_EXPIRED`) and single fill (`OFFER_CONSUMED`), one rule for every
  planner (`offers::require_fillable`, W19); bytes whose operation window is not inside the offer's
  are `OFFER_WINDOW_EXCEEDED` (4.9).
* **Irreversible effects.** The License moves (generation and assignment sequence + 1), its Worker
  is cleared, the new owner's rights start at H + 1; the offer is consumed; the buyer's coins are
  spent and the price paid with no recall; the seller loses the License, its remaining dividend
  entitlements and its mining rights (src/ops/license_dvp.rs:860-945).
* **Review.** Titles "Buy License ...", "Sell License ...", "License sale between other wallets"
  (src/ops/license_dvp.rs:1088-1134); destination `LicensePayment`; warnings `SINGLE_BLOCK`
  (SingleBlockWindow), `OPAQUE_COMMITMENTS` (Conditions), `UNBOUND_DIVIDENDS` (UnboundDividends,
  src/ops/license_dvp.rs:1018), `PAYMENT_NOT_TO_SELLER`, `APPROVALS_MISSING`, `TREASURY_FUNDS`; a
  fresh Worker assignment after the sale is stated, not built (src/ops/license_dvp.rs:886, Q17);
  high risk (src/ops/license_dvp.rs:1154-1155).
* **Refusals.** `OFFER_PROOF_INVALID` (also a fill signature that is present and does not verify:
  refused since W19, before a `BAD_SIGNATURE` warning), `MALFORMED` (an offer in neither form),
  `WRONG_CONTEXT`, `OFFER_NOT_YET_VALID`, `OFFER_EXPIRED`, `OFFER_WINDOW_EXCEEDED`,
  `OFFER_CONSUMED`, `INVALID_REQUEST` (an offer whose terms are for another kind of operation),
  `VALIDITY_WINDOW_UNSUPPORTED`, `TREASURY_PROFILE_REQUIRED`, `TREASURY_ROLE_NOT_DECLARED`,
  `LICENSE_GENERATION_STALE`, `LICENSE_NOT_OWNED`,
  `NOT_YET_ELIGIBLE`, `WINDOW_CLOSED`, `INVALID_RECIPIENT`, `PENDING_ASSIGNMENT_OR_LOCK`, `REPLAY`,
  `STALE_AUTHORITY`, `NOT_REQUIRED_SIGNER`, `COUNTERPARTY_APPROVAL_INVALID`, `RESERVED_INPUT`,
  `CANCEL_NOT_AVAILABLE` (a sale has no cancellation), the coin and fee refusals.
* **Consensus verification.** `trading_v1::verify_approval` for each approval,
  `Operation::verify_offer`, `SignedOffer::verify`, and `trading_v1::prepare_batch` of the complete
  operation (src/offers.rs:1265-1271).
* **Tests.** tests/e2e_license_dvp.rs, tests/offers_dvp.rs, tests/refusals_dvp.rs,
  tests/review_completeness_dvp.rs, tests/e2e_dividend.rs (a sold License's stale claim),
  tests/offer_checks.rs (the W19 matrix), tests/e2e_matrix.rs.

### 3.5 HashLock

* **Purpose.** Lock MUT from one sender address for a recipient under a SHA-256 condition with a
  refund height, filling a maker's single-fill hash-linked offer (src/ops/conditional.rs:8-13).
* **Request.** `HashLockRequest { offer, recipient, amount_atoms, condition, refund_height, trade,
  contract, validity_blocks, generation, sender }` (src/plan.rs:675-699); the amount must equal the
  offer's (src/ops/conditional.rs:754-756).
* **Who signs.** `Approval(0)` the sender, `Approval(1)` the recipient
  (consensus/src/trading_v1.rs:681-683), each the current key of its address; the sender's part is a
  PARTIAL operation the recipient adopts from the public container; the maker's fill is imported
  and `conditional::complete` merges the parts without a key, refusing any approval or fill
  signature that does not verify even next to a valid one, as `offers::combine` does
  (src/ops/conditional.rs:2520).
* **Fee.** max(240, encoded length of the COMPLETE wire with placeholders of the exact widths),
  paid by the sender (src/ops/conditional.rs:25-29; consensus/src/trading_v1.rs:707).
* **Conditions and timing.** The refund height R must be above the next height; consensus accepts a
  claim only in a block above the lock's and below R, and the lock may be included as late as its
  expiry E, so the recipient can rely on the WORST-CASE claim window R - E - 1 blocks only
  (`worst_case_claim_window`, src/ops/conditional.rs:514-520). The window ends within the offer's
  and two blocks before R: expiry = min(next + validity, R - 2, offer expiry), and R = next + 1 is
  refused (`INVALID_REQUEST`, `REASON_NO_CLAIM_WINDOW`; src/ops/conditional.rs:779-794); bytes from
  anyone whose worst-case window is zero are refused for every reader (src/ops/conditional.rs:1328-1333).
  The review states the worst case in the "Claim window" row and the summary, and warns
  (`SHORT_CLAIM_WINDOW`, Caution, Conditions acknowledgement) when it is below 10 blocks or below the
  number of blocks the lock may be included in, E - created + 1 (a policy rule,
  src/ops/conditional.rs:522-529, 1978-1991); the offer's own window and single fill as for the sale.
* **Irreversible effects.** Spends the sender's coins; locks the amount for the recipient until the
  refund height with no recall; consumes the offer; pays the fee
  (src/ops/conditional.rs:1914-1936).
* **Review.** Titles "Lock MUT to a hash condition", "Approve a hash lock for this wallet", "Hash
  lock between other wallets" (src/ops/conditional.rs:2000-2026); destination `LockedOutput`;
  warnings `EXTERNAL_LEG_NOT_VERIFIED` (ExternalEvidence), `NOT_FINAL_UNTIL_CERTIFIED`,
  `SHORT_CLAIM_WINDOW`, `SELF_LOCK`, `OPAQUE_TRADE_COMMITMENTS` (a Caution requiring the Conditions
  acknowledgement since Order W23, like the sale's and the fiat lock's `OPAQUE_COMMITMENTS`; before,
  a Notice without one; `tests/opaque_commitments.rs`); high risk (src/ops/conditional.rs:2050-2051).
* **Refusals.** The offer refusals of the one offer check (4.9, W19), the same codes as the sale
  and the fiat lock: `OFFER_PROOF_INVALID`, `MALFORMED` (an offer in neither form; before W19
  `OFFER_PROOF_INVALID` here), `WRONG_CONTEXT` (also for an embedded offer of another chain, before
  W19 `OFFER_PROOF_INVALID`), `OFFER_NOT_YET_VALID`, `OFFER_EXPIRED`, `OFFER_WINDOW_EXCEEDED` (before
  W19 `OFFER_PROOF_INVALID`), `OFFER_CONSUMED`, `INVALID_REQUEST` (amount, refund height,
  generation; an offer whose terms are for another kind of operation, before W19
  `OFFER_PROOF_INVALID`); and `INVALID_AMOUNT`, `INVALID_RECIPIENT`, `RESERVED_INPUT`,
  `NOT_REQUIRED_SIGNER`, `COUNTERPARTY_APPROVAL_INVALID`, `PARTIAL_INVALID`, the coin, fee and
  window refusals.
* **Consensus verification.** `SignedOffer::verify`, `Operation::verify_offer` once a fill is present,
  `verify_approval`, and `trading_v1::prepare_batch` of the complete operation
  (src/ops/conditional.rs:2846-2856).
* **Tests.** tests/e2e_conditional.rs, tests/refusals_conditional.rs,
  tests/review_completeness_conditional.rs, tests/unit_conditional.rs, tests/outbox_replace.rs (the
  partial replaced by its completion under the operation identifier), tests/cross_kind.rs (offer
  import), tests/offer_checks.rs (the W19 matrix), tests/opaque_commitments.rs (W23),
  tests/e2e_matrix.rs.

### 3.6 ConditionalClaim

* **Purpose.** The lock's recipient takes the whole locked amount by publishing the preimage before
  the refund height (src/ops/conditional.rs:14-18).
* **Request.** `ClaimRequest { lock, preimage, validity_blocks }` (src/plan.rs:744-752), usually built
  by `conditional::claim_request` from the `PreimageStore` (src/ops/conditional.rs:247-263).
* **Who signs.** One slot, `Approval(0)`: the lock's recipient (the claimant), its current key; no
  maker and no offer proof.
* **Fee.** As for the hash lock, paid by the recipient from SEPARATE coins of exactly the recipient
  address (consensus `debit`, 4.8).
* **Conditions and timing.** The lock must exist (`LOCK_NOT_FOUND`) and have been created before the
  next block; a claim only while the next height is below the refund height, else `WINDOW_CLOSED`
  (src/ops/conditional.rs:901-906; consensus/src/trading_v1.rs:2503-2505).
* **Irreversible effects.** Publishes the preimage in the block; credits the locked amount and ends
  the lock (src/ops/conditional.rs:2159-2171).
* **Review.** Titles "Claim a hash lock", "Claim of a hash lock by another wallet"
  (src/ops/conditional.rs:2218-2234); condition "Preimage origin: preimage supplied externally";
  warnings `DISCLOSES_PREIMAGE` (Danger, DisclosesPreimage), `PREIMAGE_SUPPLIED_EXTERNALLY`
  (ExternalEvidence), `CLAIM_DEADLINE_NEAR`, `OPAQUE_TRADE_COMMITMENTS` (Caution, Conditions; W23);
  high risk.
* **Refusals.** `LOCK_NOT_FOUND` (src/ops/conditional.rs:844), `PREIMAGE_MISMATCH`, `WINDOW_CLOSED`,
  `NOT_REQUIRED_SIGNER`, `NOT_YET_ELIGIBLE`, `RESERVED_INPUT`, `INVALID_REQUEST` (a fiat lock is not
  claimable), `OFFER_PROOF_INVALID`, the coin and fee refusals.
* **Consensus verification.** `trading_v1::locked`, `preimage_hash`, `verify_approval`, `prepare_batch`.
* **Tests.** tests/e2e_conditional.rs (claim before the refund height; a consensus-built claim at it
  refused), tests/refusals_conditional.rs, tests/review_completeness_conditional.rs,
  tests/unit_conditional.rs, tests/e2e_matrix.rs.

### 3.7 ConditionalRefund

* **Purpose.** The lock's sender takes the locked amount back at or after the refund height: the
  only cancellation the protocol permits (Q3; src/ops/conditional.rs:19-20).
* **Request.** `RefundRequest { lock, validity_blocks }` (src/plan.rs:768-775), or
  `CancelRequest(HashLockRefund(lock))`, which plans exactly the same refund; every other cancel
  target is `CANCEL_NOT_AVAILABLE` (src/plan.rs:1143-1151).
* **Who signs.** One slot, `Approval(0)`: the lock's sender, its current key.
* **Fee.** Paid by the sender from separate coins of exactly the sender address.
* **Conditions and timing.** Only from the refund height: below it `NOT_YET_ELIGIBLE`
  (src/ops/conditional.rs:950-955; consensus/src/trading_v1.rs:2525-2527).
* **Irreversible effects.** Returns the locked amount and ends the lock: the recipient can no longer
  claim it (src/ops/conditional.rs:2334-2342).
* **Review.** Titles "Refund a hash lock", "Refund of a hash lock by another wallet"
  (src/ops/conditional.rs:2363-2379); the "Exclusivity" condition; warning
  `OPAQUE_TRADE_COMMITMENTS` (Caution, Conditions; W23); NOT high risk, the only one of the trading
  kinds (src/ops/conditional.rs:2399-2400).
* **Refusals.** `LOCK_NOT_FOUND`, `CANCEL_NOT_AVAILABLE` (a refund of a fiat lock), `NOT_YET_ELIGIBLE`,
  `NOT_REQUIRED_SIGNER`, `RESERVED_INPUT`, `INVALID_REQUEST` (another owner), the coin and fee
  refusals.
* **Consensus verification.** As for the claim.
* **Tests.** tests/e2e_conditional.rs, tests/refusals_conditional.rs
  (`every_cancellation_but_the_hash_lock_refund_is_refused_and_the_refund_is_routed`),
  tests/review_completeness_conditional.rs, tests/e2e_matrix.rs (refused one block early by both,
  included exactly at R).

### 3.8 FiatLock

* **Purpose.** The seller locks MUT for a buyer against an opaque fiat payment-terms commitment,
  filling the maker's fiat offer; the lock ends only by a release both wallets approve
  (src/ops/fiat.rs:3-17).
* **Request.** `FiatLockRequest { offer, buyer, amount_atoms, payment_terms, trade, contract,
  validity_blocks, buyer_descriptor }` (src/plan.rs:790-805); amount and terms must equal the offer's.
  An unregistered buyer's public descriptor must be supplied.
* **Who signs.** `Approval(0)` the seller (funds the lock), `Approval(1)` the buyer, each its current
  key (the seller's plan signs slot 1 too when the buyer is an address of the same wallet, as for
  the sale); the maker's offer and fill as for the sale.
* **Fee.** max(240, complete length), paid by the seller (consensus/src/trading_v1.rs:708).
* **Conditions and timing.** Window from the next height, at most to the offer's expiry
  (src/ops/fiat.rs:480-496); no timeout, refund or unilateral release exists.
* **Irreversible effects.** Locks the amount for the buyer with NO unilateral exit (the funds may
  stay locked forever); consumes the offer; spends the seller's coins (src/ops/fiat.rs:732-759).
* **Review.** Titles "Lock MUT for a fiat sale", "Approve a fiat-settled lock for this wallet",
  "Fiat lock between other wallets" (src/ops/fiat.rs:813-844); destination `LockedOutput`; warnings
  `NO_UNILATERAL_EXIT` (Danger, NoUnilateralExit, src/ops/fiat.rs:786-793), `FIAT_NOT_VERIFIED`
  (ExternalEvidence), `OPAQUE_COMMITMENTS`; high risk (src/ops/fiat.rs:882-883).
* **Refusals.** `OFFER_PROOF_INVALID` (also a fill signature that is present and does not verify,
  W19), `MALFORMED`, `WRONG_CONTEXT`, `OFFER_NOT_YET_VALID`, `OFFER_EXPIRED`,
  `OFFER_WINDOW_EXCEEDED`, `OFFER_CONSUMED`, `INVALID_REQUEST` (terms, missing buyer descriptor, an
  offer whose terms are for another kind of operation), `INVALID_RECIPIENT`,
  `REPLAY`, `STALE_AUTHORITY`, `RESERVED_INPUT`, `CANCEL_NOT_AVAILABLE(FiatLock)` (a cancel, a refund,
  or consensus' `FiatRecoveryUnspecified`), the coin and fee refusals.
* **Consensus verification.** As for the sale: `verify_approval`, `verify_offer`, `SignedOffer::verify`,
  `prepare_batch`.
* **Tests.** tests/e2e_fiat.rs, tests/refusals_dvp.rs, tests/review_completeness_dvp.rs,
  tests/refusals_conditional.rs (a fiat lock can be neither claimed nor refunded),
  tests/offer_checks.rs (the W19 matrix), tests/e2e_matrix.rs.

### 3.9 FiatRelease

* **Purpose.** Pay a fiat lock's amount to the buyer and remove the lock: both wallets must approve,
  and it is the only way a fiat lock ends (src/ops/fiat.rs:7-15).
* **Request.** `FiatReleaseRequest { lock, validity_blocks, seller_descriptor }` (src/plan.rs:839-848).
* **Who signs.** `Approval(0)` the buyer (plans, pays the fee), `Approval(1)` the seller, each its
  current key (the buyer's plan signs slot 1 too when the seller is an address of the same wallet);
  no maker, and an offer proof is refused.
* **Fee.** Paid by the buyer from its own coins; the locked amount is paid in full
  (consensus/src/trading_v1.rs:711).
* **Conditions and timing.** The lock must exist (`LOCK_NOT_FOUND`, src/ops/fiat.rs:1045) and have
  been created before the next block; window from the next height.
* **Irreversible effects.** Releases the lock for good; for the seller: it gives up the locked
  amount for good (src/ops/fiat.rs:1300-1351).
* **Review.** Titles "Release a fiat lock to this wallet", "Release a fiat lock to the buyer", "Fiat
  release between other wallets" (src/ops/fiat.rs:1386-1417); destination `ProtocolPayout` to the
  buyer; warnings `FIAT_NOT_VERIFIED` (Danger for the seller, ExternalEvidence),
  `NO_UNILATERAL_EXIT`; high risk.
* **Refusals.** `LOCK_NOT_FOUND`, `INVALID_REQUEST` (a hash lock, mismatches), `NOT_REQUIRED_SIGNER`,
  `NOT_YET_ELIGIBLE`, `REPLAY`, `STALE_AUTHORITY`, `RESERVED_INPUT`, `OFFER_PROOF_INVALID`.
* **Consensus verification.** `trading_v1::locked`, `verify_approval`, `prepare_batch`.
* **Tests.** tests/e2e_fiat.rs, tests/refusals_dvp.rs, tests/review_completeness_dvp.rs,
  tests/e2e_matrix.rs (`LOCK_NOT_FOUND` before the lock exists and after the release).

### 3.10 BondCreate

* **Purpose.** Lock at least 100 MUT (`MINIMUM_ATOMS`, consensus/src/bonds.rs:15) as a bond lot for
  a node this wallet owns, paid by a funding transfer to a derived escrow address in the same
  block (src/ops/bond.rs:12-23).
* **Request.** `BondCreateRequest { node, node_generation, amount_atoms, nonce }`
  (src/plan.rs:870-879); no defaults. Refused below the minimum (src/ops/bond.rs:757-761) and for a
  zero nonce (src/ops/bond.rs:762-764).
* **Who signs.** Slot `Input(i)` for every funding coin: the coin owner's current key
  (src/ops/bond.rs:845-849; `WalletBook::authorize` through src/ops/payment.rs:366-369); slot
  `BondOwner`: the node's ADMITTED owner (`op.owner = node.owner`, src/ops/bond.rs:793), checked
  with `wallets.authorize(node.owner, signer)` (src/ops/bond.rs:770-776). Both are signed in one
  authorization, through the `TransferSpend` and `BondAuthorization` capabilities (4.12): the
  funding through consensus' `Transfer::sign_input` (Domain::Transaction), the operation through
  consensus' bond `Operation::sign` under Domain::BondCreate.
* **Fee.** One atom per encoded byte of the funding transfer, paid by this wallet when it owns an
  input (src/ops/bond.rs:1225-1241); the creation itself carries no fee (src/ops/bond.rs:1324).
* **Conditions and timing.** Valid in exactly one block and bound to its parent block
  (`bond_validity`, src/ops/bond.rs:358-365; consensus requires `parent.height + 1 == height` and
  the parent's id, consensus/src/bond_ops_v2.rs:235). The funding is valid only at that height and
  its escrow output is consumed by the creation in the same block (src/ops/bond.rs:443-475). At
  most 64 locked lots per lineage (src/ops/bond.rs:494-496). The earliest withdrawal is
  `B + LOCK_HEIGHTS` = B + 259,200 (consensus/src/bonds.rs:16).
* **Irreversible effects.** Spends the funding coins; locks the principal until an unbond and a
  withdrawal at the floor; exposes the whole principal to burning by equivocation evidence; no
  cancel; once signed, valid only in its block; included WITHOUT the creation, the funding strands
  the principal in the escrow output (src/ops/bond.rs:1343-1389).
* **Review.** Titles "Create a bond", "Bond creation by another wallet" (src/ops/bond.rs:1467-1477);
  destination `Escrow` labelled "a protocol escrow" (src/ops/bond.rs:1176-1181); warnings
  `ESCROW_COUPLING` (Danger, requires Irreversible, src/ops/bond.rs:1420), `BURN_EXPOSURE`
  (Conditions, src/ops/bond.rs:1431), `SINGLE_BLOCK` (SingleBlockWindow, src/ops/bond.rs:1049),
  `TREASURY_FUNDS` (TreasuryAuthority, src/ops/bond.rs:1457), `NODE_EXIT_SCHEDULED`,
  `FEE_ABOVE_MINIMUM`; extra acknowledgements Conditions and SingleBlockWindow; high risk
  (confirmation phrase) (src/ops/bond.rs:1499-1500).
* **Refusals.** `BELOW_MINIMUM_BOND`, `NODE_NOT_ELIGIBLE`, `SAME_BLOCK_FUNDING_MISSING`, `REPLAY` (lot
  exists), `NOT_REQUIRED_SIGNER(BondOwner | Input)`, `NOTHING_SPENDABLE`, `INSUFFICIENT_FUNDS`,
  `TOO_MANY_INPUTS`, `INVALID_REQUEST` (nonce, lot capacity), `STALE_AUTHORITY`, `WINDOW_CLOSED`,
  `WINDOW_NOT_OPEN`, `STALE_HEAD`, `WRONG_CONTEXT`, `FEE_BELOW_MINIMUM`, `IMMATURE_INPUT`,
  `CONSERVATION`, `SIZE_LIMIT`, `RESERVE_BACKING_VIOLATION`, `TREASURY_PROFILE_REQUIRED`,
  `TREASURY_ROLE_NOT_DECLARED`.
* **Consensus verification.** `Transfer::verify` of the funding at the next height
  (src/ops/bond.rs:2113) and `Operation::verify_owner` (src/ops/bond.rs:2121); lot id and escrow
  address from consensus (`lot_id`, `escrow_address`, src/ops/bond.rs:447-450). Consensus'
  Production-class check of the node's committed binding (E5, consensus/src/bond_ops_v2.rs:473-487)
  is deliberately NOT mirrored (wallet review fixes, the UNCERTAIN item): it cannot fail against a
  verified head, because every current and retired binding of a Production-class state passes the
  same rule or the state has no root (consensus/src/execution.rs:102-106, 364-380; consensus test
  `production_class_state_cannot_commit_a_software_marked_v2_binding`); src/ops/bond.rs:502-509
  records the decision.
* **Tests.** tests/e2e_bond.rs (`bond_create_unbond_and_withdraw_end_to_end`,
  `creation_refusals_agree_with_consensus_block_execution`), tests/refusals_bond.rs,
  tests/review_completeness_bond.rs (golden snapshots), tests/e2e_matrix.rs.

### 3.11 BondUnbond

* **Purpose.** Start the one-way notice period of an Active lot (Active to Unbonding)
  (src/ops/bond.rs:24-25).
* **Request.** `BondUnbondRequest { lot }` (src/plan.rs:892-897); the sequence is read from
  verified state, never supplied.
* **Who signs.** One slot, `BondOwner`: the lot's immutable owner (src/ops/bond.rs:934-938), checked
  with `wallets.authorize(lot.owner, signer)` (src/ops/bond.rs:885-891; an owner mismatch is
  `INVALID_REQUEST`, src/ops/bond.rs:567-569); Domain::BondUnbond (src/authorize.rs:369).
* **Fee.** None: `FeeRule::None`, payer not applicable (src/ops/bond.rs:1529-1534; Q4).
* **Conditions and timing.** The lot must be Active (src/ops/bond.rs:576) with sequence
  `lot.sequence + 1` (src/ops/bond.rs:584-587); one block, bound to its parent. The earliest
  withdrawal becomes `max(B + 259,200, U + 43,200)` (`withdrawal_floor`,
  consensus/src/bonds.rs:55-59); the lot stays exposed to burning until U + 43,200
  (consensus/src/bonds.rs:17).
* **Irreversible effects.** Moves the lot to Unbonding with no way back; starts the notice; the lot
  stops counting toward the node's weight; once signed, valid only in its block
  (src/ops/bond.rs:1606-1627).
* **Review.** Title "Start a bond's notice (unbond)" (src/ops/bond.rs:1661); no destination;
  warnings `NO_CANCEL` (Danger, Irreversible, src/ops/bond.rs:1640), `BURN_EXPOSURE`,
  `SINGLE_BLOCK`, and for a lot the Treasury owns `TREASURY_LOT` (TreasuryAuthority,
  src/ops/bond.rs:1752; wallet review fixes); high risk (src/ops/bond.rs:1784).
* **Refusals.** `LOT_UNKNOWN`, `LOT_BURNED`, `LOT_NOT_ACTIVE("unbonding" | "withdrawn")`
  (src/ops/bond.rs:578-580), `WRONG_SEQUENCE`, `NOT_YET_ELIGIBLE`, `NOT_REQUIRED_SIGNER`,
  `STALE_AUTHORITY`, `INVALID_REQUEST` (owner mismatch), and the single-block refusals.
* **Consensus verification.** `Lot::start_unbond` on a copy of the lot (src/ops/bond.rs:618) and
  `Operation::verify_command` (src/ops/bond.rs:2148).
* **Tests.** tests/e2e_bond.rs, tests/refusals_bond.rs (`unbond_refusals_agree_with_consensus`),
  tests/review_completeness_bond.rs, tests/e2e_matrix.rs.

### 3.12 BondWithdraw

* **Purpose.** End an Unbonding lot at or after its floor; the protocol pays the principal to the
  lot's immutable owner (src/ops/bond.rs:25-29).
* **Request.** `BondWithdrawRequest { lot }` (src/plan.rs:905-910).
* **Who signs.** As for the unbond: slot `BondOwner`, the lot's owner; Domain::BondWithdraw
  (src/authorize.rs:370).
* **Fee.** None (src/ops/bond.rs:1529-1534; Q4).
* **Conditions and timing.** The lot must be Unbonding (src/ops/bond.rs:577); the height must be at
  least `withdrawal_floor(B, U)`, else `NOT_YET_ELIGIBLE` with the floor (src/ops/bond.rs:601-607);
  the payout coin must not exist yet (src/ops/bond.rs:624-634). Evidence in the same block settles
  first and a burned lot is skipped (consensus/src/bond_ops_v2.rs:389-391). One block, bound to
  its parent.
* **Irreversible effects.** Ends the bond: the lot becomes Withdrawn and the protocol pays the
  principal to its owner; once signed, valid only in its block (src/ops/bond.rs:1699-1709).
* **Review.** Title "Withdraw a bond" (src/ops/bond.rs:1734); destination `ProtocolPayout` to the
  lot's owner (src/ops/bond.rs:1725-1730); warnings `SLASH_FIRST` (Notice), `SINGLE_BLOCK`, and for
  a lot the Treasury owns `TREASURY_LOT` (TreasuryAuthority); high risk.
* **Refusals.** `LOT_UNKNOWN`, `LOT_BURNED`, `LOT_NOT_UNBONDING("withdrawn" | "active")`
  (src/ops/bond.rs:581-582), `WRONG_SEQUENCE`, `NOT_YET_ELIGIBLE`, `REPLAY`, and those of the unbond.
* **Consensus verification.** `Lot::withdraw` on a copy (src/ops/bond.rs:620),
  `Operation::verify_command` (src/ops/bond.rs:2148), `payout_id` (src/ops/bond.rs:627). The tests
  add consensus' own `settle_commands` and the lifecycle `transition` at a synthetic parent (the
  real chain cannot be advanced 259,200 certified blocks in a test).
* **Tests.** tests/e2e_bond.rs (the withdrawal at exactly the floor, one block earlier refused, a
  burned lot refused), tests/refusals_bond.rs (`withdrawal_refusals_agree_with_consensus`),
  tests/review_completeness_bond.rs
  (`the_wallet_refuses_one_block_before_the_floor_and_accepts_at_it_for_random_heights`),
  tests/e2e_matrix.rs.

### 3.13 TreasuryRotate (R2)

* **Purpose.** Move a trading Treasury's active destination from generation g to g + 1; it takes
  effect at the inclusion height, and offers frozen earlier keep their old destination
  (src/ops/treasury.rs:9-35).
* **Request.** `TreasuryRotateRequest { new_descriptor, validity_blocks, treasury }`
  (src/plan.rs:918-952); without `treasury`, the one trading Treasury this wallet controls (several
  are `INVALID_REQUEST`).
* **Who signs.** One slot, `Approval(0)`: the key that currently controls the ACTIVE destination in
  the verified wallet book (src/ops/treasury.rs:785-806), declared under the Treasury profile
  (`profile::require_treasury_operation`, src/profile.rs:295) with the `Destination` role for exactly
  this Treasury (`profile::require_role`, src/profile.rs:312; and, when its fee coins are Genesis
  Treasury coins, the `Authority` role); signed under Domain::Transaction.
* **Fee.** At least max(240, the encoded size of the complete signed operation), paid by coins of
  exactly the current destination address, change back to it (src/ops/treasury.rs:536-555,
  1050-1057); a Treasury coin spent must keep the dividend reserve backed
  (`require_reserve_backing`, src/context.rs:309; src/ops/treasury.rs:1060).
* **Conditions and timing.** Window from the next height for `validity_blocks`; the body must name
  the active generation and address and the new generation must be g + 1
  (src/ops/treasury.rs:957-964, `TREASURY_GENERATION`); the new destination must already resolve to
  its descriptor's own address (src/ops/treasury.rs:983-991, `TREASURY_DESTINATION_UNRESOLVED`) and
  must never have been a destination of this Treasury (src/ops/treasury.rs:998-1000,
  `TREASURY_ADDRESS_USED`); one pending rotation per (Treasury, generation).
* **Irreversible effects.** A new active destination, which cannot be undone; the old address can
  never again be a destination; the fee; once signed it cannot be revoked until its expiry
  (src/ops/treasury.rs:1346-1401).
* **Review.** Titles "Rotate the Treasury destination", "Treasury destination rotation to this
  wallet", "Treasury destination rotation by another wallet" (src/ops/treasury.rs:1460-1481); the
  new destination is a `ProtocolPayout` row of 0 atoms with the typed check (CR-6-1 proposes a role
  of its own); warnings `TREASURY_AUTHORITY_ONLY` (TreasuryAuthority), `NEW_DESTINATION_KEY`
  (Danger), `FROZEN_OFFERS_KEEP_DESTINATION`, `TREASURY_FUNDS` (TreasuryAuthority),
  `FEE_ABOVE_MINIMUM`, `EXPIRES_SOON`; high risk (src/ops/treasury.rs:1529-1530).
* **Refusals.** `TREASURY_GENERATION`, `TREASURY_DESTINATION_UNRESOLVED`, `TREASURY_ADDRESS_USED`,
  `TREASURY_PROFILE_REQUIRED`, `TREASURY_ROLE_NOT_DECLARED`, `TREASURY_CLASS_UNDECLARED`, `STALE_AUTHORITY`,
  `COUNTERPARTY_APPROVAL_INVALID`, `OFFER_PROOF_INVALID`, `REPLAY`, `RESERVED_INPUT`,
  `NOT_YET_ELIGIBLE`, `RESERVE_BACKING_VIOLATION`, `FEE_BELOW_MINIMUM`, the coin and window
  refusals.
* **Consensus verification.** `trading_v1::verify_approval` (src/ops/treasury.rs:967) and
  `trading_v1::prepare_batch` of the complete operation (src/ops/treasury.rs:2638-2645).
* **Tests.** tests/e2e_treasury.rs, tests/refusals_treasury.rs, tests/review_completeness_treasury.rs
  (golden), tests/treasury_outbox_and_properties.rs, tests/e2e_matrix.rs.

### 3.14 TreasuryFreezeOffer

* **Purpose.** An off-chain hybrid signature by the active destination's wallet over the freeze
  body only, authorizing a Treasury hash-linked offer at a named generation; it covers no funding
  lock and no Bitcoin data (src/ops/treasury.rs:37-50).
* **Request.** `TreasuryFreezeOfferRequest { prepared_offer }` (src/plan.rs:954-971): the proposal
  `[PROPOSAL_TAG, freeze body, maker offer]` the host built with `freeze_proposal`
  (src/ops/treasury.rs:1685-1701) from consensus' `prepare_treasury_offer`.
* **Who signs.** Slot `TreasuryFreeze`: the wallet named in the body (`wallet_descriptor`), which
  must control the destination address (src/ops/treasury.rs:1954-1966, 1979-1981), under the
  Treasury profile with the `Destination` role for the Treasury the body names (a freeze spends no
  coin, so the `Authority` role is not needed). Signed through the `TreasuryFreeze` capability over
  the wallet's strict mirror of consensus' freeze body (the one capability without a consensus
  builder at signing time; 4.12).
* **Fee.** None (`FeeRule::None`, src/ops/treasury.rs:2253-2258).
* **Conditions and timing.** Signable ONLY at its creation head (the body's anchor and state root
  must be the view's, else `STALE_HEAD`, src/ops/treasury.rs:1859-1864); the named generation must
  be effective and its successor not (`TREASURY_GENERATION`, src/ops/treasury.rs:1883-1889); the
  offer window starts at the anchor and lasts at most 10,080 blocks (`TREASURY_OFFER_TERMS`,
  src/ops/treasury.rs:1890-1896); hash-linked terms with network 1, 2 or 3 (mainnet is refused,
  src/ops/treasury.rs:1897-1912); one pending freeze per offer.
* **Irreversible effects.** The freeze cannot be revoked until the offer's expiry; proceeds settle
  to the frozen address (src/ops/treasury.rs:2156-2163).
* **Review.** Titles "Authorize a Treasury offer freeze", "Treasury offer freeze of another wallet"
  (src/ops/treasury.rs:2222-2240); warnings `TREASURY_AUTHORITY_ONLY` (TreasuryAuthority),
  `BITCOIN_SETTLEMENT_NOT_VERIFIED` (ExternalEvidence, src/ops/treasury.rs:2190-2200),
  `OPAQUE_TRADE_COMMITMENTS` (Caution, Conditions; W23), `SIGNABLE_AT_CREATION_HEAD_ONLY`; high
  risk.
* **Refusals.** `TREASURY_GENERATION`, `TREASURY_OFFER_TERMS`, `TREASURY_PROFILE_REQUIRED`,
  `TREASURY_ROLE_NOT_DECLARED`, `TREASURY_CLASS_UNDECLARED`, `STALE_HEAD`, `NOT_YET_ELIGIBLE`,
  `MALFORMED` (also maker offer bytes in neither accepted form, through the one offer decoder:
  before W19 `OFFER_PROOF_INVALID` here), `OFFER_PROOF_INVALID` (a maker offer that is not the
  body's, or whose signature does not verify), `NOT_REQUIRED_SIGNER(TreasuryFreeze)`,
  `RESERVED_INPUT`.
* **Consensus verification.** At planning, consensus' `prepare_treasury_offer` must produce exactly
  the proposal's body (src/ops/treasury.rs:1987-2008); for signed bytes
  `verify_frozen_treasury_offer_at_creation` (src/ops/treasury.rs:2654-2661). A freeze is never
  `Confirmed` in the outbox: it settles `InputsSpent` once the offer is filled, or `Expired`.
* **Tests.** tests/e2e_treasury.rs (frozen offers keep their destination), tests/refusals_treasury.rs,
  tests/review_completeness_treasury.rs, tests/btc_boundary.rs (network codes), tests/e2e_matrix.rs
  (frozen-offer parity).

R1, the rotation of the Genesis Treasury AUTHORITY, is a `WalletRotation` (3.2) under the Treasury
profile with the declared `Authority` role: `select::require_profile_for_treasury`
(src/ops/select.rs:83) refuses it to an ordinary identity (`TREASURY_PROFILE_REQUIRED`) and to a
Treasury identity declared without that role (`TREASURY_ROLE_NOT_DECLARED`), also through `adopt`
(tests/treasury_roles.rs pins every role and kind pair); its reserve rule counts the new address
(src/ops/rotation.rs:585).

## 4. Cross-cutting statements

### 4.1 What the approval gate enforces, and what it does not

The gate enforces an ORDER and a BINDING, not a person. `ReviewGate::present` (src/authorize.rs:731)
puts one review on screen; a review for another head is `Stale` and clears everything. The person
types the last eight characters of every destination that needs it (`confirm_destination`,
src/authorize.rs:788), the confirmation phrase of a high-risk review (`confirm_phrase`,
src/authorize.rs:803) and every acknowledgement the review derived from its own rows
(`acknowledge`, src/authorize.rs:823; the destination acknowledgement only after every typed
check). `approve` (src/authorize.rs:857) refuses a moved head (`STALE_HEAD`), a review older than
`MAX_REVIEW_AGE` (600 s, src/authorize.rs:69), a missing acknowledgement, check or phrase, and
issues ONE approval, withdrawing every earlier one of that gate. An approval is single use, not
`Clone`, older than `MAX_APPROVAL_AGE` (120 s, src/authorize.rs:71) is refused, and
`run_authorization` (src/authorize.rs:984) refuses it for any plan whose kind, recomputed review
digest or scope differs (`PLAN_CHANGED`, src/authorize.rs:1023). The digest binds the kind, the
schema, every unsigned object, the anchor and the state root (`binding_digest`,
src/review.rs:573), so the signed bytes are exactly the reviewed unsigned bytes plus signatures.

Order W5 is pinned in one test, `tests/approval_flow.rs`,
`order_w5_one_live_approval_re_presentation_withdraws_and_the_binding_is_exact`: a second approval
of a gate withdraws the first, and presenting the same review again withdraws the live one
(`APPROVAL_REVOKED`); a plan that differs from the reviewed bytes in one field is `PLAN_CHANGED`;
the same anchor over another state root, and another Genesis at the same height, are another head
(`STALE_HEAD`, for the signer and for the gate); the exact plan at the exact head is authorized
(further: `a_gate_withdraws_the_approval_it_issued_even_while_the_caller_holds_it`,
`an_approval_given_for_another_wallets_reading_of_the_same_bytes_cannot_authorize_the_plan`).
`Approval::binding` exposes what an approval was given for, so an outbox can keep it with the queued
bytes and check it again at export (4.4).

It does NOT prove that a human was present, and it does not protect against a malicious host
process that holds the key: the typed checks and acknowledgements are ordinary calls such a process
could make itself, or it could sign without this crate (README, "What the gates are, and what they
are not"). The typed check is 32 bits (the last eight hex characters): carelessness and look-alikes,
not a determined grinder. It is an interim human-error aid, not a checksum and not address
authentication; it is kept on top of the checksummed address text (Q10 follows W2, 4.11).

### 4.2 The production gate is closed

`SigningGate::production()` (src/authorize.rs:273) returns `GATE_CLOSED` while
`mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED` is false; no `KeySigner` exists without a gate.
Nothing in this crate flips or works around it.

### 4.3 TEST-VALUE signing exists only in tests

The only signing gate that opens is the TEST-VALUE gate, compiled only under `cfg(test)` or the
non-shipping feature `test-value-signing` (Cargo.toml:46; `TEST_VALUE_SIGNING_ENABLED`,
src/authorize.rs:78), which this crate's own tests get through a dev-dependency on itself and which
no shipping root enables (pinned by `tests/build_independence.rs`). It refuses a production chain
(`CHAIN_CLASS_MISMATCH`, src/authorize.rs:315). Every result in this document is therefore
Simulated/TEST-VALUE: NATIVE PASS (offline, TEST-VALUE) at most.

### 4.4 The outbox: queued is not delivered is not settled (Q1)

A returned identifier means "queued locally", never "delivered" and never "settled"
(src/outbox.rs:6). Every commit re-verifies the bytes through consensus code and derives the
record's identifier, completeness, missing signatures, validity and reserved coins and resources
from the BYTES; a caller's metadata that disagrees is refused. Reconciliation reads verified state
only (src/outbox.rs:19). There is no revoke: `forget` releases the local reservations and cancels
nothing (src/outbox.rs:21). A queued partial record is completed with `replace_partial`
(src/outbox.rs:488; in memory src/outbox.rs:663, durable src/outbox_sqlite.rs:550): the complete
operation takes the partial's place and reservations in one atomic step (src/outbox.rs:24), checked
by `admit_replacement` (src/outbox.rs:372). Non-coin resources are reserved through
`resource_key(namespace, id)` (src/outbox.rs:262); the ten namespaces are registered in
`RESOURCE_NAMESPACES` (src/outbox.rs:279). No delivery path exists for non-Transfer operations in
this protocol version (README, "Findings and limits"): the core builds, reviews, signs, queues and
exports them.

**View-verified export (Order W6).** `Outbox::pending` lists the open records after re-checking
only their UNKEYED checksum. That catches accidental damage, not someone who can rewrite the
outbox file (they can recompute the checksum): it is NOT authentication, and its records are not for
delivery. `Outbox::export_verified(id, view)` is the export for delivery (`export::verify_record`,
src/export.rs). Against the host's CURRENT verified view it checks, in this order (a record that
fails several is refused for the first):

1. the bytes: they decode as an operation of the record's kind and commit to exactly the record's
   identifier, completeness, missing signatures, validity and reservations (`OUTBOX_INTEGRITY`);
   when the record carries an approval binding, a view of another chain is refused here
   (`WRONG_CONTEXT`);
2. the status, from verified state: a stored settled or forgotten status only ever refuses (it is
   not covered by the checksum); an open record is judged afresh: a view older than the head the
   record was queued at is `Stale`, then the kind's reconciliation says `Confirmed`, `Expired`,
   `Conflicting` (another operation consumed its inputs or resources) or `Stranded`; each is
   `NOT_DELIVERABLE` naming the `DeliveryStatus`;
3. the approval binding, when the record carries one: the binding digest of the bytes' unsigned
   form at the approved head is the approved review digest, of the same kind, at a head no later
   than the view's (`APPROVAL_BINDING_MISMATCH`);
4. every signature present, through the kind's consensus verification at the next height
   (`check_signed`, the check `commit` runs); a partial record passes when every signature it
   carries verifies, and `VerifiedExport::missing` says what is still missing.

`Outbox::commit_approved(signed, binding, view)` takes the binding of the approval the operation
was authorized with (`Approval::binding`, taken before `Signer::authorize` consumes the approval: an
`ApprovalBinding` of kind, schema, review digest, scope, anchor and state root), checks it against
the bytes and stores it with the record; the same bytes already queued under another binding, or
without one, are `APPROVAL_BINDING_MISMATCH`. A record queued with `commit` (imported bytes, a
counterparty's part) exports with `ApprovalEvidence::NotRecorded`: nothing is claimed about an
approval. The binding is a sixth field of the stored record metadata, so a record without one keeps
exactly its former encoding and checksum. The trait's default methods serve an outbox that does not
store bindings (the desktop's, until the desktop lane adopts them): `commit_approved` checks the
binding and commits without storing it. What this cannot do: the binding, like the checksum, is
unkeyed. Someone who can rewrite the outbox file can put OTHER validly signed bytes (an operation
this wallet signed earlier, or one it is a party to) in a record together with a matching binding,
or rewrite a forgotten record's status to queued; export then releases bytes that are valid, signed
and self-consistent, but not the ones approved for that record. Protection at rest is the host's
(the desktop's DPAPI baseline, Order W10); the chain rejects anything invalid. Tests:
`tests/outbox_export.rs`, each against the in-memory and the SQLite outbox
(`an_approved_operation_exports_with_its_binding_and_a_plain_commit_as_not_recorded`,
`the_binding_survives_a_restart_and_a_record_without_one_keeps_its_old_encoding`,
`a_binding_that_does_not_fit_the_bytes_is_refused_at_commit` (another approval, another chain, a
later head), `a_rewritten_store_is_refused_at_export_even_with_a_recomputed_checksum` (a tampered
signature, substituted bytes, bytes that are no operation, the wrong approval),
`a_view_of_another_chain_is_refused`, `stale_expired_confirmed_conflicting_and_forgotten_records_say_so`),
and `tests/e2e_bond.rs`, `creation_refusals_agree_with_consensus_block_execution` (a stranded record
is `NOT_DELIVERABLE` with `Stranded`).

**`Stranded` is a diagnostic (Order W9).** When a bond creation's funding payment was included
WITHOUT the creation, reconciliation reports `Settlement::Stranded(h)` and the record becomes
`OutboxStatus::Stranded(h)`, h being the height at which the funding was included (before: the bare
`InputsSpent`). The durable outbox stores it as the inputs-spent code with that height, so a reader
that does not know the variant reads `InputsSpent`, what it reported before. It describes settled
history of an old or test failure; it is not a recovery path, and it does NOT replace atomic bond
funding, which is Lane P's protocol change (stage 2). Test: `tests/e2e_bond.rs`,
`creation_refusals_agree_with_consensus_block_execution` (memory and SQLite, across a restart).

### 4.5 Single-block validity (Q2)

A plan reviewed at one head is re-reviewed at every new head (`PlanSession::on_head`,
src/plan.rs:1447); the gate refuses a moved head. The License sale and the three bond operations are
valid in exactly one block (`valid_only_at`), and a bond operation is also bound to its parent
block; a host that cannot deliver within one block interval re-plans.

### 4.6 BTC custody stays external (the six surfaces)

The wallet never builds, parses or signs a Bitcoin transaction or PSBT, holds no Bitcoin key,
script, txid or address type, and verifies no Bitcoin evidence; custody is the Architect's alone.
`tests/btc_boundary.rs` pins six surfaces (its module doc, tests/btc_boundary.rs:6-22):

1. No public type has a Bitcoin-typed field; Bitcoin-named identifiers are exactly the two
   INTEGER offer terms (`bitcoin_satoshis`, `bitcoin_network`) and their constants.
2. No public function takes a Bitcoin-typed parameter; `OperationRequest` has no Bitcoin variant.
3. Hash-lock preimages are fresh OS-random values (`secret::Preimage`), never derived from a key.
4. Treasury reviews state that they change MUT authority only and print no key material.
5. A Treasury offer naming a Bitcoin network outside 1..=3 is refused (mainnet 0 by the wallet,
   `TREASURY_OFFER_TERMS`, and by consensus).
6. The lock file holds no Bitcoin crate besides the `bitcoin_hashes` hash library (with its
   encoding dependency `hex-conservative`, both reached only through `bip39` under crypto-v2).

Order W3 keeps these narrowly pinned bip39-to-crypto-v2 hash dependencies. A library name does not
authorize Bitcoin custody/signing or another wallet stack. The exemption is narrow and tested:
`tests/build_independence.rs`, `the_resolved_graph_has_no_gui_os_network_or_bitcoin_crates_and_the_right_features`,
allows exactly one Bitcoin-named package, `bitcoin_hashes`, and pins its only parent chain (bip39
under crypto-v2), and `tests/btc_boundary.rs`, `the_lock_file_has_no_bitcoin_crate_but_the_hash_library`,
pins surface 6 (no other Bitcoin crate in the lock file).

A hash-lock claim and the Treasury freeze reviews say the preimage is supplied externally and
that Bitcoin settlement is not verified by this wallet; a fiat release says no fiat payment is
verified.

### 4.7 The defaults Q1 to Q17 (settled by the Order)

The wallet plan assumed seventeen defaults; the Order (section 6, W1) settled each one
individually, and temporary limitations are not accepted as the final product's scope. The table
says what the wallet core applies NOW; section 6 gives the status of each against the Order (several
remain interim until Lane P's protocol formats exist).

| Q | Default applied | Where |
|---|---|---|
| Q1 | signed non-Transfer operations are queued locally and exported as bytes, re-verified against the current verified view first (`Outbox::export_verified`, W6); no delivery claim (interim until P4 delivery) | src/outbox.rs, src/export.rs |
| Q2 | single-block operations (bond kinds, License sale): re-review at every new head, no pre-signed windows | src/plan.rs:1447 |
| Q3 | the hash-lock refund is the only cancellation; every other cancel is a typed refusal | src/plan.rs:1149 |
| Q4 | bond unbond and withdrawal carry no fee (`FeeRule::None`): an explicit, narrow economic decision of the Order for these two dedicated operations only; it does not exempt the BondCreate funding, ordinary transfers or trades, and their replay and admission protections stay (sequence, single block, parent binding) | src/ops/bond.rs:1531 (sections 3.11, 3.12) |
| Q5 | R1 and R2 only behind an identity-checked, non-default Treasury profile: `profile::declare` is the only public way to it (the labelling is crate-private since the wallet review fixes) and the identity carries the role set it checked; each kind checks its own role at use | src/profile.rs:254, src/profile.rs:312, src/ops/select.rs:83 |
| Q6 | TEST-VALUE signing only under `cfg(test)` or the non-shipping feature; production gate closed | 4.2, 4.3 |
| Q7 | offers and fill proofs are imported and verified, never created | src/offers.rs:5 |
| Q8 | TradeID and ContractHash shown as opaque commitments with a Caution that requires the Conditions acknowledgement, on every kind that carries them (W23) | `offers::commitments_warning`, `offers::trade_commitments_warning` |
| Q9 | a License sale does not bind remaining dividends: shown, acknowledged, flagged as a protocol gap | src/ops/license_dvp.rs:1018 |
| Q10 | follows W2: the checksummed address text (PROPOSED) as the primary display, the legacy hex next to it, and the typed last-eight-characters check kept as an interim human-error aid | src/address_format.rs, `ReviewGate::confirm_destination` |
| Q11 | heights and epochs with approximate durations, labelled approximate | src/units.rs:8 |
| Q12 | public partial operations exchanged as `PartialApproval` files | src/partial.rs:55 |
| Q13 | preimages are fresh OS-random values in their own record, never derived | src/secret.rs:27 |
| Q14 | "License purchase" means a DvP of an existing License | docs/PHASE-5B-DVP.md, section 3.4 |
| Q15 | Treasury spending refused below the dividend reserve (`RESERVE_BACKING_VIOLATION`) | src/context.rs:309, src/ops/rotation.rs:585 |
| Q16 | bonds only for nodes this wallet owns, read from verified state | src/discovery/bonds.rs:232 (section 3.10) |
| Q17 | a fresh Worker assignment after a sale is out of scope but stated in the review | src/ops/license_dvp.rs:886 |

### 4.8 Protocol-level hazards found by the phases (verified against the code)

* A bond's funding payment included without its creation strands the principal: no key controls
  the escrow address and a creation can only consume a funding output of its own block. The
  review warns (`ESCROW_COUPLING`, Danger, src/ops/bond.rs:1420), the plan exports only the
  bundle, and `ops::bond::stranded_escrow` (src/ops/bond.rs:162) tells a host when it happened;
  reconciliation reports the diagnostic `Stranded` (4.4, W9). Atomic bond funding is Lane P's
  protocol change (stage 2); `Stranded` does not replace it.
* A rotation's signatures do not cover its funding transfer: whoever sees the signed rotation can
  include it with other funding (`FUNDING_NOT_BOUND`, src/ops/rotation.rs:1744). The effect is
  the same; this wallet's funding transfer then stays valid on its own until the expiry.
* Operations have no confirmation index: the canonical store indexes the identifiers of block
  TRANSACTIONS only (consensus/src/canonical_store_v2.rs:1403-1406), never block operations. The
  outbox therefore reconciles operations from their effects in verified state (the `Applied`
  record of a trading operation, a claim's or a withdrawal's payout coin, a lot's status), and a
  `ConfirmationSource` helps transactions only (src/context.rs:143).
* Consensus `debit` compares each input's owner with the payer address exactly
  (consensus/src/trading_v1.rs:2172): it does not resolve wallet authority, so a rotated wallet
  funds a lock from the coins of ONE address only, and a claimant or refunder needs fee coins at
  exactly the lock's recipient or sender address.
* No delivery path exists for non-Transfer operations (README.md:309): only payments and
  rotations reach a node's mempool; everything else is queued and exported (Q1).
* A License sale does not bind the remaining dividend entitlements of that License: the buyer
  continues the award account, the seller can no longer claim what it did not claim before the sale,
  and a seller's claim in the sale's block fails `StaleOwner`; both reviews say so
  (`UNBOUND_DIVIDENDS`, src/ops/license_dvp.rs:1018).

### 4.9 One offer check, one offer decoder; reservation namespaces

Every handler that imports a maker offer (the License sale, the fiat lock, the hash lock and the
Treasury freeze) uses one decoder, `offers::decode_maker_offer`: the canonical container labelled
`OFFER_LABEL` is the offer format of this wallet, and the consensus `OfferProof` encoding with an
all-zero fill is accepted for compatibility (the form phase 5A and the Treasury proposals used).
Since Order W19 the rules around it are one rule each, with one refusal code per failure whichever
handler reaches it:

* import (`offers::import_offer`, every planner): bytes in neither form `MALFORMED` (before W19
  `OFFER_PROOF_INVALID` on the hash-lock and Treasury paths), another chain `WRONG_CONTEXT`, an offer
  signature that does not verify `OFFER_PROOF_INVALID`, an offer whose terms are for another kind of
  operation `INVALID_REQUEST` with the reason `offers::REASON_OFFER_KIND` (before W19 a different
  reason per handler, and `OFFER_PROOF_INVALID` on the hash-lock path);
* request time (`offers::require_fillable`, every planner): `OFFER_NOT_YET_VALID` before the
  offer's first block, `OFFER_EXPIRED` after its last, `OFFER_CONSUMED` once filled;
* the offer embedded in operation bytes (`offers::check_offer`, the one mirror of consensus'
  `Operation::verify_offer`; the hash lock's own mirror was merged into it): an offer-bearing
  action without the offer, or an action that fills none but carries one, `OFFER_PROOF_INVALID`;
  another chain `WRONG_CONTEXT` (before W19 `OFFER_PROOF_INVALID` on the hash-lock path); the offer
  or the maker not the one the action names `OFFER_PROOF_INVALID`; the next block before or after
  the offer's window `OFFER_NOT_YET_VALID` / `OFFER_EXPIRED`; an operation window not inside the
  offer's `OFFER_WINDOW_EXCEEDED` (new; before W19 `INVALID_REQUEST` on the sale and fiat paths and
  `OFFER_PROOF_INVALID` on the hash-lock path); terms other than the offer's, a maker signature that
  does not verify, or a fill signature that is present and does not verify `OFFER_PROOF_INVALID`
  (the last was a `BAD_SIGNATURE` warning on the sale and fiat paths before W19); the single fill
  `OFFER_CONSUMED`.

`tests/offer_checks.rs` is the matrix: every failure class built the same way for the sale, the fiat
lock and the hash lock gives the same code from every handler and at every entry point
(`every_embedded_offer_failure_has_one_code_for_every_handler`,
`a_filled_offer_is_offer_consumed_for_every_handler_and_entry_point`,
`every_request_time_and_import_failure_has_one_code_for_every_planner`); `tests/cross_kind.rs`
proves every path accepts and rejects the same bytes.

The ten reservation namespaces are registered in `RESOURCE_NAMESPACES` (src/outbox.rs:279), each
naming one kind of resource. Two pairs name ids of one consensus table that are disjoint by kind:
"trade-offer" (an offer filled by a hash lock) and "offer" (an offer filled by a sale or a fiat
lock), and "hash-lock" (claimed or refunded) and "lock" (a fiat lock, released).

### 4.10 Findings of the phase-8 self review, and what candidate 3 did with them

* RESOLVED (W19): the two mirrors of `Operation::verify_offer` (`offers::check_offer` and the hash
  lock's own `check_offer`) mapped the same failures to different codes. They are one check now,
  with one code per failure (4.9). Hosts that keyed on the old codes see `WRONG_CONTEXT`,
  `OFFER_WINDOW_EXCEEDED`, `MALFORMED` or `INVALID_REQUEST` where the hash lock said
  `OFFER_PROOF_INVALID`, and `OFFER_WINDOW_EXCEEDED` where the sale and the fiat lock said
  `INVALID_REQUEST`.
* RESOLVED (W19): offer bytes in neither accepted form are `MALFORMED` on every path.
* RESOLVED (W23): the opaque-commitment warning is a Caution that requires the Conditions
  acknowledgement on every kind: `OPAQUE_COMMITMENTS` (the sale, the fiat lock and release) and
  `OPAQUE_TRADE_COMMITMENTS` (the hash lock, its claim and refund, the Treasury freeze; before, a
  Notice without an acknowledgement), pinned over the golden reviews by `tests/opaque_commitments.rs`,
  `every_opaque_commitment_warning_is_a_caution_with_the_conditions_acknowledgement`. A warning
  cannot replace concrete term validation, verified external-settlement evidence or the mandatory
  P5/P6 cryptographic commitments, which are Lane P's (stage 2).
* RESOLVED (W22): `LicenseDvpRequest::validity_blocks` is no longer ignored: a request that sets it
  is refused with `VALIDITY_WINDOW_UNSUPPORTED` naming P4 (3.4).
* The reservation namespace pairs of 4.9 name disjoint ids and were not merged (a rename would let a
  record queued before the upgrade stop reserving its resource).
* `docs/PHASE-6-TREASURY.md` still lists the `INVALID_REQUEST` reasons phase 8 replaced with the
  dedicated `TREASURY_*` codes; this document is the current one.

### 4.11 The address text format (Order W2)

`src/address_format.rs` encodes the 32-byte AddressID as `prefix 1 data checksum`: the 32 bytes as
52 five-bit groups in the BIP-173 alphabet and the bech32m checksum of BIP-350 (constant
`0x2bc830a3`). The prefix names the class the VERIFIED chain declares (`mut` production, `tmut`
TEST-VALUE, `umut` none declared; `ChainView::class`, never a build or configuration choice), so a
TEST-VALUE address cannot be entered into a production wallet by accident and a hand-edited prefix
breaks the checksum. Decoding is strict: one case, lowercase only (no silent normalisation), at most
90 characters, exactly 32 payload bytes with canonical padding, the expected prefix, the checksum;
every failure is a distinct `AddressError` with a stable code, and `ADDRESS_ENCODING` as a wallet
refusal (`decode_for`). Two chains of the same class, and the producer of a string, are NOT
distinguishable; the checksum detects accidents and is not authentication. Specification:
`docs/ADDRESS-FORMAT-V1.md` (PROPOSED, not frozen; registered `PROPOSED-UNFROZEN` in
`spec/DOMAIN-REGISTRY-V1.json`). The AddressID bytes, not the text, are what an operation signs:
every request keeps its 32-byte field and its full-address validation, and the signed destination
binding is unchanged. Every structured address row of a review shows the checksummed form first and
the legacy hex after it. The typed destination check (4.1) is kept as an interim human-error aid:
the checksum catches a corrupted entry, the typed check puts the destination the plan binds in
front of the person; neither is authentication (ADDRESS-FORMAT-V1 section 7, with the proposal to
type the checksummed tail instead). Tests: the unit tests of `address_format`
(`every_identifier_round_trips_under_every_class_and_the_form_is_canonical`,
`the_same_identifier_reads_differently_under_each_class_and_a_prefix_edit_breaks_the_checksum`,
`every_single_substitution_and_adjacent_transposition_is_detected`,
`every_rejection_class_has_its_own_typed_error`, `the_check_order_is_the_documented_one`, the
published BIP-350 and BIP-173 strings) and `tests/address_format_vectors.rs` over the public
TEST-VALUE vectors `tests/golden/address-format-v1.json`; the review goldens
`tests/golden/*_review.txt`. Not converted yet: the desktop's input forms (desktop lane) and the
handlers' free-text mentions of addresses (section 6, W2).

### 4.12 Typed signing capabilities (Order W4)

A key is held only SEALED (`capability::SealedKey`, its field private to src/capability.rs) by the
two signers a host builds behind a gate, `KeySigner` and `RotationSigner` (src/rotation_signer.rs;
still exported as `ops::rotation::RotationSigner`). `authorize::run_authorization` lends a handler a
`capability::KindSigner` bound to the plan's kind, after the gate, approval, head, identity, plan
binding and per-slot authority checks. From it the handler obtains only the typed capabilities its
kind holds (`capability::capabilities(kind)`), and each signs one consensus object of that kind
through its consensus-owned builder:

| Capability | Kinds | Signs |
|---|---|---|
| `TransferSpend` | Payment, WalletRotation, BondCreate | one `Transfer` input (`Transfer::sign_input`, Domain::Transaction) |
| `BondAuthorization` | BondCreate, BondUnbond, BondWithdraw | a bond `Operation` of the kind (`Operation::sign`) |
| `ClaimAuthorization` | DividendClaim | a `SignedClaim` (`SignedClaim::sign`) |
| `TradeApproval` | the six trading kinds and TreasuryRotate | one approval slot of a trading `Operation` of the kind, as the wallet's own identity (`signing_payload`) |
| `RotationProofs` | WalletRotation | both proofs of a `Rotation` (`Rotation::sign`) |
| `TreasuryFreeze` | TreasuryFreezeOffer | the freeze body (the wallet's mirror, see below) |

Any other request is `CAPABILITY_NOT_PERMITTED`, and a capability is granted only after
`domain_for` permits every purpose it signs for. No function returns a key or signs caller-chosen
bytes, and the constructors are crate-private. Direct raw signing is therefore a COMPILE ERROR for a
host and, because nothing reachable from a `KindSigner` is `pub(crate)`, for the handler modules too:
nine `compile_fail` doctests in src/capability.rs (asking a `KindSigner` for its key, a raw `sign`,
its key ring; a raw call on a capability, a capability's key; a `KeySigner`'s key and state;
`KindSigner::new`; and the W9 labelling call `with_treasury_roles`), each paired with an identical
`no_run` control that compiles. Rustdoc does not enforce the error code after `compile_fail` on this
toolchain; each code (E0599, E0616, E0624) was verified once by compiling the example as an ordinary
one. The text guards stay as additional regression checks: `build/check-signing-calls.pl` holds every
signing call to an exact allow-list (`build/signing-call-rules.txt`: the six capability signing
functions, `run_authorization` and the two approval calls), and `tests/build_independence.rs`
(`key_access_for_operations_is_sealed_and_typed`; `HybridKey` appears in the non-test code of
capability.rs, authorize.rs and rotation_signer.rs only). Gap: the `TreasuryFreeze` capability signs
the wallet's strict mirror of consensus' private freeze body, because no consensus builder exists at
signing time (the planner checked that consensus' `prepare_treasury_offer` produced exactly those
bytes, and the result is verified through consensus); a public consensus constructor belongs with
W18 (stage 2). This boundary does not protect a key from the host process that holds it. Unit tests:
`capability::tests` (`the_capability_table_is_total_exact_and_agrees_with_domain_for`,
`a_kind_obtains_exactly_its_own_capabilities`,
`a_bond_capability_signs_only_its_kind_through_consensus_under_the_domain_domain_for_selects`,
`a_trading_capability_signs_only_its_kind_and_only_as_its_own_identity`).

### 4.13 Public enums that may gain variants; the Treasury labelling (Order W9)

`AckKind`, `Settlement`, `OutboxStatus`, `Purpose`, `ExpiryKind`, `Invalidation` and `TreasuryRole`
are `#[non_exhaustive]` since candidate 3, like the new `Capability`, `AddressError`,
`ApprovalEvidence` and `DeliveryStatus`: a host matches them with a wildcard arm, and a new variant
(the `Stranded` diagnostic of 4.4) no longer breaks it. The desktop's exhaustive matches got
wildcard arms with no change of behaviour (desktop/src/operation_outbox.rs; `cargo check` of the
desktop passes on Windows). The Treasury labelling of an identity is crate-private
(`SignerIdentity::with_treasury_roles`, the former `with_profile`, crate-private since the wallet
review fixes and now pinned by the compile_fail doctest of 4.12): only `profile::declare` gives the
Treasury profile, after checking every role against the verified chain, and the handlers re-check
the identity at every use.

## 5. NOT done

* No production signing: the production gate is closed (4.2); every result is Simulated or
  TEST-VALUE, NATIVE PASS (offline, TEST-VALUE) at most, on Windows. No physical, Linux or
  production run backs anything in this document.
* No delivery path for non-Transfer operations (Q1); nothing here submits them.
* No Bitcoin system, preimage exchange, fiat settlement or external evidence is verified.
* No Worker re-assignment after a License sale (Q17); no bond withdrawal on a real chain at the
  floor (consensus' own settlement and lifecycle at a synthetic parent instead, 3.12).
* No bond-coupling acknowledgement kind (the coupling is acknowledged through `ESCROW_COUPLING`;
  `AckKind` is non-exhaustive now, so one can be added without breaking a host); `Stranded` exists
  only as a diagnostic (4.4) and atomic bond funding is Lane P's (stage 2); no `PlanObject`
  zeroization (documented, src/plan.rs `PlanObject`).
* Not merged: the two reservation-namespace pairs (4.10).
* Stage 2 (needs Lane P's protocol formats; not in this lane's stage 1): completed-operation
  delivery (W12, P4), signed validity windows (Q2, and `validity_blocks` of the License sale, W22),
  the rotation node path (W13), the separate Treasury host tool (W14), restore evidence for a new R2
  destination (W17), the Treasury identity under distinct domains and the frozen-offer lifecycle
  (W18), the P5/P6 cryptographic commitments (W23, Q8, Q9), atomic bond funding (P9), canonical
  maker creation and freeze (Q7) and the post-sale Worker assignment (Q17). The desktop lane owns
  W7, W8, W10, W11, W15 and W16.
* Change requests still open: CR-6-1 (a `DestinationRole` for an address that becomes a
  destination without receiving value now), the missing consensus accessors the phases listed (a one-address
  `WalletBook` lookup, the mempool's pending rotation authorities, a public freeze-body decoder).

## 6. Order decisions W1-W23 / Q1-Q17: code, tests, status

Status words: **completed** (implemented and tested in this lane, stage 1); **partially** (what is
named is done, the rest is named); **depends on Lane P** (needs Lane P's protocol formats, stage 2);
**desktop lane** (`cand3/desktop`); **evidence-input-blocked** (needs a production input that does
not exist). "As built" means the behaviour existed before candidate 3 and was verified, not
changed. Test names are in `wallet-core/tests/` unless a module is named. Every result: NATIVE PASS
(offline, TEST-VALUE) on Windows at most.

| Decision | Code | Tests | Status |
|---|---|---|---|
| W1 Q1-Q17 settled individually | this document (4.7 and the Q rows below) | (the Q rows) | partially: each Q row below states its own status |
| W2 checksummed, class-distinguishing address text | src/address_format.rs; review rows (src/review.rs `show_address`, `show_labelled`); docs/ADDRESS-FORMAT-V1.md; spec/DOMAIN-REGISTRY-V1.json `MUTINY-BUILD8-ADDRESS-TEXT-V1` PROPOSED-UNFROZEN | `address_format::tests` (6), address_format_vectors.rs (3; vectors golden/address-format-v1.json), the review goldens | partially: format, vectors and review display completed (PROPOSED, needs the Architect's review before freezing); typed check kept as an interim aid (4.11); the desktop's input forms (desktop lane) and the handlers' free-text address mentions are not converted |
| W3 bip39 hash dependencies | (no code change) 4.6, README "Findings and limits" | build_independence.rs `the_resolved_graph_has_no_gui_os_network_or_bitcoin_crates_and_the_right_features`; btc_boundary.rs `the_lock_file_has_no_bitcoin_crate_but_the_hash_library` | completed |
| W4 restricted raw-key access, typed capabilities | src/capability.rs, src/rotation_signer.rs, src/authorize.rs, src/ops/*.rs; `CAPABILITY_NOT_PERMITTED` | 9 compile_fail doctests + 4 controls in capability.rs; `capability::tests` (4); build_independence.rs `key_access_for_operations_is_sealed_and_typed`; build/check-signing-calls.pl (rules, probes) | completed; one gap: the freeze capability signs the wallet's mirror body (4.12, with W18) |
| W5 one live approval, re-presentation withdraws, exact binding | src/authorize.rs (as built; `Approval::binding` added for W6) | approval_flow.rs `order_w5_one_live_approval_re_presentation_withdraws_and_the_binding_is_exact` and the gate tests | completed (wording checked: no claim of human presence or host protection) |
| W6 view-verified outbox export | src/export.rs, src/outbox.rs, src/outbox_sqlite.rs; `APPROVAL_BINDING_MISMATCH`, `NOT_DELIVERABLE` | outbox_export.rs (6, memory and SQLite); e2e_bond.rs (stranded export) | completed; the binding is unkeyed (4.4); the desktop outbox uses the default methods until the desktop lane adopts them |
| W7 retire the V1 application path | - | - | desktop lane |
| W8 rename the executable | - | - | desktop lane |
| W9 crate-private Treasury labelling, non-exhaustive enums, Stranded diagnostic | src/outbox.rs, src/outbox_sqlite.rs, src/ops/bond.rs, the enums of 4.13; desktop/src/operation_outbox.rs (wildcard arms) | capability.rs compile_fail doctest (E0624); e2e_bond.rs `creation_refusals_agree_with_consensus_block_execution`; e2e_payment.rs; approval_flow.rs; desktop `cargo check` | completed |
| W10 DPAPI baseline, protected preimages | - | - | desktop lane |
| W11 explicit vault root | - | - | desktop lane |
| W12 partial file exchange; completed delivery under P4 | `PartialApproval` (as built) | partial_and_outbox.rs | partially: file exchange as built; delivery depends on Lane P (P4) |
| W13 rotation node path | - | - | depends on Lane P (stage 2) |
| W14 separate Treasury host tool | - | - | depends on Lane P (stage 2) |
| W15 composed screens in a TEST-VALUE executable | - | - | desktop lane |
| W16 manual retirement of the previous identity | - | - | desktop lane |
| W17 checked Treasury profile, restore evidence for R2 | profile (as built) | treasury_roles.rs, refusals_treasury.rs | partially: profile as built; restore evidence for a new R2 destination depends on Lane P (P6, stage 2) |
| W18 Treasury identity under distinct domains; frozen offers | current-head refusal kept (`STALE_HEAD`, 3.14) | refusals_treasury.rs | depends on Lane P (stage 2) |
| W19 one offer check, consistent codes | src/offers.rs (`check_offer`, `require_fillable`, `import_offer`, `REASON_OFFER_KIND`), src/ops/conditional.rs, src/ops/license_dvp.rs, src/ops/fiat.rs, src/ops/treasury.rs; `OFFER_WINDOW_EXCEEDED` | offer_checks.rs (3, the matrix); updated: cross_kind.rs, refusals_dvp.rs, refusals_conditional.rs, refusals_treasury.rs, review_completeness_dvp.rs | completed |
| W20 dividend claims | src/ops/dividend.rs, `review::CLAIM_DEADLINE_WARNING_EPOCHS` | refusals_dividend.rs `a_claim_to_the_zero_address_is_refused_by_wallet_policy`, `an_award_not_yet_reached_is_refused_like_consensus`, `an_expired_award_is_refused_like_consensus`, `the_at_most_wording_rests_on_consensus_refusing_a_regressing_timestamp`, `the_treasury_wallet_claims_only_through_the_treasury_profile`, `an_ordinary_claim_needs_only_its_owner_and_no_treasury_signature`; review_completeness_dividend.rs | completed ("at most" verified, 3.3); the signed height-window expiry is separate and depends on Lane P (P4) |
| W21 Treasury profile to sell a Treasury-owned License | src/ops/license_dvp.rs (`select::require_profile_for_treasury`, as built) | refusals_dvp.rs `selling_a_treasury_owned_license_needs_the_treasury_profile` | completed (verified and pinned) |
| W22 `validity_blocks` of a License sale | src/plan.rs (`Option<u64>`), src/ops/license_dvp.rs; `VALIDITY_WINDOW_UNSUPPORTED` | refusals_dvp.rs `a_license_sale_request_with_a_validity_window_is_refused_until_p4` | completed (explicit rejection); the window itself depends on Lane P (P4) |
| W23 Caution and acknowledgement for opaque commitments | src/offers.rs `trade_commitments_warning`, src/ops/conditional.rs, src/ops/treasury.rs | opaque_commitments.rs; the review goldens | completed for the warning; the P5/P6 commitments depend on Lane P |
| Q1 local queue and export, no delivery claim | src/outbox.rs, src/export.rs | partial_and_outbox.rs, outbox_export.rs | partially: interim behaviour, now with view-verified export; qualified delivery depends on Lane P (P4) |
| Q2 re-review on every head | `PlanSession::on_head` (as built) | approval_flow.rs | partially: interim behaviour; P4 revalidation depends on Lane P |
| Q3 explicit refusal of unsupported cancellation | `plan()` cancel mapping, `CANCEL_NOT_AVAILABLE` (as built); `forget` cancels nothing (4.4) | refusals_conditional.rs `every_cancellation_but_the_hash_lock_refund_is_refused_and_the_refund_is_routed` | completed (as built) |
| Q4 `FeeRule::None` for BondUnbond and BondWithdraw only | src/ops/bond.rs (as built; 4.7 states the narrow scope) | refusals_bond.rs, e2e_bond.rs | completed (as built) |
| Q5 Treasury rotations behind the checked profile | src/profile.rs, src/ops/select.rs (as built) | treasury_roles.rs | partially: profile as built; P6's common canonical authority depends on Lane P |
| Q6 signing only in tests / non-shipping TEST-VALUE | `SigningGate` (as built; refuses a production chain, `CHAIN_CLASS_MISMATCH`) | build_independence.rs | completed (as built) |
| Q7 import and verify offers only | src/offers.rs (as built) | offers_dvp.rs, offer_checks.rs | depends on Lane P (canonical maker creation and freeze) |
| Q8 opaque terms follow W23 | see W23 | opaque_commitments.rs | completed for the display; P5/P6 depend on Lane P |
| Q9 entitlements shown, not bound | `UNBOUND_DIVIDENDS` (as built) | review_completeness_dvp.rs | depends on Lane P (P5) |
| Q10 last-eight confirmation follows W2 | see W2 | see W2 | partially (as W2) |
| Q11 exact heights and epochs, approximate durations | src/units.rs (as built); the claim's "Time left" row (W20) | review goldens, refusals_dividend.rs | completed |
| Q12 public partial file exchange | src/partial.rs (as built) | partial_and_outbox.rs, adopt_offline.rs | completed within W12's scope |
| Q13 fresh OS-random preimages in protected records | src/secret.rs (as built) | btc_boundary.rs (preimages), debug_no_secret.rs | completed in the core; protection at rest is the desktop lane's (W10) |
| Q14 License purchase is DvP of an existing License | src/ops/license_dvp.rs (as built) | e2e_license_dvp.rs | completed (as built) |
| Q15 Treasury reserve backing in wallet spending | `context::require_reserve_backing` (as built) | e2e_treasury.rs, refusals_treasury.rs | completed on the wallet side |
| Q16 bonds only for nodes this wallet owns | src/discovery/bonds.rs (as built) | refusals_bond.rs | completed (as built) |
| Q17 post-sale Worker assignment | stated in the sale's review only | review_completeness_dvp.rs | depends on Lane P / later stage: not implemented in the wallet core |
| X1 truthful identity | commit trailers of this lane | - | completed |
