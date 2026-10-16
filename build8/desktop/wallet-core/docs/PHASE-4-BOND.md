# PHASE-4-BOND: bond creation, unbond and withdrawal under the locked timing

Evidence label: **NATIVE PASS (offline, TEST-VALUE)** at most. Implemented is not Qualified;
offline is not physical; simulated is not physical. Everything below was run as software on
Windows with public TEST-VALUE keys and the public synthetic fixtures; no production signing exists
(`PRODUCTION_SECURITY_QUALIFIED` is false and untouched).

## 1. Scope and files

| File | What |
|---|---|
| `src/ops/bond.rs` | handlers for `BondCreate`, `BondUnbond`, `BondWithdraw` (registered through the pre-wired `handler(kind)`), `CreateBundle`, `lot_resource`, `export_unsigned`, `stranded_escrow` |
| `src/discovery/bonds.rs` | read-only lookups: owned lots (`LotView`), owned nodes (`NodeView`), `earliest_withdrawal`, the locked constants |
| `tests/e2e_bond.rs` | real certified blocks (rig), creation refusals against full consensus block execution |
| `tests/refusals_bond.rs` | the refusal table with consensus parity, outbox reservations and reconciliation |
| `tests/review_completeness_bond.rs` | review rows, field and byte mutation, golden snapshots, hostile decoding, `Debug`, timing properties |
| `tests/support/bond_support.rs` | phase-4 test support (high-risk approval flow, JSON-fixture world, rig harness with operations) |
| `tests/golden/bond_{create,unbond,withdraw}_review.txt` | pinned review texts |

No shared file was changed. The request structs were not extended: the existing fields suffice
(`BondCreateRequest { node, node_generation, amount_atoms, nonce }`, `BondUnbondRequest { lot }`,
`BondWithdrawRequest { lot }`). The unbond/withdraw sequence is always derived from verified state.

## 2. Consensus rules mirrored (all read from the code)

* Kinds 18/19/20, domains `BondCreate`/`BondUnbond`/`BondWithdraw` (`bond_ops_v2::Action`).
* Single block: `verify_owner` requires `parent.height + 1 == height && parent.id() == parent_anchor`.
* Locked timing (`bonds.rs`): `MINIMUM_ATOMS = 10,000,000,000` (100 MUT); `LOCK_HEIGHTS = 259,200`
  (4,320 periods of 60 blocks); `EVIDENCE_HEIGHTS = 43,200` (720 periods); `withdrawal_floor(B, U) =
  max(B + 259,200, U + 43,200)`. Heights are certified blocks; durations are shown as approximate at
  the 60 s target interval (`units::approx_blocks`).
* Unbond: lot Active, `sequence == lot.sequence + 1`, `height > created_height`, `height + 43,200`
  without overflow. Withdraw: lot Unbonding, `sequence + 1`, `height >= floor`; payout coin
  `(payout_id, 0)` to `lot.owner`; evidence in the same block settles first (`settle_commands`
  skips a lot it burned); a burned lot cannot be withdrawn.
* Create (`State::apply_bond_creates_v2`, crate-private, mirrored): owner authorized by the
  authorizer through the PARENT wallet book; node is a registry member with a membership control,
  `admission.owner == owner`, control and member generation == the operation's, member physical and
  eligible (parent and next registry), lineage not revoked; funding coin exists in the NEXT state
  with `created_height == height`, not coinbase, owner == `escrow_address()`, atoms >= minimum; lot id
  unused; at most 64 locked lots per lineage. The lot holds the whole funding coin.
* The proposer must hold the funding transaction in its pool (`assembler_v2`, "Hybrid required
  funding missing"); the transfer id excludes signatures, so the creation names `(transfer id, 0)`
  before anything is signed.

## 3. Plans, objects, validity

| Kind | Objects (labels) | Requirements | Reserved (plan inputs = `describe`) | Validity |
|---|---|---|---|---|
| BondCreate | `bond-funding` (unsigned `Transfer`), `bond-create` (unsigned `Operation`) | `Input(i)` per funding coin owner, `BondOwner` (owner) | funding coins + `lot_resource(lot_id)` | created = expiry = valid_only_at = H, bound_to_parent |
| BondUnbond | `bond-unbond` | `BondOwner` | `lot_resource(lot)` | same, H = head + 1 |
| BondWithdraw | `bond-withdraw` | `BondOwner` | `lot_resource(lot)` | same |

The outbox identifier of a bond operation is `domain_hash("MUTINY-BUILD8-WALLET-BOND-OPERATION-ID-V1",
body)`; the body excludes the signature and, for a creation, commits to the funding transaction id.
Signed bytes: the `CreateBundle` encoding for a creation, the operation encoding otherwise.
`export_unsigned(plan)` gives the bytes an offline signer passes to `adopt`.

### The exported bytes and host coordination (open question 1)

A signed creation is queued and exported as ONE `CreateBundle`:
`CBOR [ "MUTINY-BUILD8-WALLET-BOND-CREATE-V1", funding bytes, create bytes ]` (canonical, strict
decoding). `funding` is a hybrid `Transaction::Transfer` encoding (what `Mempool::admit` takes);
`create` is the block operation (what `Preparation.operations` takes). Both are valid only in
block H on top of the reviewed parent. The two parts must reach the SAME proposer for block H:
the funding transaction in its pool and the creation in its operation list. Q1 (no submission path
for operations) means the core can only queue and export the bundle; nothing is delivered.

**Hazard found (not in the analysis):** if the funding transaction is included WITHOUT the creation
(for example a host submits it to a pool and the proposer has not received the creation; the
assembler selects pending transactions greedily), its escrow output is stranded for good: no key
controls the escrow address, and a later creation cannot use a funding output created in an
earlier block. `e2e_bond.rs` demonstrates this on real certified blocks. The wallet therefore
(a) builds the funding window as exactly block H (an included-alone funding can only happen in
block H itself), (b) refuses any bundle whose funding window is wider (stricter than consensus,
pinned by a test that shows consensus accepts it), (c) shows a Danger warning with the
`Irreversible` acknowledgement, and (d) offers `stranded_escrow(bundle, state)` so a host can say
that the principal is stranded (reconciliation itself can only report `InputsSpent`).

## 4. Review rows

All reviews are `high_risk` (typed `CONFIRM xxxxxxxx` phrase) and add the `Conditions` and
`SingleBlockWindow` acknowledgements; irreversible effects add `Irreversible`.

* **Create**: Money: `Moves to escrow` (address labelled "a protocol escrow", typed last-8 check),
  `Returns to this wallet` (change), `Amount`, `Network fee` (one atom per byte of the signed
  funding, payer, signed size), `Total leaving this wallet`, inputs. Conditions: Same block, Single
  block (parent anchor), Bond escrow, Funding output, Lot (id and nonce), Node (id, lineage,
  generation, admitted owner), Minimum, Withdrawal rule, Earliest withdrawal (B + 259,200 and the
  crossover block for the notice; approximate duration), Burn exposure, Weight, Bond authority
  (derived generation and address of the authorizer), Inputs, Fee rule. Effects: spent coins, locked
  principal and earliest withdrawal, burn exposure, no cancel, fee, no revocation, the stranded-escrow
  consequence (all irreversible); change; new lot. Warnings: SINGLE_BLOCK, ESCROW_COUPLING (Danger),
  BURN_EXPOSURE, NODE_EXIT_SCHEDULED, FEE_ABOVE_MINIMUM, TREASURY_FUNDS, BAD_SIGNATURE,
  TEST_VALUE_CHAIN as applicable.
* **Unbond**: no destination; fee `0`, rule "the protocol defines no fee", payer not applicable;
  Conditions: Lot, Sequence (confirmed + 1), Single block, Notice, Earliest withdrawal
  (`max(B + 259,200, U + 43,200)` with U = H), Burn exposure (until U + 43,200), Weight, Bond
  authority. Effects: Active to Unbonding with no way back, notice start, weight stops from U + 1,
  no revocation. Warnings: NO_CANCEL (Danger, `Irreversible`), BURN_EXPOSURE, SINGLE_BLOCK.
* **Withdraw**: destination `The protocol pays` to the lot's original owner; `Amount`; fee as above;
  timing `Earliest height` = the floor; Conditions: Lot (B and U), Sequence, Single block,
  Withdrawal rule (the computed floor), Payout (`payout_id:0`), Slashes first, Bond authority.

Golden snapshots pin all three texts (`tests/golden/`).

## 5. Refusals (each: no signature, no outbox row)

| Condition | Wallet refusal | Consensus | Test |
|---|---|---|---|
| principal below 100 MUT | `BELOW_MINIMUM_BOND` | funding atoms < minimum (block refused) | refusals, e2e |
| zero nonce | `INVALID_REQUEST` (wallet policy) | accepted | refusals |
| unknown node / wrong generation / not physical / not eligible / owner != admitted owner (bytes) | `NODE_NOT_ELIGIBLE` | `UnknownSigner` / `UnqualifiedPhysical` | refusals, e2e |
| node not owned by this wallet (plan, Q16) | `NOT_REQUIRED_SIGNER(bond owner)` | `UnqualifiedPhysical` | refusals, e2e |
| 64 locked lots on the lineage | `INVALID_REQUEST` | `Capacity` | refusals |
| lot identifier already used | `REPLAY` | `Duplicate` | refusals, e2e |
| lot reserved by a queued operation | `RESERVED_INPUT` | n/a (wallet) | refusals |
| funding names another output / transaction, pays another address, not same block, window wider than the block | `SAME_BLOCK_FUNDING_MISSING` | `WrongAnchor` (window: accepted, wallet stricter) | refusals, e2e |
| escrow paid twice, change not to this wallet (adopt) | `MALFORMED` | accepted (wallet policy) | refusals |
| parent anchor / height not the next block | `STALE_HEAD` / `WINDOW_CLOSED` / `WINDOW_NOT_OPEN` | `WrongAnchor` | refusals, e2e |
| Genesis / fingerprint / network | `WRONG_CONTEXT` (network of an operation: not decodable, `UNKNOWN_OPERATION`) | `WrongGenesis` / `WrongFingerprint` / `Codec` | refusals |
| rotated-away key, owner not resolved by the authorizer | `STALE_AUTHORITY` | `WrongGeneration` | refusals |
| Treasury authority on an ordinary profile | `TREASURY_PROFILE_REQUIRED` (all three kinds) | n/a | refusals |
| wrong sequence | `WRONG_SEQUENCE { expected }` | `StaleSequence` | refusals |
| unbond of an Unbonding lot / withdrawal of a Withdrawn lot | `REPLAY` | `StaleSequence` | refusals |
| unbond of a Withdrawn lot | `INVALID_REQUEST` | `StaleSequence` | refusals |
| withdrawal of an Active lot | `INVALID_REQUEST` | `StaleSequence` | refusals |
| burned lot | `INVALID_REQUEST` ("burned") | `StaleSequence` | refusals, e2e |
| unbond at or before the lock start | `NOT_YET_ELIGIBLE { height: B + 1 }` | `InvalidCounter` | refusals |
| withdrawal before the floor | `NOT_YET_ELIGIBLE { height: floor }` | `InvalidCounter` | refusals, e2e, properties |
| unknown lot / owner other than the lot's | `INVALID_REQUEST` | `WrongAnchor` | refusals |
| payout coin already exists | `REPLAY` | n/a | refusals |
| already signed (adopt), another wallet (adopt), cancel of an unbond | `MALFORMED` / `NOT_REQUIRED_SIGNER` / `CANCEL_NOT_AVAILABLE` | n/a | refusals |

## 6. Verification through consensus code

* Funding: `Transfer::verify(genesis, fingerprint, next, coins, wallets)` (BOTH halves required).
* Creation: `Operation::verify_owner(parent, wallets)`.
* Unbond and withdrawal: `Operation::verify_command(parent, wallets, lot)`; before signing the
  wallet also runs `Lot::start_unbond` / `Lot::withdraw` on a copy of the lot.
* Tests additionally use `settle_commands`, `continuity_lifecycle_v2::transition` and full candidate
  execution (`State::prepare_candidate_v2`) as oracles.

## 7. Outbox and reconciliation

Creation: Confirmed(H) when the lot exists with `created_height == H`; `InputsSpent` when a lot
with that identifier was created at another height (the nonce was used by another creation) or a
funding coin is gone; otherwise Pending until H, then Expired. Unbond: Confirmed(H) when
`unbond_height == H` and the lot sequence reached the operation's; `InputsSpent` when the sequence
was consumed by another operation or the lot was burned. Withdrawal: Confirmed at the payout coin's
height, or at H when the lot is Withdrawn at H (payout already spent). `forget` releases the lot
and coins; nothing revokes signed bytes.

## 8. Assumed defaults

Q1 (queue and export only; the bundle is the exported unit), Q2 (re-review at every new head; a
plan is invalidated by any new block), Q4 (unbond and withdrawal: `FeeRule::None`), Q6 (signing only
behind the TEST-VALUE gate in tests), Q10 (hex and typed last-8 check, including the escrow), Q11
(heights plus approximate durations), Q16 (bond only for nodes whose admitted owner this wallet
controls, read from verified `membership_v2` and the registry).

Wallet policies stricter than consensus: funding window exactly the creation's block; funding output
index 0, at most one change output, change to this wallet (adopt), the escrow paid once; non-zero
nonce; the Treasury-profile guard on all three kinds.

## 9. Open questions and decisions for the Architect

1. A funding transaction included without its creation strands the principal. Proposal: a consensus
   rule rejecting any transaction output to a bond escrow address unless the same block contains the
   matching creation, or at least a node pool policy that never selects such a transaction without
   the creation; until then the bundle-only export and the warning stand.
2. Delivery (Q1): a transport or node path that hands the bundle to the proposer of block H only.
3. Reputation detail: the review states the module-doc rule (Active from B + 1, Unbonding excluded
   from U + 1) and promises no weight. `reputation.rs` adds `atoms * (1 + age in 60-block periods) /
   10^10` per Active lot to the score; should the review state that formula?
4. Dedicated refusal codes for lot states (burned, not Active, not Unbonding, unknown) and an
   acknowledgement for the escrow coupling (both shared changes; see the phase report).

## 10. Analysis vs code

* The bond owner is the node's ADMITTED owner AddressID (whatever generation authorized the
  admission), not necessarily a generation-1 address; it is immutable for the lot.
* A withdrawal whose lot is burned by evidence in the same block is accepted and has no effect
  (`settle_commands` skips it); it is not an error.
* The stranded-escrow hazard (section 3) is not in the analysis.
* `membership_v2::Book::controls()` is crate-private; nodes are enumerated through the continuity
  registry, which is complete for bondable nodes (a creation needs both). No accessor is missing.
* In the single-member rig, a state whose member is not physical is refused by consensus before the
  bond rule (`UnsupportedOperation` from the work context); the not-eligible case reaches the bond
  rule (`UnqualifiedPhysical`).
