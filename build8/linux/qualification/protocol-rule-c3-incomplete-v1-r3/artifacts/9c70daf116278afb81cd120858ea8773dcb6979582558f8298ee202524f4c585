# Operation envelope and confirmation, version 1

Status: PROPOSED-UNFROZEN, pre-Genesis, candidate 3. Nothing here is qualified, frozen or activated.
Authority: Order of 4 October 2026 (decision P4; P8 for part B); design
`qualification/candidate-3/P-LANE-DESIGN-V1.md` section 1.a (part A) and section 9 (part B), as
amended by `qualification/candidate-3/P-LANE-DESIGN-AMENDMENTS-V1.md` (AM-4, AM-9 m5 and n1).
Implementation: `consensus/src/op_envelope_v1.rs` and the reference plumbing of
`consensus/src/canonical_store_v2.rs` (work package WP-P0). Evidence class of every test named below:
Windows host, software, TEST-VALUE (at most NATIVE-PASS-offline-TEST-VALUE); nothing here ran on
Linux and nothing is physical.

## Part A. The operation envelope

An envelope gives an eligible multiparty value operation an explicit signed inclusion-height window,
a finalized reference context and committed state preconditions that are checked again at
inclusion (Order P4). It is carried INSIDE the unsigned bytes of the operation that adopts it, so
every party signs the exact window, reference and preconditions, and the operation's identifier
changes whenever any of them changes. Retries never extend a window: renewed validity is new
bytes, a new identifier and a new review (Order Q2, W5).

### A.1 Encoding

Canonical CBOR under the repository rules (definite lengths, shortest integer and length heads,
only unsigned integers, byte strings, arrays and null here; no maps, tags, floats or text):

```
Envelope      = [1, first_height:u64, last_height:u64, [reference_height:u64, reference_block:b32], [Precondition...]]
Precondition  = [1, license:b32, [[award_epoch:u64, share:u64, remaining:u64, claims:u64] ...]]          ; LicenseEntitlements
              | [2, license:b32, assignment_sequence:u64, active_worker:null|b32, pending:null|b32]     ; LicenseAssignment
              | [3, treasury:b32, generation:u64, address:b32]                                         ; TreasuryHead
```

`b32` is a 32-byte byte string. A standalone envelope is at most 16,384 bytes, the existing
per-item bound; there is no separate count constant.

### A.2 Codec invariants (enforced by encoding AND decoding)

A value that violates a rule cannot be encoded (so it cannot be signed) and its bytes cannot be
decoded (so they cannot be admitted or executed). Errors are `op_envelope_v1::EnvelopeError`.

| Rule | Requirement | Error |
|---|---|---|
| E1 | `reference_block != 0^32` | `ZeroReference` |
| E2 | `reference_height < first_height <= last_height` | `WindowOrder` |
| E3 | `last_height - first_height <= 10,080` (`EXPIRY_HORIZON`, the existing transfer horizon of `consensus/src/transactions.rs`; no new TTL) | `Horizon` |
| E4 | preconditions strictly ascending by `(tag, subject)`; subject = License, or Treasury identity | `PreconditionOrder` |
| E5 | LicenseEntitlements: License nonzero; accounts strictly ascending by `award_epoch`; each account `award_epoch > 0`, `share > 0`, `remaining <= share`, `(share - remaining == 0) == (claims == 0)`, `claims <= share - remaining`; an empty list is legal ("no live entitlement") | `ZeroSubject`, `AccountOrder`, `Account` |
| E6 | LicenseAssignment: License nonzero, `assignment_sequence >= 1` | `ZeroSubject`, `ZeroSequence` |
| E7 | TreasuryHead: Treasury and address nonzero, `generation >= 1` | `ZeroSubject`, `ZeroGeneration` |

Decoding additionally refuses any non-canonical encoding of a valid value (`NonCanonical`: an
indefinite length, a non-minimal integer or length head), any other structure (`Codec`: wrong type,
array length, version or tag, a hash that is not 32 bytes, bytes after a standalone envelope) and a
standalone encoding above the bound (`Oversize`). Tests: `op_envelope_v1::tests::envelope_codec_rules_and_vectors`
(each rule refused in both directions with its own error; every non-canonical and structural case;
the oversize case) and `op_envelope_v1::tests::expiry_horizon_is_reused_exactly_at_and_one_beyond_the_boundary`
(a span of exactly 10,080 is accepted, 10,081 is refused both ways).

Nested byte strings (amendment AM-9 n1). The repository's canonical walker (`blocks::canonical`)
checks one CBOR item and does NOT recurse into byte strings. `Envelope::decode` therefore performs
its own exact re-encoding check over the bytes it consumed, independently of the enclosing item, and
every kind that carries an envelope inside an unsigned body that is itself a byte string must run
`canonical()` over each nested unsigned/body byte string separately before decoding it.

The License subject is also required to be nonzero for LicenseEntitlements (design 1.a.1 states it
for LicenseAssignment, the design's compile-checked skeleton for both); no real License identifier
is zero.

### A.3 Inclusion at height `H = parent.height + 1`

`Envelope::check_inclusion(parent, history)` re-validates A.2, then:

* W, window: `first_height <= H <= last_height`; otherwise `Future` (`H` below the window) or
  `Expired` (`H` above it). The window is checked before the reference.
* R, reference: if `reference_height == parent.height` the reference must equal the parent block
  itself; otherwise it must equal `history.anchor(reference_height)`, the canonical block hash of
  that height (A.7). Anything else is `ReferenceNotCanonical`. E2 and W imply
  `reference_height <= parent.height`, so a reference always names finalized history. The age of a
  reference is not bounded by consensus.
* A caller whose History holds no anchor can include only an envelope whose reference is its
  parent: it fails closed for any other reference (A.8).

`Envelope::check_preconditions(state, context)` re-validates A.2, recomputes the facts of every
committed precondition from `state` with the fact functions of A.4 and requires EXACT equality;
any difference, including facts that no longer exist, is `Stale(tag)`. Nothing is re-based,
interpolated or substituted. The carrying kind decides the state it passes (its validation point,
design 1.a.5); the trading context `(network, genesis, fingerprint)` selects the Treasury records.

Tests: `op_envelope_v1::tests::window_admits_exactly_first_through_last` (both window ends exactly,
`Future`, `Expired`, window before reference, overflow, re-validation),
`op_envelope_v1::tests::reference_parent_shortcut_history_anchor_and_fail_closed` (parent
shortcut, older reference through a matching anchor, wrong anchor, anchor at another height, empty
History fails closed), `op_envelope_v1::tests::history_anchor_insertion_refuses_a_conflicting_second_value`
(`History::insert_anchor`: a different second hash for a height is `Error::Duplicate`),
`op_envelope_v1::tests::preconditions_compare_exact_facts_and_report_the_stale_tag` and
`op_envelope_v1::tests::assignment_facts_report_sequence_worker_and_pending_id` (scheduling and
activation of an assignment make a committed LicenseAssignment stale). Through real blocks
(production assembler, real hybrid votes, `CanonicalStore::commit`; a rejected block leaves every
store table byte-identical): `op_envelope_v1::store_tests::reference_must_be_canonical_through_real_blocks`,
`op_envelope_v1::store_tests::expired_and_future_windows_reject_byte_identical` and
`op_envelope_v1::store_tests::preconditions_are_checked_again_at_inclusion_through_real_blocks`
(a head advance alone does not invalidate; a claim makes the same bytes stale).

### A.4 Fact functions

Pure functions shared by consensus, the pool and the wallet (the wallet calls them on verified
state only):

* `entitlement_facts(state, license)`: every live award account of the License in the dividend
  ledger, ascending by award epoch, as `[award_epoch, share, remaining, claims]`.
* `assignment_facts(state, license)`: the License's `assignment_sequence`, `active_worker` and the
  identifier of its pending assignment, if any; `Unavailable(2)` when the License does not exist.
* `treasury_head_facts(state, context, treasury)`: generation and address of the trading Treasury
  destination head in that context; `Unavailable(3)` when there is none.
* `assignment_id(assignment) = SHA-256("MUTINY-BUILD8-LICENSE-ASSIGNMENT-ID-V2" || 0x00 || binding)`,
  where `binding` is the unsigned 16-element enrollment binding encoding; signatures are excluded.
  Test: `op_envelope_v1::tests::assignment_identity_is_the_unsigned_binding_hash`. The domain is
  registered PROPOSED-UNFROZEN in `spec/DOMAIN-REGISTRY-V1.json` (test
  `operation_envelope_v1::envelope_domains_are_registered_as_proposed_and_unfrozen`).

### A.5 Signer-side window

`Envelope::from_head(head, validity_blocks, preconditions)` builds `first = head.height + 1`,
`last = first + validity_blocks`, reference = the head, for `validity_blocks` in `1..=10,080`: the
wallet's existing meaning (valid in the next block and the N blocks after it). Anything else is an
explicit refusal (`ValidityBlocks`, `Overflow`), never a silent cap. Wallet defaults are wallet
policy, not consensus. Test: `op_envelope_v1::tests::from_head_builds_the_reviewed_window_and_refuses_out_of_range`.

Units: window bounds and the reference are certified-block heights. MiningEpochs and
ContinuityPeriods are not used by the envelope; a 60-second MiningEpoch is not a delivery interval.

### A.6 Reference heights of a block

`referenced_heights(body)` returns the `reference_height` of every envelope that an item of the
block carries, in either item list, decoding only envelopes; a malformed item contributes nothing
here and is rejected by execution. `envelope_at(raw, index)` reads the envelope that is element
`index` of a definite array. No production item kind carries an envelope yet: the funded wallet
rotation (transaction kind 25), the funded BondCreate (operation kind 24), bond command body
version 3 and trading body version 2 adopt it in their own work packages and add their arm to
`transaction_envelope` / `operation_envelope`. Test:
`op_envelope_v1::tests::referenced_heights_reads_only_envelopes_and_skips_malformed_items`. The
block-level tests use a carrier `[2, 254, Envelope]` that exists only in the consensus crate's own
unit-test build; test `operation_envelope_v1::the_test_only_carrier_is_not_an_item_kind_of_the_library`
shows that the library every other crate links refuses it as an item and extracts nothing from it.

### A.7 The reference History is supplied by the local canonical store

Consensus validates a reference without committing any block-hash history to the StateRoot: the
canonical store supplies the canonical hash of every referenced height through the same
authenticated `History` that already carries historical evidence authority.

* `History::insert_anchor(height, block)` records a canonical block hash (a different second hash
  for the same height is `Error::Duplicate`); `History::anchor(height)` reads it.
* `CanonicalStore::operation_history(height, body)` is the single History builder of every store
  path that executes a block: besides the evidence authorities it inserts, for every height that
  `referenced_heights(body)` returns and that is below `height`, the block hash of the canonical
  row at that height, after checking that it equals that height's finalized anchor. A reference at
  or above `height` is never inserted (it cannot be finalized history of that block).
* `verify_replay` (every open of the store) builds its History inline and inserts the same anchors
  through the same function, so a chain that commit accepted is also accepted on replay.
* `prepare_pending` (production block assembly) inserts the anchors of the caller's operations and
  of every height the pool reports through the `PendingReferences` hook, because the assembler
  trial-adds pool candidates. `mempool_v2` holds no envelope-bearing item, so it reports none in
  every library build; the work package that lets a pool hold one must report its heights. Block
  VALIDATION never uses a pool report: it derives anchors from the block alone.

Retention dependency: reference lookups depend on the complete canonical block-hash prefix
(`spec/CANONICAL-RETENTION-AND-CAPACITY-V1.md`: retention frontier zero, no pruning; row "Canonical
block hash of every height"). Any future archival or pruning path must preserve the block hash of
every height, or envelopes with old references stop validating and replay fails.

Tests: `op_envelope_v1::store_tests::commit_and_replay_share_reference_history` (design test T6: a
block referencing an older height than its parent is prepared, committed and replayed after a
reopen; the same block fails closed without the store's History), and
`op_envelope_v1::store_tests::evidence_history_bounds_the_whole_body_and_its_height` (anchors from
either item list; nothing inserted at or above the block height; bounds).

### A.8 Entry points (amendment AM-4)

| Entry point | History used | Reference anchors |
|---|---|---|
| `CanonicalStore::commit` | `operation_history(height, body)` | yes |
| `CanonicalStore` open (`verify_replay`) | inline, same anchor function | yes |
| `CanonicalStore::validate_round_proposal` | `operation_history` | yes |
| `CanonicalStore::validate_node_work`, `validate_software_coordinator_work` | `operation_history` | yes |
| `CanonicalStore::validate_observation_v2` | `operation_history` | yes |
| `CanonicalStore::evidence_history(height, body)` | `operation_history`; takes the WHOLE body since AM-4 | yes |
| `CanonicalStore::prepare_pending` | caller operations plus the pool hook | yes |
| `CounterVoter::rotate_finalized` (counter-voter migration) | `evidence_history(height, &block.body)` | yes |
| `State::prepare_candidate_v2`, `execute_licensed_v2`, `AuthenticatedRound::validate_proposal`, `BlockEnvelope::verify_execute`, `assembler_v2::prepare`, `continuity_lifecycle_v2::transition` | empty History | none: fail closed, a reference must be the parent |
| `State::execute_hybrid_transfers` (no History parameter) | none | explicit fail-closed check: a transaction that carries an envelope passes only with its parent as reference and an open window |
| the `*_with_history` pass-through functions and `FinalityEvidenceStore::record` | caller-supplied | exactly what the caller inserted; the store paths above supply the anchors |

Tests: `op_envelope_v1::store_tests::entry_point_matrix_accepts_an_older_reference` (one block,
whose envelope references an older height than its parent and which also rotates the only voter's
Continuity key, is accepted by `prepare_pending`, `validate_node_work`, `evidence_history`,
`validate_round_proposal` inside a real counter voter's round whose own votes certify the block,
`commit`, `validate_observation_v2`, the counter-voter migration and `verify_replay`),
`op_envelope_v1::store_tests::prepare_pending_takes_pool_reference_heights_from_the_hook` (pool
items: only the hook supplies the anchor; commit still refuses the block because validation never
trusts a pool report) and `op_envelope_v1::tests::execute_hybrid_transfers_fails_closed_for_an_older_reference`.

### A.9 Replay

The envelope is never replay protection. Replay protection remains the consumed resources of the
carrying kind (spent inputs, sequences, single-fill records, applied-operation records,
compare-and-replace authority or Treasury head). After `last_height` the same bytes can never be
included again.

### A.10 Public vectors

`qualification/operation-envelope-v1-vectors.json` (TEST-VALUE, `synthetic_only`, not production
authorized; 17,741 bytes, SHA-256 `41999e71cbc45e0dc126b8c9b87b4b71cc38355a814799254183a346eb6792db`
as generated). Generator: `BUILD8_EXPORT_OPERATION_ENVELOPE=1 cargo test --offline --locked --lib
op_envelope_v1::tests::export_operation_envelope_vectors` in `consensus/` (it refuses to overwrite an
existing file). Readers: `op_envelope_v1::tests::committed_operation_envelope_vectors_match_the_codec`
(the file is byte-identical to the generator output; every valid vector decodes to its listed fields
and re-encodes exactly; every invalid vector is refused with its listed error) and
`operation_envelope_v1::committed_envelope_vectors_decode_through_the_public_api`.

Seven valid vectors (SHA-256 of the canonical encoding):

| Name | Bytes | SHA-256 |
|---|---|---|
| minimal_parent_reference | 44 | `19219dce2c7ad82f5b128ce4e79f45dad2561b94d4c4f3f8cb7d56953f541c89` |
| single_height_window_with_genesis_reference | 41 | `c52168b2ec56575b403b15b2bccac53b0cd367c45be13d1b84b40542a88281de` |
| horizon_boundary_span_10080 | 47 | `eada00fed3e40628e60f79dbab483467c46b7b3c38fa81052b75f617375ea138` |
| all_three_preconditions | 286 | `d73486f2cd8570cb0aab431172c600b473593d94d981652191686e2e9ebd6c73` |
| no_live_entitlement_and_detached_license | 117 | `faf76ee974143d271e48c678eabc065bf982a4e3718fdb4ce11ed774a2ba29de` |
| integer_widths_four_byte_heights | 51 | `0ad3b5a2385c9c88993be29037d6055b5458aed93f601d701910662dfb85f599` |
| integer_widths_eight_byte_heights_and_amounts | 116 | `d55b68eb857334aec71b70e42942a98d2b6944afd51d8eab5800a9eab9faccac` |

The minimal vector is `8501186518f58218645820` followed by 32 bytes `ab` and `80`. Thirty-six invalid
vectors cover every rule E1-E7 (23 single-rule values) and thirteen non-canonical or structural
encodings.

### A.11 Not covered by this part

The adoption of the envelope by the item kinds (each kind's own window/reference/precondition
checks at its validation point, their real-block tests and the transaction-carried case of the
entry-point matrix), the admission pool and its status codes, and the confirmation index are later
work packages (WP-B, WP-R, WP-T1/T2/T3, WP-POOL, WP-IDX). Part B (durable operation confirmation,
design section 9) is specified in part B below.

## Part B. Durable canonical confirmation (WP-IDX, decision P8)

Implementation: `consensus/src/operation_index_v2.rs`, `canonical_store_v2.rs`,
`store_schema_v2.rs`. This is a derived lookup of successfully executed certified
blocks. It does not change the StateRoot, charge a fee or establish finality by
itself. Certified finality is append-only; pending and unfinalized candidate
inclusions belong to the pool/candidate journal, which must fall back to pending
on an unfinalized reorg. An index record exists only after finality installation.

### B.1 Identity and record

`operation_id(list, raw)` returns `(kind, id)`, with list 0 transactions and 1
operations. Transfers use their existing unsigned id (record kind 1); funded
rotation its unsigned id (record kind 2, transaction wire tag 25); assignment
kind 10 uses `assignment_id` over the actual 16-element enrollment binding;
bond commands 19/20 use their unsigned command id; claims 23 use their body id;
funded creates 24 use their unsigned id; native trading uses its operation body
id (record kind 30). Lifecycle kinds 11, 12, 14-17, 21, 22 use
`domain_hash("MUTINY-BUILD8-BLOCK-OPERATION-ID-V1", CBOR([kind, raw]))`.
Lifecycle identities include signatures; wallet identities exclude them.
Identity derivation does not verify signatures or authorize execution.

Canonical CBOR, at most 512 bytes, strict decoding and exact re-encoding:

```
OperationRecord = [1, op_id:b32, kind:u8, height:u64, block:b32,
                   list:u8, position:u32, wire:b32, receipt]
wire = domain_hash("MUTINY-BUILD8-OPERATION-WIRE-V1", exact_signed_item)
receipt = null                              ; lifecycle
        | [fee:u64, outputs:u32]             ; transfer/funded rotation
        | [license:b32, worker:b32, assignment_generation:u64, effective_epoch:u64]
        | [outcome:u8, lot:b32, sequence:u64] ; Unbond
        | [outcome:u8, lot:b32, sequence:u64, payout:null|b32] ; Withdraw
        | [award_epoch:u64, license:b32, amount:u64] ; claim
        | [lot:b32, principal:u64, fee:u64, change:u8] ; funded create
        | [action:u8, fee_atoms:u64, native_wire:b32] ; trading
```

Receipt arrays are embedded items, not byte strings. Height is positive, block
nonzero, list 0/1, position 0..4095. Change is 0/1. Trading action is 0..6 in
the existing action order; `native_wire` is the exact existing Applied wire
hash, `domain_hash(NATIVE_NAMESPACE || "/signed", raw)`.
Bond outcome is 1 Applied or 2 NoEffectBurned (AM-5). A NoEffectBurned withdrawal
has `payout = null`; Applied has the command's existing payout id. Both record
successful canonical inclusion; NoEffectBurned explicitly grants no payout.
Outcomes come from that block's `Execution.bond_command_outcomes` and are
reproduced by full replay. Payout UTXO existence is never the authority.

### B.2 Store and replay

Schema version 4 adds `operation_index_v2(height,list,position,id,record)`,
primary key `(height,list,position)`, and named nonunique id index. Exact schema
validation counts 20 objects, including both automatic and named indexes.
One record per item is inserted in the same transaction as state, undo,
canonical rows and finality evidence. The legacy transaction confirmations
table remains for existing consumers. Index INSERT failure rolls back installation.

Every store open re-executes the complete prefix from independently trusted
Genesis and compares every record, its SQL columns, and total row count.
Missing, altered, orphaned, height-zero and future rows fail closed.
`rebuild_operation_index(genesis_state)` deletes/rebuilds only this derived
lookup under one IMMEDIATE transaction, validating the rest of the canonical
store by the same complete replay. Failure restores all prior rows.
Version-3 migration creates the table/index, populates via full replay and
sets version 4 atomically. Retired executable formats fail replay; the old
canonical schema/rows/version remain unchanged. Evidence-only stores remain
version 3. No pruning or finality rollback path is added.

Queries: `CanonicalStore::operation_records(id)` returns position-ordered
records; `operation_record_at(height,list,position)` returns the exact position.
A confirmed claim remains recorded after its payout is spent and after reopen.
Status consumers consult this index before input/effect-based fallback.

### B.3 Verification by a wallet replica

`OperationRecord::verify_in_block(body, block_hash)` verifies exact height,
block, list/position, operation identity, signed wire hash and deterministic
receipt fields. For bond outcomes this is structural proof only: the block
bytes alone do not establish whether same-block evidence neutralized a command.
The wallet MUST compare the complete record against its OWN independently
executed `CanonicalStore` index, using `verify_against_replica(replica_record)`.
Neither a remote receipt nor a current payout UTXO proves that outcome.
No remote record may turn Pending/UnfinalizedInclusion into a final result
without this verified-chain comparison.

### B.4 Evidence and remaining consumers

`consensus/tests/operation_index_v2.rs` exercises real-block claims/transfers,
spent payout persistence, exact block/position/receipt refusal, replay/tamper,
atomic rebuild and version migration, rejected certification and index write
rollback. `funded_bond_create_v1::withdraw_with_same_block_evidence_records_no_effect`
checks both execution outcomes against the actual executor in both item orders,
and proves that structural proof alone cannot authenticate the outcome.
These are Windows software TEST-VALUE tests, not Linux, physical or production
qualification. Complete every-kind integrated campaign and the pool/node/wallet
status consumers are separate packages; this part supplies their verified lookup.
