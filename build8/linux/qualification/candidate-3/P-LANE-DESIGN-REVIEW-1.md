INDEPENDENT ADVERSARIAL REVIEW: qualification/candidate-3/P-LANE-DESIGN-V1.md (commit 7bc4687, read at a9fbf8c)
Reviewer: Claude Opus 5.5, independent (did not write the design). Scratch worktree D:/Mutiny/build8-pdrev (detached a9fbf8c; no .rs/.c/.toml
difference from the design's base d56064b). Evidence class: design review by reading. The only execution: a copy of the design's scratch skeleton
(hashes match Appendix A) rerun on this Windows host: 9/9 passed, sizes identical (mocked signatures), plus one review mutant (section 4).
Nothing in the repository was compiled or run; nothing on Linux; nothing physical. No disagreement found between the brief and the Order.

1. VERDICT
P1  SATISFIED  2.1-2.9: one kind-24 item applied in one function; binds lot/node/owner/inputs/principal/change/fee/context/window/id; no escrow; 100 MUT; B = actual H.
P2  SATISFIED  3.2-3.8: one commitment under WalletRotate/Possession/Transaction, acyclic, sponsor bound; stripped/substituted/standalone replay fail (gaps: MAJOR-6, m6).
P3  SATISFIED  4.1-4.4: complete V2 enumeration, codec refusal, null absence, no implicit burn, legitimate zeros listed (test layering wrong: section 4).
P4  PARTIAL    1.a/5.1 semantics satisfied (signed window, finalized reference, preconditions, retries never extend, no TTL, units); delivery machinery
               defective: BLOCKER-1, BLOCKER-2, MAJOR-1, MAJOR-2, MAJOR-5.
P5  SATISFIED  6.1-6.8: full entitlement list + assignment facts compared after epoch events, before claims; intervening events tabulated (m2 assembly divergence).
P6  SATISFIED  7.2-7.7: Treasury records bound to T; R2 approved by T's current key, routed only to T's current generation; history/frozen/reserve kept (m10).
P7  PARTIAL    8.2-8.6 format, vectors, test-only adapters complete; "maker creation ... in the product path" has no implementable key custody (MAJOR-4).
P8  PARTIAL    9.x derived index, replay rebuild, no StateRoot change, claim never InputsSpent; receipts wrong for neutralized bond commands (MAJOR-3); m1.
P9  SATISFIED  10.1-10.6: lineage authorize in trading debit, kind 24 and kind 25; recipient vs fee payer kept apart; reserve invariant at every root.
Q4  SATISFIED  11.1: explicit narrow FeeRule::None for kinds 19/20 only; sequence, one command per lot per block, window and pool bounds kept.
Q15 SATISFIED  10.4/10.7: existing per-StateRoot backing invariant covers every new spend path; wallet policy stated for Lane W.
Q17 PARTIAL    sale cancels committed pending; reward of H to parent owner; node gate closes old sessions; (b) misses embedded C (MAJOR-5); (d) unbounded (m4).
W22 SATISFIED  5.1: validity_blocks read and applied for DvP and bond create, out-of-range refused, the reviewed window is what is signed.

2. FINDINGS
BLOCKER-1 (5.4 pool capacity + 5.3 relay; P4 delivery). "MAX_LIFECYCLE_ROWS 65,536 reused" inherits mempool_v2's rule: admission fails when count(*) over ALL
 rows, terminal ones included, reaches 65,536 (mempool_v2.rs:401-408); no code deletes lifecycle rows (only inputs_v2/rotations_v2, 307-308); terminal
 rows may not be evicted (CANONICAL-RETENTION-AND-CAPACITY-V1 L14 "Never evict silently"; HYBRID-TRANSACTION-ADMISSION-V2 L37). The design adds every
 operation class and relays each admitted item to all pinned peers. Scenario: items that expire unincluded cost nothing (fee-free claims: a new claim
 id each time a 1-block window lapses; transfers never selected); each admission leaves a permanent row at EVERY node via relay; after 65,536 lifetime
 admissions per node (honest load of ~10 items/block reaches it in ~6,500 blocks) every node returns Capacity forever: P4 delivery stops network-wide.
 Also 5.4 repeats "the admission check" (signatures included) for every pending row at every height: at the 64 MiB cap (~18,000 transfers) that is
 at least ~18,000 hybrid verifications per block on every node (relay makes it network-wide). Amendment: cap only PENDING rows; specify an archival rule for terminal rows
 (e.g. drop CONFIRMED once the canonical index holds it, EXPIRED/CONFLICTING/REJECTED after a fixed local retention) as a spec change brought to the
 Architect against L14; per-peer admission budgets for relayed items; cache signature validity by (id, wire hash), re-run only state checks.
BLOCKER-2 (5.3 relay). The per-peer ObjectQueue holds 8 objects / 4 MiB for BOTH directions: reserve() counts every row (objects.rs:329-343) and an incoming
 HAVE also reserves (object_link.rs:484-490); the transport's own test shows the 9th enqueue fails with Error::Limit whatever the kind (object_link.rs:65-78).
 Votes (kind 4), proposals (8) and certified blocks (3) use the same queue (hybrid_peer_worker_v2.rs:124-130). Scenario: an attacker streams valid cheap
 transfers to one node; each is relayed (up to 16 KiB, 117 fragments) to every peer; 8 relays per link make vote/proposal/block enqueues fail on that
 link until they drain, refilled continuously: rounds miss votes, finality stalls. The design only says "a full queue drops the relay". UNCERTAIN: no
 production vote sender exists yet, but no retry policy beats a continuously refilled 8-slot queue. Amendment: separate per-peer relay queue/budget or
 reserved slots for kinds 3/4/7/8, relay by HAVE announcement with pull, per-peer relay rate limit; test that votes still flow under relay load.
MAJOR-1 (5.5 assembly). Trials in (class, id) order with MAX_PREVIEWS = 128 (assembler_v2.rs:13, 165-168): every class-0 transaction is tried before any
 class-1 operation, so with >=128 pending transfers no claim, DvP, hash lock, Worker assignment, bond create or command is ever tried; ids are hashes
 of unsigned bytes, so anyone grinds small ids. Fee-free claims can expire unincluded; the buyer's assignment (Q17 c) can be starved. Amendment:
 per-class trial budgets/interleaving with a reserved share for fee-free structural kinds (11.1), fee-per-byte then id ordering within a class (no new
 fee); amend HYBRID-TRANSACTION-ADMISSION-V2 L41; test 200 pending transfers + 1 claim -> claim included.
MAJOR-2 (1.a.3 History, item C.1). The six internal operation_history calls are listed correctly, but the public wrapper CanonicalStore::evidence_history
 (height, operations) (canonical_store_v2.rs:1226-1239) takes operations only and production code counter_voter_v2.rs:420-430 (rotate_finalized_inner)
 re-validates a finalized block through it. Scenario: finalized block with a FundedRotation (transactions list) whose reference_height < parent.height;
 commit accepted it; the counter voter's history lacks the anchor -> ReferenceNotCanonical -> WrongAnchor -> rotate_finalized_inner fails, so the
 counter voter cannot rebind to its new Continuity signing context. execute_hybrid_transfers (execution.rs:637-649, public, no anchor/History) is not addressed either. Amendment: evidence_history
 takes the whole body; fix counter_voter_v2.rs; define kind-25 handling in execute_hybrid_transfers; extend T6 to a matrix: one block with an old reference
 accepted by commit, verify_replay, validate_round_proposal, validate_work_custody, validate_observation_v2, prepare_pending (caller and pool items) and
 the counter-voter migration.
MAJOR-3 (9.2/9.6 receipts). "Receipt ... derivable from the item bytes alone" is false for bond commands: settle_commands checks a command against the
 PARENT lot, then skips it when same-block evidence burned the lot (bond_ops_v2.rs:383-391; HYBRID-BOND-SETTLEMENT-V2 L19). Scenario: block H holds
 equivocation evidence burning lot L and the owner's Withdraw for L; the block is valid, no payout coin exists, yet the index row reports FinalizedSuccess
 with a payout at OutPoint(payout_id,0); verify_in_block recomputes the same bytes-only receipt and 9.6 makes it permanent: the wallet shows money that
 never existed. Amendment: record an execution outcome (Applied / NoEffectBurned) for kinds 19/20 at commit, check it in verify_replay, require it in
 verify_in_block; test withdraw_with_same_block_evidence_records_no_effect.
MAJOR-4 (8.2/8.4 P7 key custody and role). Offers stay signed by a Role::Transport key under Domain::TransportInitiator and wallet-core is to sign them
 "through a typed capability". wallet-core states the wallet NEVER holds that key and no (kind, purpose) reaches a transport domain, enforced by test
 (offers.rs:9-11; authorize.rs:1250-1306); the trading spec that owns the format proposes "7 Trade | ... never reuse Role 5 production transport keys"
 (D1 packet L173). The design amends D1 section 10 without surfacing this. Offer payloads cannot collide with the 64-byte handshake transcript signed
 under the same domain (handshake.rs:287), but custody separation is lost if a node transport identity signs offers. Amendment: put the choice to the
 Architect: (a) Trade role/domains per D1 section 10 (crypto-v2 change), or (b) a dedicated per-wallet trade key under Transport/TransportInitiator,
 never a node identity, with its generation, storage and the authorize.rs API change specified for Lane W.
MAJOR-5 (11.2 b, 5.2 transport). Dropping the valid_until_height clause from Rust matches_current (worker_context_v2.rs:124) leaves the embedded C Worker
 channel enforcing it: live() refuses when until_height && height > until_height (transport-v2/embedded/worker_frame_v2.c:33-35; init stores until,
 18-29). Worker sessions still end at valid_until_height on the device. Transport kinds/limits are hardcoded in embedded/object_control_v2.c:14-15, 38
 (kinds 1..8, kind 1 = 2 MiB) while TRANSPORT-OBJECTS-V2 L135/L178 require Rust and embedded C to agree. Amendment: put both C files and
 worker_frames_c_tests.rs into WP-Q17/WP-NODE (or specify that the firmware passes until=0); add C/Rust agreement tests for kinds 9-11 and kind 1 at 16 KiB.
MAJOR-6 (15 work packages). Unowned files that must change: consensus/src/settlement.rs (funded-rotation settlement proofs use transfer() and
 verify_signatures, 196-238; its vector is listed in 12.3 but the file is not), consensus/src/counter_voter_v2.rs (MAJOR-2), node/src/candidate_journal_v2.rs
 (status 5.6), both embedded C files, node/src/trading_service_v1.rs (builds tr::Meta with created/expiry at 789-795; 10 more sites in its two test
 modules). Landing G1 breaks
 node, wallet-core and desktop builds (Transaction::Rotate, Action::Create/escrow_address, trading body v1) until unowned work lands. WP-B (create-fee
 pre-sum into the trade_fees argument) and WP-R (History/anchor arguments) edit the same call execution_v2.rs:227-234; WP-T edits :216 of the same
 function. WP-T is XL (P3+P4+P5+P6+P7+P9 in one 3,353-line file). Amendment: name owners; land each consensus WP with its downstream compile fixes or
 shims; one owner for prepare_candidate_with_recovery_v2; move offers to a new trading_offer_v2.rs and split WP-T into T1 body v2/envelope/P3/P9,
 T2 P5+Q17(a), T3 P6, T4 P7.
MINOR m1 (9.3) "schema count 17 to 19" is wrong: a rowid table with PRIMARY KEY(height,list,position) gets an automatic index, as composite-key undo_v2
 does (store_schema_v2.rs:80-93 checks sqlite_autoindex_undo_v2_1): table + autoindex + named index = 20 (19 only WITHOUT ROWID). The user_version check
 (:61) is shared by evidence-only stores.
MINOR m2 (5.5) BlockBody::encode rejects any non-acknowledgement after an ack (blocks.rs:88-107): appended pool operations make every operation trial
 fail and "failing trial is skipped" silently excludes them; insert before the ack run. preview_fees runs trades on the PARENT state (trading_host_v1.rs:
 141-156; assembler_v2.rs:98-99, where a preview failure aborts the whole preparation) while P5 compares after advance_dividends: use declared meta.fee.
MINOR m3 (5.4) Which kinds reserve which resource tags is unspecified; if a HashLock with a TreasuryHead precondition takes tag 7, one pending taker of
 any frozen Treasury offer blocks every other taker and R2. Third-party griefing otherwise none found (each tag needs the owner's or maker's signature).
MINOR m4 (11.2 d) effective_epoch > inclusion_epoch is unbounded; with one pending assignment per License (license_book_v2.rs:206-216) and no cancel or
 replace, a far-future epoch (wallet error, stolen owner key) blocks reassignment until then. Identify the missing bound (Order P4) or add a replace rule.
MINOR m5 (1.a.3) Unbounded reference age makes every canonical block hash a permanent validation dependency; add a row to CANONICAL-RETENTION-AND-CAPACITY-V1.
MINOR m6 (3.4, 13) "Unsigned body plus any subset of signatures" has no encoding: the FundedRotation/BondCreate codecs need non-null role signatures.
 Define a partial object (per-slot null) and a read-only preflight (all checks except missing signatures) for sponsor and new-key reviewers (W12).
MINOR m7 (5.2) 64 FinalizedSuccess entries are about 64 x 250 B, near the 16,384-B StatusReport bound; state a per-record maximum or use 32 entries.
MINOR m8 (9.3) The v3->v4 migration can only succeed for stores without retired formats (kind 18, [2,21] wrapper, trading body v1, command v2, zero
 destinations), which fail verify_replay under the new rules; say such stores are refused.
MINOR m9 (7/10) Claims spend Treasury coins implicitly, oldest generation first (dividend_claim_v1.rs:453-475); a pending R1/R2/Treasury spend lists explicit
 inputs that a claim can consume, invisible to the pool's input keys. Draw Treasury spends from the newest generation; test claim + R1 in one block.
MINOR m10 (7.4) P6 restore evidence is a Treasury-tool duty with no artifact or verifier defined; specify what Lane W must record (plan id, re-derived key).
MINOR m11 (2.3) Kind 24 pays 1 atom/byte also for authorization bytes that kind 18 carried fee-free; state that this is the existing rule, not a
 "bundle surcharge" (UNCERTAIN whether the Architect sees a fee change).
NIT n1 The walker does not recurse into byte strings (blocks.rs:17-19): state that every nested unsigned/body string is separately canonical()-checked.
NIT n2 LicenseEntitlements omits the License dividend status; no production operation changes it today.  NIT n3 A cancelled pending Worker key is not
 tombstoned (only workers/pending are checked, license_book_v2.rs:206-216).

3. CITATION CHECK
About 280 file:line citations checked at a9fbf8c, including every item of brief B (executor order execution_v2.rs:129-274, blocks::canonical 5-51,
operation_kind 194-231, Transaction::decode 95-122, mempool_v2, evidence_history_v2::History, store commit 1367-1412 and replay 691-863,
WalletBook::authorize 145-157, trading debit 2172-2209 / apply_one 2379-2727 / verify_offer 1052-1120, Book::transfer_candidate 48-80, advance_dividends
293-301, claim 307-442, activate_due 228-260, worker channel 137-156, ObjectKind 11-57), the 14 cited tests and the cited spec lines. Wrong: 1 (schema
count, m1). Incomplete: 1 (operation_history call-site list omits the evidence_history caller, MAJOR-2). Not checked in detail: objects.rs 88-177.

4. TESTS, WORK PACKAGES, SPEC
Order evidence map: stripped (14.1/14.2), sponsor substitution (14.2), zero destinations (14.3), changed entitlements (14.5), forged succession (14.6),
expired windows (14.4/14.2), head advance (14.2/14.4), actual-inclusion timing (14.1/14.4), confirmation after payout spend (14.8) are mapped.
Missing: P2 historic-generation inputs (payer 0 and 1); R1 FundedRotation spending reserve; kind-24 input created at H (mutant "<" to "<=" survives);
trading Applied and claim sequence replay under envelopes; the entry-point matrix (MAJOR-2); neutralized command (MAJOR-3); pool lifetime, relay vs
votes, class starvation, ack ordering (BLOCKER-1/2, MAJOR-1, m2); same-block FundedRotation + kind 24 of one owner, R1 + R2, claim + R1; kind 24 without
Continuity and in a recovery block; C until_height; far-future effective epoch.
Vacuous or unreachable: 14.3 trading zero-destination "real block" rows: a reserved item failing NativeOperation::decode makes BlockBody::encode fail
(trading_host_v1.rs:37-43, blocks.rs:91), so no block exists and NativeError::Bounds plus the defensive credit check (4.3) are unreachable; a mutant
deleting that check survives. 14.5 "exact NativeError at prepare_batch on the same parent state": prepare_batch uses the parent as tentative
(trading_v1.rs:2313-2328), so own-epoch expiry/new-award staleness cannot be reproduced there. 14.4 reference_must_be_canonical builds History by hand
and passes even if the store never inserts anchors. Skeleton transaction_domain_payload_shapes_are_pairwise_disjoint: its loop condition is implied
by the following assert_ne!(a, b); review mutant (funding payer encoded as bytes = claim shape, one explicit assert removed) still passes, so
disjointness rests on three hand-picked asserts.
Work packages: MAJOR-6. Also WP-B and WP-POOL both edit assembler_v2::prepare_with_recovery (sequential, acceptable); WP-IDX needs execution outcomes
from WP-B (MAJOR-3), a hidden prerequisite.
Spec coherence: surfaced with adequate resolution: FUNDED-WALLET-ROTATION-V1 L15-16 (new key funds) vs 3.5 (old key); D1 L121/L125 and system L196
("fail closed rather than being silently cancelled") vs 6.6 committed cancel; HYBRID-BOND-SETTLEMENT-V2 L7/L23 (4096-B envelope, escrow) vs kind 24
(state the 4096-B change); LICENSE-ASSIGNMENT-STATE-V2 L19 vs 11.2 d (needs a bound, m4); WORKER-SESSION-CONTEXT-V2 L40 vs 11.2 b (C side, MAJOR-5).
NOT surfaced: D1 L173 Trade role (MAJOR-4); TRANSPORT-OBJECTS-V2 L135/L178 C agreement (MAJOR-5); CANONICAL-RETENTION L14 and ADMISSION L37
(BLOCKER-1); ADMISSION L41 ID-order selection (MAJOR-1). No locked economic rule silently changed.
Other checks, none found: C.2 phase order (all phases deterministic; trading and bond-create use the parent WalletBook, payments the running one, as
HYBRID-BOND-SETTLEMENT-V2 L23 states); C.3 kind-24 fee pre-sum (exact conservation in the bond-create phase plus all-or-nothing: no mint or loss);
C.4 partial state (index rows inside record_with_recovery's transaction; pool separate); C.5 walker (null/arrays/depth fine). D: Domain::Transaction
payloads (Transfer array(2) bytes,uint; trading array(4); claim array(3) bytes,bytes,bytes; freeze array(14); new funding array(3) bytes,bytes,uint
with distinct labels) and role payloads vs Rotation array(9), kind-18 array(10), command v3 array(9) are byte-disjoint under SHA-512(domain||0||payload)
(crypto-v2 lib.rs:159-172); ids exclude signatures, so malleability only yields pool conflicts with identical effects. E: no Order section 8
invariant weakened (m11 aside). Lane W (J): m6, MAJOR-4, plus a signed_len helper (fee >= complete length) and a "valid at my tip+1" preflight.

5. NOT VERIFIED
No repository build or test (design review; machine saturated). FN-DSA padded-signature canonicality in fn_dsa (malleability harmless here, UNCERTAIN).
Future vote-send retry policy (no production caller). Firmware caller of b8_worker_channel_init (outside this repository). Spec sections beyond those
cited; DECISION-LEDGER-V1.md not read. Nothing on Linux, nothing physical; the skeleton rerun is Windows-host software evidence with mocked signatures.
Citations hold at a9fbf8c (= d56064b source). integration/candidate-3 has since advanced to cae6e50 (Treasury-schema merge, not mine); not re-checked
there. Scratch worktree D:/Mutiny/build8-pdrev removed; no branch or other worktree modified. Files: this REVIEW.md, mutant_loop.pl, skeleton-copy/.
