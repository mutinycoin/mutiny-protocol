# V2 license assignment and canonical state

Candidate implemented; production runtime remains inactive. This composes the
qualified EnrollmentV2 owner/Worker signatures with the separate node-role hybrid
coordinator descriptor. There is no Ed25519 acceptance or fallback in this path.

Assignment bytes are canonical CBOR `[2, 10, EnrollmentV2Bytes,
OwnerAuthDescriptorBytes, NodeDescriptorBytes]`, bounded to 8 KiB. The existing
EnrollmentV2 signatures commit hashes of the exact owner and coordinator
descriptors along with network, Genesis, fingerprint, license, Worker public key
and ID, hardware MAC, configuration/assignment generations, effective epoch and
expiration height. The outer descriptors resolve those signed commitments and
cannot be substituted. The reference assignment is 5,679 bytes.

Parent-state WalletBook resolves current ownership, including old addresses after
wallet rotation. A newly submitted assignment cannot use a retired owner key.
Assignment generation must be the parent LicenseRecord generation plus one using
checked arithmetic. Ordinary assignment expiration is checked at inclusion height
H; activation is the validated candidate mining epoch plus one. Authorization
does not itself create a license or grant Continuity weight.

The two-phase Genesis constructor requires exactly twelve assignments, twelve
independently supervised expected bindings and twelve canonical bootstrap license
records in index order 0..11. It checks their derived LicenseIDs, common owner and
issuance identity, zero issue height, no previous active Worker, and all ordinary
hybrid/Worker possession signatures. Genesis binding configuration and assignment
generations are 1, effective epoch and expiration height are 0. Worker IDs, public
keys and physical MACs must be distinct. Hardware qualification remains a separate
ceremony prerequisite; this verifier does not turn a synthetic fixture into one.

Canonical V2 Book records use these reserved typed wrappers:

| Kind | Canonical value | Key domain, followed by 00 and identifier |
|---|---|---|
| 40 | `[2,40,LicenseRecordBytes]` | `MUTINY-BUILD8-LICENSE-STATE-KEY-V2`, LicenseID |
| 41 | `[2,41,AssignmentBytes,last_accepted_ticket]` | `MUTINY-BUILD8-WORKER-STATE-KEY-V2`, WorkerID |
| 42 | `[2,42,AssignmentBytes]` | `MUTINY-BUILD8-PENDING-BIND-KEY-V2`, LicenseID |

Keys use SHA256. LicenseRecord's existing nine-field byte encoding is retained
inside the explicit V2 wrapper; its owner is an AddressID resolved through the
hybrid WalletBook. Record decoding is bounded to 8,448 bytes and the total map is
bounded by the existing 10,000,000-record consensus limit. Wrong keys, malformed
reserved tags, missing active Workers and mixed V1/V2 license state reject.

Pending assignments and ticket high-water marks enter StateRoot V2 and survive
checkpoint reconstruction. All due activations validate before mutation. An epoch
moving backward cannot undo an activation. Retired Worker records remain history
and cannot authorize current work; their public keys cannot silently be reused.
A fresh Worker starts its own ticket counter at zero. A valid hybrid authority
must match the canonical active assignment and exceed that counter. Updating a
tentative counter does not establish PoW, execute monetary operations or finalize
a block. The chain executor must atomically install the full certified state.

Evidence: `license-book-v2-rust-v1.log`,
`license-wallet-state-v2-regression-v2.log`, `license-assignment-v2-python-v1.json`,
`license-assignment-v2-c-v1.log`, `license-book-v2-python-v1.json`,
`license-book-v2-c-v1.log`. Independent Python reproduces the post-reassignment
root with 12 licenses, 13 historical/current Workers and 25 inclusion proofs.
Independent C verifies all 13 corresponding owner FN-DSA authorizations.

Remaining: complete hybrid licensed execution and operation dispatch, canonical
node replay/checkpoint deployment, miner coordinator verification and sessions,
final fingerprint and ceremony integration. The new records and pure validators
do not activate production mining or seal Genesis.

## Amendment WP-Q17 (Build 8 candidate 3, 2026-10-04): post-sale Worker assignment

Integration copy; identity in `spec/imports/LICENSE-ASSIGNMENT-STATE-V2.md.identity.txt`. Everything above this
heading is the unchanged imported text. Authority: Order Q17; Restart Order L64; P-LANE-DESIGN-V1 6.6 and 11.2;
P-LANE-DESIGN-AMENDMENTS-V1 AM-7, AM-10, AM-11. Evidence: Windows-host software tests only
(NATIVE-PASS-offline-TEST-VALUE); nothing here ran on Linux or hardware.

1. Delivery window (the rule above is kept: amendment AM-10). The effective epoch is exactly the validated
   inclusion epoch plus one (`consensus/src/license_assignment_v2.rs`, `Assignment::verify_next_epoch`). An
   assignment can therefore be included only in blocks of epoch `effective_epoch - 1`, at heights up to its
   `valid_until_height`; once that epoch has passed it never becomes valid again and the owner re-signs.
   `DeliveryTerms::at(license, height, epoch)` (same file) states the exact terms consensus enforces
   (generation = parent sequence + 1, effective epoch = inclusion epoch + 1, deadline at least the inclusion
   height) for pools and wallets; `DeliveryTerms::admits` checks a binding against them without signatures.
   Known limitation: one MiningEpoch (nominally 60 s, not a guaranteed delivery interval) to deliver an
   assignment. A longer window needs the identified missing bound, the maximum lead L of `effective_epoch` over
   the inclusion epoch (unit: MiningEpochs), an Architect decision (amendments, question C.4); none is invented.
   Equal, earlier, two-epochs-ahead and far-future effective epochs are rejected, activation is never early,
   and a late delivery is rejected while its re-signed form is included: test
   `assignment_effective_epoch_is_exactly_the_next_inclusion_epoch` (consensus/tests/license_assignment_v2.rs,
   verifier and real executor blocks, byte-identical state after each rejection).
2. `valid_until_height` is the inclusion deadline only: it does not end an active assignment or its Worker
   sessions (WORKER-SESSION-CONTEXT-V2, amendment WP-Q17; transport Rust and embedded C).
3. A License sale cancels the old owner's pending assignment (Restart Order L64: "old-owner pending assignments
   become invalid"). The Book's sale hook (`consensus/src/license_book_v2.rs`, `Book::transfer_candidate`) no
   longer refuses a sale while an assignment is pending. After every other transfer check it removes the sold
   License's pending assignment (its kind-42 record disappears; no new record kind), detaches the active Worker
   (its kind-41 record and key stay as history) and sets the assignment sequence to the signed next value. It
   returns the cancelled assignment's canonical id, SHA-256 of `MUTINY-BUILD8-LICENSE-ASSIGNMENT-ID-V2`, a zero
   byte and the unsigned binding bytes (`Binding::bytes`, the 13 signed fields, no signature; registered
   PROPOSED-UNFROZEN in `spec/DOMAIN-REGISTRY-V1.json`), which the caller compares with the pending assignment
   the sale committed to. The cancelled assignment never activates; its exact bytes are rejected if offered
   again (generation stale: WrongAnchor), and the former owner cannot authorize a new one (WrongGeneration).
   Tests (consensus/src/license_book_v2_sale_tests.rs):
   `sale_cancels_the_pending_old_owner_assignment_and_returns_its_canonical_id`,
   `refused_sale_keeps_the_pending_assignment_and_the_book_byte_identical`,
   `cancelled_assignment_yields_no_work_context_and_no_reward`,
   `sale_without_pending_assignment_returns_none_and_reassigns_only_that_license`,
   `assignment_due_before_the_sale_is_detached_as_history_not_cancelled`,
   `assignment_id_domain_is_registered_proposed_unfrozen`.
   Interim, until the trading DvP commits a `LicenseAssignment` precondition (P-LANE-DESIGN-V1 6.1 and 6.6; WP-T
   T2): the current DvP body commits no pending assignment, so the trading adapter
   (`consensus/src/trading_v1.rs`, `transfer_license_candidate`) treats any cancelled id as a mismatch and the
   sale fails closed with `NativeError::LicenseLocked`, as before this amendment (D1 packet L121/L125). Test:
   `sale_with_a_pending_assignment_fails_closed_until_the_sale_commits_it`
   (consensus/tests/license_sale_assignment_v1.rs, real certified blocks).
   Not tombstoned (design review n3): the key of a cancelled pending assignment is not recorded. Re-enrollment
   is refused only for the keys of activated Workers (kept as history) and of still-pending assignments
   (`Book::schedule`). The cancelled key carries no authority and its signed assignment cannot be replayed;
   using that key again needs a fresh authorization by the current owner and a fresh possession signature by
   the key holder.
4. Mining and reward boundary of a sale included in block H (Order Q17):
   a. The reward of H goes to the seller, the parent-state owner: `State::work_context_v2`
      (`consensus/src/execution_v2.rs` 41-112) returns the owner from the PARENT Book (line 109),
      `prepare_candidate_with_recovery_v2` uses it (158), and `execute_body_inner`
      (`consensus/src/execution.rs` 708-710) requires `body.reward_owner` to equal it and pays the coinbase to it.
   b. From H+1 the License has no active Worker until the buyer's assignment activates: the sale sets
      `active_worker` to none; `Book::active` refuses the detached Worker (StaleSequence) and a not yet active one
      (UnknownSigner); `work_context_v2` requires `Book::active` (execution_v2.rs 78-80). No block can name the
      License, so no reward is paid through it.
   c. Then the buyer is rewarded: once the buyer's assignment activates at its signed epoch
      (`Book::activate_due`), `work_context_v2` returns the current owner, the buyer.
   d. The buyer is the dividend claimant from the post-sale state of H: trades execute before claims
      (execution_v2.rs 216-226) and the claimant is the License owner at claim time
      (`consensus/src/dividend_claim_v1.rs` 360-377).
   e. A re-sale needs `rights_from_height = H + 1`: the sale's License record stores H + 1
      (`consensus/src/trading_v1.rs` 2681), and a later DvP at height h requires it to be at most h (2658-2660,
      `NativeError::Time`), so a same-block re-sale is rejected and a re-sale from H + 1 is accepted.
   f. The old owner's Worker sessions lose their rights at the first canonical-state check after the sale's block
      is committed (WORKER-SESSION-CONTEXT-V2, amendment WP-Q17, item 3).
   g. New-owner authorization: an assignment is authorized by the parent-state owner
      (`license_assignment_v2.rs`, `WalletBook::authorize` at line 118), so the buyer cannot schedule one in the
      sale's own block (WrongGeneration), and the detached Worker key can never be enrolled again (Duplicate).
   Tests (consensus/tests/license_sale_assignment_v1.rs, real certified blocks):
   `sale_block_reward_goes_to_the_seller_then_none_until_buyer_activation_then_the_buyer` (a, b, c);
   `sale_without_pending_assignment_detaches_the_worker_and_its_sessions_lose_rights` (b, f);
   `re_sale_needs_rights_from_the_height_after_the_sale` (e);
   `buyer_cannot_schedule_an_assignment_in_the_sale_block` and
   `old_worker_key_can_never_be_re_enrolled_after_the_sale` (g). Existing tests:
   `license_dvp_with_dividend_claims_orders_stale_seller_buyer_authority_and_atomic_failure`
   (consensus/tests/trading_license_dividends_v1.rs:274) (d) and
   `license_dvp_canonical_restart_parent_reward_detachment_and_new_epoch_worker`
   (consensus/tests/trading_host_v1.rs:490) (a, the stored H + 1). Node tests with a live channel through a
   sale belong to WP-NODE (P-LANE-DESIGN-V1 14.11).
