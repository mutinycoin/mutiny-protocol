# Funded wallet rotation transaction

Implemented and qualified as an execution/settlement component. Node listeners,
licensed Work V2 and Desktop migration remain pending; Genesis is unsealed.

Canonical envelope is `[2,21,WalletKeyRotateV1_bytes,HybridTransferV2_bytes]`.
It is one transaction, bounded to the existing 16KiB signed transaction limit.
Both embedded objects must have the same Network/Genesis/fingerprint. No legacy
Ed25519 transaction is accepted by this decoder. Ordinary HybridTransferV2
retains its unambiguous nine-field encoding; there is no negotiated fallback.

The rotation retains both current-key signatures and both new-key possession
signatures. The transfer retains both signatures for every input, authorizing
its exact inputs, outputs, amounts, fee, validity and descriptors. A valid
rotation intentionally grants the new descriptor authority; its holder then
authorizes the funding transfer. Replacing an embedded object requires all of
that object's valid authorizations and the combined context/state checks.

The existing minimum fee of one atom per complete canonical signed transaction
byte applies to the whole envelope, including all rotation signatures. A valid
ordinary transfer fee that does not cover the added rotation is insufficient.
Inputs are mandatory, value is conserved, and fees go to the licensed winning
owner under the existing reward rule. No free-standing network rotation
operation or fee exemption is introduced.

Funded transaction ID is SHA256 of
`MUTINY-BUILD8-FUNDED-WALLET-ROTATION-ID-V1 || 00 ||
CBOR [rotation_identity32, embedded_transfer_identity32]`.
Output outpoints use this outer identity. Signature randomness changes signed
bytes but not economic identity. The canonical block commits exact signed bytes.

Execution uses a candidate state copy. For an unregistered generation-one
authority, its ID must equal its exact initial descriptor-derived AddressID.
The rotation is verified against current authenticated state and applied to the
candidate WalletBook. Funding inputs then verify against that updated book;
the complete fee and value checks must pass. New outputs, fees and authority
records commit together. Failure publishes none of them. Transactions execute
in canonical body order: a later transaction sees the prior transaction's
completed rotation. An earlier transaction can use the authority current at its
own execution point. There is never simultaneous old/new authorization.

The explicit `execute_hybrid_transfers` entry point accepts ordinary hybrid and
funded-rotation transactions; it rejects lifecycle operations until their V2
validators are integrated. Existing node entry points are not silently switched.

Settlement verifies the outer ID, all rotation/transfer signatures and certified
output inclusion. Rotation and transfer expiry are evaluated at the output's
authenticated creation height. A later certified checkpoint can prove a still
unspent output after those authorization windows have closed. These signature
checks do not independently reconstruct input ownership; execution validates
input state, and settlement relies on the separately authenticated certified
state and exact UTXO proof, as in the approved proof model.

Evidence includes exact Python reproduction of a 10,198-byte funded transaction,
its 20,000-atom fee, coinbase, five-record post-state and StateRootV2; Rust atomic
execution/replay/fee negatives; Python work/certificate/Ed448/state verification;
and pristine C verification of all four FN-DSA intents in both same-height and
later-checkpoint settlement fixtures. All fixtures are nonproduction.

---

## Amendment A1 (candidate 3, Lane P work package WP-R, 2026-10-04): the funded wallet-rotation bundle

Status: PROPOSED-UNFROZEN, pre-Genesis candidate; Windows-host software evidence only (TEST-VALUE),
nothing on Linux or physical. Authority: Order of 4 October 2026, decision P2; design
`qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 1.b, 1.c and 3 with amendments AM-1(d),
AM-9 m6 and AM-11. This amendment SUPERSEDES lines 6-58 above (the `[2,21,...]` envelope, its
signatures, the FUNDED-WALLET-ROTATION-ID-V1 identity, its execution order, entry point, settlement
and evidence). Those lines describe a retired format: the old wrapper no longer decodes. Code:
`consensus/src/funded_rotation_v2.rs`, `consensus/src/hybrid_transaction_v2.rs`.

Why it changed: in the retired envelope the rotation and an independently signed funding transfer
were two objects. A proposer could capture the funding without the rotation, a third party could fund
it unreviewed, and the funding could be replayed later on its own. The bundle makes rotation and
funding one object with one identity, signed by every party over one commitment.

Wire (hybrid transaction tag 25, at most 16 KiB):

```text
unsigned   = [1, network, genesis32, fingerprint32, Envelope, authority32,
              current_descriptor, proposed_descriptor,
              null | [sponsor_address32, sponsor_descriptor], fee,
              [[txid32, index, payer] ...],          ; 1..=128, strictly ascending (txid, index)
              [[owner32, atoms] ...]]                ; 0..=128 destinations and change
tx         = [2, 25, unsigned_bytes, authorize, possession, null | authority_funding, null | sponsor_funding]
signature  = [ed448_114_bytes, fndsa_1280_bytes]
commitment = SHA-256("MUTINY-BUILD8-FUNDED-ROTATION-COMMITMENT-V2" || 0x00 || unsigned)
id         = SHA-256("MUTINY-BUILD8-FUNDED-ROTATION-ID-V2" || 0x00 || unsigned)
authorize         old key,     WalletRotate,           ["MUTINY-BUILD8-FUNDED-ROTATION-AUTHORIZE-V2", commitment]
possession        new key,     WalletRotatePossession, ["MUTINY-BUILD8-FUNDED-ROTATION-POSSESSION-V2", commitment]
authority_funding old key,     Transaction, ["MUTINY-BUILD8-FUNDED-ROTATION-FUNDING-V2", commitment, 0]  iff a payer-0 input exists
sponsor_funding   sponsor key, Transaction, ["MUTINY-BUILD8-FUNDED-ROTATION-FUNDING-V2", commitment, 1]  iff a sponsor is named
```

`Envelope` is `spec/OPERATION-ENVELOPE-AND-CONFIRMATION-V1.md` (window, finalized reference, optional
preconditions). Output `i` is created at `OutPoint{id, i}`. FUNDED-WALLET-ROTATION-ID-V1 is RETIRED.
Public vectors: `qualification/funded-rotation-v2-public.json` (reader
`committed_funded_rotation_v2_vectors_verify`).

Codec rules (a violating value is unrepresentable; tests `codec_rules_canonical_form_and_complete_binding`,
`stripped_funding_rejects`, `sponsor_equal_to_the_rotating_authority_refused`): at least one input
(stripped funding: `Bounds`); payer 0 or 1; a payer-1 input exists iff a sponsor is named (`Bounds`);
the sponsor descriptor differs from both rotation descriptors (`Bounds`); both rotation descriptors are
WalletOwner descriptors (`Owner`), the proposed generation is the current one plus one (`Owner`) and
both key halves change (`Duplicate`); `authority` is not zero (`Bounds`); every output has a non-zero
owner and non-zero atoms (P3, `Bounds`); inputs strictly ascending (`Codec`, equal neighbours
`Duplicate`); the network is NETWORK_ID (`Binding`); every nested unsigned body is canonical-checked.

Verification at inclusion height H = parent.height + 1, in the payment phase against the RUNNING state,
so a later transaction of the same block sees the completed rotation
(`same_block_later_transaction_sees_the_completed_rotation`):

1. codec rules;
2. context equals the parent's (`Binding`);
3. envelope: window (`Future` / `Expired`), reference (the parent itself, or the canonical anchor that
   the local canonical store supplies through History; otherwise `Binding`, exactly
   `ReferenceNotCanonical`), optional preconditions (`Binding`) (`bundle_after_last_height_rejected`,
   `reference_not_canonical_rejected`, `bundle_valid_across_head_advance_within_window`,
   `head_advanced_bundle_commits_and_replays_once_the_store_supplies_anchors`);
4. an unregistered authority must be the generation-one AddressID of the current descriptor; the
   current descriptor must be current (stale generation `Owner`); the proposed address must be new
   (`Duplicate`) (`authority_registration_rule_and_stale_generation`, `competing_bundles_second_fails`);
5. the sponsor's descriptor authorizes its address in the PRE-rotation book and its wallet authority
   differs from the rotating one (`Owner`);
6. every required signature present and valid, no unrequired one (`Signature`);
7. inputs exist (`MissingInput`), Transfer maturity (`Immature`), payer 0 authorized by the OLD
   descriptor and payer 1 by the sponsor's, both in the PRE-rotation book, older generations of each
   lineage included (`Owner`; `historic_generation_inputs_of_both_payers_fund_a_bundle`,
   `third_party_coins_need_their_owners_signature`);
8. exact conservation (`Conservation`) and fee >= the complete signed length (`Fee`);
9. compare-and-replace of the authority's descriptor, then the existing generation-one registration
   of the paying descriptors.

All authority for the transition comes from the pre-state; the new key only proves possession of the
exact plan.

The three failures P2 requires: stripped funding (`stripped_funding_rejects`); an unapproved
replacement sponsor fails at the old key's `authorize` even when the attacker re-signs
`sponsor_funding` and a colluding new-key holder re-signs `possession`
(`sponsor_substitution_rejects_at_authority_signature`); later standalone funding replay: a funding
signature fails as a Transfer input signature and inside any other bundle, and after execution the
bundle replays as `Owner` and its spent inputs as `MissingInput` (`standalone_funding_replay_impossible`;
cross-domain disjointness: `cross_verify_matrix_of_every_transaction_domain_payload`). Explicitly
reviewed sponsorship remains possible (`explicit_sponsor_bundle_executes`). A Treasury rotation (R1)
cannot consume reserved backing (`treasury_r1_cannot_spend_reserved_backing`). Rejected blocks leave the
canonical store byte-identical (every table row compared by `commit_rejected` in
`consensus/tests/funded_rotation_v2.rs`). Every store entry point that executes a block accepts a
bundle with an older reference (`entry_point_matrix_accepts_a_funded_rotation_with_an_older_reference`).

Partial exchange object (AM-9 m6; never a block item): `[1, 25, unsigned_bytes, four null | signature
slots]`; `PartialRotation::preflight(state, parent, history)` runs every check except missing
signatures (present ones are verified, unrequired ones refused); `signed_len(unsigned)` gives the
complete signed length before signing (`partial_object_and_preflight_for_sponsor_and_new_key_review`).
`execute_hybrid_transfers` has no store History: a bundle verifies there only with the parent as its
reference (fail closed). Settlement verifies the bundle's id, outputs, window and all signatures
(`funded_rotation_output_has_independently_verifiable_settlement`). The Python and C reproduction
evidence of lines 54-58 covers the retired format only and has NOT been redone for the bundle.
