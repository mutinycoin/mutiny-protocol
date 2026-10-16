# Hybrid Continuity ingress and durable signing candidate

Status: component qualification; production activation remains blocked.

`votes_v2` validates dual signatures against independently supplied committed
parent authority. Non-nil votes enter the BFT reducer only after the exact
proposal passes hybrid licensed execution and PoW. Nil payloads remain explicit.
Physical eligibility, parent roots, generation, TPM identity/profile and both
public-key halves are mandatory. Duplicate lineage, TPM or either software
public key cannot increase the weighted denominator.

The caller must obtain `HeightAuthority` from authenticated canonical state.
This component does not make a peer-supplied registry authoritative. The complete
typed hybrid registry/lifecycle migration is still required.

Local ingress tracks a bounded set of node/sequence and node/round/step identities.
Exact duplicate delivery adds no weight. Reusing a sequence for a different
message, or replacing an already seen slot with a different sequence, is rejected.
Arrival order does not become a historical evidence rule. Restart may replay valid
votes to rebuild quorum; a height/parent change cannot reuse an old signed vote.
Historical equivocation verification remains separate, including evidence with
sequence misuse. Its offense definition and settlement rules are unchanged.

`counter_voter_v2` uses the existing single TPM-counter snapshot mechanism.
The same atomic snapshot contains parent anchor identity, all three authority
roots, height, BFT locks, last allocated VoteSequence, reservations and complete
dual signatures. It is not split across a new independently rollbackable database.
The local canonical snapshot is version 2, bounded to 4 MiB and at most 1,024
current-height reservations. These are local backpressure limits, not permission
to reduce quorum or reject an otherwise valid network certificate.

Before private signing, the exact unsigned message and lock state are durably
committed and the pinned counter is verified. After signing, both constituent
signatures are verified and the completed snapshot is committed before return.
Counter, signature or storage uncertainty poisons the live gate until recovery.
An interrupted completed signature is replayed byte for byte without signing
again. A partially produced/invalid hybrid signature is never publishable.

Sequence allocation is checked, starts at 1 for explicitly initialized custody,
and survives height advancement. One height/round/step has only one reservation.
An already finalized exact parent is required for advancement; changing hardware,
software key generation, lineage, TPM binding or network context cannot silently
reuse the old journal. Key rotation still requires its explicit custody transition.

The backend interface describes separate Continuity software keys, encrypted and
access-controlled on the admitted physical node. It does not claim TPM-native
Ed448 or FN-DSA. The backend must hold the exclusive host lock for counter checks
and private operations. No production backend, keys or TPM writes are introduced
by these tests.

Qualification: `hybrid-counter-voter-v3.log` passes 13 tests across the hybrid
counter gate, existing counter crash recovery, BFT locks, hybrid certificates and
hybrid equivocation. The five new gate tests cover reservation-before-signing,
failure/restart, exact retransmission, invalid FN-DSA output, interrupted counter
increments before and after signing, pending-snapshot recovery, stale writers,
disk rollback, sequence reuse, parent/root substitution and a complete synthetic
licensed proposal → dual votes → finality → next-height sequence transition.

Remaining: canonical hybrid registry/admission and reputation integration,
hybrid actor/network/certificate framing, encrypted physical-node backend and
end-to-end recovery with qualified hardware. Genesis remains unsealed.
