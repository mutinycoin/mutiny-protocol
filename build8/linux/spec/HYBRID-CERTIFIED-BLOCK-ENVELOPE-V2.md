# Hybrid certified block envelope V2

Candidate canonical encoding: `[2, WorkHeader_bytes, BlockBody_bytes,
HybridWorkAuthorityV2_bytes, HybridContinuityCertificateV2_bytes]`.
Each component retains its exact codec and bound. This is a transport container;
BlockHash remains the existing header-derived identity, independent of certificate
round or signer subset. V1 containers are not accepted by the V2 decoder.

The finite maximum is 1,745,430 bytes: 512-byte header + 65,536-byte body +
8,192-byte work authority + 1,671,168-byte certificate + 22 bytes of maximum
container overhead. The existing V1 runtime framing is not silently enlarged.
All framing, storage and proof-serving paths still need consistent V2 migration.

Amendment, 5 October 2026: the exact authenticated parent-selected unfrozen A2
capacity rule in A2-BODY-CAPACITY-V3.md permits a <=262150-byte complete body and
<=1942044-byte certified envelope, with the same grammar/domain/child bounds.
The old unmarked bound and original imported artifact identity remain historical.
Transport still caps each object at2097152; ordinary routes do not silently widen.
Retain the exact whole certified envelope in bounded finality evidence BLOBs for
authenticated replay/restart/recovery, without enlarging a state record or kind7.

Verification requires independently authenticated parent state, target/time
history and physical voter registry/roots. It executes the complete hybrid
licensed candidate and checks PoW, state root, dual Node work authorization,
derived Decision and dual Continuity quorum using parent authority. Candidate
post-state never raises its own certificate weight. The verifier returns a pure
execution result; canonical installation and conflicting-finality integrity halt
remain separate mandatory checks.

Qualification: `hybrid-certified-envelope-v1.log` exercises a synthetic executed
licensed block produced through the durable hybrid voter. It rejects every wire
truncation, trailing bytes, V1 fallback, invalid signature halves, wrong roots,
wrong reward owner, empty quorum and cloud authority. A 1,024-signer size-only
fixture fits the derived bound without claiming those copied signatures valid.

`hybrid-certified-envelope-v2-python-v1.json` independently checks canonical
encoding, PoW, block/parent identities, expected Decision, state-map roots and
Ed448, with nine negative cases. It pins the exact existing independently replayed
licensed-execution fixture. `hybrid-certified-envelope-v2-c-v1.log` verifies the
exported Continuity FN-DSA intent through pristine C, including signature/message
mutations. Public fixture authority is synthetic; none of these tests installs
production registry state, changes hardware or seals Genesis. These historical
component results are not successor A2 capacity or current Path B qualification.
