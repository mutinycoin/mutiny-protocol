# Hybrid licensed candidate execution V2

Status: candidate implementation and synthetic qualification; production is
disabled and Genesis remains unsealed.

The explicit V2 path derives license, Worker, ticket high-water mark and exact
hybrid Node descriptor from canonical V2 assignment state. Due assignments
activate at their authorized mining epoch. Work must match the independently
validated parent, target, timestamp rules, network, Genesis and fingerprint.
Both Node Ed448 and FN-DSA signatures are required.

Proposal construction first applies next-epoch assignment scheduling, numeric
ticket advancement and hybrid transaction execution to a tentative copy. The
resulting StateRoot enters the candidate that the Node signs. No current work
signature or AuthorityID enters that StateRoot. Acceptance verifies the work
authority and independently repeats execution, requiring the exact signed root.
Failure leaves the parent unchanged. PoW, certified finality and durable atomic
installation remain separate mandatory gates.

Assignment authorization uses the parent WalletBook. A wallet rotation in this
block cannot authorize an assignment through newly created same-block authority.
Assignments retain their ordinary next-mining-epoch semantics. Candidate reward
ownership comes from the canonical license, not peer input. Checkpoint records
retain retired Worker keys and their ticket high-water marks.

The existing bounded BlockBody container now recognizes only the exact V2
five-field kind-10 assignment envelope alongside its prior V1 operations. This
does not add V2 aliases for V1 lifecycle/participation objects. V1 execution
cannot accept V2 assignments. V2 execution rejects every unmigrated operation,
V1 license state, and unmigrated Continuity/admission/membership/bond/penalty
state. Full hybrid Continuity execution integration is still required before
this can execute a production Build8 chain.

Qualification: `licensed-execution-v2-rust-v2.log` passes four tests, including
the integrated two-block path, exact root verification, both signature failures,
context faults, ticket replay, failed-operation atomicity, reward substitution,
checkpoint reconstruction and next-epoch Worker replacement. The first compile
attempt's JSON-export macro error is retained in the v1 log.

`licensed-execution-v2-public-v1.json` contains synthetic public evidence only.
`verify_licensed_execution_v2.py` independently rebuilds both exact state maps
and sparse roots, verifies Ed448 and exports 15 distinct FN-DSA checks for the
pristine C verifier. A nonce change within the authorized range is valid work,
so the independent negative header case changes the signed StateRoot instead.
No private key or real wallet/Worker state enters these fixtures.

These rules must enter the final protocol manifest and regenerated dependent
vectors before any final ProtocolFingerprint or Genesis ceremony.
