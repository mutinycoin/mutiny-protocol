# Candidate hybrid membership controls

Status: synthetic component qualification; production and full canonical lifecycle activation remain blocked.

Authenticated state reserves schema 2 / tag 51 for the complete NodeAdmissionV2 binding, checked control sequence, admission height/boundary, exit boundary, and hardware-since height. The nine-field record is `[2,51,NetworkID,binding_bytes,sequence,admitted_height,admission_boundary,exit_boundary,hardware_since_height]`. Optional boundaries use CBOR null. Records are limited to 17 KiB and 1,024 physical controls. Their key is SHA-256 over `MUTINY-BUILD8-NODE-CONTROL-KEY-V2`, a zero delimiter, and NodeID. StateRootV2 commits the exact records.

Initial construction validates the current owner, supervised admission policy, native TPM evidence, Continuity possession and separate Node possession. Initial hardware, Continuity-key and Node-key generations are one. Construction produces tentative inputs only. Checkpoint reconstruction requires an independently authenticated StateRoot and retained admission evidence; reconstruction is not new admission authority. Retired owner keys cannot authorize a new admission. Node key halves cannot reuse any admitted Continuity or admission-owner key half.

Controls must match the physical registry's network generation, protocol fingerprint, NodeID, HardwareGeneration, hardware identity, native TPM key and profile commitment. Cloud members cannot acquire physical controls. Missing, duplicate and orphaned controls fail validation. The candidate parent-authority projector requires complete controls for every physical member. Standalone key records may be reconstructed for component qualification but cannot establish voting authority without their separate Node binding and controls.

Voting and participation validate controls at the authenticated parent height. Admission and hardware-since heights cannot lie in the future. A pending admission must remain ineligible and its boundary must be strictly later than the parent height. A pending exit must remain eligible until its scheduled boundary is executed, and cannot remain pending at or after that boundary. These checks prevent an overdue transition from silently retaining authority after checkpoint restoration.

ExitV2 uses the current parent's owner authority or exact Node descriptor, both constituent signatures, exact finalized parent anchor, target height and checked next sequence. Scheduling preserves the existing exit boundary rule: ceil(H/60)*60. At that boundary, after participation/reputation accounting, eligibility becomes false. Parent state and its certificate weights are unchanged. Repeated exits, stale sequence, wrong physical identity and altered post-state identity fail. All changes are returned in tentative copies. Join, hardware rotation, key rotation and recovery are not silently handled by older cryptographic paths.

Evidence: `hybrid-membership-exit-v3.log` covers five Rust tests including twelve scheduling cases, registry identity faults, duplicate/replay rejection and checkpoint reconstruction. `hybrid-membership-v2-public-v1.json` is synthetic public evidence. `hybrid-membership-python-v1.json` independently reproduces twelve transitions and StateRoots and rejects seven mutations. `hybrid-membership-pristine-c-v1.log` validates fifteen FN-DSA signature inputs and rejects message/signature mutations. The first Rust run exposed a test-harness assumption that malformed CBOR could still be hashed; the corrected test accepts rejection during either canonical hashing or decoding.

The subsequent candidate integrations add typed operation dispatch, join,
penalty/bond transitions and certified replay/install; their individual evidence
does not authorize production. Hardware/key rotation, bootstrap recovery,
protected production custody and complete runtime qualification remain. No
production keys, hardware enrollment, TPM mutation, Genesis sealing or live
membership change occurs here.

The candidate `continuity_lifecycle_v2::transition` composes native TPM parent acknowledgements and rolling refresh with hybrid exit authorization. It requires the independently authenticated parent StateRoot, exact parent height/anchor, complete matched V2 controls and admission keys, and excludes unmigrated legacy membership, admission, bonds and penalties. It derives the TPM verifier exclusively from committed admission profiles. The subsequent hybrid economic integration adds bond commands and explicitly historical-authority-validated equivocation evidence; see HYBRID-BOND-SETTLEMENT-V2.md. Transactions and fees still reject at this component boundary because it does not execute payments or rewards. Its return type includes the changed lifecycle/economic components and payouts, not a complete executable State; the explicit licensed V2 candidate executor performs full composition.

The order is parent-state ACK validation, refresh insertion, boundary reputation update, and boundary exit. A block-H refresh cannot authorize ACK H. Exit at height 60 may remove eligibility after that node earns its ordinary period-0 participation credit; the parent certificate still uses state 59. Native TPM ACKs remain liveness evidence with zero quorum weight. The block parser recognizes the V2 exit envelope, but this alone grants no execution authority and does not enable a V1 signature fallback.

Canonical registry records intentionally omit chain-anchor metadata. After validating the expected StateRoot, the transition projects the independently verified parent into a temporary registry. It does not require a restored checkpoint to contain its own BlockHash. Tests reconstruct state at heights 59, 60, 119 and 120 before continuing. The temporary returned registry refers to H-1; its serialized records still omit the anchor, preserving the existing acyclic state format.

Additional evidence: `hybrid-rolling-lifecycle-v5.log` passes thirteen targeted tests, including full 54/60, 53/60 and two 60/60 period runs. `hybrid-rolling-lifecycle-export-v1.log` adds checkpoint restoration. `hybrid-rolling-lifecycle-python-v1.json` independently verifies six selected transitions, native ACK/refresh signatures, StateRoots and six mutations. These are software-TPM fixtures, not mined or certified hardware history. An intermediate linker failure was caused by rebuilding an executable still in use by the previous test run; the sequential retry passed.

Parent-bound Join V2 is now composed after parent accounting and settlement;
see HYBRID-PHYSICAL-JOIN-V2.md. It inserts matched admission keys, controls,
physical membership and rolling freshness together. Pending joins activate after
boundary accounting with zero history/weight. Hardware/key rotations and recovery
remain rejected rather than falling through to a historical cryptographic path.
