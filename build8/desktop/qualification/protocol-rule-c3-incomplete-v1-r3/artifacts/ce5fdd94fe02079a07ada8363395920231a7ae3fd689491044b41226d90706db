# Round proposal authentication and canonical scheduling

A round proposal selects an already executed candidate for a BFT round. It is
not a Continuity vote, certificate, admission, or participation acknowledgement.
It contributes no quorum weight. Candidate custody may accept work from any
qualified Worker/coordinator; that does not make its sender the round proposer.

The signed body is deterministic CBOR:
`[1, FinalizedAnchorV1_bytes, round_u64, proposer_NodeID32,
hardware_generation_u64, BlockHash32, pol_round_u64_or_null]`.
The parent anchor binds NetworkID, GenesisID, ProtocolFingerprint, parent height
and parent BlockHash. The proposal targets exactly parent height + 1.

The signature is Ed25519 over
`H(MUTINY-BUILD8-ROUND-PROPOSAL-V1, bodyBytes)` using the node-authentication key
in canonical parent-state NodeControl. It is not signed with the wallet or TPM
Continuity key. The transport object is canonical CBOR `[bodyBytes,signature64]`,
bounded at 512 bytes. Alternate/trailing/indefinite encodings are rejected.

Verification requires exact equality with the local canonical parent, scheduled
round and scheduled NodeID; current hardware generation; a nonzero eligible
parent-state voter; and the current NodeControl authentication signature. Cloud
and other zero-weight nodes cannot become proposers by sending this envelope.
The optional proof-of-lock round must be less than the proposal round. Its
authenticated prevote quorum and the candidate's full execution are independently
checked by VoterActor before a local Continuity vote can be signed. This envelope
alone never proves that a proof of lock exists.

ProposerCursor reconstructs the existing weighted ProposerSchedule from
canonical registries, advancing exactly once per finalized height. Certificate
rounds and signer subsets do not advance canonical priorities. Round selection
uses a copy, driven by the locally persisted voter round. Reconstruction does at
most 32 height/round steps per call and returns not-ready until complete; a peer
cannot force an unbounded round jump. A change of effective authority through
authenticated recovery invalidates the derived cache.

CounterVoter/VoterActor expose persisted scheduling progress without changing
custody. This may include an interrupted unsigned reservation. A scheduler must
still call the existing counter-backed signing path to finish or reuse the exact
vote. Inspection is not permission to publish an unfinished signature.

These rules enter the final pre-Genesis protocol manifest. Runtime wiring and
complete proposer/timer qualification remain pending; this codec does not itself
authorize actual Genesis or hardware admission.
