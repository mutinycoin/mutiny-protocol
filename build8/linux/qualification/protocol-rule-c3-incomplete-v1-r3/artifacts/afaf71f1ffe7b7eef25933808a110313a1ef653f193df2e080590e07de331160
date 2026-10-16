# Continuity exit hybrid authorization V2

Candidate codec and verifier. The existing owner-or-node authorization policy is
preserved with both Ed448 and FN-DSA signatures mandatory for either route. There
is no Ed25519 compatibility path and no authority for Continuity software keys to
authorize node exit. Canonical membership execution remains separately gated.

The unsigned body is canonical CBOR [2, 14, NetworkID, GenesisID,
ProtocolFingerprint, inclusion_height, parent_finalized_anchor_ID, NodeID,
HardwareGeneration, next_control_sequence, exact_authorizer_descriptor_bytes].
The complete object is [2, 14, body_bytes, Ed448_signature, FNDSA_signature], with
maximum 4096 bytes. Descriptors are strict existing hybrid WalletOwner or Node
descriptors. Unknown roles, malformed/cross-version encodings and trailing bytes
fail. Signatures use SHA-512 over the domain, a zero byte, and the exact body:

- WalletOwner: MUTINY-BUILD8-CONTINUITY-EXIT-OWNER-V2.
- Node: MUTINY-BUILD8-CONTINUITY-EXIT-NODE-V2.

The parent anchor and control record are independently obtained from authenticated
canonical state. Genesis, fingerprint, next height, parent anchor, NodeID and
hardware generation must match. The checked next sequence must equal the signed
sequence. A pending exit rejects another request. Counter exhaustion fails.

For the owner route, the parent WalletBook must authorize the signed descriptor
for the control's owner address. A rotated-out owner cannot authorize a new exit;
the valid successor can authorize the same stable ownership lineage. For the node
route, the complete descriptor must equal the current node-authentication
descriptor pinned by the parent control. A freshly generated unrelated node key
cannot authorize exit. Domain separation prevents payment/work signatures from
being repurposed as exit signatures.

Verification alone changes no weight, registry, sequence or state. The existing
approved membership scheduling and boundary transition must execute atomically
after this verification when the V2 lifecycle integration is completed. The
operation is not admitted through an old executor merely because it decodes here.

Qualification: continuity-exit-hybrid-v3.log checks both routes, all truncated
encodings, context/generation/sequence faults, partial/damaged signatures, wrong
domains, wrong keys/roles, pending exit, overflow, retired owner rejection and
successor/node authorization after owner rotation. continuity-exit-python-v1.json
independently verifies the codec, context, Ed448 and owner rotation with 12 negative
cases. continuity-exit-pristine-c-v1.log checks all five corresponding FN-DSA
intents and signature/message mutations using the pinned pristine C implementation.
All fixtures are synthetic; no real wallet or node authority was accessed.
