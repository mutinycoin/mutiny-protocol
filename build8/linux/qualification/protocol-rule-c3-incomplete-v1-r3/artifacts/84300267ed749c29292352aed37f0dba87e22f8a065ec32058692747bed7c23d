# Initial node authentication binding V2

Candidate initial-admission codec. It connects a fresh Node-role hybrid public
descriptor to the existing owner-authorized physical admission without reusing
wallet, Continuity or native TPM private keys. It does not authorize an ordinary
join, hardware rotation, key replacement or registry mutation by itself.

Continuity NodeID is SHA-256 of ASCII MUTINY-BUILD8-PHYSICAL-NODE-ID-V2, a zero byte,
and canonical CBOR [2, NetworkID, GenesisID, Node_descriptor_bytes]. The descriptor
must have Role::Node and its explicit key generation. This network-generation-bound
NodeID is distinct from the coordinator descriptor identity in work authorization.
Both remain 32-byte protocol identities under the approved identifier policy; no
256-bit post-quantum strength claim is made for SHA-256 identifiers.

The owner-signed AdmissionV2 already binds NodeID, so it commits to this exact
descriptor through the deterministic derivation. Construction is acyclic: derive
GenesisID, generate the separate node and Continuity keys, derive NodeID, construct
the challenged physical admission and Continuity possession proof, obtain owner
authorization, then prove possession of the node-authentication key.

The node's signed body is canonical CBOR [2, completed_AdmissionV2_bytes,
Node_descriptor_bytes]. Its signature domain is ASCII
MUTINY-BUILD8-NODE-ADMISSION-POSSESSION-V2, followed by a zero byte and this body,
hashed with SHA-512 before the standard both-required Ed448/FN-DSA operations.
The complete binding is [2, body_bytes, Ed448_signature, FNDSA_signature], bounded
to 16 KiB. Complete canonical encoding and exact lengths are mandatory.

Verification repeats the current owner-policy/WalletBook, supervised expected
inputs, native TPM certification/quote, and Continuity possession checks. It then
checks NodeID derivation and both node signatures. Either node public-key half
matching a wallet-owner or Continuity constituent is rejected. A generic work
signature cannot serve as node admission possession.

The returned token is not permission to insert stale authority later. The initial
control-state constructor must repeat verification against its current trusted
ceremony inputs at insertion. Subsequent lifecycle changes need their separately
authorized canonical transitions. Existing production/runtime gates remain closed.

node-admission-hybrid-v2.log passes both signature halves, all truncations, trailing
data, changed identity/generation/domain, role rejection, all four cross-role
constituent reuse cases, and the existing admission checks. The public binding is
9,095 bytes. node-admission-python-v1.json independently reproduces NodeID and
verifies canonical encoding, owner/Continuity/node Ed448, native certification and
challenged quote. node-admission-pristine-c-v1.log verifies all three FN-DSA intents
and malformed-signature/message variants. Fixtures use software TPM keys and
assert no real physical qualification or production authority.
