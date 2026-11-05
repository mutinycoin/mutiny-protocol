# License execution implementation

Status: pre-Genesis implementation; two-phase initial bindings approved in
ARCHITECT-GENESIS-BINDINGS-AMENDMENT-V1.md.
This document does not establish a network, finalize ProtocolFingerprint, or
authorize an out-of-band mutation of established Genesis state.

LicenseRecord retains the approved nine-field schema. BindWorker uses the common
ten-field operation envelope, kind 10. Its payload is
`[owner_public_32, WorkerID_32, worker_public_32, coordinator_public_32, effective_epoch_u64]`;
the signatures field is `[owner_signature_64, worker_signature_64]`. Each signer
signs its distinct domain-separated SHA-256 digest of the first nine fields as
a nine-field CBOR array. WorkerID hashes canonical
`[1, NetworkID, GenesisID, LicenseID, worker_public_32]` under its own domain.

Owner address must match the license. Assignment sequence must increment exactly
once. An ordinary binding operation schedules activation for the next canonical
MiningEpoch, not a wall-clock timer. Candidate execution activates due bindings
from the parent records before checking work authority. Previously activated
bindings never roll back when a later allowed block timestamp is smaller.
Worker public keys cannot be reused from pending or historical bindings.

Canonical state commits licenses, signed Worker bindings, pending bindings and
each Worker's numeric last accepted ticket sequence. These records use separate
state-key domains. A Worker record is `[1, signed_binding_bstr, ticket_u64]`.
The ticket must strictly increase for accepted work. Current AuthorityID and
BlockHash never enter the ticket record: post-StateRoot precedes both hashes.

The candidate copy supplies license owner, Worker and coordinator key from the
parent's validated state and due transitions. It validates work signature,
context, target and timestamp; executes transfers and supported binding
operations; advances the ticket high-water mark; and compares the computed
post-StateRoot. Failure leaves the parent unchanged. Unknown lifecycle operations
are rejected until their typed validators are implemented. This executor alone
does not establish PoW, BFT finality or durable canonical state installation.

Genesis bootstrap uses the approved two-phase ceremony. GenesisIdentity freezes
descriptor bytes before enrollment. Its bind_workers constructor requires
exactly twelve normal owner/Worker-signed bindings for the twelve derived
licenses, generation 1, effective epoch 0 and valid_until_height 0. This last
field means the initial authorizations are usable only at height zero; canonical
active bindings persist afterward. The same common verifier checks owner,
network/Genesis/fingerprint, explicit WorkerID derivation, uniqueness, generation
and both signatures. No complete live Genesis has been built by this code.
