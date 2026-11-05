# Canonical Build8 specification V1 — approved semantics, pre-Genesis draft

Authority: ARCHITECT-AMENDMENTS-V1.txt overrides the earlier proposal. The updated
technical annex is incorporated. This document defines the operation/schema
boundaries now; it is NOT a completed implementation, final byte-vector suite,
parameter fingerprint, attestation certificate or Genesis artifact. The three policy blockers are resolved by ARCHITECT-BLOCKER-RESOLUTIONS-V1.txt.
BOOTSTRAP-RECOVERY-V1.md specifies their binding semantics. Fail closed on
unimplemented qualification; do not substitute defaults.

## Clocks, identity and consensus

NetworkID u32 = 0x4d555401. MiningEpoch is a distinct time index for the 60-second
protocol interval. ContinuityPeriod is a distinct index of 60 certified canonical
blocks. RetargetInterval is also 60 blocks but is not a MiningEpoch. Use explicit
types/field names, including in databases, attestations, certificates and wire
messages. A paused chain does not accumulate ContinuityPeriods from elapsed time.

Classification starts BOOTSTRAP_CENTRALIZED. Removing that label requires >=4
independently qualified physical voters plus measured >2/3 quorum after each
individual loss, using the ORIGINAL total denominator. No cloud/VM/vTPM weight or
bonds. Eligibility, membership and weight roots are committed, never inferred
from observed liveness. Persist propose/prevote/precommit locks and votes before
signing. Every accepted block needs licensed SHA-256d work and the required old-set
commit certificate. Mining transport is never a consensus authority.

## Reputation, bonds and lineage

Exactly: G=1000*P+A+4*S+2*H+floor(Q/10^10), R=max(0,G-D).
P,A,S,H and each bond age are ContinuityPeriod values; D is objective penalties;
Q=sum(locked_atoms*(1+bond_age)) over active qualifying lots. Direct computation,
not accumulation of prior G. Checked u256 arithmetic, fail closed on overflow.
u64 field bounds, 64 active lots/node, minimum lot 100 MUT, 4,320-period minimum
lock plus 720-period notice. No interest or downtime slash. Exact eligibility
revocation remains effective even when numeric age later increases.

Node lineage contains NodeID, owner/recovery authority, original admission period,
P,A,S,D, bond references and current hardware generation. Generation contains
hardware commitment, TPM voting key/Name/version, attestation/profile commitments
and H. Authorized physical rotation preserves lineage and bonds but resets H;
same-TPM key rotation retains H. The old generation is atomically superseded.

Physically qualified Genesis members receive provisional weight 1 until the first
certified ContinuityPeriod boundary, then the exact formula replaces it. Cloud
weight remains zero; later joiners receive no provisional history. Formula-driven
decreases from S/Q/H are explicitly approved. No high-water clamp applies.

## Common operation encoding

Deterministic CBOR fixed arrays; definite lengths, shortest encodings, no maps,
tags/floats/unknown fields. Operation envelope:
`[version=1, kind, NetworkID, GenesisID, ProtocolFingerprint, lineage_or_issuer_id,
sequence, valid_until_height, payload, authorizations]`.
IDs/roots are 32-byte strings; counters are nonnegative integers with checked
declared bounds. Reputation values use exactly 32-byte big-endian strings.
Hash/sign domains are distinct per operation and role. Transport envelopes do
not enter operation IDs. Signature bytes are excluded from the signed payload.
The authoritative byte/domain registry and full vectors are not finalized until the remaining implementation and qualification gates pass; no unreviewed encoding is advertised as interoperable.

Each operation requires the correct current lineage sequence, live authority,
full network/Genesis binding, no expired validity, proof validity, and a certified
state transition. Duplicate/replay fails or returns the same already-recorded
result without applying twice. Old-set quorum certifies all ordinary membership
changes; incoming weights cannot certify their own admission. A next-period
registry applies only after the preceding set certifies the transition.

## Required lifecycle operations

| Operation | Payload and authority | Deterministic state effect |
|---|---|---|
| ContinuityJoinV1 | New NodeID/owner recovery key, hardware commitment, TPM key/Name, platform profile, attestation evidence, possession proof and supervised admission authorization. | Reject duplicates, revoked generation, unqualified physical execution or exhausted admission capacity. Stage admission under old-set certification. Initialize actual history to zero; post-Genesis joiners receive no provisional unit or fabricated history. |
| ContinuityExitV1 | Current lineage/generation, explicit exit intent, committed node or owner/recovery authorization. | On old-set-certified transition mark ineligible at the next ContinuityPeriod boundary; retain penalties, history and bond encumbrances. Offline alone cannot create an exit. A zero-voter successor cannot produce new blocks. |
| HardwareRotateV1 | Old generation, new generation/key/profile/attestation, owner/recovery authorization or authorized existing node authority, and new-key possession proof. | Reject stale generation, cloned/used hardware or bad attestation. In ONE certified transition retire old generation, activate new one, preserve NodeID/P/A/S/D and active bonds/ages, reset H only for physical hardware change. No duplicate voting/earning interval. An old-key loss is recoverable through owner authority only if old-set quorum can still certify. |
| ContinuityRevokeV1 | Conflicting signed votes proving same network, lineage/generation, height, round and step with different voted objects. | Verify evidence and objective window before penalty; burn slashable bond, revoke eligibility, record penalties and permanent generation tombstone. Never use silence as equivocation evidence. Old-set certification still required; insufficient old-set quorum halts ordinary transitions. |
| BondUnbondNoticeV1 / BondWithdrawV1 | Lot IDs, owner signature and monotonic sequence. | Enforce 4,320-period lock then 720-period notice, evidence processing before boundary withdrawal, value conservation and no double spend. Exit/rotation does not bypass lock, notice, pending evidence or owner authorization. Removal from Q follows actual withdrawal. |

Permanently lost TPM with retained owner authority and sufficient surviving
old-set weight: normal HardwareRotateV1 to newly attested hardware, or authorized
exit. Lost TPM and lost owner authority: no invented signature and no inherited
identity. Permanently lost weight preventing old-set quorum permits only the approved
bootstrap-only recovery ceremony in BOOTSTRAP-RECOVERY-V1.md. After irreversible
decentralized activation it halts settlement until legitimate old-set authority
can be restored. Preserve the denominator and pending state. No inactivity ejection.

## License issuance is an existing schema, disabled at launch

LicenseRecordV1 array:
`[version=1, LicenseID, GenesisID, owner_AddressID, issuance_operation_id,
issuance_index, issue_height, active_WorkerID_or_null, assignment_sequence]`.
Genesis indices 0..11 identify the twelve historical-entitlement allocations;
the codec and index type do not impose a twelve-license lifetime maximum.

LicenseIssueV1 payload:
`[issuance_policy_version, authorized_policy_commitment,
issuance_sequence, entitlement_commitment_or_null, owner_outputs]`, where each
owner output is `[issuance_index, owner_AddressID]`. Canonical output ordering,
unique indices and replay protection apply. LicenseID is domain-separated from
GenesisID, issuance operation ID and issuance index. Genesis has its distinct
descriptor/index derivation, avoiding an issuance/Genesis circular hash.

Genesis parameter `new_license_issuance_enabled=false`. Reject every non-Genesis
LicenseIssueV1 while false, even with owner/admission-authority signatures or
valid PoW. Future enabling requires a formally authorized protocol/consensus
governance transition committed under an updated parameter policy; no local
configuration or generic admission signature enables it. The activation authority
must be locked before activation is possible, but the LicenseIssueV1 and
LicenseRecordV1 encodings already exist. No live Bitcoin oracle or mint function.

## Certificates, economics and durable state

ContinuityCertificateV1 includes version, NetworkID, GenesisID,
ProtocolFingerprint, purpose, height, MiningEpoch, ContinuityPeriod, round, step,
prior-certificate and parent/block/state roots, registry/reputation/attestation
roots, sorted unique TPM signatures. Verify weights from committed roots, reject
malformed/replayed/wrong-network/duplicate/weight-inconsistent evidence. TPM
P-256 ECDSA/SHA-256, fixed r||s, strict range/low-s; no aggregate cryptography.

SHA-256d, target 60 seconds, bounded 60-block retarget. Subsidy 1 MUT forever,
100-block maturity, no premine. Minimum relay/admission fee 1 atom/byte, winning
licensed Worker owner receives subsidy plus fees. No hard monetary cap or ASIC
resistance claim. Preserve the annex's transaction expiry, size/storage limits,
exact observation sequence rules and zero live Bitcoin/treasury dependency.

Admitted PENDING persists until CONFIRMED/EXPIRED/SUPERSEDED/INPUT_SPENT/REJECTED,
with atomic reason/event persistence; non-producing nodes reconcile independently
of candidate state. No silent capacity eviction. Certified-state checkpoints must
commit live UTXOs, licenses, membership, hardware generations, reputation, bonds,
penalties/revocations and sequence high-water marks. Never prune pending
transactions, slashable evidence or required checkpoint-validation material.
Complete checkpoint verification/retention vectors remain a pre-Genesis gate;
a statement that data is prunable does not authorize arbitrary deletion.
