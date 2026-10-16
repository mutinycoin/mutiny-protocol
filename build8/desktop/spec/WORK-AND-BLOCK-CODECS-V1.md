# Build8 work, block and Genesis codecs V1

Authority: ARCHITECT-GENESIS-POW-RESOLUTIONS-V1.txt, SHA-256
7cde6b5b0d68060d32a00a0b40ee78c70632899e2d26cfa8dd69c8d1c65201de (as found; preserved
in git history, commit `0da9053`).
Amended 2026-10-03 (Architect decision D3): that authority was amended in sections 2E and 2F and
its amended SHA-256 is
06037bb72a13d563a8849d75ae756756b4df391ff873235dc61b3df28925b395. The "Time and retarget" section
below is amended to match; its text as found (sha256
9d5b3dea470a2997fb5d475328acfa69266838a0b27c8f16b5ffc5609bf26b35) is preserved in the same commit.
No routine reapproval is required. Codec qualification and production state-machine
qualification are separate gates; fixtures never authorize mainnet Genesis.

## Primitive encoding

RFC 8949 deterministic CBOR fixed arrays, definite lengths, shortest unsigned
integer encodings, no maps/tags/floats/negative integers/indefinite forms. Nested
opaque byte strings carry explicitly named canonical objects, not Rust memory.
Decoder re-encoding must reproduce the original bytes and consume the entire
input. Maximum nesting is 16 for body/state content. Hashes and keys are 32-byte
strings unless the named key algorithm specifies another size. Nonce/search
endpoints are exactly eight-byte strings containing unsigned big-endian values;
this preserves a fixed-size mutable search field even at integer boundaries.

`H(domain, bytes) = SHA256(ASCII(domain) || 00 || bytes)`.
Domains have no implicit length prefix. All IDs use these exact bytes, never
display-reversed digest bytes. A listed byte-string length is its payload width,
not its CBOR prefix width.

## Body and state commitments

BlockBodyV1 is `[1, height, [reward_owner_AddressID, 100000000, fees_atoms],
transactions, operations]`. The two lists contain byte strings of full canonical
signed transactions/operations, in execution order. Do not sort away that order.
Duplicate encoded entries are rejected; semantic duplicate spends/IDs must also
be rejected by state execution. Height is >=1. Whole body <=65536 bytes, each
transaction/operation <=16384 bytes, combined count <=4096 (also constrained by
the byte cap). Fee total and reward owner require execution/license validation.
BodyRoot is H(`MUTINY-BUILD8-BODY-V1`, body bytes); this commits all body contents,
including authorizations in those objects. Their transport wrappers are excluded.

Amendment, 5 October 2026: an authenticated parent selecting the exact unfrozen
A2 rule uses A2-BODY-CAPACITY-V3.md's ONE typed oversized-operation reserve.
Remove that item and re-encode the exact ordinary projection; all limits above
remain in force on the projection, with raw aggregate <=65536. Total count still
includes the reserved item. The selected complete body is <=262150. Unmarked
history and ordinary item/transaction decoders retain the original limits.
This recorded amendment does not change the original imported artifact identity.

StateRoot uses the single 256-level sparse Merkle V2 definition in
STATE-ROOT-AND-PROOF-V2.md. Existing unique 32-byte keys and typed records are
preserved; limits remain 10 million records and 256 KiB per record. The root
commits the record count and tree root. No flat V1 root is accepted. Typed
execution remains required; canonical bytes alone do not authorize an operation.
State must not contain the current block hash
as an input to its own header: UTXO and record identities derive from canonical
operations and parent/height context, before the final PoW nonce.

## Work authority and ticket

Unsigned WorkAuthorityV1 is the following 18-field array, in exact order:

`[1, NetworkID_u32, GenesisID_32, ProtocolFingerprint_32, parent_BlockHash_32,
height_u64, timestamp_u64, BodyRoot_32, post_StateRoot_32, LicenseID_32,
WorkerID_32, assignment_sequence_u64, ticket_sequence_u64,
coordinator_Ed25519_public_32, target_32, nonce_start_8, nonce_end_8,
MiningEpoch_u64]`.

AuthorityID = H(`MUTINY-BUILD8-WORK-AUTHORITY-V1`, unsigned bytes).
Envelope is `[unsigned_bytes, coordinator_signature_64]`; Ed25519 signs AuthorityID.
The exact signature is excluded from AuthorityID. The coordinator key must be
authorized in the committed active Worker assignment, never accepted solely
because it appears inside a self-signed ticket. The owner-authorized assignment
sequence must match current state. The coordinator persists a strictly increasing
ticket sequence per Worker; consensus requires it exceed that Worker's last
canonically accepted ticket high-water mark. Identical retransmission is the same
ticket; no second accounting credit is created. Parent and epoch changes retire
work without destroying a healthy Worker authentication session.

Network/Genesis/fingerprint, parent/height, License/Worker and target must match
the validated parent state. Epoch is recomputed from the signed timestamp.
Nonce start <= end, inclusive; a miner never wraps UINT64_MAX or searches outside
its signed range. Changing ANY candidate field requires a new authority and
freshly prepared mining job. The miner may vary only nonce. Local issuance/expiry
clocks cannot rewrite historical validation. Fresh quorum work-liveness checks
and the final Continuity commit certificate remain mandatory; signature possession
alone is not physical-voter or settlement authority.

## WorkHeaderV1 and exact PoW bytes

The header is this 14-field CBOR array:

| Index | Field | Encoding |
|---:|---|---|
| 0 | version=1 | shortest unsigned integer |
| 1 | NetworkID | unsigned u32, shortest encoding |
| 2 | GenesisID | bstr32 |
| 3 | ProtocolFingerprint | bstr32 |
| 4 | parent BlockHash | bstr32 |
| 5 | candidate height | unsigned u64, shortest encoding |
| 6 | candidate timestamp | unsigned u64, shortest encoding |
| 7 | BodyRoot | bstr32 |
| 8 | post-StateRoot | bstr32 |
| 9 | LicenseID | bstr32 |
| 10 | WorkerID | bstr32 |
| 11 | AuthorityID | bstr32 |
| 12 | authoritative target | bstr32, unsigned big-endian |
| 13 | nonce | bstr8, unsigned big-endian |

Work bytes = ASCII `MUTINY-BUILD8-WORK-V1` || 00 || header CBOR.
SHA256d = SHA256(SHA256(work bytes)), with raw first digest bytes passed to the
second hash. Read the final digest as an unsigned big-endian 256-bit integer.
Valid PoW iff target is in [1,2^256-1] and digest <= target. No byte reversal.

Length is deterministic for the integer widths, not universally constant.
For the fixed NetworkID, total length is 344 + CBOR-length(height) +
CBOR-length(timestamp), where each length is 1/2/3/5/9; verify this equation
against generated vectors before lock. Nonce payload offset = total length-8.
The fixture height-one input is 350 bytes, nonce offset342; ordinary height61
fixture is351 bytes, nonce offset343. The all-zero structural vector has342
bytes and is intentionally invalid consensus work (wrong network/height/target).
No Bitcoin 80-byte header assumption applies. Per-field offsets are supplied for
every vector. Prefix caching may include only whole SHA blocks strictly before
the nonce; it is invalidated by every other byte change.

BlockHash = H(`MUTINY-BUILD8-BLOCK-V1`, header CBOR), distinct from the work digest.
The header commits AuthorityID, all body/state contents and the licensed reward
identity before nonce. The parent must already be the certified canonical parent.
Neither the current commit certificate nor a previous certificate's particular
signer subset is part of BlockHash. Peers still require valid certificate evidence;
excluding signatures from identity does not waive verification.

## Acyclic Genesis derivation

GenesisDescriptorV1 is `[1, NetworkID, t0, generation_nonce_32,
ProtocolFingerprint_32, owner_AddressID_32, purchase_commitment_32,
canonical_parameters_bytes, initial_admission_records, recovery_public_key_32]`.
Admission records are canonical byte strings in strict lexicographic order;
<=1024 records and <=1MiB whole descriptor. Parameters <=64KiB and each admission
record <=256KiB. They contain fresh public keys/policies, not derived NodeIDs or
the final state root. The complete approved parameter/admission schemas must be
present for actual Genesis; mining-only fixture parameters are explicitly partial.
GENESIS-INITIAL-STATE-V1.md defines the complete parameter and pre-state physical
admission codecs and deterministic initial-state construction.

GenesisID = H(`MUTINY-BUILD8-GENESIS-ID-V1`, descriptor bytes).
GenesisLicenseID(index) = H(`MUTINY-BUILD8-GENESIS-LICENSE-V1`, GenesisID ||
index_u64_big_endian) for initial indices0..11; this derivation is only the Genesis
allocation, not a lifetime issuance limit. Derived IDs feed initial state next.
Descriptor commitment = H(`MUTINY-BUILD8-GENESIS-DESCRIPTOR-V1`, descriptor bytes).
Height-zero object = `[1, NetworkID, GenesisID, ProtocolFingerprint, t0,
descriptor_commitment, initial_StateRoot]`.
GenesisBlockHash = H(`MUTINY-BUILD8-GENESIS-BLOCK-V1`, height-zero bytes).
No parent, Worker, ticket, nonce search, reward or fees apply to this object.

Dependency order: parameter/schema manifest -> fingerprint -> descriptor ->
GenesisID -> initial derived identities/state -> GenesisBlockHash -> height-one
candidate body/poststate -> unsigned work authority -> AuthorityID -> WorkHeader
+ nonce -> work digest / BlockHash -> Continuity certificate. There is no edge
from a final block hash/certificate back into its own authority or descriptor.

## Block envelope and Continuity evidence

The transport-neutral envelope is `[1, header_bstr, body_bstr,
authority_envelope_bstr, certificate_bstr]`, limited to330KiB. Each nested
object must independently satisfy its canonical codec and size bounds.
The BlockHash depends only on the WorkHeader, never on a signer subset.

The unsigned Continuity decision is the17-field annex array through
attestation_evidence_root, excluding signers. DecisionID is
H(`MUTINY-BUILD8-CONTINUITY-DECISION-V1`, unsigned decision bytes).
DecisionID identifies round-specific evidence and MUST NOT link canonical history.
The previous_finalized_anchor field is the FinalizedAnchorID of the finalized
parent at height H-1, as defined in FINALIZED-ANCHOR-V1.md. The certificate has the same fields plus the final signers array.
Signers are sorted unique `[NodeID, key_version_u64, signature_bstr64]`, with at
most1024 entries and256KiB total certificate bytes.

Each TPM P-256 signature verifies the prehashed digest
H(`MUTINY-BUILD8-CONTINUITY-VOTE-V1`, CBOR `[unsigned_decision_bstr,
NodeID, key_version]`). Signatures use32-byte big-endian r followed by32-byte s,
with low-s required. Public keys are compressed SEC1 points of33 bytes.
Active duplicate voting keys and zero-weight signers are rejected. Quorum is
checked against the entire committed registry, including offline members:
3*signed_weight > 2*total_weight, with checked wide arithmetic.

The evidence verifier binds body/root/owner, licensed authority, PoW and the
expected commit decision together. Passing it does not execute transactions,
prove the post-state root, or implement durable BFT locks. Those remain required
before a node may accept or settle a block.

## Time and retarget

Timestamp is u64 Unix seconds. Require timestamp >=t0 and derive epoch by checked
`(timestamp-t0)/60`. Header omits redundant epoch; authority encodes it and requires
exact equality. MTP uses all available prior canonical blocks up to11 including
Genesis; sorted timestamp at index count/2 is the median (upper middle for even
early-chain counts). Require candidate timestamp STRICTLY GREATER than that
median. The prior annex did not state a comparison operator; this exact choice
is now recorded as part of the authorized implementation. Height0 has no MTP test.
**Amended (D3, 2026-10-03): additionally require candidate timestamp >= the parent's timestamp
(equal permitted only when it is also strictly greater than the median). An implementation may
test "timestamp >= maximum of the ancestor window" only when the window includes the actual parent
and holds only validated ancestors of it; on a chain built under this rule that maximum is the
parent's timestamp regardless of window order. Height0 has no parent test. There is no
wall-clock bound on admission or relay in either direction; signing a fresh block vote is gated by
the qualified clock alone.**
*Superseded text, preserved as found:* "Local future hold means timestamp > local_now+7200; use
wide addition and do not treat that transient admission/relay hold as historical consensus
invalidity."

InitialPoWTarget applies to heights1..60. After positive height h divisible by60,
use timestamp[h]-timestamp[h-60] with signed wide subtraction, clamp900..14400,
then floor(old_target*span/3600), clamped1..2^256-1 with a 512-bit intermediate.
New target starts at h+1. Quorum pauses remain inside this span. A >2/3 coalition
can deliberately halt certification and influence the subsequent bounded target;
it still cannot authorize otherwise invalid blocks. No local pause subtraction.

Initial target derivation uses exact rational sums of actually qualified active
devices: H=sum(attempts*1000000/elapsed_microseconds). W=60*H.
Since probability is (T+1)/2^256, select
T=clamp(floor(2^256/W)-1,1,2^256-1), recording any bound clamp. This floors the
number of successful digest values, with no comfort multiplier. Displayed
difficulty is a non-authoritative exact ratio; consensus never uses floats.
