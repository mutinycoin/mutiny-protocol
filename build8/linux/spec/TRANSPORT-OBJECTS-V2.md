# Bounded transport objects V2 — offline implementation candidate

The same canonical signed transaction, settlement-proof, hybrid vote or certified
block-envelope bytes travel through
Internet/LoRa object transport. Relays treat payloads as opaque. A delivery ACK
means fragment receipt only; it cannot establish payment settlement, voting
authority or block finality.

## Current implementation registry and queue profiles

The current Rust `ObjectKind` registry in `transport-v2/src/objects.rs` recognizes
exactly the following wire object kinds. Each object must be nonempty and satisfy
its complete encoded-item cap. Unassigned kinds fail closed.

| Kind | Object | Maximum complete bytes |
| --- | --- | ---: |
| 1 | SignedTransaction | 16,384 |
| 2 | SettlementProof | 2,097,152 |
| 3 | CertifiedBlock | 2,097,152 |
| 4 | ContinuityVote | 2,097,152 |
| 5 | WorkProbeRequest | 512 |
| 6 | WorkProbeFragment | 4,096 |
| 7 | RecoveryEvidence | 262,144 |
| 8 | BlockProposal | 74,257 |
| 9 | SignedOperation | 16,384 |
| 10 | StatusQuery | 4,096 |
| 11 | StatusReport | 16,384 |
| 12 | A2BlockProposal | 270,871 |
| 13 | A2EvidenceOperation | 196,608 |

Kinds 12/13 and their separate routes are recorded in
`A2-SUCCESSOR-ROUTE-REGISTRY-V1.json` under the existing design and TEST-VALUE
successor. A2BlockProposal carries CandidateProposalV3; A2EvidenceOperation
carries exactly one supported complete admission or terminal-withdrawal operation.
The endpoint selects the applicable rules from its authenticated canonical parent
and performs full proof, authority, witness and context validation. Parser
recognition, hashing, delivery and ACKs confer no semantic admission authority.

The ordinary queue is schema 7 and accepts kinds 1..11. SignedTransaction and
SignedOperation share two submission reservations totaling at most 32,768 bytes,
in addition to eight general reservations totaling at most 4,194,304 bytes.
The explicit A2 queue is schema 8; A2 evidence consumes general capacity and is
additionally limited to one complete or incomplete kind-13 reservation of at most
196,608 bytes. Request windows, pacing, retry and deadline rules retain their
existing bounds. Recognizing a kind in a codec does not permit it in every queue.

The ordinary implementation has a checked transactional schema-6-to-7 path:
it verifies the exact old schema, pinned peer, every saved offer and new capacity
constraints before preserving rows and validating the resulting schema. Other
incompatible ordinary schemas fail. The explicit A2 queue is create-new for
initialization or exact-schema reopen; it never migrates or replaces an old queue.

Recovery kind 7 retains its historical 262,144-byte limit and meaning. Certified
A2 envelopes remain inline in canonical evidence storage under their separate
1,942,044-byte bound; they do not widen recovery kind 7 or become hash-only locators.
Transport object labels are distinct from canonical operation kinds and transaction
tags: DividendClaim operation kind 23 is unchanged; transaction tag 25
(FundedRotation) is distinct from operation kind 25 (A2TerminalWithdrawal).

This registry describes current implementation compatibility and remains unfrozen.
Embedded C recognizes kinds 1..13 with the same complete-object caps as Rust after
the attributable two-file parity change. The isolated successor recorded 15 passing
scoped host component tests across six suites; the integrated Root candidate has
not been rerun. No firmware, physical-radio, native-HANDLE fullstream, release or
production qualification is established here.

## Historical component reports

The reports below describe their identified implementation stages. Their earlier
object vocabularies and local queue versions are superseded by the registry and
queue profiles above; their test results remain scoped to the original evidence.
Object kinds 1/2 are signed transaction/settlement proof; kinds 3/4 are canonical
hybrid certified-block envelope/Continuity vote. Main-tree kinds 5/6 are the
bounded work-probe request/fragment described in HYBRID-WORK-COORDINATOR-V2.md.
Kind 7 is public recovery evidence. Kind 8 is an uncertified hybrid block
proposal with the 74,257-byte bound described below.
These are opaque transport labels,
not claims that the enclosed evidence has passed consensus validation. Unknown
kinds fail closed. ObjectID is SHA256
(`MUTINY-BUILD8-TRANSPORT-OBJECT-V2` || NUL || kind u8 || length u32BE || exact
object bytes). Object length1..2MiB; each fragment is140 bytes except the exact
remaining final fragment. No compression is enabled. Reassembly validates the
complete digest before exposing canonical bytes to the semantic verifier.

HAVE type1 payload is `[version u8=2, kind u8, length u32BE]`; frame count equals
ceil(length/140), index0. WANT/ACK/NACK use a bounded bitmap: version2 u8, first
fragment u16BE, bit count u16BE, LSB-first bitmap bytes. There are1..1080 bits;
unused high bits in the final byte must be zero, exact length required, and the
range must fit the declared object. One bits request fragments for WANT/NACK or
acknowledge receipt for ACK. Type3 carries the exact fragment bytes.

Queue storage is scoped to one independently pinned peer; reopening under a
different peer fails. At most8 objects and4MiB aggregate declared payload may be
reserved, including incomplete objects. SQLite uses foreign keys, FULL sync,
DELETE journals and a16384-page limit. Each fragment is committed transactionally.
Exact duplicates are harmless; conflicting bytes do not replace stored bytes.
Bad completed hashes are quarantined and never exposed as complete. Explicit
local discard frees records; untrusted messages cannot delete queue objects.

The earlier four-kind queue used SQLite user_version=3 and a kind IN (1,2,3,4) constraint.
The six-kind queue used version 4; recovery added version 5. That proposal
candidate used version 6 with exactly kinds 1..8. These are local cache schemas,
not Genesis state.
Older queue schemas are rejected without migration or deletion of their pending
objects. A matching queue must be provisioned explicitly; no existing live queue
has been changed. The wire HAVE version remains 2 with explicit kind values;
implementations lacking kinds 3/4 reject them rather than accepting another type.

The conservative 1,745,430-byte hybrid envelope limit fits the existing 2 MiB
object bound, requiring at most 12,468 data fragments at 140 bytes each. Two such
reservations fit the 4 MiB queue; a third fails. This establishes bounded framing,
not acceptable radio latency or airtime. Those require separate pacing/measurement.

Each outgoing fragment may be returned at most8 times. Attempt consumption is
committed before returning bytes; crash/restart can consume an attempt but cannot
reset its budget. Deduplicated enqueue does not reset attempts. ACK state survives
restart. Retransmission uses a fresh secure-session sequence; queue persistence
never includes traffic keys, session IDs as authority, or replay state.

Current tests cover loss/reordering/duplication, interrupted transaction rollback,
restart, peer mismatch, exact limits, altered object hash, malformed bitmaps,
persisted ACKs and exhausted retries. SQLite rollback on connection close is
not a physical power-loss test. Storage-device flush behavior, radio/constrained
firmware storage, scheduler pacing/expiry and complete control-message dispatch
remain integration gates. The host implementation is not claimed to fit the
ESP32 flash/RAM layout.

hybrid-continuity-object-transport-v1.log passes six tests. Actual public synthetic
hybrid envelope and vote bytes pass the existing dual-authenticated X448/ML-KEM
session, AEAD fragmentation and exact reassembly, then independently pass endpoint
vote validation and licensed block execution/certificate verification. AEAD replay,
damaged constituent signatures and cloud voting authority fail. All four object
kinds also pass loss/reordering/duplicate/restart/retry checks. Delivery of a
well-hashed but cryptographically invalid envelope remains possible by design and
does not bypass the endpoint verifier. No RF or production authority was used.
# Public cache read hardening, 2026-09-30

The host candidate checks fragment BLOB type and 1..140-byte length in SQL before
copying it into Rust. Peer identifiers likewise require a 32-byte BLOB. Outgoing
fragments require their exact position-dependent length before reserving a retry;
invalid retry counters and completion flags fail closed. Reassembly rejects extra
rows after the expected fragment count. Complete-object and bitmap reads use one
SQLite read transaction each, so metadata and fragments come from one snapshot.
Object APIs independently enforce metadata bounds, including hop limits.

`qualification/transport-storage-bounds-v1.json` records 17 passing host tests,
including corrupt one-MiB cache rows and unchanged retry budgets on failure. This
bounds Rust blob copies; it is not a bound on all SQLite page-processing memory.
Same-sized corrupt fragments remain subject to receiver object-hash validation
and independent final transaction/certificate verification. Embedded storage,
radio scheduling and physical power-loss qualification remain open.
# Public queue schema boundary

The host queue rechecks its exact version-3 tables, implicit indexes and pinned
peer inside every operation's transaction. Unexpected triggers, views, indexes,
tables or a changed peer cause rejection before delivery, retry reservation,
acknowledgement or deletion. An excess persisted fragment count is rejected.
`transport-storage-schema-v1.json` records the hostile-cache tests and the
27-test transport regression. These checks detect malformed public cache state;
they do not protect against arbitrary code running as the same OS principal.

## Authenticated host dispatch candidate

`object_link::ObjectLink` owns one completed hybrid Session and one persistent
public queue. Construction requires the queue's pinned peer to equal the peer
authenticated by that handshake. Wire dispatch calls Session authentication and
replay validation before any object mutation. HAVE/FRAGMENT use the existing
exact codecs; WANT/ACK/NACK require control fragment index zero, the persisted
object's exact total count, and a canonical bounded bitmap. Unknown objects and
requests for incomplete outgoing objects fail.

There are at most eight transient request windows, one per queued object.
`send_one` returns at most one encrypted frame per local scheduling call and
visits pending objects round-robin. Remote requests never create a transmission
loop. Retries remain durably limited to eight per fragment; a sealing failure
may consume an attempt. The caller must perform fresh handshakes at session
limits rather than retrying an expired session indefinitely.

Receipts record fragment delivery only. Completion exposes hash-checked opaque
bytes, whose consensus/payment meaning still requires endpoint verification.
An explicit complete-object read permits idempotent application delivery after
restart. Disconnect drops traffic keys and transient requests while retaining
the public queue; reattachment requires a fresh same-peer handshake. No wire
control performs deletion. This candidate does not open sockets, transmit RF,
provision pins, weaken signatures or replace final settlement verification.

`object-link-v2.log` covers authenticated loss/NACK repair, AEAD tampering,
replay, delayed duplicates, exact count checks, persisted receipt state,
reconnection, wrong-peer rejection, eight-object scheduling and retry exhaustion
across reconnect. Radio pacing, pin lifecycle integration, physical storage and
end-to-end hardware qualification remain open.

## Public recovery transport extension under integration qualification

The reviewed candidate in `qualification/recovery-network-staging-v1/source`
has been promoted into main source and adds kind 7 for the exact
public hybrid recovery-history record. Its limit is 262,144 bytes, matching the
canonical record bound. Rust and embedded C enforce the same kind and length;
At that qualification stage, unknown kind 8 and oversized records were rejected.
That stage used local queue schema 5 with kind IN (1,2,3,4,5,6,7); the proposal
extension below supersedes its object vocabulary and local schema version.
Main production launch remains gated; no live queue or firmware was changed.

Reassembly and authenticated transport only establish delivery of exact bytes.
The node dispatches a completed recovery object to the canonical store's full
proof verifier. Successful acceptance has its own `RecoveryAccepted` event;
it is not `BlockInstalled`, payment confirmation, or a quorum vote. An exact
retained proof may be retransmitted after its successor finalized without
reapplying recovery. A different or invalid record is rejected.

The staged catch-up library fetches each successor from locally pinned Genesis
history. Before executing that successor it accepts any required public recovery
record against the actual canonical parent. It imports no peer-supplied state
or checkpoint root as authority. A batch performs at most 64 successor attempts;
the source interface specifies byte bounds and requires a carrier I/O deadline.
The peer's advertised anchor is only a fetch hint, checked against the locally
verified result. The disposable pending cache may fail without disguising a
successful canonical commit.

Windows tests pass a two-block synthetic chain, interruption after proof
acceptance, restart before the resumed block, missing/corrupt/oversized proof
rejection, wrong height/context, dishonest advertised tip, and exact late
duplicates. An encrypted recovery object passes the hybrid authenticated session,
AEAD replay rejection and reassembly before semantic dispatch. The nine related
transport tests include all seven kinds, C/Rust malformed-control agreement,
loss/reordering/restart and the old-schema fence. Fresh Linux qualification
passes 14 tests in six groups with 1,003 unchanged source files, recorded in
`bootstrap-recovery-network-linux-v1.json`. C ASAN/UBSAN/leak detection is
enabled; Rust is not instrumented. Exact reviewed changes were promoted after
the main consensus regression passed 186 tests in 58 groups. Main integration
qualification is recorded separately in `recovery-integrated-v1.json`; this is
not production qualification. Final protocol compatibility/fingerprint
inputs must include the final object vocabulary before Genesis is locked.

# Uncertified proposal extension

Kind 8 carries the canonical hybrid candidate journal record: a four-element
CBOR array containing version 2, canonical WorkHeader bytes, canonical BlockBody
bytes and canonical hybrid WorkAuthority bytes. The maximum object length is
74,257 bytes, covering the existing bounded constituent codecs and CBOR framing.
At that stage Rust and embedded C enforced the same bound; kind 9 and larger objects
are rejected. Object identity includes kind and exact bytes, so a proposal is
distinct from a certificate or vote even when payload bytes coincide.

The current peer-admission guard must authorize the originating connection at
semantic dispatch and durable retry. The owning runtime checks the object hash,
strict record encoding, both Node signatures, authority/parent identity, PoW and
full historical execution before durable candidate retention. It does not sign,
install finality or award voting weight. The owning voter subsequently restores
at most one current candidate per turn through normal executed validation.

That proposal stage used queue schema 6 with exactly kinds 1..8. Old schemas, including version 5, are
refused without migration or deletion. Pending delivery objects never grant
semantic authority, and a revoked peer cannot dispatch a previously received
proposal merely because reassembly completed before revocation.

FN-DSA signature randomness may yield different valid authority representations
of the same unsigned work and block. Candidate retention deduplicates those
representations only after validating both signatures, exact header/body and
unsigned authority equality. The first retained bytes are preserved. Different
execution commitments remain conflicts; no signature or execution check is
waived. This is local candidate retention, not a change to canonical finality.

Production listener/owner-task integration and physical transport qualification
remain open. This extension does not enable firmware or alter live queues.
