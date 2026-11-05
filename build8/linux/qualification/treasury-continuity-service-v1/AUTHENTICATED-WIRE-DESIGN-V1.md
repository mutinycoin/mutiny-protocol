# Local authenticated continuity artifacts — component qualified, deployment incomplete

This successor compiled and passed the exact Linux component controls recorded
in `../candidate-3/TREASURY-CONTINUITY-IMPLEMENTATION-20261005.md`.
It implements selected-public-key authentication
and exact current-history binding. It does not establish enrolled identity,
independent administration, restore separation, native storage protection or a
production service. The normal `AuthenticatedProvider` factory is absent. Its
only constructor is private consensus `cfg(test)` modeled injection. No daemon,
service listener, command, shipping route or new feature is registered.

Ownership is limited to the provider and its dedicated authenticated-wire module,
the nonshipping service library and manifest, two Transport-role crypto domains
with separation controls, and local domain-registry entries. Model, owner,
Treasury native store, activation package and integrated dependency locks are
unchanged by this tranche. No Treasury spending-role key is used or collected.

## Exact protocol

Selected public pins are immutable: complete existing Scope, nonzero local
authentication context, canonical client Transport descriptor including generation
and canonical service Transport descriptor including generation. `PublicPins`
checks these bytes, the normal network and different client/service keys. This
public value is not an enrolled identity capability. Normal production must get
the complete tuple through an independently authenticated administrative ceremony.
No public boolean, caller trait or decoded checkpoint creates provider authority.

Each request has a new OS-generated 32-byte session nonce. It is separate from the
already existing logical operation ID, request nonce and content commitment.
Query payload is canonical `[0, request_nonce32, minimum_sequence]`; transition
payload is canonical `[1, exact Request bytes]`. All original logical Request
semantics, stable retry identity and outcomes remain unchanged.

The signed transcript is a definite canonical array of eleven fields:
`[1, direction, mode, context32, Scope(array7), client_descriptor,
service_descriptor, session_nonce32, request_wire_commitment32,
payload_length_u64, payload_commitment32]`. Client direction is 0, service is 1;
query mode is 0, transition is 1. Client request commitment is zero; service
response commitment hashes the exact complete signed client wire. The independent
session nonce prevents substituting a response from a different local exchange.

Envelope is canonical `[1, transcript_bytes, payload_bytes, signature_bytes]`.
Signature bytes are the existing 114-byte Ed448 plus 1280-byte FN-DSA-1024
BOTH_REQUIRED signature, under respectively
`MUTINY-BUILD8-LOCAL-TREASURY-CONTINUITY-CLIENT-V1` or
`MUTINY-BUILD8-LOCAL-TREASURY-CONTINUITY-SERVICE-V1`. Both use existing
Role::Transport and vetted primitive code, not spending/handshake domains.
SHA-256 payload/request commitments use the independently registered local
labels `...-PAYLOAD-V1` and `...-REQUEST-V1`, with the existing zero delimiter.
These artifact domains add no consensus operation, proof, fee, StateRoot entry or
Genesis fingerprint input. They remain PROPOSED-UNFROZEN until qualification.

Transcript is at most8192 bytes. Request payload is at most8192 bytes. Complete
snapshot retains the existing4096-history cap and32MiB+64KiB codec bound;
response payload adds2048 bytes for receipt/framing. Envelope adds8192+2048
bytes. Transport returns an untrusted Read stream; provider itself reads at most
the bound+one byte and rejects overflow before decoding. All CBOR arrays are
definite, exact bytes must re-encode identically, trailing data refuses, and
signature verification precedes expensive full-history decode. Signing binds
the full canonical payload by length and commitment without increasing the
existing crypto intent1MiB bound.

Query reply is `[0, PublicSnapshot bytes]`; transition reply is
`[1, exact Receipt bytes, PublicSnapshot bytes]`. The nonshipping durable service
constructs transition receipt and full snapshot in the SAME Immediate transaction
and commits before signing/acknowledgement. It never calls apply then queries a
potentially different head. A pre-commit failure is known refusal; a committed
transaction with lost acknowledgement is Unknown. Retry retains the same logical
operation/content, repeats its original outcome and never adds a second record.

Client checks its nonce, exact Scope, minimum/expected sequence, full contiguous
native Engine history, pending state and every retained action/outcome. It also
checks its own previously authenticated history is an exact prefix. Receipt and
snapshot heads must match; the exact original operation/action/outcome must exist
at the receipt's operation sequence. Conflict, signed stale head, fork, wrong
mode or coherent different-content reuse refuses. The private process history
is only a same-process lower bound, not restart authentication or antirollback.
The Root-owned owner still validates its complete native local records, exact
historical expectations and external current history on every startup/operation.

## Explicit limits and production inputs

`QualificationEndpoint` is an isolated software endpoint under selected public
pins. Its public constructor enrolls nothing and creates no opaque consensus
authority. No production launcher imports it. Public modeled Reserve/Consume
fixtures test authenticated continuity and storage, not genuine Treasury proof
validation. A production service must authenticate the separately authorized
verifier/client, ensure the native exact-proof/issuance checks of the approved
owner remain mandatory, and enforce the immutable externally enrolled tuple.
It must not treat the model's arbitrary bounded public bytes as genuine proof.

Fresh nonce plus signature is not trust-free evidence that a signer used the
latest independently protected service state. A new/restarted client cannot
detect rollback of the entire authoritative service from nonce echoes alone.
The adopted separately administered linearizable authority/restore boundary is
therefore a required premise; actual deployment and antirollback are unqualified.
No time value/TTL is introduced. Availability/timeout and authentication-session
deployment inputs must be reviewed without changing logical retry semantics.

Missing finite inputs: independently authenticated service and client descriptor
tuples/generations/context and authorized scope; custody locations and access
policy; enrollment, key rotation/revocation and pending-request reconciliation;
actual service administrator separation from verifier/admission DB restore;
service backup/restore policy that never regresses acknowledged history;
native SQLite main/sidecar handle pinning and durability qualification;
reviewed bounded transport and deployment routing. Normal production remains off.

Full history crypto/codec/query cost grows O(history), bounded4096 and without
eviction. EXTRA/DELETE configuration remains a software setting, not power-loss
proof. Existing path-based SQLite reopen cannot establish same-account/admin
identity stability or service-admin separation. No private key/activation secret
is logged, stored in fixture databases or included in public archives.

## Prepared semantic controls, not results

- crypto domain/role separation and either invalid signature half;
- immutable client/service generations, context, Scope, mode, request bytes,
  session/request nonces and exact response association;
- authentically signed stale head and different full-history fork against the
  process's own authenticated prefix;
- exact-content receipt/history membership and conflicting same-ID retry;
- private modeled provider using actual hybrid verification, lost ACK and stable
  retry outcome (modeled in-memory authority explicitly distinguished);
- actual isolated SQLite endpoint commit-before-ACK, retained Unknown followed
  by reopen with the same RAM identity, exact signed current response and repeat;
- two authenticated requests from concurrent authorized-client replicas sharing
  one SQLite head: exactly one commits, the other stays stale, and the committed
  receipt/snapshot are exactly signed and retained;
- the preceding four standalone durability/corrupt-BLOB controls remain present.

No compile/runtime/native VFS/physical/production result exists for this successor.
Independent full source/domain/graph review and a newly resolved offline isolated
lock precede any compiler lease. Private test keys remain RAM-only and core dumps
must be disabled during future qualification. Preserve every failed/partial run.
