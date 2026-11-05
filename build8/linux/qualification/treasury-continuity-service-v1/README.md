# Nonshipping Treasury continuity durability probe

This isolated library compiled and passed six exact native controls as part of
the 25-control Linux component campaign. It has no daemon, network listener,
production registration or production authenticated adapter. It retains public TEST evidence
only and cannot mint the opaque normal consensus provider's authority. The adopted
separately administered current-service trust model is settled; this adapter does
not establish that real boundary. No Treasury key, actual service credential or
private challenge is collected. No proof, quorum, monetary rule or TTL changes.

The manifest uses the existing pinned consensus library and rusqlite0.37 bundled
SQLite. Its patch paths preserve the existing approved crypto dependency source
closure. The separate 153-package standalone lock was resolved offline,
independently reviewed and used in the actual native run; no integrated lock was
edited. The normal Node build and exact graph exclusion were verified.
The adapter cannot be imported into a
shipping library to substitute for an authenticated provider.

Every NEW service transition commits original canonical Request bytes, original
NEW Receipt bytes and its contiguous sequence/operation ID in one SQLite Immediate
transaction before returning a public acknowledgement. Every request reloads and
validates the complete bounded history against the pinned Scope and native Engine.
There is no mutable acknowledged in-memory cache. Exact repeats return original
operation outcome/current sequence/new request nonce without adding a transition;
content conflict refuses. Public current snapshots are taken in one Deferred read
transaction. They include all confirmed terminal history, not only pending state.

Reopen enforces exact schema and independently supplied Scope, bounded contiguous
history, unique operations, canonical request/receipt bytes, exact replay outcome,
and reconstructed pending linkage. It never resets, truncates, repairs or evicts.
The existing4096 applied-record cap retains room for required confirmation as the
reviewed native model specifies. Complete replay/query grows O(history); the
public contract bounds complete snapshots at4096 Request-size records (32MiB plus
64KiB encoding allowance). The snapshot encodes deterministic replay session nonce
equal to the operation ID; that is not an original authenticated request or proof
of current state. Original request/session bytes remain recoverable from SQLite.

Public response decode and complete replay verify internal consistency only.
`Snapshot`/`AuthenticatedReceipt` normal constructors remain unavailable. Actual
provider current() requires a freshly authenticated session, immutable enrolled
service/verifier/store/context pins and linearizable current state. Request nonce
echo, copied token, database checkpoint, checksum or old signed history is not
service authentication. Real service admin/access/restore separation, deployment
public identities, enrollment/rotation authorization, protected storage and
retention/backup policy remain required inputs. Production stays disabled.

The file adapter requires an already existing protected private parent and creates
only a new file or reopens an exact existing probe. No ACLs of existing paths are
modified. Current path-based SQLite open does not provide a lifetime native VFS
identity pin or protect every recovery sidecar against same-account/admin path
substitution. EXTRA/DELETE readback is software configuration, not actual physical
power-loss qualification. Do not use this adapter to close the native VFS gap.

Executed component controls:
The authenticated artifact successor is specified in
`AUTHENTICATED-WIRE-DESIGN-V1.md`. Its ordinary provider constructor remains
unavailable; selected-key signature verification is distinct from authenticated
identity enrollment and actual independent administrator/restore separation.
Actual evidence and remaining software boundaries are recorded in
`../candidate-3/TREASURY-CONTINUITY-IMPLEMENTATION-20261005.md`.

- committed full reserve/confirm/consume/confirm history survives reopen; pending
  persists; identical retry remains ALREADY; consumed nonce never becomes NEW;
- known pre-commit rollback and commit-completed/ack-lost UNKNOWN remain distinct
  across reopened exact durable state;
- wrong Scope, conflicting same-ID content and coherently re-encoded altered
  receipt refuse without resetting or discarding retained database evidence.
- hostile TEST-only CHECK-bypass rows with oversize scope/request/receipt or
  wrong operation length refuse Corrupt before Vec deserialization; type/length
  guards and every row fetch share one SQLite snapshot, including reopen checks.

Consensus provider private tests separately cover full bounded current-history
canonical decoding/replay, sequence/order/outcome/pending/nonce substitution,
exact-content receipt binding, stale request nonce and trailing/oversize data.
They explicitly simulate authentication and administrator protection. Missing
real adapter refuses; no caller public boolean creates authority.

Further qualification needs abrupt child/process crash boundaries, two independent
connections racing consumption/current reads, all storage/ACK failures, full
capacity/final confirmation, exact owner database-restore reconciliation, actual
authenticated transport freshness/forgery/refusal and native main/sidecar identity
tests. Each attempt/source/lock/toolchain identity and failed partial is retained.
These component results are not a baseline or whole-candidate PASS.
