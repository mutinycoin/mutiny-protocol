# Hybrid transaction admission and body assembly V2

Status: candidate implementation; synthetic qualification only. No production
RPC, canonical finality executor or installed node has been switched to it.

`mempool_v2` accepts only the explicit V2 transaction enum: hybrid transfer or
funded hybrid wallet rotation. It uses a separate SQLite application ID
0x4d554d32 and schema version 2, rejects foreign databases, and binds its context
to the exact GenesisID and ProtocolFingerprint. There is no V1 decoding fallback.

Only a verified canonical executor may provide the finalized anchor, complete
execution state and confirmed transaction IDs. The queue cannot authenticate
finality itself. It stores the exact anchor and recomputed StateRoot as its
admission basis. A request against another state, stale head or unknown basis
fails. Reconciliation advances one height at a time; conflicting same-height
history or rollback fails. Reconciliation at the same exact basis revalidates
pending rows and rebuilds derived reservations without accepting new confirmation
claims for that already-processed height.

Admission verifies both owner signature halves, current wallet authority,
UTXO ownership/maturity, fee/conservation, context and inclusion-height bounds.
It reserves each input and, for a rotation, that wallet authority. Pending change
and pending new owner keys are not canonical authority. Matching duplicate
submission is idempotent; conflicting bytes or reserved inputs fail. A distinct
valid signature representation with the same transaction ID is a local submission
conflict, not consensus-invalid evidence.

Reconciliation marks authenticated inclusions confirmed, expires transactions,
detects spent inputs and revalidates remaining authorization against canonical
wallet state. A finalized owner rotation rejects pending old-key payments even
when their UTXOs remain unspent. Final statuses release reservations. Status,
reservations and basis update in one immediate SQLite transaction with FULL
synchronous rollback journaling.

Local resource limits are 64 MiB pending bytes, 65,536 retained lifecycle rows
and 128 MiB database pages. Lower caller-selected pending-byte limits are allowed.
An exhausted database fails admission; it does not prune canonical history.
Wire objects remain bounded by the existing 16 KiB consensus transaction limit.
These are local storage/selection policies, not new transaction validity rules.

`assembler_v2` selects at most 128 pending entries in transaction-ID order from
the exact verified parent basis. It validates operation bounds before copying,
derives licensed reward ownership from V2 state, and executes each tentative body
under the explicit V2 rules. Invalid/oversize trials are omitted. The final body
and numeric ticket produce a complete StateRoot before Node work signing.
Selection creates no confirmation, PoW, quorum or durable canonical state.

Evidence: `hybrid-assembly-mempool-v2.log` passes five license/execution tests and
two queue tests (one is the subprocess crash entry point). The queue test covers
reopen, context isolation, duplicate/conflict handling, rotation invalidation,
expiry, stale/forked basis, resource exhaustion, untouched foreign schema,
injected admission/reconciliation SQL failures, reservation reconstruction, and
an abrupt child exit with an uncommitted rollback journal. This is process-crash
evidence, not a physical power-cut claim. All signing identities are synthetic.

Remaining integration: hybrid Continuity state and lifecycle execution,
certified durable chain installation/replay, node RPC/session ingress, complete
Desktop submission/status UX and final reproducible qualification.

---

## Amendment A1 (candidate 3, Lane P work package WP-R, 2026-10-04)

Status: PROPOSED-UNFROZEN; Windows-host software evidence only. Authority: Order P2 and P4; design
`qualification/candidate-3/P-LANE-DESIGN-V1.md` 3.1, 3.7 and 1.a.5; amendment AM-9 m3. WP-POOL will
replace `mempool_v2` for the V2 runtime; this amendment covers the interim pool only.

"Funded hybrid wallet rotation" in line 7 now means the funded wallet-rotation bundle (hybrid
transaction tag 25, `spec/FUNDED-WALLET-ROTATION-V1.md` amendment A1). The retired
`[2,21,rotation,transfer]` wrapper cannot be decoded, so it can neither be admitted nor held: a row
carrying it makes every pending read fail (`old_rotate_wrapper_rejected`). Admission reserves every
input of the bundle and its wallet authority (one pending rotation per authority, first seen wins;
`pool_reserves_inputs_and_authority_and_reconciles_bundles`). The bundle's finalized reference is
checked at admission: `admit` verifies only a reference to the admission anchor itself (fail closed);
`admit_with_history` accepts the canonical anchors the local store supplies. Reconciliation re-checks
the window, inputs, authority generation, preconditions, signatures, conservation and fee, but not the
already verified finalized reference, because finalized history never changes (design 1.a.5). The
pool reports every pending bundle's reference height through `op_envelope_v1::PendingReferences`, so
`CanonicalStore::prepare_pending` gives the assembler those anchors
(`bundle_valid_across_head_advance_within_window`). A finalized rotation still rejects pending old-key
payments. No fee, surcharge or recipient is added.
