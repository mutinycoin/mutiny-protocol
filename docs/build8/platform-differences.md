# Frozen platform source differences

The Desktop and Linux catalogs identify different source projections. Their separate recorded gates must not be represented as a single combined candidate pass. No source payload is added by this documentation change.

## Five-file replay-parent cohort

For each file below, the frozen Desktop catalog is the exact before-image and the accepted Linux snapshot is the exact after-image in the recorded replay-parent candidate identity:

- `consensus/src/canonical_store_v2.rs`
- `consensus/src/execution_v2.rs`
- `consensus/src/votes_v2.rs`
- `consensus/src/block_envelope_v2.rs`
- `consensus/src/parent_context_v2.rs`

The production patch is `603e1799477aff266267cff22c14e672f3fc09cd277992e6bfb08f2954480d4d`. It introduces reuse of an authenticated replay parent within the existing held snapshot iteration. The source-owner review records retained fresh public checks, exact parent/state/anchor binding and no authority outside that private replay path. The later test append records `productionBodiesChanged: false` and source roster `17c2030b8f92abd0282835ec437bd52bf01fb36239723e3c4340d2c0058710be`.

The production-only review and later full test-bearing file identity are distinct evidence. In particular, the production review's canonical-store hash is not the later test-bearing file's hash. The exact frozen hashes are retained in [source provenance](source-provenance.json).

Candidate integration treatment: preserve the five accepted Linux files as an atomic cohort, retain the Desktop before-images for reproduction, and require validation of any new combined Windows/Linux source. Copying only part of this cohort would leave its internal proof interfaces inconsistent.

## Chrony adapter

`node/src/host_clock/chrony_task.rs` differs by the recorded Linux compatibility adapter, patch identity `410536277c03deacd88c37a29f7ec17fe1a60f2f0d2d49816e0cc49708675fa5`. The Linux variant adapts the existing revocable conservative lower-bound basis to the vote-clock interface. It does not establish a new source of time or physical qualification.

Candidate treatment: retain the exact Linux variant in the Linux projection and retain the Desktop original separately. This source comparison does not infer that the module is excluded from Windows compilation or prove a new combined build.

## Two unresolved common-file comparisons

Exact frozen Desktop payloads are still required for:

- `consensus/src/mempool_v2.rs`
- `crypto-v2/src/lib.rs`

Their expected hashes are recorded, but their differences cannot yet be reviewed from hashes alone. Do not silently select either platform's version or claim these differences resolved.

## Payload availability

The full Desktop catalog has 2,589 rows. Approved snapshots and publication records now supply 2,253 exact file payloads; 336 remain pending. The original 341-file request remains valid because five subsequently recovered files can serve as independent cross-checks when the publication arrives.
