# Frozen platform source differences

The Desktop and Linux catalogs identify different source projections. Their separate recorded gates must not be represented as a single combined candidate pass. The approved integration retains both exact platform variants; restored synthetic test inputs require fresh qualification.

## Five-file replay-parent cohort

For each file below, the frozen Desktop catalog is the exact before-image and the accepted Linux snapshot is the exact after-image in the recorded replay-parent candidate identity:

- `consensus/src/canonical_store_v2.rs`
- `consensus/src/execution_v2.rs`
- `consensus/src/votes_v2.rs`
- `consensus/src/block_envelope_v2.rs`
- `consensus/src/parent_context_v2.rs`

The production patch is `603e1799477aff266267cff22c14e672f3fc09cd277992e6bfb08f2954480d4d`. It introduces reuse of an authenticated replay parent within the existing held snapshot iteration. The source-owner review records retained fresh public checks, exact parent/state/anchor binding and no authority outside that private replay path. The later test append records `productionBodiesChanged: false` and source roster `17c2030b8f92abd0282835ec437bd52bf01fb36239723e3c4340d2c0058710be`.

The production-only review and later full test-bearing file identity are distinct evidence. In particular, the production review's canonical-store hash is not the later test-bearing file's hash. The exact frozen hashes are retained in [source provenance](source-provenance.json).

Candidate integration treatment: preserve the five accepted Linux files as an atomic cohort in the Linux projection, retain the Desktop before-images in the Desktop projection, and require validation of any new combined Windows/Linux source. Copying only part of this cohort would leave its internal proof interfaces inconsistent.

## Chrony adapter

`node/src/host_clock/chrony_task.rs` differs by the recorded Linux compatibility adapter, patch identity `410536277c03deacd88c37a29f7ec17fe1a60f2f0d2d49816e0cc49708675fa5`. The Linux variant adapts the existing revocable conservative lower-bound basis to the vote-clock interface. It does not establish a new source of time or physical qualification.

Candidate treatment: retain the exact Linux variant in the Linux projection and retain the Desktop original separately. This source comparison does not infer that the module is excluded from Windows compilation or prove a new combined build.

## Mempool observation marker

The Desktop `consensus/src/mempool_v2.rs` adds a read-only `change_marker()` method returning SQLite `PRAGMA data_version` and `total_changes`. The Linux frozen file lacks that method. The marker is a cheap observation signal; it is not an authenticity or state proof. Preserve each exact version in its platform projection.

## Public-key validation memo

The Desktop `crypto-v2/src/lib.rs` adds a bounded memo of successfully validated public-key pairs. Its domain-separated SHA256 key covers the public Ed448 and FNDSA key bytes. The memo stores successful validation only, clears at 4,096 entries, and falls back to full validation if its lock is poisoned. Signature verification still runs after public-key validation. Added tests cover valid/invalid key combinations, signature corruption and memo bounds/refill.

The Linux file always performs the native public-key validity/decode checks and has no memo. Keeping these exact variants separate does not approve migrating the memo into Linux or establish a cross-platform security/performance result. Line-ending changes were normalized for semantic comparison; original file hashes remain distinct and unchanged.

## Complete payload availability and candidate layout

All 2,589 frozen Desktop source files are now present and independently hash-verified against the same source record used by all four frozen compile jobs. The final internal 341-file publication is verified in full, including five overlapping independently recovered files. No source bytes remain missing.

The proposed publication layout is `build8/linux/` and `build8/desktop/`, preserving the existing repository root and its history. This keeps all eight divergent common paths explicit. The exact private snapshots remain distinct from the publication projection: generated chain state and machine-path-bearing operator/history records are withheld, and one Chrony provenance comment uses a repository-relative path. Source security guards remain unchanged. The exact approved roster is staged locally, with original machine identifiers unchanged. It has not been built or published; Vercel branch/PR production exclusion remains open.

Static include review exposes the withheld chain fixture, two Treasury documents already absent from frozen Linux, two Desktop test helpers absent from Linux optional trading-service tests, and a dangling include in an unused support copy. The exact-input restoration proposal is described in the reproducibility review. These are reproducibility gaps in the publication projection; the earlier platform gate results must not be attributed to this projection.
