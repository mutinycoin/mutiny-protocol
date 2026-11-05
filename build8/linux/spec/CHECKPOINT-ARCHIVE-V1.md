# Verified canonical checkpoint archive

The current archive transports a complete certified prefix plus its final
canonical state. It does not replace execution with a peer-provided checkpoint
claim. Restore requires the independently pinned Genesis descriptor, initial
state and target, replays every certificate/block and accepted recovery in order,
then verifies every sorted state record and the exact StateRoot. This includes
penalties/tombstones, bonds, controls, approved profiles and sequence counters.

The current binary artifact is `B8CHECK2`, a framed canonical manifest, then for each
height from zero: the block envelope (omitted at zero) and recovery frame (null
if absent). Then the manifest's number of `[key,valueBytes]` state-record frames,
and a final 32-byte SHA-256 checksum over all preceding bytes. Frames have a
4-byte big-endian length. The manifest is `[2,NetworkID,GenesisID,
ProtocolFingerprint,genesisAnchorBytes,height,BlockHash,StateRoot,nextTarget,
timestamp,recordCount,finalizedTipAnchorBytes,retentionFrontier]`.
The tip anchor must match the manifest's exact context, height and BlockHash.
The current supported retention frontier is exactly zero: the archive includes
all history required to reproduce historical authority. Nonzero frontiers fail
closed. StateRoot commits the complete Continuity registry/reputation and
canonical transaction state. The checksum detects incomplete/corrupt artifacts;
it grants no consensus authority.

Limits: manifest 1,024 bytes; block envelope 330 KiB; recovery transport 256 KiB;
state-record frame 256 KiB+64 bytes; at most the existing 10 million state records.
Exporter and importer enforce the caller's explicit byte budget. Export streams
one block/record at a time from one SQLite read snapshot and independently hashes
the sorted state stream; it does not accumulate the historical prefix in RAM.

Destination artifacts and databases must be new. Import creates a durable
quarantine marker and SQLite completion flag before initialization. An existing
uninitialized database or incomplete import cannot open as a fresh chain.
Completion is recorded only after replay, record comparison, root, checksum and
end-of-file checks. The private import initializer is unavailable to ordinary
node launch. Invalid imports remain quarantined for explicit diagnosis/removal.

The local qualification CLI is `--qualification-checkpoint-copy bundle sourceDB
bundleSHA archive newDB byteBudget`. It exposes no peer-controlled file-writing
RPC. It does not open a TPM signer or copy its journal, counters or private keys.
It does not copy a wallet or the transaction mempool. The source mempool, history
and evidence are untouched; this is a canonical checkpoint, not an operational
backup or a voter rollback mechanism.

Pruning is currently disabled. Full archive export is not permission to delete
pending transactions, slashable evidence, historical authority required by the
43,200-height window, or material needed to validate a later checkpoint. Bounded
working-store retention uses an explicit finite local database cap with no
automatic history eviction; its dependency audit is in
CANONICAL-RETENTION-AND-CAPACITY-V1.md. B8CHECK1 artifacts remain historical
qualification evidence; the current importer requires B8CHECK2.

The Rust summary's `archive_hash` (and the V5 CLI field `archive_sha256`) is the
SHA-256 of archive content preceding the footer. The independent Python report
labels this `footer_sha256` and separately records the whole-file SHA-256 as
`archive_sha256`; these are intentionally different digests.
