# Genesis PoW qualification — required Forge decision

Status: RESOLVED by ARCHITECT-GENESIS-POW-RESOLUTIONS-V1.txt. All three
recommendations below were approved with its authoritative clarifications.
This historical decision report is not a current stop. Continue implementation;
InitialPoWTarget remains unset until fleet qualification and derivation pass.

Authority: ARCHITECT-GENESIS-MINING-BASELINE-V1.txt, preserved byte-for-byte,
SHA-256 eadabada509c3333b0e92294620f93b259ae587abfe66be523a6e9c5280e4a14.
The previous three recovery/reputation decisions remain resolved.

## Source audit

The technical annex specifies domain-bound SHA-256d, licensed Worker attribution,
certified-parent authorization, a 60-second target, a 60-block retarget clamped
to 1/4..4, median-past-11 and a local two-hour future hold [superseded 2026-10-03, see the amendment note at the end of this file]. It does not specify
WorkHeaderV1, a block/body commitment codec, a ticket/authorization body codec,
the epoch time origin, or retarget timestamp endpoints. DOMAIN-REGISTRY-V1.json
explicitly lists block and Worker codecs as unfinished. The Rust crate currently
implements recovery, reputation and a signing journal, not block validation.

These are consensus dependencies of the header, not reasons to reuse the
synthetic benchmark. Exact byte order/widths and independent codecs can be
implemented without a separate approval once the semantic choices below are
settled. No new benchmark-only fields are needed or authorized.

## Concrete decisions needed

### 1. Genesis artifact versus first licensed mining candidate

The canonical draft says every accepted block requires licensed work. The annex
creates licenses in the Genesis descriptor/state, but does not define a Genesis
Worker/ticket or a parent for Genesis. The standing campaign deploys production
miner firmware only after stable two-node runtime. A literal licensed Genesis
mining header therefore has no defined authority or parent under current text.

Recommended resolution: Genesis is the explicitly trusted height-zero descriptor
and initial state, with no PoW reward or licensed mining requirement. The first
PoW candidate is height one, bound to the finalized Genesis block and a fresh
active Worker/ticket. Label its vectors `first_post_genesis_candidate`; retain
separate Genesis descriptor/ID/block vectors. Do not disguise a height-one fixture
as a mined Genesis block. This requires an explicit Genesis exception to the
draft's literal every-block rule, so it is not silently applied.

### 2. Epoch time and ticket validity

MiningEpoch is approved as a 60-second time interval, and old assignments retire
on epoch/parent change. Neither the epoch origin nor the consensus time used to
validate ticket expiry is specified. Unix-aligned epochs and Genesis-relative
epochs can select different active Worker assignments at the same timestamp.

Recommended resolution: use unsigned integer Unix seconds in the block header;
Genesis commits time t0; epoch = floor((candidate_timestamp - t0)/60), rejecting
timestamps before t0. Consensus verifies ticket epoch/expiry against the bound
candidate timestamp and the certified parent state. Coordinators stop issuing
expired work using their operational clock; that local decision cannot rewrite
historical block validity. Preserve the approved median-past and future-hold
rules [the future-hold rule was removed by Architect decision D3, 2026-10-03; see the amendment note at the end of this file]. This recommendation remains unapproved.

### 3. Exact retarget interval and quorum pauses

The annex supplies interval and clamp, but not the exact endpoint formula. Sixty
blocks contain only 59 adjacent gaps if their first/last timestamps are used.
At exactly 60 seconds per block, that choice measures 3540 seconds rather than
3600. Normalizing both by 3600 changes target despite unchanged hashrate.

Recommended resolution: the initial target applies to heights 1..60. After
certifying height h divisible by 60, target for h+1 uses timestamps at h and h-60,
including the committed Genesis timestamp for h=60. Let
`s = clamp(timestamp[h] - timestamp[h-60], 900, 14400)` with checked signed
subtraction before clamping. Set `next = clamp(floor(old_target*s/3600), 1, 2^256-1)`
using a wide intermediate. Repeat at 120, 180, etc. The uncompressed 256-bit target
is authoritative; any displayed difficulty is an exact ratio, not float consensus.

The annex distinguishes local WAITING_QUORUM operationally, but defines no
certified pause-duration accumulator for retargeting. Recommended resolution:
use the timestamp span above, including pauses; explicitly accept that a long
quorum halt can ease the next target up to 4x. Do not subtract one observer's
local outage measurements. If Forge instead requires pause exclusion, it must
define the consensus-committed pause accounting before header/vector lock.

## Work that follows resolution

Finish the actual block/body and unsigned work-authorization commitment schemas;
bind the network/Genesis/fingerprint, parent, height/epoch/time, required roots,
licensed Worker/ticket and target before the nonce. Keep certificate signer subsets
out of block identity, as already required by annex section 5. Avoid circular
proposed-block-hash/work-authorization commitments. Then lock exact bytes and
nonce offset, comparison semantics and Python/Rust/C vectors before measuring.

Select and qualify the production hashing path and real monotonic timer;
do not scale the ROM integer-MHz result to a nominal production clock. Measure
the available physical initial set, never Miner 1 multiplied by twelve. All12 is
the intended fleet, not twelve measured rates. No target safety multiplier is
introduced. The final active roster/rates and Genesis bindings remain outstanding.

No port was opened or hardware changed while preparing this decision report.
COM4 remains prohibited. No production firmware, immutable PoW vectors, final
target, ProtocolFingerprint or Genesis is claimed by these artifacts.


## Amendment note (2026-10-03, Architect decision D3)

This document is historical: its open decisions were resolved by `ARCHITECT-GENESIS-POW-RESOLUTIONS-V1.txt`. That resolution has since been amended, and two statements above are superseded:

- The "local two-hour future hold" no longer exists. There is no wall-clock admission or relay hold on unfinalized candidates or proposals; signing a fresh block vote is gated by the qualified clock only.
- The consensus timestamp rules are now median-past-11 (strictly greater, unchanged) AND "a child timestamp is at least its parent timestamp" (equal permitted only when the median rule also permits it).

The text of this file as found, before this note and the two bracketed edits, is preserved in git history (commit `0da9053`, branch `integration/self-contained`), sha256 `ad8b3872ba7e2646b7a2ddf8d8e1672df18603b312374fce9683f446cf445786`.
