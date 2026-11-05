# A2 body capacity successor V3

This normative candidate implements the direct user capacity decision of 5 October
2026 (normalized decision SHA256
`47a1480b06dc780e3838f348ad4b8619707384f56a892ee6db667475e44b336d`).
It is explicitly unfrozen: source/component validation does not freeze a carrier,
activate Production, or qualify authentic hardware. Import/V9 and unmarked-rule
history retain their original bytes. Path B separately permits remote/VM execution
and TPM forwarding; authentic physical TPM evidence, verifier-owned fresh activation
and class-complete unique physical lineage remain required and unqualified inputs.

## Exact rule selection

Only an authenticated canonical parent whose Parameters commit the exact current
`terminal-endorsement-withdrawal-v1` rule description receives this capacity.
The description is the canonical 29-item version2 array documented in
ENDORSEMENT-WITHDRAWAL-REGISTRY-V1.json. It commits all capacities and projection
algorithm version1. The selected rule participates in the protocol fingerprint.
Caller flags, matching caller roots, prefixes, markers and structural parsing do
not authenticate selection. Current and retained historical parent capabilities
are issued by the trusted canonical store. A historical capability permits
verification; it cannot authorize old-height issuance/signing. Full native
admission/withdrawal, licensed execution, PoW and parent quorum remain mandatory.

## Ordinary projection and one reserve

Ordinary items remain at most16,384 bytes. Transactions never use the reserve.
Combined transaction/operation count remains4,096, including a reserved item.
At most ONE operation larger than16,384 bytes can use the reserve. It must decode
exactly as either an enabled version3 kind15/16 public-witness wrapper (at
most147,488 bytes) or a version2 kind25 terminal-withdrawal operation (at
most196,608 bytes). All child bounds, signatures, contexts and native rules remain.
Unknown kinds, malformed inner bytes, alternate CBOR, legacy kind15/16 bodies and
cross-namespace transaction values cannot qualify from their prefix.

Remove exactly that one qualifying large item and canonically re-encode the whole
remaining BlockBody, retaining height, reward owner, subsidy, fees, list boundaries,
order and every remaining byte string. The projection must satisfy BOTH the
unchanged65,536-byte encoded-body limit and65,536-byte raw-item aggregate, together
with every ordinary per-item/count/duplicate/participation ordering/execution rule.
Do not estimate a projection by subtracting lengths. Small A2 items stay entirely
inside the ordinary budget. Two oversized items refuse atomically; no eviction,
partial execution, extra fee exemption, authority or quorum exception is introduced.

The full body is at most262,150 bytes:65,536 +196,608 raw reserved bytes +5-byte
byte-string prefix +at most1-byte array-prefix growth. This is a conservative exact
encoding bound, not a claim that independent child maxima are jointly constructible.
Body grammar/version/domain stay unchanged: BodyRoot remains
`H(MUTINY-BUILD8-BODY-V1, exact complete body bytes)`.

## Namespace separation

BlockBody.operations kind25 is TerminalEndorsementWithdrawalV1, outer version2,
arity5. BlockBody.transactions tag25 is FundedRotationV2, arity7. The decoders have
no cross-type fallback. OP kind23 remains DividendClaimV1 and is unchanged.

## Envelope, proposal, storage and recovery

The selected certified envelope uses the existing version2 five-field container
and exact component bytes. Maximum1,942,044 =512 header +262,150 body +8,192 work
authority +1,671,168 certificate +22 container overhead. The proposal/journal
maximum is270,871 =512 +262,150 +8,192 +17 for its version3 four-field container.
The transport object ceiling stays2,097,152. Existing ordinary containers/routes,
SignedOperation kind9, kind7 recovery and their budgets do not silently widen.
New Node/transport routes and schemas must be explicitly registered and reviewed;
shared capacity/source tests do not establish that ingress/store closure.

Canonical recovery retains and makes available the exact WHOLE certified envelope
bytes, including body, work authority and parent certificate, in the bounded
finality evidence BLOB. State-record limit262,144 and historical recovery kind7
remain unchanged. A body262,150 already exceeds the state-record cap by6 before a
wrapper: it must not be embedded in such a record, silently truncated, split into
uncommitted pieces, or replaced by a hash-only locator. Bounded authenticated
serving/replay/restart obtains the exact retained canonical H-1 capability, then
checks full native execution, PoW, certificate, roots and byte-for-byte equality.
Evidence availability and retention are mandatory; a syntactic BLOB is not authority.

Admission witnesses use independently authenticated FINALIZED-PARENT time.
New revocation evidence uses the independently validated CONTAINING-H timestamp.
Recovery public witness uses its specified authenticated canonical-parent context.
None of these are operation/caller clocks or live-network replay inputs.

## Qualification required before freeze

Verify exact boundaries/+1/CBOR-width transitions, wrong-rule and malformed-inner
refusal, namespace separation, two-large atomic refusal, small/large ordering,
unchanged money/fees/quorum/deadlines, full native finality/reopen/recovery/replay,
typed ingress/queues/relay and actual maximum delivery under unchanged deadlines.
Separate structural size-only fixtures from the largest constructible genuine
authenticated public fixture. Native complete campaigns and independent review
remain required; no Production signing/sealing/TPM ceremony is authorized here.
