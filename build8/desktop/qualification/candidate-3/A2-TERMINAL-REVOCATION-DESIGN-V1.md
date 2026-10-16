# A2 terminal endorsement withdrawal, candidate implementation design

SOURCE-ONLY, UNCOMPILED, UNFROZEN. Prepared by Codex hygiene worker against
`726392c7fb2ec0c0b01947cc06d3c0cbe1ab8ace`. This is a new successor design, not
an alteration of the earlier admission proposal or historical evidence. Governing
direct-user decision: `A2-USER-DECISION-20261005.md`, SHA-256
`218e1f34de1f24d9f3f55ec95e9e2fc65ecda7bed731ca331bdbd1c285618eac`.

## Authority and inclusion

Allocate block operation kind **25** in the canonical operation registry. Kind
23 remains DividendClaim and 24 remains FundedBondCreate. Hybrid wallet transaction
tag 25 is a separate namespace; no decoder fallback crosses those namespaces.
The revocation operation has no wallet signature, fee, manufacturer veto or new
voting threshold. Its explicit withdrawal judgment is authorized only when the
containing block receives its normal finalized-parent certificate. Pure proposal
execution produces tentative state and never installs canonical eligibility.

The including block at H is verified against H-1's full historical authority,
with unchanged `3*signed > 2*total`. The authenticated H state has the exclusions;
the next authority uses H's remaining weights. No valid revocation is refused to
preserve positive weight. Existing state-record/registry validation permits zero
weights; subsequent ordinary RoundMachine construction must return `NoQuorum`.
Neither canonical reopen nor recovery may reactivate a terminally excluded member
or restore bootstrap. Historical state and certificates are not rewritten.

## Canonical carrier and committed context

One operation revokes one exact target. Proposed definite canonical CBOR:

`[2, 25, context_bytes, target_bytes, evidence_bytes]`.

Context is `[1, NetworkID, GenesisID32, Fingerprint32, parent_height,
parent_block32, parent_state_root32, H, H_timestamp]`. H is exactly parent+1 and
H_timestamp is the containing candidate's already validated timestamp. Full
execution supplies this context; an operation's declared timestamp is not trusted.
New CRL validity, entry revocation dates and delegated authority are checked at
H_timestamp, never a validator wall clock, live web lookup or the old admission
time. Duplicate target operations and replays of an already withdrawn target are
rejected atomically. Sorting is for deterministic lookup, not transaction-order
authority. The exact evidence is part of the block body and retained with replay.

Target is `[1, class, scope, identity32]`: class 1 frozen root, 2 intermediate,
3 EK; scope 1 certificate-specific (SHA-256 of exact DER), 2 key-wide. EK key-wide
identity uses existing EKPUB-CANON-V1/HARDWARE-ID-V2. Root/intermediate key-wide
identity uses the reviewed C2 canonical public-key SPKI digest, never the incoming
certificate bytes. The existing reviewed parser admits one SPKI form per supported
key (RSA NULL parameters; named-curve uncompressed EC); this restriction must remain
in force for key-wide matching. Root key-wide targets resolve only through
authenticated frozen-root certificates. A certificate target never silently
becomes a key target. Manufacturer names, serials and URLs are not identities.

The carrier is at most 196608 bytes, context at most 256, target at most 64 and
evidence at most 196096. Check lengths before allocation and counts before loops.
All DER bounds retain existing MAX_CERTIFICATE_BYTES=4096, MAX_CRL_BYTES=32768,
MAX_CHAIN=5 and MAX_CRLS=4. State-record values remain within 256KiB. Bounds are
software choices for review; none is a physical certificate-size claim.

## Evidence routes

Judgment evidence is `[1, 2, true, reason_bytes, [public_evidence_bytes...]]`, with
explicit true terminal trust withdrawal, nonempty reason <=512 bytes, 1..16
nonempty retained byte strings, aggregate <=131072 bytes. No claim that this
proves the allegation. Evidence may include public certificates, CRLs and signed
reports, with private keys, activation secrets and TPM authorization excluded.
The target must resolve through authenticated canonical provenance/frozen roots;
self-asserted affected-member lists cannot establish dependence. Root withdrawal
is judgment-only. A temporary hold may support this explicitly terminal route.

CRL evidence is `[1, 1, target_certificate_der, [signer_chain_der...],
[base_and_optional_delta_crl_der...]]`. It must resolve to the exact typed target,
authenticate issuer or authorized delegated CRL signer, and check certificate
issuer, AKI/SKI, CRLSign, distribution-point/scope, critical extensions, current
validity and entry date at H_timestamp. A delegated signer's separate certificate
path ends at an authenticated existing anchor; a random manufacturer signature
is insufficient. Target and signer paths must terminate at the same authenticated
anchor. Base/delta numbers and matching issuer/IDP scope must agree.
Reason absence/unspecified and permanent reasons are terminal; certificateHold
and removeFromCRL are refused by this route. A delta that removes an entry does
not restore a previous Mutiny withdrawal. Unknown/unsupported extensions, missing
required base, partial coverage and ambiguous indirect issuer associations fail
closed. Targeting an EK key requires canonical equality to the certified key;
targeting an intermediate key requires equality to its canonical certified key.

This requires a separate strict A2 CRL parser. Current admission parser intentionally
discards entry reasons/dates and rejects indirect/delta/partial CRLs; it cannot
be reused as a terminal-revocation verifier. Preserve its historical admission
behavior. The new parser and applicable-route verification require genuine
signed direct/delegated/base+delta fixtures before executable acceptance claims.

RFC 5280 governs issuer/scope and reversible CRL statuses; trust anchors remain
inputs to path validation. Its CRL signature alone does not authorize withdrawing
Mutiny trust in that anchor. [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html).

## Authenticated dependency index

Existing provenance stores root and EK identities plus witness commitment, but
not intermediate paths. Add a typed canonical dependency Book, indexed by exact
lineage/node/hardware generation/profile commitment. Its private construction
uses full available witness verification against committed Genesis roots,
identity classes and the admission's authenticated historical reference time.
For every identity class record exact root certificate/key, intermediate
certificate/key identities and EK certificate/canonical-key identity. Bind the
index to the independently authenticated signed admission and exact witness
commitment. Do not accept a peer path, caller boolean or expected affected list.

The initial source Book retains each complete identifying public witness as a
typed `[2, 65, NetworkID, node32, lineage32, hardware_generation, profile32,
historical_reference_time, witness_bytes]` record, within 131328 bytes. It derives
the complete typed path targets by the same authenticated verification on replay;
it does not trust a serialized caller path cache. The record key commits to node,
generation and profile, so continuity/session rotations of that same profile do
not discard it. StateRoot still independently authenticates historical transition
metadata; importing such a record is never an admission authorization.

Genesis construction/public-witness verification must produce the initial index;
new admissions/hardware changes must produce their index before eligibility can
be introduced. Require complete current and pending-binding coverage; missing
paths must fail closed rather than silently skipping unknown intermediate
dependencies. Keep all prior generation entries to enforce established EK
lineage continuity through node/session/wallet rotation. No equivalence is
inferred between unrelated hardware keys. Root/intermediate effects follow
authenticated current or pending dependencies; historical EK membership mapping
continues across key rotations. This distinction needs final reviewer scrutiny
against the user's established-lineage scope before carrier freeze.

For A2-marked state, Join kind15 and HardwareRotate kind16 use the exact bounded
wrapper `[3, kind, exact_signed_V2_item_bytes, public_witness_bytes]` (arity4,
maximum147488 bytes, signed item maximum16384 and witness maximum131072). The
legacy signed admission profile already commits to the exact witness; no new
signature, domain or caller authenticity assertion is introduced. Full legacy
signature/nonce/native-possession verification remains mandatory. All wrappers'
indexes are authenticated and staged before boundary/exclusion work regardless
of listing order. Existing unmarked historical state keeps its bare V2 carriers
and rejects these wrappers; marked state refuses bare new admission carriers.
Continuity key rotation preserves the same exact profile and therefore its index.

Full candidate execution supplies two distinct authenticated times, including
recovery-projected execution. Fresh admission witnesses retain the locked
finalized-parent reference time (Genesis admissions use Genesis timestamp).
Only newly issued revocation evidence uses the validated containing-H timestamp.
The admission wrapper contains no time authority. Canonical stores provide a
descending ancestry window; replay provides it ascending. Under nondecreasing
canonical timestamps, finalized-parent time is the maximum after exact coverage,
Genesis-time and lower-bound checks, never the first or last window entry.
Older standalone lifecycle APIs lacking the relevant authenticated time fail
closed for new marked admissions/withdrawals; historical unmarked carriers remain.

Correction: immutable source tranches2/3 used containing-H time for fresh
admissions. That draft was uncompiled and superseded here; the existing admission
parent-time rule was never amended by the A2 containing-H revocation decision.

The source successor selects the index only through the committed rule-manifest
entry `terminal-endorsement-withdrawal-v1`, bound to the exact candidate rule
description under `MUTINY-BUILD8-ENDORSEMENT-WITHDRAWAL-RULE-V1`. Wrong commitment
is refused. A2-marked Genesis requires the new public-dependency constructor and
complete witness; the historical constructor cannot produce an incomplete A2
state. Without the entry, existing historical Genesis bytes remain unchanged,
and a dependency Book cannot be added opportunistically. This is protocol
selection in the Genesis fingerprint, not a runtime/feature/class override.

A terminal Book keeps sorted unique typed target records and exact committed
inclusion/evidence context. It grows monotonically. No deletion, replacement root
or reactivation method exists. Canonical reconstruction checks record key domains,
exact codecs, complete dependency coverage and eligibility consistency. Old
source lacking the Book cannot decode it as an opaque protocol record.

The source terminal row is `[2,66,exact_operation_bytes,
[sorted_unique_affected_lineage32...],derived_terminal_no_quorum_bool]` (arity5, at most1024 existing-registry
lineages, maximum231488 bytes). Its private staging derives the inclusion-time
lineage set from the union of the unchanged parent and the fully authenticated
new admission/index projection. No caller supplies that set. Retaining this set
is essential: changing a hardware profile later cannot erase a lineage already
terminally excluded at H. Future matching adds exclusions; it never deletes
the retained set. Restoration relies on the independently verified historical
StateRoot for inclusion-time metadata and rechecks exact witness/evidence bytes;
a peer record or its recomputed root is never independent finality authority.

The halt bit is private derived metadata, never an operation/caller assertion.
It is set when newly valid H withdrawal(s) have been fully applied along with
all ordinary H transitions and the resulting eligible weight is zero. It is
retained monotonically, authenticated through that H's normal parent certificate
and StateRoot, and rederived by full replay. Current-H rows must agree with the
result; a retained halt cannot coexist with regained positive weight. Historical
A2 presence followed by unrelated participation-driven zero does not set it and
does not add a new refusal to otherwise permitted ordinary recovery. Recovery
of any terminal-excluded member still refuses irrespective of this bit.
Immutable tranches3/4's book-presence/current-zero recovery guard was overbroad;
this source successor replaces that uncompiled draft without altering policy.

The separate CRL authority draft validates signer paths at committed H time,
with actual signatures, CRLSign, immutable-anchor algorithm constraints, same
target anchor, bounded direct/delegated issuer scope and required signer-path
revocation. Target cRLIssuer authorizes the exact delegated DirectoryName;
indirect CRL certificateIssuer inheritance remains distinct from serial alone.
Full distribution-point names use exact DER-compatible equality. Relative names,
ambiguous issuer lists, partial reason coverage and AKI issuer/serial alternatives
are deliberately refused by this supported profile. Valid base/delta evidence
requires matching issuer/authority key/IDP, applicable numbers and current dates.
Hold and removeFromCRL cannot create a terminal CRL entry; an applicable delta
removing a previous hold may leave a signer unrevoked, but cannot remove an
existing Mutiny terminal record. Duplicate CRL/entry extensions are rejected by
the unchanged reviewed X509 structural parser before A2 field interpretation.

## Execution ordering and preserved state

Decode and authenticate all A2 operations against the unchanged parent before
ordinary lifecycle application. Merge parent exclusions with all this block's
new exclusions before testing any join/hardware/activation operation. Clear
affected pending membership activation state, retain keys/identity/history, and
exclude affected members before and after boundary application. Unaffected
pending members may activate on their existing schedule. Same-block admissions
are refused regardless of listing order; future admissions consult the same
terminal Book. Ordinary unchanged lifecycle transitions preserve their rules.

Retain balances, licenses, dividends, bonds, unbond/withdraw deadlines, objective
penalties and reputation history byte-for-byte except changes independently
authorized by other operations in that block. Use a separate nonpunitive
membership exclusion method rather than equivocation settlement. No burn, slash,
penalty insertion, key deletion, new money operation or deadline adjustment is
authorized by this carrier. Preserve rights through canonical replay even when
zero weight prevents future settlement confirmations.

Source-only closure status: terminal projection/replay gates now drafted. A derived
terminal H halt explicitly refuses Prepared recovery as NoQuorum,
with no bootstrap rescue. Authority projection checks complete dependencies and
terminal consistency without pretending to authenticate a prospective StateRoot.
A2 recovery replacement with a new signed profile now has a source-only public
witness wrapper and canonical journal/verification ports, within the unchanged
262144 combined bound. Bare marked recovery still fails closed. Full new witness
verification at canonical-parent time precedes prospective authority; retries,
export and finality race guards compare exact outer bytes. None is compiled or
executed; authentic positive/negative recovery closure remains required.
The new TEST-only signed-DER fixtures exercise genuine direct CRL, root judgment,
hold/judgment distinction, retained members, nonpunitive state and replay, plus
distinct admission-parent/H-time and issuer-signature/base-delta controls, but
have not been compiled or executed. Delegated/current+pending/order cases,
actual containing-block certificate/zero-quorum canonical closure and meaningful
behavioral mutants remain required; source formatting is no runtime PASS.

## Required closure

Source tranche first, independent full diff review, then serialized runtime:
canonical carrier vectors/rejections; real signature CRL route/direct/delegated/
delta permanence controls; explicit root judgment and unaffected controls;
root/intermediate/EK certificate/key scope; actual parent-set signed including
block and successor reduced authority; all same-boundary/order permutations;
zero-weight finalization/reopen/NoQuorum without recovery fallback; preserved
monetary and history records; failed operation exact-state atomicity; historical
replay unaffected by local clock/network; useful compiled behavioral mutants.

No test fixture is an authentic manufacturer binding or physical enrollment.
Authentic four Genesis bindings, A5 measured requalification and hard stop E
remain external launch dependencies. Unsupported production admission stays
disabled. No current source-only work is a whole A2 or production PASS.
