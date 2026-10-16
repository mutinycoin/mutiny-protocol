# Adopted quorum activation: owned engineering map

SOURCE-ONLY implementation plan based on direct-human adoption of 2026-10-05. Worktree base is clean Main `3da6ca90e64cbcb7a75e28ebba7f0e05a7c55778`; no predecessor or running A2/Wallet/HYG tree is edited. Production remains disabled pending authentic class/alias inputs, real vetted activation adapter, platform/private enrollment route and physical qualification. Software TEST controls are not actual TPM activation.

## Complete hybrid private-signature funnel

1. Node `hybrid_voter_v2::VotingRuntime::sign` reconciles own canonical state and calls `voter_actor_v2::VoterActor::sign`. Its `replay` wrapper likewise calls the actor's replay. Install/recovery/rotation/reconciliation/observe may advance or restore custody but do not authorize a new signature by themselves. Candidate restore/validation is public native execution only.
2. `VoterActor::sign_for` checks exact requested height/round then delegates to `sign`; `sign` checks backend and pure clock before setting the halting latch. `replay` has a separate pure clock check. Activation refusal must occur before changing the latch, counter, reservation or reducer. Existing genuine-fault latching remains intact.
3. Public lower `counter_voter_v2::CounterVoter::sign` reaches crate-private `sign_at`, then `sign_inner`, then `finish`. Public lower `replay` reaches `replay_at`, then the SAME `finish`. Unsigned reservations are NEW private signatures, including reservations carrying the existing durable clock marker. That marker is not activation authority.
4. The normal hybrid block `CounterSigningBackend::sign_reserved_vote` invocation is `finish` when `signed=false`. It takes the opaque checked permit after shared capability enforcement immediately before private signing; post-sign exact/current/elapsed checks may withhold output but cannot retract bytes already produced. Fully signed counter-protected snapshot retransmission never calls the backend and retains the existing exact replay behavior.
5. Node `continuity_custody_v2::EncryptedVoteBackend::sign_vote` additionally enforces exact custody role/pins and BOTH_REQUIRED. Its public trait method is a raw custody boundary: honest normal fresh block paths must carry a checked, nonconstructible permit rather than arbitrary boolean callbacks. Possession of raw keys by malicious software remains Byzantine behavior; it cannot supply sufficient honest parent certificate weight.
6. Work-probe signing is a separate Domain::ContinuityWorkProbe path, not an admission attestation. NIL carries no block and gains no activation requirement. Legacy V1 TPM sign_digest/voter paths do not gain successor semantics. They must not be usable to certify the selected hybrid successor.

## Native accepted scope and transition classification

Derive scope only after successful full native proposal execution from authenticated canonical parent and selected manifest. A peer flag, prepared body, parsed Binding or caller's own voter map cannot mint it. Store the exact whole block identity, canonical body bytes/public witness commitments, finalized parent/network/Genesis/fingerprint, ordered operation positions/exact wire, claimant tuple, every mandatory EK identity/public area, AK Name/profile and exact authorized consensus-key binding.

Existing kind 15 Join and kind 16 HardwareRotate carry fully verified node-admission Bindings. Both enter accepted admission scope. Kind 21 ContinuityKeyRotate invokes Binding::verify with a newly accepted Continuity generation while requiring unchanged hardware/profile/original Node identity and current Node signer; it enters the new accepted consensus-binding scope without inventing new hardware qualification. Kind 22 NodeKeyRotate has no new admission Binding or AK/profile verification: it is ordinary existing Node-key authorization plus proposed-key hybrid possession and updates node_current, retaining the birth Binding. It is excluded from a new activation requirement by itself; the exact whole body still invalidates an admission-bearing block capability if it changes. Ordinary wallet/key/value operations are excluded.

Recovery's Prepared value contains a new verified replacement Binding even when no admission operation appears in the resumed block body. Scope must include that exact recovery commitment/binding and distinguish its authenticated recovery authority from ordinary parent authority; no empty-body shortcut. The reviewed A2 carrier/public-witness wrappers will be integrated normally later and must provide their native accepted receipt, not an ad-hoc opaque parse or type-25 shortcut.

Exact receipts describe transitions accepted by execution, including pending membership accepted before its effective epoch. They do not add StateRoot fields, fees or new consensus carriers. Current/retired/pending physical lineage and money/age/reputation/penalties retain existing rules. A malformed or duplicate transition must fail native execution before any local activation request.

## Freshness input: precise missing contract

There is NO applicable pre-sign absolute deadline in the present VoterActorV2. Its precommit_deadline is armed AFTER a successful precommit using the existing 3*2^min(round,6), capped-120-second timeout. Borrowing that deadline for earlier activation would change timing. VoteClock exposes qualified UTC seconds only; it supplies neither elapsed continuity nor a finite activation freshness bound.

The authorized routine design therefore requires an explicit positive finite LOCAL verifier lifetime/deadline configuration, checked arithmetic and a trusted local monotonic elapsed source; absence, zero, overflow, regression or unavailability fail closed. No numeric default or new consensus window is supplied. The existing qualified vote clock remains an independent requirement. A capability expires no later than its explicit local deadline and is consumed on expiry/private signing. A different phase/round signature needs a fresh independent challenge capability; an exact already durably signed retransmission does not. Renewal never changes locks/reservations/round/BFT deadlines or fabricates NIL.

## Nonconstructible capability boundary

Public LocalObservation is cloneable audit data and is NOT a capability. No From<LocalObservation>, boolean result, public struct literal, peer receipt, parsed profile or proposer assertion may authorize the private signer. Owned challenge completion must compare privately retained fresh unpredictable secrets for EVERY exact EK class, recheck current canonical scope and elapsed time before/after, and issue an opaque non-Clone/nonserializable signer/phase/block-bound token only within the trusted workflow. Expiring or failed completion consumes the attempt. All private buffers and response storage must use vetted erasing ownership; no custom crypto or secret logs.

A production adapter/qualified physical-class provider is currently absent, so no production factory is available. Private cfg(test) adapters may exercise mechanics only; test bypass construction is unavailable in the ordinary library/shipping graph. Public trusted adapter interfaces must be explicitly pinned/qualified, never interpreted as arbitrary caller claims. A capability requires exact verifier/signer ownership and is forgotten on restart. The counter snapshot remains the durable authority only for already fully signed bytes.

## Intended owned source/spec changes and checks

Shared consensus activation scope/capability policy; AuthenticatedRound executed proposal receipt storage; CounterVoter pure sign/replay prechecks and finish boundary; VoterActor nonfatal activation deferral classification; Node owner workflow/custody plumbing; canonical historical successor selection; new normative successor commitment/domain entries and source identity. No changes to the seven frozen dependency/source locks unless a narrowly required existing-vetted dependency edge is reviewed.

Successor selection is an authenticated named RuleManifest commitment carried by immutable GenesisParameters/fingerprint. Missing entry preserves old semantics; mismatched/unsupported selected commitment refuses. Historical replay verifies the exact selected rule/public native scope and existing strict parent certificate without local/live/private/time checks; it does not reinterpret old certificates or mistake the certificate for a mathematical TPM proof.

Meaningful controls must include: direct lower sign and unsigned replay bypass; Actor/Node alternate entry; locked reproposal selecting actual locked block rather than caller argument; unchanged reducer/counter/reservation on missing/expired capability; every EK class and both hybrid halves; exact body/witness/position/parent/network/Genesis/rule/claimant/EK/AK/consensus-key and cross-signer/phase substitution; monotonic loss/regression/deadline overflow; interrupted unsigned restart reactivation vs exact fully signed retransmit; lock-preserving renewal; ordinary/NIL/probe unaffected; final offline replay after expiry without secrets; multi-admission completeness and resulting membership excluded from containing-block denominator. TEST simulation results and later authentic physical adapter qualification remain separate.

## Concrete source successor, not yet compiled

`activation_attestation_v1` derives native executed read-only Scope/Request and
owns Gate. `activation_private_workflow_v1` implements begin/complete with direct
`mutiny_crypto_v2::fill_os_random`, complete mandatory class material, bounded
encrypted credentials, zeroized owned private responses and pre/post current
context. A request is never a signing grant. No conversion from Node's public
LocalObservation exists. Counter/Actor/HybridVoter expose owner-local configure,
native request, begin, complete and cancel; none accept a completion boolean.

The normal encrypted custody backend now refuses raw sign_vote and requires an
opaque exact-message/signer/immutable-rule PrivateSignPermit at
sign_reserved_vote. CounterVoter mints an ordinary permit only after native or
counter-protected NoAdmission classification; it consumes private activation for
Required classification. It rechecks elapsed after private signing. Existing
trusted software backends use the compatibility trait method, but are not a new
production custody implementation. The immutable activation-rule pin prevents
mutable low-level Round replacement from downgrading the rule at custody use.

Version 4 snapshots contain only PUBLIC slot classification in the existing
counter transaction. Version 2/3 byte-exact read/encode remains. Exact signed
retransmit calls no private backend. All unsigned Required/unknown reservations
fail closed without local renewed activation, even with the old clock marker.

Elapsed can advance between Actor and Counter pure prechecks. The actor clears
only its tentative local latch for Activation refusal when Counter remains
unpoisoned; no durable mutation happened. Actual post-mutation poison keeps the
actor halted. This does not change existing time-refusal or safety-fault rules.
The prepared controlled race test executes the actual lower replay refusal and
shared actor response, with a modeled protected reservation classification; it
does not claim to run a full own-canonical public Actor sign route.

The existing vetted zeroize 1.9.0 dependency is promoted to normal consensus
usage. In this isolated successor only, node/transport/wallet/desktop and the
explicit qualification probe locks add that one existing package edge; all
package/version/source/checksum resolutions are unchanged. Consensus already
records its DEV edge; crypto/release-signer locks are unchanged. Historical
original locks are retained externally. Cargo --locked acceptance remains unrun.

## Exact A2 reconciliation requirement

The reviewed Main base3da lacks `admission_public_v3` and the A2 capacity/accepted
dependency changes. After their independent native correction/review and normal
merge, Scope extraction must use `admission_public_v3::item(raw, committedParams)`
for kind15/16. Full native execution must have succeeded first. Receipt operation
WIRE and the whole scope BODY remain the exact OUTER V3 carrier bytes; the
accepted Binding comes from exact inner signed V2 bytes, and class Material uses
that exact included witness. Do not strip wrappers or infer acceptance from
Carrier::new/decode. Kind21 uses its retained accepted profile/witness dependency;
no new consensus witness carrier is invented. Recovery remains a separate exact
accepted transition. This requirement is not satisfied by current old-base unit
models and must be implemented/tested before combined integration qualification.

## Test-host and input closure proposal

Normal library material/start rejects Production-class scopes, including
Production-shaped synthetic certificate fixtures. Root explicitly requires
that refusal remain. A genuine native public-certificate scope plus simulated
private activation positive may be hosted inside consensus cfg(test), with a
private exact modeled adapter allowance unavailable in the ordinary library.
No public feature, Node bypass, public caller flag, changed Genesis class or
physical claim is authorized by this proposal. Root review precedes that test
adapter tranche. Existing ordinary Node admission positive coverage remains
missing until a supported TEST-value fixture integration is reviewed.

Current added controls are private protocol models, counter-store/reducer/dual
signature controls with MODEL classification, snapshot public-classification
roundtrip, and controlled pure-expiry latch response. They exercise actual OS
randomness, complete private result matching, typed expiry/context failures,
store bytes/real hybrid signatures where applicable. They do not exercise actual
TPM commands or prove native admissions, qualified class aliasing, current Node
delivery, whole history or physical uniqueness. All controls are UNCOMPILED.

Remaining engineering verification: Root full diff review; ordinary compile and
locked graph/guard verification; these bounded controls; native executed A2
receipt extraction after reviewed A2 merge; authentic software certificate plus
modeled activation end-to-end proposal/sign/history/restart controls; Node
public-path coverage when constructible; final successor manifest regeneration
under reviewed complete software definitions. Physical inputs, actual adapter,
private enrollment transport, qualified current/elapsed source and finite local
deployment freshness setting remain genuine production prerequisites.

## Source-v2 custody-entry elapsed correction

Root's independent review identified a source-v1 gap: consumption checked expiry
before calling the backend, while post-sign expiry could refuse output only after
the backend had already produced a private signature. Source-v2 retains trusted
elapsed source, consumption baseline and deadline inside the opaque permit.
Its custody-entry check latches expiry, unavailable/backward elapsed or poisoned
continuity. The normal encrypted backend checks on entry and again immediately
before the actual private signing call, after pin/counter checks. Post-sign
checking still refuses output if signing crosses the deadline. Ordinary permits
retain exact context checking without any elapsed/provider dependency. This
software check does not promise that an OS cannot deschedule between the last
check and invocation; it prevents entering that invocation with an already
observed expired/unknown/regressed permit.

Two additional UNCOMPILED private controls cover a consumed permit's elapsed
failure latching and advancing the clock between consumption and backend entry.
The latter runs the real counter replay/reducer and hybrid backend with modeled
classification/private activation; it requires zero private-sign calls, unchanged
counter/database, retained unsigned reservation and signer poison on refusal.
It does not claim ordinary Node encrypted-custody/native admission witness or
A2 integration coverage. Those still require the separately reviewed native test
host and receipt adaptation described above. Source-v1 remains retained exactly.
