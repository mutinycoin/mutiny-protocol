# Direct user decisions during the Build 8 takeover

These decisions supersede the identified earlier document requirements. They authorize isolated implementation and TEST-VALUE verification only, with all original production exclusions preserved.

## Maker first funding

Unfunded offers remain above consensus. First canonical funding/lock execution requires the maker's current canonical wallet authority under the existing block-execution order. A retired-generation-only offer cannot acquire a funded commitment: obtain a newly reviewed and signed offer from the current authority. No new commitment operation, carrier or fee is introduced. Local timestamps, signatures and old block references are not evidence that an unfunded offer existed canonically before rotation. This supersedes Forge's earlier pre-rotation-unfunded-existence requirement and the old T4 positive accepting retired-maker offers with current settlement approvals.

Finalized funded locks retain exact committed terms, destinations, deadlines and existing claim/refund authorization. Rotation cannot cancel those obligations or grant retired keys new authority. Required tests: rotation before funding, funding before rotation, actual same-block phase order, stale pending offers and funded-lock survival. Trading precedes payment transactions; first funding in a block thus sees the parent authority before a rotation transaction in that same block. Changing this order is not part of the decision.

Implemented first-funding authority in `trading_v1::apply_one`, after exact offer verification and before the funding action. The existing parent WalletBook authorizes the maker's offer descriptor; settlement approvals alone cannot authorize a retired offer. Claim/refund/release carriers have no new maker offer and retain their existing rules. Windows offline/locked `maker_offer_v2` passes 13/13, zero ignored, including read-only validation, assembly, certified execution, pending-pool reconciliation and finalized replay. The same-block positive preserves the exact funded lock across rotation and refunds only under current authority at its committed deadline. Closed test log SHA256 fab857863c46d4d58b79444ace96ba254d6d065c219ce9f4b07e797d639501c9. An initial test compile typo was preserved separately; it is not counted as a behavioral test.

Existing maker vector bytes remain SHA256 cc5433739899faa30d131357dd7fcb61f21b1bba4844a58c4b068702a4e2a204. This is focused software TEST-VALUE verification, not full candidate qualification.

## K1 public witness permission

Permit public EK certificates, public key areas, CRLs and nonsecret activation records as authenticated admission evidence. Exclude private keys, seeds, TPM authorization values, activation secrets and all other private material. Canonical encoding, bounds, authentication, evidence availability and retention must support independent validation and replay. Admission freshness/certificate/revocation checks use the specified context; replay never uses a current verifier clock or a live lookup. Public EK evidence identifies devices; distribute/log only what verification requires, with no anonymity claim. A signed activation result is not automatic proof of credential activation or host association.

Exact changed clause: the integration annex's restricted-EK clause at original lines 242-244 receives the narrow amendment appended to `spec/DECISION-TECHNICAL-ANNEX-V1.md`. Design K1's distribution hold is resolved by this direct permission, not by weakening certificate or possession checks. Private evidence remains restricted. The original checkout is untouched.

## K2 production host binding — historical decision superseded by Path B

Retain hard stop E wherever required physical-host association is unestablished. No permanent Architect approval, discretionary admission committee or witness assertion replaces an enforceable binding. EK/AK checks alone prove neither local node execution nor exclusion of a remote TPM relay. Continue public-witness software work and TEST-VALUE testing; unsupported Production eligibility remains disabled. Prepare the concrete host-binding threat model, guarantees and limitations. Report an unsatisfiable locked requirement as the exact architectural conflict for a later explicit policy decision. Never silently weaken it or describe disabled post-sealing enrollment as completed.

Exact retained clause: the annex's host-association hard stop at original lines 271-273 remains unchanged and is reaffirmed by the appended amendment. This is a launch dependency and does not stop other work packages.

### Direct superseding decision, 2026-10-05: Path B

The paragraph above records the earlier instruction, not current policy. The later direct Architect decision adopts Path B: qualifying physical TPM authenticity, fresh key relationship and one active canonical voting lineage remain required; node execution in a VM, remote execution and TPM request forwarding are accepted limitations. Proof that the node executes on the TPM's physical host is removed as a launch dependency. Software TPMs/vTPMs alone remain ineligible. Physical hardware classes, authenticated alias relationships, actual activation and atomic uniqueness/recovery remain incomplete requirements. A2 revocation and monetary protections are unchanged. Exact decision and clause changes are retained in the existing CODEX-PATH-B documents.

## Activation trust model — direct adoption, 2026-10-05

The existing parent-set strict weighted quorum certificate explicitly attests that every honest signer independently performed fresh private credential activation for every admission the exact block accepts. This uses the existing Byzantine trust assumption, no new committee, threshold, unanimity or responsive-only denominator. Each signer originates its own unpredictable challenge, bound to exact block, finalized parent, network/Genesis, selected rule, claimant, EK, AK Name and consensus-key tuple. Another signer's receipt or proposer assertion is insufficient. Actual TPM activation proves the required key relationship, not node execution location or hardware uniqueness.

The gate applies at every new signing boundary, including locked reproposals and alternate paths. Missing/expired authority prevents a new signature without clearing locks/reservations or manufacturing NIL. Exact durably authorized signature retransmission retains its existing rules. No numerical lifetime is supplied by this decision. Historical replay verifies historical rule, parent quorum and public evidence without private transcripts, current clock or live lookups. Existing older certificates acquire no new meaning retroactively.

Implementation/TEST verification is authorized. Actual MakeCredential/ActivateCredential adapter, private enrollment transport, class relationships, canonical-current provider and qualified deployment inputs remain software/input/physical obligations. The normal Production material route is disabled. The integrated working branch has targeted activation controls; they are not completed physical activation or full candidate acceptance.

## Treasury external protected continuity — direct adoption, 2026-10-05

Use an authenticated separately administered monotonic continuity service outside the admission database's restore/access authority. Its only authority is verifier issuance/consumption continuity: no spending keys, destinations, monetary rights, membership, quorum or mandatory online ordinary-consensus/payment/replay role. Authentication alone does not establish monotonicity; exact service identity/history and stale/fork checks are required.

Validate request, proof and authorization before durable external reservation/consumption; acknowledge external success after durability, then complete local SQLite commit before local admission success. Exact operation/content/context identity controls idempotent retries and concurrent conflicting consumers. Timeout is UNKNOWN, not failure; recorded consumption never recycles by TTL. Any ambiguous external/local outcome freezes both affected issuance and admission until authenticated exact reconciliation completes only the matching authorized local transition. Preserve consumption; never reset counters, trust an older restored database or repeat logical admission. If reconstruction is impossible, remain frozen.

No new public proof format or consensus threshold is authorized. The service's actual administrator, protected state, authenticated deployment and restore boundary remain qualification inputs. Native SQLite/VFS/journal/path handling remains unfinished software independent of the service model; real power loss remains separate physical evidence. The settled trust decision must not be requested again or reclassified as an undecided engineering design.
