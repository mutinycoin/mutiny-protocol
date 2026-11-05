# Historical blocker record — RESOLVED

All three issues below were resolved by ARCHITECT-BLOCKER-RESOLUTIONS-V1.txt.
The rejected permanent bootstrap halt recommendation is historical only. Binding
rules are in BOOTSTRAP-RECOVERY-V1.md. No further vote is requested. Remaining
implementation and physical qualification are work gates, not unresolved policy.

## Original findings and proposals (superseded by the decision)

# Pre-Genesis blockers exposed by the approved amendments

The approval is retained. This is not another vote on the whole packet. No
Genesis/fingerprint or economic change has been made. Section 12 explicitly
requires stopping on the first issue; the other two are demonstrated new
consensus/arithmetic ambiguities permitted by section 13's exception.

## 1. Lost hardware that destroys quorum — the Section 12 stop

The previous annex did not define safe removal/recovery for this case. A recovery
owner signature can authenticate intent but cannot supply the missing TPM vote.
Example: Node A owns 100% of committed weight and its TPM is permanently lost.
Remaining signed weight is zero; no old-set >2/3 certificate can authorize exit
or rotation. This remains true even if its owner has the wallet seed and a newly
attested physical laptop. With exactly one third lost, the survivors have exactly
two thirds, which also fails the strict threshold.

With enough surviving old-set weight AND retained owner recovery authority,
ordinary owner-authorized HardwareRotateV1 safely preserves lineage and bonds
under the existing quorum. No new rule is needed for that case.

**Recommended safe rule to confirm:** no quorum bypass. When surviving committed
weight cannot certify a recovery transition, the chain remains halted indefinitely
unless the old quorum can be restored. This includes permanent loss of the sole
bootstrap TPM. Pending state and the denominator remain intact. Offline status
never authorizes removal. An owner signature alone never overrides finality.

If recoverability despite permanent quorum loss is required, an explicit recovery
authority/checkpoint/finality model must instead be designed and approved. It
changes the >2/3 trust assumptions; it cannot honestly be presented as ordinary
safe rotation or solved by an inactivity timeout. Do not implement that exception
by implication. **Decision needed: accept fail-closed permanent-halt risk, or
require a separate emergency-recovery authority design before Genesis.**

## 2. Fresh bootstrap weight is zero

The exact replacement formula with P=A=S=H=Q=0 produces R=0. Node A cannot certify
its first block; without blocks it cannot earn its first ContinuityPeriod. The
old proposal's one-unit initialization was not silently added to the new equation.

**Recommended minimal exception to confirm:** one explicitly declared provisional
unit for the physically qualified Genesis Node A until the first certified
ContinuityPeriod boundary. Thereafter use the exact approved equation. This is a
bootstrap allocation, not fictitious past participation and never cloud weight.
Do not implement without confirmation because it is outside the exact formula.

## 3. Exact formula versus the separate monotonicity claim

At P=A=S=H=100, no bonds/penalties, score is 100700. After one missed period,
P=H=100, A=101, S=0 gives 100301: a decrease of 399, without an objective penalty
or hardware reset. A qualifying 100-MUT lot aged 5000 periods contributes 5001;
withdrawing it removes that contribution. These follow the requested equation.

**Recommended interpretation to confirm:** the equation controls. Historical P
and lineage age persist, but total voting reputation may decrease when the current
streak resets or an active qualifying bond leaves Q, in addition to penalties and
hardware-continuity reset. Remove the global monotonicity assertion. If strict
monotonicity is mandatory, the equation needs an explicit amendment; a hidden
high-water clamp would alter voter weights and is not authorized.

## Reproducible evidence

`qualification/reputation_model.py` generates `reputation-results.json`: 27
scenario rows, required 1/5/10-year comparisons, entry/exit, authorized and
unauthorized rotation, penalties, zero-history bootstrap, and four fail-closed
negative checks. Conservative maximum quorum arithmetic uses 113 of 256 bits.
No overflow found within the declared input bounds. It is a reference arithmetic
model, not production consensus/TPM/physical qualification. Six model tests pass; this confirms reproducibility of the findings, not Genesis readiness.

Old-versus-new and high-capital cases can concentrate enough weight to block
single-node-loss acceptance, as anticipated by the approved uncapped model. No
cap/renormalization or economic change was applied. All-supply-aged cases are
explicit stress upper bounds, not claimed realizable no-premine histories.

Historical request, now fulfilled: decisions **1 / 2 / 3** together. These resolve only the exposed
blockers; the rest of the Architect's approval remains effective.

The realizable 64-lot schedule (one owner receives all rewards, waits for coinbase
maturity and deposits 64 batches) yields largest voter shares of approximately
54.33%, 82.19%, and 89.89% at 1/5/10 nominal years against three equally old
unbonded voters. This is a conditional concentration scenario, not a prediction.
It fails the approved Survival distribution gate; at 5/10 years that member alone
exceeds two thirds. No countervailing cap, capital restriction or new formula was
introduced. This quantifies the uncapped bond rule's consequence for qualification.
