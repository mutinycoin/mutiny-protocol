# Fresh work issuance and controlled actor intervals: software successor

Independent reviewer and implementer: Codex / GPT-6. Starting source fab06461b0bfd919e9b3e25d0421e1cc2e74c381 in isolated build8-codex-work-issuance-review-v3. Public deterministic TEST-VALUE signing keys only. Windows software evidence; no physical Clock, TPM, Production custody or host-locality qualification.

## Confirmed authorization finding and correction

MAJOR C3/V2: authenticated Request could return a newly signed work offer after its qualified basis became unavailable or crossed MiningEpoch during preparation. Both genuine pre-fix regressions compiled and failed because type5 offers escaped. Failed fixtures and the closed original log remain preserved.

WorkIssuanceStore::issue and Coordinator::issue now require a final clock callback; there is no optional cached fallback. After pure preparation and canonical authority revalidation, the node obtains qualified UTC and then fresh monotonic lease elapsed time. The store rechecks the original quorum lease and candidate's current epoch before signing or durable writes. It caps the returned lifetime by the fresh remaining quorum lease and epoch. Refusal rolls back ticket selection and leaves prior authority/ticket records recoverable. Signature formats, ticket sequence rules, canonical StateRoot and exact receipt retransmission are unchanged. Existing direct fixture callers supply explicitly labelled software readings in test sources.

## Corrected release failure diagnosis

The historical Linux3823cd0 release failure at worker_coordinator_tests.rs:853 was advanced_round=None versus Some(1). Earlier finality, canonical height1, actor height2 and counter4005 passed; nil steps subsequently reached counter4009. The initial finality hypothesis is superseded, and that historical attempt remains FAIL.

The fixture advanced its driver clock while the actor used independent real Instant. A nondefault actor-timer-test-fixtures feature now permits shared controlled monotonic time only through the node DEV dependency. Normal library code has no timer trait, setter or substitutable field and calls actual Instant. Production intervals remain3,6,12,24,48,96,120seconds capped at120. Software checks refuse advancement at2999ms and advance at3000ms, preserve round-one lock/retransmissions before its six-second boundary, and refuse changing an armed timer. Separate release socket checks retain real IO deadlines.

## Identified current-source results

Release worker V2 module12/12, voter V1/V3/V4 module11/11, signed-round1/1, separate real-socket five-second case1/1, issuance store3/3, canonical180-block coordinator chain1/1: PASS; zero ignored. The final source inventories stayed unchanged during each run. Seven additional compiled behavioral mutants were killed; every mutant source and failed log is retained, with exact original bytes restored afterward. These results are component checks, not whole Clock or Production PASS.

The normal consensus artifact reports only its default feature. Separate API compile negatives reject the timer trait withE0432 and setter withE0599. An initial probe had an incorrect dependency search directory and failedE0463; it is retained and excluded from semantic verification. Compile negatives are not behavioral mutant kills.

The proposal construction source tripwire initially passed2/4 and failed2/4: an obsolete result-guard text assertion and newly existing submission relay prepare sites require reviewed semantic updates. That failed attempt remains evidence; repair/recheck is a separate successor. W15 shipping guard feature exclusions are independently owned and need integration verification. Native Linux checks on this successor and remaining targeted Clock/admission mutations remain pending. Windows native storage, elapsed boot identity, authenticated calibration/provider policy, physical accuracy and protected restart blackout remain separate requirements.

External evidence: D:/Mutiny/build8-targets/hyg3/takeover-20261004/source-followup-fab0646, including work-issuance-runtime, issue-timer-mutants, normal-actor-api-negative-attempt2, corrected historical diagnostic notes and final closure index. Original source review and earlier frozen/runtime evidence are preserved. No production signing, provisioning, publication or ceremonies were performed.
