# Specification amendment register: D3 timestamp admission (2026-10-03)

Authority: Architect decision D3 (2026-10-03) and the follow-up instruction to amend `ARCHITECT-POST-POW-CONTINUATION-V1.txt` and to reconcile equivalent active statements across the authoritative specification set.

## The approved rule (what every amendment must agree with)
1. **Consensus timestamp validity** (deterministic, clock-free, identical on every validator): a block timestamp is strictly greater than the median-time-past of its ancestor window (median-past-11, unchanged), **and** is not earlier than its parent's timestamp (equal is permitted only when the median rule also permits it). A window-maximum test is acceptable only when the window contains the actual parent and only validated ancestors of it; both canonical stores enforce that condition.
2. **No wall-clock bound on admission** of unfinalized candidates or proposals, in either direction. The former local two-hour (7,200 s) future hold is removed.
3. **Signing a fresh block vote** is gated by the validator's qualified clock alone (`block.timestamp <= qualified UTC now`, zero allowance). Replay, finalized ingestion and historical validation never read a receiver clock.

## Amended documents (provenance: the text as found is in git history; each amendment keeps the superseded wording quoted in place)
| Document | As-found sha256 | Amended sha256 | As-found commit | Amendment |
|---|---|---|---|---|
| `ARCHITECT-GENESIS-POW-RESOLUTIONS-V1.txt` | `7cde6b5b0d68060d32a00a0b40ee78c70632899e2d26cfa8dd69c8d1c65201de` | `06037bb72a13d563a8849d75ae756756b4df391ff873235dc61b3df28925b395` | `0da9053` (branch `integration/self-contained`) | 2E adds the parent rule; 2F (two-hour hold) superseded; Ticket-replay exception struck |
| `GENESIS-POW-OPEN-DECISIONS-V1.md` | `ad8b3872ba7e2646b7a2ddf8d8e1672df18603b312374fce9683f446cf445786` | `dc352ce47f995f9a61f81af2a215d77f823981b33b7a814d90654cf397358129` | `0da9053` | historical document: two supersession marks and an amendment note |
| `WORK-AND-BLOCK-CODECS-V1.md` | `9d5b3dea470a2997fb5d475328acfa69266838a0b27c8f16b5ffc5609bf26b35` | `42ea1f720d1f406e5add8cb8bc0f0de77fdb6fdc49da02c01d5e97df963714fb` | `0da9053` | authority line records both hashes of the resolutions document; time section amended |
| `DECISION-TECHNICAL-ANNEX-V1.md` | `19fbd1b35af022bb20884be4d456f4cffad99c3935d51926f2042f4b03b5a877` | `6a21ff1e40eef86f792e19f559b88b86a6d877fb00292e6f951574611d79b1c4` | `204c891` (branch `succ/docs`) | the "Timing/difficulty" row said "Future >2 hours held until locally admissible"; superseded in place, parent rule added, amendment note appended |
| `ARCHITECT-POST-POW-CONTINUATION-V1.txt` | `873b8d33e2b228f99fa1df9cc22e56e8136d4d705ae3cbab9ef7d6b06e4da76d` | `fcf5444180a71b116c0d6687646bf42a4f39f46b4e7a26af36f4d67fc2fa1987` | `204c891` | list items "MTP rules" and "local future-hold behavior" amended; banner added |
Note on the technical annex: the copy tracked in the repository before this change was an older, shorter version (472 lines); the as-found working copy (493 lines) is the current authoritative text and was imported first.

## Hash pins observed (searched `spec/`, `genesis/`, `qualification/*.json|md|txt` in the original checkout)
* `ARCHITECT-POST-POW-CONTINUATION-V1.txt` is cited by hash as authority in `CONTINUITY-ANCHOR-DECISION-V1.md`. That citation refers to the **as-found** text; it was not edited.
* `ARCHITECT-GENESIS-POW-RESOLUTIONS-V1.txt` was cited by hash only in `WORK-AND-BLOCK-CODECS-V1.md`, which now records both hashes.
* The amended `DECISION-TECHNICAL-ANNEX-V1.md`, `GENESIS-POW-OPEN-DECISIONS-V1.md` and `WORK-AND-BLOCK-CODECS-V1.md` were not found pinned by hash elsewhere.
* A search of this scope is not proof that nothing outside it pins these hashes; the original checkout also contains evidence files not searched here.

## Reviewed and deliberately NOT amended (with reasons)
| Statement | Reason |
|---|---|
| `LICENSE-EXECUTION-V1.md` line 20: "Previously activated bindings never roll back when a later allowed block timestamp is smaller." | A safety property of the binding rule. After D3 a later block's timestamp can no longer be smaller than its parent's, so the precondition cannot arise in a valid chain; the property is kept as defence in depth and is tested at the state level (`epoch_regression_never_revises_recreates_or_double_reserves_at_the_state_level`). It does not contradict D3. The document is pinned (as found) by **16** runtime-component qualification records (`RUNTIME-COMPONENT-QUALIFICATION-V1.json` … `V16`), so amending it would sever those pins for a clarification. **Read the sentence as: "(a case D3 no longer permits)".** The Architect may instead direct an in-document note at the cost of those pins. |
| `HYBRID-WORK-AUTHORITY-V2.md` lines 30 and 54: verification checks "timestamp/MTP" | Incomplete, not contradictory: the timestamp rules it refers to now also include the parent rule. Pinned (as found) by 9 protocol-rule hybrid inventory files (`protocol-rule-hybrid-inventory-v2.json` …), which are rule-manifest inputs; do not edit without the Architect. |
| `ARCHITECT-POST-ROLLING-CONTINUATION-V1.txt` line 298 (list item "MTP") and `ARCHITECT-GENESIS-POW-RESOLUTIONS-V1.txt` line 877 ("early MTP ancestor count") | Test or coverage list items; not statements of a rule. The first is pinned by 12 qualification records. |
| `BUILD8-TRADING-SYSTEM-V1.md` line 425, `BUILD8-TRADING-D1-LOCK-PACKET-V1.md` line 178, `BTC-MUT-MARKET-FEASIBILITY-DECISION-PACKET-V1.md` line 97 | Concern the Bitcoin regtest header chain and Bitcoin median-time-past (a mirror of Bitcoin's own two-hour future rule on a Bitcoin header, with the recorded candidate admission clock). Not Mutiny block timestamps; `node/src/trading_service_v1.rs` keeps that rule deliberately. |
| `DURABLE-EQUIVOCATION-INBOX-V1.md` line 6: "rejects ... future and out-of-window submissions" | Refers to equivocation evidence submissions outside the retained window, not block timestamps. |
| Other documents that mention "timestamp" (worker session context, hybrid finality storage, continuity settlement candidate, public Genesis ceremony operations, protocol rule manifest, worker Wi-Fi transport) | Describe stored or committed timestamp fields, not an admission hold. |

## Consequence for the protocol fingerprint
The protocol-rule inventories hash several of these documents. Whether any hash input changes, and therefore whether a fingerprint candidate must be regenerated, is decided at the fingerprint step; this register only records which documents changed and which pins refer to the as-found text.
