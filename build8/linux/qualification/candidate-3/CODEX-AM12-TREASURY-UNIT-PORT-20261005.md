# AM-12 Treasury phase-test successor

SOURCE ONLY; compilation and runtime pending. Codex /root/hygiene independently found two legacy unit positives conflicting with the direct user decision AM-12: they attempted first funding of an unfunded retired-maker offer after R1/R2 by changing settlement approvals only. Production `trading_v1::apply_one` correctly refuses that offer. No production check or frozen vector changes here.

Base integration: `881b628db6ecb689b15be08ca2ef8abed4313ea4`; isolated merged tree equals that base. Original `consensus/src/trading_v1_tests.rs` SHA-256 `b1a3c99f60ccfa263f37879f4845a6b50d87f2433cf007141fe567083058b630`; successor `f4b6d25f9ba733023e0c26dcef063cdf199bcaced4245a6d4ed1b5c454273ebb`. All bytes outside the two existing test functions and their adjacent explanatory comments remain identical.

`treasury_rotation_rejects_old_generation_for_creation_but_retains_frozen_funding` now requires exact `Authority` refusal and unchanged records for a retired unfunded offer even with current settlement approvals. Its positive applies actual trading-phase funding before either rotation; R1/R2 preserve the whole `NativeLock` value. Retired-key claim refuses without changing records; current-key claim pays the original historical destination. The independent refund branch preserves the original deadline: height 19 refuses `Time`, height 20 refunds to the original sender, and the lock is consumed. Existing credit mismatch/missing-record negatives remain.

`treasury_history_is_unbounded_and_old_generation_still_settles_after_many_rotations` now applies funding before five R1/R2 pairs and checks the complete lock after each. Canonical-format record replay preserves it. A retired-key claim refuses without effects; the current sixth-generation key claims the historical destination. Existing stale/forged/fresh-key/reused-destination refusals remain at the genuine next test height.

These are signed trading-phase unit fixtures using the existing synthetic `r1` test seam and canonical-format state records. They do not establish certified blocks, actual SQLite crash/reopen or physical qualification. The separate `maker_offer_v2::first_funding_before_same_block_rotation_preserves_lock_and_current_refund` target provides identified certified-block coverage; its prior result is historical, not a runtime result for this successor.

Only static byte-region checks, API/ownership inspection and `git diff --check` ran. A source-preparation assertion mistakenly counted three later negative probes instead of four; that failed attempt wrote no source and remains preserved. A follow-up static borrow correction preserves the signed R2 for both test branches; its predecessor is retained. No Cargo, signing action, Linux launch or production operation ran for this tranche.

Runtime queue after the host lease is granted, from consensus, with protected private TMP/TEMP/TMPDIR and an identified target:

```text
cargo test --offline --locked --release -j4 --lib treasury_rotation_rejects_old_generation_for_creation_but_retains_frozen_funding -- --nocapture --test-threads=2
cargo test --offline --locked --release -j4 --lib treasury_history_is_unbounded_and_old_generation_still_settles_after_many_rotations -- --nocapture --test-threads=2
```

Preserve the original identified legacy fixtures for actual pre-port failure reproduction; predicted `Authority` refusal is not a recorded RED. Require actual selected tests, zero ignored and native/final integrated execution before qualification.

External source attempts and original/successor identities: `D:/Mutiny/build8-targets/hyg3/takeover-20261004/am12-treasury-phase-tests-source-v1` (failed preparation) and `am12-treasury-phase-tests-source-v1-r1` (corrected source preparation). No original checkout or another worker's files changed.
