# Treasury historical descriptor consistency

Implemented the deferred WP-T3 exact-byte check required by takeover R2: each generation-indexed Treasury destination must match the immutable WalletBook descriptor recorded for that exact historical address. The canonical Treasury authority still owns the lineage. Today's signing descriptor is not substituted for historical bytes. Treasury routing generations and wallet key generations remain separate counters under design 7.3; no new equality between those counters was invented.

Focused Windows TEST-VALUE regression `trading_treasury_records_bind_to_the_genesis_authority`: 1 passed, 0 failed. Added exact historical map binding refusal and preservation after a further R1 rotation. Existing authority, inactive-Treasury, unrelated destination and reconstruct controls run in the same test. Evidence: `D:/Mutiny/build8-targets/codex-takeover-20261004/treasury-history-binding-1.log` and its finalized hash in `parent-focused-results.json`.

The WalletBook accessor supplies historical identity bytes only; it does not authorize spending with a retired key. Frozen offer creation-time proof is a distinct unresolved locked-rule conflict recorded in the takeover evidence directory. No canonical offer existence proof is claimed by this change. Independent review and full integrated campaigns remain pending.
