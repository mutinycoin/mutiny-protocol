# Rule M: committed V2 coverage wiring

Takeover restoration of an unwired coverage helper: Production V2 Genesis construction and current/retired committed profiles must contain exactly one identity for every Genesis-committed identity-class slot. The same check runs before StateRoot construction and reconstructed-state acceptance. V1 chains retain their previous rule; no feature changes consensus behavior.

Focused Windows TEST-VALUE regression `rule_m_v2_genesis_requires_every_committed_identity_class`: 1 passed, 0 failed. It exercises missing/excess coverage at the real constructor, a separately signed incomplete binding at StateRoot, and replay with an attacker-recomputed raw-record root. Valid complete records reconstruct. Evidence: `D:/Mutiny/build8-targets/codex-takeover-20261004/rule-m-genesis-3.log`, SHA-256 `a86dbf4a8870c4f6ebda602666f323a333a6b239c2d7907ccfeb3f2a6b4eeed6`.

Initial test compilation failure and an incorrect expected replay error were retained as runs 1 and 2. Replay intentionally reports WrongAnchor when typed-state validation refuses; no production error semantics were changed.

Coverage is a count over committed identity hashes. Actual class membership/order, EK certificate authentication, AK/EK activation and host association remain separate witness verification requirements. Software-generated fixtures do not demonstrate physical provenance or production admission. Independent final-byte review and integrated Windows/Linux campaigns remain pending.
