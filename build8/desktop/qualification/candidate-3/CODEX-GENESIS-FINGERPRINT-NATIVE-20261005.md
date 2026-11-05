# Incomplete source-rule successor: native software verification

The isolated source tranche `3f90355720a1b7e712d072e508bfee13173d13ba` was independently reviewed and imported as integration `ad8bd0f9da790b1f6ecf50da0d98c0d3316b51a1`. This report supersedes the NOT RUN runtime status in the historical source-only preparation note; it does not change that note's original scope or claim Production qualification.

| Current isolated target | Actual result | Log SHA256 |
|---|---|---|
| Python generator safeguard cases | 7 passed, no skips | e65c959645c0b2dd59b2315dfabd636cdaeb5b94290a7aaa73e0b8a924f046f0 |
| Release protocol_manifest_c3_incomplete_v1 | 3 passed, zero ignored/filtered | a4a9463b96307d04743553b590619ba7f37f7f276afefd1a718b90ae011d29cb |
| Release historical protocol_manifest | 9 passed, zero ignored/filtered | 1927ef137f4eb526e764758e49a66a7d0dd64b8eb98aa123315552056b59cf34 |
| Release Node lib genesis_artifact filter | 8 passed, zero ignored; 233 other tests filtered | 1490d8d27dfbf3bb4e516970ebf34a65e2f8738f664f75418a358dd4e3edc165 |

All three Cargo attempts completed naturally with exit0 and whole-worktree source inventories unchanged. They ran serially with offline locked dependencies, bounded jobs and a private task temporary root. The new Rust target independently hashes all351 snapshots, reconstructs canonical RuleManifest bytes/fingerprint using the existing Rust implementation, verifies exact missing-binding refusal with the public TESTVALUE fixture, checks hard stop E and independently recomputes V9. Node cases include real TESTVALUE V2 artifact reconstruction, tamper/context/class refusal, V1 Production refusal and authenticated public-witness inability to bypass physical-host stop. These are distinct focused software targets; other filtered Node tests did not execute.

After import, independent read-only verification matched all903 raw source identities, all351 artifacts/snapshots, exact19 public imports against originals, V9 and frozen Treasury inputs. Integrated verification output SHA256 `f0cc50f706c13a0a62e4c7518edad537fbe2b8feed7fb059643e5957b2d31653`. Selected report SHA256 `2c0c514d99dda6f10f7d0815cced4f98a9b04ca59a815e74699d60095f14c0b6`, manifest24549 bytes; source-only fingerprint `2fd0eeac10c0ce20ef7e7d7d41e92be72cf0f041f51e0903096ed1f3c3e6f59d`.

Full root source/process/result inventories and logs are under `D:/Mutiny/build8-targets/codex-takeover-20261004/fingerprint-*`. The first integration audit adaptation expected three superseded untracked preparation directories that correctly remain only in the owned worktree; its failed script/output are retained. The selected r3-only audit passed without importing or deleting those historical directories. Historical/superseded input evidence remains at the closed hygiene source-tranche index.

The candidate remains **INCOMPLETE**, unlocked, unsealed and without Production authority. Four authentic V2 bindings remain absent, so it cannot instantiate valid V2 parameters. Authentic root/template/PCR evidence, independent class/manifest/target approval and enforceable physical host association remain launch dependencies. Both Production entry gates retain hard stop E. Software reconstruction is not physical admission, TPM provisioning, production signing or Genesis sealing. Final frozen host campaigns and ordinary shipping artifacts retain separate requirements.
