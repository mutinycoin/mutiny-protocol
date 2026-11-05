# Genesis/fingerprint source successor — INCOMPLETE

Prepared by Codex `/root/hygiene`, 5 October 2026, in the isolated
`build8-codex-clock-review-current-v4` worktree. This is a source-only review
tranche based on executable source `8ef0af217dad00ba9f60cfb0cdc6680062ee8c4e`
and its explicit AM12 documentation amendment `bc9102fe27fb81f7f9f1b096e40cd839aa682f97`.
Later integration bytes must get a new inventory and new candidate; these
snapshots do not qualify code subsequently merged or modified.

The new, explicitly unfrozen `spec/GENESIS-INITIAL-STATE-V2.md` describes
current canonical records, bounds, four policy commitments, independent
approval and Production hard stop E. Nineteen public original inputs were
recovered byte for byte. Their raw identities and original locations are in
`spec/imports/CODEX-GENESIS-FINGERPRINT-PUBLIC-INPUTS-V1.json`; originals,
historical V9 and the frozen Treasury V1/V2 input files remain untouched.

`build/protocol-rule-candidate-scope-v2.json` is the explicit reviewed-scope
proposal. It includes all Rust source text in consensus, crypto, Node and
transport, exact build/configuration/lock metadata, 32 named normative
specifications, complete local native build directories and seven native
source-lock closures. Native locks commit each raw member, including assembly,
headers and build files; every actual member and full directory inventory is
checked. Progress/review notes, individual instances and campaign evidence
are excluded. Co-located Rust test text is conservatively identified. This
is source closure, not a compiled-artifact or offline-vendor qualification.

The standalone generator uses a small, explicit RuleManifestV1 CBOR encoder
in its own identified source, Python standard-library JSON/SHA256 and no
external codec dependency. Names, ordering, hashes, 512-entry and 128-KiB
limits and existing fingerprint domain remain unchanged. Read-only inspection
does not output a fingerprint. Generation requires one canonical new output
directory in the explicit worktree, refuses existing outputs, drive/ADS and
parent-traversal/reparse paths, source overlap, untracked Rust and native-lock
inventory/hash mismatches, and rechecks raw source and directories around
output creation. Failed or superseded attempts are preserved. This is a
stable-source check, not an OS handle barrier against an administrator
concurrently replacing paths.

The selected successor is
`qualification/protocol-rule-c3-incomplete-v1-r3/PROTOCOL-FINGERPRINT-CANDIDATE-C3-INCOMPLETE-V1.json`.
Its snapshots are immutable output identities, not inputs to themselves.
Generator identity is provenance rather than a rule artifact. The Node source
commits only the fixed selector path, never the fingerprint literal. Earlier
source-only attempts remain preserved in the owned worktree and externally
indexed; they are superseded by r3 and are not current-source evidence.

The report explicitly says INCOMPLETE, not locked/sealed/Production-authorized,
and omits all four authentic bindings with machine-readable reasons. No root,
identity template, measured PCR, enrollment, signature, Genesis artifact or
physical claim is generated. Both V1 Production refusal and V2 hard stop E
remain unchanged. Missing authentic bindings mean these rules cannot supply
valid V2 parameters; source hashes alone cannot authorize release.

Prepared tests are **NOT RUN OR COMPILED** in this source-only tranche:

* Seven Python cases cover literal independent CBOR bytes, codec limits/order,
  duplicate JSON and unsafe paths, create-new preservation, partial-source
  change, empty-directory additions and output traversal refusal.
* Three Rust cases independently hash every snapshot and reconstruct canonical
  manifest/fingerprint with the existing Rust codec, require omitted bindings
  to fail actual V2 parameter encoding while retaining Production host refusal,
  and recompute retained V9 history separately. The missing-binding probe uses
  the existing explicitly public TESTVALUE fixture, not invented Production
  material.
* Existing Node V1 and V2 refusal/artifact suites must run against the changed
  selector. Final Windows/Linux campaigns and ordinary shipping builds remain
  separate requirements.

Queue after review and an explicit host lease, with supported private temporary
and evidence roots and bounded Cargo jobs/test threads:

```text
python -B qualification/test_protocol_fingerprint_candidate_c3_v1.py
cd consensus; cargo test --locked --offline --release --jobs 4 --test protocol_manifest_c3_incomplete_v1 -- --test-threads=1
cd consensus; cargo test --locked --offline --release --jobs 4 --test protocol_manifest -- --test-threads=1
cd node; cargo test --locked --offline --release --jobs 4 --lib genesis_artifact -- --test-threads=1
```

No passing test, final freeze, physical Clock/host association, custody ceremony
or Production qualification is claimed by this note.
