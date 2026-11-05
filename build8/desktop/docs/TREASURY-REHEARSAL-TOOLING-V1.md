# Treasury rehearsal tooling V1 (D2)

Status: **IMPLEMENTED, SIMULATED / TEST-VALUE evidence only. Implemented != Qualified. Offline != Physical.
TEST-VALUE != production.**

Nothing here generates, holds, derives or substitutes a production Treasury key, descriptor or credential.
`PRODUCTION_SECURITY_QUALIFIED` is `false` (`crypto-v2/src/lib.rs:18`). That flag does **not** gate the existing
wallet functions, so every tool below enforces the refusal itself. Production custody, production key creation,
production signing and Genesis sealing stay with the Architect (Q9). The Architect is the sole external BTC
custodian; this concerns the native MUT Treasury only.

Architect decisions applied (authoritative): Q1 native Treasury wallet-authority rotation generation 1 -> 2;
Q2 dedicated non-spending proof-of-control domain; Q3 independent TEST-VALUE credentials through reviewed
rehearsal tooling; Q9 no production key generation, signing or sealing; continuation order of 4 October 2026,
section 7 (expected values from trusted configuration, succession only by canonical lineage or an exact
authorized rotation plan, durable first admission with repeatable read-only audits, comparison of the frozen
Genesis with the independently approved final manifest). The procedure draft
(`TREASURY-OFFLINE-CEREMONY-PROCEDURE-D2.md`) and the proposed answers (`D2-OPEN-QUESTIONS-PROPOSED-ANSWERS.md`)
were used as design input only; the proposals are **not approved** and nothing here approves a production
provision. Field choices that are proposals are marked below. The byte-level schema is
`docs/TREASURY-PROOF-OF-CONTROL-SCHEMA-V1.md`.

## 1. What was built

| Part | Where | Role |
|---|---|---|
| Domain `TreasuryProofOfControl` | `crypto-v2/src/lib.rs` (`Domain`, `role`, `bytes`) | New hybrid intent domain `MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1`, role `WalletOwner`, non-spending. Registered in `spec/DOMAIN-REGISTRY-V1.json` and in the existing cross-domain/role test list (`crypto-v2/src/tests.rs`). |
| Challenge codec, signer, verifier | `crypto-v2/src/treasury_proof_v1.rs` | Strict canonical CBOR, 14 fields; `Challenge::{new,encode,decode,check_descriptor,verify}`, `sign_challenge`, 1394-byte two-component signature codec. Ungated (public). |
| Frozen vectors | `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json` | Public TEST-VALUE codec/signature vectors (K1 generation 1, K2 generation 2) plus negative vectors. |
| Rehearsal key tool | `crypto-v2/src/rehearsal_keys_v1.rs`, `crypto-v2/examples/treasury_rehearsal_keys.rs` | `keygen`, `restore-check`, `sign`. Compiled only with `wallet-custody` (or in crypto-v2's own tests). Never in node or validator builds. |
| Ceremony verifier (trusted expectations) | `consensus/src/treasury_rehearsal_v1.rs` | `CeremonyConfig` (trusted network, phase/class, Treasury record, ceremony context), `Expect` (generation and exact descriptor from the record itself, from authenticated canonical state, or from an exact authorized rotation plan), read-only `verify_proof`, `audit_recorded`, `build_manifest`, `verify_frozen`, `check_ceremony_context`. |
| Durable admission store | `consensus/src/treasury_admission_v1.rs` | `AdmissionStore`: explicit creation bound to one ceremony (context and Treasury record), atomic first admission that consumes the nonce in one SQLite transaction, read-only audit opening. |
| Public tool | `consensus/examples/treasury_rehearsal.rs` | `challenge`, `create-store`, `verify` (read-only, ceremony negative controls), `admit` (durable), `manifest`, `verify-frozen`, `inspect`. Public data only. |
| Rotation harness | `consensus/tests/treasury_rehearsal_rotation_v1.rs`, `consensus/tests/support/dividend_rig.rs` | Native Treasury rotation generation 1 -> 2 on a non-production test chain through real block execution. The block-driver rig was extracted verbatim from `consensus/tests/dividends_v1.rs`, which now includes it. |
| Flow, controls, secret guard tests | `consensus/tests/treasury_rehearsal_v1.rs`, `consensus/tests/treasury_ceremony_closure_v1.rs`, `crypto-v2/src/treasury_proof_tests.rs` | See section 3. |

### 1.1 Challenge encoding and trusted expectations

```
ChallengeV1 = [ 1, NETWORK u32, phase u8 (1 REHEARSAL, 2 PRODUCTION), class u8 (2 TEST-VALUE, 1 PRODUCTION),
  generation u64 (key version), suite u16, policy u8, profile tstr,
  descriptor_sha256 bstr32, address_id bstr32, treasury_authority bstr32, treasury_record_sha256 bstr32,
  ceremony_context bstr32, nonce bstr32 ]
intent = SHA-512( "MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1" || 0x00 || ChallengeV1 )   // both algorithms sign it
```

It binds the exact descriptor bytes (SHA-256 and AddressID), the key version, the cryptographic profile (suite,
policy and profile string), the ceremony context and a single-use nonce. Phase and class are redundant and must
agree. Both the Ed448 and the FN-DSA-1024 component are required; a one-component file is not a signature.

**No circularity.** The Treasury record is inside the Genesis Parameters and therefore inside the GenesisID, so
the challenge contains **no GenesisID**. It binds a rehearsal ceremony context
`SHA-256("MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1" || 0x00 || label)` (label 4 to 64 bytes, each 0x21..0x7E)
chosen before any Genesis exists, plus the SHA-256 of the Treasury record (which carries the class byte). After the
freeze the GenesisID is recomputed and the **same recorded pre-freeze proof is verified again against the Treasury
extracted from the frozen bytes** (`verify-frozen`); a context equal to the GenesisID is refused.

**Trusted expectations.** The verifier never takes an expected value from the proof. The trusted inputs (`TRUSTED`
below) are the Treasury generation-one descriptor (`--treasury-descriptor-file`) with its pinned record hash
(`--expected-record-sha256`; the descriptor must reproduce it, every command that reads the Treasury requires it),
the ceremony context label and, for generation 2, the pinned plan identity, the trusted chain identity and the trusted
height (`--plan-identity`, `--chain-genesis`, `--chain-fingerprint`, `--trusted-height`, from the approved
configuration; never read from the plan file) together with the plan file (`--rotation-plan-file`). A generation-two
key that signs the Treasury's public identifiers is refused (`UnauthorizedSuccessor`) unless its descriptor is the
proposed descriptor of exactly the pinned plan, on the trusted chain, valid at the trusted height
(`PlanNotAuthorized`, `WrongChain`, `PlanOutOfWindow` otherwise). In the library a successor can also be the current
descriptor of the Treasury authority in canonical state records that reproduce a trusted StateRoot
(`Expect::canonical_current`).

Hashes (Q7 proposal): `descriptor_sha256` = plain SHA-256 of the descriptor bytes; `record_sha256` = SHA-256 of
`Treasury::encode()`; `authority`/AddressID = the existing `address_id`. Each is printed with its label.

### 1.2 Key tool behaviour (R-keys)

- Reuses `HybridKey::wallet_restore` and `create_wallet_phrase`. Only `Role::WalletOwner` is exposed; the
  `WalletRecovery` role of the same phrase is refused (Q13). Generation stamp 1 (K1) or 2 (K2); K2 is a separate
  credential stamped generation 2, as `wallet_restore` has no generation input.
- **Labelled-seed mode** (`--label`): deterministic, for CI. The phrase is a public function of a public label, so
  such a key is public by construction and is labelled `LABELLED-SEED-PUBLICLY-DERIVABLE`.
- **OS-entropy mode** (`--os-entropy --backup-file <path>.test-value-backup`): fresh entropy through
  `create_wallet_phrase`. The phrase is written **only** to the named backup file, created with `create_new`
  (never overwrites), under the header `# TEST-VALUE REHEARSAL BACKUP - NOT A PRODUCTION SECRET - SIMULATED
  EVIDENCE ONLY`. The path suffix is enforced and `**/*.test-value-backup` is in `.gitignore`. Delete the file
  when the rehearsal ends. Automated tests use temp dirs and delete them.
- The tool never writes a phrase, seed or private key to stdout, stderr or any log. Its public output is JSON of
  public data only, stamped `"class": "TEST-VALUE"` and `SIMULATED-REHEARSAL-NOT-PRODUCTION`.
- There is no production mode. `--production`, `--class` and the recovery role are refused by name. A production
  phase challenge is refused at signing.

### 1.3 Admission store and manifest builder behaviour (R-manifest)

`create-store` creates a new SQLite admission store bound to the ceremony context and the Treasury record hash, with a
random 32-byte store id that it prints (`admit`, `manifest` and `verify-frozen` print it too); it never reuses an
existing file, and `admit` never creates a missing store. Writable opens run `synchronous=EXTRA` with the rollback
journal and refuse a connection on which SQLite does not report these settings. Keep the `-journal` sidecar file
with the store. `admit` verifies the proof against the
trusted expectation and records it in one transaction keyed by the nonce: the nonce is consumed if and only if
that transaction commits, a repeated admission of the same nonce is `Replay` (also after a restart, and also for a
different valid proof carrying the same nonce), and any refusal leaves the store file byte-identical. `verify` is
read-only and consumes nothing.

`manifest` requires the proof to be **admitted** (the store is opened read-only and must hold exactly these
challenge, descriptor and signature bytes), builds Genesis Parameters version 3 with the rehearsal rule manifest
(one extra commitment name, so its fingerprint differs from any production rule set; Q8 proposal), asserts that
the **Test** profile accepts and the **Production** profile rejects it, and emits `genesis-manifest.json` and
`genesis-parameters.hex`: public descriptor, descriptor hash, record hash, class (`CLASS: TEST-VALUE (2)`),
proof, parameters hash. Output is a pure function of its inputs (deterministic bytes); re-running is idempotent,
and an existing different file is never overwritten.

`verify-frozen` opens the store read-only, extracts the Treasury from the frozen bytes (it must be the trusted
Treasury) and compares the frozen bytes with the **independently approved final manifest**: `--approved-manifest F`
pinned by `--approved-manifest-sha256 H` (required; the SHA-256 of the file the approver reviewed, supplied
separately, so the `manifest` command's own output cannot silently serve as the approval; this remains a procedural
control). The approval JSON carries `class_byte`, `treasury.descriptor_sha256`, `treasury.record_sha256`,
`genesis_parameters.parameters_sha256`, `admission_store_id` (required) and, for a Genesis descriptor, `genesis_id`.
With `--genesis-descriptor-file` the approval MUST name the GenesisID and `--approved-genesis-id` must equal it; the
check then covers every Genesis field and prints `PASS: the recomputed GenesisID equals the approved GenesisID`. With
`--parameters-file` it prints `PASS FOR THE PARAMETERS BYTES ONLY` and says that the other Genesis fields are NOT
compared. The store must be the one the approval names (`WrongStore`); a ceremony context equal to the recomputed
GenesisID is refused and the **recorded** proof is re-validated. It consumes nothing and can be repeated. The proof
establishes Treasury key control only; approval of the other Genesis parameters is the approved-manifest comparison.

A production-class manifest cannot be produced from rehearsal keys: the builder accepts only `Class::TestValue`
whatever the keys; a rehearsal-phase proof is accepted only against a TEST-VALUE record; a production-phase proof
is refused for signing and for verification while production is unqualified. A production-class record that
someone builds by hand is shown as `CLASS: PRODUCTION (1)` by `inspect` and is rejected by the Test profile.

## 2. How an operator runs the TEST-VALUE rehearsal

All commands exist. Run from Git Bash with `PATH` including `$HOME/.cargo/bin`, a build directory outside the
repository (`CARGO_TARGET_DIR`), and `--offline --locked` (never `--all-features`). Choose a scratch directory
outside the repository, for example `D:/scratch/d2`. `$K` = crypto-v2 key tool, `$P` = consensus public tool,
`$T` = the trusted ceremony inputs (`--treasury-descriptor-file D:/scratch/d2/key-g1.descriptor.hex
--expected-record-sha256 <approved record hash> --context-label d2-rehearsal-ceremony`):

```
K="cargo run -q --offline --locked --features wallet-custody --example treasury_rehearsal_keys --"   # in crypto-v2/
P="cargo run -q --offline --locked --example treasury_rehearsal --"                                  # in consensus/
```

(The consensus example links the test-only custody dev-dependency of the consensus crate; it contains no secret
code path and reads public files only. It is not part of a node build.)

1. K1, generation 1: `$K keygen --generation 1 --out-dir D:/scratch/d2 --label d2-rehearsal-k1` (deterministic CI
   mode), or OS-entropy: `... --os-entropy --backup-file D:/scratch/d2/k1.test-value-backup`.
   Writes `key-g1.public.json` and `key-g1.descriptor.hex`.
2. Fresh-environment restore check (A6): `$K restore-check --generation 1 --label d2-rehearsal-k1
   --expect-descriptor-file D:/scratch/d2/key-g1.descriptor.hex` (or `--backup-file`). PASS = byte-identical.
3. Challenge (A7): `$P challenge $T --descriptor-file D:/scratch/d2/key-g1.descriptor.hex --os-nonce --out
   D:/scratch/d2/challenge-g1.hex` (`--nonce-label` for deterministic runs; the trusted Treasury is required).
4. Sign (A7): `$K sign --generation 1 --label d2-rehearsal-k1 --challenge-file .../challenge-g1.hex --out
   .../proof-g1.sig.hex` (signatures are randomized; an existing output is never replaced).
5. Store and first admission (A9): `$P create-store $T --store D:/scratch/d2/admissions.sqlite` (record the printed
   `store_id`), then the read-only
   check with the negative controls `$P verify $T --descriptor-file ... --challenge-file ... --signature-file ...
   --generation 1 --negative-controls`, then `$P admit $T --descriptor-file ... --challenge-file ...
   --signature-file ... --generation 1 --store D:/scratch/d2/admissions.sqlite`. Repeating `admit` is refused as
   a replay.
6. Manifest (A8): `$P manifest $T --descriptor-file ... --challenge-file ... --signature-file ... --store
   .../admissions.sqlite --out-dir D:/scratch/d2/out`. Display with `$P inspect --parameters-file
   D:/scratch/d2/out/genesis-parameters.hex`.
7. Post-freeze recomputation (repeatable, read-only): the approver reviews `genesis-manifest.json` (it carries
   `admission_store_id`), adds `"genesis_id"` when a full Genesis descriptor is to be checked, and hands over the
   approved file and its SHA-256 separately. Then `$P verify-frozen $T --parameters-file .../genesis-parameters.hex
   --challenge-file ... --signature-file ... --store .../admissions.sqlite --approved-manifest <approved.json>
   --approved-manifest-sha256 <hex>` (or `--genesis-descriptor-file <bytes> --approved-genesis-id <hex>`, which also
   prints the recomputed GenesisID).
8. K2 (generation 2, separate credential, A10/A11): `keygen --generation 2 --label d2-rehearsal-k2`, then
   `challenge $T --descriptor-file key-g2.descriptor.hex ...`, `sign --generation 2 ...`, `verify $T --generation 2
   --rotation-plan-file <plan.hex> --plan-identity <hex> --chain-genesis <hex> --chain-fingerprint <hex>
   --trusted-height <n> ...` and `admit ... --store ...`. **No tool emits the rotation plan file today**: the
   plan (`wallet_rotation_v1::Rotation::encode`, signed by K1 and K2) is built by the tests; a plan export for
   operators is TO BE BUILT.
9. Rotation rehearsal (A10), in `consensus/`: `cargo test --offline --locked --features dividend-test-fixtures --test
   treasury_rehearsal_rotation_v1`.
10. Delete the scratch directory and any `.test-value-backup` files.

## 3. What each test proves

`crypto-v2` (`cargo test --offline --locked`, in `src/treasury_proof_tests.rs`):

- `domain_is_registered_unique_nonspending_and_role_bound`: domain bytes frozen, listed in the registry JSON, unique;
  a proof does not verify under any other WalletOwner domain and no other WalletOwner signature verifies as a proof.
- `challenge_codec_is_strict_and_canonical`: deterministic, trailing/truncated/non-minimal bytes rejected, no
  single-bit mutation decodes to the same challenge, class/phase mismatch and zero fields rejected.
- `proof_requires_both_components_and_every_binding`: single-component, mixed-component, altered descriptor, wrong key
  version, wrong profile/suite/policy, wrong context/nonce/record/authority, wrong signer all rejected.
- `production_proofs_cannot_be_signed_or_accepted_while_unqualified`: production phase refused for signing and
  verification; a rehearsal signature cannot be relabelled.
- `committed_public_vectors_verify_and_negative_vectors_fail`: the committed vectors reproduce the frozen encoding
  byte for byte and verify (both components); negative vectors fail. Regenerate (public data only) with
  `BUILD8_TREASURY_PROOF_VECTORS=<path>`.
- Key tool: `labelled_mode_is_deterministic_stamped_and_idempotent`, `tool_refuses_production_recovery_role_and_
  unsafe_paths`, `os_entropy_mode_writes_only_the_named_test_value_backup_and_never_prints_secrets` (R-guard: scans
  every emitted stream and file for the phrase and its fragments, the entropy, the Ed448 seed, an FN-DSA secret
  prefix, eight consecutive BIP39 words and secret-shaped words; every public JSON carries the TEST-VALUE marker).
- The existing `every_hybrid_intent_domain_rejects_cross_domain_and_role_relabeling` now includes the new domain.

`consensus` (`tests/treasury_rehearsal_v1.rs`, default features):

- `operator_flow_end_to_end_with_negative_controls_admission_and_class_safety`: the whole operator flow through the
  real tool entry points; 16 ceremony negative controls (payload/Ed448/FN-DSA bit flips, either component alone,
  altered descriptor, wrong key version, wrong context, trailing byte, wrong profile, production relabel,
  class/phase mismatch, descriptor not the trusted one, wrong network, replay) all reject while the control is
  accepted; the Treasury identity is refused without the trusted descriptor; `admit` never creates a missing store
  and the store is never re-created; a wrong context cannot open the store; first admission, replay refused after
  each reopen with the store byte-identical; the manifest needs the admitted proof, is byte-identical across runs,
  carries the TEST-VALUE markers and no production class, and consumes nothing; `verify-frozen` twice against the
  approved manifest leaves the store byte-identical, also with the full Genesis descriptor and the approved
  GenesisID; another Genesis wrapper, other Parameters bytes and an impostor Treasury are refused; review r4: a
  Genesis descriptor without an approved GenesisID never passes, the approval is pinned by SHA-256 (the `manifest`
  output with another pin is refused), the record-hash pin is mandatory, a second store is `WrongStore`; K2 needs the
  pinned plan with the trusted chain and height, another chain identity is `WrongChain`, an expired height
  `PlanOutOfWindow`, a second validly signed plan `PlanNotAuthorized`; an impostor K3 generation-2 proof is
  `UnauthorizedSuccessor` and consumes nothing; the secret guard scans every emitted file and stream.
- `library_controls_cover_every_rejection_reason_and_cannot_emit_production`: each rejection reason individually,
  production configurations refused at challenge, verification and manifest with no nonce consumed, a manifest
  needs an admitted proof, deterministic manifest, rehearsal rules fingerprint differs.
- `denylist_covers_public_fixtures_and_default_rehearsal_labels_and_blocks_production_class`.
- `tool_retries_are_idempotent_and_never_overwrite`: including a refused admission that leaves the store unchanged.

`consensus` (`tests/treasury_ceremony_closure_v1.rs`, default features):

- `internally_consistent_proofs_that_differ_from_the_trusted_expectation_are_refused`: wrong context, wrong
  Treasury, wrong descriptor, wrong generation, wrong class/phase (production relabel, production configuration,
  production record), wrong network, class/phase mismatch; each refused with its exact reason.
- `an_impostor_successor_is_refused_under_the_rotation_plan_and_under_canonical_lineage`: the impostor proof is
  cryptographically valid yet `UnauthorizedSuccessor`; unauthorized, foreign, forged or wrong-chain plans prove
  nothing; canonical lineage (records of a state built through `WalletBook::register`/`apply`, authenticated by their StateRoot) names the same successor; the retired key is a
  wrong key version.
- `first_admission_consumes_the_nonce_durably_and_audits_are_read_only_and_repeatable`: explicit creation,
  byte-identical store after refusals, replays and audits; restart; read-only store never admits; only the recorded
  proof passes an audit (a fresh signature over the same challenge does not); binding to another ceremony refused;
  extra schema objects (a trigger) and a relabelled schema refused.
- `concurrent_admissions_of_one_nonce_admit_exactly_once` (four threads, one file).
- `the_frozen_genesis_is_compared_with_the_independently_approved_manifest`: GenesisID mandatory for a Genesis
  descriptor (`GenesisIdNotApproved`), every Genesis field covered, `WrongStore`, and neither the manifest builder
  nor `verify_frozen` accepts an admitted generation-two proof.
- `production_context_checking_side_compares_only_the_configured_value_and_never_a_genesis_id`.
- `the_rehearsal_context_derivation_is_exactly_the_documented_one`.
- Review findings as negative tests: `r1_a_fabricated_lineage_does_not_reproduce_the_trusted_state_root`,
  `r2_only_the_pinned_plan_on_the_trusted_chain_at_the_trusted_height_establishes_a_successor`,
  `r5_a_replay_into_a_second_store_cannot_pass_the_approved_store`,
  `r6_a_label_with_a_quote_or_backslash_cannot_change_the_manifest_json`,
  `r7_admit_and_audit_refuse_an_expectation_of_another_ceremony_on_an_open_store`,
  `r8_empty_truncated_and_junk_store_files_fail_closed`.
- `stores_run_synchronous_extra_and_audit_stores_are_read_only_at_the_sqlite_level`,
  `a_damaged_admission_row_is_refused_on_read`,
  `a_restart_in_separate_processes_keeps_the_nonce_consumed_and_audits_read_only` (the test binary re-executes itself
  as two admitting and two auditing child processes) and `multi_defect_inputs_are_refused_in_the_normative_order`.

`consensus` (lib unit test `treasury_admission_v1::tests::a_failure_between_insert_and_commit_admits_nothing_and_consumes_no_nonce`):
an injected failure after the insert and before the commit leaves the file byte-identical and the nonce unused.

`consensus` (`tests/treasury_rehearsal_rotation_v1.rs`, feature `dividend-test-fixtures`):

- `treasury_rotation_rehearsal_gen1_to_gen2_with_preserved_reserves_restart_and_retry`: TEST-VALUE Treasury from K1;
  K1 proof admitted; rotation to K2 (generation 2) through real blocks. Reserve unchanged and no funds moved by the
  rotation; Genesis record and award deadline unchanged; an uncommitted preparation followed by a dropped and reopened
  store leaves no trace and the retry applies exactly once; replay, a stale rotation by the retired K1 and a
  non-advancing proposal are rejected; the retired K1 can no longer spend the old address and K2 can; the old
  (historical) address still receives value; the reserve floor holds across both generations (backing 599,999
  rejected, 600,000 accepted); a claim signed before the rotation still settles, oldest generation first; the store
  reopened after rotation reproduces identical state and reloads from canonical records; K2 proves control against
  the canonical lineage of the post-rotation state, the stranger K3 (generation 2) is `UnauthorizedSuccessor`, and an
  old or replayed proof is refused. Note: the package runner's fixture step does not list this test target.
- `rehearsal_credentials_are_independent_test_value_keys_and_the_rotation_needs_both_possessions`.

## 4. Remaining: TO BE BUILT or Architect-controlled

- **Production key creation, production signing, production manifest, Genesis sealing: Architect-controlled and
  refused by every tool here.** The production ceremony tool, its approval and any qualification are TO BE BUILT
  by decision of the Architect (Q9). This work does not flip or weaken `PRODUCTION_SECURITY_QUALIFIED`.
- **Production ceremony context: OPEN DEFINITION.** Only the checking side exists (`ExpectedContext::
  production_supplied`, `check_ceremony_context`); the construction is PROPOSED in the schema document section 6.2.
- Rotation-plan export for operators (generation 2 through the public tool): TO BE BUILT (tests build the plan).
- Replay protection is relative to the identified store: a party who can create a fresh store for the same ceremony
  can admit a replayed proof into THAT store (not prevented); it has another store id, which the approved manifest
  does not name (`WrongStore`). A party with write access to the file can delete records or substitute the file.
  Custody of the verifier machine is a procedural ceremony control. On Windows the SQLite VFS ignores the
  directory sync of `synchronous=EXTRA`; whether the journal deletion survives power loss there is not established.
- OPEN QUESTION for the Architect (review F11, not implemented): issued nonces are not recorded, so a proof signed in
  advance over any fresh nonce is admissible. Should admission accept only nonces the verifier issued and recorded in
  the store? Trade-off: closes pre-signed proofs, but adds an issued-nonce table with expiry and ties a signing
  session to one verifier store.
- Treasury trading locks are not exercised by this historical V1 rehearsal harness. AM-12 supersedes the earlier
  claim that a frozen unfunded offer still settles after rotation: unfunded freeze authorizations stay above
  consensus, and a retired-only maker offer cannot first fund even with current settlement approvals or an old
  finalized reference. The current maker must review and sign anew. Already finalized funded locks preserve exact
  terms, destinations, deadlines and existing claim/refund authority through rotation; no operation, fee or
  carrier is added. The two Treasury unit fixtures in `consensus/src/trading_v1_tests.rs` now fund before rotation,
  check historical destination/current authority settlement and lock preservation across five rotations and
  canonical-format record replay, and retain explicit unfunded first-funding refusal. This is the source-only
  successor recorded in `qualification/candidate-3/CODEX-AM12-TREASURY-UNIT-PORT-20261005.md`; compilation and
  runtime qualification remain pending, and record replay is not SQLite crash/reopen evidence. The separate
  `consensus/tests/maker_offer_v2.rs` contains certified-block first-funding/rotation tests. Native-Treasury
  "frozen" behaviour covered by the historical rehearsal here is an already-signed claim and the award deadline.
  Current admission/runtime tooling is described in `TREASURY-ADMISSION-V3.md`; this AM-12 clarification does not
  transfer historical V1 rehearsal results to current source or alter its frozen schema/vector inputs.
- Independent (Python / pristine C) verifier of the challenge signature (procedure 5.5): TO BE BUILT; the inputs
  and steps are listed in `qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-INPUTS.md`. Independent
  reproduction: pending (Cipher).
- Masked-input interactive operator tool, optional encrypted-envelope `seal`/`open` wrapper, build lock and offline
  dependency vendoring for ceremony binaries, physical media and environment attestation (procedure G9, G11,
  Q4-Q6): TO BE BUILT or Architect policy. Freshness of a "fresh environment" is procedural only.
- `GENESIS-INITIAL-STATE-V1.md` amendment for Parameters version 3 (Q11): documentation, not done here.
- The denylist is the built-in set of public fixtures and default rehearsal labels; the library also accepts extra
  public key hashes (`Denylist::with_hex_lines`; hash of `ed448 || fndsa`, printed as `key_sha256` in each key's
  public JSON). The public tool's former `--denylist-file` flag was dead (read by no command) and is removed; it is
  now refused as an unknown argument. The denylist is enforced as a refusal for a production-class record, which no
  tool here can emit. It does not make a fixture key unusable in production by itself.
- The rehearsal rule manifest (Q8) is not checked against any node-side cross-check of manifest entry names.

## 5. Evidence class

Everything above is **SIMULATED / TEST-VALUE** evidence: automated tests and rehearsal tooling over disposable
credentials on a non-production test chain. It is Implemented, not Qualified; procedural, not Physical; it is not
production custody evidence and not a qualification of the cryptographic stack. Public manifests carry
`TEST-VALUE` / `SIMULATED-REHEARSAL-NOT-PRODUCTION` and `CLASS: TEST-VALUE (2)`.
