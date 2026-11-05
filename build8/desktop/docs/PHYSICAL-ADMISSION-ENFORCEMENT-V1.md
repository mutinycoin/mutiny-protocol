# Physical admission enforcement, V1

Status: IMPLEMENTED in software on branch `succ/tpm-admission` (Windows host, offline; every test is SIMULATED / TEST-VALUE). Not
qualified, not physical, not release locked. The new schema elements (TpmProfile version 2, the provenance statement, the trust-roots
rule-manifest commitment and their three domain strings) are **PROPOSED / UNFROZEN**. They change no existing vector and are not part of
the V9 protocol fingerprint candidate. Implemented != Qualified; Offline != Physical; Simulated != Physical.

**Candidate 3 amendments (Lane A2; Order of 4 Oct 2026, decisions A4 and A8; design
`qualification/candidate-3/A-ADMISSION-DESIGN-V1.md`, PROPOSED / UNFROZEN).** (1) In the Production class the provenance statement
must be version 2 (the version-1 fields plus the committed endorsement identities and the attestation-witness commitment) and the
profile's `hardware` must equal the class-1 endorsement identity (check C6; the identity is derived from the canonical key encoding
EKPUB-CANON-V1, which answers Q4); every committed identity is subject to duplicate-live-lineage rejection. (2) The ceremony-scoped
admission authority admits no hardware after sealing: in the Production class every post-sealing JOIN, hardware rotation and recovery
replacement (V1 and V2) is refused with `AdmissionAuthorityEnded`, so the T14 limit of section 7 now applies to the Genesis ceremony
only, and the post-sealing tests formerly named `authority_attestation_is_the_anchor_*` are flipped and renamed (design section 14).
(3) A11: the EK-chain validation procedure (`consensus/src/ek_chain.rs`) and two certificate syntaxes exist as TEST-ONLY code: a
reviewed X.509 DER syntax (`consensus/tests/support/x509_syntax.rs`, dev-dependencies `x509-cert` and `p384`; ECDSA only, RSA
signatures refused until the `rsa` closure's build scripts are decided) and a TEST-VALUE syntax. No block path calls them; consensus
still declares no feature beyond its two test fixtures. RUSTSEC-2023-0071 (rsa, Marvin attack on private-key operations) is exempted
for verification-only use and must be re-reviewed if consensus ever holds an RSA private key.
Where sections 2 to 8 below differ from this, they describe the candidate-2 state.

No predicate a validator can evaluate distinguishes a correct software simulator from a TPM. Under the locked policy the anchor of physical
admission is the supervised ceremony plus the admission authority's signature. This package makes Rust do the checkable part and nothing
more:

* (a) the production/test distinction (the *admission class*) comes only from consensus-committed Genesis data, never from a label inside
  an operation or a profile;
* (b) in the Production class the authority's approval must carry a typed provenance statement whose checkable parts are checked and bound
  to the attestation key and the device (PCR) profile of the very profile it approves;
* (c) one rule set is enforced at the single choke points, so Genesis, JOIN, ROTATION, RECOVERY (V1 and V2), state reconstruction and Bond
  all follow it, with a committed-state backstop in `State::records`;
* (d) every validator-local pin remains a narrowing invariant, never a policy.

The TEST-VALUE marker stays and is rejected in the Production class, as an accidental-use guard only (section 4).

## 1. Locked-policy requirements implemented

`spec:X` means `spec/X` and `orig:X` means `X` at commit `d474110` (master), read as reference only; most of these spec files are not on
this branch, and the branch copies of the annex and blocker-resolution files are older, with different line numbers. "annex" is
`spec:DECISION-TECHNICAL-ANNEX-V1.md`.

| # | Requirement (condensed) | Source |
|---|---|---|
| R1 | Physical eligibility is supervised physical admission plus verified measured boot, not a self-reported hardware flag. | `spec:DECISION-TECHNICAL-ANNEX-V1.md:216-218` |
| R2 | Manufacturer trust roots, accepted platform profiles and admission-authority keys are committed in Genesis. | annex `:218-220` |
| R3 | An explicit admission trust role (the Architect's wallet), "not permissionless proof that any Internet claimant is bare metal". | annex `:220-228`; `spec:ADMISSION-TRUST-CODEC-V1.md:3-7` |
| R4 | Flow: inspect device and host; EK chain to approved roots; ActivateCredential binds an AK to that EK; certify a non-exportable P-256 key; nonce-bound quote and measured-boot log against an approved host profile; one live voter per hardware commitment; raw EK material stays in restricted evidence. | annex `:230-244` |
| R5 | Key attributes, algorithm, certified Name and quote signature must agree; unknown or revoked roots, replayed nonces, mismatched logs, missing admission mean NO admission. | annex `:251-259` |
| R6 | An EK proves a TPM identity, not a bare-metal host; host association is supervised; if it cannot be established, hard stop. VM guests, vTPMs, passthrough and cloud are excluded. | annex `:261-273`; `spec:PHYSICAL-ROLES-V1.md:19-20,34-38` |
| R7 | A nonzero supervised trust-manifest commitment is mandatory; the authority's signed profile attests the separately verified EK chain, ActivateCredential, host association and measured boot; the signature is not permissionless proof of bare metal. | `spec:ADMISSION-TRUST-CODEC-V1.md:25-32` |
| R8 | V2: quote verification does not distinguish a software TPM from hardware; the ceremony checks are represented by the explicitly owner-authorized trust manifest; no self-asserted eligibility shortcut. | `spec:HYBRID-PHYSICAL-ADMISSION-V2.md:59-63` |
| R9 | Policy and roots come from authenticated parent state or the locked Genesis ceremony; local configuration or a peer-supplied policy is not admission authority; a supplied external verifier cannot override committed records. | `spec:HYBRID-ADMISSION-POLICY-STATE-V1.md:3-5`; `spec:ADMISSION-TRUST-CODEC-V1.md:43-46` |
| R10 | Recovery and rotation replacements pass the full approved admission; software VM/vTPM/cloud is never installed as a weighted voter. | `spec:ARCHITECT-BLOCKER-RESOLUTIONS-V1.txt:168-172`; `spec:RECOVERY-MATERIAL-CODEC-V1.md:19-25` |
| R11 | Genesis: exactly one physical input; native certified-key properties and a nonzero trust commitment; "software-generated native-wire tests satisfy none" of the physical gates. | `spec:GENESIS-INITIAL-STATE-V1.md:12-19,49-54` |
| R12 | An EK certificate alone is not sufficient; VM guests and vTPMs are ineligible. | `spec:ARCHITECT-AMENDMENTS-V1.txt:131-145` |
| R13 | Exact fields and domains are engineering deliverables, not guessed defaults; missing exact consensus rules are not permission to invent them; do not weaken an invariant or relabel a failed test. | `spec:ARCHITECT-DECISION-LOCK-RESTART-ORDER-V1.md:87,106,108` |

## 2. Per-flow trace

Columns: (i) where the class is taken from committed state; (ii) where the authority signature is checked; (iii) where the provenance
statement is checked (C1-C5) and bound to THIS profile's attestation key and device profile; (iv) where the TEST-VALUE marker is rejected.
"rule" = `provenance::check_profile(class, profile, endorsement_root, policy_roots)` (`consensus/src/provenance.rs`); in the Legacy/Test
class it adds nothing. All functions are in `consensus/src/` unless a `node/` path is given.

| Flow | (i) class from committed state | (ii) authority signature | (iii) provenance C1-C5 | (iv) marker |
|---|---|---|---|---|
| Genesis V1 | `genesis_inputs::genesis_admission_class` (rule manifest in `descriptor.parameters` + the Genesis policy root set `{input.endorsement_root}`), called by `initial_state`, `validate_production_descriptor` and `node/src/genesis_ceremony.rs` `Ceremony::freeze_qualified_inputs`; Production requires class Production, Test requires Legacy/Test | `admission::ApprovedProfile::verify` in `initial_state` (Ed25519 by the input owner, the V1 Genesis authority) | rule in `genesis_admission_class`, again in `ApprovedProfile::verify(policy, class)` | `require_not_test_value` and the rule |
| Genesis V2 | `genesis_v2::construct` (Order A9; section 11): the class is a byte of the immutable inputs, mapped to the admission class and passed to `membership_v2::Book::genesis(.., class)`; the committed state yields the same class through `State::admission_class` | `admission_v2::Admission::verify` (owner hybrid signature) | rule in `Admission::verify` | rule; the Production class also refuses labelled and known TEST-VALUE roots |
| JOIN V1 | `join.rs` `State::apply_joins` -> `self.admission_class()` | `ApprovedProfile::verify` in `ContinuityJoin::validate(parent, policy, class)` | same | same |
| JOIN V2 | `join_v2::Join::verify_in_parent` -> `state.admission_class()`; `continuity_lifecycle_v2::transition` -> `membership_v2::Book::stage_join(.., class)` | `Admission::verify` through `node_admission_v2::Binding::verify(.., class)` and `continuity_keys_v2::Book::admit(.., class)` | same | same |
| ROTATION V1 | `rotation.rs` `State::apply_rotations` -> `self.admission_class()` | `ApprovedProfile::verify` in `HardwareRotate::validate(.., class)` | same | same |
| ROTATION V2 (hardware) | `hardware_rotate_v2::HardwareRotate::{verify_in_parent, verify_for_node_possession}` -> `state.admission_class()`; lifecycle `stage_hardware_rotation(.., class)` | `Admission::verify` through `Binding::verify` and `continuity_keys_v2::Book::replace_hardware(.., class)` | same | same |
| Key rotation V2 | `continuity_key_rotate_v2::KeyRotate::{verify_in_parent, verify_for_node_possession}`; lifecycle `stage_key_rotation(.., class)` | `Admission::verify` through `Binding::verify` and `Book::replace_software_key(.., class)` | same | same |
| RECOVERY V1 | `recovery_material.rs` `State::carry_recovery_material` -> `self.admission_class()`; `canonical_store.rs` `accept_admitted_bootstrap_recovery` -> class of the effective state; the restart replay re-verifies through `carry_recovery_material` | the recovery certificate (`recovery.rs` `ContinuityState::apply_recovery`) AND `ApprovedProfile::verify` inside `RecoveryMaterial::verify(body, policy, class)` | same | same |
| RECOVERY V2 | `recovery_replacement_v2::Replacement::verify_material` -> `state.admission_class()`; `recovery_transition_v2` -> `continuity_keys_v2::Book::stage_recovery(.., class)` | the recovery authority signature over the intent AND `Admission::verify` through `Binding::verify` | same | same |
| State reconstruction | `state_records.rs` `State::from_records` -> `AdmissionBook::from_records(records, parameters)` (class from the committed parameters record and the book's committed policy); the final `State::root` recomputes `State::admission_class` | `ApprovedProfile::verify` for every stored profile | V1: `AdmissionBook::records(class)`; V2: `execution.rs` `State::check_v2_admission_class` over every current (`continuity_keys_v2::Binding::check_class`) and retired (`retired_continuity_v2::Record::check_class`) binding | same |
| Every committed state | `execution.rs` `State::records` (every StateRoot) | as above | as above: no Production-class StateRoot exists over non-conforming admission material | same |
| Physical verifier and votes | `execution.rs` `State::prepare_candidate_with_history` -> `self.admission_class()` -> `AdmissionBook::physical_context(registry, class)`; `node/src/main.rs` `Node::open_sealed` | as above | as above | as above |
| Bond (E5) | `bond_ops.rs` `State::apply_bond_operations`, `bond_ops_v2.rs` `State::apply_bond_creates_v2` -> `self.admission_class()` | the member's committed `ApprovedProfile::verify` (V1) | V1 committed profile re-verified; V2 `Binding::check_class` | same |

**Class rule** (`provenance::class_for`, `State::admission_class`): no Genesis parameters record, or a rule manifest without the entry
`physical-admission-trust-roots-v1` => Legacy/Test (exactly the pre-package behaviour: every existing vector and every isolated TEST-VALUE
test). The entry present and equal to `H(MUTINY-BUILD8-PHYSICAL-TRUST-ROOTS-V1, CBOR(sorted roots))` of the committed policy (V1
`AdmissionPolicy`, or the immutable roots of the V2 policy record) => Production. The entry present but not matching, or present without
any policy => ERROR (fail closed; never a fallback to Legacy/Test). The parameters record is written by `initial_state`, restored verbatim
from committed records by `State::from_records`, and written by no block operation. Deliberate tightening versus the brief's wording ("otherwise Legacy/Test"): a declared but mismatched root set is
an error, because treating it as Legacy/Test would let a declared Production chain accept TEST-VALUE material.
`State::admission_class` re-decodes the parameters record and re-hashes the policy roots on every call (every StateRoot, root and Bond
create): a deliberate recomputation, so there is no cached class to invalidate when either record changes.

**Local pins (E6).** `State::prepare_candidate_with_history` matches on (policy, class): a policy-bearing state always derives its physical
map and verifier from committed records and ignores the caller's; the caller-supplied verifier is decisive only for a policy-less Legacy/Test
qualification state; Production without a policy is an error (also unreachable: `admission_class` refuses it first).
`CanonicalStore::accept_recovery_inner` and the restart replay refuse a witness-less recovery for a Production-class state. The node's
ambient `MUTINYD_PHYSICAL_PROFILE_COMMITMENT` variable is removed (`docs/BUILD-CONFIGURATIONS-V1.md` section 13); custody pins and the
explicit qualification bundle-selection pin can only make startup fail.

**Order A9.** V1 Genesis is no longer a Production Genesis implementation: `validate_production_descriptor`, `initial_state(.., Production)`,
the node ceremony's Production freeze and `VerifiedGenesis::verify` under a Production trust all refuse with
`Error::V1NotProductionGenesis` / "V1 is not a Production Genesis implementation (Order A9)" (section 11). The Production rows above
describe the class rule that `genesis_admission_class` still evaluates for test/replay; no V1 Production Genesis is built.

**Consequence for the shipping binary.** `node/src/genesis_artifact.rs` `supported_trust` uses the V9 candidate rule manifest, which commits to
no trust-root set, with `GenesisProfile::Production`. Production Genesis verification (`--verify-sealed-genesis`, `--run`, which is in any
case closed by `production_gate.rs`) therefore fails closed for every artifact until the Architect supplies the root set (Q1) and a new
candidate manifest commits to it. This is the intended "empty or unspecified root set => no Production Genesis".

## 3. Enforced versus supervised

| Fact | Status | Where |
|---|---|---|
| Admission authority signature over the profile bytes (V2: owner hybrid signature over body, quote and possession) | ENFORCED | `ApprovedProfile::verify`, `Admission::verify` |
| Endorsement root is in the committed policy set; in the Production class the set itself is committed in the Genesis rule manifest | ENFORCED as a committed label set; WHICH roots is open (Q1) | `ApprovedProfile::verify`, `Admission::verify`, `provenance::class_for` |
| C1: the trust manifest is the commitment to the typed provenance statement | ENFORCED, Production class | rule |
| C2: the statement's root equals the approval's root and is in the policy set | ENFORCED, Production class | rule |
| C3: the statement names THIS profile's attestation key (`ak_name` = 0x000b \|\| SHA-256(TPMT_PUBLIC)) | ENFORCED, Production class | rule |
| C4: the statement names THIS profile's PCR selection and digest; the selection is non-empty | ENFORCED, Production class; no required PCR mask (Q5) | rule |
| C5: five typed evidence digests present, nonzero, pairwise distinct; EK public hash nonzero | ENFORCED as structure only; report CONTENT is not verified by consensus | rule |
| TEST-VALUE marker absent | ENFORCED, Production class (accidental-use guard) | rule, `require_not_test_value` |
| AK certifies the voting key (Name, attributes); fresh nonce-bound quote over the profile's PCRs | ENFORCED (pre-existing) | `tpm.rs` |
| EK certificate chain to an approved manufacturer root | SUPERVISED, off-chain ceremony tooling (E8 is a proposal only) | evidence kind 1 digest |
| EK <-> AK binding (ActivateCredential) | SUPERVISED, off-chain, interactive (Q3) | evidence kind 2 digest |
| Bare-metal host association; not VM, vTPM, passthrough or cloud | SUPERVISED, human judgement (Q6) | evidence kind 3 digest |
| Restart persistence | SUPERVISED | evidence kind 4 digest |
| Measured-boot log replay against an approved host profile | SUPERVISED; only the PCR composite digest is on-chain | evidence kind 5 digest, C4 |
| Certificate validity period and revocation | SUPERVISED at ceremony time; consensus has no clock for it (Q2) | none |
| Definition of the `hardware` commitment | NOT DEFINED and not enforced (Q4; check C6 deliberately not implemented) | none |

## 4. The TEST-VALUE marker

`TpmProfile::is_test_value` (a trust-manifest marker or a hardware marker, both public domain hashes) identifies public, deterministic
simulator material. It is an ACCIDENTAL-USE GUARD, not proof that unmarked material is genuine hardware: anyone can remove it. It is
rejected in every Production-class admission path (Genesis, JOIN, ROTATION, RECOVERY, reconstruction, Bond) and by the node's
physical-evidence qualification mode. Production eligibility never depends on its absence alone: the Production class additionally
requires the committed trust-root set, the typed provenance statement and the authority's signature. In an isolated Legacy/Test-class chain a
marked profile can be admitted and its member can bond, by design; that is test-chain behaviour and confers nothing on any Production-class
chain. The JSON labels of the fixtures (`TEST_VALUE`, `production_eligible`, `bond_eligible`, ...) are documentation only: no shipped code
reads them (test `no_shipped_code_reads_fixture_evidence_labels`).

## 5. Provenance schema (PROPOSED / UNFROZEN)

TpmProfile version 2 (`consensus/src/tpm.rs`): canonical CBOR `[2, hardware, ak_public, voting_public, qualified_signer, pcr_bitmap,
pcr_digest, certify_message, certify_signature, admission_trust_manifest, provenance_bytes]`, 11 elements. The nine profile fields keep their
version-1 types and bounds; the profile stays at most 8192 bytes. Version 1 `[1, nine fields]` is byte-for-byte unchanged and is valid only
in the Legacy/Test class. `TpmProfile::commitment` (domain `MUTINY-BUILD8-PHYSICAL-TPM-PROFILE-V1`) covers the exact encoding and therefore
the statement. Every outer codec (ApprovedProfile, PhysicalAdmissionInput, V2 Admission, recovery material) embeds the profile bytes
unchanged, and the existing authority signatures cover the statement. No new signature domain exists.

Provenance v1 (`consensus/src/provenance.rs`), canonical CBOR of exactly 321 bytes:

| # | Field | Type | Meaning |
|---|---|---|---|
| 0 | version | uint 1 | |
| 1 | `endorsement_root` | bstr 32 | equals the approval's endorsement root and is in the committed policy set (C2) |
| 2 | `ek_public_sha256` | bstr 32 | SHA-256 of the DER-encoded EK public key (SubjectPublicKeyInfo); hash only, raw EK material stays off-chain (R4, Q7); nonzero (C5) |
| 3 | `ak_name` | bstr 34 | 0x000b \|\| SHA-256(TPMT_PUBLIC of THIS profile's AK) (C3) |
| 4 | `platform_profile_sha256` | bstr 32 | `H(MUTINY-BUILD8-PLATFORM-PROFILE-V1, pcr_bitmap \|\| pcr_digest)` of THIS profile (C4) |
| 5 | evidence | array of exactly five `[kind uint, digest bstr 32]`, kinds 1..5 in this order | 1 EK-chain verification report; 2 ActivateCredential (external credential) report; 3 platform observation / host association report; 4 post-reboot restart verification report; 5 candidate platform profile report. Nonzero, pairwise distinct (C5) |

The five kinds are exactly the five reports the supervised Desktop review already requires (`orig:desktop/src/admission.rs:18-24`;
`orig:qualification/export_native_tpm_fixture.py:15-17`), replacing a language-specific JSON-of-hashes preimage with canonical
CBOR.

Domains (registered with status PROPOSED-UNFROZEN in `spec/DOMAIN-REGISTRY-V1.json`; `H(d, b) = SHA-256(d || 0x00 || b)`):

* `MUTINY-BUILD8-ADMISSION-PROVENANCE-V1`, body = the 321 provenance bytes. C1: `admission_trust_manifest == H(..)`.
* `MUTINY-BUILD8-PLATFORM-PROFILE-V1`, body = `pcr_bitmap (3 bytes) || pcr_digest (32 bytes)`.
* `MUTINY-BUILD8-PHYSICAL-TRUST-ROOTS-V1`, body = canonical CBOR array of the root set (32-byte byte strings, ascending, unique, nonzero,
  1..1024). It is committed in the Genesis rule manifest under the entry name `physical-admission-trust-roots-v1`.

Public TEST-VALUE example: the deterministic simulator's statement for the TEST-VALUE root `H(MUTINY-BUILD8-TEST-VALUE-ENDORSEMENT-ROOT-V1,
"")`. It is limit material (T14), not evidence. The values were computed independently from this schema text and are pinned by the test
`documented_test_value_provenance_example_matches_the_encoder`. Inputs: `ak_public`, `pcr_bitmap` and `pcr_digest` of the committed simulator
fixture `qualification/TEST-VALUE-SOFTWARE-TPM-FIXTURE-V1.json`; `ek_public_sha256 = H(MUTINY-BUILD8-TEST-VALUE-PROVENANCE-V1, "ek-public")`;
evidence digest k = `H(MUTINY-BUILD8-TEST-VALUE-PROVENANCE-V1, label_k)` with the labels `ek-chain-verification`, `activate-credential`,
`host-association`, `restart-verification`, `candidate-platform-profile`.

```
provenance (321 bytes)  86015820fef7ba57cb5be22c726c654257dbc3911f6470a9194baa17ddd9bf5c7af322665820705493ec23029699ac5e5c5c0dc191ec41e42fd2
                        79dbbc8674379fa22b6c2d7f5822000b867490fe24b0d860d8bb55dd1394b38e8df502eb8d27f07e69f9782d5001615e5820524465ec946a87
                        917d91a99adf35a5c85f9ef6a43125a7a890dd0707eeaaf4cc85820158208cf9c77b16656e3d12dd38ad83f29d93368889c6aa76ecc7a35ef4
                        4907fae67e82025820bf37fb90e3e98cc24cf8567024b829f9ad26c0b3b6b03fe877ff62d123088079820358207fec6057ffe37d01b0851fe0
                        bd7b5a2b79cccaa6644cee2d3c0083a646b7635f82045820d58bc81f072f28ca115c32fdf6283a419328034b88c8941b293de3b6e4ba2eb682
                        05582048b7de525a49c0b30ed0c87a36ee69a5158f533847c196f957a1ee4f0bf12143
trust manifest (C1)     dee7106a724b2db25c36b4f50357d51feaca6bb84e9d57ab5f7639e135e48ab8
trust-roots commitment  57fc4e1dfc32b27d814340a2aec15bad77138bda2e209a6d0a7e94f9f3876544   (set = {TEST-VALUE root})
```

## 6. Negative tests (analysis T1-T15)

| ID | Test (file :: function) | API exercised |
|---|---|---|
| T1 | `consensus/tests/physical_admission_enforcement.rs` :: `production_genesis_rejects_marked_stripped_and_inconsistent_software_profiles`; `consensus/tests/genesis_test_value_reject.rs` :: `unmarked_profile_is_rejected_by_production_genesis_without_class_and_provenance` (FLIPPED; formerly `negative_control_unmarked_profile_passes_production_descriptor_validation`) and `test_value_profile_rejected_by_production_genesis` | `genesis_inputs::validate_production_descriptor`, `genesis_admission_class`, `initial_state(Production)` |
| T2 | `physical_admission_enforcement.rs` :: `genesis_class_must_match_the_declared_profile_in_both_directions`; `node/src/genesis_artifact.rs` :: `production_trust_requires_production_class_and_edited_profiles_never_open` | `validate_production_descriptor`, `genesis_admission_class`, `initial_state(Production / Test)`; node `VerifiedGenesis::verify` |
| T3 | V1: `consensus/src/join.rs` :: `production_class_join_rejects_marked_stripped_and_inconsistent_software_profiles`; V2: `physical_admission_enforcement.rs` :: `production_class_v2_join_and_admission_reject_marked_stripped_and_inconsistent_software_profiles`, `production_class_v2_lifecycle_join_rejects_software_profiles_except_the_documented_limit` | `ContinuityJoin::validate`, `State::apply_joins` (parent and candidate unchanged); `join_v2::Join::verify`, `admission_v2::Admission::verify`, `continuity_lifecycle_v2::transition` (-> `membership_v2::Book::stage_join`; parent unchanged) |
| T4 | V1: `consensus/src/rotation.rs` :: `production_class_rotation_rejects_marked_stripped_and_inconsistent_software_profiles`; V2: `physical_admission_enforcement.rs` :: `production_class_v2_hardware_rotation_rejects_software_profiles_except_the_documented_limit` | `HardwareRotate::validate`, `State::apply_rotations` (old generation, history and bonds unchanged); `hardware_rotate_v2::HardwareRotate::verify`. The C6 half of T4 is not applicable (C6 not adopted, Q4) |
| T5 | V1: `consensus/src/recovery_material.rs` :: `production_class_recovery_rejects_marked_stripped_and_inconsistent_software_material` (the registry recovery is applied first, so the call reaches the class rule; the refusal leaves the staged candidate unchanged; positive controls in both classes); V2: `physical_admission_enforcement.rs` :: `production_class_v2_recovery_replacement_rejects_software_profiles_except_the_documented_limit` | `RecoveryMaterial::verify`, `State::carry_recovery_material` (the path of every recovery accept and restart replay); `recovery_replacement_v2::Replacement::verify_material`, `recovery_transition_v2::Prepared::verify` |
| T6 | (i) inside T3-T5 the rejected candidate is asserted unchanged (no member, no control), so no Bond create can name the node (`apply_bond_operations` requires both); (ii) `physical_admission_enforcement.rs` :: `production_class_reconstruction_refuses_injected_software_profiles`, `production_class_v1_state_has_no_root_over_injected_software_profiles` (the V1 `State::records` backstop itself), `production_class_state_cannot_commit_a_software_marked_v2_binding`; (iii) `consensus/src/bond_ops.rs` :: `production_class_bond_create_rechecks_the_members_committed_profile` (V1) and `production_class_v2_bond_create_rechecks_the_members_committed_binding` (V2) | `AdmissionBook::records`, `AdmissionBook::from_records`, `State::from_records`, `State::records`, `membership_v2::Book::genesis`; `State::apply_bond_operations` and `State::apply_bond_creates_v2` (E5) |
| T7 | `consensus/tests/host_independence_guard.rs` :: `no_shipped_code_reads_fixture_evidence_labels`; `consensus/tests/software_admission_fixtures.rs` :: `relabeled_fixture_is_a_drift_failure_not_a_different_evidence_class` | source guard; drift comparison |
| T8 | `consensus/tests/recovery_native_store.rs` :: `native_recovery_material_is_atomic_restartable_and_checkpoint_replayable` (extended) | `State::prepare_candidate` with (a) the committed context, (b) an empty map and a reject-all verifier, (c) a wrong PhysicalMember map and an ACCEPT-ALL verifier, on the empty block AND on blocks that carry an attestation refresh of the recovered member (so the map and the verifier are consulted): identical root, or identical error, in all three; garbage refresh evidence is refused even under (c) |
| T9 | `physical_admission_enforcement.rs` :: `admission_class_comes_only_from_committed_genesis_data` | `State::admission_class` and `State::root` fail for a declared root set without a policy and for a mismatched set; `prepare_candidate_with_history` calls `admission_class` first (not separately tested) |
| T10 | `node/src/main.rs` :: `custody_configuration_tests::physical_profile_pin_only_narrows_and_never_admits`; the environment variable is no longer read at all (guards below) | `Node::open_pinned` |
| T11 | `node/src/tpm_backend.rs` :: `public_custody_manifest_cannot_substitute_another_network_key_or_counter` (extended), `helper_*` tests; `node/src/main.rs` :: `production_custody_fields_are_exact_and_explicit`, `custody_pins_take_identity_from_consensus_and_helper_config_changes_nothing_else` | `Pins::verify`, `HelperConfig`, `production_custody`, `production_pins` |
| T12 | (i) `host_independence_guard.rs` :: `no_host_name_lookup_in_consensus_or_node_code`, `no_environment_read_in_consensus_or_node_code_outside_allow_list`; `private_evidence_guard.rs` :: `shipped_sources_and_config_name_no_developer_host_or_helper`; (ii) `physical_admission_enforcement.rs` :: `a_configured_peer_absent_from_the_committed_registry_cannot_vote`; (iii) `node/src/main.rs` :: `physical_profile_pin_only_narrows_and_never_admits`, `runtime_ingress_tests::physical_mode_rejects_test_value_and_uncommitted_profiles_at_runtime`; `genesis_artifact.rs` :: `production_trust_requires_production_class_and_edited_profiles_never_open` | source guards; `certificates::Certificate::verify_quorum` with `ContinuityState::voters`; `Node::open_pinned`; `VerifiedGenesis::verify` |
| T13 | `physical_admission_enforcement.rs` :: `production_rule_checks_c1_to_c5_one_field_at_a_time`, `production_class_refuses_the_hardware_marker_even_with_a_consistent_statement` (a version-2 profile that keeps the hardware marker with an otherwise consistent statement is refused for the marker alone), `provenance_codec_is_canonical_fixed_size_and_typed`, `version_1_profile_bytes_are_unchanged_and_version_2_commits_to_provenance` | `provenance::check_profile_detailed` (precise `Failure` per check), `ApprovedProfile::verify`, `join_v2::Join::verify`, `Provenance::decode`, `TpmProfile::decode` |
| T14 | `authority_attestation_is_the_anchor_*` in `join.rs`, `rotation.rs`, `recovery_material.rs`, `physical_admission_enforcement.rs` (Genesis, V2 JOIN), plus the limit cases inside the V2 lifecycle and hardware-rotation tests and the Bond test | the same APIs, ACCEPTING the limit material |
| T15 | `software_admission_fixtures.rs` :: `committed_test_value_admission_fixtures_match_generator`, `fixtures_are_labelled_simulated_marked_and_low_s`, `tracked_json_profiles_are_test_value_or_synthetic`; the committed fixtures are refused in the Production class inside the T3, T4 and T5 V1 tests | drift, labels, low-S, tracked-profile guard |

The negative admission tests are paired with positive controls: the same construction accepted in the Legacy/Test class, or the T14
limit material accepted in the Production class through the same API, in the same test or in the matching
`authority_attestation_is_the_anchor_*` test. A rejection therefore does not come from a broken setup.

Each defense in depth has a test that fails when that defense alone is removed (mutants of the independent review, re-run on this
branch; simulated/offline evidence): the V1 class check in `carry_recovery_material` and, together with it, the `State::records`
backstop (T5 V1), the `State::records` backstop alone (T6 (ii)), the V2 Bond recheck (T6 (iii)), the V2 class check in
`Replacement::verify_material` (T5 V2), the hardware-marker check (T13) and the committed physical context in
`prepare_candidate_with_history` (T8). The class argument of `continuity_keys_v2::Book::stage_recovery` in
`recovery_transition_v2::Prepared::verify` is not separately observable: `Prepared::verify` runs `verify_material` first.

## 7. The known limit (T14), and what E8 would and would not add

An authority-signed software profile carrying a self-made, internally consistent provenance statement IS accepted in the Production class.
The tests that show it are named `authority_attestation_is_the_anchor_*`, and no comment or document claims otherwise. The checks make the
authority's statement typed, specific to this attestation key and this device profile, and mutually consistent, so tooling mistakes and
mix-and-match fail closed. They cannot make a statement true.

E8 (NOT approved, NOT implemented; a proposal that needs the Architect's explicit approval, D-DEP): a ceremony-side EK-chain verifier in Rust that parses the EK leaf and intermediates,
verifies them to a pinned root, extracts the leaf public key and emits `ek_public_sha256` and the kind-1 report digest. It needs either new
vetted crates (`rsa`, `x509-cert`, possibly `p384`; source locks, vendoring, audit) or hand-written RSA/X.509 code, which the locked
hardening text treats as a hard stop (`spec:ARCHITECT-MAXIMUM-SECURITY-HARDENING-V1.txt:1774-1785`). What it would add: chain validation would run in reviewed Rust ceremony code instead of the external tooling that produces the kind-1
report today, and a statement could no longer name a root the leaf does not chain to. What it would NOT add: a software actor that replays a genuine PUBLIC EK certificate chain passes any chain
check; only the supervised, interactive ActivateCredential step (the verifier's secret) shows possession of that EK. Putting the chain
on-chain for validators would also conflict with R4 (Q7).

## 8. Open decisions (precise questions, with proposals)

Each question is open in the locked text; this package implements the fail-closed mechanism and nothing more.

* **Q1 Roots.** What does `endorsement_root` commit to (SHA-256 of the root certificate DER, of its SubjectPublicKeyInfo, or of the issuing
  intermediate), and which manufacturer roots are approved? Mechanism now: the Production class exists only when the Genesis rule manifest
  carries `physical-admission-trust-roots-v1` equal to the commitment of the policy root set; the V9 candidate manifest carries none, so no
  Production Genesis can be built or verified (`genesis_inputs::genesis_admission_class`, `node/src/genesis_artifact.rs` `supported_trust`).
  Proposal: SHA-256 of the DER of each approved manufacturer ROOT certificate, chosen by the Architect from the supervised EK-chain evidence,
  committed in a V10 rule manifest. Note for V1: the V1 Genesis policy is synthesized from the single admission input (`initial_state`:
  `endorsement_roots = {input.endorsement_root}`), so a V1 Production chain commits to exactly ONE root and can never admit a TPM that chains
  to another root (the V1 policy is immutable). A multi-root set needs the V2 policy record or a new V1 Genesis input field (wire change).
  Code: the V10 manifest content; `genesis_inputs::initial_state` only if multi-root V1 is wanted.
* **Q2 Revocation and validity.** Are certificate validity and revocation evaluated only by the supervisor at ceremony time and recorded in
  the kind-1 report? How, if at all, is a compromised root or device removed after Genesis (the annex says "Revocation is an on-chain quorum
  action", `spec:DECISION-TECHNICAL-ANNEX-V1.md:259`; the hybrid policy text does not authorize an operation to replace endorsement trust
  roots, `spec:HYBRID-ADMISSION-POLICY-STATE-V1.md:24`)? Proposal: ceremony-time evaluation recorded in report kind 1; post-Genesis removal
  by an explicit, separately specified quorum operation (not designed here). Code: none today.
* **Q3 ActivateCredential record.** Confirm that the interactive ActivateCredential result is represented only by the authority's signature
  over the provenance statement (digest kind 2), that the verifier of record generating the credential challenge is distinct from the node
  operator, and what the kind-2 report must contain. Proposal: yes; the report records the challenge, the EK and AK Names and a commitment
  to the recovered secret, produced by the supervisor's tool. Code: none (`provenance::EvidenceKind::ActivateCredential` is a digest only).
* **Q4 Hardware commitment.** Define `hardware`. Today it is free: the qualification export tool derives it as SHA-256 of the EK public-key
  PEM file bytes (`orig:qualification/export_native_tpm_fixture.py:22`), which is not per network, while the annex asks for a "per-network
  hardware commitment" (`spec:DECISION-TECHNICAL-ANNEX-V1.md:238`). Proposal: `hardware = H("MUTINY-BUILD8-PHYSICAL-HARDWARE-ID-V1",
  NETWORK_ID_u32_be || ek_public_sha256)`, where `ek_public_sha256` is SHA-256 of the DER-encoded EK public key (statement
  field 2) (per NetworkID; per GenesisID is impossible for the Genesis member, whose profile is an input of
  GenesisID). Ready patch (check C6, NOT applied; it would make the duplicate-hardware and "same TPM keeps H" rules EK-based instead of
  label-based):
  ```rust
  // provenance.rs
  pub const HARDWARE_ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-PHYSICAL-HARDWARE-ID-V1";
  pub fn hardware_id(ek_public_sha256: Hash) -> Hash {
      let mut body = crate::NETWORK_ID.to_be_bytes().to_vec();
      body.extend_from_slice(&ek_public_sha256);
      domain_hash(HARDWARE_ID_DOMAIN, &body)
  }
  // enum Failure: HardwareMismatch,
  // check_profile_detailed, after the C5 checks:
  if profile.hardware != hardware_id(p.ek_public_sha256) {
      return Err(Failure::HardwareMismatch);
  }
  ```
  plus registering the domain and a T13 case. Code: `consensus/src/provenance.rs`.
  **EK uniqueness (independent review, MINOR-7; documented here, NO rule added).** Every duplicate check compares only the node,
  the lineage, the `hardware` label and the voting key (V1: JOIN `join.rs` `State::apply_joins` ~224-235, ROTATION `rotation.rs`
  ~270-281, RECOVERY `recovery_material.rs` ~169-177; V2: `membership_v2.rs` ~317 and `recovery_replacement_v2.rs`
  `Replacement::verify_material` ~306-345). Two authority-signed admissions whose provenance statements carry the SAME
  `ek_public_sha256` but DIFFERENT `hardware` labels therefore both pass: one TPM can be admitted twice, as two voters, under two
  labels. Whether that is the same hardware is exactly this decision. Ready patch (NOT applied; Production class only, the
  Legacy/Test class unchanged): reject a LIVE duplicate `ek_public_sha256` in ANOTHER lineage. In each admission path above, after
  the class rule, collect `ek_public_sha256 -> lineage` from the statement of every live member's committed profile (V1: the
  `AdmissionBook` profile named by the member's `attestation`; V2: the current bindings of `continuity_keys_v2`) and refuse the
  incoming profile with `Error::Duplicate` when its `ek_public_sha256` is present for a different lineage (a lineage replacing its
  own member, by key rotation or a same-TPM recovery, is not a duplicate); one T3/T4/T5 case per flow (two consistent statements
  with one EK hash and two labels: the second admission is refused, the first is unchanged). Whether a RETIRED generation's EK may
  return under a new lineage is decided together with "same TPM keeps H". If C6 is adopted (`hardware` derived from
  `ek_public_sha256`), the existing duplicate-`hardware` checks already enforce this and the patch is unnecessary. Code:
  `consensus/src/provenance.rs` (a helper returning the live `ek_public_sha256 -> lineage` map) and the five admission paths above.
* **Q5 Device / PCR profile.** Which PCRs are required; is the composite pinned per node (today: per approved profile) or chosen from an
  accepted-profile set committed in Genesis (`spec:DECISION-TECHNICAL-ANNEX-V1.md:218-220`); how are firmware and kernel updates admitted?
  Implemented now: only a non-empty selection, bound by C4. Proposal: a committed accepted-profile set (bitmap and digest pairs) in the rule
  manifest, checked like the roots; updates through hardware rotation with a new approval. Code: `provenance::check_profile_detailed` (C4).
* **Q6 Host association.** Confirm that bare metal / not VM / not vTPM / not passthrough / not cloud stays a supervised human attestation
  (digest kind 3) with no machine predicate, and that no machine-checkable negative filter (for example a vendor allow-list) is wanted unless
  specified. Proposal: confirm as stated. Code: none.
* **Q7 Raw EK material.** May any raw EK material (certificate chain, EK public key) appear in consensus state, or only hashes
  (`spec:DECISION-TECHNICAL-ANNEX-V1.md:242-244` keeps it in restricted admission evidence)? Implemented: hash only (`ek_public_sha256`).
  This decides whether validators could ever verify the chain. Proposal: hashes only. Code: `provenance::Provenance`.
* **Q8 Authority succession.** Confirm that the admission authority is the policy owner wallet only (V1: the Genesis input owner; V2: the
  policy owner following canonical wallet rotation, `admission_policy_v2.rs` `Record::current`) and that an admitted node's owner must equal
  it (`admission_v2.rs` `Admission::verify`). Proposal: confirm; no committee (none is invented here). Code: none.
* **Q9 Stack.** Is Production Genesis the V1 codec (`genesis_inputs::initial_state`, the V9 candidate) or the V2 hybrid stack, which has NO
  Genesis constructor (none is invented here)? This decides where a V10 manifest and the Production root set land and whether the V9 candidate
  is superseded. Proposal: V2 first (the hybrid policy text calls the V1 policy legacy and says final production Genesis validation
  must require the V2 policy record before live admissions, `spec:HYBRID-ADMISSION-POLICY-STATE-V1.md:28-34`), keeping the V1 rule now
  implemented as the stopgap. Code:
  `membership_v2::Book::genesis` (V2 book constructor, already class-aware) plus a future V2 Genesis constructor.
* **Q10 Class representation.** Chosen: a named commitment in the Genesis rule manifest (`physical-admission-trust-roots-v1`) checked against
  the committed policy roots (E1). It changes no codec and keeps every committed vector byte-identical. Its costs: the class needs the
  parameters record, which only V1 Genesis writes today, and V1 then supports a single root. Alternatives: an explicit class byte in the V2
  policy record (a new record version; wire change to `spec:HYBRID-PHYSICAL-ADMISSION-V2.md:7-11`), or a class derived from a stored
  `GenesisProfile` (new state record). Proposal: keep E1 for V1; decide the V2 form together with Q9.
* **D-DEP (only if E8 or on-chain chain verification is wanted).** Approve either new vetted crates (`rsa`, `x509-cert`, possibly `p384`)
  with source locks, vendoring and audit, or a hand-written strict DER/RSA verifier (a custom primitive, listed as a hard stop in
  `spec:ARCHITECT-MAXIMUM-SECURITY-HARDENING-V1.txt:1774-1785`). Proposal: neither until Q1, Q3 and Q7 are answered.

## 9. V9 fingerprint candidate

`qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V9.json` was NOT regenerated or edited. Consensus source files changed by this package
(A = Stage A, B = Stage B):

| File | Stage | Key of the V9 `files` map |
|---|---|---|
| `consensus/src/join.rs`, `consensus/src/recovery_material.rs`, `consensus/src/rotation.rs` | A (test modules only) and B | yes |
| `consensus/src/admission.rs`, `bond_ops.rs`, `canonical_store.rs`, `execution.rs`, `genesis_inputs.rs`, `lib.rs`, `state_records.rs`, `tpm.rs` | B | yes |
| `consensus/src/provenance.rs` (new) | B | no |
| `consensus/src/admission_v2.rs`, `bond_ops_v2.rs`, `continuity_key_rotate_v2.rs`, `continuity_keys_v2.rs`, `continuity_lifecycle_v2.rs`, `execution_v2.rs`, `hardware_rotate_v2.rs`, `join_v2.rs`, `membership_v2.rs`, `node_admission_v2.rs`, `recovery_replacement_v2.rs`, `recovery_transition_v2.rs`, `retired_continuity_v2.rs` | B | no |

Eleven changed files are keys of the V9 candidate, so the V9 candidate's file hashes no longer describe this branch; the candidate itself
(manifest, fingerprint) is unchanged. `spec/DOMAIN-REGISTRY-V1.json` (three PROPOSED-UNFROZEN entries) is not a V9 key; the candidate's
`rules/domain-registry.json` entry is a separate snapshot and is unchanged.

The rule manifest compiled into `node/src/genesis_artifact.rs` (`supported_trust`) is unchanged; it commits to no trust-root set, which keeps
Production Genesis closed (section 2). A V10 candidate, if Cipher decides on one, would need the changed files above and, once Q1 is
answered, the `physical-admission-trust-roots-v1` entry.

## 10. Git history

The three formerly tracked Node A-derived admission fixtures (`qualification/{JOIN,RECOVERY-MATERIAL,ROTATION}-PHYSICAL-FIXTURE-V1.json`) are
removed from the tip and gitignored; their bytes remain in the private Git history. That history was deliberately left untouched (no
rewrite, no rekeying, no TPM clearing), as directed by the Architect. Whether that history is ever published is a separate, pending
decision. Since the review fixes, `.gitignore` also names the lowercase and any-capitalisation private-evidence spellings, so a
case-sensitive checkout ignores the directory `qualification/node-a-linux/` as well (a pre-existing gap that `core.ignorecase` hid on
Windows; checked with `git -c core.ignorecase=false` in a scratch clone with placeholder files, no private file involved).

## 11. Genesis V2 (Order A9/A10/A1)

Status: IMPLEMENTED in software on branch `cand3/genesis-v2` (Lane A1; Windows host, offline; every test value is TEST-VALUE). Not
qualified, not physical, not release locked. Every new schema and domain is **PROPOSED / UNFROZEN**. Design:
`qualification/candidate-3/A-GENESIS-V2-DESIGN.md`; fingerprint rules: `qualification/candidate-3/FINGERPRINT-REGENERATION-NOTE.md`.
The Order answered Q1 (roots are root-certificate DER SHA-256 values, as a SET with validation constraints: A1), Q9 (V2 is the
Production Genesis target: A9) and Q10 (the class is an explicit byte of the immutable Genesis inputs: A10).

**What exists.** `consensus/src/genesis_v2.rs`: the immutable input record `Inputs` (GenesisInputsV2) with the state-resident
`Parameters` (GenesisParametersV2, tag 64, stored at `H(MUTINY-BUILD8-GENESIS-PARAMETERS-KEY-V2, empty)`), the explicit constructor
`construct(inputs, enrollment)` (no class or profile argument) and the verifier `verify(inputs, enrollment, approved, claimed)`;
`State::admission_class` reads the class from that record when present (`provenance.rs`). Node: `node/src/genesis_ceremony_v2.rs`
(identity freeze) and `node/src/genesis_artifact_v2.rs` (`BUILD8-SEALED-GENESIS-V2` freeze and verify, `supported_trust_v2`).
`main.rs` and `production_gate.rs` are unchanged.

**Class (A10).** One byte (1 Production, 2 TestValue) inside the parameters record, therefore inside the GenesisID preimage
(`H(MUTINY-BUILD8-GENESIS-ID-V2, inputs)`). The rule manifest carries `genesis-class-v2`, `endorsement-root-set-v2` and
`accepted-pcr-profile-set-v1`; the parameters codec refuses a record whose manifest disagrees with its own class, root set or PCR slot,
or that carries the V1 entry `physical-admission-trust-roots-v1`. Production maps to the Production admission rule (sections 1-6);
TestValue maps to the Legacy/Test rule. Tests (`consensus/tests/genesis_v2.rs` unless noted):
`class_byte_must_be_known_and_committed_by_the_manifest`, `golden_identity_pins_the_preimage_including_the_class_byte`,
`class_changed_after_construction_is_refused_everywhere`, `manifest_must_commit_to_exactly_this_root_set_class_and_pcr_slot`,
`class_and_identity_ignore_the_process_environment` (child process with Production-naming variables),
`genesis_v2_sources_read_no_environment_feature_or_profile`, node `the_artifact_file_name_never_changes_identity_or_class` and
`test_value_identity_freezes_durably_and_the_file_name_changes_nothing`; the verifier's expected class can only refuse
(`verifier_refuses_foreign_trust_tampered_claims_and_tampered_enrollment`, node
`production_or_foreign_trust_refuses_the_test_value_artifact`).

**Trust-anchor SET (A1 representation).** `EndorsementRootSetV2`: 1..1024 entries ascending by `root_cert_der_sha256`, each with
Lane A2's `ek_chain::AnchorConstraints` (max intermediates, signature algorithms, EK classes, revocation mode; explicit inputs,
no defaults; Genesis codec version 2), the exact structure the EK-chain procedure consumes (review F2,
`genesis_commits_exactly_the_structures_the_chain_pcr_and_identity_checks_consume`), and a TEST-VALUE label
that only the TestValue class may (and must) use. Constraint values are committed but NOT enforced at Genesis (no EK-certificate data exists there); the
EK-chain procedure that reads them is a library not yet wired into any block or Genesis path. The state's V2 policy roots must equal the set; the member's root must be in
it; a later V2 JOIN cannot name a root outside it (`a_second_root_outside_the_frozen_set_is_refused_at_genesis_in_state_and_at_join`,
which also accepts a JOIN naming the set's other root). Production refuses an empty set, all-equal-byte placeholders, labelled roots
and the V1 TEST-VALUE root (`production_class_refuses_empty_placeholder_test_value_and_zero_roots`); TestValue requires labelled roots
(`test_value_class_requires_labelled_test_value_roots`); duplicate and unsorted roots are refused on bytes
(`root_set_order_uniqueness_and_version_are_enforced_on_bytes`). LIMIT: code cannot recognize an invented random-looking root hash; the
authority against it is the independently approved manifest (the verifier compares exact manifest bytes), supplied by the Architect.

**PCR-profile set (A5) and identity classes (A4).** Genesis commits Lane A2's `AcceptedPcrProfiles` (bank, selection, digest,
interpretation, update rule; manifest entry `accepted-pcr-profile-set-v1` = its own commitment) and A2's ordered `IdentityClasses`
(manifest entry `endorsement-identity-classes-v1`); both are single definitions read by A2's checks. Membership and requalification are
library functions, not wired into admission. Production also refuses PCR profiles whose digest bytes are all equal
(`production_class_refuses_placeholder_pcr_profiles`).

**V1 (A9).** Test/replay only. Refusals: `physical_admission_enforcement.rs`
`authority_attestation_is_the_anchor_consistent_software_provenance_passes_the_v1_class_rule_but_production_is_refused` (consensus
paths, exact `Error::V1NotProductionGenesis`); node `v1_artifact_under_production_trust_is_refused_with_the_order_a9_message` and
`v1_production_ceremony_freeze_is_refused_with_the_order_a9_message` (exact message, no ceremony file).

**Positive and real-block evidence (Windows, software, TEST-VALUE).** `test_value_genesis_constructs_identically_twice_and_verifies`;
`constructed_genesis_opens_the_v2_store_and_finalizes_a_real_block` (the V2 canonical store accepts the constructed state as its
trusted Genesis, a block assembled by the production assembler and certified by the Genesis member's hybrid vote commits, and a block
whose certificate commits to another post-state is refused with the Genesis records byte-identical); node
`test_value_v2_genesis_freezes_to_an_artifact_and_verifies` (from the committed fixture
`qualification/GENESIS-V2-TEST-VALUE-FIXTURE-V1.json`, regenerated only by `export_test_value_fixture_when_requested`).

**Evidence-input-blocked.** The real root set and constraint values, the accepted PCR-profile set, the production Treasury, owner and
recovery descriptors, the real Genesis member evidence, and a regenerated manifest carrying the four entries.

**LIMIT (review F1; not a closed bypass).** Any party can CONSTRUCT a Production-class V2 Genesis from an invented, unlabelled root and
authority-signed software provenance, and `verify` accepts it against a trust built from the same self-made manifest
(`production_genesis_from_an_invented_root_constructs_and_only_the_approved_manifest_refuses_it`). `construct` cannot know whether a root
hash names an authentic certificate. What refuses such a Genesis is the independently approved manifest: the binary-supported trust
(V9 candidate manifest, class Production) verifies no Production Genesis, and only an Architect-supplied manifest derived from authentic
manufacturer material can make one acceptable.
