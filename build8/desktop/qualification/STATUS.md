# Build8 qualification status — 2026-09-29

The three Architect policy blockers are resolved. No routine vote is pending.
No Genesis or complete ProtocolFingerprint has been created.

Passed software checks:

- Twelve Rust recovery/reputation tests and strict clippy checks.
- Eight deterministic Python reputation tests and 27 scenario rows.
- Independent CBOR/Ed25519 verification of the public recovery fixture.
- Nine desktop tests; separate recovery-role derivation additionally matches an
  independent Python HMAC-SHA512/Ed25519 public vector.
- Consensus dependency audit: 80 dependencies, no reported advisory findings.

Real Node A evidence (local node-a-*.json is excluded from source history):

- Administrator inventory: TPM present/ready/enabled, STM, manufacturer EK cert.
- Four-certificate manufacturer chain: signatures, validity, key usage, CA path
  constraints and pinned downloaded CA bytes verified independently.
- Online revocation status unavailable: the relevant certificates have no
  revocation endpoints. Do not report a successful online revocation check.
- TPM EK public modulus matches the manufacturer certificate.
- Fresh transient P-256 AK and test voting key creation, nonce-bound SHA-256 PCR
  quote (PCR 0/2/4/7), and key certification passed.
- Independent transcript verification passed; seven tamper cases rejected.
- ActivateCredential blocked by Windows TBS in this unelevated session. The
  reviewed run-node-a-tpm-proof.ps1 wrapper is awaiting Administrator execution.
  It verifies executable/library hashes and the Microsoft library signature.
- All own transient handles were flushed. No private material was persisted,
  no existing persistent key was removed, and no TPM/registry/boot policy changed.

These results do NOT establish full physical admission. Pending: successful
credential possession verification, approved manufacturer trust/revocation policy
in the final manifest, supervised physical-host association, measured boot log
verification, and durable production key enrollment. Test keys are not Genesis
voting identities. The probe's local self-challenge is a capability test; final
admission must use the separately verified supervised challenge transcript.

The updated Desktop is open for the user to unlock the existing wallet and export
only the separate bootstrap recovery public identity. No phrase/password is
requested or read by the agent.

Remaining software gates include durable BFT state/locks, ordinary signature
verification, active registry recovery commitment/persistence, complete canonical
object schemas, adversarial node/network qualification and real ESP32 difficulty
measurement. Model/mock-admission tests cannot substitute for these gates.

Sources: manufacturer CA publication is ST TN1330; Windows command restrictions
are documented by Microsoft. Neither establishes qualification of this machine:

- https://www.st.com/resource/en/technical_note/tn1330-st-trusted-platform-module-tpm-endorsement-key-ek-certificates-stmicroelectronics.pdf
- https://learn.microsoft.com/en-us/windows/win32/tbs/command-blocking

## TPM test evidence provenance (2026-10-03)

- Portable tests and examples use the deterministic SOFTWARE TPM TEST-VALUE fixture
  (`consensus/tests/support/software_tpm.rs`, committed export
  `qualification/TEST-VALUE-SOFTWARE-TPM-FIXTURE-V1.json`, drift-tested). Its signatures are
  real ECDSA over its own public keys; it is labelled `TEST_VALUE:true, physical_tpm:false,
  production_eligible:false, bond_eligible:false`, carries the TEST-VALUE trust-manifest marker, is
  rejected by production Genesis input validation, by every Production-class admission path and
  Bond create, and by the node's physical-evidence mode. SIMULATED != PHYSICAL: it never qualifies
  hardware. In an isolated Legacy/Test-class test chain a simulated member can be admitted and can
  bond by design; that confers nothing on a Production-class chain. The JSON labels are
  documentation only; no shipped code reads them.
- Real host TPM evidence (Node A quote and public fixture) is PRIVATE, gitignored and never compiled
  in. Physical-only checks read it at runtime from `BUILD8_PHYSICAL_TPM_PROFILE_FIXTURE` /
  `BUILD8_PHYSICAL_TPM_LIVE_QUOTE`, are `#[ignore]`d, and fail loudly when run without it.
  Implemented != Qualified; Offline != Physical.

## Admission operation fixtures (TPM admission package, 2026-10-03)

- The three formerly tracked JOIN / RECOVERY-MATERIAL / ROTATION fixtures embedded one real host's
  TPM profile. They are removed from the tip and replaced by deterministic TEST-VALUE equivalents:
  `qualification/JOIN-TEST-VALUE-FIXTURE-V1.json`,
  `qualification/RECOVERY-MATERIAL-TEST-VALUE-FIXTURE-V1.json`,
  `qualification/ROTATION-TEST-VALUE-FIXTURE-V1.json` (generator `consensus/tests/support/software_tpm.rs`,
  drift test `consensus/tests/software_admission_fixtures.rs`). Class: SIMULATED / TEST-VALUE
  (`TEST_VALUE:true, physical_tpm:false, qualifies_hardware:false, production_eligible:false,
  bond_eligible:false`, `real_host_evidence:"none"`). They prove software behaviour only.
- The same unit checks run over REAL evidence only at runtime, from an untracked path:
  `BUILD8_PHYSICAL_JOIN_FIXTURE`, `BUILD8_PHYSICAL_RECOVERY_MATERIAL_FIXTURE`,
  `BUILD8_PHYSICAL_ROTATION_FIXTURE` (ignored tests `physical_*_fixture_from_runtime_path` in
  `consensus/src/{join,recovery_material,rotation}.rs`; reported SKIPPED-PHYSICAL when absent).
  The old file names are gitignored so real evidence copied back cannot be committed.
- The old fixture bytes remain in the private Git history, deliberately untouched (no history
  rewrite, no rekeying); publishing that history is a separate pending decision.
- Guard: every tracked JSON that embeds a TPM profile carries the TEST-VALUE marker or an
  allow-listed synthetic repeated-byte hardware id (`tracked_json_profiles_are_test_value_or_synthetic`).

## Physical admission enforcement (TPM admission package, 2026-10-03)

Class: IMPLEMENTED; the package's tests are NATIVE PASS (offline, TEST-VALUE) on Windows with SIMULATED
TPM material. Not qualified, not physical, not release locked. Details, trace and open questions:
`docs/PHYSICAL-ADMISSION-ENFORCEMENT-V1.md`.

- The admission class comes only from committed Genesis data (a trust-root commitment in the
  Genesis rule manifest that must equal the committed policy roots). In the Production class every
  admission path (Genesis, JOIN, ROTATION, RECOVERY, V1 and V2), state reconstruction, every
  StateRoot and Bond create require a typed provenance statement bound to the profile's attestation
  key and PCR profile, and reject the TEST-VALUE marker. Schema and domains are PROPOSED / UNFROZEN.
- The V9 candidate rule manifest commits to no trust-root set, so no Production-class Genesis can be
  built or verified until the Architect decides the roots (Q1) and a new candidate commits to them.
- Existing real-host material is a version-1 profile without a provenance statement: valid only in
  the Legacy/Test class. Production use needs a new authority approval of a version-2 profile.
- Known limit: an authority-signed software profile with a self-consistent statement is accepted in
  the Production class (tests `authority_attestation_is_the_anchor_*`). The anchor remains the
  supervised ceremony and the authority's signature; no check proves hardware.
- Not verified: the Linux-only helper-file checks (`node/src/tpm_backend.rs`) were not compiled or
  run on Linux in this package; no physical TPM was used.
