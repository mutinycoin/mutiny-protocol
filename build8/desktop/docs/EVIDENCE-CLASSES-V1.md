# Evidence classes, V1

Every result produced for Build 8 carries exactly one class, so a reader can tell what it does and does not establish.
Implemented ≠ Qualified. Offline ≠ Physical. Simulated ≠ Physical. Deployed ≠ Release locked.

| Class | What it is | Can establish | Cannot establish |
|---|---|---|---|
| **IMPLEMENTED** | Source exists, compiles and its own checks pass in the stated configuration. | That the behaviour is present and the build is clean. | Qualification, hardware behaviour, production readiness. |
| **NATIVE PASS (offline, TEST-VALUE)** | Automated tests pass on the native toolchain with no network and only TEST-VALUE data (software TPM doubles, rehearsal keys, test chains). Debug and release profiles are named separately. | Software correctness against the tests and the exact source commit. | Physical clock accuracy, real TPM behaviour, production keys or custody, release lock. |
| **SIMULATED** | A software double stands in for hardware (the deterministic software TPM, `ControlledClock`, a fake chrony client, a labelled-seed rehearsal key). Always labelled TEST-VALUE and carrying `physical_tpm:false`, `production_eligible:false`, `bond_eligible:false` where a fixture exists. | That code paths accept and reject the right shapes. | That any hardware or operator process does. A simulator is indistinguishable from a real TPM to the Rust verifier, so a marker is only a guard against accidental use. |
| **PHYSICAL** | Evidence produced by the real device, host or reference (a real TPM quote, a measured oscillator drift over a stated interval, a live chrony/NTS session) with provenance recorded. | Qualification of that hardware class or host, if and only if its acceptance criteria are met. | Anything about a different class, host or time. |
| **DEPLOYED** | The artifact is running somewhere. | That it was installed. | That it is release-locked or qualified. |
| **RELEASE LOCKED** | The protocol fingerprint, source locks and Genesis are sealed under the Architect's explicit action. | Nothing is assumed until that action is recorded. | – |

## Rules for the Linux native test package
* Every test the package runs is **NATIVE PASS (offline, TEST-VALUE)** at most. The runner records the profile (debug or release) for each result.
* Tests that need private or physical evidence are `#[ignore]`d and are reported as **SKIPPED-PHYSICAL**, listing the environment variables that would supply the evidence. They are never counted as passed.
* A passing run says nothing about clock-drift classes, real TPMs, live NTS, production keys or Genesis.
* The package is identified by its source commit and tree, its per-file SHA-256 manifest, the lockfile hashes, the toolchain and the SHA-256 of its runner.

## TPM admission labels
* Fixture labels (`TEST_VALUE`, `physical_tpm`, `production_eligible`, `bond_eligible`, ...) are documentation; no shipped code reads them. What consensus enforces is the admission class committed in Genesis: in the Production class the TEST-VALUE marker is rejected and a typed provenance statement is required at every admission path and at Bond creation. An isolated Legacy/Test-class test chain can admit and bond a simulated member by design; that establishes software behaviour only. See `docs/PHYSICAL-ADMISSION-ENFORCEMENT-V1.md`.
* A simulated profile signed by the admission authority with a self-consistent (version-2) provenance statement is accepted in the Production class at V2 Genesis construction only (test `production_genesis_from_an_invented_root_constructs_and_only_the_approved_manifest_refuses_it`; V1 Production Genesis is refused, test `authority_attestation_is_the_anchor_consistent_software_provenance_passes_the_v1_class_rule_but_production_is_refused`), and such a Genesis is verifiable only against an approved manifest that commits to its roots; after sealing, the Production class refuses every authority-signed hardware admission (Order A8, candidate 3). Such a result is SIMULATED: it shows that the anchor is the supervised ceremony and the authority's signature, never that software is hardware.
