# Treasury continuity implementation ledger

Direct human approval adopts the external protected continuity trust model for implementation and TEST-VALUE verification. No policy choice remains pending on that model. Authority stays limited to verifier issuance/consumption; no spending keys, ordinary consensus/enrollment/payment dependency, committee or changed proof format.

Current source implementation (production construction remains unavailable):

- `consensus/src/treasury_continuity_v1.rs` implements exact-scope, operation/content matching, monotonic sequence, new-versus-repeated outcomes, bounded retained public records, irreversible consumption, pending-local freeze and exact-record confirmation. Confirmation is itself an ordered transition. Fresh request nonce/context checks supplement, but do not substitute for, authenticated current-state transport.
- `treasury_admission_v3` has crate-private ordering hooks. Native descriptor/expected binding and OS nonce precede reservation; reservation precedes SQLite issuance. Full hybrid proof and exact unconsumed issuance precede external consumption; SQLite consume/admission still commits atomically before local success. Legacy public TEST-VALUE methods and unconditional production refusal remain intact.
- Controls cover lost acknowledgments, conflicting identifiers, wrong scope/service/store, stale sequence/receipt, exact reconciliation, concurrent identical consumption, real hybrid invalid-proof refusal before external mutation, and external consumption followed by local rollback/reopen. The service in these controls is explicitly simulated outside the local SQLite file; it is not a qualified protected administrator domain.

Targeted Windows compilation and runtime completed on 2026-10-05 at 15:26:49Z: four tests passed, zero failed or ignored (281 filtered), using the exact named Rust 1.98.1 toolchain, `--offline --locked --release`, a new protected C: target/TMP, and one test thread. All 2,207 inventoried source files were unchanged during the run. Receipt: `C:/Users/admin/MutinyBuild8-Codex-RootSoftware-20261005-ff913ef404004325bca531d1780dd8b1/evidence/treasury2-result.json`; Cargo log SHA-256 `d5c9110a253bb3663c6508e31116c5fb6fbc6c8db7fb2c090bfe19dadd32ab0f`. The preceding PowerShell stderr-handling failure produced no test result and remains preserved. This is a targeted TEST-VALUE result, not complete Treasury antirollback qualification.

The successor Linux campaign naturally closed on 2026-10-05 at 18:26:23Z with
25 exact PASS, zero FAIL and zero ignored. It covered the owner/model's fourteen
controls plus eleven real hybrid authenticated-wire, domain and native endpoint
controls. Ordinary default Node compilation and all-target checks also passed.
Independent verification checked all 449 recovered files, every actual test log,
the unchanged 2,217-file source, and package/vendor inventories. Receipt:
`D:/Mutiny/build8-targets/codex-takeover-20261004/ROOT-TREASURY25-INDEPENDENT-CLOSURE1.json`,
SHA-256 `fd70f71abde7dcb5adcd661345fc94c334c580c9515edd2fcfb7455b11233de2`.
The separately reviewed 153-package standalone lock is retained at
`qualification/treasury-continuity-service-v1/Cargo.lock`, SHA-256
`2aa27d089215232c243778546f27d05bbb96789bac31fcf09b1baaeb27a10ee7`.
Adding this identical qualified lock and updating this ledger are subsequent
source provenance changes; the recorded 2,217-file campaign identity is preserved.

The V3 setup refusal before compilation, unrun V4, and partial V5 local recovery
remain preserved. Recovery-only V6 corrected POSIX metadata path classification;
it did not rerun tests or relax the approved graph constraints.

Completed software portions include canonical bounded request/receipt/history,
hybrid selected-key authentication, exact retry/content/context matching,
durable native endpoint transactions before acknowledgement, the owning verifier
freeze/reconciliation model, and the listed executable component controls.
Fresh signatures do not by themselves establish an independently administered,
monotonic service. The endpoint's test identity does not enroll a real service.

Finite unfinished software: deployed authenticated transport and enrolled
current-state provider construction/rotation; exact authenticated restart/audit
integration; the remaining external/local crash boundaries; reviewed OS-handle/VFS
protection for main database and journal/path substitution. Allocation bounds for
all native admission readers must be established before hostile rows are decoded.
The completed component tests do not close these remaining software items.

Required actual deployment inputs: service administrator/access and restore domains; authenticated public service identity; pinned verifier/store/context identities; protected storage provider and retention/backup policy. Supply public inputs only, never credentials or spending keys. Production eligibility remains disabled until this actual boundary, reconciliation and native filesystem behavior qualify. Native crash tests and real power-loss evidence will be reported separately.
