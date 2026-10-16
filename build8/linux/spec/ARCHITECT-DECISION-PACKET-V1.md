# Build8 Architect decision packet V1 — approved as amended

Authority: [Architect amendments](ARCHITECT-AMENDMENTS-V1.txt), SHA-256
`198823d669cb2c1ef1fc5b4d8654861f68a12050eeeeb6637a61325e9dbed281`.

Approval is effective. No routine reapproval is requested. The amendments control
all conflicts with the original packet. The old accumulator, full hardware-reset
policy and permanent twelve-license ceiling are superseded.

| Area | Recorded approved decision |
|---|---|
| Bootstrap | BOOTSTRAP_CENTRALIZED; physical Node A only after qualification. End label only after >=4 independent physical voters and every measured single-node-loss test preserves >2/3 of original committed weight. |
| Quorum | Strict >2/3, durable propose/prevote/precommit locks; no silent offline removal. VM/cloud/vTPM weight zero; Vultr no bonds. |
| Clocks | MiningEpoch = 60 seconds. ContinuityPeriod = 60 certified blocks. Distinct types/fields everywhere. |
| Reputation | Direct exact G=1000*P+A+4*S+2*H+floor(Q/10^10); R=max(0,G-D). No additive compounding, cap or hidden baseline. Checked integer arithmetic. |
| Hardware rotation | Authenticated, newly attested physical generation atomically supersedes the old; preserve admission/history/P/bonds/bond ages/penalties/lineage, reset H. Same-TPM verified key rotation retains H. |
| Bonds | Optional physical-only lots >=100 MUT; minimum lock 4,320 ContinuityPeriods, notice 720; no interest or downtime slashing; objective equivocation revocation and slash. |
| TPM/certificates | Supervised EK/ActivateCredential/TPM P-256/fresh quote/measured-platform qualification. Deterministic CBOR with network/Genesis/fingerprint, explicit round/step, roots and sorted unique signatures. No transport authority. |
| Economics | SHA-256d; 60-second block target; bounded 60-block retarget; 1 MUT forever; maturity 100; no premine; 1 atom/byte relay/admission fee; licensed winner's owner receives subsidy/fees. |
| Licenses | Twelve fresh Genesis licenses, not a lifetime maximum. LicenseIssueV1/LicenseRecordV1 defined; new_license_issuance_enabled=false at Genesis. Future activation requires formally authorized consensus/governance. No live Bitcoin dependence. |
| Durable state | No silent pending eviction; explicit terminal events, independent non-producing-node reconciliation, exact checkpoint/pruning qualification before Genesis. |

Updated [technical annex](DECISION-TECHNICAL-ANNEX-V1.md) and
[canonical specification draft](CANONICAL-BUILD8-SPEC-V1.md) incorporate these rules.
The exact source amendment is preserved, rather than treating the summary as its
replacement. Wallet restore PASS remains valid; both historical purchase copies
were freshly reverified for exactly twelve entitlements.

The three exposed policy blockers are resolved by the preserved
ARCHITECT-BLOCKER-RESOLUTIONS-V1.txt. BOOTSTRAP-RECOVERY-V1.md incorporates the
bootstrap-only recovery authority, irreversible old-set-certified decentralized
activation, provisional Genesis weight 1, permitted formula decreases and dynamic
concentration reporting. No routine decision stop remains.

Current qualification: 27 model scenarios, eight Python tests, twelve Rust
recovery/reputation tests and independent public CBOR/signature verification pass.
These use simulated physical admission. Node A inventory confirms a ready TPM and
EK certificate; full attestation is pending. No ProtocolFingerprint or Genesis has
been created. Complete node state, canonical codecs, physical TPM qualification,
adversarial checks and real initial difficulty measurement remain required.
