# Independent targeted A11 and public Genesis witness source review

Reviewer: Codex independent worker /root/hygiene, branch cand3/hygiene. Read-only review of a separate integration checkout; no author edits in the reviewed parent source and no Cargo/build/runtime campaign under this review. Review is independent from the parent implementation. This is a targeted source review, not a whole A-lane PASS, Production qualification, hardware admission, activation, locality or Genesis seal claim.

Observed integration HEAD: a3444930f3409d61f9aa6a21b7d732fe1617bb64. The promotion was staged/uncommitted while inspected. Parent formatting and staging occurred during the read-only review; the final digests below identify the inspected source bytes. Source comments subsequently corrected by the parent require their own successor source identity; these hashes remain historical review evidence.

## Findings

No actionable executable bypass was found within the reviewed parser promotion and public Genesis witness boundary.

1. X509Syntax parse_certificate/parse_crl reject inputs above existing 4096/32768-byte bounds before DER decoding. strict DER requires exact re-encoding. The parser has no OS trust, network fetch, ambient clock or private signing calls. The explicit RSA signature width and s<n checks survive promotion (x509_syntax.rs:572-578), including PSS with pinned same-hash MGF/salt. tests/support/x509_syntax.rs is a re-export of the normal library parser, so the prior RSA/ECDSA and s+n tests now exercise that implementation. Earlier red/green tests remain separate evidence; this reviewer did not rerun them on these promoted bytes.
2. certified_public_key_sha256 (x509_syntax.rs:68-80) computes SHA-256 over strict canonical certificate.tbs_certificate.subject_public_key_info DER after bounded certificate parsing. This matches existing provenance.rs:80-82 C2 SPKI meaning. It does not replace canonical hardware identity derivation, hash the whole certificate or reinterpret TPMT_PUBLIC as C2. The witness separately checks certified leaf key == parsed TPM public-area key and canonical identity/root at every ordered class position (attestation_witness.rs verify_witness). The single existing C2 field is checked against the first ordered endorsement leaf; all additional classes remain authenticated through their committed canonical identities and witness commitment.
3. Public evidence verification first verifies independently supplied Approved class/exact manifest/target and complete Genesis reconstruction. It then binds bundle network IDs and exact admitted NodeID, checks accepted PCR selection/digest, requires the admitted statement, and validates the exact committed witness under approved roots/classes. Certificate and CRL validation use Inputs.timestamp, never the verifier's current clock. This validates public certificate/key/identity/commitment consistency. ActivationRecord contains commitments and matching AK Name, and a successful result proves neither genuine credential activation nor execution locality.
4. Public bundle decoding bounds total bytes and entry counts before allocation, refuses indefinite/noncanonical/trailing encodings, and bounds each witness before copying. Existing witness decoding has a bounded whole input (131072 bytes) and class/chain/list count limits; per-field limits are enforced on exact re-encoding before verification. Actual fleet evidence may not fit these proposed software limits; this is an input/qualification dependency, not a demonstrated parser bypass.
5. VerifiedGenesisV2::verify/load and verify_with_public_evidence both unconditionally reject Production through require_supported_host_binding after reconstruction; verify_reconstruction is private. The new node test establishes software Production-class reconstruction and authenticated public-evidence positivity before checking both hard-stop E refusals. Existing main shipping entry paths still use V1 Production refusal and production_gate, which remains false. Deterministic consensus construct/freeze and public Constructed state representations are software reconstruction APIs and are not an eligibility result; callers cannot treat them as physical approval.
6. The public fixture explicitly labels synthetic_only=true and production_authorized=false. Its inputs use public software evidence and its records do not constitute approved fleet material. Independent caller trust remains essential: Approved copied from the same untrusted artifact would be circular approval. The reviewed production loader has independent supported trust and cannot obtain eligibility from fixture labels.

Minor actionable source/document corrections: ek_chain.rs:7-10 still describes test-only parser/RSA refusal; attestation_witness.rs:9-12 still says distribution is stopped by K1; CODEX-WITNESS-ENROLLMENT-DESIGN-20261004.md:13 calls current syntax test-only. Parent notified and owns current-versus-historical wording correction. These stale statements do not change the executable findings.

## Remaining launch and verification dependencies

No enforceable physical-host association, locality or remote-relay exclusion exists in these bytes. Hard stop E and post-sealing Production admission_scope refusal remain required; no Architect, committee or signed activation-result substitute is introduced. Actual manufacturer certificates/CRLs, approved fleet roots/constraints, PCR values and class templates are missing. Exact witness availability and lifetime retention need integrated artifact/archive evidence; a sidecar API and commitment do not prove distribution or complete historical replay availability. A future admission carrier remains unspecified. Frozen final integration bytes, affected lock/vendor provenance, native offline/empty-CARGO_HOME campaigns, parser negatives and end-to-end replay still need their own successor verification. The new test checks cannot close those dependencies or the entire prior A-lane review.

The previously identified generic RSA PSS canonical-representative defect was resolved before this promotion by explicit s<n enforcement. Its prior red and green evidence is preserved separately; no arbitrary-signature forgery or whole-lane closure is claimed.

## Exact inspected source identity

| Path under D:/Mutiny/build8-cand3 | SHA-256 |
| --- | --- |
| consensus/src/x509_syntax.rs | a595d48ac9fa58a7a4bc7d768f4a893b000a75ea4616489a789900ef45b22da2 |
| consensus/src/admission_evidence_v1.rs | 87283d262e705271766fc67a1bbfd9993858d41dbe083f991c5553e1930e0145 |
| node/src/genesis_artifact_v2.rs | 294065e054a19e8511f846e509ae6e104271e6699fe1ae8022dab1bb1c733e55 |
| consensus/tests/genesis_v2.rs | e2177ff29e70924905c03080c7baf3c3416a88c5c6de8491b12a2d88e60f426e |
| consensus/tests/support/x509_syntax.rs | dee153b09cc30c76d885a6f2f3cfbd8f22b56a0e8c971bbee7850a43fabae839 |
| consensus/Cargo.toml | 8a4d5475d7d051d221b6f246922d6c900da3955d8b1b5fb3fad7136b2f9610bb |
| consensus/src/lib.rs | e9ee2669b54cd34b6836c3585009a1232fa07a1034dc1bf63f22d0fe57faacc1 |
| spec/DECISION-TECHNICAL-ANNEX-V1.md | 5a8d3b3167913131dcaa5754faca09795c64d4369da0534e337b683bb7765319 |
| qualification/candidate-3/PUBLIC-GENESIS-WITNESS-SOFTWARE-FIXTURE-V1.json | 1cc7f6ce07491396dafddb3c1516a326bdd373fd7ec9d0692488158f0bf8e6c9 |
| consensus/src/attestation_witness.rs | 3c163ddbf5ce04a060f2401f9357522ded8258afcf731ec7fdf625a126ca4a8d |
| consensus/src/ek_chain.rs | 7e2063c056589fa4744afd042a60d175bcaac121e61fb3e4ea359db6c1ad4c4d |
| consensus/src/provenance.rs | 63af21f5cb1cdbdeee94e0fcb3b4c06f6224b4e98f96395d8e3b681f2108bc28 |
| node/src/genesis_artifact.rs | 9340e3dbf54ff4a64421fca4bc9969612209eca0abe7d53e79c22d5757572656 |
| node/src/production_gate.rs | 61750a4010a5bcbb5e574aa81e1b75b41420be76caf96f270feda79b3808ec9f |
| node/src/main.rs | d679a59c61bf4eb4edec63c858a2261a94694bd023b7635d37ab2e1404d856c5 |
| node/src/genesis_ceremony_v2.rs | 309ba28f9e8161fa6ea356de8a9f79cd9eff905986da7760717d511848311ab3 |

No task-owned process was started or stopped by this review. The separate dirty V3 worktree and frozen historical inputs remain preserved.
