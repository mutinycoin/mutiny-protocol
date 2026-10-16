# Treasury proof of control: independent reproduction RESULT (candidate 3)

Recorded by Cipher on 2026-10-04 from the reports of an independent reproducer agent (Claude Opus 5.5) that did NOT write the schema, the vectors or the implementation and did not read the implementation, its tests or its commit messages.
Evidence class: Windows-host software verification of TEST-VALUE data, at most NATIVE-PASS-offline-TEST-VALUE. Nothing here is Linux, physical or production evidence; it does not qualify the cryptographic implementation, does not create a production descriptor
and does not authorize production signing or Genesis sealing. A Production class byte is necessary but does not by itself establish key provenance.

## Result
**REPRODUCED** for the FINAL input set below (round 3: 208 comparisons, 208 agreed, 0 differing, 0 disagreements between implementations).
Round 1 (V1 files): REPRODUCED, 1,176 comparisons, 0 differences, and it found specification gaps S1-S7 (the rotation plan's chain identity was not a trusted input; the GenesisID rule and layouts were undefined; Ed448 small-order public keys are forgeable under RFC 8032; the order of refusals for multi-defect inputs was undetermined; canonical-lineage input undefined; plan rules under-specified; naming).
Round 2 (revised text + additions): REPRODUCED WITH DIFFERENCES: 195 comparisons, 193 agreed; the 2 differences were wrong informational labels (`plain_rfc8032_ed448_verdict_of_the_forgery` for the identity and order-2 keys); no verdict differed. Corrected in round 3 and re-verified.

## Final input set (SHA-256, verified by the reproducer on its copies)
| File | Bytes | SHA-256 |
|---|---|---|
| `docs/TREASURY-PROOF-OF-CONTROL-SCHEMA-V1.md` | 70557 | `4ca7401ebb0248dec3600b599cc2a9deeb64a4c35308bc1f3d12607400992b9f` |
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json` | 16790 | `45c04c4be24d430e170cb42e1fe380bc9da51e495228abb238f485e495e3779f` |
| `qualification/TREASURY-PROOF-OF-CONTROL-PREIMAGE-VECTORS-V1.json` | 66813 | `d2b2c1c8bb53c3473d0496a8de0049a029a9eb596a3121e730f89138c7c7b9c6` |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json` | 100868 | `38f47d58c3e53f49e21dc3ecc8c9d8dddb8a905ffd45176188677914690763fe` |
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json` | 112675 | `b98b5e31edd28e3d8ac70e0cb7b82f15926b2fe1a9ee08ad68e8a2b4123708b3` |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json` | 104888 | `cf10d6d8976d8cdcb96c8c6184ea1651962c24a4b5dcde240c633249f6336173` |

## What was independent
Hashes (SHA-256/512, SHAKE256): own pure-Python code, CPython hashlib (OpenSSL 3.0.21), CPython HACL* modules, OpenSSL 3.5.7 CLI. CBOR: own strict reader/encoder plus an independent Perl splitter. Ed448: own RFC 8032 implementation (reproduces the RFC 8032 section 7.4 known answer) and OpenSSL 3.5.7
(same upstream lineage as the repository's port: not fully independent of it). FN-DSA draft profile: the pinned C reference compiled with an own C driver (MSVC, AVX2 and plain), the vendored fn-dsa-vrfy Rust crate called directly (two builds), and an own Python verifier (parameters from the pinned C source). Every call was cross-checked; 0 disagreements.
Ceremony logic, plan rules, the StateRoot of the canonical lineage, the GenesisID derivation, the normative refusal order (decoder D1-D6, I1-I2, V1-V6, C1-C9), the small-order key rule and the sequences were implemented from the TEXT ONLY and compared with the vectors.

## Limits (all stated by the reproducer)
- The store model was a JSON file, not SQLite; the SQLite durability (`synchronous=EXTRA`), read-only connection and cross-process claims were not exercised by the reproducer. `admission_store_id` is symbolic in the vectors; the "missing store id is refused" rule is a usage refusal of the public tool and was not reproduced.
- No independent specification of the FN-DSA draft exists; the C and Rust FN-DSA code share an author and the Python verifier takes its parameters from the pinned C source; the c-fn-dsa folder carries no git metadata (its upstream commit 1b858880... is unconfirmed); OpenSSL shares lineage with the repository's Ed448 port.
- Two minor text ambiguities remain, exposed by no vector: which role bytes are "known" (WrongRole vs DescriptorInvalid for a role other than 1), and the tool-level missing-store-id rule.
- A cryptographic caveat the reproducer proved and the schema now states: under textbook RFC 8032 the order-1, order-2 and both order-4 Ed448 public keys admit a signature forgery without a private key; the schema refuses all four at descriptor decoding.

The reproducers' reports: `scratchpad/cand3/treasury-repro/REPORT-ROUND-1.md` (round 1, recorded verbatim in substance); rounds 2 and 3 are in the agent's final messages and `RESULTS-ROUND2.json`, `RESULTS-ROUND3.json` (same folder).
