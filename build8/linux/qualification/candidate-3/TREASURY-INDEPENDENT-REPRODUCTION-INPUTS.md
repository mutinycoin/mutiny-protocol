# Treasury proof of control: independent reproduction inputs (candidate 3)

**Independent reproduction: pending (Cipher).** Nothing in this file claims a result: Cipher records the result of
each round. Round 2 adds the two V2-ADDITIONS files (steps 10 to 13) and reuses the unchanged V1 files. Prepared by
the Treasury-schema lane (C3) for Cipher, who will have another agent reproduce everything from the files below
alone, without access to the implementation's source code. SIMULATED / TEST-VALUE: every key derives from a public
label; there is no production material anywhere in these inputs.

## 1. The complete inputs

These files are the complete input. The table is generated (`consensus/tests/treasury_schema_conformance_v1.rs`;
the test fails if a listed file changes without this table being regenerated). Verify each SHA-256 before starting.

<!-- BEGIN GENERATED: reproduction-inputs -->
| File | Bytes | SHA-256 | Content |
|---|---|---|---|
| `docs/TREASURY-PROOF-OF-CONTROL-SCHEMA-V1.md` | 70557 | `4ca7401ebb0248dec3600b599cc2a9deeb64a4c35308bc1f3d12607400992b9f` | the specification (whole file) |
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json` | 16790 | `45c04c4be24d430e170cb42e1fe380bc9da51e495228abb238f485e495e3779f` | V1 codec and signature vectors; public descriptors of the K1/K2 test keys in `descriptor` |
| `qualification/TREASURY-PROOF-OF-CONTROL-PREIMAGE-VECTORS-V1.json` | 66813 | `d2b2c1c8bb53c3473d0496a8de0049a029a9eb596a3121e730f89138c7c7b9c6` | exact preimages per V1 vector and 18 derived negative vectors |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json` | 100868 | `38f47d58c3e53f49e21dc3ecc8c9d8dddb8a905ffd45176188677914690763fe` | ceremony keys, trusted configuration, rotation plan, 10 proofs, 12 cases, 2 sequences |
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json` | 112675 | `b98b5e31edd28e3d8ac70e0cb7b82f15926b2fe1a9ee08ad68e8a2b4123708b3` | V2 additions: 4 Ed448 small-order keys with forged proofs, honest control, 10 multi-defect probes |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json` | 104888 | `cf10d6d8976d8cdcb96c8c6184ea1651962c24a4b5dcde240c633249f6336173` | V2 additions: trusted chain, height and pinned plan, 3 plans, lineage records and root, 14 succession cases, Genesis derivation and 8 verdicts, 7 ceremony-order probes |
<!-- END GENERATED: reproduction-inputs -->

The schema document (sections 2 to 7, Appendix A and section 13) is the specification; the five vector files are the
data (schema section 13 lists the same set). The
"test public descriptors" are the `descriptor` fields of the V1 vectors and the `keys` of the ceremony vectors. An
independent verifier needs: SHA-256, SHA-512, SHAKE256, a CBOR reader that reports exact item bytes, an RFC 8032
Ed448 verifier with context support (for example OpenSSL 3), and an FN-DSA verifier for the profile
`MUTINY-FNDSA1024-PORNIN-20260722-V1` (Thomas Pornin's 22 July 2026 draft variant, not FIPS 206 final; for example the
C implementation c-fn-dsa at the commit named in schema A.5, with external-mu or raw-message verification).

## 2. Steps an independent verifier performs

1. **Literals.** Check the domain literal is 42 bytes and the profile literal 35 bytes (schema A.1).
2. **Parse.** For each V1 vector and each ceremony proof, split the challenge into its 14 CBOR items and check the
   types, the order, the strictness rules (schema section 3: definite array, no trailing byte, re-encoding identical)
   and the 253-byte length; compare the split with `challenge_items` of the preimage vectors. Split each descriptor
   into its 9 items (`descriptor_items`).
3. **Hash.** Recompute `descriptor_sha256 = SHA-256(descriptor)`, the AddressID (schema A.9), the Treasury record
   bytes and `treasury_record_sha256` of the ceremony vectors from the K1 descriptor and class 2 (schema A.10), and
   the rehearsal context from the label (schema A.11). Compare with challenge items 9 to 13 and with the vector
   fields.
4. **Rebuild the preimage.** `intent = SHA-512(domain || 0x00 || challenge)`; compare with `intent_sha512` /
   `intent`. For the preimage vectors also compare `intent_preimage_hex`.
5. **Verify BOTH signatures independently.** Split the 1,394-byte serialization (114 then 1,280 bytes). Ed448: RFC
   8032 pure Ed448, empty context, over the 64-byte intent (dom4 `53696745643434380000`); also confirm that a
   non-empty context and Ed448ph fail. FN-DSA: compute `hpk = SHAKE256(public_key, 64)` and
   `mu = SHAKE256(hpk || 0x00 || 0x00 || intent, 64)`, compare with the preimage vectors, and verify the signature
   over the raw 64-byte intent with an empty context (or over `mu` in external-mu mode). Record each verdict
   separately; a proof is valid only if both are.
6. **Run the negative cases.** Every entry of `negative` in the preimage vectors must be refused for its stated
   reason (or, where a verifier's error names differ, for the same cause), and nothing in it may verify.
7. **Ceremony cases.** With the trusted configuration of the ceremony vectors (network, phase 1, class 2, Treasury
   record, context) and the expectation named by each case (generation one; rotation plan; canonical lineage), apply
   schema section 7.2 in order and compare with `ceremony`. Check the rotation plan: decode it, check its unsigned
   body against `unsigned_body_hex`, verify its authorization by K1 under `MUTINY-BUILD8-WALLET-KEY-ROTATE-V1` and its
   possession by K2 under `MUTINY-BUILD8-WALLET-KEY-ROTATE-POSSESSION-V1` (same intent rule and components), and confirm
   that only K2 is an authorized successor: the impostor K3 must be refused although both of its signatures verify.
   This covers wrong context, wrong class, wrong phase, wrong authority/Treasury, wrong descriptor, wrong generation
   and the impostor successor.
8. **Sequences.** Replay `nonce_replay` and `repeatable_audit` with any durable single-use store bound to (context,
   record hash): first admission consumes the nonce; a replayed admission (also of a different proof with the same
   nonce, also after a restart) fails; read-only audits re-validate the recorded proof and change nothing; an
   unrecorded proof is not admitted; `verify_frozen` on the changed Parameters fails the approved-manifest comparison.
9. **Evaluation order.** For every input with more than one defect apply schema section 7.0 (decoder steps D1 to D6,
   then the signature serialization I2, then V1 to V6 or C1 to C9) and compare with `expected` of
   `multi_defect_probes` (proof additions) and `result` of `ceremony_order_probes` (ceremony additions).
10. **Ed448 small-order keys.** For each entry of `ed448_small_order.keys` (proof additions): check the key's order,
   that plain RFC 8032 accepts the stated forgery exactly where `plain_rfc8032_ed448_verdict_of_the_forgery` says so,
   that the FN-DSA half in `fndsa_signatures` verifies, and that a verifier applying schema section 4 refuses the
   descriptor (`DescriptorInvalid`).
11. **Trusted succession inputs.** Take the trusted chain (network, genesis, fingerprint), the trusted height and the
   pinned plan identity from `trusted_configuration_additions` (ceremony additions), recompute each plan identity from
   its `unsigned_body_hex`, verify the plans in `signed_plans`, and evaluate `succession_cases` with schema section 7.3.
   The V1 `rotation_plan` expectation is the plan `PLAN_K1_K2` under these inputs.
12. **Canonical lineage.** Recompute the StateRoot of `canonical_lineage.records` (schema 7.3 block) and of the
   fabricated records; only the first equals `canonical_state_root`.
13. **Genesis.** Split the Parameters and the Genesis descriptor (schema 7.5 block), recompute the GenesisID and
   evaluate `genesis.verdicts` with the order of schema 7.5 (a store id is symbolic: `approved` is the store P1 was
   admitted to, `other` a second store of the same ceremony).
14. **Report** per step the inputs used (with their SHA-256), the independent tools and versions, every verdict and
   every difference. A difference is evidence; it is not to be resolved by changing a vector.

## 3. What a successful reproduction establishes, and what it does not

It establishes that the specification, the vectors and an independent implementation agree on the encoding, the
hashes, the preimage, both signature verdicts and the ceremony verdicts. It does not qualify the cryptographic
implementation, does not create a production descriptor, does not authorize production signing or Genesis sealing,
and says nothing about physical custody. A Production class byte is necessary but does not by itself establish key
provenance. After Cipher records the reproduction, the schema's "Frozen identity (candidate 3)" section may be
declared frozen.
