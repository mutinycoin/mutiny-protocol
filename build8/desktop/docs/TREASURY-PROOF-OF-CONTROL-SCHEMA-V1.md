# Treasury proof-of-control: schema V1

Status: **architecture APPROVED by the Architect** (continuation order of 4 October 2026, section 7: the 14-item
architecture, the definite canonical array, the declared types, strict re-encoding and limits, the SHA-512 framed
intent, the BOTH_REQUIRED Ed448 + FN-DSA profile, descriptor SHA-256, the domain-separated AddressID and the
canonical Treasury-record SHA-256). **Byte-level closure prepared in candidate 3; NOT byte-frozen until the
independent reproduction recorded by Cipher (pending).** Implemented != Qualified; Simulated != Physical. Every
key, proof and vector here is TEST-VALUE. `PRODUCTION_SECURITY_QUALIFIED` is `false`: a production-phase proof can
be neither signed nor accepted.

Sources of truth: `crypto-v2/src/treasury_proof_v1.rs` (challenge codec, signer, verifier); `crypto-v2/src/lib.rs`
(`Domain::TreasuryProofOfControl`, `intent`, the hybrid signature, the descriptor and AddressID encodings);
`consensus/src/treasury_v1.rs` (Treasury record); `consensus/src/treasury_rehearsal_v1.rs` (ceremony layer: trusted
expectations, succession, audit, manifest, post-freeze check); `consensus/src/treasury_admission_v1.rs` (durable
single-use admission). Appendix A and the blocks of sections 7.3 and 7.5 export the exact definitions from these
files; section 13 lists the reproduction inputs and section 14 records their identities. The V1 vector files are
unchanged; additions made after the independent review (F1 to F11) and the independent reproduction (S1 to S7) are
marked and their vectors are in two new V2-ADDITIONS files (section 9).

Generated blocks. Every block between `<!-- BEGIN GENERATED: name -->` and `<!-- END GENERATED: name -->` is
written by `consensus/tests/treasury_schema_conformance_v1.rs` from the public API, exact source lines and the
committed vector files, and that test fails on any byte difference (section 10). Regenerate in `consensus/` with
`BUILD8_TREASURY_SCHEMA_DOC=<file> BUILD8_TREASURY_INPUTS_DOC=<file> cargo test --offline --locked --test
treasury_schema_conformance_v1`: the two files are this document and
`qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-INPUTS.md` with every block regenerated and all other
text unchanged. Hex is lowercase, lengths are in bytes and `||` is concatenation.

## 1. Purpose and properties

A proof of control shows that the holder of a hybrid **Ed448 + FN-DSA-1024** wallet-owner key controls the
**exact public descriptor bytes** that name the native MUT Treasury authority. It is:

* **Non-spending.** It is signed under its own domain, which no transaction, rotation, Bond or other authorization
  verifies, so a proof is never valid as a spend and a spend is never valid as a proof
  (`every_hybrid_intent_domain_rejects_cross_domain_and_role_relabeling`,
  `domain_is_registered_unique_nonspending_and_role_bound`).
* **Both-signatures.** Both the Ed448 and the FN-DSA component are required (`BOTH_REQUIRED`); a single component is
  malformed and a zeroed, swapped or foreign component fails (`proof_requires_both_components_and_every_binding`,
  `preimage_vectors_are_exact_and_reproducible_from_the_committed_v1_vectors`).
* **Bound** to the exact descriptor bytes, the key version (generation), the cryptographic profile (suite, policy,
  profile string), the proof phase and class, the Treasury record, a public ceremony context and a single-use nonce.
* **Not circular.** The challenge contains **no GenesisID**. The Treasury record is inside the Genesis Parameters and
  therefore inside the GenesisID, so binding the GenesisID would be circular. The context is a public ceremony
  identifier fixed *before* any Genesis exists; after the freeze the GenesisID is recomputed and the same recorded
  pre-freeze proof is verified again against the Treasury extracted from the frozen bytes (section 7.5).
* **Key control only.** A verified proof establishes that the holder of the key controls the descriptor. It does
  **not** approve any other Genesis parameter: the frozen Genesis is compared separately with the independently
  approved final manifest (section 7.5).

## 2. Constants

<!-- BEGIN GENERATED: constants -->
| Name | Value | Exported from |
|---|---|---|
| Challenge version | `1` | `treasury_proof_v1::CHALLENGE_VERSION` |
| Network | `0x4d555401` (u32; CBOR `1a4d555401`) | `NETWORK` |
| Domain literal | `MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1` (42 bytes, ASCII, no terminator) | `Domain::TreasuryProofOfControl.bytes()` |
| Domain role | `WalletOwner` (a key of any other role is refused) | `Domain::role` (A.2); the V1 vector fails under a relabelled role |
| Wallet crypto suite id | `1` (u16) | `WALLET_CRYPTO_SUITE_ID` |
| Signature policy | `BOTH_REQUIRED`, id `1` (u8) | `BOTH_REQUIRED_POLICY_ID` |
| FN-DSA profile literal | `MUTINY-FNDSA1024-PORNIN-20260722-V1` (35 bytes) | `PROFILE` |
| Phase | `1` = Rehearsal, `2` = Production | `Phase` |
| Class | `1` = PRODUCTION, `2` = TEST-VALUE; phase 1 requires class 2, phase 2 requires class 1 | `CLASS_PRODUCTION`, `CLASS_TEST_VALUE`, `Phase::required_class` |
| Challenge items | `14` | `FIELDS` |
| Challenge size | `253` to `261` bytes; the decoder accepts 1 to `1024` | encoding; `Challenge::decode` |
| Signature serialization | Ed448 `114` bytes then FN-DSA `1280` bytes = `1394` bytes | `SIGNATURE_BYTES`, `signature_to_bytes` |
| Intent payload limit | `1048576` bytes | `intent` |
| Descriptor decode limit | `2048` bytes | `PublicKey::decode_descriptor` |
<!-- END GENERATED: constants -->

## 3. The challenge (the signed payload)

Canonical CBOR as written by the `minicbor` encoder (definite lengths, shortest-form integers): a definite-length
array of exactly 14 items in the order below. The type column is the encoder call of `Challenge::encode_unchecked`,
read from the source; the decoder `Challenge::decode` reads the same sequence (section 10 checks both).

<!-- BEGIN GENERATED: challenge-fields -->
| # | Item | CBOR type (encoder call) | Value | Refused when (verifier) |
|---|---|---|---|---|
| 1 | `version` | unsigned integer (`u8`) | `1` | other value: `Malformed` |
| 2 | `network` | unsigned integer (`u32`) | `0x4d555401` | other network: `Malformed` |
| 3 | `phase` | unsigned integer (`u8`) | `1` Rehearsal or `2` Production | other value: `Malformed`; `2`: `ProductionRefused` |
| 4 | `class` | unsigned integer (`u8`) | `2` with phase 1, `1` with phase 2 | other: `ClassPhaseMismatch` |
| 5 | `generation` | unsigned integer (`u64`) | key version of the descriptor, at least `1` | `0`: `ZeroField`; not the descriptor's: `WrongKeyVersion` |
| 6 | `suite_id` | unsigned integer (`u16`) | `1` | other: `WrongProfile` |
| 7 | `policy_id` | unsigned integer (`u8`) | `1` (BOTH_REQUIRED) | other: `WrongProfile` |
| 8 | `profile` | text string (`str`) | `MUTINY-FNDSA1024-PORNIN-20260722-V1` (35 bytes) | other: `WrongProfile` |
| 9 | `descriptor_sha256` | byte string, 32 bytes (`bytes`) | `SHA-256(descriptor)` | other: `AlteredDescriptor` |
| 10 | `address_id` | byte string, 32 bytes (`bytes`) | AddressID of the descriptor at its generation (A.9) | other: `AlteredDescriptor` |
| 11 | `treasury_authority` | byte string, 32 bytes (`bytes`) | generation-one AddressID of the Treasury | zero: `ZeroField`; not the trusted Treasury: `TreasuryMismatch` |
| 12 | `treasury_record_sha256` | byte string, 32 bytes (`bytes`) | `SHA-256(Treasury record)` (A.10) | zero: `ZeroField`; not the trusted record: `TreasuryMismatch` |
| 13 | `ceremony_context` | byte string, 32 bytes (`bytes`) | ceremony context (section 6) | zero: `ZeroField`; not the expected context: `WrongContext` |
| 14 | `nonce` | byte string, 32 bytes (`bytes`) | 32 public bytes, single use | zero: `ZeroField`; already admitted: `Replay` |

Encoded size (`Challenge::encode`): 253 bytes for generation 1 to 23; 254 bytes for generation 24 to 255; 255 bytes for generation 256 to 65535; 257 bytes for generation 65536 to 4294967295; 261 bytes for generation 4294967296 or more.
<!-- END GENERATED: challenge-fields -->

Decoder (strict), in this order (normative since the independent reproduction, S5; the first failing step
decides the refusal):

* **D1** the payload is 1 to 1,024 bytes (`Malformed`).
* **D2** the items are read in order: a definite array header of exactly 14 items, version 1 and network
  `0x4d555401`, phase 1 or 2, then each item with its type (unsigned integers within their declared width, item 8 a
  definite-length valid UTF-8 text string, items 9 to 14 definite byte strings of exactly 32 bytes). Any item that
  cannot be read so, including a truncated item, an indefinite-length item and invalid UTF-8, is `Malformed`. A
  non-shortest integer or length is read by its value here and refused only at D6.
* **D3** no byte follows item 14 (`Malformed`).
* **D4** the class equals the class the phase requires (`ClassPhaseMismatch`).
* **D5** generation and items 11 to 14 are non-zero (`ZeroField`).
* **D6** the decoded value re-encodes to the identical bytes (`NonCanonical`: a non-shortest integer or length).

Tests: `challenge_codec_is_strict_and_canonical`, the codec negatives of the preimage vectors
(`truncated_challenge`, `extended_challenge`, `non_canonical_integer_version`, `indefinite_length_array`,
`profile_as_byte_string`, `other_network`, `class_phase_mismatch`, `zero_nonce`) and the multi-defect probes of the
V2 additions (`class_phase_mismatch_and_truncated` and nine others).

## 4. Signatures: intent, the two components and the serialization

* **Intent.** Both components sign the same 64 bytes: `intent = SHA-512(domain || 0x00 || challenge)`, with the
  42-byte domain literal, one zero byte and the challenge bytes, no length prefix and no other framing (A.3).
* **Ed448** is pure RFC 8032 Ed448 (phflag 0) with an **empty context** over the 64-byte intent: 57-byte public
  key, 114-byte signature `R || S`. The public key and `R` must decode to curve points that are **not of order 1, 2 or
  4** (the key check refuses `A` when `[4]A` is the identity; it decodes through the 4-isogeny and refuses a point it
  maps to the identity). Added after the independent reproduction (S3, corrected in round 3): under textbook RFC 8032
  (section 5.2.3 decoding, section 5.2.7 check) `R = [s]B, S = s` verifies for every message under ALL FOUR keys of
  order 1, 2 and 4, because `[4]A` is the identity; OpenSSL 3.5.7 and the vendored verifier already refuse the order-2
  and identity encodings at decoding, so they accept it under the two order-4 keys only. The rule refuses all four:
  this implementation refuses such a key when the descriptor is decoded (`DescriptorInvalid`), with public vectors in
  the V2 additions (A.4,
  `ed448_small_order_keys_are_forgeable_under_rfc8032_and_refused_by_this_port`,
  `proof_additions_v2_small_order_keys_and_multi_defect_probes_hold`).
* **FN-DSA-1024** signs the 64-byte intent as a **raw message** (hash identifier `0x00`) with an **empty context**:
  1,793-byte public key (header `0x0a`), 1,280-byte signature (header `0x3a`, then the 40-byte nonce); the message
  representative is `mu = SHAKE256(SHAKE256(public_key, 64) || 0x00 || 0x00 || intent, 64)` (A.5). The profile
  `MUTINY-FNDSA1024-PORNIN-20260722-V1` is Thomas Pornin's 22 July 2026 implementation of an unpublished FN-DSA
  draft (source commits in A.5); it is **not** FIPS 206 final, and an independent verifier must implement exactly
  this variant.
* **Serialization** (the proof's signature file and every vector): `ed448 (114 bytes) || fndsa (1280 bytes)` =
  1,394 bytes, no header, no length prefix, fixed order; any other length is `Malformed` (A.6).

The preimage vectors pin each statement against the vendored sources: a non-empty Ed448 context, Ed448ph, a
non-empty FN-DSA context and the FN-DSA pre-hash framing all fail, and FN-DSA verification over `mu` itself
(external-mu mode) succeeds (`preimage_vectors_are_exact_and_reproducible_from_the_committed_v1_vectors`).

## 5. Descriptor, AddressID and Treasury record

* The **descriptor** is the canonical CBOR of the wallet-owner public key at a generation (`PublicKey::descriptor`):
  a definite array of 9 items `[1, NETWORK u32, role u8 (WalletOwner = 1), generation u64, suite u16, policy u8,
  profile text, ed448 bytes(57), fndsa bytes(1793)]`; decoding is strict (at most 2,048 bytes, version 1, the network,
  suite 1, policy 1 and the profile pinned, both public keys valid (section 4 and header `0x0a`), no trailing bytes,
  re-encoding must match); any failure is `DescriptorInvalid`, a decodable non-WalletOwner role is `WrongRole`.
  Normative (round 3): `WrongRole` is returned only when the WHOLE descriptor decodes and validates with a role other
  than WalletOwner; a descriptor with a non-WalletOwner role AND any other invalid field, and an unknown role byte,
  are `DescriptorInvalid`. "Both public keys valid": the Ed448 key as in section 4; the FN-DSA key is exactly 1,793
  bytes with header byte `0x0a` AND every one of its 1,024 14-bit coefficients below q = 12289 (the vendored
  `VerifyingKey1024::decode` refuses any coefficient >= q).
  Example split: A.8. `descriptor_sha256 = SHA-256(descriptor)`.
* **AddressID** `= SHA-256("MUTINY-BUILD8-HYBRID-ADDRESS-V1" || 0x00 || descriptor)` (A.9). Item 10 is the AddressID of
  the proven descriptor at its generation; item 11 is the **generation-one** AddressID of the Treasury (the Treasury
  authority).
* The **Treasury record** (`consensus::treasury_v1::Treasury::encode`) is the CBOR array `[2, 60, class,
  descriptor]` with the generation-one descriptor as a byte string and the class byte 1 (PRODUCTION) or 2
  (TEST-VALUE); `treasury_record_sha256 = SHA-256(record)` (A.10). The class byte is inside the hashed record, so a
  TEST-VALUE record never has the hash of a PRODUCTION record of the same descriptor.

## 6. Ceremony context (item 13)

### 6.1 Rehearsal derivation (implemented)

`ceremony_context = SHA-256("MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1" || 0x00 || label)`, where `label` is 4 to
64 bytes and every byte is an ASCII graphic character `0x21..0x7E` (no space, no control character, no non-ASCII
byte); any other label is refused (`Codec`). Exported in A.11; tested by
`the_rehearsal_context_derivation_is_exactly_the_documented_one`. A label may contain `"` and `\`; every JSON
output escapes it (`r6_a_label_with_a_quote_or_backslash_cannot_change_the_manifest_json`).

### 6.2 Production construction: OPEN DEFINITION (needs Architect confirmation)

No locked text defines the production ceremony context. The procedure draft
(`docs/d2-treasury-ceremony/TREASURY-OFFLINE-CEREMONY-PROCEDURE-D2.md`, section 5.2) binds only a ceremony nonce,
and the proposed answers (`D2-OPEN-QUESTIONS-PROPOSED-ANSWERS.md`, Q8 and section 3) mention "a public
ceremony/candidate identifier" without bytes. This document therefore defines **no production bytes**.

Interface. A production ceremony context MUST be a non-zero 32-byte value, fixed before the descriptor is frozen,
supplied to the verifier by trusted, Architect-approved ceremony configuration, never equal to (and never derived
from) a GenesisID, and it MUST bind: the network (`0x4d555401`); the phase and class (2 / PRODUCTION); the Treasury
identity (generation-one AddressID) and the exact descriptor being proven (SHA-256); the identity of the Genesis
Parameters or rule manifest the ceremony serves (proposed: the protocol fingerprint of the rule manifest, which does
not contain the Treasury record); the identity of the approved ceremony configuration; and the ceremony instance
that scopes its nonces (a fresh public random value, the nonce domain).

PROPOSED derivation (not implemented; for the Architect's decision):
`SHA-256("MUTINY-BUILD8-TREASURY-PRODUCTION-CONTEXT-V1" || 0x00 || ProductionContextV1)` where `ProductionContextV1`
is the canonical CBOR definite array `[1, network u32, phase u8 (2), class u8 (1), treasury_authority bstr32,
descriptor_sha256 bstr32, rule_manifest_fingerprint bstr32, ceremony_configuration_sha256 bstr32,
ceremony_instance bstr32]` and `ceremony_configuration_sha256` is computed over the configuration without the context
value itself. The domain literal is not registered in `spec/DOMAIN-REGISTRY-V1.json` because no code uses it.
Trade-off for the Architect: binding the Genesis Parameters hash instead of the rule-manifest fingerprint would tie
the proof to every Genesis parameter, so any later change of an unrelated parameter would need a new production
signing session; the approved-manifest comparison (section 7.5) already covers those parameters.

Implemented: only the checking side. `ExpectedContext::production_supplied` holds the configured value (zero refused),
`CeremonyConfig::new` accepts it only with a PRODUCTION-class record, and `check_ceremony_context` accepts exactly
the configured value with a production-phase challenge and refuses another value (`WrongContext`), the other phase
(`WrongPhase`) and a value equal to a known GenesisID (`ContextIsGenesisId`)
(`production_context_checking_side_compares_only_the_configured_value_and_never_a_genesis_id`). Every production
proof stays refused (`ProductionRefused`) while production is unqualified.

### 6.3 Never a GenesisID

The rehearsal context is a label hash under its own domain and is fixed before Genesis. After the freeze,
`verify_frozen` recomputes the GenesisID of a full Genesis descriptor and refuses a context equal to it
(`ContextIsGenesisId`).

## 7. Verification

### 7.0 Normative evaluation order (added after the independent reproduction, S5)

For inputs with more than one defect, the FIRST failing step decides the refusal:

1. **Input stage.** I1: the strict challenge decode, D1 to D6 (section 3). I2: the signature serialization, exactly
   1,394 bytes (`Malformed`, A.6). I2 comes before every verification step, so a production-phase challenge with a
   114-byte signature is `Malformed`, not `ProductionRefused`.
2. **Cryptographic layer** (`Challenge::verify`, 7.1): V1 to V6.
3. **Ceremony layer** (`verify_proof`, 7.2): C1 to C9; the ceremony layer runs I1 and I2 first and calls the
   cryptographic checks at C8 and C9.

Normative clarifications (round 3, verified against the code):

* **Wrapping.** Every decoder refusal D1 to D6 and the serialization refusal I2 reach the ceremony layer wrapped in
  `Proof`: `Proof(Malformed)`, `Proof(ClassPhaseMismatch)`, `Proof(ZeroField)`, `Proof(NonCanonical)`. The only
  unwrapped cryptographic refusal is `ProductionRefused`. Vector: `generation_one_proof_with_class_1` (P1 with class
  byte 1) is `REJECT Proof(ClassPhaseMismatch)`.
* **Expectation first.** The expectation (`Expect`, built from trusted configuration, lineage records or the plan) is
  established BEFORE the proof is examined. If it cannot be established, its refusal is the result whatever the
  proof contains: fabricated lineage records with a malformed proof are `SuccessionUnproven`, not `Proof(Malformed)`.
  The public tool also builds the expectation before reading the proof files.
* **Vector detail.** The `flip_fndsa_bit` change of `ceremony_order_probes` XORs `0x01` into byte 100 of the FN-DSA
  signature, which is byte 214 of the 1,394-byte serialization.

Public vectors: `multi_defect_probes` of the V2 proof additions (for example
`class_phase_mismatch_and_truncated`, `production_phase_with_an_ed448_only_signature`) and `ceremony_order_probes` of
the V2 ceremony additions (for example `impostor_with_a_bad_signature`); test
`multi_defect_inputs_are_refused_in_the_normative_order`.

### 7.1 Cryptographic layer (`crypto-v2`, `Challenge::verify`)

1. **V1** A production phase is refused (`ProductionRefused`) while `PRODUCTION_SECURITY_QUALIFIED` is false; the
   signer refuses it too (`production_proofs_cannot_be_signed_or_accepted_while_unqualified`).
2. **V2** The presented descriptor decodes as a WalletOwner descriptor (section 5: `DescriptorInvalid`, `WrongRole`);
   the descriptor decoder pins suite, policy and profile and validates both keys, before any challenge item is
   compared.
3. **V3** Its generation equals item 5 (`WrongKeyVersion`). **V4** Items 6 to 8 equal the suite, policy and profile
   (`WrongProfile`). **V5** `SHA-256(descriptor)` equals item 9 and its AddressID equals item 10
   (`AlteredDescriptor`).
4. **V6** Both components verify over the intent under the descriptor's key (`BadSignature`). The signer also
   refuses a key that does not hold the descriptor (`WrongSigner`).

This layer proves that the holder of the descriptor's key signed this challenge. It says nothing about which
Treasury, ceremony or successor is expected: an impostor's proof passes it (ceremony vector
`reject_impostor_successor_rotation_plan` has crypto verdict `VALID`).

### 7.2 Ceremony layer: expected values from trusted configuration (`consensus`, `verify_proof`)

The verifier never takes an expected value from the proof. `CeremonyConfig` holds the trusted inputs; `Expect` adds
the generation and the exact descriptor of that generation and has no constructor that takes a descriptor from a
proof. Order: decode, production refusal, class, network, phase and context, generation, Treasury binding, expected
descriptor, the cryptographic layer. A proof whose own fields are consistent but differ from the expectation is
refused:

| Expected value | Trusted source | Refusal | Tests |
|---|---|---|---|
| Network | configuration (must be `0x4d555401`; the decoder admits no other) | `WrongNetwork`; `Malformed` in the payload | `internally_consistent_proofs_that_differ_from_the_trusted_expectation_are_refused` |
| Phase and class | context kind (rehearsal or production) and the Treasury record's class byte; they must agree | `ProductionRefused`, `ClassMismatch` | same; `library_controls_cover_every_rejection_reason_and_cannot_emit_production` |
| Ceremony context | label derivation (6.1) or the configured production value (6.2) | `WrongContext`, `WrongPhase` | same; `production_context_checking_side_compares_only_the_configured_value_and_never_a_genesis_id`; ceremony vector `reject_wrong_context` |
| Treasury identity | the trusted generation-one Treasury record: authority (item 11) and record hash (item 12) | `TreasuryMismatch` | ceremony vectors `reject_wrong_treasury_authority`, `reject_wrong_class_record` |
| Generation | the record (1), canonical lineage or the authorized rotation plan (2) | `Proof(WrongKeyVersion)` | ceremony vectors `reject_wrong_generation_one_under_plan`, `reject_wrong_generation_two_as_one` |
| Exact descriptor | generation 1: the record's own descriptor; generation 2 or later: section 7.3 | `AlteredDescriptor` (generation 1), `UnauthorizedSuccessor` (later) | ceremony vectors `reject_wrong_descriptor`, `reject_impostor_successor_rotation_plan` |

Order labels used by 7.0: C1 production refusal, C2 class, C3 network, C4 phase and context, C5 generation, C6
Treasury binding, C7 expected descriptor, C8 the descriptor checks V2 to V5, C9 the signatures V6.

**Trusted configuration items added after the independent review (F1-F3, F5)** and the independent reproduction
(S1, S4). They are part of `CeremonyConfig` (or of the approved manifest), never read from a proof, a plan file or a
state export, and an expectation that needs a missing item establishes nothing (`SuccessionUnproven`):

| Trusted item | Used by | Refusal | Vectors and tests |
|---|---|---|---|
| Trusted chain identity: network, genesis, fingerprint | rotation plan (7.3) | `WrongChain`; a configuration for another network: `WrongNetwork` | `reject_plan_of_another_chain_identity`, `reject_plan_when_the_trusted_chain_is_another`; `r2_only_the_pinned_plan_on_the_trusted_chain_at_the_trusted_height_establishes_a_successor` |
| Trusted height | rotation plan (7.3) | `PlanOutOfWindow` | `reject_plan_expired_at_the_trusted_height`, `reject_plan_before_its_creation_height` |
| Pinned plan identity (`Rotation::identity`) | rotation plan (7.3) | `PlanNotAuthorized` | `reject_second_validly_signed_plan_not_pinned` |
| Canonical StateRoot | canonical lineage (7.3) | `SuccessionUnproven` | `reject_fabricated_lineage_records`; `r1_a_fabricated_lineage_does_not_reproduce_the_trusted_state_root` |
| Approved GenesisID (approved manifest) | post-freeze check of a Genesis descriptor (7.5) | `GenesisIdNotApproved`, `ManifestMismatch` | `genesis.verdicts` of the V2 ceremony additions |
| Admission store id (approved manifest) | post-freeze check (7.4, 7.5) | `WrongStore` | `r5_a_replay_into_a_second_store_cannot_pass_the_approved_store` |

The V1 ceremony vectors took the chain identity from the plan itself; the V2 ceremony additions state the trusted
chain (`trusted_configuration_additions`), and the V1 `rotation_plan` and `canonical_lineage` expectations are those
inputs (the V1 verdicts are unchanged).

### 7.3 Succession: canonical lineage or the exact authorized rotation plan

A generation-two key that signs the Treasury's public identifiers (authority and record hash are public) proves
nothing about succession. A generation N >= 2 descriptor is accepted only when it is one of the following.

**Canonical lineage** (`Expect::canonical_current`, input: canonical state RECORDS plus the trusted StateRoot). The
records must reproduce the trusted StateRoot under the repository's canonical state decoder (`State::from_records`:
the state-tree root of the records first, then typed records and the canonical round trip); a state that carries a
Treasury record must carry exactly the trusted one; the expected descriptor is the CURRENT descriptor of the Treasury
authority (wallet record kind 30). Only the current key proves control; a retired generation is
`Proof(WrongKeyVersion)`. Anything else is `SuccessionUnproven`. The root, the record encodings and the lineage
example:

<!-- BEGIN GENERATED: lineage-state -->
```text
domain_hash(d, b) = SHA-256(d || 0x00 || b)
leaf(key, record) = domain_hash("MUTINY-BUILD8-STATE-LEAF-V2", CBOR [2, key bstr32, record bstr])
branch(l, r)      = domain_hash("MUTINY-BUILD8-STATE-BRANCH-V2", l || r)
empty[256] = domain_hash("MUTINY-BUILD8-STATE-EMPTY-V2", empty); empty[d] = branch(empty[d+1], empty[d+1])
subtree(records, d): none -> empty[d]; one record (k, v) -> leaf(k, v) lifted from depth 256 to d with
  the empty[] siblings; otherwise split by bit d of the key (bit 0 = most significant bit of byte 0;
  0 = left) and branch(subtree(left, d+1), subtree(right, d+1))
StateRoot = domain_hash("MUTINY-BUILD8-STATE-V2", CBOR [2, count u64, subtree(records, 0) bstr32]); records strictly increasing by key
wallet records: key domain_hash("MUTINY-BUILD8-WALLET-AUTHORITY-STATE-V1", authority) -> CBOR [1, 30, authority bstr32, current descriptor bstr]
                key domain_hash("MUTINY-BUILD8-WALLET-ADDRESS-STATE-V1", AddressID) -> CBOR [1, 31, authority bstr32, descriptor of that AddressID bstr]
```

Example (`canonical_lineage` of `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json`): K1 registered, then the plan K1 -> K2 applied.

| Key | Record kind | Record bytes | Record SHA-256 |
|---|---|---|---|
| `849300a9d37a4b06f558bf731e3359538283575abcb9b2e026b5adedb0ee09f4` | 31 | 1944 | `3ac4dd422d723f541dd664c038355753b813dd268c902a570dd6b1fa542f4e14` |
| `b9b9c5bb795dd2b203ed919afe71eccf9015f49564774ef52f853a0347a7b4ee` | 31 | 1944 | `6fa4983c6b5f15c1c8ac80a94fd34e7da9be2f59e8c1aec389d5c9af2a423582` |
| `f315247881548550f5978617e11f8ed968691d1f4871095983c20d27db254932` | 30 | 1944 | `f3735cd6c92e307dc6a753c931ca350d1066abfb85453da2c39778e7219471dc` |

```text
StateRoot of these 3 records (the trusted canonical_state_root) = 3236b2c4554bb368333b6960d0eda3b5a0a2ffe8417ededdd5eb129b61205d8e
the fabricated records (K3 current, no K1 signature) give      19771356c67a40bee297ba95c71379cd7c39b582c648f8c02cb3f4ea4a32628f
```
<!-- END GENERATED: lineage-state -->

**Exact rotation plan** (`Expect::authorized_rotation`, inputs: the plan bytes plus the trusted chain, trusted height
and pinned identity). In this order:

1. The plan's unsigned body is well formed (A.12): version 1; the protocol network; non-zero genesis, fingerprint and
   authority; `current` and `proposed` are WalletOwner descriptors with **generation(proposed) = generation(current) +
   1**, different Ed448 and different FN-DSA keys; `0 <= expiry_height - created_height <= 10080`. Its identity
   `SHA-256("MUTINY-BUILD8-WALLET-ROTATION-ID-V1" || 0x00 || unsigned body)` equals the pinned identity
   (`PlanNotAuthorized`). Order within this step: the body is checked first, because the identity is defined only for
   a well-formed body; a malformed body is `SuccessionUnproven` whatever the pinned identity, and `PlanNotAuthorized`
   applies only to a well-formed body with another identity.
2. Its network, genesis and fingerprint equal the trusted chain (`WrongChain`).
3. Its authority is the Treasury authority and its `current` is the record's generation-one descriptor
   (`SuccessionUnproven`).
4. The trusted height `h` satisfies `created_height <= h <= expiry_height` (`PlanOutOfWindow`). This replaces the
   former "checked at its own creation height": the height is the trusted configuration's, never the plan's.
5. The authorization by the current key under `MUTINY-BUILD8-WALLET-KEY-ROTATE-V1` and the possession by the proposed
   key under `MUTINY-BUILD8-WALLET-KEY-ROTATE-POSSESSION-V1` both verify over the unsigned body
   (`SuccessionUnproven`).

The proposed descriptor is then the expected descriptor. The plan's canonical inclusion is not established here; that
is what the canonical-lineage path proves. Any other generation-two descriptor is `UnauthorizedSuccessor`. Tests:
`an_impostor_successor_is_refused_under_the_rotation_plan_and_under_canonical_lineage`,
`r1_a_fabricated_lineage_does_not_reproduce_the_trusted_state_root`,
`r2_only_the_pinned_plan_on_the_trusted_chain_at_the_trusted_height_establishes_a_successor`, the real-block harness
`treasury_rotation_rehearsal_gen1_to_gen2_with_preserved_reserves_restart_and_retry` (feature
`dividend-test-fixtures`), the ceremony vectors `reject_impostor_successor_rotation_plan` and
`reject_impostor_successor_canonical_lineage`, and `succession_cases` of the V2 ceremony additions
(`ceremony_additions_v2_state_the_trusted_succession_inputs_and_every_verdict_holds`).

### 7.4 Nonce: first admission consumes it durably in an identified store; audits consume nothing

* `verify_proof` is read-only.
* **Store.** `create-store` (`AdmissionStore::create`) creates a new SQLite file bound to one ceremony (context and
  Treasury record hash) with a random 32-byte **store id**; an existing file is never reused and an admission never
  creates a missing store. Every open validates the exact schema (object names and SQL) and the binding, and reads
  back the connection settings: writable connections run `journal_mode=DELETE` and `synchronous=EXTRA` (EXTRA also
  syncs the directory after the rollback journal is deleted), read-only connections are `query_only` and reported
  read-only by SQLite; anything else is refused (`stores_run_synchronous_extra_and_audit_stores_are_read_only_at_the_sqlite_level`).
* **First admission** (`AdmissionStore::admit`): after the full verification the proof (challenge, descriptor,
  signature) is recorded in one `IMMEDIATE` transaction keyed by the nonce. The nonce is consumed if and only if that
  transaction commits; any refusal leaves the store file byte-identical; a second admission of a used nonce,
  including a different valid proof carrying it and including after a restart in another process, is `Replay`;
  concurrent admissions of one nonce admit exactly once; a damaged row is refused on read (`Store`).
* **Audits** (`audit_recorded`, `build_manifest`, `verify_frozen`) take the store by shared reference and write
  nothing; the public tool opens the store read-only for them. They accept only the **recorded** bytes
  (`NotAdmitted` otherwise, also for a fresh, equally valid signature over the same challenge); repeated audits leave
  the store byte-identical.
* Tests: `first_admission_consumes_the_nonce_durably_and_audits_are_read_only_and_repeatable`,
  `concurrent_admissions_of_one_nonce_admit_exactly_once`,
  `a_restart_in_separate_processes_keeps_the_nonce_consumed_and_audits_read_only`,
  `a_damaged_admission_row_is_refused_on_read`, `r7_admit_and_audit_refuse_an_expectation_of_another_ceremony_on_an_open_store`,
  `r8_empty_truncated_and_junk_store_files_fail_closed`,
  `a_failure_between_insert_and_commit_admits_nothing_and_consumes_no_nonce`,
  `operator_flow_end_to_end_with_negative_controls_admission_and_class_safety` and the sequences `nonce_replay` and
  `repeatable_audit` of the ceremony vectors.
* **Stated limits (not closed).** Replay protection is RELATIVE TO THE IDENTIFIED STORE. A party who can create a
  fresh store for the same ceremony can admit a replayed proof into THAT store; it is not prevented. Such a store has
  another id, and deleting and re-creating a store also produces a new id, so `verify_frozen` against an approved
  manifest that names the original store refuses it (`WrongStore`,
  `r5_a_replay_into_a_second_store_cannot_pass_the_approved_store`). A party with write access to the file can
  delete records or substitute the file; custody of the verifier machine and its storage is a procedural ceremony
  control. Keep the `-journal` sidecar file with the store (after a crash it is the rollback record of an
  uncommitted admission). On Windows the SQLite VFS ignores the directory-sync request of `synchronous=EXTRA`;
  whether NTFS persists the journal deletion across power loss without it is not established here.
* **OPEN QUESTION for the Architect (review F11, not implemented):** issued nonces are not recorded, so a proof
  signed in advance over any fresh nonce is admissible. Should admission accept only nonces the verifier issued and
  recorded in the store? Trade-off: it closes pre-signed proofs and makes the store the issuing authority, but adds a
  write before signing (an issued-nonce table with its own expiry and replay rules) and ties signing sessions to one
  verifier store.

### 7.5 After the freeze: approved manifest; key control only

The input of `verify_frozen` (read-only, repeatable) is EITHER the frozen Genesis Parameters bytes OR a full Genesis
descriptor (layouts and GenesisID derivation below). The approved manifest is supplied independently and is pinned
by its SHA-256 (the public tool requires `--approved-manifest-sha256`; this is a procedural control: the pin says
which file was approved). Rewritten after the independent reproduction (S2) and the review (F3); in this order:

1. The expectation is generation one (`Proof(WrongKeyVersion)`); the challenge decodes (a `Proof` refusal otherwise) and is not
   production (`ProductionRefused`).
2. The frozen input decodes (`Codec`); for a Genesis descriptor its GenesisID is recomputed.
3. **A Genesis descriptor requires an approval that names the GenesisID** (`GenesisIdNotApproved`). An approval for
   Parameters bytes names no GenesisID.
4. The Treasury extracted from the frozen Parameters is exactly the trusted Treasury (`FrozenMismatch`; Parameters
   without a Treasury too).
5. The frozen bytes equal the approved manifest: class, descriptor hash, record hash, SHA-256 of the exact Parameters
   bytes, and, when the approval names a GenesisID, the recomputed GenesisID (`ManifestMismatch`). An approval that
   names a GenesisID cannot be satisfied by Parameters bytes alone (`ManifestMismatch`). With a Genesis descriptor
   every Genesis field is covered, because the GenesisID hashes the whole descriptor.
6. The store carries the store id the approved manifest names (`WrongStore`). The store id is a mandatory field of
   the approved manifest (`ApprovedManifest::admission_store_id` has no absent value); the public tool refuses an
   approval JSON without `admission_store_id` before any comparison (usage refusal, exit 2), so `WrongStore` never
   arises from a missing id.
7. The ceremony context is the expected one and not the recomputed GenesisID (`WrongContext`, `ContextIsGenesisId`).
8. The proof is the one recorded at admission and still verifies (`NotAdmitted`, then 7.2).

The proof establishes Treasury **key control**; it is not approval of any other Genesis parameter: a frozen Genesis
that differs only in another parameter carries the same Treasury record and the same valid proof and is refused by
the manifest comparison alone (`the_frozen_genesis_is_compared_with_the_independently_approved_manifest`). In the V1
ceremony vectors, `genesis_id_for_genesis_descriptor_input` applies only to the `genesis_descriptor` step; the full
verdict table is `genesis.verdicts` of the V2 ceremony additions.

<!-- BEGIN GENERATED: genesis-derivation -->
```text
Parameters (version 3) = CBOR [1, 3, initial_target bstr32, rules bstr, Treasury record bstr]   (version 2: [1, 2, initial_target, rules], no Treasury)
rules = CBOR [1, network u32, [[name bstr, hash bstr32], ...]]   (names ASCII graphic, strictly increasing)
rule fingerprint = SHA-256("MUTINY-BUILD8-PROTOCOL-FINGERPRINT-V1" || 0x00 || rules)
GenesisDescriptor = CBOR [1, network u32, timestamp u64, nonce bstr32, fingerprint bstr32, owner bstr32,
                          purchase bstr32, Parameters bstr, admission_records [bstr, ...] (strictly increasing), recovery bstr32]
GenesisID = SHA-256("MUTINY-BUILD8-GENESIS-ID-V1" || 0x00 || GenesisDescriptor)
```

Example: the frozen inputs of the ceremony vectors (`frozen` of `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json`, repeated in `genesis` of `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json`).

| # | Parameters item | Offset | Length | CBOR initial bytes | Value |
|---|---|---|---|---|---|
| 1 | `version` | 1 | 1 | `01` | 1 |
| 2 | `parameters_version` | 2 | 1 | `03` | 3 |
| 3 | `initial_target` | 3 | 34 | `5820` | `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` |
| 4 | `rules` | 37 | 82 | `5850` | 80 bytes, SHA-256 `3fb3d0e08431f6cdadb416b06af43cc48dc4b5784b99d0dba64908fb632c1928`; fingerprint `5822a70ac8b353a5f02acfca71f82996ad0a89796ab3d5b2c2fe15a4638ee585` |
| 5 | `treasury_record` | 119 | 1914 | `590777` | 1911 bytes, SHA-256 `034fef8d8e95a7155a73d785a18fe54dec4000e6ac62d3620f28d3e6f4ee3fd1` (A.10) |

Parameters: 2033 bytes, parameters_sha256 = `ec52373dd5dbaa5fad3716f974af310ef501058390df27d91ced5c55c67bb935`

| # | GenesisDescriptor item | Offset | Length | CBOR initial bytes | Value |
|---|---|---|---|---|---|
| 1 | `version` | 1 | 1 | `01` | 1 |
| 2 | `network` | 2 | 5 | `1a4d555401` | 1297437697 |
| 3 | `timestamp` | 7 | 1 | `01` | 1 |
| 4 | `nonce` | 8 | 34 | `5820` | `9caffa2277d9530150f85957606edfc20bbf6dd3d63c97ce7dfc5d44e41c2d6e` |
| 5 | `fingerprint` | 42 | 34 | `5820` | `5822a70ac8b353a5f02acfca71f82996ad0a89796ab3d5b2c2fe15a4638ee585` (the rule fingerprint) |
| 6 | `owner` | 76 | 34 | `5820` | `53048b3df832ddedff1a8f8729c49a2eb2d8fc6c46aac78ca576085c74f470aa` |
| 7 | `purchase` | 110 | 34 | `5820` | `df59c527dff2f1954ec75d47c77a68da9e06f1374187fb45f342a551eef2e3db` |
| 8 | `parameters` | 144 | 2036 | `5907f1` | the Parameters above (2033 bytes) |
| 9 | `admission_records` | 2180 | 1 | `80` | [] |
| 10 | `recovery` | 2181 | 34 | `5820` | `8dd0aabb179a8d4047763c13615470e2dd99fee9a0d078de9139d9818ff5a8cd` |

```text
GenesisDescriptor: 2215 bytes; SHA-256(GenesisDescriptor) = f46ad18b7e7569e5f9514b4ac907e2af3f9839ec59da1be2746626d64c660b42 (NOT the GenesisID)
GenesisID preimage = "MUTINY-BUILD8-GENESIS-ID-V1" || 0x00 || GenesisDescriptor (2243 bytes)
GenesisID = 7212958b853f0217b4fa01a39df61e1dcbce0700584ced9f23863251ac4bbe4e
```
<!-- END GENERATED: genesis-derivation -->

### 7.6 Refusal names (S7)

Names are kept (vectors carry them); their meaning:

| Name | Layer | Meaning |
|---|---|---|
| `AlteredDescriptor` | ceremony, generation 1 | the presented descriptor is not the trusted record's descriptor |
| `Proof(AlteredDescriptor)` | cryptographic (V5) | the presented descriptor's SHA-256 or AddressID is not challenge item 9 or 10 |
| `UnauthorizedSuccessor` | ceremony, generation 2 or later | the presented descriptor is not the successor established by 7.3 |
| `Proof(WrongKeyVersion)` | ceremony (C5) or cryptographic (V3) | the challenge's generation is not the expected generation, or not the descriptor's |
| `SuccessionUnproven` | ceremony | the lineage or plan establishes no successor, or the trusted configuration lacks the item it needs |
| `Proof(Malformed)` | input stage | the challenge or the signature serialization does not decode (D1 to D3, I2) |

## 8. Public TEST-VALUE examples

A.13 gives the complete V1 example (vector `d2-vector-k1`: challenge, intent, preimage, both signatures' lengths and
the computed verdict) and A.14 a ceremony example. Note on the V1 codec vectors: their items 12 (record hash), 13
(context) and 14 (nonce), and item 11 of `d2-vector-k2`, are SHA-256 of the ASCII tags `vector-treasury-record`,
`vector-ceremony-context`, `vector-nonce-1`, `vector-nonce-2` and `vector-treasury-authority`, not the derivations of
sections 5 and 6. The V1 vectors test the codec and both signatures, not a ceremony; `d2-vector-k2` is not an
authorized succession. The ceremony vectors use the specified derivations.

## 9. Vectors

| File | Content | Generator and check |
|---|---|---|
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json` | V1 codec and signature vectors: `d2-vector-k1` (generation 1), `d2-vector-k2` (generation 2), each with a flipped-challenge negative; unchanged | crypto-v2 `committed_public_vectors_verify_and_negative_vectors_fail` (`BUILD8_TREASURY_PROOF_VECTORS=<path>`) |
| `qualification/TREASURY-PROOF-OF-CONTROL-PREIMAGE-VECTORS-V1.json` | deterministic: per V1 vector the item split of challenge and descriptor, the intent preimage, the Ed448 dom4/R/S and the FN-DSA hashed key, mu input and mu; 18 negatives (codec, signature codec, signature, descriptor); unchanged | crypto-v2 `preimage_vectors_are_exact_and_reproducible_from_the_committed_v1_vectors` (`BUILD8_TREASURY_PREIMAGE_VECTORS=<path>`; regeneration is byte-identical) |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json` | keys K1 (Treasury), K2 (authorized successor), K3 (impostor), S (stranger); trusted configuration; rotation plan; 10 proofs; 12 cases with crypto and ceremony verdicts; sequences `nonce_replay` and `repeatable_audit`; unchanged | consensus `ceremony_vectors_are_complete_reproducible_and_every_verdict_holds` (`BUILD8_TREASURY_CEREMONY_VECTORS=<path>`; FN-DSA signatures are randomized, so regeneration changes only the signatures and the encoded plan) |
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json` | added (S3, S5): the four Ed448 keys of order 1, 2 and 4 in proofs with a forged Ed448 half and a valid FN-DSA half (all `DescriptorInvalid`), an honest control, and ten `multi_defect_probes` with their first refusal and rule | crypto-v2 `proof_additions_v2_small_order_keys_and_multi_defect_probes_hold` (`BUILD8_TREASURY_PROOF_ADDITIONS=<path>`; only `fndsa_signatures` are randomized) |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json` | added (F1-F3, F5; S1, S2, S4, S5, S6): trusted chain, height, pinned plan identity and canonical StateRoot; three plans; lineage records and fabricated records; 14 `succession_cases`; Parameters and Genesis items, GenesisID and 8 post-freeze verdicts; 7 `ceremony_order_probes` | consensus `ceremony_additions_v2_state_the_trusted_succession_inputs_and_every_verdict_holds` (`BUILD8_TREASURY_CEREMONY_ADDITIONS=<path>`; only `signed_plans` are randomized) |

## 10. Mechanical comparison

`consensus/tests/treasury_schema_conformance_v1.rs` regenerates every generated block from the public API
(`Domain::bytes`, `PROFILE`, `NETWORK`, `WALLET_CRYPTO_SUITE_ID`, `BOTH_REQUIRED_POLICY_ID`, the
`treasury_proof_v1` constants, `Challenge`, `PublicKey`, `Treasury::encode`, `ceremony_context`, `Rotation`,
`GenesisDescriptor`, `Parameters`, `state_root`), from the exact source lines of A.2 (each must occur in its file),
from the encoder and decoder call sequences of `treasury_proof_v1.rs` and from the five committed vector files, and
requires byte equality with this document and with the reproduction input list. It also checks: every test named
here exists, carries `#[test]`, is not ignored and, when its file is feature-gated, its feature is named here; the
domain registry entries (`spec/DOMAIN-REGISTRY-V1.json`); the reproduction-input prose and the tooling status
paragraph (hashed in section 14); and that no document claims a completed reproduction or a qualification while
`qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-RESULT-V1.md` does not exist. Its perturbation test changes
one byte of this document, of each vector file, of a constant and of a pinned source line and requires a reported
difference each time (`one_changed_byte_of_the_document_a_vector_a_constant_or_a_source_line_is_detected`).

## 11. Approval status and open items

* Approved by the Architect (order section 7): the items listed in the status line.
* Open: the production ceremony context construction (6.2); nonce freshness, review F11 (7.4); the independent
  reproduction of the V2 additions (pending, Cipher; `qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-INPUTS.md`);
  the FN-DSA profile is an unpublished draft variant; a rotation-plan export for operators of the public tool;
  directory durability of SQLite on Windows (7.4).
* Not changed by this document: production proofs stay refused; the manifest builder accepts only TEST-VALUE.

## 12. Appendix A: exact definitions (generated)

<!-- BEGIN GENERATED: appendix-a -->
Exported from the source lines of A.2 and from the committed vector files; every value below was recomputed or verified while this block was generated.

### A.1 Literals

| Literal | Bytes | Length | Hex |
|---|---|---|---|
| Proof domain | `MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1` | 42 | `4d5554494e592d4255494c44382d54524541535552592d50524f4f462d4f462d434f4e54524f4c2d5631` |
| Separator | one zero byte | 1 | `00` |
| FN-DSA profile | `MUTINY-FNDSA1024-PORNIN-20260722-V1` | 35 | `4d5554494e592d464e445341313032342d504f524e494e2d32303236303732322d5631` |
| AddressID prefix | `MUTINY-BUILD8-HYBRID-ADDRESS-V1` | 31 | `4d5554494e592d4255494c44382d4859425249442d414444524553532d5631` |
| Rehearsal context domain | `MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1` | 43 | `4d5554494e592d4255494c44382d54524541535552592d52454845415253414c2d434f4e544558542d5631` |
| Ed448 dom4 (phflag 0, empty context) | `SigEd448`, then `00` `00` | 10 | `53696745643434380000` |
| Rotation authorization domain | `MUTINY-BUILD8-WALLET-KEY-ROTATE-V1` | 34 | `4d5554494e592d4255494c44382d57414c4c45542d4b45592d524f544154452d5631` |
| Rotation possession domain | `MUTINY-BUILD8-WALLET-KEY-ROTATE-POSSESSION-V1` | 45 | `4d5554494e592d4255494c44382d57414c4c45542d4b45592d524f544154452d504f5353455353494f4e2d5631` |

### A.2 Source lines (each occurs, trimmed, in the named file)

```text
crypto-v2/src/lib.rs [proof domain literal]
    Self::TreasuryProofOfControl => b"MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1",
crypto-v2/src/lib.rs [domain role: WalletOwner]
    | Self::ContinuityExitOwner | Self::BondCreate | Self::BondUnbond | Self::BondWithdraw | Self::NodeKeyRotateOwner | Self::TreasuryProofOfControl => Role::WalletOwner,
crypto-v2/src/lib.rs [network]
    pub const NETWORK: u32 = 0x4d555401;
crypto-v2/src/lib.rs [FN-DSA profile literal]
    pub const PROFILE: &str = "MUTINY-FNDSA1024-PORNIN-20260722-V1";
crypto-v2/src/lib.rs [suite id]
    pub const WALLET_CRYPTO_SUITE_ID: u16 = 1;
crypto-v2/src/lib.rs [policy id (BOTH_REQUIRED)]
    pub const BOTH_REQUIRED_POLICY_ID: u8 = 1;
crypto-v2/src/lib.rs [intent payload limit]
    if payload.len() > 1024 * 1024 {
crypto-v2/src/lib.rs [intent: domain bytes]
    h.update(domain.bytes());
crypto-v2/src/lib.rs [intent: one zero byte]
    h.update([0]);
crypto-v2/src/lib.rs [intent: payload, no length prefix]
    h.update(payload);
crypto-v2/src/lib.rs [intent: SHA-512]
    let mut h = Sha512::new();
crypto-v2/src/lib.rs [FN-DSA signature header]
    || signature.fndsa[0] != 0x3a
crypto-v2/src/lib.rs [FN-DSA verification: raw message, empty context]
    .verify(&signature.fndsa, &DOMAIN_NONE, &HASH_ID_RAW, &m)
crypto-v2/src/lib.rs [FN-DSA signing: raw message, empty context]
    key.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, &m, &mut sig.fndsa)
crypto-v2/src/lib.rs [FN-DSA public key header]
    || self.fndsa[0] != 0x0a
crypto-v2/src/lib.rs [descriptor decode limit]
    if raw.len() > 2048 {
crypto-v2/src/lib.rs [descriptor: 9 items for a wallet key]
    e.array(if wallet { 9 } else { 8 })
crypto-v2/src/lib.rs [AddressID prefix and zero byte]
    h.update(b"MUTINY-BUILD8-HYBRID-ADDRESS-V1\0");
crypto-v2/src/lib.rs [descriptor decode validates the Ed448 key]
    if unsafe { build8_qual_ed448_public_valid(self.ed448.as_ptr(), 57) } != 1
crypto-v2/src/treasury_proof_v1.rs [challenge version]
    pub const CHALLENGE_VERSION: u8 = 1;
crypto-v2/src/treasury_proof_v1.rs [class PRODUCTION]
    pub const CLASS_PRODUCTION: u8 = 1;
crypto-v2/src/treasury_proof_v1.rs [class TEST-VALUE]
    pub const CLASS_TEST_VALUE: u8 = 2;
crypto-v2/src/treasury_proof_v1.rs [signature serialization length]
    pub const SIGNATURE_BYTES: usize = 114 + 1280;
crypto-v2/src/treasury_proof_v1.rs [challenge items]
    const FIELDS: u64 = 14;
crypto-v2/src/treasury_proof_v1.rs [challenge decode limit]
    if raw.is_empty() || raw.len() > 1024 {
crypto-v2/src/treasury_proof_v1.rs [items 9 to 14 are 32-byte strings]
    let h = |d: &mut minicbor::Decoder<'_>| -> Result<[u8; 32], ProofError> {
crypto-v2/src/treasury_proof_v1.rs [decode order: end of input (D3)]
    if d.position() != raw.len() {
crypto-v2/src/treasury_proof_v1.rs [decode order: class/phase then zero fields (D4, D5)]
    challenge.check_shape()?;
crypto-v2/src/treasury_proof_v1.rs [canonical re-encoding]
    if challenge.encode_unchecked() != raw {
crypto-v2/src/treasury_proof_v1.rs [serialization: Ed448 first]
    ed448: raw[..114].try_into().unwrap(),
crypto-v2/src/treasury_proof_v1.rs [serialization: FN-DSA second]
    fndsa: raw[114..].try_into().unwrap(),
qualification/openssl-curve448-port/profile_adapter.c [Ed448: pure (phflag 0), empty context]
    return ossl_ed448_verify(NULL,intent,intent_length,signature,public_key,NULL,0,0,NULL)==1;
qualification/openssl-curve448-port/profile_adapter.c [Ed448: R decodes and is not of small order]
    || !build8_qual_ed448_public_valid(signature,57))return 0;
qualification/openssl-curve448-port/profile_adapter.c [Ed448 key check: decode through the 4-isogeny]
    int ok=ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio(point,public_key)==C448_SUCCESS;
qualification/openssl-curve448-port/profile_adapter.c [Ed448 key check: refuse points of order 1, 2 or 4]
    if(ok)ok=!ossl_curve448_point_eq(point,ossl_curve448_point_identity);
consensus/src/lib.rs [domain_hash: domain]
    h.update(domain);
consensus/src/lib.rs [domain_hash: body after one zero byte]
    h.update(body);
consensus/src/treasury_rehearsal_v1.rs [rehearsal context domain]
    const CONTEXT_DOMAIN: &[u8] = b"MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1";
consensus/src/treasury_rehearsal_v1.rs [rehearsal label rule]
    if !(4..=64).contains(&label.len()) || !label.bytes().all(|b| b.is_ascii_graphic()) {
consensus/src/treasury_rehearsal_v1.rs [rehearsal context derivation]
    Ok(domain_hash(CONTEXT_DOMAIN, label.as_bytes()))
consensus/src/treasury_rehearsal_v1.rs [lineage: records must reproduce the trusted StateRoot]
    let state = State::from_records(records, root).map_err(|_| Refusal::SuccessionUnproven)?;
consensus/src/treasury_rehearsal_v1.rs [plan: identity equals the pinned identity]
    if identity != pinned {
consensus/src/treasury_rehearsal_v1.rs [plan: trusted chain identity]
    if plan.network != chain.network || plan.genesis != chain.genesis || plan.fingerprint != chain.fingerprint {
consensus/src/treasury_rehearsal_v1.rs [plan: validity window at the trusted height]
    if chain.height < plan.created_height || chain.height > plan.expiry_height {
consensus/src/treasury_rehearsal_v1.rs [post-freeze: GenesisID mandatory for a descriptor]
    if is_genesis_descriptor && approved.genesis_id.is_none() {
consensus/src/treasury_rehearsal_v1.rs [post-freeze: the approved store]
    if store.store_id() != approved.admission_store_id {
consensus/src/treasury_v1.rs [Treasury record version]
    const RECORD_VERSION: u8 = 2;
consensus/src/treasury_v1.rs [Treasury record tag]
    pub(crate) const RECORD_TAG: u8 = 60;
consensus/src/treasury_admission_v1.rs [admission store schema]
    pub const STORE_SCHEMA: &str = "MUTINY-D2-TREASURY-ADMISSION-STORE-V2";
consensus/src/treasury_admission_v1.rs [admission store durability]
    const WRITE_PRAGMAS: &str = "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;";
consensus/src/treasury_admission_v1.rs [admission store id: 32 random bytes]
    mutiny_crypto_v2::fill_os_random(&mut store_id).map_err(|_| Refusal::Store)?;
consensus/src/wallet_rotation_v1.rs [rotation plan: authorization domain]
    .sign(Domain::WalletRotate, &body)
consensus/src/wallet_rotation_v1.rs [rotation plan: possession domain]
    .sign(Domain::WalletRotatePossession, &body)
consensus/src/wallet_rotation_v1.rs [rotation plan identity domain]
    b"MUTINY-BUILD8-WALLET-ROTATION-ID-V1",
consensus/src/wallet_rotation_v1.rs [rotation plan: proposed generation = current + 1]
    if old_generation.checked_add(1) != Some(new_generation) {
consensus/src/wallet_rotation_v1.rs [rotation plan: window at most the expiry horizon]
    .is_none_or(|span| span > crate::transactions::EXPIRY_HORIZON)
consensus/src/wallet_authority_v1.rs [wallet current-key record key]
    domain_hash(b"MUTINY-BUILD8-WALLET-AUTHORITY-STATE-V1", &id)
consensus/src/wallet_authority_v1.rs [wallet address record key]
    domain_hash(b"MUTINY-BUILD8-WALLET-ADDRESS-STATE-V1", &address)
consensus/src/state_tree.rs [state tree: branch]
    domain_hash(b"MUTINY-BUILD8-STATE-BRANCH-V2", &raw)
consensus/src/state_tree.rs [state tree: empty leaf]
    d[256] = domain_hash(b"MUTINY-BUILD8-STATE-EMPTY-V2", &[]);
consensus/src/state_tree.rs [state tree: leaf domain]
    b"MUTINY-BUILD8-STATE-LEAF-V2",
consensus/src/state_tree.rs [state tree: commitment]
    Ok(domain_hash(b"MUTINY-BUILD8-STATE-V2", &e.into_writer()))
consensus/src/state_tree.rs [state tree: key bits, most significant first]
    key[depth / 8] & (0x80 >> (depth % 8)) != 0
consensus/src/blocks.rs [GenesisID]
    Ok(domain_hash(b"MUTINY-BUILD8-GENESIS-ID-V1", &self.encode()?))
consensus/src/genesis_inputs.rs [Parameters: 5 items with a Treasury]
    e.array(if self.treasury.is_some() { 5 } else { 4 })
consensus/src/protocol_manifest.rs [rule fingerprint domain]
    pub const DOMAIN: &[u8] = b"MUTINY-BUILD8-PROTOCOL-FINGERPRINT-V1";
```

### A.3 Intent: the 64 bytes that BOTH signatures cover

```text
intent = SHA-512( domain (42 bytes) || 0x00 || challenge )
         no length prefix and no other framing; for a 253-byte challenge the SHA-512 input is 296 bytes
domain || 0x00 (43 bytes):
4d5554494e592d4255494c44382d54524541535552592d50524f4f462d4f462d
434f4e54524f4c2d563100
```

### A.4 Ed448 component (pure RFC 8032 Ed448)

```text
public key 57 bytes; signature 114 bytes = R (57 bytes) || S (57 bytes)
verify(public key, message = intent (64 bytes), context = empty, phflag = 0)
dom4 = "SigEd448" || 0x00 (phflag) || 0x00 (context length) = 53696745643434380000
k = SHAKE256(dom4 || R || public key || intent, 114 bytes) as in RFC 8032 section 5.2.7
the public key and R must decode (canonical encoding of a curve point) and must NOT be of order 1, 2 or 4:
  the key check decodes through the 4-isogeny and refuses a point it maps to the identity (A.2, Ed448 key check)
  textbook RFC 8032 (5.2.3 decoding, 5.2.7 check) accepts R = [s]B, S = s under EVERY such key for EVERY
  message, since [4]A is the identity (OpenSSL 3.5.7 and the vendored verifier already refuse the order-2
  and identity encodings at decoding, so they accept it under the two order-4 keys only); every such key
  is refused when the descriptor is decoded: DescriptorInvalid (4 of 4 small-order keys in
  qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json, ed448_small_order; 4 of them forgeable under textbook RFC 8032)
```

### A.5 FN-DSA component (profile `MUTINY-FNDSA1024-PORNIN-20260722-V1`, n = 1024)

```text
public key 1793 bytes = header 0x0a || 1792 bytes
signature  1280 bytes = header 0x3a || nonce r (40 bytes) || compressed s2 (1239 bytes)
hpk = SHAKE256(public key, 64 bytes)
mu  = SHAKE256(hpk || 0x00 (raw message: no pre-hash) || 0x00 (context length: empty context) || intent, 64 bytes)
c   = HashToPoint(SHAKE256(r || mu)): 16-bit little-endian samples v, keep v < 61445, coefficient v mod 12289
the lattice check itself is the vendored fn-dsa-vrfy (qualification/crypto-v2-sources/rust-fn-dsa-custody-v2)
sources: rust-fn-dsa upstream 0629bb118ebf077857e78c1bd067c704a37795ed (custody copy; verification arithmetic unchanged); C reference c-fn-dsa 1b858880dcac091b5e5f84f0e4d8617c35ba1392
this is a pre-standard draft variant, not FIPS 206 final
```

### A.6 Signature serialization (1394 bytes)

| Offset | Length | Content |
|---|---|---|
| 0 | 114 | Ed448 signature (R, then S) |
| 114 | 1280 | FN-DSA signature (header 0x3a first) |

No header and no length prefix; the order is fixed; any other length (114 alone, 1280 alone) is `Malformed`.

### A.7 Challenge items of the example (V1 vector `d2-vector-k1`)

| # | Item | Offset | Length | CBOR initial bytes | Value |
|---|---|---|---|---|---|
| 1 | `version` | 1 | 1 | `01` | 1 |
| 2 | `network` | 2 | 5 | `1a4d555401` | 1297437697 |
| 3 | `phase` | 7 | 1 | `01` | 1 |
| 4 | `class` | 8 | 1 | `02` | 2 |
| 5 | `generation` | 9 | 1 | `01` | 1 |
| 6 | `suite_id` | 10 | 1 | `01` | 1 |
| 7 | `policy_id` | 11 | 1 | `01` | 1 |
| 8 | `profile` | 12 | 37 | `7823` | `MUTINY-FNDSA1024-PORNIN-20260722-V1` |
| 9 | `descriptor_sha256` | 49 | 34 | `5820` | `5bd93d3e1010dee6957f4e800be90fe680d0f0ba86a1cad5028cb0fca5cbde62` |
| 10 | `address_id` | 83 | 34 | `5820` | `d9f6f3cc827dcef1dac14b0fd3bc0040dd8a44ef248cebb20c02bd1ebe24cb21` |
| 11 | `treasury_authority` | 117 | 34 | `5820` | `d9f6f3cc827dcef1dac14b0fd3bc0040dd8a44ef248cebb20c02bd1ebe24cb21` |
| 12 | `treasury_record_sha256` | 151 | 34 | `5820` | `69b39ff685ea3853e886df64290fb229584b774241c4e49267b607f6655ffe9c` |
| 13 | `ceremony_context` | 185 | 34 | `5820` | `d638d04fed33c61e9b137b5e3d60752139f1baa3bd97285fb5c39599342eaeae` |
| 14 | `nonce` | 219 | 34 | `5820` | `550c414a297ca548bf9bfadd0d560621f53858e792275e397a2f30b8ed44aa28` |

### A.8 Descriptor of the example (1903 bytes, generation 1)

| # | Item | Offset | Length | CBOR initial bytes | Value |
|---|---|---|---|---|---|
| 1 | `version` | 1 | 1 | `01` | 1 |
| 2 | `network` | 2 | 5 | `1a4d555401` | 1297437697 |
| 3 | `role` | 7 | 1 | `01` | 1 |
| 4 | `generation` | 8 | 1 | `01` | 1 |
| 5 | `suite_id` | 9 | 1 | `01` | 1 |
| 6 | `policy_id` | 10 | 1 | `01` | 1 |
| 7 | `profile` | 11 | 37 | `7823` | `MUTINY-FNDSA1024-PORNIN-20260722-V1` |
| 8 | `ed448_public_key` | 48 | 59 | `5839` | 57 bytes, first byte `80`, SHA-256 `4ec8874f8b73185f0106c2a42f6e359d7a9da353f49ae16ba54b3bb7441ba090` |
| 9 | `fndsa_public_key` | 107 | 1796 | `590701` | 1793 bytes, first byte `0a`, SHA-256 `510daf7c1a573fe4d865293b8531a9ee31e093d10c5c0b4ae77f89eaed53afc0` |

descriptor_sha256 = `5bd93d3e1010dee6957f4e800be90fe680d0f0ba86a1cad5028cb0fca5cbde62`

### A.9 AddressID

```text
AddressID = SHA-256("MUTINY-BUILD8-HYBRID-ADDRESS-V1" || 0x00 || descriptor)
example (item 10 of A.7): d9f6f3cc827dcef1dac14b0fd3bc0040dd8a44ef248cebb20c02bd1ebe24cb21
```

### A.10 Treasury record and record hash (ceremony vectors: Treasury K1 `c3-vector-k1`, TEST-VALUE)

```text
record = CBOR [version, tag, class, generation-one descriptor as a byte string]
84        array of 4 items
02        version 2
183c      tag 60
02        class 2 (TEST-VALUE; 1 = PRODUCTION)
59076f    byte string of 1903 bytes: the descriptor
record length 1911; treasury_record_sha256 = SHA-256(record) =
034fef8d8e95a7155a73d785a18fe54dec4000e6ac62d3620f28d3e6f4ee3fd1
```

### A.11 Rehearsal ceremony context

```text
ceremony_context = SHA-256("MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1" || 0x00 || label), label 4 to 64 bytes, each 0x21..0x7E
example label "c3-vector-ceremony" (18 bytes): a793f44c2d1dd9cb72abfac83cf0a183bff061e5918d9d19d5486909581dcbc6
```

### A.12 Rotation plan (succession evidence; `wallet_rotation_v1::Rotation`)

Unsigned body of the ceremony-vector plan K1 -> K2 (3924 bytes); the authorization (by the current key under `MUTINY-BUILD8-WALLET-KEY-ROTATE-V1`) and the possession (by the proposed key under `MUTINY-BUILD8-WALLET-KEY-ROTATE-POSSESSION-V1`) are hybrid signatures over this body with the intent rule of A.3 and the components of A.4 to A.6. The encoded plan is the CBOR array `[1, body as a byte string, authorization Ed448, authorization FN-DSA, possession Ed448, possession FN-DSA]`.

| # | Item | Offset | Length | CBOR initial bytes | Value |
|---|---|---|---|---|---|
| 1 | `version` | 1 | 1 | `01` | 1 |
| 2 | `network` | 2 | 5 | `1a4d555401` | 1297437697 |
| 3 | `genesis` | 7 | 34 | `5820` | `0ca662fff344d64989aae280209aac43411610334bd14bbf3f97cbafe0c4c1ec` |
| 4 | `fingerprint` | 41 | 34 | `5820` | `d16c73b46fa5291a1345de4038125e577df4bbc991052f6ea7efa97e0cc3489f` |
| 5 | `authority` | 75 | 34 | `5820` | `1366a49932060f6461267ae35db0fa1abc8d4eccce1df1685e46736dea012249` |
| 6 | `current_descriptor` | 109 | 1906 | `59076f` | K1 descriptor (1903 bytes) |
| 7 | `proposed_descriptor` | 2015 | 1906 | `59076f` | K2 descriptor (1903 bytes) |
| 8 | `created_height` | 3921 | 1 | `01` | 1 |
| 9 | `expiry_height` | 3922 | 2 | `1864` | 100 |

### A.13 Complete public example (V1 vector `d2-vector-k1`)

```text
challenge (253 bytes):
8e011a4d555401010201010178234d5554494e592d464e445341313032342d50
4f524e494e2d32303236303732322d563158205bd93d3e1010dee6957f4e800b
e90fe680d0f0ba86a1cad5028cb0fca5cbde625820d9f6f3cc827dcef1dac14b
0fd3bc0040dd8a44ef248cebb20c02bd1ebe24cb215820d9f6f3cc827dcef1da
c14b0fd3bc0040dd8a44ef248cebb20c02bd1ebe24cb21582069b39ff685ea38
53e886df64290fb229584b774241c4e49267b607f6655ffe9c5820d638d04fed
33c61e9b137b5e3d60752139f1baa3bd97285fb5c39599342eaeae5820550c41
4a297ca548bf9bfadd0d560621f53858e792275e397a2f30b8ed44aa28
intent preimage = domain || 0x00 || challenge (296 bytes):
4d5554494e592d4255494c44382d54524541535552592d50524f4f462d4f462d
434f4e54524f4c2d5631008e011a4d555401010201010178234d5554494e592d
464e445341313032342d504f524e494e2d32303236303732322d563158205bd9
3d3e1010dee6957f4e800be90fe680d0f0ba86a1cad5028cb0fca5cbde625820
d9f6f3cc827dcef1dac14b0fd3bc0040dd8a44ef248cebb20c02bd1ebe24cb21
5820d9f6f3cc827dcef1dac14b0fd3bc0040dd8a44ef248cebb20c02bd1ebe24
cb21582069b39ff685ea3853e886df64290fb229584b774241c4e49267b607f6
655ffe9c5820d638d04fed33c61e9b137b5e3d60752139f1baa3bd97285fb5c3
9599342eaeae5820550c414a297ca548bf9bfadd0d560621f53858e792275e39
7a2f30b8ed44aa28
intent = SHA-512(intent preimage) (64 bytes):
296389101f258401840ef80a155d3d32855783d66f81b4f1f624f83fd5515227
9b1ea25867dc7ff0a5de6265dced0e5975e235e36a8fe71d47b03bf5e2001c3c
Ed448 signature: 114 bytes, SHA-256 5c37e839f88cecd703b8ef6079ea046b0ab1430c08fff1e4378f1a9898544fef
FN-DSA signature: 1280 bytes, header 3a, SHA-256 25e6768dc193f59c349a0131c2a282b30a1899723329250583fc50c280ca544c
FN-DSA hpk: cf629315455c74c4bee3968669ed991b5c2e1c7857955dbc27985cf0f840f4cdcf41f6b07a2bfcbfd99de0f91d8f52e6f629527d748190ca2ccb4a9fd949c89a
FN-DSA mu:  2a7f5d6e530c6f9ba2d3a1085a67abd27b46158b1c2b401e8672f8d158338788b40307800ae446c80ba32e864d414d5e17cca0ec0762f3456c9a0344c4e5ac39
verdict: VALID (both components verify; computed while generating this block)
```

### A.14 Ceremony example (ceremony vectors)

```text
trusted configuration: network 0x4d555401, phase 1, class 2, Treasury authority 1366a49932060f6461267ae35db0fa1abc8d4eccce1df1685e46736dea012249
                       record hash 034fef8d8e95a7155a73d785a18fe54dec4000e6ac62d3620f28d3e6f4ee3fd1, context label "c3-vector-ceremony"
P1, K1, generation 1 (253 bytes):
8e011a4d555401010201010178234d5554494e592d464e445341313032342d50
4f524e494e2d32303236303732322d5631582091d79fc13b01e49e734e1385f1
10f5e3bcd36c75b33f458675802e69758b3e8758201366a49932060f6461267a
e35db0fa1abc8d4eccce1df1685e46736dea01224958201366a49932060f6461
267ae35db0fa1abc8d4eccce1df1685e46736dea0122495820034fef8d8e95a7
155a73d785a18fe54dec4000e6ac62d3620f28d3e6f4ee3fd15820a793f44c2d
1dd9cb72abfac83cf0a183bff061e5918d9d19d5486909581dcbc65820a047ce
b8a1c6f29813b4ebc45ccccbed9991961bffe2496069f2e7860eaaba7c
intent: c7b4485caed79fc824d8aefee1ec2fa004e20a0dc59066fa7a19c74611485413a92fe96ede96caa6e903dacedb13955b7057a4fca2563f7a59e9da4b391a8319
verdicts: crypto VALID; ceremony (expectation: the record's own key) ACCEPT
trusted succession inputs (qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json): chain genesis 0ca662fff344d64989aae280209aac43411610334bd14bbf3f97cbafe0c4c1ec
    fingerprint d16c73b46fa5291a1345de4038125e577df4bbc991052f6ea7efa97e0cc3489f, trusted height 50, pinned plan identity 4d5c8c49a932d8646b5399214bfae0b1fae76547aa670a341fd7b2529971fe08
P3, impostor K3, generation 2: crypto VALID; ceremony (expectation: the pinned plan K1 -> K2) REJECT UnauthorizedSuccessor
```
<!-- END GENERATED: appendix-a -->

## 13. Final input set for reproduction

Every file a second independent reproduction needs (the V1 files are unchanged; the V2 additions are new). Prepared
for Cipher; the reproduction of the additions is pending. The schema document is the sixth input: its SHA-256 over the
whole file is in `qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-INPUTS.md` and the SHA-256 of every byte
before section 14 is in section 14 (a file cannot contain its own hash).

<!-- BEGIN GENERATED: final-inputs -->
| File | Bytes | SHA-256 | Role |
|---|---|---|---|
| `docs/TREASURY-PROOF-OF-CONTROL-SCHEMA-V1.md` | see `qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-INPUTS.md` (whole file) and section 14 (every byte before it) | | the specification |
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json` | 16790 | `45c04c4be24d430e170cb42e1fe380bc9da51e495228abb238f485e495e3779f` | V1 codec and signature vectors (unchanged) |
| `qualification/TREASURY-PROOF-OF-CONTROL-PREIMAGE-VECTORS-V1.json` | 66813 | `d2b2c1c8bb53c3473d0496a8de0049a029a9eb596a3121e730f89138c7c7b9c6` | V1 exact preimages and 18 negatives (unchanged) |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json` | 100868 | `38f47d58c3e53f49e21dc3ecc8c9d8dddb8a905ffd45176188677914690763fe` | V1 ceremony vectors (unchanged) |
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json` | 112675 | `b98b5e31edd28e3d8ac70e0cb7b82f15926b2fe1a9ee08ad68e8a2b4123708b3` | V2 additions: Ed448 small-order keys, multi-defect probes |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json` | 104888 | `cf10d6d8976d8cdcb96c8c6184ea1651962c24a4b5dcde240c633249f6336173` | V2 additions: trusted succession inputs, lineage, Genesis verdicts, ceremony-order probes |
<!-- END GENERATED: final-inputs -->

## 14. Frozen identity (candidate 3)

**Frozen only after independent reproduction (pending).** Cipher records the result of the first independent
reproduction (V1 files); the reproduction of the V2 additions is pending. Until Cipher records it, the identities below are the
candidate-3 values, not a byte freeze.

<!-- BEGIN GENERATED: frozen-identity -->
| Artifact | Bytes | SHA-256 |
|---|---|---|
| `docs/TREASURY-PROOF-OF-CONTROL-SCHEMA-V1.md`, every byte before the line `## 14. Frozen identity (candidate 3)` | 67734 | `21dfb29428c793c6ff1f9d25302aedca1c21a161eb624bdac286c2dfbb656812` |
| `qualification/candidate-3/TREASURY-INDEPENDENT-REPRODUCTION-INPUTS.md`, every byte outside the generated block `reproduction-inputs` | 7346 | `9a5a2dd566fc6ad476f9662ecefc56b7c21d60ae769865cc4d434187d90adcc4` |
| `docs/TREASURY-REHEARSAL-TOOLING-V1.md`, the status paragraph (from `Status:` to the first blank line) | 136 | `21d1b440282f053b6357a385dfb03e33d9262aabbfc09f34d0a3c488bc99189e` |
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json` | 16790 | `45c04c4be24d430e170cb42e1fe380bc9da51e495228abb238f485e495e3779f` |
| `qualification/TREASURY-PROOF-OF-CONTROL-PREIMAGE-VECTORS-V1.json` | 66813 | `d2b2c1c8bb53c3473d0496a8de0049a029a9eb596a3121e730f89138c7c7b9c6` |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json` | 100868 | `38f47d58c3e53f49e21dc3ecc8c9d8dddb8a905ffd45176188677914690763fe` |
| `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json` | 112675 | `b98b5e31edd28e3d8ac70e0cb7b82f15926b2fe1a9ee08ad68e8a2b4123708b3` |
| `qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json` | 104888 | `cf10d6d8976d8cdcb96c8c6184ea1651962c24a4b5dcde240c633249f6336173` |
| `crypto-v2/src/treasury_proof_v1.rs` | 11944 | `da3dbaad6210770f2745993b8bce78d7a80d118d62c37e5b0763e7e94ceec790` |
| `consensus/src/treasury_rehearsal_v1.rs` | 40300 | `a1fce8200e6b28ef3d444303d944e32c5627c724db219b9787411ccf4a76bdaa` |
| `consensus/src/treasury_admission_v1.rs` | 19785 | `e3c35872b9aa5f505f4857cdccb520fc427a79ef1fbc64af7f3094661c0f5ae7` |
| `spec/DOMAIN-REGISTRY-V1.json`: the 3 lines whose `ascii` is `MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1`, `MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1`, `MUTINY-BUILD8-HYBRID-ADDRESS-V1`, in file order, each with its LF | 2466 | `6dddffd9de436dd7b2726119e120ff67c709948e0b15dd4c4d32fbd0ce88c049` |
<!-- END GENERATED: frozen-identity -->

This record does not qualify the cryptographic implementation, does not create a production descriptor and does not
authorize production signing or Genesis sealing. A Production class byte is necessary but does not by itself
establish key provenance: provenance comes from the reviewed offline custody ceremony through which the Architect
supplies the production public descriptor.
