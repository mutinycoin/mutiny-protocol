# Genesis initial state V2 — explicitly unfrozen candidate

Status: CANDIDATE / UNFROZEN, 5 October 2026. This specification describes the current V2 constructor and verifier. It is not a final Genesis lock, Production qualification, enrollment, provisioning or sealing authorization. Architect A9/A10/A14 and the user's K1/K2 decisions govern; this supersedes the earlier representations in `qualification/candidate-3/A-GENESIS-V2-DESIGN.md` sections2–5 where section9/current implementation differ. V1 remains historical/test replay and must refuse Production before artifact parsing; no reinterpretation or fallback.

## 1. Codec and identity

All wire records use deterministic CBOR: definite arrays, shortest integers, exact version/network/arity and fixed-length values, no trailing bytes, and exact canonical re-encoding. NetworkID is the existing `0x4d555401`. Hashes are 32 bytes. `H(domain,x)` is existing SHA256(domain || NUL || x). Existing domains and allocations are preserved; this document allocates none.

`GenesisID = H(MUTINY-BUILD8-GENESIS-ID-V2, GenesisInputsV2)`.
`GenesisBlockV2 = [2, NetworkID, GenesisID, ProtocolFingerprint, timestamp, InitialStateRoot]`.
`GenesisBlockHash = H(MUTINY-BUILD8-GENESIS-BLOCK-V2, GenesisBlockV2)`.
The state parameters key is `H(MUTINY-BUILD8-GENESIS-PARAMETERS-KEY-V2, empty)`.

General rule manifests exclude live instance keys/owners/Workers, GenesisID/block hash, timestamps, enrollment assignments, leaf certificates, evidence logs and this manifest's own fingerprint. The independently approved network-wide trust-root, accepted-PCR and identity-class policy commitments below are rules; individual member certificates/activation records are not rule artifacts.

## 2. Immutable parameters and four bindings

`GenesisParametersV2 = [2, 64, NetworkID, class, InitialPoWTarget, RuleManifestV1 bytes, EndorsementRootSetV2 bytes, AcceptedPcrProfiles bytes, IdentityClasses bytes]` (array9), at most256KiB, stored verbatim at the parameters key and written by no normal block operation. InitialPoWTarget is nonzero. Class1=Production, class2=TestValue; any other byte refuses. Class is read only from these immutable bytes, enters Genesis identity and determines admission rules. No local filename/flag/environment/profile can change it. A verifier's expected class may reject, never override.

RuleManifestV1 retains `[1,NetworkID,[[artifactNameBytes,artifactSHA256]...]]`: unique strictly ascending ASCII graphic names1..128 bytes, 1..512 entries and max128KiB. Each hash is exactly32 bytes. Fingerprint is `H(MUTINY-BUILD8-PROTOCOL-FINGERPRINT-V1, manifest bytes)`. The V2 parameters require these exact entries once each, with the same values their own fields compute:

| Name | Existing commitment |
|---|---|
| genesis-class-v2 | H(MUTINY-BUILD8-GENESIS-CLASS-V2, class byte) |
| endorsement-root-set-v2 | H(MUTINY-BUILD8-ENDORSEMENT-ROOT-SET-V2, root set canonical bytes) |
| accepted-pcr-profile-set-v1 | H(MUTINY-BUILD8-ACCEPTED-PCR-PROFILES-V1, accepted set canonical bytes) |
| endorsement-identity-classes-v1 | H(MUTINY-BUILD8-EK-IDENTITY-CLASSES-V1, identity classes canonical bytes) |

V1 `physical-admission-trust-roots-v1` is forbidden in V2. Missing/mismatched entries refuse; source-only incomplete candidates omit the unresolved four-entry set and therefore cannot instantiate a valid Production Genesis. Never insert invented hashes or public TESTVALUE material as authentic Production bindings.

### Root universe

`EndorsementRootSetV2 = [1,[entry...]]`, each `entry=[root certificate DER SHA256, constraints, test_value_label|null]`, ascending unique nonzero root hash, 1..1024 entries, max140KiB. `constraints` is actual `ek_chain::AnchorConstraints` version2: `[2,max_intermediates,[signature codes...],[[EK tag,size]...],revocation]`. Maximum intermediates3; both lists nonempty, sorted/unique; at most8 EK classes. Signature codes1..6 are RSA-PKCS1-SHA256, RSA-PKCS1-SHA384, RSA-PSS-SHA256, RSA-PSS-SHA384, ECDSA-P256-SHA256, ECDSA-P384-SHA384. EK class tag1 uses RSA2048/3072/4096 bits; tag2 uses TPM curve identifiers P256/P384/P521. Revocation1=CRL required,2=no CRL published. Values are explicit approved inputs, not defaults; certificate/key parsing must independently enforce its supported profile.

Production root labels are null and roots with all bytes equal or the known V1 TESTVALUE root refuse. These accidental-use checks cannot detect an invented random-looking hash: independent approval/authentic DER provenance is mandatory. TestValue roots have labels1..64 bytes and equal `H(MUTINY-BUILD8-TEST-VALUE-ENDORSEMENT-ROOT-V2,label)`. The committed policy roots exactly equal this universe; member roots must belong; no policy replacement operation adds roots.

### Accepted measurements and identity classes

`AcceptedPcrProfiles = [1,update_rule,[[bank,selection,digest,interpretation]...]]`, 1..64 entries, max8192 encoded bytes, ordered/unique by existing platform-profile id. Bank is TPM_ALG_SHA256=0x000b; selection exactly3 bytes over PCR0..23 and nonempty; digest exactly32 bytes; interpretation1 is TPM Quote composite; update rule1 freezes the set at Genesis. Identifier is the existing C4 platform-profile commitment. Real selections/digests/interpretation require measured approved evidence. Production refuses all-equal-byte profile digests. The requalification helper alone is not a wired consensus operation or permission to invent an update kind.

`IdentityClasses = [1,[[algorithm,size,template_sha256]...]]`, 1..4 classes and max512 encoded bytes, no repeated class tuple; list ORDER is significant and class1 is primary hardware. Algorithm/size rules are the existing RSA/ECC rules above; template hash is nonzero and commits every TPMT_PUBLIC byte before the key. Every required class must be covered. Coverage count alone is not class/EK authenticity: the witness verifier separately checks ordered membership, key/template and certificates. Hardware identity uses existing `MUTINY-BUILD8-PHYSICAL-HARDWARE-ID-V2` over NetworkID-u32-be and canonical EK key bytes, not certificate SPKI encoding, TPM object template or caller-chosen id. Current and retired committed identities are compared under rule M; changing EK class or signed labels cannot create a second lineage for an already recorded identity. This comparison authenticates no physical host by itself.

## 3. Inputs, enrollment and initial state

`GenesisInputsV2 = [2,NetworkID,timestamp,nonce,parameters bytes,admission_owner bytes,member bytes,recovery bytes,treasury bytes,purchase]` (array10), max288KiB. Timestamp, nonce and purchase are nonzero. Owner is generation1 WalletOwner; recovery generation1 WalletRecovery; Treasury has its existing exact Genesis-authenticated descriptor/class rules. Descriptor max2048 bytes; no cryptographic half may alias the role-separated owner/recovery/Treasury keys. Member input `[2,endorsement_root,tpm_profile bytes]` names one initial member and a root in the committed set; profile bytes1..8192 and whole member record max9KiB, with existing TPM profile/certified-key checks.

Derive GenesisID before generating the separate node/Continuity keys, deriving NodeID, challenged admission/Continuity possession, owner authorization and node-authentication possession. No policy is an input to its own GenesisID. `EnrollmentV2 = [2,supervised_nonce,member_binding bytes,[12 assignment bytes],[12 supervised binding bytes]]` (array5), max128KiB; exact twelve entries, all context-bound to the frozen identity and checked by existing V2 binding/assignment constructors. Supervised nonce is nonzero. Nothing in source-only candidate generation performs this ceremony.

The constructor derives initial components from these inputs/enrollment, never caller-supplied state records: no coins/premine; registered admission owner; twelve bootstrap License IDs from GenesisID/index with purchase issuance and owner/Worker-signed assignments; one physical-class member/control/Continuity binding with generation1 and zero prior history; existing bootstrap participation/freshness evidence; immutable admission policy with exact root universe; recovery authority/commitment; Treasury/dividend configuration with empty ledger/status book. V1 books, bonds, penalties, retired/key/recovery histories and transient accounting slots start empty. Parameters are the sole protocol record. Every final state must pass ordinary records/StateRoot validity and class/root/profile/identity-coverage backstops; presence of V2 parameters with V1 policy/parameters is an error, not fallback.

## 4. Independent verification and public witness boundary

`Approved` supplies exact independently authenticated class, canonical manifest bytes and qualified initial target. A prover artifact/file hash/self-built manifest is not that approval. Verification strictly decodes inputs/enrollment, checks Approved before construction, reconstructs all components, and compares GenesisID, every record key and byte/count, StateRoot, block bytes and block hash exactly. Nodes additionally enforce independent artifact/block pins and compact sorted canonical JSON with exact fields; V2 artifact max4MiB. A hash proves identity of bytes, not manufacturing provenance or release authority.

K1 public evidence may contain exact authenticated EK certificates/public areas, CRLs and nonsecret activation records, with existing canonical size/path/signature/availability/retention/context/ref-time checks. Replay uses committed historical reference time and available authenticated evidence, independent of verifier wall clock/network. Never include private keys, seeds, TPM authentication or activation secrets. Certified public-key commitment uses existing C2 SPKI encoding; EK identity remains canonical key encoding. Authenticating a signed activation result does not prove locality or that a live physical host currently executes this node.

Path B supersedes the node-execution-location requirement. Remote/VM execution and TPM request forwarding alone are not grounds for refusal. Both `VerifiedGenesisV2::verify` and `verify_with_public_evidence` retain `require_qualified_physical_evidence`: the unsupported Production path refuses because qualifying physical TPM authenticity, canonical hardware-lineage uniqueness, fresh credential activation and accepted platform-profile qualification have not been established through an implemented and qualified production input path. No caller boolean, local approval, committee, Architect signature, source inventory or software fixture lifts that stop. Public reconstruction APIs and synthetic Production-class regression fixtures demonstrate codec/protocol checks, not Production entry eligibility. Production remains disabled. These interfaces do not claim to prove where the node executes.

## 5. Provenance and completion dependencies

This is an unfrozen current-code successor, not a verbatim copy of the earlier design. Exact imported V1/public specification/profile originals are recorded in `spec/imports/CODEX-GENESIS-FINGERPRINT-PUBLIC-INPUTS-V1.json`; originals and historical V9 stay unchanged. Root universe, identity-class templates, measured accepted-PCR profiles, authentic initial member/enrollment, independent manifest/target approval, qualifying physical TPM authenticity, hardware-lineage uniqueness, fresh credential activation and platform qualification remain genuine input/launch dependencies. Node execution on the TPM physical host is not a launch dependency under Path B. Source inventory may be INCOMPLETE; no placeholder value closes a dependency. Constructor/replay/source tests and independent canonical recomputation are software evidence only, separate from physical qualification and custody ceremonies.

## Explicit TEST-VALUE DER alias successor

The independently selected `TestValueEndorsementDerAliasV1` artifact in
`spec/TESTVALUE-ENDORSEMENT-DER-ALIAS-V1.md` permits only the distinguished
57-byte TEST-VALUE label binding to exact root certificate DER. Its exact
artifact digest, logical RootID, DER digest and constraints are committed in
the existing parameters and fingerprint. No selector means historical rules;
Production refuses the selector. This candidate amendment does not change
the Production trust evidence requirements or any original sealed identity.
