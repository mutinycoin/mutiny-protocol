//! SOFTWARE TPM SIMULATOR - TEST VALUE ONLY.
//!
//! Deterministic, explicitly labelled test evidence: a restricted P-256 "attestation key", a
//! "voting key", a certify attestation and quotes, all carrying REAL valid ECDSA signatures that
//! the production verifier (`mutiny_consensus_v8::tpm`) accepts. Nothing here is a TPM, nothing
//! here is physical evidence, and nothing here may ever qualify hardware, be production Genesis
//! input or confer Bond eligibility on a Production-class chain (an isolated Legacy/Test-class
//! test chain may admit and bond a simulated member by design). Profiles carry the crate's
//! TEST-VALUE markers; every Production-class admission path rejects them. The marker is an
//! accidental-use guard on this public deterministic material, NOT proof that any other
//! material is genuine hardware: a stripped, consistent statement
//! (`Strip::ConsistentProvenance`) shows the documented limit.
//!
//! This file is compiled only into tests and examples via `#[path]`; it is not part of any
//! shipping artifact. Keys derive from public seed labels, so they are public by construction.
//! It never reads, contains or derives from any real host TPM evidence.
#![allow(dead_code)]
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    admission::{AdmissionPolicy, ApprovedProfile},
    anchors::FinalizedAnchor,
    domain_hash,
    join::{ContinuityJoin, node_id},
    membership::NodeControl,
    recovery::{Anchor, Certificate, Recovery, loss_commitment},
    genesis_inputs::Parameters,
    protocol_manifest::RuleManifest,
    provenance::{self, Endorsement, Provenance},
    endorsement_identity::{EkPublicKey, TPM_ECC_NIST_P256},
    recovery_material::RecoveryMaterial,
    rotation::HardwareRotate,
    tpm::{TpmProfile, encode_quote, test_value_hardware, test_value_trust_manifest},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};

pub const FIXTURE_SCHEMA: &str = "BUILD8-TEST-VALUE-SOFTWARE-TPM-FIXTURE-V1";
pub const AK_SEED_LABEL: &str = "MUTINY-BUILD8-TEST-VALUE-SOFTWARE-TPM-V1/ak";
pub const VOTING_SEED_LABEL: &str = "MUTINY-BUILD8-TEST-VALUE-SOFTWARE-TPM-V1/voting";
/// Candidate 3 (Order A4): the simulator's TEST-VALUE endorsement key, an ECC P-256 key from
/// `<label>/<hex SEC1 voting point>`, so every simulator identity has its own endorsement identity.
pub const EK_SEED_LABEL: &str = "MUTINY-BUILD8-TEST-VALUE-SOFTWARE-TPM-V1/ek";
pub const WARNING: &str =
    "SOFTWARE SIMULATOR TEST VALUE. Not a TPM. Never evidence of physical qualification.";

fn blob(x: &[u8]) -> Vec<u8> {
    let mut b = (x.len() as u16).to_be_bytes().to_vec();
    b.extend(x);
    b
}
/// TPM2B_PUBLIC for a P-256 ECDSA key (copied layout from the in-repo software doubles).
fn public(key: &SigningKey, restricted: bool) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(0x23u16.to_be_bytes());
    b.extend(0xbu16.to_be_bytes());
    b.extend((if restricted { 0x50472u32 } else { 0x40472u32 }).to_be_bytes());
    b.extend(blob(&[]));
    for x in [0x10u16, 0x18, 0xb, 3, 0x10] {
        b.extend(x.to_be_bytes());
    }
    let p = key.verifying_key().to_encoded_point(false);
    b.extend(blob(p.x().unwrap()));
    b.extend(blob(p.y().unwrap()));
    blob(&b)
}
fn header(kind: u16, signer: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut b = 0xff544347u32.to_be_bytes().to_vec();
    b.extend(kind.to_be_bytes());
    b.extend(blob(signer));
    b.extend(blob(extra));
    b.extend([0u8; 16]);
    b.push(1);
    b.extend([0u8; 8]);
    b
}
fn tpm_sig(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let s: Signature = key.sign(message);
    let raw = s.to_bytes();
    let mut b = vec![0, 0x18, 0, 0xb];
    b.extend(blob(&raw[..32]));
    b.extend(blob(&raw[32..]));
    b
}
/// Deterministic scalar from a public label: SHA-256(label || counter) until valid.
pub fn seeded_key(label: &str) -> SigningKey {
    for counter in 0u8..=255 {
        let mut h = Sha256::new();
        h.update(label.as_bytes());
        h.update([counter]);
        let d: [u8; 32] = h.finalize().into();
        if let Ok(k) = SigningKey::from_bytes((&d).into()) {
            return k;
        }
    }
    unreachable!("a valid P-256 scalar is found within a few attempts")
}

pub struct TestTpm {
    ak: SigningKey,
    voting: SigningKey,
    profile: TpmProfile,
}
impl TestTpm {
    /// The standard TEST-VALUE profile (carries the TEST-VALUE marker).
    pub fn new() -> Self {
        Self::with_manifest(test_value_trust_manifest())
    }
    /// NEGATIVE-CONTROL ONLY: same simulator, caller-chosen trust manifest and a hardware id that
    /// does not carry the marker, so tests can show production rejection is driven by the marker.
    pub fn unmarked_negative_control() -> Self {
        let mut t = Self::with_manifest([0x5a; 32]);
        t.profile.hardware = domain_hash(b"MUTINY-BUILD8-TEST-VALUE-UNMARKED-CONTROL-V1", &[]);
        t.resign_certify();
        t
    }
    fn with_manifest(manifest: Hash) -> Self {
        let ak = seeded_key(AK_SEED_LABEL);
        let voting = seeded_key(VOTING_SEED_LABEL);
        let mut signer = vec![0, 0xb];
        signer.extend(Sha256::digest(b"TEST-VALUE qualified name"));
        let profile = TpmProfile {
            hardware: test_value_hardware(),
            ak_public: public(&ak, true),
            voting_public: public(&voting, false),
            qualified_signer: signer,
            pcr_bitmap: [0x95, 0, 0],
            pcr_digest: Sha256::digest(b"TEST-VALUE PCR digest").into(),
            certify_message: vec![],
            certify_signature: vec![],
            admission_trust_manifest: manifest,
            provenance: None,
        };
        let mut t = Self { ak, voting, profile };
        t.resign_certify();
        t
    }
    /// Same simulator keys with an edited profile; the certify statement is re-signed (it covers
    /// the voting key Name and qualified signer only). For negative tests.
    pub fn edited(&self, edit: impl FnOnce(&mut TpmProfile)) -> Self {
        let mut t = Self {
            ak: self.ak.clone(),
            voting: self.voting.clone(),
            profile: self.profile.clone(),
        };
        edit(&mut t.profile);
        t.resign_certify();
        t
    }
    /// A distinct simulator identity (keys from `<seed label>/<tag>`), TEST-VALUE marked.
    pub fn with_identity(tag: &str) -> Self {
        let ak = seeded_key(&format!("{AK_SEED_LABEL}/{tag}"));
        let voting = seeded_key(&format!("{VOTING_SEED_LABEL}/{tag}"));
        Self::new().edited_keys(ak, voting)
    }
    fn edited_keys(&self, ak: SigningKey, voting: SigningKey) -> Self {
        let mut t = Self {
            profile: self.profile.clone(),
            ak,
            voting,
        };
        t.profile.ak_public = public(&t.ak, true);
        t.profile.voting_public = public(&t.voting, false);
        t.resign_certify();
        t
    }
    /// Marker-stripped / relabeled simulator material (analysis section 5 variants a-e). None of it
    /// is physical; (d) is the documented limit material (T14).
    pub fn stripped(variant: Strip) -> Self {
        Self::new().strip(variant)
    }
    /// `stripped` applied to this identity. The stripped hardware label is per voting key, so two
    /// stripped identities never share a hardware label.
    pub fn strip(&self, variant: Strip) -> Self {
        let stripped_hardware =
            domain_hash(b"MUTINY-BUILD8-TEST-VALUE-STRIPPED-HARDWARE-V1", &self.voting_point());
        let stripped_manifest = domain_hash(b"MUTINY-BUILD8-TEST-VALUE-STRIPPED-MANIFEST-V1", &[]);
        let base = self;
        match variant {
            Strip::HardwareOnly => base.edited(|p| p.hardware = stripped_hardware),
            Strip::ManifestOnly => base.edited(|p| p.admission_trust_manifest = stripped_manifest),
            Strip::Both => base.edited(|p| {
                p.hardware = stripped_hardware;
                p.admission_trust_manifest = stripped_manifest;
            }),
            Strip::ConsistentProvenance(root) => {
                // Order A4 (C6): `hardware` IS the class-1 endorsement identity of the statement.
                let identity = base.ek_identity();
                let unmarked = base.edited(|p| p.hardware = identity);
                let statement = unmarked.consistent_provenance(root);
                unmarked.with_provenance(statement)
            }
            Strip::ConsistentProvenanceV1(root) => {
                let unmarked = base.edited(|p| p.hardware = stripped_hardware);
                let statement = unmarked.consistent_provenance_v1(root);
                unmarked.with_provenance(statement)
            }
            Strip::ZeroManifest => base.edited(|p| {
                p.hardware = stripped_hardware;
                p.admission_trust_manifest = [0; 32];
            }),
        }
    }
    /// The simulator's TEST-VALUE endorsement key (ECC P-256, public seed; Order A4). Not an EK of
    /// any TPM: a public key whose canonical encoding derives this identity's endorsement identity.
    pub fn simulator_ek(&self) -> EkPublicKey {
        let key = seeded_key(&format!("{EK_SEED_LABEL}/{}", hex::encode(self.voting_point())));
        let point = key.verifying_key().to_encoded_point(false);
        EkPublicKey::Ecc {
            curve: TPM_ECC_NIST_P256,
            x: point.x().unwrap().to_vec(),
            y: point.y().unwrap().to_vec(),
        }
    }
    /// `endorsement_identity::ek_identity` of `simulator_ek`.
    pub fn ek_identity(&self) -> Hash {
        self.simulator_ek().identity().unwrap()
    }
    /// A version-2 provenance statement consistent with THIS profile (C2-C5 hold for `root`, and
    /// the A4 checks hold once `hardware` is `ek_identity()`): its AK Name, its PCR profile digest,
    /// five distinct nonzero labelled evidence digests, the simulator endorsement identity under
    /// `root` and a labelled witness commitment. Self-made by the simulator: it is exactly what an
    /// authority-signed software profile can carry (T14, limit L1 of the candidate-3 design).
    pub fn consistent_provenance(&self, root: Hash) -> Provenance {
        let label = |part: &str| domain_hash(b"MUTINY-BUILD8-TEST-VALUE-PROVENANCE-V1", part.as_bytes());
        Provenance {
            endorsement: Some(Endorsement {
                identities: vec![(root, self.ek_identity())],
                witness_sha256: label("attestation-witness"),
            }),
            ..self.consistent_provenance_v1(root)
        }
    }
    /// The version-1 statement (321 bytes, no endorsement identity): the documented example of
    /// `docs/PHYSICAL-ADMISSION-ENFORCEMENT-V1.md` section 5. Refused in the Production class since
    /// candidate 3 (`Failure::MissingEndorsementIdentity`).
    pub fn consistent_provenance_v1(&self, root: Hash) -> Provenance {
        let label = |part: &str| domain_hash(b"MUTINY-BUILD8-TEST-VALUE-PROVENANCE-V1", part.as_bytes());
        Provenance {
            endorsement: None,
            endorsement_root: root,
            ek_public_sha256: label("ek-public"),
            ak_name: provenance::ak_name(&self.profile.ak_public).unwrap(),
            platform_profile_sha256: provenance::platform_profile(
                self.profile.pcr_bitmap,
                self.profile.pcr_digest,
            ),
            evidence: [
                label("ek-chain-verification"),
                label("activate-credential"),
                label("host-association"),
                label("restart-verification"),
                label("candidate-platform-profile"),
            ],
        }
    }
    /// Install `statement` as this profile's version-2 provenance with the matching trust
    /// manifest (C1 holds), so a negative test can break exactly one other check.
    pub fn with_provenance(&self, statement: Provenance) -> Self {
        let manifest = statement.commitment();
        self.edited(|p| {
            p.admission_trust_manifest = manifest;
            p.provenance = Some(statement);
        })
    }
    fn resign_certify(&mut self) {
        let p = &self.profile;
        let mut name = vec![0, 0xb];
        name.extend(Sha256::digest(&p.voting_public[2..]));
        let mut m = header(0x8017, &p.qualified_signer, &[0, 0xff, 0x55, 0xaa]);
        m.extend(blob(&name));
        m.extend(blob(&p.qualified_signer));
        self.profile.certify_signature = tpm_sig(&self.ak, &m);
        self.profile.certify_message = m;
        self.profile.verify_certified_key().unwrap();
    }
    pub fn profile(&self) -> &TpmProfile {
        &self.profile
    }
    /// SEC1-compressed voting key, as the registry carries it.
    pub fn voting_point(&self) -> [u8; 33] {
        mutiny_consensus_v8::tpm::public_key(&self.profile.voting_public, false).unwrap()
    }
    /// Fresh quote over any 32-byte challenge, signed by the simulator AK.
    pub fn quote(&self, challenge: Hash) -> Vec<u8> {
        let p = &self.profile;
        let mut m = header(0x8018, &p.qualified_signer, &challenge);
        m.extend(1u32.to_be_bytes());
        m.extend(0xbu16.to_be_bytes());
        m.push(3);
        m.extend(p.pcr_bitmap);
        m.extend(blob(&p.pcr_digest));
        encode_quote(&m, &tpm_sig(&self.ak, &m)).unwrap()
    }
    /// Voting-key possession signature over a 32-byte digest (raw r||s). The `ecdsa` crate in
    /// this lock does NOT normalize P-256 signatures, while the JOIN/ROTATION/RECOVERY verifiers
    /// reject high-S, so the signature is normalized to low-S explicitly.
    pub fn possession(&self, digest: Hash) -> [u8; 64] {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let s: Signature = self.voting.sign_prehash(&digest).unwrap();
        let s = s.normalize_s().unwrap_or(s);
        let mut out = [0u8; 64];
        out.copy_from_slice(&s.to_bytes());
        out
    }
    pub fn challenge() -> Hash {
        domain_hash(b"MUTINY-BUILD8-TEST-VALUE-SOFTWARE-TPM-V1/challenge-1", &[])
    }
    pub fn second_challenge() -> Hash {
        domain_hash(b"MUTINY-BUILD8-TEST-VALUE-SOFTWARE-TPM-V1/challenge-2", &[])
    }
    /// The committed JSON form. Field names mirror the private physical fixture, plus explicit
    /// TEST_VALUE labels. Deterministic: byte-identical on every run.
    pub fn fixture_json(&self) -> serde_json::Value {
        let p = &self.profile;
        let (c1, c2) = (Self::challenge(), Self::second_challenge());
        serde_json::json!({
            "schema": FIXTURE_SCHEMA,
            "TEST_VALUE": true,
            "physical_tpm": false,
            "qualifies_hardware": false,
            "production_eligible": false,
            "bond_eligible": false,
            "actual_genesis_admission": false,
            "warning": WARNING,
            "provenance": {
                "generator": "consensus/tests/support/software_tpm.rs",
                "kind": "deterministic software simulator (p256 ECDSA, RFC 6979); not a TPM",
                "ak_seed": format!("SHA-256(\"{AK_SEED_LABEL}\" || counter byte), first valid P-256 scalar"),
                "voting_seed": format!("SHA-256(\"{VOTING_SEED_LABEL}\" || counter byte), first valid P-256 scalar"),
                "derivation": "Keys are public by construction. Signatures are genuine ECDSA over the attestation messages; no signed field of any real host evidence is reused or edited.",
                "regenerate": "BUILD8_EXPORT_TEST_VALUE_TPM_FIXTURE=<new file path> cargo test --offline --locked --test software_tpm_fixture",
                "real_host_evidence": "none"
            },
            "hardware": hex::encode(p.hardware),
            "ak_public": hex::encode(&p.ak_public),
            "voting_public": hex::encode(&p.voting_public),
            "qualified_signer": hex::encode(&p.qualified_signer),
            "pcr_bitmap": hex::encode(p.pcr_bitmap),
            "pcr_digest": hex::encode(p.pcr_digest),
            "certify_message": hex::encode(&p.certify_message),
            "certify_signature": hex::encode(&p.certify_signature),
            "admission_trust_manifest": hex::encode(p.admission_trust_manifest),
            "profile": hex::encode(p.encode().unwrap()),
            "commitment": hex::encode(p.commitment().unwrap()),
            "challenge": hex::encode(c1),
            "quote_evidence": hex::encode(self.quote(c1)),
            "second_challenge": hex::encode(c2),
            "second_quote_evidence": hex::encode(self.quote(c2)),
        })
    }
    /// Pretty JSON with a trailing newline (LF).
    pub fn fixture_text(&self) -> String {
        pretty(&self.fixture_json())
    }
}
fn pretty(v: &serde_json::Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    s
}

// ---------------------------------------------------------------------------------------------
// TEST-VALUE admission operation fixtures (JOIN, RECOVERY MATERIAL, ROTATION).
//
// They replace three formerly tracked fixtures derived from one real host's TPM. Every value
// below derives from public labels or public fixed seeds: the shared Genesis/fingerprint context,
// the admission authority, the TEST-VALUE endorsement root and the recovery authority are
// SHA-256 labels; owner and Node-authentication keys are the fixed public Ed25519 seeds [61; 32]
// and [62; 32] that the consumer unit tests (consensus/src/{join,recovery_material,rotation}.rs)
// rely on; the TPM is the deterministic simulator above (its profile carries both TEST-VALUE
// markers). There are no real counter values. Real physical evidence is supplied to the same
// checks at RUNTIME by path (BUILD8_PHYSICAL_{JOIN,RECOVERY_MATERIAL,ROTATION}_FIXTURE).
// ---------------------------------------------------------------------------------------------
pub const ADMISSION_FIXTURE_DOMAIN: &[u8] = b"MUTINY-BUILD8-TEST-VALUE-ADMISSION-FIXTURES-V1";
pub const JOIN_FIXTURE_FILE: &str = "JOIN-TEST-VALUE-FIXTURE-V1.json";
pub const RECOVERY_FIXTURE_FILE: &str = "RECOVERY-MATERIAL-TEST-VALUE-FIXTURE-V1.json";
pub const ROTATION_FIXTURE_FILE: &str = "ROTATION-TEST-VALUE-FIXTURE-V1.json";
/// Public fixed Ed25519 seeds the consumer tests use for the owner and Node authentication.
pub const OWNER_SEED: [u8; 32] = [61; 32];
pub const NODE_AUTH_SEED: [u8; 32] = [62; 32];
/// Node of the rotated lineage in the ROTATION fixture (its consumer test hard-codes it).
pub const ROTATION_NODE: Hash = [7; 32];

pub fn fixture_label(part: &str) -> Hash {
    domain_hash(ADMISSION_FIXTURE_DOMAIN, part.as_bytes())
}
fn ed25519(seed: Hash) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&seed)
}
fn ed25519_sign(key: &ed25519_dalek::SigningKey, digest: &Hash) -> [u8; 64] {
    use ed25519_dalek::Signer as _;
    key.sign(digest).to_bytes()
}
/// Reserved TEST-VALUE endorsement-root label. It names no certificate and no manufacturer.
pub fn test_value_endorsement_root() -> Hash {
    domain_hash(b"MUTINY-BUILD8-TEST-VALUE-ENDORSEMENT-ROOT-V1", &[])
}
/// Shared TEST-VALUE Genesis/fingerprint context of the three admission fixtures.
pub fn fixture_context() -> (Hash, Hash) {
    (fixture_label("genesis"), fixture_label("fingerprint"))
}
pub fn admission_authority() -> ed25519_dalek::SigningKey {
    ed25519(fixture_label("admission-authority"))
}
pub fn recovery_authority() -> ed25519_dalek::SigningKey {
    ed25519(fixture_label("recovery-authority"))
}
pub fn fixture_policy() -> AdmissionPolicy {
    let (genesis, fingerprint) = fixture_context();
    AdmissionPolicy {
        genesis,
        fingerprint,
        authority: admission_authority().verifying_key().to_bytes(),
        endorsement_roots: [test_value_endorsement_root()].into_iter().collect(),
    }
}
/// The admission authority's V1 approval of `profile` under `policy` (Ed25519 over the domain
/// digest; the signed bytes include the exact profile bytes).
pub fn approve(policy: &AdmissionPolicy, endorsement_root: Hash, profile: &TpmProfile) -> ApprovedProfile {
    let mut approved = ApprovedProfile {
        genesis: policy.genesis,
        fingerprint: policy.fingerprint,
        endorsement_root,
        profile: profile.encode().unwrap(),
        signature: [0; 64],
    };
    approved.signature = ed25519_sign(&admission_authority(), &approved.signing_digest().unwrap());
    approved
}
fn common(schema: &str, kind: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": schema,
        "TEST_VALUE": true,
        "physical_tpm": false,
        "qualifies_hardware": false,
        "production_eligible": false,
        "bond_eligible": false,
        "actual_genesis": false,
        "warning": WARNING,
        "provenance": {
            "generator": "consensus/tests/support/software_tpm.rs",
            "kind": kind,
            "derivation": "Context, admission authority, recovery authority and endorsement root are SHA-256 labels under MUTINY-BUILD8-TEST-VALUE-ADMISSION-FIXTURES-V1; owner and Node-authentication keys are the public Ed25519 seeds [61;32] and [62;32]; the TPM is the deterministic software simulator (TEST-VALUE marked). P-256 possession signatures are RFC 6979 and normalized to low-S. No real counter values.",
            "regenerate": "BUILD8_EXPORT_TEST_VALUE_ADMISSION_FIXTURES=<new directory> cargo test --offline --locked --test software_admission_fixtures",
            "real_host_evidence": "none"
        }
    })
}
/// JOIN: parent height 58, join height 59 (admission boundary 60), Node from seed [62; 32].
pub fn join_fixture_json() -> serde_json::Value {
    let tpm = TestTpm::new();
    let (parent, policy, join) = join_operation(&tpm);
    let mut v = common(
        "BUILD8-JOIN-TEST-VALUE-FIXTURE-V1",
        "deterministic software simulator JOIN (operation kind 15); not a TPM",
    );
    v["admission_performed"] = false.into();
    v["parent"] = hex::encode(parent.encode()).into();
    v["policy"] = hex::encode(policy.encode().unwrap()).into();
    v["operation"] = hex::encode(join.encode().unwrap()).into();
    v["challenge"] = hex::encode(join.challenge().unwrap()).into();
    v["profile_commitment"] = hex::encode(tpm.profile().commitment().unwrap()).into();
    v
}
/// Typed JOIN builder for any simulator profile (the fixture uses `TestTpm::new()`).
pub fn join_operation(tpm: &TestTpm) -> (FinalizedAnchor, AdmissionPolicy, ContinuityJoin) {
    let (genesis, fingerprint) = fixture_context();
    let policy = fixture_policy();
    let owner = ed25519(OWNER_SEED);
    let node_auth = ed25519(NODE_AUTH_SEED);
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis,
        fingerprint,
        height: 58,
        block: fixture_label("join/parent-block"),
    };
    let node_authentication = node_auth.verifying_key().to_bytes();
    let mut join = ContinuityJoin {
        genesis,
        fingerprint,
        height: 59,
        parent_anchor: parent.id(),
        node: node_id(genesis, node_authentication),
        owner: owner.verifying_key().to_bytes(),
        node_authentication,
        approved_profile: approve(&policy, test_value_endorsement_root(), tpm.profile())
            .encode()
            .unwrap(),
        evidence: vec![],
        owner_signature: [0; 64],
        node_signature: [0; 64],
        possession_signature: [0; 64],
    };
    join.evidence = tpm.quote(join.challenge().unwrap());
    join.owner_signature = ed25519_sign(&owner, &join.owner_digest().unwrap());
    join.node_signature = ed25519_sign(&node_auth, &join.node_digest().unwrap());
    join.possession_signature = tpm.possession(join.possession_digest().unwrap());
    (parent, policy, join)
}
/// RECOVERY MATERIAL: anchor height 6, sequence 1, old generation 0, operation/reason 1, loss
/// commitment over [(lineage, 0)]; replacement Node from seed [62; 32].
pub fn recovery_fixture_json() -> serde_json::Value {
    let (certificate, material, policy) = recovery_material(&TestTpm::new());
    let mut v = common(
        "BUILD8-RECOVERY-MATERIAL-TEST-VALUE-FIXTURE-V1",
        "deterministic software simulator bootstrap-recovery replacement material; not a TPM",
    );
    v["recovery_applied"] = false.into();
    v["historical_lineage_and_authorities_synthetic"] = true.into();
    v["certificate"] = hex::encode(certificate.encode()).into();
    v["material"] = hex::encode(material.encode().unwrap()).into();
    v["policy"] = hex::encode(policy.encode().unwrap()).into();
    v["challenge"] = hex::encode(RecoveryMaterial::challenge(&certificate.body)).into();
    v["recovery_authority"] = hex::encode(recovery_authority().verifying_key().to_bytes()).into();
    v
}
/// Typed recovery builder for any simulator profile (the fixture uses `TestTpm::new()`).
pub fn recovery_material(tpm: &TestTpm) -> (Certificate, RecoveryMaterial, AdmissionPolicy) {
    let (genesis, fingerprint) = fixture_context();
    let policy = fixture_policy();
    let node_auth = ed25519(NODE_AUTH_SEED);
    let authority = recovery_authority();
    let lineage = fixture_label("recovery/lineage");
    let profile = tpm.profile();
    let body = Recovery {
        network: NETWORK_ID,
        genesis,
        fingerprint,
        anchor: Anchor {
            height: 6,
            tip: fixture_label("recovery/anchor-tip"),
            state_root: fixture_label("recovery/anchor-state-root"),
            registry_root: fixture_label("recovery/anchor-registry-root"),
        },
        sequence: 1,
        lineage,
        old_generation: 0,
        new_node: node_id(genesis, node_auth.verifying_key().to_bytes()),
        new_hardware: profile.hardware,
        attestation: profile.commitment().unwrap(),
        new_voting_key: tpm.voting_point(),
        operation: 1,
        reason: 1,
        ceremony_commitment: loss_commitment(&[(lineage, 0)]).unwrap(),
    };
    let certificate = Certificate {
        body: body.clone(),
        signature: ed25519_sign(&authority, &body.digest()),
    };
    let mut material = RecoveryMaterial {
        approved_profile: approve(&policy, test_value_endorsement_root(), profile)
            .encode()
            .unwrap(),
        node_authentication: node_auth.verifying_key().to_bytes(),
        quote: tpm.quote(RecoveryMaterial::challenge(&body)),
        node_signature: [0; 64],
        possession_signature: [0; 64],
    };
    material.node_signature = ed25519_sign(&node_auth, &material.node_digest(&body));
    material.possession_signature = tpm.possession(material.possession_digest(&body));
    (certificate, material, policy)
}
/// The parent control a ROTATION fixture expects (the consumer test builds the same one).
pub fn rotation_parent_control() -> NodeControl {
    NodeControl {
        node: ROTATION_NODE,
        generation: 0,
        owner: ed25519(OWNER_SEED).verifying_key().to_bytes(),
        node_authentication: ed25519(NODE_AUTH_SEED).verifying_key().to_bytes(),
        sequence: 0,
        exit_boundary: None,
        admitted_height: 0,
        admission_boundary: None,
        hardware_since_height: 0,
    }
}
/// ROTATION: Node [7; 32], parent height 6, rotation height 7, sequence 1, generations 0 -> 1,
/// authorized by the owner seed [61; 32]; Node authentication seed [62; 32].
pub fn rotation_fixture_json() -> serde_json::Value {
    let (parent, policy, rotation) = rotation_operation(&TestTpm::new());
    let mut v = common(
        "BUILD8-ROTATION-TEST-VALUE-FIXTURE-V1",
        "deterministic software simulator hardware rotation (operation kind 16); not a TPM",
    );
    v["rotation_performed"] = false.into();
    v["old_lineage_and_authorities_fixture_only"] = true.into();
    v["parent"] = hex::encode(parent.encode()).into();
    v["policy"] = hex::encode(policy.encode().unwrap()).into();
    v["operation"] = hex::encode(rotation.encode().unwrap()).into();
    v["challenge"] = hex::encode(rotation.challenge().unwrap()).into();
    v
}
/// Typed rotation builder for any simulator profile (the fixture uses `TestTpm::new()`).
pub fn rotation_operation(tpm: &TestTpm) -> (FinalizedAnchor, AdmissionPolicy, HardwareRotate) {
    let (genesis, fingerprint) = fixture_context();
    let policy = fixture_policy();
    let owner = ed25519(OWNER_SEED);
    let node_auth = ed25519(NODE_AUTH_SEED);
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis,
        fingerprint,
        height: 6,
        block: fixture_label("rotation/parent-block"),
    };
    let mut rotation = HardwareRotate {
        genesis,
        fingerprint,
        height: 7,
        parent_anchor: parent.id(),
        node: ROTATION_NODE,
        old_generation: 0,
        new_generation: 1,
        sequence: 1,
        authorizer: owner.verifying_key().to_bytes(),
        node_authentication: node_auth.verifying_key().to_bytes(),
        approved_profile: approve(&policy, test_value_endorsement_root(), tpm.profile())
            .encode()
            .unwrap(),
        evidence: vec![],
        authorization: [0; 64],
        node_signature: [0; 64],
        possession: [0; 64],
    };
    rotation.evidence = tpm.quote(rotation.challenge().unwrap());
    rotation.authorization = ed25519_sign(&owner, &rotation.authorization_digest().unwrap());
    rotation.node_signature = ed25519_sign(&node_auth, &rotation.node_digest().unwrap());
    rotation.possession = tpm.possession(rotation.possession_digest().unwrap());
    (parent, policy, rotation)
}
/// Marker-stripping / relabeling variants (analysis section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strip {
    /// (a) hardware marker replaced, trust-manifest marker kept.
    HardwareOnly,
    /// (b) trust-manifest marker replaced, hardware marker kept.
    ManifestOnly,
    /// (c) both replaced with arbitrary nonzero values; no provenance (version 1).
    Both,
    /// (d) both replaced AND a self-consistent provenance statement naming this root (profile
    /// version 2; statement version 2 since candidate 3, `hardware` = the endorsement identity).
    ConsistentProvenance(Hash),
    /// (d') as (d) with the version-1 statement and the stripped hardware label (pre-candidate-3
    /// material; the documented v1 example).
    ConsistentProvenanceV1(Hash),
    /// (e) markers stripped and the trust manifest all-zero.
    ZeroManifest,
}
/// Genesis rule manifest committing to `roots` (Production admission class) plus one labelled
/// TEST-VALUE rule. Test construction only: the real root set is an open Architect decision.
pub fn production_rules(roots: &std::collections::BTreeSet<Hash>) -> RuleManifest {
    RuleManifest {
        commitments: vec![
            (
                provenance::TRUST_ROOTS_COMMITMENT.to_vec(),
                provenance::trust_roots_commitment(roots).unwrap(),
            ),
            (b"test-value-rules".to_vec(), fixture_label("rules")),
        ],
    }
}
/// Genesis parameters record (no Treasury) for state-level Production-class tests.
pub fn production_parameters(roots: &std::collections::BTreeSet<Hash>) -> Vec<u8> {
    Parameters {
        initial_target: [255; 32],
        rules: production_rules(roots),
        treasury: None,
    }
    .encode()
    .unwrap()
}
/// Every software profile that must NOT pass the Production class under a policy whose root set
/// contains `root`: the marked profile, the stripped variants (a), (b), (c), (e) and a consistent
/// statement broken in exactly one check (C1..C5), with the precise expected failure (None: the
/// profile is refused before the provenance rule, e.g. a zero trust manifest).
pub fn production_negative_variants(root: Hash) -> Vec<(&'static str, TestTpm, Option<provenance::Failure>)> {
    use provenance::Failure as F;
    let consistent = TestTpm::stripped(Strip::ConsistentProvenance(root));
    let statement = consistent.profile().provenance.clone().unwrap();
    let with = |edit: &dyn Fn(&mut Provenance)| {
        let mut s = statement.clone();
        edit(&mut s);
        consistent.with_provenance(s)
    };
    let empty_selection = {
        let empty = consistent.edited(|p| p.pcr_bitmap = [0; 3]);
        let mut s = statement.clone();
        s.platform_profile_sha256 = provenance::platform_profile([0; 3], empty.profile().pcr_digest);
        empty.with_provenance(s)
    };
    vec![
        ("marked TEST-VALUE profile", TestTpm::new(), Some(F::TestValueMarker)),
        ("(a) hardware marker replaced, manifest marker kept", TestTpm::stripped(Strip::HardwareOnly), Some(F::TestValueMarker)),
        ("(b) manifest marker replaced, hardware marker kept", TestTpm::stripped(Strip::ManifestOnly), Some(F::TestValueMarker)),
        ("(c) both markers replaced, no provenance", TestTpm::stripped(Strip::Both), Some(F::MissingProvenance)),
        ("(e) markers stripped, zero trust manifest", TestTpm::stripped(Strip::ZeroManifest), None),
        ("C1 trust manifest is not the provenance commitment", consistent.edited(|p| p.admission_trust_manifest[0] ^= 1), Some(F::ManifestMismatch)),
        ("C2 provenance root differs from the approved root", with(&|s| s.endorsement_root[0] ^= 1), Some(F::RootMismatch)),
        ("C3 ak_name of another attestation key", with(&|s| s.ak_name[33] ^= 1), Some(F::AttestationKeyMismatch)),
        ("C4 platform profile of other PCRs", with(&|s| s.platform_profile_sha256[0] ^= 1), Some(F::PlatformProfileMismatch)),
        ("C4 empty PCR selection", empty_selection, Some(F::EmptyPcrSelection)),
        ("C5 zero evidence digest", with(&|s| s.evidence[2] = [0; 32]), Some(F::ZeroEvidence)),
        ("C5 zero EK public hash", with(&|s| s.ek_public_sha256 = [0; 32]), Some(F::ZeroEvidence)),
        ("C5 duplicate evidence digests", with(&|s| s.evidence[4] = s.evidence[0]), Some(F::DuplicateEvidence)),
        // Candidate 3, Order A4 / A7.
        ("A4 version-1 statement (no endorsement identity)", TestTpm::stripped(Strip::ConsistentProvenanceV1(root)), Some(F::MissingEndorsementIdentity)),
        ("A4 C6 hardware relabeled (label-only identity change)", consistent.edited(|p| p.hardware[0] ^= 1), Some(F::HardwareMismatch)),
        ("A4 identity root differs from the statement root", with(&|s| s.endorsement.as_mut().unwrap().identities[0].0[0] ^= 1), Some(F::IdentityRootMismatch)),
        ("A4 second identity rooted outside the policy", with(&|s| s.endorsement.as_mut().unwrap().identities.push(([0x42; 32], [0x43; 32]))), Some(F::RootNotInPolicy)),
        ("A4 the same identity twice", with(&|s| { let e = s.endorsement.as_mut().unwrap(); let first = e.identities[0]; e.identities.push(first); }), Some(F::DuplicateIdentity)),
        ("A4 zero endorsement identity", with(&|s| s.endorsement.as_mut().unwrap().identities[0].1 = [0; 32]), Some(F::ZeroEvidence)),
        ("A4 five identities", with(&|s| { let e = s.endorsement.as_mut().unwrap(); for i in 1..5u8 { e.identities.push((e.identities[0].0, [i; 32])); } }), Some(F::MissingEndorsementIdentity)),
        ("A7 zero witness commitment", with(&|s| s.endorsement.as_mut().unwrap().witness_sha256 = [0; 32]), Some(F::ZeroEvidence)),
    ]
}
/// (committed file name, pretty LF text) for the three admission fixtures.
pub fn admission_fixture_texts() -> [(&'static str, String); 3] {
    [
        (JOIN_FIXTURE_FILE, pretty(&join_fixture_json())),
        (RECOVERY_FIXTURE_FILE, pretty(&recovery_fixture_json())),
        (ROTATION_FIXTURE_FILE, pretty(&rotation_fixture_json())),
    ]
}
