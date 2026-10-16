//! Public CEREMONY-level vectors for the Treasury proof of control (continuation order, section 7):
//! the trusted configuration, the succession evidence (exact rotation plan, canonical lineage),
//! positive and negative cases with their exact expected refusals, and the nonce-replay and
//! repeatable-audit sequences. FN-DSA signatures are randomized, so the committed file is generated
//! once (`BUILD8_TREASURY_CEREMONY_VECTORS=<path> cargo test --test treasury_ceremony_vectors_v1`) and
//! this test (1) recomputes every deterministic field from the public labels and requires equality,
//! (2) re-verifies the committed signatures and rotation plan and (3) replays every case and sequence
//! through the real ceremony verifier and a file-backed admission store.
//! SIMULATED / TEST-VALUE: every key derives from a public label; nothing here is production material.
use mutiny_consensus_v8::{
    Hash,
    blocks::GenesisDescriptor,
    genesis_inputs::Parameters,
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
};
use crate::{
    treasury_admission_v1::AdmissionStore,
    treasury_rehearsal_v1::{self as r, ApprovedManifest, Denylist, Expect, Refusal},
};
use mutiny_crypto_v2::{
    Domain, HybridSignature, NETWORK, PublicKey,
    rehearsal_keys_v1::Credential,
    treasury_proof_v1::{self as proof, Challenge, Phase},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha512};

#[path = "support/treasury_ceremony_support.rs"]
mod support;
use support::{Ceremony, TRUSTED_HEIGHT, h32, lineage_state, plan_fingerprint, plan_genesis, trusted_chain};

const COMMITTED: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json");
const TAG: &str = "c3-vector";
const OTHER_CONTEXT_LABEL: &str = "c3-vector-other-ceremony";
const INITIAL_TARGET: [u8; 32] = [255; 32];

fn nonce(tag: &str) -> [u8; 32] {
    h32(&format!("c3-vector-nonce-{tag}"))
}
fn key<'a>(c: &'a Ceremony, id: &str) -> &'a Credential {
    match id {
        "K1" => &c.k1,
        "K2" => &c.k2,
        "K3" => &c.k3,
        "S" => &c.stranger,
        _ => panic!("unknown key {id}"),
    }
}
fn intent(challenge: &[u8]) -> String {
    hex::encode(Sha512::digest([Domain::TreasuryProofOfControl.bytes(), &[0u8][..], challenge].concat()))
}

/// Every proof of the vectors: (id, signer, deterministic challenge).
fn challenges(c: &Ceremony) -> Vec<(&'static str, &'static str, Challenge)> {
    let d = |id: &str| key(c, id).descriptor().unwrap();
    let record = r::record_sha256(&c.treasury).unwrap();
    let production_record = r::record_sha256(&Treasury::new(Class::Production, d("K1")).unwrap()).unwrap();
    let context = c.config.context().value();
    let other_context = r::ceremony_context(OTHER_CONTEXT_LABEL).unwrap();
    let authority = c.treasury.authority();
    let stranger_treasury = Treasury::new(Class::TestValue, d("S")).unwrap();
    let new = |id: &str, phase, authority, record, context, n: &str| Challenge::new(&d(id), phase, authority, record, context, nonce(n)).unwrap();
    vec![
        ("P1", "K1", new("K1", Phase::Rehearsal, authority, record, context, "1")),
        ("P2", "K2", new("K2", Phase::Rehearsal, authority, record, context, "2")),
        ("P2_same_nonce_as_P1", "K2", new("K2", Phase::Rehearsal, authority, record, context, "1")),
        ("P3_impostor", "K3", new("K3", Phase::Rehearsal, authority, record, context, "3")),
        ("P4_other_context", "K1", new("K1", Phase::Rehearsal, authority, record, other_context, "4")),
        ("P5_production_phase", "K1", new("K1", Phase::Production, authority, production_record, context, "5")),
        ("P6_production_class_record", "K1", new("K1", Phase::Rehearsal, authority, production_record, context, "6")),
        (
            "P7_other_treasury",
            "S",
            new("S", Phase::Rehearsal, stranger_treasury.authority(), r::record_sha256(&stranger_treasury).unwrap(), context, "7"),
        ),
        ("P8_wrong_descriptor", "S", new("S", Phase::Rehearsal, authority, record, context, "8")),
        ("P9_unrecorded", "K1", new("K1", Phase::Rehearsal, authority, record, context, "9")),
    ]
}

/// (name, proof, expectation, crypto-layer verdict, ceremony verdict).
const CASES: [(&str, &str, &str, &str, &str); 12] = [
    ("accept_generation_one", "P1", "generation_one", "VALID", "ACCEPT"),
    ("accept_successor_rotation_plan", "P2", "rotation_plan", "VALID", "ACCEPT"),
    ("accept_successor_canonical_lineage", "P2", "canonical_lineage", "VALID", "ACCEPT"),
    ("reject_impostor_successor_rotation_plan", "P3_impostor", "rotation_plan", "VALID", "REJECT UnauthorizedSuccessor"),
    ("reject_impostor_successor_canonical_lineage", "P3_impostor", "canonical_lineage", "VALID", "REJECT UnauthorizedSuccessor"),
    ("reject_wrong_context", "P4_other_context", "generation_one", "VALID", "REJECT WrongContext"),
    ("reject_wrong_phase_production", "P5_production_phase", "generation_one", "ProductionRefused", "REJECT ProductionRefused"),
    ("reject_wrong_class_record", "P6_production_class_record", "generation_one", "VALID", "REJECT TreasuryMismatch"),
    ("reject_wrong_treasury_authority", "P7_other_treasury", "generation_one", "VALID", "REJECT TreasuryMismatch"),
    ("reject_wrong_descriptor", "P8_wrong_descriptor", "generation_one", "VALID", "REJECT AlteredDescriptor"),
    ("reject_wrong_generation_one_under_plan", "P1", "rotation_plan", "VALID", "REJECT Proof(WrongKeyVersion)"),
    ("reject_wrong_generation_two_as_one", "P2", "generation_one", "VALID", "REJECT Proof(WrongKeyVersion)"),
];
/// One sequence step: (action, proof or frozen input, expectation, expected result).
type Step = (&'static str, &'static str, &'static str, &'static str);
/// Sequences: (name, steps).
fn sequences() -> Vec<(&'static str, Vec<Step>)> {
    vec![
        (
            "nonce_replay",
            vec![
                ("admit", "P1", "generation_one", "ACCEPT"),
                ("admit", "P1", "generation_one", "REJECT Replay"),
                ("verify", "P2_same_nonce_as_P1", "rotation_plan", "ACCEPT"),
                ("admit", "P2_same_nonce_as_P1", "rotation_plan", "REJECT Replay"),
                ("restart", "-", "-", "REOPENED"),
                ("admit", "P1", "generation_one", "REJECT Replay"),
                ("verify", "P1", "generation_one", "ACCEPT"),
                ("admit", "P3_impostor", "rotation_plan", "REJECT UnauthorizedSuccessor"),
                ("admit", "P2", "rotation_plan", "ACCEPT"),
            ],
        ),
        (
            "repeatable_audit",
            vec![
                ("admit", "P1", "generation_one", "ACCEPT"),
                ("verify_frozen", "frozen_parameters", "generation_one", "PASS STORE-UNCHANGED"),
                ("verify_frozen", "frozen_parameters", "generation_one", "PASS STORE-UNCHANGED"),
                ("verify_frozen", "genesis_descriptor", "generation_one", "PASS STORE-UNCHANGED"),
                ("audit", "P9_unrecorded", "generation_one", "REJECT NotAdmitted"),
                ("verify_frozen", "changed_parameters", "generation_one", "REJECT ManifestMismatch"),
                ("restart", "-", "-", "REOPENED"),
                ("verify_frozen", "frozen_parameters", "generation_one", "PASS STORE-UNCHANGED"),
                ("admit", "P1", "generation_one", "REJECT Replay"),
            ],
        ),
    ]
}

fn genesis_descriptor(parameters: &[u8]) -> GenesisDescriptor {
    GenesisDescriptor {
        timestamp: 1,
        nonce: h32("c3-vector-genesis-nonce"),
        fingerprint: r::rehearsal_rules().fingerprint().unwrap(),
        owner: h32("c3-vector-genesis-owner"),
        purchase: h32("c3-vector-genesis-purchase"),
        parameters: parameters.to_vec(),
        admission_records: vec![],
        recovery: h32("c3-vector-genesis-recovery"),
    }
}
fn parameters(c: &Ceremony, initial_target: [u8; 32]) -> Vec<u8> {
    Parameters { initial_target, rules: r::rehearsal_rules(), treasury: Some(c.treasury.clone()) }.encode().unwrap()
}

/// Everything that is a pure function of the public labels (no signature, no encoded plan).
fn deterministic(c: &Ceremony) -> Value {
    let keys: serde_json::Map<String, Value> = [
        ("K1", "Treasury generation-one key (the trusted Treasury record carries its descriptor)"),
        ("K2", "authorized successor: proposed descriptor of the rotation plan, generation 2"),
        ("K3", "impostor: an unrelated generation-2 key that signs the Treasury's public identifiers"),
        ("S", "stranger: an unrelated generation-one key"),
    ]
    .iter()
    .map(|(id, role)| {
        let k = key(c, id);
        let d = k.descriptor().unwrap();
        let (public, generation) = PublicKey::decode_descriptor(&d).unwrap();
        let label = match *id {
            "K1" => format!("{TAG}-k1"),
            "K2" => format!("{TAG}-k2"),
            "K3" => format!("{TAG}-k3"),
            _ => format!("{TAG}-stranger"),
        };
        (
            id.to_string(),
            json!({
                "label_public": label,
                "role": role,
                "generation": generation,
                "descriptor_hex": hex::encode(&d),
                "descriptor_sha256": hex::encode(proof::sha256(&d)),
                "address_id": hex::encode(public.address_id(generation).unwrap()),
            }),
        )
    })
    .collect();
    let plan = c.plan();
    let record = c.treasury.encode().unwrap();
    let proofs: serde_json::Map<String, Value> = challenges(c)
        .into_iter()
        .map(|(id, signer, ch)| {
            let raw = ch.encode().unwrap();
            (
                id.to_string(),
                json!({
                    "signer": signer,
                    "phase": ch.phase as u8,
                    "class": ch.class,
                    "generation": ch.generation,
                    "nonce": hex::encode(ch.nonce),
                    "challenge_hex": hex::encode(&raw),
                    "intent_sha512": intent(&raw),
                }),
            )
        })
        .collect();
    let cases: Vec<Value> = CASES
        .iter()
        .map(|(name, p, e, crypto, ceremony)| json!({"name": name, "proof": p, "expectation": e, "crypto": crypto, "ceremony": ceremony}))
        .collect();
    let sequences: Vec<Value> = sequences()
        .into_iter()
        .map(|(name, steps)| {
            let steps: Vec<Value> = steps
                .into_iter()
                .enumerate()
                .map(|(i, (action, input, expectation, result))| json!({"step": i + 1, "action": action, "input": input, "expectation": expectation, "result": result}))
                .collect();
            json!({"name": name, "store": "a new admission store bound to (ceremony_context, treasury_record_sha256)", "steps": steps})
        })
        .collect();
    let frozen = parameters(c, INITIAL_TARGET);
    let genesis = genesis_descriptor(&frozen);
    json!({
        "schema": "BUILD8-TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1",
        "synthetic_only": true,
        "test_value": true,
        "production_authorized": false,
        "note": "Public data only. Keys derive from public labels (TEST-VALUE). FN-DSA signatures are randomized, so the signatures are fixed by this file and verification is the check; every other field is a pure function of the labels. 'crypto' is the verdict of the strict challenge decoder plus both signatures over the proof's own descriptor (Challenge::verify); 'ceremony' is the verdict against the TRUSTED expectation. P5 carries a hybrid signature made through the raw signing API by a TEST-VALUE key solely as a negative control: its phase byte is 2 and it must be refused.",
        "keys": keys,
        "trusted_configuration": {
            "network": NETWORK,
            "phase": 1,
            "class": 2,
            "treasury_record_hex": hex::encode(&record),
            "treasury_record_sha256": hex::encode(proof::sha256(&record)),
            "treasury_authority": hex::encode(c.treasury.authority()),
            "treasury_descriptor": "K1",
            "ceremony_context_label": c.label,
            "ceremony_context": hex::encode(c.config.context().value()),
            "other_ceremony_context_label": OTHER_CONTEXT_LABEL,
            "other_ceremony_context": hex::encode(r::ceremony_context(OTHER_CONTEXT_LABEL).unwrap()),
        },
        "expectations": {
            "generation_one": {"generation": 1, "descriptor": "K1", "source": "the trusted Treasury record"},
            "rotation_plan": {"generation": 2, "descriptor": "K2", "source": "rotation_plan: authority = treasury_authority, current = K1 descriptor, proposed = K2 descriptor; authorization by K1 under MUTINY-BUILD8-WALLET-KEY-ROTATE-V1 and possession by K2 under MUTINY-BUILD8-WALLET-KEY-ROTATE-POSSESSION-V1, both over unsigned_body_hex; genesis and fingerprint equal to the trusted chain identity below"},
            "canonical_lineage": {"generation": 2, "descriptor": "K2", "source": "authenticated canonical state: the current descriptor of treasury_authority after the canonical application of rotation_plan"},
        },
        "rotation_plan": {
            "genesis": hex::encode(plan_genesis()),
            "fingerprint": hex::encode(plan_fingerprint()),
            "authority": hex::encode(plan.authority),
            "current": "K1",
            "proposed": "K2",
            "created_height": plan.created_height,
            "expiry_height": plan.expiry_height,
            "unsigned_body_hex": hex::encode(plan.unsigned().unwrap()),
        },
        "proofs": proofs,
        "cases": cases,
        "sequences": sequences,
        "frozen": {
            "initial_target_hex": hex::encode(INITIAL_TARGET),
            "frozen_parameters_hex": hex::encode(&frozen),
            "changed_parameters_hex": hex::encode(parameters(c, [254; 32])),
            "genesis_descriptor_hex": hex::encode(genesis.encode().unwrap()),
            "genesis_id": hex::encode(genesis.id().unwrap()),
            "approved_manifest": {
                "class": 2,
                "descriptor_sha256": hex::encode(proof::sha256(c.treasury.descriptor())),
                "record_sha256": hex::encode(proof::sha256(&record)),
                "parameters_sha256": hex::encode(proof::sha256(&frozen)),
                "genesis_id_for_genesis_descriptor_input": hex::encode(genesis.id().unwrap()),
            },
        },
    })
}

/// A complete file: the deterministic part plus fresh signatures and the encoded, signed plan.
fn generate(c: &Ceremony) -> Value {
    let mut value = deterministic(c);
    let mut signatures = serde_json::Map::new();
    for (id, signer, ch) in challenges(c) {
        let k = key(c, signer);
        let sig = if ch.phase == Phase::Production {
            // Negative control only: a TEST-VALUE key signs a phase-2 payload through the raw API.
            k.key().sign(Domain::TreasuryProofOfControl, &ch.encode().unwrap()).unwrap()
        } else {
            proof::sign_challenge(k.key(), &k.descriptor().unwrap(), &ch).unwrap()
        };
        signatures.insert(id.to_string(), json!(hex::encode(proof::signature_to_bytes(&sig))));
    }
    value["signatures"] = Value::Object(signatures);
    value["rotation_plan_encoded_hex"] = json!(hex::encode(c.plan().encode().unwrap()));
    value
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn verdict(r: Result<impl Sized, Refusal>) -> String {
    match r {
        Ok(_) => "ACCEPT".to_string(),
        Err(e) => format!("REJECT {e:?}"),
    }
}

struct Loaded {
    c: Ceremony,
    file: Value,
    plan: Rotation,
}
impl Loaded {
    fn expectation(&self, name: &str) -> Expect {
        match name {
            "generation_one" => Expect::genesis_key(&self.c.config),
            // The trusted succession inputs that this file leaves implicit are stated by the V2 additions
            // file (qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json): the
            // trusted chain (network, plan genesis, plan fingerprint) at the trusted height, the pinned
            // plan identity (derived here from the public labels, never from the plan file) and the
            // canonical lineage records with their StateRoot.
            "rotation_plan" => {
                let config = self.c.config.clone().with_trusted_chain(trusted_chain(TRUSTED_HEIGHT)).unwrap().with_authorized_plan(self.c.plan().identity().unwrap()).unwrap();
                Expect::authorized_rotation(&config, &self.plan).unwrap()
            }
            "canonical_lineage" => {
                let (records, root) = lineage_state(&self.c.k1.descriptor().unwrap(), std::slice::from_ref(&self.plan));
                Expect::canonical_current(&self.c.config.clone().with_canonical_root(root).unwrap(), &records).unwrap()
            }
            other => panic!("unknown expectation {other}"),
        }
    }
    fn proof(&self, id: &str) -> (Vec<u8>, Vec<u8>, HybridSignature) {
        let p = &self.file["proofs"][id];
        let descriptor = bytes(&self.file["keys"][p["signer"].as_str().unwrap()]["descriptor_hex"]);
        let signature = proof::signature_from_bytes(&bytes(&self.file["signatures"][id])).unwrap();
        (descriptor, bytes(&p["challenge_hex"]), signature)
    }
    /// The approved manifest of the file, naming the admission store of the sequence (store ids are
    /// random per store; the V2 additions state the store-id rule).
    fn approved(&self, store_id: Hash) -> ApprovedManifest {
        let a = &self.file["frozen"]["approved_manifest"];
        let h = |k: &str| <[u8; 32]>::try_from(bytes(&a[k])).unwrap();
        ApprovedManifest {
            class: Class::TestValue,
            descriptor_sha256: h("descriptor_sha256"),
            record_sha256: h("record_sha256"),
            parameters_sha256: h("parameters_sha256"),
            genesis_id: None,
            admission_store_id: store_id,
        }
    }
}

#[test]
fn ceremony_vectors_are_complete_reproducible_and_every_verdict_holds() {
    let c = Ceremony::new(TAG);
    if let Ok(path) = std::env::var("BUILD8_TREASURY_CEREMONY_VECTORS") {
        std::fs::write(path, serde_json::to_string_pretty(&generate(&c)).unwrap() + "\n").unwrap();
    }
    let committed: Value = serde_json::from_str(COMMITTED).expect("committed ceremony vectors file");
    // (1) Every deterministic field equals a fresh derivation from the public labels.
    let mut without_signatures = committed.clone();
    let object = without_signatures.as_object_mut().unwrap();
    assert!(object.remove("signatures").is_some() && object.remove("rotation_plan_encoded_hex").is_some());
    assert_eq!(without_signatures, deterministic(&c), "deterministic fields");
    // (2) The committed plan is canonical, carries the committed unsigned body and both rotation
    //     signatures verify (Expect::authorized_rotation checks them).
    let plan = Rotation::decode(&bytes(&committed["rotation_plan_encoded_hex"])).unwrap();
    assert_eq!(hex::encode(plan.unsigned().unwrap()), committed["rotation_plan"]["unsigned_body_hex"].as_str().unwrap());
    assert_eq!(plan.identity().unwrap(), c.plan().identity().unwrap(), "the committed plan is the pinned plan");
    let loaded = Loaded { c, file: committed, plan };
    let deny = Denylist::default();
    // (3a) Every case: the crypto-layer verdict and the ceremony verdict, exactly.
    let cases = loaded.file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), CASES.len());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let (descriptor, challenge, signature) = loaded.proof(case["proof"].as_str().unwrap());
        // The hybrid signature itself always verifies over the proof's intent (randomized, committed).
        let (public, _) = PublicKey::decode_descriptor(&descriptor).unwrap();
        assert!(public.verify(Domain::TreasuryProofOfControl, &challenge, &signature).is_ok(), "{name}: hybrid signature");
        let crypto = match Challenge::decode(&challenge).and_then(|ch| ch.verify(&descriptor, &signature)) {
            Ok(()) => "VALID".to_string(),
            Err(e) => format!("{e:?}"),
        };
        assert_eq!(crypto, case["crypto"].as_str().unwrap(), "{name}: crypto layer");
        let expect = loaded.expectation(case["expectation"].as_str().unwrap());
        assert_eq!(verdict(r::verify_proof(&expect, &descriptor, &challenge, &signature, &deny)), case["ceremony"].as_str().unwrap(), "{name}: ceremony");
    }
    // (3b) Every sequence, through a file-backed store; audits must leave the file byte-identical.
    let frozen = &loaded.file["frozen"];
    for sequence in loaded.file["sequences"].as_array().unwrap() {
        let name = sequence["name"].as_str().unwrap();
        let dir = support::scratch_dir(&format!("vectors-{name}"));
        let path = dir.join("admissions.sqlite");
        let created = AdmissionStore::create(&path, &loaded.c.config).unwrap();
        let store_id = created.store_id();
        drop(created);
        let mut store = AdmissionStore::open(&path, &loaded.c.config).unwrap();
        for step in sequence["steps"].as_array().unwrap() {
            let action = step["action"].as_str().unwrap();
            let input = step["input"].as_str().unwrap();
            let expected = step["result"].as_str().unwrap();
            let got = match action {
                "restart" => {
                    drop(store);
                    store = AdmissionStore::open(&path, &loaded.c.config).unwrap();
                    "REOPENED".to_string()
                }
                "admit" | "verify" | "audit" => {
                    let (d, ch, s) = loaded.proof(input);
                    let expect = loaded.expectation(step["expectation"].as_str().unwrap());
                    match action {
                        "admit" => verdict(store.admit(&expect, &d, &ch, &s, &deny)),
                        "verify" => verdict(r::verify_proof(&expect, &d, &ch, &s, &deny)),
                        _ => verdict(r::audit_recorded(&store, &expect, &d, &ch, &s, &deny)),
                    }
                }
                "verify_frozen" => {
                    let (raw, is_descriptor, approved) = match input {
                        "frozen_parameters" => (bytes(&frozen["frozen_parameters_hex"]), false, loaded.approved(store_id)),
                        "changed_parameters" => (bytes(&frozen["changed_parameters_hex"]), false, loaded.approved(store_id)),
                        "genesis_descriptor" => {
                            // A Genesis-descriptor input requires the approval to name the GenesisID.
                            let id = <[u8; 32]>::try_from(bytes(&frozen["approved_manifest"]["genesis_id_for_genesis_descriptor_input"])).unwrap();
                            (bytes(&frozen["genesis_descriptor_hex"]), true, ApprovedManifest { genesis_id: Some(id), ..loaded.approved(store_id) })
                        }
                        other => panic!("unknown frozen input {other}"),
                    };
                    let (_, ch, s) = loaded.proof("P1");
                    let before = support::file_sha256(&path);
                    let audit = AdmissionStore::open_read_only(&path, &loaded.c.config).unwrap();
                    let result = r::verify_frozen(&raw, is_descriptor, &Expect::genesis_key(&loaded.c.config), &approved, &audit, &ch, &s);
                    drop(audit);
                    match result {
                        Ok(_) if support::file_sha256(&path) == before => "PASS STORE-UNCHANGED".to_string(),
                        Ok(_) => "PASS STORE-CHANGED".to_string(),
                        Err(e) => format!("REJECT {e:?}"),
                    }
                }
                other => panic!("unknown action {other}"),
            };
            assert_eq!(got, expected, "{name} step {}", step["step"]);
        }
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    // The frozen inputs are the ones the ceremony builder produces from the admitted P1.
    let (d1, b1, s1) = loaded.proof("P1");
    let mut scratch = AdmissionStore::in_memory(&loaded.c.config).unwrap();
    scratch.admit(&Expect::genesis_key(&loaded.c.config), &d1, &b1, &s1, &deny).unwrap();
    let manifest = r::build_manifest(&Expect::genesis_key(&loaded.c.config), &d1, &b1, &s1, INITIAL_TARGET, &r::rehearsal_rules(), &deny, &scratch).unwrap();
    assert_eq!(hex::encode(&manifest.parameters), frozen["frozen_parameters_hex"].as_str().unwrap());
}

// Historical V1/V2 software model only. Superseded unrestricted admission is
// compiled in this test crate, never exported by the shipping library graph.
// Only paths required by the isolated frozen model are supplied here.
pub use mutiny_consensus_v8::{domain_hash, blocks, execution, genesis_inputs, protocol_manifest, treasury_v1, wallet_rotation_v1, dividend_state_v1, NETWORK_ID};
#[path = "../src/treasury_rehearsal_v1.rs"]
mod treasury_rehearsal_v1;
#[path = "../src/treasury_admission_v1.rs"]
mod treasury_admission_v1;
