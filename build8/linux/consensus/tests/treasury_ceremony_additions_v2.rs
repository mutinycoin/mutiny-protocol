//! Ceremony-level V2 ADDITIONS to the Treasury proof-of-control vectors (new file; the V1 vector files
//! keep their bytes), added after the independent review (F1-F3, F5) and the independent reproduction
//! (S1, S2, S4, S5, S6): the trusted succession inputs (trusted chain identity and height, pinned plan
//! identity, canonical StateRoot with its records), succession cases that depend on them, the exact
//! Genesis derivation with the verdict table of the post-freeze check, the store-id rule and
//! ceremony-level inputs with more than one defect. Rotation-plan signatures are randomized, so the
//! committed file is generated once (`BUILD8_TREASURY_CEREMONY_ADDITIONS=<path> cargo test --test
//! treasury_ceremony_additions_v2`); this test recomputes every other field from the public labels and
//! the committed V1 ceremony vectors, re-verifies the signed plans and replays every verdict.
//! SIMULATED / TEST-VALUE: every key derives from a public label.
use mutiny_consensus_v8::{
    Hash,
    blocks::{GenesisDescriptor, state_root},
    genesis_inputs::Parameters,
    treasury_v1::Class,
    wallet_authority_v1::{address_key, current_key},
    wallet_rotation_v1::Rotation,
};
use crate::{
    treasury_admission_v1::AdmissionStore,
    treasury_rehearsal_v1::{self as r, ApprovedManifest, CeremonyConfig, Denylist, Expect, Refusal, TrustedChain},
};
use mutiny_crypto_v2::{HybridSignature, PublicKey, treasury_proof_v1 as proof};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[path = "support/treasury_ceremony_support.rs"]
mod support;
use support::{Ceremony, TRUSTED_HEIGHT, h32, lineage_state, plan_fingerprint, plan_genesis, rotation_plan, trusted_chain};

const COMMITTED: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS.json");
const V1: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json");
const TAG: &str = "c3-vector";

fn other_genesis() -> Hash {
    h32("c3-vector-other-genesis")
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))).unwrap()
}
fn verdict<T>(r: Result<T, Refusal>) -> String {
    match r {
        Ok(_) => "ACCEPT".to_string(),
        Err(e) => format!("REJECT {e:?}"),
    }
}
/// The plans of the additions: (name, current, proposed, genesis). Signers are the current and proposed keys.
/// (name, current key, proposed key, genesis of the plan).
type PlanSpec = (&'static str, &'static str, &'static str, fn() -> Hash);
fn plan_specs() -> [PlanSpec; 3] {
    [("PLAN_K1_K2", "K1", "K2", plan_genesis), ("PLAN_K1_K3_RIVAL", "K1", "K3", plan_genesis), ("PLAN_K1_K2_OTHER_CHAIN", "K1", "K2", other_genesis)]
}
fn key<'a>(c: &'a Ceremony, id: &str) -> &'a mutiny_crypto_v2::rehearsal_keys_v1::Credential {
    match id {
        "K1" => &c.k1,
        "K2" => &c.k2,
        "K3" => &c.k3,
        _ => &c.stranger,
    }
}
fn signed_plan(c: &Ceremony, name: &str) -> Rotation {
    let (_, from, to, genesis) = plan_specs().into_iter().find(|p| p.0 == name).unwrap();
    rotation_plan(c.treasury.authority(), key(c, from).key(), key(c, from).descriptor().unwrap(), key(c, to).key(), key(c, to).descriptor().unwrap(), genesis(), plan_fingerprint())
}
/// The reviewer's fabricated wallet records (no K1 signature anywhere): K3 current at generation 2.
fn fabricated_records(c: &Ceremony) -> Vec<(Hash, Vec<u8>)> {
    let id = c.treasury.authority();
    let record = |kind: u8, raw: &[u8]| {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4).unwrap().u8(1).unwrap().u8(kind).unwrap().bytes(&id).unwrap().bytes(raw).unwrap();
        e.into_writer()
    };
    let addr = |raw: &[u8]| {
        let (p, g) = PublicKey::decode_descriptor(raw).unwrap();
        p.address_id(g).unwrap()
    };
    let (k1d, k3d) = (c.k1.descriptor().unwrap(), c.k3.descriptor().unwrap());
    let mut m = BTreeMap::new();
    m.insert(current_key(id), record(30, &k3d));
    m.insert(address_key(addr(&k1d)), record(31, &k1d));
    m.insert(address_key(addr(&k3d)), record(31, &k3d));
    m.into_iter().collect()
}
fn rows(records: &[(Hash, Vec<u8>)]) -> Value {
    json!(records.iter().map(|(k, v)| json!({"key": hex::encode(k), "value": hex::encode(v)})).collect::<Vec<_>>())
}

/// Succession cases: (name, expectation, plan, pinned plan, chain genesis, height, proof, result).
type SuccessionCase = (&'static str, &'static str, &'static str, &'static str, &'static str, u64, &'static str, &'static str);
const SUCCESSION: [SuccessionCase; 14] = [
    ("accept_pinned_plan_at_the_trusted_height", "rotation_plan", "PLAN_K1_K2", "PLAN_K1_K2", "trusted", TRUSTED_HEIGHT, "P2", "ACCEPT"),
    ("accept_pinned_plan_at_its_creation_height", "rotation_plan", "PLAN_K1_K2", "PLAN_K1_K2", "trusted", 1, "P2", "ACCEPT"),
    ("accept_pinned_plan_at_its_expiry_height", "rotation_plan", "PLAN_K1_K2", "PLAN_K1_K2", "trusted", 100, "P2", "ACCEPT"),
    ("reject_plan_before_its_creation_height", "rotation_plan", "PLAN_K1_K2", "PLAN_K1_K2", "trusted", 0, "P2", "REJECT PlanOutOfWindow"),
    ("reject_plan_expired_at_the_trusted_height", "rotation_plan", "PLAN_K1_K2", "PLAN_K1_K2", "trusted", 101, "P2", "REJECT PlanOutOfWindow"),
    ("reject_second_validly_signed_plan_not_pinned", "rotation_plan", "PLAN_K1_K3_RIVAL", "PLAN_K1_K2", "trusted", TRUSTED_HEIGHT, "P3_impostor", "REJECT PlanNotAuthorized"),
    ("accept_rival_only_when_it_is_the_pinned_plan", "rotation_plan", "PLAN_K1_K3_RIVAL", "PLAN_K1_K3_RIVAL", "trusted", TRUSTED_HEIGHT, "P3_impostor", "ACCEPT"),
    ("reject_impostor_under_the_pinned_plan", "rotation_plan", "PLAN_K1_K2", "PLAN_K1_K2", "trusted", TRUSTED_HEIGHT, "P3_impostor", "REJECT UnauthorizedSuccessor"),
    ("reject_plan_of_another_chain_identity", "rotation_plan", "PLAN_K1_K2_OTHER_CHAIN", "PLAN_K1_K2_OTHER_CHAIN", "trusted", TRUSTED_HEIGHT, "P2", "REJECT WrongChain"),
    ("reject_plan_when_the_trusted_chain_is_another", "rotation_plan", "PLAN_K1_K2", "PLAN_K1_K2", "other", TRUSTED_HEIGHT, "P2", "REJECT WrongChain"),
    ("accept_canonical_lineage_against_the_trusted_root", "canonical_lineage", "honest", "-", "-", 0, "P2", "ACCEPT"),
    ("reject_impostor_under_canonical_lineage", "canonical_lineage", "honest", "-", "-", 0, "P3_impostor", "REJECT UnauthorizedSuccessor"),
    ("reject_fabricated_lineage_records", "canonical_lineage", "fabricated", "-", "-", 0, "P3_impostor", "REJECT SuccessionUnproven"),
    ("reject_retired_key_under_canonical_lineage", "canonical_lineage", "honest", "-", "-", 0, "P1", "REJECT Proof(WrongKeyVersion)"),
];
/// Post-freeze verdict table: (name, frozen input, approval names the GenesisID, store, result).
const GENESIS: [(&str, &str, bool, &str, &str); 8] = [
    ("parameters_with_approval_without_genesis_id", "frozen_parameters", false, "approved", "PASS"),
    ("parameters_with_approval_naming_a_genesis_id", "frozen_parameters", true, "approved", "REJECT ManifestMismatch"),
    ("descriptor_with_approval_without_genesis_id", "genesis_descriptor", false, "approved", "REJECT GenesisIdNotApproved"),
    ("descriptor_with_approved_genesis_id", "genesis_descriptor", true, "approved", "PASS"),
    ("tampered_descriptor_with_approved_genesis_id", "tampered_genesis_descriptor", true, "approved", "REJECT ManifestMismatch"),
    ("tampered_descriptor_without_genesis_id", "tampered_genesis_descriptor", false, "approved", "REJECT GenesisIdNotApproved"),
    ("changed_parameters", "changed_parameters", false, "approved", "REJECT ManifestMismatch"),
    ("approved_input_in_another_store_of_the_same_ceremony", "frozen_parameters", false, "other", "REJECT WrongStore"),
];
/// Ceremony inputs with more than one defect: (name, proof, expectation, change, result, rule).
const ORDER: [(&str, &str, &str, &str, &str, &str); 8] = [
    ("generation_one_proof_with_class_1", "P1", "generation_one", "class_1", "REJECT Proof(ClassPhaseMismatch)", "I1: a decoder refusal (D1 to D6) is wrapped as Proof(X) by the ceremony layer"),
    ("production_phase_and_wrong_generation", "P5_production_phase", "rotation_plan", "none", "REJECT ProductionRefused", "C1 production refusal precedes every comparison"),
    ("wrong_context_and_wrong_generation", "P4_other_context", "rotation_plan", "none", "REJECT WrongContext", "C4 context precedes C5 generation"),
    ("wrong_generation_and_wrong_treasury", "P7_other_treasury", "rotation_plan", "none", "REJECT Proof(WrongKeyVersion)", "C5 generation precedes C6 Treasury binding"),
    ("wrong_treasury_and_wrong_descriptor", "P7_other_treasury", "generation_one", "none", "REJECT TreasuryMismatch", "C6 Treasury binding precedes C7 expected descriptor"),
    ("impostor_with_a_bad_signature", "P3_impostor", "rotation_plan", "flip_fndsa_bit", "REJECT UnauthorizedSuccessor", "C7 expected descriptor precedes C9 signatures"),
    ("wrong_record_with_an_ed448_only_signature", "P6_production_class_record", "generation_one", "ed448_only", "REJECT Proof(Malformed)", "I2 signature serialization precedes C1 to C9"),
    ("wrong_context_with_a_trailing_byte", "P4_other_context", "generation_one", "trailing_byte", "REJECT Proof(Malformed)", "I1 challenge decode precedes C1 to C9"),
];

struct Ctx {
    c: Ceremony,
    v1: Value,
    plans: BTreeMap<String, Rotation>,
}
impl Ctx {
    fn proof(&self, id: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let p = &self.v1["proofs"][id];
        (bytes(&self.v1["keys"][p["signer"].as_str().unwrap()]["descriptor_hex"]), bytes(&p["challenge_hex"]), bytes(&self.v1["signatures"][id]))
    }
    fn plan_expect(&self, plan: &str, pinned: &str, chain: &str, height: u64) -> Result<Expect, Refusal> {
        let genesis = if chain == "trusted" { plan_genesis() } else { other_genesis() };
        let config = self.c.config.clone().with_trusted_chain(TrustedChain { genesis, height, ..trusted_chain(height) })?.with_authorized_plan(self.plans[pinned].identity().unwrap())?;
        Expect::authorized_rotation(&config, &self.plans[plan])
    }
    fn lineage_expect(&self, which: &str) -> Result<Expect, Refusal> {
        let (records, root) = lineage_state(&self.c.k1.descriptor().unwrap(), &[self.plans["PLAN_K1_K2"].clone()]);
        let presented = if which == "honest" { records } else { fabricated_records(&self.c) };
        Expect::canonical_current(&self.c.config.clone().with_canonical_root(root).unwrap(), &presented)
    }
    fn named_expect(&self, name: &str) -> Result<Expect, Refusal> {
        match name {
            "generation_one" => Ok(Expect::genesis_key(&self.c.config)),
            "rotation_plan" => self.plan_expect("PLAN_K1_K2", "PLAN_K1_K2", "trusted", TRUSTED_HEIGHT),
            _ => self.lineage_expect("honest"),
        }
    }
}

fn genesis_inputs(v1: &Value) -> (Vec<u8>, GenesisDescriptor, GenesisDescriptor) {
    let frozen = &v1["frozen"];
    let descriptor = GenesisDescriptor::decode(&bytes(&frozen["genesis_descriptor_hex"])).unwrap();
    let tampered = GenesisDescriptor { timestamp: 4242, owner: h32("c3-vector-unapproved-owner"), recovery: h32("c3-vector-unapproved-recovery"), ..descriptor.clone() };
    (bytes(&frozen["frozen_parameters_hex"]), descriptor, tampered)
}

fn deterministic(ctx: &Ctx) -> Value {
    let c = &ctx.c;
    let (records, root) = lineage_state(&c.k1.descriptor().unwrap(), &[ctx.plans["PLAN_K1_K2"].clone()]);
    let fabricated = fabricated_records(c);
    let plans: serde_json::Map<String, Value> = plan_specs()
        .iter()
        .map(|(name, from, to, _)| {
            let p = &ctx.plans[*name];
            (name.to_string(), json!({"current": from, "proposed": to, "genesis": hex::encode(p.genesis), "fingerprint": hex::encode(p.fingerprint), "created_height": p.created_height, "expiry_height": p.expiry_height, "unsigned_body_hex": hex::encode(p.unsigned().unwrap()), "identity": hex::encode(p.identity().unwrap())}))
        })
        .collect();
    let succession: Vec<Value> = SUCCESSION
        .iter()
        .map(|(name, e, plan, pinned, chain, height, proof_id, result)| {
            let expectation = if *e == "rotation_plan" {
                json!({"kind": e, "plan": plan, "pinned_plan": pinned, "trusted_chain_genesis": if *chain == "trusted" { "trusted" } else { "other_genesis" }, "trusted_height": height})
            } else {
                json!({"kind": e, "records": plan})
            };
            json!({"name": name, "expectation": expectation, "proof": proof_id, "result": result})
        })
        .collect();
    let (parameters, genesis, tampered) = genesis_inputs(&ctx.v1);
    let raw = genesis.encode().unwrap();
    let p = Parameters::decode(&parameters).unwrap();
    let genesis_verdicts: Vec<Value> = GENESIS.iter().map(|(n, i, g, s, res)| json!({"name": n, "input": i, "approval_names_genesis_id": g, "store": s, "result": res})).collect();
    let order: Vec<Value> = ORDER.iter().map(|(n, p, e, ch, res, rule)| json!({"name": n, "proof": p, "expectation": e, "change": ch, "result": res, "rule": rule})).collect();
    json!({
        "schema": "BUILD8-TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V2-ADDITIONS",
        "synthetic_only": true,
        "test_value": true,
        "production_authorized": false,
        "added_after": "the independent review (F1-F3, F5) and the independent reproduction, round 1 (S1, S2, S4, S5, S6)",
        "note": "Public data only (TEST-VALUE keys from public labels). Extends the V1 ceremony vectors: keys, Treasury record, ceremony context, proofs and signatures are those of the V1 file. Rotation-plan signatures in signed_plans are randomized; every other field is a pure function of the labels and the V1 file. Results follow schema sections 7.0 to 7.5.",
        "extends": {"path": "qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json", "sha256": hex::encode(Sha256::digest(V1.as_bytes()))},
        "trusted_configuration_additions": {
            "trusted_chain": {"network": trusted_chain(TRUSTED_HEIGHT).network, "genesis": hex::encode(plan_genesis()), "fingerprint": hex::encode(plan_fingerprint()), "height": TRUSTED_HEIGHT},
            "other_genesis": hex::encode(other_genesis()),
            "authorized_plan_identity": hex::encode(ctx.plans["PLAN_K1_K2"].identity().unwrap()),
            "plan_identity_rule": "identity = SHA-256(\"MUTINY-BUILD8-WALLET-ROTATION-ID-V1\" || 0x00 || unsigned_body)",
            "canonical_state_root": hex::encode(root),
            "admission_store_id_rule": "a random 32-byte id drawn when the store is created; verify_frozen requires the store to carry the id the approved manifest names (approved: the store P1 was admitted to; other: a second store of the same ceremony to which P1 was admitted again)",
        },
        "rotation_plans": plans,
        "canonical_lineage": {
            "rule": "records of canonical state after registering K1 and applying PLAN_K1_K2 at its creation height; they must reproduce canonical_state_root (schema 7.3)",
            "records": rows(&records),
            "state_root": hex::encode(root),
            "fabricated_records": rows(&fabricated),
            "fabricated_records_state_root": hex::encode(state_root(&fabricated).unwrap()),
        },
        "succession_cases": succession,
        "genesis": {
            "parameters_hex": hex::encode(&parameters),
            "parameters_sha256": hex::encode(Sha256::digest(&parameters)),
            "parameters_items": {"version": 1, "parameters_version": 3, "initial_target": hex::encode(p.initial_target), "rules_hex": hex::encode(p.rules.encode().unwrap()), "rule_fingerprint": hex::encode(p.rules.fingerprint().unwrap()), "treasury_record_hex": hex::encode(p.treasury.as_ref().unwrap().encode().unwrap())},
            "genesis_descriptor_hex": hex::encode(&raw),
            "genesis_descriptor_sha256": hex::encode(Sha256::digest(&raw)),
            "genesis_id_preimage_prefix_hex": hex::encode(b"MUTINY-BUILD8-GENESIS-ID-V1\0"),
            "genesis_id": hex::encode(genesis.id().unwrap()),
            "tampered_genesis_descriptor_hex": hex::encode(tampered.encode().unwrap()),
            "tampered_genesis_id": hex::encode(tampered.id().unwrap()),
            "approved_manifest": {"class": 2, "descriptor_sha256": hex::encode(proof::sha256(c.treasury.descriptor())), "record_sha256": hex::encode(r::record_sha256(&c.treasury).unwrap()), "parameters_sha256": hex::encode(Sha256::digest(&parameters)), "genesis_id_when_named": hex::encode(genesis.id().unwrap()), "admission_store_id": "approved"},
            "verdicts": genesis_verdicts,
        },
        "ceremony_order_probes": order,
    })
}

#[test]
fn ceremony_additions_v2_state_the_trusted_succession_inputs_and_every_verdict_holds() {
    let c = Ceremony::new(TAG);
    let v1: Value = serde_json::from_str(V1).unwrap();
    let generating = std::env::var("BUILD8_TREASURY_CEREMONY_ADDITIONS").ok();
    let committed: Value = serde_json::from_str(COMMITTED).unwrap_or(json!({}));
    // The signed plans: PLAN_K1_K2 is the committed V1 plan; the others come from this file.
    let mut plans = BTreeMap::new();
    plans.insert("PLAN_K1_K2".to_string(), Rotation::decode(&bytes(&v1["rotation_plan_encoded_hex"])).unwrap());
    for (name, ..) in plan_specs().iter().skip(1) {
        // Committed plans are reused (byte-stable regeneration); fresh ones only when absent.
        let plan = match committed["signed_plans"][*name].as_str() {
            Some(hex_plan) => Rotation::decode(&hex::decode(hex_plan).unwrap()).unwrap(),
            None if generating.is_some() => signed_plan(&c, name),
            None => panic!("committed plan {name} missing"),
        };
        plans.insert(name.to_string(), plan);
    }
    let ctx = Ctx { c, v1, plans };
    let fresh = deterministic(&ctx);
    if let Some(path) = generating {
        let mut file = fresh.clone();
        file["signed_plans"] = json!(plan_specs().iter().skip(1).map(|(n, ..)| (n.to_string(), json!(hex::encode(ctx.plans[*n].encode().unwrap())))).collect::<serde_json::Map<_, _>>());
        std::fs::write(path, serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
        return;
    }
    let mut without = committed.clone();
    assert!(without.as_object_mut().unwrap().remove("signed_plans").is_some());
    assert_eq!(without, fresh, "deterministic fields");
    // Signed plans carry the committed bodies and both signatures verify (each is valid by itself).
    for (name, plan) in &ctx.plans {
        assert_eq!(hex::encode(plan.unsigned().unwrap()), fresh["rotation_plans"][name]["unsigned_body_hex"].as_str().unwrap());
        plan.verify(plan.genesis, plan.fingerprint, 1, ctx.c.treasury.authority(), &ctx.c.k1.descriptor().unwrap()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
    let deny = Denylist::default();
    let run = |e: Result<Expect, Refusal>, proof_id: &str| -> String {
        let (d, ch, s) = ctx.proof(proof_id);
        match e {
            Err(x) => format!("REJECT {x:?}"),
            Ok(e) => verdict(r::verify_proof(&e, &d, &ch, &proof::signature_from_bytes(&s).unwrap(), &deny)),
        }
    };
    for case in fresh["succession_cases"].as_array().unwrap() {
        let e = &case["expectation"];
        let expect = if e["kind"] == "rotation_plan" {
            let chain = if e["trusted_chain_genesis"] == "trusted" { "trusted" } else { "other" };
            ctx.plan_expect(e["plan"].as_str().unwrap(), e["pinned_plan"].as_str().unwrap(), chain, e["trusted_height"].as_u64().unwrap())
        } else {
            ctx.lineage_expect(e["records"].as_str().unwrap())
        };
        assert_eq!(run(expect, case["proof"].as_str().unwrap()), case["result"].as_str().unwrap(), "{}", case["name"]);
    }
    // The canonical lineage records reproduce the stated root; the fabricated ones do not.
    let lineage = &fresh["canonical_lineage"];
    let parse_rows = |v: &Value| -> Vec<(Hash, Vec<u8>)> { v.as_array().unwrap().iter().map(|x| (bytes(&x["key"]).try_into().unwrap(), bytes(&x["value"]))).collect() };
    assert_eq!(hex::encode(state_root(&parse_rows(&lineage["records"])).unwrap()), lineage["state_root"].as_str().unwrap());
    assert_ne!(lineage["fabricated_records_state_root"], lineage["state_root"]);
    // Genesis derivation: GenesisID = SHA-256(prefix || descriptor) and the verdict table.
    let g = &fresh["genesis"];
    let raw = bytes(&g["genesis_descriptor_hex"]);
    assert_eq!(hex::encode(Sha256::digest([bytes(&g["genesis_id_preimage_prefix_hex"]), raw.clone()].concat())), g["genesis_id"].as_str().unwrap());
    let (parameters, descriptor, tampered) = genesis_inputs(&ctx.v1);
    let (d1, b1, s1) = ctx.proof("P1");
    let s1 = proof::signature_from_bytes(&s1).unwrap();
    let expect = Expect::genesis_key(&ctx.c.config);
    let dir = support::scratch_dir("additions-genesis");
    let mut stores = BTreeMap::new();
    for name in ["approved", "other"] {
        let path = dir.join(format!("{name}.sqlite"));
        drop(AdmissionStore::create(&path, &ctx.c.config).unwrap());
        AdmissionStore::open(&path, &ctx.c.config).unwrap().admit(&expect, &d1, &b1, &s1, &deny).unwrap();
        stores.insert(name, AdmissionStore::open_read_only(&path, &ctx.c.config).unwrap());
    }
    let approved_id = stores["approved"].store_id();
    for v in g["verdicts"].as_array().unwrap() {
        let (input, is_descriptor) = match v["input"].as_str().unwrap() {
            "frozen_parameters" => (parameters.clone(), false),
            "changed_parameters" => (bytes(&ctx.v1["frozen"]["changed_parameters_hex"]), false),
            "genesis_descriptor" => (descriptor.encode().unwrap(), true),
            _ => (tampered.encode().unwrap(), true),
        };
        let approved = ApprovedManifest {
            class: Class::TestValue,
            descriptor_sha256: proof::sha256(ctx.c.treasury.descriptor()),
            record_sha256: r::record_sha256(&ctx.c.treasury).unwrap(),
            parameters_sha256: Sha256::digest(&parameters).into(),
            genesis_id: v["approval_names_genesis_id"].as_bool().unwrap().then(|| descriptor.id().unwrap()),
            admission_store_id: approved_id,
        };
        let got = match r::verify_frozen(&input, is_descriptor, &expect, &approved, &stores[v["store"].as_str().unwrap()], &b1, &s1) {
            Ok(_) => "PASS".to_string(),
            Err(e) => format!("REJECT {e:?}"),
        };
        assert_eq!(got, v["result"].as_str().unwrap(), "{}", v["name"]);
    }
    drop(stores);
    std::fs::remove_dir_all(&dir).unwrap();
    // Ceremony inputs with more than one defect: input stage (decode_proof), then verify_proof.
    for p in fresh["ceremony_order_probes"].as_array().unwrap() {
        let (d, mut ch, mut s) = ctx.proof(p["proof"].as_str().unwrap());
        match p["change"].as_str().unwrap() {
            "flip_fndsa_bit" => s[114 + 100] ^= 1,
            "ed448_only" => s.truncate(114),
            "trailing_byte" => ch.push(0),
            "class_1" => ch[8] = 0x01,
            _ => {}
        }
        let got = match r::decode_proof(&ch, &s) {
            Err(e) => format!("REJECT {e:?}"),
            Ok((_, sig)) => run_with(&ctx, p["expectation"].as_str().unwrap(), &d, &ch, &sig),
        };
        assert_eq!(got, p["result"].as_str().unwrap(), "{}", p["name"]);
    }
}
fn run_with(ctx: &Ctx, expectation: &str, d: &[u8], ch: &[u8], sig: &HybridSignature) -> String {
    match ctx.named_expect(expectation) {
        Err(e) => format!("REJECT {e:?}"),
        Ok(e) => verdict(r::verify_proof(&e, d, ch, sig, &Denylist::default())),
    }
}

#[test]
fn a_trusted_configuration_without_the_succession_inputs_establishes_no_successor() {
    let c = Ceremony::new(TAG);
    let v1: Value = serde_json::from_str(V1).unwrap();
    let plan = Rotation::decode(&bytes(&v1["rotation_plan_encoded_hex"])).unwrap();
    let (records, _) = lineage_state(&c.k1.descriptor().unwrap(), std::slice::from_ref(&plan));
    assert_eq!(Expect::authorized_rotation(&c.config, &plan), Err(Refusal::SuccessionUnproven));
    assert_eq!(Expect::canonical_current(&c.config, &records), Err(Refusal::SuccessionUnproven));
    let _: CeremonyConfig = c.config.clone();
}

// Historical V1/V2 software model only. Superseded unrestricted admission is
// compiled in this test crate, never exported by the shipping library graph.
// Only paths required by the isolated frozen model are supplied here.
pub use mutiny_consensus_v8::{domain_hash, blocks, execution, genesis_inputs, protocol_manifest, treasury_v1, wallet_rotation_v1, dividend_state_v1, NETWORK_ID};
#[path = "../src/treasury_rehearsal_v1.rs"]
mod treasury_rehearsal_v1;
#[path = "../src/treasury_admission_v1.rs"]
mod treasury_admission_v1;
