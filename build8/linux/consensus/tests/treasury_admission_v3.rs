//! Current V3 public TEST-VALUE issuance/admission checks. Historical V1/V2
//! model verdicts are separate targets, not current freshness evidence.
use mutiny_consensus_v8::{
    treasury_admission_v3::{AdmissionStore, StoreIdentity},
    treasury_rehearsal_v3::{
        self as r, ApprovedManifest, CeremonyConfig, Denylist, Expect, ExpectedContext, Refusal,
    },
    treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::{
    HybridSignature, NETWORK,
    rehearsal_keys_v1::Credential,
    treasury_proof_v1::{self as proof, Challenge, Phase},
};
#[path = "support/treasury_ceremony_support_v3.rs"]
mod support;
#[path = "support/test_dir.rs"]
mod test_dir;
#[path = "../examples/treasury_rehearsal.rs"]
#[allow(dead_code)]
mod tool;
use support::Ceremony;
use test_dir::TestDir;
fn signed(key: &Credential, c: &Challenge) -> (Vec<u8>, Vec<u8>, HybridSignature) {
    let d = key.descriptor().unwrap();
    let s = proof::sign_challenge(key.key(), &d, c).unwrap();
    (d, c.encode().unwrap(), s)
}
fn issued(
    store: &mut AdmissionStore,
    expect: &Expect,
    key: &Credential,
) -> (Vec<u8>, Vec<u8>, HybridSignature) {
    let c = store
        .issue(expect, &key.descriptor().unwrap(), &Denylist::default())
        .unwrap();
    signed(key, &c)
}
fn unissued(
    config: &CeremonyConfig,
    key: &Credential,
    nonce: [u8; 32],
) -> (Vec<u8>, Vec<u8>, HybridSignature) {
    let d = key.descriptor().unwrap();
    let c = Challenge::new(
        &d,
        Phase::Rehearsal,
        config.treasury().authority(),
        r::record_sha256(config.treasury()).unwrap(),
        config.context().value(),
        nonce,
    )
    .unwrap();
    signed(key, &c)
}
#[test]
fn os_issued_challenges_single_consume_and_exact_read_only_audits_survive_restart() {
    let c = Ceremony::new("PUBLIC-v3-flow");
    let expect = Expect::genesis_key(&c.config);
    let deny = Denylist::default();
    let dir = TestDir::new("treasury-v3-flow");
    let path = dir.file("store.sqlite");
    let id = AdmissionStore::create(&path, &c.config).unwrap();
    let mut store = AdmissionStore::open(&path, &c.config, id).unwrap();
    let durability = store.durability().unwrap();
    assert_eq!(durability.synchronous, 3);
    assert_eq!(durability.journal_mode, "delete");
    assert!(!durability.query_only && !durability.read_only);
    let ch = store
        .issue(&expect, &c.k1.descriptor().unwrap(), &deny)
        .unwrap();
    let other = store
        .issue(&expect, &c.k1.descriptor().unwrap(), &deny)
        .unwrap();
    assert_ne!(ch.nonce, [0; 32]);
    assert_ne!(ch.nonce, other.nonce);
    let registered = store.issued(&ch.nonce).unwrap().unwrap();
    assert!(!registered.consumed);
    let (d, b, s) = signed(&c.k1, &ch);
    assert_eq!(registered.challenge, b);
    assert_eq!(registered.descriptor, d);
    r::verify_proof(&store, &expect, &d, &b, &s, &deny).unwrap();
    let mut bad = s.clone();
    bad.fndsa[41] ^= 1;
    assert!(store.admit(&expect, &d, &b, &bad, &deny).is_err());
    assert!(!store.issued(&ch.nonce).unwrap().unwrap().consumed);
    let mut bad = s.clone();
    bad.ed448[17] ^= 1;
    assert!(store.admit(&expect, &d, &b, &bad, &deny).is_err());
    assert!(!store.issued(&ch.nonce).unwrap().unwrap().consumed);
    store.admit(&expect, &d, &b, &s, &deny).unwrap();
    drop(store);
    let before = std::fs::read(&path).unwrap();
    let mut store = AdmissionStore::open(&path, &c.config, id).unwrap();
    assert_eq!(
        store.admit(&expect, &d, &b, &s, &deny),
        Err(Refusal::Replay)
    );
    drop(store);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    for _ in 0..2 {
        let store = AdmissionStore::open_read_only(&path, &c.config, id).unwrap();
        let durability = store.durability().unwrap();
        assert!(durability.query_only && durability.read_only);

        r::verify_proof(&store, &expect, &d, &b, &s, &deny).unwrap();
        r::audit_recorded(&store, &expect, &d, &b, &s, &deny).unwrap();
        let fresh = proof::sign_challenge(c.k1.key(), &d, &ch).unwrap();
        assert_ne!(fresh, s);
        assert_eq!(
            r::verify_proof(&store, &expect, &d, &b, &fresh, &deny),
            Err(Refusal::NotAdmitted)
        );
        let m = r::build_manifest(
            &expect,
            &d,
            &b,
            &s,
            [255; 32],
            &r::rehearsal_rules(),
            &deny,
            &store,
        )
        .unwrap();
        let approved = ApprovedManifest {
            class: Class::TestValue,
            descriptor_sha256: proof::sha256(&d),
            record_sha256: r::record_sha256(&c.treasury).unwrap(),
            parameters_sha256: proof::sha256(&m.parameters),
            genesis_id: None,
            admission_store_id: id.store_id(),
        };
        r::verify_frozen(&m.parameters, false, &expect, &approved, &store, &b, &s).unwrap();
        let genesis = mutiny_consensus_v8::blocks::GenesisDescriptor {
            timestamp: 1,
            nonce: [1; 32],
            fingerprint: r::rehearsal_rules().fingerprint().unwrap(),
            owner: [2; 32],
            purchase: [3; 32],
            parameters: m.parameters.clone(),
            admission_records: vec![],
            recovery: [4; 32],
        };
        let raw = genesis.encode().unwrap();
        let named = ApprovedManifest {
            genesis_id: Some(genesis.id().unwrap()),
            ..approved.clone()
        };
        r::verify_frozen(&raw, true, &expect, &named, &store, &b, &s).unwrap();
        assert_eq!(
            r::verify_frozen(&raw, true, &expect, &approved, &store, &b, &s),
            Err(Refusal::GenesisIdNotApproved)
        );
        let changed = mutiny_consensus_v8::blocks::GenesisDescriptor {
            timestamp: 2,
            ..genesis
        };
        assert_eq!(
            r::verify_frozen(
                &changed.encode().unwrap(),
                true,
                &expect,
                &named,
                &store,
                &b,
                &s
            ),
            Err(Refusal::ManifestMismatch)
        );

        assert_eq!(store.admissions().unwrap().len(), 1);
        drop(store);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
#[test]
fn unissued_nonce_foreign_store_and_invalid_expectation_accept_nothing() {
    let c = Ceremony::new("PUBLIC-v3-unknown");
    let expect = Expect::genesis_key(&c.config);
    let deny = Denylist::default();
    let dir = TestDir::new("treasury-v3-unknown");
    let path = dir.file("store.sqlite");
    let id = AdmissionStore::create(&path, &c.config).unwrap();
    let before = std::fs::read(&path).unwrap();
    let missing = dir.file("missing.sqlite");
    assert_eq!(
        AdmissionStore::open(&missing, &c.config, id).err(),
        Some(Refusal::Store)
    );
    assert!(!missing.exists(), "open must not create a missing store");
    assert_eq!(
        AdmissionStore::open_read_only(&missing, &c.config, id).err(),
        Some(Refusal::Store)
    );
    assert!(
        !missing.exists(),
        "read-only open must not create a missing store"
    );
    assert_eq!(
        StoreIdentity::from_trusted_id([0; 32]),
        Err(Refusal::WrongStore)
    );
    let foreign = StoreIdentity::from_trusted_id([0x91; 32]).unwrap();
    assert_eq!(
        AdmissionStore::open(&path, &c.config, foreign).err(),
        Some(Refusal::WrongStore)
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "wrong ID refused before writable configuration"
    );
    let (d, b, s) = unissued(&c.config, &c.k1, [0x82; 32]);
    Challenge::decode(&b).unwrap().verify(&d, &s).unwrap();
    let mut store = AdmissionStore::open(&path, &c.config, id).unwrap();
    assert_eq!(
        r::verify_proof(&store, &expect, &d, &b, &s, &deny),
        Err(Refusal::UnknownChallenge)
    );
    assert_eq!(
        store.admit(&expect, &d, &b, &s, &deny),
        Err(Refusal::UnknownChallenge)
    );
    assert_eq!(
        store.issue(&expect, &c.stranger.descriptor().unwrap(), &deny),
        Err(Refusal::AlteredDescriptor)
    );
    assert!(store.admissions().unwrap().is_empty());
    drop(store);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let second = dir.file("second.sqlite");
    let second_id = AdmissionStore::create(&second, &c.config).unwrap();
    assert_ne!(id, second_id);
    assert_eq!(
        AdmissionStore::open(&second, &c.config, id).err(),
        Some(Refusal::WrongStore)
    );
    let mut second_store = AdmissionStore::open(&second, &c.config, second_id).unwrap();
    assert_eq!(
        second_store.admit(&expect, &d, &b, &s, &deny),
        Err(Refusal::UnknownChallenge)
    );
}
#[test]
fn issued_successor_requires_exact_trusted_plan_or_canonical_lineage() {
    let c = Ceremony::new("PUBLIC-v3-lineage");
    let plan = c.plan();
    let config = c.plan_config();
    let expect = Expect::authorized_rotation(&config, &plan).unwrap();
    let deny = Denylist::default();
    let dir = TestDir::new("treasury-v3-lineage");
    let path = dir.file("store.sqlite");
    let id = AdmissionStore::create(&path, &config).unwrap();
    let mut store = AdmissionStore::open(&path, &config, id).unwrap();
    assert_eq!(
        store.issue(&expect, &c.k3.descriptor().unwrap(), &deny),
        Err(Refusal::UnauthorizedSuccessor)
    );
    let (d, b, s) = issued(&mut store, &expect, &c.k2);
    store.admit(&expect, &d, &b, &s, &deny).unwrap();
    let (canonical, records) = c.lineage_config();
    let current = Expect::canonical_current(&canonical, &records).unwrap();
    r::audit_recorded(&store, &current, &d, &b, &s, &deny).unwrap();
    assert!(
        store
            .issue(&current, &c.k1.descriptor().unwrap(), &deny)
            .is_err()
    );
    let other =
        CeremonyConfig::rehearsal(NETWORK, c.treasury.clone(), "PUBLIC-foreign-context").unwrap();
    assert_eq!(
        store.issue(
            &Expect::genesis_key(&other),
            &c.k1.descriptor().unwrap(),
            &deny
        ),
        Err(Refusal::StoreBinding)
    );
}
#[test]
fn concurrent_current_admission_consumes_one_registered_issuance_once() {
    let c = Ceremony::new("PUBLIC-v3-race");
    let expect = Expect::genesis_key(&c.config);
    let dir = TestDir::new("treasury-v3-race");
    let path = dir.file("store.sqlite");
    let id = AdmissionStore::create(&path, &c.config).unwrap();
    let mut store = AdmissionStore::open(&path, &c.config, id).unwrap();
    let (d, b, s) = issued(&mut store, &expect, &c.k1);
    drop(store);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let (path, config, expect, d, b, s, barrier) = (
            path.clone(),
            c.config.clone(),
            expect.clone(),
            d.clone(),
            b.clone(),
            s.clone(),
            barrier.clone(),
        );
        threads.push(std::thread::spawn(move || {
            let mut store = AdmissionStore::open(&path, &config, id).unwrap();
            barrier.wait();
            store
                .admit(&expect, &d, &b, &s, &Denylist::default())
                .map(|_| ())
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(Refusal::Replay))
            .count(),
        3
    );
}
#[test]
fn same_id_snapshot_rollback_is_not_protected_and_production_entry_stays_disabled() {
    let c = Ceremony::new("PUBLIC-v3-rollback");
    let expect = Expect::genesis_key(&c.config);
    let deny = Denylist::default();
    let dir = TestDir::new("treasury-v3-rollback");
    let path = dir.file("store.sqlite");
    let id = AdmissionStore::create(&path, &c.config).unwrap();
    let mut store = AdmissionStore::open(&path, &c.config, id).unwrap();
    let (d, b, s) = issued(&mut store, &expect, &c.k1);
    drop(store);
    let snapshot = std::fs::read(&path).unwrap();
    let mut store = AdmissionStore::open(&path, &c.config, id).unwrap();
    store.admit(&expect, &d, &b, &s, &deny).unwrap();
    drop(store);
    // Explicit TEST-VALUE limitation: the same-ID pre-consume snapshot restores
    // issuance. This is why a DB-only guard cannot enable a production ceremony.
    std::fs::write(&path, &snapshot).unwrap();
    let mut restored = AdmissionStore::open(&path, &c.config, id).unwrap();
    assert!(restored.admit(&expect, &d, &b, &s, &deny).is_ok());
    drop(restored);
    let production = CeremonyConfig::new(
        NETWORK,
        Treasury::new(Class::Production, d.clone()).unwrap(),
        ExpectedContext::production_supplied([0x51; 32]).unwrap(),
    )
    .unwrap();
    let forbidden = dir.file("production.sqlite");
    assert_eq!(
        AdmissionStore::create(&forbidden, &production),
        Err(Refusal::ProductionRefused)
    );
    assert!(!forbidden.exists());
    assert_eq!(
        AdmissionStore::open(&path, &production, id).err(),
        Some(Refusal::ProductionRefused)
    );
    assert_eq!(
        AdmissionStore::open_read_only(&path, &production, id).err(),
        Some(Refusal::ProductionRefused)
    );
    let mut test_store = AdmissionStore::open(&path, &c.config, id).unwrap();
    let production_expect = Expect::genesis_key(&production);
    assert_eq!(
        test_store.issue(&production_expect, &d, &deny),
        Err(Refusal::ProductionRefused)
    );
    assert_eq!(
        test_store.admit(&production_expect, &d, &b, &s, &deny),
        Err(Refusal::ProductionRefused)
    );
}

fn run_tool(args: &[String]) -> (i32, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = tool::run(args, &mut out, &mut err);
    (
        result,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}
#[test]
fn current_tool_requires_trusted_id_and_registry_before_acceptance() {
    let c = Ceremony::new("PUBLIC-v3-tool");
    let dir = TestDir::new("treasury-v3-tool");
    let key_path = dir.file("key.hex");
    let store_path = dir.file("store.sqlite");
    let challenge_path = dir.file("challenge.hex");
    let signature_path = dir.file("signature.hex");
    std::fs::write(&key_path, hex::encode(c.k1.descriptor().unwrap())).unwrap();
    let trusted = vec![
        "--treasury-descriptor-file".into(),
        key_path.to_str().unwrap().into(),
        "--expected-record-sha256".into(),
        hex::encode(r::record_sha256(&c.treasury).unwrap()),
        "--context-label".into(),
        c.label.clone(),
    ];
    let command = |name: &str, extra: Vec<String>| {
        let mut args = vec![name.into()];
        args.extend(trusted.clone());
        args.extend(extra);
        args
    };
    let (code, out, err) = run_tool(&command(
        "create-store",
        vec!["--store".into(), store_path.to_str().unwrap().into()],
    ));
    assert_eq!(code, 0, "{err}");
    let id = out
        .lines()
        .find_map(|line| line.strip_prefix("store_id "))
        .unwrap()
        .to_string();
    let issue_args = vec![
        "--generation".into(),
        "1".into(),
        "--descriptor-file".into(),
        key_path.to_str().unwrap().into(),
        "--store".into(),
        store_path.to_str().unwrap().into(),
        "--out".into(),
        challenge_path.to_str().unwrap().into(),
    ];
    let before = std::fs::read(&store_path).unwrap();
    assert_ne!(run_tool(&command("challenge", issue_args.clone())).0, 0);
    assert_eq!(std::fs::read(&store_path).unwrap(), before);
    assert!(!challenge_path.exists());
    let mut args = issue_args.clone();
    args.extend(["--expected-store-id".into(), hex::encode([0x92; 32])]);
    assert_ne!(run_tool(&command("challenge", args)).0, 0);
    assert_eq!(std::fs::read(&store_path).unwrap(), before);
    let mut args = issue_args.clone();
    args.extend(["--expected-store-id".into(), id.clone()]);
    for rejected in [
        vec!["--nonce-label".into(), "PUBLIC-prover-nonce".into()],
        vec!["--os-nonce".into()],
    ] {
        let mut provided = args.clone();
        provided.extend(rejected);
        assert_ne!(run_tool(&command("challenge", provided)).0, 0);
        assert_eq!(std::fs::read(&store_path).unwrap(), before);
        assert!(
            !challenge_path.exists(),
            "caller nonce flags refused before issuance"
        );
    }
    let (code, _, err) = run_tool(&command("challenge", args.clone()));
    assert_eq!(code, 0, "{err}");
    let bytes = hex::decode(std::fs::read_to_string(&challenge_path).unwrap().trim()).unwrap();
    let ch = Challenge::decode(&bytes).unwrap();
    let signature = proof::sign_challenge(c.k1.key(), &c.k1.descriptor().unwrap(), &ch).unwrap();
    std::fs::write(
        &signature_path,
        hex::encode(proof::signature_to_bytes(&signature)),
    )
    .unwrap();
    let proof_args = vec![
        "--generation".into(),
        "1".into(),
        "--descriptor-file".into(),
        key_path.to_str().unwrap().into(),
        "--challenge-file".into(),
        challenge_path.to_str().unwrap().into(),
        "--signature-file".into(),
        signature_path.to_str().unwrap().into(),
        "--store".into(),
        store_path.to_str().unwrap().into(),
        "--expected-store-id".into(),
        id,
    ];
    let (code, _, err) = run_tool(&command("verify", proof_args.clone()));
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run_tool(&command("admit", proof_args.clone()));
    assert_eq!(code, 0, "{err}");
    assert_ne!(run_tool(&command("admit", proof_args.clone())).0, 0);
    let final_bytes = std::fs::read(&store_path).unwrap();
    let mut checks = proof_args;
    checks.push("--negative-controls".into());
    let (code, out, err) = run_tool(&command("verify", checks));
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("[FAIL]"));
    assert_eq!(std::fs::read(&store_path).unwrap(), final_bytes);
    let challenge_before = std::fs::read(&challenge_path).unwrap();
    assert_ne!(run_tool(&command("challenge", args)).0, 0);
    assert_eq!(std::fs::read(&challenge_path).unwrap(), challenge_before);
    assert_eq!(std::fs::read(&store_path).unwrap(), final_bytes);
}

#[test]
fn foreign_schema_is_refused_without_repair_or_migration() {
    let c = Ceremony::new("PUBLIC-v3-schema");
    let dir = TestDir::new("treasury-v3-schema");
    for (name, change) in [
        (
            "v2.sqlite",
            "UPDATE store_binding SET schema='MUTINY-D2-TREASURY-ADMISSION-STORE-V2'",
        ),
        ("extra.sqlite", "CREATE TABLE untrusted_extra(x)"),
    ] {
        let path = dir.file(name);
        let id = AdmissionStore::create(&path, &c.config).unwrap();
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(change).unwrap();
        drop(db);
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            AdmissionStore::open(&path, &c.config, id).err(),
            Some(Refusal::StoreBinding)
        );
        assert_eq!(
            AdmissionStore::open_read_only(&path, &c.config, id).err(),
            Some(Refusal::StoreBinding)
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "foreign evidence is neither repaired nor migrated"
        );
    }
}

#[test]
fn current_denylist_applies_to_admission_and_authenticated_audit() {
    let c = Ceremony::new("PUBLIC-v3-deny-policy");
    let expect = Expect::genesis_key(&c.config);
    let deny = Denylist::default();
    let denied = deny
        .clone()
        .with_hex_lines(&hex::encode(c.k1.key_sha256()))
        .unwrap();
    let dir = TestDir::new("treasury-v3-deny-policy");
    let path = dir.file("store.sqlite");
    let id = AdmissionStore::create(&path, &c.config).unwrap();
    let mut store = AdmissionStore::open(&path, &c.config, id).unwrap();
    let (d, b, s) = issued(&mut store, &expect, &c.k1);
    assert_eq!(
        store.admit(&expect, &d, &b, &s, &denied),
        Err(Refusal::Denylisted)
    );
    assert_eq!(
        r::verify_proof(&store, &expect, &d, &b, &s, &denied),
        Err(Refusal::Denylisted)
    );
    assert!(
        !store
            .issued(&Challenge::decode(&b).unwrap().nonce)
            .unwrap()
            .unwrap()
            .consumed
    );
    store.admit(&expect, &d, &b, &s, &deny).unwrap();
    drop(store);
    let before = std::fs::read(&path).unwrap();
    let audit = AdmissionStore::open_read_only(&path, &c.config, id).unwrap();
    assert_eq!(
        r::audit_recorded(&audit, &expect, &d, &b, &s, &denied),
        Err(Refusal::Denylisted)
    );
    r::audit_recorded(&audit, &expect, &d, &b, &s, &deny).unwrap();
    drop(audit);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
