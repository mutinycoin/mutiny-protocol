//! Treasury proof-of-control closure (Architect order section 7), ceremony layer:
//! trusted expectations, succession (canonical lineage authenticated against a trusted StateRoot / the
//! exact pinned rotation plan on the trusted chain at the trusted height), durable single-use admission
//! in an identified store with repeatable read-only audits, comparison of the frozen Genesis with the
//! independently approved manifest, and the checking side of the production ceremony context. Includes
//! the negative tests for the independent review's findings F1-F9 (scratch tests r1-r9).
//! SIMULATED / TEST-VALUE evidence only (keys derive from public labels; Windows-host software runs).
use mutiny_consensus_v8::{
    Hash,
    blocks::GenesisDescriptor,
    genesis_inputs::Parameters,
    treasury_v1::{Class, Treasury},
    wallet_authority_v1::{address_key, current_key},
};
use crate::{
    treasury_admission_v1::{AdmissionStore, STORE_SCHEMA},
    treasury_rehearsal_v1::{self as r, ApprovedManifest, CeremonyConfig, Denylist, ExpectedContext, Expect, Refusal, TrustedChain},
};
use mutiny_crypto_v2::{
    Domain, NETWORK, PublicKey,
    treasury_proof_v1::{self as proof, Challenge, Phase, ProofError},
};
use std::collections::BTreeMap;

#[path = "support/treasury_ceremony_support.rs"]
mod support;
use support::{Ceremony, TRUSTED_HEIGHT, h32, plan_fingerprint, plan_genesis, proof_for, trusted_chain};

fn deny() -> Denylist {
    Denylist::default()
}
fn approval(c: &Ceremony, parameters: &[u8], store: &AdmissionStore, genesis_id: Option<Hash>) -> ApprovedManifest {
    ApprovedManifest {
        class: Class::TestValue,
        descriptor_sha256: proof::sha256(c.treasury.descriptor()),
        record_sha256: r::record_sha256(&c.treasury).unwrap(),
        parameters_sha256: proof::sha256(parameters),
        genesis_id,
        admission_store_id: store.store_id(),
    }
}

#[test]
fn internally_consistent_proofs_that_differ_from_the_trusted_expectation_are_refused() {
    let c = Ceremony::new("c3-trust");
    let expect = Expect::genesis_key(&c.config);
    let (d1, b1, s1) = proof_for(&c.config, &c.k1, h32("trust-n1"));
    // Control: the expected proof is accepted (so every refusal below is not vacuous).
    assert!(r::verify_proof(&expect, &d1, &b1, &s1, &deny()).is_ok());

    // Wrong context: a proof made for ANOTHER rehearsal (self-consistent, validly signed).
    let other = CeremonyConfig::rehearsal(NETWORK, c.treasury.clone(), "c3-trust-other").unwrap();
    let (d, b, s) = proof_for(&other, &c.k1, h32("trust-n2"));
    assert!(r::verify_proof(&Expect::genesis_key(&other), &d, &b, &s, &deny()).is_ok(), "valid for its own ceremony");
    assert_eq!(r::verify_proof(&expect, &d, &b, &s, &deny()), Err(Refusal::WrongContext));

    // Wrong Treasury: the stranger's own Treasury (consistent with itself), presented to this ceremony.
    let stranger_treasury = Treasury::new(Class::TestValue, c.stranger.descriptor().unwrap()).unwrap();
    let stranger_config = CeremonyConfig::rehearsal(NETWORK, stranger_treasury, &c.label).unwrap();
    let (d, b, s) = proof_for(&stranger_config, &c.stranger, h32("trust-n3"));
    assert!(r::verify_proof(&Expect::genesis_key(&stranger_config), &d, &b, &s, &deny()).is_ok());
    assert_eq!(r::verify_proof(&expect, &d, &b, &s, &deny()), Err(Refusal::TreasuryMismatch));

    // Same authority, another record (the same descriptor sealed as PRODUCTION class): the record hash
    // differs, so the binding fails although the authority matches (review mutant M10b).
    let production_record = Treasury::new(Class::Production, d1.clone()).unwrap();
    let same_authority = Challenge::new(&d1, Phase::Rehearsal, c.treasury.authority(), r::record_sha256(&production_record).unwrap(), c.config.context().value(), h32("trust-n6")).unwrap();
    let (d, b, s) = support::signed(&c.k1, &same_authority);
    assert_eq!(r::verify_proof(&expect, &d, &b, &s, &deny()), Err(Refusal::TreasuryMismatch));
    // Wrong descriptor at generation 1: the stranger signs THIS Treasury's public identifiers.
    let (d, b, s) = proof_for(&c.config, &c.stranger, h32("trust-n4"));
    assert_eq!(r::verify_proof(&expect, &d, &b, &s, &deny()), Err(Refusal::AlteredDescriptor));

    // Wrong generation: the generation-1 proof against the expectation of the authorized successor.
    let successor = Expect::authorized_rotation(&c.plan_config(), &c.plan()).unwrap();
    assert_eq!(successor.generation(), 2);
    assert_eq!(r::verify_proof(&successor, &d1, &b1, &s1, &deny()), Err(Refusal::Proof(ProofError::WrongKeyVersion)));

    // Wrong class / phase: a production-phase proof (class 1, raw TEST-VALUE signature made only as a
    // negative control) is refused, and so is any production configuration.
    let pc = Challenge::new(&d1, Phase::Production, c.treasury.authority(), r::record_sha256(&c.treasury).unwrap(), c.config.context().value(), h32("trust-n5")).unwrap();
    assert_eq!(proof::sign_challenge(c.k1.key(), &d1, &pc), Err(ProofError::ProductionRefused));
    let praw = c.k1.key().sign(Domain::TreasuryProofOfControl, &pc.encode().unwrap()).unwrap();
    assert_eq!(r::verify_proof(&expect, &d1, &pc.encode().unwrap(), &praw, &deny()), Err(Refusal::ProductionRefused));
    let production = Treasury::new(Class::Production, d1.clone()).unwrap();
    assert_eq!(CeremonyConfig::rehearsal(NETWORK, production.clone(), &c.label), Err(Refusal::ClassMismatch), "a rehearsal never expects a production record");
    assert_eq!(
        CeremonyConfig::new(NETWORK, c.treasury.clone(), ExpectedContext::production_supplied(h32("p")).unwrap()),
        Err(Refusal::ClassMismatch),
        "a production context never expects a TEST-VALUE record"
    );
    let production_config = CeremonyConfig::new(NETWORK, production, ExpectedContext::production_supplied(h32("p")).unwrap()).unwrap();
    assert_eq!(r::verify_proof(&Expect::genesis_key(&production_config), &d1, &b1, &s1, &deny()), Err(Refusal::ProductionRefused));

    // Wrong network in the trusted configuration.
    assert_eq!(CeremonyConfig::rehearsal(NETWORK ^ 1, c.treasury.clone(), &c.label), Err(Refusal::WrongNetwork));
    assert_eq!(c.config.clone().with_trusted_chain(TrustedChain { network: NETWORK ^ 1, ..trusted_chain(1) }), Err(Refusal::WrongNetwork));

    // Class/phase mismatch inside the payload (class 1 with phase 1) never decodes.
    let mut mixed = Challenge::decode(&b1).unwrap();
    mixed.class = proof::CLASS_PRODUCTION;
    let mixed_bytes = mixed.encode_unchecked();
    assert_eq!(r::verify_proof(&expect, &d1, &mixed_bytes, &s1, &deny()), Err(Refusal::Proof(ProofError::ClassPhaseMismatch)));
}

/// F1 (review r1): canonical lineage is authenticated against the trusted StateRoot. Fabricated wallet
/// records that name the impostor K3 as the current key (no K1 signature anywhere) do not reproduce the
/// trusted root; the honest lineage does, and still refuses K3.
#[test]
fn r1_a_fabricated_lineage_does_not_reproduce_the_trusted_state_root() {
    let c = Ceremony::new("c3-r1");
    let (config, records) = c.lineage_config();
    let canonical = Expect::canonical_current(&config, &records).unwrap();
    assert_eq!(canonical.generation(), 2);
    let (d2, b2, s2) = proof_for(&c.config, &c.k2, h32("r1-n2"));
    let (d3, b3, s3) = proof_for(&c.config, &c.k3, h32("r1-n3"));
    assert!(r::verify_proof(&canonical, &d2, &b2, &s2, &deny()).is_ok());
    assert_eq!(r::verify_proof(&canonical, &d3, &b3, &s3, &deny()), Err(Refusal::UnauthorizedSuccessor));
    // The reviewer's fabricated book: hand-encoded records, K3 current at generation 2.
    let id = c.treasury.authority();
    let (k1d, k3d) = (c.k1.descriptor().unwrap(), c.k3.descriptor().unwrap());
    let record = |kind: u8, raw: &[u8]| {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4).unwrap().u8(1).unwrap().u8(kind).unwrap().bytes(&id).unwrap().bytes(raw).unwrap();
        e.into_writer()
    };
    let addr = |raw: &[u8]| {
        let (p, g) = PublicKey::decode_descriptor(raw).unwrap();
        p.address_id(g).unwrap()
    };
    let mut fabricated = BTreeMap::new();
    fabricated.insert(current_key(id), record(30, &k3d));
    fabricated.insert(address_key(addr(&k1d)), record(31, &k1d));
    fabricated.insert(address_key(addr(&k3d)), record(31, &k3d));
    let fabricated: Vec<(Hash, Vec<u8>)> = fabricated.into_iter().collect();
    assert_eq!(Expect::canonical_current(&config, &fabricated), Err(Refusal::SuccessionUnproven), "fabricated records against the trusted root");
    // One honest record altered: the root no longer matches.
    let mut altered = records.clone();
    altered[0].1.push(0);
    assert_eq!(Expect::canonical_current(&config, &altered), Err(Refusal::SuccessionUnproven));
    // No trusted root in the configuration: no lineage at all.
    assert_eq!(Expect::canonical_current(&c.config, &records), Err(Refusal::SuccessionUnproven));
    // A canonical state that carries a Treasury record must carry exactly the trusted one: the same
    // wallet lineage under the trusted record is accepted, under another record it is refused.
    let (with_trusted, root_t) = support::lineage_state_with(Some(&c.treasury), &k1d, &[c.plan()]);
    let at_trusted = Expect::canonical_current(&c.config.clone().with_canonical_root(root_t).unwrap(), &with_trusted).unwrap();
    assert_eq!(at_trusted.descriptor_sha256(), canonical.descriptor_sha256());
    let other_record = Treasury::new(Class::TestValue, c.stranger.descriptor().unwrap()).unwrap();
    let (with_other, root_o) = support::lineage_state_with(Some(&other_record), &k1d, &[c.plan()]);
    assert_eq!(Expect::canonical_current(&c.config.clone().with_canonical_root(root_o).unwrap(), &with_other), Err(Refusal::SuccessionUnproven), "a state of another Treasury record");
    // Records of a valid state presented with the root of another valid state.
    assert_eq!(Expect::canonical_current(&c.config.clone().with_canonical_root(root_t).unwrap(), &records), Err(Refusal::SuccessionUnproven));
}

/// F2 / S1 / S6 (review r2, r9): only the exact pinned plan, on the trusted chain, at the trusted height,
/// with both rotation signatures, establishes a successor.
#[test]
fn r2_only_the_pinned_plan_on_the_trusted_chain_at_the_trusted_height_establishes_a_successor() {
    let c = Ceremony::new("c3-r2");
    let plan = c.plan();
    let config = c.plan_config();
    let by_plan = Expect::authorized_rotation(&config, &plan).unwrap();
    let (d2, b2, s2) = proof_for(&c.config, &c.k2, h32("r2-n2"));
    let (d3, b3, s3) = proof_for(&c.config, &c.k3, h32("r2-n3"));
    Challenge::decode(&b3).unwrap().verify(&d3, &s3).expect("impostor proof is cryptographically valid");
    assert_eq!(r::verify_proof(&by_plan, &d2, &b2, &s2, &deny()).map(|p| p.generation), Ok(2));
    assert_eq!(r::verify_proof(&by_plan, &d3, &b3, &s3, &deny()), Err(Refusal::UnauthorizedSuccessor));
    // A rival plan K1 -> K3, validly signed by K1 (and possessed by K3), is not the pinned plan.
    let (k1d, k3d) = (c.k1.descriptor().unwrap(), c.k3.descriptor().unwrap());
    let rival = support::rotation_plan(c.treasury.authority(), c.k1.key(), k1d.clone(), c.k3.key(), k3d.clone(), plan_genesis(), plan_fingerprint());
    assert_eq!(Expect::authorized_rotation(&config, &rival), Err(Refusal::PlanNotAuthorized));
    // The pin decides: pinning the rival names K3 (so the pin is the trusted input, not the plan file).
    let rival_pinned = c.config.clone().with_trusted_chain(trusted_chain(TRUSTED_HEIGHT)).unwrap().with_authorized_plan(rival.identity().unwrap()).unwrap();
    assert!(r::verify_proof(&Expect::authorized_rotation(&rival_pinned, &rival).unwrap(), &d3, &b3, &s3, &deny()).is_ok());
    // The chain identity comes from the configuration: the plan's own fields do not make it trusted.
    for (genesis, fingerprint) in [(h32("another-genesis"), plan_fingerprint()), (plan_genesis(), h32("another-fingerprint"))] {
        let other_chain = c.config.clone().with_trusted_chain(TrustedChain { genesis, fingerprint, ..trusted_chain(TRUSTED_HEIGHT) }).unwrap();
        let pinned = other_chain.with_authorized_plan(plan.identity().unwrap()).unwrap();
        assert_eq!(Expect::authorized_rotation(&pinned, &plan), Err(Refusal::WrongChain));
    }
    // Validity window at the trusted height: [created 1, expiry 100] inclusive.
    for (height, ok) in [(0u64, false), (1, true), (100, true), (101, false), (u64::MAX, false)] {
        let at = c.config.clone().with_trusted_chain(trusted_chain(height)).unwrap().with_authorized_plan(plan.identity().unwrap()).unwrap();
        let got = Expect::authorized_rotation(&at, &plan);
        if ok {
            assert!(got.is_ok(), "height {height}: {got:?}");
        } else {
            assert_eq!(got, Err(Refusal::PlanOutOfWindow), "height {height}");
        }
    }
    // Missing trusted inputs: no succession.
    assert_eq!(Expect::authorized_rotation(&c.config, &plan), Err(Refusal::SuccessionUnproven));
    let no_pin = c.config.clone().with_trusted_chain(trusted_chain(TRUSTED_HEIGHT)).unwrap();
    assert_eq!(Expect::authorized_rotation(&no_pin, &plan), Err(Refusal::SuccessionUnproven));
    // Bad signatures under the pinned identity (the identity covers the unsigned body only).
    let mut no_possession = plan.clone();
    no_possession.possession.fndsa[7] ^= 1;
    assert_eq!(Expect::authorized_rotation(&config, &no_possession), Err(Refusal::SuccessionUnproven));
    let body = plan.unsigned().unwrap();
    let mut swapped_auth = plan.clone();
    swapped_auth.authorization = c.k1.key().sign(Domain::WalletRotatePossession, &body).unwrap();
    assert_eq!(Expect::authorized_rotation(&config, &swapped_auth), Err(Refusal::SuccessionUnproven));
    let mut other_possessor = plan.clone();
    other_possessor.possession = c.k3.key().sign(Domain::WalletRotatePossession, &body).unwrap();
    assert_eq!(Expect::authorized_rotation(&config, &other_possessor), Err(Refusal::SuccessionUnproven));
    let mut proof_domain = plan.clone();
    proof_domain.authorization = c.k1.key().sign(Domain::TreasuryProofOfControl, &body).unwrap();
    assert_eq!(Expect::authorized_rotation(&config, &proof_domain), Err(Refusal::SuccessionUnproven));
    // A plan altered after signing has another identity.
    let mut forged = plan.clone();
    forged.proposed = k3d.clone();
    assert_eq!(Expect::authorized_rotation(&config, &forged), Err(Refusal::PlanNotAuthorized));
    // A plan by a key that is not the Treasury key, even if pinned, establishes nothing.
    let foreign = support::rotation_plan(c.treasury.authority(), c.stranger.key(), c.stranger.descriptor().unwrap(), c.k3.key(), k3d, plan_genesis(), plan_fingerprint());
    let foreign_pinned = c.config.clone().with_trusted_chain(trusted_chain(TRUSTED_HEIGHT)).unwrap().with_authorized_plan(foreign.identity().unwrap()).unwrap();
    assert_eq!(Expect::authorized_rotation(&foreign_pinned, &foreign), Err(Refusal::SuccessionUnproven));
}

#[test]
fn an_impostor_successor_is_refused_under_the_rotation_plan_and_under_canonical_lineage() {
    let c = Ceremony::new("c3-succ");
    let by_plan = Expect::authorized_rotation(&c.plan_config(), &c.plan()).unwrap();
    let (d2, b2, s2) = proof_for(&c.config, &c.k2, h32("succ-n2"));
    let (d3, b3, s3) = proof_for(&c.config, &c.k3, h32("succ-n3"));
    // The crypto layer alone accepts BOTH: each is a self-consistent proof by its own key that binds the
    // Treasury's public identifiers. Only succession separates them.
    Challenge::decode(&b3).unwrap().verify(&d3, &s3).expect("impostor proof is cryptographically valid");
    assert_eq!(r::verify_proof(&by_plan, &d2, &b2, &s2, &deny()).map(|p| p.generation), Ok(2));
    assert_eq!(r::verify_proof(&by_plan, &d3, &b3, &s3, &deny()), Err(Refusal::UnauthorizedSuccessor));
    // Canonical lineage after the canonical rotation transition names the same successor.
    let (config, records) = c.lineage_config();
    let canonical = Expect::canonical_current(&config, &records).unwrap();
    assert_eq!(canonical.descriptor_sha256(), by_plan.descriptor_sha256(), "the canonical successor is the planned one");
    assert!(r::verify_proof(&canonical, &d2, &b2, &s2, &deny()).is_ok());
    assert_eq!(r::verify_proof(&canonical, &d3, &b3, &s3, &deny()), Err(Refusal::UnauthorizedSuccessor));
    // The retired generation-1 key no longer proves control of the Treasury.
    let (d1, b1, s1) = proof_for(&c.config, &c.k1, h32("succ-n1"));
    assert_eq!(r::verify_proof(&canonical, &d1, &b1, &s1, &deny()), Err(Refusal::Proof(ProofError::WrongKeyVersion)));
    // Before any rotation the current key is the record's key.
    let (records0, root0) = support::lineage_state(&c.k1.descriptor().unwrap(), &[]);
    let at_genesis = Expect::canonical_current(&c.config.clone().with_canonical_root(root0).unwrap(), &records0).unwrap();
    assert_eq!(at_genesis.generation(), 1);
    // A state without this Treasury establishes nothing.
    let (records_s, root_s) = support::lineage_state(&c.stranger.descriptor().unwrap(), &[]);
    assert_eq!(Expect::canonical_current(&c.config.clone().with_canonical_root(root_s).unwrap(), &records_s), Err(Refusal::SuccessionUnproven));
}

#[test]
fn first_admission_consumes_the_nonce_durably_and_audits_are_read_only_and_repeatable() {
    let c = Ceremony::new("c3-nonce");
    let expect = Expect::genesis_key(&c.config);
    let (d1, b1, s1) = proof_for(&c.config, &c.k1, h32("nonce-n1"));
    let dir = support::scratch_dir("nonce");
    let path = dir.join("admissions.sqlite");
    // Explicit creation; an open never creates; an existing file is never re-created.
    assert_eq!(AdmissionStore::open(&path, &c.config).err(), Some(Refusal::Store));
    assert_eq!(AdmissionStore::open_read_only(&path, &c.config).err(), Some(Refusal::Store));
    assert!(!path.exists());
    let created = AdmissionStore::create(&path, &c.config).unwrap();
    let store_id = created.store_id();
    assert_ne!(store_id, [0; 32]);
    drop(created);
    assert_eq!(AdmissionStore::create(&path, &c.config).err(), Some(Refusal::Store));
    let empty = support::file_sha256(&path);

    // Refused attempts consume nothing and leave the file byte-identical.
    let mut store = AdmissionStore::open(&path, &c.config).unwrap();
    assert_eq!(store.store_id(), store_id, "the id survives a reopen");
    let mut bad = s1.clone();
    bad.fndsa[100] ^= 1;
    assert_eq!(store.admit(&expect, &d1, &b1, &bad, &deny()), Err(Refusal::Proof(ProofError::BadSignature)));
    let (d3, b3, s3) = proof_for(&c.config, &c.k3, h32("nonce-n3"));
    let plan_expect = Expect::authorized_rotation(&c.plan_config(), &c.plan()).unwrap();
    assert_eq!(store.admit(&plan_expect, &d3, &b3, &s3, &deny()), Err(Refusal::UnauthorizedSuccessor));
    drop(store);
    assert_eq!(support::file_sha256(&path), empty);

    // FIRST ADMISSION.
    let mut store = AdmissionStore::open(&path, &c.config).unwrap();
    let admitted = store.admit(&expect, &d1, &b1, &s1, &deny()).unwrap();
    assert_eq!(admitted.nonce, h32("nonce-n1"));
    // The same proof again, and a DIFFERENT valid proof under the same nonce (the successor's), are replays.
    assert_eq!(store.admit(&expect, &d1, &b1, &s1, &deny()), Err(Refusal::Replay));
    let (d2, b2, s2) = proof_for(&c.config, &c.k2, h32("nonce-n1"));
    assert!(r::verify_proof(&plan_expect, &d2, &b2, &s2, &deny()).is_ok());
    assert_eq!(store.admit(&plan_expect, &d2, &b2, &s2, &deny()), Err(Refusal::Replay));
    drop(store);
    let after_first = support::file_sha256(&path);
    assert_ne!(after_first, empty);

    // Restart: the record survives; a replayed admission still fails and changes nothing.
    let mut store = AdmissionStore::open(&path, &c.config).unwrap();
    assert_eq!(store.admissions().unwrap().len(), 1);
    assert_eq!(store.admit(&expect, &d1, &b1, &s1, &deny()), Err(Refusal::Replay));
    drop(store);
    assert_eq!(support::file_sha256(&path), after_first);

    // Audits through a READ-ONLY store: repeatable, consume nothing, cannot write.
    for _ in 0..2 {
        let audit = AdmissionStore::open_read_only(&path, &c.config).unwrap();
        assert!(audit.is_read_only());
        assert_eq!(r::audit_recorded(&audit, &expect, &d1, &b1, &s1, &deny()), Ok(admitted.clone()));
        drop(audit);
        assert_eq!(support::file_sha256(&path), after_first, "an audit leaves the store byte-identical");
    }
    let mut audit = AdmissionStore::open_read_only(&path, &c.config).unwrap();
    let (d4, b4, s4) = proof_for(&c.config, &c.k1, h32("nonce-n4"));
    assert_eq!(audit.admit(&expect, &d4, &b4, &s4, &deny()), Err(Refusal::Store), "a read-only store never admits");
    // ... and refuses before looking at the proof or the expectation (review mutant M4b).
    assert_eq!(audit.admit(&expect, &d1, &b1, &bad, &deny()), Err(Refusal::Store));
    assert_eq!(audit.admit(&Expect::genesis_key(&CeremonyConfig::rehearsal(NETWORK, c.treasury.clone(), "c3-nonce-x").unwrap()), &d4, &b4, &s4, &deny()), Err(Refusal::Store));
    // Only the RECORDED proof passes an audit: an unrecorded valid proof, and the recorded nonce with a
    // fresh (randomized, equally valid) signature, are not the recorded proof.
    assert_eq!(r::audit_recorded(&audit, &expect, &d4, &b4, &s4, &deny()), Err(Refusal::NotAdmitted));
    let resigned = proof::sign_challenge(c.k1.key(), &d1, &Challenge::decode(&b1).unwrap()).unwrap();
    assert_ne!(resigned, s1);
    assert_eq!(r::audit_recorded(&audit, &expect, &d1, &b1, &resigned, &deny()), Err(Refusal::NotAdmitted));
    drop(audit);
    assert_eq!(support::file_sha256(&path), after_first);

    // Binding: another ceremony (context or Treasury) cannot open this store.
    let other_context = CeremonyConfig::rehearsal(NETWORK, c.treasury.clone(), "c3-nonce-other").unwrap();
    assert_eq!(AdmissionStore::open(&path, &other_context).err(), Some(Refusal::StoreBinding));
    let other_treasury = CeremonyConfig::rehearsal(NETWORK, Treasury::new(Class::TestValue, c.stranger.descriptor().unwrap()).unwrap(), &c.label).unwrap();
    assert_eq!(AdmissionStore::open_read_only(&path, &other_treasury).err(), Some(Refusal::StoreBinding));
    assert_eq!(support::file_sha256(&path), after_first);

    // A store file with an extra schema object (here a trigger that would erase consumed nonces), with
    // a table whose definition differs (no primary key) or with a wrong schema label is refused.
    let tampered = dir.join("tampered.sqlite");
    drop(AdmissionStore::create(&tampered, &c.config).unwrap());
    {
        let db = rusqlite::Connection::open(&tampered).unwrap();
        db.execute_batch("CREATE TRIGGER forget AFTER INSERT ON admissions BEGIN DELETE FROM admissions; END;").unwrap();
    }
    assert_eq!(AdmissionStore::open(&tampered, &c.config).err(), Some(Refusal::StoreBinding));
    let redefined = dir.join("redefined.sqlite");
    drop(AdmissionStore::create(&redefined, &c.config).unwrap());
    {
        let db = rusqlite::Connection::open(&redefined).unwrap();
        db.execute_batch("DROP TABLE admissions; CREATE TABLE admissions(nonce BLOB, challenge BLOB, descriptor BLOB, signature BLOB);").unwrap();
    }
    assert_eq!(AdmissionStore::open(&redefined, &c.config).err(), Some(Refusal::StoreBinding), "same table names, weaker definition");
    let relabelled = dir.join("relabelled.sqlite");
    drop(AdmissionStore::create(&relabelled, &c.config).unwrap());
    {
        let db = rusqlite::Connection::open(&relabelled).unwrap();
        db.execute("UPDATE store_binding SET schema='OTHER'", []).unwrap();
        assert_ne!(STORE_SCHEMA, "OTHER");
    }
    assert_eq!(AdmissionStore::open(&relabelled, &c.config).err(), Some(Refusal::StoreBinding));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// F4 / F9 (review mutants M4a, M17): the settings SQLite reports, read back.
#[test]
fn stores_run_synchronous_extra_and_audit_stores_are_read_only_at_the_sqlite_level() {
    let c = Ceremony::new("c3-pragmas");
    let dir = support::scratch_dir("pragmas");
    let path = dir.join("admissions.sqlite");
    let created = AdmissionStore::create(&path, &c.config).unwrap();
    let d = created.durability().unwrap();
    assert_eq!((d.synchronous, d.journal_mode.as_str(), d.query_only, d.read_only), (3, "delete", false, false), "create: {d:?}");
    drop(created);
    let writable = AdmissionStore::open(&path, &c.config).unwrap();
    let d = writable.durability().unwrap();
    assert_eq!((d.synchronous, d.journal_mode.as_str(), d.query_only, d.read_only), (3, "delete", false, false), "open: {d:?}");
    drop(writable);
    let audit = AdmissionStore::open_read_only(&path, &c.config).unwrap();
    let d = audit.durability().unwrap();
    assert!(d.query_only && d.read_only, "read-only open: {d:?}");
    assert!(audit.is_read_only());
    drop(audit);
    let scratch = AdmissionStore::in_memory(&c.config).unwrap();
    let d = scratch.durability().unwrap();
    assert_eq!((d.synchronous, d.journal_mode.as_str(), d.read_only), (3, "memory", false), "in-memory: {d:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// F9 (review mutant M23): a damaged row is refused on read, never repaired or trusted.
#[test]
fn a_damaged_admission_row_is_refused_on_read() {
    let c = Ceremony::new("c3-damaged");
    let expect = Expect::genesis_key(&c.config);
    let (d1, b1, s1) = proof_for(&c.config, &c.k1, h32("damaged-n1"));
    let dir = support::scratch_dir("damaged");
    let path = dir.join("admissions.sqlite");
    drop(AdmissionStore::create(&path, &c.config).unwrap());
    AdmissionStore::open(&path, &c.config).unwrap().admit(&expect, &d1, &b1, &s1, &deny()).unwrap();
    {
        // The row's key no longer equals the nonce inside its challenge (all CHECK constraints still hold).
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute("UPDATE admissions SET nonce=?1", [h32("another-nonce").as_slice()]).unwrap();
    }
    let audit = AdmissionStore::open_read_only(&path, &c.config).unwrap();
    assert_eq!(audit.recorded(&h32("another-nonce")), Err(Refusal::Store));
    assert_eq!(audit.admissions(), Err(Refusal::Store));
    assert_eq!(audit.recorded(&h32("damaged-n1")), Ok(None), "the original nonce is no longer recorded");
    assert_eq!(r::audit_recorded(&audit, &expect, &d1, &b1, &s1, &deny()), Err(Refusal::NotAdmitted));
    drop(audit);
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute("UPDATE admissions SET nonce=?1, challenge=x'00'", [h32("damaged-n1").as_slice()]).unwrap();
    }
    let audit = AdmissionStore::open_read_only(&path, &c.config).unwrap();
    assert_eq!(audit.recorded(&h32("damaged-n1")), Err(Refusal::Store), "a challenge that no longer decodes");
    assert_eq!(r::audit_recorded(&audit, &expect, &d1, &b1, &s1, &deny()), Err(Refusal::Store));
    drop(audit);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn concurrent_admissions_of_one_nonce_admit_exactly_once() {
    let c = Ceremony::new("c3-race");
    let expect = Expect::genesis_key(&c.config);
    let (d1, b1, s1) = proof_for(&c.config, &c.k1, h32("race-n1"));
    let dir = support::scratch_dir("race");
    let path = dir.join("admissions.sqlite");
    drop(AdmissionStore::create(&path, &c.config).unwrap());
    let barrier = std::sync::Barrier::new(4);
    let results: Vec<Result<_, Refusal>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let mut store = AdmissionStore::open(&path, &c.config).unwrap();
                    barrier.wait();
                    store.admit(&expect, &d1, &b1, &s1, &deny()).map(|p| p.nonce)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1, "{results:?}");
    assert_eq!(results.iter().filter(|r| **r == Err(Refusal::Replay)).count(), 3, "{results:?}");
    assert_eq!(AdmissionStore::open_read_only(&path, &c.config).unwrap().admissions().unwrap().len(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

const CHILD_MODE: &str = "BUILD8_C3_CHILD_MODE";
const CHILD_DIR: &str = "BUILD8_C3_CHILD_DIR";
const CHILD_TEST: &str = "child_process_step_of_the_restart_test";

/// Helper for the multi-process restart test: does nothing unless that test runs this binary as a
/// child process with `BUILD8_C3_CHILD_MODE` (`admit` or `audit`) and `BUILD8_C3_CHILD_DIR`.
#[test]
fn child_process_step_of_the_restart_test() {
    let (Ok(mode), Ok(dir)) = (std::env::var(CHILD_MODE), std::env::var(CHILD_DIR)) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let c = Ceremony::new("c3-proc");
    let expect = Expect::genesis_key(&c.config);
    let read = |n: &str| hex::decode(std::fs::read_to_string(dir.join(n)).unwrap().trim()).unwrap();
    let (d, b, s) = (read("d.hex"), read("c.hex"), proof::signature_from_bytes(&read("s.hex")).unwrap());
    let path = dir.join("admissions.sqlite");
    let result = match mode.as_str() {
        "admit" => AdmissionStore::open(&path, &c.config).and_then(|mut store| store.admit(&expect, &d, &b, &s, &deny()).map(|_| ())),
        "audit" => AdmissionStore::open_read_only(&path, &c.config).and_then(|store| r::audit_recorded(&store, &expect, &d, &b, &s, &deny()).map(|_| ())),
        other => panic!("unknown child mode {other}"),
    };
    println!("C3-CHILD-RESULT pid={} {result:?}", std::process::id());
}

/// F9: restart across separate OS processes (this test binary re-executed as children), not only an
/// in-process reopen: the admission made by one process is a replay for the next, and read-only
/// audits by further processes leave the store byte-identical.
#[test]
fn a_restart_in_separate_processes_keeps_the_nonce_consumed_and_audits_read_only() {
    let c = Ceremony::new("c3-proc");
    let (d1, b1, s1) = proof_for(&c.config, &c.k1, h32("proc-n1"));
    let dir = support::scratch_dir("proc");
    std::fs::write(dir.join("d.hex"), hex::encode(&d1)).unwrap();
    std::fs::write(dir.join("c.hex"), hex::encode(&b1)).unwrap();
    std::fs::write(dir.join("s.hex"), hex::encode(proof::signature_to_bytes(&s1))).unwrap();
    let path = dir.join("admissions.sqlite");
    drop(AdmissionStore::create(&path, &c.config).unwrap());
    let child = |mode: &str| -> (u32, String) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
            .env(CHILD_MODE, mode)
            .env(CHILD_DIR, &dir)
            .output()
            .unwrap();
        assert!(out.status.success(), "child {mode}: {}", String::from_utf8_lossy(&out.stderr));
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        // The harness may print the test name on the same line before the child's output.
        let line = text.lines().find_map(|l| l.split_once("C3-CHILD-RESULT ").map(|(_, rest)| rest)).unwrap_or_else(|| panic!("no child result: {text}")).to_string();
        let (pid, result) = line.split_once(' ').unwrap();
        (pid.trim_start_matches("pid=").parse().unwrap(), result.to_string())
    };
    let (first_pid, first) = child("admit");
    assert_eq!(first, "Ok(())");
    let (second_pid, second) = child("admit");
    assert_eq!(second, "Err(Replay)");
    assert_ne!(first_pid, second_pid);
    assert_ne!(first_pid, std::process::id());
    let before = support::file_sha256(&path);
    for _ in 0..2 {
        assert_eq!(child("audit").1, "Ok(())");
        assert_eq!(support::file_sha256(&path), before, "a read-only audit in another process changed the store");
    }
    // And this process (a third view of the same file) also sees the nonce consumed.
    let mut store = AdmissionStore::open(&path, &c.config).unwrap();
    assert_eq!(store.admit(&Expect::genesis_key(&c.config), &d1, &b1, &s1, &deny()), Err(Refusal::Replay));
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// F5 (review r5): a fresh store for the same ceremony CAN admit a replayed nonce (not prevented; stated
/// limit), but it has another store id, so the approved manifest that names the original store refuses
/// it, and a deleted-and-re-created store at the same path gets a new id too.
#[test]
fn r5_a_replay_into_a_second_store_cannot_pass_the_approved_store() {
    let c = Ceremony::new("c3-r5");
    let expect = Expect::genesis_key(&c.config);
    let (d1, b1, s1) = proof_for(&c.config, &c.k1, h32("r5-n1"));
    let dir = support::scratch_dir("r5");
    let (a, b) = (dir.join("a.sqlite"), dir.join("b.sqlite"));
    let store_a = AdmissionStore::create(&a, &c.config).unwrap();
    let id_a = store_a.store_id();
    drop(store_a);
    AdmissionStore::open(&a, &c.config).unwrap().admit(&expect, &d1, &b1, &s1, &deny()).unwrap();
    let audit_a = AdmissionStore::open_read_only(&a, &c.config).unwrap();
    let manifest = r::build_manifest(&expect, &d1, &b1, &s1, [255; 32], &r::rehearsal_rules(), &deny(), &audit_a).unwrap();
    assert!(manifest.text.contains(&format!("\"admission_store_id\": \"{}\"", hex::encode(id_a))));
    let approved = approval(&c, &manifest.parameters, &audit_a, None);
    assert_eq!(approved.admission_store_id, id_a);
    assert!(r::verify_frozen(&manifest.parameters, false, &expect, &approved, &audit_a, &b1, &s1).is_ok());
    drop(audit_a);
    // Store B for the same ceremony admits the same nonce (re-signed): the limit, not prevented.
    let store_b = AdmissionStore::create(&b, &c.config).unwrap();
    assert_ne!(store_b.store_id(), id_a);
    drop(store_b);
    let resigned = proof::sign_challenge(c.k1.key(), &d1, &Challenge::decode(&b1).unwrap()).unwrap();
    assert!(AdmissionStore::open(&b, &c.config).unwrap().admit(&expect, &d1, &b1, &resigned, &deny()).is_ok(), "replay into a fresh store");
    let audit_b = AdmissionStore::open_read_only(&b, &c.config).unwrap();
    assert!(r::audit_recorded(&audit_b, &expect, &d1, &b1, &resigned, &deny()).is_ok(), "store B's own audit passes");
    assert_eq!(r::verify_frozen(&manifest.parameters, false, &expect, &approved, &audit_b, &b1, &resigned), Err(Refusal::WrongStore));
    drop(audit_b);
    // Deleting store A and re-creating it at the same path gives a new id as well.
    std::fs::remove_file(&a).unwrap();
    let recreated = AdmissionStore::create(&a, &c.config).unwrap();
    assert_ne!(recreated.store_id(), id_a);
    drop(recreated);
    AdmissionStore::open(&a, &c.config).unwrap().admit(&expect, &d1, &b1, &s1, &deny()).unwrap();
    let audit_a2 = AdmissionStore::open_read_only(&a, &c.config).unwrap();
    assert_eq!(r::verify_frozen(&manifest.parameters, false, &expect, &approved, &audit_a2, &b1, &s1), Err(Refusal::WrongStore));
    drop(audit_a2);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// F9 (review r7, mutant M5b): an already-open store refuses an expectation of another ceremony.
#[test]
fn r7_admit_and_audit_refuse_an_expectation_of_another_ceremony_on_an_open_store() {
    let c = Ceremony::new("c3-r7");
    let other = CeremonyConfig::rehearsal(NETWORK, c.treasury.clone(), "c3-r7-other").unwrap();
    let (d, b, s) = proof_for(&other, &c.k1, h32("r7-n"));
    let mut store = AdmissionStore::in_memory(&c.config).unwrap();
    assert_eq!(store.admit(&Expect::genesis_key(&other), &d, &b, &s, &deny()), Err(Refusal::StoreBinding));
    assert_eq!(r::audit_recorded(&store, &Expect::genesis_key(&other), &d, &b, &s, &deny()), Err(Refusal::StoreBinding));
    assert!(store.admissions().unwrap().is_empty());
}

/// Review r8: degenerate store files fail closed (an empty file, truncated copies, a non-database file);
/// a damaged store never admits a recorded nonce again.
#[test]
fn r8_empty_truncated_and_junk_store_files_fail_closed() {
    let c = Ceremony::new("c3-r8");
    let expect = Expect::genesis_key(&c.config);
    let dir = support::scratch_dir("r8");
    let empty = dir.join("empty.sqlite");
    std::fs::write(&empty, b"").unwrap();
    assert_eq!(AdmissionStore::open(&empty, &c.config).err(), Some(Refusal::StoreBinding));
    assert_eq!(AdmissionStore::open_read_only(&empty, &c.config).err(), Some(Refusal::StoreBinding));
    let real = dir.join("real.sqlite");
    drop(AdmissionStore::create(&real, &c.config).unwrap());
    let (d1, b1, s1) = proof_for(&c.config, &c.k1, h32("r8-n1"));
    AdmissionStore::open(&real, &c.config).unwrap().admit(&expect, &d1, &b1, &s1, &deny()).unwrap();
    let bytes = std::fs::read(&real).unwrap();
    for cut in [bytes.len() / 2, bytes.len() - 1, 4096] {
        let trunc = dir.join(format!("trunc-{cut}.sqlite"));
        std::fs::write(&trunc, &bytes[..cut.min(bytes.len())]).unwrap();
        let audit = AdmissionStore::open_read_only(&trunc, &c.config).map(|s| r::audit_recorded(&s, &expect, &d1, &b1, &s1, &deny()).map(|_| ()));
        let admit = AdmissionStore::open(&trunc, &c.config).map(|mut s| s.admit(&expect, &d1, &b1, &s1, &deny()).map(|_| ()));
        let intact = audit == Ok(Ok(())) && admit == Ok(Err(Refusal::Replay));
        let refused = |x: &Result<Result<(), Refusal>, Refusal>| matches!(x, Ok(Err(Refusal::Store)) | Err(Refusal::Store | Refusal::StoreBinding));
        assert!(intact || (refused(&audit) && refused(&admit)), "cut {cut}: audit {audit:?}, admit {admit:?}");
        assert_ne!(admit, Ok(Ok(())), "cut {cut}: a damaged store admitted the recorded nonce again");
    }
    let junk = dir.join("junk.sqlite");
    std::fs::write(&junk, b"not a database at all, just some text that is long enough").unwrap();
    assert!(matches!(AdmissionStore::open_read_only(&junk, &c.config).err(), Some(Refusal::Store | Refusal::StoreBinding)));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// F3 / S2 (review r3): a full Genesis descriptor needs an approval that names the GenesisID; the
/// GenesisID then covers every Genesis field. A Parameters-only input is checked against an approval
/// that names no GenesisID; an approval that names one cannot be checked from Parameters alone.
#[test]
fn the_frozen_genesis_is_compared_with_the_independently_approved_manifest() {
    let c = Ceremony::new("c3-frozen");
    let expect = Expect::genesis_key(&c.config);
    let (d1, b1, s1) = proof_for(&c.config, &c.k1, h32("frozen-n1"));
    let mut store = AdmissionStore::in_memory(&c.config).unwrap();
    store.admit(&expect, &d1, &b1, &s1, &deny()).unwrap();
    let manifest = r::build_manifest(&expect, &d1, &b1, &s1, [255; 32], &r::rehearsal_rules(), &deny(), &store).unwrap();
    let parameters = manifest.parameters.clone();
    let approved = approval(&c, &parameters, &store, None);
    let genesis = GenesisDescriptor {
        timestamp: 1,
        nonce: [1; 32],
        fingerprint: r::rehearsal_rules().fingerprint().unwrap(),
        owner: [2; 32],
        purchase: [3; 32],
        parameters: parameters.clone(),
        admission_records: vec![],
        recovery: [4; 32],
    };
    let raw_genesis = genesis.encode().unwrap();
    let id = genesis.id().unwrap();
    let named = ApprovedManifest { genesis_id: Some(id), ..approved.clone() };
    // Parameters only (approval without a GenesisID); then the full descriptor with the approved GenesisID.
    for _ in 0..2 {
        let rep = r::verify_frozen(&parameters, false, &expect, &approved, &store, &b1, &s1).unwrap();
        assert_eq!((rep.class, rep.genesis_id, rep.parameters_sha256), (Class::TestValue, None, approved.parameters_sha256));
        assert_eq!(r::verify_frozen(&raw_genesis, true, &expect, &named, &store, &b1, &s1).unwrap().genesis_id, Some(id));
    }
    assert_eq!(store.admissions().unwrap().len(), 1, "audits consume nothing");
    // F3: a Genesis descriptor with an approval that names no GenesisID is refused, whatever its fields.
    assert_eq!(r::verify_frozen(&raw_genesis, true, &expect, &approved, &store, &b1, &s1), Err(Refusal::GenesisIdNotApproved));
    let tampered = GenesisDescriptor { timestamp: 999, nonce: [7; 32], fingerprint: [0x66; 32], owner: [0xee; 32], purchase: [0xdd; 32], recovery: [0xcc; 32], ..genesis.clone() };
    assert_eq!(r::verify_frozen(&tampered.encode().unwrap(), true, &expect, &approved, &store, &b1, &s1), Err(Refusal::GenesisIdNotApproved));
    assert_eq!(r::verify_frozen(&tampered.encode().unwrap(), true, &expect, &named, &store, &b1, &s1), Err(Refusal::ManifestMismatch), "every field is covered by the GenesisID");
    // An approval naming a GenesisID cannot be satisfied by Parameters alone.
    assert_eq!(r::verify_frozen(&parameters, false, &expect, &named, &store, &b1, &s1), Err(Refusal::ManifestMismatch));
    // The proof proves KEY CONTROL only: a frozen Genesis with another (unapproved) parameter carries the
    // same Treasury record and the same valid proof, and is refused by the approved-manifest check alone.
    let changed = Parameters { initial_target: [254; 32], ..Parameters::decode(&parameters).unwrap() }.encode().unwrap();
    assert_eq!(r::verify_frozen(&changed, false, &expect, &approved, &store, &b1, &s1), Err(Refusal::ManifestMismatch));
    for wrong in [
        ApprovedManifest { class: Class::Production, ..approved.clone() },
        ApprovedManifest { descriptor_sha256: h32("x"), ..approved.clone() },
        ApprovedManifest { record_sha256: h32("x"), ..approved.clone() },
    ] {
        assert_eq!(r::verify_frozen(&parameters, false, &expect, &wrong, &store, &b1, &s1), Err(Refusal::ManifestMismatch), "{wrong:?}");
    }
    assert_eq!(
        r::verify_frozen(&parameters, false, &expect, &ApprovedManifest { admission_store_id: h32("another-store"), ..approved.clone() }, &store, &b1, &s1),
        Err(Refusal::WrongStore)
    );
    let other_id = GenesisDescriptor { nonce: [9; 32], ..genesis.clone() };
    assert_eq!(r::verify_frozen(&other_id.encode().unwrap(), true, &expect, &named, &store, &b1, &s1), Err(Refusal::ManifestMismatch));
    // A frozen Treasury other than the trusted one, and Parameters without a Treasury.
    let stranger = Treasury::new(Class::TestValue, c.stranger.descriptor().unwrap()).unwrap();
    let foreign = Parameters { treasury: Some(stranger), ..Parameters::decode(&parameters).unwrap() }.encode().unwrap();
    assert_eq!(r::verify_frozen(&foreign, false, &expect, &approved, &store, &b1, &s1), Err(Refusal::FrozenMismatch));
    let v2 = Parameters { treasury: None, ..Parameters::decode(&parameters).unwrap() }.encode().unwrap();
    assert_eq!(r::verify_frozen(&v2, false, &expect, &approved, &store, &b1, &s1), Err(Refusal::FrozenMismatch));
    // A valid but never admitted proof is not the recorded proof.
    let (_, b2, s2) = proof_for(&c.config, &c.k1, h32("frozen-n2"));
    assert_eq!(r::verify_frozen(&parameters, false, &expect, &approved, &store, &b2, &s2), Err(Refusal::NotAdmitted));
    // verify-frozen is a generation-one check of the sealed record, and so is the manifest builder
    // (review mutant M18): even an ADMITTED generation-two proof of the authorized successor builds no
    // manifest and passes no frozen check.
    let successor = Expect::authorized_rotation(&c.plan_config(), &c.plan()).unwrap();
    let (d2, b2, s2) = proof_for(&c.config, &c.k2, h32("frozen-n3"));
    store.admit(&successor, &d2, &b2, &s2, &deny()).unwrap();
    assert!(r::audit_recorded(&store, &successor, &d2, &b2, &s2, &deny()).is_ok());
    assert_eq!(r::build_manifest(&successor, &d2, &b2, &s2, [255; 32], &r::rehearsal_rules(), &deny(), &store), Err(Refusal::Proof(ProofError::WrongKeyVersion)));
    assert_eq!(r::verify_frozen(&parameters, false, &successor, &approved, &store, &b2, &s2), Err(Refusal::Proof(ProofError::WrongKeyVersion)));
    assert_eq!(r::verify_frozen(&parameters, false, &successor, &approved, &store, &b1, &s1), Err(Refusal::Proof(ProofError::WrongKeyVersion)));
}

/// F8 (review r6): labels may contain `"` and `\`; the manifest stays valid JSON with the exact label
/// and no injected key.
#[test]
fn r6_a_label_with_a_quote_or_backslash_cannot_change_the_manifest_json() {
    let k1 = mutiny_crypto_v2::rehearsal_keys_v1::Credential::from_label("c3-r6-k1", 1).unwrap();
    let treasury = Treasury::new(Class::TestValue, k1.descriptor().unwrap()).unwrap();
    for label in ["ab\"cd", "ab\\cd", "x\"},\"class_byte\":1,\"q\":{\"y\":\"z", "plain-label"] {
        let config = CeremonyConfig::rehearsal(NETWORK, treasury.clone(), label).unwrap();
        let expect = Expect::genesis_key(&config);
        let (d, b, s) = proof_for(&config, &k1, h32("r6-n"));
        let mut store = AdmissionStore::in_memory(&config).unwrap();
        store.admit(&expect, &d, &b, &s, &deny()).unwrap();
        let m = r::build_manifest(&expect, &d, &b, &s, [255; 32], &r::rehearsal_rules(), &deny(), &store).unwrap();
        let v: serde_json::Value = serde_json::from_str(&m.text).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(v["proof_of_control"]["ceremony_context_label"], label);
        assert_eq!(v["class_byte"], 2, "{label}");
        assert!(v.get("q").is_none(), "{label}: an injected key");
    }
}

#[test]
fn production_context_checking_side_compares_only_the_configured_value_and_never_a_genesis_id() {
    let c = Ceremony::new("c3-prodctx");
    let d1 = c.k1.descriptor().unwrap();
    let production = Treasury::new(Class::Production, d1.clone()).unwrap();
    assert_eq!(ExpectedContext::production_supplied([0; 32]), Err(Refusal::Codec));
    let supplied = h32("architect-approved-production-context (placeholder, not a defined construction)");
    let expected = ExpectedContext::production_supplied(supplied).unwrap();
    assert_eq!((expected.phase(), expected.value(), expected.label()), (Phase::Production, supplied, None));
    let config = CeremonyConfig::new(NETWORK, production.clone(), expected.clone()).unwrap();
    assert_eq!((config.phase(), config.class()), (Phase::Production, Class::Production));
    let challenge = |phase: Phase, context| Challenge::new(&d1, phase, production.authority(), r::record_sha256(&production).unwrap(), context, h32("prodctx-n")).unwrap();
    // Exactly the configured value is accepted by the comparison; anything else is refused.
    assert_eq!(r::check_ceremony_context(&expected, &challenge(Phase::Production, supplied), None), Ok(()));
    assert_eq!(r::check_ceremony_context(&expected, &challenge(Phase::Production, h32("other")), None), Err(Refusal::WrongContext));
    let rehearsal_value = r::ceremony_context("c3-prodctx-ceremony").unwrap();
    assert_eq!(r::check_ceremony_context(&expected, &challenge(Phase::Production, rehearsal_value), None), Err(Refusal::WrongContext));
    assert_eq!(r::check_ceremony_context(&expected, &challenge(Phase::Rehearsal, supplied), None), Err(Refusal::WrongPhase));
    assert_eq!(r::check_ceremony_context(c.config.context(), &challenge(Phase::Production, rehearsal_value), None), Err(Refusal::WrongPhase));
    // Never the GenesisID: once the GenesisID is known, a context equal to it is refused.
    assert_eq!(r::check_ceremony_context(&expected, &challenge(Phase::Production, supplied), Some(&supplied)), Err(Refusal::ContextIsGenesisId));
    assert_eq!(r::check_ceremony_context(&expected, &challenge(Phase::Production, supplied), Some(&h32("another-id"))), Ok(()));
    // The checking side does not open production: every production step stays refused.
    assert_eq!(r::build_challenge(&config, &d1, h32("n")), Err(Refusal::ProductionRefused));
    let raw = c.k1.key().sign(Domain::TreasuryProofOfControl, &challenge(Phase::Production, supplied).encode().unwrap()).unwrap();
    assert_eq!(r::verify_proof(&Expect::genesis_key(&config), &d1, &challenge(Phase::Production, supplied).encode().unwrap(), &raw, &deny()), Err(Refusal::ProductionRefused));
    let store = AdmissionStore::in_memory(&config).unwrap();
    let mut writable = AdmissionStore::in_memory(&config).unwrap();
    assert_eq!(writable.admit(&Expect::genesis_key(&config), &d1, &challenge(Phase::Production, supplied).encode().unwrap(), &raw, &deny()), Err(Refusal::ProductionRefused));
    assert_eq!(
        r::build_manifest(&Expect::genesis_key(&config), &d1, &challenge(Phase::Production, supplied).encode().unwrap(), &raw, [255; 32], &r::rehearsal_rules(), &deny(), &store),
        Err(Refusal::ProductionRefused)
    );
    assert!(writable.admissions().unwrap().is_empty() && store.admissions().unwrap().is_empty());
}

#[test]
fn the_rehearsal_context_derivation_is_exactly_the_documented_one() {
    use sha2::{Digest, Sha256};
    for label in ["abcd", "d2-rehearsal-ceremony", "x".repeat(64).as_str(), "!~#$"] {
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1");
        h.update([0u8]);
        h.update(label.as_bytes());
        assert_eq!(r::ceremony_context(label).unwrap(), <[u8; 32]>::from(h.finalize()), "{label}");
    }
    // 4..=64 bytes, each 0x21..=0x7E: shorter, longer, a space, a control byte or non-ASCII are refused.
    for label in ["abc", "x".repeat(65).as_str(), "has space", "tab\there", "caf\u{e9}"] {
        assert_eq!(r::ceremony_context(label), Err(Refusal::Codec), "{label:?}");
    }
}

/// S5: the normative input order (challenge decode, then the signature serialization) and the decoder's
/// own order (reading, end of input, class/phase, zero fields, re-encoding) for multi-defect inputs.
#[test]
fn multi_defect_inputs_are_refused_in_the_normative_order() {
    let c = Ceremony::new("c3-order");
    let (_, b1, s1) = proof_for(&c.config, &c.k1, h32("order-n1"));
    let sig = proof::signature_to_bytes(&s1);
    let mut class_trunc = b1.clone();
    class_trunc[8] = 0x01;
    class_trunc.pop();
    assert_eq!(r::decode_proof(&class_trunc, &sig).err(), Some(Refusal::Proof(ProofError::Malformed)), "reading fails before shape checks");
    let mut zero_trailing = b1[..b1.len() - 32].to_vec();
    zero_trailing.extend([0u8; 32]);
    zero_trailing.push(0);
    assert_eq!(r::decode_proof(&zero_trailing, &sig).err(), Some(Refusal::Proof(ProofError::Malformed)), "end of input before zero fields");
    let mut nonminimal_class = vec![b1[0], 0x18, 0x01];
    nonminimal_class.extend_from_slice(&b1[2..]);
    nonminimal_class[9] = 0x01;
    assert_eq!(r::decode_proof(&nonminimal_class, &sig).err(), Some(Refusal::Proof(ProofError::ClassPhaseMismatch)), "class/phase before re-encoding");
    assert_eq!(r::decode_proof(&nonminimal_class, &sig[..114]).err(), Some(Refusal::Proof(ProofError::ClassPhaseMismatch)), "the challenge (I1) before the signature (I2)");
    // Challenge before signature serialization: a malformed challenge with a 114-byte signature.
    assert_eq!(r::decode_proof(&b1[..b1.len() - 1], &sig[..114]).err(), Some(Refusal::Proof(ProofError::Malformed)));
    // A valid production-phase challenge with a 114-byte signature: the serialization (input stage)
    // refuses before the production refusal (verification stage).
    let pc = Challenge::new(&c.k1.descriptor().unwrap(), Phase::Production, c.treasury.authority(), r::record_sha256(&c.treasury).unwrap(), c.config.context().value(), h32("order-p"))
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(r::decode_proof(&pc, &sig[..114]).err(), Some(Refusal::Proof(ProofError::Malformed)));
    assert!(r::decode_proof(&pc, &sig).is_ok());
}

// Historical V1/V2 software model only. Superseded unrestricted admission is
// compiled in this test crate, never exported by the shipping library graph.
// Only paths required by the isolated frozen model are supplied here.
pub use mutiny_consensus_v8::{domain_hash, blocks, execution, genesis_inputs, protocol_manifest, treasury_v1, wallet_rotation_v1, dividend_state_v1, NETWORK_ID};
#[path = "../src/treasury_rehearsal_v1.rs"]
mod treasury_rehearsal_v1;
#[path = "../src/treasury_admission_v1.rs"]
mod treasury_admission_v1;
