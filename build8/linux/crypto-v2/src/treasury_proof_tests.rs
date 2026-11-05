//! Treasury proof-of-control domain, codec, signer, verifier, key tool and secret guard.
//! TEST-VALUE only: every key here derives from a public label.
use super::*;
use crate::rehearsal_keys_v1::{self as keys, Credential};
use crate::treasury_proof_v1::{self as proof, Challenge, Phase, ProofError};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json");
const REGISTRY: &str = include_str!("../../spec/DOMAIN-REGISTRY-V1.json");

fn h32(tag: &str) -> [u8; 32] {
    Sha256::digest(tag.as_bytes()).into()
}
fn challenge_for(c: &Credential, nonce: &str) -> Challenge {
    let descriptor = c.descriptor().unwrap();
    let authority = c.key().public().address_id(1).unwrap();
    Challenge::new(&descriptor, Phase::Rehearsal, authority, h32("record"), h32("context"), h32(nonce)).unwrap()
}
fn k1() -> Credential {
    Credential::from_label("d2-unit-k1", 1).unwrap()
}
fn k2() -> Credential {
    Credential::from_label("d2-unit-k2", 2).unwrap()
}

#[test]
fn domain_is_registered_unique_nonspending_and_role_bound() {
    let d = Domain::TreasuryProofOfControl;
    assert_eq!(d.bytes(), b"MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1");
    assert_eq!(d.role(), Role::WalletOwner);
    // The registry file lists the domain bytes and its purpose (the encoding is not frozen until the Architect approves the schema).
    let registry: serde_json::Value = serde_json::from_str(REGISTRY).unwrap();
    let listed = registry["domains"].as_array().unwrap();
    let entry = listed
        .iter()
        .find(|e| e["ascii"] == "MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1")
        .expect("registered");
    assert!(entry["purpose"].as_str().unwrap().contains("non-spending"));
    assert_eq!(listed.iter().filter(|e| e["ascii"] == entry["ascii"]).count(), 1);
    // A proof never verifies as any other WalletOwner authorization, and no other WalletOwner
    // authorization verifies as a proof.
    let key = k1();
    let challenge = challenge_for(&key, "n-domain");
    let payload = challenge.encode().unwrap();
    let sig = proof::sign_challenge(key.key(), &key.descriptor().unwrap(), &challenge).unwrap();
    let others = [
        Domain::Transaction,
        Domain::WalletRotate,
        Domain::WalletRotatePossession,
        Domain::MinerEnrollment,
        Domain::PhysicalAdmission,
        Domain::ContinuityExitOwner,
        Domain::BondCreate,
        Domain::BondUnbond,
        Domain::BondWithdraw,
        Domain::NodeKeyRotateOwner,
    ];
    for other in others {
        assert_ne!(other.bytes(), d.bytes());
        assert!(key.key().public().verify(other, &payload, &sig).is_err(), "proof replayed as {other:?}");
        let foreign = key.key().sign(other, &payload).unwrap();
        assert!(key.key().public().verify(d, &payload, &foreign).is_err(), "{other:?} replayed as proof");
    }
}

#[test]
fn challenge_codec_is_strict_and_canonical() {
    let c = challenge_for(&k1(), "n-codec");
    let raw = c.encode().unwrap();
    assert_eq!(Challenge::decode(&raw).unwrap(), c);
    assert_eq!(raw, c.encode().unwrap(), "deterministic");
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(Challenge::decode(&trailing), Err(ProofError::Malformed));
    assert_eq!(Challenge::decode(&raw[..raw.len() - 1]), Err(ProofError::Malformed));
    assert!(Challenge::decode(&[]).is_err());
    // No single-bit mutation decodes to the same challenge.
    for i in 0..raw.len() {
        let mut m = raw.clone();
        m[i] ^= 0x01;
        if let Ok(decoded) = Challenge::decode(&m) {
            assert_ne!(decoded, c, "a mutated payload must not decode to the same challenge (byte {i})");
        }
    }
    // Phase and class are redundant and must agree, in the builder and the decoder.
    let mut bad = c.clone();
    bad.class = proof::CLASS_PRODUCTION;
    assert_eq!(bad.encode(), Err(ProofError::ClassPhaseMismatch));
    assert_eq!(Challenge::decode(&bad.encode_unchecked()), Err(ProofError::ClassPhaseMismatch));
    let mut zero = c.clone();
    zero.nonce = [0; 32];
    assert_eq!(zero.encode(), Err(ProofError::ZeroField));
    // A non-minimal integer encoding of the same value is non canonical.
    let mut longer = raw.clone();
    assert_eq!(longer[0], 0x8e);
    longer.splice(1..2, [0x18, 0x01]);
    assert!(Challenge::decode(&longer).is_err());
}

#[test]
fn proof_requires_both_components_and_every_binding() {
    let key = k1();
    let desc = key.descriptor().unwrap();
    let c = challenge_for(&key, "n-bind");
    let sig = proof::sign_challenge(key.key(), &desc, &c).unwrap();
    c.verify(&desc, &sig).expect("control");
    // Single component: each half alone, and each half swapped with a foreign half.
    let mut only_ed = sig.clone();
    only_ed.fndsa = [0; 1280];
    assert_eq!(c.verify(&desc, &only_ed), Err(ProofError::BadSignature));
    let mut only_pq = sig.clone();
    only_pq.ed448 = [0; 114];
    assert_eq!(c.verify(&desc, &only_pq), Err(ProofError::BadSignature));
    let other = k2();
    let other_challenge = challenge_for(&other, "n-bind");
    let other_sig = proof::sign_challenge(other.key(), &other.descriptor().unwrap(), &other_challenge).unwrap();
    let mut mixed = sig.clone();
    mixed.fndsa = other_sig.fndsa;
    assert_eq!(c.verify(&desc, &mixed), Err(ProofError::BadSignature));
    mixed = sig.clone();
    mixed.ed448 = other_sig.ed448;
    assert_eq!(c.verify(&desc, &mixed), Err(ProofError::BadSignature));
    // A one-component file is not even a signature.
    let bytes = proof::signature_to_bytes(&sig);
    assert!(proof::signature_from_bytes(&bytes[..114]).is_err());
    assert!(proof::signature_from_bytes(&bytes[114..]).is_err());
    assert_eq!(proof::signature_from_bytes(&bytes).unwrap(), sig);
    // Altered descriptor bytes: a different valid key of the same generation, and a flipped byte.
    let impostor = Credential::from_label("d2-unit-impostor", 1).unwrap();
    assert_eq!(c.verify(&impostor.descriptor().unwrap(), &sig), Err(ProofError::AlteredDescriptor));
    for at in [0usize, 9, 40, desc.len() / 2, desc.len() - 1] {
        let mut flipped = desc.clone();
        flipped[at] ^= 0x40;
        assert!(c.verify(&flipped, &sig).is_err(), "flipped descriptor byte {at}");
    }
    // Wrong key version: the same key stamped generation 2.
    let g2 = key.key().public().descriptor(2).unwrap();
    assert_eq!(c.verify(&g2, &sig), Err(ProofError::WrongKeyVersion));
    // Wrong profile / suite / policy are bound and rejected before any signature check.
    for tamper in 0..3 {
        let mut p = c.clone();
        match tamper {
            0 => p.profile = "MUTINY-FNDSA1024-OTHER-V1".into(),
            1 => p.suite_id = 2,
            _ => p.policy_id = 2,
        }
        assert_eq!(p.verify(&desc, &sig), Err(ProofError::WrongProfile));
    }
    // Wrong ceremony context, nonce, record hash or authority: the signature no longer matches.
    for tamper in 0..4 {
        let mut p = c.clone();
        match tamper {
            0 => p.ceremony_context = h32("other-context"),
            1 => p.nonce = h32("other-nonce"),
            2 => p.treasury_record_sha256 = h32("other-record"),
            _ => p.treasury_authority = h32("other-authority"),
        }
        assert_eq!(p.verify(&desc, &sig), Err(ProofError::BadSignature), "tamper {tamper}");
    }
    // The signer refuses a foreign credential and a challenge for another descriptor.
    assert_eq!(proof::sign_challenge(other.key(), &desc, &c), Err(ProofError::WrongSigner));
    assert!(proof::sign_challenge(other.key(), &other.descriptor().unwrap(), &c).is_err());
}

#[test]
fn production_proofs_cannot_be_signed_or_accepted_while_unqualified() {
    assert!(!PRODUCTION_SECURITY_QUALIFIED);
    let key = k1();
    let desc = key.descriptor().unwrap();
    let authority = key.key().public().address_id(1).unwrap();
    let c = Challenge::new(&desc, Phase::Production, authority, h32("record"), h32("context"), h32("n-prod")).unwrap();
    assert_eq!(c.class, proof::CLASS_PRODUCTION);
    assert_eq!(proof::sign_challenge(key.key(), &desc, &c), Err(ProofError::ProductionRefused));
    // Even a signature made through the raw API is not accepted as a production proof.
    let raw = key.key().sign(Domain::TreasuryProofOfControl, &c.encode().unwrap()).unwrap();
    assert_eq!(c.verify(&desc, &raw), Err(ProofError::ProductionRefused));
    // A rehearsal signature cannot be relabelled production: class and phase are signed bytes.
    let r = challenge_for(&key, "n-prod");
    let sig = proof::sign_challenge(key.key(), &desc, &r).unwrap();
    let mut relabel = r.clone();
    relabel.phase = Phase::Production;
    relabel.class = proof::CLASS_PRODUCTION;
    assert!(relabel.verify(&desc, &sig).is_err());
}

#[test]
fn committed_public_vectors_verify_and_negative_vectors_fail() {
    // Regenerate with BUILD8_TREASURY_PROOF_VECTORS=<path> (writes public data only).
    let mut cases = Vec::new();
    for (label, generation) in [("d2-vector-k1", 1u64), ("d2-vector-k2", 2)] {
        let key = Credential::from_label(label, generation).unwrap();
        let descriptor = key.descriptor().unwrap();
        let authority = if generation == 1 { key.key().public().address_id(1).unwrap() } else { h32("vector-treasury-authority") };
        let c = Challenge::new(
            &descriptor,
            Phase::Rehearsal,
            authority,
            h32("vector-treasury-record"),
            h32("vector-ceremony-context"),
            h32(&format!("vector-nonce-{generation}")),
        )
        .unwrap();
        let payload = c.encode().unwrap();
        let sig = proof::sign_challenge(key.key(), &descriptor, &c).unwrap();
        let mut flipped = payload.clone();
        *flipped.last_mut().unwrap() ^= 1;
        cases.push(serde_json::json!({
            "label_public": label,
            "generation": generation,
            "class": "TEST-VALUE",
            "domain": std::str::from_utf8(Domain::TreasuryProofOfControl.bytes()).unwrap(),
            "descriptor": hex::encode(&descriptor),
            "descriptor_sha256": hex::encode(proof::sha256(&descriptor)),
            "challenge": hex::encode(&payload),
            "intent": hex::encode(intent(Domain::TreasuryProofOfControl, &payload).unwrap()),
            "ed448_signature": hex::encode(sig.ed448),
            "fndsa_signature": hex::encode(sig.fndsa),
            "negative_flipped_challenge": hex::encode(&flipped),
        }));
    }
    let fresh = serde_json::json!({
        "schema": "BUILD8-TREASURY-PROOF-OF-CONTROL-VECTORS-V1",
        "synthetic_only": true,
        "test_value": true,
        "production_authorized": false,
        "note": "Public data only. Keys derive from public labels and are TEST-VALUE. Signatures are randomized; verification is the check.",
        "challenge_fields": "[1,NETWORK,phase,class,generation,suite,policy,profile,descriptor_sha256,address_id,treasury_authority,treasury_record_sha256,ceremony_context,nonce]",
        "vectors": cases,
    });
    if let Ok(path) = std::env::var("BUILD8_TREASURY_PROOF_VECTORS") {
        std::fs::write(path, serde_json::to_string_pretty(&fresh).unwrap() + "\n").unwrap();
    }
    let committed: serde_json::Value = serde_json::from_str(VECTORS).expect("committed vectors file");
    assert_eq!(committed["test_value"], true);
    assert_eq!(committed["production_authorized"], false);
    let list = committed["vectors"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    for (v, f) in list.iter().zip(fresh["vectors"].as_array().unwrap()) {
        let descriptor = hex::decode(v["descriptor"].as_str().unwrap()).unwrap();
        let payload = hex::decode(v["challenge"].as_str().unwrap()).unwrap();
        // The frozen encoding is reproduced byte for byte from the public inputs (fresh run).
        assert_eq!(v["challenge"], f["challenge"], "challenge encoding is frozen");
        assert_eq!(v["descriptor"], f["descriptor"]);
        assert_eq!(v["intent"], f["intent"]);
        assert_eq!(v["descriptor_sha256"], f["descriptor_sha256"]);
        // The committed signature verifies, both components.
        let challenge = Challenge::decode(&payload).unwrap();
        let sig = HybridSignature {
            ed448: hex::decode(v["ed448_signature"].as_str().unwrap()).unwrap().try_into().unwrap(),
            fndsa: hex::decode(v["fndsa_signature"].as_str().unwrap()).unwrap().try_into().unwrap(),
        };
        challenge.verify(&descriptor, &sig).expect("committed vector verifies");
        // Negative vectors: a flipped challenge fails; the proof is not valid in another domain.
        let bad = hex::decode(v["negative_flipped_challenge"].as_str().unwrap()).unwrap();
        if let Ok(c) = Challenge::decode(&bad) {
            assert!(c.verify(&descriptor, &sig).is_err());
        }
        let (public, _) = PublicKey::decode_descriptor(&descriptor).unwrap();
        assert!(public.verify(Domain::TreasuryProofOfControl, &bad, &sig).is_err());
        assert!(public.verify(Domain::Transaction, &payload, &sig).is_err());
    }
}

// ---------------------------------------------------------------- rehearsal key tool + guard

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut nonce = [0; 8];
    fill_os_random(&mut nonce).unwrap();
    let dir = std::env::temp_dir().join(format!("build8-rehearsal-keys-{tag}-{}", keys::hex(&nonce)));
    std::fs::create_dir(&dir).unwrap();
    dir
}
fn cli(args: &[&str]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = keys::run(&args, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

/// Secret-shape guard. `phrase` is the known secret of the run under test.
fn assert_public_only(what: &str, text: &str, phrase: &str, key: &HybridKey) {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    for w in words.windows(3) {
        assert!(!text.contains(&w.join(" ")), "{what}: contains a phrase fragment");
    }
    let list: std::collections::BTreeSet<&str> = bip39::Language::English.word_list().iter().copied().collect();
    let tokens: Vec<&str> = text.split(|c: char| !c.is_ascii_alphabetic()).filter(|t| !t.is_empty()).collect();
    let mut run = 0;
    for t in &tokens {
        run = if list.contains(t) { run + 1 } else { 0 };
        assert!(run < 8, "{what}: eight or more consecutive BIP39 words");
    }
    let lower = text.to_ascii_lowercase();
    let entropy = bip39::Mnemonic::parse_in(bip39::Language::English, phrase).unwrap().to_entropy();
    assert!(!lower.contains(&keys::hex(&entropy)), "{what}: entropy");
    assert!(!lower.contains(&keys::hex(&key.ed_seed[..])), "{what}: Ed448 seed");
    assert!(!lower.contains(&keys::hex(&key.fn_secret[..32])), "{what}: FN-DSA secret prefix");
    for banned in ["mnemonic", "passphrase", "private key", "begin private", "seed phrase"] {
        assert!(!lower.contains(banned), "{what}: secret-shaped word {banned}");
    }
}

#[test]
fn labelled_mode_is_deterministic_stamped_and_idempotent() {
    assert_eq!(keys::label_phrase("d2-unit-k1").unwrap().as_str(), keys::label_phrase("d2-unit-k1").unwrap().as_str());
    assert_ne!(keys::label_phrase("d2-unit-k1").unwrap().as_str(), keys::label_phrase("d2-unit-k2").unwrap().as_str());
    assert!(keys::label_phrase("a b").is_err() && keys::label_phrase("x").is_err() && keys::label_phrase("../../etc").is_err());
    let a = Credential::from_label("d2-unit-k1", 1).unwrap();
    assert_eq!(a.descriptor().unwrap(), Credential::from_label("d2-unit-k1", 1).unwrap().descriptor().unwrap());
    // Generation is a stamp on the same key; K2 is a different key.
    assert_eq!(a.key().public(), Credential::from_label("d2-unit-k1", 2).unwrap().key().public());
    assert_ne!(a.key().public(), k2().key().public());
    assert!(Credential::from_label("d2-unit-k1", 3).is_err() && Credential::from_label("d2-unit-k1", 0).is_err());
    assert_eq!(PublicKey::decode_descriptor(&k2().descriptor().unwrap()).unwrap().1, 2);

    let dir = temp_dir("labelled");
    let d = dir.to_str().unwrap();
    let (code, out1, err1) = cli(&["keygen", "--generation", "1", "--out-dir", d, "--label", "d2-unit-k1"]);
    assert_eq!((code, err1.as_str()), (0, ""), "{out1}");
    let json1 = std::fs::read_to_string(dir.join("key-g1.public.json")).unwrap();
    assert!(json1.contains("\"class\": \"TEST-VALUE\"") && json1.contains(keys::EVIDENCE_LABEL));
    assert!(json1.contains("LABELLED-SEED-PUBLICLY-DERIVABLE") && json1.contains("TEST-VALUE != production"));
    // Retry with identical inputs is safe and byte identical; different inputs are refused.
    let (code, out2, _) = cli(&["keygen", "--generation", "1", "--out-dir", d, "--label", "d2-unit-k1"]);
    assert_eq!(code, 0);
    assert_eq!(out1, out2);
    assert_eq!(json1, std::fs::read_to_string(dir.join("key-g1.public.json")).unwrap());
    let (code, _, err) = cli(&["keygen", "--generation", "1", "--out-dir", d, "--label", "d2-unit-other"]);
    assert_eq!(code, 2);
    assert!(err.contains("REFUSED"));
    assert_eq!(json1, std::fs::read_to_string(dir.join("key-g1.public.json")).unwrap(), "refused retry changed nothing");
    // Restore check: byte identical descriptor, and a wrong label or key version fails.
    let expect = dir.join("key-g1.descriptor.hex");
    let (code, out, _) = cli(&["restore-check", "--generation", "1", "--label", "d2-unit-k1", "--expect-descriptor-file", expect.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    let (code, _, _) = cli(&["restore-check", "--generation", "1", "--label", "d2-unit-k2", "--expect-descriptor-file", expect.to_str().unwrap()]);
    assert_eq!(code, 1);
    let (code, _, _) = cli(&["restore-check", "--generation", "2", "--label", "d2-unit-k1", "--expect-descriptor-file", expect.to_str().unwrap()]);
    assert_eq!(code, 1, "wrong key version");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tool_refuses_production_recovery_role_and_unsafe_paths() {
    let dir = temp_dir("refuse");
    let d = dir.to_str().unwrap();
    for args in [
        vec!["keygen", "--production", "--generation", "1", "--out-dir", d, "--label", "d2-unit-k1"],
        vec!["keygen", "--class", "production", "--generation", "1", "--out-dir", d, "--label", "d2-unit-k1"],
        vec!["keygen", "--wallet-recovery", "--generation", "1", "--out-dir", d, "--label", "d2-unit-k1"],
        vec!["sign", "production"],
    ] {
        let (code, out, err) = cli(&args);
        assert_eq!(code, 2);
        assert!(err.contains("no production mode") && out.is_empty());
    }
    // OS-entropy mode needs a named TEST-VALUE backup path; a generic path is refused.
    let (code, _, err) = cli(&["keygen", "--generation", "1", "--out-dir", d, "--os-entropy"]);
    assert_eq!(code, 2, "{err}");
    let plain = dir.join("backup.txt");
    let (code, _, _) = cli(&["keygen", "--generation", "1", "--out-dir", d, "--os-entropy", "--backup-file", plain.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(!plain.exists());
    // Unknown generation, missing directory, unknown flag.
    assert_eq!(cli(&["keygen", "--generation", "3", "--out-dir", d, "--label", "d2-unit-k1"]).0, 2);
    assert_eq!(cli(&["keygen", "--generation", "1", "--out-dir", "Z:/no/such/dir", "--label", "d2-unit-k1"]).0, 2);
    assert_eq!(cli(&["keygen", "--generation", "1", "--out-dir", d, "--label", "d2-unit-k1", "--phrase"]).0, 2);
    assert_eq!(cli(&[]).0, 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn os_entropy_mode_writes_only_the_named_test_value_backup_and_never_prints_secrets() {
    let dir = temp_dir("os");
    let d = dir.to_str().unwrap();
    let backup = dir.join("k1.test-value-backup");
    let b = backup.to_str().unwrap();
    let (code, out, err) = cli(&["keygen", "--generation", "1", "--out-dir", d, "--os-entropy", "--backup-file", b]);
    assert_eq!(code, 0, "{err}");
    // The backup carries the loud header; it is the only secret-bearing file.
    let text = std::fs::read_to_string(&backup).unwrap();
    assert!(text.starts_with(keys::BACKUP_HEADER));
    let phrase = text.lines().last().unwrap().to_string();
    assert_eq!(phrase.split_whitespace().count(), 24);
    let key = HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap();
    // Refuses to overwrite an existing backup (no silent loss of a key).
    let (code, _, _) = cli(&["keygen", "--generation", "2", "--out-dir", d, "--os-entropy", "--backup-file", b]);
    assert_eq!(code, 2);
    assert_eq!(text, std::fs::read_to_string(&backup).unwrap());
    // Restore from the backup medium alone and sign a challenge with it.
    let expect = dir.join("key-g1.descriptor.hex");
    let (code, out2, err2) = cli(&["restore-check", "--generation", "1", "--backup-file", b, "--expect-descriptor-file", expect.to_str().unwrap()]);
    assert_eq!(code, 0, "{err2}");
    // Wrong generation stamp in the backup is refused.
    assert_eq!(cli(&["restore-check", "--generation", "2", "--backup-file", b, "--expect-descriptor-file", expect.to_str().unwrap()]).0, 2);
    // A backup lacking the header is not accepted.
    let fake = dir.join("fake.test-value-backup");
    std::fs::write(&fake, format!("generation=1\n{phrase}\n")).unwrap();
    assert_eq!(cli(&["restore-check", "--generation", "1", "--backup-file", fake.to_str().unwrap(), "--expect-descriptor-file", expect.to_str().unwrap()]).0, 2);

    let descriptor = key.public().descriptor(1).unwrap();
    let c = Challenge::new(&descriptor, Phase::Rehearsal, key.public().address_id(1).unwrap(), h32("r"), h32("c"), h32("n-os")).unwrap();
    let cfile = dir.join("challenge.hex");
    std::fs::write(&cfile, keys::hex(&c.encode().unwrap())).unwrap();
    let sig = dir.join("proof.sig.hex");
    let (code, out3, err3) = cli(&["sign", "--generation", "1", "--backup-file", b, "--challenge-file", cfile.to_str().unwrap(), "--out", sig.to_str().unwrap()]);
    assert_eq!(code, 0, "{err3}");
    let signature = proof::signature_from_bytes(&keys::unhex(&std::fs::read_to_string(&sig).unwrap()).unwrap()).unwrap();
    c.verify(&descriptor, &signature).unwrap();
    // A second signing to the same output path is refused (signatures are randomized).
    assert_eq!(cli(&["sign", "--generation", "1", "--backup-file", b, "--challenge-file", cfile.to_str().unwrap(), "--out", sig.to_str().unwrap()]).0, 2);
    // A production challenge is refused by the CLI.
    let p = Challenge::new(&descriptor, Phase::Production, key.public().address_id(1).unwrap(), h32("r"), h32("c"), h32("n-p")).unwrap();
    let pfile = dir.join("production-challenge.hex");
    std::fs::write(&pfile, keys::hex(&p.encode().unwrap())).unwrap();
    let psig = dir.join("p.sig");
    let (code, _, err) = cli(&["sign", "--generation", "1", "--backup-file", b, "--challenge-file", pfile.to_str().unwrap(), "--out", psig.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.contains("PRODUCTION_SECURITY_QUALIFIED"));
    assert!(!psig.exists());

    // R-guard: every emitted stream and every non-backup file is public-only and TEST-VALUE.
    for (name, text) in [("keygen stdout", &out), ("restore stdout", &out2), ("sign stdout", &out3), ("sign stderr", &err3)] {
        assert_public_only(name, text, &phrase, &key);
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.to_str().unwrap().to_string();
        if name.ends_with(keys::BACKUP_SUFFIX) {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_public_only(&name, &text, &phrase, &key);
        if name.ends_with("public.json") {
            assert!(text.contains("TEST-VALUE") && text.contains("OS-ENTROPY"));
        }
    }
    assert!(out.contains("TEST-VALUE"));
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!backup.exists());
}

// ------------------------------------------------- exact preimages (continuation order, section 7)
//
// The deterministic companion of the committed V1 vectors: for each V1 vector the exact bytes each of
// the TWO signatures covers, the CBOR item split of the challenge and descriptor, and derived negative
// vectors. Every value is a pure function of the committed V1 file, so the committed file must equal a
// fresh derivation exactly. Regenerate (public data only) with BUILD8_TREASURY_PREIMAGE_VECTORS=<path>.

const PREIMAGE_VECTORS: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-PREIMAGE-VECTORS-V1.json");
/// RFC 8032 Ed448 dom4(phflag = 0, context = empty) = "SigEd448" || 0x00 || 0x00.
const ED448_DOM4_PURE_EMPTY_CONTEXT: &[u8] = b"SigEd448\x00\x00";
const CHALLENGE_ITEM_NAMES: [&str; 14] = [
    "version",
    "network",
    "phase",
    "class",
    "generation",
    "suite_id",
    "policy_id",
    "profile",
    "descriptor_sha256",
    "address_id",
    "treasury_authority",
    "treasury_record_sha256",
    "ceremony_context",
    "nonce",
];
const DESCRIPTOR_ITEM_NAMES: [&str; 9] = ["version", "network", "role", "generation", "suite_id", "policy_id", "profile", "ed448_public_key", "fndsa_public_key"];

unsafe extern "C" {
    // Vendored OpenSSL curve448 (custody copy): RFC 8032 Ed448 verification with explicit context and
    // prehash flag. The production path calls it with an empty context and phflag 0
    // (qualification/openssl-curve448-port/profile_adapter.c, build8_qual_ed448_verify).
    fn ossl_ed448_verify(
        ctx: *mut std::ffi::c_void,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        public_key: *const u8,
        context: *const u8,
        context_len: usize,
        phflag: u8,
        propq: *const std::ffi::c_char,
    ) -> i32;
}
fn ed448_verify_with(public: &[u8; 57], signature: &[u8; 114], message: &[u8], context: &[u8], phflag: u8) -> bool {
    let context_ptr = if context.is_empty() { std::ptr::null() } else { context.as_ptr() };
    unsafe {
        ossl_ed448_verify(
            std::ptr::null_mut(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            public.as_ptr(),
            context_ptr,
            context.len(),
            phflag,
            std::ptr::null(),
        ) == 1
    }
}
fn shake256_64(input: &[u8]) -> [u8; 64] {
    let mut sh = fn_dsa::SHAKE256::new();
    sh.inject(input);
    sh.flip();
    let mut out = [0u8; 64];
    sh.extract(&mut out);
    out
}

/// The CBOR items of a definite-length array of unsigned integers, text and byte strings: offset,
/// length, the initial byte(s) with the length argument ("cbor_header") and the decoded value.
fn cbor_items(raw: &[u8], names: &[&str]) -> Vec<serde_json::Value> {
    use minicbor::data::Type;
    let mut d = minicbor::Decoder::new(raw);
    assert_eq!(d.array().unwrap(), Some(names.len() as u64));
    let mut out = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let start = d.position();
        let (value, payload) = match d.datatype().unwrap() {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => (serde_json::json!(d.u64().unwrap()), 0),
            Type::String => {
                let s = d.str().unwrap();
                (serde_json::json!(s), s.len())
            }
            Type::Bytes => {
                let b = d.bytes().unwrap();
                (serde_json::json!(hex::encode(b)), b.len())
            }
            other => panic!("unexpected CBOR item {other:?}"),
        };
        let end = d.position();
        out.push(serde_json::json!({
            "index": i + 1,
            "name": name,
            "offset": start,
            "length": end - start,
            "cbor_header": hex::encode(&raw[start..end - payload]),
            "value": value,
        }));
    }
    assert_eq!(d.position(), raw.len(), "no trailing bytes");
    out
}

fn v1_bytes(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}
fn v1_signature(v: &serde_json::Value) -> HybridSignature {
    HybridSignature { ed448: v1_bytes(v, "ed448_signature").try_into().unwrap(), fndsa: v1_bytes(v, "fndsa_signature").try_into().unwrap() }
}
fn result_name(r: std::result::Result<(), ProofError>) -> String {
    match r {
        Ok(()) => "VALID".to_string(),
        Err(e) => format!("{e:?}"),
    }
}
/// Evaluate one negative vector exactly as a verifier must: strict challenge decode, two-component
/// signature codec, then the descriptor bindings and BOTH signatures (in `domain` when one is named).
fn evaluate_negative(n: &serde_json::Value, base: &serde_json::Value) -> String {
    let pick = |key: &str, base_key: &str| hex::decode(n[key].as_str().unwrap_or_else(|| base[base_key].as_str().unwrap())).unwrap();
    let challenge_bytes = pick("challenge_hex", "challenge");
    let descriptor = pick("descriptor_hex", "descriptor");
    let serialization = match n["signature_serialization_hex"].as_str() {
        Some(s) => hex::decode(s).unwrap(),
        None => proof::signature_to_bytes(&v1_signature(base)),
    };
    let challenge = match Challenge::decode(&challenge_bytes) {
        Ok(c) => c,
        Err(e) => return format!("{e:?}"),
    };
    let signature = match proof::signature_from_bytes(&serialization) {
        Ok(s) => s,
        Err(e) => return format!("{e:?}"),
    };
    if let Some(domain) = n["domain"].as_str() {
        let other = [Domain::Transaction].into_iter().find(|d| d.bytes() == domain.as_bytes()).expect("known domain");
        let (public, _) = PublicKey::decode_descriptor(&descriptor).unwrap();
        return match public.verify(other, &challenge_bytes, &signature) {
            Ok(()) => "VALID".to_string(),
            Err(_) => "BadSignature".to_string(),
        };
    }
    result_name(challenge.verify(&descriptor, &signature))
}

fn preimage_vectors() -> serde_json::Value {
    let committed: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let list = committed["vectors"].as_array().unwrap();
    let domain = Domain::TreasuryProofOfControl.bytes();
    let mut vectors = Vec::new();
    for v in list {
        let challenge = v1_bytes(v, "challenge");
        let descriptor = v1_bytes(v, "descriptor");
        let signature = v1_signature(v);
        let (public, generation) = PublicKey::decode_descriptor(&descriptor).unwrap();
        // Intent: SHA-512 over domain || 0x00 || challenge, no length prefix (the source's own intent()).
        let preimage = [domain, &[0u8][..], &challenge[..]].concat();
        let m = intent(Domain::TreasuryProofOfControl, &challenge).unwrap();
        assert_eq!(<[u8; 64]>::from(sha2::Sha512::digest(&preimage)), m);
        // Ed448: pure RFC 8032 Ed448 over the 64-byte intent with dom4(0, "").
        assert!(ed448_verify_with(&public.ed448, &signature.ed448, &m, b"", 0));
        assert!(!ed448_verify_with(&public.ed448, &signature.ed448, &m, b"x", 0), "a non-empty context must not verify");
        assert!(!ed448_verify_with(&public.ed448, &signature.ed448, &m, b"", 1), "Ed448ph must not verify");
        assert!(!ed448_verify_with(&public.ed448, &signature.ed448, &challenge, b"", 0), "the raw challenge is not the message");
        // FN-DSA-1024: raw message (HASH_ID_RAW), empty context; mu = SHAKE256(hpk || 0x00 || 0x00 || m).
        let hpk = fn_dsa::hashed_vrfykey_from_vrfykey(&public.fndsa);
        assert_eq!(hpk, shake256_64(&public.fndsa));
        let mu_input = [&hpk[..], &[0u8, 0u8][..], &m[..]].concat();
        let mu = fn_dsa::compute_mu(&hpk, &fn_dsa::DOMAIN_NONE, &fn_dsa::HASH_ID_RAW, &m);
        assert_eq!(mu, shake256_64(&mu_input));
        let vk = fn_dsa::VerifyingKey1024::decode(&public.fndsa).unwrap();
        assert!(vk.verify(&signature.fndsa, &fn_dsa::DOMAIN_NONE, &fn_dsa::HASH_ID_RAW, &m));
        assert!(vk.verify(&signature.fndsa, &fn_dsa::DOMAIN_NONE, &fn_dsa::HASH_ID_EXTMU, &mu), "mu is exactly what is signed");
        assert!(!vk.verify(&signature.fndsa, &fn_dsa::DomainContext(b"x"), &fn_dsa::HASH_ID_RAW, &m), "a non-empty context must not verify");
        assert!(!vk.verify(&signature.fndsa, &fn_dsa::DOMAIN_NONE, &fn_dsa::HASH_ID_SHA512, &m), "the pre-hash framing must not verify");
        Challenge::decode(&challenge).unwrap().verify(&descriptor, &signature).expect("V1 vector verifies");
        let address_prefix = b"MUTINY-BUILD8-HYBRID-ADDRESS-V1\0";
        let address = <[u8; 32]>::from(Sha256::digest([&address_prefix[..], &descriptor[..]].concat()));
        assert_eq!(address, public.address_id(generation).unwrap());
        vectors.push(serde_json::json!({
            "label_public": v["label_public"],
            "generation": generation,
            "challenge_hex": hex::encode(&challenge),
            "challenge_length": challenge.len(),
            "challenge_items": cbor_items(&challenge, &CHALLENGE_ITEM_NAMES),
            "intent_preimage_hex": hex::encode(&preimage),
            "intent_preimage_length": preimage.len(),
            "intent_sha512": hex::encode(m),
            "descriptor_length": descriptor.len(),
            "descriptor_sha256": hex::encode(proof::sha256(&descriptor)),
            "descriptor_items": cbor_items(&descriptor, &DESCRIPTOR_ITEM_NAMES),
            "address_id_preimage_prefix_hex": hex::encode(address_prefix),
            "address_id": hex::encode(address),
            "ed448": {
                "scheme": "RFC 8032 Ed448 (pure, phflag 0), context empty",
                "dom4_hex": hex::encode(ED448_DOM4_PURE_EMPTY_CONTEXT),
                "message_hex": hex::encode(m),
                "public_key_hex": hex::encode(public.ed448),
                "signature_hex": hex::encode(signature.ed448),
                "r_hex": hex::encode(&signature.ed448[..57]),
                "s_hex": hex::encode(&signature.ed448[57..]),
                "verdict": "VALID",
            },
            "fndsa": {
                "scheme": "FN-DSA-1024, profile MUTINY-FNDSA1024-PORNIN-20260722-V1, raw message (hash identifier 0x00), empty context",
                "message_hex": hex::encode(m),
                "public_key_header_hex": hex::encode(&public.fndsa[..1]),
                "hashed_public_key_shake256_64_hex": hex::encode(hpk),
                "mu_input_hex": hex::encode(&mu_input),
                "mu_shake256_64_hex": hex::encode(mu),
                "signature_header_hex": hex::encode(&signature.fndsa[..1]),
                "signature_nonce_hex": hex::encode(&signature.fndsa[1..41]),
                "signature_hex": hex::encode(signature.fndsa),
                "verdict": "VALID",
            },
            "signature_serialization_hex": hex::encode(proof::signature_to_bytes(&signature)),
            "signature_serialization_length": proof::SIGNATURE_BYTES,
            "verdict": "VALID",
        }));
    }
    // Derived negative vectors (based on d2-vector-k1; d2-vector-k2 supplies the foreign components).
    let k1 = &list[0];
    let k2 = &list[1];
    let c = v1_bytes(k1, "challenge");
    let s1 = proof::signature_to_bytes(&v1_signature(k1));
    let s2 = proof::signature_to_bytes(&v1_signature(k2));
    let with = |at: usize, replace: &[u8], len: usize| [&c[..at], replace, &c[at + len..]].concat();
    let profile_at = 12; // offset of item 8 (profile) in a generation-1 challenge
    assert_eq!(&c[profile_at..profile_at + 2], &[0x78, 0x23]);
    let class_at = 8; // offset of item 4 (class)
    assert_eq!(c[class_at], 0x02);
    let (k1_public, _) = PublicKey::decode_descriptor(&v1_bytes(k1, "descriptor")).unwrap();
    let (k2_public, _) = PublicKey::decode_descriptor(&v1_bytes(k2, "descriptor")).unwrap();
    let transaction = Domain::Transaction.bytes();
    let n = |name: &str, layer: &str, expected: &str, fields: serde_json::Value| {
        let mut o = serde_json::json!({"name": name, "based_on": "d2-vector-k1", "layer": layer, "expected": expected});
        for (k, v) in fields.as_object().unwrap() {
            o[k] = v.clone();
        }
        o
    };
    let negatives = vec![
        n("truncated_challenge", "codec", "Malformed", serde_json::json!({"challenge_hex": hex::encode(&c[..c.len() - 1])})),
        n("extended_challenge", "codec", "Malformed", serde_json::json!({"challenge_hex": hex::encode([&c[..], &[0u8][..]].concat())})),
        n("non_canonical_integer_version", "codec", "NonCanonical", serde_json::json!({"challenge_hex": hex::encode(with(1, &[0x18, 0x01], 1))})),
        n("indefinite_length_array", "codec", "Malformed", serde_json::json!({"challenge_hex": hex::encode([&[0x9f][..], &c[1..], &[0xff][..]].concat())})),
        n("profile_as_byte_string", "codec", "Malformed", serde_json::json!({"challenge_hex": hex::encode(with(profile_at, &[0x58], 1))})),
        n("other_network", "codec", "Malformed", serde_json::json!({"challenge_hex": hex::encode(with(6, &[0x02], 1))})),
        n("class_phase_mismatch", "codec", "ClassPhaseMismatch", serde_json::json!({"challenge_hex": hex::encode(with(class_at, &[0x01], 1))})),
        n("zero_nonce", "codec", "ZeroField", serde_json::json!({"challenge_hex": hex::encode([&c[..c.len() - 32], &[0u8; 32][..]].concat())})),
        n("flipped_challenge_last_byte", "signature", "BadSignature", serde_json::json!({"challenge_hex": k1["negative_flipped_challenge"]})),
        n(
            "wrong_domain_transaction",
            "signature",
            "BadSignature",
            serde_json::json!({
                "domain": std::str::from_utf8(transaction).unwrap(),
                "intent_sha512": hex::encode(sha2::Sha512::digest([transaction, &[0u8][..], &c[..]].concat())),
            }),
        ),
        n("ed448_component_only", "signature_codec", "Malformed", serde_json::json!({"signature_serialization_hex": hex::encode(&s1[..114])})),
        n("fndsa_component_only", "signature_codec", "Malformed", serde_json::json!({"signature_serialization_hex": hex::encode(&s1[114..])})),
        n("ed448_with_zero_fndsa", "signature", "BadSignature", serde_json::json!({"signature_serialization_hex": hex::encode([&s1[..114], &[0u8; 1280][..]].concat())})),
        n("zero_ed448_with_fndsa", "signature", "BadSignature", serde_json::json!({"signature_serialization_hex": hex::encode([&[0u8; 114][..], &s1[114..]].concat())})),
        n("swapped_serialization_order", "signature", "BadSignature", serde_json::json!({"signature_serialization_hex": hex::encode([&s1[114..], &s1[..114]].concat())})),
        n("mixed_components_k1_ed448_k2_fndsa", "signature", "BadSignature", serde_json::json!({"signature_serialization_hex": hex::encode([&s1[..114], &s2[114..]].concat())})),
        n("same_key_stamped_generation_2", "descriptor", "WrongKeyVersion", serde_json::json!({"descriptor_hex": hex::encode(k1_public.descriptor(2).unwrap())})),
        n("other_key_same_generation", "descriptor", "AlteredDescriptor", serde_json::json!({"descriptor_hex": hex::encode(k2_public.descriptor(1).unwrap())})),
    ];
    serde_json::json!({
        "schema": "BUILD8-TREASURY-PROOF-OF-CONTROL-PREIMAGE-VECTORS-V1",
        "synthetic_only": true,
        "test_value": true,
        "production_authorized": false,
        "note": "Public data only, derived deterministically from qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json (TEST-VALUE keys from public labels). For each V1 vector: the CBOR item split, the exact intent preimage and the exact bytes each of the two signatures covers. A negative vector names only what differs from d2-vector-k1; its expected value is the first refusal of a strict verifier.",
        "source_vectors": "qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json",
        "source_vectors_sha256": hex::encode(Sha256::digest(VECTORS.as_bytes())),
        "domain": {"ascii": std::str::from_utf8(domain).unwrap(), "hex": hex::encode(domain), "length": domain.len()},
        "profile": {"ascii": PROFILE, "hex": hex::encode(PROFILE.as_bytes()), "length": PROFILE.len()},
        "rules": {
            "intent": "intent = SHA-512(domain || 0x00 || challenge); no length prefix; payload at most 1,048,576 bytes",
            "ed448": "RFC 8032 Ed448, phflag 0, context empty: verify(public_key, intent, signature) with dom4 = SigEd448 || 0x00 || 0x00; the public key and R must decode to points other than the identity",
            "fndsa": "FN-DSA-1024 (profile string above), raw message: hpk = SHAKE256(public_key, 64), mu = SHAKE256(hpk || 0x00 || 0x00 || intent, 64), c = HashToPoint(SHAKE256(signature[1..41] || mu)); public key header 0x0a, signature header 0x3a",
            "serialization": "signature = ed448 (114 bytes) || fndsa (1280 bytes) = 1394 bytes; any other length is malformed; no header, no length prefix",
        },
        "vectors": vectors,
        "negative": negatives,
    })
}

#[test]
fn preimage_vectors_are_exact_and_reproducible_from_the_committed_v1_vectors() {
    let fresh = preimage_vectors();
    if let Ok(path) = std::env::var("BUILD8_TREASURY_PREIMAGE_VECTORS") {
        std::fs::write(path, serde_json::to_string_pretty(&fresh).unwrap() + "\n").unwrap();
    }
    let committed: serde_json::Value = serde_json::from_str(PREIMAGE_VECTORS).expect("committed preimage vectors file");
    assert_eq!(committed, fresh, "the committed preimage vectors equal a fresh derivation");
    // Every negative vector is refused for exactly its stated reason, and nothing in it is VALID.
    let v1: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let base = &v1["vectors"][0];
    let negatives = committed["negative"].as_array().unwrap();
    assert_eq!(negatives.len(), 18);
    for n in negatives {
        assert_eq!(evaluate_negative(n, base), n["expected"].as_str().unwrap(), "{}", n["name"]);
    }
    // The positive vectors evaluate VALID through the same evaluator.
    assert_eq!(evaluate_negative(&serde_json::json!({}), base), "VALID");
}

// --------------------------------------- Ed448 small-order public keys (independent reproduction S3)
//
// A key A of order dividing 4 makes the cofactored RFC 8032 equation [4][S]B = [4]R + [4][k]A hold for
// R = [r]B, S = r and EVERY message, with no private key. The vendored OpenSSL verifier (cofactored)
// accepts such a forgery; the repository's key check (`build8_qual_ed448_public_valid`, which decodes
// through the 4-isogeny and refuses points it maps to the identity) must refuse every small-order key,
// both as a verification key and inside a descriptor. Construction uses only existing primitives: R from
// `ossl_ed448_public_from_private`, S from the clamped SHAKE256 scalar reduced modulo the group order.

/// Ed448 group order L, little-endian (RFC 8032: 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885).
const ED448_ORDER_LE_HEX: &str = "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00";
/// The four Ed448 points of order 1, 2 and 4 (RFC 8032 encodings): (1) all-zero = (+-1, 0) order 4,
/// (2) (1, 0) with the sign bit = the other order-4 point, (3) y = p - 1 = (0, -1) order 2, (4) y = 1 = identity.
fn ed448_small_order_keys() -> Vec<(&'static str, [u8; 57])> {
    let mut sign = [0u8; 57];
    sign[56] = 0x80;
    let mut order2 = [0xffu8; 57]; // p - 1 = 2^448 - 2^224 - 2, little-endian, sign bit clear
    order2[0] = 0xfe;
    order2[28] = 0xfe;
    order2[56] = 0x00;
    let mut identity = [0u8; 57];
    identity[0] = 1;
    vec![("all-zero encoding, order 4", [0u8; 57]), ("(1, 0) with the sign bit, order 4", sign), ("(0, -1), order 2", order2), ("identity (0, 1)", identity)]
}
fn le_ge(a: &[u8; 57], b: &[u8; 57]) -> bool {
    for i in (0..57).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}
fn le_sub(a: &mut [u8; 57], b: &[u8; 57]) {
    let mut borrow = 0i16;
    for i in 0..57 {
        let v = a[i] as i16 - b[i] as i16 - borrow;
        borrow = if v < 0 { 1 } else { 0 };
        a[i] = (v + 256 * borrow) as u8;
    }
    assert_eq!(borrow, 0);
}
/// (R, S) = ([s]B, s mod L) for the clamped scalar s of `seed` (RFC 8032 key derivation).
fn ed448_forgery(seed: &[u8; 57]) -> [u8; 114] {
    let mut r = [0u8; 57];
    assert_eq!(unsafe { ossl_ed448_public_from_private(std::ptr::null_mut(), r.as_mut_ptr(), seed.as_ptr(), std::ptr::null()) }, 1);
    let mut sh = fn_dsa::SHAKE256::new();
    sh.inject(seed);
    sh.flip();
    let mut h = [0u8; 114];
    sh.extract(&mut h);
    let mut s: [u8; 57] = h[..57].try_into().unwrap();
    s[0] &= 0xfc;
    s[56] = 0;
    s[55] |= 0x80;
    let order: [u8; 57] = hex::decode(ED448_ORDER_LE_HEX).unwrap().try_into().unwrap();
    while le_ge(&s, &order) {
        le_sub(&mut s, &order);
    }
    let mut sig = [0u8; 114];
    sig[..57].copy_from_slice(&r);
    sig[57..].copy_from_slice(&s);
    sig
}
fn raw_ed448_verify(public: &[u8; 57], sig: &[u8; 114], message: &[u8]) -> bool {
    ed448_verify_with(public, sig, message, b"", 0)
}

#[test]
fn ed448_small_order_keys_are_forgeable_under_rfc8032_and_refused_by_this_port() {
    let v1: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let k1 = &v1["vectors"][0];
    let challenge = hex::decode(k1["challenge"].as_str().unwrap()).unwrap();
    let messages: Vec<Vec<u8>> = vec![
        intent(Domain::TreasuryProofOfControl, &challenge).unwrap().to_vec(),
        intent(Domain::Transaction, b"any payload").unwrap().to_vec(),
        vec![0u8; 64],
    ];
    let mut seed = [0u8; 57];
    seed[..32].copy_from_slice(&Sha256::digest(b"c3-small-order-forgery-seed"));
    let forged = ed448_forgery(&seed);
    // The honest control: the forgery's R is the public key of `seed`, so (R, S) is NOT a signature by R.
    let keys = ed448_small_order_keys();
    for (name, key) in &keys {
        // The repository refuses every small-order key, whatever the message.
        assert_eq!(unsafe { build8_qual_ed448_public_valid(key.as_ptr(), 57) }, 0, "{name}: key accepted");
        for m in &messages {
            assert_eq!(unsafe { build8_qual_ed448_verify(key.as_ptr(), 57, forged.as_ptr(), 114, m.as_ptr(), 64) }, 0, "{name}: forgery accepted by the port");
        }
    }
    // The attack is real against the plain RFC 8032 verifier for the two order-4 keys (every message).
    for (name, key) in &keys[..2] {
        for m in &messages {
            assert!(raw_ed448_verify(key, &forged, m), "{name}: the plain verifier refuses the forgery (construction broken)");
        }
    }
    // An honest key is unaffected.
    let (honest, _) = PublicKey::decode_descriptor(&hex::decode(k1["descriptor"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(unsafe { build8_qual_ed448_public_valid(honest.ed448.as_ptr(), 57) }, 1);
    // Inside a descriptor: the descriptor decoder refuses the key (validate -> Key), so a proof is DescriptorInvalid.
    for (name, key) in &keys {
        let mut public = honest.clone();
        public.ed448 = *key;
        assert_eq!(public.validate(), Err(Error::Key), "{name}");
        assert_eq!(public.descriptor(1), Err(Error::Key), "{name}");
    }
}

// ------------------------ V2 additions: small-order keys (S3) and multi-defect probes (S5), NEW file
//
// `qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json` (the V1 files keep their bytes):
// (1) every Ed448 key of order 1, 2 or 4 inside an otherwise well-formed proof whose Ed448 half is the
//     forgery above and whose FN-DSA half is a valid signature by the honest FN-DSA key: refused as
//     `DescriptorInvalid`; the plain RFC 8032 verdict of the forgery is recorded next to it;
// (2) the multi-defect probes of the independent reproduction, each with the first refusal of the
//     normative evaluation order (schema section 7.0) and the rule that decides it.
// The FN-DSA halves of (1) are randomized and kept in `fndsa_signatures`; every other field is a pure
// function of the committed V1 and ceremony V1 vector files. Regenerate (public data only) with
// BUILD8_TREASURY_PROOF_ADDITIONS=<path>.

const PROOF_ADDITIONS: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS.json");
const CEREMONY_VECTORS_V1: &str = include_str!("../../qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json");
const ADDRESS_PREFIX: &[u8] = b"MUTINY-BUILD8-HYBRID-ADDRESS-V1\0";

/// The strict evaluation of one presented proof at the cryptographic layer, in the normative order of
/// schema section 7.0: challenge decode (D1 to D6), signature serialization (I2), then
/// `Challenge::verify` (V1 to V6). The result is the first refusal, or VALID.
fn evaluate_strict(challenge: &[u8], descriptor: &[u8], serialization: &[u8]) -> String {
    let c = match Challenge::decode(challenge) {
        Ok(c) => c,
        Err(e) => return format!("{e:?}"),
    };
    let s = match proof::signature_from_bytes(serialization) {
        Ok(s) => s,
        Err(e) => return format!("{e:?}"),
    };
    result_name(c.verify(descriptor, &s))
}
fn splice(raw: &[u8], at: usize, remove: usize, insert: &[u8]) -> Vec<u8> {
    [&raw[..at], insert, &raw[at + remove..]].concat()
}
/// Offset of the payload of item `index` (0-based) of a definite CBOR array, from `cbor_items`.
fn payload_offset(raw: &[u8], names: &[&str], index: usize) -> usize {
    let item = &cbor_items(raw, names)[index];
    item["offset"].as_u64().unwrap() as usize + item["cbor_header"].as_str().unwrap().len() / 2
}
/// `challenge` with items 9 and 10 recomputed for `descriptor` (SHA-256 and AddressID, schema A.9).
fn rebind(challenge: &[u8], descriptor: &[u8]) -> Vec<u8> {
    let sha = proof::sha256(descriptor);
    let address = <[u8; 32]>::from(Sha256::digest([ADDRESS_PREFIX, descriptor].concat()));
    let at9 = payload_offset(challenge, &CHALLENGE_ITEM_NAMES, 8);
    let at10 = payload_offset(challenge, &CHALLENGE_ITEM_NAMES, 9);
    splice(&splice(challenge, at9, 32, &sha), at10, 32, &address)
}
fn json_hex(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("{key} missing"))).unwrap()
}

/// Everything of the additions file except the randomized FN-DSA halves (`fndsa_signatures`).
fn proof_additions_deterministic() -> serde_json::Value {
    let v1: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let cer: serde_json::Value = serde_json::from_str(CEREMONY_VECTORS_V1).unwrap();
    let k1v = &v1["vectors"][0];
    let k2v = &v1["vectors"][1];
    assert_eq!((k1v["label_public"].as_str(), k2v["label_public"].as_str()), (Some("d2-vector-k1"), Some("d2-vector-k2")));
    let c = json_hex(k1v, "challenge");
    let d1 = json_hex(k1v, "descriptor");
    let d2 = json_hex(k2v, "descriptor");
    let s1 = proof::signature_to_bytes(&v1_signature(k1v));
    let key_at = payload_offset(&d1, &DESCRIPTOR_ITEM_NAMES, 7);
    assert_eq!(&d1[key_at - 2..key_at], &[0x58, 0x39], "item 8 is a 57-byte string");
    // (1) small-order keys.
    let mut seed = [0u8; 57];
    seed[..32].copy_from_slice(&Sha256::digest(b"c3-small-order-forgery-seed"));
    let forged = ed448_forgery(&seed);
    let order_of = |name: &str| if name.contains("order 4") { 4 } else if name.contains("order 2") { 2 } else { 1 };
    let mut keys = Vec::new();
    for (name, key) in ed448_small_order_keys() {
        let descriptor = splice(&d1, key_at, 57, &key);
        let challenge = rebind(&c, &descriptor);
        let m = intent(Domain::TreasuryProofOfControl, &challenge).unwrap();
        keys.push(serde_json::json!({
            "name": name,
            "order": order_of(name),
            "public_key_hex": hex::encode(key),
            "repository_key_check": if unsafe { build8_qual_ed448_public_valid(key.as_ptr(), 57) } == 1 { "ACCEPTED" } else { "REFUSED" },
            // Textbook RFC 8032 (section 5.2.3 decoding, 5.2.7 check [4][S]B = [4]R + [4][k]A): with [4]A the
            // identity and S = s, R = [s]B the equation holds for every message, for all four keys.
            "plain_rfc8032_ed448_verdict_of_the_forgery": "VALID",
            "vendored_openssl_ed448_verdict_of_the_forgery": if raw_ed448_verify(&key, &forged, &m) { "VALID" } else { "INVALID" },
            "descriptor_hex": hex::encode(&descriptor),
            "challenge_hex": hex::encode(&challenge),
            "intent_sha512": hex::encode(m),
            "expected": "DescriptorInvalid",
        }));
    }
    let honest_challenge = c.clone();
    let honest_m = intent(Domain::TreasuryProofOfControl, &honest_challenge).unwrap();
    let (honest, _) = PublicKey::decode_descriptor(&d1).unwrap();
    // (2) multi-defect probes (independent reproduction, attack.py), each with its deciding rule.
    let p5 = &cer["proofs"]["P5_production_phase"];
    let p5_challenge = json_hex(p5, "challenge_hex");
    let p5_descriptor = json_hex(&cer["keys"][p5["signer"].as_str().unwrap()], "descriptor_hex");
    let p5_signature = hex::decode(cer["signatures"]["P5_production_phase"].as_str().unwrap()).unwrap();
    let mut cpm_trunc = c.clone();
    cpm_trunc[8] = 0x01;
    cpm_trunc.pop();
    let nc_cpm = [&c[..1], &[0x18, 0x01][..], &c[2..8], &[0x01][..], &c[9..]].concat();
    let nm_len = splice(&c, 49, 2, &[0x59, 0x00, 0x20]);
    let ind_prof = [&c[..12], &[0x7f][..], &c[12..49], &[0xff][..], &c[49..]].concat();
    let mut bad_utf8 = c.clone();
    bad_utf8[14] = 0xff;
    let zn_tr = [&c[..221], &[0u8; 32][..], &[0x00][..]].concat();
    let suite2 = {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(9).unwrap().u8(1).unwrap().u32(NETWORK).unwrap().u8(Role::WalletOwner as u8).unwrap().u64(1).unwrap();
        e.u16(2).unwrap().u8(BOTH_REQUIRED_POLICY_ID).unwrap().str(PROFILE).unwrap().bytes(&honest.ed448).unwrap().bytes(&honest.fndsa).unwrap();
        e.into_writer()
    };
    let mut not_a_point = [0xffu8; 57];
    not_a_point[56] = 0x00;
    let bad_point = splice(&d1, key_at, 57, &not_a_point);
    let probes: Vec<(&str, Vec<u8>, Vec<u8>, Vec<u8>, &str, &str)> = vec![
        ("class_phase_mismatch_and_truncated", cpm_trunc, d1.clone(), s1.clone(), "Malformed", "D2 before D4: the truncated last item cannot be read, so the class/phase rule is never reached"),
        (
            "non_minimal_version_and_class_phase_mismatch",
            nc_cpm,
            d1.clone(),
            s1.clone(),
            "ClassPhaseMismatch",
            "D2 reads a non-shortest integer by its value; D4 (class/phase) precedes D6 (re-encoding), which alone refuses the non-shortest form",
        ),
        ("non_minimal_length_of_item_9", nm_len, d1.clone(), s1.clone(), "NonCanonical", "D2 reads a non-shortest length by its value; D6 (re-encoding) refuses it"),
        ("indefinite_length_profile", ind_prof, d1.clone(), s1.clone(), "Malformed", "D2: every item has a definite length; an indefinite-length text string is not read"),
        ("invalid_utf8_in_the_profile", bad_utf8, d1.clone(), s1.clone(), "Malformed", "D2: item 8 must read as a valid UTF-8 text string; the profile comparison (V4) is never reached"),
        ("zero_nonce_and_trailing_byte", zn_tr, d1.clone(), s1.clone(), "Malformed", "D3 (no byte after item 14) precedes D5 (zero fields)"),
        (
            "production_phase_with_an_ed448_only_signature",
            p5_challenge,
            p5_descriptor,
            p5_signature[..114].to_vec(),
            "Malformed",
            "I2 (the 1,394-byte serialization) precedes every verification step, including the production refusal V1",
        ),
        ("generation_two_descriptor_with_an_fndsa_only_signature", c.clone(), d2, s1[114..].to_vec(), "Malformed", "I2 precedes the descriptor checks V2 to V5"),
        ("descriptor_with_suite_2", rebind(&c, &suite2), suite2, s1.clone(), "DescriptorInvalid", "V2: the descriptor decoder pins suite 1, policy 1 and the profile, before the challenge items are compared (V4)"),
        ("descriptor_ed448_key_not_a_point", rebind(&c, &bad_point), bad_point, s1.clone(), "DescriptorInvalid", "V2: both public keys are validated when the descriptor is decoded"),
    ];
    let probes: Vec<serde_json::Value> = probes
        .into_iter()
        .map(|(name, challenge, descriptor, serialization, expected, rule)| {
            serde_json::json!({
                "name": name,
                "challenge_hex": hex::encode(&challenge),
                "descriptor_hex": hex::encode(&descriptor),
                "signature_serialization_hex": hex::encode(&serialization),
                "signature_serialization_length": serialization.len(),
                "expected": expected,
                "rule": rule,
            })
        })
        .collect();
    serde_json::json!({
        "schema": "BUILD8-TREASURY-PROOF-OF-CONTROL-VECTORS-V2-ADDITIONS",
        "synthetic_only": true,
        "test_value": true,
        "production_authorized": false,
        "added_after": "independent reproduction, round 1: S3 (Ed448 public keys of small order) and S5 (evaluation order of inputs with more than one defect)",
        "note": "Public data only (TEST-VALUE keys from public labels). The FN-DSA halves in fndsa_signatures are randomized; every other field is a pure function of the two source files. 'expected' is the first refusal of a strict verifier evaluating in the normative order of schema section 7.0: challenge decode D1 to D6, signature serialization I2, then V1 to V6.",
        "sources": {
            "v1_vectors": {"path": "qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json", "sha256": hex::encode(Sha256::digest(VECTORS.as_bytes()))},
            "ceremony_vectors_v1": {"path": "qualification/TREASURY-PROOF-OF-CONTROL-CEREMONY-VECTORS-V1.json", "sha256": hex::encode(Sha256::digest(CEREMONY_VECTORS_V1.as_bytes()))},
        },
        "ed448_small_order": {
            "rule": "An Ed448 public key (and R) must decode and must not be of order 1, 2 or 4 (refuse A when [4]A is the identity); the repository decodes through the 4-isogeny and refuses points it maps to the identity (build8_qual_ed448_public_valid). Under textbook RFC 8032 (section 5.2.3 decoding, section 5.2.7 check) the forgery below verifies under EVERY one of the four keys for every message, because [4]A is the identity (plain_rfc8032_ed448_verdict_of_the_forgery); the vendored OpenSSL verifier, like OpenSSL 3.5.7, already refuses the order-2 and identity encodings at decoding, so it accepts the forgery only under the two order-4 keys (vendored_openssl_ed448_verdict_of_the_forgery).",
            "group_order_le_hex": ED448_ORDER_LE_HEX,
            "forgery": {
                "construction": "s = clamp(SHAKE256(seed, 114)[0..57]) reduced modulo the group order; R = encode([s]B) (the RFC 8032 public key of seed); S = s; signature = R || S. No private key of any small-order point is involved.",
                "seed_hex": hex::encode(seed),
                "r_hex": hex::encode(&forged[..57]),
                "s_hex": hex::encode(&forged[57..]),
                "ed448_signature_hex": hex::encode(forged),
            },
            "base": "d2-vector-k1 of the V1 vectors: its descriptor with item 8 (Ed448 key) replaced, and its challenge with items 9 and 10 recomputed for that descriptor; the FN-DSA half is a fresh signature over the intent by the d2-vector-k1 FN-DSA key (fndsa_signatures)",
            "keys": keys,
            "honest_control": {
                "name": "honest d2-vector-k1 key with the forged Ed448 half",
                "public_key_hex": hex::encode(honest.ed448),
                "repository_key_check": if unsafe { build8_qual_ed448_public_valid(honest.ed448.as_ptr(), 57) } == 1 { "ACCEPTED" } else { "REFUSED" },
                "plain_rfc8032_ed448_verdict_of_the_forgery": if raw_ed448_verify(&honest.ed448, &forged, &honest_m) { "VALID" } else { "INVALID" },
                "vendored_openssl_ed448_verdict_of_the_forgery": if raw_ed448_verify(&honest.ed448, &forged, &honest_m) { "VALID" } else { "INVALID" },
                "descriptor_hex": hex::encode(&d1),
                "challenge_hex": hex::encode(&honest_challenge),
                "intent_sha512": hex::encode(honest_m),
                "expected": "BadSignature",
            },
        },
        "multi_defect_probes": probes,
    })
}

#[test]
fn proof_additions_v2_small_order_keys_and_multi_defect_probes_hold() {
    let fresh = proof_additions_deterministic();
    if let Ok(path) = std::env::var("BUILD8_TREASURY_PROOF_ADDITIONS") {
        // The FN-DSA halves: fresh signatures by the honest d2-vector-k1 key over each intent.
        let key = Credential::from_label("d2-vector-k1", 1).unwrap();
        let mut halves = serde_json::Map::new();
        let small = fresh["ed448_small_order"]["keys"].as_array().unwrap().iter().chain([&fresh["ed448_small_order"]["honest_control"]]);
        for entry in small {
            let challenge = json_hex(entry, "challenge_hex");
            // Keep a committed half when its challenge is unchanged (byte-stable regeneration).
            let name = entry["name"].as_str().unwrap();
            let kept = serde_json::from_str::<serde_json::Value>(PROOF_ADDITIONS).ok().and_then(|c| c["fndsa_signatures"][name].as_str().map(str::to_string));
            let half = kept.unwrap_or_else(|| hex::encode(key.key().sign(Domain::TreasuryProofOfControl, &challenge).unwrap().fndsa));
            halves.insert(name.to_string(), serde_json::json!(half));
        }
        let mut file = fresh.clone();
        file["fndsa_signatures"] = serde_json::Value::Object(halves);
        std::fs::write(path, serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
    }
    let committed: serde_json::Value = serde_json::from_str(PROOF_ADDITIONS).expect("committed additions file");
    let mut deterministic = committed.clone();
    let halves = deterministic.as_object_mut().unwrap().remove("fndsa_signatures").expect("fndsa_signatures");
    assert_eq!(deterministic, fresh, "every deterministic field equals a fresh derivation");
    // (1) Each small-order key: the repository refuses the key, the FN-DSA half is valid by itself, the
    //     forgery is VALID for plain RFC 8032 exactly for the order-4 keys, and the proof is refused.
    let (honest, _) = PublicKey::decode_descriptor(&hex::decode(fresh["ed448_small_order"]["honest_control"]["descriptor_hex"].as_str().unwrap()).unwrap()).unwrap();
    let vk = fn_dsa::VerifyingKey1024::decode(&honest.fndsa).unwrap();
    let forged = hex::decode(fresh["ed448_small_order"]["forgery"]["ed448_signature_hex"].as_str().unwrap()).unwrap();
    let small = committed["ed448_small_order"]["keys"].as_array().unwrap();
    assert_eq!(small.len(), 4);
    for entry in small.iter().chain([&committed["ed448_small_order"]["honest_control"]]) {
        let name = entry["name"].as_str().unwrap();
        let fndsa = hex::decode(halves[name].as_str().unwrap()).unwrap();
        let m = json_hex(entry, "intent_sha512");
        assert!(vk.verify(&fndsa, &fn_dsa::DOMAIN_NONE, &fn_dsa::HASH_ID_RAW, &m), "{name}: the FN-DSA half verifies");
        let serialization = [&forged[..], &fndsa[..]].concat();
        assert_eq!(evaluate_strict(&json_hex(entry, "challenge_hex"), &json_hex(entry, "descriptor_hex"), &serialization), entry["expected"].as_str().unwrap(), "{name}");
    }
    let verdicts: Vec<(&str, &str, &str, &str)> = small
        .iter()
        .map(|e| (e["repository_key_check"].as_str().unwrap(), e["plain_rfc8032_ed448_verdict_of_the_forgery"].as_str().unwrap(), e["vendored_openssl_ed448_verdict_of_the_forgery"].as_str().unwrap(), e["expected"].as_str().unwrap()))
        .collect();
    assert_eq!(
        verdicts,
        vec![
            ("REFUSED", "VALID", "VALID", "DescriptorInvalid"),
            ("REFUSED", "VALID", "VALID", "DescriptorInvalid"),
            ("REFUSED", "VALID", "INVALID", "DescriptorInvalid"),
            ("REFUSED", "VALID", "INVALID", "DescriptorInvalid"),
        ],
        "all four keys are forgeable under textbook RFC 8032 (the vendored OpenSSL already refuses the order-2 and identity encodings at decoding) and every small-order key is refused"
    );
    let control = &committed["ed448_small_order"]["honest_control"];
    assert_eq!((control["repository_key_check"].as_str(), control["plain_rfc8032_ed448_verdict_of_the_forgery"].as_str()), (Some("ACCEPTED"), Some("INVALID")));
    // (2) Each multi-defect probe is refused with exactly the stated first refusal.
    let probes = committed["multi_defect_probes"].as_array().unwrap();
    let expected = [
        "Malformed",
        "ClassPhaseMismatch",
        "NonCanonical",
        "Malformed",
        "Malformed",
        "Malformed",
        "Malformed",
        "Malformed",
        "DescriptorInvalid",
        "DescriptorInvalid",
    ];
    assert_eq!(probes.len(), expected.len());
    for (p, want) in probes.iter().zip(expected) {
        let got = evaluate_strict(&json_hex(p, "challenge_hex"), &json_hex(p, "descriptor_hex"), &json_hex(p, "signature_serialization_hex"));
        assert_eq!((got.as_str(), p["expected"].as_str().unwrap()), (want, want), "{}", p["name"]);
    }
}

/// S5 decoder order D4 before D5: a challenge with a class/phase mismatch AND a zero nonce is
/// `ClassPhaseMismatch` (fresh after mutant N18 of the fixer campaign survived without it).
#[test]
fn decoder_checks_class_and_phase_before_zero_fields() {
    let v1: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let c = hex::decode(v1["vectors"][0]["challenge"].as_str().unwrap()).unwrap();
    let mut both = [&c[..c.len() - 32], &[0u8; 32][..]].concat();
    both[8] = 0x01;
    assert_eq!(Challenge::decode(&both), Err(ProofError::ClassPhaseMismatch));
    let zero_only = [&c[..c.len() - 32], &[0u8; 32][..]].concat();
    assert_eq!(Challenge::decode(&zero_only), Err(ProofError::ZeroField));
}

/// Round 3: `WrongRole` only for a fully valid descriptor of another role; a non-WalletOwner role
/// together with another invalid field is `DescriptorInvalid`.
#[test]
fn wrong_role_only_for_an_otherwise_valid_descriptor() {
    let v1: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let d1 = hex::decode(v1["vectors"][0]["descriptor"].as_str().unwrap()).unwrap();
    let c = Challenge::decode(&hex::decode(v1["vectors"][0]["challenge"].as_str().unwrap()).unwrap()).unwrap();
    let mut recovery = d1.clone();
    assert_eq!(recovery[7], 0x01, "role byte");
    recovery[7] = 0x02; // WalletRecovery, otherwise valid
    assert_eq!(c.check_descriptor(&recovery).err(), Some(ProofError::WrongRole));
    let mut both = recovery.clone();
    both[9] = 0x02; // and suite 2
    assert_eq!(c.check_descriptor(&both).err(), Some(ProofError::DescriptorInvalid));
}
