//! Deterministic parser campaign; accepting a canonical encoding is not authority.
use mutiny_consensus_v8::{
    admission_v2::{Admission, Policy},
    continuity_v2::{Certificate, Vote},
    settlement::SettlementProof,
    transactions_v2::Transfer,
};
use mutiny_crypto_v2::PublicKey;
fn public_fixture(name: &str, field: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qualification")
        .join(name);
    let f: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    hex::decode(f[field].as_str().unwrap()).unwrap()
}
fn check(raw: &[u8]) {
    macro_rules! canonical {
        ($t:ty) => {
            if let Ok(v) = <$t>::decode(raw) {
                assert_eq!(v.encode().unwrap(), raw);
            }
        };
    }
    canonical!(Admission);
    canonical!(Policy);
    canonical!(Certificate);
    canonical!(Vote);
    canonical!(SettlementProof);
    canonical!(Transfer);
    if let Ok((p, g)) = PublicKey::decode_descriptor(raw) {
        assert_eq!(p.descriptor(g).unwrap(), raw);
    }
}
#[test]
fn bounded_hostile_wire_never_panics_or_accepts_an_alternate_encoding() {
    let admission = public_fixture("admission-public-v2.json", "admission");
    let policy = public_fixture("admission-public-v2.json", "policy");
    let transfer = public_fixture("hybrid-transaction-public-v2.json", "transaction");
    let settlement = public_fixture("settlement-public-v1.json", "proof");
    let decoded = SettlementProof::decode(&settlement).unwrap();
    let certificate = decoded.certificate.encode().unwrap();
    let vote = decoded.certificate.votes[0].encode().unwrap();
    let descriptor = Transfer::decode(&transfer).unwrap().inputs[0]
        .descriptor
        .clone();
    let seeds = [
        admission,
        policy,
        transfer,
        settlement,
        certificate,
        vote,
        descriptor,
    ];
    let mut cases = 0usize;
    for seed in &seeds {
        check(seed);
        cases += 1;
        // Every possible truncation; embedded byte strings must not turn a
        // missing tail into an accepted shorter canonical object.
        for end in 0..seed.len() {
            check(&seed[..end]);
            cases += 1;
        }
        for at in (0..seed.len()).step_by(7) {
            for byte in [0, 0x18, 0x58, 0x80, 0x9b, 0xbf, 0xff] {
                let mut mutated = seed.clone();
                mutated[at] = byte;
                check(&mutated);
                cases += 1;
            }
        }
        let mut trailing = seed.clone();
        trailing.extend_from_slice(&[0, 0xff]);
        check(&trailing);
        cases += 1;
    }
    // Deterministic public fuzz stream. Not used for keys or entropy.
    let mut state = 0xd9a51e7859273c61u64;
    for length in 0..4096 {
        let mut raw = vec![0; length];
        for b in &mut raw {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = state as u8;
        }
        check(&raw);
        cases += 1;
    }
    for depth in [17, 64, 1024] {
        let mut raw = vec![0x81; depth];
        raw.push(0);
        check(&raw);
        cases += 1;
    }
    for tag in [0x5b, 0x7b, 0x9b, 0xbb] {
        let mut raw = vec![tag];
        raw.extend_from_slice(&u64::MAX.to_be_bytes());
        check(&raw);
        cases += 1;
    }
    let report = serde_json::json!({"schema":"BUILD8-HYBRID-HOSTILE-WIRE-V1","result":"PASS","cases":cases,
        "decoders_per_case":7,"cryptographic_authorization_asserted":false,"production_qualified":false,
        "scope":"Deterministic truncation, mutation, random bytes, nesting and claimed-length bounds; no exhaustive fuzzing claim."});
    if std::env::var("BUILD8_EXPORT_PUBLIC_REPORTS").as_deref() == Ok("1") {
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/hybrid-hostile-wire-v1.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    }
}
