#![cfg(feature = "zeroize")]
use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

#[test]
fn independent_openssl_argon2id_public_vectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("build8-public-vectors.json")).unwrap();
    assert_eq!(fixture["synthetic_only"], true);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for c in cases {
        let u = |name: &str| c[name].as_u64().unwrap() as u32;
        let params = Params::new(u("memory"), u("rounds"), u("lanes"), Some(u("length") as usize)).unwrap();
        let mut blocks = Zeroizing::new(vec![Block::default(); params.block_count()]);
        let mut output = Zeroizing::new([0u8;64]);
        let password = hex::decode(c["password"].as_str().unwrap()).unwrap();
        let salt = hex::decode(c["salt"].as_str().unwrap()).unwrap();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(&password, &salt, &mut output[..u("length") as usize], blocks.as_mut_slice()).unwrap();
        assert_eq!(hex::encode(&output[..u("length") as usize]), c["expected"].as_str().unwrap());
    }
}
