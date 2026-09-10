pub mod domains;

use argon2::{Algorithm, Argon2, Params, Version};
use mutiny_types::Hash256;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid hard-coded Argon2 parameters")]
    InvalidArgon2Params,
    #[error("Argon2 hashing failed")]
    Argon2Failure,
}

pub fn sha256_domain(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let mut h = Sha256::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    Hash256(h.finalize().into())
}

/// Mutiny V1 block-signing digest over the exact 208-byte header core.
pub fn block_signing_digest(header_core: &[u8; 208]) -> Hash256 {
    sha256_domain(domains::BLOCK_SIGN, &[header_core])
}

/// Mutiny V1 block identifier over the exact 272-byte full header.
pub fn block_hash(header: &[u8; 272]) -> Hash256 {
    sha256_domain(domains::BLOCK_ID, &[header])
}

pub fn anchor_entropy(
    anchor_epoch: u64,
    anchor_license_id: &[u8; 32],
    anchor_ticket_index: u16,
    anchor_argon2_proof: &[u8; 32],
) -> Hash256 {
    let epoch = anchor_epoch.to_be_bytes();
    let ticket = anchor_ticket_index.to_be_bytes();
    sha256_domain(
        domains::ANCHOR_ENTROPY,
        &[&epoch, anchor_license_id, &ticket, anchor_argon2_proof],
    )
}

pub fn epoch_seed(anchor_entropy: &[u8; 32], epoch: u64) -> Hash256 {
    let epoch_be = epoch.to_be_bytes();
    sha256_domain(domains::EPOCH_SEED, &[anchor_entropy, &epoch_be])
}

pub fn ticket_seed(epoch_seed: &[u8; 32], license_id: &[u8; 32], ticket_index: u16) -> Hash256 {
    let ticket = ticket_index.to_be_bytes();
    sha256_domain(domains::TICKET_SEED, &[epoch_seed, license_id, &ticket])
}

pub fn ticket_salt(epoch_seed: &[u8; 32], license_id: &[u8; 32], ticket_index: u16) -> Hash256 {
    let ticket = ticket_index.to_be_bytes();
    sha256_domain(domains::ARGON2_SALT, &[epoch_seed, license_id, &ticket])
}

/// The single Mutiny V1 consensus Argon2 entry point.
///
/// Hard-coded consensus parameters:
/// - Argon2id
/// - version 0x13
/// - memory = 64 KiB
/// - time cost = 2
/// - parallelism = 1
/// - output = 32 bytes
/// - secret = empty
/// - associated data = empty
pub fn mutiny_argon2id(
    ticket_seed: &[u8; 32],
    ticket_salt: &[u8; 32],
) -> Result<Hash256, CryptoError> {
    let params = Params::new(64, 2, 1, Some(32)).map_err(|_| CryptoError::InvalidArgon2Params)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(ticket_seed, ticket_salt, &mut out)
        .map_err(|_| CryptoError::Argon2Failure)?;
    Ok(Hash256(out))
}

/// Big-endian fixed-width integers compare lexicographically byte-for-byte.
pub fn proof_below_target(proof: &[u8; 32], target: &[u8; 32]) -> bool {
    proof < target
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn pack_a_normal_epoch_vector() {
        let anchor_license: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let anchor_proof: [u8; 32] = (0x20u8..0x40).collect::<Vec<_>>().try_into().unwrap();
        let ae = anchor_entropy(12345, &anchor_license, 17, &anchor_proof);
        assert_eq!(
            ae.0,
            h("bc2d5215bb3652645efe1c458f0d1701a59f15fbcb90de28940607f75814f074")
        );

        let es = epoch_seed(&ae.0, 12346);
        assert_eq!(
            es.0,
            h("dc15d46d94897906e2acc59d6c119d25f7151e464eb24b078c09436be73c31a8")
        );

        let license: [u8; 32] = (0xa0u8..0xc0).collect::<Vec<_>>().try_into().unwrap();
        let seed = ticket_seed(&es.0, &license, 5);
        assert_eq!(
            seed.0,
            h("eebeb06e7347a9854809849ffb7ec882f5a05d2ab66ee2a6850f39ca63f1059e")
        );

        let salt = ticket_salt(&es.0, &license, 5);
        assert_eq!(
            salt.0,
            h("0bb8de31936a38e744768ac62a9951bd97b28055dc3daf19888d34cd3f1f9afe")
        );

        let proof = mutiny_argon2id(&seed.0, &salt.0).unwrap();
        assert_eq!(
            proof.0,
            h("51bef0bee57e6b25d2e598ea3a8d105dc2346bf678d4c62597a86a65aeccb87f")
        );
    }

    #[test]
    fn proof_target_boundary_is_strict() {
        let proof = h("51bef0bee57e6b25d2e598ea3a8d105dc2346bf678d4c62597a86a65aeccb87f");
        let plus_one = h("51bef0bee57e6b25d2e598ea3a8d105dc2346bf678d4c62597a86a65aeccb880");
        let equal = proof;
        let minus_one = h("51bef0bee57e6b25d2e598ea3a8d105dc2346bf678d4c62597a86a65aeccb87e");
        assert!(proof_below_target(&proof, &plus_one));
        assert!(!proof_below_target(&proof, &equal));
        assert!(!proof_below_target(&proof, &minus_one));
    }

    #[test]
    fn pack_a_block1_vector() {
        let genesis: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let es = epoch_seed(&genesis, 64);
        assert_eq!(
            es.0,
            h("9429a970554c05698e789e3665732b61aac61ef0ef637f2c2cd1d1ac82240255")
        );

        let license: [u8; 32] = (0xa0u8..0xc0).collect::<Vec<_>>().try_into().unwrap();
        let seed = ticket_seed(&es.0, &license, 5);
        assert_eq!(
            seed.0,
            h("f666af76de21efd9c222b8de4d40a8c59522cb436b9c66c181fc6741a289ea63")
        );
        let salt = ticket_salt(&es.0, &license, 5);
        assert_eq!(
            salt.0,
            h("2abc36c6c3fe395ef3c6267fdef01b01cd995bf1558afe0e5f8d375917de49b2")
        );
        let proof = mutiny_argon2id(&seed.0, &salt.0).unwrap();
        assert_eq!(
            proof.0,
            h("b46e4c3b720ede3d5c5acf732b5a5f886de1e0d8f724b199dba2edf7cad5c51b")
        );
    }
}
