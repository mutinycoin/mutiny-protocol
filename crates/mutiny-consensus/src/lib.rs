use mutiny_crypto::{
    anchor_entropy, epoch_seed, mutiny_argon2id, proof_below_target, ticket_salt, ticket_seed,
    CryptoError,
};
use mutiny_types::Hash256;
use num_bigint::BigUint;
use num_traits::One;
use thiserror::Error;

pub const W_MAX: u16 = 2048;
pub const L_SAT: u64 = 65_536;
pub const DIFFICULTY_Q32_ONE: u64 = 1u64 << 32;

#[derive(Debug, Error)]
pub enum ConsensusMathError {
    #[error("authorized capacity is zero")]
    ZeroAuthorizedCapacity,
    #[error("derived integer does not fit 32 bytes")]
    DoesNotFitU256,
}

#[derive(Debug, Error)]
pub enum MiningError {
    #[error("ticket index is outside the deterministic work allocation")]
    BadTicketIndex,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Exact Mutiny V1 equal-work allocation.
///
/// For 0 < L < N, W is the smallest positive integer satisfying:
///
/// `W^25 * N^16 >= W_MAX^25 * L^16`
///
/// with N=65,536 and W_MAX=2,048.
pub fn work_units(eligible_licenses: u64) -> u16 {
    if eligible_licenses == 0 {
        return 0;
    }
    if eligible_licenses >= L_SAT {
        return W_MAX;
    }

    let n = BigUint::from(L_SAT);
    let l = BigUint::from(eligible_licenses);
    let c = BigUint::from(W_MAX);

    let n16 = n.pow(16);
    let rhs = c.pow(25) * l.pow(16);

    let mut lo: u16 = 1;
    let mut hi: u16 = W_MAX;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let lhs = BigUint::from(mid).pow(25) * &n16;
        if lhs >= rhs {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

pub fn authorized_capacity(eligible_licenses: u64) -> u128 {
    (eligible_licenses as u128) * (work_units(eligible_licenses) as u128)
}

/// Derive the frozen 256-bit target:
///
/// B = floor(2^256 / A)
/// T = min(2^256 - 1, floor(B * C_q32 / 2^32))
pub fn derive_target(
    authorized_capacity: u128,
    correction_q32: u64,
) -> Result<[u8; 32], ConsensusMathError> {
    if authorized_capacity == 0 {
        return Err(ConsensusMathError::ZeroAuthorizedCapacity);
    }

    let two256 = BigUint::one() << 256usize;
    let max_u256 = &two256 - BigUint::one();
    let base = &two256 / BigUint::from(authorized_capacity);
    let corrected = (base * BigUint::from(correction_q32)) >> 32usize;
    let final_target = if corrected > max_u256 {
        max_u256
    } else {
        corrected
    };

    biguint_to_u256_be(&final_target)
}

fn biguint_to_u256_be(value: &BigUint) -> Result<[u8; 32], ConsensusMathError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(ConsensusMathError::DoesNotFitU256);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// Complete Pack-A mining derivation for one deterministic ticket.
pub struct TicketDerivation {
    pub anchor_entropy: Hash256,
    pub epoch_seed: Hash256,
    pub ticket_seed: Hash256,
    pub ticket_salt: Hash256,
    pub argon2_proof: Hash256,
    pub winning: bool,
}

pub fn derive_ticket(
    anchor_epoch: u64,
    anchor_license_id: &[u8; 32],
    anchor_ticket_index: u16,
    anchor_argon2_proof: &[u8; 32],
    epoch: u64,
    license_id: &[u8; 32],
    ticket_index: u16,
    work_units_for_epoch: u16,
    target: &[u8; 32],
) -> Result<TicketDerivation, MiningError> {
    if ticket_index >= work_units_for_epoch {
        return Err(MiningError::BadTicketIndex);
    }

    let ae = anchor_entropy(
        anchor_epoch,
        anchor_license_id,
        anchor_ticket_index,
        anchor_argon2_proof,
    );
    let es = epoch_seed(&ae.0, epoch);
    let seed = ticket_seed(&es.0, license_id, ticket_index);
    let salt = ticket_salt(&es.0, license_id, ticket_index);
    let proof = mutiny_argon2id(&seed.0, &salt.0)?;
    let winning = proof_below_target(&proof.0, target);

    Ok(TicketDerivation {
        anchor_entropy: ae,
        epoch_seed: es,
        ticket_seed: seed,
        ticket_salt: salt,
        argon2_proof: proof,
        winning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn pack_a_work_allocation_table() {
        let vectors = [
            (0, 0),
            (1, 2),
            (12, 9),
            (64, 25),
            (256, 59),
            (1024, 144),
            (4096, 348),
            (16_384, 844),
            (32_768, 1315),
            (65_536, 2048),
            (65_537, 2048),
        ];
        for (licenses, expected) in vectors {
            assert_eq!(work_units(licenses), expected, "L={licenses}");
        }
        assert_eq!(authorized_capacity(12), 108);
    }

    #[test]
    fn pack_e_initial_twelve_license_target_is_reproducible() {
        let target = derive_target(108, DIFFICULTY_Q32_ONE).unwrap();
        assert_eq!(
            target,
            h("025ed097b425ed097b425ed097b425ed097b425ed097b425ed097b425ed097b4")
        );
    }

    #[test]
    fn pack_a_ticket_index_boundary() {
        let anchor_license: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let anchor_proof: [u8; 32] = (0x20u8..0x40).collect::<Vec<_>>().try_into().unwrap();
        let license: [u8; 32] = (0xa0u8..0xc0).collect::<Vec<_>>().try_into().unwrap();
        let target = [0xff; 32];

        assert!(derive_ticket(
            12345,
            &anchor_license,
            17,
            &anchor_proof,
            12346,
            &license,
            8,
            9,
            &target,
        )
        .is_ok());

        assert!(matches!(
            derive_ticket(
                12345,
                &anchor_license,
                17,
                &anchor_proof,
                12346,
                &license,
                9,
                9,
                &target,
            ),
            Err(MiningError::BadTicketIndex)
        ));
    }
}
