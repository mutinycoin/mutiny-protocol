use mutiny_codec::{write_u16_be, write_u32_be, write_u64_be, write_u8, write_varuint};
use mutiny_crypto::{domains, sha256_domain};
use mutiny_types::{Hash256, LicenseId, StateRoot, TxId};
use num_bigint::BigUint;
use std::collections::BTreeMap;
use thiserror::Error;

pub const SMT_DEPTH: usize = 256;
pub const LICENSE_RECORD_V1_LEN: usize = 141;

pub const LICENSE_STATUS_PENDING: u8 = 0x00;
pub const LICENSE_STATUS_ACTIVE: u8 = 0x01;
pub const LICENSE_STATUS_REVOKED: u8 = 0x02;

pub const PURCHASE_METHOD_BTC: u8 = 0x01;
pub const PURCHASE_METHOD_MUT: u8 = 0x02;

pub const PS_CONSUMED_EVIDENCE: u16 = 0x0001;
pub const PS_OFFENSE_EVENT: u16 = 0x0002;
pub const PS_HISTORICAL_LICENSE_KEY: u16 = 0x0003;
pub const PS_DIVIDEND_ACCOUNT: u16 = 0x0004;
pub const PS_TREASURY_STATE: u16 = 0x0005;
pub const PS_CONSUMED_NATIVE_PAYMENT: u16 = 0x0006;
pub const PS_DIFFICULTY_HISTORY: u16 = 0x0007;
pub const PS_MINING_PRESENCE_STATE: u16 = 0x0008;
pub const PS_BITCOIN_HEADER: u16 = 0x0009;
pub const PS_BITCOIN_BEST_CHAIN: u16 = 0x000A;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StateError {
    #[error("compressed proof sibling count does not match bitmap")]
    ProofSiblingCount,
    #[error("compressed proof redundantly encodes a default sibling")]
    RedundantDefaultSibling,
    #[error("license record field is invalid")]
    InvalidLicenseRecord,
    #[error("mining presence state field is invalid")]
    InvalidMiningPresenceState,
    #[error("arithmetic overflow")]
    Overflow,
}

pub fn smt_empty_hashes() -> Vec<Hash256> {
    let mut out = Vec::with_capacity(SMT_DEPTH + 1);
    out.push(sha256_domain(domains::SMT_EMPTY_LEAF, &[]));
    for i in 0..SMT_DEPTH {
        let h = sha256_domain(domains::SMT_NODE, &[&out[i].0, &out[i].0]);
        out.push(h);
    }
    out
}

pub fn smt_empty_root() -> Hash256 {
    smt_empty_hashes()[SMT_DEPTH]
}

pub fn smt_node(left: &[u8; 32], right: &[u8; 32]) -> Hash256 {
    sha256_domain(domains::SMT_NODE, &[left, right])
}

fn key_bit_msb(key: &[u8; 32], depth: usize) -> u8 {
    debug_assert!(depth < 256);
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

pub fn single_leaf_root(key: &[u8; 32], leaf: &[u8; 32]) -> Hash256 {
    let empties = smt_empty_hashes();
    let mut cur = Hash256(*leaf);
    for depth in (0..SMT_DEPTH).rev() {
        let sibling = empties[SMT_DEPTH - 1 - depth];
        cur = if key_bit_msb(key, depth) == 0 {
            smt_node(&cur.0, &sibling.0)
        } else {
            smt_node(&sibling.0, &cur.0)
        };
    }
    cur
}

/// Root of a sparse tree whose inputs are already domain-separated leaf hashes.
pub fn sparse_root(entries: &BTreeMap<[u8; 32], [u8; 32]>) -> Hash256 {
    if entries.is_empty() {
        return smt_empty_root();
    }
    let empties = smt_empty_hashes();
    let mut level: BTreeMap<BigUint, Hash256> = entries
        .iter()
        .map(|(k, v)| (BigUint::from_bytes_be(k), Hash256(*v)))
        .collect();

    for height in 0..SMT_DEPTH {
        let mut next = BTreeMap::<BigUint, Hash256>::new();
        let mut consumed = BTreeMap::<BigUint, ()>::new();
        let default = empties[height];
        for (index, value) in level.iter() {
            if consumed.contains_key(index) {
                continue;
            }
            let sibling_index = index.clone() ^ BigUint::from(1u8);
            let sibling = level.get(&sibling_index).copied().unwrap_or(default);
            let is_right = (index.clone() & BigUint::from(1u8)) == BigUint::from(1u8);
            let parent = if is_right {
                smt_node(&sibling.0, &value.0)
            } else {
                smt_node(&value.0, &sibling.0)
            };
            next.insert(index.clone() >> 1usize, parent);
            consumed.insert(index.clone(), ());
            consumed.insert(sibling_index, ());
        }
        level = next;
    }
    level
        .get(&BigUint::from(0u8))
        .copied()
        .unwrap_or(empties[SMT_DEPTH])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedSmtProofV1 {
    pub bitmap: [u8; 32],
    /// Serialized in increasing root-depth order.
    pub nondefault_siblings: Vec<[u8; 32]>,
}

fn bitmap_set(bitmap: &[u8; 32], depth: usize) -> bool {
    ((bitmap[depth / 8] >> (7 - (depth % 8))) & 1) == 1
}

pub fn verify_compressed_proof(
    key: &[u8; 32],
    leaf: &[u8; 32],
    proof: &CompressedSmtProofV1,
    expected_root: &[u8; 32],
) -> Result<bool, StateError> {
    let expected_count: usize = proof.bitmap.iter().map(|b| b.count_ones() as usize).sum();
    if expected_count != proof.nondefault_siblings.len() {
        return Err(StateError::ProofSiblingCount);
    }
    let empties = smt_empty_hashes();
    let mut by_depth = BTreeMap::<usize, [u8; 32]>::new();
    let mut cursor = 0usize;
    for depth in 0..SMT_DEPTH {
        if bitmap_set(&proof.bitmap, depth) {
            let sibling = proof.nondefault_siblings[cursor];
            let default = empties[SMT_DEPTH - 1 - depth].0;
            if sibling == default {
                return Err(StateError::RedundantDefaultSibling);
            }
            by_depth.insert(depth, sibling);
            cursor += 1;
        }
    }

    let mut cur = Hash256(*leaf);
    for depth in (0..SMT_DEPTH).rev() {
        let sibling = by_depth
            .get(&depth)
            .copied()
            .unwrap_or(empties[SMT_DEPTH - 1 - depth].0);
        cur = if key_bit_msb(key, depth) == 0 {
            smt_node(&cur.0, &sibling)
        } else {
            smt_node(&sibling, &cur.0)
        };
    }
    Ok(cur.0 == *expected_root)
}

pub fn utxo_key(txid: &TxId, output_index: u16) -> Hash256 {
    let index = output_index.to_be_bytes();
    sha256_domain(domains::UTXO_KEY, &[&txid.0, &index])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoValueV1 {
    pub amount_strikes: u64,
    pub output_type: u8,
    pub payload: Vec<u8>,
    pub creation_epoch: u64,
    pub creation_height: u64,
    pub coinbase: bool,
}

impl UtxoValueV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_be(&mut out, self.amount_strikes);
        write_u8(&mut out, self.output_type);
        write_varuint(&mut out, self.payload.len() as u64);
        out.extend_from_slice(&self.payload);
        write_u64_be(&mut out, self.creation_epoch);
        write_u64_be(&mut out, self.creation_height);
        write_u8(&mut out, u8::from(self.coinbase));
        out
    }
}

pub fn utxo_leaf(key: &[u8; 32], value: &UtxoValueV1) -> Hash256 {
    let encoded = value.encode();
    sha256_domain(domains::UTXO_LEAF, &[key, &encoded])
}

/// Canonical 141-byte LicenseRecordV1.
///
/// Implementation-time clarification of the previously frozen 141-byte size:
/// the 33 bytes not enumerated in the prose Pack-C summary are the immutable
/// purchase provenance fields `purchase_method:u8` + `purchase_id:bytes32`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenseRecordV1 {
    pub version: u16,
    pub status: u8,
    pub purchase_method: u8,
    pub purchase_id: [u8; 32],
    pub owner_public_key: [u8; 32],
    pub owner_key_sequence: u32,
    pub mining_public_key: [u8; 32],
    pub mining_key_sequence: u32,
    pub issued_epoch: u64,
    pub activation_epoch: u64,
    pub strike_weight: u8,
    pub suspended_until_epoch: u64,
    pub revocation_epoch: u64,
}

impl LicenseRecordV1 {
    pub fn validate(&self) -> Result<(), StateError> {
        if self.version != 1
            || !matches!(
                self.status,
                LICENSE_STATUS_PENDING | LICENSE_STATUS_ACTIVE | LICENSE_STATUS_REVOKED
            )
            || !matches!(
                self.purchase_method,
                PURCHASE_METHOD_BTC | PURCHASE_METHOD_MUT
            )
            || self.strike_weight > 16
        {
            return Err(StateError::InvalidLicenseRecord);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, StateError> {
        self.validate()?;
        let mut out = Vec::with_capacity(LICENSE_RECORD_V1_LEN);
        write_u16_be(&mut out, self.version);
        write_u8(&mut out, self.status);
        write_u8(&mut out, self.purchase_method);
        out.extend_from_slice(&self.purchase_id);
        out.extend_from_slice(&self.owner_public_key);
        write_u32_be(&mut out, self.owner_key_sequence);
        out.extend_from_slice(&self.mining_public_key);
        write_u32_be(&mut out, self.mining_key_sequence);
        write_u64_be(&mut out, self.issued_epoch);
        write_u64_be(&mut out, self.activation_epoch);
        write_u8(&mut out, self.strike_weight);
        write_u64_be(&mut out, self.suspended_until_epoch);
        write_u64_be(&mut out, self.revocation_epoch);
        debug_assert_eq!(out.len(), LICENSE_RECORD_V1_LEN);
        Ok(out)
    }
}

pub fn license_leaf(
    license_id: &LicenseId,
    record: &LicenseRecordV1,
) -> Result<Hash256, StateError> {
    let encoded = record.encode()?;
    Ok(sha256_domain(
        domains::LICENSE_LEAF,
        &[&license_id.0, &encoded],
    ))
}

pub fn external_payment_leaf(payment_id: &[u8; 32], canonical_value: &[u8]) -> Hash256 {
    sha256_domain(
        domains::EXTERNAL_PAYMENT_LEAF,
        &[payment_id, canonical_value],
    )
}

pub fn protocol_state_key(object_type: u16, object_id: &[u8; 32]) -> Hash256 {
    let t = object_type.to_be_bytes();
    sha256_domain(domains::PROTOCOL_STATE_KEY, &[&t, object_id])
}

pub fn protocol_state_leaf(key: &[u8; 32], canonical_value: &[u8]) -> Hash256 {
    sha256_domain(domains::PROTOCOL_STATE_LEAF, &[key, canonical_value])
}

/// Pack-K canonical 46-byte MiningPresenceStateV1 ProtocolState value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MiningPresenceStateV1 {
    pub version: u16,
    pub mining_key_sequence: u32,
    pub last_presence_epoch: u64,
    pub last_presence_operation_id: [u8; 32],
}

impl MiningPresenceStateV1 {
    pub const ENCODED_LEN: usize = 46;

    pub fn validate(&self) -> Result<(), StateError> {
        if self.version != 1 {
            return Err(StateError::InvalidMiningPresenceState);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; 46], StateError> {
        self.validate()?;
        let mut out = [0u8; 46];
        out[..2].copy_from_slice(&self.version.to_be_bytes());
        out[2..6].copy_from_slice(&self.mining_key_sequence.to_be_bytes());
        out[6..14].copy_from_slice(&self.last_presence_epoch.to_be_bytes());
        out[14..46].copy_from_slice(&self.last_presence_operation_id);
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TreasuryStateV1 {
    pub available_strikes: u64,
    pub reserved_dividend_strikes: u64,
}

impl TreasuryStateV1 {
    pub fn encode(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.available_strikes.to_be_bytes());
        out[8..].copy_from_slice(&self.reserved_dividend_strikes.to_be_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LicenseDividendAccountV1 {
    pub license_id: LicenseId,
    pub award_epoch: u64,
    pub claim_deadline_epoch: u64,
    pub claimable_strikes: u64,
}

impl LicenseDividendAccountV1 {
    pub fn encode(&self) -> [u8; 56] {
        let mut out = [0u8; 56];
        out[..32].copy_from_slice(&self.license_id.0);
        out[32..40].copy_from_slice(&self.award_epoch.to_be_bytes());
        out[40..48].copy_from_slice(&self.claim_deadline_epoch.to_be_bytes());
        out[48..56].copy_from_slice(&self.claimable_strikes.to_be_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusMetaV1 {
    pub block_height: u64,
    pub eligible_license_count: u64,
    pub total_licenses_issued: u64,
    pub difficulty_correction_q32: u64,
    pub base_fee_rate_q32: u64,
    pub total_issued_strikes: u64,
}

impl ConsensusMetaV1 {
    pub fn encode(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        for (i, value) in [
            self.block_height,
            self.eligible_license_count,
            self.total_licenses_issued,
            self.difficulty_correction_q32,
            self.base_fee_rate_q32,
            self.total_issued_strikes,
        ]
        .into_iter()
        .enumerate()
        {
            out[i * 8..(i + 1) * 8].copy_from_slice(&value.to_be_bytes());
        }
        out
    }

    pub fn root(&self) -> Hash256 {
        let encoded = self.encode();
        sha256_domain(domains::META_ROOT, &[&encoded])
    }
}

pub fn state_root(
    utxo_root: &[u8; 32],
    license_root: &[u8; 32],
    external_payment_root: &[u8; 32],
    protocol_state_root: &[u8; 32],
    meta_root: &[u8; 32],
) -> StateRoot {
    StateRoot(
        sha256_domain(
            domains::STATE_ROOT,
            &[
                utxo_root,
                license_root,
                external_payment_root,
                protocol_state_root,
                meta_root,
            ],
        )
        .0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn license_fixture() -> (LicenseId, LicenseRecordV1) {
        (
            LicenseId((0x80u8..0xa0).collect::<Vec<_>>().try_into().unwrap()),
            LicenseRecordV1 {
                version: 1,
                status: LICENSE_STATUS_ACTIVE,
                purchase_method: PURCHASE_METHOD_BTC,
                purchase_id: (0x60u8..0x80).collect::<Vec<_>>().try_into().unwrap(),
                owner_public_key: (0x20u8..0x40).collect::<Vec<_>>().try_into().unwrap(),
                owner_key_sequence: 7,
                mining_public_key: (0x40u8..0x60).collect::<Vec<_>>().try_into().unwrap(),
                mining_key_sequence: 3,
                issued_epoch: 1000,
                activation_epoch: 1064,
                strike_weight: 1,
                suspended_until_epoch: 0,
                revocation_epoch: 0,
            },
        )
    }

    #[test]
    fn pack_c_empty_hashes() {
        let e = smt_empty_hashes();
        let vectors = [
            (
                0,
                "0e80585277a6e38f1478afaddb5ffd3251eb946d72234b24f47bb5e5f6f91f49",
            ),
            (
                1,
                "17e6a00dee7dabc0ed5c8255247247bb8c653470731a78aea92d2343244d7456",
            ),
            (
                2,
                "ff8c84b5982cca1e66415ce536454a4b5a338fe8da41ef49cbdedc206b100fbc",
            ),
            (
                8,
                "9ceed62f9738155788280db867756b23ac2aa5939f791ce6d17fc4dc31858c79",
            ),
            (
                16,
                "1059d962cd03ff2e7604a8513b8ce16c9008e9b5f6d800ee85b2f570fe6c4130",
            ),
            (
                32,
                "e5644c296f6f08416e1f1a3091539afe6cdb582edda0ce00464badc3f42975cd",
            ),
            (
                64,
                "53bf49ff6f6e772fe6971a7da06da294e52f82b9b76c7809a8a6a13ece1f4db3",
            ),
            (
                128,
                "240ce70b80530011ff88d0efe3f721d3c83d7fa529b59de3dc9991fd196fe965",
            ),
            (
                255,
                "f0a2c5a6c5c557433e64e1bf94b3dbdd7f5796b583016dcca312c6edf250046d",
            ),
            (
                256,
                "32584d12dab59c5261dcfff96c549940d8a168ac254e1a38dc389a7b72370d7a",
            ),
        ];
        for (i, expected) in vectors {
            assert_eq!(e[i].0, h32(expected), "empty level {i}");
        }
    }

    #[test]
    fn pack_c_utxo_and_membership_vectors() {
        let txid = TxId((0u8..32).collect::<Vec<_>>().try_into().unwrap());
        let key = utxo_key(&txid, 3);
        assert_eq!(
            key.0,
            h32("c5d1ce7dd268def158dffd6a60f6a7fb07deaf065c9c9266c8d19510f36b5dd1")
        );
        let value = UtxoValueV1 {
            amount_strikes: 800_000_000,
            output_type: 1,
            payload: (0xb0u8..0xd0).collect(),
            creation_epoch: 12346,
            creation_height: 100,
            coinbase: true,
        };
        assert_eq!(value.encode().len(), 59);
        let leaf = utxo_leaf(&key.0, &value);
        assert_eq!(
            leaf.0,
            h32("6b69299e8f7d3b9b5653e75f667b0216ac6a2ff659294e693095d0d5364a167b")
        );
        let root = single_leaf_root(&key.0, &leaf.0);
        assert_eq!(
            root.0,
            h32("1857df9dbecfd2806f8e0b9eec73f24e4c7aca9f5aa7499612078036e0150662")
        );
        let proof = CompressedSmtProofV1 {
            bitmap: [0; 32],
            nondefault_siblings: vec![],
        };
        assert!(verify_compressed_proof(&key.0, &leaf.0, &proof, &root.0).unwrap());

        let mut absent = key.0;
        absent[31] ^= 1;
        let mut bitmap = [0u8; 32];
        bitmap[31] = 1;
        let proof = CompressedSmtProofV1 {
            bitmap,
            nondefault_siblings: vec![leaf.0],
        };
        let empty_leaf = smt_empty_hashes()[0];
        assert!(verify_compressed_proof(&absent, &empty_leaf.0, &proof, &root.0).unwrap());
    }

    #[test]
    fn pack_c_license_record_and_transfer_vectors() {
        let (license_id, record) = license_fixture();
        let encoded = record.encode().unwrap();
        assert_eq!(encoded.len(), 141);
        let leaf = license_leaf(&license_id, &record).unwrap();
        assert_eq!(
            leaf.0,
            h32("38a4dc6d118f8cd47a4c28382452820c91c88e1cd2a75f98d858a893a33ff9b1")
        );
        let root = single_leaf_root(&license_id.0, &leaf.0);
        assert_eq!(
            root.0,
            h32("6e71e5a7d03fa995047d850a44e43b808868ca284aef010af6291d001eb7f5bb")
        );

        let mut transferred = record.clone();
        transferred.owner_public_key = (0x60u8..0x80).collect::<Vec<_>>().try_into().unwrap();
        transferred.owner_key_sequence = 8;
        transferred.mining_public_key = (0xa0u8..0xc0).collect::<Vec<_>>().try_into().unwrap();
        transferred.mining_key_sequence = 4;
        let leaf2 = license_leaf(&license_id, &transferred).unwrap();
        assert_eq!(
            leaf2.0,
            h32("971b7689297527b45e630016c0c9dd8a44de57a977618cb098948681fe1f7930")
        );
        assert_eq!(
            single_leaf_root(&license_id.0, &leaf2.0).0,
            h32("e040385fd3d8d5dcc3b0a299dd0bfcaad42c9515b73937f2cc690f6221928f6a")
        );
        assert_eq!(transferred.strike_weight, 1);
        assert_eq!(transferred.purchase_id, record.purchase_id);
    }

    #[test]
    fn pack_c_protocol_state_treasury_dividend_vector() {
        let (license_id, _) = license_fixture();
        let treasury_key = protocol_state_key(PS_TREASURY_STATE, &[0u8; 32]);
        let treasury = TreasuryStateV1 {
            available_strikes: 1_000_000_000_000,
            reserved_dividend_strikes: 12_345_678,
        };
        let treasury_leaf = protocol_state_leaf(&treasury_key.0, &treasury.encode());
        assert_eq!(
            treasury_key.0,
            h32("5e38d73afecf4835001f3663bf0a8404ecd3c3ab912a5f3eacaa770a2567e0d8")
        );
        assert_eq!(
            treasury_leaf.0,
            h32("b9a13068409049333fdb44651eab34975c7408bcea4bed9c11083d7881e5f750")
        );

        let dividend = LicenseDividendAccountV1 {
            license_id,
            award_epoch: 131_072,
            claim_deadline_epoch: 196_608,
            claimable_strikes: 12_345_678,
        };
        let dividend_key = protocol_state_key(PS_DIVIDEND_ACCOUNT, &license_id.0);
        let dividend_leaf = protocol_state_leaf(&dividend_key.0, &dividend.encode());
        assert_eq!(
            dividend_key.0,
            h32("dfeb1d029f4cd74b3ad2b5810aa685c28e0f7d870f50b54d429fbdb6428d30f5")
        );
        assert_eq!(
            dividend_leaf.0,
            h32("aa520b9153cd3abd8d94f2454af36915d71149456337cdb48cb5caa8e86f987b")
        );

        let mut entries = BTreeMap::new();
        entries.insert(treasury_key.0, treasury_leaf.0);
        entries.insert(dividend_key.0, dividend_leaf.0);
        let root = sparse_root(&entries);
        assert_eq!(
            root.0,
            h32("1a4a9fb2cb7dbd6c368d734e6413bf985ae54902ecf173baaa6f51a64679ff77")
        );
    }

    #[test]
    fn pack_c_meta_and_state_root_vector() {
        let meta = ConsensusMetaV1 {
            block_height: 2000,
            eligible_license_count: 12,
            total_licenses_issued: 12,
            difficulty_correction_q32: 1u64 << 32,
            base_fee_rate_q32: 1u64 << 32,
            total_issued_strikes: 1_000_812_345_678,
        };
        assert_eq!(hex::encode(meta.encode()), "00000000000007d0000000000000000c000000000000000c00000001000000000000000100000000000000e90510794e");
        let meta_root = meta.root();
        assert_eq!(
            meta_root.0,
            h32("4d2797347aa7d2ea39746daeb56b1a77e39265e21b518143613402048607cb07")
        );

        let root = state_root(
            &h32("1857df9dbecfd2806f8e0b9eec73f24e4c7aca9f5aa7499612078036e0150662"),
            &h32("6e71e5a7d03fa995047d850a44e43b808868ca284aef010af6291d001eb7f5bb"),
            &h32("32584d12dab59c5261dcfff96c549940d8a168ac254e1a38dc389a7b72370d7a"),
            &h32("1a4a9fb2cb7dbd6c368d734e6413bf985ae54902ecf173baaa6f51a64679ff77"),
            &meta_root.0,
        );
        assert_eq!(
            root.0,
            h32("2c1b812062d5d542b9b58a19ce664fb5739a300ac6a3179256d0c00bc7554789")
        );
    }

    #[test]
    fn compressed_proof_rejects_redundant_default() {
        let key = [0u8; 32];
        let mut bitmap = [0u8; 32];
        bitmap[0] = 0x80;
        let default = smt_empty_hashes()[255].0;
        let proof = CompressedSmtProofV1 {
            bitmap,
            nondefault_siblings: vec![default],
        };
        assert_eq!(
            verify_compressed_proof(&key, &smt_empty_hashes()[0].0, &proof, &smt_empty_root().0),
            Err(StateError::RedundantDefaultSibling)
        );
    }

    #[test]
    fn pack_k_mining_presence_state_golden_vector_is_exact() {
        assert_eq!(PS_MINING_PRESENCE_STATE, 0x0008);
        let license_id = h32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let operation_id = h32("f309184d23803800792f346483912110ddd4db4c23fbc2c4feb85883e75096f5");
        let value = MiningPresenceStateV1 {
            version: 1,
            mining_key_sequence: 2,
            last_presence_epoch: 1500,
            last_presence_operation_id: operation_id,
        };
        let encoded = value.encode().unwrap();
        assert_eq!(encoded.len(), 46);
        assert_eq!(hex::encode(encoded), "00010000000200000000000005dcf309184d23803800792f346483912110ddd4db4c23fbc2c4feb85883e75096f5");
        let key = protocol_state_key(PS_MINING_PRESENCE_STATE, &license_id);
        assert_eq!(
            hex::encode(key.0),
            "9011f89936dbab070850345c476d6ab950609f3086e3ed09f6704673b9dff592"
        );
        let leaf = protocol_state_leaf(&key.0, &encoded);
        assert_eq!(
            hex::encode(leaf.0),
            "6ca16ae0c05afdc35a6c8f86f8786b620aa420af3df9484366fd728896e0d0ea"
        );
        assert_eq!(
            hex::encode(single_leaf_root(&key.0, &leaf.0).0),
            "dd4486124588a7a2df3fe05a196b09d2ac8bb155a09c9a2c74697ba198312b83"
        );

        let mut wrong_version = value;
        wrong_version.version = 2;
        assert_eq!(
            wrong_version.validate(),
            Err(StateError::InvalidMiningPresenceState)
        );
    }
}

/// Pack M R2 authenticated Bitcoin header ProtocolState value.
/// ObjectID is the Bitcoin block hash in internal byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinHeaderStateV1 {
    pub version: u16,
    pub height: u32,
    pub raw_header: [u8; 80],
    pub relative_chainwork: [u8; 32],
}

impl BitcoinHeaderStateV1 {
    pub const ENCODED_LEN: usize = 118;

    pub fn validate(&self) -> bool {
        self.version == 1
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[..2].copy_from_slice(&self.version.to_be_bytes());
        out[2..6].copy_from_slice(&self.height.to_be_bytes());
        out[6..86].copy_from_slice(&self.raw_header);
        out[86..118].copy_from_slice(&self.relative_chainwork);
        out
    }
}

/// Pack M R2 Bitcoin best-chain singleton ProtocolState value.
/// ObjectID is bytes32(0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinBestChainStateV1 {
    pub version: u16,
    pub best_tip_hash_internal: [u8; 32],
    pub best_tip_height: u32,
    pub best_tip_relative_chainwork: [u8; 32],
}

impl BitcoinBestChainStateV1 {
    pub const ENCODED_LEN: usize = 70;

    pub fn validate(&self) -> bool {
        self.version == 1
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[..2].copy_from_slice(&self.version.to_be_bytes());
        out[2..34].copy_from_slice(&self.best_tip_hash_internal);
        out[34..38].copy_from_slice(&self.best_tip_height.to_be_bytes());
        out[38..70].copy_from_slice(&self.best_tip_relative_chainwork);
        out
    }
}

/// Root helper over only Pack-M Bitcoin ProtocolState objects.
///
/// The integrated node will merge these exact key/leaf pairs into its complete
/// ProtocolState map in the next 6.6A runtime-integration candidate.
pub fn bitcoin_header_protocol_state_root(
    headers: &[([u8; 32], BitcoinHeaderStateV1)],
    best_chain: Option<&BitcoinBestChainStateV1>,
) -> Hash256 {
    let mut entries = BTreeMap::<[u8; 32], [u8; 32]>::new();

    for (block_hash_internal, state) in headers {
        let key = protocol_state_key(PS_BITCOIN_HEADER, block_hash_internal);
        let value = state.encode();
        let leaf = protocol_state_leaf(&key.0, &value);
        entries.insert(key.0, leaf.0);
    }

    if let Some(best) = best_chain {
        let object_id = [0u8; 32];
        let key = protocol_state_key(PS_BITCOIN_BEST_CHAIN, &object_id);
        let value = best.encode();
        let leaf = protocol_state_leaf(&key.0, &value);
        entries.insert(key.0, leaf.0);
    }

    sparse_root(&entries)
}

#[cfg(test)]
mod pack_m_r2_bitcoin_state_tests {
    use super::*;

    const RAW: [&str; 6] = [
        "01000000fba9fcccdcbc07db8a1e1166cc84a386ca5ed154ee2824bc2b6e80150521d75d5033651fbfd182bc9fe3f587494ef41d6cf7d9e83e1dfbab6a5ce8160fae391e58d4496bffff7f2000000000",
        "010000004a0042407c83e3a11ab888a970349373cadd32d9a5dde968f8e4f25612f1960989bf5dca10a465a78c133bdac9dd2c8544b1e1a58187e22e86ec8fe632ee1a24b0d6496bffff7f2003000000",
        "01000000bbe5cc968a01d463c128c7541a7a550c52a49f642e3a7d0c5edc1232848f33258cff64ac05b34fb7ddb5b722918353f710707e56b7a1e48a3ccb0373b585821008d9496bffff7f2002000000",
        "010000009263013f4f360222c2c2d3f77f50fe889d100b0c4f5bb92cdc8ac1e77d8cb256ce2818c74c5f5b2aeb4d91ff1e44685f40aaf27812add4d2db92460cedb71eea60db496bffff7f2004000000",
        "01000000315bd66962b7d7a011557e4f42ba51aa45d08a304a8b0130d991e04f0ff60138df392887a51635cc79f01c00eee0016b5bd72e545bafea7dcc8fc7371d5835b7b8dd496bffff7f2005000000",
        "01000000a2970f2d4c46e10e8ffc45b5618a9bddbd6810820190c613a9a8c454aeb55779e87cf812f59ee6e88f217411ad2c4f5f8e10c0e8fbf7e5f270f922bc4d0680f510e0496bffff7f2006000000",
    ];
    const HASHES: [&str; 6] = [
        "4a0042407c83e3a11ab888a970349373cadd32d9a5dde968f8e4f25612f19609",
        "bbe5cc968a01d463c128c7541a7a550c52a49f642e3a7d0c5edc1232848f3325",
        "9263013f4f360222c2c2d3f77f50fe889d100b0c4f5bb92cdc8ac1e77d8cb256",
        "315bd66962b7d7a011557e4f42ba51aa45d08a304a8b0130d991e04f0ff60138",
        "a2970f2d4c46e10e8ffc45b5618a9bddbd6810820190c613a9a8c454aeb55779",
        "ec158b45993acf90d6e2a65e5950a072db8409beb9337f542bd4d379d99b3278",
    ];

    fn hex_bytes(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn h32(s: &str) -> [u8; 32] {
        hex_bytes(s).try_into().unwrap()
    }

    fn h80(s: &str) -> [u8; 80] {
        hex_bytes(s).try_into().unwrap()
    }

    fn cw(value: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = value;
        out
    }

    fn header(i: usize) -> ([u8; 32], BitcoinHeaderStateV1) {
        (
            h32(HASHES[i]),
            BitcoinHeaderStateV1 {
                version: 1,
                height: 800_353 + i as u32,
                raw_header: h80(RAW[i]),
                relative_chainwork: cw(((i + 1) * 2) as u8),
            },
        )
    }

    #[test]
    fn pack_m_r2_header_state_key_leaf_and_one_header_root_exact() {
        let (hash, state) = header(0);
        assert!(state.validate());
        assert_eq!(state.encode().len(), 118);

        let key = protocol_state_key(PS_BITCOIN_HEADER, &hash);
        assert_eq!(
            key.0,
            h32("c2ff32890f59524268cc3270e2c812e07b8db48620b4145d73944202d90bff00")
        );
        let leaf = protocol_state_leaf(&key.0, &state.encode());
        assert_eq!(
            leaf.0,
            h32("1c7c150e8200eb9eaee99781b2b49e8fc39aeb5d30f68ec670ae5dabaaa56fa9")
        );

        assert_eq!(
            bitcoin_header_protocol_state_root(&[(hash, state)], None).0,
            h32("43b077bd20cfe5501f90dd05982b4fc404ca67c5af9a55d10d88e1a189ae977e")
        );
    }

    #[test]
    fn pack_m_r2_best_chain_key_and_one_header_combined_root_exact() {
        let first = header(0);
        let best = BitcoinBestChainStateV1 {
            version: 1,
            best_tip_hash_internal: first.0,
            best_tip_height: 800_353,
            best_tip_relative_chainwork: cw(2),
        };
        assert!(best.validate());
        assert_eq!(best.encode().len(), 70);

        let key = protocol_state_key(PS_BITCOIN_BEST_CHAIN, &[0u8; 32]);
        assert_eq!(
            key.0,
            h32("afb539d375a08af653cdd44e576d7121be5bbb4bbe6b4141587e293cd2b8b443")
        );
        assert_eq!(
            bitcoin_header_protocol_state_root(&[first], Some(&best)).0,
            h32("f35cb7d4577cd0b808e28a3c483edebf7f8daa07de6b3e289d16e08f1e75978a")
        );
    }

    #[test]
    fn pack_m_r2_six_headers_plus_best_root_exact() {
        let headers = (0..6).map(header).collect::<Vec<_>>();
        let best = BitcoinBestChainStateV1 {
            version: 1,
            best_tip_hash_internal: headers[5].0,
            best_tip_height: 800_358,
            best_tip_relative_chainwork: cw(12),
        };
        assert_eq!(
            bitcoin_header_protocol_state_root(&headers, Some(&best)).0,
            h32("b0de6e47c05087e0ccac0d680975d49cd24d5a078b0f9eeb76b0b130fe9c7317")
        );
    }

    #[test]
    fn pack_m_r2_state_versions_are_closed_to_v1() {
        let (_, mut header) = header(0);
        header.version = 2;
        assert!(!header.validate());

        let best = BitcoinBestChainStateV1 {
            version: 2,
            best_tip_hash_internal: [0u8; 32],
            best_tip_height: 0,
            best_tip_relative_chainwork: [0u8; 32],
        };
        assert!(!best.validate());
    }
}
