use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mutiny_codec::{
    read_u16_be, read_u256_be, read_u32_be, read_u64_be, read_u8, read_varuint, write_u16_be,
    write_u32_be, write_u64_be, write_u8, write_varuint,
};
use mutiny_crypto::{domains, sha256_domain};
use mutiny_types::{AddressId, Hash256, TxId, WtxId};
use thiserror::Error;

pub const OUTPUT_PUBKEY_HASH: u8 = 0x01;
pub const OUTPUT_MULTISIG: u8 = 0x02;
pub const OUTPUT_EPOCH_LOCKED: u8 = 0x03;
pub const OUTPUT_TREASURY: u8 = 0x04;
pub const OUTPUT_LICENSE_PAYMENT: u8 = 0x05;

pub const WITNESS_PUBKEY_HASH: u8 = 0x01;
pub const WITNESS_MULTISIG: u8 = 0x02;
pub const WITNESS_PROTOCOL_AUTH: u8 = 0x03;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TxError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("address does not match public key")]
    AddressMismatch,
    #[error("invalid multisig policy")]
    InvalidMultisigPolicy,
    #[error("invalid multisig witness")]
    InvalidMultisigWitness,
    #[error("epoch lock not yet mature")]
    EpochLocked,
    #[error("unsupported epoch-lock inner type")]
    UnsupportedEpochLockInnerType,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("malformed canonical transaction encoding")]
    MalformedEncoding,
    #[error("transaction exceeds V1 input/output limits")]
    TooManyInputsOrOutputs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    pub amount_strikes: u64,
    pub output_type: u8,
    pub payload: Vec<u8>,
}

impl TxOutput {
    pub fn encode(&self, out: &mut Vec<u8>) {
        write_u64_be(out, self.amount_strikes);
        write_u8(out, self.output_type);
        write_varuint(out, self.payload.len() as u64);
        out.extend_from_slice(&self.payload);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseCommitmentV1 {
    pub block_epoch: u64,
    pub block_height: u64,
    pub parent_block_hash: [u8; 32],
    pub protocol_operations_root: [u8; 32],
}

impl CoinbaseCommitmentV1 {
    pub fn encode(&self, out: &mut Vec<u8>) {
        write_u64_be(out, self.block_epoch);
        write_u64_be(out, self.block_height);
        out.extend_from_slice(&self.parent_block_hash);
        out.extend_from_slice(&self.protocol_operations_root);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxInput {
    Outpoint {
        previous_txid: [u8; 32],
        previous_output_index: u16,
    },
    Coinbase {
        commitment: CoinbaseCommitmentV1,
    },
}

impl TxInput {
    pub fn encode_core(&self, out: &mut Vec<u8>) {
        match self {
            TxInput::Outpoint {
                previous_txid,
                previous_output_index,
            } => {
                out.extend_from_slice(previous_txid);
                write_u16_be(out, *previous_output_index);
            }
            TxInput::Coinbase { commitment } => {
                out.extend_from_slice(&[0u8; 32]);
                write_u16_be(out, 0xffff);
                commitment.encode(out);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionCoreV1 {
    pub version: u16,
    pub network_id: u32,
    pub valid_from_epoch: u64,
    pub expiry_epoch: u64,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

impl TransactionCoreV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_be(&mut out, self.version);
        write_u32_be(&mut out, self.network_id);
        write_u64_be(&mut out, self.valid_from_epoch);
        write_u64_be(&mut out, self.expiry_epoch);
        write_varuint(&mut out, self.inputs.len() as u64);
        for input in &self.inputs {
            input.encode_core(&mut out);
        }
        write_varuint(&mut out, self.outputs.len() as u64);
        for output in &self.outputs {
            output.encode(&mut out);
        }
        out
    }

    pub fn txid(&self) -> TxId {
        TxId(sha256_domain(domains::TX_ID, &[&self.encode()]).0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessV1 {
    pub witness_type: u8,
    pub payload: Vec<u8>,
}

impl WitnessV1 {
    pub fn encode(&self, out: &mut Vec<u8>) {
        write_u8(out, self.witness_type);
        write_varuint(out, self.payload.len() as u64);
        out.extend_from_slice(&self.payload);
    }

    pub fn pubkey_hash(public_key: [u8; 32], signature: [u8; 64]) -> Self {
        let mut payload = Vec::with_capacity(96);
        payload.extend_from_slice(&public_key);
        payload.extend_from_slice(&signature);
        Self {
            witness_type: WITNESS_PUBKEY_HASH,
            payload,
        }
    }

    pub fn protocol_auth(operation_id: [u8; 32]) -> Self {
        Self {
            witness_type: WITNESS_PROTOCOL_AUTH,
            payload: operation_id.to_vec(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionV1 {
    pub core: TransactionCoreV1,
    pub witnesses: Vec<WitnessV1>,
}

impl TransactionV1 {
    pub fn encode_full(&self) -> Vec<u8> {
        let mut out = self.core.encode();
        for w in &self.witnesses {
            w.encode(&mut out);
        }
        out
    }

    /// Decode one canonical Mutiny V1 transaction from the front of `input`.
    ///
    /// The wire format has no witness-count field: ordinary transactions have exactly one
    /// witness envelope per input; coinbase has no witness bytes. Canonical VarUInt decoding
    /// is inherited from `mutiny-codec`, so non-minimal encodings are rejected.
    pub fn decode_from(input: &mut &[u8]) -> Result<Self, TxError> {
        fn take_vec(input: &mut &[u8], n: usize) -> Result<Vec<u8>, TxError> {
            if input.len() < n {
                return Err(TxError::MalformedEncoding);
            }
            let (head, tail) = input.split_at(n);
            *input = tail;
            Ok(head.to_vec())
        }
        fn cv<T>(r: Result<T, mutiny_codec::DecodeError>) -> Result<T, TxError> {
            r.map_err(|_| TxError::MalformedEncoding)
        }

        let version = cv(read_u16_be(input))?;
        let network_id = cv(read_u32_be(input))?;
        let valid_from_epoch = cv(read_u64_be(input))?;
        let expiry_epoch = cv(read_u64_be(input))?;
        let input_count = cv(read_varuint(input))?;
        if input_count > 1024 {
            return Err(TxError::TooManyInputsOrOutputs);
        }

        let mut inputs = Vec::with_capacity(input_count as usize);
        let mut coinbase = false;
        for idx in 0..input_count {
            let previous_txid = cv(read_u256_be(input))?;
            let previous_output_index = cv(read_u16_be(input))?;
            if previous_txid == [0u8; 32] && previous_output_index == 0xffff {
                if input_count != 1 || idx != 0 {
                    return Err(TxError::MalformedEncoding);
                }
                let commitment = CoinbaseCommitmentV1 {
                    block_epoch: cv(read_u64_be(input))?,
                    block_height: cv(read_u64_be(input))?,
                    parent_block_hash: cv(read_u256_be(input))?,
                    protocol_operations_root: cv(read_u256_be(input))?,
                };
                inputs.push(TxInput::Coinbase { commitment });
                coinbase = true;
            } else {
                inputs.push(TxInput::Outpoint {
                    previous_txid,
                    previous_output_index,
                });
            }
        }

        let output_count = cv(read_varuint(input))?;
        if output_count > 1024 {
            return Err(TxError::TooManyInputsOrOutputs);
        }
        let mut outputs = Vec::with_capacity(output_count as usize);
        for _ in 0..output_count {
            let amount_strikes = cv(read_u64_be(input))?;
            let output_type = cv(read_u8(input))?;
            let payload_len = cv(read_varuint(input))?;
            let payload_len =
                usize::try_from(payload_len).map_err(|_| TxError::MalformedEncoding)?;
            let payload = take_vec(input, payload_len)?;
            outputs.push(TxOutput {
                amount_strikes,
                output_type,
                payload,
            });
        }

        let witness_count = if coinbase { 0 } else { input_count as usize };
        let mut witnesses = Vec::with_capacity(witness_count);
        for _ in 0..witness_count {
            let witness_type = cv(read_u8(input))?;
            let payload_len = cv(read_varuint(input))?;
            let payload_len =
                usize::try_from(payload_len).map_err(|_| TxError::MalformedEncoding)?;
            let payload = take_vec(input, payload_len)?;
            witnesses.push(WitnessV1 {
                witness_type,
                payload,
            });
        }

        Ok(Self {
            core: TransactionCoreV1 {
                version,
                network_id,
                valid_from_epoch,
                expiry_epoch,
                inputs,
                outputs,
            },
            witnesses,
        })
    }

    pub fn decode_full(bytes: &[u8]) -> Result<Self, TxError> {
        let mut input = bytes;
        let tx = Self::decode_from(&mut input)?;
        if !input.is_empty() {
            return Err(TxError::MalformedEncoding);
        }
        Ok(tx)
    }

    pub fn txid(&self) -> TxId {
        self.core.txid()
    }

    pub fn wtxid(&self) -> WtxId {
        WtxId(sha256_domain(domains::WTX_ID, &[&self.encode_full()]).0)
    }

    pub fn leaf(&self) -> Hash256 {
        let txid = self.txid();
        let wtxid = self.wtxid();
        sha256_domain(domains::TX_LEAF, &[txid.as_bytes(), wtxid.as_bytes()])
    }

    pub fn serialized_len(&self) -> usize {
        self.encode_full().len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrevoutCommitmentV1 {
    pub previous_txid: [u8; 32],
    pub previous_output_index: u16,
    pub amount_strikes: u64,
    pub output_type: u8,
    pub payload: Vec<u8>,
}

impl PrevoutCommitmentV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.previous_txid);
        write_u16_be(&mut out, self.previous_output_index);
        write_u64_be(&mut out, self.amount_strikes);
        write_u8(&mut out, self.output_type);
        write_varuint(&mut out, self.payload.len() as u64);
        out.extend_from_slice(&self.payload);
        out
    }
}

pub fn sighash_all(txid: &TxId, input_index: u16, prevout: &PrevoutCommitmentV1) -> Hash256 {
    let idx = input_index.to_be_bytes();
    let prev = prevout.encode();
    sha256_domain(domains::TX_SIGN, &[txid.as_bytes(), &idx, &prev])
}

pub fn address_id(public_key: &[u8; 32]) -> AddressId {
    AddressId(sha256_domain(domains::ADDRESS, &[public_key]).0)
}

pub fn verify_pubkey_hash_witness(
    address: &AddressId,
    digest: &[u8; 32],
    witness: &WitnessV1,
) -> Result<(), TxError> {
    if witness.witness_type != WITNESS_PUBKEY_HASH || witness.payload.len() != 96 {
        return Err(TxError::InvalidSignature);
    }
    let public_key: [u8; 32] = witness.payload[..32].try_into().unwrap();
    let signature: [u8; 64] = witness.payload[32..].try_into().unwrap();
    if address_id(&public_key) != *address {
        return Err(TxError::AddressMismatch);
    }
    let vk = VerifyingKey::from_bytes(&public_key).map_err(|_| TxError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(&signature);
    vk.verify(digest, &sig)
        .map_err(|_| TxError::InvalidSignature)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigPayloadV1 {
    pub threshold: u8,
    pub public_keys: Vec<[u8; 32]>,
}

impl MultisigPayloadV1 {
    pub fn validate(&self) -> Result<(), TxError> {
        if self.public_keys.is_empty()
            || self.public_keys.len() > 16
            || self.threshold == 0
            || self.threshold as usize > self.public_keys.len()
        {
            return Err(TxError::InvalidMultisigPolicy);
        }
        for pair in self.public_keys.windows(2) {
            if pair[0] >= pair[1] {
                return Err(TxError::InvalidMultisigPolicy);
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TxError> {
        self.validate()?;
        let mut out = Vec::with_capacity(2 + 32 * self.public_keys.len());
        write_u8(&mut out, self.threshold);
        write_u8(&mut out, self.public_keys.len() as u8);
        for key in &self.public_keys {
            out.extend_from_slice(key);
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedSignatureV1 {
    pub key_index: u8,
    pub signature: [u8; 64],
}

pub fn multisig_witness(signatures: &[IndexedSignatureV1]) -> WitnessV1 {
    let mut payload = Vec::with_capacity(1 + 65 * signatures.len());
    write_u8(&mut payload, signatures.len() as u8);
    for s in signatures {
        write_u8(&mut payload, s.key_index);
        payload.extend_from_slice(&s.signature);
    }
    WitnessV1 {
        witness_type: WITNESS_MULTISIG,
        payload,
    }
}

pub fn verify_multisig(
    payload: &MultisigPayloadV1,
    digest: &[u8; 32],
    signatures: &[IndexedSignatureV1],
) -> Result<(), TxError> {
    payload.validate()?;
    if signatures.len() < payload.threshold as usize || signatures.len() > payload.public_keys.len()
    {
        return Err(TxError::InvalidMultisigWitness);
    }
    let mut prev = None;
    for item in signatures {
        if let Some(p) = prev {
            if item.key_index <= p {
                return Err(TxError::InvalidMultisigWitness);
            }
        }
        let idx = item.key_index as usize;
        if idx >= payload.public_keys.len() {
            return Err(TxError::InvalidMultisigWitness);
        }
        let vk = VerifyingKey::from_bytes(&payload.public_keys[idx])
            .map_err(|_| TxError::InvalidPublicKey)?;
        let sig = Signature::from_bytes(&item.signature);
        vk.verify(digest, &sig)
            .map_err(|_| TxError::InvalidSignature)?;
        prev = Some(item.key_index);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochLockedPayloadV1 {
    pub unlock_epoch: u64,
    pub inner_output_type: u8,
    pub inner_payload: Vec<u8>,
}

impl EpochLockedPayloadV1 {
    pub fn validate(&self) -> Result<(), TxError> {
        match self.inner_output_type {
            OUTPUT_PUBKEY_HASH | OUTPUT_MULTISIG => Ok(()),
            _ => Err(TxError::UnsupportedEpochLockInnerType),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, TxError> {
        self.validate()?;
        let mut out = Vec::new();
        write_u64_be(&mut out, self.unlock_epoch);
        write_u8(&mut out, self.inner_output_type);
        write_varuint(&mut out, self.inner_payload.len() as u64);
        out.extend_from_slice(&self.inner_payload);
        Ok(out)
    }
    pub fn check_epoch(&self, candidate_epoch: u64) -> Result<(), TxError> {
        if candidate_epoch < self.unlock_epoch {
            Err(TxError::EpochLocked)
        } else {
            Ok(())
        }
    }
}

pub fn protocol_operations_empty_root() -> Hash256 {
    sha256_domain(domains::PROTOCOL_OPS_EMPTY, &[])
}

pub fn merkle_root(leaves: &[Hash256]) -> Option<Hash256> {
    if leaves.is_empty() {
        return None;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 == level.len() {
                next.push(level[i]);
            } else {
                next.push(sha256_domain(
                    domains::TX_NODE,
                    &[level[i].as_bytes(), level[i + 1].as_bytes()],
                ));
            }
            i += 2;
        }
        level = next;
    }
    Some(level[0])
}

pub fn required_base_fee(rate_q32: u64, tx_weight: u64) -> Result<u64, TxError> {
    let product = (rate_q32 as u128)
        .checked_mul(tx_weight as u128)
        .ok_or(TxError::Overflow)?;
    let denom = 1u128 << 32;
    let fee = product.checked_add(denom - 1).ok_or(TxError::Overflow)? / denom;
    u64::try_from(fee).map_err(|_| TxError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn b1_core() -> TransactionCoreV1 {
        TransactionCoreV1 {
            version: 1,
            network_id: 0x4d555401,
            valid_from_epoch: 12346,
            expiry_epoch: 12410,
            inputs: vec![TxInput::Outpoint {
                previous_txid: (0x40u8..0x60).collect::<Vec<_>>().try_into().unwrap(),
                previous_output_index: 2,
            }],
            outputs: vec![TxOutput {
                amount_strikes: 999_990_000,
                output_type: OUTPUT_PUBKEY_HASH,
                payload: h32("b6b7fa4d26a59625a92fb1218f041b1230ebd53650024eca30d04974531ba5d9")
                    .to_vec(),
            }],
        }
    }

    #[test]
    fn pack_b_pubkey_hash_vector() {
        let core = b1_core();
        assert_eq!(core.encode().len(), 100);
        assert_eq!(hex::encode(core.encode()), "00014d555401000000000000303a000000000000307a01404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000201000000003b9aa2f00120b6b7fa4d26a59625a92fb1218f041b1230ebd53650024eca30d04974531ba5d9");
        let txid = core.txid();
        assert_eq!(
            txid.0,
            h32("ce16cf9dd894b62240b8f869b07790803ffc2b5a9cd0d43ee159c35ae25e3228")
        );

        let signing = SigningKey::from_bytes(&(1u8..=32).collect::<Vec<_>>().try_into().unwrap());
        let public = signing.verifying_key().to_bytes();
        assert_eq!(
            public,
            h32("79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
        );
        let address = address_id(&public);
        assert_eq!(
            address.0,
            h32("e93f30cb3b073a543178a9efd6efdeea3c5f51ede93175456336099cc967fbca")
        );
        let prev = PrevoutCommitmentV1 {
            previous_txid: (0x40u8..0x60).collect::<Vec<_>>().try_into().unwrap(),
            previous_output_index: 2,
            amount_strikes: 1_000_000_000,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: address.0.to_vec(),
        };
        let digest = sighash_all(&txid, 0, &prev);
        assert_eq!(
            digest.0,
            h32("890c9a9aee98b00b90c75bf50f8bdc0ec8d752ba1bfea04f3fd78d192e4a7e25")
        );
        let sig = signing.sign(&digest.0).to_bytes();
        let expected_sig: [u8; 64] = hex::decode("fbf9d0690edd01981e82f4a24180b87137c76d486ff4c51eea52a71accc8e0a9b8f834ee08dbacb4b44ded67badb7c77378b2c1a035ae16d479c7b443a903b02")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(sig, expected_sig);
        let witness = WitnessV1::pubkey_hash(public, sig);
        verify_pubkey_hash_witness(&address, &digest.0, &witness).unwrap();
        let tx = TransactionV1 {
            core,
            witnesses: vec![witness],
        };
        assert_eq!(tx.serialized_len(), 198);
        assert_eq!(
            tx.wtxid().0,
            h32("fef53d8593fb98f0a773532e6c8745045d8d144c9efd86bb3ed7279700c3c5ad")
        );
        assert_eq!(
            tx.leaf().0,
            h32("e3fcd26d6ac792feb61466f0b43262d1dd54abe82d1f3f9c2307c1342dccf923")
        );
    }

    #[test]
    fn pack_b_multisig_payload_and_policy() {
        let keys = vec![
            h32("22eadcea5dd731a5553a4b0c8d24a87bc5f2e478a5a706e93db941b2e94b199a"),
            h32("2a4d3dc0e31f3361257280cb496a49bfbbd5086fb234a2610a40567db67b67af"),
            h32("6ca208d831af3d772afdd2310025657b6e248ff276fc31dd2ada819a66df3ce0"),
        ];
        let m = MultisigPayloadV1 {
            threshold: 2,
            public_keys: keys,
        };
        assert_eq!(hex::encode(m.encode().unwrap()), "020322eadcea5dd731a5553a4b0c8d24a87bc5f2e478a5a706e93db941b2e94b199a2a4d3dc0e31f3361257280cb496a49bfbbd5086fb234a2610a40567db67b67af6ca208d831af3d772afdd2310025657b6e248ff276fc31dd2ada819a66df3ce0");
        let bad = MultisigPayloadV1 {
            threshold: 2,
            public_keys: vec![
                h32("2a4d3dc0e31f3361257280cb496a49bfbbd5086fb234a2610a40567db67b67af"),
                h32("22eadcea5dd731a5553a4b0c8d24a87bc5f2e478a5a706e93db941b2e94b199a"),
            ],
        };
        assert_eq!(bad.validate(), Err(TxError::InvalidMultisigPolicy));
    }

    #[test]
    fn pack_b_epoch_locked_vector() {
        let e = EpochLockedPayloadV1 {
            unlock_epoch: 21_000,
            inner_output_type: OUTPUT_PUBKEY_HASH,
            inner_payload: h32("e93f30cb3b073a543178a9efd6efdeea3c5f51ede93175456336099cc967fbca")
                .to_vec(),
        };
        assert_eq!(
            hex::encode(e.encode().unwrap()),
            "00000000000052080120e93f30cb3b073a543178a9efd6efdeea3c5f51ede93175456336099cc967fbca"
        );
        assert_eq!(e.check_epoch(20_999), Err(TxError::EpochLocked));
        assert_eq!(e.check_epoch(21_000), Ok(()));
        assert_eq!(e.check_epoch(21_001), Ok(()));
    }

    #[test]
    fn pack_b_base_fee_vector() {
        let fee = required_base_fee(5_368_709_120, 198).unwrap();
        assert_eq!(fee, 248);
        let total = 10_000u64;
        let priority = total - fee;
        let treasury = fee / 2;
        let miner_base = fee - treasury;
        assert_eq!(
            (priority, treasury, miner_base, priority + miner_base),
            (9_752, 124, 124, 9_876)
        );
    }

    #[test]
    fn pack_b_empty_protocol_root_and_coinbase() {
        let empty = protocol_operations_empty_root();
        assert_eq!(
            empty.0,
            h32("2f05e28d114979aa8b796403e64cc672ca10e5c075469dca00910fb76750da2b")
        );
        let core = TransactionCoreV1 {
            version: 1,
            network_id: 0x4d555401,
            valid_from_epoch: 12346,
            expiry_epoch: 0,
            inputs: vec![TxInput::Coinbase {
                commitment: CoinbaseCommitmentV1 {
                    block_epoch: 12346,
                    block_height: 100,
                    parent_block_hash: (0xc0u8..0xe0).collect::<Vec<_>>().try_into().unwrap(),
                    protocol_operations_root: empty.0,
                },
            }],
            outputs: vec![TxOutput {
                amount_strikes: 800_000_000,
                output_type: OUTPUT_PUBKEY_HASH,
                payload: h32("b6b7fa4d26a59625a92fb1218f041b1230ebd53650024eca30d04974531ba5d9")
                    .to_vec(),
            }],
        };
        assert_eq!(core.encode().len(), 180);
        assert_eq!(hex::encode(core.encode()), "00014d555401000000000000303a0000000000000000010000000000000000000000000000000000000000000000000000000000000000ffff000000000000303a0000000000000064c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf2f05e28d114979aa8b796403e64cc672ca10e5c075469dca00910fb76750da2b01000000002faf08000120b6b7fa4d26a59625a92fb1218f041b1230ebd53650024eca30d04974531ba5d9");
        let tx = TransactionV1 {
            core,
            witnesses: vec![],
        };
        assert_eq!(
            tx.txid().0,
            h32("82fbbde5d9f9b04209278bc171239b3ebca1717e846845069f1e91e1eb7e3852")
        );
        assert_eq!(
            tx.wtxid().0,
            h32("fb15f3b1a9c27335271b2d7ab0e852ffd1b8c03447c226739cfdef3f3c7160cb")
        );
        assert_eq!(
            tx.leaf().0,
            h32("bc729af1fc6ab9e9d6bc213e6f184882e5b04779310dbae5fcda04aae37b2434")
        );
    }

    #[test]
    fn pack_b_merkle_two_leaf_vector() {
        let coinbase = Hash256(h32(
            "bc729af1fc6ab9e9d6bc213e6f184882e5b04779310dbae5fcda04aae37b2434",
        ));
        let b1 = Hash256(h32(
            "e3fcd26d6ac792feb61466f0b43262d1dd54abe82d1f3f9c2307c1342dccf923",
        ));
        assert_eq!(
            merkle_root(&[coinbase, b1]).unwrap().0,
            h32("6c8413905395b8ec33e0f9130f82dd3b9fc4bd449ed3ffecbba6ee4dfeedd109")
        );
    }

    #[test]
    fn protocol_auth_wire_vector() {
        let op = h32("4ab3451d3fca916fbc585f083dd0a82ff5166dd6a7a66716da9edec2c150ece5");
        let mut encoded = Vec::new();
        WitnessV1::protocol_auth(op).encode(&mut encoded);
        assert_eq!(
            hex::encode(encoded),
            "03204ab3451d3fca916fbc585f083dd0a82ff5166dd6a7a66716da9edec2c150ece5"
        );
    }
    #[test]
    fn canonical_full_decode_roundtrip() {
        let core = b1_core();
        let txid = core.txid();
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let prev = PrevoutCommitmentV1 {
            previous_txid: match &core.inputs[0] {
                TxInput::Outpoint { previous_txid, .. } => *previous_txid,
                _ => unreachable!(),
            },
            previous_output_index: 2,
            amount_strikes: 1_000_000_000,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: address_id(&sk.verifying_key().to_bytes()).0.to_vec(),
        };
        let digest = sighash_all(&txid, 0, &prev);
        let tx = TransactionV1 {
            core,
            witnesses: vec![WitnessV1::pubkey_hash(
                sk.verifying_key().to_bytes(),
                sk.sign(&digest.0).to_bytes(),
            )],
        };
        let encoded = tx.encode_full();
        let decoded = TransactionV1::decode_full(&encoded).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(decoded.encode_full(), encoded);
    }

    #[test]
    fn coinbase_full_decode_roundtrip() {
        let tx = TransactionV1 {
            core: TransactionCoreV1 {
                version: 1,
                network_id: 0x4d555403,
                valid_from_epoch: 64,
                expiry_epoch: 0,
                inputs: vec![TxInput::Coinbase {
                    commitment: CoinbaseCommitmentV1 {
                        block_epoch: 64,
                        block_height: 1,
                        parent_block_hash: [9u8; 32],
                        protocol_operations_root: protocol_operations_empty_root().0,
                    },
                }],
                outputs: vec![TxOutput {
                    amount_strikes: 800_000_000,
                    output_type: OUTPUT_PUBKEY_HASH,
                    payload: [4u8; 32].to_vec(),
                }],
            },
            witnesses: vec![],
        };
        let encoded = tx.encode_full();
        assert_eq!(TransactionV1::decode_full(&encoded).unwrap(), tx);
    }
}
