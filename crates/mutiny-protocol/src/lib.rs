use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mutiny_bitcoin::{BitcoinHeader, BitcoinSpvProofV1};
use mutiny_codec::{
    read_u16_be, read_u32_be, read_varuint, write_u16_be, write_u32_be, write_u64_be, write_varuint,
};
use mutiny_crypto::{domains, sha256_domain};
use mutiny_state::{
    LicenseDividendAccountV1, LicenseRecordV1, StateError, TreasuryStateV1, LICENSE_STATUS_REVOKED,
    PURCHASE_METHOD_BTC, PURCHASE_METHOD_MUT,
};
use mutiny_types::{AddressId, EvidenceId, Hash256, LicenseId, OperationId, TxId};
use thiserror::Error;

pub const OP_LICENSE_PURCHASE_BTC: u16 = 0x0001;
pub const OP_LICENSE_PURCHASE_MUT: u16 = 0x0002;
pub const OP_LICENSE_TRANSFER: u16 = 0x0003;
pub const OP_LICENSE_MINING_KEY_ROTATE: u16 = 0x0004;
pub const OP_PUNISHMENT_EVIDENCE: u16 = 0x0005;
pub const OP_BOOTSTRAP_COMMITMENT: u16 = 0x0006;
pub const OP_DIVIDEND_CLAIM: u16 = 0x0007;
pub const OP_MINING_PRESENCE: u16 = 0x0008;
pub const OP_BITCOIN_HEADERS: u16 = 0x0009;

/// Network Identity V1 consensus/runtime namespace.
/// These values are distinct from Pack-H P2P and Pack-L worker magic.
pub const MAINNET_NETWORK_ID: u32 = 0x4D55_5401;
pub const TESTNET_NETWORK_ID: u32 = 0x4D55_5402;
pub const DEVNET_NETWORK_ID: u32 = 0x4D55_5403;

/// Corrected Mainnet Genesis Authority V1.1.
///
/// The embedded bytes are the exact formally locked 989-byte
/// GenesisBlockV1 containing the canonical 26-byte ASCII motto:
///
/// No Masters. Only the Many.
///
/// GenesisID = SHA256("MUTINY-GENESIS-ID-V1" || GenesisBlockV1).
pub const MAINNET_GENESIS_ID: [u8; 32] = [
    0x9d, 0xef, 0x7a, 0x0c, 0xc8, 0x3e, 0x92, 0xf6, 0xe1, 0xd8, 0x69, 0x2e, 0x9c, 0x29, 0xbb, 0x3f,
    0x11, 0xa8, 0x98, 0x6b, 0x9c, 0xb5, 0x90, 0xb8, 0x92, 0x14, 0x77, 0x4e, 0x2c, 0x7e, 0x54, 0x81,
];
pub const MAINNET_GENESIS_BLOCK_V1: &[u8; 989] = include_bytes!("mainnet-genesisblock-v1.1.bin");
pub const MAINNET_GENESIS_MOTTO: &[u8; 26] = b"No Masters. Only the Many.";

/// Pack-K is activated only for the formally locked Devnet identity in Build 6.3.
/// Mainnet/Testnet remain inactive until a later explicit consensus lock assigns them
/// their own `(NetworkID, GenesisID, activation_epoch)` tuple.
pub const PACK_K_DEVNET_NETWORK_ID: u32 = DEVNET_NETWORK_ID;
pub const PACK_K_DEVNET_GENESIS_ID: [u8; 32] = [
    0x4c, 0x60, 0x3d, 0xf8, 0x83, 0x9c, 0xe0, 0x20, 0xb4, 0x2a, 0x12, 0x68, 0xa5, 0x4a, 0x19, 0x38,
    0x65, 0x7a, 0x1b, 0x78, 0x12, 0xd2, 0xdf, 0x92, 0xc4, 0x80, 0x3d, 0x63, 0x35, 0x5e, 0x70, 0x2c,
];
pub const PACK_K_DEVNET_ACTIVATION_EPOCH: u64 = 1500;
pub const MINING_PRESENCE_WINDOW_EPOCHS: u64 = 16;
pub const MINING_PRESENCE_UNSIGNED_LEN: usize = 80;
pub const MINING_PRESENCE_FULL_LEN: usize = 144;

pub fn pack_k_activation_epoch(network_id: u32, genesis_id: &[u8; 32]) -> Option<u64> {
    if network_id == MAINNET_NETWORK_ID && genesis_id == &MAINNET_GENESIS_ID {
        return Some(11);
    }

    (network_id == PACK_K_DEVNET_NETWORK_ID && *genesis_id == PACK_K_DEVNET_GENESIS_ID)
        .then_some(PACK_K_DEVNET_ACTIVATION_EPOCH)
}

pub fn pack_k_active(network_id: u32, genesis_id: &[u8; 32], epoch: u64) -> bool {
    pack_k_activation_epoch(network_id, genesis_id).is_some_and(|activation| epoch >= activation)
}

pub const OFFENSE_INVALID_SIGNED_WORK: u16 = 0x0001;
pub const OFFENSE_LICENSE_STATE_EQUIVOCATION: u16 = 0x0002;
pub const OFFENSE_SAME_TICKET_EQUIVOCATION: u16 = 0x0003;

pub const STRIKE_DECAY_EPOCHS: u64 = 1u64 << 21;
pub const REVOCATION_THRESHOLD: u8 = 16;
pub const ACTIVATION_DELAY_EPOCHS: u64 = 1u64 << 6;
pub const DIVIDEND_CLAIM_WINDOW: u64 = 1u64 << 16;
pub const DIVIDEND_AWARD_INTERVAL: u64 = 1u64 << 17;
pub const DIVIDEND_FRACTION_NUMERATOR: u64 = 1;
pub const DIVIDEND_FRACTION_DENOMINATOR: u64 = 2;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("invalid protocol operation version")]
    BadVersion,
    #[error("invalid manifest")]
    InvalidManifest,
    #[error("invalid authorization signature")]
    InvalidSignature,
    #[error("stale owner key sequence")]
    StaleOwnerSequence,
    #[error("stale mining key sequence")]
    StaleMiningSequence,
    #[error("license is permanently revoked")]
    Revoked,
    #[error("invalid offense weight")]
    BadOffenseWeight,
    #[error("dividend claim is outside its claim window")]
    DividendExpired,
    #[error("dividend claim exceeds claimable balance")]
    DividendOverdraw,
    #[error("treasury reserved-dividend accounting underflow")]
    TreasuryUnderflow,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("Pack K mining presence is not active for this network/genesis/epoch")]
    MiningPresenceInactive,
    #[error("mining presence NetworkID mismatch")]
    MiningPresenceNetwork,
    #[error("mining presence GenesisID mismatch")]
    MiningPresenceGenesis,
    #[error("mining presence epoch mismatch")]
    MiningPresenceEpoch,
    #[error("invalid mining presence payload")]
    InvalidMiningPresence,
    #[error(transparent)]
    State(#[from] StateError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolOperationV1 {
    pub op_type: u16,
    pub op_version: u16,
    pub payload: Vec<u8>,
}

impl ProtocolOperationV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_be(&mut out, self.op_type);
        write_u16_be(&mut out, self.op_version);
        write_varuint(&mut out, self.payload.len() as u64);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn operation_id(&self) -> OperationId {
        OperationId(sha256_domain(domains::PROTOCOL_OP_ID, &[&self.encode()]).0)
    }
}

pub fn unsigned_operation_bytes(op_type: u16, op_version: u16, unsigned_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_u16_be(&mut out, op_type);
    write_u16_be(&mut out, op_version);
    write_varuint(&mut out, unsigned_payload.len() as u64);
    out.extend_from_slice(unsigned_payload);
    out
}

pub fn operation_signing_digest(op_type: u16, op_version: u16, unsigned_payload: &[u8]) -> Hash256 {
    let bytes = unsigned_operation_bytes(op_type, op_version, unsigned_payload);
    sha256_domain(domains::PROTOCOL_OP_SIGN, &[&bytes])
}

fn verify_owner_signature(
    public_key: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ProtocolError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| ProtocolError::InvalidSignature)?;
    let sig = Signature::from_bytes(signature);
    key.verify(digest, &sig)
        .map_err(|_| ProtocolError::InvalidSignature)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenseManifestEntryV1 {
    pub owner_public_key: [u8; 32],
    pub mining_public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutLicenseManifestV1 {
    pub version: u16,
    pub network_id: u32,
    pub purchase_nonce: [u8; 32],
    pub licenses: Vec<LicenseManifestEntryV1>,
}

impl MutLicenseManifestV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != 1 || self.licenses.is_empty() || self.licenses.len() > 1024 {
            return Err(ProtocolError::InvalidManifest);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(42 + self.licenses.len() * 64);
        write_u16_be(&mut out, self.version);
        write_u32_be(&mut out, self.network_id);
        out.extend_from_slice(&self.purchase_nonce);
        write_u32_be(&mut out, self.licenses.len() as u32);
        for entry in &self.licenses {
            out.extend_from_slice(&entry.owner_public_key);
            out.extend_from_slice(&entry.mining_public_key);
        }
        Ok(out)
    }

    pub fn manifest_hash(&self) -> Result<Hash256, ProtocolError> {
        let bytes = self.encode()?;
        Ok(sha256_domain(domains::MUT_LICENSE_MANIFEST, &[&bytes]))
    }
}

pub const BOOTSTRAP_LICENSE_COUNT_V1: usize = 12;

/// Special Genesis-committed Bitcoin bootstrap manifest. Unlike ordinary
/// post-Genesis BTC manifests, BootstrapManifestV1 deliberately omits a
/// GenesisID field so Genesis can commit to its hash without circularity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapManifestV1 {
    pub version: u16,
    pub network_id: u32,
    pub purchase_nonce: [u8; 32],
    pub licenses: Vec<LicenseManifestEntryV1>,
}

impl BootstrapManifestV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != 1 || self.licenses.len() != BOOTSTRAP_LICENSE_COUNT_V1 {
            return Err(ProtocolError::InvalidManifest);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(42 + self.licenses.len() * 64);
        write_u16_be(&mut out, self.version);
        write_u32_be(&mut out, self.network_id);
        out.extend_from_slice(&self.purchase_nonce);
        write_u32_be(&mut out, self.licenses.len() as u32);
        for entry in &self.licenses {
            out.extend_from_slice(&entry.owner_public_key);
            out.extend_from_slice(&entry.mining_public_key);
        }
        Ok(out)
    }

    pub fn decode(mut input: &[u8]) -> Result<Self, ProtocolError> {
        let version = read_u16_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)?;
        let network_id = read_u32_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)?;
        if input.len() < 36 {
            return Err(ProtocolError::InvalidManifest);
        }
        let purchase_nonce: [u8; 32] = input[..32]
            .try_into()
            .map_err(|_| ProtocolError::InvalidManifest)?;
        input = &input[32..];
        let count = read_u32_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)? as usize;
        if count != BOOTSTRAP_LICENSE_COUNT_V1 || input.len() != count * 64 {
            return Err(ProtocolError::InvalidManifest);
        }
        let mut licenses = Vec::with_capacity(count);
        for _ in 0..count {
            let owner_public_key: [u8; 32] = input[..32]
                .try_into()
                .map_err(|_| ProtocolError::InvalidManifest)?;
            let mining_public_key: [u8; 32] = input[32..64]
                .try_into()
                .map_err(|_| ProtocolError::InvalidManifest)?;
            input = &input[64..];
            licenses.push(LicenseManifestEntryV1 {
                owner_public_key,
                mining_public_key,
            });
        }
        let manifest = Self {
            version,
            network_id,
            purchase_nonce,
            licenses,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn manifest_hash(&self) -> Result<Hash256, ProtocolError> {
        let bytes = self.encode()?;
        Ok(sha256_domain(domains::BOOTSTRAP_MANIFEST, &[&bytes]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcLicenseManifestV1 {
    pub version: u16,
    pub network_id: u32,
    /// Ordinary post-Genesis BTC manifests bind to one Mutiny Genesis ID.
    pub genesis_hash: [u8; 32],
    pub purchase_nonce: [u8; 32],
    pub licenses: Vec<LicenseManifestEntryV1>,
}

impl BtcLicenseManifestV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != 1 || self.licenses.is_empty() || self.licenses.len() > 1024 {
            return Err(ProtocolError::InvalidManifest);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(74 + self.licenses.len() * 64);
        write_u16_be(&mut out, self.version);
        write_u32_be(&mut out, self.network_id);
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&self.purchase_nonce);
        write_u32_be(&mut out, self.licenses.len() as u32);
        for entry in &self.licenses {
            out.extend_from_slice(&entry.owner_public_key);
            out.extend_from_slice(&entry.mining_public_key);
        }
        Ok(out)
    }

    pub fn decode(mut input: &[u8]) -> Result<Self, ProtocolError> {
        let version = read_u16_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)?;
        let network_id = read_u32_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)?;
        if input.len() < 64 {
            return Err(ProtocolError::InvalidManifest);
        }
        let genesis_hash: [u8; 32] = input[..32]
            .try_into()
            .map_err(|_| ProtocolError::InvalidManifest)?;
        let purchase_nonce: [u8; 32] = input[32..64]
            .try_into()
            .map_err(|_| ProtocolError::InvalidManifest)?;
        input = &input[64..];
        let count = read_u32_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)? as usize;
        if count == 0 || count > 1024 || input.len() != count * 64 {
            return Err(ProtocolError::InvalidManifest);
        }
        let mut licenses = Vec::with_capacity(count);
        for _ in 0..count {
            let owner_public_key: [u8; 32] = input[..32]
                .try_into()
                .map_err(|_| ProtocolError::InvalidManifest)?;
            let mining_public_key: [u8; 32] = input[32..64]
                .try_into()
                .map_err(|_| ProtocolError::InvalidManifest)?;
            input = &input[64..];
            licenses.push(LicenseManifestEntryV1 {
                owner_public_key,
                mining_public_key,
            });
        }
        let manifest = Self {
            version,
            network_id,
            genesis_hash,
            purchase_nonce,
            licenses,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn manifest_hash(&self) -> Result<Hash256, ProtocolError> {
        let bytes = self.encode()?;
        Ok(sha256_domain(domains::BTC_MANIFEST, &[&bytes]))
    }
}

pub fn bitcoin_payment_id(txid_internal: &[u8; 32], output_index: u32) -> Hash256 {
    sha256_domain(
        domains::BTC_PAYMENT_ID,
        &[txid_internal, &output_index.to_be_bytes()],
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicensePurchaseBtcV1 {
    pub manifest: BtcLicenseManifestV1,
    pub proof: BitcoinSpvProofV1,
}

impl LicensePurchaseBtcV1 {
    pub fn payload(&self) -> Result<Vec<u8>, ProtocolError> {
        let manifest = self.manifest.encode()?;
        let mut out = Vec::new();
        write_varuint(&mut out, manifest.len() as u64);
        out.extend_from_slice(&manifest);
        write_varuint(&mut out, self.proof.raw_transaction.len() as u64);
        out.extend_from_slice(&self.proof.raw_transaction);
        write_u32_be(&mut out, self.proof.payment_output_index);
        write_u32_be(&mut out, self.proof.manifest_output_index);
        write_u32_be(&mut out, self.proof.tx_index);
        write_varuint(&mut out, self.proof.merkle_branch.len() as u64);
        for sibling in &self.proof.merkle_branch {
            out.extend_from_slice(sibling);
        }
        write_varuint(&mut out, self.proof.headers.len() as u64);
        for header in &self.proof.headers {
            out.extend_from_slice(&header.raw);
        }
        write_u32_be(&mut out, self.proof.containing_block_height);
        Ok(out)
    }

    pub fn operation(&self) -> Result<ProtocolOperationV1, ProtocolError> {
        Ok(ProtocolOperationV1 {
            op_type: OP_LICENSE_PURCHASE_BTC,
            op_version: 1,
            payload: self.payload()?,
        })
    }

    pub fn decode_payload(mut input: &[u8]) -> Result<Self, ProtocolError> {
        let manifest_len =
            usize::try_from(read_varuint(&mut input).map_err(|_| ProtocolError::InvalidManifest)?)
                .map_err(|_| ProtocolError::InvalidManifest)?;
        if input.len() < manifest_len {
            return Err(ProtocolError::InvalidManifest);
        }
        let manifest = BtcLicenseManifestV1::decode(&input[..manifest_len])?;
        input = &input[manifest_len..];
        let tx_len =
            usize::try_from(read_varuint(&mut input).map_err(|_| ProtocolError::InvalidManifest)?)
                .map_err(|_| ProtocolError::InvalidManifest)?;
        if input.len() < tx_len {
            return Err(ProtocolError::InvalidManifest);
        }
        let raw_transaction = input[..tx_len].to_vec();
        input = &input[tx_len..];
        let payment_output_index =
            read_u32_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)?;
        let manifest_output_index =
            read_u32_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)?;
        let tx_index = read_u32_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)?;
        let branch_len =
            usize::try_from(read_varuint(&mut input).map_err(|_| ProtocolError::InvalidManifest)?)
                .map_err(|_| ProtocolError::InvalidManifest)?;
        if branch_len > 64 || input.len() < branch_len * 32 {
            return Err(ProtocolError::InvalidManifest);
        }
        let mut merkle_branch = Vec::with_capacity(branch_len);
        for _ in 0..branch_len {
            let h: [u8; 32] = input[..32]
                .try_into()
                .map_err(|_| ProtocolError::InvalidManifest)?;
            input = &input[32..];
            merkle_branch.push(h);
        }
        let header_len =
            usize::try_from(read_varuint(&mut input).map_err(|_| ProtocolError::InvalidManifest)?)
                .map_err(|_| ProtocolError::InvalidManifest)?;
        if header_len > 64 || input.len() < header_len * 80 + 4 {
            return Err(ProtocolError::InvalidManifest);
        }
        let mut headers = Vec::with_capacity(header_len);
        for _ in 0..header_len {
            let raw: [u8; 80] = input[..80]
                .try_into()
                .map_err(|_| ProtocolError::InvalidManifest)?;
            input = &input[80..];
            headers.push(BitcoinHeader { raw });
        }
        let containing_block_height =
            read_u32_be(&mut input).map_err(|_| ProtocolError::InvalidManifest)?;
        if !input.is_empty() {
            return Err(ProtocolError::InvalidManifest);
        }
        Ok(Self {
            manifest,
            proof: BitcoinSpvProofV1 {
                raw_transaction,
                payment_output_index,
                manifest_output_index,
                tx_index,
                merkle_branch,
                headers,
                containing_block_height,
            },
        })
    }

    pub fn license_ids(&self) -> Result<Vec<LicenseId>, ProtocolError> {
        let parsed = mutiny_bitcoin::parse_transaction(&self.proof.raw_transaction)
            .map_err(|_| ProtocolError::InvalidManifest)?;
        let payment = bitcoin_payment_id(&parsed.txid_internal, self.proof.payment_output_index);
        self.manifest
            .licenses
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                Ok(derive_license_id(
                    self.manifest.network_id,
                    PURCHASE_METHOD_BTC,
                    &payment.0,
                    i as u32,
                    &entry.owner_public_key,
                ))
            })
            .collect()
    }
}

pub fn native_payment_id(payment_txid: &TxId, output_index: u16) -> Hash256 {
    let index = output_index.to_be_bytes();
    sha256_domain(domains::MUT_PAYMENT_ID, &[&payment_txid.0, &index])
}

pub fn derive_license_id(
    network_id: u32,
    purchase_method: u8,
    purchase_id: &[u8; 32],
    manifest_index: u32,
    initial_owner_public_key: &[u8; 32],
) -> LicenseId {
    let network = network_id.to_be_bytes();
    let index = manifest_index.to_be_bytes();
    LicenseId(
        sha256_domain(
            domains::LICENSE_ID,
            &[
                &network,
                &[purchase_method],
                purchase_id,
                &index,
                initial_owner_public_key,
            ],
        )
        .0,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicensePurchaseMutV1 {
    pub payment_txid: TxId,
    pub payment_output_index: u16,
    pub manifest: MutLicenseManifestV1,
}

impl LicensePurchaseMutV1 {
    pub fn payload(&self) -> Result<Vec<u8>, ProtocolError> {
        let manifest = self.manifest.encode()?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.payment_txid.0);
        write_u16_be(&mut out, self.payment_output_index);
        write_varuint(&mut out, manifest.len() as u64);
        out.extend_from_slice(&manifest);
        Ok(out)
    }

    pub fn operation(&self) -> Result<ProtocolOperationV1, ProtocolError> {
        Ok(ProtocolOperationV1 {
            op_type: OP_LICENSE_PURCHASE_MUT,
            op_version: 1,
            payload: self.payload()?,
        })
    }

    pub fn license_ids(&self) -> Result<Vec<LicenseId>, ProtocolError> {
        let payment = native_payment_id(&self.payment_txid, self.payment_output_index);
        self.manifest
            .licenses
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                Ok(derive_license_id(
                    self.manifest.network_id,
                    PURCHASE_METHOD_MUT,
                    &payment.0,
                    i as u32,
                    &entry.owner_public_key,
                ))
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenseTransferV1 {
    pub license_id: LicenseId,
    pub expected_owner_sequence: u32,
    pub expected_mining_sequence: u32,
    pub new_owner_public_key: [u8; 32],
    pub new_mining_public_key: [u8; 32],
    pub owner_signature: [u8; 64],
}

impl LicenseTransferV1 {
    pub fn unsigned_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(104);
        out.extend_from_slice(&self.license_id.0);
        write_u32_be(&mut out, self.expected_owner_sequence);
        write_u32_be(&mut out, self.expected_mining_sequence);
        out.extend_from_slice(&self.new_owner_public_key);
        out.extend_from_slice(&self.new_mining_public_key);
        out
    }

    pub fn signing_digest(&self) -> Hash256 {
        operation_signing_digest(OP_LICENSE_TRANSFER, 1, &self.unsigned_payload())
    }

    pub fn operation(&self) -> ProtocolOperationV1 {
        let mut payload = self.unsigned_payload();
        payload.extend_from_slice(&self.owner_signature);
        ProtocolOperationV1 {
            op_type: OP_LICENSE_TRANSFER,
            op_version: 1,
            payload,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalLicenseKeysV1 {
    pub owner_public_key: [u8; 32],
    pub owner_key_sequence: u32,
    pub mining_public_key: [u8; 32],
    pub mining_key_sequence: u32,
}

pub fn apply_license_transfer(
    record: &mut LicenseRecordV1,
    transfer: &LicenseTransferV1,
) -> Result<HistoricalLicenseKeysV1, ProtocolError> {
    if record.status == LICENSE_STATUS_REVOKED {
        return Err(ProtocolError::Revoked);
    }
    if record.owner_key_sequence != transfer.expected_owner_sequence {
        return Err(ProtocolError::StaleOwnerSequence);
    }
    if record.mining_key_sequence != transfer.expected_mining_sequence {
        return Err(ProtocolError::StaleMiningSequence);
    }
    verify_owner_signature(
        &record.owner_public_key,
        &transfer.signing_digest().0,
        &transfer.owner_signature,
    )?;
    let historical = HistoricalLicenseKeysV1 {
        owner_public_key: record.owner_public_key,
        owner_key_sequence: record.owner_key_sequence,
        mining_public_key: record.mining_public_key,
        mining_key_sequence: record.mining_key_sequence,
    };
    record.owner_public_key = transfer.new_owner_public_key;
    record.mining_public_key = transfer.new_mining_public_key;
    record.owner_key_sequence = record
        .owner_key_sequence
        .checked_add(1)
        .ok_or(ProtocolError::Overflow)?;
    record.mining_key_sequence = record
        .mining_key_sequence
        .checked_add(1)
        .ok_or(ProtocolError::Overflow)?;
    Ok(historical)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiningKeyRotateV1 {
    pub license_id: LicenseId,
    pub expected_owner_sequence: u32,
    pub expected_mining_sequence: u32,
    pub new_mining_public_key: [u8; 32],
    pub owner_signature: [u8; 64],
}

impl MiningKeyRotateV1 {
    pub fn unsigned_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72);
        out.extend_from_slice(&self.license_id.0);
        write_u32_be(&mut out, self.expected_owner_sequence);
        write_u32_be(&mut out, self.expected_mining_sequence);
        out.extend_from_slice(&self.new_mining_public_key);
        out
    }
    pub fn signing_digest(&self) -> Hash256 {
        operation_signing_digest(OP_LICENSE_MINING_KEY_ROTATE, 1, &self.unsigned_payload())
    }
    pub fn operation(&self) -> ProtocolOperationV1 {
        let mut payload = self.unsigned_payload();
        payload.extend_from_slice(&self.owner_signature);
        ProtocolOperationV1 {
            op_type: OP_LICENSE_MINING_KEY_ROTATE,
            op_version: 1,
            payload,
        }
    }
}

pub fn apply_mining_key_rotation(
    record: &mut LicenseRecordV1,
    rotation: &MiningKeyRotateV1,
) -> Result<HistoricalLicenseKeysV1, ProtocolError> {
    if record.status == LICENSE_STATUS_REVOKED {
        return Err(ProtocolError::Revoked);
    }
    if record.owner_key_sequence != rotation.expected_owner_sequence {
        return Err(ProtocolError::StaleOwnerSequence);
    }
    if record.mining_key_sequence != rotation.expected_mining_sequence {
        return Err(ProtocolError::StaleMiningSequence);
    }
    verify_owner_signature(
        &record.owner_public_key,
        &rotation.signing_digest().0,
        &rotation.owner_signature,
    )?;
    let historical = HistoricalLicenseKeysV1 {
        owner_public_key: record.owner_public_key,
        owner_key_sequence: record.owner_key_sequence,
        mining_public_key: record.mining_public_key,
        mining_key_sequence: record.mining_key_sequence,
    };
    record.mining_public_key = rotation.new_mining_public_key;
    record.mining_key_sequence = record
        .mining_key_sequence
        .checked_add(1)
        .ok_or(ProtocolError::Overflow)?;
    Ok(historical)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiningPresenceV1 {
    pub network_id: u32,
    pub genesis_id: [u8; 32],
    pub license_id: LicenseId,
    pub expected_mining_sequence: u32,
    pub presence_epoch: u64,
    pub mining_signature: [u8; 64],
}

impl MiningPresenceV1 {
    pub fn unsigned_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MINING_PRESENCE_UNSIGNED_LEN);
        write_u32_be(&mut out, self.network_id);
        out.extend_from_slice(&self.genesis_id);
        out.extend_from_slice(&self.license_id.0);
        write_u32_be(&mut out, self.expected_mining_sequence);
        write_u64_be(&mut out, self.presence_epoch);
        debug_assert_eq!(out.len(), MINING_PRESENCE_UNSIGNED_LEN);
        out
    }

    pub fn signing_digest(&self) -> Hash256 {
        operation_signing_digest(OP_MINING_PRESENCE, 1, &self.unsigned_payload())
    }

    pub fn operation(&self) -> ProtocolOperationV1 {
        let mut payload = self.unsigned_payload();
        payload.extend_from_slice(&self.mining_signature);
        debug_assert_eq!(payload.len(), MINING_PRESENCE_FULL_LEN);
        ProtocolOperationV1 {
            op_type: OP_MINING_PRESENCE,
            op_version: 1,
            payload,
        }
    }

    pub fn decode_operation(op: &ProtocolOperationV1) -> Result<Self, ProtocolError> {
        if op.op_type != OP_MINING_PRESENCE
            || op.op_version != 1
            || op.payload.len() != MINING_PRESENCE_FULL_LEN
        {
            return Err(ProtocolError::InvalidMiningPresence);
        }
        Ok(Self {
            network_id: u32::from_be_bytes(
                op.payload[0..4]
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidMiningPresence)?,
            ),
            genesis_id: op.payload[4..36]
                .try_into()
                .map_err(|_| ProtocolError::InvalidMiningPresence)?,
            license_id: LicenseId(
                op.payload[36..68]
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidMiningPresence)?,
            ),
            expected_mining_sequence: u32::from_be_bytes(
                op.payload[68..72]
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidMiningPresence)?,
            ),
            presence_epoch: u64::from_be_bytes(
                op.payload[72..80]
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidMiningPresence)?,
            ),
            mining_signature: op.payload[80..144]
                .try_into()
                .map_err(|_| ProtocolError::InvalidMiningPresence)?,
        })
    }

    pub fn verify_against(
        &self,
        record: &LicenseRecordV1,
        expected_network_id: u32,
        expected_genesis_id: &[u8; 32],
        block_epoch: u64,
    ) -> Result<(), ProtocolError> {
        if !pack_k_active(expected_network_id, expected_genesis_id, block_epoch) {
            return Err(ProtocolError::MiningPresenceInactive);
        }
        if self.network_id != expected_network_id {
            return Err(ProtocolError::MiningPresenceNetwork);
        }
        if self.genesis_id != *expected_genesis_id {
            return Err(ProtocolError::MiningPresenceGenesis);
        }
        if self.presence_epoch != block_epoch {
            return Err(ProtocolError::MiningPresenceEpoch);
        }
        if record.status == LICENSE_STATUS_REVOKED {
            return Err(ProtocolError::Revoked);
        }
        if record.mining_key_sequence != self.expected_mining_sequence {
            return Err(ProtocolError::StaleMiningSequence);
        }
        verify_owner_signature(
            &record.mining_public_key,
            &self.signing_digest().0,
            &self.mining_signature,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PunishmentEvidenceV1 {
    pub offense_type: u16,
    pub accused_license_id: LicenseId,
    pub evidence: Vec<u8>,
}

impl PunishmentEvidenceV1 {
    pub fn canonical_evidence(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_be(&mut out, self.offense_type);
        out.extend_from_slice(&self.accused_license_id.0);
        write_varuint(&mut out, self.evidence.len() as u64);
        out.extend_from_slice(&self.evidence);
        out
    }
    pub fn evidence_id(&self) -> EvidenceId {
        EvidenceId(
            sha256_domain(
                domains::PUNISHMENT_EVIDENCE_ID,
                &[&self.canonical_evidence()],
            )
            .0,
        )
    }
    pub fn operation(&self) -> ProtocolOperationV1 {
        ProtocolOperationV1 {
            op_type: OP_PUNISHMENT_EVIDENCE,
            op_version: 1,
            payload: self.canonical_evidence(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffenseApplicationV1 {
    pub new_strike_weight: u8,
    pub suspended_until_epoch: u64,
    pub offense_expiry_epoch: u64,
    pub revoked: bool,
}

pub fn offense_weight(offense_type: u16) -> Result<u8, ProtocolError> {
    match offense_type {
        OFFENSE_INVALID_SIGNED_WORK => Ok(1),
        OFFENSE_LICENSE_STATE_EQUIVOCATION => Ok(2),
        OFFENSE_SAME_TICKET_EQUIVOCATION => Ok(4),
        _ => Err(ProtocolError::BadOffenseWeight),
    }
}

pub fn apply_offense(
    record: &mut LicenseRecordV1,
    offense_type: u16,
    applied_epoch: u64,
) -> Result<OffenseApplicationV1, ProtocolError> {
    if record.status == LICENSE_STATUS_REVOKED {
        return Err(ProtocolError::Revoked);
    }
    let weight = offense_weight(offense_type)?;
    let new_weight = record
        .strike_weight
        .checked_add(weight)
        .ok_or(ProtocolError::Overflow)?;
    let expiry = applied_epoch
        .checked_add(STRIKE_DECAY_EPOCHS)
        .ok_or(ProtocolError::Overflow)?;
    if new_weight >= REVOCATION_THRESHOLD {
        // LicenseRecordV1.strike_weight is a compact canonical summary. Once revocation
        // triggers it is pinned at the V1 threshold, while individual offense records
        // retain their exact weights and expiry epochs in ProtocolState.
        record.strike_weight = REVOCATION_THRESHOLD;
        record.status = LICENSE_STATUS_REVOKED;
        record.revocation_epoch = applied_epoch;
        return Ok(OffenseApplicationV1 {
            new_strike_weight: REVOCATION_THRESHOLD,
            suspended_until_epoch: record.suspended_until_epoch,
            offense_expiry_epoch: expiry,
            revoked: true,
        });
    }
    let exponent = 5u32 + new_weight as u32;
    let timeout = 1u64.checked_shl(exponent).ok_or(ProtocolError::Overflow)?;
    let base = record.suspended_until_epoch.max(applied_epoch);
    let suspended_until = base.checked_add(timeout).ok_or(ProtocolError::Overflow)?;
    record.strike_weight = new_weight;
    record.suspended_until_epoch = suspended_until;
    Ok(OffenseApplicationV1 {
        new_strike_weight: new_weight,
        suspended_until_epoch: suspended_until,
        offense_expiry_epoch: expiry,
        revoked: false,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DividendAwardCalculationV1 {
    pub available_before: u64,
    pub dividend_pool: u64,
    pub eligible_licenses: u64,
    pub per_license_strikes: u64,
    pub total_reserved_strikes: u64,
    pub undistributed_remainder_strikes: u64,
}

pub fn calculate_dividend_award(
    available_strikes: u64,
    eligible_licenses: u64,
) -> Result<DividendAwardCalculationV1, ProtocolError> {
    let dividend_pool = available_strikes
        .checked_mul(DIVIDEND_FRACTION_NUMERATOR)
        .ok_or(ProtocolError::Overflow)?
        / DIVIDEND_FRACTION_DENOMINATOR;
    let per_license_strikes = if eligible_licenses == 0 {
        0
    } else {
        dividend_pool / eligible_licenses
    };
    let total_reserved_strikes = per_license_strikes
        .checked_mul(eligible_licenses)
        .ok_or(ProtocolError::Overflow)?;
    let undistributed_remainder_strikes = dividend_pool
        .checked_sub(total_reserved_strikes)
        .ok_or(ProtocolError::Overflow)?;
    Ok(DividendAwardCalculationV1 {
        available_before: available_strikes,
        dividend_pool,
        eligible_licenses,
        per_license_strikes,
        total_reserved_strikes,
        undistributed_remainder_strikes,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DividendClaimV1 {
    pub license_id: LicenseId,
    pub expected_owner_sequence: u32,
    pub amount_strikes: u64,
    pub destination_address_id: AddressId,
    pub payment_txid: TxId,
    pub owner_signature: [u8; 64],
}

impl DividendClaimV1 {
    pub fn unsigned_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(108);
        out.extend_from_slice(&self.license_id.0);
        write_u32_be(&mut out, self.expected_owner_sequence);
        write_u64_be(&mut out, self.amount_strikes);
        out.extend_from_slice(&self.destination_address_id.0);
        out.extend_from_slice(&self.payment_txid.0);
        out
    }
    pub fn signing_digest(&self) -> Hash256 {
        operation_signing_digest(OP_DIVIDEND_CLAIM, 1, &self.unsigned_payload())
    }
    pub fn operation(&self) -> ProtocolOperationV1 {
        let mut payload = self.unsigned_payload();
        payload.extend_from_slice(&self.owner_signature);
        ProtocolOperationV1 {
            op_type: OP_DIVIDEND_CLAIM,
            op_version: 1,
            payload,
        }
    }
}

pub fn apply_dividend_claim(
    record: &LicenseRecordV1,
    account: &mut LicenseDividendAccountV1,
    treasury: &mut TreasuryStateV1,
    claim: &DividendClaimV1,
    block_epoch: u64,
) -> Result<(), ProtocolError> {
    if record.status == LICENSE_STATUS_REVOKED {
        return Err(ProtocolError::Revoked);
    }
    if record.owner_key_sequence != claim.expected_owner_sequence {
        return Err(ProtocolError::StaleOwnerSequence);
    }
    if account.license_id != claim.license_id
        || block_epoch < account.award_epoch
        || block_epoch >= account.claim_deadline_epoch
    {
        return Err(ProtocolError::DividendExpired);
    }
    if claim.amount_strikes == 0 || claim.amount_strikes > account.claimable_strikes {
        return Err(ProtocolError::DividendOverdraw);
    }
    verify_owner_signature(
        &record.owner_public_key,
        &claim.signing_digest().0,
        &claim.owner_signature,
    )?;
    account.claimable_strikes -= claim.amount_strikes;
    treasury.reserved_dividend_strikes = treasury
        .reserved_dividend_strikes
        .checked_sub(claim.amount_strikes)
        .ok_or(ProtocolError::TreasuryUnderflow)?;
    Ok(())
}

pub fn protocol_operation_leaf(id: &OperationId) -> Hash256 {
    sha256_domain(domains::PROTOCOL_OP_LEAF, &[&id.0])
}

pub fn protocol_operations_root(
    operations: &[ProtocolOperationV1],
) -> Result<Hash256, ProtocolError> {
    if operations.is_empty() {
        return Ok(sha256_domain(domains::PROTOCOL_OPS_EMPTY, &[]));
    }
    for pair in operations.windows(2) {
        let a = (pair[0].op_type, pair[0].operation_id().0);
        let b = (pair[1].op_type, pair[1].operation_id().0);
        if a >= b {
            return Err(ProtocolError::InvalidManifest);
        }
    }
    let mut level: Vec<Hash256> = operations
        .iter()
        .map(|op| protocol_operation_leaf(&op.operation_id()))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 == level.len() {
                next.push(level[i]);
            } else {
                next.push(sha256_domain(
                    domains::PROTOCOL_OP_NODE,
                    &[&level[i].0, &level[i + 1].0],
                ));
            }
            i += 2;
        }
        level = next;
    }
    Ok(level[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap_manifest_fixture() -> BootstrapManifestV1 {
        BootstrapManifestV1 {
            version: 1,
            network_id: 0x4D55_5403,
            purchase_nonce: [0x42; 32],
            licenses: (0..BOOTSTRAP_LICENSE_COUNT_V1)
                .map(|i| LicenseManifestEntryV1 {
                    owner_public_key: [i as u8; 32],
                    mining_public_key: [(i as u8).wrapping_add(1); 32],
                })
                .collect(),
        }
    }

    #[test]
    fn build54_bootstrap_manifest_omits_genesis_id_and_roundtrips() {
        let manifest = bootstrap_manifest_fixture();
        let encoded = manifest.encode().unwrap();
        assert_eq!(
            encoded.len(),
            2 + 4 + 32 + 4 + BOOTSTRAP_LICENSE_COUNT_V1 * 64
        );
        assert_eq!(BootstrapManifestV1::decode(&encoded).unwrap(), manifest);
    }

    #[test]
    fn build54_bootstrap_manifest_requires_exactly_twelve_licenses() {
        let mut manifest = bootstrap_manifest_fixture();
        manifest.licenses.pop();
        assert_eq!(
            manifest.validate().unwrap_err(),
            ProtocolError::InvalidManifest
        );
    }
    use ed25519_dalek::{Signer, SigningKey};
    use mutiny_state::{LICENSE_STATUS_ACTIVE, PURCHASE_METHOD_MUT};

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn signing(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }
    fn pubkey(byte: u8) -> [u8; 32] {
        signing(byte).verifying_key().to_bytes()
    }

    fn manifest() -> MutLicenseManifestV1 {
        MutLicenseManifestV1 {
            version: 1,
            network_id: 0x4d555401,
            purchase_nonce: (0xa0u8..0xc0).collect::<Vec<_>>().try_into().unwrap(),
            licenses: vec![
                LicenseManifestEntryV1 {
                    owner_public_key: pubkey(1),
                    mining_public_key: pubkey(101),
                },
                LicenseManifestEntryV1 {
                    owner_public_key: pubkey(2),
                    mining_public_key: pubkey(102),
                },
            ],
        }
    }

    fn purchase() -> LicensePurchaseMutV1 {
        LicensePurchaseMutV1 {
            payment_txid: TxId((0x40u8..0x60).collect::<Vec<_>>().try_into().unwrap()),
            payment_output_index: 0,
            manifest: manifest(),
        }
    }

    fn active_record(_license_id: LicenseId) -> LicenseRecordV1 {
        LicenseRecordV1 {
            version: 1,
            status: LICENSE_STATUS_ACTIVE,
            purchase_method: PURCHASE_METHOD_MUT,
            purchase_id: native_payment_id(&purchase().payment_txid, 0).0,
            owner_public_key: pubkey(1),
            owner_key_sequence: 0,
            mining_public_key: pubkey(101),
            mining_key_sequence: 0,
            issued_epoch: 12_346,
            activation_epoch: 12_410,
            strike_weight: 0,
            suspended_until_epoch: 0,
            revocation_epoch: 0,
        }
    }

    #[test]
    fn pack_d_native_purchase_vectors() {
        let p = purchase();
        assert_eq!(
            p.manifest.manifest_hash().unwrap().0,
            h32("7278d3a72f981303fdfe2c84e8dbec0028a8ba4c0e14d51205abeb1d97a80506")
        );
        assert_eq!(
            native_payment_id(&p.payment_txid, 0).0,
            h32("671fdb49f5fb9040c932becfa218554265c3012c9a131a2bd119ec2b0045b3b6")
        );
        let ids = p.license_ids().unwrap();
        assert_eq!(
            ids[0].0,
            h32("00d03f2eb009ee6330e3ae76ea2b58ccc5e9a65a45f6db1c43ce9a9ca875fb80")
        );
        assert_eq!(
            ids[1].0,
            h32("bfae7f688b2afc79535257d4fc2599ee05c4f5486bbaad7bd8f6ebe9aa4b2e5c")
        );
        assert_eq!(
            p.operation().unwrap().operation_id().0,
            h32("56e82f3b92837999ff72f64e09cc21aadee3d4a65b88132d1cc1d3326cbacbcd")
        );
    }

    #[test]
    fn pack_d_transfer_vector_and_state_transition() {
        let lid = purchase().license_ids().unwrap()[0];
        let mut t = LicenseTransferV1 {
            license_id: lid,
            expected_owner_sequence: 0,
            expected_mining_sequence: 0,
            new_owner_public_key: pubkey(3),
            new_mining_public_key: pubkey(103),
            owner_signature: [0; 64],
        };
        assert_eq!(
            t.signing_digest().0,
            h32("fa1424009d35d7b76f2896910d7c985ba0621420179f23937a221f67fcaead1f")
        );
        t.owner_signature = signing(1).sign(&t.signing_digest().0).to_bytes();
        let expected_sig: [u8; 64] = hex::decode("be096601f8a42ad1a86e11b9a4b09ab8501f2d12588d03992558c8c03d6cbbbfd9df071cfd1ae6801daa995c8c3f099ac5db328acd39ebfe6218487249516706").unwrap().try_into().unwrap();
        assert_eq!(t.owner_signature, expected_sig);
        assert_eq!(
            t.operation().operation_id().0,
            h32("36f328d9141c309ea20938f9a74a6be23d30ce86c543d4b33bb9d1c161386281")
        );
        let mut r = active_record(lid);
        let old = apply_license_transfer(&mut r, &t).unwrap();
        assert_eq!(old.owner_public_key, pubkey(1));
        assert_eq!(r.owner_public_key, pubkey(3));
        assert_eq!(r.mining_public_key, pubkey(103));
        assert_eq!((r.owner_key_sequence, r.mining_key_sequence), (1, 1));
        assert_eq!(r.strike_weight, 0);
    }

    #[test]
    fn pack_d_rotation_vector_and_state_transition() {
        let lid = purchase().license_ids().unwrap()[0];
        let mut r = active_record(lid);
        let mut t = LicenseTransferV1 {
            license_id: lid,
            expected_owner_sequence: 0,
            expected_mining_sequence: 0,
            new_owner_public_key: pubkey(3),
            new_mining_public_key: pubkey(103),
            owner_signature: [0; 64],
        };
        t.owner_signature = signing(1).sign(&t.signing_digest().0).to_bytes();
        apply_license_transfer(&mut r, &t).unwrap();
        let mut rot = MiningKeyRotateV1 {
            license_id: lid,
            expected_owner_sequence: 1,
            expected_mining_sequence: 1,
            new_mining_public_key: pubkey(104),
            owner_signature: [0; 64],
        };
        assert_eq!(
            rot.signing_digest().0,
            h32("8d7c24d4b396755bb39d796be8fd9cb368f3ffa89d9fe6859eccfb745c6fdfdd")
        );
        rot.owner_signature = signing(3).sign(&rot.signing_digest().0).to_bytes();
        assert_eq!(
            rot.operation().operation_id().0,
            h32("b31d93119da99cbc7880064a8bfd4498fa2d942f41aea8ea67e264c523f523f1")
        );
        apply_mining_key_rotation(&mut r, &rot).unwrap();
        assert_eq!(r.owner_key_sequence, 1);
        assert_eq!(r.mining_key_sequence, 2);
        assert_eq!(r.mining_public_key, pubkey(104));
    }

    #[test]
    fn pack_d_punishment_and_decay_metadata_vector() {
        let lid = purchase().license_ids().unwrap()[1];
        let evidence = PunishmentEvidenceV1 {
            offense_type: OFFENSE_INVALID_SIGNED_WORK,
            accused_license_id: lid,
            evidence: (0..272).map(|i| (i % 256) as u8).collect(),
        };
        assert_eq!(
            evidence.evidence_id().0,
            h32("a9a28538e0e2be945cfd550a8fac8913db00abac042a92ef25e4e4048ac4aef1")
        );
        assert_eq!(
            evidence.operation().operation_id().0,
            h32("72e28797d42021e44fa591cb061e2a8fc7ddee6dde950417195e7c871fa86e1c")
        );
        let mut r = LicenseRecordV1 {
            owner_public_key: pubkey(2),
            mining_public_key: pubkey(102),
            ..active_record(lid)
        };
        let applied = apply_offense(&mut r, OFFENSE_INVALID_SIGNED_WORK, 12_346).unwrap();
        assert_eq!(applied.new_strike_weight, 1);
        assert_eq!(applied.suspended_until_epoch, 12_410);
        assert_eq!(applied.offense_expiry_epoch, 2_109_498);
        assert!(!applied.revoked);
    }

    #[test]
    fn build52_dividend_award_is_exactly_half_with_floor_rounding() {
        let c = calculate_dividend_award(1_000_001, 12).unwrap();
        assert_eq!(c.dividend_pool, 500_000);
        assert_eq!(c.per_license_strikes, 41_666);
        assert_eq!(c.total_reserved_strikes, 499_992);
        assert_eq!(c.undistributed_remainder_strikes, 8);
        assert_eq!(c.available_before - c.total_reserved_strikes, 500_009);
    }

    #[test]
    fn build52_dividend_award_with_zero_eligible_reserves_nothing() {
        let c = calculate_dividend_award(999, 0).unwrap();
        assert_eq!(c.dividend_pool, 499);
        assert_eq!(c.per_license_strikes, 0);
        assert_eq!(c.total_reserved_strikes, 0);
        assert_eq!(c.undistributed_remainder_strikes, 499);
    }

    #[test]
    fn pack_d_dividend_claim_vector() {
        let lid = purchase().license_ids().unwrap()[0];
        let mut r = active_record(lid);
        let mut t = LicenseTransferV1 {
            license_id: lid,
            expected_owner_sequence: 0,
            expected_mining_sequence: 0,
            new_owner_public_key: pubkey(3),
            new_mining_public_key: pubkey(103),
            owner_signature: [0; 64],
        };
        t.owner_signature = signing(1).sign(&t.signing_digest().0).to_bytes();
        apply_license_transfer(&mut r, &t).unwrap();
        let mut claim = DividendClaimV1 {
            license_id: lid,
            expected_owner_sequence: 1,
            amount_strikes: 12_345_678,
            destination_address_id: AddressId(
                (0xd0u8..0xf0).collect::<Vec<_>>().try_into().unwrap(),
            ),
            payment_txid: TxId((0x80u8..0xa0).collect::<Vec<_>>().try_into().unwrap()),
            owner_signature: [0; 64],
        };
        assert_eq!(
            claim.signing_digest().0,
            h32("ab00367d97b2d4e915ea01819fbadfcaef83e276076321659a2497f2549fbc34")
        );
        claim.owner_signature = signing(3).sign(&claim.signing_digest().0).to_bytes();
        assert_eq!(
            claim.operation().operation_id().0,
            h32("72ae4cc212319004f11f3cfee4ddeb9ae291767b6e00dc46c129d5640e4320c4")
        );
        let mut account = LicenseDividendAccountV1 {
            license_id: lid,
            award_epoch: 131_072,
            claim_deadline_epoch: 196_608,
            claimable_strikes: 12_345_678,
        };
        let mut treasury = TreasuryStateV1 {
            available_strikes: 875_000_000_002,
            reserved_dividend_strikes: 124_999_999_998,
        };
        apply_dividend_claim(&r, &mut account, &mut treasury, &claim, 150_000).unwrap();
        assert_eq!(account.claimable_strikes, 0);
        assert_eq!(treasury.reserved_dividend_strikes, 124_987_654_320);
        let mut expired = account;
        expired.claimable_strikes = 1;
        assert_eq!(
            apply_dividend_claim(
                &r,
                &mut expired,
                &mut treasury,
                &DividendClaimV1 {
                    amount_strikes: 1,
                    ..claim
                },
                196_608
            ),
            Err(ProtocolError::DividendExpired)
        );
    }

    #[test]
    fn pack_d_protocol_operation_root_vector() {
        let p = purchase();
        let lid = p.license_ids().unwrap()[0];
        let mut t = LicenseTransferV1 {
            license_id: lid,
            expected_owner_sequence: 0,
            expected_mining_sequence: 0,
            new_owner_public_key: pubkey(3),
            new_mining_public_key: pubkey(103),
            owner_signature: [0; 64],
        };
        t.owner_signature = signing(1).sign(&t.signing_digest().0).to_bytes();
        let mut rot = MiningKeyRotateV1 {
            license_id: lid,
            expected_owner_sequence: 1,
            expected_mining_sequence: 1,
            new_mining_public_key: pubkey(104),
            owner_signature: [0; 64],
        };
        rot.owner_signature = signing(3).sign(&rot.signing_digest().0).to_bytes();
        let evidence = PunishmentEvidenceV1 {
            offense_type: OFFENSE_INVALID_SIGNED_WORK,
            accused_license_id: p.license_ids().unwrap()[1],
            evidence: (0..272).map(|i| (i % 256) as u8).collect(),
        };
        let mut claim = DividendClaimV1 {
            license_id: lid,
            expected_owner_sequence: 1,
            amount_strikes: 12_345_678,
            destination_address_id: AddressId(
                (0xd0u8..0xf0).collect::<Vec<_>>().try_into().unwrap(),
            ),
            payment_txid: TxId((0x80u8..0xa0).collect::<Vec<_>>().try_into().unwrap()),
            owner_signature: [0; 64],
        };
        claim.owner_signature = signing(3).sign(&claim.signing_digest().0).to_bytes();
        let ops = vec![
            p.operation().unwrap(),
            t.operation(),
            rot.operation(),
            evidence.operation(),
            claim.operation(),
        ];
        assert_eq!(
            protocol_operations_root(&ops).unwrap().0,
            h32("c1c94ce7477dd4de29ba20395d30343de62e24b961c319b380fcab8a086ee3a1")
        );
        let mut wrong = ops.clone();
        wrong.swap(0, 1);
        assert!(protocol_operations_root(&wrong).is_err());
    }

    #[test]
    fn network_identity_v1_registry_is_exact_and_magic_separated() {
        assert_eq!(MAINNET_NETWORK_ID, 0x4d55_5401);
        assert_eq!(TESTNET_NETWORK_ID, 0x4d55_5402);
        assert_eq!(DEVNET_NETWORK_ID, 0x4d55_5403);
        assert_eq!(PACK_K_DEVNET_NETWORK_ID, DEVNET_NETWORK_ID);

        assert_eq!(MAINNET_GENESIS_BLOCK_V1.len(), 989);
        assert_eq!(&MAINNET_GENESIS_BLOCK_V1[0..2], &[0x00, 0x01]);
        assert_eq!(
            &MAINNET_GENESIS_BLOCK_V1[2..6],
            &MAINNET_NETWORK_ID.to_be_bytes()
        );
        assert_eq!(
            u64::from_be_bytes(MAINNET_GENESIS_BLOCK_V1[6..14].try_into().unwrap()),
            1_788_630_436_000
        );
        assert_eq!(
            u32::from_be_bytes(MAINNET_GENESIS_BLOCK_V1[14..18].try_into().unwrap()),
            963_648
        );
        assert_eq!(MAINNET_GENESIS_BLOCK_V1[18], 11);
        assert_eq!(
            hex::encode(&MAINNET_GENESIS_BLOCK_V1[899..931]),
            "e08ca8e75aa57e03b3f42575dbd0ecf7b64898d5a05ff22ad66c40adcfa0d2c7"
        );
        assert_eq!(
            hex::encode(&MAINNET_GENESIS_BLOCK_V1[931..963]),
            "865fecb5c02562d25d262739809c3ebe51e5a14d9e40bc0ecb1ca8cf042ab4f9"
        );
        assert_eq!(&MAINNET_GENESIS_BLOCK_V1[963..989], MAINNET_GENESIS_MOTTO);
        assert_eq!(
            sha256_domain(domains::GENESIS_ID, &[MAINNET_GENESIS_BLOCK_V1]).0,
            MAINNET_GENESIS_ID
        );

        for magic in [
            0x4d55_544d,
            0x4d55_5454,
            0x4d55_5444,
            0x4d55_574d,
            0x4d55_5754,
            0x4d55_5744,
        ] {
            assert_ne!(MAINNET_NETWORK_ID, magic);
            assert_ne!(TESTNET_NETWORK_ID, magic);
            assert_ne!(DEVNET_NETWORK_ID, magic);
        }
    }

    #[test]
    fn pack_k_activation_tuple_is_exact_and_devnet_only() {
        assert_eq!(OP_MINING_PRESENCE, 0x0008);
        assert_eq!(PACK_K_DEVNET_NETWORK_ID, 0x4d55_5403);
        assert_eq!(PACK_K_DEVNET_ACTIVATION_EPOCH, 1500);
        assert_eq!(MINING_PRESENCE_WINDOW_EPOCHS, 16);
        assert_eq!(MINING_PRESENCE_UNSIGNED_LEN, 80);
        assert_eq!(MINING_PRESENCE_FULL_LEN, 144);
        assert_eq!(
            pack_k_activation_epoch(PACK_K_DEVNET_NETWORK_ID, &PACK_K_DEVNET_GENESIS_ID),
            Some(1500)
        );
        assert!(!pack_k_active(
            PACK_K_DEVNET_NETWORK_ID,
            &PACK_K_DEVNET_GENESIS_ID,
            1499
        ));
        assert!(pack_k_active(
            PACK_K_DEVNET_NETWORK_ID,
            &PACK_K_DEVNET_GENESIS_ID,
            1500
        ));
        assert_eq!(
            pack_k_activation_epoch(0x4d55_5401, &PACK_K_DEVNET_GENESIS_ID),
            None
        );
        assert_eq!(
            pack_k_activation_epoch(MAINNET_NETWORK_ID, &MAINNET_GENESIS_ID),
            Some(11)
        );
        let mut wrong_genesis = PACK_K_DEVNET_GENESIS_ID;
        wrong_genesis[31] ^= 1;
        assert_eq!(
            pack_k_activation_epoch(PACK_K_DEVNET_NETWORK_ID, &wrong_genesis),
            None
        );
    }

    #[test]
    fn pack_k_mining_presence_golden_vector_and_signature_are_exact() {
        let sk = SigningKey::from_bytes(&[0x6b; 32]);
        assert_eq!(
            hex::encode(sk.verifying_key().to_bytes()),
            "8320a51977d8c38ca8a4927c670df5821e449761945e15e9efb26a1509d230ea"
        );
        let license_id = LicenseId((0x80u8..0xa0).collect::<Vec<_>>().try_into().unwrap());
        let mut presence = MiningPresenceV1 {
            network_id: PACK_K_DEVNET_NETWORK_ID,
            genesis_id: PACK_K_DEVNET_GENESIS_ID,
            license_id,
            expected_mining_sequence: 2,
            presence_epoch: 1500,
            mining_signature: [0u8; 64],
        };
        assert_eq!(hex::encode(presence.unsigned_payload()), "4d5554034c603df8839ce020b42a1268a54a1938657a1b7812d2df92c4803d63355e702c808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0000000200000000000005dc");
        assert_eq!(
            hex::encode(presence.signing_digest().0),
            "32cd240c0dcd3669f30f5254e4f51220a51dddec8653dda0e0cdf344eab71acb"
        );
        presence.mining_signature = sk.sign(&presence.signing_digest().0).to_bytes();
        assert_eq!(hex::encode(presence.mining_signature), "632cce7f87792f93c8f72ff6f15db38ebec0440fcf3b3def7fc8efdc29890f92951ab8f8b1a75ba7fab09a4aa003f2e164c5e4235dc3b2780d0d5001d4a1000d");
        let op = presence.operation();
        assert_eq!(op.payload.len(), 144);
        assert_eq!(op.encode().len(), 150);
        assert_eq!(hex::encode(op.encode()), "0008000190014d5554034c603df8839ce020b42a1268a54a1938657a1b7812d2df92c4803d63355e702c808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0000000200000000000005dc632cce7f87792f93c8f72ff6f15db38ebec0440fcf3b3def7fc8efdc29890f92951ab8f8b1a75ba7fab09a4aa003f2e164c5e4235dc3b2780d0d5001d4a1000d");
        assert_eq!(
            hex::encode(op.operation_id().0),
            "f309184d23803800792f346483912110ddd4db4c23fbc2c4feb85883e75096f5"
        );
        assert_eq!(MiningPresenceV1::decode_operation(&op).unwrap(), presence);

        let record = LicenseRecordV1 {
            version: 1,
            status: LICENSE_STATUS_ACTIVE,
            purchase_method: PURCHASE_METHOD_MUT,
            purchase_id: [0x44; 32],
            owner_public_key: [0x55; 32],
            owner_key_sequence: 7,
            mining_public_key: sk.verifying_key().to_bytes(),
            mining_key_sequence: 2,
            issued_epoch: 1000,
            activation_epoch: 1064,
            strike_weight: 0,
            suspended_until_epoch: 0,
            revocation_epoch: 0,
        };
        presence
            .verify_against(
                &record,
                PACK_K_DEVNET_NETWORK_ID,
                &PACK_K_DEVNET_GENESIS_ID,
                1500,
            )
            .unwrap();
    }

    #[test]
    fn pack_k_mining_presence_rejects_inactive_wrong_binding_sequence_signature_and_revocation() {
        let sk = SigningKey::from_bytes(&[0x6b; 32]);
        let license_id = LicenseId((0x80u8..0xa0).collect::<Vec<_>>().try_into().unwrap());
        let mut presence = MiningPresenceV1 {
            network_id: PACK_K_DEVNET_NETWORK_ID,
            genesis_id: PACK_K_DEVNET_GENESIS_ID,
            license_id,
            expected_mining_sequence: 2,
            presence_epoch: 1500,
            mining_signature: [0u8; 64],
        };
        presence.mining_signature = sk.sign(&presence.signing_digest().0).to_bytes();
        let mut record = LicenseRecordV1 {
            version: 1,
            status: LICENSE_STATUS_ACTIVE,
            purchase_method: PURCHASE_METHOD_MUT,
            purchase_id: [0x44; 32],
            owner_public_key: [0x55; 32],
            owner_key_sequence: 7,
            mining_public_key: sk.verifying_key().to_bytes(),
            mining_key_sequence: 2,
            issued_epoch: 1000,
            activation_epoch: 1064,
            strike_weight: 0,
            suspended_until_epoch: 0,
            revocation_epoch: 0,
        };

        assert_eq!(
            presence.verify_against(
                &record,
                PACK_K_DEVNET_NETWORK_ID,
                &PACK_K_DEVNET_GENESIS_ID,
                1499
            ),
            Err(ProtocolError::MiningPresenceInactive)
        );

        let mut wrong_network = presence.clone();
        wrong_network.network_id ^= 1;
        assert_eq!(
            wrong_network.verify_against(
                &record,
                PACK_K_DEVNET_NETWORK_ID,
                &PACK_K_DEVNET_GENESIS_ID,
                1500
            ),
            Err(ProtocolError::MiningPresenceNetwork)
        );

        let mut wrong_genesis = presence.clone();
        wrong_genesis.genesis_id[0] ^= 1;
        assert_eq!(
            wrong_genesis.verify_against(
                &record,
                PACK_K_DEVNET_NETWORK_ID,
                &PACK_K_DEVNET_GENESIS_ID,
                1500
            ),
            Err(ProtocolError::MiningPresenceGenesis)
        );

        assert_eq!(
            presence.verify_against(
                &record,
                PACK_K_DEVNET_NETWORK_ID,
                &PACK_K_DEVNET_GENESIS_ID,
                1501
            ),
            Err(ProtocolError::MiningPresenceEpoch)
        );

        record.mining_key_sequence = 3;
        assert_eq!(
            presence.verify_against(
                &record,
                PACK_K_DEVNET_NETWORK_ID,
                &PACK_K_DEVNET_GENESIS_ID,
                1500
            ),
            Err(ProtocolError::StaleMiningSequence)
        );
        record.mining_key_sequence = 2;

        let mut bad_sig = presence.clone();
        bad_sig.mining_signature[0] ^= 1;
        assert_eq!(
            bad_sig.verify_against(
                &record,
                PACK_K_DEVNET_NETWORK_ID,
                &PACK_K_DEVNET_GENESIS_ID,
                1500
            ),
            Err(ProtocolError::InvalidSignature)
        );

        record.status = LICENSE_STATUS_REVOKED;
        assert_eq!(
            presence.verify_against(
                &record,
                PACK_K_DEVNET_NETWORK_ID,
                &PACK_K_DEVNET_GENESIS_ID,
                1500
            ),
            Err(ProtocolError::Revoked)
        );
    }
}

/// Pack M R2 canonical authenticated Bitcoin-header import operation.
///
/// Payload:
///   network_id:u32_be || genesis_id:bytes32 || canonical VarUInt(header_count)
///   || header_count * raw Bitcoin bytes80.
///
/// The operation is authority-free; Bitcoin proof of work is validated by the
/// later node integration layer. This type freezes only the canonical wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinHeadersV1 {
    pub network_id: u32,
    pub genesis_id: [u8; 32],
    pub headers: Vec<[u8; 80]>,
}

fn pack_m_write_varuint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn pack_m_read_varuint(input: &[u8]) -> Result<(u64, usize), &'static str> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (i, byte) in input.iter().copied().enumerate().take(10) {
        let low = (byte & 0x7f) as u64;
        if shift >= 64 || (shift == 63 && low > 1) {
            return Err("Pack M VarUInt overflow");
        }
        value |= low << shift;
        if byte & 0x80 == 0 {
            let mut canonical = Vec::new();
            pack_m_write_varuint(value, &mut canonical);
            if canonical.as_slice() != &input[..=i] {
                return Err("Pack M VarUInt is not minimally encoded");
            }
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err("unterminated Pack M VarUInt")
}

impl BitcoinHeadersV1 {
    pub const MAX_HEADERS: usize = 256;

    pub fn payload(&self) -> Result<Vec<u8>, &'static str> {
        if self.headers.is_empty() || self.headers.len() > Self::MAX_HEADERS {
            return Err("BITCOIN_HEADERS header_count must be in 1..=256");
        }
        let mut out = Vec::with_capacity(4 + 32 + 2 + self.headers.len() * 80);
        out.extend_from_slice(&self.network_id.to_be_bytes());
        out.extend_from_slice(&self.genesis_id);
        pack_m_write_varuint(self.headers.len() as u64, &mut out);
        for header in &self.headers {
            out.extend_from_slice(header);
        }
        Ok(out)
    }

    pub fn decode_payload(input: &[u8]) -> Result<Self, &'static str> {
        if input.len() < 37 {
            return Err("BITCOIN_HEADERS payload is truncated");
        }
        let network_id = u32::from_be_bytes(
            input[..4]
                .try_into()
                .map_err(|_| "invalid BITCOIN_HEADERS network_id")?,
        );
        let genesis_id: [u8; 32] = input[4..36]
            .try_into()
            .map_err(|_| "invalid BITCOIN_HEADERS genesis_id")?;
        let (count, count_len) = pack_m_read_varuint(&input[36..])?;
        let count: usize = count
            .try_into()
            .map_err(|_| "BITCOIN_HEADERS header_count does not fit usize")?;
        if count == 0 || count > Self::MAX_HEADERS {
            return Err("BITCOIN_HEADERS header_count must be in 1..=256");
        }
        let body = 36usize
            .checked_add(count_len)
            .ok_or("BITCOIN_HEADERS length overflow")?;
        let header_bytes = count
            .checked_mul(80)
            .ok_or("BITCOIN_HEADERS length overflow")?;
        let expected = body
            .checked_add(header_bytes)
            .ok_or("BITCOIN_HEADERS length overflow")?;
        if input.len() != expected {
            return Err("BITCOIN_HEADERS payload length mismatch");
        }

        let mut headers = Vec::with_capacity(count);
        let mut pos = body;
        for _ in 0..count {
            headers.push(
                input[pos..pos + 80]
                    .try_into()
                    .map_err(|_| "invalid BITCOIN_HEADERS raw header")?,
            );
            pos += 80;
        }
        Ok(Self {
            network_id,
            genesis_id,
            headers,
        })
    }

    pub fn to_operation(&self) -> Result<ProtocolOperationV1, &'static str> {
        Ok(ProtocolOperationV1 {
            op_type: OP_BITCOIN_HEADERS,
            op_version: 1,
            payload: self.payload()?,
        })
    }

    pub fn from_operation(op: &ProtocolOperationV1) -> Result<Self, &'static str> {
        if op.op_type != OP_BITCOIN_HEADERS || op.op_version != 1 {
            return Err("not a BITCOIN_HEADERS v1 operation");
        }
        Self::decode_payload(&op.payload)
    }
}

#[cfg(test)]
mod pack_m_r2_bitcoin_headers_wire_tests {
    use super::*;

    const GENESIS: &str = "4c603df8839ce020b42a1268a54a1938657a1b7812d2df92c4803d63355e702c";
    const HEADERS: [&str; 6] = [
        "01000000fba9fcccdcbc07db8a1e1166cc84a386ca5ed154ee2824bc2b6e80150521d75d5033651fbfd182bc9fe3f587494ef41d6cf7d9e83e1dfbab6a5ce8160fae391e58d4496bffff7f2000000000",
        "010000004a0042407c83e3a11ab888a970349373cadd32d9a5dde968f8e4f25612f1960989bf5dca10a465a78c133bdac9dd2c8544b1e1a58187e22e86ec8fe632ee1a24b0d6496bffff7f2003000000",
        "01000000bbe5cc968a01d463c128c7541a7a550c52a49f642e3a7d0c5edc1232848f33258cff64ac05b34fb7ddb5b722918353f710707e56b7a1e48a3ccb0373b585821008d9496bffff7f2002000000",
        "010000009263013f4f360222c2c2d3f77f50fe889d100b0c4f5bb92cdc8ac1e77d8cb256ce2818c74c5f5b2aeb4d91ff1e44685f40aaf27812add4d2db92460cedb71eea60db496bffff7f2004000000",
        "01000000315bd66962b7d7a011557e4f42ba51aa45d08a304a8b0130d991e04f0ff60138df392887a51635cc79f01c00eee0016b5bd72e545bafea7dcc8fc7371d5835b7b8dd496bffff7f2005000000",
        "01000000a2970f2d4c46e10e8ffc45b5618a9bddbd6810820190c613a9a8c454aeb55779e87cf812f59ee6e88f217411ad2c4f5f8e10c0e8fbf7e5f270f922bc4d0680f510e0496bffff7f2006000000",
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

    fn fixture(count: usize) -> BitcoinHeadersV1 {
        BitcoinHeadersV1 {
            network_id: 0x4d55_5403,
            genesis_id: h32(GENESIS),
            headers: HEADERS[..count].iter().map(|x| h80(x)).collect(),
        }
    }

    #[test]
    fn pack_m_r2_one_header_operation_id_exact() {
        let op = fixture(1).to_operation().unwrap();
        assert_eq!(op.op_type, 0x0009);
        assert_eq!(op.op_version, 1);
        assert_eq!(
            op.operation_id().0,
            h32("588ae9865d8a8ab01a06dbc07897ec27afeeb18a7d84f510f6f52da4798b51e6")
        );
        let decoded = BitcoinHeadersV1::from_operation(&op).unwrap();
        assert_eq!(decoded, fixture(1));
    }

    #[test]
    fn pack_m_r2_six_header_operation_id_exact() {
        let op = fixture(6).to_operation().unwrap();
        assert_eq!(
            op.operation_id().0,
            h32("5a71630f57c855685392ae36790c50cf97f625d04e98be09a93503b5558b96c7")
        );
        assert_eq!(BitcoinHeadersV1::from_operation(&op).unwrap(), fixture(6));
    }

    #[test]
    fn pack_m_r2_header_count_bound_is_closed() {
        let empty = BitcoinHeadersV1 {
            network_id: 0x4d55_5403,
            genesis_id: h32(GENESIS),
            headers: Vec::new(),
        };
        assert!(empty.payload().is_err());

        let full = BitcoinHeadersV1 {
            network_id: 0x4d55_5403,
            genesis_id: h32(GENESIS),
            headers: vec![[0u8; 80]; 256],
        };
        assert!(full.payload().is_ok());

        let overflow = BitcoinHeadersV1 {
            network_id: 0x4d55_5403,
            genesis_id: h32(GENESIS),
            headers: vec![[0u8; 80]; 257],
        };
        assert!(overflow.payload().is_err());
    }

    #[test]
    fn pack_m_r2_nonminimal_varuint_rejected() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x4d55_5403u32.to_be_bytes());
        payload.extend_from_slice(&h32(GENESIS));
        payload.extend_from_slice(&[0x81, 0x00]);
        payload.extend_from_slice(&h80(HEADERS[0]));
        assert!(BitcoinHeadersV1::decode_payload(&payload).is_err());
    }
}
