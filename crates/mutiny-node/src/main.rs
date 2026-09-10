mod bitcoin;
mod bitcoin_headers;
mod blocksync;
mod bootstrap;
mod dividends;
mod mainnet_bootstrap;
mod mining_signer;
use mining_signer::MiningAuthority;
mod presence;
mod punishment;
mod rpc;
mod storage;
#[allow(dead_code)]
mod worker_mining;
mod worker_runtime;
#[allow(dead_code)]
mod worker_scheduler;
#[allow(dead_code)]
mod worker_service;

use mutiny_protocol::{DEVNET_NETWORK_ID, MAINNET_GENESIS_ID, MAINNET_NETWORK_ID};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mutiny_codec::{read_varuint, write_varuint};
use mutiny_consensus::{authorized_capacity, derive_target, work_units, DIFFICULTY_Q32_ONE};
use mutiny_crypto::{
    block_hash, block_signing_digest, domains, epoch_seed, mutiny_argon2id, proof_below_target,
    sha256_domain, ticket_salt, ticket_seed,
};
use mutiny_duplex::{
    candidate_should_replace, preferred_direction, ConnectionDirection, DuplexSession,
};
use mutiny_keystore::{self, KeyRole, WalletBackupEntry, WatchWalletEntry};
use mutiny_p2p::{
    initiator_handshake, responder_handshake, Frame, PeerInfo, CAP_BUILD45_NODE,
    CAP_PEER_DISCOVERY, MSG_ADDR, MSG_BLOCK, MSG_BLOCK_ANNOUNCE, MSG_DEVNET_BLOCK_RESULT,
    MSG_DEVNET_TX_RESULT, MSG_GET_ADDR, MSG_GET_BLOCK, MSG_GET_HEADERS, MSG_GET_TX, MSG_HEADERS,
    MSG_PING, MSG_PONG, MSG_TX, MSG_TX_ANNOUNCE, P2P_MAGIC_DEVNET,
};
use mutiny_protocol::{
    apply_license_transfer, apply_mining_key_rotation, native_payment_id, protocol_operations_root,
    HistoricalLicenseKeysV1, LicenseManifestEntryV1, LicensePurchaseMutV1, LicenseTransferV1,
    MiningKeyRotateV1, MiningPresenceV1, MutLicenseManifestV1, ProtocolOperationV1,
    ACTIVATION_DELAY_EPOCHS as PROTOCOL_ACTIVATION_DELAY_EPOCHS, MINING_PRESENCE_WINDOW_EPOCHS,
    OP_BITCOIN_HEADERS, OP_DIVIDEND_CLAIM, OP_LICENSE_MINING_KEY_ROTATE, OP_LICENSE_PURCHASE_BTC,
    OP_LICENSE_PURCHASE_MUT, OP_LICENSE_TRANSFER, OP_MINING_PRESENCE, OP_PUNISHMENT_EVIDENCE,
    PACK_K_DEVNET_ACTIVATION_EPOCH,
};
use mutiny_state::{
    external_payment_leaf, license_leaf, protocol_state_key, protocol_state_leaf, sparse_root,
    state_root, utxo_key, utxo_leaf, ConsensusMetaV1, LicenseRecordV1, MiningPresenceStateV1,
    UtxoValueV1, LICENSE_STATUS_ACTIVE, LICENSE_STATUS_PENDING, LICENSE_STATUS_REVOKED,
    PS_CONSUMED_EVIDENCE, PS_CONSUMED_NATIVE_PAYMENT, PS_DIFFICULTY_HISTORY, PS_DIVIDEND_ACCOUNT,
    PS_HISTORICAL_LICENSE_KEY, PS_MINING_PRESENCE_STATE, PS_OFFENSE_EVENT, PS_TREASURY_STATE,
    PURCHASE_METHOD_BTC, PURCHASE_METHOD_MUT,
};
use mutiny_transaction::{
    address_id, merkle_root, required_base_fee, sighash_all, verify_pubkey_hash_witness,
    CoinbaseCommitmentV1, PrevoutCommitmentV1, TransactionCoreV1, TransactionV1, TxInput, TxOutput,
    WitnessV1, OUTPUT_LICENSE_PAYMENT, OUTPUT_PUBKEY_HASH, OUTPUT_TREASURY,
};
use mutiny_types::{AddressId, Hash256, LicenseId, TxId};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env, fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(not(test))]
use std::sync::OnceLock;

#[cfg(test)]
use mutiny_p2p::{load_or_create_node_key, P2pError};
#[cfg(test)]
use std::io::Read;
#[cfg(test)]
use std::net::Shutdown;

const BUILD_NAME: &str = "Mutiny Protocol V1.0 Build 7.0 Candidate 1";
const BUILD_DESCRIPTION: &str = "First-Node Mainnet Bootstrap Activation";
// Inherited locked Build 5.9 scope: Local Authenticated RPC & Service Boundary.
const MOTTO: &str = "No Masters. Only the Many.";

const BOOTSTRAP_LICENSE_COUNT: usize = 12;
const ACTIVATION_DELAY_EPOCHS: u64 = PROTOCOL_ACTIVATION_DELAY_EPOCHS;
const DEFAULT_EPOCH_MS: u64 = 60_000;
const DEFAULT_DATA_DIR: &str = "devnet-data-build6.3";
const MAX_SIDE_BRANCHES: usize = 16;
const MAX_RUNTIME_PEERS: usize = 256;
const MAX_LIVE_DUPLEX_PEERS: usize = 64;
const MAX_INBOUND_DUPLEX_PEERS: usize = 48;
const MAX_INBOUND_DUPLEX_PEERS_PER_IP: usize = 8;
const MAX_INBOUND_HANDSHAKES: usize = 32;
const MAX_INBOUND_HANDSHAKES_PER_IP: usize = 4;
const MAX_ANNOUNCE_WORKERS: usize = 16;
const MAX_EXPENSIVE_REQUESTS_PER_WINDOW: u32 = 16;
const EXPENSIVE_REQUEST_WINDOW: Duration = Duration::from_secs(10);
const EXPENSIVE_REQUEST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_TX_RELAY_INTERLEAVED_FRAMES: usize = 1024;
const MAX_NETWORK_MEMPOOL_TXS: usize = 4096;
const MAX_ADDR_ADMISSIONS_PER_SESSION: usize = 16;
const MAX_DIAL_ATTEMPTS_PER_ROUND: usize = 16;
const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEVNET_FIXED_GENESIS_TIME_MS: u128 = 1_800_000_000_000;
const DEFAULT_P2P_LISTEN: &str = "127.0.0.1:24588";
const NODE_PASSPHRASE_FILE_ENV: &str = "MUTINY_NODE_PASSPHRASE_FILE";
const STRIKES_PER_MUT: u64 = 100_000_000;
const DEVNET_BTC_PRICE_SATS_PER_LICENSE: u64 = 2_048;
const DEVNET_BTC_BITS: u32 = 0x207f_ffff;
const DEVNET_BTC_TRUSTED_CHECKPOINT_INTERNAL: [u8; 32] = [0x53; 32];
const DEVNET_BTC_TREASURY_SCRIPT: &[u8] = &[
    0x00, 0x20, 0x4d, 0x55, 0x54, 0x49, 0x4e, 0x59, 0x2d, 0x42, 0x54, 0x43, 0x2d, 0x54, 0x52, 0x45,
    0x41, 0x53, 0x55, 0x52, 0x59, 0x2d, 0x44, 0x45, 0x56, 0x4e, 0x45, 0x54, 0x2d, 0x56, 0x31, 0x00,
    0x00, 0x01,
];
const ERA_LENGTH: u64 = 1u64 << 21;
const COINBASE_MATURITY: u64 = 16;
const BASE_FEE_MIN_Q32: u64 = 1u64 << 32;
const BASE_FEE_MAX_Q32: u64 = (1u64 << 20) << 32;
const BLOCK_WEIGHT_TARGET: u64 = 1u64 << 16;
const BLOCK_WEIGHT_MAX: u64 = 1u64 << 17;
const DIFFICULTY_EASIER_STEP_Q32: u64 = 4_341_736_423;
const DIFFICULTY_HARDER_STEP_Q32: u64 = 4_248_701_965;
const DIFFICULTY_C_MIN_Q32: u64 = 1u64 << 16;
const DIFFICULTY_C_MAX_Q32: u64 = 1u64 << 48;

const OFFLINE_SPEND_REQUEST_MAGIC: &[u8; 8] = b"MUTOSRQ1";
const OFFLINE_SPEND_SIGNATURE_MAGIC: &[u8; 8] = b"MUTOSIG1";
const OFFLINE_SPEND_VERSION: u16 = 1;
const OFFLINE_SPEND_MAX_SUBMIT_BLOCKS: u64 = 144;
const DEVNET_GENESIS_ID_HEX: &str =
    "4c603df8839ce020b42a1268a54a1938657a1b7812d2df92c4803d63355e702c";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeNetwork {
    Devnet,
    Mainnet,
}

/// Node-local context that must accompany received-block ingress.  It contains
/// no consensus data and is intentionally immutable for the lifetime of a
/// running node.
#[derive(Debug, Clone)]
struct RuntimeIngressContext {
    runtime: RuntimeNetwork,
    bootstrap_witness: Option<mainnet_bootstrap::BootstrapWitnessProvider>,
}

impl RuntimeNetwork {
    fn from_cli(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("devnet") {
            "devnet" => Ok(Self::Devnet),
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Err("Testnet is inactive and fail-closed".into()),
            other => Err(format!("unsupported Mutiny network {other}")),
        }
    }

    fn p2p_magic(self) -> u32 {
        match self {
            Self::Devnet => P2P_MAGIC_DEVNET,
            Self::Mainnet => mutiny_p2p::P2P_MAGIC_MAINNET,
        }
    }

    fn network_id(self) -> u32 {
        match self {
            Self::Devnet => DEVNET_NETWORK_ID,
            Self::Mainnet => MAINNET_NETWORK_ID,
        }
    }

    fn genesis_id(self) -> Result<[u8; 32], String> {
        match self {
            Self::Devnet => decode32(DEVNET_GENESIS_ID_HEX),
            Self::Mainnet => Ok(MAINNET_GENESIS_ID),
        }
    }
}

fn serde_default_license_status_active() -> u8 {
    LICENSE_STATUS_ACTIVE
}
fn serde_default_purchase_method_btc() -> u8 {
    PURCHASE_METHOD_BTC
}
fn serde_default_activation_epoch() -> u64 {
    ACTIVATION_DELAY_EPOCHS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LicenseState {
    // Display/local-wallet index only; LicenseID is the consensus identity. u32 avoids
    // imposing the Devnet deterministic-key fixture's 255-key limit on validated chain state.
    index: u32,
    license_id: String,
    purchase_id: String,
    owner_public_key: String,
    mining_public_key: String,
    payment_address_id: String,
    #[serde(default = "serde_default_license_status_active")]
    status: u8,
    #[serde(default = "serde_default_purchase_method_btc")]
    purchase_method: u8,
    #[serde(default)]
    owner_key_sequence: u32,
    #[serde(default)]
    mining_key_sequence: u32,
    #[serde(default)]
    issued_epoch: u64,
    #[serde(default = "serde_default_activation_epoch")]
    activation_epoch: u64,
    #[serde(default)]
    strike_weight: u8,
    #[serde(default)]
    suspended_until_epoch: u64,
    #[serde(default)]
    revocation_epoch: u64,
}

impl LicenseState {
    fn record(&self) -> Result<LicenseRecordV1, String> {
        Ok(LicenseRecordV1 {
            version: 1,
            status: self.status,
            purchase_method: self.purchase_method,
            purchase_id: decode32(&self.purchase_id)?,
            owner_public_key: decode32(&self.owner_public_key)?,
            owner_key_sequence: self.owner_key_sequence,
            mining_public_key: decode32(&self.mining_public_key)?,
            mining_key_sequence: self.mining_key_sequence,
            issued_epoch: self.issued_epoch,
            activation_epoch: self.activation_epoch,
            strike_weight: self.strike_weight,
            suspended_until_epoch: self.suspended_until_epoch,
            revocation_epoch: self.revocation_epoch,
        })
    }

    fn is_eligible(&self, epoch: u64) -> bool {
        self.status == LICENSE_STATUS_ACTIVE
            && epoch >= self.activation_epoch
            && epoch >= self.suspended_until_epoch
            && self.revocation_epoch == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct HistoricalLicenseKeyState {
    operation_id: String,
    license_id: String,
    owner_public_key: String,
    owner_key_sequence: u32,
    mining_public_key: String,
    mining_key_sequence: u32,
}

impl HistoricalLicenseKeyState {
    fn value_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(104);
        out.extend_from_slice(&decode32(&self.license_id)?);
        out.extend_from_slice(&decode32(&self.owner_public_key)?);
        out.extend_from_slice(&self.owner_key_sequence.to_be_bytes());
        out.extend_from_slice(&decode32(&self.mining_public_key)?);
        out.extend_from_slice(&self.mining_key_sequence.to_be_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BitcoinPaymentState {
    payment_id: String,
    txid_internal: String,
    payment_output_index: u32,
    paid_sats: u64,
    containing_block_hash_internal: String,
    containing_block_height: u32,
    sixth_confirmation_hash_internal: String,
    sixth_confirmation_height: u32,
    sixth_confirmation_timestamp: u32,
}

impl BitcoinPaymentState {
    fn value_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(120);
        out.extend_from_slice(&decode32(&self.txid_internal)?);
        out.extend_from_slice(&self.payment_output_index.to_be_bytes());
        out.extend_from_slice(&self.paid_sats.to_be_bytes());
        out.extend_from_slice(&decode32(&self.containing_block_hash_internal)?);
        out.extend_from_slice(&self.containing_block_height.to_be_bytes());
        out.extend_from_slice(&decode32(&self.sixth_confirmation_hash_internal)?);
        out.extend_from_slice(&self.sixth_confirmation_height.to_be_bytes());
        out.extend_from_slice(&self.sixth_confirmation_timestamp.to_be_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UtxoState {
    txid: String,
    output_index: u16,
    amount_strikes: u64,
    output_type: u8,
    payload: String,
    creation_epoch: u64,
    creation_height: u64,
    coinbase: bool,
}

impl UtxoState {
    fn value(&self) -> Result<UtxoValueV1, String> {
        Ok(UtxoValueV1 {
            amount_strikes: self.amount_strikes,
            output_type: self.output_type,
            payload: hex::decode(&self.payload).map_err(|e| e.to_string())?,
            creation_epoch: self.creation_epoch,
            creation_height: self.creation_height,
            coinbase: self.coinbase,
        })
    }

    fn prevout(&self) -> Result<PrevoutCommitmentV1, String> {
        Ok(PrevoutCommitmentV1 {
            previous_txid: decode32(&self.txid)?,
            previous_output_index: self.output_index,
            amount_strikes: self.amount_strikes,
            output_type: self.output_type,
            payload: hex::decode(&self.payload).map_err(|e| e.to_string())?,
        })
    }

    fn spendable_at_height(&self, candidate_height: u64) -> bool {
        !self.coinbase || candidate_height >= self.creation_height.saturating_add(COINBASE_MATURITY)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredTxInput {
    previous_txid: String,
    previous_output_index: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredTxOutput {
    amount_strikes: u64,
    output_type: u8,
    payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredWitness {
    witness_type: u8,
    payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingTxState {
    txid: String,
    wtxid: String,
    valid_from_epoch: u64,
    expiry_epoch: u64,
    inputs: Vec<StoredTxInput>,
    outputs: Vec<StoredTxOutput>,
    witnesses: Vec<StoredWitness>,
    fee_strikes: u64,
    base_fee_strikes: u64,
    from_license: u8,
    to_license: u8,
    amount_strikes: u64,
}

impl PendingTxState {
    fn has_license_payment_output(&self) -> bool {
        self.outputs
            .iter()
            .any(|o| o.output_type == OUTPUT_LICENSE_PAYMENT)
    }

    fn has_protocol_auth_witness(&self) -> bool {
        self.witnesses
            .iter()
            .any(|w| w.witness_type == mutiny_transaction::WITNESS_PROTOCOL_AUTH)
    }

    #[cfg(test)]
    fn to_transaction(&self) -> Result<TransactionV1, String> {
        self.to_transaction_for_network(DEVNET_NETWORK_ID)
    }

    fn to_transaction_for_network(&self, network_id: u32) -> Result<TransactionV1, String> {
        let inputs = self
            .inputs
            .iter()
            .map(|i| {
                Ok(TxInput::Outpoint {
                    previous_txid: decode32(&i.previous_txid)?,
                    previous_output_index: i.previous_output_index,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let outputs = self
            .outputs
            .iter()
            .map(|o| {
                Ok(TxOutput {
                    amount_strikes: o.amount_strikes,
                    output_type: o.output_type,
                    payload: hex::decode(&o.payload).map_err(|e| e.to_string())?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let witnesses = self
            .witnesses
            .iter()
            .map(|w| {
                Ok(WitnessV1 {
                    witness_type: w.witness_type,
                    payload: hex::decode(&w.payload).map_err(|e| e.to_string())?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(TransactionV1 {
            core: TransactionCoreV1 {
                version: 1,
                network_id,
                valid_from_epoch: self.valid_from_epoch,
                expiry_epoch: self.expiry_epoch,
                inputs,
                outputs,
            },
            witnesses,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PendingProtocolOperationState {
    operation: String,
    required_txid: String,
}

impl PendingProtocolOperationState {
    fn operation(&self) -> Result<ProtocolOperationV1, String> {
        decode_protocol_operation_hex(&self.operation)
    }
}

fn transaction_is_protocol_bound(state: &DevnetState, txid: &str) -> bool {
    state
        .pending_protocol_operations
        .iter()
        .any(|op| op.required_txid == txid)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfirmedTxState {
    tx: PendingTxState,
    block_height: u64,
    block_epoch: u64,
    block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockState {
    height: u64,
    epoch: u64,
    /// Exact frozen 272-byte Mutiny V1 header, lowercase hex.
    header: String,
    /// Canonical full Pack-B transaction bytes in block order (coinbase first), lowercase hex.
    transactions: Vec<String>,
    /// Canonical protocol-operation bytes in frozen `(type, OperationID)` order.
    #[serde(default)]
    protocol_operations: Vec<String>,
    block_hash: String,
    parent_hash: String,
    miner_license_id: String,
    ticket_index: u16,
    argon2_proof: String,
    target: String,
    reward_strikes: u64,
    total_fees_strikes: u64,
    treasury_fee_share_strikes: u64,
    block_weight: u64,
    transaction_root: String,
    state_root: String,
    coinbase_txid: String,
    transaction_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SideBranchState {
    fork_height: u64,
    tip_height: u64,
    tip_hash: String,
    chain_work: String,
    blocks: Vec<BlockState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DevnetState {
    format_version: u16,
    network_id: u32,
    motto: String,
    genesis_time_ms: u128,
    genesis_hash: String,
    epoch_ms: u64,
    height: u64,
    tip_hash: String,
    tip_epoch: u64,
    anchor_epoch: u64,
    anchor_license_id: String,
    anchor_ticket_index: u16,
    anchor_argon2_proof: String,
    total_issued_strikes: u64,
    difficulty_history_count: u8,
    difficulty_history_bitmap: u64,
    difficulty_correction_q32: u64,
    base_fee_rate_q32: u64,
    current_state_root: String,
    licenses: Vec<LicenseState>,
    #[serde(default)]
    consumed_native_payments: Vec<String>,
    #[serde(default)]
    consumed_bitcoin_payments: Vec<BitcoinPaymentState>,
    #[serde(default)]
    consumed_evidence: Vec<String>,
    #[serde(default)]
    offense_events: Vec<punishment::OffenseEventState>,
    #[serde(default)]
    treasury_reserved_dividend_strikes: u64,
    #[serde(default)]
    dividend_accounts: Vec<dividends::DividendAccountState>,
    #[serde(default)]
    historical_license_keys: Vec<HistoricalLicenseKeyState>,
    #[serde(default)]
    mining_presence: Vec<presence::MiningPresenceState>,
    #[serde(default)]
    bitcoin_headers: Vec<bitcoin_headers::BitcoinHeaderStateStored>,
    #[serde(default)]
    bitcoin_best_chain: Option<bitcoin_headers::BitcoinBestChainStored>,
    utxos: Vec<UtxoState>,
    mempool: Vec<PendingTxState>,
    #[serde(default)]
    pending_protocol_operations: Vec<PendingProtocolOperationState>,
    confirmed_transactions: Vec<ConfirmedTxState>,
    blocks: Vec<BlockState>,
    #[serde(default)]
    side_branches: Vec<SideBranchState>,
}

#[derive(Debug)]
struct ValidatedTx {
    pending: PendingTxState,
    tx: TransactionV1,
    fee: u64,
    base_fee: u64,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn announce_tip_to_peer_authenticated_sync_bridge(
    peer: &str,
    state: &DevnetState,
    node_key: &SigningKey,
) -> Result<(), String> {
    let announced = decode32(&state.tip_hash)?;

    let mut stream = TcpStream::connect(peer)
        .map_err(|e| format!("connect authenticated Pack-H peer {peer}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("set authenticated Pack-H read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("set authenticated Pack-H write timeout: {e}"))?;
    stream
        .set_nodelay(true)
        .map_err(|e| format!("set authenticated Pack-H TCP_NODELAY: {e}"))?;

    let _info = initiator_handshake(
        &mut stream,
        node_key,
        CAP_BUILD45_NODE,
        DEVNET_NETWORK_ID,
        P2P_MAGIC_DEVNET,
    )
    .map_err(|e| format!("authenticated Pack-H initiator handshake: {e}"))?;

    Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK_ANNOUNCE, 0, announced.to_vec())
        .map_err(|e| e.to_string())?
        .write_to(&mut stream)
        .map_err(|e| format!("write unsolicited authenticated BLOCKANNOUNCE: {e}"))?;

    println!(
        "Authenticated Pack-H unsolicited BLOCKANNOUNCE frame sent: {}",
        hex::encode(announced)
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut interleaved = 0usize;
    let mut headers_served = 0usize;

    loop {
        if Instant::now() >= deadline {
            return Err(
                "timed out waiting for announced-block GETBLOCK after authenticated sync prelude"
                    .into(),
            );
        }

        let frame = Frame::read_from(&mut stream, P2P_MAGIC_DEVNET)
            .map_err(|e| format!("read reverse authenticated Pack-H sync frame: {e}"))?;

        match frame.message_type {
            MSG_GET_HEADERS => {
                if frame.request_id == 0 {
                    return Err(
                        "authenticated GETHEADERS must use nonzero independent RequestID".into(),
                    );
                }
                let payload = blocksync::serve_get_headers(state, &frame.payload)?;
                Frame::new(P2P_MAGIC_DEVNET, MSG_HEADERS, frame.request_id, payload)
                    .map_err(|e| e.to_string())?
                    .write_to(&mut stream)
                    .map_err(|e| format!("write authenticated Pack-H HEADERS response: {e}"))?;
                headers_served = headers_served.saturating_add(1);
                println!(
                    "Authenticated Pack-H GETHEADERS served: request_id={} count={}",
                    frame.request_id, headers_served
                );
            }
            MSG_GET_BLOCK => {
                if frame.request_id == 0 {
                    return Err(
                        "authenticated GETBLOCK must use nonzero independent RequestID".into(),
                    );
                }
                if frame.payload.as_slice() != &announced[..] {
                    return Err(format!(
                        "authenticated GETBLOCK requested unexpected hash {}",
                        hex::encode(&frame.payload)
                    ));
                }

                let payload = blocksync::serve_get_block(state, &frame.payload)?;
                Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK, frame.request_id, payload)
                    .map_err(|e| e.to_string())?
                    .write_to(&mut stream)
                    .map_err(|e| format!("write authenticated Pack-H BLOCK response: {e}"))?;

                println!(
                    "Authenticated Pack-H announced GETBLOCK served: request_id={} hash={}",
                    frame.request_id,
                    hex::encode(announced)
                );
                println!(
                    "Authenticated Pack-H sync prelude GETHEADERS responses served: {}",
                    headers_served
                );

                thread::sleep(Duration::from_millis(750));
                return Ok(());
            }
            MSG_PING => {
                if frame.request_id == 0 {
                    return Err("authenticated Pack-H PING request must be nonzero".into());
                }
                Frame::new(P2P_MAGIC_DEVNET, MSG_PONG, frame.request_id, frame.payload)
                    .map_err(|e| e.to_string())?
                    .write_to(&mut stream)
                    .map_err(|e| format!("write authenticated Pack-H PONG: {e}"))?;
            }
            MSG_GET_ADDR => {
                if frame.request_id == 0 {
                    return Err("authenticated Pack-H GETADDR request must be nonzero".into());
                }
                let payload = encode_peer_addresses(&[], state.tip_epoch)?;
                Frame::new(P2P_MAGIC_DEVNET, MSG_ADDR, frame.request_id, payload)
                    .map_err(|e| e.to_string())?
                    .write_to(&mut stream)
                    .map_err(|e| format!("write authenticated Pack-H ADDR response: {e}"))?;
            }
            MSG_ADDR | MSG_BLOCK_ANNOUNCE | MSG_TX_ANNOUNCE => {
                interleaved = interleaved.saturating_add(1);
            }
            other => {
                interleaved = interleaved.saturating_add(1);
                if interleaved > 64 {
                    return Err(format!(
                        "too many interleaved authenticated Pack-H frames before announced GETBLOCK; last type={other:#06x}"
                    ));
                }
            }
        }
    }
}
fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let runtime_network = RuntimeNetwork::from_cli(option_value(&args, "--network"))?;
    if cmd == "node" && has_flag(&args, "--help") {
        print_help();
        return Ok(());
    }
    let ingress = RuntimeIngressContext {
        runtime: runtime_network,
        bootstrap_witness: option_value(&args, "--bootstrap-witness")
            .map(mainnet_bootstrap::BootstrapWitnessProvider::new),
    };
    if runtime_network == RuntimeNetwork::Mainnet
        && !matches!(
            cmd,
            "help"
                | "init"
                | "bootstrap-mainnet"
                | "node"
                | "node-key-init"
                | "node-key-info"
                | "node-key-migrate"
                | "status"
                | "check"
                | "storage-verify"
                | "storage-info"
                | "mining-signer-init"
                | "mining-signer-check"
                | "wallet-mine-one"
                | "wallet-mining-presence"
                | "blocks"
                | "licenses"
                | "utxos"
                | "mempool"
                | "balance"
        )
    {
        return Err(format!(
            "command '{cmd}' has no supported Mainnet runtime path; refusing Devnet defaults"
        ));
    }
    if runtime_network == RuntimeNetwork::Mainnet && cmd == "node" && has_flag(&args, "--mine") {
        required_option(&args, "--mining-key-label")?;
        required_option(&args, "--mining-license")?;
        required_option(&args, "--wallet-passphrase-file")?;
    }
    let data_dir = option_value(&args, "--data-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(if runtime_network == RuntimeNetwork::Mainnet {
                "mainnet-data-build6.7"
            } else {
                DEFAULT_DATA_DIR
            })
        });
    if let Some(path) = option_value(&args, "--node-passphrase-file") {
        env::set_var(NODE_PASSPHRASE_FILE_ENV, path);
    }

    match cmd {
        "init" => {
            let epoch_ms = option_value(&args, "--epoch-ms")
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_EPOCH_MS);
            match runtime_network {
                RuntimeNetwork::Devnet => {
                    init_build54_genesis_devnet(&data_dir, epoch_ms, has_flag(&args, "--force"))?
                }
                RuntimeNetwork::Mainnet => {
                    init_mainnet_genesis(&data_dir, epoch_ms, has_flag(&args, "--force"))?
                }
            }
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            validate_runtime_tuple(&state, runtime_network)?;
            print_banner(&state);
            println!("Initialized {}", data_dir.display());
            print_status(&state);
        }
        "bootstrap-mainnet" => {
            if runtime_network != RuntimeNetwork::Mainnet {
                return Err("bootstrap-mainnet requires --network mainnet".into());
            }
            let provider = ingress.bootstrap_witness.as_ref().ok_or(
                "bootstrap-mainnet requires --bootstrap-witness PATH",
            )?;
            let live = load_state_for_runtime(&data_dir, &ingress)?;
            validate_runtime_tuple(&live, RuntimeNetwork::Mainnet)?;
            const EXPECTED_GENESIS_STATE_ROOT: &str =
                "e08ca8e75aa57e03b3f42575dbd0ecf7b64898d5a05ff22ad66c40adcfa0d2c7";
            if live.height != 0
                || live.tip_epoch != 0
                || live.tip_hash != hex::encode(MAINNET_GENESIS_ID)
                || live.current_state_root != EXPECTED_GENESIS_STATE_ROOT
                || !live.blocks.is_empty()
                || !live.licenses.is_empty()
                || !live.bitcoin_headers.is_empty()
                || live.bitcoin_best_chain.is_some()
                || !live.mempool.is_empty()
                || !live.pending_protocol_operations.is_empty()
                || !live.confirmed_transactions.is_empty()
                || !live.side_branches.is_empty()
            {
                return Err("bootstrap-mainnet requires the exact clean Mainnet height-0 state".into());
            }
            let witness = provider
                .load()
                .map_err(|e| e.to_string())?
                .decode()
                .map_err(|e| e.to_string())?;
            let staged = mainnet_bootstrap::build_staged_mainnet_block1_transition(
                &live, &witness,
            )
            .map_err(|e| format!("Mainnet Block 1 bootstrap refused: {e:?}"))?;

            const EXPECTED_BLOCK1: &str =
                "9d8026ac82592abb40cb1809142af67ea57b89e19ad51db35ff3d53f09907ded";
            const EXPECTED_STATE_ROOT: &str =
                "4d844f0393da16e076f0873358b3471425261e9fda0bf011124f1dae705faae7";
            const EXPECTED_PAYMENT_ID: &str =
                "e7aa3d2f8459a0fd58683e1a7c3ea79c08403e1a82aec051db72fe0e3ddd8a89";

            if staged.state.height != 1
                || staged.state.tip_epoch != 10
                || staged.state.tip_hash != EXPECTED_BLOCK1
                || staged.state.current_state_root != EXPECTED_STATE_ROOT
                || staged.state.licenses.len() != BOOTSTRAP_LICENSE_COUNT
                || staged.proof.license_count != BOOTSTRAP_LICENSE_COUNT
                || staged.proof.issued_epoch != 10
                || staged.proof.activation_epoch != 74
                || hex::encode(staged.proof.bitcoin_payment_id) != EXPECTED_PAYMENT_ID
            {
                return Err("Mainnet Block 1 staged authority tuple mismatch".into());
            }
            check_state(&staged.state)?;
            blocksync::verify_full_replay(&staged.state)?;

            save_state(&data_dir, &staged.state)?;
            let committed = load_state_for_runtime(&data_dir, &ingress)?;
            if serde_json::to_vec(&committed).map_err(|e| e.to_string())?
                != serde_json::to_vec(&staged.state).map_err(|e| e.to_string())?
            {
                return Err("Mainnet Block 1 committed state does not match staged state".into());
            }

            print_banner(&committed);
            println!("Canonical Mainnet Block 1 committed");
            println!("Block hash:        {}", committed.tip_hash);
            println!("StateRoot:         {}", committed.current_state_root);
            println!("Issued epoch:      {}", staged.proof.issued_epoch);
            println!("Activation epoch:  {}", staged.proof.activation_epoch);
            println!("Mining licenses:   {}", committed.licenses.len());
            println!(
                "BitcoinPaymentID:  {}",
                hex::encode(staged.proof.bitcoin_payment_id)
            );
            println!("P2P listener started: NO");
            println!("Mining activated: NO");
        }
        "node-key-init" => {
            let passphrase = read_required_passphrase_file(&args)?;
            let key = create_node_identity_for_runtime(&data_dir, &passphrase, runtime_network)?;
            println!("Created encrypted node identity");
            print_node_identity_for_runtime(&data_dir, &key, runtime_network);
        }
        "node-key-info" => {
            let passphrase = read_required_passphrase_file(&args)?;
            let key = load_encrypted_node_key_for_runtime(&data_dir, &passphrase, runtime_network)?;
            print_node_identity_for_runtime(&data_dir, &key, runtime_network);
        }
        "node-key-migrate" => {
            if runtime_network == RuntimeNetwork::Mainnet {
                return Err(
                    "Mainnet legacy node-key migration is unsupported and fail-closed".into(),
                );
            }
            let passphrase = read_required_passphrase_file(&args)?;
            let key = migrate_legacy_node_identity(&data_dir, &passphrase)?;
            println!("Migrated legacy plaintext node identity into encrypted MutinySecretFileV1");
            println!("Legacy file removed. Filesystem deletion is not a guaranteed secure erase.");
            print_node_identity_for_runtime(&data_dir, &key, runtime_network);
        }
        "key-create" => {
            let passphrase = read_required_passphrase_file(&args)?;
            let role = parse_wallet_key_role(required_option(&args, "--role")?)?;
            let label = required_option(&args, "--label")?;
            let path = wallet_key_path(&data_dir, role, label)?;
            let (key, bytes) = mutiny_keystore::generate(role, DEVNET_NETWORK_ID, &passphrase)
                .map_err(|e| e.to_string())?;
            mutiny_keystore::write_new_file(&path, &bytes).map_err(|e| e.to_string())?;
            println!("Created encrypted {} key", role.name());
            println!("Label:      {label}");
            println!(
                "Public key: {}",
                hex::encode(key.verifying_key().to_bytes())
            );
            println!("Path:       {}", path.display());
            println!("Status:     available for Build 6.1 secure wallet signing/recovery; deterministic Devnet paths remain explicit fixtures");
        }
        "key-info" => {
            let passphrase = read_required_passphrase_file(&args)?;
            let role = parse_wallet_key_role(required_option(&args, "--role")?)?;
            let label = required_option(&args, "--label")?;
            let path = wallet_key_path(&data_dir, role, label)?;
            let key = mutiny_keystore::load_file(&path, role, DEVNET_NETWORK_ID, &passphrase)
                .map_err(|e| e.to_string())?;
            println!("Role:       {}", role.name());
            println!("Label:      {label}");
            println!("NetworkID:  0x{DEVNET_NETWORK_ID:08x}");
            println!(
                "Public key: {}",
                hex::encode(key.verifying_key().to_bytes())
            );
            println!("Path:       {}", path.display());
        }
        "wallet-backup-create" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let output = Path::new(required_option(&args, "--output")?);
            let entries = collect_wallet_backup_entries(&data_dir, &passphrase)?;
            if entries.is_empty() {
                return Err(
                    "wallet backup requires at least one encrypted owner/mining key".into(),
                );
            }
            let bytes = mutiny_keystore::encode_wallet_backup(DEVNET_NETWORK_ID, &entries)
                .map_err(|e| e.to_string())?;
            mutiny_keystore::write_new_file(output, &bytes).map_err(|e| e.to_string())?;
            println!("Created MutinyWalletBackupV1");
            println!("NetworkID: 0x{DEVNET_NETWORK_ID:08x}");
            println!("Entries:   {}", entries.len());
            println!("Bytes:     {}", bytes.len());
            println!("Path:      {}", output.display());
            println!("Secrets remain individually encrypted as MutinySecretFileV1; backup contains no passphrase.");
        }
        "wallet-backup-verify" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let input = Path::new(required_option(&args, "--input")?);
            let bytes = fs::read(input)
                .map_err(|e| format!("read wallet backup {}: {e}", input.display()))?;
            let entries = verify_wallet_backup_bytes(&bytes, &passphrase)?;
            println!("Wallet backup verification: PASS");
            println!("NetworkID: 0x{DEVNET_NETWORK_ID:08x}");
            println!("Entries:   {}", entries.len());
            for entry in entries {
                println!(
                    "  {} {:<20} {}",
                    entry.role.name(),
                    entry.label,
                    hex::encode(entry.public_key)
                );
            }
        }
        "wallet-backup-restore" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let input = Path::new(required_option(&args, "--input")?);
            let bytes = fs::read(input)
                .map_err(|e| format!("read wallet backup {}: {e}", input.display()))?;
            let restored = restore_wallet_backup_bytes(&data_dir, &bytes, &passphrase)?;
            println!("Restored MutinyWalletBackupV1");
            println!("NetworkID: 0x{DEVNET_NETWORK_ID:08x}");
            println!("Entries:   {}", restored.len());
            for entry in restored {
                println!(
                    "  {} {:<20} {}",
                    entry.role.name(),
                    entry.label,
                    hex::encode(entry.public_key)
                );
            }
            println!("Restore is no-clobber; existing key labels are never overwritten.");
        }
        "wallet-watch-export" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let output = Path::new(required_option(&args, "--output")?);
            let entries = collect_wallet_backup_entries(&data_dir, &passphrase)?;
            if entries.is_empty() {
                return Err(
                    "watch-only export requires at least one verified owner/mining key".into(),
                );
            }
            let watch = entries
                .into_iter()
                .map(|entry| WatchWalletEntry {
                    role: entry.role,
                    label: entry.label,
                    public_key: entry.public_key,
                })
                .collect::<Vec<_>>();
            let bytes = mutiny_keystore::encode_watch_wallet(DEVNET_NETWORK_ID, &watch)
                .map_err(|e| e.to_string())?;
            mutiny_keystore::write_new_file(output, &bytes).map_err(|e| e.to_string())?;
            println!("Created MutinyWatchWalletV1");
            println!("NetworkID: 0x{DEVNET_NETWORK_ID:08x}");
            println!("Entries:   {}", watch.len());
            println!("Bytes:     {}", bytes.len());
            println!("Path:      {}", output.display());
            println!("Watch-only file contains public keys and labels only; no encrypted secret-file payloads or passphrase.");
        }
        "wallet-watch" => {
            let input = Path::new(required_option(&args, "--input")?);
            let bytes = fs::read(input)
                .map_err(|e| format!("read watch wallet {}: {e}", input.display()))?;
            let (network_id, entries) =
                mutiny_keystore::decode_watch_wallet(&bytes).map_err(|e| e.to_string())?;
            if network_id != DEVNET_NETWORK_ID {
                return Err("watch-wallet NetworkID mismatch".into());
            }
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            println!("MutinyWatchWalletV1 - {} public entries", entries.len());
            for entry in entries {
                let matches = watch_wallet_matches(&state, &entry);
                if matches.is_empty() {
                    println!(
                        "  {} {:<20} {}  no current on-chain authority match",
                        entry.role.name(),
                        entry.label,
                        hex::encode(entry.public_key)
                    );
                } else {
                    println!(
                        "  {} {:<20} {}  {}",
                        entry.role.name(),
                        entry.label,
                        hex::encode(entry.public_key),
                        matches.join(", ")
                    );
                }
            }
        }
        "wallet-offline-send-create" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let from = parse_license_number(
                required_option(&args, "--from-license")?,
                state.licenses.len(),
            )?;
            let to = parse_license_number(
                required_option(&args, "--to-license")?,
                state.licenses.len(),
            )?;
            let amount = parse_mut_amount(required_option(&args, "--amount")?)?;
            let output = Path::new(required_option(&args, "--output")?);
            let request = create_offline_send_request(&state, from, to, amount)?;
            let bytes = request.encode()?;
            mutiny_keystore::write_new_file(output, &bytes).map_err(|e| e.to_string())?;
            println!("Created MutinyOfflineSpendRequestV1");
            print_offline_spend_request(&request)?;
            println!(
                "Request SHA-256: {}",
                hex::encode(offline_request_hash(&bytes))
            );
            println!("Path:             {}", output.display());
            println!("No owner private key or passphrase was loaded.");
        }
        "wallet-offline-inspect" => {
            let input = Path::new(required_option(&args, "--request")?);
            let bytes = fs::read(input)
                .map_err(|e| format!("read offline spend request {}: {e}", input.display()))?;
            let request = OfflineSpendRequestV1::decode(&bytes)?;
            println!("MutinyOfflineSpendRequestV1 inspection");
            print_offline_spend_request(&request)?;
            println!(
                "Request SHA-256: {}",
                hex::encode(offline_request_hash(&bytes))
            );
        }
        "wallet-offline-sign" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let input = Path::new(required_option(&args, "--request")?);
            let output = Path::new(required_option(&args, "--output")?);
            let expected_txid = required_option(&args, "--expect-txid")?;
            let expected_destination = decode32(required_option(&args, "--expect-destination")?)?;
            let expected_amount = parse_mut_amount(required_option(&args, "--expect-amount")?)?;
            let max_fee_strikes: u64 = required_option(&args, "--max-fee-strikes")?
                .parse()
                .map_err(|_| "--max-fee-strikes must be an unsigned integer")?;
            let owner_label = required_option(&args, "--owner-key-label")?;
            let bytes = fs::read(input)
                .map_err(|e| format!("read offline spend request {}: {e}", input.display()))?;
            let request = OfflineSpendRequestV1::decode(&bytes)?;
            validate_offline_request_static(&request)?;
            let txid = request.txid()?;
            if txid.to_hex() != expected_txid {
                return Err(format!(
                    "--expect-txid mismatch: request is {}",
                    txid.to_hex()
                ));
            }
            if request.outputs[0].payload.as_slice() != &expected_destination[..] {
                return Err(format!(
                    "--expect-destination mismatch: request destination is {}",
                    hex::encode(&request.outputs[0].payload)
                ));
            }
            if request.amount_strikes != expected_amount {
                return Err(format!(
                    "--expect-amount mismatch: request amount is {} MUT",
                    format_mut(request.amount_strikes)
                ));
            }
            if request.fee_strikes > max_fee_strikes {
                return Err(format!(
                    "offline request fee {} Strikes exceeds operator maximum {}",
                    request.fee_strikes, max_fee_strikes
                ));
            }
            let owner_key =
                load_wallet_key(&data_dir, KeyRole::LicenseOwner, owner_label, &passphrase)?;
            if owner_key.verifying_key().to_bytes() != request.owner_public_key {
                return Err(format!("encrypted owner key label '{owner_label}' does not match the request owner public key"));
            }
            let signatures = request
                .prevouts
                .iter()
                .enumerate()
                .map(|(i, prevout)| {
                    let digest = sighash_all(&txid, i as u16, &prevout.prevout());
                    owner_key.sign(&digest.0).to_bytes()
                })
                .collect::<Vec<_>>();
            let signed = OfflineSpendSignatureV1 {
                network_id: request.network_id,
                request_hash: offline_request_hash(&bytes),
                owner_public_key: request.owner_public_key,
                signatures,
            };
            let signed_bytes = signed.encode()?;
            mutiny_keystore::write_new_file(output, &signed_bytes).map_err(|e| e.to_string())?;
            println!("Created MutinyOfflineSpendSignatureV1");
            print_offline_spend_request(&request)?;
            println!("Owner key label:  {owner_label}");
            println!("Request SHA-256:  {}", hex::encode(signed.request_hash));
            println!("Signatures:       {}", signed.signatures.len());
            println!("Path:             {}", output.display());
            println!("Only consensus Ed25519 signatures leave the offline signer; no seed or passphrase is exported.");
        }
        "wallet-offline-submit" => {
            let request_path = Path::new(required_option(&args, "--request")?);
            let signed_path = Path::new(required_option(&args, "--signed")?);
            let request_bytes = fs::read(request_path).map_err(|e| {
                format!("read offline spend request {}: {e}", request_path.display())
            })?;
            let signed_bytes = fs::read(signed_path).map_err(|e| {
                format!(
                    "read offline spend signature {}: {e}",
                    signed_path.display()
                )
            })?;
            let request = OfflineSpendRequestV1::decode(&request_bytes)?;
            let signed = OfflineSpendSignatureV1::decode(&signed_bytes)?;
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let pending = submit_offline_spend(&state, &request_bytes, &request, &signed)?;
            validate_pending_candidate(&state, &pending, false)?;
            println!("Accepted air-gapped encrypted-owner transaction authorization");
            println!("TXID:     {}", pending.txid);
            println!("WTXID:    {}", pending.wtxid);
            println!("Amount:   {} MUT", format_mut(pending.amount_strikes));
            println!("Fee:      {} Strikes", pending.fee_strikes);
            println!("Base fee: {} Strikes", pending.base_fee_strikes);
            state.mempool.push(pending);
            save_state(&data_dir, &state)?;
            println!("Status:   MEMPOOL");
            println!("No wallet passphrase or owner secret was loaded by the online submit path.");
        }
        "rpc-token-init" => {
            let output = Path::new(required_option(&args, "--output")?);
            rpc::create_token_file(output)?;
            println!("Created MutinyRpcTokenV1");
            println!("Bytes:   {}", rpc::RPC_TOKEN_FILE_LEN);
            println!("Path:    {}", output.display());
            println!("Protect this control-plane token with operating-system file permissions; it is not a wallet key.");
        }
        "rpc-serve" => {
            let listen = option_value(&args, "--listen").unwrap_or(rpc::DEFAULT_RPC_LISTEN);
            let token_path = Path::new(required_option(&args, "--rpc-token-file")?);
            let max_requests = option_value(&args, "--max-requests")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| "--max-requests must be an integer")
                })
                .transpose()?;
            rpc::serve(&data_dir, listen, token_path, max_requests)?;
        }
        "rpc-call" => {
            let server = required_option(&args, "--server")?;
            let token_path = Path::new(required_option(&args, "--rpc-token-file")?);
            let method = required_option(&args, "--method")?;
            let params_json = option_value(&args, "--params-json").unwrap_or("{}");
            let response = rpc::call(server, token_path, method, params_json)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&response).map_err(|e| e.to_string())?
            );
        }
        "wallet-send" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let from = parse_license_number(
                required_option(&args, "--from-license")?,
                state.licenses.len(),
            )?;
            let to = parse_license_number(
                required_option(&args, "--to-license")?,
                state.licenses.len(),
            )?;
            let amount = parse_mut_amount(required_option(&args, "--amount")?)?;
            let label = required_option(&args, "--owner-key-label")?;
            let owner_key =
                load_owner_key_for_license(&data_dir, &state, from, label, &passphrase)?;
            let pending =
                create_send_transaction_with_signer(&state, from, to, amount, &owner_key)?;
            println!("Created encrypted-custody signed transaction");
            println!("Owner key label: {label}");
            println!("TXID:     {}", pending.txid);
            println!("WTXID:    {}", pending.wtxid);
            println!("Amount:   {} MUT", format_mut(pending.amount_strikes));
            println!("Fee:      {} Strikes", pending.fee_strikes);
            println!("Base fee: {} Strikes", pending.base_fee_strikes);
            state.mempool.push(pending);
            save_state(&data_dir, &state)?;
            println!("Status:   MEMPOOL");
        }
        "wallet-license-buy-mut" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let payer = parse_license_number(
                required_option(&args, "--payer-license")?,
                state.licenses.len(),
            )?;
            let count: usize = required_option(&args, "--count")?
                .parse()
                .map_err(|_| "--count must be an integer")?;
            let owner_label = required_option(&args, "--owner-key-label")?;
            let new_owner_labels = option_values(&args, "--new-owner-key-label");
            let new_mining_labels = option_values(&args, "--new-mining-key-label");
            if new_owner_labels.len() != count || new_mining_labels.len() != count {
                return Err("secure native purchase requires exactly --count repeated --new-owner-key-label and --new-mining-key-label values".into());
            }
            let owner_key =
                load_owner_key_for_license(&data_dir, &state, payer, owner_label, &passphrase)?;
            let mut entries = Vec::with_capacity(count);
            for i in 0..count {
                let owner_public_key = load_wallet_public_key(
                    &data_dir,
                    KeyRole::LicenseOwner,
                    new_owner_labels[i],
                    &passphrase,
                )?;
                let mining_public_key = load_wallet_public_key(
                    &data_dir,
                    KeyRole::LicenseMining,
                    new_mining_labels[i],
                    &passphrase,
                )?;
                entries.push(LicenseManifestEntryV1 {
                    owner_public_key,
                    mining_public_key,
                });
            }
            let (pending, pending_op, ids, price_each) =
                create_native_license_purchase_with_signer(&state, payer, entries, &owner_key)?;
            println!("Created encrypted-custody native Mining License purchase");
            println!("Payer owner key: {owner_label}");
            println!("Payment TXID:   {}", pending.txid);
            println!("Licenses:       {}", ids.len());
            println!("Price/license:  {} MUT", format_mut(price_each));
            println!(
                "Protocol OpID:  {}",
                pending_op.operation()?.operation_id().to_hex()
            );
            for (i, id) in ids.iter().enumerate() {
                println!(
                    "  pending {:02}: {} owner={} mining={}",
                    state.licenses.len() + i + 1,
                    hex::encode(id.0),
                    new_owner_labels[i],
                    new_mining_labels[i]
                );
            }
            state.mempool.push(pending);
            state.pending_protocol_operations.push(pending_op);
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "license-adopt-keystore-dev" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            if dev_owner_signing_key_for_license(&state.licenses[license_index]).is_none() {
                return Err("license-adopt-keystore-dev only bridges a deterministic Devnet fixture owner into encrypted custody".into());
            }
            let owner_label = required_option(&args, "--new-owner-key-label")?;
            let mining_label = required_option(&args, "--new-mining-key-label")?;
            let new_owner =
                load_wallet_public_key(&data_dir, KeyRole::LicenseOwner, owner_label, &passphrase)?;
            let new_mining = load_wallet_public_key(
                &data_dir,
                KeyRole::LicenseMining,
                mining_label,
                &passphrase,
            )?;
            let permanent_id = state.licenses[license_index].license_id.clone();
            let (fee_tx, pending_op, op) =
                create_license_transfer_operation(&state, license_index, new_owner, new_mining)?;
            println!("Created explicit Devnet fixture -> encrypted custody transfer");
            println!("LicenseID:       {permanent_id}");
            println!("New owner key:   {owner_label}");
            println!("New mining key:  {mining_label}");
            println!("Fee TXID:        {}", fee_tx.txid);
            println!("Protocol OpID:   {}", op.operation_id().to_hex());
            state.mempool.push(fee_tx);
            state.pending_protocol_operations.push(pending_op);
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "wallet-license-transfer" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let owner_label = required_option(&args, "--owner-key-label")?;
            let new_owner_label = required_option(&args, "--new-owner-key-label")?;
            let new_mining_label = required_option(&args, "--new-mining-key-label")?;
            let owner_key = load_owner_key_for_license(
                &data_dir,
                &state,
                license_index,
                owner_label,
                &passphrase,
            )?;
            let new_owner = load_wallet_public_key(
                &data_dir,
                KeyRole::LicenseOwner,
                new_owner_label,
                &passphrase,
            )?;
            let new_mining = load_wallet_public_key(
                &data_dir,
                KeyRole::LicenseMining,
                new_mining_label,
                &passphrase,
            )?;
            let permanent_id = state.licenses[license_index].license_id.clone();
            let (fee_tx, pending_op, op) = create_license_transfer_operation_with_signer(
                &state,
                license_index,
                new_owner,
                new_mining,
                &owner_key,
            )?;
            println!("Created encrypted-custody Mining License owner transfer");
            println!("LicenseID:       {permanent_id}");
            println!("Current owner:   {owner_label}");
            println!("New owner:       {new_owner_label}");
            println!("New mining:      {new_mining_label}");
            println!("Fee TXID:        {}", fee_tx.txid);
            println!("Protocol OpID:   {}", op.operation_id().to_hex());
            state.mempool.push(fee_tx);
            state.pending_protocol_operations.push(pending_op);
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "wallet-license-rotate-mining" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let owner_label = required_option(&args, "--owner-key-label")?;
            let new_mining_label = required_option(&args, "--new-mining-key-label")?;
            let owner_key = load_owner_key_for_license(
                &data_dir,
                &state,
                license_index,
                owner_label,
                &passphrase,
            )?;
            let new_mining = load_wallet_public_key(
                &data_dir,
                KeyRole::LicenseMining,
                new_mining_label,
                &passphrase,
            )?;
            let permanent_id = state.licenses[license_index].license_id.clone();
            let (fee_tx, pending_op, op) = create_mining_key_rotation_operation_with_signer(
                &state,
                license_index,
                new_mining,
                &owner_key,
            )?;
            println!("Created encrypted-custody Mining License mining-key rotation");
            println!("LicenseID:       {permanent_id}");
            println!("Owner key:       {owner_label}");
            println!("New mining key:  {new_mining_label}");
            println!("Fee TXID:        {}", fee_tx.txid);
            println!("Protocol OpID:   {}", op.operation_id().to_hex());
            state.mempool.push(fee_tx);
            state.pending_protocol_operations.push(pending_op);
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "wallet-dividend-claim" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let amount = parse_mut_amount(required_option(&args, "--amount")?)?;
            let owner_label = required_option(&args, "--owner-key-label")?;
            let owner_key = load_owner_key_for_license(
                &data_dir,
                &state,
                license_index,
                owner_label,
                &passphrase,
            )?;
            let (payment, pending_op, claim) = dividends::create_claim_bundle_with_signer(
                &state,
                license_index,
                amount,
                &owner_key,
            )?;
            let op = pending_op.operation()?;
            println!("Created encrypted-custody Treasury dividend claim");
            println!("Owner key:     {owner_label}");
            println!("LicenseID:     {}", hex::encode(claim.license_id.0));
            println!("Amount:        {} MUT", format_mut(claim.amount_strikes));
            println!("Payment TXID:  {}", payment.txid);
            println!("Protocol OpID: {}", op.operation_id().to_hex());
            state.mempool.push(payment);
            state.pending_protocol_operations.push(pending_op);
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "mining-signer-init" | "mining-signer-check" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let chosen = required_option(&args, "--mining-license-id")?;
            let li = state
                .licenses
                .iter()
                .position(|l| l.license_id == chosen)
                .ok_or("chosen LicenseID absent from canonical state")?;
            let signer = mining_signer::load(&state, li, &args, cmd == "mining-signer-init")?;
            println!("Role: mining; NetworkID: 0x{:08x}", state.network_id);
            println!("LicenseID: {}", state.licenses[li].license_id);
            println!("Derived public key: {}", hex::encode(signer.public_key()));
            println!("Signer: MiningSigner::sign_candidate; record format: MUTMSA01");
        }
        "wallet-mine-one" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let mining_label = required_option(&args, "--mining-key-label")?;
            let mining_key: Box<dyn MiningAuthority> = if runtime_network == RuntimeNetwork::Mainnet
            {
                Box::new(mining_signer::load(&state, license_index, &args, false)?)
            } else {
                Box::new(load_mining_key_for_license(
                    &data_dir,
                    &state,
                    license_index,
                    mining_label,
                    &passphrase,
                )?)
            };
            let requested = option_value(&args, "--epoch").and_then(|v| v.parse().ok());
            let epoch = requested.unwrap_or_else(|| next_mineable_epoch(&state));
            let before_height = state.height;
            if runtime_network == RuntimeNetwork::Mainnet {
                if let Some(accepted) =
                    stage_mainnet_mining_attempt(&state, epoch, license_index, mining_key.as_ref())?
                {
                    save_state(&data_dir, &accepted)?;
                    state = accepted;
                }
            } else {
                mine_epoch_with_signer(
                    &mut state,
                    epoch,
                    Some((license_index, mining_key.as_ref())),
                )?;
                save_state(&data_dir, &state)?;
            }
            println!("Custody mining key: {mining_label}");
            if state.height > before_height {
                println!("Encrypted-custody block signing: CONFIRMED");
            } else {
                println!("Encrypted-custody block signing: no winning ticket in this epoch");
            }
            print_status(&state);
        }
        "wallet-mining-presence" => {
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let mining_label = required_option(&args, "--mining-key-label")?;
            let mining_key = load_mining_key_for_license(
                &data_dir,
                &state,
                license_index,
                mining_label,
                &passphrase,
            )?;
            let epoch: u64 = required_option(&args, "--epoch")?
                .parse()
                .map_err(|_| "--epoch must be a u64")?;
            let op = presence::create_operation(&state, license_index, epoch, &mining_key)?;
            let encoded = hex::encode(op.encode());
            if state
                .pending_protocol_operations
                .iter()
                .any(|pending| pending.operation == encoded)
            {
                return Err("identical MINING_PRESENCE operation is already queued".into());
            }
            println!("Created encrypted-custody Pack-K MINING_PRESENCE");
            println!(
                "LicenseID:      {}",
                state.licenses[license_index].license_id
            );
            println!("Mining key:     {mining_label}");
            println!("Presence epoch: {epoch}");
            println!(
                "Mining seq:     {}",
                state.licenses[license_index].mining_key_sequence
            );
            println!("Protocol OpID:  {}", op.operation_id().to_hex());
            println!("Fee TX:         none");
            state
                .pending_protocol_operations
                .push(PendingProtocolOperationState {
                    operation: encoded,
                    required_txid: String::new(),
                });
            save_state(&data_dir, &state)?;
            println!("Status: queued only for exact epoch {epoch}");
        }
        "mining-presence" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            presence::print_presence(&state)?;
        }
        "storage-info" => {
            if let Some(meta) = storage::inspect_meta(&data_dir)? {
                print_storage_meta(&meta);
            } else if state_path(&data_dir).exists() || storage::exists(&data_dir) {
                println!("Storage format: legacy Build 5.9 migration pending");
            } else {
                return Err("no Mutiny storage found; run `mutinyd init` first".into());
            }
        }
        "storage-migrate" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let meta = storage::inspect_meta(&data_dir)?
                .ok_or("storage migration did not produce metadata")?;
            validate_storage_meta(&state, &meta)?;
            print_storage_meta(&meta);
            println!("Storage migration/upgrade: PASS");
        }
        "storage-verify" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            check_state(&state)?;
            verify_replay_for_ingress(&state, &ingress)?;
            let meta =
                storage::inspect_meta(&data_dir)?.ok_or("MutinyStorageV1 metadata is missing")?;
            validate_storage_meta(&state, &meta)?;
            print_storage_meta(&meta);
            println!("Storage integrity: PASS");
            println!("Canonical replay: PASS");
        }
        "status" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            print_banner(&state);
            print_status(&state);
        }
        "mine-one" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let requested = option_value(&args, "--epoch").and_then(|v| v.parse().ok());
            let epoch = requested.unwrap_or_else(|| next_mineable_epoch(&state));
            mine_epoch(&mut state, epoch)?;
            save_state(&data_dir, &state)?;
            for peer in option_values(&args, "--peer") {
                if let Err(e) = blocksync::announce_tip_to_peer(&data_dir, peer, &state) {
                    eprintln!("peer {peer} block announcement failed: {e}");
                }
            }
            print_status(&state);
        }
        "advance-empty" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let target: u64 = required_option(&args, "--to-epoch")?
                .parse()
                .map_err(|_| "--to-epoch must be a u64")?;
            advance_empty_epochs_fast(&mut state, target)?;
            save_state(&data_dir, &state)?;
            println!("Advanced canonical empty-epoch observations through epoch {target}.");
            print_status(&state);
        }
        "run" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            if let Some(v) = option_value(&args, "--epoch-ms").and_then(|v| v.parse::<u64>().ok()) {
                state.epoch_ms = v.max(1);
            }
            let peers = option_values(&args, "--peer");
            let max_epochs =
                option_value(&args, "--max-epochs").and_then(|v| v.parse::<u64>().ok());
            let mut attempted = 0u64;
            print_banner(&state);
            loop {
                let epoch = next_mineable_epoch(&state);
                mine_epoch(&mut state, epoch)?;
                save_state(&data_dir, &state)?;
                for peer in &peers {
                    if state.blocks.last().is_some_and(|b| b.epoch == epoch) {
                        if let Err(e) = blocksync::announce_tip_to_peer(&data_dir, peer, &state) {
                            eprintln!("peer {peer} block announcement failed: {e}");
                        }
                    }
                }
                attempted += 1;
                if max_epochs.is_some_and(|m| attempted >= m) {
                    break;
                }
                thread::sleep(Duration::from_millis(state.epoch_ms));
            }
            print_status(&state);
        }
        "balances" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            print_balances(&state)?;
        }
        "utxos" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let license = option_value(&args, "--license")
                .map(|v| parse_license_number(v, state.licenses.len()))
                .transpose()?;
            print_utxos(&state, license)?;
        }
        "send" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let from = parse_license_number(
                required_option(&args, "--from-license")?,
                state.licenses.len(),
            )?;
            let to = parse_license_number(
                required_option(&args, "--to-license")?,
                state.licenses.len(),
            )?;
            let amount = parse_mut_amount(required_option(&args, "--amount")?)?;
            let pending = create_send_transaction(&state, from, to, amount)?;
            println!("Created signed transaction");
            println!("TXID:     {}", pending.txid);
            println!("WTXID:    {}", pending.wtxid);
            println!("Amount:   {} MUT", format_mut(pending.amount_strikes));
            println!("Fee:      {} Strikes", pending.fee_strikes);
            println!("Base fee: {} Strikes", pending.base_fee_strikes);
            println!("Inputs:   {}", pending.inputs.len());
            state.mempool.push(pending.clone());
            save_state(&data_dir, &state)?;
            println!("Status:   MEMPOOL");
            for peer in option_values(&args, "--peer") {
                match push_tx_to_peer(&data_dir, peer, &pending) {
                    Ok(msg) => println!("Relayed to {peer}: {msg}"),
                    Err(e) => eprintln!("relay to {peer} failed: {e}"),
                }
            }
        }
        "license-buy-mut" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let payer = parse_license_number(
                required_option(&args, "--payer-license")?,
                state.licenses.len(),
            )?;
            let count: usize = required_option(&args, "--count")?
                .parse()
                .map_err(|_| "--count must be an integer")?;
            let (pending, pending_op, ids, price_each) =
                create_native_license_purchase(&state, payer, count)?;
            println!("Created native Mining License purchase");
            println!("Payment TXID:   {}", pending.txid);
            println!("Licenses:       {}", ids.len());
            println!("Price/license:  {} MUT", format_mut(price_each));
            println!(
                "Total payment:  {} MUT",
                format_mut(
                    price_each
                        .checked_mul(ids.len() as u64)
                        .ok_or("license purchase amount overflow")?
                )
            );
            println!(
                "Protocol OpID:  {}",
                pending_op.operation()?.operation_id().to_hex()
            );
            for (i, id) in ids.iter().enumerate() {
                println!(
                    "  pending {:02}: {}",
                    state.licenses.len() + i + 1,
                    hex::encode(id.0)
                );
            }
            state.mempool.push(pending);
            state.pending_protocol_operations.push(pending_op);
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "license-buy-btc-dev" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let count: usize = required_option(&args, "--count")?
                .parse()
                .map_err(|_| "--count must be an integer")?;
            let variant: u32 = option_value(&args, "--variant")
                .unwrap_or("0")
                .parse()
                .map_err(|_| "--variant must be a nonnegative u32")?;
            let fixture = bitcoin::create_dev_purchase(&state, count, variant)?;
            println!("Created deterministic Devnet Bitcoin SPV Mining License purchase");
            println!(
                "Bitcoin TXID:      {}",
                mutiny_bitcoin::display_hex_from_internal(fixture.txid_internal)
            );
            println!("BitcoinPaymentID:  {}", hex::encode(fixture.payment_id));
            println!("Licenses:          {}", fixture.ids.len());
            println!(
                "Price/license:     {} sats (PaymentEpoch {})",
                fixture.price_each, fixture.payment_epoch
            );
            println!("Total payment:     {} sats", fixture.paid_sats);
            println!("Containing height: {}", fixture.containing_height);
            println!("Sixth confirmation:{}", fixture.sixth_height);
            println!("Sixth timestamp:   {}", fixture.sixth_timestamp);
            println!(
                "Header OpID:       {}",
                fixture.header_operation.operation_id().to_hex()
            );
            println!(
                "Protocol OpID:     {}",
                fixture.operation.operation_id().to_hex()
            );
            println!("Mutiny fee TX:     none (Bitcoin SPV-funded Protocol Op)");
            for (i, id) in fixture.ids.iter().enumerate() {
                println!(
                    "  pending {:02}: {}",
                    state.licenses.len() + i + 1,
                    hex::encode(id.0)
                );
            }
            state
                .pending_protocol_operations
                .push(fixture.header_pending);
            state.pending_protocol_operations.push(fixture.pending);
            save_state(&data_dir, &state)?;
            println!("Status: header authentication queued first; purchase follows after six authenticated best-chain confirmations");
        }
        "bitcoin-payments" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            bitcoin::print_payments(&state);
        }
        "bootstrap-dev" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let fixture = bootstrap::apply_devnet_bootstrap_block(&mut state)?;
            save_state(&data_dir, &state)?;
            let written = bootstrap::write_fixture(&data_dir, &state)?;
            if written.genesis_id != fixture.genesis_id
                || written.bootstrap_operation_id != fixture.bootstrap_operation_id
            {
                return Err(
                    "Build 5.4 bootstrap artifact changed after Block-1 application".into(),
                );
            }
            bootstrap::print_fixture(&fixture);
            println!("Block-1 hash:            {}", state.tip_hash);
            println!("Block-1 StateRoot:       {}", state.current_state_root);
            println!(
                "Artifact:                {}",
                data_dir.join("build54-bootstrap-devnet-v1.json").display()
            );
            println!("Pack-J literal-vector reconciliation: REQUIRED BEFORE BUILD 5.4 LOCK");
            print_status(&state);
        }
        "license-transfer" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let new_owner =
                dev_key_slot_public_key(required_option(&args, "--new-owner-key-slot")?)?;
            let new_mining =
                dev_key_slot_public_key(required_option(&args, "--new-mining-key-slot")?)?;
            let permanent_id = state.licenses[license_index].license_id.clone();
            let before_owner_seq = state.licenses[license_index].owner_key_sequence;
            let before_mining_seq = state.licenses[license_index].mining_key_sequence;
            let (fee_tx, pending_op, op) =
                create_license_transfer_operation(&state, license_index, new_owner, new_mining)?;
            println!("Created Mining License owner transfer");
            println!("LicenseID:       {permanent_id}");
            println!(
                "Owner sequence:  {before_owner_seq} -> {}",
                before_owner_seq
                    .checked_add(1)
                    .ok_or("owner sequence overflow")?
            );
            println!(
                "Mining sequence: {before_mining_seq} -> {}",
                before_mining_seq
                    .checked_add(1)
                    .ok_or("mining sequence overflow")?
            );
            println!("Fee TXID:        {}", fee_tx.txid);
            println!("Protocol OpID:   {}", op.operation_id().to_hex());
            state.mempool.push(fee_tx);
            state.pending_protocol_operations.push(pending_op);
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "license-rotate-mining" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let new_mining =
                dev_key_slot_public_key(required_option(&args, "--new-mining-key-slot")?)?;
            let permanent_id = state.licenses[license_index].license_id.clone();
            let owner_seq = state.licenses[license_index].owner_key_sequence;
            let before_mining_seq = state.licenses[license_index].mining_key_sequence;
            let (fee_tx, pending_op, op) =
                create_mining_key_rotation_operation(&state, license_index, new_mining)?;
            println!("Created Mining License mining-key rotation");
            println!("LicenseID:       {permanent_id}");
            println!("Owner sequence:  {owner_seq} (unchanged)");
            println!(
                "Mining sequence: {before_mining_seq} -> {}",
                before_mining_seq
                    .checked_add(1)
                    .ok_or("mining sequence overflow")?
            );
            println!("Fee TXID:        {}", fee_tx.txid);
            println!("Protocol OpID:   {}", op.operation_id().to_hex());
            state.mempool.push(fee_tx);
            state.pending_protocol_operations.push(pending_op);
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "punish-dev" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let tier: u8 = required_option(&args, "--tier")?
                .parse()
                .map_err(|_| "--tier must be 1, 2, or 3")?;
            let variant: u32 = option_value(&args, "--variant")
                .unwrap_or("0")
                .parse()
                .map_err(|_| "--variant must be a nonnegative u32")?;
            let license_id = state.licenses[license_index].license_id.clone();
            let queued = punishment::queued_weight_for_license(&state, &license_id)?;
            let active = state.licenses[license_index].strike_weight;
            if active
                .checked_add(queued)
                .ok_or("punishment weight overflow")?
                >= 16
            {
                return Err("active strikes plus already-queued punishment evidence already reach the revocation threshold".into());
            }
            let op = punishment::create_dev_operation(&state, license_index, tier, variant)?;
            let (evidence_id, offense_type, weight, accused) = punishment::operation_summary(&op)?;
            if state.consumed_evidence.iter().any(|id| id == &evidence_id) {
                return Err("deterministic Devnet EvidenceID has already been consumed; choose another --variant".into());
            }
            if state
                .pending_protocol_operations
                .iter()
                .any(|pending| pending.operation.as_str() == hex::encode(op.encode()))
            {
                return Err(
                    "deterministic Devnet evidence is already queued; choose another --variant"
                        .into(),
                );
            }
            println!("Created deterministic Devnet punishment evidence");
            println!("LicenseID:    {accused}");
            println!("Offense type: 0x{offense_type:04x}");
            println!("Weight:       +{weight}");
            println!("EvidenceID:   {evidence_id}");
            println!("Protocol OpID: {}", op.operation_id().to_hex());
            println!("Fee TX:       none (permissionless Protocol Op)");
            state
                .pending_protocol_operations
                .push(PendingProtocolOperationState {
                    operation: hex::encode(op.encode()),
                    required_txid: String::new(),
                });
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "offenses" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            punishment::print_offenses(&state, license_index)?;
        }
        "dividends" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let license = option_value(&args, "--license")
                .map(|v| parse_license_number(v, state.licenses.len()))
                .transpose()?;
            dividends::print_dividends(&state, license)?;
        }
        "dividend-claim" => {
            let mut state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let amount = parse_mut_amount(required_option(&args, "--amount")?)?;
            let (payment, pending_op, claim) =
                dividends::create_claim_bundle(&state, license_index, amount)?;
            let op = pending_op.operation()?;
            println!("Created Treasury dividend claim");
            println!("LicenseID:     {}", hex::encode(claim.license_id.0));
            println!("Amount:        {} MUT", format_mut(claim.amount_strikes));
            println!("Payment TXID:  {}", payment.txid);
            println!("Protocol OpID: {}", op.operation_id().to_hex());
            println!("Fee:           0 Strikes (protocol-authorized Treasury payment)");
            state.mempool.push(payment);
            state.pending_protocol_operations.push(pending_op);
            save_state(&data_dir, &state)?;
            println!("Status: queued for the next locally mined block");
        }
        "licenses" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            print_licenses(&state)?;
        }
        "license-history" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            print_license_history(&state, license_index)?;
        }
        "mempool" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            print_mempool(&state);
        }
        "branches" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            print_branches(&state);
        }
        "peers" => {
            print_cached_peers(&data_dir)?;
        }
        "tx" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let query = args.get(1).ok_or("usage: mutinyd tx <TXID>")?;
            print_tx(&state, query)?;
        }
        "check" => {
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            check_state(&state)?;
            verify_replay_for_ingress(&state, &ingress)?;
            println!("State validation: PASS");
            println!("Full block replay: PASS");
            println!("Canonical height: {}", state.height);
            println!("Canonical tip epoch: {}", canonical_tip_epoch(&state));
            println!("Current local epoch: {}", state.tip_epoch);
            println!(
                "Canonical tip StateRoot: {}",
                canonical_tip_state_root(&state)
            );
            println!("Current StateRoot: {}", state.current_state_root);
            println!("Canonical tip: {}", state.tip_hash);
            println!("ChainWork: {}", chainwork_hex(&state)?);
        }
        "worker-reference-key-init" => {
            let path = Path::new(required_option(&args, "--worker-key-file")?);
            let key = worker_runtime::create_reference_worker_key(path)?;
            println!("Created reference Pack-L worker key");
            worker_runtime::print_reference_worker_key(path, &key);
        }
        "worker-reference-key-info" => {
            let path = Path::new(required_option(&args, "--worker-key-file")?);
            let key = worker_runtime::load_reference_worker_key(path)?;
            worker_runtime::print_reference_worker_key(path, &key);
        }
        "worker-reference-ignore-cancel-one" => {
            let connect = required_option(&args, "--connect")?;
            let worker_key_file = Path::new(required_option(&args, "--worker-key-file")?);
            let node_public_key = required_option(&args, "--node-public-key")?;
            let node_id = required_option(&args, "--node-id")?;
            worker_runtime::run_reference_worker_ignore_cancel_one_from_strings(
                connect,
                worker_key_file,
                node_public_key,
                node_id,
            )?;
        }
        "worker-reference-one" => {
            let connect = required_option(&args, "--connect")?;
            let worker_key_file = Path::new(required_option(&args, "--worker-key-file")?);
            let node_public_key = required_option(&args, "--node-public-key")?;
            let node_id = required_option(&args, "--node-id")?;
            worker_runtime::run_reference_worker_one_from_strings(
                connect,
                worker_key_file,
                node_public_key,
                node_id,
            )?;
        }
        "worker-reassign-one-serve" => {
            let listen =
                option_value(&args, "--listen").unwrap_or(worker_service::DEFAULT_WORKER_LISTEN);
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let mining_label = required_option(&args, "--mining-key-label")?;
            let mining_key = load_mining_key_for_license(
                &data_dir,
                &state,
                license_index,
                mining_label,
                &passphrase,
            )?;
            let ticket_index = required_option(&args, "--ticket-index")?
                .parse::<u16>()
                .map_err(|_| "--ticket-index must be an unsigned 16-bit integer".to_string())?;
            let target_epoch = option_value(&args, "--epoch")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| "--epoch must be an unsigned integer".to_string())
                })
                .transpose()?
                .unwrap_or_else(|| next_mineable_epoch(&state));
            let node_key = load_runtime_node_key(&data_dir)?;
            worker_runtime::serve_one_reassigned_ticket(
                &data_dir,
                listen,
                target_epoch,
                license_index,
                ticket_index,
                &node_key,
                &mining_key,
            )?;
        }
        "worker-cancel-one-serve" => {
            let listen =
                option_value(&args, "--listen").unwrap_or(worker_service::DEFAULT_WORKER_LISTEN);
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let mining_label = required_option(&args, "--mining-key-label")?;
            let mining_key = load_mining_key_for_license(
                &data_dir,
                &state,
                license_index,
                mining_label,
                &passphrase,
            )?;
            let cancel_reason = required_option(&args, "--cancel-reason")?
                .parse::<u8>()
                .map_err(|_| "--cancel-reason must be 1..7".to_string())?;
            if !(1..=7).contains(&cancel_reason) {
                return Err("--cancel-reason must be 1..7".into());
            }
            let target_epoch = option_value(&args, "--epoch")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| "--epoch must be an unsigned integer".to_string())
                })
                .transpose()?
                .unwrap_or_else(|| next_mineable_epoch(&state));
            let node_key = load_runtime_node_key(&data_dir)?;
            worker_runtime::serve_one_cancelled_ticket(
                &data_dir,
                listen,
                target_epoch,
                license_index,
                cancel_reason,
                &node_key,
                &mining_key,
            )?;
        }
        "worker-watch-one-serve" => {
            let listen =
                option_value(&args, "--listen").unwrap_or(worker_service::DEFAULT_WORKER_LISTEN);
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let mining_label = required_option(&args, "--mining-key-label")?;
            let mining_key = load_mining_key_for_license(
                &data_dir,
                &state,
                license_index,
                mining_label,
                &passphrase,
            )?;
            let target_epoch = option_value(&args, "--epoch")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| "--epoch must be an unsigned integer".to_string())
                })
                .transpose()?
                .unwrap_or_else(|| next_mineable_epoch(&state));
            let node_key = load_runtime_node_key(&data_dir)?;
            println!("Build 6.4 Candidate 4G autonomous Pack-L lifecycle watcher");
            worker_runtime::serve_one_lifecycle_watched_ticket(
                &data_dir,
                listen,
                target_epoch,
                license_index,
                &node_key,
                &mining_key,
                mining_label,
                &passphrase,
            )?;
        }
        "worker-mine-one-serve" => {
            let listen =
                option_value(&args, "--listen").unwrap_or(worker_service::DEFAULT_WORKER_LISTEN);
            let passphrase = read_required_wallet_passphrase_file(&args)?;
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let license_index =
                parse_license_number(required_option(&args, "--license")?, state.licenses.len())?;
            let mining_label = required_option(&args, "--mining-key-label")?;
            let mining_key = load_mining_key_for_license(
                &data_dir,
                &state,
                license_index,
                mining_label,
                &passphrase,
            )?;
            let target_epoch = option_value(&args, "--epoch")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| "--epoch must be an unsigned integer".to_string())
                })
                .transpose()?
                .unwrap_or_else(|| next_mineable_epoch(&state));
            let node_key = load_runtime_node_key(&data_dir)?;
            println!("Build 6.4 Candidate 4E bounded Pack-L mining runtime");
            println!("Encrypted-custody mining license: {}", license_index + 1);
            println!("Encrypted-custody mining key label: {mining_label}");
            let outcome = worker_runtime::serve_one_mining_ticket(
                &data_dir,
                listen,
                target_epoch,
                license_index,
                &node_key,
                &mining_key,
            )?;

            let mut authenticated_pack_h_announcements = 0usize;
            if outcome.block_accepted {
                let announced_state = load_state_for_runtime(&data_dir, &ingress)?;
                for peer in option_values(&args, "--peer") {
                    announce_tip_to_peer_authenticated_sync_bridge(peer, &announced_state, &node_key)
                        .map_err(|e| {
                            format!(
                                "worker-finalized block authenticated Pack-H sync bridge to {peer} failed: {e}"
                            )
                        })?;
                    authenticated_pack_h_announcements += 1;
                    println!(
                        "Pack-L worker-finalized block announced through authenticated Pack-H sync bridge peer: {peer}"
                    );
                }
            }
            println!(
                "Pack-L worker-finalized authenticated Pack-H sync-bridge announcements: {authenticated_pack_h_announcements}"
            );
        }
        "worker-serve" => {
            let listen =
                option_value(&args, "--listen").unwrap_or(worker_service::DEFAULT_WORKER_LISTEN);
            let max_connections = option_value(&args, "--max-connections")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| "--max-connections must be an unsigned integer".to_string())
                })
                .transpose()?;
            if max_connections == Some(0) {
                return Err("--max-connections must be greater than zero".into());
            }

            let key = load_runtime_node_key(&data_dir)?;
            let node_id = mutiny_p2p::node_id(&key.verifying_key().to_bytes());
            println!("Build 6.4 Candidate 4A Pack-L worker runtime");
            println!("Worker-service encrypted NodeID: {}", node_id.to_hex());
            println!(
                "Worker-service node identity: {}",
                node_keystore_path(&data_dir).display()
            );

            worker_service::serve_authenticated_workers(
                &data_dir,
                DEVNET_NETWORK_ID,
                mutiny_worker::WORKER_MAGIC_DEVNET,
                listen,
                &key,
                max_connections,
            )
            .map_err(|e| e.to_string())?;
        }
        "node" => run_network_node(&data_dir, &args)?,
        "duplex-selftest" => run_duplex_selftest(&data_dir)?,
        "sync" => {
            let peer = required_option(&args, "--peer")?;
            let report = sync_from_peer(&data_dir, peer)?;
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            print_sync_report(peer, &report);
            print_status(&state);
        }
        "peer-status" => {
            return Err("Build 4 removed snapshot peer-status. Use `sync --peer ...` on a disposable/fresh node or inspect local `status`.".into());
        }
        "relay-tx" => {
            let query = args
                .get(1)
                .ok_or("usage: mutinyd relay-tx <TXID> --peer HOST:PORT")?;
            let peer = required_option(&args, "--peer")?;
            let state = load_state_for_runtime(&data_dir, &ingress)?;
            let pending = state
                .mempool
                .iter()
                .find(|t| t.txid == *query)
                .ok_or("transaction is not in local mempool")?;
            if pending.has_license_payment_output()
                || transaction_is_protocol_bound(&state, &pending.txid)
            {
                return Err("protocol-bound operations propagate at block level; mine the queued transaction + operation locally".into());
            }
            println!(
                "Peer result: {}",
                push_tx_to_peer(&data_dir, peer, pending)?
            );
        }
        _ => print_help(),
    }
    Ok(())
}

fn print_help() {
    println!("  Mainnet mining requires --mining-custody-dir PATH --anti-equivocation-dir PATH --mining-license-id HEX --mining-key-label NAME --wallet-passphrase-file PATH");
    println!("  mutinyd mining-signer-init|mining-signer-check --network mainnet --data-dir PATH [Mainnet mining options]");
    println!("{BUILD_NAME} - {BUILD_DESCRIPTION}");
    println!("{MOTTO}\n");
    println!("Commands:");
    println!("  Runtime: --network devnet|mainnet; bootstrap-mainnet explicitly commits authenticated Mainnet Block 1");
    println!("  mutinyd init [--data-dir PATH] [--epoch-ms N] [--force]");
    println!("  mutinyd bootstrap-mainnet --network mainnet --data-dir PATH --bootstrap-witness PATH");
    println!("  mutinyd node-key-init --passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd node-key-info --passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd node-key-migrate --passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd key-create --role owner|mining --label NAME --passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd key-info --role owner|mining --label NAME --passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd wallet-backup-create --output FILE --wallet-passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd wallet-backup-verify --input FILE --wallet-passphrase-file PATH");
    println!("  mutinyd wallet-backup-restore --input FILE --wallet-passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd wallet-watch-export --output FILE --wallet-passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd wallet-watch --input FILE [--data-dir PATH]");
    println!("  mutinyd wallet-offline-send-create --from-license N --to-license N --amount MUT --output FILE [--data-dir PATH]");
    println!("  mutinyd wallet-offline-inspect --request FILE");
    println!("  mutinyd wallet-offline-sign --request FILE --output FILE --owner-key-label NAME --wallet-passphrase-file PATH --expect-txid TXID --expect-destination ADDRESSID --expect-amount MUT --max-fee-strikes N [--data-dir PATH]");
    println!("  mutinyd wallet-offline-submit --request FILE --signed FILE [--data-dir PATH]");
    println!("  mutinyd rpc-token-init --output FILE");
    println!("  mutinyd rpc-serve [--listen 127.0.0.1:24589] --rpc-token-file FILE [--max-requests N] [--data-dir PATH]");
    println!("  mutinyd rpc-call --server 127.0.0.1:24589 --rpc-token-file FILE --method METHOD [--params-json JSON]");
    println!("  mutinyd wallet-send --from-license N --to-license N --amount MUT --owner-key-label NAME --wallet-passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd wallet-license-buy-mut --payer-license N --count N --owner-key-label NAME --new-owner-key-label NAME... --new-mining-key-label NAME... --wallet-passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd license-adopt-keystore-dev --license N --new-owner-key-label NAME --new-mining-key-label NAME --wallet-passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd wallet-license-transfer --license N --owner-key-label NAME --new-owner-key-label NAME --new-mining-key-label NAME --wallet-passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd wallet-license-rotate-mining --license N --owner-key-label NAME --new-mining-key-label NAME --wallet-passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd wallet-dividend-claim --license N --amount MUT --owner-key-label NAME --wallet-passphrase-file PATH [--data-dir PATH]");
    println!("  mutinyd wallet-mine-one --license N --mining-key-label NAME --wallet-passphrase-file PATH [--epoch E] [--data-dir PATH]");
    println!("  mutinyd wallet-mining-presence --license N --mining-key-label NAME --wallet-passphrase-file PATH --epoch E [--data-dir PATH]");
    println!("  mutinyd mining-presence [--data-dir PATH]");
    println!("  mutinyd storage-info [--data-dir PATH]");
    println!("  mutinyd storage-migrate [--data-dir PATH]");
    println!("  mutinyd storage-verify [--data-dir PATH]");
    println!("  mutinyd status [--data-dir PATH]");
    println!("  mutinyd mine-one [--data-dir PATH] [--epoch E]");
    println!("  mutinyd advance-empty --to-epoch E [--data-dir PATH]");
    println!("  mutinyd run [--data-dir PATH] [--epoch-ms N] [--max-epochs N]");
    println!("  mutinyd balances [--data-dir PATH]");
    println!("  mutinyd utxos [--data-dir PATH] [--license N]");
    println!("  mutinyd send --from-license N --to-license N --amount MUT [--data-dir PATH]");
    println!("  mutinyd license-buy-mut --payer-license N --count N [--data-dir PATH]");
    println!("  mutinyd license-buy-btc-dev --count N [--variant N] [--data-dir PATH]");
    println!("  mutinyd bitcoin-payments [--data-dir PATH]");
    println!("  mutinyd bootstrap-dev [--data-dir PATH]");
    println!("  mutinyd license-transfer --license N --new-owner-key-slot N --new-mining-key-slot N [--data-dir PATH]");
    println!(
        "  mutinyd license-rotate-mining --license N --new-mining-key-slot N [--data-dir PATH]"
    );
    println!("  mutinyd punish-dev --license N --tier 1|2|3 [--variant N] [--data-dir PATH]");
    println!("  mutinyd offenses --license N [--data-dir PATH]");
    println!("  mutinyd dividends [--license N] [--data-dir PATH]");
    println!("  mutinyd dividend-claim --license N --amount MUT [--data-dir PATH]");
    println!("  mutinyd licenses [--data-dir PATH]");
    println!("  mutinyd license-history --license N [--data-dir PATH]");
    println!("  mutinyd mempool [--data-dir PATH]");
    println!("  mutinyd branches [--data-dir PATH]");
    println!("  mutinyd peers [--data-dir PATH]");
    println!("  mutinyd tx <TXID> [--data-dir PATH]");
    println!("  mutinyd check [--data-dir PATH]");
    println!("  mutinyd worker-reference-key-init --worker-key-file PATH");
    println!("  mutinyd worker-reference-key-info --worker-key-file PATH");
    println!("  mutinyd worker-reference-one --connect HOST:PORT --worker-key-file PATH --node-public-key HEX --node-id HEX");
    println!("  mutinyd worker-reference-ignore-cancel-one --connect HOST:PORT --worker-key-file PATH --node-public-key HEX --node-id HEX");
    println!("  mutinyd worker-reassign-one-serve --data-dir PATH --listen HOST:PORT --license N --ticket-index N --mining-key-label NAME --wallet-passphrase-file PATH --node-passphrase-file PATH [--epoch E]");
    println!("  mutinyd worker-cancel-one-serve --data-dir PATH --listen HOST:PORT --license N --cancel-reason 1..7 --mining-key-label NAME --wallet-passphrase-file PATH --node-passphrase-file PATH [--epoch E]");
    println!("  mutinyd worker-watch-one-serve --data-dir PATH --listen HOST:PORT --license N --mining-key-label NAME --wallet-passphrase-file PATH --node-passphrase-file PATH [--epoch E]");
    println!("  mutinyd worker-mine-one-serve --data-dir PATH --listen HOST:PORT --license N --mining-key-label NAME --wallet-passphrase-file PATH --node-passphrase-file PATH [--epoch E] [--peer HOST:PORT]...");
    println!("  mutinyd worker-serve [--data-dir PATH] [--listen HOST:PORT] [--max-connections N] --node-passphrase-file PATH");
    println!("  mutinyd node [--data-dir PATH] [--listen HOST:PORT] [--peer HOST:PORT]... [--mine [--mining-license N --mining-key-label NAME --wallet-passphrase-file PATH]] [--epoch-ms N] [--max-rounds N] --node-passphrase-file PATH");
    println!("  mutinyd duplex-selftest [--data-dir PATH]");
    println!("  mutinyd sync --peer HOST:PORT [--data-dir PATH] --node-passphrase-file PATH");
    println!("  mutinyd peer-status  (snapshot status removed in Build 4)");
    println!(
        "  mutinyd relay-tx <TXID> --peer HOST:PORT [--data-dir PATH] --node-passphrase-file PATH"
    );
}

fn option_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .position(|x| x == key)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn option_values<'a>(args: &'a [String], key: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < args.len() {
        if args[i] == key {
            out.push(args[i + 1].as_str());
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn required_option<'a>(args: &'a [String], key: &str) -> Result<&'a str, String> {
    option_value(args, key).ok_or_else(|| format!("missing required option {key}"))
}

fn has_flag(args: &[String], key: &str) -> bool {
    args.iter().any(|x| x == key)
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("state.json")
}

fn bootstrap_license_states() -> Vec<LicenseState> {
    let mut licenses = Vec::with_capacity(BOOTSTRAP_LICENSE_COUNT);
    for i in 0..BOOTSTRAP_LICENSE_COUNT {
        let seed = dev_seed(i as u8);
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        let purchase_id = sha256_domain(
            domains::BOOTSTRAP_MANIFEST,
            &[b"DEVNET-BOOTSTRAP", &[i as u8]],
        )
        .0;
        let lid = sha256_domain(
            domains::LICENSE_ID,
            &[
                &DEVNET_NETWORK_ID.to_be_bytes(),
                &[0x01],
                &purchase_id,
                &(i as u32).to_be_bytes(),
                &pk,
            ],
        )
        .0;
        let addr = address_id(&pk).0;
        licenses.push(LicenseState {
            index: i as u32,
            license_id: hex::encode(lid),
            purchase_id: hex::encode(purchase_id),
            owner_public_key: hex::encode(pk),
            mining_public_key: hex::encode(pk),
            payment_address_id: hex::encode(addr),
            status: LICENSE_STATUS_ACTIVE,
            purchase_method: PURCHASE_METHOD_BTC,
            owner_key_sequence: 0,
            mining_key_sequence: 0,
            issued_epoch: 0,
            activation_epoch: ACTIVATION_DELAY_EPOCHS,
            strike_weight: 0,
            suspended_until_epoch: 0,
            revocation_epoch: 0,
        });
    }
    licenses
}

fn init_devnet(dir: &Path, epoch_ms: u64, force: bool) -> Result<(), String> {
    if (state_path(dir).exists() || storage::exists(dir)) && !force {
        return Err(format!(
            "{} already contains Mutiny node state; use --force to recreate",
            dir.display()
        ));
    }
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    if force {
        if state_path(dir).exists() {
            fs::remove_file(state_path(dir))
                .map_err(|e| format!("remove legacy {}: {e}", state_path(dir).display()))?;
        }
        storage::reset_for_init(dir)?;
    }
    let genesis_time_ms = DEVNET_FIXED_GENESIS_TIME_MS;
    let mut genesis_material = Vec::new();
    genesis_material.extend_from_slice(&DEVNET_NETWORK_ID.to_be_bytes());
    genesis_material.extend_from_slice(&(genesis_time_ms as u64).to_be_bytes());
    genesis_material.extend_from_slice(MOTTO.as_bytes());
    let genesis_hash = sha256_domain(domains::GENESIS_ID, &[&genesis_material]).0;

    let licenses = bootstrap_license_states();

    let mut state = DevnetState {
        format_version: 9,
        network_id: DEVNET_NETWORK_ID,
        motto: MOTTO.into(),
        genesis_time_ms,
        genesis_hash: hex::encode(genesis_hash),
        epoch_ms: epoch_ms.max(1),
        height: 0,
        tip_hash: hex::encode(genesis_hash),
        tip_epoch: 0,
        anchor_epoch: 0,
        anchor_license_id: hex::encode([0u8; 32]),
        anchor_ticket_index: 0,
        anchor_argon2_proof: hex::encode(genesis_hash),
        total_issued_strikes: 0,
        difficulty_history_count: 0,
        difficulty_history_bitmap: 0,
        difficulty_correction_q32: DIFFICULTY_Q32_ONE,
        base_fee_rate_q32: BASE_FEE_MIN_Q32,
        current_state_root: String::new(),
        licenses,
        consumed_native_payments: Vec::new(),
        consumed_bitcoin_payments: Vec::new(),
        consumed_evidence: Vec::new(),
        offense_events: Vec::new(),
        treasury_reserved_dividend_strikes: 0,
        dividend_accounts: Vec::new(),
        historical_license_keys: Vec::new(),
        mining_presence: Vec::new(),
        bitcoin_headers: Vec::new(),
        bitcoin_best_chain: None,
        utxos: Vec::new(),
        mempool: Vec::new(),
        pending_protocol_operations: Vec::new(),
        confirmed_transactions: Vec::new(),
        blocks: Vec::new(),
        side_branches: Vec::new(),
    };
    refresh_current_state_root(&mut state)?;
    save_state(dir, &state)
}

fn init_build54_genesis_devnet(dir: &Path, epoch_ms: u64, force: bool) -> Result<(), String> {
    // Keep the long-lived integrated Devnet test initializer intact for regression compatibility,
    // but the Build 5.4 CLI must model the real lifecycle: Genesis contains no Mining Licenses.
    init_devnet(dir, epoch_ms, force)?;
    let mut state = load_state(dir)?;
    state.format_version = 10;
    state.licenses.clear();
    state.consumed_native_payments.clear();
    state.consumed_bitcoin_payments.clear();
    state.consumed_evidence.clear();
    state.offense_events.clear();
    state.treasury_reserved_dividend_strikes = 0;
    state.dividend_accounts.clear();
    state.historical_license_keys.clear();
    state.bitcoin_headers.clear();
    state.bitcoin_best_chain = None;
    state.utxos.clear();
    state.mempool.clear();
    state.pending_protocol_operations.clear();
    state.confirmed_transactions.clear();
    state.blocks.clear();
    state.side_branches.clear();
    state.height = 0;
    state.tip_epoch = 0;
    state.total_issued_strikes = 0;
    state.difficulty_history_count = 0;
    state.difficulty_history_bitmap = 0;
    state.difficulty_correction_q32 = DIFFICULTY_Q32_ONE;
    state.base_fee_rate_q32 = BASE_FEE_MIN_Q32;
    bootstrap::initialize_genesis_state(&mut state)?;
    save_state(dir, &state)
}

fn init_mainnet_genesis(dir: &Path, epoch_ms: u64, force: bool) -> Result<(), String> {
    // Reuse only the existing storage initialization mechanics.  The resulting
    // consensus state is reset before it is ever returned or committed as
    // Mainnet, and binds the locked Mainnet tuple directly.
    init_devnet(dir, epoch_ms, force)?;
    let mut state = load_state(dir)?;
    state.format_version = 10;
    state.network_id = MAINNET_NETWORK_ID;
    state.genesis_hash = hex::encode(MAINNET_GENESIS_ID);
    state.genesis_time_ms = 0;
    state.height = 0;
    state.tip_hash = hex::encode(MAINNET_GENESIS_ID);
    state.tip_epoch = 0;
    state.anchor_epoch = 0;
    state.anchor_license_id = hex::encode([0u8; 32]);
    state.anchor_ticket_index = 0;
    state.anchor_argon2_proof = hex::encode(MAINNET_GENESIS_ID);
    state.total_issued_strikes = 0;
    state.difficulty_history_count = 0;
    state.difficulty_history_bitmap = 0;
    state.difficulty_correction_q32 = DIFFICULTY_Q32_ONE;
    state.base_fee_rate_q32 = BASE_FEE_MIN_Q32;
    state.licenses.clear();
    state.consumed_native_payments.clear();
    state.consumed_bitcoin_payments.clear();
    state.consumed_evidence.clear();
    state.offense_events.clear();
    state.treasury_reserved_dividend_strikes = 0;
    state.dividend_accounts.clear();
    state.historical_license_keys.clear();
    state.mining_presence.clear();
    state.bitcoin_headers.clear();
    state.bitcoin_best_chain = None;
    state.utxos.clear();
    state.mempool.clear();
    state.pending_protocol_operations.clear();
    state.confirmed_transactions.clear();
    state.blocks.clear();
    state.side_branches.clear();
    refresh_current_state_root(&mut state)?;
    save_state(dir, &state)
}

fn runtime_for_state(state: &DevnetState) -> Result<RuntimeNetwork, String> {
    let runtime = match state.network_id {
        DEVNET_NETWORK_ID => RuntimeNetwork::Devnet,
        MAINNET_NETWORK_ID => RuntimeNetwork::Mainnet,
        _ => return Err("state NetworkID is not an active Mutiny runtime network".into()),
    };
    validate_runtime_tuple(state, runtime)?;
    Ok(runtime)
}

fn validate_runtime_tuple(state: &DevnetState, runtime: RuntimeNetwork) -> Result<(), String> {
    if state.network_id != runtime.network_id()
        || ((runtime == RuntimeNetwork::Mainnet || state.format_version >= 10)
            && decode32(&state.genesis_hash)? != runtime.genesis_id()?)
    {
        return Err("runtime NetworkID/GenesisID tuple does not match stored state".into());
    }
    Ok(())
}

fn require_mainnet_canonical_tip(state: &DevnetState) -> Result<(), String> {
    if state.network_id != MAINNET_NETWORK_ID {
        return Ok(());
    }
    validate_runtime_tuple(state, RuntimeNetwork::Mainnet)?;
    let valid = if state.height == 0 {
        state.blocks.is_empty() && state.tip_epoch == 0 && state.tip_hash == state.genesis_hash
    } else {
        state.blocks.last().is_some_and(|block| {
            state.blocks.len() as u64 == state.height
                && block.height == state.height
                && state.tip_epoch == block.epoch
                && state.tip_hash == block.block_hash
                && state.current_state_root == block.state_root
        })
    };
    if !valid {
        return Err("LOCAL_BOOTSTRAP_INPUT: Mainnet snapshot is not at its committed canonical block tip; locally advanced snapshots require explicit witness-authenticated recovery before runtime use".into());
    }
    Ok(())
}

fn decode_devnet_state(bytes: &[u8]) -> Result<DevnetState, String> {
    let mut state: DevnetState = serde_json::from_slice(bytes).map_err(|e| {
        format!(
            "cannot decode integrated Devnet state ({e}); use a valid locked Build 5.9 state or initialize a fresh Build 6.1 data directory."
        )
    })?;
    if !matches!(state.format_version, 4 | 5 | 6 | 7 | 8 | 9 | 10) {
        return Err("unsupported consensus-state serialization format; Build 6.1 accepts inherited format_version 4 through 10".into());
    }
    // This field is the inherited integrated Devnet state schema marker, not the Build 6.1
    // storage-envelope version. Format 10 remains the lifecycle-correct Pack-J state.
    if state.format_version < 10 {
        state.format_version = 9;
    }
    Ok(state)
}

fn chainwork_bytes32(state: &DevnetState) -> Result<[u8; 32], String> {
    let bytes = chainwork(state)?.to_bytes_be();
    if bytes.len() > 32 {
        return Err("ChainWork exceeds 256-bit storage metadata field".into());
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

fn storage_identity(state: &DevnetState) -> Result<storage::SnapshotIdentity, String> {
    Ok(storage::SnapshotIdentity {
        network_id: state.network_id,
        genesis_id: decode32(&state.genesis_hash)?,
        height: state.height,
        tip_hash: decode32(&state.tip_hash)?,
        state_root: decode32(&state.current_state_root)?,
        chainwork: chainwork_bytes32(state)?,
    })
}

fn validate_storage_meta(state: &DevnetState, meta: &storage::StorageMetaV1) -> Result<(), String> {
    let runtime = match state.network_id {
        DEVNET_NETWORK_ID => RuntimeNetwork::Devnet,
        MAINNET_NETWORK_ID => RuntimeNetwork::Mainnet,
        _ => return Err("storage NetworkID is not an active Mutiny runtime network".into()),
    };
    validate_storage_meta_for_runtime(state, meta, runtime)
}

fn validate_storage_meta_for_runtime(
    state: &DevnetState,
    meta: &storage::StorageMetaV1,
    runtime: RuntimeNetwork,
) -> Result<(), String> {
    let expected = storage_identity(state)?;
    if meta.network_id != runtime.network_id() || expected.network_id != runtime.network_id() {
        return Err("storage NetworkID mismatch".into());
    }
    if state.format_version >= 10
        && (meta.genesis_id != runtime.genesis_id()?
            || expected.genesis_id != runtime.genesis_id()?)
    {
        return Err("storage GenesisID mismatch".into());
    }
    if meta.network_id != expected.network_id
        || meta.genesis_id != expected.genesis_id
        || meta.height != expected.height
        || meta.tip_hash != expected.tip_hash
        || meta.state_root != expected.state_root
        || meta.chainwork != expected.chainwork
    {
        return Err("storage metadata does not match decoded state snapshot".into());
    }
    Ok(())
}

fn verify_replay_for_ingress(
    state: &DevnetState,
    ingress: &RuntimeIngressContext,
) -> Result<(), String> {
    validate_runtime_tuple(state, ingress.runtime)?;
    match ingress.runtime {
        RuntimeNetwork::Devnet => blocksync::verify_full_replay(state),
        RuntimeNetwork::Mainnet => {
            let mut canonical = state.clone();
            canonical.mempool.clear();
            canonical.pending_protocol_operations.clear();
            canonical.side_branches.clear();
            blocksync::verify_full_replay_for_runtime(
                &canonical,
                ingress.runtime,
                ingress.bootstrap_witness.as_ref(),
            )
            .map_err(|e| e.to_string())
        }
    }
}

fn load_state_for_runtime(
    dir: &Path,
    ingress: &RuntimeIngressContext,
) -> Result<DevnetState, String> {
    let state = load_state_with_ingress(dir, Some(ingress))?;
    validate_runtime_tuple(&state, ingress.runtime)?;
    require_mainnet_canonical_tip(&state)?;
    Ok(state)
}

fn load_state(dir: &Path) -> Result<DevnetState, String> {
    load_state_with_ingress(dir, None)
}

fn load_state_with_ingress(
    dir: &Path,
    ingress: Option<&RuntimeIngressContext>,
) -> Result<DevnetState, String> {
    let loaded = match ingress {
        Some(ingress) => storage::load_snapshot_for_network(
            dir,
            ingress.runtime.network_id(),
            (ingress.runtime == RuntimeNetwork::Mainnet).then_some(MAINNET_GENESIS_ID),
            |bytes, meta| {
                if ingress.runtime == RuntimeNetwork::Mainnet {
                    let state = decode_devnet_state(bytes)?;
                    validate_storage_meta_for_runtime(&state, meta, ingress.runtime)?;
                    require_mainnet_canonical_tip(&state)?;
                    check_state(&state)?;
                    verify_replay_for_ingress(&state, ingress)?;
                }
                Ok(())
            },
        )?,
        None => storage::load_snapshot(dir)?,
    };
    if let Some(loaded) = loaded {
        let mut state = decode_devnet_state(&loaded.bytes)?;
        validate_storage_meta(&state, &loaded.meta)?;
        if let Some(ingress) = ingress {
            validate_runtime_tuple(&state, ingress.runtime)?;
        }
        check_state(&state)?;
        if loaded.recovery != storage::RecoveryAction::None {
            // Recovery must prove the authoritative state from canonical block history before
            // the node exposes RPC/network service. Volatile pending work is never authoritative.
            match ingress {
                // The Mainnet callback verified this exact authenticated snapshot before
                // storage recovery could remove its journal. Do not repeat the expensive replay.
                Some(ingress) if ingress.runtime == RuntimeNetwork::Mainnet => {}
                Some(ingress) => verify_replay_for_ingress(&state, ingress)?,
                None => blocksync::verify_full_replay(&state)?,
            }
            eprintln!(
                "Build 6.0 storage recovery: {:?}; canonical replay verified at generation {}.",
                loaded.recovery, loaded.meta.generation
            );
            if !state.mempool.is_empty() || !state.pending_protocol_operations.is_empty() {
                state.mempool.clear();
                state.pending_protocol_operations.clear();
                save_state(dir, &state)?;
                eprintln!(
                    "Build 6.0 storage recovery: purged volatile mempool/protocol-operation state."
                );
            }
        }
        return Ok(state);
    }

    let Some(legacy) = storage::prepare_legacy_migration(dir, &state_path(dir))? else {
        return Err("cannot read state; run `mutinyd init` first or provide a locked Build 5.9 data directory for migration".into());
    };
    let bytes = fs::read(&legacy)
        .map_err(|e| format!("read staged Build 5.9 state {}: {e}", legacy.display()))?;
    let state = decode_devnet_state(&bytes)?;
    check_state(&state)?;
    match ingress {
        Some(ingress) => verify_replay_for_ingress(&state, ingress)?,
        None => blocksync::verify_full_replay(&state)?,
    }
    save_state(dir, &state)?;
    let meta =
        storage::inspect_meta(dir)?.ok_or("Build 6.0 migration committed no storage metadata")?;
    eprintln!("Build 6.0 storage migration: locked Build 5.9 state -> MutinyStorageV1 generation {} (height {}).", meta.generation, meta.height);
    Ok(state)
}

fn save_state(dir: &Path, state: &DevnetState) -> Result<(), String> {
    require_mainnet_canonical_tip(state)?;
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?;
    let identity = storage_identity(state)?;
    storage::commit_snapshot(dir, &bytes, &identity)?;
    Ok(())
}

fn print_storage_meta(meta: &storage::StorageMetaV1) {
    println!("Storage format:     MutinyStorageV1");
    println!("Storage version:    {}", storage::STORAGE_FORMAT_VERSION);
    println!("Generation:         {}", meta.generation);
    println!("NetworkID:          0x{:08x}", meta.network_id);
    println!("GenesisID:          {}", hex::encode(meta.genesis_id));
    println!("Canonical height:   {}", meta.height);
    println!("Canonical tip:      {}", hex::encode(meta.tip_hash));
    println!("Current StateRoot:  {}", hex::encode(meta.state_root));
    println!("ChainWork (32-byte): {}", hex::encode(meta.chainwork));
    println!("Snapshot SHA-256:   {}", hex::encode(meta.snapshot_sha256));
}

fn apply_scheduled_license_transitions(
    state: &mut DevnetState,
    epoch: u64,
) -> Result<usize, String> {
    punishment::expire_events(state, epoch)?;
    let mut activated = 0usize;
    for license in &mut state.licenses {
        if license.status == LICENSE_STATUS_PENDING && epoch >= license.activation_epoch {
            license.status = LICENSE_STATUS_ACTIVE;
            activated += 1;
        }
    }
    let (returned, awarded, reserved) = dividends::process_epoch(state, epoch)?;
    if returned > 0 {
        println!(
            "Dividend expiry returned {} MUT to Treasury availability at epoch {epoch}.",
            format_mut(returned)
        );
    }
    if epoch > 0 && epoch % mutiny_protocol::DIVIDEND_AWARD_INTERVAL == 0 {
        println!(
            "Dividend award epoch {epoch}: {awarded} eligible licenses, {} MUT reserved.",
            format_mut(reserved)
        );
    }
    Ok(activated)
}

fn dev_signing_key_for_public_key(public_key: &[u8; 32]) -> Option<SigningKey> {
    for slot in 0u16..=255 {
        let key = SigningKey::from_bytes(&dev_seed(slot as u8));
        if key.verifying_key().to_bytes() == *public_key {
            return Some(key);
        }
    }
    None
}

fn dev_owner_signing_key_for_license(license: &LicenseState) -> Option<SigningKey> {
    let expected = decode32(&license.owner_public_key).ok()?;
    dev_signing_key_for_public_key(&expected)
}

fn dev_signing_key_for_license(license: &LicenseState) -> Option<SigningKey> {
    let expected = decode32(&license.mining_public_key).ok()?;
    dev_signing_key_for_public_key(&expected)
}

fn mineable_license_indices(state: &DevnetState, epoch: u64) -> Vec<usize> {
    state
        .licenses
        .iter()
        .enumerate()
        .filter_map(|(i, license)| {
            (license.is_eligible(epoch) && dev_signing_key_for_license(license).is_some())
                .then_some(i)
        })
        .collect()
}

fn base_eligible_license_count(state: &DevnetState, epoch: u64) -> u64 {
    presence::base_eligible_count(state, epoch)
}

fn eligible_license_count(state: &DevnetState, epoch: u64) -> u64 {
    presence::participation_eligible_count(state, epoch)
}

fn difficulty_observation_enabled(state: &DevnetState, epoch: u64) -> bool {
    if state.height == 0 {
        return false;
    }
    if state.format_version >= 10 {
        // The special Bootstrap block is not a mining opportunity. The network does not have
        // an eligible ticket lottery until the earliest Bootstrap license activation epoch.
        if let Some(first_activation) = state.licenses.iter().map(|l| l.activation_epoch).min() {
            return epoch >= first_activation;
        }
        return false;
    }
    true
}

fn advance_empty_epochs_fast(state: &mut DevnetState, through_epoch: u64) -> Result<(), String> {
    if state.height == 0 {
        return Err("advance-empty requires at least one canonical block".into());
    }
    if through_epoch <= state.tip_epoch {
        return Err("--to-epoch must be greater than the current local epoch".into());
    }
    while state.tip_epoch < through_epoch {
        state.tip_epoch = state.tip_epoch.checked_add(1).ok_or("epoch overflow")?;
        apply_scheduled_license_transitions(state, state.tip_epoch)?;
        if difficulty_observation_enabled(state, state.tip_epoch) {
            append_difficulty_result(state, false)?;
        }
    }
    refresh_current_state_root(state)?;
    Ok(())
}

fn next_mineable_epoch(state: &DevnetState) -> u64 {
    if state.height == 0 {
        ACTIVATION_DELAY_EPOCHS.max(state.tip_epoch.saturating_add(1))
    } else if state.format_version >= 10
        && base_eligible_license_count(state, state.tip_epoch.saturating_add(1)) == 0
    {
        state
            .licenses
            .iter()
            .filter(|l| l.activation_epoch > state.tip_epoch)
            .map(|l| l.activation_epoch)
            .min()
            .unwrap_or_else(|| state.tip_epoch.saturating_add(1))
    } else {
        state.tip_epoch + 1
    }
}

fn subsidy(epoch: u64) -> u64 {
    let era = epoch / ERA_LENGTH;
    if era >= 64 {
        return 0;
    }
    (8 * STRIKES_PER_MUT) >> era
}

fn stage_mainnet_mining_attempt(
    state: &DevnetState,
    epoch: u64,
    license_index: usize,
    signer: &dyn MiningAuthority,
) -> Result<Option<DevnetState>, String> {
    validate_runtime_tuple(state, RuntimeNetwork::Mainnet)?;
    require_mainnet_canonical_tip(state)?;
    let mut candidate = state.clone();
    mine_epoch_with_signer(&mut candidate, epoch, Some((license_index, signer)))?;
    if candidate.height == state.height {
        return Ok(None);
    }
    if candidate.height != state.height.checked_add(1).ok_or("height overflow")? {
        return Err("mining candidate did not produce exactly one block".into());
    }
    let block = candidate
        .blocks
        .last()
        .ok_or("mining candidate omitted its block")?;
    let payload = blocksync::encode_block_payload(block)?;
    let (header, txs, operations) = blocksync::decode_block_payload(&payload)?;
    let mut accepted = state.clone();
    blocksync::validate_and_apply_block(&mut accepted, header, txs, operations)?;
    if accepted.tip_hash != candidate.tip_hash
        || accepted.current_state_root != candidate.current_state_root
    {
        return Err("Mainnet constructor and production validator disagree".into());
    }
    require_mainnet_canonical_tip(&accepted)?;
    Ok(Some(accepted))
}

fn mine_epoch(state: &mut DevnetState, epoch: u64) -> Result<(), String> {
    mine_epoch_with_signer(state, epoch, None)
}

fn mine_epoch_with_signer(
    state: &mut DevnetState,
    epoch: u64,
    secure_signer: Option<(usize, &dyn MiningAuthority)>,
) -> Result<(), String> {
    if state.format_version >= 10 && state.height == 0 {
        return Err("Build 5.4 requires bootstrap-dev to commit Block 1 before mining".into());
    }
    if epoch <= state.tip_epoch && state.height > 0 {
        return Err("candidate epoch must be greater than tip epoch".into());
    }
    if state.height == 0 && epoch < ACTIVATION_DELAY_EPOCHS {
        return Err("bootstrap licenses are not active yet".into());
    }

    // An explicit future --epoch may intentionally skip candidate epochs during fork tests.
    // Once Block 1 exists, those skipped mineable epochs are canonical empty observations on
    // this branch and must update the rolling difficulty controller before the candidate.
    if state.height > 0 && state.network_id == MAINNET_NETWORK_ID {
        // Same scheduled transitions and difficulty observations as validation;
        // intermediate roots are not consumed by empty-epoch transitions.
        blocksync::advance_empty_epochs(state, epoch.saturating_sub(1))?;
    } else if state.height > 0 {
        while state.tip_epoch.saturating_add(1) < epoch {
            state.tip_epoch = state.tip_epoch.saturating_add(1);
            let activated = apply_scheduled_license_transitions(state, state.tip_epoch)?;
            if difficulty_observation_enabled(state, state.tip_epoch) {
                append_difficulty_result(state, false)?;
            }
            refresh_current_state_root(state)?;
            if activated > 0 {
                println!(
                    "Activated {activated} Mining License(s) at epoch {}.",
                    state.tip_epoch
                );
            }
            println!("Recorded skipped epoch {} as empty.", state.tip_epoch);
        }
    }

    let activated = apply_scheduled_license_transitions(state, epoch)?;
    if activated > 0 {
        println!("Activated {activated} Mining License(s) at epoch {epoch}.");
    }
    let mineable = if let Some((license_index, signer)) = secure_signer {
        let license = state
            .licenses
            .get(license_index)
            .ok_or("license number out of range")?;
        if !license.is_eligible(epoch) {
            return Err("selected encrypted-custody Mining License is not base-eligible in the candidate epoch".into());
        }
        if signer.public_key() != decode32(&license.mining_public_key)? {
            return Err(
                "provided signing key does not match the current on-chain mining authority".into(),
            );
        }
        vec![license_index]
    } else {
        mineable_license_indices(state, epoch)
    };

    let anchor = if state.height == 0 {
        decode32(&state.genesis_hash)?
    } else {
        mutiny_crypto::anchor_entropy(
            state.anchor_epoch,
            &decode32(&state.anchor_license_id)?,
            state.anchor_ticket_index,
            &decode32(&state.anchor_argon2_proof)?,
        )
        .0
    };
    let es = epoch_seed(&anchor, epoch);
    let parent_participation = eligible_license_count(state, epoch);
    println!(
        "Epoch {epoch}: {} parent-branch participation-eligible licenses ({} local custody keys), C_Q32={}",
        parent_participation, mineable.len(), state.difficulty_correction_q32
    );

    for li in mineable {
        let license_id = decode32(&state.licenses[li].license_id)?;
        let selected_secure = secure_signer
            .filter(|(license_index, _)| *license_index == li)
            .map(|(_, signer)| signer);
        let dev_signer_storage;
        let candidate_signer: &dyn MiningAuthority = if let Some(signer) = selected_secure {
            signer
        } else {
            dev_signer_storage = dev_signing_key_for_license(&state.licenses[li])
                .ok_or("local Devnet does not hold the selected Mining License private key")?;
            &dev_signer_storage
        };
        let operations = candidate_protocol_operations(state, epoch, li, candidate_signer)?;
        let candidate_eligible =
            presence::candidate_eligible_count(state, epoch, &license_id, &operations)?;
        let w = work_units(candidate_eligible);
        let a = authorized_capacity(candidate_eligible);
        let target =
            derive_target(a, state.difficulty_correction_q32).map_err(|e| e.to_string())?;
        println!(
            "  candidate license {}: eligible_count={}, W_E={}, A_E={}, self_presence={}",
            li + 1,
            candidate_eligible,
            w,
            a,
            operations.iter().any(|op| op.op_type == OP_MINING_PRESENCE
                && presence::decode_operation(op).is_ok_and(|p| p.license_id.0 == license_id))
        );
        for ticket in 0..w {
            let seed = ticket_seed(&es.0, &license_id, ticket);
            let salt = ticket_salt(&es.0, &license_id, ticket);
            let proof = mutiny_argon2id(&seed.0, &salt.0).map_err(|e| e.to_string())?;
            if proof_below_target(&proof.0, &target) {
                accept_dev_block_with_signer_and_operations(
                    state,
                    epoch,
                    li,
                    ticket,
                    proof.0,
                    target,
                    selected_secure,
                    operations,
                )?;
                return Ok(());
            }
        }
    }

    println!("No winning ticket in epoch {epoch}; epoch is empty.");
    state.tip_epoch = epoch;
    if difficulty_observation_enabled(state, epoch) {
        append_difficulty_result(state, false)?;
    }
    refresh_current_state_root(state)?;
    Ok(())
}

#[cfg(test)]
fn accept_dev_block(
    state: &mut DevnetState,
    epoch: u64,
    license_index: usize,
    ticket: u16,
    proof: [u8; 32],
    target: [u8; 32],
) -> Result<(), String> {
    accept_dev_block_with_signer(state, epoch, license_index, ticket, proof, target, None)
}

#[cfg(test)]
fn accept_dev_block_with_signer(
    state: &mut DevnetState,
    epoch: u64,
    license_index: usize,
    ticket: u16,
    proof: [u8; 32],
    target: [u8; 32],
    secure_signer: Option<&dyn MiningAuthority>,
) -> Result<(), String> {
    let dev_signer_storage;
    let candidate_signer: &dyn MiningAuthority = if let Some(signer) = secure_signer {
        signer
    } else {
        dev_signer_storage = dev_signing_key_for_license(
            state
                .licenses
                .get(license_index)
                .ok_or("license number out of range")?,
        )
        .ok_or("local Devnet does not hold the selected Mining License private key")?;
        &dev_signer_storage
    };
    let operations = candidate_protocol_operations(state, epoch, license_index, candidate_signer)?;
    accept_dev_block_with_signer_and_operations(
        state,
        epoch,
        license_index,
        ticket,
        proof,
        target,
        secure_signer,
        operations,
    )
}

fn accept_dev_block_with_signer_and_operations(
    state: &mut DevnetState,
    epoch: u64,
    license_index: usize,
    ticket: u16,
    proof: [u8; 32],
    target: [u8; 32],
    secure_signer: Option<&dyn MiningAuthority>,
    operations: Vec<ProtocolOperationV1>,
) -> Result<(), String> {
    let runtime = runtime_for_state(state)?;
    if runtime == RuntimeNetwork::Mainnet && secure_signer.is_none() {
        return Err("Mainnet mining requires an authorized operational mining signer".into());
    }
    let height = state.height + 1;
    let parent = decode32(&state.tip_hash)?;
    let license_id = decode32(&state.licenses[license_index].license_id)?;
    let reward = subsidy(epoch);

    // Pack K must not retroactively change the inherited local acceptance helper before
    // its formally locked activation boundary. Production block validation already
    // derives and verifies the canonical target independently in blocksync. Once Pack K
    // is active, local construction additionally proves that the caller-supplied target
    // matches the participation-aware candidate count.
    if presence::active(state, epoch) {
        let derived_candidate_count =
            presence::candidate_eligible_count(state, epoch, &license_id, &operations)?;
        let expected_target = derive_target(
            authorized_capacity(derived_candidate_count),
            state.difficulty_correction_q32,
        )
        .map_err(|e| e.to_string())?;
        if target != expected_target {
            return Err(
                "local candidate target does not match Pack-K eligible-count derivation".into(),
            );
        }
    }
    let mut selected_state = state.clone();
    selected_state.mempool = selected_block_mempool(state, &operations)?;
    let mut working_utxos = state.utxos.clone();
    let validated = validate_and_apply_mempool(
        &selected_state,
        &mut working_utxos,
        epoch,
        height,
        &operations,
    )?;

    let mut total_fees = 0u64;
    let mut treasury_share = 0u64;
    for v in &validated {
        total_fees = total_fees.checked_add(v.fee).ok_or("fee overflow")?;
        treasury_share = treasury_share
            .checked_add(v.base_fee / 2)
            .ok_or("treasury fee overflow")?;
    }
    let miner_fee_share = total_fees
        .checked_sub(treasury_share)
        .ok_or("fee split underflow")?;
    let miner_coinbase_amount = reward
        .checked_add(miner_fee_share)
        .ok_or("coinbase overflow")?;

    let protocol_root = protocol_operations_root(&operations).map_err(|e| e.to_string())?;
    let commitment = CoinbaseCommitmentV1 {
        block_epoch: epoch,
        block_height: height,
        parent_block_hash: parent,
        protocol_operations_root: protocol_root.0,
    };
    let mut coinbase_outputs = vec![TxOutput {
        amount_strikes: miner_coinbase_amount,
        output_type: OUTPUT_PUBKEY_HASH,
        payload: decode32(&state.licenses[license_index].payment_address_id)?.to_vec(),
    }];
    if treasury_share > 0 {
        coinbase_outputs.push(TxOutput {
            amount_strikes: treasury_share,
            output_type: OUTPUT_TREASURY,
            payload: treasury_id_for_network(state.network_id).to_vec(),
        });
    }
    let coinbase = TransactionV1 {
        core: TransactionCoreV1 {
            version: 1,
            network_id: state.network_id,
            valid_from_epoch: epoch,
            expiry_epoch: 0,
            inputs: vec![TxInput::Coinbase { commitment }],
            outputs: coinbase_outputs,
        },
        witnesses: vec![],
    };
    let coinbase_txid = coinbase.txid();
    add_outputs_as_utxos(&mut working_utxos, &coinbase, epoch, height, true)?;

    let mut txs = Vec::with_capacity(1 + validated.len());
    txs.push(coinbase.clone());
    txs.extend(validated.iter().map(|v| v.tx.clone()));
    let leaves = txs.iter().map(TransactionV1::leaf).collect::<Vec<_>>();
    let tx_root = merkle_root(&leaves).ok_or("block must contain coinbase")?;
    let block_weight = block_body_weight(&txs, &operations)?;
    if block_weight > BLOCK_WEIGHT_MAX {
        return Err(format!(
            "block weight {block_weight} exceeds {BLOCK_WEIGHT_MAX}"
        ));
    }

    let mut post_protocol_state = state.clone();
    post_protocol_state.tip_epoch = epoch;
    let created_licenses =
        apply_protocol_operations(&mut post_protocol_state, &txs, &operations, epoch)?;

    let next_total_issued = state
        .total_issued_strikes
        .checked_add(reward)
        .ok_or("supply overflow")?;

    let mut next_history_count = state.difficulty_history_count;
    let mut next_history_bitmap = state.difficulty_history_bitmap;
    let mut next_correction = state.difficulty_correction_q32;
    if state.height > 0 {
        append_history_values(
            &mut next_history_count,
            &mut next_history_bitmap,
            &mut next_correction,
            true,
        )?;
    }
    let next_base_fee = adjusted_base_fee_rate(state.base_fee_rate_q32, block_weight)?;

    let next_state_root = compute_state_root(
        &post_protocol_state,
        &working_utxos,
        height,
        next_total_issued,
        next_history_count,
        next_history_bitmap,
        next_correction,
        next_base_fee,
    )?;

    // Exact frozen Mutiny V1 208-byte header core layout.
    let mut core = [0u8; 208];
    core[0..2].copy_from_slice(&1u16.to_be_bytes());
    core[2..6].copy_from_slice(&state.network_id.to_be_bytes());
    core[6..14].copy_from_slice(&epoch.to_be_bytes());
    core[14..46].copy_from_slice(&parent);
    core[46..78].copy_from_slice(&tx_root.0);
    core[78..110].copy_from_slice(&next_state_root);
    core[110..142].copy_from_slice(&target);
    core[142..174].copy_from_slice(&license_id);
    core[174..176].copy_from_slice(&ticket.to_be_bytes());
    core[176..208].copy_from_slice(&proof);

    let dev_signer;
    let sk: &dyn MiningAuthority = if let Some(signer) = secure_signer {
        if signer.public_key() != decode32(&state.licenses[license_index].mining_public_key)? {
            return Err(
                "provided signing key does not match the selected Mining License authority".into(),
            );
        }
        signer
    } else {
        dev_signer = dev_signing_key_for_license(&state.licenses[license_index])
            .ok_or("local Devnet does not hold the selected Mining License private key")?;
        &dev_signer
    };
    let sig = sk.sign_candidate(state, height, &core)?;
    let mut header = [0u8; 272];
    header[..208].copy_from_slice(&core);
    header[208..].copy_from_slice(&sig);
    let bh = block_hash(&header).0;
    let block_hash_hex = hex::encode(bh);

    state.height = height;
    state.tip_epoch = epoch;
    state.tip_hash = block_hash_hex.clone();
    state.anchor_epoch = epoch;
    state.anchor_license_id = hex::encode(license_id);
    state.anchor_ticket_index = ticket;
    state.anchor_argon2_proof = hex::encode(proof);
    state.total_issued_strikes = next_total_issued;
    state.difficulty_history_count = next_history_count;
    state.difficulty_history_bitmap = next_history_bitmap;
    state.difficulty_correction_q32 = next_correction;
    state.base_fee_rate_q32 = next_base_fee;
    state.current_state_root = hex::encode(next_state_root);
    state.utxos = working_utxos;
    state.licenses = post_protocol_state.licenses;
    state.consumed_native_payments = post_protocol_state.consumed_native_payments;
    state.consumed_bitcoin_payments = post_protocol_state.consumed_bitcoin_payments;
    state.bitcoin_headers = post_protocol_state.bitcoin_headers;
    state.bitcoin_best_chain = post_protocol_state.bitcoin_best_chain;
    state.consumed_evidence = post_protocol_state.consumed_evidence;
    state.offense_events = post_protocol_state.offense_events;
    // Authority operations commit displaced owner/mining keys into ProtocolState.
    // The header StateRoot above was computed from post_protocol_state, so the
    // accepted local state must persist the same historical-key objects.
    state.historical_license_keys = post_protocol_state.historical_license_keys;
    state.mining_presence = post_protocol_state.mining_presence;
    // Build 5.2 Hotfix 2: dividend ProtocolState is part of the same committed
    // post-operation state used to compute the header StateRoot. Persist it
    // alongside the other protocol-state collections after local acceptance.
    state.treasury_reserved_dividend_strikes =
        post_protocol_state.treasury_reserved_dividend_strikes;
    state.dividend_accounts = post_protocol_state.dividend_accounts;

    let confirmed_ids = validated
        .iter()
        .map(|v| v.pending.txid.clone())
        .collect::<HashSet<_>>();
    let mut transaction_ids = Vec::new();
    for v in validated {
        transaction_ids.push(v.pending.txid.clone());
        state.confirmed_transactions.push(ConfirmedTxState {
            tx: v.pending,
            block_height: height,
            block_epoch: epoch,
            block_hash: block_hash_hex.clone(),
        });
    }
    state
        .mempool
        .retain(|pending| !confirmed_ids.contains(&pending.txid));
    let confirmed_operation_bytes = operations
        .iter()
        .map(|op| hex::encode(op.encode()))
        .collect::<HashSet<_>>();
    state.pending_protocol_operations.retain(|pending| {
        !confirmed_ids.contains(&pending.required_txid)
            && !confirmed_operation_bytes.contains(&pending.operation)
    });
    state.blocks.push(BlockState {
        height,
        epoch,
        header: hex::encode(header),
        transactions: txs.iter().map(|tx| hex::encode(tx.encode_full())).collect(),
        protocol_operations: operations
            .iter()
            .map(|op| hex::encode(op.encode()))
            .collect(),
        block_hash: block_hash_hex.clone(),
        parent_hash: hex::encode(parent),
        miner_license_id: hex::encode(license_id),
        ticket_index: ticket,
        argon2_proof: hex::encode(proof),
        target: hex::encode(target),
        reward_strikes: reward,
        total_fees_strikes: total_fees,
        treasury_fee_share_strikes: treasury_share,
        block_weight,
        transaction_root: hex::encode(tx_root.0),
        state_root: hex::encode(next_state_root),
        coinbase_txid: coinbase_txid.to_hex(),
        transaction_ids,
    });

    println!(
        "WIN - block {height} accepted, license {}, ticket {ticket}, subsidy {} MUT, txs {}, ops {}, new licenses {}, fees {} Strikes",
        license_index + 1,
        format_mut(reward),
        txs.len().saturating_sub(1),
        operations.len(),
        created_licenses,
        total_fees
    );
    println!("BlockHash:       {block_hash_hex}");
    println!("TransactionRoot: {}", hex::encode(tx_root.0));
    println!("StateRoot:       {}", hex::encode(next_state_root));
    Ok(())
}

fn validate_and_apply_mempool(
    state: &DevnetState,
    working_utxos: &mut Vec<UtxoState>,
    epoch: u64,
    height: u64,
    operations: &[ProtocolOperationV1],
) -> Result<Vec<ValidatedTx>, String> {
    let mut out = Vec::new();
    for pending in &state.mempool {
        let tx = pending.to_transaction_for_network(state.network_id)?;
        if tx.txid().to_hex() != pending.txid || tx.wtxid().to_hex() != pending.wtxid {
            return Err(format!("mempool transaction {} ID mismatch", pending.txid));
        }
        if tx.core.version != 1 || tx.core.network_id != state.network_id {
            return Err(format!(
                "transaction {} has wrong version/network",
                pending.txid
            ));
        }
        if epoch < tx.core.valid_from_epoch
            || (tx.core.expiry_epoch != 0 && epoch > tx.core.expiry_epoch)
        {
            return Err(format!(
                "transaction {} is outside its epoch validity window",
                pending.txid
            ));
        }
        if tx.core.inputs.is_empty()
            || tx.core.outputs.is_empty()
            || tx.core.inputs.len() > 1024
            || tx.core.outputs.len() > 1024
        {
            return Err(format!(
                "transaction {} has invalid input/output count",
                pending.txid
            ));
        }
        if tx.witnesses.len() != tx.core.inputs.len() {
            return Err(format!(
                "transaction {} witness count mismatch",
                pending.txid
            ));
        }

        if let Some(op) = dividends::claim_operation_for_tx(operations, &tx.txid())? {
            dividends::validate_and_apply_payment(state, working_utxos, &tx, op, epoch, height)?;
            out.push(ValidatedTx {
                pending: pending.clone(),
                tx,
                fee: 0,
                base_fee: 0,
            });
            continue;
        }

        let mut seen = HashSet::<(String, u16)>::new();
        let mut input_sum: u128 = 0;
        let mut consumed = Vec::<(String, u16)>::new();
        for (input_index, input) in tx.core.inputs.iter().enumerate() {
            let (previous_txid, previous_output_index) = match input {
                TxInput::Outpoint {
                    previous_txid,
                    previous_output_index,
                } => (hex::encode(previous_txid), *previous_output_index),
                TxInput::Coinbase { .. } => {
                    return Err("ordinary transaction cannot contain coinbase input".into())
                }
            };
            if !seen.insert((previous_txid.clone(), previous_output_index)) {
                return Err(format!("transaction {} duplicates an input", pending.txid));
            }
            let utxo = working_utxos
                .iter()
                .find(|u| u.txid == previous_txid && u.output_index == previous_output_index)
                .ok_or_else(|| format!("transaction {} references missing UTXO", pending.txid))?;
            if !utxo.spendable_at_height(height) {
                return Err(format!(
                    "transaction {} spends immature coinbase",
                    pending.txid
                ));
            }
            if utxo.output_type != OUTPUT_PUBKEY_HASH {
                return Err(format!(
                    "Integrated V1 send path cannot spend output type {}",
                    utxo.output_type
                ));
            }
            let address = AddressId(decode32(&utxo.payload)?);
            let digest = sighash_all(&tx.txid(), input_index as u16, &utxo.prevout()?);
            verify_pubkey_hash_witness(&address, &digest.0, &tx.witnesses[input_index])
                .map_err(|e| format!("transaction {} signature failure: {e}", pending.txid))?;
            input_sum = input_sum
                .checked_add(utxo.amount_strikes as u128)
                .ok_or("input sum overflow")?;
            consumed.push((previous_txid, previous_output_index));
        }

        let mut output_sum: u128 = 0;
        for output in &tx.core.outputs {
            if output.amount_strikes == 0 {
                return Err(format!(
                    "transaction {} contains zero-value output",
                    pending.txid
                ));
            }
            match output.output_type {
                OUTPUT_PUBKEY_HASH => {
                    if output.payload.len() != 32 {
                        return Err(format!(
                            "transaction {} has invalid address payload",
                            pending.txid
                        ));
                    }
                }
                OUTPUT_LICENSE_PAYMENT => {
                    if output.payload.len() != 32 {
                        return Err(format!(
                            "transaction {} has invalid LICENSE_PAYMENT manifest hash",
                            pending.txid
                        ));
                    }
                }
                other => {
                    return Err(format!("Integrated Build 5.0 ordinary transaction output type unsupported: {other}"));
                }
            }
            output_sum = output_sum
                .checked_add(output.amount_strikes as u128)
                .ok_or("output sum overflow")?;
        }
        if input_sum < output_sum {
            return Err(format!("transaction {} creates value", pending.txid));
        }
        let fee_u128 = input_sum - output_sum;
        let fee = u64::try_from(fee_u128).map_err(|_| "fee overflow")?;
        let base_fee = required_base_fee(state.base_fee_rate_q32, tx.serialized_len() as u64)
            .map_err(|e| e.to_string())?;
        if fee < base_fee {
            return Err(format!(
                "transaction {} underpays Base Fee: {} < {}",
                pending.txid, fee, base_fee
            ));
        }

        for (txid, index) in consumed {
            let pos = working_utxos
                .iter()
                .position(|u| u.txid == txid && u.output_index == index)
                .ok_or("UTXO disappeared during block application")?;
            working_utxos.remove(pos);
        }
        add_outputs_as_utxos(working_utxos, &tx, epoch, height, false)?;
        out.push(ValidatedTx {
            pending: pending.clone(),
            tx,
            fee,
            base_fee,
        });
    }
    Ok(out)
}

fn add_outputs_as_utxos(
    utxos: &mut Vec<UtxoState>,
    tx: &TransactionV1,
    epoch: u64,
    height: u64,
    coinbase: bool,
) -> Result<(), String> {
    let txid = tx.txid().to_hex();
    for (i, output) in tx.core.outputs.iter().enumerate() {
        let output_index = u16::try_from(i).map_err(|_| "output index overflow")?;
        utxos.push(UtxoState {
            txid: txid.clone(),
            output_index,
            amount_strikes: output.amount_strikes,
            output_type: output.output_type,
            payload: hex::encode(&output.payload),
            creation_epoch: epoch,
            creation_height: height,
            coinbase,
        });
    }
    Ok(())
}

fn create_send_transaction(
    state: &DevnetState,
    from: usize,
    to: usize,
    amount: u64,
) -> Result<PendingTxState, String> {
    let sk = state
        .licenses
        .get(from)
        .and_then(dev_owner_signing_key_for_license)
        .ok_or("local Devnet wallet does not hold the current owner private key for this Mining License")?;
    create_send_transaction_with_signer(state, from, to, amount, &sk)
}

fn create_send_transaction_with_signer(
    state: &DevnetState,
    from: usize,
    to: usize,
    amount: u64,
    sk: &SigningKey,
) -> Result<PendingTxState, String> {
    if amount == 0 {
        return Err("amount must be greater than zero".into());
    }
    if from >= state.licenses.len() || to >= state.licenses.len() {
        return Err("license number out of range".into());
    }
    let expected_owner = decode32(&state.licenses[from].owner_public_key)?;
    if sk.verifying_key().to_bytes() != expected_owner {
        return Err(
            "provided signing key does not match the current on-chain owner authority".into(),
        );
    }

    let candidate_epoch = next_mineable_epoch(state);
    let candidate_height = state.height + 1;
    let from_address = decode32(&state.licenses[from].payment_address_id)?;
    let to_address = decode32(&state.licenses[to].payment_address_id)?;
    let reserved = mempool_reserved_inputs(state);

    let mut candidates = state
        .utxos
        .iter()
        .filter(|u| {
            u.output_type == OUTPUT_PUBKEY_HASH
                && decode32(&u.payload)
                    .map(|p| p == from_address)
                    .unwrap_or(false)
                && u.spendable_at_height(candidate_height)
                && !reserved.contains(&(u.txid.clone(), u.output_index))
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(|u| (u.creation_height, u.txid.clone(), u.output_index));

    let mut selected = Vec::<UtxoState>::new();
    let mut total = 0u64;
    for utxo in candidates {
        total = total
            .checked_add(utxo.amount_strikes)
            .ok_or("balance overflow")?;
        selected.push(utxo);
        let estimated = estimate_send_weight(selected.len(), 2)?;
        let fee = required_base_fee(state.base_fee_rate_q32, estimated as u64)
            .map_err(|e| e.to_string())?;
        if total >= amount.saturating_add(fee) {
            break;
        }
    }
    if selected.is_empty() {
        return Err("no spendable UTXOs; coinbase rewards require 16-block maturity".into());
    }

    let fee_two = required_base_fee(
        state.base_fee_rate_q32,
        estimate_send_weight(selected.len(), 2)? as u64,
    )
    .map_err(|e| e.to_string())?;
    if total < amount.saturating_add(fee_two) {
        return Err(format!(
            "insufficient spendable balance: have {} MUT, need at least {} MUT plus fee",
            format_mut(total),
            format_mut(amount)
        ));
    }
    let change = total - amount - fee_two;

    let mut outputs = vec![TxOutput {
        amount_strikes: amount,
        output_type: OUTPUT_PUBKEY_HASH,
        payload: to_address.to_vec(),
    }];
    if change > 0 {
        outputs.push(TxOutput {
            amount_strikes: change,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: from_address.to_vec(),
        });
    }
    let inputs = selected
        .iter()
        .map(|u| {
            Ok(TxInput::Outpoint {
                previous_txid: decode32(&u.txid)?,
                previous_output_index: u.output_index,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let core = TransactionCoreV1 {
        version: 1,
        network_id: state.network_id,
        valid_from_epoch: candidate_epoch,
        expiry_epoch: 0,
        inputs,
        outputs,
    };
    let txid = core.txid();
    let public = sk.verifying_key().to_bytes();
    let mut witnesses = Vec::with_capacity(selected.len());
    for (i, utxo) in selected.iter().enumerate() {
        let digest = sighash_all(&txid, i as u16, &utxo.prevout()?);
        let signature = sk.sign(&digest.0).to_bytes();
        witnesses.push(WitnessV1::pubkey_hash(public, signature));
    }
    let tx = TransactionV1 { core, witnesses };
    let actual_base = required_base_fee(state.base_fee_rate_q32, tx.serialized_len() as u64)
        .map_err(|e| e.to_string())?;
    let input_sum = selected.iter().try_fold(0u64, |acc, u| {
        acc.checked_add(u.amount_strikes)
            .ok_or("input sum overflow")
    })?;
    let output_sum = tx.core.outputs.iter().try_fold(0u64, |acc, o| {
        acc.checked_add(o.amount_strikes)
            .ok_or("output sum overflow")
    })?;
    let actual_fee = input_sum.checked_sub(output_sum).ok_or("fee underflow")?;
    if actual_fee < actual_base {
        return Err(format!(
            "internal fee construction error: actual fee {actual_fee} below Base Fee {actual_base}"
        ));
    }

    // Self-verify every witness before accepting into our own mempool.
    for (i, utxo) in selected.iter().enumerate() {
        let digest = sighash_all(&tx.txid(), i as u16, &utxo.prevout()?);
        let address = AddressId(decode32(&utxo.payload)?);
        verify_pubkey_hash_witness(&address, &digest.0, &tx.witnesses[i])
            .map_err(|e| format!("self-verification failed: {e}"))?;
    }

    Ok(PendingTxState {
        txid: tx.txid().to_hex(),
        wtxid: tx.wtxid().to_hex(),
        valid_from_epoch: candidate_epoch,
        expiry_epoch: 0,
        inputs: selected
            .iter()
            .map(|u| StoredTxInput {
                previous_txid: u.txid.clone(),
                previous_output_index: u.output_index,
            })
            .collect(),
        outputs: tx
            .core
            .outputs
            .iter()
            .map(|o| StoredTxOutput {
                amount_strikes: o.amount_strikes,
                output_type: o.output_type,
                payload: hex::encode(&o.payload),
            })
            .collect(),
        witnesses: tx
            .witnesses
            .iter()
            .map(|w| StoredWitness {
                witness_type: w.witness_type,
                payload: hex::encode(&w.payload),
            })
            .collect(),
        fee_strikes: actual_fee,
        base_fee_strikes: actual_base,
        from_license: from as u8,
        to_license: to as u8,
        amount_strikes: amount,
    })
}

fn pending_native_license_count(state: &DevnetState) -> Result<usize, String> {
    let mempool_txids = state
        .mempool
        .iter()
        .map(|tx| tx.txid.as_str())
        .collect::<HashSet<_>>();
    state
        .pending_protocol_operations
        .iter()
        .try_fold(0usize, |acc, pending| {
            if !mempool_txids.contains(pending.required_txid.as_str()) {
                return Ok(acc);
            }
            let op = pending.operation()?;
            if op.op_type != OP_LICENSE_PURCHASE_MUT || op.op_version != 1 {
                return Ok(acc);
            }
            let purchase = decode_native_purchase_operation(&op)?;
            acc.checked_add(purchase.manifest.licenses.len())
                .ok_or_else(|| "pending native Mining License count overflow".into())
        })
}

fn create_native_license_purchase(
    state: &DevnetState,
    payer: usize,
    count: usize,
) -> Result<
    (
        PendingTxState,
        PendingProtocolOperationState,
        Vec<LicenseId>,
        u64,
    ),
    String,
> {
    if count == 0 || count > 32 {
        return Err("Build 5.0 Devnet purchase count must be 1..=32".into());
    }
    if payer >= state.licenses.len() {
        return Err("payer license number out of range".into());
    }
    let pending_license_count = pending_native_license_count(state)?;
    let fixture_total = state
        .licenses
        .len()
        .checked_add(pending_license_count)
        .and_then(|v| v.checked_add(count))
        .ok_or("license count overflow")?;
    if fixture_total > 255 {
        return Err("Build 5.0 local deterministic Devnet wallet fixture supports at most 255 generated license keys; validated protocol state itself has no 255-license consensus cap".into());
    }

    let candidate_epoch = next_mineable_epoch(state);
    let candidate_height = state.height + 1;
    let price_each = subsidy(candidate_epoch).max(1);
    let payment_amount = price_each
        .checked_mul(count as u64)
        .ok_or("license purchase amount overflow")?;
    let payer_address = decode32(&state.licenses[payer].payment_address_id)?;

    let next_index = state
        .licenses
        .len()
        .checked_add(pending_license_count)
        .ok_or("license fixture index overflow")?;
    let mut entries = Vec::with_capacity(count);
    for offset in 0..count {
        let index =
            u8::try_from(next_index + offset).map_err(|_| "Devnet license index overflow")?;
        let key = SigningKey::from_bytes(&dev_seed(index))
            .verifying_key()
            .to_bytes();
        entries.push(LicenseManifestEntryV1 {
            owner_public_key: key,
            mining_public_key: key,
        });
    }
    let tip = decode32(&state.tip_hash)?;
    let nonce = sha256_domain(
        domains::MUT_LICENSE_MANIFEST,
        &[
            b"DEVNET-NATIVE-PURCHASE-NONCE",
            &tip,
            &candidate_epoch.to_be_bytes(),
            &(next_index as u32).to_be_bytes(),
            &[payer as u8],
            &[count as u8],
        ],
    )
    .0;
    let manifest = MutLicenseManifestV1 {
        version: 1,
        network_id: DEVNET_NETWORK_ID,
        purchase_nonce: nonce,
        licenses: entries,
    };
    let manifest_hash = manifest.manifest_hash().map_err(|e| e.to_string())?;

    let reserved = mempool_reserved_inputs(state);
    let mut candidates = state
        .utxos
        .iter()
        .filter(|u| {
            u.output_type == OUTPUT_PUBKEY_HASH
                && decode32(&u.payload)
                    .map(|p| p == payer_address)
                    .unwrap_or(false)
                && u.spendable_at_height(candidate_height)
                && !reserved.contains(&(u.txid.clone(), u.output_index))
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(|u| (u.creation_height, u.txid.clone(), u.output_index));

    let mut selected = Vec::<UtxoState>::new();
    let mut total = 0u64;
    for utxo in candidates {
        total = total
            .checked_add(utxo.amount_strikes)
            .ok_or("balance overflow")?;
        selected.push(utxo);
        let estimated = estimate_license_purchase_weight(selected.len(), true)?;
        let fee = required_base_fee(state.base_fee_rate_q32, estimated as u64)
            .map_err(|e| e.to_string())?;
        if total >= payment_amount.saturating_add(fee) {
            break;
        }
    }
    if selected.is_empty() {
        return Err("no spendable UTXOs; coinbase rewards require 16-block maturity".into());
    }
    let fee_two = required_base_fee(
        state.base_fee_rate_q32,
        estimate_license_purchase_weight(selected.len(), true)? as u64,
    )
    .map_err(|e| e.to_string())?;
    if total < payment_amount.saturating_add(fee_two) {
        return Err(format!(
            "insufficient spendable balance: have {} MUT, need {} MUT plus fee",
            format_mut(total),
            format_mut(payment_amount)
        ));
    }
    let change = total - payment_amount - fee_two;
    let mut outputs = vec![TxOutput {
        amount_strikes: payment_amount,
        output_type: OUTPUT_LICENSE_PAYMENT,
        payload: manifest_hash.0.to_vec(),
    }];
    if change > 0 {
        outputs.push(TxOutput {
            amount_strikes: change,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: payer_address.to_vec(),
        });
    }
    let inputs = selected
        .iter()
        .map(|u| {
            Ok(TxInput::Outpoint {
                previous_txid: decode32(&u.txid)?,
                previous_output_index: u.output_index,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let core = TransactionCoreV1 {
        version: 1,
        network_id: DEVNET_NETWORK_ID,
        valid_from_epoch: candidate_epoch,
        expiry_epoch: 0,
        inputs,
        outputs,
    };
    let txid = core.txid();
    let sk = dev_owner_signing_key_for_license(&state.licenses[payer])
        .ok_or("local Devnet wallet does not hold the current owner private key for the payer Mining License")?;
    let public = sk.verifying_key().to_bytes();
    let mut witnesses = Vec::with_capacity(selected.len());
    for (i, utxo) in selected.iter().enumerate() {
        let digest = sighash_all(&txid, i as u16, &utxo.prevout()?);
        witnesses.push(WitnessV1::pubkey_hash(
            public,
            sk.sign(&digest.0).to_bytes(),
        ));
    }
    let tx = TransactionV1 { core, witnesses };
    let actual_base = required_base_fee(state.base_fee_rate_q32, tx.serialized_len() as u64)
        .map_err(|e| e.to_string())?;
    let input_sum = selected.iter().try_fold(0u64, |acc, u| {
        acc.checked_add(u.amount_strikes)
            .ok_or("input sum overflow")
    })?;
    let output_sum = tx.core.outputs.iter().try_fold(0u64, |acc, o| {
        acc.checked_add(o.amount_strikes)
            .ok_or("output sum overflow")
    })?;
    let actual_fee = input_sum.checked_sub(output_sum).ok_or("fee underflow")?;
    if actual_fee < actual_base {
        return Err("internal native license purchase fee construction error".into());
    }
    for (i, utxo) in selected.iter().enumerate() {
        let digest = sighash_all(&tx.txid(), i as u16, &utxo.prevout()?);
        let address = AddressId(decode32(&utxo.payload)?);
        verify_pubkey_hash_witness(&address, &digest.0, &tx.witnesses[i])
            .map_err(|e| format!("native purchase self-verification failed: {e}"))?;
    }

    let purchase = LicensePurchaseMutV1 {
        payment_txid: tx.txid(),
        payment_output_index: 0,
        manifest,
    };
    let ids = purchase.license_ids().map_err(|e| e.to_string())?;
    let operation = purchase.operation().map_err(|e| e.to_string())?;
    let pending = PendingTxState {
        txid: tx.txid().to_hex(),
        wtxid: tx.wtxid().to_hex(),
        valid_from_epoch: candidate_epoch,
        expiry_epoch: 0,
        inputs: selected
            .iter()
            .map(|u| StoredTxInput {
                previous_txid: u.txid.clone(),
                previous_output_index: u.output_index,
            })
            .collect(),
        outputs: tx
            .core
            .outputs
            .iter()
            .map(|o| StoredTxOutput {
                amount_strikes: o.amount_strikes,
                output_type: o.output_type,
                payload: hex::encode(&o.payload),
            })
            .collect(),
        witnesses: tx
            .witnesses
            .iter()
            .map(|w| StoredWitness {
                witness_type: w.witness_type,
                payload: hex::encode(&w.payload),
            })
            .collect(),
        fee_strikes: actual_fee,
        base_fee_strikes: actual_base,
        from_license: payer as u8,
        to_license: payer as u8,
        amount_strikes: payment_amount,
    };
    let pending_op = PendingProtocolOperationState {
        operation: hex::encode(operation.encode()),
        required_txid: tx.txid().to_hex(),
    };
    Ok((pending, pending_op, ids, price_each))
}

fn create_native_license_purchase_with_signer(
    state: &DevnetState,
    payer: usize,
    entries: Vec<LicenseManifestEntryV1>,
    sk: &SigningKey,
) -> Result<
    (
        PendingTxState,
        PendingProtocolOperationState,
        Vec<LicenseId>,
        u64,
    ),
    String,
> {
    let count = entries.len();
    if count == 0 || count > 32 {
        return Err(
            "secure native purchase requires 1..=32 encrypted owner/mining key pairs".into(),
        );
    }
    if payer >= state.licenses.len() {
        return Err("payer license number out of range".into());
    }
    if sk.verifying_key().to_bytes() != decode32(&state.licenses[payer].owner_public_key)? {
        return Err(
            "provided signing key does not match the current on-chain owner authority".into(),
        );
    }

    let candidate_epoch = next_mineable_epoch(state);
    let candidate_height = state.height + 1;
    let price_each = subsidy(candidate_epoch).max(1);
    let payment_amount = price_each
        .checked_mul(count as u64)
        .ok_or("license purchase amount overflow")?;
    let payer_address = decode32(&state.licenses[payer].payment_address_id)?;

    let mut keyset_bytes = Vec::with_capacity(count * 64);
    for entry in &entries {
        keyset_bytes.extend_from_slice(&entry.owner_public_key);
        keyset_bytes.extend_from_slice(&entry.mining_public_key);
    }
    let keyset_hash = sha256_domain(
        domains::MUT_LICENSE_MANIFEST,
        &[b"BUILD56-SECURE-NATIVE-KEYSET-V1", keyset_bytes.as_slice()],
    );
    let tip = decode32(&state.tip_hash)?;
    let epoch_be = candidate_epoch.to_be_bytes();
    let payer_be = u32::try_from(payer)
        .map_err(|_| "payer license index overflow")?
        .to_be_bytes();
    let count_be = u32::try_from(count)
        .map_err(|_| "secure purchase count overflow")?
        .to_be_bytes();
    let nonce = sha256_domain(
        domains::MUT_LICENSE_MANIFEST,
        &[
            b"BUILD56-SECURE-NATIVE-PURCHASE-NONCE-V1",
            &tip,
            &epoch_be,
            &payer_be,
            &count_be,
            &keyset_hash.0,
        ],
    )
    .0;
    let manifest = MutLicenseManifestV1 {
        version: 1,
        network_id: state.network_id,
        purchase_nonce: nonce,
        licenses: entries,
    };
    let manifest_hash = manifest.manifest_hash().map_err(|e| e.to_string())?;

    let reserved = mempool_reserved_inputs(state);
    let mut candidates = state
        .utxos
        .iter()
        .filter(|u| {
            u.output_type == OUTPUT_PUBKEY_HASH
                && decode32(&u.payload)
                    .map(|p| p == payer_address)
                    .unwrap_or(false)
                && u.spendable_at_height(candidate_height)
                && !reserved.contains(&(u.txid.clone(), u.output_index))
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(|u| (u.creation_height, u.txid.clone(), u.output_index));

    let mut selected = Vec::<UtxoState>::new();
    let mut total = 0u64;
    for utxo in candidates {
        total = total
            .checked_add(utxo.amount_strikes)
            .ok_or("balance overflow")?;
        selected.push(utxo);
        let estimated = estimate_license_purchase_weight(selected.len(), true)?;
        let fee = required_base_fee(state.base_fee_rate_q32, estimated as u64)
            .map_err(|e| e.to_string())?;
        if total >= payment_amount.saturating_add(fee) {
            break;
        }
    }
    if selected.is_empty() {
        return Err("no spendable UTXOs for secure native purchase".into());
    }
    let fee_two = required_base_fee(
        state.base_fee_rate_q32,
        estimate_license_purchase_weight(selected.len(), true)? as u64,
    )
    .map_err(|e| e.to_string())?;
    if total < payment_amount.saturating_add(fee_two) {
        return Err(format!(
            "insufficient spendable balance: have {} MUT, need {} MUT plus fee",
            format_mut(total),
            format_mut(payment_amount)
        ));
    }
    let change = total - payment_amount - fee_two;
    let mut outputs = vec![TxOutput {
        amount_strikes: payment_amount,
        output_type: OUTPUT_LICENSE_PAYMENT,
        payload: manifest_hash.0.to_vec(),
    }];
    if change > 0 {
        outputs.push(TxOutput {
            amount_strikes: change,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: payer_address.to_vec(),
        });
    }
    let inputs = selected
        .iter()
        .map(|u| {
            Ok(TxInput::Outpoint {
                previous_txid: decode32(&u.txid)?,
                previous_output_index: u.output_index,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let core = TransactionCoreV1 {
        version: 1,
        network_id: state.network_id,
        valid_from_epoch: candidate_epoch,
        expiry_epoch: 0,
        inputs,
        outputs,
    };
    let txid = core.txid();
    let public = sk.verifying_key().to_bytes();
    let mut witnesses = Vec::with_capacity(selected.len());
    for (i, utxo) in selected.iter().enumerate() {
        let digest = sighash_all(&txid, i as u16, &utxo.prevout()?);
        witnesses.push(WitnessV1::pubkey_hash(
            public,
            sk.sign(&digest.0).to_bytes(),
        ));
    }
    let tx = TransactionV1 { core, witnesses };
    let actual_base = required_base_fee(state.base_fee_rate_q32, tx.serialized_len() as u64)
        .map_err(|e| e.to_string())?;
    let input_sum = selected.iter().try_fold(0u64, |acc, u| {
        acc.checked_add(u.amount_strikes)
            .ok_or("input sum overflow")
    })?;
    let output_sum = tx.core.outputs.iter().try_fold(0u64, |acc, o| {
        acc.checked_add(o.amount_strikes)
            .ok_or("output sum overflow")
    })?;
    let actual_fee = input_sum.checked_sub(output_sum).ok_or("fee underflow")?;
    if actual_fee < actual_base {
        return Err("internal secure native license purchase fee construction error".into());
    }
    for (i, utxo) in selected.iter().enumerate() {
        let digest = sighash_all(&tx.txid(), i as u16, &utxo.prevout()?);
        let address = AddressId(decode32(&utxo.payload)?);
        verify_pubkey_hash_witness(&address, &digest.0, &tx.witnesses[i])
            .map_err(|e| format!("secure native purchase self-verification failed: {e}"))?;
    }

    let purchase = LicensePurchaseMutV1 {
        payment_txid: tx.txid(),
        payment_output_index: 0,
        manifest,
    };
    let ids = purchase.license_ids().map_err(|e| e.to_string())?;
    let operation = purchase.operation().map_err(|e| e.to_string())?;
    let pending = PendingTxState {
        txid: tx.txid().to_hex(),
        wtxid: tx.wtxid().to_hex(),
        valid_from_epoch: candidate_epoch,
        expiry_epoch: 0,
        inputs: selected
            .iter()
            .map(|u| StoredTxInput {
                previous_txid: u.txid.clone(),
                previous_output_index: u.output_index,
            })
            .collect(),
        outputs: tx
            .core
            .outputs
            .iter()
            .map(|o| StoredTxOutput {
                amount_strikes: o.amount_strikes,
                output_type: o.output_type,
                payload: hex::encode(&o.payload),
            })
            .collect(),
        witnesses: tx
            .witnesses
            .iter()
            .map(|w| StoredWitness {
                witness_type: w.witness_type,
                payload: hex::encode(&w.payload),
            })
            .collect(),
        fee_strikes: actual_fee,
        base_fee_strikes: actual_base,
        from_license: payer as u8,
        to_license: payer as u8,
        amount_strikes: payment_amount,
    };
    let pending_op = PendingProtocolOperationState {
        operation: hex::encode(operation.encode()),
        required_txid: tx.txid().to_hex(),
    };
    Ok((pending, pending_op, ids, price_each))
}

fn dev_key_slot_public_key(slot_text: &str) -> Result<[u8; 32], String> {
    let slot: u16 = slot_text
        .parse()
        .map_err(|_| "Devnet key slot must be an integer in 1..=256")?;
    if !(1..=256).contains(&slot) {
        return Err("Devnet key slot must be in 1..=256".into());
    }
    Ok(SigningKey::from_bytes(&dev_seed((slot - 1) as u8))
        .verifying_key()
        .to_bytes())
}

fn ensure_no_pending_authority_operation(
    state: &DevnetState,
    license_id: &[u8; 32],
) -> Result<(), String> {
    for pending in &state.pending_protocol_operations {
        let op = pending.operation()?;
        if authority_operation_license_id(&op)?.is_some_and(|id| id.0 == *license_id) {
            return Err("a pending authority operation already targets this Mining License; confirm or remove it before queuing another".into());
        }
    }
    Ok(())
}

fn create_license_transfer_operation(
    state: &DevnetState,
    license_index: usize,
    new_owner_public_key: [u8; 32],
    new_mining_public_key: [u8; 32],
) -> Result<
    (
        PendingTxState,
        PendingProtocolOperationState,
        ProtocolOperationV1,
    ),
    String,
> {
    let owner_key = state
        .licenses
        .get(license_index)
        .and_then(dev_owner_signing_key_for_license)
        .ok_or("local Devnet wallet does not hold the current owner private key for this Mining License")?;
    create_license_transfer_operation_with_signer(
        state,
        license_index,
        new_owner_public_key,
        new_mining_public_key,
        &owner_key,
    )
}

fn create_license_transfer_operation_with_signer(
    state: &DevnetState,
    license_index: usize,
    new_owner_public_key: [u8; 32],
    new_mining_public_key: [u8; 32],
    owner_key: &SigningKey,
) -> Result<
    (
        PendingTxState,
        PendingProtocolOperationState,
        ProtocolOperationV1,
    ),
    String,
> {
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    let license_id = decode32(&license.license_id)?;
    ensure_no_pending_authority_operation(state, &license_id)?;
    if owner_key.verifying_key().to_bytes() != decode32(&license.owner_public_key)? {
        return Err(
            "provided signing key does not match the current on-chain owner authority".into(),
        );
    }
    let mut transfer = LicenseTransferV1 {
        license_id: LicenseId(license_id),
        expected_owner_sequence: license.owner_key_sequence,
        expected_mining_sequence: license.mining_key_sequence,
        new_owner_public_key,
        new_mining_public_key,
        owner_signature: [0u8; 64],
    };
    transfer.owner_signature = owner_key.sign(&transfer.signing_digest().0).to_bytes();
    let operation = transfer.operation();
    let fee_marker = authority_fee_marker(&license_id);
    let fee_tx = create_send_transaction_with_signer(
        state,
        license_index,
        license_index,
        fee_marker,
        owner_key,
    )?;
    let pending_op = PendingProtocolOperationState {
        operation: hex::encode(operation.encode()),
        required_txid: fee_tx.txid.clone(),
    };
    Ok((fee_tx, pending_op, operation))
}

fn create_mining_key_rotation_operation(
    state: &DevnetState,
    license_index: usize,
    new_mining_public_key: [u8; 32],
) -> Result<
    (
        PendingTxState,
        PendingProtocolOperationState,
        ProtocolOperationV1,
    ),
    String,
> {
    let owner_key = state
        .licenses
        .get(license_index)
        .and_then(dev_owner_signing_key_for_license)
        .ok_or("local Devnet wallet does not hold the current owner private key for this Mining License")?;
    create_mining_key_rotation_operation_with_signer(
        state,
        license_index,
        new_mining_public_key,
        &owner_key,
    )
}

fn create_mining_key_rotation_operation_with_signer(
    state: &DevnetState,
    license_index: usize,
    new_mining_public_key: [u8; 32],
    owner_key: &SigningKey,
) -> Result<
    (
        PendingTxState,
        PendingProtocolOperationState,
        ProtocolOperationV1,
    ),
    String,
> {
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    let license_id = decode32(&license.license_id)?;
    ensure_no_pending_authority_operation(state, &license_id)?;
    if owner_key.verifying_key().to_bytes() != decode32(&license.owner_public_key)? {
        return Err(
            "provided signing key does not match the current on-chain owner authority".into(),
        );
    }
    let mut rotation = MiningKeyRotateV1 {
        license_id: LicenseId(license_id),
        expected_owner_sequence: license.owner_key_sequence,
        expected_mining_sequence: license.mining_key_sequence,
        new_mining_public_key,
        owner_signature: [0u8; 64],
    };
    rotation.owner_signature = owner_key.sign(&rotation.signing_digest().0).to_bytes();
    let operation = rotation.operation();
    let fee_marker = authority_fee_marker(&license_id);
    let fee_tx = create_send_transaction_with_signer(
        state,
        license_index,
        license_index,
        fee_marker,
        owner_key,
    )?;
    let pending_op = PendingProtocolOperationState {
        operation: hex::encode(operation.encode()),
        required_txid: fee_tx.txid.clone(),
    };
    Ok((fee_tx, pending_op, operation))
}

fn estimate_license_purchase_weight(
    input_count: usize,
    with_change: bool,
) -> Result<usize, String> {
    if input_count == 0 {
        return Err("invalid native purchase input shape".into());
    }
    let inputs = (0..input_count)
        .map(|i| TxInput::Outpoint {
            previous_txid: [i as u8; 32],
            previous_output_index: i as u16,
        })
        .collect::<Vec<_>>();
    let mut outputs = vec![TxOutput {
        amount_strikes: 1,
        output_type: OUTPUT_LICENSE_PAYMENT,
        payload: vec![0u8; 32],
    }];
    if with_change {
        outputs.push(TxOutput {
            amount_strikes: 1,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: vec![0u8; 32],
        });
    }
    let witnesses = (0..input_count)
        .map(|_| WitnessV1::pubkey_hash([0u8; 32], [0u8; 64]))
        .collect::<Vec<_>>();
    Ok(TransactionV1 {
        core: TransactionCoreV1 {
            version: 1,
            network_id: DEVNET_NETWORK_ID,
            valid_from_epoch: 1,
            expiry_epoch: 0,
            inputs,
            outputs,
        },
        witnesses,
    }
    .serialized_len())
}

fn estimate_send_weight(input_count: usize, output_count: usize) -> Result<usize, String> {
    if input_count == 0 || output_count == 0 || output_count > 2 {
        return Err("invalid send weight shape".into());
    }
    let inputs = (0..input_count)
        .map(|i| TxInput::Outpoint {
            previous_txid: [i as u8; 32],
            previous_output_index: i as u16,
        })
        .collect::<Vec<_>>();
    let outputs = (0..output_count)
        .map(|_| TxOutput {
            amount_strikes: 1,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: vec![0u8; 32],
        })
        .collect::<Vec<_>>();
    let witnesses = (0..input_count)
        .map(|_| WitnessV1::pubkey_hash([0u8; 32], [0u8; 64]))
        .collect::<Vec<_>>();
    Ok(TransactionV1 {
        core: TransactionCoreV1 {
            version: 1,
            network_id: DEVNET_NETWORK_ID,
            valid_from_epoch: 1,
            expiry_epoch: 0,
            inputs,
            outputs,
        },
        witnesses,
    }
    .serialized_len())
}

fn mempool_reserved_inputs(state: &DevnetState) -> HashSet<(String, u16)> {
    state
        .mempool
        .iter()
        .flat_map(|tx| {
            tx.inputs
                .iter()
                .map(|i| (i.previous_txid.clone(), i.previous_output_index))
        })
        .collect()
}

fn block_body_weight(
    txs: &[TransactionV1],
    operations: &[ProtocolOperationV1],
) -> Result<u64, String> {
    let mut weight = varuint_len(txs.len() as u64) as u64;
    for tx in txs {
        weight = weight
            .checked_add(tx.serialized_len() as u64)
            .ok_or("block weight overflow")?;
    }
    weight = weight
        .checked_add(varuint_len(operations.len() as u64) as u64)
        .ok_or("block weight overflow")?;
    for op in operations {
        weight = weight
            .checked_add(op.encode().len() as u64)
            .ok_or("block weight overflow")?;
    }
    Ok(weight)
}

fn varuint_len(mut value: u64) -> usize {
    let mut len = 1usize;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn adjusted_base_fee_rate(current: u64, block_weight: u64) -> Result<u64, String> {
    if block_weight == BLOCK_WEIGHT_TARGET {
        return Ok(current);
    }
    let (difference, increase) = if block_weight > BLOCK_WEIGHT_TARGET {
        (block_weight - BLOCK_WEIGHT_TARGET, true)
    } else {
        (BLOCK_WEIGHT_TARGET - block_weight, false)
    };
    let numerator = (current as u128)
        .checked_mul(difference as u128)
        .ok_or("Base Fee multiplication overflow")?;
    let denominator = 64u128 * BLOCK_WEIGHT_TARGET as u128;
    let delta = u64::try_from(numerator / denominator).map_err(|_| "Base Fee delta overflow")?;
    if increase {
        Ok(current.saturating_add(delta).min(BASE_FEE_MAX_Q32))
    } else {
        Ok(current.saturating_sub(delta).max(BASE_FEE_MIN_Q32))
    }
}

fn append_difficulty_result(state: &mut DevnetState, success: bool) -> Result<(), String> {
    append_history_values(
        &mut state.difficulty_history_count,
        &mut state.difficulty_history_bitmap,
        &mut state.difficulty_correction_q32,
        success,
    )
}

fn append_history_values(
    count: &mut u8,
    bitmap: &mut u64,
    correction: &mut u64,
    success: bool,
) -> Result<(), String> {
    let result = u64::from(success);
    if *count < 64 {
        *bitmap |= result << *count;
        *count += 1;
    } else {
        *bitmap = (*bitmap >> 1) | (result << 63);
    }
    let r = *count as u64;
    let s = bitmap.count_ones() as u64;
    if 64u64.saturating_mul(s) < 40u64.saturating_mul(r) {
        *correction =
            correction_step(*correction, DIFFICULTY_EASIER_STEP_Q32)?.min(DIFFICULTY_C_MAX_Q32);
    } else if 64u64.saturating_mul(s) > 41u64.saturating_mul(r) {
        *correction =
            correction_step(*correction, DIFFICULTY_HARDER_STEP_Q32)?.max(DIFFICULTY_C_MIN_Q32);
    }
    Ok(())
}

fn correction_step(current: u64, multiplier_q32: u64) -> Result<u64, String> {
    let value = ((current as u128) * (multiplier_q32 as u128)) >> 32;
    u64::try_from(value).map_err(|_| "difficulty correction overflow".into())
}

fn refresh_current_state_root(state: &mut DevnetState) -> Result<(), String> {
    let root = compute_state_root(
        state,
        &state.utxos,
        state.height,
        state.total_issued_strikes,
        state.difficulty_history_count,
        state.difficulty_history_bitmap,
        state.difficulty_correction_q32,
        state.base_fee_rate_q32,
    )?;
    state.current_state_root = hex::encode(root);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compute_state_root(
    state: &DevnetState,
    utxos: &[UtxoState],
    height: u64,
    total_issued: u64,
    difficulty_count: u8,
    difficulty_bitmap: u64,
    difficulty_correction: u64,
    base_fee_rate: u64,
) -> Result<[u8; 32], String> {
    let utxo_root = compute_utxo_root(utxos)?;
    let license_root = compute_license_root(state)?;
    let external_payment_root = compute_external_payment_root(state)?;
    let protocol_root =
        compute_protocol_state_root(state, utxos, difficulty_count, difficulty_bitmap)?;
    let meta_root = ConsensusMetaV1 {
        block_height: height,
        eligible_license_count: eligible_license_count(state, state.tip_epoch),
        total_licenses_issued: state.licenses.len() as u64,
        difficulty_correction_q32: difficulty_correction,
        base_fee_rate_q32: base_fee_rate,
        total_issued_strikes: total_issued,
    }
    .root();
    Ok(state_root(
        &utxo_root.0,
        &license_root.0,
        &external_payment_root.0,
        &protocol_root.0,
        &meta_root.0,
    )
    .0)
}

fn compute_utxo_root(utxos: &[UtxoState]) -> Result<Hash256, String> {
    let mut entries = BTreeMap::<[u8; 32], [u8; 32]>::new();
    for u in utxos {
        let txid = TxId(decode32(&u.txid)?);
        let key = utxo_key(&txid, u.output_index);
        let leaf = utxo_leaf(&key.0, &u.value()?);
        if entries.insert(key.0, leaf.0).is_some() {
            return Err("duplicate UTXO key".into());
        }
    }
    Ok(sparse_root(&entries))
}

fn compute_license_root(state: &DevnetState) -> Result<Hash256, String> {
    let mut entries = BTreeMap::<[u8; 32], [u8; 32]>::new();
    for l in &state.licenses {
        let license_id = LicenseId(decode32(&l.license_id)?);
        let record = l.record()?;
        let leaf = license_leaf(&license_id, &record).map_err(|e| e.to_string())?;
        entries.insert(license_id.0, leaf.0);
    }
    Ok(sparse_root(&entries))
}

fn compute_external_payment_root(state: &DevnetState) -> Result<Hash256, String> {
    let mut entries = BTreeMap::<[u8; 32], [u8; 32]>::new();
    for payment in &state.consumed_bitcoin_payments {
        let payment_id = decode32(&payment.payment_id)?;
        let leaf = external_payment_leaf(&payment_id, &payment.value_bytes()?);
        if entries.insert(payment_id, leaf.0).is_some() {
            return Err("duplicate BitcoinPaymentID ExternalPayment key".into());
        }
    }
    Ok(sparse_root(&entries))
}

fn compute_protocol_state_root(
    state: &DevnetState,
    utxos: &[UtxoState],
    difficulty_count: u8,
    difficulty_bitmap: u64,
) -> Result<Hash256, String> {
    let treasury = dividends::treasury_state(state, utxos)?;
    let zero = [0u8; 32];
    let treasury_key = protocol_state_key(PS_TREASURY_STATE, &zero);
    let treasury_value = treasury.encode();
    let treasury_leaf = protocol_state_leaf(&treasury_key.0, &treasury_value);

    let difficulty_key = protocol_state_key(PS_DIFFICULTY_HISTORY, &zero);
    let mut difficulty_value = [0u8; 9];
    difficulty_value[0] = difficulty_count;
    difficulty_value[1..].copy_from_slice(&difficulty_bitmap.to_be_bytes());
    let difficulty_leaf = protocol_state_leaf(&difficulty_key.0, &difficulty_value);

    let mut entries = BTreeMap::<[u8; 32], [u8; 32]>::new();
    entries.insert(treasury_key.0, treasury_leaf.0);
    entries.insert(difficulty_key.0, difficulty_leaf.0);
    for account_state in &state.dividend_accounts {
        let account = account_state.account()?;
        let key = protocol_state_key(PS_DIVIDEND_ACCOUNT, &account.license_id.0);
        let value = account.encode();
        let leaf = protocol_state_leaf(&key.0, &value);
        if entries.insert(key.0, leaf.0).is_some() {
            return Err("duplicate dividend-account protocol-state key".into());
        }
    }
    for evidence_hex in &state.consumed_evidence {
        let evidence_id = decode32(evidence_hex)?;
        let key = protocol_state_key(PS_CONSUMED_EVIDENCE, &evidence_id);
        let leaf = protocol_state_leaf(&key.0, &[]);
        if entries.insert(key.0, leaf.0).is_some() {
            return Err("duplicate consumed EvidenceID protocol-state key".into());
        }
    }
    for event in &state.offense_events {
        let evidence_id = decode32(&event.evidence_id)?;
        let key = protocol_state_key(PS_OFFENSE_EVENT, &evidence_id);
        let value = event.value_bytes()?;
        let leaf = protocol_state_leaf(&key.0, &value);
        if entries.insert(key.0, leaf.0).is_some() {
            return Err("duplicate active-offense protocol-state key".into());
        }
    }
    for payment_hex in &state.consumed_native_payments {
        let payment_id = decode32(payment_hex)?;
        let key = protocol_state_key(PS_CONSUMED_NATIVE_PAYMENT, &payment_id);
        // Consumed-payment objects are presence-only in the integrated Devnet engine.
        // The object ID is the NativePaymentID; the canonical value is the empty byte string.
        let leaf = protocol_state_leaf(&key.0, &[]);
        if entries.insert(key.0, leaf.0).is_some() {
            return Err("duplicate consumed NativePaymentID protocol-state key".into());
        }
    }
    for historical in &state.historical_license_keys {
        // ProtocolState type 0x0003 uses the authority-changing OperationID as ObjectID.
        let operation_id = decode32(&historical.operation_id)?;
        let key = protocol_state_key(PS_HISTORICAL_LICENSE_KEY, &operation_id);
        let value = historical.value_bytes()?;
        let leaf = protocol_state_leaf(&key.0, &value);
        if entries.insert(key.0, leaf.0).is_some() {
            return Err("duplicate historical-license-key protocol-state key".into());
        }
    }
    for presence_state in &state.mining_presence {
        let license_id = decode32(&presence_state.license_id)?;
        let key = protocol_state_key(PS_MINING_PRESENCE_STATE, &license_id);
        let value = presence_state
            .value()?
            .encode()
            .map_err(|e| e.to_string())?;
        let leaf = protocol_state_leaf(&key.0, &value);
        if entries.insert(key.0, leaf.0).is_some() {
            return Err("duplicate mining-presence protocol-state key".into());
        }
    }
    bitcoin_headers::insert_protocol_state_entries(state, &mut entries)?;
    Ok(sparse_root(&entries))
}

fn treasury_id_for_network(network_id: u32) -> [u8; 32] {
    sha256_domain(domains::TREASURY_ID, &[&network_id.to_be_bytes()]).0
}

#[cfg(test)]
fn treasury_id() -> [u8; 32] {
    treasury_id_for_network(DEVNET_NETWORK_ID)
}

fn check_state(state: &DevnetState) -> Result<(), String> {
    let valid_tuple = (state.network_id == DEVNET_NETWORK_ID
        && (state.format_version < 10 || state.genesis_hash == DEVNET_GENESIS_ID_HEX))
        || (state.network_id == MAINNET_NETWORK_ID
            && state.genesis_hash == hex::encode(MAINNET_GENESIS_ID));
    if !valid_tuple || state.motto != MOTTO {
        return Err("network identity mismatch".into());
    }
    let expected_tip = state
        .blocks
        .last()
        .map(|b| b.block_hash.clone())
        .unwrap_or_else(|| state.genesis_hash.clone());
    if state.tip_hash != expected_tip {
        return Err("tip hash does not match block history".into());
    }
    if state.height != state.blocks.len() as u64 {
        return Err("height does not match block count".into());
    }
    let mut license_ids = HashSet::new();
    for license in &state.licenses {
        license.record()?.validate().map_err(|e| e.to_string())?;
        if !license_ids.insert(license.license_id.clone()) {
            return Err("duplicate LicenseID in license registry".into());
        }
        let owner = decode32(&license.owner_public_key)?;
        if decode32(&license.payment_address_id)? != address_id(&owner).0 {
            return Err(
                "Mining License payment address is not derived from current owner key".into(),
            );
        }
    }
    let mut payment_ids = HashSet::new();
    for payment in &state.consumed_native_payments {
        decode32(payment)?;
        if !payment_ids.insert(payment.clone()) {
            return Err("duplicate consumed NativePaymentID".into());
        }
    }
    bitcoin::check_state(state)?;
    bitcoin_headers::check_state(state)?;
    punishment::check_state(state)?;
    dividends::check_state(state)?;
    presence::check_state(state)?;
    let mut historical_ids = HashSet::new();
    for historical in &state.historical_license_keys {
        decode32(&historical.operation_id)?;
        decode32(&historical.license_id)?;
        decode32(&historical.owner_public_key)?;
        decode32(&historical.mining_public_key)?;
        if !historical_ids.insert(historical.operation_id.clone()) {
            return Err("duplicate historical-license-key OperationID".into());
        }
    }
    let total_utxo = state.utxos.iter().try_fold(0u128, |acc, u| {
        acc.checked_add(u.amount_strikes as u128)
            .ok_or("UTXO supply overflow")
    })?;
    if total_utxo != state.total_issued_strikes as u128 {
        return Err(format!(
            "supply invariant failed: UTXOs={} Strikes, issued={} Strikes",
            total_utxo, state.total_issued_strikes
        ));
    }
    let root = compute_state_root(
        state,
        &state.utxos,
        state.height,
        state.total_issued_strikes,
        state.difficulty_history_count,
        state.difficulty_history_bitmap,
        state.difficulty_correction_q32,
        state.base_fee_rate_q32,
    )?;
    if hex::encode(root) != state.current_state_root {
        return Err("current StateRoot mismatch".into());
    }
    Ok(())
}

fn print_balances(state: &DevnetState) -> Result<(), String> {
    let candidate_height = state.height + 1;
    let reserved = mempool_reserved_inputs(state);
    let mut sum_total = 0u64;
    for l in &state.licenses {
        let address = decode32(&l.payment_address_id)?;
        let mut total = 0u64;
        let mut spendable = 0u64;
        let mut immature = 0u64;
        let mut reserved_amount = 0u64;
        for u in &state.utxos {
            if u.output_type != OUTPUT_PUBKEY_HASH || decode32(&u.payload)? != address {
                continue;
            }
            total = total
                .checked_add(u.amount_strikes)
                .ok_or("balance overflow")?;
            if reserved.contains(&(u.txid.clone(), u.output_index)) {
                reserved_amount = reserved_amount
                    .checked_add(u.amount_strikes)
                    .ok_or("balance overflow")?;
            } else if u.spendable_at_height(candidate_height) {
                spendable = spendable
                    .checked_add(u.amount_strikes)
                    .ok_or("balance overflow")?;
            } else {
                immature = immature
                    .checked_add(u.amount_strikes)
                    .ok_or("balance overflow")?;
            }
        }
        sum_total = sum_total.checked_add(total).ok_or("balance overflow")?;
        println!(
            "license {:02}  {}  total {:>14} MUT  spendable {:>14}  immature {:>14}  reserved {:>14}",
            l.index + 1,
            &l.license_id[..16],
            format_mut(total),
            format_mut(spendable),
            format_mut(immature),
            format_mut(reserved_amount)
        );
    }
    let treasury_total = dividends::treasury_total(&state.utxos)?;
    let treasury = dividends::treasury_state(state, &state.utxos)?;
    println!("Treasury total:     {} MUT", format_mut(treasury_total));
    println!(
        "Treasury available: {} MUT",
        format_mut(treasury.available_strikes)
    );
    println!(
        "Treasury reserved:  {} MUT",
        format_mut(treasury.reserved_dividend_strikes)
    );
    println!("Wallet total: {} MUT", format_mut(sum_total));
    println!(
        "Issued:       {} MUT",
        format_mut(state.total_issued_strikes)
    );
    Ok(())
}

fn print_utxos(state: &DevnetState, license: Option<usize>) -> Result<(), String> {
    let candidate_height = state.height + 1;
    let filter_address = license
        .map(|i| {
            state
                .licenses
                .get(i)
                .ok_or_else(|| "license number out of range".to_string())
                .and_then(|l| decode32(&l.payment_address_id))
        })
        .transpose()?;
    for u in &state.utxos {
        if let Some(addr) = filter_address {
            if u.output_type != OUTPUT_PUBKEY_HASH || decode32(&u.payload)? != addr {
                continue;
            }
        }
        let kind = if u.output_type == OUTPUT_TREASURY {
            "TREASURY"
        } else if u.output_type == OUTPUT_LICENSE_PAYMENT {
            "LICENSE_PAYMENT"
        } else if u.coinbase {
            "COINBASE"
        } else {
            "PAYMENT"
        };
        println!(
            "{}:{}  {:>12} MUT  {}  h={} e={}  {}",
            &u.txid[..16],
            u.output_index,
            format_mut(u.amount_strikes),
            kind,
            u.creation_height,
            u.creation_epoch,
            if u.spendable_at_height(candidate_height) {
                "spendable"
            } else {
                "immature"
            }
        );
    }
    Ok(())
}

fn print_mempool(state: &DevnetState) {
    if state.mempool.is_empty() {
        println!("Mempool is empty.");
    }
    for tx in &state.mempool {
        println!(
            "{}  L{:02}->L{:02}  {} MUT  fee {} Strikes  inputs {}",
            tx.txid,
            tx.from_license + 1,
            tx.to_license + 1,
            format_mut(tx.amount_strikes),
            tx.fee_strikes,
            tx.inputs.len()
        );
    }
    if !state.pending_protocol_operations.is_empty() {
        println!(
            "Pending protocol operations: {}",
            state.pending_protocol_operations.len()
        );
        for pending in &state.pending_protocol_operations {
            if let Ok(op) = pending.operation() {
                println!("  0x{:04x}  {}", op.op_type, op.operation_id().to_hex());
            }
        }
    }
}

fn print_tx(state: &DevnetState, query: &str) -> Result<(), String> {
    let matches = state
        .mempool
        .iter()
        .filter(|t| t.txid.starts_with(query))
        .map(|t| (t, None))
        .chain(
            state
                .confirmed_transactions
                .iter()
                .filter(|r| r.tx.txid.starts_with(query))
                .map(|r| (&r.tx, Some(r))),
        )
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err("transaction not found".into());
    }
    if matches.len() > 1 {
        return Err("transaction prefix is ambiguous; provide more TXID characters".into());
    }
    let (tx, confirmed) = matches[0];
    println!("TXID:      {}", tx.txid);
    println!("WTXID:     {}", tx.wtxid);
    println!(
        "Transfer:  license {} -> license {}",
        tx.from_license + 1,
        tx.to_license + 1
    );
    println!("Amount:    {} MUT", format_mut(tx.amount_strikes));
    println!("Fee:       {} Strikes", tx.fee_strikes);
    println!("Base Fee:  {} Strikes", tx.base_fee_strikes);
    println!("Inputs:    {}", tx.inputs.len());
    println!("Outputs:   {}", tx.outputs.len());
    match confirmed {
        Some(r) => {
            println!("Status:    CONFIRMED");
            println!("Block:     {}", r.block_height);
            println!("Epoch:     {}", r.block_epoch);
            println!("BlockHash: {}", r.block_hash);
        }
        None => println!("Status:    MEMPOOL"),
    }
    Ok(())
}

fn parse_license_number(s: &str, license_count: usize) -> Result<usize, String> {
    let n: usize = s.parse().map_err(|_| "license number must be an integer")?;
    if n == 0 || n > license_count {
        return Err(format!("license number must be 1..={license_count}"));
    }
    Ok(n - 1)
}

fn parse_mut_amount(s: &str) -> Result<u64, String> {
    if s.starts_with('-') || s.starts_with('+') || s.is_empty() {
        return Err("amount must be a positive decimal MUT value".into());
    }
    let mut parts = s.split('.');
    let whole = parts.next().unwrap_or("0");
    let frac = parts.next().unwrap_or("");
    if parts.next().is_some() || whole.is_empty() || frac.len() > 8 {
        return Err("amount must have at most 8 decimal places".into());
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err("amount contains non-decimal characters".into());
    }
    let whole_value: u64 = whole.parse().map_err(|_| "amount is too large")?;
    let mut frac_text = frac.to_string();
    while frac_text.len() < 8 {
        frac_text.push('0');
    }
    let frac_value: u64 = if frac_text.is_empty() {
        0
    } else {
        frac_text.parse().map_err(|_| "invalid fractional amount")?
    };
    whole_value
        .checked_mul(STRIKES_PER_MUT)
        .and_then(|v| v.checked_add(frac_value))
        .ok_or_else(|| "amount is too large".into())
}

fn format_mut(strikes: u64) -> String {
    format!(
        "{}.{}",
        strikes / STRIKES_PER_MUT,
        format_args!("{:08}", strikes % STRIKES_PER_MUT)
    )
}

fn dev_seed(i: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (j, b) in seed.iter_mut().enumerate() {
        *b = i.wrapping_mul(17).wrapping_add(j as u8).wrapping_add(1);
    }
    seed
}

fn decode32(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    v.try_into()
        .map_err(|_| "expected 32-byte hex value".to_string())
}

fn decode_protocol_operation_hex(encoded: &str) -> Result<ProtocolOperationV1, String> {
    let bytes = hex::decode(encoded).map_err(|e| e.to_string())?;
    decode_protocol_operation_bytes(&bytes)
}

fn decode_protocol_operation_bytes(bytes: &[u8]) -> Result<ProtocolOperationV1, String> {
    if bytes.len() < 5 {
        return Err("protocol operation is truncated".into());
    }
    let op_type = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    let op_version = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
    let mut input = &bytes[4..];
    let payload_len = read_varuint(&mut input).map_err(|e| e.to_string())?;
    let payload_len =
        usize::try_from(payload_len).map_err(|_| "protocol operation payload length overflow")?;
    if input.len() != payload_len {
        return Err("protocol operation payload length mismatch".into());
    }
    Ok(ProtocolOperationV1 {
        op_type,
        op_version,
        payload: input.to_vec(),
    })
}

fn decode_mut_manifest(bytes: &[u8]) -> Result<MutLicenseManifestV1, String> {
    if bytes.len() < 42 {
        return Err("native license manifest is truncated".into());
    }
    let version = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    let network_id = u32::from_be_bytes(bytes[2..6].try_into().unwrap());
    let purchase_nonce: [u8; 32] = bytes[6..38].try_into().unwrap();
    let count = u32::from_be_bytes(bytes[38..42].try_into().unwrap()) as usize;
    if count == 0 || count > 1024 {
        return Err("native license manifest count outside 1..=1024".into());
    }
    let expected = 42usize
        .checked_add(count.checked_mul(64).ok_or("manifest length overflow")?)
        .ok_or("manifest length overflow")?;
    if bytes.len() != expected {
        return Err("native license manifest length mismatch".into());
    }
    let mut licenses = Vec::with_capacity(count);
    let mut offset = 42usize;
    for _ in 0..count {
        let owner_public_key = bytes[offset..offset + 32].try_into().unwrap();
        let mining_public_key = bytes[offset + 32..offset + 64].try_into().unwrap();
        licenses.push(LicenseManifestEntryV1 {
            owner_public_key,
            mining_public_key,
        });
        offset += 64;
    }
    let manifest = MutLicenseManifestV1 {
        version,
        network_id,
        purchase_nonce,
        licenses,
    };
    manifest.validate().map_err(|e| e.to_string())?;
    Ok(manifest)
}

fn decode_native_purchase_operation(
    op: &ProtocolOperationV1,
) -> Result<LicensePurchaseMutV1, String> {
    if op.op_type != OP_LICENSE_PURCHASE_MUT || op.op_version != 1 {
        return Err("operation is not a V1 native Mining License purchase".into());
    }
    if op.payload.len() < 35 {
        return Err("native Mining License purchase payload is truncated".into());
    }
    let payment_txid = TxId(op.payload[0..32].try_into().unwrap());
    let payment_output_index = u16::from_be_bytes(op.payload[32..34].try_into().unwrap());
    let mut input = &op.payload[34..];
    let manifest_len = read_varuint(&mut input).map_err(|e| e.to_string())?;
    let manifest_len = usize::try_from(manifest_len).map_err(|_| "manifest length overflow")?;
    if input.len() != manifest_len {
        return Err("native Mining License purchase manifest length mismatch".into());
    }
    let manifest = decode_mut_manifest(input)?;
    Ok(LicensePurchaseMutV1 {
        payment_txid,
        payment_output_index,
        manifest,
    })
}

fn decode_license_transfer_operation(
    op: &ProtocolOperationV1,
) -> Result<LicenseTransferV1, String> {
    if op.op_type != OP_LICENSE_TRANSFER || op.op_version != 1 {
        return Err("operation is not a V1 Mining License transfer".into());
    }
    if op.payload.len() != 168 {
        return Err("Mining License transfer payload must be exactly 168 bytes".into());
    }
    Ok(LicenseTransferV1 {
        license_id: LicenseId(op.payload[0..32].try_into().unwrap()),
        expected_owner_sequence: u32::from_be_bytes(op.payload[32..36].try_into().unwrap()),
        expected_mining_sequence: u32::from_be_bytes(op.payload[36..40].try_into().unwrap()),
        new_owner_public_key: op.payload[40..72].try_into().unwrap(),
        new_mining_public_key: op.payload[72..104].try_into().unwrap(),
        owner_signature: op.payload[104..168].try_into().unwrap(),
    })
}

fn decode_mining_key_rotation_operation(
    op: &ProtocolOperationV1,
) -> Result<MiningKeyRotateV1, String> {
    if op.op_type != OP_LICENSE_MINING_KEY_ROTATE || op.op_version != 1 {
        return Err("operation is not a V1 Mining License mining-key rotation".into());
    }
    if op.payload.len() != 136 {
        return Err("Mining License mining-key rotation payload must be exactly 136 bytes".into());
    }
    Ok(MiningKeyRotateV1 {
        license_id: LicenseId(op.payload[0..32].try_into().unwrap()),
        expected_owner_sequence: u32::from_be_bytes(op.payload[32..36].try_into().unwrap()),
        expected_mining_sequence: u32::from_be_bytes(op.payload[36..40].try_into().unwrap()),
        new_mining_public_key: op.payload[40..72].try_into().unwrap(),
        owner_signature: op.payload[72..136].try_into().unwrap(),
    })
}

fn authority_operation_license_id(op: &ProtocolOperationV1) -> Result<Option<LicenseId>, String> {
    match op.op_type {
        OP_LICENSE_TRANSFER => Ok(Some(decode_license_transfer_operation(op)?.license_id)),
        OP_LICENSE_MINING_KEY_ROTATE => {
            Ok(Some(decode_mining_key_rotation_operation(op)?.license_id))
        }
        _ => Ok(None),
    }
}

fn sorted_pending_protocol_operations_for_epoch(
    state: &DevnetState,
    block_epoch: u64,
) -> Result<Vec<ProtocolOperationV1>, String> {
    let mempool_txids = state
        .mempool
        .iter()
        .map(|tx| tx.txid.as_str())
        .collect::<HashSet<_>>();
    let mut queued = Vec::new();
    let mut seen = HashSet::<[u8; 32]>::new();
    for pending in &state.pending_protocol_operations {
        if !pending.required_txid.is_empty()
            && !mempool_txids.contains(pending.required_txid.as_str())
        {
            continue;
        }
        let op = pending.operation()?;
        if op.op_version != 1 {
            return Err("unknown protocol operation version in pending queue".into());
        }
        if !matches!(
            op.op_type,
            OP_LICENSE_PURCHASE_BTC
                | OP_LICENSE_PURCHASE_MUT
                | OP_LICENSE_TRANSFER
                | OP_LICENSE_MINING_KEY_ROTATE
                | OP_PUNISHMENT_EVIDENCE
                | OP_DIVIDEND_CLAIM
                | OP_MINING_PRESENCE
                | OP_BITCOIN_HEADERS
        ) {
            return Err(format!(
                "Build 5.4 live engine does not accept protocol operation type 0x{:04x}",
                op.op_type
            ));
        }
        if !seen.insert(op.operation_id().0) {
            return Err("duplicate pending protocol OperationID".into());
        }
        queued.push(op);
    }
    if queued.len() > 1024 {
        return Err("pending protocol operation count exceeds V1 maximum 1024".into());
    }
    queued.sort_by_key(|op| (op.op_type, op.operation_id().0));

    // Reorg restoration can legitimately resurrect a dependent authority chain:
    // transfer(seq 0/0) -> funding -> rotate(seq 1/1). Only operations whose expected
    // sequences match the current canonical authority are block-ready. Future-sequence
    // operations remain queued for the next block instead of poisoning the current one.
    let mut selected = Vec::new();
    let mut selected_authority_targets = HashSet::<[u8; 32]>::new();
    let mut selected_presence_targets = HashSet::<[u8; 32]>::new();
    for op in queued {
        match op.op_type {
            OP_LICENSE_PURCHASE_BTC => {
                if bitcoin::dependency_ready_at_epoch(state, &op, block_epoch)? {
                    selected.push(op);
                }
            }
            OP_LICENSE_PURCHASE_MUT => selected.push(op),
            OP_LICENSE_TRANSFER => {
                let transfer = decode_license_transfer_operation(&op)?;
                let license = state
                    .licenses
                    .iter()
                    .find(|license| license.license_id == hex::encode(transfer.license_id.0))
                    .ok_or("pending Mining License transfer references unknown LicenseID")?;
                let current_owner = license.owner_key_sequence;
                let current_mining = license.mining_key_sequence;
                if transfer.expected_owner_sequence < current_owner
                    || transfer.expected_mining_sequence < current_mining
                {
                    return Err("stale pending Mining License transfer authority sequence".into());
                }
                if transfer.expected_owner_sequence > current_owner
                    || transfer.expected_mining_sequence > current_mining
                {
                    continue;
                }
                if selected_authority_targets.insert(transfer.license_id.0) {
                    selected.push(op);
                }
            }
            OP_LICENSE_MINING_KEY_ROTATE => {
                let rotation = decode_mining_key_rotation_operation(&op)?;
                let license = state
                    .licenses
                    .iter()
                    .find(|license| license.license_id == hex::encode(rotation.license_id.0))
                    .ok_or("pending mining-key rotation references unknown LicenseID")?;
                let current_owner = license.owner_key_sequence;
                let current_mining = license.mining_key_sequence;
                if rotation.expected_owner_sequence < current_owner
                    || rotation.expected_mining_sequence < current_mining
                {
                    return Err("stale pending mining-key rotation authority sequence".into());
                }
                if rotation.expected_owner_sequence > current_owner
                    || rotation.expected_mining_sequence > current_mining
                {
                    continue;
                }
                if selected_authority_targets.insert(rotation.license_id.0) {
                    selected.push(op);
                }
            }
            OP_PUNISHMENT_EVIDENCE => {
                if punishment::dependency_ready(state, &op)? {
                    selected.push(op);
                }
            }
            OP_DIVIDEND_CLAIM => {
                if dividends::dependency_ready(state, &op)? {
                    selected.push(op);
                }
            }
            OP_MINING_PRESENCE => {
                let mining_presence = presence::decode_operation(&op)?;
                if mining_presence.presence_epoch < block_epoch {
                    // Presence is epoch-bound and can never become valid again.
                    continue;
                }
                if mining_presence.presence_epoch > block_epoch {
                    // Future presence remains queued for its exact epoch.
                    continue;
                }
                presence::validate_operation_against_parent(state, &op, block_epoch)?;
                if selected_authority_targets.contains(&mining_presence.license_id.0) {
                    return Err("Pack K forbids same-block authority change plus MINING_PRESENCE for one LicenseID".into());
                }
                if !selected_presence_targets.insert(mining_presence.license_id.0) {
                    return Err("Pack K permits at most one pending MINING_PRESENCE per LicenseID per block".into());
                }
                selected.push(op);
            }
            OP_BITCOIN_HEADERS => {
                if block_epoch < bitcoin_headers::PACK_M_BTC_DISABLE_EPOCH {
                    selected.push(op);
                }
            }
            _ => unreachable!("queued operation types were checked above"),
        }
    }

    protocol_operations_root(&selected).map_err(|e| e.to_string())?;
    Ok(selected)
}

#[cfg(test)]
fn sorted_pending_protocol_operations(
    state: &DevnetState,
) -> Result<Vec<ProtocolOperationV1>, String> {
    sorted_pending_protocol_operations_for_epoch(state, next_mineable_epoch(state))
}

fn candidate_protocol_operations(
    state: &DevnetState,
    epoch: u64,
    license_index: usize,
    signer: &dyn MiningAuthority,
) -> Result<Vec<ProtocolOperationV1>, String> {
    let mut operations = sorted_pending_protocol_operations_for_epoch(state, epoch)?;
    if !presence::active(state, epoch) {
        return Ok(operations);
    }

    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    let license_id = decode32(&license.license_id)?;
    let authority_conflict = operations.iter().any(|op| {
        authority_operation_license_id(op)
            .ok()
            .flatten()
            .is_some_and(|id| id.0 == license_id)
    });

    let existing_self_presence = operations
        .iter()
        .filter(|op| op.op_type == OP_MINING_PRESENCE)
        .map(presence::decode_operation)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|p| p.license_id.0 == license_id)
        .count();
    if existing_self_presence > 1 {
        return Err("candidate has duplicate self-presence operations".into());
    }

    if authority_conflict {
        if !presence::license_has_fresh_presence(state, license, epoch) {
            return Err("candidate mining license needs self-presence but has a same-block authority change".into());
        }
    } else if existing_self_presence == 0 {
        operations.push(signer.presence(state, license_index, epoch)?);
    }

    operations.sort_by_key(|op| (op.op_type, op.operation_id().0));
    presence::prevalidate_block_operations(state, &operations, epoch)?;
    protocol_operations_root(&operations).map_err(|e| e.to_string())?;
    Ok(operations)
}

fn selected_protocol_transaction_ids(
    state: &DevnetState,
    operations: &[ProtocolOperationV1],
) -> Result<HashSet<String>, String> {
    let selected_opids = operations
        .iter()
        .map(|op| op.operation_id().0)
        .collect::<HashSet<_>>();
    let mut txids = HashSet::new();
    for pending in &state.pending_protocol_operations {
        let op = pending.operation()?;
        if selected_opids.contains(&op.operation_id().0) && !pending.required_txid.is_empty() {
            txids.insert(pending.required_txid.clone());
        }
    }
    Ok(txids)
}

fn selected_block_mempool(
    state: &DevnetState,
    operations: &[ProtocolOperationV1],
) -> Result<Vec<PendingTxState>, String> {
    let selected_protocol_txids = selected_protocol_transaction_ids(state, operations)?;
    Ok(state
        .mempool
        .iter()
        .filter(|pending| {
            !transaction_is_protocol_bound(state, &pending.txid)
                || selected_protocol_txids.contains(&pending.txid)
        })
        .cloned()
        .collect())
}

fn authority_fee_marker(license_id: &[u8; 32]) -> u64 {
    // Consensus-independent of local registry ordering: derive a compact positive self-payment
    // marker from the permanent LicenseID. The owner signature in the Protocol Op provides
    // authority; this marker only pairs the same-block fee transaction to its target license.
    u16::from_be_bytes([license_id[0], license_id[1]]) as u64 + 1
}

fn authority_fee_ticket_matches(
    state: &DevnetState,
    tx: &TransactionV1,
    license_index: usize,
) -> bool {
    let Some(license) = state.licenses.get(license_index) else {
        return false;
    };
    let Ok(license_id) = decode32(&license.license_id) else {
        return false;
    };
    let Ok(address) = decode32(&license.payment_address_id) else {
        return false;
    };
    if tx.core.inputs.is_empty() || tx.core.outputs.is_empty() {
        return false;
    }
    if tx.core.outputs[0].output_type != OUTPUT_PUBKEY_HASH
        || tx.core.outputs[0].amount_strikes != authority_fee_marker(&license_id)
        || tx.core.outputs[0].payload.as_slice() != &address[..]
    {
        return false;
    }
    if tx
        .core
        .outputs
        .iter()
        .any(|o| o.output_type != OUTPUT_PUBKEY_HASH || o.payload.as_slice() != &address[..])
    {
        return false;
    }
    for input in &tx.core.inputs {
        let (txid, index) = match input {
            TxInput::Outpoint {
                previous_txid,
                previous_output_index,
            } => (hex::encode(previous_txid), *previous_output_index),
            TxInput::Coinbase { .. } => return false,
        };
        let Some(u) = state
            .utxos
            .iter()
            .find(|u| u.txid == txid && u.output_index == index)
        else {
            return false;
        };
        if u.output_type != OUTPUT_PUBKEY_HASH || u.payload != license.payment_address_id {
            return false;
        }
    }
    true
}

fn authority_fee_ticket_license_index(state: &DevnetState, tx: &TransactionV1) -> Option<usize> {
    let matches = state
        .licenses
        .iter()
        .enumerate()
        .filter_map(|(i, _)| authority_fee_ticket_matches(state, tx, i).then_some(i))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

fn store_historical_keys(
    state: &mut DevnetState,
    operation: &ProtocolOperationV1,
    license_id: &LicenseId,
    historical: HistoricalLicenseKeysV1,
) -> Result<(), String> {
    let opid = operation.operation_id().to_hex();
    if state
        .historical_license_keys
        .iter()
        .any(|h| h.operation_id == opid)
    {
        return Err("duplicate historical-license-key OperationID".into());
    }
    state
        .historical_license_keys
        .push(HistoricalLicenseKeyState {
            operation_id: opid,
            license_id: hex::encode(license_id.0),
            owner_public_key: hex::encode(historical.owner_public_key),
            owner_key_sequence: historical.owner_key_sequence,
            mining_public_key: hex::encode(historical.mining_public_key),
            mining_key_sequence: historical.mining_key_sequence,
        });
    state
        .historical_license_keys
        .sort_by(|a, b| a.operation_id.cmp(&b.operation_id));
    Ok(())
}

fn apply_protocol_operations(
    state: &mut DevnetState,
    txs: &[TransactionV1],
    operations: &[ProtocolOperationV1],
    block_epoch: u64,
) -> Result<usize, String> {
    // Pack K presence validity is defined against the parent branch, before any
    // same-block operation mutates license authority or discipline state.
    presence::prevalidate_block_operations(state, operations, block_epoch)?;
    let mut created = 0usize;
    let mut seen_payment = state
        .consumed_native_payments
        .iter()
        .map(|s| decode32(s))
        .collect::<Result<HashSet<_>, _>>()?;
    let mut known_licenses = state
        .licenses
        .iter()
        .map(|l| decode32(&l.license_id))
        .collect::<Result<HashSet<_>, _>>()?;
    let mut referenced_license_payments = HashMap::<(String, u16), usize>::new();
    let mut used_fee_tickets = HashSet::<usize>::new();
    let mut authority_targets = HashSet::<[u8; 32]>::new();

    for op in operations {
        if op.op_version != 1 {
            return Err("unknown protocol operation version in block".into());
        }
        match op.op_type {
            OP_BITCOIN_HEADERS => {
                bitcoin_headers::apply_operation(state, op, block_epoch)?;
            }
            OP_LICENSE_PURCHASE_BTC => {
                let ids = bitcoin::apply_operation(state, op, block_epoch)?;
                for id in &ids {
                    if !known_licenses.insert(id.0) {
                        return Err("derived Bitcoin Mining LicenseID already exists".into());
                    }
                }
                created = created
                    .checked_add(ids.len())
                    .ok_or("created-license count overflow")?;
            }
            OP_LICENSE_PURCHASE_MUT => {
                let purchase = decode_native_purchase_operation(op)?;
                *referenced_license_payments
                    .entry((
                        purchase.payment_txid.to_hex(),
                        purchase.payment_output_index,
                    ))
                    .or_insert(0) += 1;
                if purchase.manifest.network_id != state.network_id {
                    return Err("native Mining License purchase manifest NetworkID mismatch".into());
                }
                let payment_id =
                    native_payment_id(&purchase.payment_txid, purchase.payment_output_index);
                if !seen_payment.insert(payment_id.0) {
                    return Err("NativePaymentID has already been consumed".into());
                }
                let tx_pos = txs
                    .iter()
                    .position(|tx| tx.txid() == purchase.payment_txid)
                    .ok_or("native Mining License purchase references a transaction not earlier in the block")?;
                if tx_pos == 0 {
                    return Err("native Mining License purchase cannot reference coinbase".into());
                }
                let payment_tx = &txs[tx_pos];
                let output = payment_tx
                    .core
                    .outputs
                    .get(purchase.payment_output_index as usize)
                    .ok_or("native Mining License purchase output index is out of range")?;
                if output.output_type != OUTPUT_LICENSE_PAYMENT || output.payload.len() != 32 {
                    return Err("native Mining License purchase does not reference a LICENSE_PAYMENT output".into());
                }
                let expected_manifest_hash = purchase
                    .manifest
                    .manifest_hash()
                    .map_err(|e| e.to_string())?;
                if output.payload.as_slice() != &expected_manifest_hash.0[..] {
                    return Err("LICENSE_PAYMENT manifest hash mismatch".into());
                }
                let price_each = subsidy(block_epoch).max(1);
                let required = price_each
                    .checked_mul(purchase.manifest.licenses.len() as u64)
                    .ok_or("native Mining License price overflow")?;
                if output.amount_strikes < required {
                    return Err(format!(
                        "LICENSE_PAYMENT underpays native Mining License price: {} < {} Strikes",
                        output.amount_strikes, required
                    ));
                }
                let ids = purchase.license_ids().map_err(|e| e.to_string())?;
                for (id, entry) in ids.iter().zip(purchase.manifest.licenses.iter()) {
                    if !known_licenses.insert(id.0) {
                        return Err("derived LicenseID already exists".into());
                    }
                    let index = u32::try_from(state.licenses.len())
                        .map_err(|_| "license registry index overflow")?;
                    let payment_address_id = address_id(&entry.owner_public_key).0;
                    state.licenses.push(LicenseState {
                        index,
                        license_id: hex::encode(id.0),
                        purchase_id: hex::encode(payment_id.0),
                        owner_public_key: hex::encode(entry.owner_public_key),
                        mining_public_key: hex::encode(entry.mining_public_key),
                        payment_address_id: hex::encode(payment_address_id),
                        status: LICENSE_STATUS_PENDING,
                        purchase_method: PURCHASE_METHOD_MUT,
                        owner_key_sequence: 0,
                        mining_key_sequence: 0,
                        issued_epoch: block_epoch,
                        activation_epoch: block_epoch
                            .checked_add(ACTIVATION_DELAY_EPOCHS)
                            .ok_or("activation epoch overflow")?,
                        strike_weight: 0,
                        suspended_until_epoch: 0,
                        revocation_epoch: 0,
                    });
                    created += 1;
                }
                state
                    .consumed_native_payments
                    .push(hex::encode(payment_id.0));
            }
            OP_LICENSE_TRANSFER => {
                let transfer = decode_license_transfer_operation(op)?;
                if !authority_targets.insert(transfer.license_id.0) {
                    return Err("V1 authority rules permit at most one authority operation per Mining License per block".into());
                }
                let license_index = state
                    .licenses
                    .iter()
                    .position(|l| l.license_id == hex::encode(transfer.license_id.0))
                    .ok_or("Mining License transfer references unknown LicenseID")?;
                let fee_pos = txs.iter().enumerate().skip(1).find_map(|(pos, tx)| {
                    (!used_fee_tickets.contains(&pos) && authority_fee_ticket_matches(state, tx, license_index)).then_some(pos)
                }).ok_or("Mining License transfer is missing its owner-funded authority fee ticket transaction")?;
                used_fee_tickets.insert(fee_pos);
                let mut record = state.licenses[license_index].record()?;
                let historical =
                    apply_license_transfer(&mut record, &transfer).map_err(|e| e.to_string())?;
                state.licenses[license_index].owner_public_key =
                    hex::encode(record.owner_public_key);
                state.licenses[license_index].owner_key_sequence = record.owner_key_sequence;
                state.licenses[license_index].mining_public_key =
                    hex::encode(record.mining_public_key);
                state.licenses[license_index].mining_key_sequence = record.mining_key_sequence;
                state.licenses[license_index].payment_address_id =
                    hex::encode(address_id(&record.owner_public_key).0);
                store_historical_keys(state, op, &transfer.license_id, historical)?;
            }
            OP_LICENSE_MINING_KEY_ROTATE => {
                let rotation = decode_mining_key_rotation_operation(op)?;
                if !authority_targets.insert(rotation.license_id.0) {
                    return Err("V1 authority rules permit at most one authority operation per Mining License per block".into());
                }
                let license_index = state
                    .licenses
                    .iter()
                    .position(|l| l.license_id == hex::encode(rotation.license_id.0))
                    .ok_or("Mining-key rotation references unknown LicenseID")?;
                let fee_pos = txs.iter().enumerate().skip(1).find_map(|(pos, tx)| {
                    (!used_fee_tickets.contains(&pos) && authority_fee_ticket_matches(state, tx, license_index)).then_some(pos)
                }).ok_or("Mining-key rotation is missing its owner-funded authority fee ticket transaction")?;
                used_fee_tickets.insert(fee_pos);
                let mut record = state.licenses[license_index].record()?;
                let historical =
                    apply_mining_key_rotation(&mut record, &rotation).map_err(|e| e.to_string())?;
                state.licenses[license_index].mining_public_key =
                    hex::encode(record.mining_public_key);
                state.licenses[license_index].mining_key_sequence = record.mining_key_sequence;
                store_historical_keys(state, op, &rotation.license_id, historical)?;
            }
            OP_PUNISHMENT_EVIDENCE => {
                punishment::apply_operation(state, op, block_epoch)?;
            }
            OP_DIVIDEND_CLAIM => {
                dividends::apply_operation(state, txs, op, block_epoch)?;
            }
            OP_MINING_PRESENCE => {
                presence::apply_validated_operation(state, op)?;
            }
            _ => {
                return Err(format!(
                    "block contains unsupported protocol operation 0x{:04x}/v{}",
                    op.op_type, op.op_version
                ))
            }
        }
    }

    for tx in txs.iter().skip(1) {
        let txid = tx.txid().to_hex();
        for (index, output) in tx.core.outputs.iter().enumerate() {
            if output.output_type != OUTPUT_LICENSE_PAYMENT {
                continue;
            }
            let index =
                u16::try_from(index).map_err(|_| "LICENSE_PAYMENT output index overflow")?;
            match referenced_license_payments.get(&(txid.clone(), index)).copied().unwrap_or(0) {
                1 => {}
                0 => return Err("LICENSE_PAYMENT output is missing its exactly-one native purchase Protocol Op".into()),
                _ => return Err("LICENSE_PAYMENT output is referenced by more than one native purchase Protocol Op".into()),
            }
        }
    }
    state.consumed_native_payments.sort();
    state.consumed_native_payments.dedup();
    Ok(created)
}

fn print_licenses(state: &DevnetState) -> Result<(), String> {
    println!(
        "Mining Licenses: {} total, {} eligible at epoch {}",
        state.licenses.len(),
        eligible_license_count(state, state.tip_epoch),
        state.tip_epoch
    );
    for license in &state.licenses {
        let status = match license.status {
            LICENSE_STATUS_PENDING => "PENDING",
            LICENSE_STATUS_ACTIVE => "ACTIVE",
            LICENSE_STATUS_REVOKED => "REVOKED",
            _ => "INVALID",
        };
        println!(
            "license {:03}  {}  {:8}  method={}  issued={}  activates={}  owner_seq={}  mining_seq={}  owner={}  mining={}  strikes={}  suspended_until={}  revoked_at={}",
            license.index as usize + 1,
            &license.license_id[..16],
            status,
            if license.purchase_method == PURCHASE_METHOD_BTC { "BTC" } else { "MUT" },
            license.issued_epoch,
            license.activation_epoch,
            license.owner_key_sequence,
            license.mining_key_sequence,
            &license.owner_public_key[..16],
            &license.mining_public_key[..16],
            license.strike_weight,
            license.suspended_until_epoch,
            license.revocation_epoch,
        );
    }
    println!(
        "Consumed NativePaymentIDs: {}",
        state.consumed_native_payments.len()
    );
    println!(
        "Consumed BitcoinPaymentIDs: {}",
        state.consumed_bitcoin_payments.len()
    );
    println!("Consumed EvidenceIDs: {}", state.consumed_evidence.len());
    println!("Active offense events: {}", state.offense_events.len());
    println!(
        "Historical license-key snapshots: {}",
        state.historical_license_keys.len()
    );
    println!("Pack-K presence records: {}", state.mining_presence.len());
    println!("Pack-K activation epoch: {PACK_K_DEVNET_ACTIVATION_EPOCH}");
    println!(
        "Pack-K active now: {}",
        presence::active(state, state.tip_epoch)
    );
    Ok(())
}

fn print_license_history(state: &DevnetState, license_index: usize) -> Result<(), String> {
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    let mut rows = state
        .historical_license_keys
        .iter()
        .filter(|h| h.license_id == license.license_id)
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| a.operation_id.cmp(&b.operation_id));
    println!(
        "Mining License {:03} history - LicenseID {}",
        license.index as usize + 1,
        license.license_id
    );
    if rows.is_empty() {
        println!("No historical authority snapshots.");
        return Ok(());
    }
    for (i, h) in rows.iter().enumerate() {
        println!(
            "snapshot {:02}  op={}  owner_seq={} owner={}  mining_seq={} mining={}",
            i + 1,
            h.operation_id,
            h.owner_key_sequence,
            h.owner_public_key,
            h.mining_key_sequence,
            h.mining_public_key,
        );
    }
    Ok(())
}

fn print_banner(state: &DevnetState) {
    if state.network_id == MAINNET_NETWORK_ID {
        println!("{BUILD_NAME} - Mainnet runtime");
    } else {
        println!("{BUILD_NAME} - {BUILD_DESCRIPTION}");
    }
    println!("{}", state.motto);
    println!(
        "Network: {} (0x{:08x})\n",
        if state.network_id == MAINNET_NETWORK_ID {
            "Mainnet"
        } else {
            "Devnet"
        },
        state.network_id
    );
}

fn canonical_tip_epoch(state: &DevnetState) -> u64 {
    state.blocks.last().map(|b| b.epoch).unwrap_or(0)
}

fn canonical_tip_state_root(state: &DevnetState) -> &str {
    // Every post-Genesis canonical block commits its exact StateRoot in the frozen V1 header.
    // For height zero this integrated Devnet scaffold has no block header, so the current
    // Genesis-state root is the best available representation until final Pack-J Genesis is wired.
    state
        .blocks
        .last()
        .map(|b| b.state_root.as_str())
        .unwrap_or(state.current_state_root.as_str())
}

fn print_status(state: &DevnetState) {
    let eligible = eligible_license_count(state, state.tip_epoch);
    let w = work_units(eligible);
    println!("Canonical height:        {}", state.height);
    println!("Canonical tip epoch:     {}", canonical_tip_epoch(state));
    println!("Current local epoch:     {}", state.tip_epoch);
    println!("Mining Licenses total:   {}", state.licenses.len());
    println!("Eligible licenses:       {}", eligible);
    println!(
        "Base-eligible licenses:  {}",
        base_eligible_license_count(state, state.tip_epoch)
    );
    println!(
        "Pack-K activation epoch: {}",
        decode32(&state.genesis_hash)
            .ok()
            .and_then(|genesis| mutiny_protocol::pack_k_activation_epoch(
                state.network_id,
                &genesis
            ))
            .map(|epoch| epoch.to_string())
            .unwrap_or_else(|| "inactive".into())
    );
    println!(
        "Pack-K presence active:  {}",
        presence::active(state, state.tip_epoch)
    );
    println!("Pack-K presence records: {}", state.mining_presence.len());
    println!(
        "Pending licenses:        {}",
        state
            .licenses
            .iter()
            .filter(|l| l.status == LICENSE_STATUS_PENDING)
            .count()
    );
    println!("Work units/license:      {}", w);
    println!("Authorized tickets:      {}", authorized_capacity(eligible));
    println!(
        "Total issued:            {} MUT",
        format_mut(state.total_issued_strikes)
    );
    println!("UTXOs:                   {}", state.utxos.len());
    println!("Mempool:                 {} tx", state.mempool.len());
    println!(
        "Pending protocol ops:    {}",
        state.pending_protocol_operations.len()
    );
    println!(
        "Consumed native pays:    {}",
        state.consumed_native_payments.len()
    );
    println!(
        "Consumed Bitcoin pays:   {}",
        state.consumed_bitcoin_payments.len()
    );
    println!("Consumed EvidenceIDs:    {}", state.consumed_evidence.len());
    println!("Active offense events:   {}", state.offense_events.len());
    println!("Dividend accounts:       {}", state.dividend_accounts.len());
    println!(
        "Dividend reserve:        {} MUT",
        format_mut(state.treasury_reserved_dividend_strikes)
    );
    println!(
        "Historical key snaps:    {}",
        state.historical_license_keys.len()
    );
    println!("Archived branches:       {}", state.side_branches.len());
    println!(
        "Difficulty C Q32:        {}",
        state.difficulty_correction_q32
    );
    println!("Base Fee Q32:            {}", state.base_fee_rate_q32);
    println!("Epoch duration:          {} ms", state.epoch_ms);
    println!(
        "Canonical tip StateRoot: {}",
        canonical_tip_state_root(state)
    );
    println!("Current StateRoot:       {}", state.current_state_root);
    println!("Canonical tip:           {}", state.tip_hash);
}

fn print_sync_report(peer: &str, report: &blocksync::SyncReport) {
    println!("Sync decision from {peer}: {}", report.decision);
    if report.downloaded_blocks > 0 {
        println!(
            "  downloaded/validated: {} block(s)",
            report.downloaded_blocks
        );
    }
    if report.reorg {
        println!(
            "  common ancestor:      height {}",
            report.common_ancestor_height
        );
        println!(
            "  disconnected:         {} block(s)",
            report.disconnected_blocks
        );
        println!("  connected:            {} block(s)", report.applied_blocks);
        println!("  mempool restored:     {} tx", report.restored_mempool);
    } else if report.applied_blocks > 0 {
        println!(
            "  applied:               {} block(s)",
            report.applied_blocks
        );
    }
}

fn print_branches(state: &DevnetState) {
    if state.side_branches.is_empty() {
        println!("No archived side branches.");
        return;
    }
    for (i, branch) in state.side_branches.iter().enumerate() {
        println!(
            "branch {:02}: fork_height={} tip_height={} blocks={} chainwork={} tip={}",
            i + 1,
            branch.fork_height,
            branch.tip_height,
            branch.blocks.len(),
            branch.chain_work,
            branch.tip_hash
        );
    }
}

type PeerRegistry = Arc<Mutex<HashSet<String>>>;

type SessionRegistry = Arc<Mutex<HashMap<String, Arc<Mutex<PersistentSession>>>>>;

// Build 4.4.1 keeps a shutdown handle for every accepted inbound TCP session.  The
// handler still owns the real stream; this registry owns only a try_clone() handle
// so bounded node shutdown can half-close the write side and let the remote peer
// observe an orderly FIN before the process exits.
#[cfg(test)]
#[derive(Default)]
struct InboundSessionRegistryState {
    next_id: u64,
    streams: HashMap<u64, TcpStream>,
}

#[cfg(test)]
type InboundSessionRegistry = Arc<Mutex<InboundSessionRegistryState>>;

#[cfg(test)]
fn new_inbound_session_registry() -> InboundSessionRegistry {
    Arc::new(Mutex::new(InboundSessionRegistryState::default()))
}

#[cfg(test)]
fn register_inbound_shutdown_handle(
    registry: &InboundSessionRegistry,
    stream: &TcpStream,
) -> Result<u64, String> {
    let handle = stream
        .try_clone()
        .map_err(|e| format!("clone inbound TCP session: {e}"))?;
    let mut state = registry
        .lock()
        .map_err(|_| "inbound session registry mutex poisoned")?;
    let id = state.next_id;
    state.next_id = state.next_id.saturating_add(1);
    state.streams.insert(id, handle);
    Ok(id)
}

#[cfg(test)]
fn unregister_inbound_shutdown_handle(
    registry: &InboundSessionRegistry,
    id: u64,
) -> Result<(), String> {
    let mut state = registry
        .lock()
        .map_err(|_| "inbound session registry mutex poisoned")?;
    state.streams.remove(&id);
    Ok(())
}

#[cfg(test)]
fn begin_graceful_inbound_shutdown(registry: &InboundSessionRegistry) -> Result<usize, String> {
    let state = registry
        .lock()
        .map_err(|_| "inbound session registry mutex poisoned")?;
    let mut initiated = 0usize;
    for stream in state.streams.values() {
        // Shutdown::Write sends FIN but leaves the read side alive long enough for the
        // peer to classify the close as orderly rather than as a reset.
        if stream.shutdown(Shutdown::Write).is_ok() {
            initiated += 1;
        }
    }
    Ok(initiated)
}

#[cfg(test)]
fn finish_inbound_shutdown(registry: &InboundSessionRegistry) -> Result<(), String> {
    let mut state = registry
        .lock()
        .map_err(|_| "inbound session registry mutex poisoned")?;
    for stream in state.streams.values() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    state.streams.clear();
    Ok(())
}

#[derive(Debug)]
struct PersistentSession {
    stream: Option<TcpStream>,
    consecutive_failures: u32,
    retry_after: Option<Instant>,
    connections_established: u64,
    operations_completed: u64,
    transport_failures: u64,
    peer_shutdowns: u64,
}

impl PersistentSession {
    fn new() -> Self {
        Self {
            stream: None,
            consecutive_failures: 0,
            retry_after: None,
            connections_established: 0,
            operations_completed: 0,
            transport_failures: 0,
            peer_shutdowns: 0,
        }
    }
}

fn new_session_registry() -> SessionRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

fn session_backoff_seconds(consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return 0;
    }
    1u64 << consecutive_failures.saturating_sub(1).min(5)
}

fn looks_like_orderly_peer_shutdown(error: &str) -> bool {
    let e = error.to_ascii_lowercase();
    e.contains("failed to fill whole buffer")
        || e.contains("unexpected end of file")
        || e.contains("unexpected eof")
        || e.contains("connection closed cleanly")
}

fn mark_session_failure(session: &mut PersistentSession) {
    session.stream = None;
    session.consecutive_failures = session.consecutive_failures.saturating_add(1).min(32);
    session.retry_after = Some(
        Instant::now() + Duration::from_secs(session_backoff_seconds(session.consecutive_failures)),
    );
}

fn stream_has_orderly_eof(stream: &TcpStream) -> Result<bool, String> {
    // Before starting the next request, do a non-blocking MSG_PEEK-equivalent check.
    // A TCP FIN is readable as EOF (peek == 0); an idle live socket reports WouldBlock.
    // This makes graceful peer shutdown observable before a subsequent write turns a
    // half-closed connection into a BrokenPipe/ConnectionReset diagnostic.
    stream
        .set_nonblocking(true)
        .map_err(|e| format!("set peer socket nonblocking: {e}"))?;
    let mut byte = [0u8; 1];
    let peek = stream.peek(&mut byte);
    let restore = stream.set_nonblocking(false);
    if let Err(e) = restore {
        return Err(format!("restore peer socket blocking mode: {e}"));
    }
    match peek {
        Ok(0) => Ok(true),
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

fn with_persistent_peer<T, F>(
    data_dir: &Path,
    sessions: &SessionRegistry,
    peer: &str,
    operation: F,
) -> Result<T, String>
where
    F: FnOnce(&mut TcpStream) -> Result<T, String>,
{
    let slot = {
        let mut registry = sessions
            .lock()
            .map_err(|_| "session registry mutex poisoned")?;
        registry
            .entry(peer.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(PersistentSession::new())))
            .clone()
    };

    let mut session = slot
        .lock()
        .map_err(|_| "persistent session mutex poisoned")?;
    if let Some(retry_after) = session.retry_after.as_ref() {
        let now = Instant::now();
        if *retry_after > now {
            let wait = retry_after.saturating_duration_since(now);
            return Err(format!(
                "persistent session to {peer} is backing off for {} ms",
                wait.as_millis()
            ));
        }
    }

    if session.stream.is_none() {
        match connect_authenticated(data_dir, peer) {
            Ok(stream) => {
                session.stream = Some(stream);
                session.connections_established = session.connections_established.saturating_add(1);
                session.consecutive_failures = 0;
                session.retry_after = None;
                println!("Persistent session established with {peer}");
            }
            Err(e) => {
                session.transport_failures = session.transport_failures.saturating_add(1);
                mark_session_failure(&mut session);
                return Err(e);
            }
        }
    }

    match stream_has_orderly_eof(session.stream.as_ref().expect("stream established")) {
        Ok(true) => {
            session.peer_shutdowns = session.peer_shutdowns.saturating_add(1);
            mark_session_failure(&mut session);
            return Err(format!("connection closed cleanly by peer {peer}"));
        }
        Ok(false) => {}
        Err(e) => {
            session.transport_failures = session.transport_failures.saturating_add(1);
            mark_session_failure(&mut session);
            return Err(e);
        }
    }

    let result = operation(session.stream.as_mut().expect("stream established"));
    match result {
        Ok(value) => {
            session.operations_completed = session.operations_completed.saturating_add(1);
            session.consecutive_failures = 0;
            session.retry_after = None;
            Ok(value)
        }
        Err(e) => {
            if looks_like_orderly_peer_shutdown(&e) {
                session.peer_shutdowns = session.peer_shutdowns.saturating_add(1);
            } else {
                session.transport_failures = session.transport_failures.saturating_add(1);
            }
            mark_session_failure(&mut session);
            Err(e)
        }
    }
}

#[cfg(test)]
fn shutdown_persistent_sessions(sessions: &SessionRegistry) -> Result<(), String> {
    let slots = {
        let registry = sessions
            .lock()
            .map_err(|_| "session registry mutex poisoned")?;
        registry.values().cloned().collect::<Vec<_>>()
    };
    for slot in slots {
        let mut session = slot
            .lock()
            .map_err(|_| "persistent session mutex poisoned")?;
        if let Some(mut stream) = session.stream.take() {
            // A local bounded-run shutdown is not a peer failure.  Send FIN first, then
            // briefly allow the responder to acknowledge/close its side before forcing
            // the local descriptor closed.  Metrics are printed only after stream=None.
            let _ = stream.shutdown(Shutdown::Write);
            let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte);
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
    Ok(())
}

fn legacy_node_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("node-key.bin")
}

fn node_keystore_path(data_dir: &Path) -> PathBuf {
    data_dir.join("secrets").join("node-identity.msk")
}

struct SecretPassphrase(Vec<u8>);

impl std::ops::Deref for SecretPassphrase {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SecretPassphrase {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn strip_one_line_ending(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    bytes
}

fn read_passphrase_path(path: &Path) -> Result<SecretPassphrase, String> {
    let bytes =
        fs::read(path).map_err(|e| format!("read passphrase file {}: {e}", path.display()))?;
    let bytes = strip_one_line_ending(bytes);
    if bytes.len() < 12 {
        return Err("passphrase file must contain at least 12 bytes after one trailing line ending is removed".into());
    }
    Ok(SecretPassphrase(bytes))
}

fn read_required_passphrase_file(args: &[String]) -> Result<SecretPassphrase, String> {
    read_passphrase_path(Path::new(required_option(args, "--passphrase-file")?))
}

fn parse_wallet_key_role(value: &str) -> Result<KeyRole, String> {
    match value {
        "owner" => Ok(KeyRole::LicenseOwner),
        "mining" => Ok(KeyRole::LicenseMining),
        "node" => Err("use node-key-init/node-key-info for the node identity role".into()),
        _ => Err("--role must be owner or mining".into()),
    }
}

fn validate_key_label(label: &str) -> Result<(), String> {
    if label.is_empty() || label.len() > 64 {
        return Err("key label must contain 1..64 characters".into());
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("key label may contain only ASCII letters, digits, '-' and '_'".into());
    }
    Ok(())
}

fn wallet_key_path(data_dir: &Path, role: KeyRole, label: &str) -> Result<PathBuf, String> {
    validate_key_label(label)?;
    Ok(data_dir
        .join("secrets")
        .join(format!("{}-{label}.msk", role.name())))
}

fn read_required_wallet_passphrase_file(args: &[String]) -> Result<SecretPassphrase, String> {
    read_passphrase_path(Path::new(required_option(
        args,
        "--wallet-passphrase-file",
    )?))
}

fn load_wallet_key(
    data_dir: &Path,
    role: KeyRole,
    label: &str,
    passphrase: &[u8],
) -> Result<SigningKey, String> {
    load_wallet_key_for_network(data_dir, role, label, passphrase, DEVNET_NETWORK_ID)
}

fn load_wallet_key_for_network(
    data_dir: &Path,
    role: KeyRole,
    label: &str,
    passphrase: &[u8],
    network_id: u32,
) -> Result<SigningKey, String> {
    let path = wallet_key_path(data_dir, role, label)?;
    if !path.exists() {
        return Err(format!(
            "encrypted {} key label '{}' does not exist",
            role.name(),
            label
        ));
    }
    mutiny_keystore::load_file(&path, role, network_id, passphrase).map_err(|e| e.to_string())
}

fn load_owner_key_for_license(
    data_dir: &Path,
    state: &DevnetState,
    license_index: usize,
    label: &str,
    passphrase: &[u8],
) -> Result<SigningKey, String> {
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    let key = load_wallet_key_for_network(
        data_dir,
        KeyRole::LicenseOwner,
        label,
        passphrase,
        state.network_id,
    )?;
    let expected = decode32(&license.owner_public_key)?;
    if key.verifying_key().to_bytes() != expected {
        return Err(format!("encrypted owner key label '{}' does not match the current on-chain owner authority for license {}", label, license_index + 1));
    }
    Ok(key)
}

fn load_mining_key_for_license(
    data_dir: &Path,
    state: &DevnetState,
    license_index: usize,
    label: &str,
    passphrase: &[u8],
) -> Result<SigningKey, String> {
    let license = state
        .licenses
        .get(license_index)
        .ok_or("license number out of range")?;
    let key = load_wallet_key_for_network(
        data_dir,
        KeyRole::LicenseMining,
        label,
        passphrase,
        state.network_id,
    )?;
    let expected = decode32(&license.mining_public_key)?;
    if key.verifying_key().to_bytes() != expected {
        return Err(format!("encrypted mining key label '{}' does not match the current on-chain mining authority for license {}", label, license_index + 1));
    }
    Ok(key)
}

fn load_wallet_public_key(
    data_dir: &Path,
    role: KeyRole,
    label: &str,
    passphrase: &[u8],
) -> Result<[u8; 32], String> {
    Ok(load_wallet_key(data_dir, role, label, passphrase)?
        .verifying_key()
        .to_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineSpendPrevoutV1 {
    previous_txid: [u8; 32],
    previous_output_index: u16,
    amount_strikes: u64,
    output_type: u8,
    payload: Vec<u8>,
}

impl OfflineSpendPrevoutV1 {
    fn prevout(&self) -> PrevoutCommitmentV1 {
        PrevoutCommitmentV1 {
            previous_txid: self.previous_txid,
            previous_output_index: self.previous_output_index,
            amount_strikes: self.amount_strikes,
            output_type: self.output_type,
            payload: self.payload.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineSpendRequestV1 {
    network_id: u32,
    genesis_id: [u8; 32],
    from_license_id: [u8; 32],
    to_license_id: [u8; 32],
    owner_public_key: [u8; 32],
    created_height: u64,
    max_submit_height: u64,
    valid_from_epoch: u64,
    expiry_epoch: u64,
    amount_strikes: u64,
    fee_strikes: u64,
    prevouts: Vec<OfflineSpendPrevoutV1>,
    outputs: Vec<TxOutput>,
}

impl OfflineSpendRequestV1 {
    fn core(&self) -> Result<TransactionCoreV1, String> {
        let inputs = self
            .prevouts
            .iter()
            .map(|p| TxInput::Outpoint {
                previous_txid: p.previous_txid,
                previous_output_index: p.previous_output_index,
            })
            .collect::<Vec<_>>();
        Ok(TransactionCoreV1 {
            version: 1,
            network_id: self.network_id,
            valid_from_epoch: self.valid_from_epoch,
            expiry_epoch: self.expiry_epoch,
            inputs,
            outputs: self.outputs.clone(),
        })
    }

    fn txid(&self) -> Result<TxId, String> {
        Ok(self.core()?.txid())
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        if self.prevouts.is_empty()
            || self.prevouts.len() > 1024
            || self.outputs.is_empty()
            || self.outputs.len() > 1024
        {
            return Err("offline spend request input/output count outside 1..=1024".into());
        }
        let mut out = Vec::new();
        out.extend_from_slice(OFFLINE_SPEND_REQUEST_MAGIC);
        out.extend_from_slice(&OFFLINE_SPEND_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_id.to_be_bytes());
        out.extend_from_slice(&self.genesis_id);
        out.extend_from_slice(&self.from_license_id);
        out.extend_from_slice(&self.to_license_id);
        out.extend_from_slice(&self.owner_public_key);
        out.extend_from_slice(&self.created_height.to_be_bytes());
        out.extend_from_slice(&self.max_submit_height.to_be_bytes());
        out.extend_from_slice(&self.valid_from_epoch.to_be_bytes());
        out.extend_from_slice(&self.expiry_epoch.to_be_bytes());
        out.extend_from_slice(&self.amount_strikes.to_be_bytes());
        out.extend_from_slice(&self.fee_strikes.to_be_bytes());
        out.extend_from_slice(&(self.prevouts.len() as u16).to_be_bytes());
        for prevout in &self.prevouts {
            if prevout.payload.len() > u16::MAX as usize {
                return Err("offline spend prevout payload too large".into());
            }
            out.extend_from_slice(&prevout.previous_txid);
            out.extend_from_slice(&prevout.previous_output_index.to_be_bytes());
            out.extend_from_slice(&prevout.amount_strikes.to_be_bytes());
            out.push(prevout.output_type);
            out.extend_from_slice(&(prevout.payload.len() as u16).to_be_bytes());
            out.extend_from_slice(&prevout.payload);
        }
        out.extend_from_slice(&(self.outputs.len() as u16).to_be_bytes());
        for output in &self.outputs {
            if output.payload.len() > u16::MAX as usize {
                return Err("offline spend output payload too large".into());
            }
            out.extend_from_slice(&output.amount_strikes.to_be_bytes());
            out.push(output.output_type);
            out.extend_from_slice(&(output.payload.len() as u16).to_be_bytes());
            out.extend_from_slice(&output.payload);
        }
        let checksum: [u8; 32] = Sha256::digest(&out).into();
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 + 2 + 4 + 32 * 4 + 8 * 6 + 2 + 2 + 32 {
            return Err("malformed MutinyOfflineSpendRequestV1".into());
        }
        let checksum_at = bytes.len() - 32;
        let expected: [u8; 32] = Sha256::digest(&bytes[..checksum_at]).into();
        if &expected[..] != &bytes[checksum_at..] {
            return Err("offline spend request checksum mismatch".into());
        }
        fn take<'a>(
            bytes: &'a [u8],
            at: &mut usize,
            end: usize,
            n: usize,
        ) -> Result<&'a [u8], String> {
            if *at + n > end {
                return Err("malformed MutinyOfflineSpendRequestV1".into());
            }
            let out = &bytes[*at..*at + n];
            *at += n;
            Ok(out)
        }
        let mut at = 0usize;
        if take(bytes, &mut at, checksum_at, 8)? != OFFLINE_SPEND_REQUEST_MAGIC {
            return Err("invalid offline spend request magic".into());
        }
        let version = u16::from_be_bytes(take(bytes, &mut at, checksum_at, 2)?.try_into().unwrap());
        if version != OFFLINE_SPEND_VERSION {
            return Err("unsupported offline spend request version".into());
        }
        let network_id =
            u32::from_be_bytes(take(bytes, &mut at, checksum_at, 4)?.try_into().unwrap());
        let genesis_id = take(bytes, &mut at, checksum_at, 32)?.try_into().unwrap();
        let from_license_id = take(bytes, &mut at, checksum_at, 32)?.try_into().unwrap();
        let to_license_id = take(bytes, &mut at, checksum_at, 32)?.try_into().unwrap();
        let owner_public_key = take(bytes, &mut at, checksum_at, 32)?.try_into().unwrap();
        let created_height =
            u64::from_be_bytes(take(bytes, &mut at, checksum_at, 8)?.try_into().unwrap());
        let max_submit_height =
            u64::from_be_bytes(take(bytes, &mut at, checksum_at, 8)?.try_into().unwrap());
        let valid_from_epoch =
            u64::from_be_bytes(take(bytes, &mut at, checksum_at, 8)?.try_into().unwrap());
        let expiry_epoch =
            u64::from_be_bytes(take(bytes, &mut at, checksum_at, 8)?.try_into().unwrap());
        let amount_strikes =
            u64::from_be_bytes(take(bytes, &mut at, checksum_at, 8)?.try_into().unwrap());
        let fee_strikes =
            u64::from_be_bytes(take(bytes, &mut at, checksum_at, 8)?.try_into().unwrap());
        let input_count =
            u16::from_be_bytes(take(bytes, &mut at, checksum_at, 2)?.try_into().unwrap()) as usize;
        if input_count == 0 || input_count > 1024 {
            return Err("offline spend request input count outside 1..=1024".into());
        }
        let mut prevouts = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let previous_txid = take(bytes, &mut at, checksum_at, 32)?.try_into().unwrap();
            let previous_output_index =
                u16::from_be_bytes(take(bytes, &mut at, checksum_at, 2)?.try_into().unwrap());
            let amount =
                u64::from_be_bytes(take(bytes, &mut at, checksum_at, 8)?.try_into().unwrap());
            let output_type = take(bytes, &mut at, checksum_at, 1)?[0];
            let payload_len =
                u16::from_be_bytes(take(bytes, &mut at, checksum_at, 2)?.try_into().unwrap())
                    as usize;
            let payload = take(bytes, &mut at, checksum_at, payload_len)?.to_vec();
            prevouts.push(OfflineSpendPrevoutV1 {
                previous_txid,
                previous_output_index,
                amount_strikes: amount,
                output_type,
                payload,
            });
        }
        let output_count =
            u16::from_be_bytes(take(bytes, &mut at, checksum_at, 2)?.try_into().unwrap()) as usize;
        if output_count == 0 || output_count > 1024 {
            return Err("offline spend request output count outside 1..=1024".into());
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let amount =
                u64::from_be_bytes(take(bytes, &mut at, checksum_at, 8)?.try_into().unwrap());
            let output_type = take(bytes, &mut at, checksum_at, 1)?[0];
            let payload_len =
                u16::from_be_bytes(take(bytes, &mut at, checksum_at, 2)?.try_into().unwrap())
                    as usize;
            let payload = take(bytes, &mut at, checksum_at, payload_len)?.to_vec();
            outputs.push(TxOutput {
                amount_strikes: amount,
                output_type,
                payload,
            });
        }
        if at != checksum_at {
            return Err("offline spend request has trailing bytes".into());
        }
        let request = Self {
            network_id,
            genesis_id,
            from_license_id,
            to_license_id,
            owner_public_key,
            created_height,
            max_submit_height,
            valid_from_epoch,
            expiry_epoch,
            amount_strikes,
            fee_strikes,
            prevouts,
            outputs,
        };
        validate_offline_request_static(&request)?;
        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineSpendSignatureV1 {
    network_id: u32,
    request_hash: [u8; 32],
    owner_public_key: [u8; 32],
    signatures: Vec<[u8; 64]>,
}

impl OfflineSpendSignatureV1 {
    fn encode(&self) -> Result<Vec<u8>, String> {
        if self.signatures.is_empty() || self.signatures.len() > 1024 {
            return Err("offline spend signature count outside 1..=1024".into());
        }
        let mut out = Vec::new();
        out.extend_from_slice(OFFLINE_SPEND_SIGNATURE_MAGIC);
        out.extend_from_slice(&OFFLINE_SPEND_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_id.to_be_bytes());
        out.extend_from_slice(&self.request_hash);
        out.extend_from_slice(&self.owner_public_key);
        out.extend_from_slice(&(self.signatures.len() as u16).to_be_bytes());
        for signature in &self.signatures {
            out.extend_from_slice(signature);
        }
        let checksum: [u8; 32] = Sha256::digest(&out).into();
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 + 2 + 4 + 32 + 32 + 2 + 64 + 32 {
            return Err("malformed MutinyOfflineSpendSignatureV1".into());
        }
        let checksum_at = bytes.len() - 32;
        let expected: [u8; 32] = Sha256::digest(&bytes[..checksum_at]).into();
        if &expected[..] != &bytes[checksum_at..] {
            return Err("offline spend signature checksum mismatch".into());
        }
        fn take<'a>(
            bytes: &'a [u8],
            at: &mut usize,
            end: usize,
            n: usize,
        ) -> Result<&'a [u8], String> {
            if *at + n > end {
                return Err("malformed MutinyOfflineSpendSignatureV1".into());
            }
            let out = &bytes[*at..*at + n];
            *at += n;
            Ok(out)
        }
        let mut at = 0usize;
        if take(bytes, &mut at, checksum_at, 8)? != OFFLINE_SPEND_SIGNATURE_MAGIC {
            return Err("invalid offline spend signature magic".into());
        }
        let version = u16::from_be_bytes(take(bytes, &mut at, checksum_at, 2)?.try_into().unwrap());
        if version != OFFLINE_SPEND_VERSION {
            return Err("unsupported offline spend signature version".into());
        }
        let network_id =
            u32::from_be_bytes(take(bytes, &mut at, checksum_at, 4)?.try_into().unwrap());
        let request_hash = take(bytes, &mut at, checksum_at, 32)?.try_into().unwrap();
        let owner_public_key = take(bytes, &mut at, checksum_at, 32)?.try_into().unwrap();
        let count =
            u16::from_be_bytes(take(bytes, &mut at, checksum_at, 2)?.try_into().unwrap()) as usize;
        if count == 0 || count > 1024 || at + count * 64 != checksum_at {
            return Err("invalid offline spend signature count".into());
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(take(bytes, &mut at, checksum_at, 64)?.try_into().unwrap());
        }
        if at != checksum_at {
            return Err("offline spend signature has trailing bytes".into());
        }
        Ok(Self {
            network_id,
            request_hash,
            owner_public_key,
            signatures,
        })
    }
}

fn offline_request_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn validate_offline_request_static(request: &OfflineSpendRequestV1) -> Result<(), String> {
    if request.network_id != DEVNET_NETWORK_ID {
        return Err("offline spend request NetworkID mismatch".into());
    }
    if request.genesis_id != decode32(DEVNET_GENESIS_ID_HEX)? {
        return Err("offline spend request GenesisID mismatch".into());
    }
    if request.amount_strikes == 0 {
        return Err("offline spend amount must be greater than zero".into());
    }
    if request.max_submit_height < request.created_height
        || request.max_submit_height - request.created_height > OFFLINE_SPEND_MAX_SUBMIT_BLOCKS
    {
        return Err("offline spend submission horizon is invalid".into());
    }
    if request.prevouts.is_empty()
        || request.prevouts.len() > 1024
        || request.outputs.is_empty()
        || request.outputs.len() > 2
    {
        return Err("offline spend request has invalid input/output shape".into());
    }
    let owner_address = address_id(&request.owner_public_key).0;
    let mut input_sum = 0u64;
    for prevout in &request.prevouts {
        if prevout.output_type != OUTPUT_PUBKEY_HASH
            || prevout.payload.as_slice() != &owner_address[..]
        {
            return Err(
                "offline spend prevout is not controlled by the declared owner public key".into(),
            );
        }
        input_sum = input_sum
            .checked_add(prevout.amount_strikes)
            .ok_or("offline spend input sum overflow")?;
    }
    if request.outputs[0].amount_strikes != request.amount_strikes
        || request.outputs[0].output_type != OUTPUT_PUBKEY_HASH
        || request.outputs[0].payload.len() != 32
    {
        return Err("offline spend destination output does not match declared amount/type".into());
    }
    if request.outputs.len() == 2 {
        let change = &request.outputs[1];
        if change.amount_strikes == 0
            || change.output_type != OUTPUT_PUBKEY_HASH
            || change.payload.as_slice() != &owner_address[..]
        {
            return Err("offline spend change output is invalid".into());
        }
    }
    let output_sum = request.outputs.iter().try_fold(0u64, |acc, o| {
        acc.checked_add(o.amount_strikes)
            .ok_or("offline spend output sum overflow")
    })?;
    let actual_fee = input_sum
        .checked_sub(output_sum)
        .ok_or("offline spend creates value")?;
    if actual_fee != request.fee_strikes {
        return Err("offline spend declared fee does not match input/output value".into());
    }
    let core = request.core()?;
    if core.inputs.len() != request.prevouts.len() {
        return Err("offline spend input/prevout count mismatch".into());
    }
    Ok(())
}

fn create_offline_send_request(
    state: &DevnetState,
    from: usize,
    to: usize,
    amount: u64,
) -> Result<OfflineSpendRequestV1, String> {
    if amount == 0 {
        return Err("amount must be greater than zero".into());
    }
    if from >= state.licenses.len() || to >= state.licenses.len() {
        return Err("license number out of range".into());
    }
    if state.genesis_hash != DEVNET_GENESIS_ID_HEX {
        return Err("offline signing requires the locked Devnet GenesisID".into());
    }
    let candidate_epoch = next_mineable_epoch(state);
    let candidate_height = state.height + 1;
    let from_address = decode32(&state.licenses[from].payment_address_id)?;
    let to_address = decode32(&state.licenses[to].payment_address_id)?;
    let owner_public_key = decode32(&state.licenses[from].owner_public_key)?;
    if address_id(&owner_public_key).0 != from_address {
        return Err("current owner public key does not match the license payment address".into());
    }
    let reserved = mempool_reserved_inputs(state);
    let mut candidates = state
        .utxos
        .iter()
        .filter(|u| {
            u.output_type == OUTPUT_PUBKEY_HASH
                && decode32(&u.payload)
                    .map(|p| p == from_address)
                    .unwrap_or(false)
                && u.spendable_at_height(candidate_height)
                && !reserved.contains(&(u.txid.clone(), u.output_index))
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(|u| (u.creation_height, u.txid.clone(), u.output_index));
    let mut selected = Vec::<UtxoState>::new();
    let mut total = 0u64;
    for utxo in candidates {
        total = total
            .checked_add(utxo.amount_strikes)
            .ok_or("balance overflow")?;
        selected.push(utxo);
        let estimated = estimate_send_weight(selected.len(), 2)?;
        let fee = required_base_fee(state.base_fee_rate_q32, estimated as u64)
            .map_err(|e| e.to_string())?;
        if total >= amount.saturating_add(fee) {
            break;
        }
    }
    if selected.is_empty() {
        return Err("no spendable UTXOs; coinbase rewards require 16-block maturity".into());
    }
    let fee = required_base_fee(
        state.base_fee_rate_q32,
        estimate_send_weight(selected.len(), 2)? as u64,
    )
    .map_err(|e| e.to_string())?;
    if total < amount.saturating_add(fee) {
        return Err(format!(
            "insufficient spendable balance: have {} MUT, need at least {} MUT plus fee",
            format_mut(total),
            format_mut(amount)
        ));
    }
    let change = total - amount - fee;
    let mut outputs = vec![TxOutput {
        amount_strikes: amount,
        output_type: OUTPUT_PUBKEY_HASH,
        payload: to_address.to_vec(),
    }];
    if change > 0 {
        outputs.push(TxOutput {
            amount_strikes: change,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: from_address.to_vec(),
        });
    }
    let prevouts = selected
        .iter()
        .map(|u| {
            Ok(OfflineSpendPrevoutV1 {
                previous_txid: decode32(&u.txid)?,
                previous_output_index: u.output_index,
                amount_strikes: u.amount_strikes,
                output_type: u.output_type,
                payload: hex::decode(&u.payload).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let request = OfflineSpendRequestV1 {
        network_id: DEVNET_NETWORK_ID,
        genesis_id: decode32(&state.genesis_hash)?,
        from_license_id: decode32(&state.licenses[from].license_id)?,
        to_license_id: decode32(&state.licenses[to].license_id)?,
        owner_public_key,
        created_height: state.height,
        max_submit_height: state
            .height
            .checked_add(OFFLINE_SPEND_MAX_SUBMIT_BLOCKS)
            .ok_or("offline spend submission height overflow")?,
        valid_from_epoch: candidate_epoch,
        expiry_epoch: 0,
        amount_strikes: amount,
        fee_strikes: fee,
        prevouts,
        outputs,
    };
    validate_offline_request_static(&request)?;
    Ok(request)
}

fn print_offline_spend_request(request: &OfflineSpendRequestV1) -> Result<(), String> {
    println!("NetworkID:         0x{:08x}", request.network_id);
    println!("GenesisID:         {}", hex::encode(request.genesis_id));
    println!(
        "From LicenseID:    {}",
        hex::encode(request.from_license_id)
    );
    println!("To LicenseID:      {}", hex::encode(request.to_license_id));
    println!(
        "Owner public key:  {}",
        hex::encode(request.owner_public_key)
    );
    println!("TXID:              {}", request.txid()?.to_hex());
    println!(
        "Amount:            {} MUT",
        format_mut(request.amount_strikes)
    );
    println!("Fee:               {} Strikes", request.fee_strikes);
    println!(
        "Destination:       {}",
        hex::encode(&request.outputs[0].payload)
    );
    if request.outputs.len() == 2 {
        println!(
            "Change address:    {}",
            hex::encode(&request.outputs[1].payload)
        );
    }
    println!("Inputs:            {}", request.prevouts.len());
    println!("Created height:    {}", request.created_height);
    println!("Max submit height: {}", request.max_submit_height);
    println!("Valid from epoch:  {}", request.valid_from_epoch);
    Ok(())
}

fn submit_offline_spend(
    state: &DevnetState,
    request_bytes: &[u8],
    request: &OfflineSpendRequestV1,
    signed: &OfflineSpendSignatureV1,
) -> Result<PendingTxState, String> {
    validate_offline_request_static(request)?;
    if signed.network_id != request.network_id
        || signed.request_hash != offline_request_hash(request_bytes)
        || signed.owner_public_key != request.owner_public_key
    {
        return Err("offline signed authorization does not match the spend request".into());
    }
    if signed.signatures.len() != request.prevouts.len() {
        return Err("offline signed authorization signature count mismatch".into());
    }
    if state.genesis_hash != hex::encode(request.genesis_id) {
        return Err("offline spend request does not belong to this GenesisID".into());
    }
    if state.height > request.max_submit_height {
        return Err("offline spend request has exceeded its 144-block submission horizon".into());
    }
    let candidate_epoch = next_mineable_epoch(state);
    let candidate_height = state.height + 1;
    if candidate_epoch < request.valid_from_epoch
        || (request.expiry_epoch != 0 && candidate_epoch > request.expiry_epoch)
    {
        return Err("offline spend transaction is outside its epoch validity window".into());
    }
    let from = state
        .licenses
        .iter()
        .position(|l| l.license_id == hex::encode(request.from_license_id))
        .ok_or("offline spend source LicenseID is not present in current state")?;
    let to = state
        .licenses
        .iter()
        .position(|l| l.license_id == hex::encode(request.to_license_id))
        .ok_or("offline spend destination LicenseID is not present in current state")?;
    if decode32(&state.licenses[from].owner_public_key)? != request.owner_public_key {
        return Err("offline spend request owner authority is stale".into());
    }
    let from_address = decode32(&state.licenses[from].payment_address_id)?;
    let to_address = decode32(&state.licenses[to].payment_address_id)?;
    if request.outputs[0].payload.as_slice() != &to_address[..] {
        return Err(
            "offline spend destination authority/payment address changed after request creation"
                .into(),
        );
    }
    if request.outputs.len() == 2 && request.outputs[1].payload.as_slice() != &from_address[..] {
        return Err("offline spend change address does not match current source owner".into());
    }
    let reserved = mempool_reserved_inputs(state);
    for prevout in &request.prevouts {
        let txid_hex = hex::encode(prevout.previous_txid);
        if reserved.contains(&(txid_hex.clone(), prevout.previous_output_index)) {
            return Err("offline spend request input is already reserved by the mempool".into());
        }
        let current = state
            .utxos
            .iter()
            .find(|u| u.txid == txid_hex && u.output_index == prevout.previous_output_index)
            .ok_or("offline spend request input is no longer unspent")?;
        if !current.spendable_at_height(candidate_height) {
            return Err(
                "offline spend request input is not spendable at the next block height".into(),
            );
        }
        if current.amount_strikes != prevout.amount_strikes
            || current.output_type != prevout.output_type
            || hex::decode(&current.payload).map_err(|e| e.to_string())? != prevout.payload
        {
            return Err(
                "offline spend request prevout commitment does not match current UTXO state".into(),
            );
        }
    }
    let core = request.core()?;
    let txid = core.txid();
    let mut witnesses = Vec::with_capacity(request.prevouts.len());
    for (i, (prevout, sig_bytes)) in request
        .prevouts
        .iter()
        .zip(signed.signatures.iter())
        .enumerate()
    {
        let witness = WitnessV1::pubkey_hash(request.owner_public_key, *sig_bytes);
        let digest = sighash_all(&txid, i as u16, &prevout.prevout());
        verify_pubkey_hash_witness(&AddressId(from_address), &digest.0, &witness)
            .map_err(|e| format!("offline spend signature {i} failed: {e}"))?;
        witnesses.push(witness);
    }
    let tx = TransactionV1 { core, witnesses };
    let input_sum = request.prevouts.iter().try_fold(0u64, |acc, p| {
        acc.checked_add(p.amount_strikes)
            .ok_or("offline spend input sum overflow")
    })?;
    let output_sum = tx.core.outputs.iter().try_fold(0u64, |acc, o| {
        acc.checked_add(o.amount_strikes)
            .ok_or("offline spend output sum overflow")
    })?;
    let actual_fee = input_sum
        .checked_sub(output_sum)
        .ok_or("offline spend fee underflow")?;
    if actual_fee != request.fee_strikes {
        return Err("offline spend fee changed from signed request".into());
    }
    let actual_base = required_base_fee(state.base_fee_rate_q32, tx.serialized_len() as u64)
        .map_err(|e| e.to_string())?;
    if actual_fee < actual_base {
        return Err(format!(
            "offline spend request became stale because Base Fee rose: {} < {}",
            actual_fee, actual_base
        ));
    }
    let from_license =
        u8::try_from(from).map_err(|_| "offline spend local display index exceeds u8")?;
    let to_license =
        u8::try_from(to).map_err(|_| "offline spend local display index exceeds u8")?;
    Ok(PendingTxState {
        txid: tx.txid().to_hex(),
        wtxid: tx.wtxid().to_hex(),
        valid_from_epoch: tx.core.valid_from_epoch,
        expiry_epoch: tx.core.expiry_epoch,
        inputs: request
            .prevouts
            .iter()
            .map(|p| StoredTxInput {
                previous_txid: hex::encode(p.previous_txid),
                previous_output_index: p.previous_output_index,
            })
            .collect(),
        outputs: tx
            .core
            .outputs
            .iter()
            .map(|o| StoredTxOutput {
                amount_strikes: o.amount_strikes,
                output_type: o.output_type,
                payload: hex::encode(&o.payload),
            })
            .collect(),
        witnesses: tx
            .witnesses
            .iter()
            .map(|w| StoredWitness {
                witness_type: w.witness_type,
                payload: hex::encode(&w.payload),
            })
            .collect(),
        fee_strikes: actual_fee,
        base_fee_strikes: actual_base,
        from_license,
        to_license,
        amount_strikes: request.amount_strikes,
    })
}

fn wallet_file_role_and_label(name: &str) -> Option<(KeyRole, String)> {
    for role in [KeyRole::LicenseOwner, KeyRole::LicenseMining] {
        let prefix = format!("{}-", role.name());
        if let Some(rest) = name
            .strip_prefix(&prefix)
            .and_then(|v| v.strip_suffix(".msk"))
        {
            if validate_key_label(rest).is_ok() {
                return Some((role, rest.to_string()));
            }
        }
    }
    None
}

fn collect_wallet_backup_entries(
    data_dir: &Path,
    passphrase: &[u8],
) -> Result<Vec<WalletBackupEntry>, String> {
    let secrets = data_dir.join("secrets");
    if !secrets.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for item in fs::read_dir(&secrets).map_err(|e| format!("read {}: {e}", secrets.display()))? {
        let item = item.map_err(|e| format!("read wallet secrets directory entry: {e}"))?;
        let file_type = item
            .file_type()
            .map_err(|e| format!("inspect wallet secret directory entry: {e}"))?;
        if !file_type.is_file() {
            continue;
        }
        let name = item.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((role, label)) = wallet_file_role_and_label(name) else {
            continue;
        };
        let path = item.path();
        let secret_file = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let metadata = mutiny_keystore::inspect(&secret_file)
            .map_err(|e| format!("inspect {}: {e}", path.display()))?;
        if metadata.role != role || metadata.network_id != DEVNET_NETWORK_ID {
            return Err(format!(
                "wallet key filename/metadata mismatch: {}",
                path.display()
            ));
        }
        let key = mutiny_keystore::open(&secret_file, role, DEVNET_NETWORK_ID, passphrase)
            .map_err(|e| format!("verify {}: {e}", path.display()))?;
        let public_key = key.verifying_key().to_bytes();
        if public_key != metadata.public_key {
            return Err(format!(
                "wallet key public metadata mismatch: {}",
                path.display()
            ));
        }
        entries.push(WalletBackupEntry {
            role,
            label,
            public_key,
            secret_file,
        });
    }
    entries.sort_by(|a, b| (a.role as u8, a.label.as_str()).cmp(&(b.role as u8, b.label.as_str())));
    Ok(entries)
}

fn verify_wallet_backup_bytes(
    bytes: &[u8],
    passphrase: &[u8],
) -> Result<Vec<WalletBackupEntry>, String> {
    let (network_id, entries) =
        mutiny_keystore::decode_wallet_backup(bytes).map_err(|e| e.to_string())?;
    if network_id != DEVNET_NETWORK_ID {
        return Err("wallet backup NetworkID mismatch".into());
    }
    if entries.is_empty() {
        return Err("wallet backup contains no owner/mining keys".into());
    }
    for entry in &entries {
        let key = mutiny_keystore::open(
            &entry.secret_file,
            entry.role,
            DEVNET_NETWORK_ID,
            passphrase,
        )
        .map_err(|e| {
            format!(
                "verify backup {} key '{}': {e}",
                entry.role.name(),
                entry.label
            )
        })?;
        if key.verifying_key().to_bytes() != entry.public_key {
            return Err(format!(
                "backup {} key '{}' public-key mismatch",
                entry.role.name(),
                entry.label
            ));
        }
    }
    Ok(entries)
}

fn restore_wallet_backup_bytes(
    data_dir: &Path,
    bytes: &[u8],
    passphrase: &[u8],
) -> Result<Vec<WalletBackupEntry>, String> {
    let entries = verify_wallet_backup_bytes(bytes, passphrase)?;
    let mut targets = Vec::with_capacity(entries.len());
    for entry in &entries {
        let path = wallet_key_path(data_dir, entry.role, &entry.label)?;
        if path.exists() {
            return Err(format!(
                "restore would overwrite existing encrypted {} key label '{}'",
                entry.role.name(),
                entry.label
            ));
        }
        targets.push(path);
    }
    let mut created: Vec<PathBuf> = Vec::new();
    for (entry, path) in entries.iter().zip(targets.iter()) {
        if let Err(e) = mutiny_keystore::write_new_file(path, &entry.secret_file) {
            for created_path in created.iter().rev() {
                let _ = fs::remove_file(created_path);
            }
            return Err(format!(
                "restore write {} failed: {e}; restored files from this attempt were rolled back",
                path.display()
            ));
        }
        created.push(path.clone());
    }
    Ok(entries)
}

fn watch_wallet_matches(state: &DevnetState, entry: &WatchWalletEntry) -> Vec<String> {
    let key_hex = hex::encode(entry.public_key);
    let mut out = Vec::new();
    for (i, license) in state.licenses.iter().enumerate() {
        let matched = match entry.role {
            KeyRole::LicenseOwner => license.owner_public_key == key_hex,
            KeyRole::LicenseMining => license.mining_public_key == key_hex,
            KeyRole::NodeIdentity => false,
        };
        if matched {
            out.push(format!("license {} {}", i + 1, entry.role.name()));
        }
    }
    out
}

fn create_node_identity(data_dir: &Path, passphrase: &[u8]) -> Result<SigningKey, String> {
    create_node_identity_for_runtime(data_dir, passphrase, RuntimeNetwork::Devnet)
}

fn create_node_identity_for_runtime(
    data_dir: &Path,
    passphrase: &[u8],
    runtime: RuntimeNetwork,
) -> Result<SigningKey, String> {
    if legacy_node_key_path(data_dir).exists() {
        return Err("legacy plaintext node-key.bin exists; run node-key-migrate instead of generating a second NodeID".into());
    }
    let path = node_keystore_path(data_dir);
    let (key, bytes) =
        mutiny_keystore::generate(KeyRole::NodeIdentity, runtime.network_id(), passphrase)
            .map_err(|e| e.to_string())?;
    mutiny_keystore::write_new_file(&path, &bytes).map_err(|e| e.to_string())?;
    Ok(key)
}

fn load_encrypted_node_key_uncached(
    data_dir: &Path,
    passphrase: &[u8],
) -> Result<SigningKey, String> {
    load_encrypted_node_key_for_runtime(data_dir, passphrase, RuntimeNetwork::Devnet)
}

fn load_encrypted_node_key_for_runtime(
    data_dir: &Path,
    passphrase: &[u8],
    runtime: RuntimeNetwork,
) -> Result<SigningKey, String> {
    if legacy_node_key_path(data_dir).exists() {
        return Err("legacy plaintext node-key.bin is refused by Build 6.1; run node-key-migrate --passphrase-file PATH".into());
    }
    let path = node_keystore_path(data_dir);
    if !path.exists() {
        return Err(
            "encrypted node identity is not initialized; run node-key-init --passphrase-file PATH"
                .into(),
        );
    }
    mutiny_keystore::load_file(
        &path,
        KeyRole::NodeIdentity,
        runtime.network_id(),
        passphrase,
    )
    .map_err(|e| e.to_string())
}

fn migrate_legacy_node_identity(data_dir: &Path, passphrase: &[u8]) -> Result<SigningKey, String> {
    let legacy = legacy_node_key_path(data_dir);
    let secure = node_keystore_path(data_dir);
    if secure.exists() {
        return Err("encrypted node identity already exists; refusing ambiguous migration".into());
    }
    let raw = fs::read(&legacy).map_err(|e| format!("read legacy {}: {e}", legacy.display()))?;
    let mut seed: [u8; 32] = raw
        .try_into()
        .map_err(|_| "legacy node-key.bin must contain exactly 32 bytes".to_string())?;
    let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let bytes =
        mutiny_keystore::seal_seed(&seed, KeyRole::NodeIdentity, DEVNET_NETWORK_ID, passphrase)
            .map_err(|e| e.to_string())?;
    seed.fill(0);
    mutiny_keystore::write_new_file(&secure, &bytes).map_err(|e| e.to_string())?;
    let verify = mutiny_keystore::load_file(
        &secure,
        KeyRole::NodeIdentity,
        DEVNET_NETWORK_ID,
        passphrase,
    )
    .map_err(|e| e.to_string())?;
    if verify.verifying_key().to_bytes() != expected {
        let _ = fs::remove_file(&secure);
        return Err("post-migration node public key mismatch".into());
    }
    if let Err(e) = fs::remove_file(&legacy) {
        let _ = fs::remove_file(&secure);
        return Err(format!(
            "could not remove legacy plaintext key after verified migration: {e}"
        ));
    }
    Ok(verify)
}

fn print_node_identity(data_dir: &Path, key: &SigningKey) {
    print_node_identity_for_runtime(data_dir, key, RuntimeNetwork::Devnet);
}

fn print_node_identity_for_runtime(data_dir: &Path, key: &SigningKey, runtime: RuntimeNetwork) {
    let public_key = key.verifying_key().to_bytes();
    println!("NetworkID:  0x{:08x}", runtime.network_id());
    println!("Public key: {}", hex::encode(public_key));
    println!("NodeID:     {}", mutiny_p2p::node_id(&public_key).to_hex());
    println!("Path:       {}", node_keystore_path(data_dir).display());
    println!("Format:     MutinySecretFileV1 / Argon2id + ChaCha20 + HMAC-SHA256");
}

#[cfg(not(test))]
static RUNTIME_NODE_KEY: OnceLock<SigningKey> = OnceLock::new();

#[cfg(not(test))]
static MAINNET_RUNTIME_NODE_KEY: OnceLock<(PathBuf, SigningKey)> = OnceLock::new();

fn load_runtime_node_key_for_runtime(
    data_dir: &Path,
    runtime: RuntimeNetwork,
) -> Result<SigningKey, String> {
    if runtime == RuntimeNetwork::Devnet {
        return load_runtime_node_key(data_dir);
    }
    #[cfg(not(test))]
    if let Some((cached_dir, key)) = MAINNET_RUNTIME_NODE_KEY.get() {
        if cached_dir != data_dir {
            return Err("Mainnet node identity cache is bound to another data directory".into());
        }
        return Ok(key.clone());
    }
    let path = env::var(NODE_PASSPHRASE_FILE_ENV)
        .map_err(|_| "network commands require --node-passphrase-file PATH".to_string())?;
    let passphrase = read_passphrase_path(Path::new(&path))?;
    let key = load_encrypted_node_key_for_runtime(data_dir, &passphrase, runtime)?;
    #[cfg(not(test))]
    {
        let _ = MAINNET_RUNTIME_NODE_KEY.set((data_dir.to_path_buf(), key.clone()));
    }
    Ok(key)
}

fn load_runtime_node_key(data_dir: &Path) -> Result<SigningKey, String> {
    #[cfg(test)]
    {
        if let Ok(path) = env::var(NODE_PASSPHRASE_FILE_ENV) {
            let passphrase = read_passphrase_path(Path::new(&path))?;
            return load_encrypted_node_key_uncached(data_dir, &passphrase);
        }
        return load_or_create_node_key(&legacy_node_key_path(data_dir)).map_err(|e| e.to_string());
    }
    #[cfg(not(test))]
    {
        if let Some(key) = RUNTIME_NODE_KEY.get() {
            return Ok(key.clone());
        }
        let path = env::var(NODE_PASSPHRASE_FILE_ENV).map_err(|_| {
            "network commands require --node-passphrase-file PATH in Build 6.1".to_string()
        })?;
        let passphrase = read_passphrase_path(Path::new(&path))?;
        let key = load_encrypted_node_key_uncached(data_dir, &passphrase)?;
        let _ = RUNTIME_NODE_KEY.set(key.clone());
        Ok(key)
    }
}

fn peer_cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join("peers.json")
}

fn advertise_path(data_dir: &Path) -> PathBuf {
    data_dir.join("advertise.addr")
}

fn peer_snapshot(peers: &PeerRegistry) -> Result<Vec<String>, String> {
    let guard = peers.lock().map_err(|_| "peer registry mutex poisoned")?;
    let mut out = guard.iter().cloned().collect::<Vec<_>>();
    out.sort();
    Ok(out)
}

fn load_peer_cache(data_dir: &Path) -> Result<HashSet<String>, String> {
    let path = peer_cache_path(data_dir);
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let raw = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let peers: Vec<String> =
        serde_json::from_slice(&raw).map_err(|e| format!("decode {}: {e}", path.display()))?;
    Ok(peers.into_iter().collect())
}

fn save_peer_cache(data_dir: &Path, peers: &[String]) -> Result<(), String> {
    fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let mut sorted = peers.to_vec();
    sorted.sort();
    sorted.dedup();
    let raw = serde_json::to_vec_pretty(&sorted).map_err(|e| e.to_string())?;
    fs::write(peer_cache_path(data_dir), raw).map_err(|e| e.to_string())
}

fn register_runtime_peer(
    data_dir: &Path,
    peers: &PeerRegistry,
    peer: &str,
    local_listen: &str,
) -> Result<bool, String> {
    let socket: SocketAddr = peer
        .parse()
        .map_err(|_| format!("invalid advertised peer address {peer}"))?;
    if socket.port() == 0 || socket.ip().is_unspecified() || peer == local_listen {
        return Ok(false);
    }
    let (inserted, snapshot) = {
        let mut guard = peers.lock().map_err(|_| "peer registry mutex poisoned")?;
        if guard.len() >= MAX_RUNTIME_PEERS && !guard.contains(peer) {
            return Ok(false);
        }
        let inserted = guard.insert(peer.to_string());
        let snapshot = guard.iter().cloned().collect::<Vec<_>>();
        (inserted, snapshot)
    };
    if inserted {
        save_peer_cache(data_dir, &snapshot)?;
    }
    Ok(inserted)
}

fn encode_peer_addresses(addrs: &[String], last_seen_epoch: u64) -> Result<Vec<u8>, String> {
    if addrs.len() > MAX_RUNTIME_PEERS {
        return Err("ADDR exceeds 256 peers".into());
    }
    let mut out = Vec::new();
    write_varuint(&mut out, addrs.len() as u64);
    for text in addrs {
        let socket: SocketAddr = text
            .parse()
            .map_err(|_| format!("invalid peer socket {text}"))?;
        match socket.ip() {
            IpAddr::V4(ip) => {
                out.push(0x01);
                out.push(4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(0x02);
                out.push(16);
                out.extend_from_slice(&ip.octets());
            }
        }
        out.extend_from_slice(&socket.port().to_be_bytes());
        out.extend_from_slice(&CAP_BUILD45_NODE.to_be_bytes());
        out.extend_from_slice(&last_seen_epoch.to_be_bytes());
    }
    Ok(out)
}

fn decode_peer_addresses(payload: &[u8]) -> Result<Vec<String>, String> {
    let mut input = payload;
    let count = read_varuint(&mut input).map_err(|e| e.to_string())?;
    if count > MAX_RUNTIME_PEERS as u64 {
        return Err("ADDR exceeds 256 peers".into());
    }
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if input.len() < 2 {
            return Err("truncated PeerAddress".into());
        }
        let network_type = input[0];
        let len = input[1] as usize;
        input = &input[2..];
        if input.len() < len + 14 {
            return Err("truncated PeerAddress body".into());
        }
        let address = &input[..len];
        input = &input[len..];
        let port = u16::from_be_bytes(input[..2].try_into().unwrap());
        let _services = u32::from_be_bytes(input[2..6].try_into().unwrap());
        let _last_seen_epoch = u64::from_be_bytes(input[6..14].try_into().unwrap());
        input = &input[14..];
        let ip = match (network_type, len) {
            (0x01, 4) => IpAddr::V4(Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            )),
            (0x02, 16) => {
                let bytes: [u8; 16] = address.try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => return Err("unsupported PeerAddress network type/length".into()),
        };
        if port != 0 && !ip.is_unspecified() {
            out.push(SocketAddr::new(ip, port).to_string());
        }
    }
    if !input.is_empty() {
        return Err("trailing bytes after ADDR payload".into());
    }
    Ok(out)
}

fn print_cached_peers(data_dir: &Path) -> Result<(), String> {
    let mut peers = load_peer_cache(data_dir)?.into_iter().collect::<Vec<_>>();
    peers.sort();
    if peers.is_empty() {
        println!("No cached peers.");
    } else {
        for (i, peer) in peers.iter().enumerate() {
            println!("peer {:02}: {peer}", i + 1);
        }
    }
    Ok(())
}

fn connect_authenticated(data_dir: &Path, peer: &str) -> Result<TcpStream, String> {
    let socket: SocketAddr = peer
        .parse()
        .map_err(|_| format!("invalid peer socket {peer}"))?;
    let mut stream = TcpStream::connect_timeout(&socket, P2P_CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {peer}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    let key = load_runtime_node_key(data_dir).map_err(|e| e.to_string())?;
    let info = initiator_handshake(
        &mut stream,
        &key,
        CAP_BUILD45_NODE,
        DEVNET_NETWORK_ID,
        P2P_MAGIC_DEVNET,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "Authenticated peer {} ({})",
        peer,
        &info.node_id.to_hex()[..16]
    );
    if info.capabilities & CAP_PEER_DISCOVERY != 0 {
        if let Ok(advertise) = fs::read_to_string(advertise_path(data_dir)) {
            let advertise = advertise.trim();
            if !advertise.is_empty() {
                if let Ok(payload) = encode_peer_addresses(&[advertise.to_string()], 0) {
                    Frame::new(P2P_MAGIC_DEVNET, MSG_ADDR, 0x4200, payload)
                        .map_err(|e| e.to_string())?
                        .write_to(&mut stream)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
    }
    Ok(stream)
}

fn sync_from_peer(data_dir: &Path, peer: &str) -> Result<blocksync::SyncReport, String> {
    let sessions = new_session_registry();
    sync_from_peer_persistent(data_dir, &sessions, peer)
}

fn sync_from_peer_persistent(
    data_dir: &Path,
    sessions: &SessionRegistry,
    peer: &str,
) -> Result<blocksync::SyncReport, String> {
    let mut state = load_state(data_dir)?;
    let report = blocksync::sync_state_from_peer_persistent(data_dir, sessions, peer, &mut state)?;
    save_state(data_dir, &state)?;
    Ok(report)
}

fn push_tx_to_peer(
    data_dir: &Path,
    peer: &str,
    pending: &PendingTxState,
) -> Result<String, String> {
    let sessions = new_session_registry();
    push_tx_to_peer_persistent(data_dir, &sessions, peer, pending)
}

fn service_tx_relay_interleaved_frame(
    data_dir: &Path,
    stream: &mut TcpStream,
    frame: &Frame,
) -> Result<bool, String> {
    match frame.message_type {
        MSG_ADDR => {
            // An authenticated peer may advertise addresses immediately after handshake.
            // Validate the canonical payload and consume it without stealing the active
            // transaction RequestID lane. relay-tx is a one-shot compatibility command,
            // so it does not mutate the caller's peer cache here.
            decode_peer_addresses(&frame.payload)?;
            Ok(true)
        }
        MSG_PING => {
            Frame::new(
                P2P_MAGIC_DEVNET,
                MSG_PONG,
                frame.request_id,
                frame.payload.clone(),
            )
            .map_err(|e| e.to_string())?
            .write_to(stream)
            .map_err(|e| e.to_string())?;
            Ok(true)
        }
        MSG_GET_ADDR => {
            let payload = encode_peer_addresses(&[], 0)?;
            Frame::new(P2P_MAGIC_DEVNET, MSG_ADDR, frame.request_id, payload)
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
            Ok(true)
        }
        MSG_GET_HEADERS => {
            let state = load_state(data_dir)?;
            let payload = blocksync::serve_get_headers(&state, &frame.payload)?;
            Frame::new(P2P_MAGIC_DEVNET, MSG_HEADERS, frame.request_id, payload)
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
            Ok(true)
        }
        MSG_GET_BLOCK => {
            let state = load_state(data_dir)?;
            let payload = blocksync::serve_get_block(&state, &frame.payload)?;
            Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK, frame.request_id, payload)
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn read_tx_relay_expected_response(
    data_dir: &Path,
    stream: &mut TcpStream,
    expected_request_id: u64,
    expected_message_types: &[u16],
    label: &str,
) -> Result<Frame, String> {
    // The authenticated connection is full duplex. Peer-discovery ADDR traffic,
    // RequestID-zero announcements, PING, and safe reverse read-only requests may arrive
    // before the GETTX/TX_RESULT belonging to this relay. Keep the waiter finite and
    // aligned with the already inherited 20-second response horizon.
    let deadline = Instant::now() + EXPENSIVE_REQUEST_RESPONSE_TIMEOUT;
    let mut interleaved_frames = 0usize;
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "peer exceeded response deadline while awaiting {label}"
            ));
        }
        let frame = Frame::read_from(stream, P2P_MAGIC_DEVNET).map_err(|e| e.to_string())?;
        if Instant::now() >= deadline {
            return Err(format!(
                "peer exceeded response deadline while awaiting {label}"
            ));
        }
        if frame.request_id == expected_request_id
            && expected_message_types.contains(&frame.message_type)
        {
            return Ok(frame);
        }
        interleaved_frames = interleaved_frames.saturating_add(1);
        if interleaved_frames > MAX_TX_RELAY_INTERLEAVED_FRAMES {
            return Err(format!(
                "peer sent too many interleaved frames while awaiting {label}"
            ));
        }
        if frame.request_id == 0 {
            continue;
        }
        if service_tx_relay_interleaved_frame(data_dir, stream, &frame)? {
            continue;
        }
        return Err(format!(
            "peer returned unexpected frame while awaiting {label}: type={:#06x} request_id={}",
            frame.message_type, frame.request_id
        ));
    }
}

fn push_tx_to_peer_persistent(
    data_dir: &Path,
    sessions: &SessionRegistry,
    peer: &str,
    pending: &PendingTxState,
) -> Result<String, String> {
    // Frozen Pack-H TXANNOUNCE -> GETTX -> TX inventory flow. The synchronous compatibility
    // caller now tolerates legitimate full-duplex interleaves without changing any message ID,
    // payload, RequestID, validation, or transaction semantics.
    with_persistent_peer(data_dir, sessions, peer, |stream| {
        let txid = decode32(&pending.txid)?;
        Frame::new(P2P_MAGIC_DEVNET, MSG_TX_ANNOUNCE, 4, txid.to_vec())
            .map_err(|e| e.to_string())?
            .write_to(stream)
            .map_err(|e| e.to_string())?;

        let first = read_tx_relay_expected_response(
            data_dir,
            stream,
            4,
            &[MSG_GET_TX, MSG_DEVNET_TX_RESULT],
            "GETTX/TX_RESULT",
        )?;
        if first.message_type == MSG_DEVNET_TX_RESULT {
            return String::from_utf8(first.payload).map_err(|e| e.to_string());
        }
        if first.payload.as_slice() != &txid[..] {
            return Err("peer GETTX payload does not match announced transaction".into());
        }

        let payload = pending
            .to_transaction_for_network(DEVNET_NETWORK_ID)?
            .encode_full();
        Frame::new(P2P_MAGIC_DEVNET, MSG_TX, first.request_id, payload)
            .map_err(|e| e.to_string())?
            .write_to(stream)
            .map_err(|e| e.to_string())?;
        let result = read_tx_relay_expected_response(
            data_dir,
            stream,
            first.request_id,
            &[MSG_DEVNET_TX_RESULT],
            "TX_RESULT",
        )?;
        String::from_utf8(result.payload).map_err(|e| e.to_string())
    })
}

#[cfg(test)]
fn gossip_transaction(
    data_dir: PathBuf,
    peers: PeerRegistry,
    sessions: SessionRegistry,
    pending: PendingTxState,
) {
    // Fire-and-forget relay. Duplicate announcements stop naturally because peers answer
    // ALREADY_KNOWN and do not request the full transaction again.
    thread::spawn(move || {
        let targets = match peer_snapshot(&peers) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("peer registry error during gossip: {e}");
                return;
            }
        };
        for peer in &targets {
            match push_tx_to_peer_persistent(&data_dir, &sessions, peer, &pending) {
                Ok(result) if result.starts_with("ACCEPTED") => {
                    println!("Gossiped {} to {peer}: {result}", pending.txid);
                }
                Ok(_) => {}
                Err(e) => eprintln!("Transaction gossip to {peer} failed: {e}"),
            }
        }
    });
}

fn chainwork(state: &DevnetState) -> Result<BigUint, String> {
    let two256 = BigUint::from(1u8) << 256usize;
    let mut total = BigUint::from(0u8);
    for block in &state.blocks {
        let target = BigUint::from_bytes_be(&decode32(&block.target)?);
        let work = &two256 / (target + BigUint::from(1u8));
        total += work;
    }
    Ok(total)
}

fn chainwork_hex(state: &DevnetState) -> Result<String, String> {
    Ok(format!("0x{}", chainwork(state)?.to_str_radix(16)))
}

fn validate_pending_candidate(
    state: &DevnetState,
    pending: &PendingTxState,
    allow_protocol_bound: bool,
) -> Result<(), String> {
    // A native license payment is inseparable from its Protocol Op 0x0002. Build 5.0
    // propagates that bundle in completed BLOCK bodies; TXANNOUNCE has no op-bundle field yet.
    // Refuse an orphan payment transaction from TX-only gossip. Reorg restoration passes
    // allow_protocol_bound=true because it reconstructs the operation bundle from the
    // previously validated disconnected block immediately after restoring the transaction.
    if pending.has_license_payment_output() && !allow_protocol_bound {
        return Err("native Mining License payment requires its Protocol Op 0x0002 bundle; Build 5.2 accepts it through validated block propagation".into());
    }
    if pending.has_protocol_auth_witness() && !allow_protocol_bound {
        return Err("protocol-authorized Treasury payment requires its signed DividendClaim Protocol Op 0x0007 bundle; Build 5.2 accepts it through validated block propagation".into());
    }
    if state.mempool.iter().any(|t| t.txid == pending.txid)
        || state
            .confirmed_transactions
            .iter()
            .any(|t| t.tx.txid == pending.txid)
    {
        return Err("ALREADY_KNOWN".into());
    }
    if pending.has_protocol_auth_witness() && allow_protocol_bound {
        // Reorg restoration only reaches this path for a transaction reconstructed from a
        // previously validated disconnected block. Validate its canonical stored envelope here;
        // the restored matching 0x0007 operation performs full Treasury authorization before
        // reconfirmation.
        let tx = pending.to_transaction_for_network(state.network_id)?;
        if tx.txid().to_hex() != pending.txid || tx.wtxid().to_hex() != pending.wtxid {
            return Err("restored protocol-authorized transaction ID mismatch".into());
        }
        if tx.core.version != 1
            || tx.core.network_id != state.network_id
            || tx.core.inputs.is_empty()
            || tx.core.outputs.is_empty()
            || tx.witnesses.len() != tx.core.inputs.len()
        {
            return Err("restored protocol-authorized transaction envelope is invalid".into());
        }
        return Ok(());
    }
    let mut temp = state.clone();
    temp.mempool.push(pending.clone());
    let mut working = temp.utxos.clone();
    validate_and_apply_mempool(
        &temp,
        &mut working,
        next_mineable_epoch(&temp),
        temp.height + 1,
        &[],
    )?;
    Ok(())
}

fn validate_received_pending(state: &DevnetState, pending: &PendingTxState) -> Result<(), String> {
    let already_known = state.mempool.iter().any(|tx| tx.txid == pending.txid)
        || state
            .confirmed_transactions
            .iter()
            .any(|tx| tx.tx.txid == pending.txid);
    if state.mempool.len() >= MAX_NETWORK_MEMPOOL_TXS && !already_known {
        return Err(format!(
            "network mempool admission cap {} reached",
            MAX_NETWORK_MEMPOOL_TXS
        ));
    }
    validate_pending_candidate(state, pending, false)
}

#[cfg(test)]
fn serve_authenticated_frame(
    stream: &mut TcpStream,
    frame: Frame,
    data_dir: &Path,
    shared: &Arc<Mutex<DevnetState>>,
    gossip_peers: &PeerRegistry,
    sessions: &SessionRegistry,
    local_listen: &str,
) -> Result<(), String> {
    match frame.message_type {
        MSG_ADDR => {
            for peer in decode_peer_addresses(&frame.payload)? {
                if register_runtime_peer(data_dir, gossip_peers, &peer, local_listen)? {
                    println!("Discovered authenticated peer {peer}");
                }
            }
        }
        MSG_PING => {
            Frame::new(P2P_MAGIC_DEVNET, MSG_PONG, frame.request_id, frame.payload)
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
        }
        MSG_PONG => {
            // PONG is normally consumed by the outbound requester. Accepting an unsolicited
            // one is harmless and keeps the persistent session protocol symmetric.
        }
        MSG_GET_ADDR => {
            let mut peers = peer_snapshot(gossip_peers)?;
            if let Ok(advertise) = fs::read_to_string(advertise_path(data_dir)) {
                let advertised = advertise.trim();
                if !advertised.is_empty() && !peers.iter().any(|p| p == advertised) {
                    peers.push(advertised.to_string());
                }
            }
            peers.truncate(MAX_RUNTIME_PEERS);
            let epoch = shared.lock().map_err(|_| "state mutex poisoned")?.tip_epoch;
            let payload = encode_peer_addresses(&peers, epoch)?;
            Frame::new(P2P_MAGIC_DEVNET, MSG_ADDR, frame.request_id, payload)
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
        }
        MSG_GET_HEADERS => {
            let state = shared.lock().map_err(|_| "state mutex poisoned")?;
            let payload = blocksync::serve_get_headers(&state, &frame.payload)?;
            Frame::new(P2P_MAGIC_DEVNET, MSG_HEADERS, frame.request_id, payload)
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
        }
        MSG_GET_BLOCK => {
            let state = shared.lock().map_err(|_| "state mutex poisoned")?;
            let payload = blocksync::serve_get_block(&state, &frame.payload)?;
            Frame::new(P2P_MAGIC_DEVNET, MSG_BLOCK, frame.request_id, payload)
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
        }
        MSG_BLOCK_ANNOUNCE => {
            if frame.payload.len() != 32 {
                return Err("BLOCKANNOUNCE payload must be one 32-byte BlockHash".into());
            }
            let announced: [u8; 32] = frame.payload.as_slice().try_into().unwrap();
            let announced_hex = hex::encode(announced);
            let known = {
                let state = shared.lock().map_err(|_| "state mutex poisoned")?;
                blocksync::block_known(&state, &announced_hex)
            };
            if known {
                let msg = format!("ALREADY_KNOWN {announced_hex}");
                Frame::new(
                    P2P_MAGIC_DEVNET,
                    MSG_DEVNET_BLOCK_RESULT,
                    frame.request_id,
                    msg.into_bytes(),
                )
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
            } else {
                Frame::new(
                    P2P_MAGIC_DEVNET,
                    MSG_GET_BLOCK,
                    frame.request_id,
                    announced.to_vec(),
                )
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
                let block_frame =
                    Frame::read_from(stream, P2P_MAGIC_DEVNET).map_err(|e| e.to_string())?;
                if block_frame.message_type != MSG_BLOCK
                    || block_frame.request_id != frame.request_id
                {
                    return Err("expected matching BLOCK after GETBLOCK".into());
                }
                let (header, txs, operations) =
                    blocksync::decode_block_payload(&block_frame.payload)?;
                if block_hash(&header).0 != announced {
                    return Err("announced BlockHash does not match supplied BLOCK".into());
                }
                let result = {
                    let mut state = shared.lock().map_err(|_| "state mutex poisoned")?;
                    match blocksync::validate_and_apply_announced_block(
                        &mut state,
                        header,
                        txs,
                        operations,
                        &RuntimeIngressContext {
                            runtime: RuntimeNetwork::Devnet,
                            bootstrap_witness: None,
                        },
                    ) {
                        Ok(hash) => {
                            save_state(data_dir, &state)?;
                            format!("ACCEPTED {hash}")
                        }
                        Err(e) => format!("REJECTED {e}"),
                    }
                };
                Frame::new(
                    P2P_MAGIC_DEVNET,
                    MSG_DEVNET_BLOCK_RESULT,
                    frame.request_id,
                    result.into_bytes(),
                )
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
            }
        }
        MSG_TX_ANNOUNCE => {
            if frame.payload.len() != 32 {
                return Err("TXANNOUNCE payload must be one 32-byte TXID".into());
            }
            let announced: [u8; 32] = frame.payload.as_slice().try_into().unwrap();
            let announced_hex = hex::encode(announced);
            let known = {
                let state = shared.lock().map_err(|_| "state mutex poisoned")?;
                state.mempool.iter().any(|t| t.txid == announced_hex)
                    || state
                        .confirmed_transactions
                        .iter()
                        .any(|t| t.tx.txid == announced_hex)
            };
            if known {
                let msg = format!("ALREADY_KNOWN {announced_hex}");
                Frame::new(
                    P2P_MAGIC_DEVNET,
                    MSG_DEVNET_TX_RESULT,
                    frame.request_id,
                    msg.into_bytes(),
                )
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
            } else {
                Frame::new(
                    P2P_MAGIC_DEVNET,
                    MSG_GET_TX,
                    frame.request_id,
                    announced.to_vec(),
                )
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
                let tx_frame =
                    Frame::read_from(stream, P2P_MAGIC_DEVNET).map_err(|e| e.to_string())?;
                if tx_frame.message_type != MSG_TX || tx_frame.request_id != frame.request_id {
                    return Err("expected matching Pack-H TX response after GETTX".into());
                }
                let tx =
                    TransactionV1::decode_full(&tx_frame.payload).map_err(|e| e.to_string())?;
                if tx.txid().0 != announced {
                    return Err("canonical TX payload does not match announced TXID".into());
                }
                let (result, accepted_pending) = {
                    let mut state = shared.lock().map_err(|_| "state mutex poisoned")?;
                    let pending = blocksync::pending_from_transaction(&state, &tx)?;
                    let result = match validate_received_pending(&state, &pending) {
                        Ok(()) => {
                            state.mempool.push(pending.clone());
                            save_state(data_dir, &state)?;
                            format!("ACCEPTED {}", pending.txid)
                        }
                        Err(e) if e == "ALREADY_KNOWN" => format!("ALREADY_KNOWN {}", pending.txid),
                        Err(e) => format!("REJECTED {e}"),
                    };
                    let accepted = result.starts_with("ACCEPTED").then_some(pending);
                    (result, accepted)
                };
                Frame::new(
                    P2P_MAGIC_DEVNET,
                    MSG_DEVNET_TX_RESULT,
                    frame.request_id,
                    result.into_bytes(),
                )
                .map_err(|e| e.to_string())?
                .write_to(stream)
                .map_err(|e| e.to_string())?;
                if let Some(pending) = accepted_pending {
                    gossip_transaction(
                        data_dir.to_path_buf(),
                        gossip_peers.clone(),
                        sessions.clone(),
                        pending,
                    );
                }
            }
        }
        other => {
            return Err(format!(
                "unsupported Build 4.4.1 Devnet message {other:#06x}"
            ))
        }
    }
    Ok(())
}

#[cfg(test)]
fn handle_p2p_connection(
    mut stream: TcpStream,
    data_dir: PathBuf,
    shared: Arc<Mutex<DevnetState>>,
    gossip_peers: PeerRegistry,
    sessions: SessionRegistry,
    local_listen: String,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(180)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;

    let key = load_runtime_node_key(&data_dir).map_err(|e| e.to_string())?;
    let info = responder_handshake(
        &mut stream,
        &key,
        CAP_BUILD45_NODE,
        DEVNET_NETWORK_ID,
        P2P_MAGIC_DEVNET,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "Persistent inbound session authenticated ({})",
        &info.node_id.to_hex()[..16]
    );

    loop {
        let frame = match Frame::read_from(&mut stream, P2P_MAGIC_DEVNET) {
            Ok(frame) => frame,
            Err(P2pError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                println!(
                    "Persistent inbound session closed ({})",
                    &info.node_id.to_hex()[..16]
                );
                return Ok(());
            }
            Err(e) => return Err(e.to_string()),
        };
        serve_authenticated_frame(
            &mut stream,
            frame,
            &data_dir,
            &shared,
            &gossip_peers,
            &sessions,
            &local_listen,
        )?;
    }
}

#[cfg(test)]
fn ping_peer_persistent(
    data_dir: &Path,
    sessions: &SessionRegistry,
    peer: &str,
    nonce: u64,
) -> Result<(), String> {
    with_persistent_peer(data_dir, sessions, peer, |stream| {
        let payload = nonce.to_be_bytes().to_vec();
        Frame::new(P2P_MAGIC_DEVNET, MSG_PING, 0x4300 ^ nonce, payload.clone())
            .map_err(|e| e.to_string())?
            .write_to(stream)
            .map_err(|e| e.to_string())?;
        let response = Frame::read_from(stream, P2P_MAGIC_DEVNET).map_err(|e| e.to_string())?;
        if response.message_type != MSG_PONG || response.payload != payload {
            return Err("peer did not return matching PONG".into());
        }
        Ok(())
    })
}

fn run_duplex_selftest(data_dir: &Path) -> Result<(), String> {
    use std::sync::mpsc;

    let lab = data_dir.join("duplex-selftest");
    let client_dir = lab.join("client");
    let server_dir = lab.join("server");
    let _ = fs::remove_dir_all(&lab);
    fs::create_dir_all(&client_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&server_dir).map_err(|e| e.to_string())?;

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || -> Result<mutiny_duplex::DuplexMetrics, String> {
        let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        let key = SigningKey::from_bytes(&[0x55u8; 32]);
        let info = responder_handshake(
            &mut stream,
            &key,
            CAP_BUILD45_NODE,
            DEVNET_NETWORK_ID,
            P2P_MAGIC_DEVNET,
        )
        .map_err(|e| e.to_string())?;
        let local_id = mutiny_p2p::node_id(&key.verifying_key().to_bytes()).0;
        let remote_id = info.node_id.0;
        let lane_high = local_id > remote_id;
        let duplex = DuplexSession::from_authenticated_stream(stream, P2P_MAGIC_DEVNET, lane_high)
            .map_err(|e| e.to_string())?;
        ready_tx.send(()).map_err(|e| e.to_string())?;

        let first = duplex
            .recv_unsolicited(Duration::from_secs(5))
            .map_err(|e| e.to_string())?
            .ok_or("server did not receive first duplex request")?;
        let second = duplex
            .recv_unsolicited(Duration::from_secs(5))
            .map_err(|e| e.to_string())?
            .ok_or("server did not receive second duplex request")?;

        duplex
            .send_unsolicited(MSG_BLOCK_ANNOUNCE, vec![0x45; 32])
            .map_err(|e| e.to_string())?;

        for frame in [&second, &first] {
            let (message_type, payload) = match frame.message_type {
                MSG_PING => (MSG_PONG, frame.payload.clone()),
                MSG_GET_ADDR => (MSG_ADDR, b"duplex-addr".to_vec()),
                other => return Err(format!("unexpected selftest request type {other:#06x}")),
            };
            duplex
                .send_frame(
                    Frame::new(P2P_MAGIC_DEVNET, message_type, frame.request_id, payload)
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
        }

        let reverse = duplex
            .request(
                MSG_PING,
                b"reverse".to_vec(),
                &[MSG_PONG],
                Duration::from_secs(5),
            )
            .map_err(|e| e.to_string())?;
        if reverse.payload.as_slice() != b"reverse" {
            return Err("reverse duplex PONG payload mismatch".into());
        }
        let metrics = duplex.metrics();
        duplex.close();
        Ok(metrics)
    });

    let mut stream = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let key = SigningKey::from_bytes(&[0x56u8; 32]);
    let info = initiator_handshake(
        &mut stream,
        &key,
        CAP_BUILD45_NODE,
        DEVNET_NETWORK_ID,
        P2P_MAGIC_DEVNET,
    )
    .map_err(|e| e.to_string())?;
    let local_id = mutiny_p2p::node_id(&key.verifying_key().to_bytes()).0;
    let remote_id = info.node_id.0;
    let lane_high = local_id > remote_id;
    let preferred = preferred_direction(local_id, remote_id);
    let client = DuplexSession::from_authenticated_stream(stream, P2P_MAGIC_DEVNET, lane_high)
        .map_err(|e| e.to_string())?;
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;

    let c1 = client.clone();
    let ping = thread::spawn(move || {
        c1.request_with_id(
            101,
            MSG_PING,
            b"alpha".to_vec(),
            &[MSG_PONG],
            Duration::from_secs(5),
        )
    });
    let c2 = client.clone();
    let addr_req = thread::spawn(move || {
        c2.request_with_id(
            102,
            MSG_GET_ADDR,
            Vec::new(),
            &[MSG_ADDR],
            Duration::from_secs(5),
        )
    });

    let ping_response = ping
        .join()
        .map_err(|_| "PING request thread panicked")?
        .map_err(|e| e.to_string())?;
    let addr_response = addr_req
        .join()
        .map_err(|_| "GETADDR request thread panicked")?
        .map_err(|e| e.to_string())?;
    if ping_response.request_id != 101 || ping_response.payload.as_slice() != b"alpha" {
        return Err("out-of-order PING response routed incorrectly".into());
    }
    if addr_response.request_id != 102 || addr_response.payload.as_slice() != b"duplex-addr" {
        return Err("out-of-order GETADDR response routed incorrectly".into());
    }

    let announce = client
        .recv_unsolicited(Duration::from_secs(5))
        .map_err(|e| e.to_string())?
        .ok_or("client did not receive unsolicited BLOCKANNOUNCE")?;
    if announce.message_type != MSG_BLOCK_ANNOUNCE
        || announce.request_id != 0
        || announce.payload != vec![0x45; 32]
    {
        return Err("unsolicited BLOCKANNOUNCE routing mismatch".into());
    }

    let reverse = client
        .recv_unsolicited(Duration::from_secs(5))
        .map_err(|e| e.to_string())?
        .ok_or("client did not receive reverse-direction request")?;
    if reverse.message_type != MSG_PING || reverse.payload.as_slice() != b"reverse" {
        return Err("reverse-direction request routing mismatch".into());
    }
    client
        .send_frame(
            Frame::new(
                P2P_MAGIC_DEVNET,
                MSG_PONG,
                reverse.request_id,
                reverse.payload,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;

    let server_metrics = server
        .join()
        .map_err(|_| "duplex selftest server thread panicked")??;
    let client_metrics = client.metrics();
    client.close();

    println!("Duplex authenticated loopback selftest: PASS");
    println!("RequestID 101/102 out-of-order routing: PASS");
    println!("Unsolicited BLOCKANNOUNCE during pending requests: PASS");
    println!("Reverse-direction request on same TCP session: PASS");
    println!(
        "Deterministic duplicate preference for this pair: {:?}",
        preferred
    );
    println!(
        "client metrics: sent={} received={} requests={} responses={} unsolicited={} timeouts={}",
        client_metrics.frames_sent,
        client_metrics.frames_received,
        client_metrics.requests_started,
        client_metrics.responses_routed,
        client_metrics.unsolicited_routed,
        client_metrics.request_timeouts,
    );
    println!(
        "server metrics: sent={} received={} requests={} responses={} unsolicited={} timeouts={}",
        server_metrics.frames_sent,
        server_metrics.frames_received,
        server_metrics.requests_started,
        server_metrics.responses_routed,
        server_metrics.unsolicited_routed,
        server_metrics.request_timeouts,
    );
    Ok(())
}

// =========================================================================================
// Build 4.5.2 - frozen live asynchronous duplex peer manager
// =========================================================================================

#[derive(Clone)]
struct LiveDuplexPeer {
    node_id_hex: String,
    address: Option<String>,
    direction: ConnectionDirection,
    source_ip: Option<IpAddr>,
    session: DuplexSession,
}

type LiveDuplexRegistry = Arc<Mutex<HashMap<String, LiveDuplexPeer>>>;

#[derive(Debug, Default)]
struct DuplexManagerCounters {
    authenticated_candidates: u64,
    accepted_sessions: u64,
    duplicate_drops: u64,
    duplicate_replacements: u64,
    dial_failures: u64,
    reconnect_successes: u64,
    live_peer_cap_drops: u64,
    inbound_live_cap_drops: u64,
    inbound_ip_cap_drops: u64,
    inbound_admission_drops: u64,
    announce_worker_drops: u64,
    request_budget_closes: u64,
    request_budget_delays: u64,
}

type DuplexManagerStats = Arc<Mutex<DuplexManagerCounters>>;

#[derive(Debug, Default)]
struct DuplexDialState {
    consecutive_failures: u32,
    retry_after: Option<Instant>,
    successful_connects: u64,
}

type DuplexDialRegistry = Arc<Mutex<HashMap<String, DuplexDialState>>>;

#[derive(Default)]
struct InboundAdmissionState {
    total: usize,
    by_ip: HashMap<IpAddr, usize>,
}

type InboundAdmission = Arc<Mutex<InboundAdmissionState>>;

struct InboundAdmissionPermit {
    admission: InboundAdmission,
    ip: IpAddr,
}

impl Drop for InboundAdmissionPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.admission.lock() {
            state.total = state.total.saturating_sub(1);
            if let Some(count) = state.by_ip.get_mut(&self.ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.by_ip.remove(&self.ip);
                }
            }
        }
    }
}

fn try_acquire_inbound_admission(
    admission: &InboundAdmission,
    ip: IpAddr,
) -> Result<Option<InboundAdmissionPermit>, String> {
    let mut state = admission
        .lock()
        .map_err(|_| "inbound admission mutex poisoned")?;
    let per_ip = state.by_ip.get(&ip).copied().unwrap_or(0);
    if state.total >= MAX_INBOUND_HANDSHAKES || per_ip >= MAX_INBOUND_HANDSHAKES_PER_IP {
        return Ok(None);
    }
    state.total += 1;
    *state.by_ip.entry(ip).or_insert(0) += 1;
    Ok(Some(InboundAdmissionPermit {
        admission: admission.clone(),
        ip,
    }))
}

static ANNOUNCE_WORKERS: AtomicUsize = AtomicUsize::new(0);

struct AnnounceWorkPermit;

impl Drop for AnnounceWorkPermit {
    fn drop(&mut self) {
        ANNOUNCE_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_announce_work() -> Option<AnnounceWorkPermit> {
    loop {
        let current = ANNOUNCE_WORKERS.load(Ordering::Acquire);
        if current >= MAX_ANNOUNCE_WORKERS {
            return None;
        }
        if ANNOUNCE_WORKERS
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(AnnounceWorkPermit);
        }
    }
}

struct ExpensiveRequestBudget {
    window_started: Instant,
    used: u32,
}

impl ExpensiveRequestBudget {
    fn new() -> Self {
        Self {
            window_started: Instant::now(),
            used: 0,
        }
    }

    fn try_consume(&mut self) -> bool {
        if self.window_started.elapsed() >= EXPENSIVE_REQUEST_WINDOW {
            self.window_started = Instant::now();
            self.used = 0;
        }
        if self.used >= MAX_EXPENSIVE_REQUESTS_PER_WINDOW {
            return false;
        }
        self.used += 1;
        true
    }

    fn remaining_until_reset(&self) -> Duration {
        EXPENSIVE_REQUEST_WINDOW.saturating_sub(self.window_started.elapsed())
    }

    fn reset_and_consume(&mut self) {
        self.window_started = Instant::now();
        self.used = 1;
    }
}

fn is_expensive_peer_request(message_type: u16) -> bool {
    matches!(message_type, MSG_GET_HEADERS | MSG_GET_BLOCK | MSG_GET_TX)
}

fn new_live_duplex_registry() -> LiveDuplexRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

fn new_duplex_manager_stats() -> DuplexManagerStats {
    Arc::new(Mutex::new(DuplexManagerCounters::default()))
}

fn new_duplex_dial_registry() -> DuplexDialRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

fn live_duplex_snapshot(registry: &LiveDuplexRegistry) -> Result<Vec<LiveDuplexPeer>, String> {
    let mut state = registry
        .lock()
        .map_err(|_| "duplex peer registry mutex poisoned")?;
    state.retain(|_, peer| !peer.session.is_closed());
    Ok(state.values().cloned().collect())
}

fn update_duplex_peer_address(
    registry: &LiveDuplexRegistry,
    node_id_hex: &str,
    address: &str,
) -> Result<(), String> {
    let mut state = registry
        .lock()
        .map_err(|_| "duplex peer registry mutex poisoned")?;
    if let Some(peer) = state.get_mut(node_id_hex) {
        peer.address = Some(address.to_string());
    }
    Ok(())
}

fn register_duplex_candidate(
    registry: &LiveDuplexRegistry,
    stats: &DuplexManagerStats,
    local_node_id: [u8; 32],
    info: &PeerInfo,
    address: Option<String>,
    source_ip: Option<IpAddr>,
    direction: ConnectionDirection,
    session: DuplexSession,
) -> Result<bool, String> {
    let remote_node_id = info.node_id.0;
    let remote_hex = info.node_id.to_hex();
    if remote_node_id == local_node_id {
        session.close();
        return Err("refusing self duplex session".into());
    }
    {
        let mut counters = stats
            .lock()
            .map_err(|_| "duplex manager stats mutex poisoned")?;
        counters.authenticated_candidates = counters.authenticated_candidates.saturating_add(1);
    }

    let mut state = registry
        .lock()
        .map_err(|_| "duplex peer registry mutex poisoned")?;
    if let Some(current) = state.get(&remote_hex).cloned() {
        if current.session.is_closed() {
            state.remove(&remote_hex);
        } else if candidate_should_replace(
            local_node_id,
            remote_node_id,
            current.direction,
            direction,
        ) {
            current.session.close();
            state.insert(
                remote_hex.clone(),
                LiveDuplexPeer {
                    node_id_hex: remote_hex.clone(),
                    address: address.or(current.address),
                    direction,
                    source_ip,
                    session: session.clone(),
                },
            );
            let mut counters = stats
                .lock()
                .map_err(|_| "duplex manager stats mutex poisoned")?;
            counters.accepted_sessions = counters.accepted_sessions.saturating_add(1);
            counters.duplicate_replacements = counters.duplicate_replacements.saturating_add(1);
            println!(
                "Duplex duplicate collapse: replaced {:?} with preferred {:?} for {}",
                current.direction,
                direction,
                &remote_hex[..16]
            );
            return Ok(true);
        } else {
            if let Some(existing) = state.get_mut(&remote_hex) {
                if existing.address.is_none() {
                    existing.address = address.clone();
                }
            }
            session.close();
            let mut counters = stats
                .lock()
                .map_err(|_| "duplex manager stats mutex poisoned")?;
            counters.duplicate_drops = counters.duplicate_drops.saturating_add(1);
            println!(
                "Duplex duplicate collapse: kept {:?}, dropped {:?} for {}",
                current.direction,
                direction,
                &remote_hex[..16]
            );
            return Ok(false);
        }
    }

    state.retain(|_, peer| !peer.session.is_closed());
    if direction == ConnectionDirection::Inbound {
        let inbound_count = state
            .values()
            .filter(|peer| peer.direction == ConnectionDirection::Inbound)
            .count();
        if inbound_count >= MAX_INBOUND_DUPLEX_PEERS {
            session.close();
            let mut counters = stats
                .lock()
                .map_err(|_| "duplex manager stats mutex poisoned")?;
            counters.inbound_live_cap_drops = counters.inbound_live_cap_drops.saturating_add(1);
            return Ok(false);
        }
        if let Some(ip) = source_ip {
            let same_ip = state
                .values()
                .filter(|peer| {
                    peer.direction == ConnectionDirection::Inbound && peer.source_ip == Some(ip)
                })
                .count();
            if same_ip >= MAX_INBOUND_DUPLEX_PEERS_PER_IP {
                session.close();
                let mut counters = stats
                    .lock()
                    .map_err(|_| "duplex manager stats mutex poisoned")?;
                counters.inbound_ip_cap_drops = counters.inbound_ip_cap_drops.saturating_add(1);
                return Ok(false);
            }
        }
    }
    if state.len() >= MAX_LIVE_DUPLEX_PEERS {
        session.close();
        let mut counters = stats
            .lock()
            .map_err(|_| "duplex manager stats mutex poisoned")?;
        counters.live_peer_cap_drops = counters.live_peer_cap_drops.saturating_add(1);
        return Ok(false);
    }

    state.insert(
        remote_hex.clone(),
        LiveDuplexPeer {
            node_id_hex: remote_hex.clone(),
            address,
            direction,
            source_ip,
            session: session.clone(),
        },
    );
    let mut counters = stats
        .lock()
        .map_err(|_| "duplex manager stats mutex poisoned")?;
    counters.accepted_sessions = counters.accepted_sessions.saturating_add(1);
    println!(
        "Live duplex session registered: {} direction={:?} preferred={:?}",
        &remote_hex[..16],
        direction,
        preferred_direction(local_node_id, remote_node_id)
    );
    Ok(true)
}

fn find_transaction_payload(state: &DevnetState, txid: [u8; 32]) -> Result<Vec<u8>, String> {
    let txid_hex = hex::encode(txid);
    if let Some(pending) = state.mempool.iter().find(|t| t.txid == txid_hex) {
        return Ok(pending
            .to_transaction_for_network(state.network_id)?
            .encode_full());
    }
    if let Some(confirmed) = state
        .confirmed_transactions
        .iter()
        .find(|t| t.tx.txid == txid_hex)
    {
        return Ok(confirmed
            .tx
            .to_transaction_for_network(state.network_id)?
            .encode_full());
    }
    Err("requested transaction not found".into())
}

fn duplex_announce_tx_to_registry(
    registry: &LiveDuplexRegistry,
    txid: [u8; 32],
    exclude_node_id: Option<&str>,
) {
    let peers = match live_duplex_snapshot(registry) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("duplex registry snapshot failed during TXANNOUNCE: {e}");
            return;
        }
    };
    for peer in peers {
        if exclude_node_id.is_some_and(|id| id == peer.node_id_hex.as_str()) {
            continue;
        }
        if let Err(e) = peer
            .session
            .send_unsolicited(MSG_TX_ANNOUNCE, txid.to_vec())
        {
            eprintln!(
                "duplex TXANNOUNCE to {} failed: {e}",
                &peer.node_id_hex[..16]
            );
        }
    }
}

static BLOCK_SYNC_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

struct BlockSyncPermit;

impl Drop for BlockSyncPermit {
    fn drop(&mut self) {
        BLOCK_SYNC_IN_FLIGHT.store(false, std::sync::atomic::Ordering::Release);
    }
}

fn try_acquire_block_sync() -> Option<BlockSyncPermit> {
    BLOCK_SYNC_IN_FLIGHT
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .ok()
        .map(|_| BlockSyncPermit)
}
fn duplex_announce_block_to_registry(registry: &LiveDuplexRegistry, hash: [u8; 32]) {
    let peers = match live_duplex_snapshot(registry) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("duplex registry snapshot failed during BLOCKANNOUNCE: {e}");
            return;
        }
    };
    for peer in peers {
        if let Err(e) = peer
            .session
            .send_unsolicited(MSG_BLOCK_ANNOUNCE, hash.to_vec())
        {
            eprintln!(
                "duplex BLOCKANNOUNCE to {} failed: {e}",
                &peer.node_id_hex[..16]
            );
        }
    }
}

// A commit error may occur after durable metadata publication. Continuing
// from the old in-memory tip would permit a stale follow-up commit. Stop the
// entire Mainnet runtime; startup owns journal recovery and authentication.
fn save_live_runtime_state(dir: &Path, state: &DevnetState) -> Result<(), String> {
    let result = save_state(dir, state);
    if state.network_id == MAINNET_NETWORK_ID {
        if let Err(error) = &result {
            eprintln!("LOCAL_STORAGE_FAILURE: {error}; Mainnet runtime stopping for recovery");
            std::process::exit(1);
        }
    }
    result
}

#[derive(Debug, PartialEq, Eq)]
enum RuntimeIngressDisposition {
    Persist(String),
    LocalFailure(String),
    ConsensusReject(String),
}

// Classify only the completed validation result. This helper cannot validate,
// mutate live state, persist, send peer messages, or update peer reputation.
fn classify_runtime_ingress_result(
    result: Result<String, blocksync::RuntimeBlockApplyError>,
) -> RuntimeIngressDisposition {
    match result {
        Ok(hash) => RuntimeIngressDisposition::Persist(hash),
        Err(blocksync::RuntimeBlockApplyError::LocalBootstrapInput(message)) => {
            RuntimeIngressDisposition::LocalFailure(message)
        }
        Err(error @ blocksync::RuntimeBlockApplyError::ConsensusTransition(_)) => {
            RuntimeIngressDisposition::ConsensusReject(error.to_string())
        }
    }
}

fn process_duplex_block_announce(
    data_dir: PathBuf,
    shared: Arc<Mutex<DevnetState>>,
    session: DuplexSession,
    remote_node_id_hex: String,
    announced: [u8; 32],
    legacy_request_id: Option<u64>,
    _work_permit: AnnounceWorkPermit,
    ingress: Arc<RuntimeIngressContext>,
) {
    let block_sync_permit = if legacy_request_id.is_none() {
        match try_acquire_block_sync() {
            Some(permit) => Some(permit),
            None => return,
        }
    } else {
        None
    };

    thread::spawn(move || {
        let _block_sync_permit = block_sync_permit;
        let _work_permit = _work_permit;
        let announced_hex = hex::encode(announced);
        let known = match shared.lock() {
            Ok(state) => blocksync::block_known(&state, &announced_hex),
            Err(_) => return,
        };
        if known {
            if let Some(request_id) = legacy_request_id {
                let message = format!("ALREADY_KNOWN {announced_hex}");
                let _ = session.send_frame(
                    Frame::new(
                        ingress.runtime.p2p_magic(),
                        MSG_DEVNET_BLOCK_RESULT,
                        request_id,
                        message.into_bytes(),
                    )
                    .expect("fixed Devnet block result frame"),
                );
            }
            return;
        }

        // Compatibility path for one-shot Build-4.x announcers. They expect GETBLOCK and a
        // final Devnet acknowledgement on their original RequestID. The normal 4.5.1 live
        // path uses RequestID zero and independently allocated duplex requests below.
        if let Some(request_id) = legacy_request_id {
            let block_frame = match session.request_with_id(
                request_id,
                MSG_GET_BLOCK,
                announced.to_vec(),
                &[MSG_BLOCK],
                EXPENSIVE_REQUEST_RESPONSE_TIMEOUT,
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("legacy-compatible duplex GETBLOCK failed: {e}");
                    return;
                }
            };
            let (header, txs, operations) =
                match blocksync::decode_block_payload(&block_frame.payload) {
                    Ok(v) => v,
                    Err(e) => {
                        let message = format!("REJECTED {e}");
                        let _ = session.send_frame(
                            Frame::new(
                                ingress.runtime.p2p_magic(),
                                MSG_DEVNET_BLOCK_RESULT,
                                request_id,
                                message.into_bytes(),
                            )
                            .expect("fixed Devnet block result frame"),
                        );
                        return;
                    }
                };
            if block_hash(&header).0 != announced {
                let _ = session.send_frame(
                    Frame::new(
                        ingress.runtime.p2p_magic(),
                        MSG_DEVNET_BLOCK_RESULT,
                        request_id,
                        b"REJECTED announced BlockHash does not match supplied BLOCK".to_vec(),
                    )
                    .expect("fixed block result frame"),
                );
                return;
            }
            let base = match shared.lock() {
                Ok(state) => state.clone(),
                Err(_) => return,
            };
            let extends_tip = decode32(&base.tip_hash)
                .map(|tip| header[14..46] == tip)
                .unwrap_or(false);
            if ingress.runtime == RuntimeNetwork::Mainnet && base.height > 0 && !extends_tip {
                // A competing parent requires branch reconstruction, not a peer-invalid verdict.
                let mut candidate = base.clone();
                let result = match blocksync::sync_state_from_peer_duplex_for_runtime(
                    &remote_node_id_hex[..16],
                    &session,
                    &mut candidate,
                    &ingress,
                ) {
                    Ok(report) => {
                        let mut current = match shared.lock() {
                            Ok(state) => state,
                            Err(_) => return,
                        };
                        if current.tip_hash != base.tip_hash || current.height != base.height {
                            return;
                        }
                        if report.applied_blocks > 0 || report.reorg {
                            if let Err(error) = blocksync::refresh_pending_after_runtime_commit(
                                &mut candidate,
                                &current,
                            ) {
                                eprintln!("LOCAL_PENDING_FAILURE: {error}");
                                return;
                            }
                            if let Err(error) = save_live_runtime_state(&data_dir, &candidate) {
                                format!("LOCAL_STORAGE_FAILURE: {error}")
                            } else {
                                *current = candidate;
                                format!("RECONCILED {}", report.decision)
                            }
                        } else {
                            format!("RECONCILED {}", report.decision)
                        }
                    }
                    Err(blocksync::RuntimeBlockApplyError::LocalBootstrapInput(error)) => {
                        eprintln!("LOCAL_BOOTSTRAP_INPUT: {error}");
                        return;
                    }
                    Err(error) => format!("REJECTED {error}"),
                };
                let _ = session.send_frame(
                    Frame::new(
                        ingress.runtime.p2p_magic(),
                        MSG_DEVNET_BLOCK_RESULT,
                        request_id,
                        result.into_bytes(),
                    )
                    .expect("fixed block result frame"),
                );
                return;
            }
            let result = {
                let mut state = match shared.lock() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if block_hash(&header).0 != announced {
                    "REJECTED announced BlockHash does not match supplied BLOCK".to_string()
                } else {
                    let mut candidate = state.clone();
                    let target = if ingress.runtime == RuntimeNetwork::Mainnet {
                        &mut candidate
                    } else {
                        &mut *state
                    };
                    match classify_runtime_ingress_result(
                        blocksync::validate_and_apply_announced_block(
                            target, header, txs, operations, &ingress,
                        ),
                    ) {
                        RuntimeIngressDisposition::Persist(hash) => {
                            let to_save = if ingress.runtime == RuntimeNetwork::Mainnet {
                                &candidate
                            } else {
                                &state
                            };
                            if let Err(e) = save_live_runtime_state(&data_dir, to_save) {
                                if ingress.runtime == RuntimeNetwork::Mainnet {
                                    format!("LOCAL_STORAGE_FAILURE: {e}")
                                } else {
                                    format!("REJECTED save failed: {e}")
                                }
                            } else {
                                if ingress.runtime == RuntimeNetwork::Mainnet {
                                    *state = candidate;
                                }
                                format!("ACCEPTED {hash}")
                            }
                        }
                        RuntimeIngressDisposition::LocalFailure(e) => {
                            eprintln!("LOCAL_BOOTSTRAP_INPUT: {e}");
                            return;
                        }
                        RuntimeIngressDisposition::ConsensusReject(e) => format!("REJECTED {e}"),
                    }
                }
            };
            let _ = session.send_frame(
                Frame::new(
                    ingress.runtime.p2p_magic(),
                    MSG_DEVNET_BLOCK_RESULT,
                    request_id,
                    result.into_bytes(),
                )
                .expect("fixed Devnet block result frame"),
            );
            return;
        }

        let base = match shared.lock() {
            Ok(state) => state.clone(),
            Err(_) => {
                eprintln!("state mutex poisoned while processing duplex block announcement");
                return;
            }
        };
        if ingress.runtime == RuntimeNetwork::Mainnet {
            let frame = match session.request(
                MSG_GET_BLOCK,
                announced.to_vec(),
                &[MSG_BLOCK],
                EXPENSIVE_REQUEST_RESPONSE_TIMEOUT,
            ) {
                Ok(frame) => frame,
                Err(e) => {
                    eprintln!("Mainnet GETBLOCK failed: {e}");
                    return;
                }
            };
            let (header, txs, operations) = match blocksync::decode_block_payload(&frame.payload) {
                Ok(block) => block,
                Err(e) => {
                    eprintln!("REJECTED Mainnet BLOCK decode: {e}");
                    return;
                }
            };
            if block_hash(&header).0 != announced {
                eprintln!("REJECTED announced BlockHash does not match supplied BLOCK");
                return;
            }
            let parent_matches = decode32(&base.tip_hash)
                .map(|tip| header[14..46] == tip)
                .unwrap_or(false);
            if base.height == 0 || parent_matches {
                let mut state = match shared.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                if state.height != base.height || state.tip_hash != base.tip_hash {
                    return;
                }
                let mut candidate = state.clone();
                match classify_runtime_ingress_result(
                    blocksync::validate_and_apply_announced_block(
                        &mut candidate,
                        header,
                        txs,
                        operations,
                        &ingress,
                    ),
                ) {
                    RuntimeIngressDisposition::Persist(hash) => {
                        match save_live_runtime_state(&data_dir, &candidate) {
                            Ok(()) => {
                                *state = candidate;
                                println!("ACCEPTED {hash}");
                            }
                            Err(e) => {
                                eprintln!("LOCAL_STORAGE_FAILURE after Mainnet block ingress: {e}")
                            }
                        }
                    }
                    RuntimeIngressDisposition::LocalFailure(e) => {
                        eprintln!("LOCAL_BOOTSTRAP_INPUT: {e}")
                    }
                    RuntimeIngressDisposition::ConsensusReject(e) => eprintln!("REJECTED {e}"),
                }
                return;
            }
        }
        let base_tip = base.tip_hash.clone();
        let mut candidate = base;
        match blocksync::sync_state_from_peer_duplex_for_runtime(
            &remote_node_id_hex[..16],
            &session,
            &mut candidate,
            &ingress,
        ) {
            Ok(report) if report.applied_blocks > 0 || report.reorg => {
                let mut current = match shared.lock() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if current.tip_hash != base_tip {
                    println!(
                        "Duplex BLOCKANNOUNCE sync: local tip changed concurrently; retrying later"
                    );
                    return;
                }
                if ingress.runtime == RuntimeNetwork::Mainnet {
                    if let Err(error) =
                        blocksync::refresh_pending_after_runtime_commit(&mut candidate, &current)
                    {
                        eprintln!("LOCAL_PENDING_FAILURE: {error}");
                        return;
                    }
                    if let Err(e) = save_live_runtime_state(&data_dir, &candidate) {
                        eprintln!("LOCAL_STORAGE_FAILURE after Mainnet block sync: {e}");
                        return;
                    }
                    *current = candidate;
                } else {
                    *current = candidate;
                    if let Err(e) = save_live_runtime_state(&data_dir, &current) {
                        eprintln!("save after duplex block sync failed: {e}");
                        return;
                    }
                }
                print_sync_report(&format!("duplex:{}", &remote_node_id_hex[..16]), &report);
            }
            Ok(_) => {}
            Err(e) => eprintln!("Duplex BLOCKANNOUNCE reconciliation failed: {e}"),
        }
    });
}

fn process_duplex_tx_announce(
    data_dir: PathBuf,
    shared: Arc<Mutex<DevnetState>>,
    registry: LiveDuplexRegistry,
    session: DuplexSession,
    remote_node_id_hex: String,
    announced: [u8; 32],
    legacy_request_id: Option<u64>,
    _work_permit: AnnounceWorkPermit,
    runtime: RuntimeNetwork,
) {
    thread::spawn(move || {
        let _work_permit = _work_permit;
        let announced_hex = hex::encode(announced);
        let known = match shared.lock() {
            Ok(state) => {
                state.mempool.iter().any(|t| t.txid == announced_hex)
                    || state
                        .confirmed_transactions
                        .iter()
                        .any(|t| t.tx.txid == announced_hex)
            }
            Err(_) => return,
        };
        if known {
            if let Some(request_id) = legacy_request_id {
                let message = format!("ALREADY_KNOWN {announced_hex}");
                let _ = session.send_frame(
                    Frame::new(
                        runtime.p2p_magic(),
                        MSG_DEVNET_TX_RESULT,
                        request_id,
                        message.into_bytes(),
                    )
                    .expect("fixed Devnet TX result frame"),
                );
            }
            return;
        }

        let tx_response = match legacy_request_id {
            Some(request_id) => session.request_with_id(
                request_id,
                MSG_GET_TX,
                announced.to_vec(),
                &[MSG_TX],
                EXPENSIVE_REQUEST_RESPONSE_TIMEOUT,
            ),
            None => session.request(
                MSG_GET_TX,
                announced.to_vec(),
                &[MSG_TX],
                EXPENSIVE_REQUEST_RESPONSE_TIMEOUT,
            ),
        };
        let frame = match tx_response {
            Ok(v) => v,
            Err(e) => {
                eprintln!("duplex GETTX for {announced_hex} failed: {e}");
                return;
            }
        };
        let tx = match TransactionV1::decode_full(&frame.payload) {
            Ok(v) => v,
            Err(e) => {
                if let Some(request_id) = legacy_request_id {
                    let message = format!("REJECTED {e}");
                    let _ = session.send_frame(
                        Frame::new(
                            runtime.p2p_magic(),
                            MSG_DEVNET_TX_RESULT,
                            request_id,
                            message.into_bytes(),
                        )
                        .expect("fixed Devnet TX result frame"),
                    );
                }
                eprintln!("duplex TX decode failed: {e}");
                return;
            }
        };
        if tx.txid().0 != announced {
            if let Some(request_id) = legacy_request_id {
                let _ = session.send_frame(
                    Frame::new(
                        runtime.p2p_magic(),
                        MSG_DEVNET_TX_RESULT,
                        request_id,
                        b"REJECTED canonical TX payload does not match announced TXID".to_vec(),
                    )
                    .expect("fixed Devnet TX result frame"),
                );
            }
            eprintln!("duplex TX payload did not match announced TXID");
            return;
        }
        let accepted_pending = {
            let mut state = match shared.lock() {
                Ok(v) => v,
                Err(_) => return,
            };
            let pending = match blocksync::pending_from_transaction(&state, &tx) {
                Ok(v) => v,
                Err(e) => {
                    if let Some(request_id) = legacy_request_id {
                        let message = format!("REJECTED {e}");
                        let _ = session.send_frame(
                            Frame::new(
                                runtime.p2p_magic(),
                                MSG_DEVNET_TX_RESULT,
                                request_id,
                                message.into_bytes(),
                            )
                            .expect("fixed Devnet TX result frame"),
                        );
                    }
                    eprintln!("duplex pending conversion failed: {e}");
                    return;
                }
            };
            match validate_received_pending(&state, &pending) {
                Ok(()) => {
                    state.mempool.push(pending.clone());
                    if let Err(e) = save_live_runtime_state(&data_dir, &state) {
                        if let Some(request_id) = legacy_request_id {
                            let message = format!("REJECTED save failed: {e}");
                            let _ = session.send_frame(
                                Frame::new(
                                    runtime.p2p_magic(),
                                    MSG_DEVNET_TX_RESULT,
                                    request_id,
                                    message.into_bytes(),
                                )
                                .expect("fixed Devnet TX result frame"),
                            );
                        }
                        eprintln!("save after duplex TX acceptance failed: {e}");
                        return;
                    }
                    println!(
                        "Accepted duplex transaction {} from {}",
                        pending.txid,
                        &remote_node_id_hex[..16]
                    );
                    if let Some(request_id) = legacy_request_id {
                        let message = format!("ACCEPTED {}", pending.txid);
                        let _ = session.send_frame(
                            Frame::new(
                                runtime.p2p_magic(),
                                MSG_DEVNET_TX_RESULT,
                                request_id,
                                message.into_bytes(),
                            )
                            .expect("fixed Devnet TX result frame"),
                        );
                    }
                    pending
                }
                Err(e) if e == "ALREADY_KNOWN" => {
                    if let Some(request_id) = legacy_request_id {
                        let message = format!("ALREADY_KNOWN {}", pending.txid);
                        let _ = session.send_frame(
                            Frame::new(
                                runtime.p2p_magic(),
                                MSG_DEVNET_TX_RESULT,
                                request_id,
                                message.into_bytes(),
                            )
                            .expect("fixed Devnet TX result frame"),
                        );
                    }
                    return;
                }
                Err(e) => {
                    if let Some(request_id) = legacy_request_id {
                        let message = format!("REJECTED {e}");
                        let _ = session.send_frame(
                            Frame::new(
                                runtime.p2p_magic(),
                                MSG_DEVNET_TX_RESULT,
                                request_id,
                                message.into_bytes(),
                            )
                            .expect("fixed Devnet TX result frame"),
                        );
                    }
                    eprintln!("Rejected duplex transaction {announced_hex}: {e}");
                    return;
                }
            }
        };
        if !accepted_pending.has_license_payment_output() {
            match decode32(&accepted_pending.txid) {
                Ok(txid) => {
                    duplex_announce_tx_to_registry(&registry, txid, Some(&remote_node_id_hex))
                }
                Err(e) => eprintln!("accepted duplex TXID decode failed: {e}"),
            }
        }
    });
}

fn spawn_duplex_dispatcher(
    data_dir: PathBuf,
    shared: Arc<Mutex<DevnetState>>,
    peer_registry: PeerRegistry,
    duplex_registry: LiveDuplexRegistry,
    stats: DuplexManagerStats,
    local_listen: String,
    remote_node_id_hex: String,
    session: DuplexSession,
    ingress: Arc<RuntimeIngressContext>,
) {
    thread::spawn(move || {
        let mut request_budget = ExpensiveRequestBudget::new();
        let mut addr_admissions = 0usize;
        loop {
            let frame = match session.recv_unsolicited(Duration::from_millis(500)) {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    if session.is_closed() {
                        break;
                    }
                    continue;
                }
                Err(_) => break,
            };
            if is_expensive_peer_request(frame.message_type) && !request_budget.try_consume() {
                let delay = request_budget.remaining_until_reset();
                if let Ok(mut counters) = stats.lock() {
                    counters.request_budget_delays =
                        counters.request_budget_delays.saturating_add(1);
                }
                eprintln!(
                    "duplex dispatcher {}: pacing expensive request for {} ms",
                    &remote_node_id_hex[..16],
                    delay.as_millis()
                );
                if !delay.is_zero() {
                    thread::sleep(delay);
                }
                request_budget.reset_and_consume();
            }
            let result: Result<(), String> = (|| {
                match frame.message_type {
                    MSG_PING => {
                        session
                            .send_frame(
                                Frame::new(
                                    ingress.runtime.p2p_magic(),
                                    MSG_PONG,
                                    frame.request_id,
                                    frame.payload,
                                )
                                .map_err(|e| e.to_string())?,
                            )
                            .map_err(|e| e.to_string())?;
                    }
                    MSG_GET_ADDR => {
                        let mut peers = peer_snapshot(&peer_registry)?;
                        if !peers.iter().any(|p| p == &local_listen) {
                            peers.push(local_listen.clone());
                        }
                        peers.truncate(MAX_RUNTIME_PEERS);
                        let epoch = shared.lock().map_err(|_| "state mutex poisoned")?.tip_epoch;
                        let payload = encode_peer_addresses(&peers, epoch)?;
                        session
                            .send_frame(
                                Frame::new(
                                    ingress.runtime.p2p_magic(),
                                    MSG_ADDR,
                                    frame.request_id,
                                    payload,
                                )
                                .map_err(|e| e.to_string())?,
                            )
                            .map_err(|e| e.to_string())?;
                    }
                    MSG_GET_HEADERS => {
                        let payload = {
                            let state = shared.lock().map_err(|_| "state mutex poisoned")?;
                            blocksync::serve_get_headers(&state, &frame.payload)?
                        };
                        session
                            .send_frame(
                                Frame::new(
                                    ingress.runtime.p2p_magic(),
                                    MSG_HEADERS,
                                    frame.request_id,
                                    payload,
                                )
                                .map_err(|e| e.to_string())?,
                            )
                            .map_err(|e| e.to_string())?;
                    }
                    MSG_GET_BLOCK => {
                        let payload = {
                            let state = shared.lock().map_err(|_| "state mutex poisoned")?;
                            blocksync::serve_get_block(&state, &frame.payload)?
                        };
                        session
                            .send_frame(
                                Frame::new(
                                    ingress.runtime.p2p_magic(),
                                    MSG_BLOCK,
                                    frame.request_id,
                                    payload,
                                )
                                .map_err(|e| e.to_string())?,
                            )
                            .map_err(|e| e.to_string())?;
                    }
                    MSG_GET_TX => {
                        if frame.payload.len() != 32 {
                            return Err("GETTX payload must be one 32-byte TXID".into());
                        }
                        let txid: [u8; 32] = frame.payload.as_slice().try_into().unwrap();
                        let payload = {
                            let state = shared.lock().map_err(|_| "state mutex poisoned")?;
                            find_transaction_payload(&state, txid)?
                        };
                        session
                            .send_frame(
                                Frame::new(
                                    ingress.runtime.p2p_magic(),
                                    MSG_TX,
                                    frame.request_id,
                                    payload,
                                )
                                .map_err(|e| e.to_string())?,
                            )
                            .map_err(|e| e.to_string())?;
                    }
                    MSG_ADDR => {
                        let discovered = decode_peer_addresses(&frame.payload)?;
                        for candidate in discovered {
                            if addr_admissions >= MAX_ADDR_ADMISSIONS_PER_SESSION {
                                break;
                            }
                            if register_runtime_peer(
                                &data_dir,
                                &peer_registry,
                                &candidate,
                                &local_listen,
                            )? {
                                addr_admissions += 1;
                                println!(
                                    "Discovered duplex peer via {}: {candidate}",
                                    &remote_node_id_hex[..16]
                                );
                            }
                            update_duplex_peer_address(
                                &duplex_registry,
                                &remote_node_id_hex,
                                &candidate,
                            )?;
                        }
                    }
                    MSG_BLOCK_ANNOUNCE => {
                        if frame.payload.len() != 32 {
                            return Err(
                                "BLOCKANNOUNCE payload must be one 32-byte BlockHash".into()
                            );
                        }
                        let announced: [u8; 32] = frame.payload.as_slice().try_into().unwrap();
                        if let Some(work_permit) = try_acquire_announce_work() {
                            process_duplex_block_announce(
                                data_dir.clone(),
                                shared.clone(),
                                session.clone(),
                                remote_node_id_hex.clone(),
                                announced,
                                (frame.request_id != 0).then_some(frame.request_id),
                                work_permit,
                                ingress.clone(),
                            );
                        } else {
                            if let Ok(mut counters) = stats.lock() {
                                counters.announce_worker_drops =
                                    counters.announce_worker_drops.saturating_add(1);
                            }
                            return Err("announcement worker cap reached".into());
                        }
                    }
                    MSG_TX_ANNOUNCE => {
                        if frame.payload.len() != 32 {
                            return Err("TXANNOUNCE payload must be one 32-byte TXID".into());
                        }
                        let announced: [u8; 32] = frame.payload.as_slice().try_into().unwrap();
                        if let Some(work_permit) = try_acquire_announce_work() {
                            process_duplex_tx_announce(
                                data_dir.clone(),
                                shared.clone(),
                                duplex_registry.clone(),
                                session.clone(),
                                remote_node_id_hex.clone(),
                                announced,
                                (frame.request_id != 0).then_some(frame.request_id),
                                work_permit,
                                ingress.runtime,
                            );
                        } else {
                            if let Ok(mut counters) = stats.lock() {
                                counters.announce_worker_drops =
                                    counters.announce_worker_drops.saturating_add(1);
                            }
                            return Err("announcement worker cap reached".into());
                        }
                    }
                    MSG_PONG
                    | MSG_HEADERS
                    | MSG_BLOCK
                    | MSG_TX
                    | MSG_DEVNET_BLOCK_RESULT
                    | MSG_DEVNET_TX_RESULT => {
                        // Matching responses are consumed by the RequestID router. A response
                        // that reaches this path is stale/unsolicited and is harmlessly ignored.
                    }
                    other => {
                        return Err(format!(
                            "unsupported Build 4.5.1 duplex message {other:#06x}"
                        ))
                    }
                }
                Ok(())
            })();
            if let Err(e) = result {
                eprintln!("duplex dispatcher {}: {e}", &remote_node_id_hex[..16]);
            }
        }
        println!(
            "Live duplex dispatcher closed for {}",
            &remote_node_id_hex[..16]
        );
    });
}

fn connect_authenticated_duplex(
    data_dir: &Path,
    peer: &str,
    runtime: RuntimeNetwork,
) -> Result<(TcpStream, PeerInfo), String> {
    let socket: SocketAddr = peer
        .parse()
        .map_err(|_| format!("invalid peer socket {peer}"))?;
    let mut stream = TcpStream::connect_timeout(&socket, P2P_CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {peer}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    let key = load_runtime_node_key_for_runtime(data_dir, runtime).map_err(|e| e.to_string())?;
    let info = initiator_handshake(
        &mut stream,
        &key,
        CAP_BUILD45_NODE,
        runtime.network_id(),
        runtime.p2p_magic(),
    )
    .map_err(|e| e.to_string())?;
    stream.set_read_timeout(None).map_err(|e| e.to_string())?;
    Ok((stream, info))
}

fn dial_duplex_peer(
    data_dir: &Path,
    address: &str,
    local_listen: &str,
    local_node_id: [u8; 32],
    shared: Arc<Mutex<DevnetState>>,
    peer_registry: PeerRegistry,
    duplex_registry: LiveDuplexRegistry,
    stats: DuplexManagerStats,
    dial_registry: DuplexDialRegistry,
    ingress: Arc<RuntimeIngressContext>,
) -> Result<(), String> {
    if live_duplex_snapshot(&duplex_registry)?.len() >= MAX_LIVE_DUPLEX_PEERS {
        return Ok(());
    }
    {
        let mut dials = dial_registry
            .lock()
            .map_err(|_| "duplex dial registry mutex poisoned")?;
        let dial = dials.entry(address.to_string()).or_default();
        if let Some(retry_after) = dial.retry_after {
            if Instant::now() < retry_after {
                return Ok(());
            }
        }
    }

    let (stream, info) = match connect_authenticated_duplex(data_dir, address, ingress.runtime) {
        Ok(v) => v,
        Err(e) => {
            let mut dials = dial_registry
                .lock()
                .map_err(|_| "duplex dial registry mutex poisoned")?;
            let dial = dials.entry(address.to_string()).or_default();
            dial.consecutive_failures = dial.consecutive_failures.saturating_add(1).min(32);
            dial.retry_after = Some(
                Instant::now()
                    + Duration::from_secs(session_backoff_seconds(dial.consecutive_failures)),
            );
            {
                let mut counters = stats
                    .lock()
                    .map_err(|_| "duplex manager stats mutex poisoned")?;
                counters.dial_failures = counters.dial_failures.saturating_add(1);
            }
            return Err(e);
        }
    };

    let remote_id = info.node_id.0;
    let lane_high = local_node_id > remote_id;
    let session =
        DuplexSession::from_authenticated_stream(stream, ingress.runtime.p2p_magic(), lane_high)
            .map_err(|e| e.to_string())?;
    let accepted = register_duplex_candidate(
        &duplex_registry,
        &stats,
        local_node_id,
        &info,
        Some(address.to_string()),
        None,
        ConnectionDirection::Outbound,
        session.clone(),
    )?;
    if accepted {
        {
            let mut dials = dial_registry
                .lock()
                .map_err(|_| "duplex dial registry mutex poisoned")?;
            let dial = dials.entry(address.to_string()).or_default();
            if dial.successful_connects > 0 {
                {
                    let mut counters = stats
                        .lock()
                        .map_err(|_| "duplex manager stats mutex poisoned")?;
                    counters.reconnect_successes = counters.reconnect_successes.saturating_add(1);
                }
            }
            dial.successful_connects = dial.successful_connects.saturating_add(1);
            dial.consecutive_failures = 0;
            dial.retry_after = None;
        }
        spawn_duplex_dispatcher(
            data_dir.to_path_buf(),
            shared,
            peer_registry,
            duplex_registry.clone(),
            stats.clone(),
            local_listen.to_string(),
            info.node_id.to_hex(),
            session.clone(),
            ingress,
        );
        if info.capabilities & CAP_PEER_DISCOVERY != 0 {
            if let Ok(payload) = encode_peer_addresses(&[local_listen.to_string()], 0) {
                let _ = session.send_unsolicited(MSG_ADDR, payload);
            }
        }
    }
    Ok(())
}

fn start_duplex_listener(
    listen: &str,
    data_dir: PathBuf,
    shared: Arc<Mutex<DevnetState>>,
    peer_registry: PeerRegistry,
    duplex_registry: LiveDuplexRegistry,
    stats: DuplexManagerStats,
    local_node_id: [u8; 32],
    ingress: Arc<RuntimeIngressContext>,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    println!("P2P duplex listening on {listen}");
    let listen_name = listen.to_string();
    let admission: InboundAdmission = Arc::new(Mutex::new(InboundAdmissionState::default()));
    thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = match incoming {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("duplex accept error: {e}");
                    continue;
                }
            };
            let remote_ip = match stream.peer_addr() {
                Ok(addr) => addr.ip(),
                Err(e) => {
                    eprintln!("duplex inbound peer address error: {e}");
                    continue;
                }
            };
            let admission_permit = match try_acquire_inbound_admission(&admission, remote_ip) {
                Ok(Some(permit)) => permit,
                Ok(None) => {
                    if let Ok(mut counters) = stats.lock() {
                        counters.inbound_admission_drops =
                            counters.inbound_admission_drops.saturating_add(1);
                    }
                    continue;
                }
                Err(e) => {
                    eprintln!("duplex inbound admission error: {e}");
                    continue;
                }
            };
            let dir = data_dir.clone();
            let state = shared.clone();
            let peers = peer_registry.clone();
            let registry = duplex_registry.clone();
            let stats = stats.clone();
            let local_listen = listen_name.clone();
            let ingress = ingress.clone();
            thread::spawn(move || {
                let _admission_permit = admission_permit;
                let result: Result<(), String> = (|| {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .map_err(|e| e.to_string())?;
                    stream
                        .set_write_timeout(Some(Duration::from_secs(10)))
                        .map_err(|e| e.to_string())?;
                    stream.set_nodelay(true).map_err(|e| e.to_string())?;
                    let key = load_runtime_node_key_for_runtime(&dir, ingress.runtime)
                        .map_err(|e| e.to_string())?;
                    let info = responder_handshake(
                        &mut stream,
                        &key,
                        CAP_BUILD45_NODE,
                        ingress.runtime.network_id(),
                        ingress.runtime.p2p_magic(),
                    )
                    .map_err(|e| e.to_string())?;
                    stream.set_read_timeout(None).map_err(|e| e.to_string())?;
                    let lane_high = local_node_id > info.node_id.0;
                    let session = DuplexSession::from_authenticated_stream(
                        stream,
                        ingress.runtime.p2p_magic(),
                        lane_high,
                    )
                    .map_err(|e| e.to_string())?;
                    let accepted = register_duplex_candidate(
                        &registry,
                        &stats,
                        local_node_id,
                        &info,
                        None,
                        Some(remote_ip),
                        ConnectionDirection::Inbound,
                        session.clone(),
                    )?;
                    if accepted {
                        spawn_duplex_dispatcher(
                            dir.clone(),
                            state,
                            peers,
                            registry.clone(),
                            stats.clone(),
                            local_listen.clone(),
                            info.node_id.to_hex(),
                            session.clone(),
                            ingress,
                        );
                        if info.capabilities & CAP_PEER_DISCOVERY != 0 {
                            if let Ok(payload) = encode_peer_addresses(&[local_listen], 0) {
                                let _ = session.send_unsolicited(MSG_ADDR, payload);
                            }
                        }
                    }
                    Ok(())
                })();
                if let Err(e) = result {
                    eprintln!("duplex inbound handshake/session error: {e}");
                }
            });
        }
    });
    Ok(())
}

fn ensure_known_duplex_peers(
    data_dir: &Path,
    local_listen: &str,
    local_node_id: [u8; 32],
    shared: Arc<Mutex<DevnetState>>,
    peer_registry: PeerRegistry,
    duplex_registry: LiveDuplexRegistry,
    stats: DuplexManagerStats,
    dial_registry: DuplexDialRegistry,
    ingress: Arc<RuntimeIngressContext>,
) -> Result<(), String> {
    let known = peer_snapshot(&peer_registry)?;
    let live = live_duplex_snapshot(&duplex_registry)?;
    let mut dial_attempts = 0usize;
    for address in known {
        if address == local_listen {
            continue;
        }
        if live.iter().any(|peer| {
            peer.address.as_deref() == Some(address.as_str()) && !peer.session.is_closed()
        }) {
            continue;
        }
        if dial_attempts >= MAX_DIAL_ATTEMPTS_PER_ROUND {
            break;
        }
        dial_attempts += 1;
        if let Err(e) = dial_duplex_peer(
            data_dir,
            &address,
            local_listen,
            local_node_id,
            shared.clone(),
            peer_registry.clone(),
            duplex_registry.clone(),
            stats.clone(),
            dial_registry.clone(),
            ingress.clone(),
        ) {
            eprintln!("duplex dial {address} failed: {e}");
        }
    }
    Ok(())
}

fn request_duplex_peer_addresses(session: &DuplexSession) -> Result<Vec<String>, String> {
    let response = session
        .request(
            MSG_GET_ADDR,
            Vec::new(),
            &[MSG_ADDR],
            Duration::from_secs(10),
        )
        .map_err(|e| e.to_string())?;
    decode_peer_addresses(&response.payload)
}

fn ping_duplex_peer(session: &DuplexSession, nonce: u64) -> Result<(), String> {
    let payload = nonce.to_be_bytes().to_vec();
    let response = session
        .request(
            MSG_PING,
            payload.clone(),
            &[MSG_PONG],
            Duration::from_secs(10),
        )
        .map_err(|e| e.to_string())?;
    if response.payload != payload {
        return Err("duplex PONG payload mismatch".into());
    }
    Ok(())
}

fn print_duplex_stats(
    registry: &LiveDuplexRegistry,
    stats: &DuplexManagerStats,
) -> Result<(), String> {
    let peers = live_duplex_snapshot(registry)?;
    println!("Live duplex peer statistics (pre-shutdown):");
    if peers.is_empty() {
        println!("duplex peers: none connected");
    }
    for (index, peer) in peers.iter().enumerate() {
        let metrics = peer.session.metrics();
        println!(
            "duplex {:02}: node={} direction={:?} address={} sent={} received={} requests={} responses={} unsolicited={} timeouts={} reader_exits={} pending_rejects={} queue_closes={} rate_closes={} state={}",
            index + 1,
            &peer.node_id_hex[..16],
            peer.direction,
            peer.address.as_deref().unwrap_or("learned-inbound"),
            metrics.frames_sent,
            metrics.frames_received,
            metrics.requests_started,
            metrics.responses_routed,
            metrics.unsolicited_routed,
            metrics.request_timeouts,
            metrics.reader_exits,
            metrics.pending_limit_rejections,
            metrics.unsolicited_overflow_closes,
            metrics.rate_limit_closes,
            if peer.session.is_closed() { "disconnected" } else { "connected" },
        );
    }
    let counters = stats
        .lock()
        .map_err(|_| "duplex manager stats mutex poisoned")?;
    println!(
        "duplex manager: authenticated_candidates={} accepted_sessions={} duplicate_drops={} duplicate_replacements={} dial_failures={} reconnect_successes={} live_peer_cap_drops={} inbound_live_cap_drops={} inbound_ip_cap_drops={} inbound_admission_drops={} announce_worker_drops={} request_budget_closes={} request_budget_delays={}",
        counters.authenticated_candidates,
        counters.accepted_sessions,
        counters.duplicate_drops,
        counters.duplicate_replacements,
        counters.dial_failures,
        counters.reconnect_successes,
        counters.live_peer_cap_drops,
        counters.inbound_live_cap_drops,
        counters.inbound_ip_cap_drops,
        counters.inbound_admission_drops,
        counters.announce_worker_drops,
        counters.request_budget_closes,
        counters.request_budget_delays,
    );
    Ok(())
}

fn shutdown_duplex_registry(registry: &LiveDuplexRegistry) -> Result<(), String> {
    let peers = {
        let state = registry
            .lock()
            .map_err(|_| "duplex peer registry mutex poisoned")?;
        state.values().cloned().collect::<Vec<_>>()
    };
    for peer in peers {
        peer.session.close();
    }
    thread::sleep(Duration::from_millis(100));
    Ok(())
}

/// Build 4.5.1 makes the normal `mutinyd node` runtime use the asynchronous DuplexSession
/// engine. The Build 4.4.1 implementation remains above as a temporary regression fallback,
/// but no live node traffic is intentionally routed through it from this command.
fn run_network_node(data_dir: &Path, args: &[String]) -> Result<(), String> {
    if option_value(args, "--max-epochs").is_some() {
        return Err("`mutinyd node --max-epochs` is reserved for mining epoch semantics; use `--max-rounds N` for bounded network loops.".into());
    }
    let max_rounds = option_value(args, "--max-rounds")
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| "--max-rounds must be an unsigned integer".to_string())
        })
        .transpose()?;
    let listen = option_value(args, "--listen")
        .unwrap_or(DEFAULT_P2P_LISTEN)
        .to_string();
    let ingress = Arc::new(RuntimeIngressContext {
        runtime: RuntimeNetwork::from_cli(option_value(args, "--network"))?,
        bootstrap_witness: option_value(args, "--bootstrap-witness")
            .map(mainnet_bootstrap::BootstrapWitnessProvider::new),
    });
    let mut state = load_state_for_runtime(data_dir, &ingress)?;
    validate_runtime_tuple(&state, ingress.runtime)?;
    fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    fs::write(advertise_path(data_dir), listen.as_bytes()).map_err(|e| e.to_string())?;

    let mut initial_peers = load_peer_cache(data_dir)?;
    for peer in option_values(args, "--peer") {
        if peer != listen.as_str() && peer.parse::<SocketAddr>().is_ok() {
            initial_peers.insert(peer.to_string());
        }
    }
    let mut cached = initial_peers.iter().cloned().collect::<Vec<_>>();
    cached.sort();
    save_peer_cache(data_dir, &cached)?;

    if let Some(v) = option_value(args, "--epoch-ms").and_then(|v| v.parse::<u64>().ok()) {
        state.epoch_ms = v.max(1);
        save_live_runtime_state(data_dir, &state)?;
    }
    let key =
        load_runtime_node_key_for_runtime(data_dir, ingress.runtime).map_err(|e| e.to_string())?;
    let local_node_id_hash = mutiny_p2p::node_id(&key.verifying_key().to_bytes());
    let local_node_id = local_node_id_hash.0;
    println!("NodeID: {}", local_node_id_hash.to_hex());

    let mining_enabled = has_flag(args, "--mine");
    let secure_mining = if mining_enabled && option_value(args, "--mining-key-label").is_some() {
        let label = required_option(args, "--mining-key-label")?;
        let passphrase = read_passphrase_path(Path::new(required_option(
            args,
            "--wallet-passphrase-file",
        )?))?;
        let license_index = parse_license_number(
            required_option(args, "--mining-license")?,
            state.licenses.len(),
        )?;
        let key: Box<dyn MiningAuthority> = if ingress.runtime == RuntimeNetwork::Mainnet {
            Box::new(mining_signer::load(&state, license_index, args, false)?)
        } else {
            Box::new(load_mining_key_for_license(
                data_dir,
                &state,
                license_index,
                label,
                &passphrase,
            )?)
        };
        println!(
            "Encrypted-custody mining: license {} via key label {}",
            license_index + 1,
            label
        );
        Some((license_index, key))
    } else {
        None
    };

    let shared = Arc::new(Mutex::new(state));
    let peer_registry: PeerRegistry = Arc::new(Mutex::new(initial_peers));
    let duplex_registry = new_live_duplex_registry();
    let duplex_stats = new_duplex_manager_stats();
    let dial_registry = new_duplex_dial_registry();

    start_duplex_listener(
        &listen,
        data_dir.to_path_buf(),
        shared.clone(),
        peer_registry.clone(),
        duplex_registry.clone(),
        duplex_stats.clone(),
        local_node_id,
        ingress.clone(),
    )?;

    // Both sides may dial simultaneously. The authenticated NodeID election collapses the
    // race deterministically to one logical peer relationship.
    ensure_known_duplex_peers(
        data_dir,
        &listen,
        local_node_id,
        shared.clone(),
        peer_registry.clone(),
        duplex_registry.clone(),
        duplex_stats.clone(),
        dial_registry.clone(),
        ingress.clone(),
    )?;

    if mining_enabled {
        if secure_mining.is_none() {
            println!("Mining signer mode: deterministic Devnet fixture (use --mining-license/--mining-key-label/--wallet-passphrase-file for encrypted custody)");
        }
        println!("Node running in mining + live fork resolution + asynchronous duplex mode. Press Ctrl+C to stop.");
    } else {
        println!("Node running in live fork resolution + asynchronous duplex mode. Press Ctrl+C to stop.");
    }
    println!("Transport: one logical authenticated peer relationship per NodeID with RequestID-routed concurrent traffic.");
    println!("Announcements: BLOCKANNOUNCE/TXANNOUNCE are unsolicited; peers fetch bodies with independent GETBLOCK/GETTX RequestIDs.");

    let mut round = 0u64;
    let mut mainnet_mining_base: Option<String> = None;
    let mut mainnet_mining_cursor: Option<u64> = None;
    let mut mainnet_mining_paused = false;
    loop {
        ensure_known_duplex_peers(
            data_dir,
            &listen,
            local_node_id,
            shared.clone(),
            peer_registry.clone(),
            duplex_registry.clone(),
            duplex_stats.clone(),
            dial_registry.clone(),
            ingress.clone(),
        )?;

        let (sleep_ms, mined_hash) = if mining_enabled && ingress.runtime == RuntimeNetwork::Mainnet
        {
            let base = shared.lock().map_err(|_| "state mutex poisoned")?.clone();
            if mainnet_mining_base.as_deref() != Some(base.tip_hash.as_str()) {
                mainnet_mining_base = Some(base.tip_hash.clone());
                mainnet_mining_cursor = None;
                mainnet_mining_paused = false;
            }
            if mainnet_mining_paused {
                (base.epoch_ms, None)
            } else {
                let epoch = next_mineable_epoch(&base).max(
                    mainnet_mining_cursor
                        .map(|epoch| epoch.saturating_add(1))
                        .unwrap_or(0),
                );
                let (license_index, key) = secure_mining
                    .as_ref()
                    .ok_or("Mainnet mining requires encrypted operational custody")?;
                // Expensive mining and proof verification never hold the network state lock.
                let result =
                    stage_mainnet_mining_attempt(&base, epoch, *license_index, key.as_ref());
                mainnet_mining_cursor = Some(epoch);
                match result {
                    Err(error) => {
                        eprintln!("LOCAL_MINING_INPUT: {error}; local mining paused for this tip, network validation continues");
                        mainnet_mining_paused = true;
                        (base.epoch_ms, None)
                    }
                    Ok(None) => (base.epoch_ms, None),
                    Ok(Some(mut accepted)) => {
                        let mut current = shared.lock().map_err(|_| "state mutex poisoned")?;
                        if current.tip_hash != base.tip_hash || current.height != base.height {
                            mainnet_mining_base = None;
                            mainnet_mining_cursor = None;
                            (current.epoch_ms, None)
                        } else if let Err(error) =
                            blocksync::refresh_pending_after_runtime_commit(&mut accepted, &current)
                        {
                            eprintln!("LOCAL_MINING_INPUT: pending-work refresh failed: {error}; network validation continues");
                            mainnet_mining_paused = true;
                            (current.epoch_ms, None)
                        } else {
                            save_live_runtime_state(data_dir, &accepted)?;
                            let hash = decode32(&accepted.tip_hash)?;
                            *current = accepted;
                            (current.epoch_ms, Some(hash))
                        }
                    }
                }
            }
        } else if mining_enabled {
            let mut state = shared.lock().map_err(|_| "state mutex poisoned")?;
            let before = state.height;
            let epoch = next_mineable_epoch(&state);
            if let Some((license_index, key)) = &secure_mining {
                mine_epoch_with_signer(&mut state, epoch, Some((*license_index, key.as_ref())))?;
            } else {
                mine_epoch(&mut state, epoch)?;
            }
            save_live_runtime_state(data_dir, &state)?;
            let hash = if state.height > before {
                Some(decode32(&state.tip_hash)?)
            } else {
                None
            };
            (state.epoch_ms, hash)
        } else {
            let state = shared.lock().map_err(|_| "state mutex poisoned")?;
            (state.epoch_ms, None)
        };

        if let Some(hash) = mined_hash {
            duplex_announce_block_to_registry(&duplex_registry, hash);
        }

        // Polling remains as a safety net while unsolicited BLOCKANNOUNCE provides the fast path.
        // Every request runs over the same full-duplex session and is routed by RequestID.
        for peer in live_duplex_snapshot(&duplex_registry)? {
            let Some(_block_sync_permit) = try_acquire_block_sync() else {
                continue;
            };
            let base = shared.lock().map_err(|_| "state mutex poisoned")?.clone();
            let base_tip = base.tip_hash.clone();
            let mut candidate = base;
            match blocksync::sync_state_from_peer_duplex_for_runtime(
                &peer.node_id_hex[..16],
                &peer.session,
                &mut candidate,
                &ingress,
            ) {
                Ok(report) if report.applied_blocks > 0 || report.reorg => {
                    let mut current = shared.lock().map_err(|_| "state mutex poisoned")?;
                    if current.tip_hash == base_tip {
                        if ingress.runtime == RuntimeNetwork::Mainnet {
                            blocksync::refresh_pending_after_runtime_commit(
                                &mut candidate,
                                &current,
                            )?;
                            save_live_runtime_state(data_dir, &candidate)?;
                            *current = candidate;
                        } else {
                            *current = candidate;
                            save_live_runtime_state(data_dir, &current)?;
                        }
                        print_sync_report(&format!("duplex:{}", &peer.node_id_hex[..16]), &report);
                        if report.reorg && report.restored_mempool > 0 {
                            println!("Live duplex reorg restored {} transaction(s); re-announcing inventory.", report.restored_mempool);
                            for tx in &current.mempool {
                                if tx.has_license_payment_output()
                                    || transaction_is_protocol_bound(&current, &tx.txid)
                                {
                                    continue;
                                }
                                if let Ok(txid) = decode32(&tx.txid) {
                                    duplex_announce_tx_to_registry(&duplex_registry, txid, None);
                                }
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    if !peer.session.is_closed() {
                        eprintln!(
                            "duplex reconciliation with {} failed: {e}",
                            &peer.node_id_hex[..16]
                        );
                    }
                }
            }
        }

        if round % 8 == 0 {
            let snapshot = shared.lock().map_err(|_| "state mutex poisoned")?.clone();
            for tx in &snapshot.mempool {
                if tx.has_license_payment_output()
                    || transaction_is_protocol_bound(&snapshot, &tx.txid)
                {
                    continue;
                }
                if let Ok(txid) = decode32(&tx.txid) {
                    duplex_announce_tx_to_registry(&duplex_registry, txid, None);
                }
            }
        }

        if round % 16 == 0 {
            for peer in live_duplex_snapshot(&duplex_registry)? {
                match request_duplex_peer_addresses(&peer.session) {
                    Ok(discovered) => {
                        for candidate in discovered {
                            match register_runtime_peer(
                                data_dir,
                                &peer_registry,
                                &candidate,
                                &listen,
                            ) {
                                Ok(true) => println!(
                                    "Discovered peer via duplex {}: {candidate}",
                                    &peer.node_id_hex[..16]
                                ),
                                Ok(false) => {}
                                Err(e) => eprintln!("Ignoring duplex peer address: {e}"),
                            }
                        }
                    }
                    Err(e) if !peer.session.is_closed() => eprintln!("duplex GETADDR failed: {e}"),
                    Err(_) => {}
                }
            }
        }

        if round % 2 == 0 {
            for peer in live_duplex_snapshot(&duplex_registry)? {
                if let Err(e) = ping_duplex_peer(&peer.session, round) {
                    if !peer.session.is_closed() {
                        eprintln!(
                            "duplex liveness check to {} failed: {e}",
                            &peer.node_id_hex[..16]
                        );
                        peer.session.close();
                        eprintln!(
                            "duplex liveness eviction: {} closed after failed authenticated PING; reconnect permitted",
                            &peer.node_id_hex[..16]
                        );
                    }
                }
            }
        }

        round = round.saturating_add(1);
        if max_rounds.is_some_and(|m| round >= m) {
            break;
        }
        thread::sleep(Duration::from_millis(sleep_ms));
    }

    print_duplex_stats(&duplex_registry, &duplex_stats)?;
    shutdown_duplex_registry(&duplex_registry)?;
    {
        let state = shared.lock().map_err(|_| "state mutex poisoned")?;
        print_status(&state);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build451_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn build451_duplicate_registry_converges_to_preferred_direction() {
        let mut local = [0u8; 32];
        local[31] = 1;
        let mut remote = [0u8; 32];
        remote[31] = 2;
        let info = PeerInfo {
            node_public_key: [9u8; 32],
            node_id: Hash256(remote),
            capabilities: CAP_BUILD45_NODE,
            selected_version: 1,
        };
        let registry = new_live_duplex_registry();
        let stats = new_duplex_manager_stats();

        let (_a1, b1) = build451_tcp_pair();
        let inbound =
            DuplexSession::from_authenticated_stream(b1, P2P_MAGIC_DEVNET, false).unwrap();
        assert!(register_duplex_candidate(
            &registry,
            &stats,
            local,
            &info,
            Some("127.0.0.1:24589".into()),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ConnectionDirection::Inbound,
            inbound.clone(),
        )
        .unwrap());

        let (a2, _b2) = build451_tcp_pair();
        let outbound =
            DuplexSession::from_authenticated_stream(a2, P2P_MAGIC_DEVNET, false).unwrap();
        assert!(register_duplex_candidate(
            &registry,
            &stats,
            local,
            &info,
            Some("127.0.0.1:24589".into()),
            None,
            ConnectionDirection::Outbound,
            outbound.clone(),
        )
        .unwrap());

        assert!(inbound.is_closed());
        let peers = live_duplex_snapshot(&registry).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].direction, ConnectionDirection::Outbound);
        assert_eq!(peers[0].node_id_hex, hex::encode(remote));
        let counters = stats.lock().unwrap();
        assert_eq!(counters.duplicate_replacements, 1);
        outbound.close();
    }

    #[test]
    fn build451_request_id_lane_matches_authenticated_nodeid_ordering() {
        let mut low = [0u8; 32];
        low[31] = 1;
        let mut high = [0u8; 32];
        high[31] = 2;
        assert!(!(low > high));
        assert!(high > low);
        assert_eq!(
            preferred_direction(low, high),
            ConnectionDirection::Outbound
        );
        assert_eq!(preferred_direction(high, low), ConnectionDirection::Inbound);
    }

    #[test]
    fn build452_runtime_has_no_legacy_node_entrypoint() {
        let source = include_str!("main.rs");
        let legacy = ["fn ", "run_network_node_legacy", "("].concat();
        let live = [
            "fn ",
            "run_network_node",
            "(data_dir: &Path, args: &[String])",
        ]
        .concat();
        let dispatch = ["\"node\"", " => ", "run_network_node(&data_dir, &args)?"].concat();
        assert!(!source.contains(&legacy));
        assert!(source.contains(&dispatch));
        assert!(source.contains(&live));
    }

    #[test]
    fn build452_legacy_responder_is_test_only() {
        let source = include_str!("main.rs");
        for signature in [
            "fn handle_p2p_connection(",
            "fn serve_authenticated_frame(",
            "fn gossip_transaction(",
            "fn ping_peer_persistent(",
        ] {
            let guarded = format!("#[cfg(test)]\n{signature}");
            assert!(
                source.contains(&guarded),
                "legacy helper escaped test-only gate: {signature}"
            );
        }
    }

    fn build56_secure_owner_state(seed_byte: u8) -> (DevnetState, SigningKey) {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build56-secure-owner-{}-{}",
            std::process::id(),
            seed_byte
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let key = SigningKey::from_bytes(&[seed_byte; 32]);
        let public = key.verifying_key().to_bytes();
        state.licenses[0].owner_public_key = hex::encode(public);
        state.licenses[0].payment_address_id = hex::encode(address_id(&public).0);
        state.utxos.push(UtxoState {
            txid: hex::encode([seed_byte.wrapping_add(1); 32]),
            output_index: 0,
            amount_strikes: 100 * STRIKES_PER_MUT,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: hex::encode(address_id(&public).0),
            creation_epoch: 1,
            creation_height: 0,
            coinbase: false,
        });
        (state, key)
    }

    // Build 5.8 offline signing intentionally binds requests to the locked Pack-J Devnet
    // GenesisID. The older Build 5.6 synthetic owner fixture predates that operational
    // requirement and uses init_devnet's legacy regression Genesis hash. Upgrade only
    // the test fixture here; production create/submit paths must continue to reject any
    // state whose GenesisID is not the locked Devnet value.
    fn build58_secure_owner_state(seed_byte: u8) -> (DevnetState, SigningKey) {
        let (mut state, key) = build56_secure_owner_state(seed_byte);
        state.genesis_hash = DEVNET_GENESIS_ID_HEX.to_string();
        (state, key)
    }

    #[test]
    fn build56_secure_send_uses_supplied_owner_key_and_rejects_mismatch() {
        let (state, owner_key) = build56_secure_owner_state(0xa1);
        let pending =
            create_send_transaction_with_signer(&state, 0, 1, STRIKES_PER_MUT, &owner_key).unwrap();
        let tx = pending.to_transaction().unwrap();
        assert_eq!(
            &tx.witnesses[0].payload[..32],
            &owner_key.verifying_key().to_bytes()
        );
        let wrong = SigningKey::from_bytes(&[0xa2; 32]);
        let err =
            create_send_transaction_with_signer(&state, 0, 1, STRIKES_PER_MUT, &wrong).unwrap_err();
        assert!(err.contains("current on-chain owner authority"));
        let fixture_err = create_send_transaction(&state, 0, 1, STRIKES_PER_MUT).unwrap_err();
        assert!(
            fixture_err.contains("local Devnet wallet does not hold the current owner private key")
        );
    }

    #[test]
    fn build56_secure_transfer_is_signed_by_current_encrypted_owner() {
        let (state, owner_key) = build56_secure_owner_state(0xa3);
        let new_owner = SigningKey::from_bytes(&[0xa4; 32])
            .verifying_key()
            .to_bytes();
        let new_mining = SigningKey::from_bytes(&[0xa5; 32])
            .verifying_key()
            .to_bytes();
        let (fee_tx, _, op) = create_license_transfer_operation_with_signer(
            &state, 0, new_owner, new_mining, &owner_key,
        )
        .unwrap();
        let transfer = decode_license_transfer_operation(&op).unwrap();
        assert_eq!(transfer.new_owner_public_key, new_owner);
        assert_eq!(transfer.new_mining_public_key, new_mining);
        let vk = owner_key.verifying_key();
        vk.verify_strict(
            &transfer.signing_digest().0,
            &Signature::from_bytes(&transfer.owner_signature),
        )
        .unwrap();
        assert_eq!(
            &fee_tx.to_transaction().unwrap().witnesses[0].payload[..32],
            &vk.to_bytes()
        );
    }

    #[test]
    fn build56_secure_mining_rotation_is_signed_by_current_encrypted_owner() {
        let (state, owner_key) = build56_secure_owner_state(0xa6);
        let new_mining = SigningKey::from_bytes(&[0xa7; 32])
            .verifying_key()
            .to_bytes();
        let (_, _, op) =
            create_mining_key_rotation_operation_with_signer(&state, 0, new_mining, &owner_key)
                .unwrap();
        let rotation = decode_mining_key_rotation_operation(&op).unwrap();
        assert_eq!(rotation.new_mining_public_key, new_mining);
        owner_key
            .verifying_key()
            .verify_strict(
                &rotation.signing_digest().0,
                &Signature::from_bytes(&rotation.owner_signature),
            )
            .unwrap();
    }

    #[test]
    fn build56_secure_native_purchase_commits_supplied_custody_keys() {
        let (state, owner_key) = build56_secure_owner_state(0xa8);
        let new_owner = SigningKey::from_bytes(&[0xa9; 32])
            .verifying_key()
            .to_bytes();
        let new_mining = SigningKey::from_bytes(&[0xaa; 32])
            .verifying_key()
            .to_bytes();
        let entries = vec![LicenseManifestEntryV1 {
            owner_public_key: new_owner,
            mining_public_key: new_mining,
        }];
        let (payment, pending_op, ids, _) =
            create_native_license_purchase_with_signer(&state, 0, entries, &owner_key).unwrap();
        assert_eq!(ids.len(), 1);
        let op = pending_op.operation().unwrap();
        let purchase = decode_native_purchase_operation(&op).unwrap();
        assert_eq!(purchase.manifest.licenses[0].owner_public_key, new_owner);
        assert_eq!(purchase.manifest.licenses[0].mining_public_key, new_mining);
        assert_eq!(
            &payment.to_transaction().unwrap().witnesses[0].payload[..32],
            &owner_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn build56_secure_block_header_is_signed_by_supplied_mining_key() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build56-secure-mining-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let mining_key = SigningKey::from_bytes(&[0xab; 32]);
        state.licenses[0].mining_public_key = hex::encode(mining_key.verifying_key().to_bytes());
        accept_dev_block_with_signer(
            &mut state,
            ACTIVATION_DELAY_EPOCHS,
            0,
            0,
            [0x11u8; 32],
            [0xffu8; 32],
            Some(&mining_key),
        )
        .unwrap();
        let header = hex::decode(&state.blocks[0].header).unwrap();
        let core: [u8; 208] = header[..208].try_into().unwrap();
        let digest = block_signing_digest(&core);
        let sig_bytes: [u8; 64] = header[208..272].try_into().unwrap();
        mining_key
            .verifying_key()
            .verify_strict(&digest.0, &Signature::from_bytes(&sig_bytes))
            .unwrap();
    }

    #[test]
    fn build56_secure_block_rejects_wrong_mining_key() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build56-wrong-mining-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let expected = SigningKey::from_bytes(&[0xacu8; 32]);
        let wrong = SigningKey::from_bytes(&[0xadu8; 32]);
        state.licenses[0].mining_public_key = hex::encode(expected.verifying_key().to_bytes());
        let err = accept_dev_block_with_signer(
            &mut state,
            ACTIVATION_DELAY_EPOCHS,
            0,
            0,
            [0x11u8; 32],
            [0xffu8; 32],
            Some(&wrong),
        )
        .unwrap_err();
        assert!(err.contains("selected Mining License authority"));
    }

    #[test]
    fn build56_secure_dividend_claim_uses_supplied_owner_key() {
        let (mut state, owner_key) = build56_secure_owner_state(0xae);
        let treasury_amount = 24 * STRIKES_PER_MUT;
        state.utxos.push(UtxoState {
            // Keep this Treasury outpoint distinct from build56_secure_owner_state(0xae),
            // whose fixture wallet UTXO is af..af:0. Duplicate outpoints are invalid
            // state and would make the validator correctly observe the non-Treasury UTXO.
            txid: hex::encode([0xb0u8; 32]),
            output_index: 0,
            amount_strikes: treasury_amount,
            output_type: OUTPUT_TREASURY,
            payload: hex::encode(treasury_id()),
            creation_epoch: 1,
            creation_height: 0,
            coinbase: false,
        });
        state.tip_epoch = mutiny_protocol::DIVIDEND_AWARD_INTERVAL;
        dividends::process_epoch(&mut state, mutiny_protocol::DIVIDEND_AWARD_INTERVAL).unwrap();
        let claimable = state
            .dividend_accounts
            .iter()
            .find(|a| a.license_id == state.licenses[0].license_id)
            .unwrap()
            .claimable_strikes;
        let (payment, pending_op, claim) = dividends::create_claim_bundle_with_signer(
            &state,
            0,
            claimable.min(STRIKES_PER_MUT),
            &owner_key,
        )
        .unwrap();
        let payment_tx = payment.to_transaction().unwrap();
        let operation = pending_op.operation().unwrap();
        let opid = operation.operation_id().0;
        assert!(!payment_tx.witnesses.is_empty());
        assert!(payment_tx.witnesses.iter().all(|w| {
            w.witness_type == mutiny_transaction::WITNESS_PROTOCOL_AUTH
                && w.payload.as_slice() == &opid[..]
        }));
        owner_key
            .verifying_key()
            .verify_strict(
                &claim.signing_digest().0,
                &Signature::from_bytes(&claim.owner_signature),
            )
            .unwrap();
    }

    #[test]
    fn build57_backup_restore_roundtrip_preserves_secret_bytes_and_keys() {
        let source =
            std::env::temp_dir().join(format!("mutiny-build57-backup-src-{}", std::process::id()));
        let target =
            std::env::temp_dir().join(format!("mutiny-build57-backup-dst-{}", std::process::id()));
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
        fs::create_dir_all(source.join("secrets")).unwrap();
        fs::create_dir_all(target.join("secrets")).unwrap();
        let pass = b"build57 recovery passphrase";
        let owner_seed = [0x71u8; 32];
        let mining_seed = [0x72u8; 32];
        let owner_bytes =
            mutiny_keystore::seal_seed(&owner_seed, KeyRole::LicenseOwner, DEVNET_NETWORK_ID, pass)
                .unwrap();
        let mining_bytes = mutiny_keystore::seal_seed(
            &mining_seed,
            KeyRole::LicenseMining,
            DEVNET_NETWORK_ID,
            pass,
        )
        .unwrap();
        mutiny_keystore::write_new_file(
            &wallet_key_path(&source, KeyRole::LicenseOwner, "alpha").unwrap(),
            &owner_bytes,
        )
        .unwrap();
        mutiny_keystore::write_new_file(
            &wallet_key_path(&source, KeyRole::LicenseMining, "beta").unwrap(),
            &mining_bytes,
        )
        .unwrap();
        let entries = collect_wallet_backup_entries(&source, pass).unwrap();
        let bundle = mutiny_keystore::encode_wallet_backup(DEVNET_NETWORK_ID, &entries).unwrap();
        let restored = restore_wallet_backup_bytes(&target, &bundle, pass).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(
            fs::read(wallet_key_path(&target, KeyRole::LicenseOwner, "alpha").unwrap()).unwrap(),
            owner_bytes
        );
        assert_eq!(
            fs::read(wallet_key_path(&target, KeyRole::LicenseMining, "beta").unwrap()).unwrap(),
            mining_bytes
        );
        let owner = load_wallet_key(&target, KeyRole::LicenseOwner, "alpha", pass).unwrap();
        assert_eq!(
            owner.verifying_key().to_bytes(),
            SigningKey::from_bytes(&owner_seed)
                .verifying_key()
                .to_bytes()
        );
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
    }

    #[test]
    fn build57_backup_wrong_passphrase_tamper_and_clobber_fail_before_restore() {
        let source =
            std::env::temp_dir().join(format!("mutiny-build57-fail-src-{}", std::process::id()));
        let target =
            std::env::temp_dir().join(format!("mutiny-build57-fail-dst-{}", std::process::id()));
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
        fs::create_dir_all(source.join("secrets")).unwrap();
        fs::create_dir_all(target.join("secrets")).unwrap();
        let pass = b"build57 recovery passphrase";
        let bytes = mutiny_keystore::seal_seed(
            &[0x73u8; 32],
            KeyRole::LicenseOwner,
            DEVNET_NETWORK_ID,
            pass,
        )
        .unwrap();
        let path = wallet_key_path(&source, KeyRole::LicenseOwner, "alpha").unwrap();
        mutiny_keystore::write_new_file(&path, &bytes).unwrap();
        let entries = collect_wallet_backup_entries(&source, pass).unwrap();
        let bundle = mutiny_keystore::encode_wallet_backup(DEVNET_NETWORK_ID, &entries).unwrap();
        assert!(verify_wallet_backup_bytes(&bundle, b"wrong recovery passphrase").is_err());
        let mut tampered = bundle.clone();
        tampered[20] ^= 1;
        assert!(restore_wallet_backup_bytes(&target, &tampered, pass).is_err());
        assert!(!wallet_key_path(&target, KeyRole::LicenseOwner, "alpha")
            .unwrap()
            .exists());
        mutiny_keystore::write_new_file(
            &wallet_key_path(&target, KeyRole::LicenseOwner, "alpha").unwrap(),
            &bytes,
        )
        .unwrap();
        assert!(restore_wallet_backup_bytes(&target, &bundle, pass)
            .unwrap_err()
            .contains("overwrite"));
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&target);
    }

    #[test]
    fn build57_watch_only_export_contains_public_metadata_and_matches_authority() {
        let dir = std::env::temp_dir().join(format!("mutiny-build57-watch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let owner = SigningKey::from_bytes(&[0x74u8; 32])
            .verifying_key()
            .to_bytes();
        let mining = SigningKey::from_bytes(&[0x75u8; 32])
            .verifying_key()
            .to_bytes();
        state.licenses[0].owner_public_key = hex::encode(owner);
        state.licenses[0].mining_public_key = hex::encode(mining);
        let owner_entry = WatchWalletEntry {
            role: KeyRole::LicenseOwner,
            label: "owner".into(),
            public_key: owner,
        };
        let mining_entry = WatchWalletEntry {
            role: KeyRole::LicenseMining,
            label: "mining".into(),
            public_key: mining,
        };
        assert_eq!(
            watch_wallet_matches(&state, &owner_entry),
            vec!["license 1 owner".to_string()]
        );
        assert_eq!(
            watch_wallet_matches(&state, &mining_entry),
            vec!["license 1 mining".to_string()]
        );
        let bytes =
            mutiny_keystore::encode_watch_wallet(DEVNET_NETWORK_ID, &[owner_entry, mining_entry])
                .unwrap();
        assert!(bytes.len() < mutiny_keystore::FILE_LEN * 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build60_legacy_state_migration_preserves_consensus_checkpoint() {
        let source = std::env::temp_dir().join(format!(
            "mutiny-build60-migrate-source-{}",
            std::process::id()
        ));
        let legacy = std::env::temp_dir().join(format!(
            "mutiny-build60-migrate-legacy-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&legacy);
        init_build54_genesis_devnet(&source, 1, true).unwrap();
        let original = load_state(&source).unwrap();
        let original_bytes = serde_json::to_vec_pretty(&original).unwrap();
        fs::create_dir_all(&legacy).unwrap();
        fs::write(state_path(&legacy), &original_bytes).unwrap();

        let migrated = load_state(&legacy).unwrap();
        assert_eq!(migrated.height, original.height);
        assert_eq!(migrated.tip_hash, original.tip_hash);
        assert_eq!(migrated.current_state_root, original.current_state_root);
        assert_eq!(
            chainwork_hex(&migrated).unwrap(),
            chainwork_hex(&original).unwrap()
        );
        assert!(!state_path(&legacy).exists());
        let meta = storage::inspect_meta(&legacy).unwrap().unwrap();
        assert_eq!(meta.generation, 1);
        validate_storage_meta(&migrated, &meta).unwrap();
        blocksync::verify_full_replay(&migrated).unwrap();

        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&legacy);
    }

    #[test]
    fn build70_runtime_identity_is_current_and_ascii() {
        assert_eq!(BUILD_NAME, "Mutiny Protocol V1.0 Build 7.0 Candidate 1");
        assert!(BUILD_NAME.is_ascii());
        assert!(BUILD_DESCRIPTION.is_ascii());
        // Older identities here are negative fixtures, never runtime labels.
        for stale in [
            "Build 6.3 Candidate",
            "Build 6.7 Candidate",
            "Build 6.8 Candidate",
            "Build 6.9 Candidate",
        ] {
            assert!(!BUILD_NAME.contains(stale));
            assert!(!BUILD_DESCRIPTION.contains(stale));
        }
    }

    #[test]
    fn build70_release_identity_pack_k_constants_and_inherited_cli_are_explicit() {
        assert_eq!(BUILD_NAME, "Mutiny Protocol V1.0 Build 7.0 Candidate 1");
        assert_eq!(
            BUILD_DESCRIPTION,
            "First-Node Mainnet Bootstrap Activation"
        );
        assert_eq!(DEFAULT_DATA_DIR, "devnet-data-build6.3");
        assert_eq!(OP_MINING_PRESENCE, 0x0008);
        assert_eq!(PS_MINING_PRESENCE_STATE, 0x0008);
        assert_eq!(PACK_K_DEVNET_ACTIVATION_EPOCH, 1500);
        assert_eq!(MINING_PRESENCE_WINDOW_EPOCHS, 16);
        assert_eq!(MAX_RUNTIME_PEERS, 256);
        assert_eq!(MAX_LIVE_DUPLEX_PEERS, 64);
        assert_eq!(MAX_INBOUND_DUPLEX_PEERS, 48);
        assert_eq!(MAX_INBOUND_DUPLEX_PEERS_PER_IP, 8);
        assert_eq!(MAX_INBOUND_HANDSHAKES, 32);
        assert_eq!(MAX_INBOUND_HANDSHAKES_PER_IP, 4);
        assert_eq!(MAX_ANNOUNCE_WORKERS, 16);
        assert_eq!(MAX_EXPENSIVE_REQUESTS_PER_WINDOW, 16);
        assert_eq!(EXPENSIVE_REQUEST_WINDOW, Duration::from_secs(10));
        assert_eq!(EXPENSIVE_REQUEST_RESPONSE_TIMEOUT, Duration::from_secs(20));
        assert_eq!(MAX_NETWORK_MEMPOOL_TXS, 4096);
        assert_eq!(MAX_ADDR_ADMISSIONS_PER_SESSION, 16);
        assert_eq!(MAX_DIAL_ATTEMPTS_PER_ROUND, 16);
        assert_eq!(P2P_CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(mutiny_duplex::DEFAULT_MAX_PENDING_REQUESTS, 64);
        assert_eq!(mutiny_duplex::DEFAULT_MAX_UNSOLICITED_FRAMES, 128);
        assert_eq!(mutiny_duplex::DEFAULT_MAX_FRAMES_PER_WINDOW, 512);
        assert_eq!(
            mutiny_duplex::DEFAULT_MAX_BYTES_PER_WINDOW,
            16 * 1024 * 1024
        );
        let source = include_str!("main.rs");
        for command in [
            "wallet-backup-create",
            "wallet-backup-verify",
            "wallet-backup-restore",
            "wallet-watch-export",
            "wallet-watch",
            "wallet-offline-send-create",
            "wallet-offline-inspect",
            "wallet-offline-sign",
            "wallet-offline-submit",
            "rpc-token-init",
            "rpc-serve",
            "rpc-call",
            "storage-info",
            "storage-migrate",
            "storage-verify",
            "wallet-mining-presence",
            "mining-presence",
        ] {
            assert!(
                source.contains(command),
                "missing Build 6.1 inherited command: {command}"
            );
        }
    }

    #[test]
    fn build61_inbound_handshake_admission_caps_total_and_per_ip() {
        let admission: InboundAdmission = Arc::new(Mutex::new(InboundAdmissionState::default()));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let mut permits = Vec::new();
        for _ in 0..MAX_INBOUND_HANDSHAKES_PER_IP {
            permits.push(
                try_acquire_inbound_admission(&admission, ip)
                    .unwrap()
                    .unwrap(),
            );
        }
        assert!(try_acquire_inbound_admission(&admission, ip)
            .unwrap()
            .is_none());
        assert!(try_acquire_inbound_admission(&admission, other)
            .unwrap()
            .is_some());
        drop(permits.pop());
        assert!(try_acquire_inbound_admission(&admission, ip)
            .unwrap()
            .is_some());
    }

    #[test]
    fn build61_live_peer_cap_refuses_new_nodeid_without_evicting_existing_peer() {
        let registry = new_live_duplex_registry();
        let stats = new_duplex_manager_stats();
        let (base_raw, base_peer_raw) = build451_tcp_pair();
        let base =
            DuplexSession::from_authenticated_stream(base_raw, P2P_MAGIC_DEVNET, false).unwrap();
        let base_peer =
            DuplexSession::from_authenticated_stream(base_peer_raw, P2P_MAGIC_DEVNET, true)
                .unwrap();
        {
            let mut state = registry.lock().unwrap();
            for i in 0..MAX_LIVE_DUPLEX_PEERS {
                let mut id = [0u8; 32];
                id[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                let hex_id = hex::encode(id);
                state.insert(
                    hex_id.clone(),
                    LiveDuplexPeer {
                        node_id_hex: hex_id,
                        address: None,
                        direction: ConnectionDirection::Outbound,
                        source_ip: None,
                        session: base.clone(),
                    },
                );
            }
        }
        let (candidate_raw, candidate_peer_raw) = build451_tcp_pair();
        let candidate =
            DuplexSession::from_authenticated_stream(candidate_raw, P2P_MAGIC_DEVNET, false)
                .unwrap();
        let candidate_peer =
            DuplexSession::from_authenticated_stream(candidate_peer_raw, P2P_MAGIC_DEVNET, true)
                .unwrap();
        let info = PeerInfo {
            node_public_key: [0x22; 32],
            node_id: Hash256([0xee; 32]),
            capabilities: CAP_BUILD45_NODE,
            selected_version: 1,
        };
        let accepted = register_duplex_candidate(
            &registry,
            &stats,
            [0x11; 32],
            &info,
            None,
            None,
            ConnectionDirection::Outbound,
            candidate.clone(),
        )
        .unwrap();
        assert!(!accepted);
        assert!(candidate.is_closed());
        assert_eq!(registry.lock().unwrap().len(), MAX_LIVE_DUPLEX_PEERS);
        assert_eq!(stats.lock().unwrap().live_peer_cap_drops, 1);
        base.close();
        base_peer.close();
        candidate_peer.close();
    }

    #[test]
    fn build61_inbound_live_caps_preserve_outbound_reserve_and_limit_source_ip() {
        let stats = new_duplex_manager_stats();
        let registry = new_live_duplex_registry();
        let (base_raw, base_peer_raw) = build451_tcp_pair();
        let base =
            DuplexSession::from_authenticated_stream(base_raw, P2P_MAGIC_DEVNET, false).unwrap();
        let base_peer =
            DuplexSession::from_authenticated_stream(base_peer_raw, P2P_MAGIC_DEVNET, true)
                .unwrap();
        {
            let mut state = registry.lock().unwrap();
            for i in 0..MAX_INBOUND_DUPLEX_PEERS {
                let mut id = [0u8; 32];
                id[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                let node_id_hex = hex::encode(id);
                state.insert(
                    node_id_hex.clone(),
                    LiveDuplexPeer {
                        node_id_hex,
                        address: None,
                        direction: ConnectionDirection::Inbound,
                        source_ip: Some(IpAddr::V4(Ipv4Addr::new(
                            10,
                            1,
                            (i / 250) as u8,
                            (i % 250 + 1) as u8,
                        ))),
                        session: base.clone(),
                    },
                );
            }
        }
        let (in_raw, in_peer_raw) = build451_tcp_pair();
        let inbound =
            DuplexSession::from_authenticated_stream(in_raw, P2P_MAGIC_DEVNET, false).unwrap();
        let inbound_peer =
            DuplexSession::from_authenticated_stream(in_peer_raw, P2P_MAGIC_DEVNET, true).unwrap();
        let inbound_info = PeerInfo {
            node_public_key: [0x31; 32],
            node_id: Hash256([0xf1; 32]),
            capabilities: CAP_BUILD45_NODE,
            selected_version: 1,
        };
        assert!(!register_duplex_candidate(
            &registry,
            &stats,
            [0x11; 32],
            &inbound_info,
            None,
            Some(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))),
            ConnectionDirection::Inbound,
            inbound.clone(),
        )
        .unwrap());
        assert!(inbound.is_closed());
        assert_eq!(stats.lock().unwrap().inbound_live_cap_drops, 1);

        let (out_raw, out_peer_raw) = build451_tcp_pair();
        let outbound =
            DuplexSession::from_authenticated_stream(out_raw, P2P_MAGIC_DEVNET, false).unwrap();
        let outbound_peer =
            DuplexSession::from_authenticated_stream(out_peer_raw, P2P_MAGIC_DEVNET, true).unwrap();
        let outbound_info = PeerInfo {
            node_public_key: [0x32; 32],
            node_id: Hash256([0xf2; 32]),
            capabilities: CAP_BUILD45_NODE,
            selected_version: 1,
        };
        assert!(register_duplex_candidate(
            &registry,
            &stats,
            [0x11; 32],
            &outbound_info,
            Some("127.0.0.1:29999".into()),
            None,
            ConnectionDirection::Outbound,
            outbound.clone(),
        )
        .unwrap());
        assert_eq!(registry.lock().unwrap().len(), MAX_INBOUND_DUPLEX_PEERS + 1);

        let ip_registry = new_live_duplex_registry();
        let shared_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        {
            let mut state = ip_registry.lock().unwrap();
            for i in 0..MAX_INBOUND_DUPLEX_PEERS_PER_IP {
                let mut id = [0u8; 32];
                id[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                let node_id_hex = hex::encode(id);
                state.insert(
                    node_id_hex.clone(),
                    LiveDuplexPeer {
                        node_id_hex,
                        address: None,
                        direction: ConnectionDirection::Inbound,
                        source_ip: Some(shared_ip),
                        session: base.clone(),
                    },
                );
            }
        }
        let (ip_raw, ip_peer_raw) = build451_tcp_pair();
        let ip_candidate =
            DuplexSession::from_authenticated_stream(ip_raw, P2P_MAGIC_DEVNET, false).unwrap();
        let ip_peer =
            DuplexSession::from_authenticated_stream(ip_peer_raw, P2P_MAGIC_DEVNET, true).unwrap();
        let ip_info = PeerInfo {
            node_public_key: [0x33; 32],
            node_id: Hash256([0xf3; 32]),
            capabilities: CAP_BUILD45_NODE,
            selected_version: 1,
        };
        assert!(!register_duplex_candidate(
            &ip_registry,
            &stats,
            [0x11; 32],
            &ip_info,
            None,
            Some(shared_ip),
            ConnectionDirection::Inbound,
            ip_candidate.clone(),
        )
        .unwrap());
        assert!(ip_candidate.is_closed());
        assert_eq!(stats.lock().unwrap().inbound_ip_cap_drops, 1);

        base.close();
        base_peer.close();
        inbound_peer.close();
        outbound.close();
        outbound_peer.close();
        ip_peer.close();
    }

    #[test]
    fn build61_announcement_worker_budget_is_bounded_and_released() {
        let mut permits = Vec::new();
        while let Some(permit) = try_acquire_announce_work() {
            permits.push(permit);
            assert!(permits.len() <= MAX_ANNOUNCE_WORKERS);
        }
        assert!(try_acquire_announce_work().is_none());
        if let Some(permit) = permits.pop() {
            drop(permit);
            let replacement =
                try_acquire_announce_work().expect("released permit becomes available");
            drop(replacement);
        }
        drop(permits);
    }

    #[test]
    fn build61_hotfix1_expensive_request_budget_backpressures_without_closing() {
        let mut budget = ExpensiveRequestBudget::new();
        for _ in 0..MAX_EXPENSIVE_REQUESTS_PER_WINDOW {
            assert!(budget.try_consume());
        }
        assert!(!budget.try_consume());
        let delay = budget.remaining_until_reset();
        assert!(!delay.is_zero());
        assert!(delay <= EXPENSIVE_REQUEST_WINDOW);
        budget.reset_and_consume();
        assert_eq!(budget.used, 1);
        assert!(EXPENSIVE_REQUEST_RESPONSE_TIMEOUT > EXPENSIVE_REQUEST_WINDOW);
        assert!(is_expensive_peer_request(MSG_GET_HEADERS));
        assert!(is_expensive_peer_request(MSG_GET_BLOCK));
        assert!(is_expensive_peer_request(MSG_GET_TX));
        assert!(!is_expensive_peer_request(MSG_PING));
        assert!(!is_expensive_peer_request(MSG_BLOCK_ANNOUNCE));
    }

    #[test]
    fn build61_network_mempool_admission_cap_rejects_new_unique_transactions() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build61-mempool-cap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let template = PendingTxState {
            txid: hex::encode([0x11u8; 32]),
            wtxid: hex::encode([0x22u8; 32]),
            valid_from_epoch: 1,
            expiry_epoch: 0,
            inputs: vec![],
            outputs: vec![],
            witnesses: vec![],
            fee_strikes: 0,
            base_fee_strikes: 0,
            from_license: 0,
            to_license: 0,
            amount_strikes: 0,
        };
        state.mempool.reserve(MAX_NETWORK_MEMPOOL_TXS);
        for i in 0..MAX_NETWORK_MEMPOOL_TXS {
            let mut pending = template.clone();
            let mut id = [0u8; 32];
            id[24..].copy_from_slice(&(i as u64).to_be_bytes());
            pending.txid = hex::encode(id);
            state.mempool.push(pending);
        }
        let mut candidate = template;
        candidate.txid = hex::encode([0xffu8; 32]);
        let err = validate_received_pending(&state, &candidate).unwrap_err();
        assert_eq!(
            err,
            format!(
                "network mempool admission cap {} reached",
                MAX_NETWORK_MEMPOOL_TXS
            )
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build58_offline_fixed_vectors_match_independent_verifier() {
        let seed = [0x81u8; 32];
        let owner_key = SigningKey::from_bytes(&seed);
        let owner_public_key = owner_key.verifying_key().to_bytes();
        let destination_key = SigningKey::from_bytes(&[0x82u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            hex::encode(owner_public_key),
            "93db9f2ee0f7e39e942fb59441190bf20b9c43cfcc8a051a152499cf392b7a37"
        );
        assert_eq!(
            hex::encode(address_id(&owner_public_key).0),
            "a74a21496e15157bf0b6e2f0c7c990d8a3ce7b474160e4d70479c0b884e09929"
        );
        assert_eq!(
            hex::encode(destination_key),
            "fa01347a991e04ae0f1a6d81db29a5ea4eeb5965f577ac9efb44e7b1f2fbb028"
        );
        assert_eq!(
            hex::encode(address_id(&destination_key).0),
            "3524c1dbbce35406c494d738ae8fd9530a539ab1c36b1db224ff0da8a277054c"
        );
        let request = OfflineSpendRequestV1 {
            network_id: DEVNET_NETWORK_ID,
            genesis_id: decode32(DEVNET_GENESIS_ID_HEX).unwrap(),
            from_license_id: [0x31; 32],
            to_license_id: [0x32; 32],
            owner_public_key,
            created_height: 37,
            max_submit_height: 181,
            valid_from_epoch: 142,
            expiry_epoch: 0,
            amount_strikes: STRIKES_PER_MUT,
            fee_strikes: 400,
            prevouts: vec![OfflineSpendPrevoutV1 {
                previous_txid: [0x11; 32],
                previous_output_index: 2,
                amount_strikes: 2 * STRIKES_PER_MUT,
                output_type: OUTPUT_PUBKEY_HASH,
                payload: address_id(&owner_public_key).0.to_vec(),
            }],
            outputs: vec![
                TxOutput {
                    amount_strikes: STRIKES_PER_MUT,
                    output_type: OUTPUT_PUBKEY_HASH,
                    payload: address_id(&destination_key).0.to_vec(),
                },
                TxOutput {
                    amount_strikes: 99_999_600,
                    output_type: OUTPUT_PUBKEY_HASH,
                    payload: address_id(&owner_public_key).0.to_vec(),
                },
            ],
        };
        let request_bytes = request.encode().unwrap();
        assert_eq!(request_bytes.len(), 389);
        assert_eq!(
            hex::encode(&request_bytes[request_bytes.len() - 32..]),
            "64191b7d866b1752e96b7f60e00a6d8bfcb655a20ae59159249304000bcea42c"
        );
        assert_eq!(
            hex::encode(offline_request_hash(&request_bytes)),
            "90cd4d681ac3502dbbc178a64e8f8b1a1bca2d5d3198965d619e346eb5635770"
        );
        let decoded = OfflineSpendRequestV1::decode(&request_bytes).unwrap();
        assert_eq!(decoded, request);
        let txid = request.txid().unwrap();
        assert_eq!(
            txid.to_hex(),
            "23a3cd3c8993523f406d2bfee93737227298c37cfb1b9391be400d6641d023ef"
        );
        let digest = sighash_all(&txid, 0, &request.prevouts[0].prevout());
        assert_eq!(
            hex::encode(digest.0),
            "f2071f05b81ba3f1c73daa9cfb7172bededb18e117928a1e3bbdc2f4f023075c"
        );
        let signature = owner_key.sign(&digest.0).to_bytes();
        assert_eq!(hex::encode(signature), "4d85c0a0a27d66b41352d089890a18ed3a56472f108928cd37b9a5dd8c61d7f56617902f0c002d2c500f718a86b4a33ab1fe4ca45b1f3513e338bbce7a74690f");
        let signed = OfflineSpendSignatureV1 {
            network_id: DEVNET_NETWORK_ID,
            request_hash: offline_request_hash(&request_bytes),
            owner_public_key,
            signatures: vec![signature],
        };
        let signed_bytes = signed.encode().unwrap();
        assert_eq!(signed_bytes.len(), 176);
        assert_eq!(
            hex::encode(&signed_bytes[signed_bytes.len() - 32..]),
            "6a441a137caa77a4308e4fd45362fe1d238a397c4b7bfc82da01d0623dbb30eb"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&signed_bytes)),
            "467ea4bec05333386cbb005ed2c960a86403e08b2569e972f44974773986bd20"
        );
        assert_eq!(
            OfflineSpendSignatureV1::decode(&signed_bytes).unwrap(),
            signed
        );
        let tx = TransactionV1 {
            core: request.core().unwrap(),
            witnesses: vec![WitnessV1::pubkey_hash(owner_public_key, signature)],
        };
        assert_eq!(
            tx.wtxid().to_hex(),
            "4afb6a2ee7083c8b4e8799dd4d67bc3dbab9104779d0f91fe17712f2f87d5249"
        );
    }

    #[test]
    fn build58_offline_request_checksum_and_signature_binding_reject_tamper() {
        let (state, owner_key) = build58_secure_owner_state(0xb1);
        let request = create_offline_send_request(&state, 0, 1, STRIKES_PER_MUT).unwrap();
        let mut request_bytes = request.encode().unwrap();
        request_bytes[40] ^= 1;
        assert!(OfflineSpendRequestV1::decode(&request_bytes)
            .unwrap_err()
            .contains("checksum"));
        let request_bytes = request.encode().unwrap();
        let txid = request.txid().unwrap();
        let signatures = request
            .prevouts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                owner_key
                    .sign(&sighash_all(&txid, i as u16, &p.prevout()).0)
                    .to_bytes()
            })
            .collect::<Vec<_>>();
        let mut signed = OfflineSpendSignatureV1 {
            network_id: DEVNET_NETWORK_ID,
            request_hash: offline_request_hash(&request_bytes),
            owner_public_key: request.owner_public_key,
            signatures,
        };
        signed.request_hash[0] ^= 1;
        assert!(
            submit_offline_spend(&state, &request_bytes, &request, &signed)
                .unwrap_err()
                .contains("does not match")
        );
    }

    #[test]
    fn build58_offline_signed_spend_submits_without_loading_owner_secret_online() {
        let (state, owner_key) = build58_secure_owner_state(0xb2);
        let request = create_offline_send_request(&state, 0, 1, STRIKES_PER_MUT).unwrap();
        let request_bytes = request.encode().unwrap();
        let txid = request.txid().unwrap();
        let signatures = request
            .prevouts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                owner_key
                    .sign(&sighash_all(&txid, i as u16, &p.prevout()).0)
                    .to_bytes()
            })
            .collect::<Vec<_>>();
        let signed = OfflineSpendSignatureV1 {
            network_id: DEVNET_NETWORK_ID,
            request_hash: offline_request_hash(&request_bytes),
            owner_public_key: request.owner_public_key,
            signatures,
        };
        let pending = submit_offline_spend(&state, &request_bytes, &request, &signed).unwrap();
        validate_pending_candidate(&state, &pending, false).unwrap();
        assert_eq!(pending.txid, txid.to_hex());
        assert_eq!(
            &pending.to_transaction().unwrap().witnesses[0].payload[..32],
            &owner_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn build58_offline_submit_rejects_stale_authority_spent_input_and_horizon() {
        let (state, owner_key) = build58_secure_owner_state(0xb3);
        let request = create_offline_send_request(&state, 0, 1, STRIKES_PER_MUT).unwrap();
        let request_bytes = request.encode().unwrap();
        let txid = request.txid().unwrap();
        let signatures = request
            .prevouts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                owner_key
                    .sign(&sighash_all(&txid, i as u16, &p.prevout()).0)
                    .to_bytes()
            })
            .collect::<Vec<_>>();
        let signed = OfflineSpendSignatureV1 {
            network_id: DEVNET_NETWORK_ID,
            request_hash: offline_request_hash(&request_bytes),
            owner_public_key: request.owner_public_key,
            signatures,
        };
        let mut stale = state.clone();
        stale.licenses[0].owner_public_key = hex::encode(
            SigningKey::from_bytes(&[0xb4; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(
            submit_offline_spend(&stale, &request_bytes, &request, &signed)
                .unwrap_err()
                .contains("stale")
        );
        let mut spent = state.clone();
        let p = &request.prevouts[0];
        spent.utxos.retain(|u| {
            !(u.txid == hex::encode(p.previous_txid) && u.output_index == p.previous_output_index)
        });
        assert!(
            submit_offline_spend(&spent, &request_bytes, &request, &signed)
                .unwrap_err()
                .contains("no longer unspent")
        );
        let mut late = state.clone();
        late.height = request.max_submit_height + 1;
        assert!(
            submit_offline_spend(&late, &request_bytes, &request, &signed)
                .unwrap_err()
                .contains("144-block")
        );
    }

    #[test]
    fn build56_fixed_wallet_signing_vectors_match_independent_verifier() {
        let owner_seed: [u8; 32] = (0x20u8..0x40).collect::<Vec<_>>().try_into().unwrap();
        let new_owner_seed: [u8; 32] = (0x40u8..0x60).collect::<Vec<_>>().try_into().unwrap();
        let new_mining_seed: [u8; 32] = (0x60u8..0x80).collect::<Vec<_>>().try_into().unwrap();
        let owner = SigningKey::from_bytes(&owner_seed);
        let new_owner = SigningKey::from_bytes(&new_owner_seed)
            .verifying_key()
            .to_bytes();
        let new_mining = SigningKey::from_bytes(&new_mining_seed)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            hex::encode(owner.verifying_key().to_bytes()),
            "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
        );
        assert_eq!(
            hex::encode(new_owner),
            "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"
        );
        assert_eq!(
            hex::encode(new_mining),
            "174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5"
        );

        let mut license = [0u8; 32];
        for (i, b) in license.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut transfer = LicenseTransferV1 {
            license_id: LicenseId(license),
            expected_owner_sequence: 7,
            expected_mining_sequence: 9,
            new_owner_public_key: new_owner,
            new_mining_public_key: new_mining,
            owner_signature: [0u8; 64],
        };
        assert_eq!(
            transfer.signing_digest().to_hex(),
            "6777a81183bc1d5b57b44e6b35c43c2a4b843b0d39cee64827b47619dc493da2"
        );
        transfer.owner_signature = owner.sign(&transfer.signing_digest().0).to_bytes();
        assert_eq!(hex::encode(transfer.owner_signature), "512f22c0d92350d575eaf0f964c2291c9a97b172c91153543db7c78bf41d662e09c0ceb857255d1682ddd69ab612ff8fb1f2521f1409803861fe93f548aa9b07");
        assert_eq!(
            transfer.operation().operation_id().to_hex(),
            "b17ce17973041942932012fafd72cf383fbd7f4680222952744e18edb75324c3"
        );

        let mut rotation = MiningKeyRotateV1 {
            license_id: LicenseId(license),
            expected_owner_sequence: 7,
            expected_mining_sequence: 9,
            new_mining_public_key: new_mining,
            owner_signature: [0u8; 64],
        };
        assert_eq!(
            rotation.signing_digest().to_hex(),
            "e822c2ccae5c9fbbbfda00f6a50176c21bfd6784037a4a56047a030ec3f485ef"
        );
        rotation.owner_signature = owner.sign(&rotation.signing_digest().0).to_bytes();
        assert_eq!(hex::encode(rotation.owner_signature), "b459f16331e2350525a65785c2ffa56435d1c4c2c2a6a8cde911b11da19eee7f123c7e7e1c825303775df890d37ae01df33018244e41226bfe81552e92861c0e");
        assert_eq!(
            rotation.operation().operation_id().to_hex(),
            "4f5415334e8bd2e5c3d055a754426ed668d53e7c2a450d0641e1ace037cdbdb4"
        );

        let mut core = [0u8; 208];
        for (i, b) in core.iter_mut().enumerate() {
            *b = ((i * 17 + 3) & 0xff) as u8;
        }
        let digest = block_signing_digest(&core);
        assert_eq!(
            digest.to_hex(),
            "b0896cac8f6359473ffb2efe7d90c2eef790c33c67047c4fae45016bcafb4156"
        );
        let mining = SigningKey::from_bytes(&new_mining_seed);
        let signature = mining.sign(&digest.0).to_bytes();
        assert_eq!(hex::encode(signature), "bd7bbd2d6c950423883b172f5b4dac0ff96d60179be3a1e66043cc70c007bae9ae445e041c375545d14663ad62ffff5be328afff91a1ab365ab94f11dd85530a");
        let mut header = [0u8; 272];
        header[..208].copy_from_slice(&core);
        header[208..].copy_from_slice(&signature);
        assert_eq!(
            block_hash(&header).to_hex(),
            "72887a342250475b2c9fbc591af43a151068ef4ab1aa0397fa7fa48e7d68e96f"
        );
    }

    #[test]
    fn build56_wallet_cli_is_explicit_and_dev_fixture_bridge_is_named() {
        let source = include_str!("main.rs");
        for command in [
            "wallet-send",
            "wallet-license-buy-mut",
            "wallet-license-transfer",
            "wallet-license-rotate-mining",
            "wallet-dividend-claim",
            "wallet-mine-one",
            "license-adopt-keystore-dev",
        ] {
            assert!(
                source.contains(command),
                "missing Build 5.6 custody command: {command}"
            );
        }
        assert!(source
            .contains("only bridges a deterministic Devnet fixture owner into encrypted custody"));
    }

    #[test]
    fn build56_production_wallet_custody_surface_remains_present() {
        let source = include_str!("main.rs");
        for command in [
            "wallet-send",
            "wallet-license-buy-mut",
            "wallet-license-transfer",
            "wallet-license-rotate-mining",
            "wallet-dividend-claim",
            "wallet-mine-one",
            "license-adopt-keystore-dev",
        ] {
            assert!(
                source.contains(command),
                "missing locked Build 5.6 custody command: {command}"
            );
        }
    }

    #[test]
    fn build53_locally_accepted_btc_purchase_persists_external_payment_state_and_root() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build66b-local-btc-root-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_build54_genesis_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        bootstrap::apply_devnet_bootstrap_block(&mut state).unwrap();

        let fixture = bitcoin::create_dev_purchase(&state, 1, 77).unwrap();
        let expected_payment = hex::encode(fixture.payment_id);
        let expected_license = hex::encode(fixture.ids[0].0);
        state
            .pending_protocol_operations
            .push(fixture.header_pending);
        state.pending_protocol_operations.push(fixture.pending);

        for _ in 0..512 {
            let epoch = next_mineable_epoch(&state);
            mine_epoch(&mut state, epoch).unwrap();
            if state
                .consumed_bitcoin_payments
                .iter()
                .any(|payment| payment.payment_id == expected_payment)
            {
                break;
            }
        }

        assert!(
            state.height >= 3,
            "fixture did not confirm header state then BTC purchase"
        );
        assert!(state
            .consumed_bitcoin_payments
            .iter()
            .any(|payment| payment.payment_id == expected_payment));
        assert!(state.licenses.iter().any(|license| {
            license.license_id == expected_license && license.purchase_method == PURCHASE_METHOD_BTC
        }));
        assert!(state.pending_protocol_operations.is_empty());
        bitcoin_headers::check_state(&state).unwrap();
        check_state(&state).unwrap();
        blocksync::verify_full_replay(&state).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build52_hotfix2_locally_accepted_claim_persists_dividend_state_and_root() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build52-hotfix2-local-claim-root-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();

        let treasury_amount = 12 * STRIKES_PER_MUT;
        state.utxos.push(UtxoState {
            txid: hex::encode([0xd2u8; 32]),
            output_index: 0,
            amount_strikes: treasury_amount,
            output_type: OUTPUT_TREASURY,
            payload: hex::encode(treasury_id()),
            creation_epoch: 1,
            creation_height: 0,
            coinbase: false,
        });
        state.total_issued_strikes = treasury_amount;
        state.tip_epoch = mutiny_protocol::DIVIDEND_AWARD_INTERVAL;
        dividends::process_epoch(&mut state, mutiny_protocol::DIVIDEND_AWARD_INTERVAL).unwrap();
        refresh_current_state_root(&mut state).unwrap();

        let original_reserve = state.treasury_reserved_dividend_strikes;
        let original_claimable = state
            .dividend_accounts
            .iter()
            .find(|a| a.license_id == state.licenses[0].license_id)
            .unwrap()
            .claimable_strikes;
        let amount = original_claimable / 2;
        let (payment, operation, _) = dividends::create_claim_bundle(&state, 0, amount).unwrap();
        state.mempool.push(payment);
        state.pending_protocol_operations.push(operation);

        accept_dev_block(
            &mut state,
            mutiny_protocol::DIVIDEND_AWARD_INTERVAL + 1,
            0,
            0,
            [0x11u8; 32],
            [0xffu8; 32],
        )
        .unwrap();

        assert_eq!(
            state.treasury_reserved_dividend_strikes,
            original_reserve - amount
        );
        let account = state
            .dividend_accounts
            .iter()
            .find(|a| a.license_id == state.licenses[0].license_id)
            .unwrap();
        assert_eq!(account.claimable_strikes, original_claimable - amount);
        check_state(&state).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    fn build500_purchase_fixture(
        state: &DevnetState,
        count: usize,
    ) -> (TransactionV1, ProtocolOperationV1) {
        let mut entries = Vec::new();
        for offset in 0..count {
            let index = (state.licenses.len() + offset) as u8;
            let pk = SigningKey::from_bytes(&dev_seed(index))
                .verifying_key()
                .to_bytes();
            entries.push(LicenseManifestEntryV1 {
                owner_public_key: pk,
                mining_public_key: pk,
            });
        }
        let manifest = MutLicenseManifestV1 {
            version: 1,
            network_id: DEVNET_NETWORK_ID,
            purchase_nonce: [0x5au8; 32],
            licenses: entries,
        };
        let manifest_hash = manifest.manifest_hash().unwrap();
        let price = subsidy(100).max(1) * count as u64;
        let tx = TransactionV1 {
            core: TransactionCoreV1 {
                version: 1,
                network_id: DEVNET_NETWORK_ID,
                valid_from_epoch: 100,
                expiry_epoch: 0,
                inputs: vec![],
                outputs: vec![TxOutput {
                    amount_strikes: price,
                    output_type: OUTPUT_LICENSE_PAYMENT,
                    payload: manifest_hash.0.to_vec(),
                }],
            },
            witnesses: vec![],
        };
        let purchase = LicensePurchaseMutV1 {
            payment_txid: tx.txid(),
            payment_output_index: 0,
            manifest,
        };
        (tx, purchase.operation().unwrap())
    }

    #[test]
    fn build500_queued_native_purchases_reserve_distinct_fixture_keys_and_utxos() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build500-queued-purchases-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        state.tip_epoch = 100;
        let payer_address = state.licenses[0].payment_address_id.clone();
        for (byte, amount) in [
            (0xa1u8, 20 * STRIKES_PER_MUT),
            (0xa2u8, 20 * STRIKES_PER_MUT),
        ] {
            state.utxos.push(UtxoState {
                txid: hex::encode([byte; 32]),
                output_index: 0,
                amount_strikes: amount,
                output_type: OUTPUT_PUBKEY_HASH,
                payload: payer_address.clone(),
                creation_epoch: 1,
                creation_height: 1,
                coinbase: false,
            });
        }

        let (first_tx, first_op, first_ids, _) =
            create_native_license_purchase(&state, 0, 2).unwrap();
        state.mempool.push(first_tx.clone());
        state.pending_protocol_operations.push(first_op.clone());
        let (second_tx, second_op, second_ids, _) =
            create_native_license_purchase(&state, 0, 2).unwrap();

        assert_ne!(
            first_tx.inputs[0].previous_txid,
            second_tx.inputs[0].previous_txid
        );
        assert!(first_ids.iter().all(|id| !second_ids.contains(id)));
        let first_purchase =
            decode_native_purchase_operation(&first_op.operation().unwrap()).unwrap();
        let second_purchase =
            decode_native_purchase_operation(&second_op.operation().unwrap()).unwrap();
        assert_ne!(
            first_purchase.manifest.licenses[0].owner_public_key,
            second_purchase.manifest.licenses[0].owner_public_key
        );
        assert_eq!(
            first_purchase.manifest.licenses[0].owner_public_key,
            SigningKey::from_bytes(&dev_seed(12))
                .verifying_key()
                .to_bytes()
        );
        assert_eq!(
            second_purchase.manifest.licenses[0].owner_public_key,
            SigningKey::from_bytes(&dev_seed(14))
                .verifying_key()
                .to_bytes()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build500_native_purchase_creates_pending_licenses_and_consumes_payment() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build500-purchase-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        state.tip_epoch = 100;
        let (payment_tx, operation) = build500_purchase_fixture(&state, 2);
        let coinbase_placeholder = TransactionV1 {
            core: TransactionCoreV1 {
                version: 1,
                network_id: DEVNET_NETWORK_ID,
                valid_from_epoch: 100,
                expiry_epoch: 0,
                inputs: vec![TxInput::Coinbase {
                    commitment: CoinbaseCommitmentV1 {
                        block_epoch: 100,
                        block_height: 1,
                        parent_block_hash: [0u8; 32],
                        protocol_operations_root: [0u8; 32],
                    },
                }],
                outputs: vec![TxOutput {
                    amount_strikes: 1,
                    output_type: OUTPUT_PUBKEY_HASH,
                    payload: [1u8; 32].to_vec(),
                }],
            },
            witnesses: vec![],
        };
        let before = state.licenses.len();
        assert_eq!(
            apply_protocol_operations(
                &mut state,
                &[coinbase_placeholder, payment_tx],
                &[operation],
                100
            )
            .unwrap(),
            2
        );
        assert_eq!(state.licenses.len(), before + 2);
        assert_eq!(state.consumed_native_payments.len(), 1);
        assert!(state.licenses[before..]
            .iter()
            .all(|l| l.status == LICENSE_STATUS_PENDING && l.activation_epoch == 164));
        assert_eq!(
            eligible_license_count(&state, 163),
            BOOTSTRAP_LICENSE_COUNT as u64
        );
        assert_eq!(
            apply_scheduled_license_transitions(&mut state, 164).unwrap(),
            2
        );
        assert_eq!(
            eligible_license_count(&state, 164),
            (BOOTSTRAP_LICENSE_COUNT + 2) as u64
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build500_license_payment_requires_exactly_one_purchase_op() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build500-exact-op-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let state = load_state(&dir).unwrap();
        let (payment_tx, operation) = build500_purchase_fixture(&state, 1);
        let coinbase_placeholder = TransactionV1 {
            core: TransactionCoreV1 {
                version: 1,
                network_id: DEVNET_NETWORK_ID,
                valid_from_epoch: 100,
                expiry_epoch: 0,
                inputs: vec![TxInput::Coinbase {
                    commitment: CoinbaseCommitmentV1 {
                        block_epoch: 100,
                        block_height: 1,
                        parent_block_hash: [0u8; 32],
                        protocol_operations_root: [0u8; 32],
                    },
                }],
                outputs: vec![TxOutput {
                    amount_strikes: 1,
                    output_type: OUTPUT_PUBKEY_HASH,
                    payload: [9u8; 32].to_vec(),
                }],
            },
            witnesses: vec![],
        };
        let mut missing = state.clone();
        assert!(apply_protocol_operations(
            &mut missing,
            &[coinbase_placeholder.clone(), payment_tx.clone()],
            &[],
            100
        )
        .is_err());
        let mut duplicate = state;
        assert!(apply_protocol_operations(
            &mut duplicate,
            &[coinbase_placeholder, payment_tx],
            &[operation.clone(), operation],
            100
        )
        .is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build500_orphan_license_payment_is_rejected_from_tx_only_gossip() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build500-orphan-payment-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let state = load_state(&dir).unwrap();
        let pending = PendingTxState {
            txid: hex::encode([0x11u8; 32]),
            wtxid: hex::encode([0x22u8; 32]),
            valid_from_epoch: 64,
            expiry_epoch: 0,
            inputs: vec![],
            outputs: vec![StoredTxOutput {
                amount_strikes: 1,
                output_type: OUTPUT_LICENSE_PAYMENT,
                payload: hex::encode([0x33u8; 32]),
            }],
            witnesses: vec![],
            fee_strikes: 0,
            base_fee_strikes: 0,
            from_license: 0,
            to_license: 0,
            amount_strikes: 1,
        };
        let error = validate_received_pending(&state, &pending).unwrap_err();
        assert!(error.contains("Protocol Op 0x0002"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build500_consumed_native_payment_is_committed_in_protocol_state_root() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build500-consumed-root-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let before = compute_protocol_state_root(&state, &state.utxos, 0, 0).unwrap();
        state
            .consumed_native_payments
            .push(hex::encode([0x44u8; 32]));
        let after = compute_protocol_state_root(&state, &state.utxos, 0, 0).unwrap();
        assert_ne!(before, after);
        let _ = fs::remove_dir_all(&dir);
    }

    fn build501_fund_license(state: &mut DevnetState, license_index: usize, byte: u8) {
        state.utxos.push(UtxoState {
            txid: hex::encode([byte; 32]),
            output_index: 0,
            amount_strikes: 32 * STRIKES_PER_MUT,
            output_type: OUTPUT_PUBKEY_HASH,
            payload: state.licenses[license_index].payment_address_id.clone(),
            creation_epoch: 1,
            creation_height: 1,
            coinbase: false,
        });
    }

    fn build501_coinbase_placeholder(epoch: u64) -> TransactionV1 {
        TransactionV1 {
            core: TransactionCoreV1 {
                version: 1,
                network_id: DEVNET_NETWORK_ID,
                valid_from_epoch: epoch,
                expiry_epoch: 0,
                inputs: vec![TxInput::Coinbase {
                    commitment: CoinbaseCommitmentV1 {
                        block_epoch: epoch,
                        block_height: 1,
                        parent_block_hash: [0u8; 32],
                        protocol_operations_root: [0u8; 32],
                    },
                }],
                outputs: vec![TxOutput {
                    amount_strikes: 1,
                    output_type: OUTPUT_PUBKEY_HASH,
                    payload: [1u8; 32].to_vec(),
                }],
            },
            witnesses: vec![],
        }
    }

    #[test]
    fn build501_transfer_preserves_license_id_rotates_both_authorities_and_commits_history() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build501-transfer-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        state.tip_epoch = 100;
        build501_fund_license(&mut state, 0, 0xa1);
        let permanent = state.licenses[0].license_id.clone();
        let before_root = compute_protocol_state_root(&state, &state.utxos, 0, 0).unwrap();
        let new_owner = dev_key_slot_public_key("200").unwrap();
        let new_mining = dev_key_slot_public_key("201").unwrap();
        let (fee, _pending, op) =
            create_license_transfer_operation(&state, 0, new_owner, new_mining).unwrap();
        let fee_tx = fee.to_transaction().unwrap();
        assert_eq!(authority_fee_ticket_license_index(&state, &fee_tx), Some(0));
        assert_eq!(
            apply_protocol_operations(
                &mut state,
                &[build501_coinbase_placeholder(101), fee_tx],
                &[op.clone()],
                101
            )
            .unwrap(),
            0
        );
        assert_eq!(state.licenses[0].license_id, permanent);
        assert_eq!(state.licenses[0].owner_key_sequence, 1);
        assert_eq!(state.licenses[0].mining_key_sequence, 1);
        assert_eq!(
            decode32(&state.licenses[0].owner_public_key).unwrap(),
            new_owner
        );
        assert_eq!(
            decode32(&state.licenses[0].mining_public_key).unwrap(),
            new_mining
        );
        assert_eq!(state.historical_license_keys.len(), 1);
        assert_eq!(
            state.historical_license_keys[0].operation_id,
            op.operation_id().to_hex()
        );
        let after_root = compute_protocol_state_root(&state, &state.utxos, 0, 0).unwrap();
        assert_ne!(before_root, after_root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build501_locally_accepted_transfer_persists_history_and_matches_committed_state_root() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build501-local-transfer-root-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        state.tip_epoch = 100;
        build501_fund_license(&mut state, 0, 0xa2);
        state.total_issued_strikes = 32 * STRIKES_PER_MUT;
        refresh_current_state_root(&mut state).unwrap();

        let new_owner = dev_key_slot_public_key("200").unwrap();
        let new_mining = dev_key_slot_public_key("201").unwrap();
        let (fee, pending_op, _op) =
            create_license_transfer_operation(&state, 0, new_owner, new_mining).unwrap();
        state.mempool.push(fee);
        state.pending_protocol_operations.push(pending_op);

        accept_dev_block(&mut state, 101, 1, 0, [0x11u8; 32], [0xffu8; 32]).unwrap();

        assert_eq!(state.historical_license_keys.len(), 1);
        check_state(&state).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build501_rotation_changes_only_mining_authority_and_old_key_fails_new_signature_check() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build501-rotate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        state.tip_epoch = 100;
        build501_fund_license(&mut state, 0, 0xb1);
        let owner_before = state.licenses[0].owner_public_key.clone();
        let old_mining = decode32(&state.licenses[0].mining_public_key).unwrap();
        let new_mining = dev_key_slot_public_key("202").unwrap();
        let (fee, _pending, op) =
            create_mining_key_rotation_operation(&state, 0, new_mining).unwrap();
        let fee_tx = fee.to_transaction().unwrap();
        apply_protocol_operations(
            &mut state,
            &[build501_coinbase_placeholder(101), fee_tx],
            &[op],
            101,
        )
        .unwrap();
        assert_eq!(state.licenses[0].owner_public_key, owner_before);
        assert_eq!(state.licenses[0].owner_key_sequence, 0);
        assert_eq!(state.licenses[0].mining_key_sequence, 1);
        assert_eq!(
            decode32(&state.licenses[0].mining_public_key).unwrap(),
            new_mining
        );
        assert_eq!(state.historical_license_keys.len(), 1);
        let digest = [0x5au8; 32];
        let old_sk = dev_signing_key_for_public_key(&old_mining).unwrap();
        let old_sig = old_sk.sign(&digest).to_bytes();
        let new_vk = VerifyingKey::from_bytes(&new_mining).unwrap();
        assert!(new_vk
            .verify_strict(&digest, &Signature::from_bytes(&old_sig))
            .is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build501_authority_fee_transaction_is_protocol_bound_and_not_inventory_gossip() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build501-bound-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        state.tip_epoch = 100;
        build501_fund_license(&mut state, 0, 0xc1);
        let new_mining = dev_key_slot_public_key("203").unwrap();
        let (fee, pending_op, _) =
            create_mining_key_rotation_operation(&state, 0, new_mining).unwrap();
        assert!(!transaction_is_protocol_bound(&state, &fee.txid));
        state.mempool.push(fee.clone());
        state.pending_protocol_operations.push(pending_op);
        assert!(transaction_is_protocol_bound(&state, &fee.txid));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build501_reconstructed_license_payment_keeps_payer_as_cli_recipient_metadata() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build501-display-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        state.tip_epoch = 100;
        build501_fund_license(&mut state, 2, 0xd1);
        let (pending, _, _, _) = create_native_license_purchase(&state, 2, 1).unwrap();
        let tx = pending.to_transaction().unwrap();
        let rebuilt = blocksync::pending_from_transaction(&state, &tx).unwrap();
        assert_eq!(rebuilt.from_license, 2);
        assert_eq!(rebuilt.to_license, 2);
        assert_eq!(rebuilt.txid, pending.txid);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build501_stale_authority_sequence_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build501-stale-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        state.tip_epoch = 100;
        build501_fund_license(&mut state, 0, 0xe1);
        let new_mining = dev_key_slot_public_key("204").unwrap();
        let (fee, _, op) = create_mining_key_rotation_operation(&state, 0, new_mining).unwrap();
        let fee_tx = fee.to_transaction().unwrap();
        apply_protocol_operations(
            &mut state,
            &[build501_coinbase_placeholder(101), fee_tx.clone()],
            &[op.clone()],
            101,
        )
        .unwrap();
        let err = apply_protocol_operations(
            &mut state,
            &[build501_coinbase_placeholder(102), fee_tx],
            &[op],
            102,
        )
        .unwrap_err();
        assert!(
            err.contains("stale mining key sequence") || err.contains("stale owner key sequence")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pack_i_peer_address_roundtrip_ipv4_and_ipv6() {
        let input = vec!["127.0.0.1:24588".to_string(), "[::1]:24589".to_string()];
        let encoded = encode_peer_addresses(&input, 123).unwrap();
        let decoded = decode_peer_addresses(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn peer_address_rejects_trailing_bytes() {
        let mut encoded = encode_peer_addresses(&["127.0.0.1:24588".to_string()], 0).unwrap();
        encoded.push(0);
        assert!(decode_peer_addresses(&encoded).is_err());
    }

    #[test]
    fn mut_amount_round_trip() {
        for text in ["1", "1.5", "0.00000001", "12.34567890", "999.00000000"] {
            let value = parse_mut_amount(text).unwrap();
            assert_eq!(parse_mut_amount(&format_mut(value)).unwrap(), value);
        }
        assert_eq!(parse_mut_amount("8").unwrap(), 800_000_000);
        assert!(parse_mut_amount("1.000000001").is_err());
    }

    #[test]
    fn send_weight_has_fixed_witness_shape() {
        let one = estimate_send_weight(1, 2).unwrap();
        let two = estimate_send_weight(2, 2).unwrap();
        assert!(one > 100);
        assert!(two > one);
    }

    #[test]
    fn pack_h_tx_inventory_is_one_txid() {
        let txid = [0x5au8; 32];
        let frame = Frame::new(P2P_MAGIC_DEVNET, MSG_TX_ANNOUNCE, 4, txid.to_vec()).unwrap();
        assert_eq!(frame.message_type, 0x0020);
        assert_eq!(frame.payload.len(), 32);
        assert_eq!(frame.payload.as_slice(), &txid[..]);
    }

    #[test]
    fn build62_hotfix1_tx_relay_survives_interleaved_addr_before_gettx() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let txid = [0x5au8; 32];
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let addr_payload = encode_peer_addresses(&["127.0.0.1:24588".to_string()], 0).unwrap();
            Frame::new(P2P_MAGIC_DEVNET, MSG_ADDR, 0x4200, addr_payload)
                .unwrap()
                .write_to(&mut stream)
                .unwrap();
            Frame::new(P2P_MAGIC_DEVNET, MSG_GET_TX, 4, txid.to_vec())
                .unwrap()
                .write_to(&mut stream)
                .unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let response = read_tx_relay_expected_response(
            Path::new("."),
            &mut client,
            4,
            &[MSG_GET_TX, MSG_DEVNET_TX_RESULT],
            "GETTX/TX_RESULT",
        )
        .unwrap();
        assert_eq!(response.message_type, MSG_GET_TX);
        assert_eq!(response.request_id, 4);
        assert_eq!(response.payload.as_slice(), &txid[..]);
        server.join().unwrap();
    }

    #[test]
    fn build62_hotfix1_tx_relay_survives_interleaved_addr_before_tx_result() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let addr_payload = encode_peer_addresses(&[], 0).unwrap();
            Frame::new(P2P_MAGIC_DEVNET, MSG_ADDR, 0x4200, addr_payload)
                .unwrap()
                .write_to(&mut stream)
                .unwrap();
            Frame::new(
                P2P_MAGIC_DEVNET,
                MSG_DEVNET_TX_RESULT,
                4,
                b"ACCEPTED test".to_vec(),
            )
            .unwrap()
            .write_to(&mut stream)
            .unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let response = read_tx_relay_expected_response(
            Path::new("."),
            &mut client,
            4,
            &[MSG_DEVNET_TX_RESULT],
            "TX_RESULT",
        )
        .unwrap();
        assert_eq!(response.message_type, MSG_DEVNET_TX_RESULT);
        assert_eq!(response.request_id, 4);
        assert_eq!(response.payload.as_slice(), b"ACCEPTED test");
        server.join().unwrap();
    }

    #[test]
    fn build4_block_roundtrip_replays_from_genesis() {
        let dir = std::env::temp_dir().join(format!("mutiny-build4-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let genesis = load_state(&dir).unwrap();
        let mut source = genesis.clone();
        for epoch in 64..80 {
            mine_epoch(&mut source, epoch).unwrap();
            if source.height == 1 {
                break;
            }
        }
        assert_eq!(
            source.height, 1,
            "deterministic Devnet should find a block in the test window"
        );
        assert_eq!(source.blocks.len(), 1);
        let payload = blocksync::encode_block_payload(&source.blocks[0]).unwrap();
        let (header, txs, operations) = blocksync::decode_block_payload(&payload).unwrap();
        let mut replay = genesis;
        blocksync::validate_and_apply_block(&mut replay, header, txs.clone(), operations.clone())
            .unwrap();
        assert_eq!(replay.tip_hash, source.tip_hash);
        assert_eq!(replay.current_state_root, source.current_state_root);
        assert_eq!(replay.total_issued_strikes, source.total_issued_strikes);
        blocksync::verify_full_replay(&source).unwrap();

        let mut bad_header = header;
        bad_header[208] ^= 0x01;
        let mut rejected = load_state(&dir).unwrap();
        assert!(
            blocksync::validate_and_apply_block(&mut rejected, bad_header, txs, operations)
                .is_err()
        );
        assert_eq!(rejected.height, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn difficulty_history_pack_e_boundaries() {
        let mut count = 0u8;
        let mut bitmap = 0u64;
        let mut correction = DIFFICULTY_Q32_ONE;
        for result in [true, true, true, true, true, false, false, false] {
            append_history_values(&mut count, &mut bitmap, &mut correction, result).unwrap();
        }
        assert_eq!(count, 8);
        assert_eq!(bitmap.count_ones(), 5);
    }

    #[test]
    fn persistent_session_backoff_is_bounded_power_of_two() {
        assert_eq!(session_backoff_seconds(0), 0);
        assert_eq!(session_backoff_seconds(1), 1);
        assert_eq!(session_backoff_seconds(2), 2);
        assert_eq!(session_backoff_seconds(3), 4);
        assert_eq!(session_backoff_seconds(6), 32);
        assert_eq!(session_backoff_seconds(31), 32);
    }

    #[test]
    fn persistent_session_reuses_one_authenticated_tcp_connection_for_two_pings_build44() {
        let base = std::env::temp_dir().join(format!(
            "mutiny-build44-session-test-{}",
            std::process::id()
        ));
        let client_dir = base.join("client");
        let server_dir = base.join("server");
        let _ = fs::remove_dir_all(&base);
        init_devnet(&client_dir, 1, true).unwrap();
        init_devnet(&server_dir, 1, true).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let addr_text = addr.to_string();
        let server_listen = addr_text.clone();
        let server_state = Arc::new(Mutex::new(load_state(&server_dir).unwrap()));
        let server_peers: PeerRegistry = Arc::new(Mutex::new(HashSet::new()));
        let server_sessions = new_session_registry();
        let server_dir_thread = server_dir.clone();
        let server_state_thread = server_state.clone();
        let server_peers_thread = server_peers.clone();
        let server_sessions_thread = server_sessions.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_p2p_connection(
                stream,
                server_dir_thread,
                server_state_thread,
                server_peers_thread,
                server_sessions_thread,
                server_listen,
            )
            .unwrap();
        });

        let client_sessions = new_session_registry();
        ping_peer_persistent(&client_dir, &client_sessions, &addr_text, 1).unwrap();
        ping_peer_persistent(&client_dir, &client_sessions, &addr_text, 2).unwrap();
        {
            let registry = client_sessions.lock().unwrap();
            let slot = registry.get(&addr_text).unwrap().clone();
            drop(registry);
            let session = slot.lock().unwrap();
            assert_eq!(session.connections_established, 1);
            assert_eq!(session.operations_completed, 2);
            assert_eq!(session.transport_failures, 0);
            assert_eq!(session.peer_shutdowns, 0);
        }

        // Dropping the sole outbound registry closes the reused socket, allowing the responder
        // loop to observe EOF and exit. If the second ping had opened another connection, it
        // would have no accepting responder and this test would fail instead of returning PONG.
        drop(client_sessions);
        server.join().unwrap();
        let _ = fs::remove_dir_all(&base);
    }
    #[test]
    fn build44_diagnostics_separate_canonical_tip_from_empty_epoch_state() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build44-diagnostics-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        for epoch in 64..96 {
            let before = state.height;
            mine_epoch(&mut state, epoch).unwrap();
            if state.height > before {
                break;
            }
        }
        assert_eq!(state.height, 1);
        let committed_epoch = canonical_tip_epoch(&state);
        let committed_root = canonical_tip_state_root(&state).to_string();
        let committed_hash = state.tip_hash.clone();

        state.tip_epoch = state.tip_epoch.saturating_add(1);
        append_difficulty_result(&mut state, false).unwrap();
        refresh_current_state_root(&mut state).unwrap();

        assert_eq!(canonical_tip_epoch(&state), committed_epoch);
        assert_eq!(canonical_tip_state_root(&state), committed_root.as_str());
        assert_eq!(state.tip_hash, committed_hash);
        assert!(state.tip_epoch > committed_epoch);
        assert_ne!(state.current_state_root, committed_root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build441_preflight_peek_distinguishes_fin_from_idle_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(20));
            stream.shutdown(Shutdown::Write).unwrap();
            thread::sleep(Duration::from_millis(50));
        });
        let client = TcpStream::connect(addr).unwrap();
        assert!(!stream_has_orderly_eof(&client).unwrap());
        thread::sleep(Duration::from_millis(40));
        assert!(stream_has_orderly_eof(&client).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn build441_graceful_inbound_half_close_delivers_fin() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (server_stream, _) = listener.accept().unwrap();

        let registry = new_inbound_session_registry();
        let id = register_inbound_shutdown_handle(&registry, &server_stream).unwrap();
        assert_eq!(begin_graceful_inbound_shutdown(&registry).unwrap(), 1);

        let mut byte = [0u8; 1];
        assert_eq!(
            client.read(&mut byte).unwrap(),
            0,
            "remote must observe orderly FIN/EOF"
        );
        unregister_inbound_shutdown_handle(&registry, id).unwrap();
        finish_inbound_shutdown(&registry).unwrap();
    }

    #[test]
    fn build441_bounded_shutdown_marks_local_outbound_disconnected_after_fin() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            // The local session manager must send FIN before dropping the socket.
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });

        let stream = TcpStream::connect(addr).unwrap();
        let sessions = new_session_registry();
        let slot = Arc::new(Mutex::new(PersistentSession::new()));
        {
            let mut session = slot.lock().unwrap();
            session.stream = Some(stream);
            session.connections_established = 1;
        }
        sessions
            .lock()
            .unwrap()
            .insert(addr.to_string(), slot.clone());

        shutdown_persistent_sessions(&sessions).unwrap();
        {
            let session = slot.lock().unwrap();
            assert!(session.stream.is_none());
            assert_eq!(
                session.peer_shutdowns, 0,
                "our own shutdown is not a peer shutdown"
            );
            assert_eq!(
                session.transport_failures, 0,
                "our own shutdown is not a transport fault"
            );
        }
        server.join().unwrap();
    }

    #[test]
    fn build44_session_metrics_distinguish_shutdown_text_from_transport_fault() {
        assert!(looks_like_orderly_peer_shutdown(
            "failed to fill whole buffer"
        ));
        assert!(looks_like_orderly_peer_shutdown("Unexpected end of file"));
        assert!(!looks_like_orderly_peer_shutdown(
            "An existing connection was forcibly closed by the remote host. (os error 10054)"
        ));
        let mut session = PersistentSession::new();
        session.connections_established = 3;
        assert_eq!(session.connections_established.saturating_sub(1), 2);
    }

    #[test]
    fn build55_genesis_init_does_not_create_any_node_secret_file() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build55-init-secrets-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_build54_genesis_devnet(&dir, 1, true).unwrap();
        assert!(!legacy_node_key_path(&dir).exists());
        assert!(!node_keystore_path(&dir).exists());
        check_state(&load_state(&dir).unwrap()).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build55_encrypted_node_identity_roundtrips_without_plaintext_file() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build55-node-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let passphrase = b"correct horse battery staple";
        let created = create_node_identity(&dir, passphrase).unwrap();
        assert!(!legacy_node_key_path(&dir).exists());
        let secure = fs::read(node_keystore_path(&dir)).unwrap();
        assert_eq!(secure.len(), mutiny_keystore::FILE_LEN);
        assert_ne!(&secure[88..120], &created.to_bytes());
        let loaded = load_encrypted_node_key_uncached(&dir, passphrase).unwrap();
        assert_eq!(
            created.verifying_key().to_bytes(),
            loaded.verifying_key().to_bytes()
        );
        assert_eq!(
            mutiny_p2p::node_id(&created.verifying_key().to_bytes()),
            mutiny_p2p::node_id(&loaded.verifying_key().to_bytes())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build55_legacy_node_key_is_refused_until_migration_preserves_node_id() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build55-migrate-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let seed = [0x5au8; 32];
        fs::write(legacy_node_key_path(&dir), seed).unwrap();
        let expected = SigningKey::from_bytes(&seed);
        let err =
            load_encrypted_node_key_uncached(&dir, b"correct horse battery staple").unwrap_err();
        assert!(err.contains("refused"));
        let migrated = migrate_legacy_node_identity(&dir, b"correct horse battery staple").unwrap();
        assert_eq!(
            expected.verifying_key().to_bytes(),
            migrated.verifying_key().to_bytes()
        );
        assert!(!legacy_node_key_path(&dir).exists());
        assert!(node_keystore_path(&dir).exists());
        let reopened =
            load_encrypted_node_key_uncached(&dir, b"correct horse battery staple").unwrap();
        assert_eq!(
            expected.verifying_key().to_bytes(),
            reopened.verifying_key().to_bytes()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build55_passphrase_file_and_wallet_labels_are_strict() {
        let dir =
            std::env::temp_dir().join(format!("mutiny-build55-passphrase-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let pass = dir.join("pass.txt");
        fs::write(&pass, b"abcdefghijklmnop\r\n").unwrap();
        assert_eq!(&*read_passphrase_path(&pass).unwrap(), b"abcdefghijklmnop");
        fs::write(&pass, b"short\n").unwrap();
        assert!(read_passphrase_path(&pass).is_err());
        assert!(wallet_key_path(&dir, KeyRole::LicenseOwner, "cold_owner_01").is_ok());
        assert!(wallet_key_path(&dir, KeyRole::LicenseMining, "../../escape").is_err());
        assert!(parse_wallet_key_role("node").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build55_empty_or_plaintext_identity_never_satisfies_secure_loader() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build55-secure-loader-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let passphrase = b"correct horse battery staple";
        assert!(load_encrypted_node_key_uncached(&dir, passphrase)
            .unwrap_err()
            .contains("not initialized"));
        fs::write(legacy_node_key_path(&dir), [1u8; 32]).unwrap();
        assert!(load_encrypted_node_key_uncached(&dir, passphrase)
            .unwrap_err()
            .contains("refused"));
        let _ = fs::remove_dir_all(&dir);
    }

    fn c1c_temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mutiny-build67-c1c-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    // This fixture deliberately changes a bootstrap mining public key and parent
    // commitment. It tests ordinary transitions only; it is NOT canonical Mainnet
    // Block1 evidence and cannot substitute for operational-signer release proof.
    pub(super) fn ordinary_mainnet_synthetic_parent() -> (DevnetState, SigningKey) {
        static PARENT: std::sync::OnceLock<DevnetState> = std::sync::OnceLock::new();
        let mut state = PARENT
            .get_or_init(|| {
                let dir = c1c_temp_dir("ordinary-synthetic-parent");
                init_mainnet_genesis(&dir, 1, true).unwrap();
                let genesis = load_state(&dir).unwrap();
                let decoded = c1c_witness_provider().load().unwrap().decode().unwrap();
                let staged =
                    mainnet_bootstrap::build_staged_mainnet_block1_transition(&genesis, &decoded)
                        .unwrap();
                fs::remove_dir_all(&dir).unwrap();
                staged.state
            })
            .clone();
        let signer = SigningKey::from_bytes(&[0x67; 32]);
        state.licenses[0].mining_public_key = hex::encode(signer.verifying_key().to_bytes());
        refresh_current_state_root(&mut state).unwrap();
        let root = state.current_state_root.clone();
        state.blocks.last_mut().unwrap().state_root = root;
        require_mainnet_canonical_tip(&state).unwrap();
        (state, signer)
    }

    #[test]
    fn ordinary_mainnet_network_binding_and_pack_k_boundaries() {
        let (mut state, owner) = build56_secure_owner_state(0x68);
        state.network_id = MAINNET_NETWORK_ID;
        state.genesis_hash = hex::encode(MAINNET_GENESIS_ID);
        state.format_version = 10;
        assert!(!presence::active(&state, 10));
        assert!(presence::active(&state, 11));
        let pending =
            create_send_transaction_with_signer(&state, 0, 1, STRIKES_PER_MUT, &owner).unwrap();
        let tx = pending
            .to_transaction_for_network(state.network_id)
            .unwrap();
        assert_eq!(tx.core.network_id, MAINNET_NETWORK_ID);
        let stored = serde_json::to_vec(&pending).unwrap();
        let reloaded: PendingTxState = serde_json::from_slice(&stored).unwrap();
        assert_eq!(
            reloaded
                .to_transaction_for_network(state.network_id)
                .unwrap(),
            tx
        );
        assert_ne!(
            reloaded.to_transaction().unwrap().core.network_id,
            tx.core.network_id
        );
        assert_ne!(treasury_id_for_network(MAINNET_NETWORK_ID), treasury_id());
        state.genesis_hash = DEVNET_GENESIS_ID_HEX.to_string();
        assert!(runtime_for_state(&state).is_err());
        assert!(!presence::active(&state, 11));
        state.network_id = DEVNET_NETWORK_ID;
        assert!(!presence::active(&state, 1499));
        assert!(presence::active(&state, 1500));
        state.genesis_hash = state.genesis_hash.to_uppercase();
        assert!(!presence::active(&state, 1500));
    }

    #[test]
    fn ordinary_mainnet_mining_failures_leave_parent_exactly_unchanged() {
        let (state, signer) = ordinary_mainnet_synthetic_parent();
        let before = serde_json::to_vec(&state).unwrap();
        assert!(stage_mainnet_mining_attempt(&state, 73, 0, &signer)
            .unwrap_err()
            .contains("base-eligible"));
        let wrong = SigningKey::from_bytes(&[0x69; 32]);
        assert!(stage_mainnet_mining_attempt(&state, 74, 0, &wrong)
            .unwrap_err()
            .contains("mining authority"));
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        let mut advanced = state.clone();
        advanced.tip_epoch += 1;
        assert!(require_mainnet_canonical_tip(&advanced).is_err());
        assert!(stage_mainnet_mining_attempt(&advanced, 74, 0, &signer).is_err());
    }

    #[test]
    fn hotfix1_ordinary_mainnet_signed_blocks_apply_without_witness_and_reject_atomically() {
        let (mut parent, signer) = ordinary_mainnet_synthetic_parent();
        let ingress = hotfix1_ingress(None);
        for expected_height in 2..=3 {
            let original = serde_json::to_vec(&parent).unwrap();
            let first_epoch = 74.max(parent.tip_epoch + 1);
            let mut produced = None;
            for epoch in first_epoch..first_epoch + 128 {
                produced = stage_mainnet_mining_attempt(&parent, epoch, 0, &signer).unwrap();
                assert_eq!(serde_json::to_vec(&parent).unwrap(), original);
                if produced.is_some() {
                    break;
                }
            }
            let expected = produced.expect("bounded deterministic signer must produce a block");
            assert_eq!(expected.height, expected_height);
            let mut constructed = parent.clone();
            mine_epoch_with_signer(&mut constructed, expected.tip_epoch, Some((0, &signer)))
                .unwrap();
            assert_eq!(
                serde_json::to_vec(&constructed).unwrap(),
                serde_json::to_vec(&expected).unwrap(),
                "raw constructor state must equal independently validated state"
            );
            let payload = blocksync::encode_block_payload(expected.blocks.last().unwrap()).unwrap();
            let (header, txs, ops) = blocksync::decode_block_payload(&payload).unwrap();
            // Runtime context is checked independently of stored identity.
            let devnet_ingress = RuntimeIngressContext {
                runtime: RuntimeNetwork::Devnet,
                bootstrap_witness: None,
            };
            let mut unchanged = parent.clone();
            assert!(matches!(
                blocksync::validate_and_apply_announced_block(
                    &mut unchanged,
                    header,
                    txs.clone(),
                    ops.clone(),
                    &devnet_ingress
                ),
                Err(blocksync::RuntimeBlockApplyError::ConsensusTransition(_))
            ));
            assert_eq!(serde_json::to_vec(&unchanged).unwrap(), original);
            // Even a correctly bound Devnet state must reject this Mainnet header.
            let mut devnet = parent.clone();
            devnet.network_id = DEVNET_NETWORK_ID;
            devnet.genesis_hash = DEVNET_GENESIS_ID_HEX.to_string();
            let before_devnet = serde_json::to_vec(&devnet).unwrap();
            assert!(matches!(
                blocksync::validate_and_apply_announced_block(
                    &mut devnet,
                    header,
                    txs.clone(),
                    ops.clone(),
                    &devnet_ingress
                ),
                Err(blocksync::RuntimeBlockApplyError::ConsensusTransition(_))
            ));
            assert_eq!(serde_json::to_vec(&devnet).unwrap(), before_devnet);
            let mut wrong_genesis = parent.clone();
            wrong_genesis.genesis_hash = DEVNET_GENESIS_ID_HEX.to_string();
            let before_wrong = serde_json::to_vec(&wrong_genesis).unwrap();
            assert!(matches!(
                blocksync::validate_and_apply_announced_block(
                    &mut wrong_genesis,
                    header,
                    txs.clone(),
                    ops.clone(),
                    &ingress
                ),
                Err(blocksync::RuntimeBlockApplyError::ConsensusTransition(_))
            ));
            assert_eq!(serde_json::to_vec(&wrong_genesis).unwrap(), before_wrong);
            // Testnet cannot produce a runtime context at all.
            assert!(RuntimeNetwork::from_cli(Some("testnet"))
                .unwrap_err()
                .contains("inactive and fail-closed"));
            assert_eq!(serde_json::to_vec(&unchanged).unwrap(), original);
            let mut bad = header;
            bad[0] ^= 1;
            assert!(matches!(
                blocksync::validate_and_apply_announced_block(
                    &mut parent,
                    bad,
                    txs.clone(),
                    ops.clone(),
                    &ingress
                ),
                Err(blocksync::RuntimeBlockApplyError::ConsensusTransition(_))
            ));
            assert_eq!(serde_json::to_vec(&parent).unwrap(), original);
            blocksync::validate_and_apply_announced_block(&mut parent, header, txs, ops, &ingress)
                .unwrap();
            assert_eq!(
                serde_json::to_vec(&parent).unwrap(),
                serde_json::to_vec(&expected).unwrap()
            );
            require_mainnet_canonical_tip(&parent).unwrap();
        }
    }

    #[test]
    fn ordinary_mainnet_pending_refresh_merges_deduplicates_and_revalidates() {
        let (mut current, owner) = build56_secure_owner_state(0x6a);
        current.network_id = MAINNET_NETWORK_ID;
        current.genesis_hash = hex::encode(MAINNET_GENESIS_ID);
        let first =
            create_send_transaction_with_signer(&current, 0, 1, STRIKES_PER_MUT, &owner).unwrap();
        let mut extra = current.utxos.last().unwrap().clone();
        extra.txid = hex::encode([0x6b; 32]);
        current.utxos.push(extra.clone());
        let mut second_source = current.clone();
        second_source.utxos.retain(|utxo| utxo.txid == extra.txid);
        let second =
            create_send_transaction_with_signer(&second_source, 0, 1, 2 * STRIKES_PER_MUT, &owner)
                .unwrap();
        current.mempool.push(first.clone());
        let mut accepted = current.clone();
        accepted.mempool = vec![second.clone(), first.clone()];
        let root = accepted.current_state_root.clone();
        blocksync::refresh_pending_after_runtime_commit(&mut accepted, &current).unwrap();
        assert_eq!(accepted.mempool.len(), 2);
        assert!(accepted.mempool.iter().any(|tx| tx.txid == first.txid));
        assert!(accepted.mempool.iter().any(|tx| tx.txid == second.txid));
        assert_eq!(accepted.current_state_root, root);
        accepted.utxos.clear();
        blocksync::refresh_pending_after_runtime_commit(&mut accepted, &current).unwrap();
        assert!(accepted.mempool.is_empty());
        let wrong_network = first.to_transaction().unwrap();
        assert!(
            blocksync::pending_from_transaction(&current, &wrong_network)
                .unwrap_err()
                .contains("network")
        );
    }

    #[test]
    fn ordinary_mainnet_pending_presence_tracks_adopted_mining_authority() {
        let (mut current, signer) = ordinary_mainnet_synthetic_parent();
        blocksync::advance_empty_epochs(&mut current, 74).unwrap();
        let op = presence::create_operation(&current, 0, 80, &signer).unwrap();
        let pending = PendingProtocolOperationState {
            operation: hex::encode(op.encode()),
            required_txid: String::new(),
        };
        current.pending_protocol_operations.push(pending.clone());
        let mut accepted = current.clone();
        blocksync::refresh_pending_after_runtime_commit(&mut accepted, &current).unwrap();
        assert_eq!(accepted.pending_protocol_operations.len(), 1);
        accepted.tip_epoch = 80;
        blocksync::refresh_pending_after_runtime_commit(&mut accepted, &current).unwrap();
        assert!(accepted.pending_protocol_operations.is_empty());
        accepted.tip_epoch = 74;
        accepted.licenses[0].mining_key_sequence += 1;
        blocksync::refresh_pending_after_runtime_commit(&mut accepted, &current).unwrap();
        assert!(accepted.pending_protocol_operations.is_empty());
        accepted.licenses[0].mining_key_sequence -= 1;
        accepted.genesis_hash = DEVNET_GENESIS_ID_HEX.to_string();
        blocksync::refresh_pending_after_runtime_commit(&mut accepted, &current).unwrap();
        assert!(accepted.pending_protocol_operations.is_empty());
    }

    #[test]
    fn hotfix1_shared_result_classification_preserves_caller_dispositions() {
        assert_eq!(
            classify_runtime_ingress_result(Ok("accepted-hash".into())),
            RuntimeIngressDisposition::Persist("accepted-hash".into())
        );
        assert_eq!(
            classify_runtime_ingress_result(Err(
                blocksync::RuntimeBlockApplyError::LocalBootstrapInput("missing witness".into())
            )),
            RuntimeIngressDisposition::LocalFailure("missing witness".into())
        );
        assert_eq!(
            classify_runtime_ingress_result(Err(
                blocksync::RuntimeBlockApplyError::ConsensusTransition("invalid header".into())
            )),
            RuntimeIngressDisposition::ConsensusReject(
                "CONSENSUS_TRANSITION: invalid header".into()
            )
        );
    }

    #[test]
    fn hotfix1_ordinary_devnet_accepts_and_mainnet_rejects_same_block() {
        let dir = c1c_temp_dir("hotfix1-devnet-ordinary");
        init_devnet(&dir, 1, true).unwrap();
        let mut parent = load_state(&dir).unwrap();
        for epoch in ACTIVATION_DELAY_EPOCHS..ACTIVATION_DELAY_EPOCHS + 128 {
            mine_epoch(&mut parent, epoch).unwrap();
            if parent.height == 1 {
                break;
            }
        }
        assert_eq!(parent.height, 1);
        let mut produced = parent.clone();
        for epoch in parent.tip_epoch + 1..parent.tip_epoch + 129 {
            mine_epoch(&mut produced, epoch).unwrap();
            if produced.height == 2 {
                break;
            }
        }
        assert_eq!(produced.height, 2);
        let payload = blocksync::encode_block_payload(produced.blocks.last().unwrap()).unwrap();
        let (header, txs, ops) = blocksync::decode_block_payload(&payload).unwrap();
        let mut direct = parent.clone();
        blocksync::validate_and_apply_block(&mut direct, header, txs.clone(), ops.clone()).unwrap();
        let mut routed = parent.clone();
        let devnet = RuntimeIngressContext {
            runtime: RuntimeNetwork::Devnet,
            bootstrap_witness: None,
        };
        blocksync::validate_and_apply_announced_block(
            &mut routed,
            header,
            txs.clone(),
            ops.clone(),
            &devnet,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&routed).unwrap(),
            serde_json::to_vec(&direct).unwrap()
        );
        let mainnet = hotfix1_ingress(None);
        let before = serde_json::to_vec(&parent).unwrap();
        assert!(matches!(
            blocksync::validate_and_apply_announced_block(
                &mut parent,
                header,
                txs.clone(),
                ops.clone(),
                &mainnet
            ),
            Err(blocksync::RuntimeBlockApplyError::ConsensusTransition(_))
        ));
        assert_eq!(serde_json::to_vec(&parent).unwrap(), before);
        let (mut mainnet_parent, _) = ordinary_mainnet_synthetic_parent();
        let mainnet_before = serde_json::to_vec(&mainnet_parent).unwrap();
        assert!(matches!(
            blocksync::validate_and_apply_announced_block(
                &mut mainnet_parent,
                header,
                txs,
                ops,
                &mainnet
            ),
            Err(blocksync::RuntimeBlockApplyError::ConsensusTransition(_))
        ));
        assert_eq!(serde_json::to_vec(&mainnet_parent).unwrap(), mainnet_before);
        fs::remove_dir_all(dir).unwrap();
    }

    fn c1c_witness_provider() -> mainnet_bootstrap::BootstrapWitnessProvider {
        mainnet_bootstrap::BootstrapWitnessProvider::new(
            std::env::var_os("MUTINY_MAINNET_BOOTSTRAP_WITNESS")
                .expect("set MUTINY_MAINNET_BOOTSTRAP_WITNESS for C1C validation"),
        )
    }

    fn hotfix1_ingress(
        witness: Option<mainnet_bootstrap::BootstrapWitnessProvider>,
    ) -> RuntimeIngressContext {
        RuntimeIngressContext {
            runtime: RuntimeNetwork::Mainnet,
            bootstrap_witness: witness,
        }
    }

    #[test]
    fn hotfix1_announced_mainnet_block1_classifies_and_retries_atomically() {
        let dir = c1c_temp_dir("hotfix1-announced");
        init_mainnet_genesis(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let provider = c1c_witness_provider();
        let decoded = provider.load().unwrap().decode().unwrap();
        let expected =
            mainnet_bootstrap::build_staged_mainnet_block1_transition(&state, &decoded).unwrap();
        let before = serde_json::to_vec(&state).unwrap();
        let missing = hotfix1_ingress(None);
        let error = blocksync::validate_and_apply_announced_block(
            &mut state,
            expected.header,
            expected.transactions.clone(),
            expected.operations.clone(),
            &missing,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            blocksync::RuntimeBlockApplyError::LocalBootstrapInput(_)
        ));
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        let valid = hotfix1_ingress(Some(provider));
        let hash = blocksync::validate_and_apply_announced_block(
            &mut state,
            expected.header,
            expected.transactions,
            expected.operations,
            &valid,
        )
        .unwrap();
        assert_eq!(hash, expected.state.tip_hash);
        assert_eq!(
            serde_json::to_vec(&state).unwrap(),
            serde_json::to_vec(&expected.state).unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hotfix1_announced_mainnet_invalid_block_is_consensus_and_atomic() {
        let dir = c1c_temp_dir("hotfix1-invalid");
        init_mainnet_genesis(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let provider = c1c_witness_provider();
        let decoded = provider.load().unwrap().decode().unwrap();
        let expected =
            mainnet_bootstrap::build_staged_mainnet_block1_transition(&state, &decoded).unwrap();
        let before = serde_json::to_vec(&state).unwrap();
        let mut header = expected.header;
        header[46] ^= 1;
        let error = blocksync::validate_and_apply_announced_block(
            &mut state,
            header,
            expected.transactions,
            expected.operations,
            &hotfix1_ingress(Some(provider)),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            blocksync::RuntimeBlockApplyError::ConsensusTransition(_)
        ));
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn c1c_mainnet_route_stages_c1b_and_commits_only_after_received_block_matches() {
        let dir = c1c_temp_dir("route");
        init_mainnet_genesis(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        validate_runtime_tuple(&state, RuntimeNetwork::Mainnet).unwrap();
        let provider = c1c_witness_provider();
        let decoded = provider.load().unwrap().decode().unwrap();
        let expected =
            mainnet_bootstrap::build_staged_mainnet_block1_transition(&state, &decoded).unwrap();
        let before = state.clone();
        let mut malformed = expected.header;
        malformed[46] ^= 1;
        let error = blocksync::validate_and_apply_block_for_runtime(
            &mut state,
            malformed,
            expected.transactions.clone(),
            expected.operations.clone(),
            RuntimeNetwork::Mainnet,
            Some(&provider),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            blocksync::RuntimeBlockApplyError::ConsensusTransition(_)
        ));
        assert_eq!(state.height, before.height);
        assert_eq!(state.tip_hash, before.tip_hash);
        let accepted = blocksync::validate_and_apply_block_for_runtime(
            &mut state,
            expected.header,
            expected.transactions.clone(),
            expected.operations.clone(),
            RuntimeNetwork::Mainnet,
            Some(&provider),
        )
        .unwrap();
        assert_eq!(accepted, expected.state.tip_hash);
        assert_eq!(state.height, 1);
        assert_eq!(
            serde_json::to_vec(&state).unwrap(),
            serde_json::to_vec(&expected.state).unwrap()
        );
        save_state(&dir, &state).unwrap();
        let cold_loaded = load_state(&dir).unwrap();
        assert_eq!(cold_loaded.height, 1);
        assert_eq!(cold_loaded.network_id, MAINNET_NETWORK_ID);
        assert!(matches!(
            blocksync::verify_full_replay_for_runtime(&cold_loaded, RuntimeNetwork::Mainnet, None),
            Err(blocksync::RuntimeBlockApplyError::LocalBootstrapInput(_))
        ));
        blocksync::verify_full_replay_for_runtime(
            &cold_loaded,
            RuntimeNetwork::Mainnet,
            Some(&provider),
        )
        .unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn c1c_mainnet_witness_failures_are_local_and_leave_state_unchanged() {
        let dir = c1c_temp_dir("local-input");
        init_mainnet_genesis(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        let original = state.clone();
        let error = blocksync::validate_and_apply_block_for_runtime(
            &mut state,
            [0u8; 272],
            Vec::new(),
            Vec::new(),
            RuntimeNetwork::Mainnet,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            blocksync::RuntimeBlockApplyError::LocalBootstrapInput(_)
        ));
        assert_eq!(
            serde_json::to_vec(&state).unwrap(),
            serde_json::to_vec(&original).unwrap()
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod c1c_runtime_closure_tests {
    use super::*;

    fn dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("mutiny-c1c-closure-{label}-{}", std::process::id()))
    }

    #[test]
    fn c1c_network_selection_is_explicit_and_testnet_is_closed() {
        assert_eq!(
            RuntimeNetwork::from_cli(None).unwrap(),
            RuntimeNetwork::Devnet
        );
        assert_eq!(
            RuntimeNetwork::from_cli(Some("mainnet")).unwrap(),
            RuntimeNetwork::Mainnet
        );
        assert!(RuntimeNetwork::from_cli(Some("testnet")).is_err());
        assert!(RuntimeNetwork::from_cli(Some("other")).is_err());
    }

    #[test]
    fn c1c_storage_tuples_bind_selected_network_and_reject_cross_network() {
        let dev_dir = dir("dev");
        let main_dir = dir("main");
        init_build54_genesis_devnet(&dev_dir, 1, true).unwrap();
        init_mainnet_genesis(&main_dir, 1, true).unwrap();
        let dev = load_state(&dev_dir).unwrap();
        let main = load_state(&main_dir).unwrap();
        let dev_meta = storage::inspect_meta(&dev_dir).unwrap().unwrap();
        let main_meta = storage::inspect_meta(&main_dir).unwrap().unwrap();
        validate_storage_meta_for_runtime(&dev, &dev_meta, RuntimeNetwork::Devnet).unwrap();
        validate_storage_meta_for_runtime(&main, &main_meta, RuntimeNetwork::Mainnet).unwrap();
        assert!(
            validate_storage_meta_for_runtime(&dev, &dev_meta, RuntimeNetwork::Mainnet).is_err()
        );
        assert!(
            validate_storage_meta_for_runtime(&main, &main_meta, RuntimeNetwork::Devnet).is_err()
        );
        let mut wrong_genesis = main.clone();
        wrong_genesis.genesis_hash = DEVNET_GENESIS_ID_HEX.to_string();
        assert!(validate_storage_meta_for_runtime(
            &wrong_genesis,
            &main_meta,
            RuntimeNetwork::Mainnet
        )
        .is_err());
        let _ = fs::remove_dir_all(&dev_dir);
        let _ = fs::remove_dir_all(&main_dir);
    }

    #[test]
    fn c1c_witness_provider_errors_are_local_and_side_effect_free() {
        let base = dir("witness");
        fs::create_dir_all(&base).unwrap();
        let missing = mainnet_bootstrap::BootstrapWitnessProvider::new(base.join("missing"));
        assert!(matches!(
            missing.load(),
            Err(mainnet_bootstrap::BootstrapInputError::Missing(_))
        ));
        let directory = mainnet_bootstrap::BootstrapWitnessProvider::new(&base);
        assert!(matches!(
            directory.load(),
            Err(mainnet_bootstrap::BootstrapInputError::Missing(_))
        ));
        let short = base.join("short.bin");
        fs::write(&short, [0u8; 4]).unwrap();
        assert!(matches!(
            mainnet_bootstrap::BootstrapWitnessProvider::new(&short).load(),
            Err(mainnet_bootstrap::BootstrapInputError::WrongLength(4))
        ));
        let wrong_hash = base.join("wrong-hash.bin");
        fs::write(
            &wrong_hash,
            vec![0u8; mainnet_bootstrap::MAINNET_BOOTSTRAP_WITNESS_LEN],
        )
        .unwrap();
        assert!(matches!(
            mainnet_bootstrap::BootstrapWitnessProvider::new(&wrong_hash).load(),
            Err(mainnet_bootstrap::BootstrapInputError::WrongHash)
        ));
        let _ = fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod pack_m_candidate2_runtime_integration_tests {
    use super::*;

    const PACK_M_HEADER_1: &str =
        "01000000fba9fcccdcbc07db8a1e1166cc84a386ca5ed154ee2824bc2b6e80150521d75d5033651fbfd182bc9fe3f587494ef41d6cf7d9e83e1dfbab6a5ce8160fae391e58d4496bffff7f2000000000";

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "mutiny-build66a-candidate2-runtime-replay-{}",
            std::process::id()
        ))
    }

    #[test]
    fn build66a_candidate2_header_state_is_persistent_rooted_and_full_replay_exact() {
        let dir = temp_dir();
        let _ = fs::remove_dir_all(&dir);
        init_build54_genesis_devnet(&dir, 1, true).unwrap();
        let mut state = load_state(&dir).unwrap();
        bootstrap::apply_devnet_bootstrap_block(&mut state).unwrap();

        let raw: [u8; 80] = hex::decode(PACK_M_HEADER_1).unwrap().try_into().unwrap();
        let op = mutiny_protocol::BitcoinHeadersV1 {
            network_id: DEVNET_NETWORK_ID,
            genesis_id: decode32(&state.genesis_hash).unwrap(),
            headers: vec![raw],
        }
        .to_operation()
        .unwrap();

        state
            .pending_protocol_operations
            .push(PendingProtocolOperationState {
                operation: hex::encode(op.encode()),
                required_txid: String::new(),
            });

        let starting_height = state.height;
        for _ in 0..512 {
            let epoch = next_mineable_epoch(&state);
            mine_epoch(&mut state, epoch).unwrap();
            if state.height > starting_height {
                break;
            }
        }
        assert!(
            state.height > starting_height,
            "failed to mine a block carrying BITCOIN_HEADERS"
        );
        assert_eq!(state.bitcoin_headers.len(), 1);
        assert!(state.bitcoin_best_chain.is_some());
        bitcoin_headers::check_state(&state).unwrap();

        let committed_root = state.current_state_root.clone();
        assert_eq!(
            state.blocks.last().unwrap().state_root,
            committed_root,
            "accepted block StateRoot must equal committed current StateRoot"
        );
        let mut recomputed = state.clone();
        refresh_current_state_root(&mut recomputed).unwrap();
        assert_eq!(
            recomputed.current_state_root, committed_root,
            "committed DevnetState must reproduce its accepted block StateRoot"
        );

        save_state(&dir, &state).unwrap();
        let loaded = load_state(&dir).unwrap();
        assert_eq!(loaded.current_state_root, committed_root);
        assert_eq!(loaded.bitcoin_headers, state.bitcoin_headers);
        assert_eq!(loaded.bitcoin_best_chain, state.bitcoin_best_chain);
        blocksync::verify_full_replay(&loaded).unwrap();

        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod hotfix1_release_tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    #[ignore = "requires a release executable and fresh identity proof directory"]
    fn build69_release_help_and_mainnet_identity_are_current() {
        let exe =
            PathBuf::from(env::var_os("MUTINY_HOTFIX1_RELEASE_EXE").expect("release executable"));
        let evidence = PathBuf::from(
            env::var_os("MUTINY_BUILD69_IDENTITY_PROOF_DIR")
                .expect("fresh identity proof directory"),
        );
        fs::create_dir(&evidence).expect("identity evidence must be fresh");
        let working = evidence.join("empty-help-working-directory");
        fs::create_dir(&working).unwrap();
        let help_out = evidence.join("help.stdout.log");
        let help_err = evidence.join("help.stderr.log");
        let child = Command::new(&exe)
            .current_dir(&working)
            .arg("--help")
            .stdin(Stdio::null())
            .stdout(Stdio::from(fs::File::create(&help_out).unwrap()))
            .stderr(Stdio::from(fs::File::create(&help_err).unwrap()))
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut child = EvidenceChild {
            child,
            exit_path: evidence.join("help.exit-code.txt"),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "help did not exit");
            std::thread::sleep(Duration::from_millis(20));
        };
        record_exit_status(&evidence.join("help.exit-code.txt"), &status).unwrap();
        assert!(status.success(), "help must exit successfully");
        assert!(
            child.try_wait().unwrap().is_some(),
            "help process remains live"
        );
        assert_eq!(
            fs::read_dir(&working).unwrap().count(),
            0,
            "help created runtime state"
        );
        fs::write(
            evidence.join("help-process.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "pid": pid, "reaped": true, "working_directory_entries": 0
            }))
            .unwrap(),
        )
        .unwrap();
        let help = fs::read_to_string(&help_out).expect("help must be valid UTF-8");
        assert!(fs::read(&help_err).unwrap().is_empty());
        assert!(help.contains("Mutiny Protocol V1.0 Build 7.0 Candidate 1"));

        // Local isolated Genesis state exercises the actual Mainnet print_banner path.
        // Native-host acceptance runs help only and initializes no state.
        let mainnet = evidence.join("mainnet-runtime");
        command(
            &exe,
            &[
                "init",
                "--network",
                "mainnet",
                "--data-dir",
                mainnet.to_str().unwrap(),
                "--epoch-ms",
                "50",
            ],
            &evidence,
            "mainnet-init",
        );
        command(
            &exe,
            &[
                "status",
                "--network",
                "mainnet",
                "--data-dir",
                mainnet.to_str().unwrap(),
            ],
            &evidence,
            "mainnet-status",
        );
        let mainnet_output =
            fs::read_to_string(evidence.join("mainnet-status.stdout.log")).unwrap();
        assert!(
            mainnet_output.contains("Mutiny Protocol V1.0 Build 7.0 Candidate 1 - Mainnet runtime")
        );
        for output in [&help, &mainnet_output] {
            // Intentional negative fixtures for older release identities.
            for stale in [
                "Build 6.3 Candidate",
                "Build 6.7 Candidate",
                "Build 6.8 Candidate",
                "Build 6.9 Candidate",
            ] {
                assert!(!output.contains(stale), "stale runtime identity: {stale}");
            }
            for marker in ['\u{00c3}', '\u{00c2}', '\u{00e2}', '\u{fffd}'] {
                assert!(!output.contains(marker), "malformed runtime output");
            }
        }
        fs::write(
            evidence.join("PASS.txt"),
            "BUILD70_RELEASE_IDENTITY_AND_HELP_NO_STATE_PASS",
        )
        .unwrap();
    }

    fn record_exit_status(path: &Path, status: &std::process::ExitStatus) -> std::io::Result<()> {
        #[cfg(unix)]
        let (signal, core_dumped) = {
            use std::os::unix::process::ExitStatusExt;
            (status.signal(), Some(status.core_dumped()))
        };
        #[cfg(not(unix))]
        let (signal, core_dumped): (Option<i32>, Option<bool>) = (None, None);
        let text = status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| {
                signal
                    .map(|signal| format!("SIGNAL:{signal}"))
                    .unwrap_or_else(|| "NO_NATIVE_EXIT_CODE".into())
            });
        fs::write(path, text)?;
        let details = serde_json::json!({
            "success": status.success(),
            "exit_code": status.code(),
            "signal": signal,
            "core_dumped": core_dumped,
        });
        fs::write(
            path.with_extension("json"),
            serde_json::to_vec_pretty(&details).expect("serialize test exit status"),
        )
    }

    #[cfg(unix)]
    fn expected_abort_signal(evidence: &Path) -> i32 {
        use std::os::unix::process::ExitStatusExt;
        static SIGNAL: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
        *SIGNAL.get_or_init(|| {
            // Observe the standard-library abort on this host, without a hard-coded signal
            // number or another dependency. The probe exits before any lifecycle setup.
            let output = Command::new(env::current_exe().expect("current lifecycle test binary"))
                .current_dir(evidence)
                .args([
                    "--exact",
                    "hotfix1_release_tests::hotfix1_real_release_authenticated_ingress_matrix",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("MUTINY_TEST_ABORT_SIGNAL_PROBE", "1")
                .output()
                .expect("launch isolated abort reference");
            fs::write(evidence.join("abort-reference.stdout.log"), &output.stdout).unwrap();
            fs::write(evidence.join("abort-reference.stderr.log"), &output.stderr).unwrap();
            record_exit_status(
                &evidence.join("abort-reference.exit-code.txt"),
                &output.status,
            )
            .unwrap();
            assert!(
                !output.status.success(),
                "abort reference exited successfully"
            );
            assert!(String::from_utf8_lossy(&output.stderr)
                .lines()
                .any(|line| line == "TEST_ONLY_STD_ABORT_SIGNAL_REFERENCE"));
            output
                .status
                .signal()
                .expect("abort reference must terminate by Unix signal")
        })
    }

    struct EvidenceChild {
        child: std::process::Child,
        exit_path: PathBuf,
    }
    impl std::ops::Deref for EvidenceChild {
        type Target = std::process::Child;
        fn deref(&self) -> &Self::Target {
            &self.child
        }
    }
    impl std::ops::DerefMut for EvidenceChild {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.child
        }
    }
    impl Drop for EvidenceChild {
        fn drop(&mut self) {
            if matches!(self.child.try_wait(), Ok(None)) {
                let _ = self.child.kill();
            }
            if let Ok(status) = self.child.wait() {
                let _ = record_exit_status(&self.exit_path, &status);
            }
        }
    }

    fn command(exe: &Path, args: &[&str], dir: &Path, label: &str) {
        let output = Command::new(exe)
            .current_dir(exe.parent().unwrap())
            .args(args)
            .output()
            .unwrap();
        fs::write(dir.join(format!("{label}.stdout.log")), &output.stdout).unwrap();
        fs::write(dir.join(format!("{label}.stderr.log")), &output.stderr).unwrap();
        record_exit_status(&dir.join(format!("{label}.exit-code.txt")), &output.status).unwrap();
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn initialize(exe: &Path, dir: &Path, pass: &Path) {
        fs::create_dir(dir).unwrap();
        command(
            exe,
            &[
                "init",
                "--network",
                "mainnet",
                "--data-dir",
                dir.to_str().unwrap(),
                "--epoch-ms",
                "50",
            ],
            dir,
            "init",
        );
        command(
            exe,
            &[
                "node-key-init",
                "--network",
                "mainnet",
                "--data-dir",
                dir.to_str().unwrap(),
                "--passphrase-file",
                pass.to_str().unwrap(),
            ],
            dir,
            "node-key-init",
        );
    }

    fn announced_process(
        exe: &Path,
        dir: &Path,
        pass: &Path,
        witness: Option<&Path>,
        header: [u8; 272],
        txs: &[TransactionV1],
        ops: &[ProtocolOperationV1],
        legacy: bool,
        label: &str,
    ) -> Vec<String> {
        let genesis = load_state(dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let stdout = fs::File::create(dir.join(format!("{label}.stdout.log"))).unwrap();
        let stderr = fs::File::create(dir.join(format!("{label}.stderr.log"))).unwrap();
        let mut cmd = Command::new(exe);
        cmd.current_dir(exe.parent().unwrap());
        if let Some(stage) = label.strip_prefix("crash-") {
            cmd.env("MUTINY_DEV_STORAGE_CRASH_AFTER", stage);
        }
        cmd.args([
            "node",
            "--network",
            "mainnet",
            "--data-dir",
            dir.to_str().unwrap(),
            "--listen",
            &address.to_string(),
            "--node-passphrase-file",
            pass.to_str().unwrap(),
            "--max-rounds",
            "200",
        ]);
        if let Some(witness) = witness {
            cmd.args(["--bootstrap-witness", witness.to_str().unwrap()]);
        }
        let mut child = EvidenceChild {
            child: cmd
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .spawn()
                .unwrap(),
            exit_path: dir.join(format!("{label}.exit-code.txt")),
        };
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut stream = loop {
            if let Ok(stream) = TcpStream::connect(address) {
                break stream;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("{label} node exited before listen: {status}");
            }
            assert!(Instant::now() < deadline, "{label}: listener timeout");
            thread::sleep(Duration::from_millis(25));
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let key = SigningKey::from_bytes(&[0x59; 32]);
        let magic = RuntimeNetwork::Mainnet.p2p_magic();
        initiator_handshake(
            &mut stream,
            &key,
            CAP_BUILD45_NODE,
            MAINNET_NETWORK_ID,
            magic,
        )
        .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let request_id = if legacy { 7 } else { 0 };
        Frame::new(
            magic,
            MSG_BLOCK_ANNOUNCE,
            request_id,
            block_hash(&header).0.to_vec(),
        )
        .unwrap()
        .write_to(&mut stream)
        .unwrap();

        // Payload encoding is specified by the existing production decoder.
        let mut payload = header.to_vec();
        write_varuint(&mut payload, txs.len() as u64);
        for tx in txs {
            let bytes = tx.encode_full();
            payload.extend_from_slice(&bytes);
        }
        write_varuint(&mut payload, ops.len() as u64);
        for op in ops {
            let bytes = op.encode();
            payload.extend_from_slice(&bytes);
        }
        let mut fetched = false;
        let mut last_announce = Instant::now();
        let mut results = Vec::new();
        while Instant::now() < deadline {
            match Frame::read_from(&mut stream, magic) {
                Ok(frame) => {
                    let response = match frame.message_type {
                        MSG_GET_BLOCK => {
                            assert_eq!(frame.payload, block_hash(&header).0);
                            fetched = true;
                            Some((MSG_BLOCK, payload.clone()))
                        }
                        MSG_GET_HEADERS => Some((
                            MSG_HEADERS,
                            blocksync::serve_get_headers(&genesis, &frame.payload).unwrap(),
                        )),
                        MSG_PING => Some((MSG_PONG, frame.payload.clone())),
                        MSG_GET_ADDR => Some((
                            MSG_ADDR,
                            encode_peer_addresses(&[], genesis.tip_epoch).unwrap(),
                        )),
                        MSG_DEVNET_BLOCK_RESULT => {
                            results.push(String::from_utf8(frame.payload).unwrap());
                            None
                        }
                        MSG_ADDR | MSG_TX_ANNOUNCE | MSG_BLOCK_ANNOUNCE => None,
                        other => panic!("unexpected peer message {other}"),
                    };
                    if let Some((kind, bytes)) = response {
                        if Frame::new(magic, kind, frame.request_id, bytes)
                            .unwrap()
                            .write_to(&mut stream)
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                Err(P2pError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => break,
            }
            if !legacy && !fetched && last_announce.elapsed() >= Duration::from_secs(1) {
                Frame::new(magic, MSG_BLOCK_ANNOUNCE, 0, block_hash(&header).0.to_vec())
                    .unwrap()
                    .write_to(&mut stream)
                    .unwrap();
                last_announce = Instant::now();
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
        }
        drop(stream);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                panic!("{label}: node process deadline exceeded");
            }
            thread::sleep(Duration::from_millis(25));
        };
        record_exit_status(&dir.join(format!("{label}.exit-code.txt")), &status).unwrap();
        fs::write(
            dir.join(format!("{label}.peer-results.json")),
            serde_json::to_vec(&results).unwrap(),
        )
        .unwrap();
        if let Some(stage) = label.strip_prefix("crash-") {
            assert!(!status.success(), "{label}: expected native crash");
            assert!(fs::read_to_string(dir.join(format!("{label}.stderr.log")))
                .unwrap()
                .contains(&format!("aborting after {stage}")));
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.code(), None, "{label}: expected signal termination");
                assert_eq!(
                    status.signal(),
                    Some(expected_abort_signal(dir)),
                    "{label}: termination must match the observed standard-library abort",
                );
            }
            #[cfg(windows)]
            assert!(
                status.code().is_some(),
                "{label}: expected native abnormal exit code"
            );
        } else {
            assert!(status.success(), "{label}: node failed");
        }
        assert!(fetched, "{label}: actual GETBLOCK was not served");
        results
    }

    fn refused(exe: &Path, args: &[&str], evidence: &Path, label: &str) -> String {
        let output = Command::new(exe)
            .current_dir(exe.parent().unwrap())
            .args(args)
            .output()
            .unwrap();
        fs::write(evidence.join(format!("{label}.stdout.log")), &output.stdout).unwrap();
        fs::write(evidence.join(format!("{label}.stderr.log")), &output.stderr).unwrap();
        record_exit_status(
            &evidence.join(format!("{label}.exit-code.txt")),
            &output.status,
        )
        .unwrap();
        assert!(!output.status.success(), "{label}: expected failure");
        String::from_utf8(output.stderr).unwrap()
    }

    fn tree_bytes(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn walk(base: &Path, dir: &Path, out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                assert!(!entry.file_type().unwrap().is_symlink());
                if path.is_dir() {
                    walk(base, &path, out);
                } else {
                    out.insert(
                        path.strip_prefix(base).unwrap().to_path_buf(),
                        fs::read(path).unwrap(),
                    );
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(dir, dir, &mut out);
        out
    }

    fn copy_tree(root: &Path, from: &Path, to: &Path) {
        assert!(to.starts_with(root));
        fs::create_dir(to).unwrap();
        for (rel, bytes) in tree_bytes(from) {
            let path = to.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }

    fn lifecycle(
        exe: &Path,
        root: &Path,
        pass: &Path,
        witness: &Path,
        canonical: &mainnet_bootstrap::StagedMainnetBlock1Transition,
    ) {
        let dir = root.join("duplex");
        let text = dir.to_str().unwrap();
        let pass_text = pass.to_str().unwrap();
        let witness_text = witness.to_str().unwrap();
        let committed = tree_bytes(&dir.join("storage"));
        for i in 0..3 {
            command(
                exe,
                &[
                    "node",
                    "--network",
                    "mainnet",
                    "--data-dir",
                    text,
                    "--listen",
                    "127.0.0.1:0",
                    "--max-rounds",
                    "1",
                    "--node-passphrase-file",
                    pass_text,
                ],
                root,
                &format!("cold-restart-{i}"),
            );
            assert_eq!(tree_bytes(&dir.join("storage")), committed);
            assert_eq!(
                serde_json::to_vec(&load_state(&dir).unwrap()).unwrap(),
                serde_json::to_vec(&canonical.state).unwrap()
            );
        }
        command(
            exe,
            &[
                "check",
                "--network",
                "mainnet",
                "--data-dir",
                text,
                "--bootstrap-witness",
                witness_text,
            ],
            root,
            "full-replay",
        );
        let err = refused(
            exe,
            &["check", "--network", "mainnet", "--data-dir", text],
            root,
            "replay-no-witness",
        );
        assert!(err.contains("LOCAL_BOOTSTRAP_INPUT"));
        let mut bad_bytes = fs::read(witness).unwrap();
        bad_bytes[100] ^= 1;
        let wrong_hash = root.join("wrong-hash-witness.bin");
        fs::write(&wrong_hash, bad_bytes).unwrap();
        for (i, bad) in [
            root.join("wrong-witness.bin"),
            wrong_hash,
            root.join("absent-witness.bin"),
            root.to_path_buf(),
        ]
        .iter()
        .enumerate()
        {
            let err = refused(
                exe,
                &[
                    "check",
                    "--network",
                    "mainnet",
                    "--data-dir",
                    text,
                    "--bootstrap-witness",
                    bad.to_str().unwrap(),
                ],
                root,
                &format!("wrong-witness-{i}"),
            );
            assert!(err.contains("LOCAL_BOOTSTRAP_INPUT"));
            assert_eq!(tree_bytes(&dir.join("storage")), committed);
        }
        refused(
            exe,
            &[
                "node",
                "--network",
                "devnet",
                "--data-dir",
                text,
                "--max-rounds",
                "1",
                "--listen",
                "127.0.0.1:0",
                "--node-passphrase-file",
                pass_text,
            ],
            root,
            "mainnet-as-devnet",
        );
        assert_eq!(tree_bytes(&dir.join("storage")), committed);
        let dev = root.join("devnet");
        fs::create_dir(&dev).unwrap();
        let dt = dev.to_str().unwrap();
        command(
            exe,
            &[
                "init",
                "--network",
                "devnet",
                "--data-dir",
                dt,
                "--epoch-ms",
                "50",
            ],
            root,
            "devnet-init",
        );
        command(
            exe,
            &[
                "node-key-init",
                "--network",
                "devnet",
                "--data-dir",
                dt,
                "--passphrase-file",
                pass_text,
            ],
            root,
            "devnet-key",
        );
        for i in 0..2 {
            command(
                exe,
                &[
                    "node",
                    "--network",
                    "devnet",
                    "--data-dir",
                    dt,
                    "--listen",
                    "127.0.0.1:0",
                    "--max-rounds",
                    "1",
                    "--node-passphrase-file",
                    pass_text,
                ],
                root,
                &format!("devnet-restart-{i}"),
            );
        }
        command(
            exe,
            &["check", "--network", "devnet", "--data-dir", dt],
            root,
            "devnet-replay",
        );
        let dev_before = tree_bytes(&dev.join("storage"));
        refused(
            exe,
            &[
                "node",
                "--network",
                "mainnet",
                "--data-dir",
                dt,
                "--listen",
                "127.0.0.1:0",
                "--max-rounds",
                "1",
                "--node-passphrase-file",
                pass_text,
            ],
            root,
            "devnet-as-mainnet",
        );
        assert_eq!(tree_bytes(&dev.join("storage")), dev_before);
        let testnet = root.join("testnet-inactive");
        for cmd in ["init", "node", "status", "check"] {
            let e = refused(
                exe,
                &[
                    cmd,
                    "--network",
                    "testnet",
                    "--data-dir",
                    testnet.to_str().unwrap(),
                ],
                root,
                &format!("testnet-{cmd}"),
            );
            assert!(e.contains("Testnet is inactive"));
            assert!(!testnet.exists());
        }
        let corrupt = root.join("corrupt-snapshot");
        copy_tree(root, &dir, &corrupt);
        let meta = storage::inspect_meta(&corrupt).unwrap().unwrap();
        let path = corrupt
            .join("storage/state")
            .join(format!("generation-{:020}.mst", meta.generation));
        let mut bytes = fs::read(&path).unwrap();
        bytes[30] ^= 1;
        fs::write(&path, bytes).unwrap();
        let before = tree_bytes(&corrupt.join("storage"));
        refused(
            exe,
            &[
                "storage-verify",
                "--network",
                "mainnet",
                "--data-dir",
                corrupt.to_str().unwrap(),
                "--bootstrap-witness",
                witness_text,
            ],
            root,
            "corrupt-snapshot-refusal",
        );
        assert_eq!(tree_bytes(&corrupt.join("storage")), before);
        for stage in [
            "before-journal",
            "journal",
            "snapshot-tmp",
            "snapshot",
            "meta-tmp",
            "meta",
            "before-finalize",
            "finalize",
            "prune",
        ] {
            let crash = root.join(format!("crash-{stage}"));
            initialize(exe, &crash, pass);
            announced_process(
                exe,
                &crash,
                pass,
                Some(witness),
                canonical.header,
                &canonical.transactions,
                &canonical.operations,
                false,
                &format!("crash-{stage}"),
            );
            let before = tree_bytes(&crash.join("storage"));
            refused(
                exe,
                &[
                    "status",
                    "--network",
                    "devnet",
                    "--data-dir",
                    crash.to_str().unwrap(),
                ],
                root,
                &format!("crash-{stage}-wrong-network"),
            );
            assert_eq!(tree_bytes(&crash.join("storage")), before);
            if ["meta", "before-finalize"].contains(&stage) {
                for attempt in 0..2 {
                    let err = refused(
                        exe,
                        &[
                            "status",
                            "--network",
                            "mainnet",
                            "--data-dir",
                            crash.to_str().unwrap(),
                        ],
                        root,
                        &format!("crash-{stage}-missing-witness-{attempt}"),
                    );
                    assert!(err.contains("LOCAL_BOOTSTRAP_INPUT"));
                    assert_eq!(tree_bytes(&crash.join("storage")), before);
                }
            }
            command(
                exe,
                &[
                    "storage-verify",
                    "--network",
                    "mainnet",
                    "--data-dir",
                    crash.to_str().unwrap(),
                    "--bootstrap-witness",
                    witness_text,
                ],
                root,
                &format!("crash-{stage}-recover"),
            );
            let state = load_state(&crash).unwrap();
            let expected = if ["meta", "before-finalize", "finalize", "prune"].contains(&stage) {
                1
            } else {
                0
            };
            assert_eq!(state.height, expected);
            if expected == 1 {
                assert_eq!(
                    serde_json::to_vec(&state).unwrap(),
                    serde_json::to_vec(&canonical.state).unwrap()
                );
            }
            if expected == 0 {
                announced_process(
                    exe,
                    &crash,
                    pass,
                    Some(witness),
                    canonical.header,
                    &canonical.transactions,
                    &canonical.operations,
                    false,
                    "post-recovery-retry",
                );
                assert_eq!(
                    serde_json::to_vec(&load_state(&crash).unwrap()).unwrap(),
                    serde_json::to_vec(&canonical.state).unwrap()
                );
            }
            command(
                exe,
                &[
                    "status",
                    "--network",
                    "mainnet",
                    "--data-dir",
                    crash.to_str().unwrap(),
                ],
                root,
                &format!("crash-{stage}-cold"),
            );
        }
        fs::write(
            root.join("C1D-LIFECYCLE-PASS.txt"),
            b"C1D_LIFECYCLE_DETERMINISTIC_RUN_PASS",
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires an independently built release mutinyd and a fresh durable proof directory"]
    fn hotfix1_real_release_authenticated_ingress_matrix() {
        #[cfg(unix)]
        if env::var("MUTINY_TEST_ABORT_SIGNAL_PROBE").as_deref() == Ok("1") {
            eprintln!("TEST_ONLY_STD_ABORT_SIGNAL_REFERENCE");
            std::process::abort();
        }
        let exe =
            PathBuf::from(env::var_os("MUTINY_HOTFIX1_RELEASE_EXE").expect("release executable"));
        let root = PathBuf::from(
            env::var_os("MUTINY_HOTFIX1_RELEASE_PROOF_DIR").expect("fresh proof directory"),
        );
        fs::create_dir(&root).unwrap();
        let witness =
            PathBuf::from(env::var_os("MUTINY_MAINNET_BOOTSTRAP_WITNESS").expect("witness input"));
        let pass = root.join("synthetic-test-passphrase.private");
        fs::write(&pass, b"Mutiny synthetic integration test passphrase only").unwrap();
        let bad = root.join("wrong-witness.bin");
        fs::write(&bad, b"invalid test witness").unwrap();
        let template = root.join("template");
        initialize(&exe, &template, &pass);
        let genesis = load_state(&template).unwrap();
        let decoded = mainnet_bootstrap::BootstrapWitnessProvider::new(&witness)
            .load()
            .unwrap()
            .decode()
            .unwrap();
        let canonical =
            mainnet_bootstrap::build_staged_mainnet_block1_transition(&genesis, &decoded).unwrap();
        assert!(RuntimeNetwork::from_cli(Some("testnet")).is_err());
        for legacy in [false, true] {
            let tag = if legacy { "legacy" } else { "duplex" };
            let dir = root.join(tag);
            initialize(&exe, &dir, &pass);
            let before = serde_json::to_vec(&load_state(&dir).unwrap()).unwrap();
            let generation = storage::inspect_meta(&dir).unwrap().unwrap().generation;
            for (label, provider) in [("missing", None), ("bad", Some(bad.as_path()))] {
                let replies = announced_process(
                    &exe,
                    &dir,
                    &pass,
                    provider,
                    canonical.header,
                    &canonical.transactions,
                    &canonical.operations,
                    legacy,
                    label,
                );
                assert!(replies.iter().all(|s| !s.starts_with("REJECTED")));
                assert!(fs::read_to_string(dir.join(format!("{label}.stderr.log")))
                    .unwrap()
                    .contains("LOCAL_BOOTSTRAP_INPUT"));
                assert_eq!(
                    serde_json::to_vec(&load_state(&dir).unwrap()).unwrap(),
                    before
                );
                assert_eq!(
                    storage::inspect_meta(&dir).unwrap().unwrap().generation,
                    generation
                );
            }
            let mut invalid = canonical.header;
            invalid[46] ^= 1;
            let replies = announced_process(
                &exe,
                &dir,
                &pass,
                Some(&witness),
                invalid,
                &canonical.transactions,
                &canonical.operations,
                legacy,
                "invalid",
            );
            let stderr = fs::read_to_string(dir.join("invalid.stderr.log")).unwrap();
            assert!(
                replies
                    .iter()
                    .any(|s| s.starts_with("REJECTED CONSENSUS_TRANSITION"))
                    || stderr.contains("REJECTED CONSENSUS_TRANSITION")
            );
            assert!(!stderr.contains("LOCAL_BOOTSTRAP_INPUT"));
            assert_eq!(
                serde_json::to_vec(&load_state(&dir).unwrap()).unwrap(),
                before
            );
            assert_eq!(
                storage::inspect_meta(&dir).unwrap().unwrap().generation,
                generation
            );
            announced_process(
                &exe,
                &dir,
                &pass,
                Some(&witness),
                canonical.header,
                &canonical.transactions,
                &canonical.operations,
                legacy,
                "retry",
            );
            let after = load_state(&dir).unwrap();
            assert_eq!(after.height, 1);
            assert_eq!(
                serde_json::to_vec(&after).unwrap(),
                serde_json::to_vec(&canonical.state).unwrap()
            );
            assert_eq!(after.tip_hash, canonical.state.tip_hash);
            assert_eq!(after.current_state_root, canonical.state.current_state_root);
            assert_eq!(
                storage::inspect_meta(&dir).unwrap().unwrap().generation,
                generation + 1
            );
            command(
                &exe,
                &[
                    "status",
                    "--network",
                    "mainnet",
                    "--data-dir",
                    dir.to_str().unwrap(),
                ],
                &dir,
                "cold-status",
            );
            let mut live = after.clone();
            let err = blocksync::validate_and_apply_announced_block(
                &mut live,
                invalid,
                canonical.transactions.clone(),
                canonical.operations.clone(),
                &RuntimeIngressContext {
                    runtime: RuntimeNetwork::Mainnet,
                    bootstrap_witness: None,
                },
            )
            .unwrap_err();
            assert!(matches!(
                err,
                blocksync::RuntimeBlockApplyError::ConsensusTransition(_)
            ));
            assert_eq!(
                serde_json::to_vec(&live).unwrap(),
                serde_json::to_vec(&after).unwrap()
            );
        }
        if env::var_os("MUTINY_C1D_LIFECYCLE_PROOF").is_some() {
            lifecycle(&exe, &root, &pass, &witness, &canonical);
        }
        fs::write(
            root.join("PASS.txt"),
            b"REAL_AUTHENTICATED_RELEASE_INGRESS_MATRIX_PASS",
        )
        .unwrap();
    }
    #[test]
    #[ignore = "requires approved production custody, passed signer matrix and independently built release binary"]
    fn hotfix1_signed_mainnet_release_lifecycle() {
        let prerequisite = PathBuf::from(
            env::var_os("MUTINY_SIGNER_MATRIX_PASS").expect("signer matrix evidence"),
        );
        assert_eq!(
            fs::read_to_string(prerequisite).unwrap(),
            "SIGNER_FOCUSED_AND_PRODUCTION_AUTHENTICATION_PASS"
        );
        let exe =
            PathBuf::from(env::var_os("MUTINY_HOTFIX1_RELEASE_EXE").expect("release executable"));
        let root = PathBuf::from(
            env::var_os("MUTINY_SIGNED_RELEASE_PROOF_DIR").expect("fresh proof directory"),
        );
        fs::create_dir(&root).unwrap();
        let witness = PathBuf::from(
            env::var_os("MUTINY_MAINNET_BOOTSTRAP_WITNESS").expect("canonical witness"),
        );
        let pass = root.join("synthetic-node-passphrase.private");
        fs::write(&pass, b"Synthetic release node identity passphrase only").unwrap();
        let miner = root.join("miner");
        initialize(&exe, &miner, &pass);
        let genesis = load_state(&miner).unwrap();
        let decoded = mainnet_bootstrap::BootstrapWitnessProvider::new(&witness)
            .load()
            .unwrap()
            .decode()
            .unwrap();
        let canonical =
            mainnet_bootstrap::build_staged_mainnet_block1_transition(&genesis, &decoded).unwrap();
        let duplex = root.join("duplex");
        let legacy = root.join("legacy");
        initialize(&exe, &duplex, &pass);
        initialize(&exe, &legacy, &pass);
        for (dir, old) in [(&miner, false), (&duplex, false), (&legacy, true)] {
            announced_process(
                &exe,
                dir,
                &pass,
                Some(&witness),
                canonical.header,
                &canonical.transactions,
                &canonical.operations,
                old,
                "canonical-block1",
            );
            assert_eq!(load_state(dir).unwrap().height, 1);
        }
        let custody_path = PathBuf::from(
            env::var_os("MUTINY_PROOF_MINING_CUSTODY_DIR")
                .expect("explicit external mining custody directory"),
        );
        let secret_pass_path = PathBuf::from(
            env::var_os("MUTINY_PROOF_MINING_PASSPHRASE_FILE")
                .expect("explicit external mining passphrase file"),
        );
        let guard_path = PathBuf::from(
            env::var_os("MUTINY_PROOF_ANTI_EQUIVOCATION_DIR")
                .expect("existing external durable signer history"),
        );
        let custody = custody_path.to_str().unwrap();
        let secret_pass = secret_pass_path.to_str().unwrap();
        let guard = guard_path.to_str().unwrap();
        let id = "080139e853eee69fb808a09127596052cbbcc626a1aa9b7b52eea0a29911bde7";
        let expected = "fc91a3012dd25cf50331d3c3d77b3c255ea209095b07b117ad115d51352d8974";
        let state = load_state(&miner).unwrap();
        let li = state
            .licenses
            .iter()
            .position(|l| l.license_id == id)
            .unwrap();
        let number = (li + 1).to_string();
        let common = [
            "--network",
            "mainnet",
            "--data-dir",
            miner.to_str().unwrap(),
            "--mining-custody-dir",
            custody,
            "--mining-key-label",
            "license-01",
            "--wallet-passphrase-file",
            secret_pass,
            "--anti-equivocation-dir",
            guard,
            "--mining-license-id",
            id,
        ];
        let init = if Path::new(guard).join("authority.v1").exists() {
            "mining-signer-check"
        } else {
            "mining-signer-init"
        };
        let mut init_args = vec![init];
        init_args.extend_from_slice(&common);
        command(&exe, &init_args, &root, "production-signer-authentication");
        let mut facts = Vec::new();
        for wanted in 2..=4u64 {
            let parent = load_state(&miner).unwrap();
            let mut found = false;
            for epoch in next_mineable_epoch(&parent)..=next_mineable_epoch(&parent) + 1024 {
                let epoch_text = epoch.to_string();
                let mut args = vec!["wallet-mine-one"];
                args.extend_from_slice(&common);
                args.extend_from_slice(&["--license", &number, "--epoch", &epoch_text]);
                command(
                    &exe,
                    &args,
                    &root,
                    &format!("mine-height{wanted}-epoch{epoch}"),
                );
                if load_state(&miner).unwrap().height == wanted {
                    found = true;
                    break;
                }
            }
            assert!(
                found,
                "no winning candidate within bounded production search"
            );
            let accepted = load_state(&miner).unwrap();
            require_mainnet_canonical_tip(&accepted).unwrap();
            let block = accepted.blocks.last().unwrap();
            let payload = blocksync::encode_block_payload(block).unwrap();
            let (header, txs, ops) = blocksync::decode_block_payload(&payload).unwrap();
            assert_eq!(&header[2..6], &MAINNET_NETWORK_ID.to_be_bytes());
            assert_eq!(hex::encode(&header[142..174]), id);
            let core: [u8; 208] = header[..208].try_into().unwrap();
            let signature: [u8; 64] = header[208..].try_into().unwrap();
            ed25519_dalek::VerifyingKey::from_bytes(&decode32(expected).unwrap())
                .unwrap()
                .verify_strict(
                    &block_signing_digest(&core).0,
                    &ed25519_dalek::Signature::from_bytes(&signature),
                )
                .unwrap();
            fs::write(
                root.join(format!("canonical-block{wanted}.payload")),
                &payload,
            )
            .unwrap();
            for (dir, old) in [(&duplex, false), (&legacy, true)] {
                let replies = announced_process(
                    &exe,
                    dir,
                    &pass,
                    None,
                    header,
                    &txs,
                    &ops,
                    old,
                    &format!("signed-block{wanted}"),
                );
                assert!(replies.iter().all(|v| !v.starts_with("REJECTED")));
                let persisted = load_state(dir).unwrap();
                validate_runtime_tuple(&persisted, RuntimeNetwork::Mainnet).unwrap();
                assert_eq!(persisted.height, wanted);
                assert_eq!(persisted.tip_hash, accepted.tip_hash);
                assert_eq!(persisted.current_state_root, accepted.current_state_root);
            }
            facts.push(serde_json::json!({"height":wanted,"hash":accepted.tip_hash,"epoch":accepted.tip_epoch,"license_id":id,"mining_public_key":expected,"ticket_index":u16::from_be_bytes(header[174..176].try_into().unwrap()),"argon2_proof":hex::encode(&header[176..208]),"target":hex::encode(&header[110..142]),"duplex_ingress":"PASS","legacy_ingress":"PASS","bootstrap_witness_used":false}));
            fs::write(
                root.join("SIGNED-BLOCK-FACTS.json"),
                serde_json::to_vec_pretty(&facts).unwrap(),
            )
            .unwrap();
            if wanted == 3 {
                let public_history = fs::read_dir(guard)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .filter(|p| p.extension().is_some_and(|x| x == "authorization"))
                    .map(|p| {
                        let bytes = fs::read(&p).unwrap();
                        (p, bytes)
                    })
                    .collect::<Vec<_>>();
                assert!(public_history.len() >= 2);
                for dir in [&miner, &duplex, &legacy] {
                    command(
                        &exe,
                        &[
                            "node",
                            "--network",
                            "mainnet",
                            "--data-dir",
                            dir.to_str().unwrap(),
                            "--listen",
                            "127.0.0.1:0",
                            "--node-passphrase-file",
                            pass.to_str().unwrap(),
                            "--max-rounds",
                            "1",
                        ],
                        dir,
                        "cold-restart-height3-no-witness",
                    );
                    let cold = load_state(dir).unwrap();
                    assert_eq!(cold.height, 3);
                    assert_eq!(cold.tip_hash, accepted.tip_hash);
                    require_mainnet_canonical_tip(&cold).unwrap();
                }
                for (path, bytes) in public_history {
                    assert_eq!(fs::read(path).unwrap(), bytes);
                }
                let mut args = vec!["mining-signer-check"];
                args.extend_from_slice(&common);
                command(&exe, &args, &root, "signer-reopen-after-height3");
            }
        }
        fs::write(
            root.join("PASS.txt"),
            b"CANONICAL_SIGNED_MAINNET_BLOCK2_BLOCK3_COLD_RESTART_BLOCK4_BOTH_INGRESS_PASS",
        )
        .unwrap();
    }
}
