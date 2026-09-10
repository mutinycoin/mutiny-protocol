//! Proposed node-local decoder for the immutable Pack M Mainnet bootstrap witness.
//! This module intentionally performs no state transition, persistence, or runtime dispatch.
use mutiny_bitcoin::{
    canonical_manifest_script, display_hex_from_internal, median_time_past_11,
    merkle_root_from_branch, parse_transaction, validate_payment, BitcoinHeader, BitcoinSpvProofV1,
};
#[cfg(test)]
use mutiny_crypto::{domains, sha256_domain};
use mutiny_protocol::{
    bitcoin_payment_id, derive_license_id, protocol_operations_root, BitcoinHeadersV1,
    BootstrapManifestV1, ProtocolOperationV1, MAINNET_GENESIS_ID, MAINNET_NETWORK_ID,
    OP_BITCOIN_HEADERS, OP_BOOTSTRAP_COMMITMENT,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt, fs,
    path::{Path, PathBuf},
};

pub const MAINNET_BOOTSTRAP_WITNESS_LEN: usize = 161_323;
const WITNESS_SHA256: [u8; 32] = [
    0xb1, 0x15, 0xc1, 0x1c, 0xc8, 0xa4, 0x08, 0x5a, 0x5d, 0x95, 0x0b, 0xe6, 0x08, 0xc0, 0xe6, 0x44,
    0x8d, 0x9d, 0x38, 0x23, 0xd3, 0xab, 0x15, 0xfb, 0x43, 0x9d, 0x1f, 0xd2, 0x31, 0xaa, 0x61, 0x26,
];
const ANCHOR: [u8; 32] = [
    0x32, 0x2d, 0x83, 0x9f, 0x2a, 0x0d, 0x04, 0x63, 0x1b, 0x7b, 0x40, 0xdd, 0xa2, 0xa8, 0x5a, 0x45,
    0x5b, 0x7f, 0x32, 0x9a, 0x9d, 0x76, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const COUNTS: [usize; 8] = [256, 256, 256, 256, 256, 256, 256, 211];
const LENGTHS: [usize; 8] = [20518, 20518, 20518, 20518, 20518, 20518, 20518, 16918];
const BOOTSTRAP_MANIFEST_LEN: usize = 810;
const BOOTSTRAP_MANIFEST_HASH: [u8; 32] = [
    0x86, 0x5f, 0xec, 0xb5, 0xc0, 0x25, 0x62, 0xd2, 0x5d, 0x26, 0x27, 0x39, 0x80, 0x9c, 0x3e, 0xbe,
    0x51, 0xe5, 0xa1, 0x4d, 0x9e, 0x40, 0xbc, 0x0e, 0xcb, 0x1c, 0xa8, 0xcf, 0x04, 0x2a, 0xb4, 0xf9,
];
const BOOTSTRAP_PURCHASE_NONCE: [u8; 32] = [
    0xaa, 0xc9, 0xbf, 0x3a, 0xbb, 0xde, 0xaf, 0x0b, 0x7a, 0xeb, 0x79, 0xc1, 0x25, 0x62, 0x09, 0xa0,
    0x4c, 0xf9, 0x93, 0xf0, 0xa7, 0xd7, 0x31, 0x98, 0x68, 0x54, 0xd8, 0xf1, 0x00, 0x95, 0xb6, 0x54,
];
const BOOTSTRAP_OWNER_KEY_00: [u8; 32] = [
    0xd3, 0xe5, 0x29, 0x88, 0x9d, 0x94, 0xde, 0x51, 0x33, 0x0a, 0xdf, 0x3a, 0x79, 0x68, 0xf2, 0x88,
    0x49, 0xde, 0xa8, 0x85, 0xa7, 0x9f, 0xc2, 0xe0, 0xa5, 0xa4, 0xa9, 0xdd, 0xa5, 0x5e, 0xfc, 0xde,
];
const BOOTSTRAP_MINING_KEY_00: [u8; 32] = [
    0xfc, 0x91, 0xa3, 0x01, 0x2d, 0xd2, 0x5c, 0xf5, 0x03, 0x31, 0xd3, 0xc3, 0xd7, 0x7b, 0x3c, 0x25,
    0x5e, 0xa2, 0x09, 0x09, 0x5b, 0x07, 0xb1, 0x17, 0xad, 0x11, 0x5d, 0x51, 0x35, 0x2d, 0x89, 0x74,
];
const BOOTSTRAP_MANIFEST_HEX: &str = "00014d555401aac9bf3abbdeaf0b7aeb79c1256209a04cf993f0a7d731986854d8f10095b6540000000cd3e529889d94de51330adf3a7968f28849dea885a79fc2e0a5a4a9dda55efcdefc91a3012dd25cf50331d3c3d77b3c255ea209095b07b117ad115d51352d8974345de656ddae79b89e97ec812b521e2866f2c0d4c1d84e617c7376d1470979367ea66fdd17e333ab03144704ae68b9968683fcc4f5b4f48531fefd0bb732b70d5b8d2ab42c0f17387ac9680608781bdeca6c0202464f1384bddb4a335a15f1ff2e15743e8f7bda9aa3cd1aa806809930ab201423dddbd1f5b4f7bc9b86057ada332ea153bd45d385c59a3d0491bb6025b7cf387182cacb6ea1009c03e48cb11a0dc06aec03b111cb1e3bd32cefa355c47698d6c696076a222b37723729eb91e6cf20bd30214cb5f513636bf8825c39f75835b61969aefad67ac91363f0626fc2a3f7876f117d4360f756a6f5e58a46d067f4aa9b09be2cf4dae4e0877af89cba11049c7c3024c8357dbf03ef0159e8f879eafb1c32c4660a5a2bd4c8f9587002e81be95e1c4f9f5538f32950622079a13d728fdaa1bcf44a8dbcd9335a7598052a348c7259c88090506745915312ff82028f71a93d68d8d9656538197907cdca8d389abfa7b88537aea61c8811a1afabdf1e7b6ac35e5bab41e386d447c008167d633b658dcc9fa883c60b323f3e6caf68aeede33f4f67a364b2019a469f4bbfe93b38921607ea098f93fdb94429a46997c6ed30c0486a9811c8961437d04f119dba0b18785fb2f4d1dac98348557a78c8a1a2e80d76dd2aa68d840ee95bb7c9936569808932d7657cd622a6fb26465ebad2c38da7ce82346c070a63f3ae476acba9552674e58c0a7c97adec1c21e32ae5518bb7ab92e284ae07951147cbbdffdd3942103d6375ec635f10c0252b872376215bae1d57826e1efe24148b67350019a4c1f3646ce9eb00a857552c62564dfd3fffadf932eb47d92ff6aeaf9864ab48d7b3518a7f54b72f423621c1b4623ff8a596bd70b8531b035e7c08551e47b40cc24da4ef86a39f403e4fb7459a7cb2e6f8bdbc695534db98f1148267e8fb6fc08cd4e59b64f44ba991e4671d2890781c41ce51eb29729d63c89a13ddf1080c";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapInputError {
    Missing(PathBuf),
    Unreadable(PathBuf, String),
    WrongLength(usize),
    WrongHash,
    Decode(&'static str),
}

/// Consensus/transition failures are intentionally separate from local witness acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MainnetBootstrapTransitionError {
    BitcoinHeaderOperation(String),
    TerminalHeight,
    TerminalHash,
    FinalMtp,
    ContainingBlock,
    BitcoinTransaction,
    BitcoinTxid,
    BitcoinMerkleProof,
    PaymentOutput,
    PaymentAmount,
    TreasuryScript,
    ManifestOutput,
    ManifestValue,
    ManifestScript,
    BootstrapManifest,
    BootstrapManifestHash,
    BootstrapManifestInvariant,
    BitcoinPaymentId,
    AuthenticatedState,
    ExternalPaymentRoot,
    LicenseRoot,
    ProtocolStateRoot,
    MetaRoot,
    StateRoot,
    Commitment,
    Operation,
    Transaction,
    Target,
    Block,
    ReceivedBlock1,
    InternalInvariant,
}

/// Facts which have been independently checked before authenticated-state materialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMainnetBootstrapProof {
    pub accepted_header_count: usize,
    pub terminal_height: u32,
    pub terminal_hash_internal: [u8; 32],
    pub final_mtp: u32,
    pub containing_height: u32,
    pub txid_internal: [u8; 32],
    pub payment_output_index: u32,
    pub payment_amount_sats: u64,
    pub manifest_output_index: u32,
    pub merkle_transaction_index: u32,
    pub merkle_sibling_count: usize,
    pub manifest_hash: [u8; 32],
    pub license_count: usize,
    pub issued_epoch: u64,
    pub activation_epoch: u64,
    pub bitcoin_payment_id: [u8; 32],
    pub external_payment_root: [u8; 32],
    pub license_root: [u8; 32],
    pub protocol_state_root: [u8; 32],
    pub meta_root: [u8; 32],
    pub state_root: [u8; 32],
}

/// Fully constructed, non-persisted result.  The live caller remains unchanged
/// until a future explicitly-authorized runtime integration chooses to commit it.
pub(super) struct StagedMainnetBlock1Transition {
    pub(super) state: super::DevnetState,
    pub(super) proof: ValidatedMainnetBootstrapProof,
    pub(super) header: [u8; 272],
    pub(super) transactions: Vec<super::TransactionV1>,
    pub(super) operations: Vec<ProtocolOperationV1>,
}

/// Verifies the complete received Block-1 body against the independently
/// constructed staged transition without committing either result.
pub(super) fn compare_received_mainnet_block1(
    expected: &StagedMainnetBlock1Transition,
    received_header: &[u8; 272],
    received_transactions: &[super::TransactionV1],
    received_operations: &[ProtocolOperationV1],
) -> Result<(), MainnetBootstrapTransitionError> {
    if received_header != &expected.header
        || received_header[0..2] != expected.header[0..2]
        || received_header[2..6] != expected.header[2..6]
        || received_header[6..14] != expected.header[6..14]
        || received_header[14..46] != expected.header[14..46]
        || received_header[46..78] != expected.header[46..78]
        || received_header[78..110] != expected.header[78..110]
        || received_header[110..142] != expected.header[110..142]
        || received_header[142..174] != expected.header[142..174]
        || received_header[174..176] != expected.header[174..176]
        || received_header[176..208] != expected.header[176..208]
        || received_header[208..272] != expected.header[208..272]
    {
        return Err(MainnetBootstrapTransitionError::ReceivedBlock1);
    }
    let expected_transactions = expected
        .transactions
        .iter()
        .map(super::TransactionV1::encode_full)
        .collect::<Vec<_>>();
    let actual_transactions = received_transactions
        .iter()
        .map(super::TransactionV1::encode_full)
        .collect::<Vec<_>>();
    let expected_operations = expected
        .operations
        .iter()
        .map(ProtocolOperationV1::encode)
        .collect::<Vec<_>>();
    let actual_operations = received_operations
        .iter()
        .map(ProtocolOperationV1::encode)
        .collect::<Vec<_>>();
    if actual_transactions != expected_transactions || actual_operations != expected_operations {
        return Err(MainnetBootstrapTransitionError::ReceivedBlock1);
    }
    Ok(())
}

fn canonical_mainnet_bootstrap_manifest(
) -> Result<BootstrapManifestV1, MainnetBootstrapTransitionError> {
    let bytes = hex::decode(BOOTSTRAP_MANIFEST_HEX)
        .map_err(|_| MainnetBootstrapTransitionError::BootstrapManifest)?;
    if bytes.len() != BOOTSTRAP_MANIFEST_LEN {
        return Err(MainnetBootstrapTransitionError::BootstrapManifestInvariant);
    }
    let manifest = BootstrapManifestV1::decode(&bytes)
        .map_err(|_| MainnetBootstrapTransitionError::BootstrapManifest)?;
    if manifest.purchase_nonce != BOOTSTRAP_PURCHASE_NONCE || manifest.licenses.len() != 12 {
        return Err(MainnetBootstrapTransitionError::BootstrapManifestInvariant);
    }
    if manifest
        .manifest_hash()
        .map_err(|_| MainnetBootstrapTransitionError::BootstrapManifest)?
        .0
        != BOOTSTRAP_MANIFEST_HASH
    {
        return Err(MainnetBootstrapTransitionError::BootstrapManifestHash);
    }
    Ok(manifest)
}

fn stage_mainnet_bitcoin_headers(
    state: &mut super::DevnetState,
    witness: &DecodedMainnetBootstrapWitness,
) -> Result<(), MainnetBootstrapTransitionError> {
    if witness.batches.len() != 8
        || witness
            .batches
            .iter()
            .map(|batch| batch.headers.len())
            .sum::<usize>()
            != 2_003
    {
        return Err(MainnetBootstrapTransitionError::BitcoinHeaderOperation(
            "locked bootstrap must contain exactly eight batches / 2003 headers".into(),
        ));
    }
    for batch in &witness.batches {
        let payload = batch
            .payload()
            .map_err(|e| MainnetBootstrapTransitionError::BitcoinHeaderOperation(e.to_string()))?;
        let operation = ProtocolOperationV1 {
            op_type: OP_BITCOIN_HEADERS,
            op_version: 1,
            payload,
        };
        super::bitcoin_headers::apply_operation(state, &operation, 10)
            .map_err(MainnetBootstrapTransitionError::BitcoinHeaderOperation)?;
    }
    Ok(())
}

fn staged_terminal_chain(
    state: &super::DevnetState,
) -> Result<(u32, [u8; 32]), MainnetBootstrapTransitionError> {
    let best = state
        .bitcoin_best_chain
        .as_ref()
        .ok_or(MainnetBootstrapTransitionError::TerminalHeight)?;
    let hash = hex::decode(&best.tip_hash_internal)
        .map_err(|_| MainnetBootstrapTransitionError::InternalInvariant)?
        .try_into()
        .map_err(|_| MainnetBootstrapTransitionError::InternalInvariant)?;
    Ok((best.tip_height, hash))
}

/// Reads the selected branch from the authenticated production header state.
/// The traversal deliberately follows `previous_block_internal` from the selected
/// tip, rather than treating the stored vector order as consensus order.
fn staged_best_chain_headers(
    state: &super::DevnetState,
) -> Result<Vec<(u32, BitcoinHeader)>, MainnetBootstrapTransitionError> {
    let (_, mut tip_hash) = staged_terminal_chain(state)?;
    let mut index = HashMap::with_capacity(state.bitcoin_headers.len());
    for stored in &state.bitcoin_headers {
        let hash: [u8; 32] = hex::decode(&stored.block_hash_internal)
            .map_err(|_| MainnetBootstrapTransitionError::InternalInvariant)?
            .try_into()
            .map_err(|_| MainnetBootstrapTransitionError::InternalInvariant)?;
        let raw: [u8; 80] = hex::decode(&stored.raw_header)
            .map_err(|_| MainnetBootstrapTransitionError::InternalInvariant)?
            .try_into()
            .map_err(|_| MainnetBootstrapTransitionError::InternalInvariant)?;
        let header = BitcoinHeader { raw };
        if header.hash_internal() != hash || index.insert(hash, (stored.height, header)).is_some() {
            return Err(MainnetBootstrapTransitionError::InternalInvariant);
        }
    }

    let mut reverse = Vec::new();
    while let Some((height, header)) = index.get(&tip_hash) {
        reverse.push((*height, header.clone()));
        tip_hash = header.previous_block_internal();
    }
    if reverse.len() != 2_003 || reverse.first().map(|(height, _)| *height) != Some(965_651) {
        return Err(MainnetBootstrapTransitionError::TerminalHeight);
    }
    reverse.reverse();
    if reverse.first().map(|(height, _)| *height) != Some(963_649) {
        return Err(MainnetBootstrapTransitionError::TerminalHeight);
    }
    Ok(reverse)
}

fn staged_final_mtp_and_containing_merkle_root(
    state: &super::DevnetState,
) -> Result<(u32, [u8; 32]), MainnetBootstrapTransitionError> {
    let chain = staged_best_chain_headers(state)?;
    let terminal_headers: Vec<BitcoinHeader> = chain
        .iter()
        .rev()
        .take(11)
        .map(|(_, header)| header.clone())
        .collect();
    let mtp = median_time_past_11(&terminal_headers)
        .map_err(|_| MainnetBootstrapTransitionError::FinalMtp)?;
    if mtp != 1_788_631_036 {
        return Err(MainnetBootstrapTransitionError::FinalMtp);
    }
    let containing = chain
        .iter()
        .find(|(height, _)| *height == 965_646)
        .map(|(_, header)| header.clone())
        .ok_or(MainnetBootstrapTransitionError::ContainingBlock)?;
    Ok((mtp, containing.merkle_root_internal()))
}

fn validate_bootstrap_transaction_facts(
    witness: &DecodedMainnetBootstrapWitness,
) -> Result<[u8; 32], MainnetBootstrapTransitionError> {
    if witness.raw_transaction.len() != 277 {
        return Err(MainnetBootstrapTransitionError::BitcoinTransaction);
    }
    let transaction = parse_transaction(&witness.raw_transaction)
        .map_err(|_| MainnetBootstrapTransitionError::BitcoinTransaction)?;
    let payment_output = transaction
        .outputs
        .get(witness.payment_output_index as usize)
        .ok_or(MainnetBootstrapTransitionError::PaymentOutput)?;
    let manifest_output = transaction
        .outputs
        .get(witness.manifest_output_index as usize)
        .ok_or(MainnetBootstrapTransitionError::ManifestOutput)?;
    if display_hex_from_internal(transaction.txid_internal)
        != "3f5994ddaa7adc586fcd980fbd3f6c816884312ab00588ed0c4f4f36a9a2b5d2"
    {
        return Err(MainnetBootstrapTransitionError::BitcoinTxid);
    }
    if witness.payment_output_index != 0 {
        return Err(MainnetBootstrapTransitionError::PaymentOutput);
    }
    if payment_output.value_sats != 24_576 {
        return Err(MainnetBootstrapTransitionError::PaymentAmount);
    }
    let policy =
        super::bitcoin_headers::resolve_tuple_policy(MAINNET_NETWORK_ID, &MAINNET_GENESIS_ID)
            .ok_or(MainnetBootstrapTransitionError::TreasuryScript)?;
    let treasury_script = policy
        .treasury_script_pubkey
        .ok_or(MainnetBootstrapTransitionError::TreasuryScript)?;
    if payment_output.script_pubkey.as_slice() != treasury_script {
        return Err(MainnetBootstrapTransitionError::TreasuryScript);
    }
    if witness.manifest_output_index != 1 {
        return Err(MainnetBootstrapTransitionError::ManifestOutput);
    }
    if manifest_output.value_sats != 0 {
        return Err(MainnetBootstrapTransitionError::ManifestValue);
    }
    let manifest = canonical_mainnet_bootstrap_manifest()?;
    let manifest_hash = manifest
        .manifest_hash()
        .map_err(|_| MainnetBootstrapTransitionError::BootstrapManifestHash)?;
    if manifest_output.script_pubkey != canonical_manifest_script(&manifest_hash.0) {
        return Err(MainnetBootstrapTransitionError::ManifestScript);
    }
    if bitcoin_payment_id(&transaction.txid_internal, witness.payment_output_index).0
        != hex::decode("e7aa3d2f8459a0fd58683e1a7c3ea79c08403e1a82aec051db72fe0e3ddd8a89")
            .map_err(|_| MainnetBootstrapTransitionError::InternalInvariant)?
            .as_slice()
    {
        return Err(MainnetBootstrapTransitionError::BitcoinPaymentId);
    }
    Ok(transaction.txid_internal)
}

fn validate_bootstrap_merkle_proof(
    txid_internal: [u8; 32],
    witness: &DecodedMainnetBootstrapWitness,
    containing_merkle_root: [u8; 32],
) -> Result<(), MainnetBootstrapTransitionError> {
    if witness.merkle_transaction_index != 181 || witness.merkle_siblings.len() != 12 {
        return Err(MainnetBootstrapTransitionError::BitcoinMerkleProof);
    }
    if merkle_root_from_branch(
        txid_internal,
        witness.merkle_transaction_index,
        &witness.merkle_siblings,
    ) != containing_merkle_root
    {
        return Err(MainnetBootstrapTransitionError::BitcoinMerkleProof);
    }
    Ok(())
}

/// Delegates transaction, Merkle, output-script, and six-confirmation semantics
/// to the production Bitcoin verifier after deriving its header window from the
/// staged authenticated chain.
fn validate_bootstrap_payment_with_production_primitive(
    state: &super::DevnetState,
    witness: &DecodedMainnetBootstrapWitness,
) -> Result<[u8; 32], MainnetBootstrapTransitionError> {
    let manifest = canonical_mainnet_bootstrap_manifest()?;
    let manifest_hash = manifest
        .manifest_hash()
        .map_err(|_| MainnetBootstrapTransitionError::BootstrapManifestHash)?;
    let policy =
        super::bitcoin_headers::resolve_tuple_policy(MAINNET_NETWORK_ID, &MAINNET_GENESIS_ID)
            .ok_or(MainnetBootstrapTransitionError::TreasuryScript)?;
    let treasury_script = policy
        .treasury_script_pubkey
        .ok_or(MainnetBootstrapTransitionError::TreasuryScript)?;
    let chain = staged_best_chain_headers(state)?;
    let headers = chain
        .iter()
        .filter(|(height, _)| (witness.containing_height..=965_651).contains(height))
        .map(|(_, header)| header.clone())
        .collect();
    let proof = BitcoinSpvProofV1 {
        raw_transaction: witness.raw_transaction.clone(),
        payment_output_index: witness.payment_output_index,
        manifest_output_index: witness.manifest_output_index,
        tx_index: witness.merkle_transaction_index,
        merkle_branch: witness.merkle_siblings.clone(),
        headers,
        containing_block_height: witness.containing_height,
    };
    let validated = validate_payment(&proof, &manifest_hash.0, treasury_script, 24_576)
        .map_err(|_| MainnetBootstrapTransitionError::BitcoinMerkleProof)?;
    if validated.paid_sats != 24_576
        || validated.containing_block_height != 965_646
        || validated.sixth_confirmation_height != 965_651
        || validated.sixth_confirmation_timestamp != 1_788_634_382
    {
        return Err(MainnetBootstrapTransitionError::BitcoinMerkleProof);
    }
    Ok(validated.txid_internal)
}

/// Builds the authenticated-state portion on a clone only.  This is deliberately
/// kept separate from Block-1 assembly so callers cannot observe a partial write.
fn materialize_authenticated_mainnet_bootstrap_state(
    header_state: &super::DevnetState,
    witness: &DecodedMainnetBootstrapWitness,
) -> Result<
    (
        super::DevnetState,
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ),
    MainnetBootstrapTransitionError,
> {
    let mut next = header_state.clone();
    let manifest = canonical_mainnet_bootstrap_manifest()?;
    let payment = validate_bootstrap_payment_with_production_primitive(&next, witness)?;
    let payment_id = bitcoin_payment_id(&payment, witness.payment_output_index);
    if next.bitcoin_headers.len() != 2_003 {
        return Err(MainnetBootstrapTransitionError::BitcoinHeaderOperation(
            "staged bootstrap did not retain exactly 2003 headers".into(),
        ));
    }
    if next.bitcoin_best_chain.is_none() {
        return Err(MainnetBootstrapTransitionError::TerminalHeight);
    }
    if !next.licenses.is_empty() || !next.consumed_bitcoin_payments.is_empty() {
        return Err(MainnetBootstrapTransitionError::AuthenticatedState);
    }
    for (index, entry) in manifest.licenses.iter().enumerate() {
        let license_id = derive_license_id(
            MAINNET_NETWORK_ID,
            super::PURCHASE_METHOD_BTC,
            &payment_id.0,
            index as u32,
            &entry.owner_public_key,
        );
        next.licenses.push(super::LicenseState {
            index: index as u32,
            license_id: license_id.to_hex(),
            purchase_id: payment_id.to_hex(),
            owner_public_key: hex::encode(entry.owner_public_key),
            mining_public_key: hex::encode(entry.mining_public_key),
            payment_address_id: hex::encode(super::address_id(&entry.owner_public_key).0),
            status: super::LICENSE_STATUS_PENDING,
            purchase_method: super::PURCHASE_METHOD_BTC,
            owner_key_sequence: 0,
            mining_key_sequence: 0,
            issued_epoch: 10,
            activation_epoch: 74,
            strike_weight: 0,
            suspended_until_epoch: 0,
            revocation_epoch: 0,
        });
    }
    let chain = staged_best_chain_headers(&next)?;
    let containing = chain
        .iter()
        .find(|(height, _)| *height == witness.containing_height)
        .map(|(_, header)| header.hash_internal())
        .ok_or(MainnetBootstrapTransitionError::ContainingBlock)?;
    let (_, tip) = staged_terminal_chain(&next)?;
    next.consumed_bitcoin_payments
        .push(super::BitcoinPaymentState {
            payment_id: payment_id.to_hex(),
            txid_internal: hex::encode(payment),
            payment_output_index: witness.payment_output_index,
            paid_sats: 24_576,
            containing_block_hash_internal: hex::encode(containing),
            containing_block_height: witness.containing_height,
            sixth_confirmation_hash_internal: hex::encode(tip),
            sixth_confirmation_height: 965_651,
            sixth_confirmation_timestamp: 1_788_634_382,
        });
    let external_payment_root = super::compute_external_payment_root(&next)
        .map_err(|_| MainnetBootstrapTransitionError::ExternalPaymentRoot)?;
    let license_root = super::compute_license_root(&next)
        .map_err(|_| MainnetBootstrapTransitionError::LicenseRoot)?;
    let protocol_state_root = super::compute_protocol_state_root(&next, &[], 0, 0)
        .map_err(|_| MainnetBootstrapTransitionError::ProtocolStateRoot)?;
    let meta_root = super::ConsensusMetaV1 {
        block_height: 1,
        eligible_license_count: 0,
        total_licenses_issued: 12,
        difficulty_correction_q32: super::DIFFICULTY_Q32_ONE,
        base_fee_rate_q32: super::BASE_FEE_MIN_Q32,
        total_issued_strikes: 0,
    }
    .root();
    let state_root = super::state_root(
        &super::sparse_root(&std::collections::BTreeMap::new()).0,
        &license_root.0,
        &external_payment_root.0,
        &protocol_state_root.0,
        &meta_root.0,
    );
    Ok((
        next,
        external_payment_root.0,
        license_root.0,
        protocol_state_root.0,
        meta_root.0,
        state_root.0,
    ))
}

fn build_mainnet_bootstrap_commitment(
    state: &super::DevnetState,
    witness: &DecodedMainnetBootstrapWitness,
) -> Result<(Vec<u8>, ProtocolOperationV1), MainnetBootstrapTransitionError> {
    let manifest = canonical_mainnet_bootstrap_manifest()?;
    let manifest_hash = manifest
        .manifest_hash()
        .map_err(|_| MainnetBootstrapTransitionError::BootstrapManifestHash)?;
    let txid = validate_bootstrap_transaction_facts(witness)?;
    let payment_id = bitcoin_payment_id(&txid, witness.payment_output_index);
    let chain = staged_best_chain_headers(state)?;
    let containing_hash = chain
        .iter()
        .find(|(height, _)| *height == witness.containing_height)
        .map(|(_, header)| header.hash_internal())
        .ok_or(MainnetBootstrapTransitionError::ContainingBlock)?;
    let (_, terminal_hash) = staged_terminal_chain(state)?;
    let (final_mtp, _) = staged_final_mtp_and_containing_merkle_root(state)?;
    let mut commitment = Vec::with_capacity(614);
    commitment.extend_from_slice(&1u16.to_be_bytes());
    commitment.extend_from_slice(&MAINNET_GENESIS_ID);
    commitment.extend_from_slice(&manifest_hash.0);
    commitment.extend_from_slice(&payment_id.0);
    commitment.extend_from_slice(&witness.anchor_height.to_be_bytes());
    commitment.extend_from_slice(&witness.anchor_hash_internal);
    commitment.extend_from_slice(&witness.containing_height.to_be_bytes());
    commitment.extend_from_slice(&containing_hash);
    commitment.extend_from_slice(&965_651u32.to_be_bytes());
    commitment.extend_from_slice(&terminal_hash);
    commitment.extend_from_slice(&final_mtp.to_be_bytes());
    commitment.extend_from_slice(&10u64.to_be_bytes());
    commitment.extend_from_slice(&74u64.to_be_bytes());
    commitment.extend_from_slice(&(manifest.licenses.len() as u32).to_be_bytes());
    for (index, entry) in manifest.licenses.iter().enumerate() {
        let id = derive_license_id(
            MAINNET_NETWORK_ID,
            super::PURCHASE_METHOD_BTC,
            &payment_id.0,
            index as u32,
            &entry.owner_public_key,
        );
        commitment.extend_from_slice(&id.0);
    }
    if commitment.len() != 614 {
        return Err(MainnetBootstrapTransitionError::Commitment);
    }
    let operation = ProtocolOperationV1 {
        op_type: OP_BOOTSTRAP_COMMITMENT,
        op_version: 1,
        payload: commitment.clone(),
    };
    Ok((commitment, operation))
}

fn build_canonical_mainnet_block1_body(
    state_root: [u8; 32],
    operation: ProtocolOperationV1,
) -> Result<
    (
        super::TransactionV1,
        [u8; 32],
        [u8; 32],
        [u8; 272],
        [u8; 32],
    ),
    MainnetBootstrapTransitionError,
> {
    let operation_root = protocol_operations_root(&[operation])
        .map_err(|_| MainnetBootstrapTransitionError::Operation)?;
    let coinbase = super::TransactionV1 {
        core: super::TransactionCoreV1 {
            version: 1,
            network_id: MAINNET_NETWORK_ID,
            valid_from_epoch: 10,
            expiry_epoch: 0,
            inputs: vec![super::TxInput::Coinbase {
                commitment: super::CoinbaseCommitmentV1 {
                    block_epoch: 10,
                    block_height: 1,
                    parent_block_hash: MAINNET_GENESIS_ID,
                    protocol_operations_root: operation_root.0,
                },
            }],
            outputs: Vec::new(),
        },
        witnesses: Vec::new(),
    };
    let transaction_root = super::merkle_root(&[coinbase.leaf()])
        .ok_or(MainnetBootstrapTransitionError::Transaction)?;
    let target = super::derive_target(super::authorized_capacity(12), super::DIFFICULTY_Q32_ONE)
        .map_err(|_| MainnetBootstrapTransitionError::Target)?;
    let mut header = [0u8; 272];
    header[0..2].copy_from_slice(&1u16.to_be_bytes());
    header[2..6].copy_from_slice(&MAINNET_NETWORK_ID.to_be_bytes());
    header[6..14].copy_from_slice(&10u64.to_be_bytes());
    header[14..46].copy_from_slice(&MAINNET_GENESIS_ID);
    header[46..78].copy_from_slice(&transaction_root.0);
    header[78..110].copy_from_slice(&state_root);
    header[110..142].copy_from_slice(&target);
    let block_hash = super::block_hash(&header).0;
    Ok((coinbase, transaction_root.0, target, header, block_hash))
}

pub(super) fn build_staged_mainnet_block1_transition(
    live_state: &super::DevnetState,
    witness: &DecodedMainnetBootstrapWitness,
) -> Result<StagedMainnetBlock1Transition, MainnetBootstrapTransitionError> {
    if live_state.network_id != MAINNET_NETWORK_ID
        || live_state.genesis_hash != hex::encode(MAINNET_GENESIS_ID)
        || live_state.height != 0
        || !live_state.blocks.is_empty()
        || !live_state.licenses.is_empty()
        || !live_state.consumed_bitcoin_payments.is_empty()
    {
        return Err(MainnetBootstrapTransitionError::AuthenticatedState);
    }
    let mut headers_only = live_state.clone();
    stage_mainnet_bitcoin_headers(&mut headers_only, witness)?;
    let (terminal_height, terminal_hash_internal) = staged_terminal_chain(&headers_only)?;
    if terminal_height != 965_651
        || terminal_hash_internal
            != hex::decode("c1e818cefb8be645c4fcce2ddc2aaea94f62a4f8663500000000000000000000")
                .map_err(|_| MainnetBootstrapTransitionError::InternalInvariant)?
                .as_slice()
    {
        return Err(MainnetBootstrapTransitionError::TerminalHash);
    }
    let (final_mtp, containing_merkle_root) =
        staged_final_mtp_and_containing_merkle_root(&headers_only)?;
    let txid_internal = validate_bootstrap_transaction_facts(witness)?;
    validate_bootstrap_merkle_proof(txid_internal, witness, containing_merkle_root)?;
    let production_txid =
        validate_bootstrap_payment_with_production_primitive(&headers_only, witness)?;
    if production_txid != txid_internal {
        return Err(MainnetBootstrapTransitionError::BitcoinPaymentId);
    }
    let manifest = canonical_mainnet_bootstrap_manifest()?;
    let manifest_hash = manifest
        .manifest_hash()
        .map_err(|_| MainnetBootstrapTransitionError::BootstrapManifestHash)?;
    let payment_id = bitcoin_payment_id(&txid_internal, witness.payment_output_index);
    let (
        mut staged,
        external_payment_root,
        license_root,
        protocol_state_root,
        meta_root,
        state_root,
    ) = materialize_authenticated_mainnet_bootstrap_state(&headers_only, witness)?;
    let (commitment, operation) = build_mainnet_bootstrap_commitment(&headers_only, witness)?;
    let operation_id = operation.operation_id();
    let operation_root = protocol_operations_root(&[operation.clone()])
        .map_err(|_| MainnetBootstrapTransitionError::Operation)?;
    let (coinbase, transaction_root, target, header, block_hash) =
        build_canonical_mainnet_block1_body(state_root, operation.clone())?;
    let block_weight = super::block_body_weight(&[coinbase.clone()], &[operation.clone()])
        .map_err(|_| MainnetBootstrapTransitionError::Block)?;
    staged.height = 1;
    staged.tip_hash = hex::encode(block_hash);
    staged.tip_epoch = 10;
    staged.anchor_epoch = 10;
    staged.anchor_license_id = hex::encode([0u8; 32]);
    staged.anchor_ticket_index = 0;
    staged.anchor_argon2_proof = hex::encode([0u8; 32]);
    staged.total_issued_strikes = 0;
    staged.difficulty_history_count = 0;
    staged.difficulty_history_bitmap = 0;
    staged.difficulty_correction_q32 = super::DIFFICULTY_Q32_ONE;
    staged.base_fee_rate_q32 = super::BASE_FEE_MIN_Q32;
    staged.current_state_root = hex::encode(state_root);
    staged.blocks.push(super::BlockState {
        height: 1,
        epoch: 10,
        header: hex::encode(header),
        transactions: vec![hex::encode(coinbase.encode_full())],
        protocol_operations: vec![hex::encode(operation.encode())],
        block_hash: hex::encode(block_hash),
        parent_hash: hex::encode(MAINNET_GENESIS_ID),
        miner_license_id: hex::encode([0u8; 32]),
        ticket_index: 0,
        argon2_proof: hex::encode([0u8; 32]),
        target: hex::encode(target),
        reward_strikes: 0,
        total_fees_strikes: 0,
        treasury_fee_share_strikes: 0,
        block_weight,
        transaction_root: hex::encode(transaction_root),
        state_root: hex::encode(state_root),
        coinbase_txid: coinbase.txid().to_hex(),
        transaction_ids: Vec::new(),
    });
    let proof = ValidatedMainnetBootstrapProof {
        accepted_header_count: 2_003,
        terminal_height,
        terminal_hash_internal,
        final_mtp,
        containing_height: witness.containing_height,
        txid_internal,
        payment_output_index: witness.payment_output_index,
        payment_amount_sats: 24_576,
        manifest_output_index: witness.manifest_output_index,
        merkle_transaction_index: witness.merkle_transaction_index,
        merkle_sibling_count: witness.merkle_siblings.len(),
        manifest_hash: manifest_hash.0,
        license_count: manifest.licenses.len(),
        issued_epoch: 10,
        activation_epoch: 74,
        bitcoin_payment_id: payment_id.0,
        external_payment_root,
        license_root,
        protocol_state_root,
        meta_root,
        state_root,
    };
    let _ = (commitment, operation_id, operation_root);
    Ok(StagedMainnetBlock1Transition {
        state: staged,
        proof,
        header,
        transactions: vec![coinbase],
        operations: vec![operation],
    })
}

impl fmt::Display for BootstrapInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(p) => write!(f, "LOCAL_INPUT_FAILURE: missing witness {}", p.display()),
            Self::Unreadable(p, e) => write!(
                f,
                "LOCAL_INPUT_FAILURE: unreadable witness {}: {e}",
                p.display()
            ),
            Self::WrongLength(n) => write!(
                f,
                "LOCAL_INPUT_FAILURE: witness length {n} != {MAINNET_BOOTSTRAP_WITNESS_LEN}"
            ),
            Self::WrongHash => write!(f, "LOCAL_INPUT_FAILURE: witness SHA-256 mismatch"),
            Self::Decode(e) => write!(f, "LOCAL_INPUT_FAILURE: witness decode: {e}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainnetBootstrapWitness(Vec<u8>);
impl MainnetBootstrapWitness {
    pub fn authenticate(bytes: Vec<u8>) -> Result<Self, BootstrapInputError> {
        if bytes.len() != MAINNET_BOOTSTRAP_WITNESS_LEN {
            return Err(BootstrapInputError::WrongLength(bytes.len()));
        }
        let h: [u8; 32] = Sha256::digest(&bytes).into();
        if h != WITNESS_SHA256 {
            return Err(BootstrapInputError::WrongHash);
        }
        Ok(Self(bytes))
    }
    pub fn decode(&self) -> Result<DecodedMainnetBootstrapWitness, BootstrapInputError> {
        decode(&self.0)
    }
}
#[derive(Debug, Clone)]
pub struct BootstrapWitnessProvider {
    path: PathBuf,
}
impl BootstrapWitnessProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
    pub fn load(&self) -> Result<MainnetBootstrapWitness, BootstrapInputError> {
        if !self.path.is_file() {
            return Err(BootstrapInputError::Missing(self.path.clone()));
        }
        let b = fs::read(&self.path)
            .map_err(|e| BootstrapInputError::Unreadable(self.path.clone(), e.to_string()))?;
        MainnetBootstrapWitness::authenticate(b)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}
#[derive(Debug, Clone)]
pub struct DecodedMainnetBootstrapWitness {
    pub version: u16,
    pub network_id: u32,
    pub genesis_id: [u8; 32],
    pub anchor_height: u32,
    pub anchor_hash_internal: [u8; 32],
    pub batches: Vec<BitcoinHeadersV1>,
    pub raw_transaction: Vec<u8>,
    pub payment_output_index: u32,
    pub manifest_output_index: u32,
    pub merkle_transaction_index: u32,
    pub merkle_siblings: Vec<[u8; 32]>,
    pub containing_height: u32,
}
struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BootstrapInputError> {
        let e = self
            .p
            .checked_add(n)
            .ok_or(BootstrapInputError::Decode("length overflow"))?;
        if e > self.b.len() {
            return Err(BootstrapInputError::Decode("truncated witness"));
        }
        let r = &self.b[self.p..e];
        self.p = e;
        Ok(r)
    }
    fn u16(&mut self) -> Result<u16, BootstrapInputError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, BootstrapInputError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn a32(&mut self) -> Result<[u8; 32], BootstrapInputError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn var(&mut self) -> Result<usize, BootstrapInputError> {
        let s = self.p;
        let mut v = 0u64;
        for i in 0..10 {
            let x = self.take(1)?[0];
            let lo = (x & 127) as u64;
            if i == 9 && lo > 1 {
                return Err(BootstrapInputError::Decode("VarUInt overflow"));
            }
            v |= lo << (i * 7);
            if x & 128 == 0 {
                let mut q = v;
                let mut c = Vec::new();
                loop {
                    let mut y = (q & 127) as u8;
                    q >>= 7;
                    if q != 0 {
                        y |= 128
                    }
                    c.push(y);
                    if q == 0 {
                        break;
                    }
                }
                if self.b[s..self.p] != c {
                    return Err(BootstrapInputError::Decode("non-minimal VarUInt"));
                }
                return usize::try_from(v)
                    .map_err(|_| BootstrapInputError::Decode("VarUInt usize overflow"));
            }
        }
        Err(BootstrapInputError::Decode("unterminated VarUInt"))
    }
}
fn decode(bytes: &[u8]) -> Result<DecodedMainnetBootstrapWitness, BootstrapInputError> {
    if bytes.len() != MAINNET_BOOTSTRAP_WITNESS_LEN {
        return Err(BootstrapInputError::WrongLength(bytes.len()));
    }
    let mut c = Cursor { b: bytes, p: 0 };
    let version = c.u16()?;
    if version != 1 {
        return Err(BootstrapInputError::Decode("wrong version"));
    }
    let network_id = c.u32()?;
    if network_id != MAINNET_NETWORK_ID {
        return Err(BootstrapInputError::Decode("wrong NetworkID"));
    }
    let genesis_id = c.a32()?;
    if genesis_id != MAINNET_GENESIS_ID {
        return Err(BootstrapInputError::Decode("wrong GenesisID"));
    }
    let anchor_height = c.u32()?;
    if anchor_height != 963648 {
        return Err(BootstrapInputError::Decode("wrong anchor height"));
    }
    let anchor_hash_internal = c.a32()?;
    if anchor_hash_internal != ANCHOR {
        return Err(BootstrapInputError::Decode("wrong anchor hash"));
    }
    if c.var()? != 8 {
        return Err(BootstrapInputError::Decode("wrong batch count"));
    }
    let mut batches = Vec::with_capacity(8);
    for i in 0..8 {
        let n = c.var()?;
        if n != LENGTHS[i] {
            return Err(BootstrapInputError::Decode("wrong batch length"));
        }
        let payload = c.take(n)?;
        let batch = BitcoinHeadersV1::decode_payload(payload)
            .map_err(|_| BootstrapInputError::Decode("malformed batch"))?;
        if batch.network_id != MAINNET_NETWORK_ID
            || batch.genesis_id != MAINNET_GENESIS_ID
            || batch.headers.len() != COUNTS[i]
            || batch
                .payload()
                .map_err(|_| BootstrapInputError::Decode("batch reencode"))?
                != payload
        {
            return Err(BootstrapInputError::Decode("invalid batch"));
        }
        batches.push(batch)
    }
    let n = c.var()?;
    if n != 277 {
        return Err(BootstrapInputError::Decode("wrong transaction length"));
    }
    let raw_transaction = c.take(n)?.to_vec();
    let payment_output_index = c.u32()?;
    if payment_output_index != 0 {
        return Err(BootstrapInputError::Decode("wrong payment index"));
    }
    let manifest_output_index = c.u32()?;
    if manifest_output_index != 1 {
        return Err(BootstrapInputError::Decode("wrong manifest index"));
    }
    let merkle_transaction_index = c.u32()?;
    if merkle_transaction_index != 181 {
        return Err(BootstrapInputError::Decode("wrong Merkle index"));
    }
    if c.var()? != 12 {
        return Err(BootstrapInputError::Decode("wrong sibling count"));
    }
    let mut merkle_siblings = Vec::with_capacity(12);
    for _ in 0..12 {
        merkle_siblings.push(c.a32()?)
    }
    let containing_height = c.u32()?;
    if containing_height != 965646 {
        return Err(BootstrapInputError::Decode("wrong containing height"));
    }
    if c.p != bytes.len() {
        return Err(BootstrapInputError::Decode("trailing bytes"));
    }
    Ok(DecodedMainnetBootstrapWitness {
        version,
        network_id,
        genesis_id,
        anchor_height,
        anchor_hash_internal,
        batches,
        raw_transaction,
        payment_output_index,
        manifest_output_index,
        merkle_transaction_index,
        merkle_siblings,
        containing_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn canonical_mainnet_bootstrap_manifest_is_exact() {
        let manifest = canonical_mainnet_bootstrap_manifest().unwrap();
        assert_eq!(manifest.licenses.len(), 12);
        assert_eq!(manifest.encode().unwrap().len(), BOOTSTRAP_MANIFEST_LEN);
        assert_eq!(manifest.manifest_hash().unwrap().0, BOOTSTRAP_MANIFEST_HASH);
    }

    #[test]
    fn invalid_prestate_is_rejected_without_mutating_live_state() {
        let state = fresh_staged_mainnet_state();
        let original_height = state.height;
        let original_tip = state.tip_hash.clone();
        let original_headers = state.bitcoin_headers.len();
        let invalid = DecodedMainnetBootstrapWitness {
            version: 1,
            network_id: MAINNET_NETWORK_ID,
            genesis_id: MAINNET_GENESIS_ID,
            anchor_height: 963_648,
            anchor_hash_internal: ANCHOR,
            batches: Vec::new(),
            raw_transaction: Vec::new(),
            payment_output_index: 0,
            manifest_output_index: 1,
            merkle_transaction_index: 181,
            merkle_siblings: Vec::new(),
            containing_height: 965_646,
        };
        let mut non_mainnet = state.clone();
        non_mainnet.network_id = 0;
        assert!(build_staged_mainnet_block1_transition(&non_mainnet, &invalid).is_err());
        assert_eq!(non_mainnet.height, original_height);
        assert_eq!(non_mainnet.tip_hash, original_tip);
        assert_eq!(non_mainnet.bitcoin_headers.len(), original_headers);
    }

    fn fresh_staged_mainnet_state() -> crate::DevnetState {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "mutiny-c1b-mainnet-bootstrap-{}-{id}",
            std::process::id(),
        ));
        let _ = fs::remove_dir_all(&directory);
        crate::init_devnet(&directory, 1, true).unwrap();
        let mut state = crate::load_state(&directory).unwrap();
        let _ = fs::remove_dir_all(&directory);
        state.network_id = MAINNET_NETWORK_ID;
        state.genesis_hash = hex::encode(MAINNET_GENESIS_ID);
        state.height = 0;
        state.tip_hash = hex::encode(MAINNET_GENESIS_ID);
        state.tip_epoch = 0;
        state.anchor_epoch = 0;
        state.licenses.clear();
        state.consumed_native_payments.clear();
        state.consumed_bitcoin_payments.clear();
        state.consumed_evidence.clear();
        state.offense_events.clear();
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
        state
    }

    #[test]
    fn staged_mainnet_headers_and_payment_match_locked_facts_when_witness_is_supplied() {
        let Some(bytes) = witness() else { return };
        let decoded = MainnetBootstrapWitness::authenticate(bytes)
            .unwrap()
            .decode()
            .unwrap();
        let mut state = fresh_staged_mainnet_state();
        stage_mainnet_bitcoin_headers(&mut state, &decoded).unwrap();
        let (height, tip) = staged_terminal_chain(&state).unwrap();
        assert_eq!(height, 965_651);
        assert_eq!(
            hex::encode(tip),
            "c1e818cefb8be645c4fcce2ddc2aaea94f62a4f8663500000000000000000000"
        );
        let (mtp, merkle_root) = staged_final_mtp_and_containing_merkle_root(&state).unwrap();
        assert_eq!(mtp, 1_788_631_036);
        let txid = validate_bootstrap_transaction_facts(&decoded).unwrap();
        validate_bootstrap_merkle_proof(txid, &decoded, merkle_root).unwrap();
        assert_eq!(
            validate_bootstrap_payment_with_production_primitive(&state, &decoded).unwrap(),
            txid
        );
        let (materialized, external_root, license_root, protocol_root, meta_root, state_root) =
            materialize_authenticated_mainnet_bootstrap_state(&state, &decoded).unwrap();
        assert_eq!(materialized.bitcoin_headers.len(), 2_003);
        assert!(materialized.bitcoin_best_chain.is_some());
        assert_eq!(materialized.licenses.len(), 12);
        assert_eq!(materialized.consumed_bitcoin_payments.len(), 1);
        assert_eq!(2_003 + 1 + 12 + 1 + 1 + 1, 2_019);
        assert_eq!(
            hex::encode(external_root),
            "6c58265f1e5ef95ca42fd7227c74aef448e0daaf96634631b1dc448aa73313b7"
        );
        assert_eq!(
            hex::encode(license_root),
            "aedd356fc7198dfcbd12bf1e90c6cfe8616d3716c65c6ee4622b08cd149b5c62"
        );
        assert_eq!(
            hex::encode(protocol_root),
            "edccc15eaa18f0b5023718f34eb67a0f3874dd3682e7398cb884a8d4d0b7dcaa"
        );
        assert_eq!(
            hex::encode(meta_root),
            "35920236c0e26605e8f183b7102410d8b1fbe26960c3d41d51387092e460506d"
        );
        assert_eq!(
            hex::encode(state_root),
            "4d844f0393da16e076f0873358b3471425261e9fda0bf011124f1dae705faae7"
        );
        let (commitment, operation) = build_mainnet_bootstrap_commitment(&state, &decoded).unwrap();
        assert_eq!(commitment.len(), 614);
        assert_eq!(
            hex::encode(sha256_domain(domains::BOOTSTRAP_COMMITMENT, &[&commitment]).0),
            "8a139736b67e3968d9436949a4284515da71d825ab451b0448790c2b19685f9d"
        );
        assert_eq!(
            operation.operation_id().to_hex(),
            "dc20721540c52505b1ff89f0ea81fc6fe76a89165d84e5da6d84c382aae331ac"
        );
        assert_eq!(
            protocol_operations_root(&[operation.clone()])
                .unwrap()
                .to_hex(),
            "2ccdca0eecbaf6710a4a3f3e286c06d9453de85389785ecfefec1f5693bac121"
        );
        let (coinbase, transaction_root, target, header, block_hash) =
            build_canonical_mainnet_block1_body(state_root, operation).unwrap();
        assert_eq!(coinbase.encode_full().len(), 138);
        assert_eq!(
            coinbase.txid().to_hex(),
            "b7ab6a1e08d4af6f6765409134bae17633b04477ebe91acb254952ba577f4edf"
        );
        assert_eq!(
            coinbase.wtxid().to_hex(),
            "faafaa5aae23c5a203980eac6b6b414fae742d3f348bb8db1bcbe7741e494137"
        );
        assert_eq!(
            hex::encode(transaction_root),
            "0761075117a31bb218f55bf1b9603a033f7420f1671a304f7ec10ea5aa81a2df"
        );
        assert_eq!(
            hex::encode(target),
            "025ed097b425ed097b425ed097b425ed097b425ed097b425ed097b425ed097b4"
        );
        assert_eq!(header.len(), 272);
        assert_eq!(
            hex::encode(block_hash),
            "9d8026ac82592abb40cb1809142af67ea57b89e19ad51db35ff3d53f09907ded"
        );
        let live_before = fresh_staged_mainnet_state();
        let complete = build_staged_mainnet_block1_transition(&live_before, &decoded).unwrap();
        assert_eq!(live_before.height, 0);
        assert!(live_before.bitcoin_headers.is_empty());
        assert_eq!(complete.proof.state_root, state_root);
        assert_eq!(complete.header, header);
        assert_eq!(complete.transactions.len(), 1);
        assert_eq!(complete.operations.len(), 1);
        assert_eq!(complete.state.height, 1);
        assert_eq!(complete.state.blocks.len(), 1);
        compare_received_mainnet_block1(
            &complete,
            &complete.header,
            &complete.transactions,
            &complete.operations,
        )
        .unwrap();
        let mut modified_header = complete.header;
        modified_header[78] ^= 1;
        assert!(compare_received_mainnet_block1(
            &complete,
            &modified_header,
            &complete.transactions,
            &complete.operations,
        )
        .is_err());
    }

    #[test]
    fn staged_mainnet_transition_is_deterministic_when_witness_is_supplied() {
        let Some(bytes) = witness() else { return };
        let decoded = MainnetBootstrapWitness::authenticate(bytes)
            .unwrap()
            .decode()
            .unwrap();
        let first = build_staged_mainnet_block1_transition(&fresh_staged_mainnet_state(), &decoded)
            .unwrap();
        let second =
            build_staged_mainnet_block1_transition(&fresh_staged_mainnet_state(), &decoded)
                .unwrap();
        assert_eq!(first.header, second.header);
        assert_eq!(first.proof, second.proof);
        assert_eq!(
            first.transactions[0].encode_full(),
            second.transactions[0].encode_full()
        );
        assert_eq!(first.operations[0].encode(), second.operations[0].encode());
        assert_eq!(first.state.tip_hash, second.state.tip_hash);
        assert_eq!(
            first.state.current_state_root,
            second.state.current_state_root
        );
    }

    #[test]
    fn malformed_transition_witness_leaves_live_state_unchanged_when_supplied() {
        let Some(bytes) = witness() else { return };
        let mut decoded = MainnetBootstrapWitness::authenticate(bytes)
            .unwrap()
            .decode()
            .unwrap();
        decoded.raw_transaction[0] ^= 1;
        let live = fresh_staged_mainnet_state();
        let before_tip = live.tip_hash.clone();
        let before_root = live.current_state_root.clone();
        assert!(build_staged_mainnet_block1_transition(&live, &decoded).is_err());
        assert_eq!(live.height, 0);
        assert_eq!(live.tip_hash, before_tip);
        assert_eq!(live.current_state_root, before_root);
        assert!(live.bitcoin_headers.is_empty());
        assert!(live.licenses.is_empty());
        assert!(live.consumed_bitcoin_payments.is_empty());
        assert!(live.blocks.is_empty());
    }

    fn witness() -> Option<Vec<u8>> {
        std::env::var_os("MUTINY_MAINNET_BOOTSTRAP_WITNESS").map(|p| fs::read(p).unwrap())
    }
    #[test]
    fn canonical_witness_decodes_when_supplied() {
        let Some(bytes) = witness() else { return };
        let d = MainnetBootstrapWitness::authenticate(bytes)
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(d.batches.len(), 8);
        assert_eq!(
            d.batches.iter().map(|x| x.headers.len()).sum::<usize>(),
            2003
        );
        assert_eq!(d.raw_transaction.len(), 277);
        assert_eq!(d.merkle_siblings.len(), 12)
    }
    #[test]
    fn provider_errors_are_local() {
        assert!(matches!(
            BootstrapWitnessProvider::new("Z:\\missing-witness").load(),
            Err(BootstrapInputError::Missing(_))
        ));
        assert!(matches!(
            MainnetBootstrapWitness::authenticate(vec![0]),
            Err(BootstrapInputError::WrongLength(1))
        ))
    }
    fn raw() -> Vec<u8> {
        witness().expect("set MUTINY_MAINNET_BOOTSTRAP_WITNESS for C1A validation")
    }
    fn reject(mutator: impl FnOnce(&mut Vec<u8>)) {
        let mut b = raw();
        mutator(&mut b);
        assert!(decode(&b).is_err());
    }
    #[test]
    fn framing_negative_matrix() {
        let b = raw();
        assert!(decode(&b[..b.len() - 1]).is_err());
        assert!(decode(&b[..74]).is_err());
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        reject(|x| x[1] ^= 1);
        reject(|x| x[2] ^= 1);
        reject(|x| x[6] ^= 1);
        reject(|x| x[41] ^= 1);
        reject(|x| x[42] ^= 1);
        reject(|x| x[74] = 7);
    }
    #[test]
    fn every_batch_length_rejects() {
        for offset in [75usize, 20596, 41117, 61638, 82159, 102680, 123201, 143722] {
            reject(|x| x[offset] ^= 1);
        }
    }
    #[test]
    fn transaction_and_index_matrix_rejects() {
        reject(|x| x[160643] ^= 1);
        reject(|x| x[160925] ^= 1);
        reject(|x| x[160929] ^= 1);
        reject(|x| x[160933] ^= 1);
        reject(|x| x[160934] ^= 1);
        reject(|x| x[161322] ^= 1);
    }
    #[test]
    fn witness_varuint_fields_reject_nonminimal_forms() {
        for (offset, replacement) in [
            (74usize, &[0x80, 0x00][..]),
            (75usize, &[0x80, 0x80, 0x00][..]),
            (160643usize, &[0x80, 0x00][..]),
            (160934usize, &[0x80, 0x00][..]),
        ] {
            reject(|x| x[offset..offset + replacement.len()].copy_from_slice(replacement));
        }
    }
    #[test]
    fn canonical_varuint_trailing_byte_is_enclosing_strictness() {
        let bytes = &[0xa6, 0xa0, 0x01, 0x00];
        let mut c = Cursor { b: bytes, p: 0 };
        assert_eq!(c.var().unwrap(), 20_518);
        assert_eq!(&c.b[c.p..], &[0x00]);
        let mut trailing = raw();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }
    #[test]
    fn provider_directory_wrong_length_and_hash_are_local() {
        assert!(matches!(
            BootstrapWitnessProvider::new(std::env::temp_dir()).load(),
            Err(BootstrapInputError::Missing(_))
        ));
        assert!(matches!(
            MainnetBootstrapWitness::authenticate(vec![0; 2]),
            Err(BootstrapInputError::WrongLength(2))
        ));
        let mut b = raw();
        b[0] ^= 1;
        assert!(matches!(
            MainnetBootstrapWitness::authenticate(b),
            Err(BootstrapInputError::WrongHash)
        ));
    }
}
