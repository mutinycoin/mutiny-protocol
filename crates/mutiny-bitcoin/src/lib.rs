use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const REQUIRED_CONFIRMATIONS: usize = 6;
pub const ANCHOR_CONTEXT_HEADERS: usize = 11;
pub const CANONICAL_MANIFEST_SCRIPT_LEN: usize = 34;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BitcoinError {
    #[error("truncated Bitcoin encoding")]
    Truncated,
    #[error("non-canonical or unsupported CompactSize")]
    BadCompactSize,
    #[error("malformed Bitcoin transaction")]
    BadTransaction,
    #[error("Bitcoin payment output index is out of range")]
    PaymentOutputMissing,
    #[error("Bitcoin manifest output index is out of range")]
    ManifestOutputMissing,
    #[error("Bitcoin payment output script does not match Treasury script")]
    WrongTreasuryScript,
    #[error("Bitcoin payment amount is below the required price")]
    Underpayment,
    #[error("Bitcoin transaction does not contain the canonical manifest commitment")]
    BadManifestCommitment,
    #[error("Bitcoin Merkle proof does not match the containing block")]
    BadMerkleProof,
    #[error("Bitcoin SPV proof has fewer than six confirmations")]
    InsufficientConfirmations,
    #[error("Bitcoin headers are not contiguous")]
    NonContiguousHeaders,
    #[error("Bitcoin compact target is invalid")]
    BadCompactTarget,
    #[error("Bitcoin header fails proof of work")]
    BadProofOfWork,
    #[error("Bitcoin header chain does not connect to the authenticated checkpoint")]
    UntrustedHeaderAnchor,
    #[error("Bitcoin header difficulty does not match the active checkpoint policy")]
    UnexpectedDifficulty,
    #[error("Bitcoin anchor context must contain exactly eleven headers")]
    BadAnchorContextLength,
    #[error("Bitcoin anchor height is not a 2016-block retarget boundary")]
    AnchorNotRetargetBoundary,
    #[error("Bitcoin fixture nonce search exhausted")]
    FixtureMiningExhausted,
    #[error("Bitcoin header timestamp is not greater than Median-Time-Past-11")]
    MedianTimePastViolation,
    #[error("Bitcoin arithmetic overflow")]
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinTxOutput {
    pub value_sats: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedBitcoinTransaction {
    /// Internal Bitcoin hash bytes, i.e. the direct double-SHA256 digest. Human display reverses these bytes.
    pub txid_internal: [u8; 32],
    pub outputs: Vec<BitcoinTxOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinHeader {
    pub raw: [u8; 80],
}

impl BitcoinHeader {
    pub fn previous_block_internal(&self) -> [u8; 32] {
        self.raw[4..36].try_into().expect("fixed slice")
    }

    pub fn merkle_root_internal(&self) -> [u8; 32] {
        self.raw[36..68].try_into().expect("fixed slice")
    }

    pub fn timestamp(&self) -> u32 {
        u32::from_le_bytes(self.raw[68..72].try_into().expect("fixed slice"))
    }

    pub fn bits(&self) -> u32 {
        u32::from_le_bytes(self.raw[72..76].try_into().expect("fixed slice"))
    }

    pub fn hash_internal(&self) -> [u8; 32] {
        double_sha256(&self.raw)
    }

    pub fn hash_display_hex(&self) -> String {
        let mut bytes = self.hash_internal();
        bytes.reverse();
        hex_lower(&bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinSpvProofV1 {
    pub raw_transaction: Vec<u8>,
    pub payment_output_index: u32,
    pub manifest_output_index: u32,
    pub tx_index: u32,
    /// Internal Bitcoin hash bytes, one sibling for each Merkle level from leaf upward.
    pub merkle_branch: Vec<[u8; 32]>,
    /// Containing header first, followed by descendant headers. Six entries means six confirmations.
    pub headers: Vec<BitcoinHeader>,
    pub containing_block_height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedBitcoinPayment {
    pub txid_internal: [u8; 32],
    pub containing_block_hash_internal: [u8; 32],
    pub containing_block_height: u32,
    pub sixth_confirmation_hash_internal: [u8; 32],
    pub sixth_confirmation_height: u32,
    pub sixth_confirmation_timestamp: u32,
    pub payment_output_index: u32,
    pub paid_sats: u64,
}

pub fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}

pub fn display_hex_from_internal(mut hash: [u8; 32]) -> String {
    hash.reverse();
    hex_lower(&hash)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, n: usize) -> Result<&'a [u8], BitcoinError> {
    let end = cursor.checked_add(n).ok_or(BitcoinError::Truncated)?;
    let out = bytes.get(*cursor..end).ok_or(BitcoinError::Truncated)?;
    *cursor = end;
    Ok(out)
}

fn read_compact_size(bytes: &[u8], cursor: &mut usize) -> Result<(u64, Vec<u8>), BitcoinError> {
    let first = *take(bytes, cursor, 1)?
        .first()
        .ok_or(BitcoinError::Truncated)?;
    match first {
        0x00..=0xfc => Ok((first as u64, vec![first])),
        0xfd => {
            let raw = take(bytes, cursor, 2)?;
            let v = u16::from_le_bytes(raw.try_into().map_err(|_| BitcoinError::Truncated)?) as u64;
            if v < 0xfd {
                return Err(BitcoinError::BadCompactSize);
            }
            let mut enc = vec![0xfd];
            enc.extend_from_slice(raw);
            Ok((v, enc))
        }
        0xfe => {
            let raw = take(bytes, cursor, 4)?;
            let v = u32::from_le_bytes(raw.try_into().map_err(|_| BitcoinError::Truncated)?) as u64;
            if v <= 0xffff {
                return Err(BitcoinError::BadCompactSize);
            }
            let mut enc = vec![0xfe];
            enc.extend_from_slice(raw);
            Ok((v, enc))
        }
        0xff => {
            let raw = take(bytes, cursor, 8)?;
            let v = u64::from_le_bytes(raw.try_into().map_err(|_| BitcoinError::Truncated)?);
            if v <= 0xffff_ffff {
                return Err(BitcoinError::BadCompactSize);
            }
            let mut enc = vec![0xff];
            enc.extend_from_slice(raw);
            Ok((v, enc))
        }
    }
}

fn usize_from_u64(v: u64) -> Result<usize, BitcoinError> {
    usize::try_from(v).map_err(|_| BitcoinError::BadTransaction)
}

/// Parses legacy and SegWit transactions and computes the legacy txid (witness excluded).
pub fn parse_transaction(bytes: &[u8]) -> Result<ParsedBitcoinTransaction, BitcoinError> {
    let mut cursor = 0usize;
    let version = take(bytes, &mut cursor, 4)?.to_vec();
    let mut stripped = version;

    let segwit =
        bytes.get(cursor) == Some(&0x00) && bytes.get(cursor + 1).is_some_and(|f| *f != 0x00);
    if segwit {
        take(bytes, &mut cursor, 2)?;
    }

    let (vin_count, vin_enc) = read_compact_size(bytes, &mut cursor)?;
    if vin_count == 0 || vin_count > (bytes.len() as u64 / 41).saturating_add(1) {
        return Err(BitcoinError::BadTransaction);
    }
    stripped.extend_from_slice(&vin_enc);
    for _ in 0..usize_from_u64(vin_count)? {
        stripped.extend_from_slice(take(bytes, &mut cursor, 36)?);
        let (script_len, script_enc) = read_compact_size(bytes, &mut cursor)?;
        stripped.extend_from_slice(&script_enc);
        stripped.extend_from_slice(take(bytes, &mut cursor, usize_from_u64(script_len)?)?);
        stripped.extend_from_slice(take(bytes, &mut cursor, 4)?);
    }

    let (vout_count, vout_enc) = read_compact_size(bytes, &mut cursor)?;
    if vout_count == 0 || vout_count > (bytes.len() as u64 / 9).saturating_add(1) {
        return Err(BitcoinError::BadTransaction);
    }
    stripped.extend_from_slice(&vout_enc);
    let mut outputs = Vec::with_capacity(usize_from_u64(vout_count)?);
    for _ in 0..usize_from_u64(vout_count)? {
        let value_bytes = take(bytes, &mut cursor, 8)?;
        stripped.extend_from_slice(value_bytes);
        let value_sats = u64::from_le_bytes(
            value_bytes
                .try_into()
                .map_err(|_| BitcoinError::Truncated)?,
        );
        let (script_len, script_enc) = read_compact_size(bytes, &mut cursor)?;
        stripped.extend_from_slice(&script_enc);
        let script = take(bytes, &mut cursor, usize_from_u64(script_len)?)?.to_vec();
        stripped.extend_from_slice(&script);
        outputs.push(BitcoinTxOutput {
            value_sats,
            script_pubkey: script,
        });
    }

    if segwit {
        for _ in 0..usize_from_u64(vin_count)? {
            let (items, _) = read_compact_size(bytes, &mut cursor)?;
            for _ in 0..usize_from_u64(items)? {
                let (len, _) = read_compact_size(bytes, &mut cursor)?;
                take(bytes, &mut cursor, usize_from_u64(len)?)?;
            }
        }
    }

    let lock_time = take(bytes, &mut cursor, 4)?;
    stripped.extend_from_slice(lock_time);
    if cursor != bytes.len() {
        return Err(BitcoinError::BadTransaction);
    }

    Ok(ParsedBitcoinTransaction {
        txid_internal: double_sha256(&stripped),
        outputs,
    })
}

pub fn canonical_manifest_script(manifest_hash: &[u8; 32]) -> [u8; CANONICAL_MANIFEST_SCRIPT_LEN] {
    let mut out = [0u8; CANONICAL_MANIFEST_SCRIPT_LEN];
    out[0] = 0x6a; // OP_RETURN
    out[1] = 0x20; // canonical direct push of 32 bytes
    out[2..].copy_from_slice(manifest_hash);
    out
}

pub fn merkle_root_from_branch(
    mut leaf_internal: [u8; 32],
    mut index: u32,
    branch: &[[u8; 32]],
) -> [u8; 32] {
    for sibling in branch {
        let mut pair = [0u8; 64];
        if index & 1 == 0 {
            pair[..32].copy_from_slice(&leaf_internal);
            pair[32..].copy_from_slice(sibling);
        } else {
            pair[..32].copy_from_slice(sibling);
            pair[32..].copy_from_slice(&leaf_internal);
        }
        leaf_internal = double_sha256(&pair);
        index >>= 1;
    }
    leaf_internal
}

pub fn compact_target_be(bits: u32) -> Result<[u8; 32], BitcoinError> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    if mantissa == 0 || bits & 0x0080_0000 != 0 || exponent == 0 || exponent > 32 {
        return Err(BitcoinError::BadCompactTarget);
    }
    let mant = [
        (mantissa >> 16) as u8,
        (mantissa >> 8) as u8,
        mantissa as u8,
    ];
    let mut out = [0u8; 32];
    if exponent <= 3 {
        let shifted = mantissa >> (8 * (3 - exponent));
        let bytes = shifted.to_be_bytes();
        out[28..].copy_from_slice(&bytes);
    } else {
        let start = 32usize
            .checked_sub(exponent)
            .ok_or(BitcoinError::BadCompactTarget)?;
        let count = (32 - start).min(3);
        out[start..start + count].copy_from_slice(&mant[..count]);
    }
    Ok(out)
}

pub const BITCOIN_MAINNET_POW_LIMIT_BITS: u32 = 0x1d00_ffff;
pub const BITCOIN_MAINNET_TARGET_SPACING_SECONDS: u32 = 600;
pub const BITCOIN_MAINNET_RETARGET_INTERVAL: u32 = 2016;
pub const BITCOIN_MAINNET_TARGET_TIMESPAN_SECONDS: u32 = 1_209_600;
pub const BITCOIN_MAINNET_RETARGET_MIN_TIMESPAN_SECONDS: u32 =
    BITCOIN_MAINNET_TARGET_TIMESPAN_SECONDS / 4;
pub const BITCOIN_MAINNET_RETARGET_MAX_TIMESPAN_SECONDS: u32 =
    BITCOIN_MAINNET_TARGET_TIMESPAN_SECONDS * 4;
pub const BITCOIN_MAINNET_MTP_WINDOW: usize = 11;

fn biguint_to_be32(value: &BigUint) -> Result<[u8; 32], BitcoinError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(BitcoinError::ArithmeticOverflow);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

fn compact_bits_from_biguint(target: &BigUint) -> Result<u32, BitcoinError> {
    if *target == BigUint::from(0u8) {
        return Err(BitcoinError::BadCompactTarget);
    }

    let bytes = target.to_bytes_be();
    let mut size = bytes.len();
    let mut mantissa = if size <= 3 {
        let mut value = 0u32;
        for byte in &bytes {
            value = (value << 8) | u32::from(*byte);
        }
        value << (8 * (3 - size))
    } else {
        (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2])
    };

    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        size = size
            .checked_add(1)
            .ok_or(BitcoinError::ArithmeticOverflow)?;
    }
    if size > u8::MAX as usize {
        return Err(BitcoinError::ArithmeticOverflow);
    }

    Ok(((size as u32) << 24) | (mantissa & 0x007f_ffff))
}

pub fn compact_bits_from_target_be(target: [u8; 32]) -> Result<u32, BitcoinError> {
    compact_bits_from_biguint(&BigUint::from_bytes_be(&target))
}

pub fn canonical_compact_target_be(bits: u32) -> Result<[u8; 32], BitcoinError> {
    let target = compact_target_be(bits)?;
    if compact_bits_from_target_be(target)? != bits {
        return Err(BitcoinError::BadCompactTarget);
    }
    Ok(target)
}

pub fn validate_mainnet_target_bits(bits: u32) -> Result<[u8; 32], BitcoinError> {
    let target = canonical_compact_target_be(bits)?;
    let pow_limit = compact_target_be(BITCOIN_MAINNET_POW_LIMIT_BITS)?;
    if target > pow_limit {
        return Err(BitcoinError::BadCompactTarget);
    }
    Ok(target)
}

pub fn header_meets_mainnet_pow(header: &BitcoinHeader) -> Result<bool, BitcoinError> {
    let target = validate_mainnet_target_bits(header.bits())?;
    let mut hash_number = header.hash_internal();
    hash_number.reverse();
    Ok(hash_number <= target)
}

pub fn bitcoin_header_work_be(bits: u32) -> Result<[u8; 32], BitcoinError> {
    let target = BigUint::from_bytes_be(&canonical_compact_target_be(bits)?);
    let numerator = BigUint::from(1u8) << 256usize;
    let work = numerator / (target + BigUint::from(1u8));
    biguint_to_be32(&work)
}

pub fn add_chainwork_be(
    parent_relative_chainwork: &[u8; 32],
    header_work: &[u8; 32],
) -> Result<[u8; 32], BitcoinError> {
    let parent = BigUint::from_bytes_be(parent_relative_chainwork);
    let work = BigUint::from_bytes_be(header_work);
    biguint_to_be32(&(parent + work))
}

pub fn bitcoin_mainnet_retarget_bits(
    old_bits: u32,
    first_period_timestamp: u32,
    last_period_timestamp: u32,
) -> Result<u32, BitcoinError> {
    let old_target = BigUint::from_bytes_be(&validate_mainnet_target_bits(old_bits)?);
    let pow_limit = BigUint::from_bytes_be(&compact_target_be(BITCOIN_MAINNET_POW_LIMIT_BITS)?);

    let elapsed_signed = i64::from(last_period_timestamp) - i64::from(first_period_timestamp);
    let elapsed = elapsed_signed.clamp(
        i64::from(BITCOIN_MAINNET_RETARGET_MIN_TIMESPAN_SECONDS),
        i64::from(BITCOIN_MAINNET_RETARGET_MAX_TIMESPAN_SECONDS),
    ) as u32;

    let mut target = old_target * BigUint::from(elapsed);
    target /= BigUint::from(BITCOIN_MAINNET_TARGET_TIMESPAN_SECONDS);
    if target > pow_limit {
        target = pow_limit;
    }

    compact_bits_from_biguint(&target)
}

pub fn expected_mainnet_bits(
    next_height: u32,
    parent_bits: u32,
    first_period_timestamp: u32,
    parent_timestamp: u32,
) -> Result<u32, BitcoinError> {
    validate_mainnet_target_bits(parent_bits)?;
    if next_height % BITCOIN_MAINNET_RETARGET_INTERVAL != 0 {
        return Ok(parent_bits);
    }
    bitcoin_mainnet_retarget_bits(parent_bits, first_period_timestamp, parent_timestamp)
}

pub fn median_timestamp_11(previous_timestamps: &[u32; 11]) -> u32 {
    let mut times = *previous_timestamps;
    times.sort_unstable();
    times[BITCOIN_MAINNET_MTP_WINDOW / 2]
}

pub fn validate_mainnet_mtp(
    candidate_timestamp: u32,
    previous_timestamps: &[u32; 11],
) -> Result<(), BitcoinError> {
    if candidate_timestamp <= median_timestamp_11(previous_timestamps) {
        return Err(BitcoinError::MedianTimePastViolation);
    }
    Ok(())
}

pub fn validate_mainnet_header_rules(
    header: &BitcoinHeader,
    next_height: u32,
    parent_bits: u32,
    first_period_timestamp: u32,
    parent_timestamp: u32,
    previous_timestamps: &[u32; 11],
) -> Result<[u8; 32], BitcoinError> {
    let expected_bits = expected_mainnet_bits(
        next_height,
        parent_bits,
        first_period_timestamp,
        parent_timestamp,
    )?;
    if header.bits() != expected_bits {
        return Err(BitcoinError::UnexpectedDifficulty);
    }
    validate_mainnet_mtp(header.timestamp(), previous_timestamps)?;
    if !header_meets_mainnet_pow(header)? {
        return Err(BitcoinError::BadProofOfWork);
    }
    bitcoin_header_work_be(header.bits())
}

pub fn header_meets_pow(header: &BitcoinHeader) -> Result<bool, BitcoinError> {
    let target = compact_target_be(header.bits())?;
    let mut hash_number = header.hash_internal();
    hash_number.reverse();
    Ok(hash_number <= target)
}

pub fn validate_header_chain(headers: &[BitcoinHeader]) -> Result<(), BitcoinError> {
    if headers.len() < REQUIRED_CONFIRMATIONS {
        return Err(BitcoinError::InsufficientConfirmations);
    }
    for header in headers {
        if !header_meets_pow(header)? {
            return Err(BitcoinError::BadProofOfWork);
        }
    }
    for pair in headers.windows(2) {
        if pair[1].previous_block_internal() != pair[0].hash_internal() {
            return Err(BitcoinError::NonContiguousHeaders);
        }
    }
    Ok(())
}

pub fn validate_fixed_header_chain(
    headers: &[BitcoinHeader],
    trusted_previous_block_internal: &[u8; 32],
    expected_bits: u32,
) -> Result<(), BitcoinError> {
    if headers.len() < REQUIRED_CONFIRMATIONS {
        return Err(BitcoinError::InsufficientConfirmations);
    }
    if headers[0].previous_block_internal() != *trusted_previous_block_internal {
        return Err(BitcoinError::UntrustedHeaderAnchor);
    }
    for header in headers {
        if header.bits() != expected_bits {
            return Err(BitcoinError::UnexpectedDifficulty);
        }
    }
    validate_header_chain(headers)
}

pub fn validate_anchor_context(
    headers: &[BitcoinHeader],
    trusted_previous_block_internal: &[u8; 32],
    expected_bits: u32,
    anchor_height: u32,
) -> Result<(), BitcoinError> {
    if headers.len() != ANCHOR_CONTEXT_HEADERS {
        return Err(BitcoinError::BadAnchorContextLength);
    }
    if anchor_height % 2016 != 0 {
        return Err(BitcoinError::AnchorNotRetargetBoundary);
    }
    if headers[0].previous_block_internal() != *trusted_previous_block_internal {
        return Err(BitcoinError::UntrustedHeaderAnchor);
    }
    for header in headers {
        if header.bits() != expected_bits {
            return Err(BitcoinError::UnexpectedDifficulty);
        }
    }
    validate_header_chain(headers)
}

pub fn median_time_past_11(headers: &[BitcoinHeader]) -> Result<u32, BitcoinError> {
    if headers.len() != ANCHOR_CONTEXT_HEADERS {
        return Err(BitcoinError::BadAnchorContextLength);
    }
    let mut times = headers
        .iter()
        .map(BitcoinHeader::timestamp)
        .collect::<Vec<_>>();
    times.sort_unstable();
    Ok(times[ANCHOR_CONTEXT_HEADERS / 2])
}

pub fn validate_payment(
    proof: &BitcoinSpvProofV1,
    expected_manifest_hash: &[u8; 32],
    treasury_script_pubkey: &[u8],
    required_sats: u64,
) -> Result<ValidatedBitcoinPayment, BitcoinError> {
    validate_header_chain(&proof.headers)?;
    let parsed = parse_transaction(&proof.raw_transaction)?;
    let root = merkle_root_from_branch(parsed.txid_internal, proof.tx_index, &proof.merkle_branch);
    if root != proof.headers[0].merkle_root_internal() {
        return Err(BitcoinError::BadMerkleProof);
    }
    let payment = parsed
        .outputs
        .get(proof.payment_output_index as usize)
        .ok_or(BitcoinError::PaymentOutputMissing)?;
    if payment.script_pubkey != treasury_script_pubkey {
        return Err(BitcoinError::WrongTreasuryScript);
    }
    if payment.value_sats < required_sats {
        return Err(BitcoinError::Underpayment);
    }
    let manifest = parsed
        .outputs
        .get(proof.manifest_output_index as usize)
        .ok_or(BitcoinError::ManifestOutputMissing)?;
    let expected_manifest_script = canonical_manifest_script(expected_manifest_hash);
    if manifest.value_sats != 0
        || manifest.script_pubkey.as_slice() != expected_manifest_script.as_slice()
    {
        return Err(BitcoinError::BadManifestCommitment);
    }
    let sixth = &proof.headers[REQUIRED_CONFIRMATIONS - 1];
    Ok(ValidatedBitcoinPayment {
        txid_internal: parsed.txid_internal,
        containing_block_hash_internal: proof.headers[0].hash_internal(),
        containing_block_height: proof.containing_block_height,
        sixth_confirmation_hash_internal: sixth.hash_internal(),
        sixth_confirmation_height: proof
            .containing_block_height
            .checked_add(REQUIRED_CONFIRMATIONS as u32 - 1)
            .ok_or(BitcoinError::ArithmeticOverflow)?,
        sixth_confirmation_timestamp: sixth.timestamp(),
        payment_output_index: proof.payment_output_index,
        paid_sats: payment.value_sats,
    })
}

pub fn mine_easy_header(
    previous_block_internal: [u8; 32],
    merkle_root_internal: [u8; 32],
    timestamp: u32,
    bits: u32,
    nonce_start: u32,
) -> Result<BitcoinHeader, BitcoinError> {
    let mut raw = [0u8; 80];
    raw[..4].copy_from_slice(&1i32.to_le_bytes());
    raw[4..36].copy_from_slice(&previous_block_internal);
    raw[36..68].copy_from_slice(&merkle_root_internal);
    raw[68..72].copy_from_slice(&timestamp.to_le_bytes());
    raw[72..76].copy_from_slice(&bits.to_le_bytes());
    let mut nonce = nonce_start;
    loop {
        raw[76..80].copy_from_slice(&nonce.to_le_bytes());
        let header = BitcoinHeader { raw };
        if header_meets_pow(&header)? {
            return Ok(header);
        }
        if nonce == u32::MAX {
            return Err(BitcoinError::FixtureMiningExhausted);
        }
        nonce = nonce.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compact(n: u64) -> Vec<u8> {
        if n < 0xfd {
            vec![n as u8]
        } else {
            panic!("fixture only")
        }
    }

    fn fixture_tx(manifest: [u8; 32], treasury_script: &[u8], value: u64, segwit: bool) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&2u32.to_le_bytes());
        if segwit {
            tx.extend_from_slice(&[0x00, 0x01]);
        }
        tx.extend_from_slice(&compact(1));
        tx.extend_from_slice(&[7u8; 32]);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.push(1);
        tx.push(0x51);
        tx.extend_from_slice(&0xffff_fffeu32.to_le_bytes());
        tx.extend_from_slice(&compact(2));
        tx.extend_from_slice(&value.to_le_bytes());
        tx.extend_from_slice(&compact(treasury_script.len() as u64));
        tx.extend_from_slice(treasury_script);
        tx.extend_from_slice(&0u64.to_le_bytes());
        let script = canonical_manifest_script(&manifest);
        tx.extend_from_slice(&compact(script.len() as u64));
        tx.extend_from_slice(&script);
        if segwit {
            tx.push(1);
            tx.push(1);
            tx.push(0x01);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    fn proof(manifest: [u8; 32], confirmations: usize) -> BitcoinSpvProofV1 {
        let treasury = [0x51u8];
        let raw_transaction = fixture_tx(manifest, &treasury, 4096, true);
        let parsed = parse_transaction(&raw_transaction).unwrap();
        let bits = 0x207f_ffff;
        let mut headers = Vec::new();
        let first =
            mine_easy_header([0u8; 32], parsed.txid_internal, 1_800_000_000, bits, 0).unwrap();
        headers.push(first);
        while headers.len() < confirmations {
            let prev = headers.last().unwrap().hash_internal();
            let marker = double_sha256(&(headers.len() as u64).to_le_bytes());
            let h = mine_easy_header(
                prev,
                marker,
                1_800_000_000 + headers.len() as u32 * 600,
                bits,
                0,
            )
            .unwrap();
            headers.push(h);
        }
        BitcoinSpvProofV1 {
            raw_transaction,
            payment_output_index: 0,
            manifest_output_index: 1,
            tx_index: 0,
            merkle_branch: vec![],
            headers,
            containing_block_height: 100,
        }
    }

    #[test]
    fn build53_segwit_txid_excludes_witness() {
        let manifest = [3u8; 32];
        let treasury = [0x51u8];
        let a = fixture_tx(manifest, &treasury, 4096, true);
        let mut b = a.clone();
        let witness_data_pos = b.len() - 5;
        b[witness_data_pos] ^= 0x55;
        assert_eq!(
            parse_transaction(&a).unwrap().txid_internal,
            parse_transaction(&b).unwrap().txid_internal
        );
    }

    #[test]
    fn build53_requires_six_confirmations() {
        let manifest = [4u8; 32];
        let p = proof(manifest, 5);
        assert_eq!(
            validate_payment(&p, &manifest, &[0x51], 2048).unwrap_err(),
            BitcoinError::InsufficientConfirmations
        );
    }

    #[test]
    fn build53_accepts_six_confirmation_spv_payment() {
        let manifest = [5u8; 32];
        let p = proof(manifest, 6);
        let v = validate_payment(&p, &manifest, &[0x51], 4096).unwrap();
        assert_eq!(v.paid_sats, 4096);
        assert_eq!(v.sixth_confirmation_height, 105);
    }

    #[test]
    fn build53_rejects_underpayment() {
        let manifest = [8u8; 32];
        let p = proof(manifest, 6);
        assert_eq!(
            validate_payment(&p, &manifest, &[0x51], 4097).unwrap_err(),
            BitcoinError::Underpayment
        );
    }

    #[test]
    fn build53_fixed_policy_rejects_untrusted_parent() {
        let manifest = [9u8; 32];
        let p = proof(manifest, 6);
        assert_eq!(
            validate_fixed_header_chain(&p.headers, &[0x55u8; 32], 0x207f_ffff).unwrap_err(),
            BitcoinError::UntrustedHeaderAnchor
        );
    }

    #[test]
    fn build53_manifest_commitment_is_exact_op_return_push32() {
        let manifest = [6u8; 32];
        let mut p = proof(manifest, 6);
        let n = p.raw_transaction.len();
        p.raw_transaction[n - 38] ^= 1;
        assert!(validate_payment(&p, &manifest, &[0x51], 2048).is_err());
    }

    #[test]
    fn build53_rejects_broken_header_link() {
        let manifest = [7u8; 32];
        let mut p = proof(manifest, 6);
        p.headers[3].raw[4] ^= 1;
        assert!(matches!(
            validate_payment(&p, &manifest, &[0x51], 2048),
            Err(BitcoinError::NonContiguousHeaders | BitcoinError::BadProofOfWork)
        ));
    }
    #[test]
    fn build54_anchor_context_requires_eleven_headers_and_retarget_boundary() {
        let manifest = [10u8; 32];
        let p = proof(manifest, 11);
        assert!(validate_anchor_context(&p.headers, &[0u8; 32], 0x207f_ffff, 806_400).is_ok());
        assert_eq!(
            validate_anchor_context(&p.headers[..10], &[0u8; 32], 0x207f_ffff, 806_400)
                .unwrap_err(),
            BitcoinError::BadAnchorContextLength
        );
        assert_eq!(
            validate_anchor_context(&p.headers, &[0u8; 32], 0x207f_ffff, 806_401).unwrap_err(),
            BitcoinError::AnchorNotRetargetBoundary
        );
    }

    #[test]
    fn build54_median_time_past_11_is_middle_timestamp() {
        let manifest = [11u8; 32];
        let p = proof(manifest, 11);
        assert_eq!(median_time_past_11(&p.headers).unwrap(), 1_800_003_000);
    }
}

#[cfg(test)]
mod pack_m_candidate3_mainnet_consensus_tests {
    use super::*;

    fn hex_bytes(text: &str) -> Vec<u8> {
        let compact = text.split_whitespace().collect::<String>();
        assert_eq!(compact.len() % 2, 0);
        (0..compact.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).unwrap())
            .collect()
    }

    fn h32(text: &str) -> [u8; 32] {
        hex_bytes(text).try_into().unwrap()
    }

    fn h80(text: &str) -> BitcoinHeader {
        BitcoinHeader {
            raw: hex_bytes(text).try_into().unwrap(),
        }
    }

    #[test]
    fn pack_m_candidate3_vector5_mainnet_genesis_pow_and_invalid_nonce() {
        let valid = h80(
            "0100000000000000000000000000000000000000000000000000000000000000
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa
             4b1e5e4a29ab5f49ffff001d1dac2b7c",
        );
        assert_eq!(valid.bits(), BITCOIN_MAINNET_POW_LIMIT_BITS);
        assert_eq!(
            valid.hash_display_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert!(header_meets_mainnet_pow(&valid).unwrap());

        let invalid = h80(
            "0100000000000000000000000000000000000000000000000000000000000000
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa
             4b1e5e4a29ab5f49ffff001d00000000",
        );
        assert_eq!(
            invalid.hash_display_hex(),
            "2bc1a7f50ab3c6d73bac757d75c7f35c6ba94de37339115abf4cb4a9983948bf"
        );
        assert!(!header_meets_mainnet_pow(&invalid).unwrap());
    }

    #[test]
    fn pack_m_candidate3_canonical_compact_and_powlimit_vectors() {
        let noncanonical = 0x0400_0123;
        let canonical = 0x0301_2300;
        let decoded = compact_target_be(noncanonical).unwrap();
        assert_eq!(compact_bits_from_target_be(decoded).unwrap(), canonical);
        assert!(canonical_compact_target_be(noncanonical).is_err());
        assert!(validate_mainnet_target_bits(noncanonical).is_err());
        assert!(validate_mainnet_target_bits(canonical).is_ok());

        assert!(validate_mainnet_target_bits(BITCOIN_MAINNET_POW_LIMIT_BITS).is_ok());
        assert!(validate_mainnet_target_bits(0x1d01_0000).is_err());
    }

    #[test]
    fn pack_m_candidate3_vectors7_and8_inherited_bits_and_exact_retarget() {
        assert_eq!(
            expected_mainnet_bits(1001, 0x1d00_ffff, 1_000_000_000, 1_000_604_800).unwrap(),
            0x1d00_ffff
        );
        assert_ne!(
            expected_mainnet_bits(1001, 0x1d00_ffff, 1_000_000_000, 1_000_604_800).unwrap(),
            0x1c7f_ff80
        );

        let exact =
            bitcoin_mainnet_retarget_bits(0x1d00_ffff, 1_000_000_000, 1_000_604_800).unwrap();
        assert_eq!(exact, 0x1c7f_ff80);
        assert_eq!(
            compact_target_be(exact).unwrap(),
            h32("000000007fff8000000000000000000000000000000000000000000000000000")
        );

        assert_eq!(
            bitcoin_mainnet_retarget_bits(0x1d00_ffff, 1_000_000_000, 1_000_000_001).unwrap(),
            0x1c3f_ffc0
        );
        assert_eq!(
            bitcoin_mainnet_retarget_bits(0x1d00_ffff, 1_000_000_000, 1_010_000_000).unwrap(),
            BITCOIN_MAINNET_POW_LIMIT_BITS
        );
    }

    #[test]
    fn pack_m_candidate3_vector9_mtp_is_strictly_greater_than_median() {
        let previous = [
            1000, 1600, 2200, 2800, 3400, 4000, 4600, 5200, 5800, 6400, 7000,
        ];
        assert_eq!(median_timestamp_11(&previous), 4000);
        assert_eq!(
            validate_mainnet_mtp(4000, &previous).unwrap_err(),
            BitcoinError::MedianTimePastViolation
        );
        assert!(validate_mainnet_mtp(4001, &previous).is_ok());
    }

    #[test]
    fn pack_m_candidate3_vector10_true_header_work_and_chainwork() {
        let work = bitcoin_header_work_be(0x207f_ffff).unwrap();
        assert_eq!(
            work,
            h32("0000000000000000000000000000000000000000000000000000000000000002")
        );

        let mut chainwork = [0u8; 32];
        for _ in 0..6 {
            chainwork = add_chainwork_be(&chainwork, &work).unwrap();
        }
        assert_eq!(
            chainwork,
            h32("000000000000000000000000000000000000000000000000000000000000000c")
        );

        for _ in 6..16 {
            chainwork = add_chainwork_be(&chainwork, &work).unwrap();
        }
        assert_eq!(
            chainwork,
            h32("0000000000000000000000000000000000000000000000000000000000000020")
        );
    }

    #[test]
    fn pack_m_candidate3_no_consensus_future_time_limit_is_intentional() {
        let previous = [
            1000, 1600, 2200, 2800, 3400, 4000, 4600, 5200, 5800, 6400, 7000,
        ];
        assert!(validate_mainnet_mtp(u32::MAX, &previous).is_ok());
    }
}
