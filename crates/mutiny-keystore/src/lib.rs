use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const MAGIC: &[u8; 8] = b"MUTKEYV1";
pub const VERSION: u16 = 1;
pub const FILE_LEN: usize = 152;
pub const WALLET_BACKUP_MAGIC: &[u8; 8] = b"MUTBKUP1";
pub const WATCH_WALLET_MAGIC: &[u8; 8] = b"MUTWATCH";
pub const WALLET_BACKUP_VERSION: u16 = 1;
pub const WATCH_WALLET_VERSION: u16 = 1;
const MAX_WALLET_ENTRIES: usize = 4096;
pub const PRODUCTION_MEMORY_KIB: u32 = 65_536;
pub const PRODUCTION_ITERATIONS: u32 = 3;
pub const PRODUCTION_PARALLELISM: u32 = 1;
const HEADER_LEN: usize = 88;
const AUTHENTICATED_LEN: usize = 120;
const MAX_MEMORY_KIB: u32 = 1_048_576;
const MAX_ITERATIONS: u32 = 10;
const MAX_PARALLELISM: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    NodeIdentity = 1,
    LicenseOwner = 2,
    LicenseMining = 3,
}

impl KeyRole {
    pub fn from_byte(v: u8) -> Result<Self, KeystoreError> {
        match v {
            1 => Ok(Self::NodeIdentity),
            2 => Ok(Self::LicenseOwner),
            3 => Ok(Self::LicenseMining),
            _ => Err(KeystoreError::BadRole),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::NodeIdentity => "node",
            Self::LicenseOwner => "owner",
            Self::LicenseMining => "mining",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub const PRODUCTION: Self = Self {
        memory_kib: PRODUCTION_MEMORY_KIB,
        iterations: PRODUCTION_ITERATIONS,
        parallelism: PRODUCTION_PARALLELISM,
    };

    fn validate(self) -> Result<(), KeystoreError> {
        if self.memory_kib < 8 || self.memory_kib > MAX_MEMORY_KIB {
            return Err(KeystoreError::BadKdfParams);
        }
        if self.iterations == 0 || self.iterations > MAX_ITERATIONS {
            return Err(KeystoreError::BadKdfParams);
        }
        if self.parallelism == 0 || self.parallelism > MAX_PARALLELISM {
            return Err(KeystoreError::BadKdfParams);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicMetadata {
    pub role: KeyRole,
    pub network_id: u32,
    pub params: KdfParams,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletBackupEntry {
    pub role: KeyRole,
    pub label: String,
    pub public_key: [u8; 32],
    pub secret_file: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchWalletEntry {
    pub role: KeyRole,
    pub label: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid Mutiny secret-file length")]
    BadLength,
    #[error("invalid Mutiny secret-file magic")]
    BadMagic,
    #[error("unsupported Mutiny secret-file version")]
    BadVersion,
    #[error("invalid Mutiny secret-file flags")]
    BadFlags,
    #[error("invalid key role")]
    BadRole,
    #[error("invalid or unsafe KDF parameters")]
    BadKdfParams,
    #[error("passphrase must contain at least 12 bytes")]
    WeakPassphrase,
    #[error("secret-file authentication failed")]
    AuthenticationFailed,
    #[error("secret-file key role mismatch")]
    RoleMismatch,
    #[error("secret-file NetworkID mismatch")]
    NetworkMismatch,
    #[error("decrypted seed does not match authenticated public key")]
    PublicKeyMismatch,
    #[error("secret file already exists")]
    AlreadyExists,
    #[error("unable to construct Argon2id parameters")]
    Argon2Params,
    #[error("Argon2id key derivation failed")]
    Argon2,
    #[error("invalid wallet backup format")]
    BadWalletBackup,
    #[error("invalid watch-wallet format")]
    BadWatchWallet,
    #[error("wallet backup/watch checksum mismatch")]
    BackupChecksumMismatch,
    #[error("wallet backup/watch key label is invalid")]
    BadWalletLabel,
    #[error("wallet backup/watch contains too many entries")]
    TooManyWalletEntries,
    #[error("wallet backup embedded key metadata mismatch")]
    BackupEntryMismatch,
}

fn read_u32(input: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(input[at..at + 4].try_into().expect("fixed-width slice"))
}

fn parse_metadata(bytes: &[u8]) -> Result<PublicMetadata, KeystoreError> {
    if bytes.len() != FILE_LEN {
        return Err(KeystoreError::BadLength);
    }
    if &bytes[..8] != MAGIC {
        return Err(KeystoreError::BadMagic);
    }
    if u16::from_be_bytes(bytes[8..10].try_into().unwrap()) != VERSION {
        return Err(KeystoreError::BadVersion);
    }
    let role = KeyRole::from_byte(bytes[10])?;
    if bytes[11] != 0 {
        return Err(KeystoreError::BadFlags);
    }
    let network_id = read_u32(bytes, 12);
    let params = KdfParams {
        memory_kib: read_u32(bytes, 16),
        iterations: read_u32(bytes, 20),
        parallelism: read_u32(bytes, 24),
    };
    params.validate()?;
    let public_key = bytes[56..88].try_into().unwrap();
    Ok(PublicMetadata {
        role,
        network_id,
        params,
        public_key,
    })
}

pub fn inspect(bytes: &[u8]) -> Result<PublicMetadata, KeystoreError> {
    parse_metadata(bytes)
}

fn derive_keys(
    passphrase: &[u8],
    salt: &[u8; 16],
    params: KdfParams,
) -> Result<[u8; 64], KeystoreError> {
    params.validate()?;
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(64),
    )
    .map_err(|_| KeystoreError::Argon2Params)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 64];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| KeystoreError::Argon2)?;
    Ok(out)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn le_u32(input: &[u8]) -> u32 {
    u32::from_le_bytes(input.try_into().unwrap())
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[0] = 0x6170_7865;
    initial[1] = 0x3320_646e;
    initial[2] = 0x7962_2d32;
    initial[3] = 0x6b20_6574;
    for i in 0..8 {
        initial[4 + i] = le_u32(&key[i * 4..i * 4 + 4]);
    }
    initial[12] = counter;
    initial[13] = le_u32(&nonce[0..4]);
    initial[14] = le_u32(&nonce[4..8]);
    initial[15] = le_u32(&nonce[8..12]);
    let mut working = initial;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(initial[i]).to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&word);
    }
    out
}

fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; input.len()];
    for (block_index, chunk) in input.chunks(64).enumerate() {
        let stream = chacha20_block(key, 1u32.wrapping_add(block_index as u32), nonce);
        let start = block_index * 64;
        for i in 0..chunk.len() {
            out[start + i] = chunk[i] ^ stream[i];
        }
    }
    out
}

fn seal_seed_with_material(
    seed: &[u8; 32],
    role: KeyRole,
    network_id: u32,
    passphrase: &[u8],
    params: KdfParams,
    salt: [u8; 16],
    nonce: [u8; 12],
) -> Result<Vec<u8>, KeystoreError> {
    if passphrase.len() < 12 {
        return Err(KeystoreError::WeakPassphrase);
    }
    params.validate()?;
    let public_key = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    let mut bytes = vec![0u8; FILE_LEN];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10] = role as u8;
    bytes[11] = 0;
    bytes[12..16].copy_from_slice(&network_id.to_be_bytes());
    bytes[16..20].copy_from_slice(&params.memory_kib.to_be_bytes());
    bytes[20..24].copy_from_slice(&params.iterations.to_be_bytes());
    bytes[24..28].copy_from_slice(&params.parallelism.to_be_bytes());
    bytes[28..44].copy_from_slice(&salt);
    bytes[44..56].copy_from_slice(&nonce);
    bytes[56..88].copy_from_slice(&public_key);

    let mut keys = derive_keys(passphrase, &salt, params)?;
    let encryption_key: [u8; 32] = keys[..32].try_into().unwrap();
    let ciphertext = chacha20_xor(&encryption_key, &nonce, seed);
    bytes[HEADER_LEN..AUTHENTICATED_LEN].copy_from_slice(&ciphertext);
    let tag = hmac_sha256(&keys[32..], &bytes[..AUTHENTICATED_LEN]);
    bytes[AUTHENTICATED_LEN..].copy_from_slice(&tag);
    keys.fill(0);
    Ok(bytes)
}

pub fn seal_seed(
    seed: &[u8; 32],
    role: KeyRole,
    network_id: u32,
    passphrase: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    seal_seed_with_material(
        seed,
        role,
        network_id,
        passphrase,
        KdfParams::PRODUCTION,
        salt,
        nonce,
    )
}

pub fn generate(
    role: KeyRole,
    network_id: u32,
    passphrase: &[u8],
) -> Result<(SigningKey, Vec<u8>), KeystoreError> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let bytes = seal_seed(&seed, role, network_id, passphrase)?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok((key, bytes))
}

pub fn open(
    bytes: &[u8],
    expected_role: KeyRole,
    expected_network_id: u32,
    passphrase: &[u8],
) -> Result<SigningKey, KeystoreError> {
    let metadata = parse_metadata(bytes)?;
    let salt: [u8; 16] = bytes[28..44].try_into().unwrap();
    let nonce: [u8; 12] = bytes[44..56].try_into().unwrap();
    let mut keys = derive_keys(passphrase, &salt, metadata.params)?;
    let expected_tag = hmac_sha256(&keys[32..], &bytes[..AUTHENTICATED_LEN]);
    if !ct_equal(&expected_tag, &bytes[AUTHENTICATED_LEN..]) {
        keys.fill(0);
        return Err(KeystoreError::AuthenticationFailed);
    }
    if metadata.role != expected_role {
        keys.fill(0);
        return Err(KeystoreError::RoleMismatch);
    }
    if metadata.network_id != expected_network_id {
        keys.fill(0);
        return Err(KeystoreError::NetworkMismatch);
    }
    let encryption_key: [u8; 32] = keys[..32].try_into().unwrap();
    let mut plain = chacha20_xor(
        &encryption_key,
        &nonce,
        &bytes[HEADER_LEN..AUTHENTICATED_LEN],
    );
    keys.fill(0);
    if plain.len() != 32 {
        plain.fill(0);
        return Err(KeystoreError::BadLength);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plain);
    plain.fill(0);
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    if key.verifying_key().to_bytes() != metadata.public_key {
        return Err(KeystoreError::PublicKeyMismatch);
    }
    Ok(key)
}

pub fn load_file(
    path: &Path,
    expected_role: KeyRole,
    expected_network_id: u32,
    passphrase: &[u8],
) -> Result<SigningKey, KeystoreError> {
    let bytes = fs::read(path)?;
    open(&bytes, expected_role, expected_network_id, passphrase)
}

pub fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), KeystoreError> {
    if path.exists() {
        return Err(KeystoreError::AlreadyExists);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let suffix = hex::encode(random);
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("secret.msk");
    let temp_name = format!(".{file_name}.{suffix}.tmp");
    let temp: PathBuf = path.with_file_name(temp_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(&temp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    match fs::hard_link(&temp, path) {
        Ok(()) => {
            fs::remove_file(&temp)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&temp);
            if path.exists() {
                Err(KeystoreError::AlreadyExists)
            } else {
                Err(e.into())
            }
        }
    }
}

fn wallet_label_valid(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn wallet_role_allowed(role: KeyRole) -> bool {
    matches!(role, KeyRole::LicenseOwner | KeyRole::LicenseMining)
}

fn wallet_sort_key(role: KeyRole, label: &str) -> (u8, &str) {
    (role as u8, label)
}

pub fn encode_wallet_backup(
    network_id: u32,
    entries: &[WalletBackupEntry],
) -> Result<Vec<u8>, KeystoreError> {
    if entries.len() > MAX_WALLET_ENTRIES || entries.len() > u16::MAX as usize {
        return Err(KeystoreError::TooManyWalletEntries);
    }
    let mut ordered = entries.to_vec();
    ordered
        .sort_by(|a, b| wallet_sort_key(a.role, &a.label).cmp(&wallet_sort_key(b.role, &b.label)));
    let mut previous: Option<(u8, String)> = None;
    let mut body = Vec::new();
    body.extend_from_slice(WALLET_BACKUP_MAGIC);
    body.extend_from_slice(&WALLET_BACKUP_VERSION.to_be_bytes());
    body.extend_from_slice(&network_id.to_be_bytes());
    body.extend_from_slice(&(ordered.len() as u16).to_be_bytes());
    for entry in &ordered {
        if !wallet_role_allowed(entry.role) || !wallet_label_valid(&entry.label) {
            return Err(KeystoreError::BadWalletLabel);
        }
        let meta = inspect(&entry.secret_file)?;
        if meta.role != entry.role
            || meta.network_id != network_id
            || meta.public_key != entry.public_key
        {
            return Err(KeystoreError::BackupEntryMismatch);
        }
        let key = (entry.role as u8, entry.label.clone());
        if previous.as_ref() == Some(&key) {
            return Err(KeystoreError::BadWalletBackup);
        }
        previous = Some(key);
        body.push(entry.role as u8);
        body.push(entry.label.len() as u8);
        body.extend_from_slice(entry.label.as_bytes());
        body.extend_from_slice(&entry.public_key);
        body.extend_from_slice(&entry.secret_file);
    }
    let checksum: [u8; 32] = Sha256::digest(&body).into();
    body.extend_from_slice(&checksum);
    Ok(body)
}

pub fn decode_wallet_backup(bytes: &[u8]) -> Result<(u32, Vec<WalletBackupEntry>), KeystoreError> {
    if bytes.len() < 8 + 2 + 4 + 2 + 32 {
        return Err(KeystoreError::BadWalletBackup);
    }
    let checksum_at = bytes.len() - 32;
    let expected: [u8; 32] = Sha256::digest(&bytes[..checksum_at]).into();
    if !ct_equal(&expected, &bytes[checksum_at..]) {
        return Err(KeystoreError::BackupChecksumMismatch);
    }
    if &bytes[..8] != WALLET_BACKUP_MAGIC {
        return Err(KeystoreError::BadWalletBackup);
    }
    if u16::from_be_bytes(bytes[8..10].try_into().unwrap()) != WALLET_BACKUP_VERSION {
        return Err(KeystoreError::BadWalletBackup);
    }
    let network_id = u32::from_be_bytes(bytes[10..14].try_into().unwrap());
    let count = u16::from_be_bytes(bytes[14..16].try_into().unwrap()) as usize;
    if count > MAX_WALLET_ENTRIES {
        return Err(KeystoreError::TooManyWalletEntries);
    }
    let mut at = 16usize;
    let mut entries = Vec::with_capacity(count);
    let mut previous: Option<(u8, String)> = None;
    for _ in 0..count {
        if at + 2 > checksum_at {
            return Err(KeystoreError::BadWalletBackup);
        }
        let role = KeyRole::from_byte(bytes[at])?;
        at += 1;
        if !wallet_role_allowed(role) {
            return Err(KeystoreError::BadWalletBackup);
        }
        let label_len = bytes[at] as usize;
        at += 1;
        if label_len == 0 || label_len > 64 || at + label_len + 32 + FILE_LEN > checksum_at {
            return Err(KeystoreError::BadWalletBackup);
        }
        let label = std::str::from_utf8(&bytes[at..at + label_len])
            .map_err(|_| KeystoreError::BadWalletLabel)?
            .to_string();
        at += label_len;
        if !wallet_label_valid(&label) {
            return Err(KeystoreError::BadWalletLabel);
        }
        let public_key: [u8; 32] = bytes[at..at + 32].try_into().unwrap();
        at += 32;
        let secret_file = bytes[at..at + FILE_LEN].to_vec();
        at += FILE_LEN;
        let key = (role as u8, label.clone());
        if let Some(prev) = &previous {
            if &key <= prev {
                return Err(KeystoreError::BadWalletBackup);
            }
        }
        previous = Some(key);
        let meta = inspect(&secret_file)?;
        if meta.role != role || meta.network_id != network_id || meta.public_key != public_key {
            return Err(KeystoreError::BackupEntryMismatch);
        }
        entries.push(WalletBackupEntry {
            role,
            label,
            public_key,
            secret_file,
        });
    }
    if at != checksum_at {
        return Err(KeystoreError::BadWalletBackup);
    }
    Ok((network_id, entries))
}

pub fn encode_watch_wallet(
    network_id: u32,
    entries: &[WatchWalletEntry],
) -> Result<Vec<u8>, KeystoreError> {
    if entries.len() > MAX_WALLET_ENTRIES || entries.len() > u16::MAX as usize {
        return Err(KeystoreError::TooManyWalletEntries);
    }
    let mut ordered = entries.to_vec();
    ordered
        .sort_by(|a, b| wallet_sort_key(a.role, &a.label).cmp(&wallet_sort_key(b.role, &b.label)));
    let mut previous: Option<(u8, String)> = None;
    let mut body = Vec::new();
    body.extend_from_slice(WATCH_WALLET_MAGIC);
    body.extend_from_slice(&WATCH_WALLET_VERSION.to_be_bytes());
    body.extend_from_slice(&network_id.to_be_bytes());
    body.extend_from_slice(&(ordered.len() as u16).to_be_bytes());
    for entry in &ordered {
        if !wallet_role_allowed(entry.role) || !wallet_label_valid(&entry.label) {
            return Err(KeystoreError::BadWalletLabel);
        }
        let key = (entry.role as u8, entry.label.clone());
        if previous.as_ref() == Some(&key) {
            return Err(KeystoreError::BadWatchWallet);
        }
        previous = Some(key);
        body.push(entry.role as u8);
        body.push(entry.label.len() as u8);
        body.extend_from_slice(entry.label.as_bytes());
        body.extend_from_slice(&entry.public_key);
    }
    let checksum: [u8; 32] = Sha256::digest(&body).into();
    body.extend_from_slice(&checksum);
    Ok(body)
}

pub fn decode_watch_wallet(bytes: &[u8]) -> Result<(u32, Vec<WatchWalletEntry>), KeystoreError> {
    if bytes.len() < 8 + 2 + 4 + 2 + 32 {
        return Err(KeystoreError::BadWatchWallet);
    }
    let checksum_at = bytes.len() - 32;
    let expected: [u8; 32] = Sha256::digest(&bytes[..checksum_at]).into();
    if !ct_equal(&expected, &bytes[checksum_at..]) {
        return Err(KeystoreError::BackupChecksumMismatch);
    }
    if &bytes[..8] != WATCH_WALLET_MAGIC {
        return Err(KeystoreError::BadWatchWallet);
    }
    if u16::from_be_bytes(bytes[8..10].try_into().unwrap()) != WATCH_WALLET_VERSION {
        return Err(KeystoreError::BadWatchWallet);
    }
    let network_id = u32::from_be_bytes(bytes[10..14].try_into().unwrap());
    let count = u16::from_be_bytes(bytes[14..16].try_into().unwrap()) as usize;
    if count > MAX_WALLET_ENTRIES {
        return Err(KeystoreError::TooManyWalletEntries);
    }
    let mut at = 16usize;
    let mut entries = Vec::with_capacity(count);
    let mut previous: Option<(u8, String)> = None;
    for _ in 0..count {
        if at + 2 > checksum_at {
            return Err(KeystoreError::BadWatchWallet);
        }
        let role = KeyRole::from_byte(bytes[at])?;
        at += 1;
        if !wallet_role_allowed(role) {
            return Err(KeystoreError::BadWatchWallet);
        }
        let label_len = bytes[at] as usize;
        at += 1;
        if label_len == 0 || label_len > 64 || at + label_len + 32 > checksum_at {
            return Err(KeystoreError::BadWatchWallet);
        }
        let label = std::str::from_utf8(&bytes[at..at + label_len])
            .map_err(|_| KeystoreError::BadWalletLabel)?
            .to_string();
        at += label_len;
        if !wallet_label_valid(&label) {
            return Err(KeystoreError::BadWalletLabel);
        }
        let public_key: [u8; 32] = bytes[at..at + 32].try_into().unwrap();
        at += 32;
        let key = (role as u8, label.clone());
        if let Some(prev) = &previous {
            if &key <= prev {
                return Err(KeystoreError::BadWatchWallet);
            }
        }
        previous = Some(key);
        entries.push(WatchWalletEntry {
            role,
            label,
            public_key,
        });
    }
    if at != checksum_at {
        return Err(KeystoreError::BadWatchWallet);
    }
    Ok((network_id, entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn build55_chacha20_matches_rfc8439_block_vector() {
        let key: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let nonce: [u8; 12] = h("000000090000004a00000000").try_into().unwrap();
        let block = chacha20_block(&key, 1, &nonce);
        assert_eq!(hex::encode(block), "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    }

    #[test]
    fn build55_hmac_sha256_matches_rfc4231_case1() {
        let key = vec![0x0b; 20];
        assert_eq!(
            hex::encode(hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn build55_argon2id_fixed_key_vector() {
        let salt: [u8; 16] = (0u8..16).collect::<Vec<_>>().try_into().unwrap();
        let params = KdfParams {
            memory_kib: 32,
            iterations: 2,
            parallelism: 1,
        };
        let keys = derive_keys(b"correct horse battery staple", &salt, params).unwrap();
        assert_eq!(hex::encode(keys), "7fd862b7d5a3c0526e371d556558e742944904409a04f91d162ad7a07f46d5138fad513b57cfcf1cc25e403595f698d91b31357e57064f063d0aa68c9fc9ae5b");
    }

    #[test]
    fn build55_fixed_secret_file_vector() {
        let seed: [u8; 32] = (0x20u8..0x40).collect::<Vec<_>>().try_into().unwrap();
        let salt: [u8; 16] = (0u8..16).collect::<Vec<_>>().try_into().unwrap();
        let nonce: [u8; 12] = (0x10u8..0x1c).collect::<Vec<_>>().try_into().unwrap();
        let params = KdfParams {
            memory_kib: 32,
            iterations: 2,
            parallelism: 1,
        };
        let bytes = seal_seed_with_material(
            &seed,
            KeyRole::NodeIdentity,
            0x4d555403,
            b"correct horse battery staple",
            params,
            salt,
            nonce,
        )
        .unwrap();
        assert_eq!(hex::encode(bytes), "4d55544b45595631000101004d555403000000200000000200000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd73b9adbfae670d1a35e3ae3b3ddc7e3a72bbd447aa7de2910be4616ecdf2d7d3e58d187748481e0a70e3f9e0c0694e86d3179f281d9b9d9d2165ee538e91ec791");
    }

    #[test]
    fn build55_wrong_passphrase_and_tamper_fail_authentication() {
        let seed = [7u8; 32];
        let salt = [9u8; 16];
        let nonce = [11u8; 12];
        let params = KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        };
        let mut bytes = seal_seed_with_material(
            &seed,
            KeyRole::NodeIdentity,
            7,
            b"abcdefghijkl",
            params,
            salt,
            nonce,
        )
        .unwrap();
        assert!(matches!(
            open(&bytes, KeyRole::NodeIdentity, 7, b"abcdefghijklX"),
            Err(KeystoreError::AuthenticationFailed)
        ));
        bytes[91] ^= 0x80;
        assert!(matches!(
            open(&bytes, KeyRole::NodeIdentity, 7, b"abcdefghijkl"),
            Err(KeystoreError::AuthenticationFailed)
        ));
    }

    #[test]
    fn build55_role_and_network_are_authenticated_and_enforced() {
        let seed = [8u8; 32];
        let bytes = seal_seed_with_material(
            &seed,
            KeyRole::LicenseOwner,
            9,
            b"abcdefghijkl",
            KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            [3u8; 16],
            [4u8; 12],
        )
        .unwrap();
        assert!(matches!(
            open(&bytes, KeyRole::LicenseMining, 9, b"abcdefghijkl"),
            Err(KeystoreError::RoleMismatch)
        ));
        assert!(matches!(
            open(&bytes, KeyRole::LicenseOwner, 10, b"abcdefghijkl"),
            Err(KeystoreError::NetworkMismatch)
        ));
    }

    #[test]
    fn build55_public_key_mismatch_is_detected_even_with_valid_mac() {
        let seed = [5u8; 32];
        let params = KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        };
        let salt = [6u8; 16];
        let nonce = [7u8; 12];
        let mut bytes = seal_seed_with_material(
            &seed,
            KeyRole::LicenseMining,
            11,
            b"abcdefghijkl",
            params,
            salt,
            nonce,
        )
        .unwrap();
        bytes[56] ^= 1;
        let mut keys = derive_keys(b"abcdefghijkl", &salt, params).unwrap();
        let tag = hmac_sha256(&keys[32..], &bytes[..AUTHENTICATED_LEN]);
        bytes[AUTHENTICATED_LEN..].copy_from_slice(&tag);
        keys.fill(0);
        assert!(matches!(
            open(&bytes, KeyRole::LicenseMining, 11, b"abcdefghijkl"),
            Err(KeystoreError::PublicKeyMismatch)
        ));
    }

    #[test]
    fn build55_file_length_and_kdf_caps_are_strict() {
        assert!(matches!(
            inspect(&[0u8; FILE_LEN - 1]),
            Err(KeystoreError::BadLength)
        ));
        let seed = [1u8; 32];
        let mut bytes = seal_seed_with_material(
            &seed,
            KeyRole::NodeIdentity,
            1,
            b"abcdefghijkl",
            KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            [1u8; 16],
            [2u8; 12],
        )
        .unwrap();
        bytes[16..20].copy_from_slice(&(MAX_MEMORY_KIB + 1).to_be_bytes());
        assert!(matches!(inspect(&bytes), Err(KeystoreError::BadKdfParams)));
    }

    fn build57_secret(seed_byte: u8, role: KeyRole, network_id: u32) -> Vec<u8> {
        seal_seed_with_material(
            &[seed_byte; 32],
            role,
            network_id,
            b"abcdefghijkl",
            KdfParams {
                memory_kib: 32,
                iterations: 1,
                parallelism: 1,
            },
            [seed_byte.wrapping_add(1); 16],
            [seed_byte.wrapping_add(2); 12],
        )
        .unwrap()
    }

    #[test]
    fn build57_wallet_backup_is_deterministic_sorted_and_roundtrips() {
        let network = 0x4d555403;
        let owner_file = build57_secret(0x21, KeyRole::LicenseOwner, network);
        let mining_file = build57_secret(0x31, KeyRole::LicenseMining, network);
        let owner_pk = inspect(&owner_file).unwrap().public_key;
        let mining_pk = inspect(&mining_file).unwrap().public_key;
        let entries = vec![
            WalletBackupEntry {
                role: KeyRole::LicenseMining,
                label: "z-miner".into(),
                public_key: mining_pk,
                secret_file: mining_file,
            },
            WalletBackupEntry {
                role: KeyRole::LicenseOwner,
                label: "a-owner".into(),
                public_key: owner_pk,
                secret_file: owner_file,
            },
        ];
        assert_eq!(
            hex::encode(owner_pk),
            "884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b"
        );
        assert_eq!(
            hex::encode(mining_pk),
            "48075a597e721a156e2e0799de5cc0c5324dc6e7eaf1cdd46250868ec53215dd"
        );
        let a = encode_wallet_backup(network, &entries).unwrap();
        let b = encode_wallet_backup(network, &entries.iter().cloned().rev().collect::<Vec<_>>())
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 434);
        assert_eq!(
            hex::encode(Sha256::digest(&a)),
            "afd19650bad09f443743d854a29cbd44d757ce22de02103a1cc0790891c0ebe6"
        );
        assert_eq!(
            hex::encode(&a[a.len() - 32..]),
            "d9530466748e8fc78f72926e32101a9cccb5338c7f22f74dafb0cc9ad68ab82f"
        );
        let (decoded_network, decoded) = decode_wallet_backup(&a).unwrap();
        assert_eq!(decoded_network, network);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].role, KeyRole::LicenseOwner);
        assert_eq!(decoded[0].label, "a-owner");
        assert_eq!(decoded[1].role, KeyRole::LicenseMining);
        assert_eq!(decoded[1].label, "z-miner");
    }

    #[test]
    fn build57_wallet_backup_checksum_and_metadata_tamper_are_rejected() {
        let network = 7;
        let file = build57_secret(0x41, KeyRole::LicenseOwner, network);
        let pk = inspect(&file).unwrap().public_key;
        let entry = WalletBackupEntry {
            role: KeyRole::LicenseOwner,
            label: "owner1".into(),
            public_key: pk,
            secret_file: file,
        };
        let mut bytes = encode_wallet_backup(network, &[entry]).unwrap();
        bytes[20] ^= 1;
        assert!(matches!(
            decode_wallet_backup(&bytes),
            Err(KeystoreError::BackupChecksumMismatch)
        ));

        let file = build57_secret(0x41, KeyRole::LicenseOwner, network);
        let mut bad_pk = inspect(&file).unwrap().public_key;
        bad_pk[0] ^= 1;
        let bad = WalletBackupEntry {
            role: KeyRole::LicenseOwner,
            label: "owner1".into(),
            public_key: bad_pk,
            secret_file: file,
        };
        assert!(matches!(
            encode_wallet_backup(network, &[bad]),
            Err(KeystoreError::BackupEntryMismatch)
        ));
    }

    #[test]
    fn build57_watch_wallet_has_no_secret_bytes_and_roundtrips() {
        let network = 0x4d555403;
        let owner_pk: [u8; 32] =
            hex::decode("884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b")
                .unwrap()
                .try_into()
                .unwrap();
        let mining_pk: [u8; 32] =
            hex::decode("48075a597e721a156e2e0799de5cc0c5324dc6e7eaf1cdd46250868ec53215dd")
                .unwrap()
                .try_into()
                .unwrap();
        let owner = WatchWalletEntry {
            role: KeyRole::LicenseOwner,
            label: "a-owner".into(),
            public_key: owner_pk,
        };
        let mining = WatchWalletEntry {
            role: KeyRole::LicenseMining,
            label: "z-miner".into(),
            public_key: mining_pk,
        };
        let bytes = encode_watch_wallet(network, &[mining.clone(), owner.clone()]).unwrap();
        assert_eq!(bytes.len(), 130);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "eedc15578460b71dd55d957153628833f4c49c29e9d163332ba3a6b8305c92c0"
        );
        assert_eq!(
            hex::encode(&bytes[bytes.len() - 32..]),
            "bf76b21741f9e6a2d39c507e81cdcae22905fade3edb57c84ed2ead080e51bfe"
        );
        let (decoded_network, decoded) = decode_watch_wallet(&bytes).unwrap();
        assert_eq!(decoded_network, network);
        assert_eq!(decoded, vec![owner, mining]);
    }

    #[test]
    fn build57_watch_wallet_tamper_and_duplicate_labels_are_rejected() {
        let network = 9;
        let entry = WatchWalletEntry {
            role: KeyRole::LicenseOwner,
            label: "same".into(),
            public_key: [3u8; 32],
        };
        assert!(matches!(
            encode_watch_wallet(network, &[entry.clone(), entry.clone()]),
            Err(KeystoreError::BadWatchWallet)
        ));
        let mut bytes = encode_watch_wallet(network, &[entry]).unwrap();
        bytes[17] ^= 1;
        assert!(matches!(
            decode_watch_wallet(&bytes),
            Err(KeystoreError::BackupChecksumMismatch)
        ));
    }
}
