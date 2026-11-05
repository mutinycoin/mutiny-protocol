//! TEST-VALUE rehearsal key tooling for the D2 Treasury ceremony rehearsal.
//!
//! SIMULATED / TEST-VALUE ONLY. Compiled only with `wallet-custody` (or in this crate's own
//! tests); never part of a node or validator build. It creates, restores and signs with
//! disposable generation-1 / generation-2 `WalletOwner` rehearsal credentials through the
//! existing hybrid wallet APIs. It has no production mode and refuses one by name.
//!
//! Secret discipline:
//! - The tool never writes a phrase, seed or private key to stdout, stderr or any log.
//! - Public output is a JSON text of public data only, stamped TEST-VALUE.
//! - A phrase is written only to an explicitly named operator path ending in
//!   `.test-value-backup` (OS-entropy mode requires one), created with `create_new`, under a loud
//!   TEST-VALUE header. Automated tests use temp directories and delete them.
//! - Labelled-seed mode is deterministic for CI: the phrase is a PUBLIC function of a public
//!   label, so such keys are public by construction and are TEST-VALUE only.
//! - Only `Role::WalletOwner` is exposed; the `WalletRecovery` role of the same phrase is refused.
use crate::{HybridKey, Role, create_wallet_phrase, treasury_proof_v1 as proof};
use sha2::{Digest, Sha256};
use std::io::Write;
use zeroize::Zeroizing;

pub const SCHEMA: &str = "MUTINY-D2-REHEARSAL-KEY-PUBLIC-V1";
pub const CLASS_NAME: &str = "TEST-VALUE";
pub const EVIDENCE_LABEL: &str = "SIMULATED-REHEARSAL-NOT-PRODUCTION";
pub const BACKUP_HEADER: &str = "# TEST-VALUE REHEARSAL BACKUP - NOT A PRODUCTION SECRET - SIMULATED EVIDENCE ONLY";
pub const BACKUP_SUFFIX: &str = ".test-value-backup";
const LABEL_DOMAIN: &[u8] = b"MUTINY-BUILD8-TREASURY-REHEARSAL-TEST-VALUE-LABEL-V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Phrase is a public function of a public label. Public by construction.
    LabelledSeed,
    OsEntropy,
}
impl Origin {
    pub fn name(self) -> &'static str {
        match self {
            Self::LabelledSeed => "LABELLED-SEED-PUBLICLY-DERIVABLE",
            Self::OsEntropy => "OS-ENTROPY",
        }
    }
}

/// A rehearsal credential: a wallet-owner key stamped with a key version (generation).
pub struct Credential {
    key: HybridKey,
    generation: u64,
    origin: Origin,
}

fn valid_label(label: &str) -> bool {
    (4..=64).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Deterministic TEST-VALUE phrase for CI: 24 words from SHA-256(domain || label).
/// The result is a function of a public label and is never a production secret.
pub fn label_phrase(label: &str) -> crate::Result<Zeroizing<String>> {
    if !valid_label(label) {
        return Err(crate::Error::Mnemonic);
    }
    let mut h = Sha256::new();
    h.update(LABEL_DOMAIN);
    h.update(label.as_bytes());
    let entropy = Zeroizing::new(<[u8; 32]>::from(h.finalize()));
    let m = bip39::Mnemonic::from_entropy(entropy.as_ref()).map_err(|_| crate::Error::Mnemonic)?;
    Ok(Zeroizing::new(m.to_string()))
}

impl Credential {
    fn from_phrase(phrase: &str, generation: u64, origin: Origin) -> crate::Result<Self> {
        if !(1..=2).contains(&generation) {
            return Err(crate::Error::Role);
        }
        let key = HybridKey::wallet_restore(phrase, Role::WalletOwner)?;
        Ok(Self { key, generation, origin })
    }
    pub fn from_label(label: &str, generation: u64) -> crate::Result<Self> {
        Self::from_phrase(&label_phrase(label)?, generation, Origin::LabelledSeed)
    }
    pub fn key(&self) -> &HybridKey {
        &self.key
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn origin(&self) -> Origin {
        self.origin
    }
    pub fn descriptor(&self) -> crate::Result<Vec<u8>> {
        self.key.public().descriptor(self.generation)
    }
    /// SHA-256 over both public key halves, independent of generation (denylist identity).
    pub fn key_sha256(&self) -> [u8; 32] {
        public_key_sha256(self.key.public())
    }
    /// Public data only, stamped TEST-VALUE. Deterministic text.
    pub fn public_json(&self) -> crate::Result<String> {
        let descriptor = self.descriptor()?;
        let address = self.key.public().address_id(self.generation)?;
        Ok(format!(
            "{{\n  \"schema\": \"{SCHEMA}\",\n  \"class\": \"{CLASS_NAME}\",\n  \"class_byte\": {},\n  \"evidence\": \"{EVIDENCE_LABEL}\",\n  \"labels\": \"Implemented != Qualified; Offline != Physical; TEST-VALUE != production\",\n  \"role\": \"WalletOwner\",\n  \"generation\": {},\n  \"origin\": \"{}\",\n  \"descriptor_hex\": \"{}\",\n  \"descriptor_sha256\": \"{}\",\n  \"address_id\": \"{}\",\n  \"key_sha256\": \"{}\"\n}}\n",
            proof::CLASS_TEST_VALUE,
            self.generation,
            self.origin.name(),
            hex(&descriptor),
            hex(&proof::sha256(&descriptor)),
            hex(&address),
            hex(&self.key_sha256()),
        ))
    }
}

pub fn public_key_sha256(public: &crate::PublicKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(public.ed448);
    h.update(public.fndsa);
    h.finalize().into()
}
pub fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if t.len() % 2 != 0 || !t.is_ascii() {
        return None;
    }
    (0..t.len() / 2).map(|i| u8::from_str_radix(&t[2 * i..2 * i + 2], 16).ok()).collect()
}

fn backup_text(phrase: &str, generation: u64) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{BACKUP_HEADER}\n# This phrase controls a disposable rehearsal key (generation {generation}). Delete this file when the rehearsal ends.\ngeneration={generation}\n{phrase}\n"
    ))
}
fn read_backup(path: &str, generation: u64) -> Result<Zeroizing<String>, &'static str> {
    if !path.ends_with(BACKUP_SUFFIX) {
        return Err("backup path must end in .test-value-backup");
    }
    let raw = Zeroizing::new(std::fs::read_to_string(path).map_err(|_| "backup file unreadable")?);
    let mut lines = raw.lines();
    if lines.next() != Some(BACKUP_HEADER) {
        return Err("not a TEST-VALUE rehearsal backup");
    }
    let _note = lines.next();
    if lines.next() != Some(format!("generation={generation}").as_str()) {
        return Err("backup generation mismatch");
    }
    let phrase = lines.next().ok_or("backup truncated")?;
    Ok(Zeroizing::new(phrase.to_string()))
}

fn create_new_file(path: &str, bytes: &[u8]) -> Result<(), &'static str> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "refusing to overwrite or create file")?;
    f.write_all(bytes).map_err(|_| "write failed")?;
    f.sync_all().map_err(|_| "sync failed")
}
/// Create the file, or accept an existing file only if it is byte-identical (safe retry).
fn create_or_identical(path: &str, bytes: &[u8]) -> Result<(), &'static str> {
    match std::fs::read(path) {
        Ok(existing) if existing == bytes => Ok(()),
        Ok(_) => Err("existing file differs; refusing to overwrite"),
        Err(_) => create_new_file(path, bytes),
    }
}

struct Args {
    values: Vec<(String, String)>,
    flags: Vec<String>,
}
impl Args {
    fn parse(raw: &[String], valued: &[&str], boolean: &[&str]) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut flags = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            let a = raw[i].as_str();
            if boolean.contains(&a) {
                flags.push(a.to_string());
                i += 1;
            } else if valued.contains(&a) {
                let v = raw.get(i + 1).ok_or_else(|| format!("{a} needs a value"))?;
                if values.iter().any(|(k, _)| k == a) {
                    return Err(format!("{a} given twice"));
                }
                values.push((a.to_string(), v.clone()));
                i += 2;
            } else {
                return Err(format!("unknown argument {a}"));
            }
        }
        Ok(Self { values, flags })
    }
    fn get(&self, key: &str) -> Option<&str> {
        self.values.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
    fn has(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }
}

const USAGE: &str = "TEST-VALUE rehearsal key tool (SIMULATED, not production)\n\
  keygen --generation <1|2> --out-dir <dir> (--label <public-label> | --os-entropy --backup-file <path>.test-value-backup)\n\
  restore-check --generation <1|2> (--label <l> | --backup-file <path>.test-value-backup) --expect-descriptor-file <file>\n\
  sign --generation <1|2> (--label <l> | --backup-file <path>.test-value-backup) --challenge-file <file> --out <file>\n";

fn credential(args: &Args, generation: u64) -> Result<(Credential, Option<Zeroizing<String>>), String> {
    match (args.get("--label"), args.get("--backup-file"), args.has("--os-entropy")) {
        (Some(label), None, false) => Credential::from_label(label, generation)
            .map(|c| (c, None))
            .map_err(|_| "invalid label or generation".to_string()),
        (None, Some(path), false) => {
            let phrase = read_backup(path, generation).map_err(|e| e.to_string())?;
            let c = Credential::from_phrase(&phrase, generation, Origin::OsEntropy)
                .map_err(|_| "backup does not restore".to_string())?;
            Ok((c, None))
        }
        _ => Err("choose exactly one of --label or --backup-file".to_string()),
    }
}

/// Command line entry point. Writes public text to `out`, short error text to `err`. Returns the
/// process exit code: 0 success, 1 failure, 2 usage or refusal.
pub fn run(raw: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let refuse = |err: &mut dyn Write, msg: &str| -> i32 {
        let _ = writeln!(err, "REFUSED: {msg}");
        2
    };
    // No production mode exists. Refuse any attempt by name before anything else happens.
    if raw.iter().any(|a| {
        let l = a.to_ascii_lowercase();
        l == "--production" || l == "production" || l == "--class" || l == "--wallet-recovery" || l.contains("recovery-role")
    }) {
        return refuse(err, "this tool is TEST-VALUE rehearsal only; there is no production mode and no recovery role");
    }
    let Some((cmd, rest)) = raw.split_first() else {
        let _ = write!(err, "{USAGE}");
        return 2;
    };
    let parsed = |valued: &[&str], boolean: &[&str]| Args::parse(rest, valued, boolean);
    let generation_of = |a: &Args| a.get("--generation").and_then(|g| g.parse::<u64>().ok()).filter(|g| (1..=2).contains(g));
    match cmd.as_str() {
        "keygen" => {
            let a = match parsed(&["--generation", "--out-dir", "--label", "--backup-file"], &["--os-entropy"]) {
                Ok(a) => a,
                Err(e) => return refuse(err, &e),
            };
            let (Some(generation), Some(dir)) = (generation_of(&a), a.get("--out-dir")) else {
                return refuse(err, "keygen needs --generation 1|2 and --out-dir");
            };
            let credential = match (a.get("--label"), a.has("--os-entropy"), a.get("--backup-file")) {
                (Some(label), false, None) => match Credential::from_label(label, generation) {
                    Ok(c) => c,
                    Err(_) => return refuse(err, "invalid label"),
                },
                (None, true, Some(path)) => {
                    if !path.ends_with(BACKUP_SUFFIX) {
                        return refuse(err, "backup path must end in .test-value-backup");
                    }
                    let phrase = match create_wallet_phrase() {
                        Ok(p) => p,
                        Err(_) => return refuse(err, "entropy unavailable"),
                    };
                    let c = match Credential::from_phrase(&phrase, generation, Origin::OsEntropy) {
                        Ok(c) => c,
                        Err(_) => return refuse(err, "key creation failed"),
                    };
                    // The only place a phrase is ever written: the named TEST-VALUE backup file.
                    if let Err(e) = create_new_file(path, backup_text(&phrase, generation).as_bytes()) {
                        return refuse(err, e);
                    }
                    c
                }
                _ => return refuse(err, "use --label, or --os-entropy together with --backup-file"),
            };
            let (json, descriptor) = match (credential.public_json(), credential.descriptor()) {
                (Ok(j), Ok(d)) => (j, d),
                _ => return refuse(err, "descriptor failed"),
            };
            let base = format!("{dir}/key-g{generation}");
            if !std::path::Path::new(dir).is_dir() {
                return refuse(err, "--out-dir must be an existing directory");
            }
            // Retry-safe: identical labelled output may be rewritten; anything different is refused.
            let json_path = format!("{base}.public.json");
            let hex_path = format!("{base}.descriptor.hex");
            for (path, bytes) in [(&json_path, json.clone().into_bytes()), (&hex_path, (hex(&descriptor) + "\n").into_bytes())] {
                if let Err(e) = create_or_identical(path, &bytes) {
                    return refuse(err, e);
                }
            }
            let _ = writeln!(
                out,
                "{CLASS_NAME} rehearsal key generation {generation} ({}) - {EVIDENCE_LABEL}\ndescriptor_sha256 {}\npublic files {json_path} {hex_path}",
                credential.origin().name(),
                hex(&proof::sha256(&descriptor))
            );
            0
        }
        "restore-check" => {
            let a = match parsed(&["--generation", "--label", "--backup-file", "--expect-descriptor-file"], &[]) {
                Ok(a) => a,
                Err(e) => return refuse(err, &e),
            };
            let (Some(generation), Some(expected)) = (generation_of(&a), a.get("--expect-descriptor-file")) else {
                return refuse(err, "restore-check needs --generation and --expect-descriptor-file");
            };
            let (credential, _) = match credential(&a, generation) {
                Ok(c) => c,
                Err(e) => return refuse(err, &e),
            };
            let expected = std::fs::read_to_string(expected).ok().and_then(|t| unhex(&t));
            let actual = credential.descriptor().ok();
            if expected.is_some() && expected == actual {
                let _ = writeln!(out, "{CLASS_NAME} restore-check PASS generation {generation}: restored descriptor is byte-identical");
                0
            } else {
                let _ = writeln!(err, "FAIL: restored descriptor differs from the expected descriptor");
                1
            }
        }
        "sign" => {
            let a = match parsed(&["--generation", "--label", "--backup-file", "--challenge-file", "--out"], &[]) {
                Ok(a) => a,
                Err(e) => return refuse(err, &e),
            };
            let (Some(generation), Some(cfile), Some(outfile)) = (generation_of(&a), a.get("--challenge-file"), a.get("--out")) else {
                return refuse(err, "sign needs --generation, --challenge-file and --out");
            };
            let (credential, _) = match credential(&a, generation) {
                Ok(c) => c,
                Err(e) => return refuse(err, &e),
            };
            let challenge_bytes = match std::fs::read_to_string(cfile).ok().and_then(|t| unhex(&t)) {
                Some(b) => b,
                None => return refuse(err, "challenge file unreadable"),
            };
            let challenge = match proof::Challenge::decode(&challenge_bytes) {
                Ok(c) => c,
                Err(_) => return refuse(err, "challenge is malformed"),
            };
            let descriptor = match credential.descriptor() {
                Ok(d) => d,
                Err(_) => return 1,
            };
            let signature = match proof::sign_challenge(credential.key(), &descriptor, &challenge) {
                Ok(s) => s,
                Err(proof::ProofError::ProductionRefused) => return refuse(err, "production proofs cannot be signed while PRODUCTION_SECURITY_QUALIFIED is false"),
                Err(e) => return refuse(err, &format!("challenge does not match this credential ({e:?})")),
            };
            // A signature is randomized; never silently replace an existing one.
            if let Err(e) = create_new_file(outfile, (hex(&proof::signature_to_bytes(&signature)) + "\n").as_bytes()) {
                return refuse(err, e);
            }
            let _ = writeln!(out, "{CLASS_NAME} proof signed, generation {generation}, both components, file {outfile}");
            0
        }
        _ => {
            let _ = write!(err, "{USAGE}");
            2
        }
    }
}
