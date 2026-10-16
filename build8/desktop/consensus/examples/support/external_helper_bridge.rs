//! QUALIFICATION TOOLING ONLY. Never linked into a shipping binary (the node does not include
//! this file; `consensus/tests/host_independence_guard.rs` checks that).
//!
//! A generic JSON-lines client for an external, operator-supplied TPM helper process used by the
//! pre-Genesis physical qualification example and the ignored physical campaign test. Every
//! host-specific value is EXPLICIT RUNTIME INPUT:
//! * a helper specification file (`HelperSpec`): the helper argv, whose first element is an
//!   absolute program path, and an optional SHA-256 pin of that program file;
//! * a custody manifest file (`ExpectedCustody`): the counter index, counter public hash,
//!   voting-key public hash and compressed voting key the helper must report;
//! * the expected initial counter, passed by the caller.
//! Nothing here confers admission, Bond or voting eligibility: the qualification run only signs
//! with a key the caller's own verifier set already commits to.
//!
//! Process context, deliberately different from production: the operator starts this tooling by
//! hand on the qualification host, and the helper is spawned with the operator's own ENVIRONMENT and
//! WORKING DIRECTORY, inherited, not cleared, because the helper may need them (for example its TPM
//! tool paths). The production channel (`node/src/tpm_backend.rs`) instead clears the environment,
//! runs in `/` and validates every helper file. Program checks here: `argv[0]` must be an absolute
//! path to a regular, non-symlink file; with a `program_sha256` pin it gets the SAME validation as
//! the production helper (`node/src/tpm_helper_policy.rs`, included below), Linux only. The further
//! argv elements are passed as given.
#![allow(dead_code)]
use mutiny_consensus_v8::{
    Hash, counter_store::MonotonicCounter, counter_voter::CounterSigningBackend,
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Component, Path},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

/// The production helper path policy, shared verbatim with the node (self-contained: std and sha2).
#[path = "../../../node/src/tpm_helper_policy.rs"]
mod tpm_helper_policy;

pub const HELPER_SCHEMA: &str = "BUILD8-QUALIFICATION-EXTERNAL-HELPER-V1";
pub const CUSTODY_SCHEMA: &str = "BUILD8-QUALIFICATION-EXTERNAL-HELPER-CUSTODY-V1";
const MAX_LINE: u64 = 65536;

fn read_json(path: &Path) -> Result<Value, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .take(MAX_LINE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_LINE {
        return Err(format!("{}: file too large", path.display()));
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
fn exact_fields(v: &Value, schema: &str, fields: &[&str]) -> Result<(), String> {
    let o = v.as_object().ok_or("JSON object required")?;
    if v["schema"] != schema || o.len() != fields.len() + 1 || fields.iter().any(|f| !o.contains_key(*f)) {
        return Err(format!("{schema}: exact fields schema, {}", fields.join(", ")));
    }
    Ok(())
}
fn hex32(v: &Value) -> Result<Hash, String> {
    hex::decode(v.as_str().ok_or("hex string required")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "32-byte hex value required".into())
}

/// How to start the helper. `argv[0]` must be an absolute path to a regular, non-symlink file.
pub struct HelperSpec {
    pub argv: Vec<String>,
    pub program_sha256: Option<Hash>,
}
impl HelperSpec {
    pub fn from_json(v: &Value) -> Result<Self, String> {
        exact_fields(v, HELPER_SCHEMA, &["argv", "program_sha256"])?;
        let argv = v["argv"]
            .as_array()
            .ok_or("argv array required")?
            .iter()
            .map(|a| a.as_str().map(str::to_owned).ok_or("argv strings required".to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let program_sha256 = if v["program_sha256"].is_null() {
            None
        } else {
            Some(hex32(&v["program_sha256"])?)
        };
        Ok(Self { argv, program_sha256 })
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::from_json(&read_json(path)?)
    }
    /// Program checks performed before any spawn (no shell is ever used). With a `program_sha256`
    /// pin, `argv[0]` gets the production helper validation (`tpm_helper_policy::check_program`: no
    /// `..`, `.` or empty component, no symlink in any component, a regular root-owned file in
    /// root-owned ancestors, no group/world write, no set-user-ID or set-group-ID bit, the pinned
    /// bytes; refused off Linux). Without a pin only the minimal check below applies.
    pub fn validate(&self) -> Result<(), String> {
        if self.argv.is_empty() || self.argv.len() > 32 {
            return Err("helper argv must have 1 to 32 elements".into());
        }
        let program = Path::new(&self.argv[0]);
        if let Some(pin) = self.program_sha256 {
            return tpm_helper_policy::check_program_on_host(program, Some(pin), false);
        }
        if !program.is_absolute()
            || program.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err("helper program must be an absolute path without '..' or '.'".into());
        }
        let m = std::fs::symlink_metadata(program).map_err(|e| e.to_string())?;
        if !m.file_type().is_file() {
            return Err("helper program must be a regular file, not a symlink".into());
        }
        Ok(())
    }
}

/// Public custody facts the helper's READY line must report exactly.
pub struct ExpectedCustody {
    pub counter_index: String,
    pub counter_public_sha256: Hash,
    pub voting_tpm_public_sha256: Hash,
    pub voting_public: [u8; 33],
}
impl ExpectedCustody {
    pub fn from_json(v: &Value) -> Result<Self, String> {
        exact_fields(
            v,
            CUSTODY_SCHEMA,
            &["counter_index", "counter_public_sha256", "voting_tpm_public_sha256", "voting_public"],
        )?;
        let counter_index = v["counter_index"].as_str().ok_or("counter_index string")?.to_owned();
        if counter_index.is_empty() || counter_index.len() > 32 {
            return Err("counter_index must be a short string".into());
        }
        Ok(Self {
            counter_index,
            counter_public_sha256: hex32(&v["counter_public_sha256"])?,
            voting_tpm_public_sha256: hex32(&v["voting_tpm_public_sha256"])?,
            voting_public: hex::decode(v["voting_public"].as_str().ok_or("voting_public hex")?)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "voting_public must be 33 bytes")?,
        })
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::from_json(&read_json(path)?)
    }
}

pub struct ExternalHelperBridge {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    pub manifest: Value,
    key: [u8; 33],
}
impl ExternalHelperBridge {
    pub fn open(
        spec: &HelperSpec,
        expected: &ExpectedCustody,
        initial_counter: Option<u64>,
    ) -> Result<Self, String> {
        spec.validate()?;
        let mut child = Command::new(&spec.argv[0])
            .args(&spec.argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| e.to_string())?;
        let input = child.stdin.take().ok_or("stdin")?;
        let mut output = BufReader::new(child.stdout.take().ok_or("stdout")?);
        let manifest = read(&mut output)?;
        let key: [u8; 33] = hex::decode(manifest["voting_public"].as_str().ok_or("public")?)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "public length")?;
        if manifest["result"] != "READY"
            || manifest["index"] != expected.counter_index.as_str()
            || manifest["counter_public_sha256"] != hex::encode(expected.counter_public_sha256)
            || manifest["voting_tpm_public_sha256"] != hex::encode(expected.voting_tpm_public_sha256)
            || key != expected.voting_public
            || initial_counter.is_some_and(|n| manifest["initial_counter"].as_u64() != Some(n))
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err("custody mismatch with the explicit custody manifest".into());
        }
        Ok(Self {
            child,
            input,
            output,
            manifest,
            key,
        })
    }
    /// Runtime inputs for the ignored physical test: BUILD8_QUALIFICATION_TPM_HELPER (helper
    /// specification file) and BUILD8_QUALIFICATION_TPM_CUSTODY_MANIFEST (custody manifest file).
    pub fn from_env(initial_counter: Option<u64>) -> Result<Self, String> {
        let var = |name: &str| {
            std::env::var(name).map_err(|_| format!("PHYSICAL QUALIFICATION INPUT MISSING: {name}"))
        };
        let spec = HelperSpec::load(Path::new(&var("BUILD8_QUALIFICATION_TPM_HELPER")?))?;
        let expected =
            ExpectedCustody::load(Path::new(&var("BUILD8_QUALIFICATION_TPM_CUSTODY_MANIFEST")?))?;
        Self::open(&spec, &expected, initial_counter)
    }
    fn request(&mut self, value: Value) -> Result<Value, String> {
        writeln!(self.input, "{value}").map_err(|e| e.to_string())?;
        self.input.flush().map_err(|e| e.to_string())?;
        let answer = read(&mut self.output)?;
        if answer["result"] != "PASS" {
            return Err(answer.to_string());
        }
        Ok(answer)
    }
    pub fn quote(&mut self, challenge: Hash) -> Result<Vec<u8>, String> {
        let answer =
            self.request(json!({"operation":"quote","challenge":hex::encode(challenge)}))?;
        let message =
            hex::decode(answer["message"].as_str().ok_or("message")?).map_err(|e| e.to_string())?;
        let signature = hex::decode(answer["signature"].as_str().ok_or("signature")?)
            .map_err(|e| e.to_string())?;
        mutiny_consensus_v8::tpm::encode_quote(&message, &signature).map_err(|e| format!("{e:?}"))
    }
}
fn read(output: &mut BufReader<ChildStdout>) -> Result<Value, String> {
    let mut line = Vec::new();
    Read::by_ref(output)
        .take(MAX_LINE + 1)
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    if line.is_empty() || line.len() as u64 > MAX_LINE {
        return Err("helper response bound/EOF".into());
    }
    serde_json::from_slice(&line).map_err(|e| e.to_string())
}
impl MonotonicCounter for ExternalHelperBridge {
    fn read(&mut self) -> Result<u64, String> {
        self.request(json!({"operation":"read"}))?["counter"]
            .as_u64()
            .ok_or("counter".into())
    }
    fn increment(&mut self) -> Result<(), String> {
        self.request(json!({"operation":"increment"}))?;
        Ok(())
    }
}
impl CounterSigningBackend for ExternalHelperBridge {
    fn public_key(&self) -> [u8; 33] {
        self.key
    }
    fn sign_digest(&mut self, digest: Hash) -> Result<[u8; 64], String> {
        let r = self.request(json!({"operation":"sign","digest":hex::encode(digest)}))?;
        hex::decode(r["signature"].as_str().ok_or("signature")?)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "signature length".into())
    }
}
impl Drop for ExternalHelperBridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
