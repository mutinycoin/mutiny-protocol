//! Bounded, host-local production custody channel. It cannot initialize/reset NV.
//!
//! The helper process is EXPLICIT RUNTIME CONFIGURATION (`HelperConfig`, the `tpm_helper`
//! object of the production `physical_voter` configuration). No host alias, helper path,
//! counter index or public pin is compiled into this library. The configuration only selects
//! how this process reaches its own custody channel: it never confers admission, Bond or voting
//! eligibility. Every value it pins can only make startup FAIL (narrowing invariant); the voting
//! key pin is taken from the consensus-derived `PhysicalMember`, never the reverse.
use crate::participation_producer::ParticipationSigner;
use mutiny_consensus_v8::{
    Hash, counter_store::MonotonicCounter, counter_voter::CounterSigningBackend,
    freshness::AttestationRefresh, participation::ParticipationAck,
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const MAX_REPLY: u64 = 65536;
const DEADLINE: Duration = Duration::from_secs(35);
/// The only argument this process ever appends to the configured helper files. It is fixed:
/// the configuration cannot add flags, a shell string or another protocol.
pub const PROTOCOL_ARGUMENT: &str = "serve-network";
/// Absolute privilege wrapper, used only when the configuration says `"privilege":"sudo-n"`.
pub const SUDO: &str = "/usr/bin/sudo";
const MAX_HELPER_FILES: usize = 4;
#[derive(Clone)]
pub struct Pins {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub node: Hash,
    pub voting_key: [u8; 33],
    pub counter_index: u32,
    pub counter_public_sha256: Hash,
    pub custody_manifest_sha256: Hash,
}
fn bytes<const N: usize>(v: &Value) -> Result<[u8; N]> {
    hex::decode(v.as_str().ok_or("TPM public field missing")?)
        .map_err(|_| "TPM public field hex")?
        .try_into()
        .map_err(|_| "TPM public field length".into())
}
impl Pins {
    fn verify(&self, hello: &Value) -> Result<u64> {
        use sha2::{Digest, Sha256};
        if hello["result"] != "READY" || hello["schema"] != "BUILD8-PRODUCTION-TPM-CHANNEL-V1" {
            return Err("Production TPM channel not ready".into());
        }
        let raw = hex::decode(
            hello["manifest_hex"]
                .as_str()
                .ok_or("TPM custody manifest missing")?,
        )
        .map_err(|_| "TPM manifest hex")?;
        if raw.len() > 16384 || Sha256::digest(&raw)[..] != self.custody_manifest_sha256 {
            return Err("TPM custody manifest pin mismatch".into());
        }
        let m: Value = serde_json::from_slice(&raw).map_err(|_| "TPM custody manifest JSON")?;
        if m["schema"] != "BUILD8-PRODUCTION-TPM-CUSTODY-V1"
            || m["actual_genesis"] != true
            || m["qualification_retired"] != true
            || m["genesis_counter"].as_u64().is_none_or(|n| n == 0)
            || bytes::<32>(&m["retired_voter_journal_sha256"])? == [0; 32]
            || bytes::<32>(&m["genesis_id"])? != self.genesis
            || bytes::<32>(&m["protocol_fingerprint"])? != self.fingerprint
            || bytes::<32>(&m["node_id"])? != self.node
            || bytes::<33>(&m["voting_public"])? != self.voting_key
            || m["counter_index"].as_u64() != Some(u64::from(self.counter_index))
            || bytes::<32>(&m["counter_public_sha256"])? != self.counter_public_sha256
        {
            return Err("TPM custody context/key/counter mismatch".into());
        }
        m["genesis_counter"]
            .as_u64()
            .ok_or("Genesis counter missing".into())
    }
}

/// One file the helper invocation executes or reads as its program (interpreter, script).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperFile {
    pub path: PathBuf,
    /// Optional pin of the exact file bytes.
    pub sha256: Option<Hash>,
}
/// Explicit, validated description of the host-local production TPM helper process.
/// JSON form (`physical_voter.tpm_helper`), exactly two fields:
/// `{"privilege":"none"|"sudo-n","argv":[{"path":"/abs/file","sha256":"<64 hex>"|null}, ...]}`.
/// `argv` holds 1 to 4 absolute FILE paths (for example an interpreter and its script); the
/// fixed `PROTOCOL_ARGUMENT` is appended. There are no free-form arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperConfig {
    pub files: Vec<HelperFile>,
    pub sudo: bool,
}
// The helper path policy lives in `tpm_helper_policy.rs` (self-contained, so the qualification
// helper bridge of the consensus examples applies the same validation to a pinned helper).
#[path = "tpm_helper_policy.rs"]
mod policy;
pub use policy::{
    PathEntry, check_helper_ancestor_entry, check_helper_file_entry, check_helper_path,
    check_helper_wrapper_entry,
};
impl HelperConfig {
    pub fn from_json(v: &Value) -> Result<Self> {
        let object = v.as_object().ok_or("tpm_helper object required")?;
        if object.len() != 2 || !object.contains_key("privilege") || !object.contains_key("argv") {
            return Err("tpm_helper fields: privilege, argv".into());
        }
        let sudo = match v["privilege"].as_str() {
            Some("none") => false,
            Some("sudo-n") => true,
            _ => return Err("tpm_helper privilege must be \"none\" or \"sudo-n\"".into()),
        };
        let argv = v["argv"].as_array().ok_or("tpm_helper argv array required")?;
        if argv.is_empty() || argv.len() > MAX_HELPER_FILES {
            return Err("tpm_helper argv must name 1 to 4 files".into());
        }
        let mut files = Vec::new();
        for entry in argv {
            let e = entry.as_object().ok_or("tpm_helper argv entry object required")?;
            if e.len() != 2 || !e.contains_key("path") || !e.contains_key("sha256") {
                return Err("tpm_helper argv entry fields: path, sha256".into());
            }
            let path = PathBuf::from(entry["path"].as_str().ok_or("tpm_helper path string")?);
            check_helper_path(&path)?;
            let sha256 = if entry["sha256"].is_null() {
                None
            } else {
                Some(bytes::<32>(&entry["sha256"]).map_err(|_| "tpm_helper sha256 must be 64 hex")?)
            };
            files.push(HelperFile { path, sha256 });
        }
        let config = Self { files, sudo };
        config.check_lexical()?;
        Ok(config)
    }
    fn check_lexical(&self) -> Result<()> {
        if self.files.is_empty() || self.files.len() > MAX_HELPER_FILES {
            return Err("tpm_helper argv must name 1 to 4 files".into());
        }
        for f in &self.files {
            check_helper_path(&f.path)?;
        }
        Ok(())
    }
    /// Full custody-path policy over an explicit metadata/byte source. Production uses the Linux
    /// adapter; tests can exercise every rule with synthetic metadata on any platform.
    pub fn validate_with(
        &self,
        lookup: &dyn Fn(&Path) -> Result<PathEntry>,
        read: &dyn Fn(&Path) -> Result<Vec<u8>>,
    ) -> Result<()> {
        self.check_lexical()?;
        // The declared `sudo` wrapper (its set-user-ID bit is the declared privilege), then every
        // configured helper file (no privilege bit is declared for any of them).
        if self.sudo {
            policy::check_program(Path::new(SUDO), None, true, lookup, read)?;
        }
        for f in &self.files {
            policy::check_program(&f.path, f.sha256, false, lookup, read)?;
        }
        Ok(())
    }
    /// Production custody is host-local Linux only: elsewhere validation always refuses. The same
    /// rules as `validate_with`, against the real filesystem (`policy::check_program_on_host`).
    pub fn validate(&self) -> Result<()> {
        self.check_lexical()?;
        if self.sudo {
            policy::check_program_on_host(Path::new(SUDO), None, true)?;
        }
        for f in &self.files {
            policy::check_program_on_host(&f.path, f.sha256, false)?;
        }
        Ok(())
    }
    /// The exact process invocation: no shell, cleared environment, fixed protocol argument.
    pub fn command(&self) -> Command {
        let mut command = if self.sudo {
            let mut c = Command::new(SUDO);
            c.arg("-n").arg("--");
            for f in &self.files {
                c.arg(&f.path);
            }
            c
        } else {
            let mut c = Command::new(&self.files[0].path);
            for f in &self.files[1..] {
                c.arg(&f.path);
            }
            c
        };
        command.arg(PROTOCOL_ARGUMENT).env_clear();
        #[cfg(unix)]
        command.current_dir("/");
        command
    }
}
fn read_message(reader: &mut impl BufRead) -> Result<Value> {
    let mut line = Vec::new();
    reader
        .take(MAX_REPLY + 1)
        .read_until(b'\n', &mut line)
        .map_err(|_| "TPM channel read failed")?;
    if line.is_empty() || line.len() > MAX_REPLY as usize || line.last() != Some(&b'\n') {
        return Err("TPM channel reply bound/EOF".into());
    }
    serde_json::from_slice(&line).map_err(|_| "TPM channel malformed JSON".into())
}
pub struct NativeTpm {
    child: Child,
    input: Option<ChildStdin>,
    replies: Option<Receiver<Result<Value>>>,
    reader: Option<JoinHandle<()>>,
    reader_cancelled: Arc<AtomicBool>,
    pins: Pins,
    sequence: u64,
    genesis_counter: u64,
    poisoned: bool,
}
impl NativeTpm {
    pub fn open(pins: Pins, helper: &HelperConfig) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err("Production TPM custody is host-local Linux only".into());
        }
        // Root-owned, non-writable paths (validated here) make a swap between this check and
        // the spawn infeasible for a non-root local attacker.
        helper.validate()?;
        let mut child = helper
            .command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| "Cannot start host-local TPM custody helper")?;
        let input = child.stdin.take().ok_or("TPM stdin unavailable")?;
        let output = child.stdout.take().ok_or("TPM stdout unavailable")?;
        let reader_cancelled = Arc::new(AtomicBool::new(false));
        #[cfg(target_os = "linux")]
        let output =
            match crate::cancellable_pipe::CancellableReader::new(output, reader_cancelled.clone())
            {
                Ok(output) => output,
                Err(_) => {
                    drop(input);
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("TPM pipe cancellation setup failed".into());
                }
            };
        let (sender, replies) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut output = BufReader::new(output);
            loop {
                let reply = read_message(&mut output);
                let failed = reply.is_err();
                if sender.send(reply).is_err() || failed {
                    break;
                }
            }
        });
        let mut backend = Self {
            child,
            input: Some(input),
            replies: Some(replies),
            reader: Some(reader),
            reader_cancelled,
            pins,
            sequence: 0,
            genesis_counter: 0,
            poisoned: false,
        };
        let hello = backend.receive()?;
        backend.genesis_counter = backend.pins.verify(&hello)?;
        Ok(backend)
    }
    pub fn genesis_counter(&self) -> u64 {
        self.genesis_counter
    }
    fn receive(&mut self) -> Result<Value> {
        self.replies
            .as_ref()
            .ok_or("TPM channel closed")?
            .recv_timeout(DEADLINE)
            .map_err(|_| "TPM channel deadline/disconnect".into())
            .and_then(|v| v)
    }
    fn request(&mut self, mut value: Value) -> Result<Value> {
        if self.poisoned {
            return Err("TPM channel is poisoned; explicit restart required".into());
        }
        self.poisoned = true;
        value["id"] = json!(self.sequence);
        let raw = serde_json::to_vec(&value).map_err(|_| "TPM request encoding")?;
        if raw.len() > 4096 {
            return Err("TPM request bound".into());
        }
        // Each request is smaller than a pipe buffer. The helper reads one request
        // per bounded reply; protocol errors permanently close this session.
        let input = self.input.as_mut().ok_or("TPM channel closed")?;
        input
            .write_all(&raw)
            .and_then(|_| input.write_all(b"\n"))
            .and_then(|_| input.flush())
            .map_err(|_| "TPM channel write failed")?;
        let reply = self.receive()?;
        if reply["id"].as_u64() != Some(self.sequence) || reply["result"] != "PASS" {
            return Err("TPM channel operation/context failed".into());
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("TPM channel sequence exhausted")?;
        self.poisoned = false;
        Ok(reply)
    }
    pub fn quote(&mut self, challenge: Hash) -> Result<Vec<u8>> {
        let reply =
            self.request(json!({"operation":"quote","challenge":hex::encode(challenge)}))?;
        self.poisoned = true;
        let evidence = hex::decode(reply["evidence"].as_str().ok_or("TPM quote evidence")?)
            .map_err(|_| "TPM quote hex")?;
        if evidence.is_empty() || evidence.len() > 16384 {
            self.poisoned = true;
            return Err("TPM quote bound".into());
        }
        self.poisoned = false;
        Ok(evidence)
    }
}
impl MonotonicCounter for NativeTpm {
    fn read(&mut self) -> Result<u64> {
        let reply = self.request(json!({"operation":"read"}))?;
        let result = reply["counter"].as_u64().ok_or("TPM counter reply".into());
        self.poisoned = result.is_err();
        result
    }
    fn increment(&mut self) -> Result<()> {
        let reply = self.request(json!({"operation":"increment"}))?;
        self.poisoned = reply["counter"].as_u64().is_none();
        if self.poisoned {
            Err("TPM increment reply".into())
        } else {
            Ok(())
        }
    }
}
impl CounterSigningBackend for NativeTpm {
    fn public_key(&self) -> [u8; 33] {
        self.pins.voting_key
    }
    fn sign_digest(&mut self, digest: Hash) -> Result<[u8; 64]> {
        let reply = self.request(json!({"operation":"sign","digest":hex::encode(digest)}))?;
        let result = bytes(&reply["signature"]);
        self.poisoned = result.is_err();
        result
    }
}
impl ParticipationSigner for NativeTpm {
    fn public_key(&self) -> [u8; 33] {
        self.pins.voting_key
    }
    fn acknowledgement(&mut self, ack: &ParticipationAck) -> Result<[u8; 64]> {
        if ack.genesis != self.pins.genesis
            || ack.fingerprint != self.pins.fingerprint
            || ack.node != self.pins.node
        {
            return Err("TPM acknowledgement context mismatch".into());
        }
        self.sign_digest(ack.signing_digest())
    }
    fn refresh_quote(&mut self, refresh: &AttestationRefresh) -> Result<Vec<u8>> {
        if refresh.genesis != self.pins.genesis
            || refresh.fingerprint != self.pins.fingerprint
            || refresh.node != self.pins.node
        {
            return Err("TPM refresh context mismatch".into());
        }
        self.quote(refresh.challenge())
    }
}
impl Drop for NativeTpm {
    fn drop(&mut self) {
        // EOF releases the root helper's host lock; disconnecting the receiver
        // also unblocks a reader waiting to send an unsolicited/malformed reply.
        self.reader_cancelled.store(true, Ordering::Release);
        self.input.take();
        self.replies.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn public_custody_manifest_cannot_substitute_another_network_key_or_counter() {
        let mut pins = Pins {
            genesis: [1; 32],
            fingerprint: [2; 32],
            node: [3; 32],
            voting_key: [4; 33],
            counter_index: 0x0180_0001,
            counter_public_sha256: [5; 32],
            custody_manifest_sha256: [0; 32],
        };
        let manifest = json!({"schema":"BUILD8-PRODUCTION-TPM-CUSTODY-V1","actual_genesis":true,"qualification_retired":true,"genesis_counter":2582,"retired_voter_journal_sha256":"06".repeat(32),"genesis_id":hex::encode(pins.genesis),"protocol_fingerprint":hex::encode(pins.fingerprint),"node_id":hex::encode(pins.node),"voting_public":hex::encode(pins.voting_key),"counter_index":pins.counter_index,"counter_public_sha256":hex::encode(pins.counter_public_sha256)});
        let raw = serde_json::to_vec(&manifest).unwrap();
        pins.custody_manifest_sha256 = Sha256::digest(&raw).into();
        let hello = |raw: Vec<u8>| json!({"result":"READY","schema":"BUILD8-PRODUCTION-TPM-CHANNEL-V1","manifest_hex":hex::encode(raw)});
        pins.verify(&hello(raw.clone())).unwrap();
        for field in [
            "genesis_id",
            "protocol_fingerprint",
            "node_id",
            "voting_public",
            "counter_index",
            "counter_public_sha256",
            "actual_genesis",
        ] {
            let mut bad = manifest.clone();
            bad[field] = match field {
                "counter_index" => json!(1),
                "actual_genesis" => json!(false),
                "voting_public" => json!("00".repeat(33)),
                _ => json!("00".repeat(32)),
            };
            let raw = serde_json::to_vec(&bad).unwrap();
            let mut altered = pins.clone();
            altered.custody_manifest_sha256 = Sha256::digest(&raw).into();
            assert!(altered.verify(&hello(raw)).is_err(), "{field}");
        }
        // Configured counter pins only narrow: a configuration naming a different counter index
        // or counter public hash than the pinned manifest refuses the channel.
        let mut wrong_index = pins.clone();
        wrong_index.counter_index ^= 1;
        assert!(wrong_index.verify(&hello(raw.clone())).is_err());
        let mut wrong_public = pins.clone();
        wrong_public.counter_public_sha256[0] ^= 1;
        assert!(wrong_public.verify(&hello(raw)).is_err());
    }
    fn file(path: &str, sha256: Option<Hash>) -> Value {
        json!({"path": path, "sha256": sha256.map(hex::encode)})
    }
    #[test]
    fn helper_configuration_is_explicit_bounded_and_absolute() {
        let ok = json!({"privilege":"none","argv":[file("/usr/local/libexec/mutiny/tpm-custody", None)]});
        let config = HelperConfig::from_json(&ok).unwrap();
        assert!(!config.sudo);
        assert_eq!(config.files.len(), 1);
        let pinned = json!({"privilege":"sudo-n","argv":[file("/usr/bin/python3.12", Some([7; 32])), file("/opt/mutiny/custody/helper.py", None)]});
        let config = HelperConfig::from_json(&pinned).unwrap();
        assert!(config.sudo);
        assert_eq!(config.files[0].sha256, Some([7; 32]));
        for bad in [
            json!({"argv":[file("/a/b", None)]}),
            json!({"privilege":"none","argv":[file("/a/b", None)],"extra":1}),
            json!({"privilege":"root","argv":[file("/a/b", None)]}),
            json!({"privilege":"none","argv":[]}),
            json!({"privilege":"none","argv":[file("/a",None),file("/b",None),file("/c",None),file("/d",None),file("/e",None)]}),
            json!({"privilege":"none","argv":[file("relative/helper", None)]}),
            json!({"privilege":"none","argv":[file("/opt/../tmp/helper", None)]}),
            json!({"privilege":"none","argv":[file("/opt/./helper", None)]}),
            json!({"privilege":"none","argv":[file("/opt//helper", None)]}),
            json!({"privilege":"none","argv":[{"path":"/opt/helper"}]}),
            json!({"privilege":"none","argv":[{"path":"/opt/helper","sha256":"zz"}]}),
            json!({"privilege":"none","argv":["/opt/helper"]}),
            json!({"privilege":"none","argv":[file("C:\\helper.exe", None)]}),
        ] {
            assert!(HelperConfig::from_json(&bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn helper_invocation_has_no_shell_cleared_environment_and_fixed_protocol() {
        let direct = HelperConfig {
            files: vec![
                HelperFile { path: "/usr/bin/python3.12".into(), sha256: None },
                HelperFile { path: "/opt/mutiny/custody/helper.py".into(), sha256: None },
            ],
            sudo: false,
        };
        let c = direct.command();
        assert_eq!(c.get_program(), std::ffi::OsStr::new("/usr/bin/python3.12"));
        let args: Vec<_> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["/opt/mutiny/custody/helper.py", PROTOCOL_ARGUMENT]);
        // No variable is passed explicitly. (`env_clear()` itself is not observable through the
        // stable Command API; it is applied unconditionally in `HelperConfig::command`.)
        assert_eq!(c.get_envs().count(), 0);
        let sudo = HelperConfig { sudo: true, ..direct };
        let c = sudo.command();
        assert_eq!(c.get_program(), std::ffi::OsStr::new(SUDO));
        let args: Vec<_> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["-n", "--", "/usr/bin/python3.12", "/opt/mutiny/custody/helper.py", PROTOCOL_ARGUMENT]);
    }
    /// Synthetic filesystem: root-owned 0755 directories and files unless overridden.
    fn synthetic(overrides: &[(&str, PathEntry)], p: &Path) -> Result<PathEntry> {
        let text = p.to_str().unwrap();
        for (name, entry) in overrides {
            if *name == text {
                return Ok(*entry);
            }
        }
        Ok(if text == "/opt/mutiny/helper" || text == SUDO {
            PathEntry { symlink: false, directory: false, regular: true, uid: 0, mode: 0o100755 }
        } else {
            PathEntry { symlink: false, directory: true, regular: false, uid: 0, mode: 0o40755 }
        })
    }
    /// Portable policy matrix with synthetic metadata: every rule is exercised on every platform.
    #[test]
    fn helper_path_policy_refuses_symlinks_writable_and_non_root_entries() {
        let config = HelperConfig {
            files: vec![HelperFile { path: "/opt/mutiny/helper".into(), sha256: Some(Sha256::digest(b"helper").into()) }],
            sudo: true,
        };
        let world = |overrides: &'static [(&'static str, PathEntry)]| {
            move |p: &Path| synthetic(overrides, p)
        };
        let read_ok = |_: &Path| -> Result<Vec<u8>> { Ok(b"helper".to_vec()) };
        config.validate_with(&world(&[]), &read_ok).unwrap();
        let cases: [(&'static [(&'static str, PathEntry)], &str); 10] = [
            (&[("/opt/mutiny/helper", PathEntry { symlink: true, directory: false, regular: false, uid: 0, mode: 0o120777 })], "symlink"),
            (&[("/opt/mutiny", PathEntry { symlink: true, directory: false, regular: false, uid: 0, mode: 0o120777 })], "symlink"),
            (&[("/opt/mutiny/helper", PathEntry { symlink: false, directory: false, regular: true, uid: 0, mode: 0o100775 })], "writable"),
            (&[("/opt/mutiny/helper", PathEntry { symlink: false, directory: false, regular: true, uid: 1000, mode: 0o100755 })], "not root-owned"),
            (&[("/opt", PathEntry { symlink: false, directory: true, regular: false, uid: 0, mode: 0o41777 })], "writable"),
            (&[("/opt", PathEntry { symlink: false, directory: true, regular: false, uid: 1000, mode: 0o40755 })], "not root-owned"),
            (&[(SUDO, PathEntry { symlink: false, directory: false, regular: true, uid: 1000, mode: 0o104755 })], "not root-owned"),
            // No privilege is declared for a helper file: set-user-ID or set-group-ID is refused,
            // even root-owned; the declared sudo wrapper may be set-user-ID but not set-group-ID.
            (&[("/opt/mutiny/helper", PathEntry { symlink: false, directory: false, regular: true, uid: 0, mode: 0o104755 })], "setuid"),
            (&[("/opt/mutiny/helper", PathEntry { symlink: false, directory: false, regular: true, uid: 0, mode: 0o102755 })], "setgid"),
            (&[(SUDO, PathEntry { symlink: false, directory: false, regular: true, uid: 0, mode: 0o106755 })], "setgid"),
        ];
        for (overrides, expected) in cases {
            let err = config.validate_with(&world(overrides), &read_ok).unwrap_err();
            assert!(err.contains(expected), "{overrides:?}: {err}");
        }
        let err = config
            .validate_with(&world(&[]), &|_: &Path| -> Result<Vec<u8>> { Ok(b"edited".to_vec()) })
            .unwrap_err();
        assert!(err.contains("sha256"), "{err}");
        // The declared wrapper is set-user-ID root on a real host: accepted (privilege declared).
        let setuid_root = PathEntry { symlink: false, directory: false, regular: true, uid: 0, mode: 0o104755 };
        config.validate_with(&world(&[(SUDO, PathEntry { symlink: false, directory: false, regular: true, uid: 0, mode: 0o104755 })]), &read_ok).unwrap();
        // The same set-user-ID program configured as a helper file (privilege "none") is refused.
        let undeclared = HelperConfig { files: vec![HelperFile { path: SUDO.into(), sha256: None }], sudo: false };
        let err = undeclared
            .validate_with(&world(&[(SUDO, PathEntry { symlink: false, directory: false, regular: true, uid: 0, mode: 0o104755 })]), &read_ok)
            .unwrap_err();
        assert!(err.contains("setuid"), "{err}");
        assert!(check_helper_wrapper_entry(setuid_root).is_ok() && check_helper_file_entry(setuid_root).is_err());
        // Without sudo the wrapper is not consulted at all.
        let direct = HelperConfig { sudo: false, ..config.clone() };
        direct
            .validate_with(&world(&[(SUDO, PathEntry { symlink: true, directory: false, regular: false, uid: 1000, mode: 0o120777 })]), &read_ok)
            .unwrap();
    }
    /// A12 (Order of 4 Oct 2026): `"privilege":"sudo-n"` declares exactly ONE privileged program, the compile-time
    /// constant `/usr/bin/sudo`, run non-interactively (`-n`: sudo never prompts, so no password is ever collected) with
    /// `--` before the configured absolute files and the fixed protocol argument. No configuration value can name another
    /// privilege mechanism, another wrapper, a sudo option or a shell string; `"none"` never runs sudo at all.
    #[test]
    fn sudo_n_declares_only_the_fixed_noninteractive_sudo_wrapper() {
        assert_eq!(SUDO, "/usr/bin/sudo");
        for privilege in [
            "sudo", "SUDO-N", "Sudo-n", "sudo-N", "sudo-n ", " sudo-n", "sudo -n", "sudo-n,none", "pkexec", "doas", "su", "root",
            "setuid", "NOPASSWD", "",
        ] {
            let v = json!({"privilege": privilege, "argv": [file("/opt/mutiny/helper", None)]});
            let err = HelperConfig::from_json(&v).unwrap_err();
            assert!(err.contains("privilege must be"), "{privilege:?}: {err}");
        }
        for privilege in [json!(null), json!(true), json!(1), json!(["sudo-n"]), json!({"sudo-n": true})] {
            let v = json!({"privilege": privilege, "argv": [file("/opt/mutiny/helper", None)]});
            assert!(HelperConfig::from_json(&v).is_err(), "{privilege}");
        }
        // A configured file can never be read as a sudo option or a relative command: every path is absolute.
        for option in ["-s", "--login", "-i", "-u", "sh", "bash -c id"] {
            let v = json!({"privilege": "sudo-n", "argv": [file(option, None)]});
            assert!(HelperConfig::from_json(&v).unwrap_err().contains("absolute"), "{option}");
        }
        let sudo = HelperConfig::from_json(&json!({"privilege":"sudo-n","argv":[file("/opt/mutiny/helper", None)]})).unwrap();
        let c = sudo.command();
        assert_eq!(c.get_program(), std::ffi::OsStr::new("/usr/bin/sudo"));
        let args: Vec<_> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["-n", "--", "/opt/mutiny/helper", PROTOCOL_ARGUMENT]);
        assert_eq!(c.get_envs().count(), 0);
        let direct = HelperConfig::from_json(&json!({"privilege":"none","argv":[file("/opt/mutiny/helper", None)]})).unwrap();
        let c = direct.command();
        assert_eq!(c.get_program(), std::ffi::OsStr::new("/opt/mutiny/helper"));
        let args: Vec<_> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, [PROTOCOL_ARGUMENT]);
    }
    /// A12: the set-user-ID bit of the declared `/usr/bin/sudo` is the ONLY set-id bit a configuration accepts. Every
    /// configured helper file is refused with a set-user-ID or set-group-ID bit in `"sudo-n"` mode exactly as in `"none"`
    /// mode, although root-owned; the wrapper itself is refused set-group-ID, user-owned, symlinked or group/world-writable,
    /// and so is a user-owned or writable ancestor directory of the wrapper.
    #[test]
    fn configured_helper_files_never_carry_set_id_bits_and_the_wrapper_is_narrow() {
        let read_ok = |_: &Path| -> Result<Vec<u8>> { Ok(b"helper".to_vec()) };
        let regular = |uid: u32, mode: u32| PathEntry { symlink: false, directory: false, regular: true, uid, mode };
        let directory = |uid: u32, mode: u32| PathEntry { symlink: false, directory: true, regular: false, uid, mode };
        for sudo in [false, true] {
            let config = HelperConfig { files: vec![HelperFile { path: "/opt/mutiny/helper".into(), sha256: None }], sudo };
            config.validate_with(&|p: &Path| synthetic(&[], p), &read_ok).unwrap();
            for mode in [0o104755, 0o102755, 0o106755, 0o104555, 0o102711] {
                let err = config
                    .validate_with(&|p: &Path| synthetic(&[("/opt/mutiny/helper", regular(0, mode))], p), &read_ok)
                    .unwrap_err();
                assert!(err.contains("setuid or setgid"), "sudo={sudo} mode={mode:o}: {err}");
            }
        }
        let config = HelperConfig { files: vec![HelperFile { path: "/opt/mutiny/helper".into(), sha256: None }], sudo: true };
        config.validate_with(&|p: &Path| synthetic(&[(SUDO, regular(0, 0o104755))], p), &read_ok).unwrap();
        let symlink = PathEntry { symlink: true, directory: false, regular: false, uid: 0, mode: 0o120777 };
        for (path, entry, expected) in [
            (SUDO, regular(0, 0o106755), "setuid or setgid"),
            (SUDO, regular(0, 0o102755), "setuid or setgid"),
            (SUDO, regular(1000, 0o104755), "not root-owned"),
            (SUDO, symlink, "symlink"),
            (SUDO, regular(0, 0o104775), "writable"),
            (SUDO, regular(0, 0o104757), "writable"),
            ("/usr", directory(1000, 0o40755), "not root-owned"),
            ("/usr/bin", directory(0, 0o40777), "writable"),
            ("/usr/bin", symlink, "symlink"),
        ] {
            let err = config.validate_with(&|p: &Path| synthetic(&[(path, entry)], p), &read_ok).unwrap_err();
            assert!(err.contains(expected), "{path} {entry:?}: {err}");
        }
    }
    /// A12, real metadata: the set-id rule reads the same bits the operating system reports. Set-user-ID and set-group-ID
    /// files created here are refused by `check_helper_file_entry` when built from REAL `std::os::unix` metadata (ownership
    /// is set to root synthetically, so only the set-id rule decides). Compiled and run on unix hosts only: NOT run on the
    /// Windows host of this round. The Linux-only test above exercises the whole Linux adapter.
    #[cfg(unix)]
    #[test]
    fn set_id_bits_read_from_real_unix_metadata_are_refused() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mut salt = [0u8; 8];
        getrandom::getrandom(&mut salt).unwrap();
        let dir = std::env::temp_dir().join(format!("build8-a12-setid-{}", hex::encode(salt)));
        std::fs::create_dir(&dir).unwrap();
        for (name, mode) in [("setuid", 0o4755), ("setgid", 0o2755), ("plain", 0o755)] {
            let p = dir.join(name);
            std::fs::write(&p, b"#!/bin/false\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let m = std::fs::symlink_metadata(&p).unwrap();
            let entry = PathEntry {
                symlink: m.file_type().is_symlink(),
                directory: m.is_dir(),
                regular: m.is_file(),
                uid: 0,
                mode: m.mode(),
            };
            let result = check_helper_file_entry(entry);
            if m.mode() & policy::SET_ID_BITS != 0 {
                assert!(result.unwrap_err().contains("setuid or setgid"), "{name}");
            } else {
                // The filesystem may drop a set-id bit (nosuid); then the plain rule applies.
                assert!(result.is_ok(), "{name}");
            }
            std::fs::remove_file(&p).unwrap();
        }
        std::fs::remove_dir(&dir).unwrap();
    }
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn helper_validation_refuses_off_linux() {
        let config = HelperConfig {
            files: vec![HelperFile { path: "/usr/bin/true".into(), sha256: None }],
            sudo: false,
        };
        assert!(config.validate().unwrap_err().contains("requires Linux"));
        // The set-id rule itself is portable (the Linux real-file case is the Linux-gated test).
        let setuid = PathEntry { symlink: false, directory: false, regular: true, uid: 0, mode: 0o104755 };
        assert!(check_helper_file_entry(setuid).unwrap_err().contains("setuid"));
        let pins = Pins {
            genesis: [0; 32],
            fingerprint: [0; 32],
            node: [0; 32],
            voting_key: [0; 33],
            counter_index: 0,
            counter_public_sha256: [0; 32],
            custody_manifest_sha256: [0; 32],
        };
        assert!(NativeTpm::open(pins, &config).is_err());
    }
    /// Real filesystem refusals on Linux (unverified on Windows hosts: compiled only on Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn helper_validation_refuses_real_symlink_group_writable_and_user_owned_files() {
        use std::os::unix::fs::PermissionsExt;
        let mut salt = [0u8; 8];
        getrandom::getrandom(&mut salt).unwrap();
        let dir = std::env::temp_dir().join(format!("build8-tpm-helper-{}", hex::encode(salt)));
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("helper");
        std::fs::write(&target, b"#!/bin/false\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let writable = dir.join("writable");
        std::fs::write(&writable, b"#!/bin/false\n").unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o775)).unwrap();
        let check = |p: &Path| HelperConfig {
            files: vec![HelperFile { path: p.to_path_buf(), sha256: None }],
            sudo: false,
        }
        .validate()
        .unwrap_err();
        assert!(check(&link).contains("symlink"));
        assert!(check(&writable).contains("writable"));
        // Unless the test itself runs as root, the temp file is user-owned.
        // SAFETY: getuid(2) has no preconditions and cannot fail.
        if unsafe { libc::getuid() } != 0 {
            assert!(check(&target).contains("not root-owned"));
        }
        // Set-user-ID / set-group-ID helper files are refused before the ownership rule. An
        // unprivileged owner may set these bits; the check is skipped only if the filesystem dropped
        // the bit (read back first).
        for (name, mode, word) in [("setuid", 0o4755, "setuid"), ("setgid", 0o2755, "setgid")] {
            use std::os::unix::fs::MetadataExt;
            let p = dir.join(name);
            std::fs::write(&p, b"#!/bin/false\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            if std::fs::metadata(&p).unwrap().mode() & mode == mode {
                assert!(check(&p).contains(word), "{name}");
            }
        }
        for name in ["link", "writable", "helper", "setuid", "setgid"] {
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn dropping_channel_cancels_reader_despite_retained_writer() {
        use std::{os::unix::net::UnixStream, time::Instant};
        let (read, retained_writer) = UnixStream::pair().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let read =
            crate::cancellable_pipe::CancellableReader::new(read, cancelled.clone()).unwrap();
        let (sender, replies) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let _ = sender.send(read_message(&mut BufReader::new(read)));
        });
        // A harmless child supplies the Child handle; the synthetic stream is
        // deliberately held open independently. Never call NativeTpm::open.
        let child = Command::new("/usr/bin/true").spawn().unwrap();
        let backend = NativeTpm {
            child,
            input: None,
            replies: Some(replies),
            reader: Some(reader),
            reader_cancelled: cancelled.clone(),
            pins: Pins {
                genesis: [0; 32],
                fingerprint: [0; 32],
                node: [0; 32],
                voting_key: [0; 33],
                counter_index: 0,
                counter_public_sha256: [0; 32],
                custody_manifest_sha256: [0; 32],
            },
            sequence: 0,
            genesis_counter: 0,
            poisoned: true,
        };
        let (finished, result) = mpsc::sync_channel(1);
        let started = Instant::now();
        let dropper = thread::spawn(move || {
            drop(backend);
            finished.send(()).unwrap();
        });
        result
            .recv_timeout(Duration::from_secs(2))
            .expect("channel Drop trapped by retained writer");
        dropper.join().unwrap();
        assert!(cancelled.load(Ordering::Acquire));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(retained_writer);
    }
    #[test]
    fn reply_reader_is_bounded_before_allocation_and_rejects_truncation() {
        use std::io::Cursor;
        let mut oversized = Cursor::new(vec![b' '; 1024 * 1024]);
        assert!(read_message(&mut oversized).is_err());
        assert_eq!(oversized.position(), MAX_REPLY + 1);
        for input in [
            b"".as_slice(),
            b"{}",
            b"not-json\n",
            b"{\"result\":\"PASS\"}\0\n",
        ] {
            assert!(read_message(&mut Cursor::new(input)).is_err());
        }
        assert_eq!(
            read_message(&mut Cursor::new(b"{\"id\":0,\"result\":\"PASS\"}\n")).unwrap()["id"],
            0
        );
    }
}
