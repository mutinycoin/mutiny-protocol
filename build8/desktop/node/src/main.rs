//! Persistent validator process. Qualification mode is intentionally explicit;
//! actual Genesis launch remains closed until the complete sealed ceremony.
const _: () = assert!(!mutiny_crypto_v2::RECEIPT_QUALIFICATION_ENABLED,
    "Provisional receipt qualification is forbidden in node executables");
const _: () = assert!(!mutiny_crypto_v2::WALLET_CUSTODY_ENABLED && !mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED,
    "Node executables must not enable wallet/owner/recovery/release private custody");
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    block_envelope::BlockEnvelope,
    blocks::GenesisDescriptor,
    canonical_store::CanonicalStore,
    execution::State,
    freshness::{PhysicalAttestationVerifier, PhysicalMember, validate_genesis},
    tpm::{PinnedTpmVerifier, TpmProfile},
    transactions::Transfer,
    *,
};
#[cfg(unix)]
use mutinyd_v8::peer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};
use mutiny_consensus_v8::{
    bft::Step, counter_voter::CounterSigningBackend, voter_actor::VoterActor, votes::Vote,
};
/// The only signing backend a shipping node links: the host-local production TPM channel
/// (`tpm_backend::NativeTpm`). Qualification custody through an external helper is separate
/// qualification tooling in the consensus examples; it is not compiled into this binary.
type SigningBackend = mutinyd_v8::tpm_backend::NativeTpm;
/// Refusal for every qualification (non-production) physical custody request.
const QUALIFICATION_CUSTODY_REFUSED: &str =
    "qualification physical custody is not available in shipping binaries";
enum Evidence {
    Fixture,
    Physical(PinnedTpmVerifier),
}
impl Clone for Evidence {
    fn clone(&self) -> Self {
        match self {
            Self::Fixture => Self::Fixture,
            Self::Physical(v) => Self::Physical(PinnedTpmVerifier {
                profiles: v.profiles.clone(),
            }),
        }
    }
}
impl PhysicalAttestationVerifier for Evidence {
    fn verify(&self, m: &PhysicalMember, c: Hash, e: &[u8]) -> Result<()> {
        match self {
            Self::Fixture if e == c => Ok(()),
            Self::Fixture => Err(Error::BadSignature),
            Self::Physical(v) => v.verify(m, c, e),
        }
    }
}
fn raw(v: &Value) -> std::result::Result<Vec<u8>, String> {
    hex::decode(v.as_str().ok_or("hex string required")?).map_err(|e| e.to_string())
}
fn public_hash(v: &Value) -> std::result::Result<Hash, String> {
    raw(v)?
        .try_into()
        .map_err(|_| "32-byte value required".into())
}
fn fail(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
/// SOFTWARE TEST-VALUE simulator, test-only (never part of the shipping binary). Declared once at file
/// scope: a #[path] inside the inline test module below would resolve from
/// node/src/runtime_ingress_tests/, which does not exist (Linux fails with ENOENT where Windows
/// collapses the `..` lexically; build/check-source-paths.pl).
#[cfg(test)]
#[path = "../../consensus/tests/support/software_tpm.rs"]
mod software_tpm;
#[cfg(test)]
mod runtime_ingress_tests {
    #[test]
    fn sealed_install_reconstructs_before_database_and_restarts_exactly() {
        use super::*;
        use mutinyd_v8::genesis_artifact::Trust;
        let vector: Value = serde_json::from_str(include_str!(
            "../../qualification/COMPLETE-GENESIS-VECTORS-V1.json"
        ))
        .unwrap();
        let mut artifact = serde_json::Map::new();
        for field in [
            "descriptor",
            "bindings",
            "approved_profile",
            "supervised_nonce",
            "evidence",
            "records",
            "state_root",
            "genesis_block",
            "genesis_block_hash",
        ] {
            artifact.insert(field.into(), vector[field].clone());
        }
        artifact.insert(
            "schema".into(),
            Value::String("BUILD8-SEALED-GENESIS-V1".into()),
        );
        let bytes = serde_json::to_vec(&artifact).unwrap();
        let mut trust = Trust {
            artifact_sha256: Sha256::digest(&bytes).into(),
            genesis_block_hash: public_hash(&vector["genesis_block_hash"]).unwrap(),
            rules: protocol_manifest::RuleManifest::decode(&raw(&vector["locked_rules"]).unwrap())
                .unwrap(),
            qualified_target: public_hash(&vector["qualified_target"]).unwrap(),
            profile: mutiny_consensus_v8::genesis_inputs::GenesisProfile::Test, // legacy treasury-less test vector
        };
        let mut salt = [0; 8];
        getrandom::getrandom(&mut salt).unwrap();
        let dir = std::env::temp_dir().join(format!("build8-sealed-install-{}", hex::encode(salt)));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("sealed.json");
        let db = dir.join("chain.sqlite");
        std::fs::write(&file, &bytes).unwrap();
        trust.genesis_block_hash[0] ^= 1;
        assert!(Node::open_sealed(&file, &db, &trust).is_err());
        assert!(!db.exists());
        trust.genesis_block_hash[0] ^= 1;
        let mut first = Node::open_sealed(&file, &db, &trust).unwrap();
        let tip = first.store.load().unwrap().0;
        assert_eq!(tip.height, 0);
        assert_eq!(tip.block, trust.genesis_block_hash);
        assert!(first.voter.is_none() && first.signer.is_none());
        drop(first);
        let mut second = Node::open_sealed(&file, &db, &trust).unwrap();
        assert_eq!(second.store.load().unwrap().0, tip);
        drop(second);
        for name in [
            "sealed.json",
            "chain.sqlite",
            "chain.candidates.sqlite",
            "chain.received-votes.sqlite",
        ] {
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
    }
    use super::*;
    #[test]
    fn pinned_bundle_hash_does_not_replace_initial_binding_signatures() {
        let first = include_str!("../../qualification/integration-state-v2-1/chain.jsonl")
            .lines()
            .next()
            .unwrap();
        let original: Value = serde_json::from_str(first).unwrap();
        let records: Vec<_> = original["initial_records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (public_hash(&r[0]).unwrap(), raw(&r[1]).unwrap()))
            .collect();
        let original_state =
            State::from_records(&records, blocks::state_root(&records).unwrap()).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "build8-initial-auth-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        for worker_signature in [false, true] {
            let mut state = original_state.clone();
            let binding = &mut state.licenses.workers.values_mut().next().unwrap().binding;
            if worker_signature {
                binding.worker_signature[0] ^= 1;
            } else {
                binding.owner_signature[0] ^= 1;
            }
            let mut bundle = original.clone();
            bundle["initial_records"] = json!(
                state
                    .records()
                    .unwrap()
                    .into_iter()
                    .map(|(k, v)| (hex::encode(k), hex::encode(v)))
                    .collect::<Vec<_>>()
            );
            let bytes = serde_json::to_vec(&bundle).unwrap();
            let pin: Hash = Sha256::digest(&bytes).into();
            let file = dir.join(format!("invalid-{worker_signature}.json"));
            std::fs::write(&file, &bytes).unwrap();
            let db = dir.join(format!("invalid-{worker_signature}.sqlite"));
            assert!(Node::open(&file, &db, pin).is_err());
            assert!(!db.exists());
            std::fs::remove_file(file).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
    }
    // SOFTWARE TEST-VALUE simulator, test-only: declared once at file scope (above); re-exported so
    // that `runtime_ingress_tests::software_tpm` keeps its path and visibility.
    pub(super) use super::software_tpm;
    /// A bundle claiming physical evidence must carry a profile every member commits to, and a
    /// software TEST-VALUE profile can never stand in for physical evidence.
    #[test]
    fn physical_mode_rejects_test_value_and_uncommitted_profiles_at_runtime() {
        use super::*;
        let fixture: Value = serde_json::from_str(include_str!(
            "../../qualification/RECOVERY-TRANSPORT-VECTORS-V1.json"
        ))
        .unwrap();
        let dir = std::env::temp_dir().join(format!("build8-physical-reject-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, tpm, expect) in [
            ("test-value", software_tpm::TestTpm::new(), "test-value"),
            ("uncommitted", software_tpm::TestTpm::unmarked_negative_control(), "unqualified physical profile"),
        ] {
            let mut bundle = fixture["bundle"].clone();
            bundle["physical_evidence_fixture_only"] = Value::Bool(false);
            bundle["physical_profile"] = json!({"profile": hex::encode(tpm.profile().encode().unwrap())});
            let bytes = serde_json::to_vec(&bundle).unwrap();
            let pin: Hash = Sha256::digest(&bytes).into();
            let file = dir.join(format!("{name}.json"));
            std::fs::write(&file, &bytes).unwrap();
            let db = dir.join(format!("{name}.sqlite"));
            let err = Node::open(&file, &db, pin).err().expect("must be rejected");
            assert!(err.contains(expect), "{name}: {err}");
            assert!(!db.exists());
            std::fs::remove_file(file).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn recovery_record_must_validate_before_successor_catchup() {
        use mutinyd_v8::{
            peer_client::PeerClient,
            peer_server::{PeerBackend, PeerReply, PeerServer},
            peer_sync::catch_up,
        };
        use std::sync::{Arc, Mutex};
        let fixture: Value = serde_json::from_str(include_str!(
            "../../qualification/RECOVERY-TRANSPORT-VECTORS-V1.json"
        ))
        .unwrap();
        assert_eq!(fixture["software_keys_only"], true);
        let dir = std::env::temp_dir().join(format!(
            "build8-recovery-peer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let bundle = dir.join("genesis.json");
        let bytes = serde_json::to_vec(&fixture["bundle"]).unwrap();
        std::fs::write(&bundle, &bytes).unwrap();
        let pin: Hash = Sha256::digest(&bytes).into();
        let mut source = Node::open(&bundle, &dir.join("source.sqlite"), pin).unwrap();
        source
            .request(&json!({"method":"submit_recovery","recovery":fixture["recovery_envelope"]}))
            .unwrap();
        source
            .request(&json!({"method":"submit_block","envelope":fixture["successor_envelope"]}))
            .unwrap();
        let context = (source.genesis, source.fingerprint);
        let source = Arc::new(Mutex::new(source));
        struct Provider {
            source: Arc<Mutex<Node>>,
            omit: bool,
        }
        impl PeerBackend for Provider {
            fn context(&self) -> (Hash, Hash) {
                self.source.lock().unwrap().context()
            }
            fn handle(&mut self, _: Hash, raw: &[u8]) -> std::result::Result<PeerReply, String> {
                let request: Value = serde_json::from_slice(raw).map_err(fail)?;
                if self.omit && request["method"] == "get_recovery" {
                    return Ok(PeerReply {
                        payload: serde_json::to_vec(
                            &json!({"id":request["id"],"result":{"envelope":null}}),
                        )
                        .unwrap(),
                        close: false,
                    });
                }
                self.source.lock().unwrap().peer_request(raw)
            }
        }
        for omit in [true, false] {
            let a = ed25519_dalek::SigningKey::from_bytes(&[47; 32]);
            let b = ed25519_dalek::SigningKey::from_bytes(&[48; 32]);
            let bp = b.verifying_key().to_bytes();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = PeerServer::start(
                listener,
                b,
                &[a.verifying_key().to_bytes()],
                Arc::new(Mutex::new(Provider {
                    source: source.clone(),
                    omit,
                })),
                2,
            )
            .unwrap();
            let destination = Arc::new(Mutex::new(
                Node::open(
                    &bundle,
                    &dir.join(format!("destination-{omit}.sqlite")),
                    pin,
                )
                .unwrap(),
            ));
            let mut client = PeerClient::connect(address, a, bp, context.0, context.1).unwrap();
            let result = catch_up(&mut client, &destination, bp, 1);
            if omit {
                assert!(result.is_err());
                assert_eq!(
                    destination.lock().unwrap().store.load().unwrap().0.height,
                    0
                );
            } else {
                assert_eq!(result.unwrap().accepted, 1);
                let mut own = destination.lock().unwrap();
                assert_eq!(
                    hex::encode(own.store.load_effective().unwrap().1.root().unwrap()),
                    fixture["effective_state_root"]
                );
                assert_eq!(
                    hex::encode(own.store.recovery_envelope(0).unwrap().unwrap()),
                    fixture["recovery_envelope"]
                );
                assert!(own.voter.is_none());
            }
            drop(client);
            server.stop().unwrap();
            drop(destination);
        }
        drop(source);
        for entry in std::fs::read_dir(&dir).unwrap() {
            let e = entry.unwrap();
            assert!(e.file_type().unwrap().is_file());
            std::fs::remove_file(e.path()).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn authenticated_catchup_executes_blocks_and_restarts_without_voting() {
        use mutinyd_v8::{peer_client::PeerClient, peer_server::PeerServer, peer_sync::catch_up};
        use std::sync::{Arc, Mutex};
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!("build8-catchup-{}", hex::encode(random)));
        std::fs::create_dir(&dir).unwrap();
        let mut rows =
            include_str!("../../qualification/integration-state-v2-1/chain.jsonl").lines();
        let initial = rows.next().unwrap().as_bytes();
        let bundle = dir.join("genesis.json");
        std::fs::write(&bundle, initial).unwrap();
        let pin: Hash = Sha256::digest(initial).into();
        let mut source = Node::open(&bundle, &dir.join("source.sqlite"), pin).unwrap();
        for row in rows.take(3) {
            let row: Value = serde_json::from_str(row).unwrap();
            assert_eq!(
                source
                    .request(&json!({"method":"submit_block","envelope":row["envelope"]}))
                    .unwrap()["status"],
                "COMMITTED"
            );
        }
        let gid = source.genesis;
        let fp = source.fingerprint;
        let a = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let b = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
        let bp = b.verifying_key().to_bytes();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let source = Arc::new(Mutex::new(source));
        let server = PeerServer::start(
            listener,
            b,
            &[a.verifying_key().to_bytes()],
            source.clone(),
            4,
        )
        .unwrap();
        let destination = Arc::new(Mutex::new(
            Node::open(&bundle, &dir.join("destination.sqlite"), pin).unwrap(),
        ));
        let mut client = PeerClient::connect(address, a, bp, gid, fp).unwrap();
        let first = catch_up(&mut client, &destination, bp, 1).unwrap();
        assert_eq!(first.local_height, 1);
        assert_eq!(first.accepted, 1);
        let second = catch_up(&mut client, &destination, bp, 64).unwrap();
        assert_eq!(second.local_height, 3);
        assert_eq!(second.accepted, 2);
        assert_eq!(
            catch_up(&mut client, &destination, bp, 64)
                .unwrap()
                .accepted,
            0
        );
        assert!(!destination.lock().unwrap().voter.is_some());
        drop(destination);
        let mut restarted = Node::open(&bundle, &dir.join("destination.sqlite"), pin).unwrap();
        assert_eq!(
            restarted.store.load().unwrap().0,
            source.lock().unwrap().store.load().unwrap().0
        );
        drop(restarted);
        drop(client);
        server.stop().unwrap();
        // A NATed source dials the behind node. Catch-up must work without
        // any reverse TCP connection, including a bounded first batch.
        let behind = Arc::new(Mutex::new(
            Node::open(&bundle, &dir.join("pushed.sqlite"), pin).unwrap(),
        ));
        let a = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let b = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = PeerServer::start(
            listener,
            b,
            &[a.verifying_key().to_bytes()],
            behind.clone(),
            4,
        )
        .unwrap();
        let mut client = PeerClient::connect(address, a, bp, gid, fp).unwrap();
        let first = mutinyd_v8::peer_sync::push_history(&mut client, &source, bp, 1).unwrap();
        assert_eq!((first.accepted, first.local_height), (1, 1));
        let second = mutinyd_v8::peer_sync::push_history(&mut client, &source, bp, 64).unwrap();
        assert_eq!((second.accepted, second.local_height), (2, 3));
        assert_eq!(
            behind.lock().unwrap().store.load().unwrap().0,
            source.lock().unwrap().store.load().unwrap().0
        );
        assert_eq!(
            mutinyd_v8::peer_sync::push_history(&mut client, &source, bp, 64)
                .unwrap()
                .accepted,
            0
        );
        drop(client);
        server.stop().unwrap();
        drop(behind);
        // An authenticated peer can still lie. A cryptographically corrupted
        // certificate must not advance or integrity-halt the local chain.
        struct Corrupt {
            source: Arc<Mutex<Node>>,
        }
        impl mutinyd_v8::peer_server::PeerBackend for Corrupt {
            fn context(&self) -> (Hash, Hash) {
                let n = self.source.lock().unwrap();
                (n.genesis, n.fingerprint)
            }
            fn handle(
                &mut self,
                _: Hash,
                raw: &[u8],
            ) -> std::result::Result<mutinyd_v8::peer_server::PeerReply, String> {
                let request: Value = serde_json::from_slice(raw).unwrap();
                let mut reply = self.source.lock().unwrap().peer_request(raw)?;
                if request["method"] == "get_block" {
                    let mut answer: Value = serde_json::from_slice(&reply.payload).unwrap();
                    let mut block = BlockEnvelope::decode(
                        &hex::decode(answer["result"]["envelope"].as_str().unwrap()).unwrap(),
                    )
                    .unwrap();
                    block.certificate.signers[0].signature[0] ^= 1;
                    answer["result"]["envelope"] = json!(hex::encode(block.encode().unwrap()));
                    reply.payload = serde_json::to_vec(&answer).unwrap();
                }
                Ok(reply)
            }
        }
        let a = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let b = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = PeerServer::start(
            listener,
            b,
            &[a.verifying_key().to_bytes()],
            Arc::new(Mutex::new(Corrupt {
                source: source.clone(),
            })),
            4,
        )
        .unwrap();
        let destination = Arc::new(Mutex::new(
            Node::open(&bundle, &dir.join("untrusted.sqlite"), pin).unwrap(),
        ));
        let mut client = PeerClient::connect(address, a, bp, gid, fp).unwrap();
        assert!(catch_up(&mut client, &destination, bp, 64).is_err());
        assert_eq!(
            destination.lock().unwrap().store.load().unwrap().0.height,
            0
        );
        assert!(
            !destination
                .lock()
                .unwrap()
                .store
                .integrity_halted()
                .unwrap()
        );
        drop(client);
        drop(destination);
        server.stop().unwrap();
        drop(source);
        for prefix in ["source", "destination", "untrusted", "pushed"] {
            for suffix in ["sqlite", "candidates.sqlite", "received-votes.sqlite"] {
                std::fs::remove_file(dir.join(format!("{prefix}.{suffix}"))).unwrap();
            }
        }
        std::fs::remove_file(bundle).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn certificate_free_candidate_and_durable_vote_finalize_after_restart() {
        let mut lines =
            include_str!("../../qualification/integration-state-v2-1/chain.jsonl").lines();
        let initial = lines.next().unwrap().as_bytes();
        let row: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        let block = BlockEnvelope::decode(&raw(&row["envelope"]).unwrap()).unwrap();
        let candidate = mutinyd_v8::candidate_journal::CandidateRecord {
            header: block.header.clone(),
            body: block.body.clone(),
            authority: block.authority.clone(),
            signature: block.authority_signature,
        };
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!("build8-ingress-{}", hex::encode(random)));
        std::fs::create_dir(&dir).unwrap();
        let bundle = dir.join("genesis.json");
        let db = dir.join("chain.sqlite");
        std::fs::write(&bundle, initial).unwrap();
        let pin: Hash = Sha256::digest(initial).into();
        let mut node = Node::open(&bundle, &db, pin).unwrap();
        assert!(node.voter.is_none());
        for method in ["cast_vote", "enable_tpm", "unknown"] {
            let reply = node
                .peer_request(&serde_json::to_vec(&json!({"id":9,"method":method})).unwrap())
                .unwrap();
            let answer: Value = serde_json::from_slice(&reply.payload).unwrap();
            assert_eq!(answer["error"], "method not available to peer transport");
            assert!(!reply.close);
        }
        let closed = node
            .peer_request(br#"{"id":10,"method":"end_session"}"#)
            .unwrap();
        assert!(closed.close);
        let mut schedule = mutinyd_v8::proposer_cursor::ProposerCursor::default();
        assert_eq!(
            schedule.selected(&mut node.store, 0).unwrap(),
            Some((0, block.certificate.signers[0].node))
        );
        // Network round numbers are not used here. Bounded reconstruction of a
        // locally persisted high round returns backpressure until complete.
        assert!(schedule.selected(&mut node.store, 65).unwrap().is_none());
        assert!(schedule.selected(&mut node.store, 65).unwrap().is_none());
        assert_eq!(
            schedule.selected(&mut node.store, 65).unwrap(),
            Some((65, block.certificate.signers[0].node))
        );
        assert!(schedule.selected(&mut node.store, 64).is_err());
        let signer = &block.certificate.signers[0];
        let vote = Vote {
            nil: false,
            decision: block.certificate.decision.clone(),
            node: signer.node,
            key_version: signer.key_version,
            signature: signer.signature,
        };
        let vote_request = json!({"method":"submit_vote","vote":hex::encode(vote.encode())});
        assert!(node.request(&vote_request).is_err()); // Cannot trust an unexecuted block vote.
        let accepted = node.request(&json!({"method":"submit_candidate","candidate":hex::encode(candidate.encode().unwrap())})).unwrap();
        assert_eq!(accepted["status"], "CANDIDATE_STORED");
        assert_eq!(node.store.load().unwrap().0.height, 0);
        drop(node);
        let mut node = Node::open(&bundle, &db, pin).unwrap();
        let mut invalid = vote.clone();
        invalid.signature[0] ^= 1;
        assert!(
            node.request(&json!({"method":"submit_vote","vote":hex::encode(invalid.encode())}))
                .is_err()
        );
        assert!(node.received_votes.height(1).unwrap().is_empty());
        let committed = node.request(&vote_request).unwrap();
        assert_eq!(committed["finalized"], hex::encode(block.block_hash()));
        assert_eq!(node.store.load().unwrap().0.height, 1);
        assert_eq!(
            schedule.selected(&mut node.store, 0).unwrap(),
            Some((0, block.certificate.signers[0].node))
        );
        assert!(node.voter.is_none()); // Zero local signing authority is sufficient to validate.
        drop(node);
        let mut node = Node::open(&bundle, &db, pin).unwrap();
        assert_eq!(node.store.load().unwrap().0.block, block.block_hash());
        assert_eq!(node.received_votes.height(1).unwrap(), vec![vote.clone()]);
        drop(node);
        let interrupted_db = dir.join("interrupted.sqlite");
        let mut interrupted = Node::open(&bundle, &interrupted_db, pin).unwrap();
        interrupted
            .candidates
            .accept(
                &mut interrupted.store,
                &candidate,
                &interrupted.physical,
                &interrupted.verifier,
            )
            .unwrap();
        interrupted
            .received_votes
            .admit(
                &mut interrupted.store,
                &vote,
                Some(&candidate),
                &interrupted.physical,
                &interrupted.verifier,
            )
            .unwrap();
        assert_eq!(interrupted.store.load().unwrap().0.height, 0);
        drop(interrupted); // Crash boundary: durable quorum, no canonical commit yet.
        let mut resumed = Node::open(&bundle, &interrupted_db, pin).unwrap();
        assert_eq!(resumed.store.load().unwrap().0.block, block.block_hash());
        assert!(resumed.voter.is_none());
        drop(resumed);
        // Explicit generated files only; custody directories are never targeted.
        for name in [
            "genesis.json",
            "chain.sqlite",
            "chain.candidates.sqlite",
            "chain.received-votes.sqlite",
            "interrupted.sqlite",
            "interrupted.candidates.sqlite",
            "interrupted.received-votes.sqlite",
        ] {
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
    }
}
struct Node {
    store: CanonicalStore,
    descriptor: GenesisDescriptor,
    initial: State,
    initial_target: Hash,
    physical: BTreeMap<Hash, PhysicalMember>,
    verifier: Evidence,
    genesis: Hash,
    fingerprint: Hash,
    bundle_hash: Hash,
    voter: Option<VoterActor>,
    signer: Option<SigningBackend>,
    production: bool,
    candidates: mutinyd_v8::candidate_journal::CandidateJournal,
    received_votes: mutinyd_v8::vote_journal::VoteJournal,
}
impl Node {
    /// Test convenience: `open_pinned` without a bundle-selection pin.
    #[cfg(test)]
    fn open(bundle: &Path, db: &Path, expected: Hash) -> std::result::Result<Self, String> {
        Self::open_pinned(bundle, db, expected, None)
    }
    /// Qualification entry point. `profile_pin` is an explicit, optional bundle-SELECTION pin
    /// (`--qualification-stdio` argument or `physical_profile_commitment` in the qualification
    /// runtime configuration). It can only refuse a bundle; it never admits a profile the Genesis
    /// registry does not commit to. No environment variable is consulted.
    fn open_pinned(
        bundle: &Path,
        db: &Path,
        expected: Hash,
        profile_pin: Option<Hash>,
    ) -> std::result::Result<Self, String> {
        let mut bytes = Vec::new();
        std::fs::File::open(bundle)
            .map_err(fail)?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(fail)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("genesis bundle too large".into());
        }
        let bundle_hash: Hash = Sha256::digest(&bytes).into();
        if bundle_hash != expected {
            return Err("pinned Genesis bundle hash mismatch".into());
        }
        let v: Value = serde_json::from_slice(&bytes).map_err(fail)?;
        if v["actual_genesis"] != false {
            return Err("qualification-only binary entry point".into());
        }
        let descriptor = GenesisDescriptor::decode(&raw(&v["descriptor"])?).map_err(fail)?;
        let records: Vec<(Hash, Vec<u8>)> = v["initial_records"]
            .as_array()
            .ok_or("records")?
            .iter()
            .map(|r| Ok((public_hash(&r[0])?, raw(&r[1])?)))
            .collect::<std::result::Result<_, String>>()?;
        let initial = State::from_records(&records, blocks::state_root(&records).map_err(fail)?)
            .map_err(fail)?;
        let authorized = licenses::LicenseBook::genesis_bindings(
            descriptor.id().map_err(fail)?,
            descriptor.fingerprint,
            descriptor.owner,
            descriptor.purchase,
            &initial
                .licenses
                .workers
                .values()
                .map(|worker| worker.binding.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(fail)?;
        if authorized.records().map_err(fail)? != initial.licenses.records().map_err(fail)? {
            return Err(
                "Genesis license state differs from the twelve authorized initial bindings".into(),
            );
        }
        let profile = if v["physical_evidence_fixture_only"] == false {
            // Physical evidence arrives at RUNTIME with the pinned bundle (bundle hash is already
            // pinned by the operator above); no host profile is compiled into this binary.
            // The carried profile is fully verified (certify signature, voting-key name) by
            // `TpmProfile::decode`, and every physical member's attestation commitment must equal
            // its commitment, so Genesis evidence can only verify against the committed profile.
            let p = TpmProfile::decode(&raw(&v["physical_profile"]["profile"])?).map_err(fail)?;
            if p.is_test_value() {
                return Err("software test-value profile is not physical evidence".into());
            }
            let commitment = p.commitment().map_err(fail)?;
            // Optional explicit bundle-selection pin: narrowing only.
            if profile_pin.is_some_and(|pin| pin != commitment) {
                return Err("unqualified physical profile".into());
            }
            let members = &initial.continuity.as_ref().ok_or("registry")?.members;
            if members.is_empty() || members.iter().any(|m| m.attestation != commitment) {
                return Err("unqualified physical profile".into());
            }
            Some(p)
        } else if v["physical_evidence_fixture_only"] == true {
            if profile_pin.is_some() {
                return Err("physical profile pin supplied for a bundle without physical evidence".into());
            }
            None
        } else {
            return Err("evidence mode required".into());
        };
        let physical: BTreeMap<_, _> = initial
            .continuity
            .as_ref()
            .ok_or("registry")?
            .members
            .iter()
            .map(|m| {
                (
                    m.node,
                    PhysicalMember {
                        node: m.node,
                        generation: m.generation,
                        continuity_key: m.voting_key,
                        hardware: m.hardware,
                        admission_commitment: m.attestation,
                        attestation_key: profile
                            .as_ref()
                            .map(|p| p.ak_public.clone())
                            .unwrap_or(vec![6; 33]),
                    },
                )
            })
            .collect();
        let verifier = if let Some(p) = profile {
            Evidence::Physical(PinnedTpmVerifier {
                profiles: BTreeMap::from([(p.commitment().map_err(fail)?, p)]),
            })
        } else {
            Evidence::Fixture
        };
        let genesis = descriptor.id().map_err(fail)?;
        if matches!(verifier, Evidence::Physical(_)) {
            if public_hash(&v["genesis_prestate"])? != genesis {
                return Err("Genesis proof binding".into());
            }
            if physical.len() != 1 {
                return Err("qualified initial physical set required".into());
            }
            let member = physical.values().next().ok_or("physical member")?;
            let record = validate_genesis(
                genesis,
                public_hash(&v["genesis_nonce"])?,
                member,
                &raw(&v["genesis_evidence"])?,
                &verifier,
            )
            .map_err(fail)?;
            if initial.accounting.freshness.get(&member.node) != Some(&record) {
                return Err("Genesis freshness mismatch".into());
            }
        }
        Self::from_initial(
            db,
            descriptor,
            initial,
            public_hash(&v["initial_target"])?,
            bundle_hash,
            physical,
            verifier,
        )
    }
    fn open_sealed(
        bundle: &Path,
        db: &Path,
        trust: &mutinyd_v8::genesis_artifact::Trust,
    ) -> std::result::Result<Self, String> {
        let verified = mutinyd_v8::genesis_artifact::VerifiedGenesis::load(bundle, trust)?;
        let registry = verified
            .initial
            .continuity
            .as_ref()
            .ok_or("Sealed Genesis registry missing")?;
        // Class from the sealed state's committed Genesis data; a Production trust profile only
        // ever yields a Production-class state (`genesis_inputs::genesis_admission_class`).
        let class = verified.initial.admission_class().map_err(fail)?;
        let (physical, verifier) = verified
            .initial
            .admission
            .physical_context(registry, class)
            .map_err(fail)?;
        let mut node = Self::from_initial(
            db,
            verified.descriptor,
            verified.initial,
            verified.target,
            verified.artifact_sha256,
            physical,
            Evidence::Physical(verifier),
        )?;
        node.production = true;
        Ok(node)
    }
    fn from_initial(
        db: &Path,
        descriptor: GenesisDescriptor,
        initial: State,
        initial_target: Hash,
        bundle_hash: Hash,
        physical: BTreeMap<Hash, PhysicalMember>,
        verifier: Evidence,
    ) -> std::result::Result<Self, String> {
        let genesis = descriptor.id().map_err(fail)?;
        let store = CanonicalStore::open_trusted_genesis(db, &descriptor, &initial, initial_target)
            .map_err(fail)?;
        let mut node = Self {
            candidates: mutinyd_v8::candidate_journal::CandidateJournal::open(
                &db.with_extension("candidates.sqlite"),
                genesis,
                descriptor.fingerprint,
                64 * 1024 * 1024,
            )?,
            received_votes: mutinyd_v8::vote_journal::VoteJournal::open(
                &db.with_extension("received-votes.sqlite"),
                genesis,
                descriptor.fingerprint,
            )?,
            store,
            physical,
            verifier,
            genesis,
            fingerprint: descriptor.fingerprint,
            descriptor,
            initial,
            initial_target,
            bundle_hash,
            voter: None,
            signer: None,
            production: false,
        };
        // A crash may occur after durable quorum ingress but before canonical
        // publication. Reexecute and finish that transition on startup; this
        // never signs or initializes TPM custody.
        node.finalize_received()?;
        Ok(node)
    }
    fn enable_production_tpm(
        &mut self,
        path: &Path,
        node: Hash,
        custody: &ProductionCustody,
        initialize: bool,
    ) -> std::result::Result<(), String> {
        if !self.production || !cfg!(target_os = "linux") {
            return Err("Sealed host-local production context required".into());
        }
        if initialize {
            if path.try_exists().map_err(fail)? || self.store.load().map_err(fail)?.0.height != 0 {
                return Err(
                    "Fresh production custody requires absent journal and height zero".into(),
                );
            }
        } else if !std::fs::symlink_metadata(path).map_err(fail)?.is_file() {
            return Err("Existing production voter journal required".into());
        }
        let physical = self
            .physical
            .get(&node)
            .ok_or("Production voter is not admitted")?;
        let pins = production_pins(self.genesis, self.fingerprint, physical, custody);
        let native = mutinyd_v8::tpm_backend::NativeTpm::open(pins, &custody.helper)?;
        let pinned = native.genesis_counter();
        let mut backend: SigningBackend = native;
        let mut build = |backend: &mut SigningBackend, initial| {
            VoterActor::open(
                path,
                node,
                initial,
                &mut self.store,
                backend,
                &self.physical,
                &self.verifier,
            )
            .map_err(fail)
        };
        let voter = if initialize {
            mutinyd_v8::custody_initialization::initialize(path, pinned, &mut backend, |backend| {
                build(backend, Some(pinned))
            })?
        } else {
            build(&mut backend, None)?
        };
        self.voter = Some(voter);
        self.signer = Some(backend);
        Ok(())
    }
    fn finalize_received(&mut self) -> std::result::Result<Option<String>, String> {
        let proposals = self.candidates.records()?;
        let block = self.received_votes.finalize_ready(
            &mut self.store,
            &proposals,
            &self.physical,
            &self.verifier,
        )?;
        if block.is_some() {
            if let Some(voter) = self.voter.as_mut() {
                voter
                    .reconcile(
                        &mut self.store,
                        self.signer.as_mut().ok_or("TPM signer unavailable")?,
                        &self.physical,
                        &self.verifier,
                    )
                    .map_err(fail)?;
            }
        }
        Ok(block.map(|b| hex::encode(b.block_hash())))
    }
    fn request(&mut self, v: &Value) -> std::result::Result<Value, String> {
        match v["method"].as_str().ok_or("method required")? {
            "status" => {
                let (tip, state) = self.store.load().map_err(fail)?;
                let anchor = FinalizedAnchor {
                    network: NETWORK_ID,
                    genesis: self.genesis,
                    fingerprint: self.fingerprint,
                    height: tip.height,
                    block: tip.block,
                };
                Ok(
                    json!({"height":tip.height,"block_hash":hex::encode(tip.block),"state_root":hex::encode(tip.root),
                    "finalized_anchor":hex::encode(anchor.id()),"next_target":hex::encode(tip.next_target),
                    "genesis_id":hex::encode(self.genesis),"protocol_fingerprint":hex::encode(self.fingerprint),
                    "bundle_sha256":hex::encode(self.bundle_hash),"integrity_halted":self.store.integrity_halted().map_err(fail)?,
                    "continuity_mode":state.continuity.ok_or("registry")?.mode(),
                    "qualification_only":true,"voting_enabled":self.voter.is_some(),"voter_height":self.voter.as_ref().map(VoterActor::height)}),
                )
            }
            "state_proof" => {
                let encoded = v["request"].as_str().ok_or("proof request required")?;
                if encoded.len() > 2 * mutinyd_v8::state_proof_service::MAX_REQUEST {
                    return Err("proof request bound".into());
                }
                let request = hex::decode(encoded).map_err(fail)?;
                let proof = mutinyd_v8::state_proof_service::respond(&mut self.store, &request)
                    .map_err(fail)?;
                Ok(json!({"proof":hex::encode(proof)}))
            }
            "submit_candidate" => {
                let encoded = v["candidate"].as_str().ok_or("candidate required")?;
                if encoded.len() > 2 * 69632 {
                    return Err("candidate request bound".into());
                }
                let proposal = mutinyd_v8::candidate_journal::CandidateRecord::decode(
                    &hex::decode(encoded).map_err(fail)?,
                )?;
                // No wall-clock admission bound: timestamps are consensus data validated by the
                // deterministic rules; signing a block vote is gated by the qualified clock.
                self.candidates.accept(
                    &mut self.store,
                    &proposal,
                    &self.physical,
                    &self.verifier,
                )?;
                if let Some(voter) = self.voter.as_mut() {
                    voter
                        .validate_candidate(
                            &mut self.store,
                            voter_actor::Proposal {
                                header: &proposal.header,
                                body: &proposal.body,
                                authority: &proposal.authority,
                                signature: &proposal.signature,
                            },
                            &self.physical,
                            &self.verifier,
                        )
                        .map_err(fail)?;
                }
                let finalized = self.finalize_received()?;
                Ok(
                    json!({"status":"CANDIDATE_STORED","block_hash":hex::encode(proposal.header.block_hash()),"finalized":finalized}),
                )
            }
            "submit_vote" => {
                let encoded = v["vote"].as_str().ok_or("vote required")?;
                if encoded.len() > 4096 {
                    return Err("vote request bound".into());
                }
                let vote = Vote::decode(&hex::decode(encoded).map_err(fail)?).map_err(fail)?;
                let proposals = self.candidates.records()?;
                let proposal = proposals
                    .iter()
                    .find(|p| p.header.block_hash() == vote.decision.block);
                let added = self.received_votes.admit(
                    &mut self.store,
                    &vote,
                    proposal,
                    &self.physical,
                    &self.verifier,
                )?;
                if let Some(voter) = self.voter.as_mut() {
                    voter.observe(&vote).map_err(fail)?;
                }
                let finalized = self.finalize_received()?;
                Ok(json!({"status":if added{"VOTE_STORED"}else{"DUPLICATE"},"finalized":finalized}))
            }
            "submit_block" => {
                let block = BlockEnvelope::decode(&raw(&v["envelope"])?).map_err(fail)?;
                // F4 (Architect, 2 Oct 2026): finalized-history ingestion consults NO receiver
                // time source. `commit_integrated` validates network, Genesis, membership, quorum,
                // signatures and the state transition deterministically, and routes a block at an
                // already-finalized height to the conflict/duplicate inspection (durable halt on
                // valid conflicting finality). A request labelled "finalized" is never trusted.
                let accepted = self
                    .store
                    .commit_integrated(&block, &self.physical, &self.verifier)
                    .map_err(fail)?;
                if let Some(voter) = self.voter.as_mut() {
                    voter
                        .reconcile(
                            &mut self.store,
                            self.signer.as_mut().ok_or("TPM signer unavailable")?,
                            &self.physical,
                            &self.verifier,
                        )
                        .map_err(fail)?;
                }
                Ok(
                    json!({"status":if accepted{"COMMITTED"}else{"ALREADY_FINALIZED"},"block_hash":hex::encode(block.block_hash())}),
                )
            }
            "get_block" => Ok(
                json!({"envelope":self.store.block_bytes(v["height"].as_u64().ok_or("height")?).map_err(fail)?.map(hex::encode)}),
            ),
            "get_recovery" => Ok(
                json!({"envelope":self.store.recovery_envelope(v["height"].as_u64().ok_or("height")?).map_err(fail)?.map(hex::encode)}),
            ),
            "submit_recovery" => {
                let added = self
                    .store
                    .accept_recovery_envelope(&raw(&v["recovery"])?)
                    .map_err(fail)?;
                Ok(json!({"status":if added{"RECOVERY_COMMITTED"}else{"ALREADY_COMMITTED"}}))
            }
            "submit_transaction" => {
                let tx = Transfer::decode(&raw(&v["transaction"])?).map_err(fail)?;
                let status = self.store.admit(&tx).map_err(fail)?;
                Ok(
                    json!({"transaction_id":hex::encode(tx.id().map_err(fail)?),"status":status.text()}),
                )
            }
            "submit_equivocation" => {
                let proof = equivocation::Evidence::decode(&raw(&v["evidence"])?).map_err(fail)?;
                let status = self
                    .store
                    .admit_equivocation(&proof, 64 * 1024 * 1024)
                    .map_err(fail)?;
                Ok(json!({"evidence_id":hex::encode(proof.id()),"status":status.text()}))
            }
            "equivocation_status" => Ok(
                json!({"status":self.store.equivocation_status(public_hash(&v["evidence_id"])?).map_err(fail)?.map(|s|s.text())}),
            ),
            "transaction_status" => Ok(
                json!({"status":self.store.transaction_status(public_hash(&v["transaction_id"])?).map_err(fail)?.map(|s|s.text())}),
            ),
            "validate_proposal" => {
                let block = BlockEnvelope::decode(&raw(&v["envelope"])?).map_err(fail)?;
                // No wall-clock admission bound (see submit_candidate).
                self.voter
                    .as_mut()
                    .ok_or("voting disabled")?
                    .validate_proposal(&mut self.store, &block, &self.physical, &self.verifier)
                    .map_err(fail)?;
                Ok(json!({"status":"VALIDATED","block_hash":hex::encode(block.block_hash())}))
            }
            "observe_vote" => {
                let vote = Vote::decode(&raw(&v["vote"])?).map_err(fail)?;
                self.voter
                    .as_mut()
                    .ok_or("voting disabled")?
                    .observe(&vote)
                    .map_err(fail)?;
                Ok(json!({"status":"OBSERVED"}))
            }
            "cast_vote" => {
                let step = match v["step"].as_str() {
                    Some("prevote") => Step::Prevote,
                    Some("precommit") => Step::Precommit,
                    _ => return Err("invalid vote step".into()),
                };
                let block = if v["block_hash"].is_null() {
                    None
                } else {
                    Some(public_hash(&v["block_hash"])?)
                };
                let pol = if v["pol_round"].is_null() {
                    None
                } else {
                    Some(v["pol_round"].as_u64().ok_or("round")?)
                };
                let vote = self
                    .voter
                    .as_mut()
                    .ok_or("voting disabled")?
                    .sign(
                        &mut self.store,
                        step,
                        block,
                        pol,
                        self.signer.as_mut().ok_or("TPM signer unavailable")?,
                    )
                    .map_err(fail)?;
                Ok(json!({"vote":hex::encode(vote.encode())}))
            }
            "timeout_precommit" => {
                let next = self
                    .voter
                    .as_mut()
                    .ok_or("voting disabled")?
                    .timeout_precommit(
                        &mut self.store,
                        self.signer.as_mut().ok_or("TPM signer unavailable")?,
                    )
                    .map_err(fail)?;
                Ok(
                    json!({"next_round":next,"status":if next.is_some(){"ADVANCED"}else{"WAITING_DEADLINE"}}),
                )
            }
            "participation_ack" | "attestation_refresh" | "work_liveness_signature" => {
                let signer = self.signer.as_mut().ok_or("physical signing disabled")?;
                self.voter
                    .as_mut()
                    .ok_or("voting disabled")?
                    .check_backend(&mut self.store, signer)
                    .map_err(fail)?;
                let (tip, state) = self.store.load_effective().map_err(fail)?;
                let member = state
                    .continuity
                    .as_ref()
                    .ok_or("registry")?
                    .members
                    .iter()
                    .find(|m| m.voting_key == signer.public_key() && m.physical && m.eligible)
                    .ok_or("ineligible physical member")?;
                let parent = FinalizedAnchor {
                    network: NETWORK_ID,
                    genesis: self.genesis,
                    fingerprint: self.fingerprint,
                    height: tip.height,
                    block: tip.block,
                };
                let height = tip.height.checked_add(1).ok_or("height overflow")?;
                if v["method"] == "work_liveness_signature" {
                    let registry = state.continuity.as_ref().ok_or("registry")?;
                    let (membership, reputation, attestation) = registry.roots().map_err(fail)?;
                    let authority = votes::HeightAuthority {
                        parent,
                        membership,
                        reputation,
                        attestation,
                        voters: registry.voters().map_err(fail)?,
                    };
                    let decision =
                        certificates::Decision::decode(&raw(&v["decision"])?).map_err(fail)?;
                    let signature = liveness::sign_probe(
                        &decision,
                        &authority,
                        state.root().map_err(fail)?,
                        member.node,
                        signer,
                    )
                    .map_err(fail)?;
                    let fragment = certificates::Certificate {
                        decision,
                        signers: vec![signature],
                    };
                    Ok(
                        json!({"proof_fragment":hex::encode(fragment.encode().map_err(fail)?),"quorum_established":false,"bft_lock_changed":false,"counter_incremented":false}),
                    )
                } else if v["method"] == "participation_ack" {
                    let mut ack = participation::ParticipationAck {
                        network: NETWORK_ID,
                        genesis: self.genesis,
                        fingerprint: self.fingerprint,
                        node: member.node,
                        height,
                        parent: parent.id(),
                        generation: member.generation,
                        signature: [0; 64],
                    };
                    let projected = participation::ParentMember {
                        node: member.node,
                        generation: member.generation,
                        key: member.voting_key,
                        admitted: true,
                        physical: true,
                        revoked: false,
                        freshness: state.accounting.freshness.get(&member.node).cloned(),
                    };
                    if !projected.freshness.as_ref().is_some_and(|f| {
                        f.eligible(member.node, member.generation, member.voting_key, height)
                    }) {
                        return Err(
                            "parent attestation freshness expired; no participation credit".into(),
                        );
                    }
                    ack.signature = signer.sign_digest(ack.signing_digest())?;
                    ack.verify(&parent, &projected).map_err(fail)?;
                    Ok(
                        json!({"operation":hex::encode(ack.encode()),"height":height,"parent_anchor":hex::encode(parent.id())}),
                    )
                } else {
                    let mut refresh = freshness::AttestationRefresh {
                        network: NETWORK_ID,
                        genesis: self.genesis,
                        fingerprint: self.fingerprint,
                        node: member.node,
                        height,
                        parent_anchor: parent.id(),
                        generation: member.generation,
                        evidence: vec![],
                    };
                    refresh.evidence = signer.quote(refresh.challenge())?;
                    refresh
                        .validate(
                            &parent,
                            self.physical
                                .get(&member.node)
                                .ok_or("admitted physical profile")?,
                            &self.verifier,
                        )
                        .map_err(fail)?;
                    Ok(
                        json!({"operation":hex::encode(refresh.encode().map_err(fail)?),"effective_first_height":height.checked_add(1).ok_or("height overflow")?,
                        "effective_last_height":height.checked_add(60).ok_or("height overflow")?}),
                    )
                }
            }
            _ => Err("unknown method".into()),
        }
    }
}
fn main() -> std::result::Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len()==2 && args[1]=="--run-installed-v2" {
        #[cfg(target_os="linux")]
        {return mutinyd_v8::hybrid_installed_actor_v2::run_installed();}
        #[cfg(not(target_os="linux"))]
        {return Err("ordinary installed V2 private factory is not supported on this platform; no fallback source selected".into());}
    }
    if args.len()==4 && args[1]=="--qualification-hybrid-stdio" {
        return mutinyd_v8::hybrid_application_stdio_v2::run(Path::new(&args[2]),public_hash(&json!(args[3]))?);
    }
    if args.len() == 5 && args[1] == "--verify-sealed-genesis" {
        let trust = mutinyd_v8::genesis_artifact::supported_trust(
            public_hash(&json!(args[3]))?,
            public_hash(&json!(args[4]))?,
        )?;
        let verified =
            mutinyd_v8::genesis_artifact::VerifiedGenesis::load(Path::new(&args[2]), &trust)?;
        let member = &verified
            .initial
            .continuity
            .as_ref()
            .ok_or("Genesis registry")?
            .members[0];
        println!(
            "{}",
            json!({"schema":"BUILD8-SEALED-GENESIS-VERIFIED-V1","result":"LEGACY_FORMAT_VALID",
            "production_qualified":false,"qualification_only":true,
            "artifact_sha256":hex::encode(verified.artifact_sha256),
            "genesis_block_hash":hex::encode(trust.genesis_block_hash),
            "genesis_id":hex::encode(verified.descriptor.id().map_err(fail)?),
            "protocol_fingerprint":hex::encode(verified.descriptor.fingerprint),
            "state_root":hex::encode(verified.initial.root().map_err(fail)?),
            "node_id":hex::encode(member.node),"hardware_generation":member.generation,
            "voting_public":hex::encode(member.voting_key),"database_opened":false,
            "tpm_accessed":false})
        );
        return Ok(());
    }
    if args.len() == 3 && args[1] == "--qualification-runtime" {
        return configured_runtime(Path::new(&args[2]), false, false);
    }
    if args.len() == 3 && args[1] == "--initialize-production-custody" {
        return configured_runtime(Path::new(&args[2]), true, true);
    }
    if args.len() == 3 && args[1] == "--run" {
        return configured_runtime(Path::new(&args[2]), true, false);
    }
    if args.len() == 3 && args[1] == "--qualification-create-peer-key" {
        return create_peer_key(Path::new(&args[2]));
    }
    let peer_mode = args.len() == 8 && args[1] == "--qualification-peer-once";
    let peer_server_mode = args.len() == 8 && args[1] == "--qualification-peer-server";
    let checkpoint_mode = args.len() == 8 && args[1] == "--qualification-checkpoint-copy";
    let profile_pin = stdio_profile_pin(&args)?;
    if !peer_mode
        && !peer_server_mode
        && !checkpoint_mode
        && (!matches!(args.len(), 5 | 6) || args[1] != "--qualification-stdio")
    {
        return Err("usage: mutinyd-v8 --qualification-stdio genesis-bundle.json chain.sqlite expected-bundle-sha256 [physical-profile-commitment-hex]; or --run production-config.json".into());
    }
    let mut node = Node::open_pinned(
        Path::new(&args[2]),
        Path::new(&args[3]),
        hex::decode(&args[4])
            .map_err(fail)?
            .try_into()
            .map_err(|_| "bundle digest")?,
        profile_pin,
    )?;
    if checkpoint_mode {
        struct RejectLegacy;
        impl recovery::PhysicalAdmissionVerifier for RejectLegacy {
            fn verify_replacement(&self, _: &recovery::Recovery) -> Result<()> {
                Err(Error::UnqualifiedPhysical)
            }
        }
        let budget = args[7].parse::<u64>().map_err(fail)?;
        let exported = node
            .store
            .export_checkpoint(Path::new(&args[5]), budget)
            .map_err(fail)?;
        let (mut restored, verified) = canonical_store::checkpoint::restore_checkpoint(
            canonical_store::checkpoint::CheckpointRestore {
                archive: Path::new(&args[5]),
                database: Path::new(&args[6]),
                descriptor: &node.descriptor,
                initial: &node.initial,
                initial_target: node.initial_target,
                physical: &node.physical,
                attestation: &node.verifier,
                legacy_recovery: &RejectLegacy,
                byte_budget: budget,
            },
        )
        .map_err(fail)?;
        if exported != verified
            || restored.load().map_err(fail)?.1.records().map_err(fail)?
                != node.store.load().map_err(fail)?.1.records().map_err(fail)?
        {
            return Err("checkpoint copy mismatch".into());
        }
        println!(
            "{}",
            json!({"schema":"BUILD8-CHECKPOINT-QUALIFICATION-V1","result":"PASS","height":verified.tip.height,
            "state_root":hex::encode(verified.tip.root),"block_hash":hex::encode(verified.tip.block),"records":verified.records,
            "archive_sha256":hex::encode(verified.archive_hash),"bytes":verified.bytes,"source_pruned":false,
            "retention_frontier":verified.retention_frontier,"voter_custody_restored":false,"actual_genesis":false})
        );
        return Ok(());
    }
    if peer_server_mode {
        return peer_server(
            node,
            Path::new(&args[5]),
            public_hash(&Value::String(args[6].clone()))?,
            &args[7],
        );
    }
    if peer_mode {
        return peer_once(
            &mut node,
            Path::new(&args[5]),
            public_hash(&Value::String(args[6].clone()))?,
            &args[7],
        );
    }
    let stdin = std::io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let mut output = std::io::stdout().lock();
    loop {
        let mut raw = Vec::new();
        let count = Read::by_ref(&mut input)
            .take(1024 * 1024 + 1)
            .read_until(b'\n', &mut raw)
            .map_err(fail)?;
        if count == 0 {
            break;
        }
        if count > 1024 * 1024 || raw.last() != Some(&b'\n') {
            return Err("RPC frame bound".into());
        }
        let request: std::result::Result<Value, _> = serde_json::from_slice(&raw);
        let response = match request {
            Ok(v) => match node.request(&v) {
                Ok(result) => json!({"id":v["id"],"result":result}),
                Err(error) => json!({"id":v["id"],"error":error}),
            },
            Err(_) => json!({"error":"malformed JSON"}),
        };
        writeln!(output, "{response}").map_err(fail)?;
        output.flush().map_err(fail)?;
    }
    Ok(())
}

#[cfg(test)]
mod custody_configuration_tests {
    use super::*;
    fn runtime_config(production: bool) -> Value {
        let mut c = json!({"schema": if production {"BUILD8-RUNTIME-V1"} else {"BUILD8-QUALIFICATION-RUNTIME-V1"},
            "actual_genesis": production, "bundle": "/b", "bundle_sha256": "00", "database": "/d",
            "database_byte_limit": 1, "worker_key": "/w", "peer_key": "/p", "worker_bind": "127.0.0.1:1",
            "peer_bind": "127.0.0.1:2", "worker_connections": 1, "peer_connections": 1, "allowed_peers": [],
            "outbound": [], "clock": {}});
        if production {
            c["genesis_block_hash"] = json!("00");
            c["filesystem_reserve_bytes"] = json!(1);
        }
        c
    }
    fn helper() -> Value {
        json!({"privilege":"sudo-n","argv":[{"path":"/usr/bin/python3.12","sha256":null},{"path":"/opt/mutiny/custody/helper.py","sha256":"11".repeat(32)}]})
    }
    fn voter() -> Value {
        json!({"node":"01".repeat(32),"journal":"/var/lib/mutiny/voter.sqlite","node_auth_key":"/etc/mutiny/node.key",
            "custody_manifest_sha256":"02".repeat(32),"counter_index":25_165_825u64,
            "counter_public_sha256":"03".repeat(32),"tpm_helper":helper()})
    }
    /// Shipping binaries contain no qualification custody: both former entry forms are refused
    /// with an explicit message, while the non-voting qualification runtime stays available.
    #[test]
    fn qualification_physical_custody_is_refused_in_shipping_binaries() {
        let args = |n: usize| -> Vec<String> {
            ["mutinyd-v8", "--qualification-stdio", "b.json", "c.sqlite", "00", "voter.sqlite", "resume"][..n]
                .iter()
                .map(|s| s.to_string())
                .collect()
        };
        assert_eq!(stdio_profile_pin(&args(7)).unwrap_err(), QUALIFICATION_CUSTODY_REFUSED);
        assert_eq!(stdio_profile_pin(&args(5)).unwrap(), None);
        let mut qualification = runtime_config(false);
        check_runtime_fields(&qualification, false).unwrap();
        qualification["physical_profile_commitment"] = json!("04".repeat(32));
        check_runtime_fields(&qualification, false).unwrap();
        qualification["physical_voter"] = voter();
        assert_eq!(
            check_runtime_fields(&qualification, false).unwrap_err(),
            QUALIFICATION_CUSTODY_REFUSED
        );
        let mut production = runtime_config(true);
        check_runtime_fields(&production, true).unwrap();
        production["physical_voter"] = voter();
        check_runtime_fields(&production, true).unwrap();
        production["physical_profile_commitment"] = json!("04".repeat(32));
        assert!(check_runtime_fields(&production, true).is_err(), "no bundle pin in production");
    }
    /// The production custody object has an exact field set; the helper is explicit runtime
    /// configuration and the counter pins are explicit fields (no compiled-in index or pin).
    #[test]
    fn production_custody_fields_are_exact_and_explicit() {
        let custody = production_custody(&voter()).unwrap();
        assert_eq!(custody.counter_index, 25_165_825);
        assert_eq!(custody.counter_public_sha256, [3; 32]);
        assert_eq!(custody.manifest_sha256, [2; 32]);
        assert!(custody.helper.sudo);
        for field in PHYSICAL_VOTER_FIELDS {
            let mut missing = voter();
            missing.as_object_mut().unwrap().remove(field);
            assert!(production_custody(&missing).is_err(), "{field}");
        }
        let mut extra = voter();
        extra["initial_counter"] = json!(1);
        assert!(production_custody(&extra).is_err());
        let mut wide = voter();
        wide["counter_index"] = json!(u64::from(u32::MAX) + 1);
        assert!(production_custody(&wide).is_err());
        let mut relative = voter();
        relative["tpm_helper"]["argv"][0]["path"] = json!("python3");
        assert!(production_custody(&relative).is_err());
    }
    /// Pins come from the ADMITTED PhysicalMember (consensus state), never the reverse: changing
    /// any helper or channel setting cannot change the GenesisID, fingerprint, NodeID or voting
    /// key the channel must prove, and no configuration value is a consensus input.
    #[test]
    fn custody_pins_take_identity_from_consensus_and_helper_config_changes_nothing_else() {
        let member = PhysicalMember {
            node: [9; 32],
            generation: 3,
            continuity_key: [2; 33],
            hardware: [4; 32],
            admission_commitment: [5; 32],
            attestation_key: vec![6; 33],
        };
        let a = production_custody(&voter()).unwrap();
        let mut other = voter();
        other["tpm_helper"] = json!({"privilege":"none","argv":[{"path":"/usr/local/libexec/other-helper","sha256":null}]});
        other["counter_index"] = json!(7);
        let b = production_custody(&other).unwrap();
        let (pa, pb) = (production_pins([7; 32], [8; 32], &member, &a), production_pins([7; 32], [8; 32], &member, &b));
        for p in [&pa, &pb] {
            assert_eq!((p.genesis, p.fingerprint, p.node, p.voting_key), ([7; 32], [8; 32], member.node, member.continuity_key));
        }
        assert_ne!(pa.counter_index, pb.counter_index, "channel pins differ, identity does not");
        // `production_pins` only borrows the member immutably: configuration cannot write
        // consensus-derived data.
    }
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut salt = [0; 8];
        getrandom::getrandom(&mut salt).unwrap();
        let dir = std::env::temp_dir().join(format!("build8-{tag}-{}", hex::encode(salt)));
        std::fs::create_dir(&dir).unwrap();
        dir
    }
    /// T10 (explicit pin form): the qualification bundle-selection pin only narrows. It cannot
    /// admit a profile that the Genesis registry does not commit to, and it refuses a bundle that
    /// carries no physical profile. No environment variable is consulted at all.
    #[test]
    fn physical_profile_pin_only_narrows_and_never_admits() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../qualification/RECOVERY-TRANSPORT-VECTORS-V1.json"
        ))
        .unwrap();
        let dir = temp_dir("profile-pin");
        let write = |name: &str, bundle: &Value| -> (std::path::PathBuf, Hash) {
            let bytes = serde_json::to_vec(bundle).unwrap();
            let file = dir.join(name);
            std::fs::write(&file, &bytes).unwrap();
            (file, Sha256::digest(&bytes).into())
        };
        // Fixture-only bundle: no pin opens; any pin is refused (nothing to select).
        let (fixture_file, fixture_pin) = write("fixture.json", &fixture["bundle"]);
        let opened = Node::open_pinned(&fixture_file, &dir.join("open.sqlite"), fixture_pin, None).unwrap();
        drop(opened);
        let err = Node::open_pinned(&fixture_file, &dir.join("pinned.sqlite"), fixture_pin, Some([1; 32]))
            .err()
            .unwrap();
        assert!(err.contains("without physical evidence"), "{err}");
        assert!(!dir.join("pinned.sqlite").exists());
        // Physical-evidence bundle whose profile no member commits to: no pin, the matching pin
        // and a different pin are all refused; the matching pin cannot admit it.
        let tpm = runtime_ingress_tests::software_tpm::TestTpm::unmarked_negative_control();
        let commitment = tpm.profile().commitment().unwrap();
        let mut bundle = fixture["bundle"].clone();
        bundle["physical_evidence_fixture_only"] = Value::Bool(false);
        bundle["physical_profile"] = json!({"profile": hex::encode(tpm.profile().encode().unwrap())});
        let (file, pin) = write("physical.json", &bundle);
        for (case, profile_pin) in [("none", None), ("matching", Some(commitment)), ("other", Some([1; 32]))] {
            let db = dir.join(format!("{case}.sqlite"));
            let err = Node::open_pinned(&file, &db, pin, profile_pin).err().expect(case);
            assert!(err.contains("unqualified physical profile"), "{case}: {err}");
            assert!(!db.exists());
        }
        // Only files this test created exist in its unique directory.
        for entry in std::fs::read_dir(&dir).unwrap() {
            let e = entry.unwrap();
            assert!(e.file_type().unwrap().is_file());
            std::fs::remove_file(e.path()).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
    }
}
#[cfg(test)]
mod production_launch_fence_tests {
    #[test]
    fn production_and_custody_entry_points_fail_before_configuration_or_platform_access() {
        let nonexistent=std::path::Path::new("BUILD8-NONEXISTENT-QUALIFICATION-CONFIGURATION");
        for (production,initialize) in [(true,false),(true,true),(false,true)] {
            assert_eq!(super::configured_runtime(nonexistent,production,initialize).unwrap_err(),
                mutinyd_v8::production_gate::CLOSED_REASON);
        }
    }
}
fn configured_runtime(
    path: &Path,
    production: bool,
    initialize_custody: bool,
) -> std::result::Result<(), String> {
    if production || initialize_custody {
        mutinyd_v8::production_gate::require_production_ready()?;
    }
    if !cfg!(target_os = "linux") {
        return Err("Configured runtime key custody requires Linux".into());
    }
    use mutinyd_v8::{
        body_assembler::Assembler,
        integrated_actor::IntegratedActor,
        operation_pool::OperationPool,
        peer_supervisor::PeerTarget,
        runtime_service::{NetworkConfig, RuntimeService},
        worker_coordinator::{JournaledCandidates, WorkerCoordinator},
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        net::SocketAddr,
        sync::{Arc, Mutex, mpsc},
    };
    fn key(path: &Path) -> std::result::Result<ed25519_dalek::SigningKey, String> {
        let metadata = std::fs::symlink_metadata(path).map_err(fail)?;
        if !metadata.is_file() || metadata.len() != 32 {
            return Err("Runtime key custody file/permissions".into());
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("Runtime key custody file/permissions".into());
        }
        let seed = zeroize::Zeroizing::new(std::fs::read(path).map_err(fail)?);
        Ok(ed25519_dalek::SigningKey::from_bytes(
            seed.as_slice().try_into().map_err(|_| "key length")?,
        ))
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(fail)?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(fail)?;
    if bytes.len() > 65536 {
        return Err("Runtime configuration bound".into());
    }
    let c: Value = serde_json::from_slice(&bytes).map_err(fail)?;
    check_runtime_fields(&c, production)?;
    let object = c.as_object().ok_or("Runtime configuration object")?;
    let file = |field: &str| -> std::result::Result<&Path, String> {
        let path = Path::new(c[field].as_str().ok_or("Runtime path")?);
        if !path.is_absolute() {
            return Err("Runtime paths must be absolute".into());
        }
        Ok(path)
    };
    let address = |field: &str| -> std::result::Result<SocketAddr, String> {
        let address: SocketAddr = c[field]
            .as_str()
            .ok_or("Runtime address")?
            .parse()
            .map_err(fail)?;
        if !production && !address.ip().is_loopback() {
            return Err("Qualification listener must be loopback".into());
        }
        Ok(address)
    };
    let targets = c["outbound"]
        .as_array()
        .ok_or("Outbound peers")?
        .iter()
        .map(|peer| {
            let obj = peer.as_object().ok_or("Outbound peer object")?;
            if obj.len() != 2 || !obj.contains_key("address") || !obj.contains_key("public") {
                return Err("Outbound peer fields".into());
            }
            let address: SocketAddr = peer["address"]
                .as_str()
                .ok_or("Outbound address")?
                .parse()
                .map_err(fail)?;
            if !production && !address.ip().is_loopback() {
                return Err("Qualification outbound must be loopback".into());
            }
            Ok(PeerTarget {
                address,
                public: public_hash(&peer["public"])?,
            })
        })
        .collect::<std::result::Result<Vec<_>, String>>()?;
    let config = NetworkConfig {
        worker_bind: address("worker_bind")?,
        peer_bind: address("peer_bind")?,
        worker_connections: c["worker_connections"]
            .as_u64()
            .ok_or("Worker limit")?
            .try_into()
            .map_err(fail)?,
        peer_connections: c["peer_connections"]
            .as_u64()
            .ok_or("Peer limit")?
            .try_into()
            .map_err(fail)?,
        allowed_peers: c["allowed_peers"]
            .as_array()
            .ok_or("Peer pins")?
            .iter()
            .map(public_hash)
            .collect::<std::result::Result<_, _>>()?,
        outbound: targets,
    };
    let peer_key = key(file("peer_key")?)?;
    let worker_key = key(file("worker_key")?)?;
    config.validate(peer_key.verifying_key().to_bytes())?;
    // The frozen clock profile is required by the field list above; the process cannot start
    // without a qualification mechanism, so no worker or signing path can see an absent basis.
    if mutinyd_v8::host_clock::SelectedClock::is_native_declaration(&c["clock"]) {
        return Err("installed native V2 clock cannot be selected by the legacy V1 runtime; ordinary V2 installation and its original owner/consumer controller are required".into());
    }
    let host_clock = mutinyd_v8::host_clock::HostClock::start(
        mutinyd_v8::host_clock::config_from_json(&c["clock"])?,
    )?;
    let database_byte_limit = c["database_byte_limit"]
        .as_u64()
        .ok_or("Database byte limit")?;
    if database_byte_limit < 1024 * 1024 {
        return Err("Database byte limit below minimum".into());
    }
    let db = file("database")?;
    let disk_guard = if production {
        Some(mutinyd_v8::disk_guard::DiskGuard::new(
            db.parent().ok_or("Database parent directory")?,
            c["filesystem_reserve_bytes"]
                .as_u64()
                .ok_or("Filesystem reserve required")?,
        )?)
    } else {
        None
    };
    let mut node = if production {
        Node::open_sealed(
            file("bundle")?,
            db,
            &mutinyd_v8::genesis_artifact::supported_trust(
                public_hash(&c["bundle_sha256"])?,
                public_hash(&c["genesis_block_hash"])?,
            )?,
        )?
    } else {
        let profile_pin = if c["physical_profile_commitment"].is_null() {
            None
        } else {
            Some(public_hash(&c["physical_profile_commitment"])?)
        };
        Node::open_pinned(
            file("bundle")?,
            db,
            public_hash(&c["bundle_sha256"])?,
            profile_pin,
        )?
    };
    node.store
        .configure_storage_budget(database_byte_limit)
        .map_err(fail)?;
    let signing = if let Some(value) = object.get("physical_voter") {
        use mutinyd_v8::{
            integrated_actor::SigningState, local_proposer::LocalProposer,
            participation_producer::Producer,
        };
        if !production {
            // Also refused by `check_runtime_fields`; repeated here so no later edit can reach a
            // qualification custody path from this function.
            return Err(QUALIFICATION_CUSTODY_REFUSED.into());
        }
        let custody = production_custody(value)?;
        // This interface intentionally has NO initial-counter or reset option.
        // A separate supervised custody ceremony must already have completed.
        let journal = Path::new(value["journal"].as_str().ok_or("Voter journal path")?);
        let auth_path = Path::new(
            value["node_auth_key"]
                .as_str()
                .ok_or("Node authentication key path")?,
        );
        if !journal.is_absolute()
            || !auth_path.is_absolute()
            || (!initialize_custody && !std::fs::symlink_metadata(journal).map_err(fail)?.is_file())
        {
            return Err("Existing absolute voter custody journal required".into());
        }
        if !matches!(node.verifier, Evidence::Physical(_)) {
            return Err("Physical voter requires qualified physical evidence".into());
        }
        let id = public_hash(&value["node"])?;
        let auth = key(auth_path)?;
        let (_, state) = node.store.load_effective().map_err(fail)?;
        let control = state
            .membership
            .controls
            .get(&id)
            .ok_or("Missing canonical Node authentication")?;
        if control.node_authentication != auth.verifying_key().to_bytes() {
            return Err("Node authentication key differs from canonical control".into());
        }
        let registry = state
            .continuity
            .as_ref()
            .ok_or("Missing Continuity registry")?;
        if !registry
            .members
            .iter()
            .any(|m| m.node == id && m.physical && m.eligible)
        {
            return Err("Physical voter lineage is not admitted and eligible".into());
        }
        if auth.verifying_key() != peer_key.verifying_key() {
            return Err("Production node authentication must match peer identity".into());
        }
        node.enable_production_tpm(journal, id, &custody, initialize_custody)?;
        let voter = node.voter.take().ok_or("Voter custody unavailable")?;
        if voter.node() != id {
            return Err("TPM custody Node identity mismatch".into());
        }
        Some(SigningState {
            voter,
            backend: node.signer.take().ok_or("TPM backend unavailable")?,
            proposer: Some(LocalProposer::open(
                &db.with_extension("proposer.sqlite"),
                id,
                auth,
                node.genesis,
                node.fingerprint,
            )?),
            participation: Some(Producer::open(
                &db.with_extension("participation.sqlite"),
                node.genesis,
                node.fingerprint,
                id,
            )?),
        })
    } else {
        None
    };
    if initialize_custody {
        if signing.is_none() {
            return Err("Physical custody configuration required".into());
        }
        println!(
            "{}",
            json!({"schema":"BUILD8-PRODUCTION-CUSTODY-INITIALIZED-V1",
            "genesis_id":hex::encode(node.genesis),"protocol_fingerprint":hex::encode(node.fingerprint),
            "result":"PASS","votes_created":0,"services_started":false})
        );
        return Ok(());
    }
    let voting_custody = signing.is_some();
    let builder = Assembler {
        transactions: mempool::Mempool::open(db, node.genesis, node.fingerprint, 64 * 1024 * 1024)
            .map_err(fail)?,
        operations: OperationPool::open(
            &db.with_extension("operations.sqlite"),
            node.genesis,
            node.fingerprint,
        )?,
        physical: node.physical.clone(),
        verifier: node.verifier.clone(),
    };
    let coordinator = coordinator::Coordinator::open(
        &db.with_extension("work.sqlite"),
        &db.with_extension("observations.sqlite"),
        node.genesis,
        node.fingerprint,
        worker_key.clone(),
    )?;
    let workers = WorkerCoordinator::new(
        node.store,
        coordinator,
        worker_key.verifying_key().to_bytes(),
        node.physical,
        node.verifier,
        JournaledCandidates {
            journal: node.candidates,
            builder,
        },
        host_clock.basis(),
    );
    // A nonvoting process never opens a TPM custody channel or protected counter journal.
    // Physical custody, when explicitly configured, must already exist.
    let mut integrated = IntegratedActor::<_, _, SigningBackend>::new(
        workers,
        node.received_votes,
        signing,
    )?;
    // The live node never reaches OS time on a consensus path: the voter guard, the work
    // coordinator and operation admission share one conservative qualified basis.
    if let Some(signing) = integrated.signing.as_mut() {
        signing.voter.set_vote_clock(host_clock.vote_clock());
    }
    let actor = Arc::new(Mutex::new(integrated));
    let shutdown = if production {
        Some(mutinyd_v8::daemon_shutdown::Shutdown::install()?)
    } else {
        None
    };
    let service = RuntimeService::start(config, worker_key, peer_key, actor)?;
    eprintln!(
        "{}",
        json!({"schema":"BUILD8-RUNTIME-STARTED-V1", "actual_genesis":production,
        "worker_address":service.worker_address.to_string(), "peer_address":service.peer_address.to_string(),
        "voting_custody":voting_custody})
    );
    let (send, receive) = mpsc::sync_channel(1);
    if !production {
        std::thread::spawn(move || {
            let mut command = Vec::new();
            let result = std::io::stdin()
                .lock()
                .take(6)
                .read_until(b'\n', &mut command)
                .map_err(fail)
                .and_then(|_| {
                    if command.is_empty() || command == b"stop\n" || command == b"stop\r\n" {
                        Ok(())
                    } else {
                        Err("Expected stop or EOF".into())
                    }
                });
            let _ = send.send(result);
        });
    }
    let mut next_capacity_check = std::time::Instant::now();
    loop {
        if std::time::Instant::now() >= next_capacity_check {
            if let Some(guard) = &disk_guard {
                if let Err(error) = guard.check() {
                    service.stop()?;
                    return Err(error);
                }
            }
            next_capacity_check = std::time::Instant::now() + std::time::Duration::from_secs(1);
        }
        if shutdown.as_ref().is_some_and(|guard| guard.requested()) {
            return service.stop();
        }
        if !production {
            match receive.try_recv() {
                Ok(command) => {
                    service.stop()?;
                    return command;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("Runtime control disconnected".into());
                }
                Err(mpsc::TryRecvError::Empty) => (),
            }
        }
        if let Some(tick) = service.poll()? {
            eprintln!(
                "{}",
                json!({"schema":"BUILD8-RUNTIME-EVENT-V1", "votes":tick.consensus.publish.len(),
                "finalized":tick.consensus.finalized.map(hex::encode), "round":tick.consensus.advanced_round})
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// `--qualification-stdio` arguments: 5 (no pin) or 6 (explicit physical-profile bundle-selection
/// pin). The former 7-argument form opened a host-specific qualification custody bridge and is
/// refused with an explicit message.
fn stdio_profile_pin(args: &[String]) -> std::result::Result<Option<Hash>, String> {
    if args.len() < 2 || args[1] != "--qualification-stdio" {
        return Ok(None);
    }
    match args.len() {
        6 => Ok(Some(public_hash(&Value::String(args[5].clone()))?)),
        7 => Err(QUALIFICATION_CUSTODY_REFUSED.into()),
        _ => Ok(None),
    }
}
/// Exact field set of BUILD8-RUNTIME-V1 / BUILD8-QUALIFICATION-RUNTIME-V1.
/// Optional: production `physical_voter`; qualification `physical_profile_commitment`.
/// A qualification `physical_voter` is refused: shipping binaries carry no qualification custody.
fn check_runtime_fields(c: &Value, production: bool) -> std::result::Result<(), String> {
    let mut fields = vec![
        "schema",
        "actual_genesis",
        "bundle",
        "bundle_sha256",
        "database",
        "database_byte_limit",
        "worker_key",
        "peer_key",
        "worker_bind",
        "peer_bind",
        "worker_connections",
        "peer_connections",
        "allowed_peers",
        "outbound",
    ];
    if production {
        fields.push("genesis_block_hash");
        fields.push("filesystem_reserve_bytes");
    }
    // `clock` is the frozen time profile (schema BUILD8-CLOCK-V1). It is REQUIRED in every
    // configuration: this process serves workers (work timestamps and epoch binding) and may hold
    // signing custody, and neither may run on an unqualified or OS-clock time basis.
    fields.push("clock");
    let object = c.as_object().ok_or("Runtime configuration object")?;
    if !production && object.contains_key("physical_voter") {
        return Err(QUALIFICATION_CUSTODY_REFUSED.into());
    }
    let optional: &[&str] = if production {
        &["physical_voter"]
    } else {
        &["physical_profile_commitment"]
    };
    let present = optional.iter().filter(|k| object.contains_key(**k)).count();
    if object.len() != fields.len() + present
        || object
            .keys()
            .any(|name| !optional.contains(&name.as_str()) && !fields.contains(&name.as_str()))
        || c["schema"]
            != if production {
                "BUILD8-RUNTIME-V1"
            } else {
                "BUILD8-QUALIFICATION-RUNTIME-V1"
            }
        || c["actual_genesis"] != production
    {
        return Err("Explicit qualification runtime configuration required".into());
    }
    Ok(())
}
/// Production custody configuration: the `physical_voter` object of BUILD8-RUNTIME-V1.
struct ProductionCustody {
    manifest_sha256: Hash,
    counter_index: u32,
    counter_public_sha256: Hash,
    helper: mutinyd_v8::tpm_backend::HelperConfig,
}
const PHYSICAL_VOTER_FIELDS: [&str; 7] = [
    "node",
    "journal",
    "node_auth_key",
    "custody_manifest_sha256",
    "counter_index",
    "counter_public_sha256",
    "tpm_helper",
];
fn production_custody(value: &Value) -> std::result::Result<ProductionCustody, String> {
    let record = value
        .as_object()
        .ok_or("Physical voter configuration object")?;
    if record.len() != PHYSICAL_VOTER_FIELDS.len()
        || PHYSICAL_VOTER_FIELDS.iter().any(|f| !record.contains_key(*f))
    {
        return Err(format!("Physical voter fields: {}", PHYSICAL_VOTER_FIELDS.join(", ")));
    }
    let counter_index = value["counter_index"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("Physical voter counter_index must be a u32")?;
    Ok(ProductionCustody {
        manifest_sha256: public_hash(&value["custody_manifest_sha256"])?,
        counter_index,
        counter_public_sha256: public_hash(&value["counter_public_sha256"])?,
        helper: mutinyd_v8::tpm_backend::HelperConfig::from_json(&value["tpm_helper"])?,
    })
}
/// Custody-channel pins. GenesisID, fingerprint, NodeID and the voting key come from consensus
/// state (the ADMITTED `PhysicalMember`); the configuration supplies only local channel pins,
/// each cross-checked against the hash-pinned custody manifest by `Pins::verify`. A pin can only
/// make startup fail; it never selects or admits a key.
fn production_pins(
    genesis: Hash,
    fingerprint: Hash,
    member: &PhysicalMember,
    custody: &ProductionCustody,
) -> mutinyd_v8::tpm_backend::Pins {
    mutinyd_v8::tpm_backend::Pins {
        genesis,
        fingerprint,
        node: member.node,
        voting_key: member.continuity_key,
        counter_index: custody.counter_index,
        counter_public_sha256: custody.counter_public_sha256,
        custody_manifest_sha256: custody.manifest_sha256,
    }
}
#[cfg(unix)]
fn create_peer_key(path: &Path) -> std::result::Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut()).map_err(fail)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(fail)?;
    file.write_all(seed.as_ref()).map_err(fail)?;
    file.sync_all().map_err(fail)?;
    std::fs::File::open(path.parent().ok_or("key parent")?)
        .map_err(fail)?
        .sync_all()
        .map_err(fail)?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    println!(
        "{}",
        json!({"public_key":hex::encode(key.verifying_key().to_bytes()),"qualification_only":true,"private_exported":false})
    );
    Ok(())
}
#[cfg(not(unix))]
fn create_peer_key(_: &Path) -> std::result::Result<(), String> {
    Err("qualification key custody requires Linux mode 0600".into())
}

#[cfg(not(unix))]
fn peer_once(_: &mut Node, _: &Path, _: Hash, _: &str) -> std::result::Result<(), String> {
    Err("peer custody qualification requires Linux".into())
}
#[cfg(unix)]
fn peer_once(
    node: &mut Node,
    key_path: &Path,
    remote: Hash,
    bind: &str,
) -> std::result::Result<(), String> {
    let address: std::net::SocketAddr = bind.parse().map_err(fail)?;
    if !address.ip().is_loopback() {
        return Err("qualification listener must be loopback".into());
    }
    let metadata = std::fs::symlink_metadata(key_path).map_err(fail)?;
    if !metadata.file_type().is_file() || metadata.len() != 32 {
        return Err("peer key custody file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("peer key permissions".into());
        }
    }
    #[cfg(not(unix))]
    return Err("peer custody qualification requires Linux".into());
    #[cfg(unix)]
    {
        let seed = zeroize::Zeroizing::new(std::fs::read(key_path).map_err(fail)?);
        let key = ed25519_dalek::SigningKey::from_bytes(
            seed.as_slice().try_into().map_err(|_| "key length")?,
        );
        let listener = std::net::TcpListener::bind(address).map_err(fail)?;
        eprintln!("qualification peer listener ready: {address}");
        let (mut stream, _) = listener.accept().map_err(fail)?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .map_err(fail)?;
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(15)))
            .map_err(fail)?;
        stream.set_nodelay(true).map_err(fail)?;
        let mut session = peer::Session::handshake(
            &mut mutinyd_v8::deadline_io::DeadlineIo::new(
                &mut stream,
                std::time::Duration::from_secs(15),
            )
            .map_err(fail)?,
            key,
            remote,
            node.genesis,
            node.fingerprint,
            false,
        )?;
        for _ in 0..4096 {
            let raw = session.receive(
                &mut mutinyd_v8::deadline_io::DeadlineIo::new(
                    &mut stream,
                    std::time::Duration::from_secs(15),
                )
                .map_err(fail)?,
            )?;
            let response = node.peer_request(&raw)?;
            session.send(
                &mut mutinyd_v8::deadline_io::DeadlineIo::new(
                    &mut stream,
                    std::time::Duration::from_secs(15),
                )
                .map_err(fail)?,
                &response.payload,
            )?;
            if response.close {
                return Ok(());
            }
        }
        Err("qualification session request bound".into())
    }
}

impl Node {
    fn peer_request(
        &mut self,
        raw: &[u8],
    ) -> std::result::Result<mutinyd_v8::peer_server::PeerReply, String> {
        let request: Value = serde_json::from_slice(raw).map_err(fail)?;
        let method = request["method"].as_str().ok_or("method")?;
        let close = method == "end_session";
        let result = if close {
            Ok(json!({"status":"CLOSED"}))
        } else if matches!(
            method,
            "status"
                | "state_proof"
                | "submit_block"
                | "submit_candidate"
                | "submit_vote"
                | "get_block"
                | "get_recovery"
                | "submit_recovery"
                | "submit_transaction"
                | "transaction_status"
                | "submit_equivocation"
                | "equivocation_status"
        ) {
            self.request(&request)
        } else {
            Err("method not available to peer transport".into())
        };
        let response = match result {
            Ok(value) => json!({"id":request["id"],"result":value}),
            Err(error) => json!({"id":request["id"],"error":error}),
        };
        Ok(mutinyd_v8::peer_server::PeerReply {
            payload: serde_json::to_vec(&response).map_err(fail)?,
            close,
        })
    }
}
impl mutinyd_v8::peer_server::PeerBackend for Node {
    fn context(&self) -> (Hash, Hash) {
        (self.genesis, self.fingerprint)
    }
    fn handle(
        &mut self,
        _: Hash,
        raw: &[u8],
    ) -> std::result::Result<mutinyd_v8::peer_server::PeerReply, String> {
        self.peer_request(raw)
    }
}
#[cfg(not(unix))]
fn peer_server(_: Node, _: &Path, _: Hash, _: &str) -> std::result::Result<(), String> {
    Err("peer custody qualification requires Linux".into())
}
#[cfg(unix)]
fn peer_server(
    node: Node,
    key_path: &Path,
    remote: Hash,
    bind: &str,
) -> std::result::Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let address: std::net::SocketAddr = bind.parse().map_err(fail)?;
    if !address.ip().is_loopback() {
        return Err("qualification listener must be loopback".into());
    }
    let metadata = std::fs::symlink_metadata(key_path).map_err(fail)?;
    if !metadata.file_type().is_file()
        || metadata.len() != 32
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("peer key custody file/permissions".into());
    }
    let seed = zeroize::Zeroizing::new(std::fs::read(key_path).map_err(fail)?);
    let key = ed25519_dalek::SigningKey::from_bytes(
        seed.as_slice().try_into().map_err(|_| "key length")?,
    );
    let listener = std::net::TcpListener::bind(address).map_err(fail)?;
    let bound = listener.local_addr().map_err(fail)?;
    let server = mutinyd_v8::peer_server::PeerServer::start(
        listener,
        key,
        &[remote],
        std::sync::Arc::new(std::sync::Mutex::new(node)),
        4,
    )?;
    eprintln!("qualification peer server ready: {bound}");
    // The controlling SSH process owns lifetime; EOF or a bounded stop command
    // shuts down and joins every session. No daemon/service is installed.
    let mut command = Vec::new();
    std::io::stdin()
        .lock()
        .take(6)
        .read_until(b'\n', &mut command)
        .map_err(fail)?;
    server.stop()?;
    if !command.is_empty() && command != b"stop\n" && command != b"stop\r\n" {
        return Err("expected stop or EOF".into());
    }
    Ok(())
}
