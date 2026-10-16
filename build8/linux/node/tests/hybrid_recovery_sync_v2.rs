//! Public synthetic signed chain; no private keys or hardware operations.
use mutiny_consensus_v8::{
    Hash, anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore, execution::State,
    mempool_v2::Mempool,
};
use mutiny_transport_v2::{
    object_link::Event,
    objects::{ObjectKind, Offer, object_id},
};
use mutinyd_v8::{
    hybrid_dispatch_v2::{self, DispatchEvent},
    hybrid_runtime_v2::HybridRuntime,
    hybrid_sync_v2::{self, HistorySource},
};

struct Fixture {
    genesis: FinalizedAnchor,
    root: Hash,
    state: State,
    blocks: [Vec<u8>; 2],
    recovery: Vec<u8>,
    target: FinalizedAnchor,
    dir: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-recovery-chain-public-v4.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        assert_eq!(f["production_authorized"], false);
        assert_eq!(f["physical_tpm"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root = raw(&f["root"]).try_into().unwrap();
        let rows: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "build8-hybrid-recovery-sync-{}",
            hex::encode(nonce)
        ));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&dir).unwrap());
        println!("RETAINED_PUBLIC_RECOVERY_SYNC_EVIDENCE={}",dir.display());
        Self {
            genesis: FinalizedAnchor::decode(&raw(&f["genesis_anchor"])).unwrap(),
            root,
            state: State::from_records(&rows, root).unwrap(),
            blocks: [raw(&f["block1"]), raw(&f["block2"])],
            recovery: raw(&f["recovery1"]),
            target: FinalizedAnchor::decode(&raw(&f["target_anchor"])).unwrap(),
            dir,
        }
    }
    fn open(&self) -> HybridRuntime {
        HybridRuntime::from_pinned_chain(
            CanonicalStore::open_trusted_genesis(
                &self.dir.join("chain.sqlite"),
                &self.genesis,
                &self.state,
                self.root,
                1000,
                [255; 32],
            )
            .unwrap(),
            Mempool::open(
                &self.dir.join("pool.sqlite"),
                self.genesis.genesis,
                self.genesis.fingerprint,
                64 * 1024 * 1024,
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn source(&self) -> Source {
        Source {
            blocks: self.blocks.clone(),
            recovery: Some(self.recovery.clone()),
            calls: vec![],
            fail_block2: false,
        }
    }
}
struct Source {
    blocks: [Vec<u8>; 2],
    recovery: Option<Vec<u8>>,
    calls: Vec<(char, u64)>,
    fail_block2: bool,
}
impl HistorySource for Source {
    fn recovery(&mut self, parent: u64, maximum_bytes: usize) -> Result<Option<Vec<u8>>, String> {
        assert_eq!(maximum_bytes, mutiny_consensus_v8::state_tree::MAX_RECORD);
        self.calls.push(('r', parent));
        Ok(if parent == 1 {
            self.recovery.clone()
        } else {
            None
        })
    }
    fn block(&mut self, height: u64, maximum_bytes: usize) -> Result<Vec<u8>, String> {
        assert_eq!(
            maximum_bytes,
            mutiny_consensus_v8::block_envelope_v2::MAX_ENVELOPE_BYTES
        );
        self.calls.push(('b', height));
        if height == 2 && self.fail_block2 {
            return Err("synthetic interruption".into());
        }
        self.blocks
            .get(height as usize - 1)
            .cloned()
            .ok_or("absent".into())
    }
}

#[test]
fn recovery_prefix_restarts_and_exact_late_delivery_is_harmless() {
    let f = Fixture::new();
    let mut runtime = f.open();
    let mut source = f.source();
    let first = hybrid_sync_v2::catch_up(&mut runtime, &mut source, &f.target, 1).unwrap();
    assert_eq!(first.installed, 1);
    assert_eq!(first.head.height, 1);
    assert!(!first.target_reached);
    assert_eq!(source.calls, vec![('r', 0), ('b', 1)]);
    source.fail_block2 = true;
    assert!(hybrid_sync_v2::catch_up(&mut runtime, &mut source, &f.target, 1).is_err());
    assert_eq!(runtime.head().unwrap(), first.head);
    assert_eq!(
        runtime.recovery_record(1).unwrap(),
        Some(f.recovery.clone())
    );
    drop(runtime);
    let mut runtime = f.open();
    source.fail_block2 = false;
    let last = hybrid_sync_v2::catch_up(&mut runtime, &mut source, &f.target, 1).unwrap();
    assert_eq!(last.installed, 1);
    assert!(last.target_reached);
    assert!(last.pending_cache_available);
    assert_eq!(last.head, f.target);
    assert!(!runtime.accept_recovery(&f.recovery).unwrap().inserted);
    assert!(!runtime.install(&f.blocks[1]).unwrap().inserted);
    drop(runtime);
    let runtime = f.open();
    assert_eq!(runtime.head().unwrap(), f.target);
}

#[test]
fn omitted_or_corrupt_recovery_cannot_authorize_successor() {
    let f = Fixture::new();
    let mut runtime = f.open();
    runtime.install(&f.blocks[0]).unwrap();
    let parent = runtime.head().unwrap();
    let mut source = f.source();
    source.recovery = None;
    assert!(hybrid_sync_v2::catch_up(&mut runtime, &mut source, &f.target, 1).is_err());
    assert_eq!(runtime.head().unwrap(), parent);
    for raw in [
        vec![0],
        {
            let mut r = f.recovery.clone();
            r.push(0);
            r
        },
        vec![0; 256 * 1024 + 1],
        {
            let mut r = f.recovery.clone();
            let n = r.len();
            r[n - 1] ^= 1;
            r
        },
    ] {
        source.recovery = Some(raw);
        assert!(hybrid_sync_v2::catch_up(&mut runtime, &mut source, &f.target, 1).is_err());
        assert_eq!(runtime.head().unwrap(), parent);
        assert!(runtime.recovery_record(1).unwrap().is_none());
    }
    source.recovery = Some(f.recovery.clone());
    assert!(
        hybrid_sync_v2::catch_up(&mut runtime, &mut source, &f.target, 1)
            .unwrap()
            .target_reached
    );
}

#[test]
fn peer_hint_and_wrong_height_never_skip_execution() {
    let f = Fixture::new();
    let mut runtime = f.open();
    let mut source = f.source();
    for bound in [0, 65, usize::MAX] {
        assert!(hybrid_sync_v2::catch_up(&mut runtime, &mut source, &f.target, bound).is_err());
    }
    for field in 0..3 {
        let mut wrong = f.target.clone();
        match field {
            0 => wrong.network ^= 1,
            1 => wrong.genesis[0] ^= 1,
            _ => wrong.fingerprint[0] ^= 1,
        }
        assert!(hybrid_sync_v2::catch_up(&mut runtime, &mut source, &wrong, 1).is_err());
    }
    assert!(source.calls.is_empty());
    source.blocks[0] = f.blocks[1].clone();
    assert!(hybrid_sync_v2::catch_up(&mut runtime, &mut source, &f.target, 1).is_err());
    assert_eq!(runtime.head().unwrap(), f.genesis);
    source = f.source();
    let mut false_tip = f.target.clone();
    false_tip.block[0] ^= 1;
    assert!(matches!(
        hybrid_sync_v2::catch_up(&mut runtime, &mut source, &false_tip, 2),
        Err(hybrid_sync_v2::SyncError::TargetMismatch)
    ));
    assert_eq!(runtime.head().unwrap(), f.target);
}

#[test]
fn dispatch_recovery_acceptance_is_not_block_finalization() {
    let f = Fixture::new();
    let mut runtime = f.open();
    assert!(runtime.accept_recovery(&f.recovery).is_err());
    assert_eq!(runtime.head().unwrap(), f.genesis);
    runtime.install(&f.blocks[0]).unwrap();
    let parent = runtime.head().unwrap();
    let event = || Event::Completed {
        offer: Offer {
            id: object_id(ObjectKind::RecoveryEvidence, &f.recovery).unwrap(),
            kind: ObjectKind::RecoveryEvidence,
            length: f.recovery.len(),
        },
        bytes: f.recovery.clone(),
    };
    let delivered = encrypted_recovery(&f);
    match hybrid_dispatch_v2::dispatch(&mut runtime, delivered).unwrap() {
        DispatchEvent::RecoveryAccepted { result, .. } => {
            assert!(result.inserted);
            assert_eq!(result.parent, parent);
        }
        _ => panic!("recovery was misclassified as finality"),
    }
    assert_eq!(runtime.head().unwrap(), parent);
    assert_eq!(runtime.confirmed_height([117; 32]).unwrap(), None);
    match hybrid_dispatch_v2::dispatch(&mut runtime, event()).unwrap() {
        DispatchEvent::RecoveryAccepted { result, .. } => assert!(!result.inserted),
        _ => panic!(),
    }
    assert!(runtime.install(&f.blocks[1]).unwrap().inserted);
    match hybrid_dispatch_v2::dispatch(&mut runtime, event()).unwrap() {
        DispatchEvent::RecoveryAccepted { result, .. } => assert!(!result.inserted),
        _ => panic!(),
    }
    assert_eq!(runtime.head().unwrap(), f.target);
}

fn encrypted_recovery(f: &Fixture) -> Event {
    use mutiny_crypto_v2::{HybridKey, Role};
    use mutiny_transport_v2::{
        Context, Endpoint, InitiatorPending, ResponderPending, objects::ObjectQueue,
    };
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let context = Context::pinned(
        f.genesis.genesis,
        f.genesis.fingerprint,
        Endpoint::pinned(a.public().clone(), 1).unwrap(),
        Endpoint::pinned(b.public().clone(), 1).unwrap(),
    )
    .unwrap();
    let (i, hello) = InitiatorPending::start(context.clone(), &a).unwrap();
    let (r, response) = ResponderPending::accept(context, &b, &hello).unwrap();
    let (i, finish) = i.accept(&a, &response).unwrap();
    let (mut r, tag) = r.finish(&finish).unwrap();
    let mut i = i.finish(&tag).unwrap();
    let mut send = ObjectQueue::open(&f.dir.join("transport-send.sqlite"), [8; 32]).unwrap();
    let mut recv = ObjectQueue::open(&f.dir.join("transport-receive.sqlite"), [8; 32]).unwrap();
    let offer = send
        .enqueue(ObjectKind::RecoveryEvidence, &f.recovery)
        .unwrap();
    let (m, p) = offer.have(1).unwrap();
    let (m, p) = r.open(&i.seal(&m, &p).unwrap()).unwrap();
    recv.offer(&Offer::parse(&m, &p).unwrap()).unwrap();
    let mut start = 0;
    while start < m.count {
        let count = (m.count - start).min(1080);
        let mut wanted = recv.missing(&offer.id, start, count).unwrap();
        while let Some((meta, payload)) = send.next_fragment(&offer.id, &wanted, 1).unwrap() {
            wanted.bits[(meta.fragment - start) as usize] = false;
            let wire = i.seal(&meta, &payload).unwrap();
            let (meta, payload) = r.open(&wire).unwrap();
            assert!(r.open(&wire).is_err(), "AEAD replay accepted");
            recv.receive(&meta, &payload).unwrap();
        }
        start += count;
    }
    let bytes = recv.read_complete(&offer.id).unwrap();
    assert_eq!(bytes, f.recovery);
    Event::Completed { offer, bytes }
}
