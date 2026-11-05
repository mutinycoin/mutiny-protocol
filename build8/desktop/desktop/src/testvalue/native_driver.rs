//! NON-SHIPPING public TEST-VALUE canonical campaign, not a peer-finality adapter.
//! The certifier fixture is included verbatim with provenance recorded at launch. Four
//! independent SQLite histories share one explicitly trusted initial public test state.
//! No fixture finish/delete is called: successful, refused and interrupted evidence stays.
use crate::{verified_sync_v2::Delivery, wallet_controller_v2::Controller};
use crate::wallet_controller_v2::host::WalletPeer;
use mutiny_transport_v2::{
    Endpoint,
    object_link::Event,
    objects::{ObjectKind, ObjectQueue},
};
use mutinyd_v8::{
    hybrid_dispatch_v2::{self, DispatchEvent},
    hybrid_peer_admission_v2::{PeerLink, Registry},
    hybrid_runtime_v2::{HybridRuntime, WorkRequest},
};
use std::{
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[path = "../wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "../wallet_host_fixture_tpm.rs"]
mod tpm;
include!("../../../consensus/tests/support/dividend_rig.rs");

pub const DRIVER_MARKER: &str = "MUTINY-WALLET-V8-TESTVALUE-NATIVE-DRIVER-V1";
type Result<T, E = String> = std::result::Result<T, E>;
fn error(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
fn limit() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
// Source-defined simulated epoch belongs only to this explicit public campaign.
// Ordinary NODE runtime and its host clock are unchanged.
static CAMPAIGN_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn campaign_clock() -> u64 {
    at(CAMPAIGN_EPOCH.load(std::sync::atomic::Ordering::SeqCst))
}
pub struct NativeDriver {
    fixture: Fixture,
    initial: State,
    initial_root: Hash,
    certifier: CanonicalStore,
    pub local: HybridRuntime,
    pub remote: HybridRuntime,
    wallet_peer: WalletPeer,
    remote_peer: PeerLink,
    // Pins remain live for the exact connections; a transcript is not an admission proof.
    _outgoing: Registry,
    _incoming: Registry,
    base: PathBuf,
    ticket: u64,
    pub last: serde_json::Value,
}
impl NativeDriver {
    pub fn new(base: &Path) -> Result<Self> {
        if !base.is_absolute() || base.exists() {
            return Err("Driver evidence directory must be new and absolute".into());
        }
        if !mutiny_consensus_v8::submission_pool_v1::private_directory(base).map_err(error)? {
            return Err("This invocation did not create the driver directory".into());
        }
        let mut fixture = fixture();
        let a = owner_key();
        let b = treasury_key();
        let recipient = second_key();
        for key in [&a, &b, &recipient] {
            if fixture.state.wallets.current(addr(key, 1)).is_none() {
                fixture
                    .state
                    .wallets
                    .register(&desc(key, 1))
                    .map_err(error)?;
            }
        }
        fixture.state.coins.clear();
        for (tag, key) in [(78, &a), (79, &b)] {
            fixture.state.coins.insert(
                OutPoint {
                    transaction: [tag; 32],
                    index: 0,
                },
                Coin {
                    output: Output {
                        owner: addr(key, 1),
                        atoms: 50_000_000_000,
                    },
                    created_height: 0,
                    coinbase: false,
                },
            );
        }
        fixture.state.dividends =
            DividendState::genesis(Treasury::new(Class::TestValue, desc(&b, 1)).map_err(error)?);
        fixture.genesis.block = mutiny_consensus_v8::domain_hash(
            b"MUTINY-WALLET-V8-TESTVALUE-GENESIS-V1",
            &fixture.genesis.genesis,
        );
        let context = mutiny_consensus_v8::trading_v1::Context {
            network: fixture.genesis.network,
            genesis: fixture.genesis.genesis,
            fingerprint: fixture.genesis.fingerprint,
        };
        fixture.state.protocol_records.extend(
            mutiny_consensus_v8::trading_v1::treasury_genesis_records(
                &context,
                addr(&b, 1),
                desc(&b, 1),
            )
            .map_err(error)?,
        );
        let initial = fixture.state.clone();
        let initial_root = initial.root().map_err(error)?;
        State::from_records(&initial.records().map_err(error)?, initial_root).map_err(error)?;
        let store = |name: &str| {
            CanonicalStore::open_trusted_genesis(
                &base.join(name),
                &fixture.genesis,
                &initial,
                initial_root,
                T0,
                [255; 32],
            )
            .map_err(error)
        };
        let certifier = store("certifier.sqlite")?;
        let runtime = |name: &str| -> Result<HybridRuntime> {
            HybridRuntime::from_pinned_chain_with_clock(
                store(&format!("{name}-chain.sqlite"))?,
                Mempool::open(
                    &base.join(format!("{name}-payment.sqlite")),
                    fixture.genesis.genesis,
                    fixture.genesis.fingerprint,
                    64 * 1024 * 1024,
                )
                .map_err(error)?,
                campaign_clock,
            )
            .map_err(error)
        };
        let local = runtime("local-node")?;
        let remote = runtime("remote-node")?;
        let ka = HybridKey::generate(Role::Transport).map_err(error)?;
        let kb = HybridKey::generate(Role::Transport).map_err(error)?;
        let pa = Endpoint::pinned(ka.public().clone(), 1).map_err(error)?;
        let pb = Endpoint::pinned(kb.public().clone(), 1).map_err(error)?;
        let outgoing = Registry::new(
            fixture.genesis.genesis,
            fixture.genesis.fingerprint,
            pa.clone(),
            vec![pb.clone()],
            1,
            1,
        )?;
        let incoming = Registry::new(
            fixture.genesis.genesis,
            fixture.genesis.fingerprint,
            pb.clone(),
            vec![pa.clone()],
            1,
            1,
        )?;
        let pending = incoming.begin()?;
        let listener = TcpListener::bind("127.0.0.1:0").map_err(error)?;
        let client = TcpStream::connect(listener.local_addr().map_err(error)?).map_err(error)?;
        let server = listener.accept().map_err(error)?.0;
        drop(listener);
        let (client, server) = std::thread::scope(|scope| -> Result<_> {
            let response =
                scope.spawn(|| pending.respond(pa.id(), server, &kb, Duration::from_secs(30)));
            let client =
                outgoing
                    .begin()?
                    .initiate(pb.id(), client, &ka, Duration::from_secs(30))?;
            Ok((
                client,
                response
                    .join()
                    .map_err(|_| "Public handshake worker panicked")??,
            ))
        })?;
        let send = ObjectQueue::open(&base.join("wallet-transport.sqlite"), client.peer_id())
            .map_err(error)?;
        let recv = ObjectQueue::open(&base.join("remote-transport.sqlite"), server.peer_id())
            .map_err(error)?;
        let wallet_peer = WalletPeer::new(client.attach(send)?);
        let remote_peer = server.attach(recv)?;
        let provenance = serde_json::json!({"driver":DRIVER_MARKER,"classification":"public TEST-VALUE; independent trusted initial model; not production or sealed Genesis",
            "initial_root":hex::encode(initial_root),"genesis":hex::encode(fixture.genesis.encode()),
            "certifier_source_sha256":hex::encode(sha2::Sha256::digest(include_bytes!("../../../consensus/tests/support/dividend_rig.rs"))),
            "licenses_source_sha256":hex::encode(sha2::Sha256::digest(include_bytes!("../wallet_host_fixture_licenses.rs"))),
            "tpm_source_sha256":hex::encode(sha2::Sha256::digest(include_bytes!("../wallet_host_fixture_tpm.rs"))),
            "stores":["certifier.sqlite","local-node-chain.sqlite","remote-node-chain.sqlite","wallet replica under explicit TEST-VALUE vault root"],"result":"IN_PROGRESS"});
        std::fs::write(
            base.join("public-driver-identity.json"),
            serde_json::to_vec_pretty(&provenance).map_err(error)?,
        )
        .map_err(error)?;
        Ok(Self {
            fixture,
            initial,
            initial_root,
            certifier,
            local,
            remote,
            wallet_peer,
            remote_peer,
            _outgoing: outgoing,
            _incoming: incoming,
            base: base.to_owned(),
            ticket: 1,
            last: provenance,
        })
    }
    pub fn initial(&self) -> (&FinalizedAnchor, &State) {
        (&self.fixture.genesis, &self.initial)
    }
    pub fn recipient(&self) -> Hash {
        addr(&second_key(), 1)
    }
    pub fn recipient_display(&self) -> String {
        mutiny_wallet_core_v8::address_format::encode(
            &self.recipient(),
            mutiny_wallet_core_v8::ChainClass::TestValue,
        )
    }
    /// Transfer only bytes already signed/queued by the actual wallet widget/controller.
    /// The owning service worker runs transport turns; the native repaint thread waits
    /// for this bounded fixture action and never dispatches protocol turns itself.
    pub fn deliver(
        &mut self,
        wallet: &mut Controller,
        id: Hash,
        payment: bool,
    ) -> Result<serde_json::Value> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.deliver_owned(wallet, id, payment))
                .join()
                .map_err(|_| "Native delivery fixture worker panicked".to_owned())?
        })
    }
    fn deliver_owned(
        &mut self,
        wallet: &mut Controller,
        id: Hash,
        payment: bool,
    ) -> Result<serde_json::Value> {
        let offer = if payment {
            wallet.advertise_payment(&mut self.wallet_peer, id, limit())?
        } else {
            wallet.advertise_operation(&mut self.wallet_peer, id, limit())?
        };
        let expected_list = match offer.kind {
            ObjectKind::SignedTransaction => 0,
            ObjectKind::SignedOperation => 1,
            _ => return Err("Wallet advertised a non-submission object".into()),
        };
        let received = self.remote_peer.receive(limit())?;
        let event =
            hybrid_dispatch_v2::dispatch_peer(&mut self.remote, &mut self.remote_peer, received)
                .map_err(error)?;
        if !matches!(event, DispatchEvent::Transport(Event::Offered(ref received_offer)) if received_offer == &offer)
        {
            return Err("Real peer did not receive the exact advertised HAVE".into());
        }
        let request = self
            .remote_peer
            .with_current(|link| link.next_missing_request(&offer.id, 0, false))?
            .map_err(error)?
            .ok_or("No missing object window")?;
        self.remote_peer.send(&request.frame, limit())?;
        wallet.peer_turn(&mut self.wallet_peer, limit())?;
        let mut complete = false;
        for _ in 0..8192 {
            wallet.peer_turn(&mut self.wallet_peer, limit())?;
            let received = self.remote_peer.receive(limit())?;
            let event = hybrid_dispatch_v2::dispatch_peer(
                &mut self.remote,
                &mut self.remote_peer,
                received,
            )
            .map_err(error)?;
            match event {
                DispatchEvent::Transport(Event::FragmentReceived) => {
                    // Larger objects use the same durable bitmap-window protocol.
                    if let Some(next) = self
                        .remote_peer
                        .with_current(|link| link.next_missing_request(&offer.id, 0, false))?
                        .map_err(error)?
                    {
                        self.remote_peer.send(&next.frame, limit())?;
                    }
                }
                DispatchEvent::Transport(_) => {}
                DispatchEvent::TransactionAccepted {
                    offer: accepted_offer,
                    id: accepted_id,
                    ..
                } if offer.kind == ObjectKind::SignedTransaction
                    && accepted_offer == offer
                    && accepted_id == id =>
                {
                    complete = true;
                    break;
                }
                DispatchEvent::OperationAccepted {
                    offer: accepted_offer,
                    id: accepted_id,
                    ..
                } if offer.kind == ObjectKind::SignedOperation
                    && accepted_offer == offer
                    && accepted_id == id =>
                {
                    complete = true;
                    break;
                }
                _ => {
                    return Err(
                        "Peer dispatch did not accept the exact advertised submission".into(),
                    );
                }
            }
        }
        if !complete {
            return Err("Bounded native transfer did not complete".into());
        }
        let (list, exact) = self
            .remote
            .exact_submission_bytes(id)
            .map_err(error)?
            .ok_or("Remote durable pool lacks exact operation")?;
        if list != expected_list {
            return Err("Remote durable pool lists a different submission carrier".into());
        }
        let expected = if payment {
            wallet
                .pending_for_transport()?
                .into_iter()
                .find(|raw| {
                    mutiny_consensus_v8::operation_index_v2::operation_id(0, raw)
                        .map(|(_, candidate)| candidate == id)
                        .unwrap_or(false)
                })
                .ok_or("Wallet no longer has exact pending payment")?
        } else {
            wallet.export(id)?
        };
        if exact != expected {
            return Err("Remote durable bytes differ from wallet queue".into());
        }
        let status = self.remote.submission_status(id).map_err(error)?;
        let own_height = match wallet.delivery(id)? {
            Delivery::ConfirmedAt(height) => Some(height),
            Delivery::Unconfirmed(_) => None,
        };
        if own_height.is_some() {
            return Err("Transport alone improperly confirmed operation".into());
        }
        self.last = serde_json::json!({"action":"real authenticated TCP/durable admission","id":hex::encode(id),"wire_sha256":hex::encode(sha2::Sha256::digest(&exact)),
            "remote_status":format!("{status:?}"),"wallet_own_confirmation_height":own_height,"confirmed":false});
        std::fs::write(
            self.base.join(format!("wire-{}.bin", hex::encode(id))),
            &exact,
        )
        .map_err(error)?;
        Ok(self.last.clone())
    }
    /// Real assembler, hybrid certificate, canonical execution and own replay index.
    /// The control only advances TEST history; it does not authorize any wallet request.
    pub fn certify_next(&mut self, wallet: &mut Controller) -> Result<serde_json::Value> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.certify_owned(wallet))
                .join()
                .map_err(|_| "Native certification fixture worker panicked".to_owned())?
        })
    }
    fn certify_owned(&mut self, wallet: &mut Controller) -> Result<serde_json::Value> {
        let parent = self.remote.head().map_err(error)?;
        let (_, state) = self.certifier.load().map_err(error)?;
        let epoch = parent.height.checked_add(1).ok_or("Height overflow")?;
        CAMPAIGN_EPOCH.store(epoch, std::sync::atomic::Ordering::SeqCst);
        let timestamp = at(epoch);
        let prepared = self
            .remote
            .prepare(WorkRequest {
                expected_parent: &parent,
                license: self.fixture.license,
                worker: self.fixture.worker,
                timestamp,
                ticket: self.ticket,
                operations: &[],
            })
            .map_err(error)?;
        let ids = prepared
            .body
            .transactions
            .iter()
            .map(|raw| (0, raw))
            .chain(prepared.body.operations.iter().map(|raw| (1, raw)))
            .map(|(list, raw)| {
                mutiny_consensus_v8::operation_index_v2::operation_id(list, raw)
                    .map(|(_, id)| (list, id))
                    .map_err(error)
            })
            .collect::<Result<Vec<_>>>()?;
        let block = certify_at(prepared, &self.fixture, &parent, &state, self.ticket);
        let raw = block.encode().map_err(error)?;
        std::fs::write(
            self.base
                .join(format!("certified-{:08}.bin", parent.height + 1)),
            &raw,
        )
        .map_err(error)?;
        if !self.certifier.commit(&block).map_err(error)? {
            return Err("Certifier did not advance".into());
        }
        // The committed block has consumed this ticket whatever the wallet then does with the new
        // head. A Treasury wallet locks itself when the block rotates its own authority (R1); a
        // ticket left unadvanced by that refusal would make every later block a stale sequence.
        self.ticket = self.ticket.checked_add(1).ok_or("Ticket overflow")?;
        self.remote.install(&raw).map_err(error)?;
        self.local.install(&raw).map_err(error)?;
        if !wallet.accept_history(&raw)? {
            return Err("Own wallet replica did not install certified history".into());
        }
        let wallet_head = wallet.with_view(|v| v.anchor().clone())?;
        if wallet_head != self.remote.head().map_err(error)?
            || wallet_head != self.local.head().map_err(error)?
        {
            return Err("Independent stores disagree on certified head".into());
        }
        let mut confirmations = Vec::new();
        // Each node answers from its own verified execution replay (`submission_status`). The
        // `confirmations_v2` row exists for list-0 transactions only, so it is still required there
        // and never asked of a list-1 operation, which the operation index alone records.
        let executed = |node: &mut HybridRuntime, list: u8, id: Hash| -> Result<Option<u64>> {
            let replayed = match node.submission_status(id).map_err(error)? {
                mutiny_consensus_v8::submission_v1::Status::Finalized(record) => Some(record.height),
                _ => None,
            };
            if list == 0 && node.confirmed_height(id).map_err(error)? != replayed {
                return Ok(None);
            }
            Ok(replayed)
        };
        for (list, id) in ids {
            let own = match wallet.delivery(id)? {
                Delivery::ConfirmedAt(height) => Some(height),
                Delivery::Unconfirmed(_) => None,
            };
            if own != Some(wallet_head.height)
                || executed(&mut self.remote, list, id)? != own
                || executed(&mut self.local, list, id)? != own
            {
                return Err(
                    "Exact included operation lacks matching independent own-replay indexes".into(),
                );
            }
            confirmations
                .push(serde_json::json!({"id":hex::encode(id),"own_confirmed_height":own}));
        }
        self.last = serde_json::json!({"action":"real certified history installed in four independent stores",
            "height":wallet_head.height,"block":hex::encode(wallet_head.block),"block_sha256":hex::encode(sha2::Sha256::digest(&raw)),
            "own_confirmations":confirmations,
            "wallet_outbox":wallet.queued_operations()?.into_iter().map(|(item,status)|serde_json::json!({"id":hex::encode(item.id),"kind":item.kind.title(),"status":status})).collect::<Vec<_>>()});
        Ok(self.last.clone())
    }
}
use sha2::Digest;

#[cfg(test)]
mod native_confirmation_tests {
    use super::*;
    use crate::{plan_review::ReviewInput, wallet_controller_v2::{ReviewOutcome, VaultRoot}};

    // Actual independent certified histories, not a fabricated confirmation source.
    // The public fixture and every failed/partial/successful child remain on disk.
    #[test]
    fn payment_confirmation_uses_exact_own_replay_after_authenticated_delivery() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let base = std::env::temp_dir().join(format!("w15-native-confirm-{}-{unique}", std::process::id()));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
        let mut driver = NativeDriver::new(&base.join("driver")).unwrap();
        let vault = VaultRoot::new(&base.join("vault")).unwrap();
        crate::chain::marker(vault.path(), false).unwrap();
        let (genesis, initial) = driver.initial();
        let mut wallet = crate::chain::open(&vault, false, genesis, initial).unwrap();
        let screen = wallet.prepare(driver.recipient(), 1_000_000).unwrap();
        for index in screen.review.destinations_needing_check() {
            wallet.review_input(ReviewInput::ConfirmDestination {
                index, typed: screen.review.destination_check_text(index),
            }).unwrap();
        }
        for ack in screen.review.acknowledgements() {
            wallet.review_input(ReviewInput::Acknowledge(*ack)).unwrap();
        }
        let ReviewOutcome::Queued(queued) = wallet.review_input(ReviewInput::Authorize).unwrap()
            else { panic!("Actual reviewed payment was not queued") };
        assert!(queued.complete);
        assert_eq!(queued.kind, mutiny_wallet_core_v8::OperationKind::Payment);
        assert!(wallet.queued_operations().unwrap().is_empty());
        assert!(matches!(wallet.delivery(queued.id).unwrap(), Delivery::Unconfirmed(_)));
        let admission = driver.deliver(&mut wallet, queued.id, true).unwrap();
        assert_eq!(admission["id"], hex::encode(queued.id));
        assert_eq!(admission["confirmed"], false);
        assert!(admission["wallet_own_confirmation_height"].is_null());
        let confirmed = driver.certify_next(&mut wallet).unwrap();
        assert_eq!(confirmed["height"], 1);
        assert_eq!(confirmed["own_confirmations"][0]["id"], hex::encode(queued.id));
        assert_eq!(confirmed["own_confirmations"][0]["own_confirmed_height"], 1);
        assert_eq!(wallet.delivery(queued.id).unwrap(), Delivery::ConfirmedAt(1));
        // This review view intentionally only indexes operation-outbox IDs. The
        // payment result must not be inferred from that bounded empty view.
        assert_eq!(wallet.with_view(|view| view.confirmed_height(&queued.id)).unwrap(), None);
        assert!(matches!(wallet.delivery([0xED; 32]).unwrap(), Delivery::Unconfirmed(_)));
        assert!(driver.remote.confirmed_height([0xED; 32]).unwrap().is_none());
        assert!(driver.local.confirmed_height([0xED; 32]).unwrap().is_none());
        let replay = CanonicalStore::open_trusted_genesis(
            &vault.path().join("public-chain.sqlite"), &driver.fixture.genesis,
            &driver.initial, driver.initial_root, T0, [255; 32],
        ).unwrap();
        let rows = replay.verified_operation_records(queued.id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].height, 1);
        assert_eq!(rows[0].op_id, queued.id);
        assert!(replay.verified_operation_records([0xED; 32]).unwrap().is_empty());
    }
}
