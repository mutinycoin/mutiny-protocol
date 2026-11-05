// Uses synthetic admitted hardware and real hybrid signatures; no TPM access.
fn qualify_observation_journal(base:&std::path::Path,runtime:&mut crate::hybrid_runtime_v2::HybridRuntime,
    issued:&mut crate::work_journal_v2::Journal,coordinator:&mut crate::hybrid_coordinator_v2::Coordinator,
    clock:&mut impl crate::hybrid_coordinator_v2::Clock,custody:crate::observation_custody_v2::Custody<'_>,
    parent:&FinalizedAnchor,timestamp:u64,delivery:&crate::hybrid_coordinator_v2::Delivery) {
    use crate::observation_journal_v2::Journal;
    let path=base.join("observations.sqlite");
    let c=&delivery.authority.work.candidate;
    let header=crate::pow::WorkHeader{candidate:c.clone(),authority:delivery.authority.id().unwrap(),nonce:delivery.authority.work.nonce_start};
    let scope=crate::worker_protocol_v2::Scope{genesis:c.genesis,fingerprint:c.fingerprint,license:c.license,worker:c.worker};
    let decode=|header:&crate::pow::WorkHeader,sequence:u64,previous:Hash|{
        let mut raw=vec![3,2];raw.extend(sequence.to_be_bytes());raw.extend(previous);raw.extend(header.work_bytes());
        let crate::worker_protocol_v2::Incoming::Result(s)=crate::worker_protocol_v2::decode(&raw,scope).unwrap() else{panic!("result")};s
    };
    let submission=decode(&header,1,[0;32]);
    let mut journal=Journal::open(&path,c.genesis,c.fingerprint,&delivery.authority.node_descriptor,true).unwrap();
    assert!(journal.matches_checkpoint(c.worker,0,[0;32]).unwrap());
    assert!(!journal.matches_checkpoint(c.worker,1,[1;32]).unwrap());
    let db=rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER synthetic_receipt_write_failure BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT,'synthetic write failure'); END;").unwrap();
    assert!(journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&submission).is_err());
    assert!(journal.load(c.worker).unwrap().is_none());
    db.execute_batch("DROP TRIGGER synthetic_receipt_write_failure;").unwrap();
    let first=journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&submission).unwrap();
    assert_eq!((first.sequence(),first.total()),(1,1));
    assert_eq!(first.candidate().0,&header);
    assert!(journal.matches_checkpoint(c.worker,1,first.chain()).unwrap());
    assert!(!journal.matches_checkpoint(c.worker,0,[0;32]).unwrap());
    let retry=journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&submission).unwrap();
    assert!(first.same_receipt(&retry));
    let candidate_path=base.join("receipt-candidates.sqlite");
    let mut candidates=crate::candidate_journal_v2::Journal::open(&candidate_path,c.genesis,c.fingerprint,1024*1024,true).unwrap();
    let record=crate::candidate_journal_v2::Record{header:header.clone(),authority:delivery.authority.clone(),body:delivery.body.clone()};
    let mut alternate=record.clone();
    match &custody {
        crate::observation_custody_v2::Custody::Physical(k)=>k.authorize_work(&runtime.chain,parent,&mut alternate.authority,&alternate.body),
        crate::observation_custody_v2::Custody::Software(k)=>k.authorize_work(&runtime.chain,parent,&mut alternate.authority,&alternate.body),
    }.unwrap();
    assert_ne!(alternate.authority.signature.fndsa,record.authority.signature.fndsa);
    assert_eq!(alternate.authority.id().unwrap(),record.authority.id().unwrap());
    candidates.preserve(runtime,&alternate).unwrap();
    let retained=candidates.preserve(runtime,&record).unwrap();
    assert_eq!(candidates.next_current(runtime,None).unwrap(),Some(alternate));
    let receipt=retry.release(retained).unwrap();
    let retained=candidates.preserve(runtime,&record).unwrap();
    let packet=journal.load(c.worker).unwrap().unwrap().release_packet(retained).unwrap();
    let descriptor=&delivery.authority.node_descriptor;
    assert_eq!(&packet[..2],&[4,2]);
    assert_eq!(u16::from_be_bytes(packet[2..4].try_into().unwrap()) as usize,descriptor.len());
    assert_eq!(&packet[4..4+descriptor.len()],descriptor.as_slice());
    assert_eq!(&packet[4+descriptor.len()..],receipt.as_slice());
    crate::observation_receipt_v2::Intent::accepted(&header,1,[0;32],0,&delivery.authority.node_descriptor).unwrap().verify(&receipt).unwrap();
    let mut other=record.clone();other.header.nonce=other.header.nonce.checked_add(1).unwrap();
    let wrong_retention=candidates.preserve(runtime,&other).unwrap();
    assert!(journal.load(c.worker).unwrap().unwrap().release(wrong_retention).is_err());
    let wrong_retention=candidates.preserve(runtime,&other).unwrap();
    assert!(journal.load(c.worker).unwrap().unwrap().release_packet(wrong_retention).is_err());
    drop(candidates);
    let mut candidates=crate::candidate_journal_v2::Journal::open(&candidate_path,c.genesis,c.fingerprint,1024*1024,false).unwrap();
    let retained=candidates.preserve(runtime,&record).unwrap();
    assert_eq!(journal.load(c.worker).unwrap().unwrap().release(retained).unwrap(),receipt);
    drop(candidates);
    let mut wrong=header.clone();wrong.nonce=wrong.nonce.checked_add(1).unwrap();
    assert!(journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&decode(&wrong,1,[0;32])).is_err());
    assert!(journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&decode(&header,3,first.chain())).is_err());
    assert!(journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&decode(&header,2,[1;32])).is_err());
    assert!(journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&decode(&header,2,first.chain())).is_err(),"same ticket credited twice");
    drop(journal);
    let mut journal=Journal::open(&path,c.genesis,c.fingerprint,&delivery.authority.node_descriptor,false).unwrap();
    let reopened=journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&submission).unwrap();
    assert!(first.same_receipt(&reopened));
    use crate::hybrid_coordinator_v2::{Accounting,Request};
    let mut candidates=crate::candidate_journal_v2::Journal::open(&candidate_path,c.genesis,c.fingerprint,1024*1024,false).unwrap();
    let request=||Request{parent,license:c.license,worker:c.worker,request_nonce:[91;32],nonce_start:0,nonce_end:100,operations:&[]};
    let before=issued.lookup(c.worker).unwrap();
    assert!(coordinator.prepare_accounted(runtime,issued,&custody,request(),
        Accounting{journal:&journal,sequence:0,chain:[0;32]},&mut candidates,clock).is_err());
    assert_eq!(issued.lookup(c.worker).unwrap(),before,"bad checkpoint consumed a ticket");
    let full_path=base.join("synthetic-full-candidates.sqlite");
    let mut full=crate::candidate_journal_v2::Journal::open(&full_path,c.genesis,c.fingerprint,1,true).unwrap();
    assert!(coordinator.prepare_accounted(runtime,issued,&custody,request(),
        Accounting{journal:&journal,sequence:1,chain:first.chain()},&mut full,clock).is_err(),"calculated checkpoint bypassed candidate retention");
    assert_eq!(issued.lookup(c.worker).unwrap(),before,"retention failure consumed a ticket");
    drop(full);std::fs::remove_file(full_path).unwrap();
    let pending=coordinator.prepare_accounted(runtime,issued,&custody,request(),
        Accounting{journal:&journal,sequence:1,chain:first.chain()},&mut candidates,clock).unwrap();
    // Synthetic interleaving: accounting advances after preparation but before
    // publication. Read the local committed offer, never an actual peer secret.
    let (next,_)=issued.lookup(c.worker).unwrap().unwrap();
    let next_header=crate::pow::WorkHeader{candidate:next.work.candidate.clone(),authority:next.id().unwrap(),nonce:0};
    let second_submission=decode(&next_header,2,first.chain());
    let second=journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&second_submission).unwrap();
    assert_eq!((second.sequence(),second.total()),(2,2));
    assert!(coordinator.release_accounted(runtime,issued,&journal,pending,clock).is_err());
    assert!(journal.accept(&runtime.chain,issued,&custody,parent,timestamp,&submission).is_err(),"older acknowledged submission accepted");
    let pending=coordinator.prepare_accounted(runtime,issued,&custody,request(),
        Accounting{journal:&journal,sequence:2,chain:second.chain()},&mut candidates,clock).unwrap();
    let next=coordinator.release_accounted(runtime,issued,&journal,pending,clock).unwrap();
    assert_eq!(next.authority.work.ticket_sequence,3);
    assert_eq!(next.request_nonce,[91;32]);
    assert!(next.valid_for_ms>0&&next.valid_for_ms<=20_000);
    assert_eq!(&next.wire[..2],&[5,2]);assert_eq!(&next.wire[2..34],&[91;32]);
    assert_eq!(u64::from_be_bytes(next.wire[34..42].try_into().unwrap()),next.authority.work.epoch);
    assert_eq!(u64::from_be_bytes(next.wire[42..50].try_into().unwrap()),next.valid_for_ms);
    assert_eq!(usize::from(u16::from_be_bytes(next.wire[50..52].try_into().unwrap())),next.wire.len()-52);
    assert_eq!(crate::work_authority_v2::Authority::decode(&next.wire[52..]).unwrap(),next.authority);
    drop(journal);
    let journal=Journal::open(&path,c.genesis,c.fingerprint,&delivery.authority.node_descriptor,false).unwrap();
    assert!(second.same_receipt(&journal.load(c.worker).unwrap().unwrap()));
    drop(journal);
    assert!(Journal::open(&path,c.genesis,[9;32],&delivery.authority.node_descriptor,false).is_err());
    db.execute("UPDATE checkpoints SET receipt=zeroblob(1672)",[]).unwrap();
    assert!(Journal::open(&path,c.genesis,c.fingerprint,&delivery.authority.node_descriptor,false).is_err());
    drop(db);std::fs::remove_file(path).unwrap();
    drop(candidates);std::fs::remove_file(candidate_path).unwrap();
}
fn qualify_observation_custody(
    custody: crate::observation_custody_v2::Custody<'_>,
    chain: &crate::canonical_store_v2::CanonicalStore, parent: &FinalizedAnchor,
    timestamp: u64, delivery: &crate::hybrid_coordinator_v2::Delivery,
) -> std::result::Result<(),String> {
    let header=crate::pow::WorkHeader { candidate: delivery.authority.work.candidate.clone(),
        authority: delivery.authority.id().unwrap(), nonce: delivery.authority.work.nonce_start };
    let request=|| crate::observation_custody_v2::Request {
        parent,timestamp,header:&header,authority:&delivery.authority,body:&delivery.body,
        sequence:1,previous:[0;32],prior_total:0,
    };
    let raw=custody.sign(chain,request())?;
    let intent=crate::observation_receipt_v2::Intent::accepted(&header,1,[0;32],0,
        &delivery.authority.node_descriptor).unwrap();
    intent.verify(&raw).unwrap();
    let mut bad=delivery.authority.clone();bad.signature.fndsa.fill(0);
    let mut invalid=request();invalid.authority=&bad;
    assert!(custody.sign(chain,invalid).is_err());
    let mut invalid=request();invalid.previous=[1;32];
    assert!(custody.sign(chain,invalid).is_err());
    Ok(())
}
fn qualify_hybrid_coordinator(
    state: &State,
    genesis: &FinalizedAnchor,
    envelope: &crate::block_envelope_v2::BlockEnvelope,
    continuity: &HybridKey,
    key: &crate::node_custody_v2::EncryptedNodeKey,
) {
    use crate::hybrid_coordinator_v2::{Clock, Coordinator, Request, Sample};
    use crate::hybrid_runtime_v2::HybridRuntime;
    use crate::work_journal_v2::Journal;
    struct TestClock {
        mono: u64,
        wall: u64,
    }
    impl Clock for TestClock {
        fn sample(&mut self) -> std::result::Result<Sample, String> {
            Ok(Sample {
                monotonic_ms: self.mono,
                unix_ms: self.wall,
            })
        }
    }
    fn admit(
        c: &mut Coordinator,
        r: &HybridRuntime,
        p: &FinalizedAnchor,
        key: &HybridKey,
        clock: &mut TestClock,
    ) {
        let decision = c.request_probe(r, p, clock).unwrap().unwrap();
        let authority = r.current_authority(p).unwrap();
        let node = *authority.voters.keys().next().unwrap();
        let voter = &authority.voters[&node];
        let mut fragment = crate::liveness_v2::Fragment {
            node,
            hardware_generation: voter.hardware_generation,
            key_generation: voter.key_generation,
            vote_sequence: 0,
            tpm_identity: voter.tpm_identity(),
            profile: voter.profile,
            signature: HybridSignature {
                ed448: [0; 114],
                fndsa: [0; 1280],
            },
        };
        fragment.sign(&decision, key).unwrap();
        let proof = crate::liveness_v2::Proof {
            decision,
            fragments: vec![fragment],
        };
        if std::env::var_os("BUILD8_EXPORT_SYNTHETIC_WORK_NETWORK").is_some() {
            let (_, state, root) = r.chain.execution_parent(p.height).unwrap();
            let records = state.records().unwrap();
            let value = serde_json::json!({"synthetic_only":true,"production_authorized":false,
                "genesis":hex::encode(p.encode()),"root":hex::encode(root),
                "records":records.iter().map(|(k,v)|serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect::<Vec<_>>(),
                "proof":hex::encode(proof.encode().unwrap())});
            use std::io::Write;
            let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/hybrid-work-network-public-v1.json");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out)
                .unwrap();
            file.write_all(serde_json::to_string_pretty(&value).unwrap().as_bytes())
                .unwrap();
        }
        assert_eq!(
            c.accept_probe(r, p, &proof, clock).unwrap(),
            crate::liveness::WorkState::Running
        );
    }
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-coordinator-v2-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let chain = crate::canonical_store_v2::CanonicalStore::open_trusted_genesis(
        &base.join("chain.sqlite"),
        genesis,
        state,
        state.root().unwrap(),
        1000,
        [255; 32],
    )
    .unwrap();
    let pool = crate::mempool_v2::Mempool::open(
        &base.join("pool.sqlite"),
        genesis.genesis,
        genesis.fingerprint,
        64 * 1024 * 1024,
    )
    .unwrap();
    let mut runtime = HybridRuntime::from_pinned_chain(chain, pool).unwrap();
    let mut journal = Journal::initialize(
        &base.join("work.sqlite"),
        genesis.genesis,
        genesis.fingerprint,
        &envelope.authority.node_descriptor,
    )
    .unwrap();
    let mut c = Coordinator::default();
    c.set_run(true);
    let mut clock = TestClock {
        mono: 0,
        wall: 1_100_000,
    };
    let candidate = &envelope.header.candidate;
    reject_worker_canonical_contexts(&runtime.chain, genesis, candidate.license, candidate.worker);
    let mut current_channel = {
        let (context, signer) = crate::worker_session_custody_v2::WorkerSessionSigner::physical(
            key, &runtime.chain, genesis, candidate.license, candidate.worker, 1100,
        ).unwrap();
        let (_, binding, _, _) = runtime.chain.current_worker_session(
            genesis, candidate.license, candidate.worker, 1100,
        ).unwrap();
        qualify_current_worker_channel(context.clone(), &signer, &binding, &runtime.chain, genesis,
            &envelope.authority.node_descriptor);
        qualify_worker_handshake_io(crate::worker_handshake_io_v2::Custody::Physical(key),
            context.clone(), &binding, &runtime.chain, genesis, &envelope.authority.node_descriptor);
        live_canonical_worker_channel(context, &signer, &binding, &runtime.chain, genesis)
    };
    let request = || Request {
        parent: genesis,
        license: candidate.license,
        worker: candidate.worker,
        request_nonce: [99; 32],
        nonce_start: 0,
        nonce_end: u64::MAX,
        operations: &[],
    };
    assert!(
        c.prepare(&mut runtime, &mut journal, key, request(), &mut clock)
            .is_err()
    );
    assert!(journal.lookup(candidate.worker).unwrap().is_none());
    admit(&mut c, &runtime, genesis, continuity, &mut clock);
    // Package P-E (decision 6): an UNAVAILABLE (unqualified) clock authorizes no new work. The
    // sample is the first thing `prepare` consults, so no ticket is reserved, nothing is prepared
    // and nothing is signed, however much lease the gate holds.
    {
        struct Unavailable;
        impl Clock for Unavailable {
            fn sample(&mut self) -> std::result::Result<Sample, String> {
                Err("Qualified clock unavailable".into())
            }
        }
        let before = journal.lookup(candidate.worker).unwrap();
        assert!(
            c.prepare(&mut runtime, &mut journal, key, request(), &mut Unavailable)
                .is_err()
        );
        assert_eq!(
            journal.lookup(candidate.worker).unwrap(),
            before,
            "an unqualified clock reserved a ticket"
        );
        // The failed sample dropped the lease context: qualification must be earned again.
        admit(&mut c, &runtime, genesis, continuity, &mut clock);
    }
    let pending = c
        .prepare(&mut runtime, &mut journal, key, request(), &mut clock)
        .unwrap();
    assert_eq!(
        journal
            .lookup(candidate.worker)
            .unwrap()
            .unwrap()
            .0
            .work
            .ticket_sequence,
        1
    );
    clock.mono = 100;
    clock.wall += 100;
    let delivered = c.release(&runtime, &journal, pending, &mut clock).unwrap();
    assert_eq!(delivered.valid_for_ms, 19_900);
    assert_eq!(delivered.request_nonce, [99; 32]);
    assert_eq!(delivered.authority.work.nonce_end, u64::MAX);
    qualify_observation_journal(&base, &mut runtime, &mut journal, &mut c, &mut clock,
        crate::observation_custody_v2::Custody::Physical(key),genesis,1100,&delivered);
    qualify_observation_custody(crate::observation_custody_v2::Custody::Physical(key),
        &runtime.chain, genesis, 1100, &delivered).unwrap();
    runtime
        .chain
        .validate_node_work(
            genesis,
            state.continuity.as_ref().unwrap().members[0].node,
            &delivered.authority,
            &delivered.body,
        )
        .unwrap();
    let (context, descriptor) = runtime
        .chain
        .current_work_context(genesis, candidate.license, candidate.worker, 1100)
        .unwrap();
    delivered
        .authority
        .verify(
            &crate::pow::WorkHeader {
                candidate: delivered.authority.work.candidate.clone(),
                authority: delivered.authority.id().unwrap(),
                nonce: 0,
            },
            &context,
            &descriptor,
        )
        .unwrap();
    // Returning to RUN cannot revive an already prepared response.
    let pending = c
        .prepare(&mut runtime, &mut journal, key, request(), &mut clock)
        .unwrap();
    c.set_run(false);
    c.set_run(true);
    assert!(c.release(&runtime, &journal, pending, &mut clock).is_err());
    // The private ticket reservation is consumed before each full execution.
    let older = c
        .prepare(&mut runtime, &mut journal, key, request(), &mut clock)
        .unwrap();
    let newer = c
        .prepare(&mut runtime, &mut journal, key, request(), &mut clock)
        .unwrap();
    assert!(c.release(&runtime, &journal, older, &mut clock).is_err());
    assert_eq!(
        c.release(&runtime, &journal, newer, &mut clock)
            .unwrap()
            .authority
            .work
            .ticket_sequence,
        6
    );
    let pending = c
        .prepare(&mut runtime, &mut journal, key, request(), &mut clock)
        .unwrap();
    clock.mono = 20_000;
    clock.wall = 1_120_000;
    assert!(
        c.release(&runtime, &journal, pending, &mut clock).is_err(),
        "epoch-crossing release"
    );
    let pending = c
        .prepare(&mut runtime, &mut journal, key, request(), &mut clock)
        .unwrap();
    let mut restarted = Coordinator::default();
    restarted.set_run(true);
    assert!(
        restarted
            .release(&runtime, &journal, pending, &mut clock)
            .is_err(),
        "cross-instance pending"
    );
    let pending = c
        .prepare(&mut runtime, &mut journal, key, request(), &mut clock)
        .unwrap();
    // Finalized Node rotation retires both the parent lease and Node authority.
    runtime.install(&envelope.encode().unwrap()).unwrap();
    assert!(qualify_observation_custody(crate::observation_custody_v2::Custody::Physical(key),
        &runtime.chain, &runtime.head().unwrap(), 1120, &delivered).is_err(),
        "retired physical Node signed a new historical observation receipt");
    let mut channel_clock = FixedWorkerClock(Sample {monotonic_ms: 101, unix_ms: 1_120_000});
    assert!(current_channel.check(&runtime.chain, &runtime.head().unwrap(), &mut channel_clock).is_err(),
        "physical Node rotation left a live Worker channel");
    assert!(crate::worker_session_custody_v2::WorkerSessionSigner::physical(
        key, &runtime.chain, genesis, candidate.license, candidate.worker, 1100,
    ).is_err());
    assert!(crate::worker_session_custody_v2::WorkerSessionSigner::physical(
        key, &runtime.chain, &runtime.head().unwrap(), candidate.license, candidate.worker, 1120,
    ).is_err(), "rotated physical Node custody cannot start a session");
    assert!(c.release(&runtime, &journal, pending, &mut clock).is_err());
    assert!(
        c.prepare(&mut runtime, &mut journal, key, request(), &mut clock)
            .is_err()
    );
    drop(journal);
    drop(runtime);
    println!("RETAINED_PUBLIC_COORDINATOR_EVIDENCE={}",base.display());
}

fn qualify_software_coordinator(
    initial: &State,
    genesis: &FinalizedAnchor,
    owner: &HybridKey,
    continuity: &HybridKey,
) {
    use crate::hybrid_coordinator_v2::{Clock, Coordinator, Request, Sample};
    use crate::hybrid_runtime_v2::HybridRuntime;
    use crate::software_coordinator_custody_v2::{EncryptedCoordinatorKey, custody_context};
    let software = HybridKey::generate(Role::Node).unwrap();
    let descriptor = software.public().descriptor(1).unwrap();
    let physical = initial
        .membership_v2
        .get(initial.continuity.as_ref().unwrap().members[0].node)
        .unwrap()
        .current_node_descriptor()
        .to_vec();
    let (_, mut assignments, mut expected, licenses, _) = license_fixture::fixtures();
    for (index, binding) in expected.iter_mut().enumerate() {
        let desc = if index < 6 { &physical } else { &descriptor };
        binding.coordinator = crate::work_authority_v2::node_identity(desc).unwrap();
        assignments[index] = license_fixture::sign(binding.clone(), owner, desc, index as u8 + 1);
    }
    let mut state = initial.clone();
    state.licenses_v2 = crate::license_book_v2::Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &state.wallets,
        genesis.genesis,
        genesis.fingerprint,
    )
    .unwrap();
    let root = state.root().unwrap();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!(
        "build8-software-coordinator-{}",
        hex::encode(random)
    ));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let chain = crate::canonical_store_v2::CanonicalStore::open_trusted_genesis(
        &base.join("chain.sqlite"),
        genesis,
        &state,
        root,
        1000,
        [255; 32],
    )
    .unwrap();
    let pool = crate::mempool_v2::Mempool::open(
        &base.join("pool.sqlite"),
        genesis.genesis,
        genesis.fingerprint,
        64 * 1024 * 1024,
    )
    .unwrap();
    let mut runtime = HybridRuntime::from_pinned_chain(chain, pool).unwrap();
    let (context, canonical) = runtime
        .chain
        .current_software_coordinator(genesis, licenses[6].id, expected[6].worker_id, 1100)
        .unwrap();
    assert_eq!(canonical, descriptor);
    assert!(
        runtime
            .chain
            .current_software_coordinator(genesis, licenses[0].id, expected[0].worker_id, 1100)
            .is_err(),
        "physical key accepted by software-only custody"
    );
    let aad = custody_context(genesis.genesis, genesis.fingerprint, &descriptor).unwrap();
    let password = "synthetic cloud work key only";
    let encrypted = software.seal_for(password, 1, &aad).unwrap();
    assert!(
        EncryptedCoordinatorKey::unlock(
            &runtime.chain,
            genesis,
            licenses[6].id,
            expected[6].worker_id,
            1100,
            &encrypted,
            "wrong"
        )
        .is_err()
    );
    let wrong_aad = custody_context([99; 32], genesis.fingerprint, &descriptor).unwrap();
    let wrong = software.seal_for(password, 1, &wrong_aad).unwrap();
    assert!(
        EncryptedCoordinatorKey::unlock(
            &runtime.chain,
            genesis,
            licenses[6].id,
            expected[6].worker_id,
            1100,
            &wrong,
            password
        )
        .is_err()
    );
    assert!(
        EncryptedCoordinatorKey::unlock(
            &runtime.chain,
            genesis,
            licenses[0].id,
            expected[0].worker_id,
            1100,
            &encrypted,
            password
        )
        .is_err()
    );
    let key = EncryptedCoordinatorKey::unlock(
        &runtime.chain,
        genesis,
        licenses[6].id,
        expected[6].worker_id,
        1100,
        &encrypted,
        password,
    )
    .unwrap();
    reject_worker_canonical_contexts(&runtime.chain, genesis, licenses[6].id, expected[6].worker_id);
    let mut current_channel = {
        use mutiny_transport_v2::worker_handshake_v2::NodeSessionSigner;
        let (context, signer) = crate::worker_session_custody_v2::WorkerSessionSigner::software(
            &key, &runtime.chain, genesis, licenses[6].id, expected[6].worker_id, 1100,
        ).unwrap();
        qualify_current_worker_channel(context.clone(), &signer, &expected[6], &runtime.chain,
            genesis, &descriptor);
        qualify_worker_carrier(context.clone(), &signer, &expected[6], &runtime.chain,
            genesis, &descriptor);
        qualify_worker_handshake_io(crate::worker_handshake_io_v2::Custody::Software(&key),
            context.clone(), &expected[6], &runtime.chain, genesis, &descriptor);
        let (other, _) = crate::worker_session_custody_v2::WorkerSessionSigner::software(
            &key, &runtime.chain, genesis, licenses[7].id, expected[7].worker_id, 1100,
        ).unwrap();
        assert!(signer.validate_context(&other).is_err(), "same key, different assignment");
        assert!(signer.sign_session(&other, &[], &[]).is_err());
        live_canonical_worker_channel(context, &signer, &expected[6], &runtime.chain, genesis)
    };
    #[cfg(target_os = "linux")]
    let secure = {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(format!("build8-software-custody-{}", hex::encode(random)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        assert!(
            EncryptedCoordinatorKey::publish_current_generation(
                &runtime.chain,
                genesis,
                licenses[6].id,
                expected[6].worker_id,
                1100,
                &path,
                &encrypted,
                "wrong"
            )
            .is_err()
        );
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        EncryptedCoordinatorKey::publish_current_generation(
            &runtime.chain,
            genesis,
            licenses[6].id,
            expected[6].worker_id,
            1100,
            &path,
            &encrypted,
            password,
        )
        .unwrap();
        assert!(
            EncryptedCoordinatorKey::publish_current_generation(
                &runtime.chain,
                genesis,
                licenses[6].id,
                expected[6].worker_id,
                1100,
                &path,
                &encrypted,
                password
            )
            .is_err()
        );
        EncryptedCoordinatorKey::unlock_generation_file(
            &runtime.chain,
            genesis,
            licenses[6].id,
            expected[6].worker_id,
            1100,
            &path,
            password,
        )
        .unwrap();
        path
    };
    struct FixedClock;
    impl Clock for FixedClock {
        fn sample(&mut self) -> std::result::Result<Sample, String> {
            Ok(Sample {
                monotonic_ms: 0,
                unix_ms: 1_100_000,
            })
        }
    }
    let mut clock = FixedClock;
    let mut c = Coordinator::default();
    c.set_run(true);
    let mut journal = crate::work_journal_v2::Journal::initialize(
        &base.join("work.sqlite"),
        genesis.genesis,
        genesis.fingerprint,
        &descriptor,
    )
    .unwrap();
    let request = |i: usize| Request {
        parent: genesis,
        license: licenses[i].id,
        worker: expected[i].worker_id,
        request_nonce: [96; 32],
        nonce_start: 0,
        nonce_end: 100,
        operations: &[],
    };
    assert!(
        c.prepare_software(&mut runtime, &mut journal, &key, request(6), &mut clock)
            .is_err(),
        "software key bypassed quorum"
    );
    let decision = c
        .request_probe(&runtime, genesis, &mut clock)
        .unwrap()
        .unwrap();
    let authority = runtime.current_authority(genesis).unwrap();
    assert_eq!(authority.voters.len(), 1);
    assert!(
        authority
            .voters
            .values()
            .all(|v| v.public != *software.public())
    );
    let (&node, voter) = authority.voters.iter().next().unwrap();
    let mut fragment = crate::liveness_v2::Fragment {
        node,
        hardware_generation: voter.hardware_generation,
        key_generation: voter.key_generation,
        vote_sequence: 0,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    assert!(
        fragment.sign(&decision, &software).is_err(),
        "Node key signed Continuity probe"
    );
    fragment.sign(&decision, continuity).unwrap();
    let proof = crate::liveness_v2::Proof {
        decision,
        fragments: vec![fragment],
    };
    c.accept_probe(&runtime, genesis, &proof, &mut clock)
        .unwrap();
    let pending = c
        .prepare_software(&mut runtime, &mut journal, &key, request(6), &mut clock)
        .unwrap();
    let delivered = c.release(&runtime, &journal, pending, &mut clock).unwrap();
    delivered
        .authority
        .verify(
            &crate::pow::WorkHeader {
                candidate: delivered.authority.work.candidate.clone(),
                authority: delivered.authority.id().unwrap(),
                nonce: 0,
            },
            &context,
            &descriptor,
        )
        .unwrap();
    runtime
        .chain
        .validate_software_coordinator_work(genesis, &delivered.authority, &delivered.body)
        .unwrap();
    qualify_observation_journal(&base,&mut runtime,&mut journal,&mut c,&mut clock,
        crate::observation_custody_v2::Custody::Software(&key),genesis,1100,&delivered);
    qualify_observation_custody(crate::observation_custody_v2::Custody::Software(&key),
        &runtime.chain, genesis, 1100, &delivered).unwrap();
    let mut changed = delivered.authority.clone();
    changed.work.candidate.state_root[0] ^= 1;
    let before = changed.clone();
    assert!(
        key.authorize_work(&runtime.chain, genesis, &mut changed, &delivered.body)
            .is_err()
    );
    assert_eq!(changed, before);
    let mut changed = delivered.authority.clone();
    changed.work.candidate.worker = expected[0].worker_id;
    assert!(
        key.authorize_work(&runtime.chain, genesis, &mut changed, &delivered.body)
            .is_err()
    );
    assert!(
        c.prepare_software(&mut runtime, &mut journal, &key, request(0), &mut clock)
            .is_err()
    );
    assert_eq!(runtime.chain.load().unwrap().0.root, root);
    assert_eq!(runtime.head().unwrap(), *genesis);
    // Ordinary owner/Worker authorization rotates the assigned coordinator at
    // the next MiningEpoch. No physical admission or cloud voting key is made.
    let replacement = HybridKey::generate(Role::Node).unwrap();
    let next_descriptor = replacement.public().descriptor(2).unwrap();
    let mut binding = expected[6].clone();
    binding.worker_public = license_fixture::worker(90);
    binding.worker_id = binding.derived_worker_id();
    binding.assignment_generation = 2;
    binding.configuration_generation = 2;
    binding.effective_epoch = 2;
    binding.valid_until_height = 20;
    binding.coordinator = crate::work_authority_v2::node_identity(&next_descriptor).unwrap();
    let assignment = license_fixture::sign(binding.clone(), owner, &next_descriptor, 90);
    let operations = [assignment.encode().unwrap()];
    let mut rotate_request = request(6);
    rotate_request.operations = &operations;
    let pending = c
        .prepare_software(&mut runtime, &mut journal, &key, rotate_request, &mut clock)
        .unwrap();
    let offered = c.release(&runtime, &journal, pending, &mut clock).unwrap();
    let header = crate::pow::WorkHeader {
        candidate: offered.authority.work.candidate.clone(),
        authority: offered.authority.id().unwrap(),
        nonce: 0,
    };
    let decision = crate::certificates::Decision {
        network: NETWORK_ID,
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: genesis.id(),
        parent: genesis.block,
        block: header.block_hash(),
        state: header.candidate.state_root,
        membership: authority.membership,
        reputation: authority.reputation,
        attestation: authority.attestation,
    };
    let mut vote = crate::continuity_v2::Vote {
        decision: decision.clone(),
        nil: false,
        node,
        hardware_generation: voter.hardware_generation,
        key_generation: voter.key_generation,
        sequence: 1,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    vote.sign(continuity).unwrap();
    let block = crate::block_envelope_v2::BlockEnvelope {
        header,
        body: offered.body,
        authority: offered.authority,
        certificate: crate::continuity_v2::Certificate {
            decision,
            votes: vec![vote],
        },
    };
    runtime.install(&block.encode().unwrap()).unwrap();
    let parent = runtime.head().unwrap();
    qualify_observation_custody(crate::observation_custody_v2::Custody::Software(&key),
        &runtime.chain, &parent, 1119, &delivered).unwrap();
    assert!(qualify_observation_custody(crate::observation_custody_v2::Custody::Software(&key),
        &runtime.chain, &parent, 1120, &delivered).is_err(),
        "retired software assignment signed a new receipt");
    let mut channel_clock = FixedWorkerClock(Sample {monotonic_ms:101, unix_ms:1_119_000});
    current_channel.check(&runtime.chain, &parent, &mut channel_clock).unwrap();
    channel_clock.0 = Sample {monotonic_ms:102, unix_ms:1_120_000};
    assert!(current_channel.check(&runtime.chain, &parent, &mut channel_clock).is_err(),
        "live channel survived exact reassignment epoch");
    assert!(current_channel.seal(&runtime.chain, &parent, &mut channel_clock, b"retired").is_err());
    assert!(crate::worker_session_custody_v2::WorkerSessionSigner::software(
        &key, &runtime.chain, genesis, licenses[6].id, expected[6].worker_id, 1100,
    ).is_err());
    {
        let (context, signer) = crate::worker_session_custody_v2::WorkerSessionSigner::software(
            &key, &runtime.chain, &parent, licenses[6].id, expected[6].worker_id, 1119,
        ).unwrap();
        qualify_worker_custody_handshake(context, &signer, &expected[6]);
    }
    assert!(crate::worker_session_custody_v2::WorkerSessionSigner::software(
        &key, &runtime.chain, &parent, licenses[6].id, expected[6].worker_id, 1120,
    ).is_err(), "old assignment retires at exact epoch boundary");
    assert!(crate::worker_session_custody_v2::WorkerSessionSigner::software(
        &key, &runtime.chain, &parent, licenses[6].id, binding.worker_id, 1120,
    ).is_err(), "old key cannot sign for replacement Worker");
    assert!(
        EncryptedCoordinatorKey::unlock(
            &runtime.chain,
            genesis,
            licenses[6].id,
            expected[6].worker_id,
            1100,
            &encrypted,
            password
        )
        .is_err()
    );
    assert!(
        EncryptedCoordinatorKey::unlock(
            &runtime.chain,
            &parent,
            licenses[6].id,
            expected[6].worker_id,
            1119,
            &encrypted,
            password
        )
        .is_ok()
    );
    assert!(
        EncryptedCoordinatorKey::unlock(
            &runtime.chain,
            &parent,
            licenses[6].id,
            expected[6].worker_id,
            1120,
            &encrypted,
            password
        )
        .is_err()
    );
    assert!(
        EncryptedCoordinatorKey::unlock(
            &runtime.chain,
            &parent,
            licenses[6].id,
            binding.worker_id,
            1120,
            &encrypted,
            password
        )
        .is_err()
    );
    let next_aad = custody_context(genesis.genesis, genesis.fingerprint, &next_descriptor).unwrap();
    let next_encrypted = replacement.seal_for(password, 2, &next_aad).unwrap();
    assert!(
        EncryptedCoordinatorKey::unlock(
            &runtime.chain,
            &parent,
            licenses[6].id,
            binding.worker_id,
            1119,
            &next_encrypted,
            password
        )
        .is_err()
    );
    let _next = EncryptedCoordinatorKey::unlock(
        &runtime.chain,
        &parent,
        licenses[6].id,
        binding.worker_id,
        1120,
        &next_encrypted,
        password,
    )
    .unwrap();
    assert_eq!(runtime.current_authority(&parent).unwrap().voters.len(), 1);
    drop(key);
    let _reopened = EncryptedCoordinatorKey::unlock(
        &runtime.chain,
        &parent,
        licenses[7].id,
        expected[7].worker_id,
        1120,
        &encrypted,
        password,
    )
    .unwrap();
    #[cfg(target_os = "linux")]
    {
        assert!(
            EncryptedCoordinatorKey::unlock_generation_file(
                &runtime.chain,
                &parent,
                licenses[6].id,
                expected[6].worker_id,
                1120,
                &secure,
                password
            )
            .is_err()
        );
        EncryptedCoordinatorKey::unlock_generation_file(
            &runtime.chain,
            &parent,
            licenses[7].id,
            expected[7].worker_id,
            1120,
            &secure,
            password,
        )
        .unwrap();
        std::fs::remove_file(secure.join(format!("node-{}-g1.vault", hex::encode(aad)))).unwrap();
        std::fs::remove_dir(secure).unwrap();
    }
    drop(journal);
    drop(runtime);
    println!("RETAINED_PUBLIC_SOFTWARE_COORDINATOR_EVIDENCE={}",base.display());
}
