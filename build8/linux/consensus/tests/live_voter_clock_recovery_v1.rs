//! Port of `signer_reserved_recovery_v1` (counter_voter_v2) to the LIVE voter path
//! (`counter_voter` / `votes`, the module the node's VoterActor drives). Recovery with an
//! UNQUALIFIED or regressed clock can only complete or retransmit the exact previously authorized
//! durable decision; it can never authorize a new vote. Controlled clocks, offline, TEST-VALUE
//! synthetic fixture (GENESIS-BINDING-VECTORS-STATE-V2). Implemented, not Qualified; Offline, not
//! Physical.
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    bft::Step,
    blocks::{BlockBody, GenesisDescriptor},
    certificates::Voter,
    counter_store::{CounterStore, MonotonicCounter},
    counter_voter::*,
    execution::{State, WorkParent},
    genesis::GenesisIdentity,
    licenses::BindWorker,
    pow::{WorkAuthority, WorkHeader},
    vote_clock_v1::ControlledClock,
    votes::{AuthenticatedRound, HeightAuthority, IngressError},
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
use std::path::PathBuf;

const NODE: Hash = [0; 32];

struct Backend {
    key: SigningKey,
    counter: u64,
    calls: u64,
    fail: bool,
}
impl MonotonicCounter for Backend {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> Result<(), String> {
        self.counter += 1;
        Ok(())
    }
}
impl CounterSigningBackend for Backend {
    fn public_key(&self) -> [u8; 33] {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }
    fn sign_digest(&mut self, digest: Hash) -> Result<[u8; 64], String> {
        self.calls += 1;
        if self.fail {
            return Err("interrupted signing".into());
        }
        let s: Signature = self.key.sign_prehash(&digest).unwrap();
        Ok(s.normalize_s().unwrap_or(s).to_bytes().into())
    }
}

struct Fx {
    state: State,
    parent: WorkParent,
    header: WorkHeader,
    body: BlockBody,
    work: WorkAuthority,
    signature: [u8; 64],
    authority: HeightAuthority,
    backend: Backend,
    path: PathBuf,
}
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
fn fixture(label: &str) -> Fx {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let descriptor = GenesisDescriptor::decode(&raw(&v["descriptor_hex"])).unwrap();
    let identity = GenesisIdentity::new(descriptor.clone()).unwrap();
    let case = &v["cases"][0];
    let bindings: Vec<_> = case["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| BindWorker::decode(&raw(&b["binding_hex"])).unwrap())
        .collect();
    let state = State {
        licenses: identity.bind_workers(&bindings).unwrap(),
        ..State::default()
    };
    let header = WorkHeader::decode(&raw(&case["height1"]["header_hex"])).unwrap();
    let body = BlockBody::decode(&raw(&case["height1"]["body_hex"])).unwrap();
    let (work, signature) =
        WorkAuthority::from_envelope(&raw(&case["height1"]["authority_envelope_hex"])).unwrap();
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: identity.id(),
        fingerprint: descriptor.fingerprint,
        height: 0,
        block: descriptor.block_hash(state.root().unwrap()).unwrap(),
    };
    let work_parent = WorkParent {
        genesis: identity.id(),
        fingerprint: descriptor.fingerprint,
        block: parent.block,
        height: 0,
        t0: descriptor.timestamp,
        target: header.candidate.target,
        ancestor_timestamps: vec![descriptor.timestamp],
    };
    let key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let backend = Backend {
        key: key.clone(),
        counter: 3000,
        calls: 0,
        fail: false,
    };
    let authority = HeightAuthority {
        parent,
        membership: [7; 32],
        reputation: [8; 32],
        attestation: [9; 32],
        voters: [(
            NODE,
            Voter {
                key_version: 1,
                public_key: backend.public_key(),
                weight: U256::one(),
            },
        )]
        .into_iter()
        .collect(),
    };
    let path = std::env::temp_dir().join(format!(
        "build8-live-recovery-{label}-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    Fx {
        state,
        parent: work_parent,
        header,
        body,
        work,
        signature,
        authority,
        backend,
        path,
    }
}
impl Fx {
    fn open(&mut self, initial: Option<u64>) -> CounterVoter {
        CounterVoter::open(
            &self.path,
            self.authority.clone(),
            NODE,
            initial,
            &mut self.backend,
        )
        .unwrap()
    }
    fn validate(&self, v: &mut CounterVoter) {
        v.round_mut()
            .unwrap()
            .validate_proposal(
                &self.state,
                &self.parent,
                &self.header,
                &self.work,
                &self.signature,
                &self.body,
            )
            .unwrap();
    }
    fn ts(&self) -> u64 {
        self.header.candidate.timestamp
    }
    fn block(&self) -> Hash {
        self.header.block_hash()
    }
    /// Reserve a decision under an ELIGIBLE clock, then interrupt at the signing boundary: the
    /// reservation is durably committed, the signature is never produced.
    fn interrupted(&mut self, proposal: Option<Hash>) {
        let mut v = self.open(Some(3000));
        v.set_vote_clock(ControlledClock::at(self.ts()));
        self.validate(&mut v);
        self.backend.fail = true;
        let e = v
            .sign(Step::Prevote, proposal, None, &mut self.backend)
            .unwrap_err();
        assert!(matches!(e, CounterVoterError::Backend), "{e:?}");
        assert_eq!(self.backend.calls, 1);
        assert_eq!(self.backend.counter, 3001, "the reservation is one commit");
        // The interrupted signer is poisoned in-process; only a reopen can continue.
        assert!(matches!(v.progress(), Err(CounterVoterError::Poisoned)));
        drop(v);
        self.backend.fail = false;
    }
}

#[test]
fn reserved_block_vote_recovers_identically_under_an_unqualified_or_regressed_clock() {
    for (label, regress) in [("unqualified", false), ("regressed", true)] {
        let mut fx = fixture(label);
        let block = fx.block();
        fx.interrupted(Some(block));
        // Reopen with the DEFAULT (fail-closed unqualified) clock, or a clock far behind the block.
        let mut v = fx.open(None);
        if regress {
            v.set_vote_clock(ControlledClock::at(fx.ts() - 100));
        }
        let reserved = v.progress().unwrap().1.expect("reservation survived");
        assert_eq!(reserved.signature, [0; 64]);
        assert!(!reserved.nil);
        assert_eq!(reserved.decision.block, block);
        let before = fx.backend.counter;
        let recovered = v.replay(Step::Prevote, &mut fx.backend).unwrap().unwrap();
        // Exactly the reserved decision, now signed: nothing else was created.
        assert_eq!(recovered.signing_digest(), reserved.signing_digest());
        assert_eq!(recovered.decision.block, block);
        assert_ne!(recovered.signature, [0; 64]);
        assert_eq!(
            fx.backend.counter,
            before + 1,
            "one commit, no second logical vote"
        );
        assert_eq!(fx.backend.calls, 2);
        // Retransmission needs no clock and no counter.
        assert_eq!(
            v.replay(Step::Prevote, &mut fx.backend).unwrap().unwrap(),
            recovered
        );
        assert_eq!(fx.backend.counter, before + 1);
        assert_eq!(fx.backend.calls, 2);
        // A NEW slot (the precommit) is a fresh vote and needs the qualified, eligible clock.
        fx.validate(&mut v);
        v.round_mut().unwrap().observe(&recovered).unwrap();
        let refused = v
            .sign(Step::Precommit, Some(block), None, &mut fx.backend)
            .unwrap_err();
        assert!(
            matches!(
                refused,
                CounterVoterError::Ingress(
                    IngressError::ClockUnqualified | IngressError::FutureTimestamp { .. }
                )
            ),
            "{refused:?}"
        );
        assert_eq!(fx.backend.calls, 2, "the refusal signed nothing");
        assert_eq!(fx.backend.counter, before + 1);
        assert!(
            v.progress().is_ok(),
            "a time refusal does not poison custody"
        );
        // With a qualified, eligible clock the same slot is authorized.
        v.set_vote_clock(ControlledClock::at(fx.ts()));
        let precommit = v
            .sign(Step::Precommit, Some(block), None, &mut fx.backend)
            .unwrap();
        assert!(!precommit.nil);
    }
}

#[test]
fn sign_path_returns_the_exact_reserved_vote_without_the_clock_for_the_bound_decision() {
    let mut fx = fixture("sign-path");
    let block = fx.block();
    fx.interrupted(Some(block));
    let mut v = fx.open(None); // default unqualified clock
    fx.validate(&mut v);
    let before = fx.backend.counter;
    // The decision the reducer would now vote equals the stored one: not a fresh vote.
    let vote = v
        .sign(Step::Prevote, Some(block), None, &mut fx.backend)
        .unwrap();
    assert_eq!(vote.decision.block, block);
    assert_ne!(vote.signature, [0; 64]);
    assert_eq!(fx.backend.counter, before + 1);
}

#[test]
fn a_different_decision_in_a_reserved_slot_is_a_conflict_and_only_the_original_completes() {
    let mut fx = fixture("conflict");
    let block = fx.block();
    fx.interrupted(None); // a reserved NIL prevote
    let mut v = fx.open(None);
    fx.validate(&mut v);
    v.set_vote_clock(ControlledClock::at(u64::MAX)); // even a perfectly eligible clock
    let before = (fx.backend.counter, fx.backend.calls);
    let refused = v
        .sign(Step::Prevote, Some(block), None, &mut fx.backend)
        .unwrap_err();
    assert!(
        matches!(refused, CounterVoterError::ConflictingVote),
        "{refused:?}"
    );
    assert!(matches!(v.progress(), Err(CounterVoterError::Poisoned)));
    assert_eq!(
        (fx.backend.counter, fx.backend.calls),
        before,
        "nothing signed"
    );
    drop(v);
    // After reopen only the original nil decision completes.
    let mut v = fx.open(None);
    let completed = v.replay(Step::Prevote, &mut fx.backend).unwrap().unwrap();
    assert!(completed.nil);
    assert_eq!(completed.decision.block, [0; 32]);
}

/// Re-encode a version-3 snapshot as the version-1 record an old build wrote (no gated marker).
fn to_legacy(v3: &[u8]) -> Vec<u8> {
    let mut d = Decoder::new(v3);
    assert_eq!(d.array().unwrap(), Some(4));
    assert_eq!(d.u8().unwrap(), 3);
    let height = d.u64().unwrap();
    let state = d.bytes().unwrap().to_vec();
    let count = d.array().unwrap().unwrap();
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(height)
        .unwrap()
        .bytes(&state)
        .unwrap()
        .array(count)
        .unwrap();
    for _ in 0..count {
        assert_eq!(d.array().unwrap(), Some(5));
        let round = d.u64().unwrap();
        let step = d.u8().unwrap();
        let vote = d.bytes().unwrap().to_vec();
        let signed = d.bool().unwrap();
        let _gated = d.bool().unwrap();
        e.array(4)
            .unwrap()
            .u64(round)
            .unwrap()
            .u8(step)
            .unwrap()
            .bytes(&vote)
            .unwrap()
            .bool(signed)
            .unwrap();
    }
    e.into_writer()
}

#[test]
fn a_legacy_unmarked_unsigned_reservation_needs_a_qualified_eligible_clock_to_complete() {
    let mut fx = fixture("legacy");
    let block = fx.block();
    fx.interrupted(Some(block));
    // Rewrite the durable record exactly as a version-1 build left it: unsigned, NO guard marker.
    let context = AuthenticatedRound::new(fx.authority.clone())
        .unwrap()
        .signing_context(NODE)
        .unwrap();
    let mut store = CounterStore::open(&fx.path, context, None, &mut fx.backend).unwrap();
    let legacy = to_legacy(store.snapshot());
    store.commit(&legacy, &mut fx.backend).unwrap();
    drop(store);
    let calls = fx.backend.calls;
    let counter = fx.backend.counter;
    let mut v = fx.open(None); // default unqualified clock
    // Unqualified: refused as a time deferral, nothing signed, custody not poisoned.
    let refused = v.replay(Step::Prevote, &mut fx.backend).unwrap_err();
    assert!(
        matches!(
            refused,
            CounterVoterError::Ingress(
                IngressError::ClockUnqualified | IngressError::UnknownProposal
            )
        ),
        "{refused:?}"
    );
    fx.validate(&mut v);
    let refused = v.replay(Step::Prevote, &mut fx.backend).unwrap_err();
    assert!(matches!(
        refused,
        CounterVoterError::Ingress(IngressError::ClockUnqualified)
    ));
    // Regressed clock: still refused (the block is in the future for this validator).
    v.set_vote_clock(ControlledClock::at(fx.ts() - 100));
    let refused = v.replay(Step::Prevote, &mut fx.backend).unwrap_err();
    assert!(matches!(
        refused,
        CounterVoterError::Ingress(IngressError::FutureTimestamp { .. })
    ));
    assert_eq!((fx.backend.calls, fx.backend.counter), (calls, counter));
    assert!(v.progress().is_ok());
    // Qualified and eligible: it completes, and the record is rewritten as version 3 with the
    // marker, so later recovery no longer depends on the clock.
    v.set_vote_clock(ControlledClock::at(fx.ts()));
    let done = v.replay(Step::Prevote, &mut fx.backend).unwrap().unwrap();
    assert_eq!(done.decision.block, block);
    assert_ne!(done.signature, [0; 64]);
    drop(v);
    let mut v = fx.open(None); // unqualified again
    assert_eq!(
        v.replay(Step::Prevote, &mut fx.backend).unwrap().unwrap(),
        done
    );
    drop(v);
    let context = AuthenticatedRound::new(fx.authority.clone())
        .unwrap()
        .signing_context(NODE)
        .unwrap();
    let store = CounterStore::open(&fx.path, context, None, &mut fx.backend).unwrap();
    assert_eq!(store.snapshot()[1], 3, "rewritten as version 3");
}

// -------------------------------------------------------------------------------------------------
// Order of 4 Oct 2026, decisions C3 and C6, on the LIVE voter path with the real holdover engine
// behind the vote clock (controlled elapsed source; software, Windows host; Implemented, not
// Qualified; Simulated, not Physical).
// -------------------------------------------------------------------------------------------------
use mutiny_consensus_v8::holdover_clock_v1::{
    AnchorError, ClockProfile, ControlledElapsed, HoldoverClock, LeapView, PersistedAnchor,
    SourceSample, Status, Unqualified, inspect_legacy_v1,
};
use std::sync::Arc;

/// The REFERENCE BUDGET profile (a requirements profile, not a hardware qualification).
fn q250() -> ClockProfile {
    ClockProfile {
        max_source_uncertainty_ms: 248,
        max_calibration_half_width_ms: 250,
        min_sources: 1,
        max_faulty_sources: 0,
        drift_bound_ppb: 8680,
        max_holdover_ms: 86_400_000,
        max_interval_half_width_ms: 1000,
        max_suspend_gap_ms: 50,
        confirm_calibrations: 1,
    }
}
/// A holdover clock right after one poll: an authenticated sample at `utc_ms` (13 ms uncertainty,
/// capture age 0) under a view that vouches for everything.
fn holdover_at(utc_ms: u64) -> (Arc<HoldoverClock>, Arc<ControlledElapsed>) {
    let e = ControlledElapsed::start(41);
    let c = HoldoverClock::new(q250(), e.clone()).unwrap();
    assert!(c.set_leap_view(LeapView::Clear { valid_until_ms: u64::MAX }));
    let s = SourceSample {
        source: "chrony-nts".into(),
        authenticated: true,
        utc_ms,
        uncertainty_ms: 13,
        at: e.now(),
    };
    assert_eq!(c.calibrate(&[s]), Ok(true));
    (c, e)
}

#[test]
fn c3_a_fresh_vote_between_polls_is_judged_on_the_holdover_clock_at_its_own_instant() {
    let mut fx = fixture("c3-fresh");
    let block = fx.block();
    // Right after the poll the qualified second is 4 s behind the block: a fresh vote is refused as
    // future-dated and nothing is signed.
    let (clock, elapsed) = holdover_at((fx.ts() - 4) * 1000 + 500);
    let mut v = fx.open(Some(3000));
    v.set_vote_clock(clock.clone());
    fx.validate(&mut v);
    let refused = v.sign(Step::Prevote, Some(block), None, &mut fx.backend).unwrap_err();
    assert!(
        matches!(
            refused,
            CounterVoterError::Ingress(IngressError::FutureTimestamp { ahead_seconds: 4 })
        ),
        "{refused:?}"
    );
    assert_eq!(fx.backend.calls, 0);
    // 4.9 s later and with NO new poll the same decision is eligible: the engine recomputed age and
    // uncertainty from the elapsed source (lower bound + 4_900 - 1 ms of drift), it did not reuse
    // the poll's verdict.
    elapsed.run(4_900);
    let vote = v.sign(Step::Prevote, Some(block), None, &mut fx.backend).unwrap();
    assert!(!vote.nil);
    assert_eq!(vote.decision.block, block);
    assert_eq!(fx.backend.calls, 1);
}

#[test]
fn c3_holdover_ending_between_polls_refuses_fresh_votes_but_keeps_the_exact_recovery_exception() {
    let mut fx = fixture("c3-ended");
    let block = fx.block();
    fx.interrupted(Some(block)); // a durable, guard-marked reservation of the prevote
    let (clock, elapsed) = holdover_at(fx.ts() * 1000 + 500);
    // The adapter's view ends 4.8 s after the poll; the decisions come 4.9 s after it.
    let (_, hi) = clock.interval_ms().unwrap();
    assert!(clock.set_leap_view(LeapView::Clear { valid_until_ms: hi + 4_800 }));
    elapsed.run(4_900);
    let mut v = fx.open(None);
    v.set_vote_clock(clock.clone());
    // The exact reserved decision completes (the existing recovery exception, no clock needed) and
    // its retransmission is exact ...
    let before = fx.backend.counter;
    let recovered = v.replay(Step::Prevote, &mut fx.backend).unwrap().unwrap();
    assert_eq!(recovered.decision.block, block);
    assert_eq!(fx.backend.counter, before + 1);
    assert_eq!(v.replay(Step::Prevote, &mut fx.backend).unwrap().unwrap(), recovered);
    // ... while a NEW slot is a fresh vote and is refused: the holdover ended between polls.
    fx.validate(&mut v);
    v.round_mut().unwrap().observe(&recovered).unwrap();
    let calls = fx.backend.calls;
    let refused = v
        .sign(Step::Precommit, Some(block), None, &mut fx.backend)
        .unwrap_err();
    assert!(
        matches!(refused, CounterVoterError::Ingress(IngressError::ClockUnqualified)),
        "{refused:?}"
    );
    assert_eq!(fx.backend.calls, calls, "the refusal signed nothing");
    assert_eq!(clock.status(), Status::Unqualified(Unqualified::LeapTransition));
}

/// A genuine version-1 clock anchor (the retired encoding), carrying a high-water mark that would
/// freeze any clock that imported it.
fn legacy_v1(profile: [u8; 32], lower_ms: u64, upper_ms: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"MCLKANC1");
    b.extend_from_slice(&profile);
    for v in [lower_ms, upper_ms, 1u64, 2u64] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    b.extend_from_slice(&5u128.to_be_bytes());
    b.extend_from_slice(&u64::MAX.to_be_bytes());
    let sum = mutiny_consensus_v8::domain_hash(b"MUTINY-CLOCK-ANCHOR-V1", &b);
    b.extend_from_slice(&sum);
    b
}

#[test]
fn c6_refusing_old_unknown_or_unprotected_clock_records_never_touches_signer_state() {
    // Order C6: v1 and unknown clock records are refused and nothing in them is imported or
    // ratcheted; a valid V2 record is evidence only (Order C4). None of this resets, rewrites or
    // even reads the signer's decisions, counters, locks or halt records: the clock modules have no
    // access to them, and the durable signer state is byte-identical afterwards.
    let mut fx = fixture("c6");
    let block = fx.block();
    fx.interrupted(Some(block));
    let progress = {
        let v = fx.open(None);
        format!("{:?}", v.progress().unwrap())
    };
    let bytes = std::fs::read(&fx.path).unwrap();
    let (counter, calls) = (fx.backend.counter, fx.backend.calls);
    let (writer, elapsed) = holdover_at(fx.ts() * 1000);
    let v2 = writer.persisted(1, 2).unwrap().encode();
    let v1 = legacy_v1(q250().id(), fx.ts() * 1000 - 13, fx.ts() * 1000 + 14);
    let mut v9 = v2.clone();
    v9[7] = b'9';
    let restarted = HoldoverClock::new(q250(), elapsed.clone()).unwrap();
    assert_eq!(PersistedAnchor::decode(&v1), Err(AnchorError::Legacy));
    assert!(inspect_legacy_v1(&v1).is_some(), "readable for a log line only");
    assert_eq!(PersistedAnchor::decode(&v9), Err(AnchorError::Version(9)));
    assert!(restarted.assess_restart(&PersistedAnchor::decode(&v2).unwrap()).is_ok());
    assert!(restarted.set_leap_view(LeapView::Clear { valid_until_ms: u64::MAX }));
    assert_eq!(restarted.status(), Status::Unqualified(Unqualified::NeverCalibrated));
    assert_eq!(restarted.persisted_high_water(), 0, "nothing imported or ratcheted");
    // The signer's durable state is untouched: same bytes, same counter, nothing signed.
    assert_eq!(std::fs::read(&fx.path).unwrap(), bytes);
    assert_eq!((fx.backend.counter, fx.backend.calls), (counter, calls));
    let mut v = fx.open(None);
    assert_eq!(format!("{:?}", v.progress().unwrap()), progress);
    // And the reserved decision completes exactly as it would have: once, one counter step.
    let recovered = v.replay(Step::Prevote, &mut fx.backend).unwrap().unwrap();
    assert_eq!(recovered.decision.block, block);
    assert_eq!(fx.backend.counter, counter + 1);
}
