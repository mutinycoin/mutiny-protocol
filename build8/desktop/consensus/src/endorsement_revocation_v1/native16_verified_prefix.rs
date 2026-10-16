//! Registered private TEST-only historical-prefix verifier foundation.
//! No caller State/root/approval constructor or shipping authority.
//! Four V7 foundation controls qualified separately; native121 successor is unrun.
use super::*;
use crate::{block_envelope_v2::BlockEnvelope, evidence_history_v2::History,
    votes::IngressError, votes_v2::HeightAuthority};
use std::collections::VecDeque;

// Local modeled-test resource ceilings, not protocol or timeout amendments.
// Two native sixty-height periods plus the genuinely authorized activation H121.
// This is a private TEST resource bound, never a protocol/deadline amendment.
const MAX_PREFIX_ROWS: usize = 121;
const MAX_PREFIX_RAW_BYTES: usize = 32 * 1024 * 1024;

struct VerifiedRow {
    exact_envelope: Vec<u8>,
    execution: ExecutionPin,
    finalized: FinalizedAnchor,
    resulting_root: Hash,
}

struct VerifiedPrefix {
    rows: Vec<VerifiedRow>,
    state: State,
    root: Hash,
    parent: WorkParent,
    history: History,
    admitted_joins: usize,
    // Private accumulated verifier state; never caller-supplied snapshots.
    timestamps: Vec<u64>,
    aggregate_raw_bytes: usize,
    origin_anchor: Hash,
    origin_root: Hash,
    profile_max_rows: usize,
    profile_max_joins: usize,
}

// Parent may name this private capability but cannot populate its fields. Only
// a complete VerifiedPrefix creates it; neither parsing nor a final State does.
pub(super) struct ReplayPins { pins: Vec<ExecutionPin> }
impl ReplayPins {
    pub(super) fn pin(&self,index:usize)->Option<&ExecutionPin> { self.pins.get(index) }
    pub(super) fn select(&self,state:&State,parent:&WorkParent,header:&WorkHeader,
        authority:&Authority,body:&BlockBody)->Result<usize> {
        let root=state.root().map_err(|_|Error::WrongAnchor)?;
        let header=header.encode();let authority=authority.encode()?;
        let mut selected=None;
        for (index,pin) in self.pins.iter().enumerate() {
            if !pin.prepared.parent.matches(parent) || pin.prepared.root!=root
                || pin.header!=header || pin.authority!=authority {continue;}
            let anchor=FinalizedAnchor {network:crate::NETWORK_ID,genesis:parent.genesis,
                fingerprint:parent.fingerprint,height:parent.height,block:parent.block};
            let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
                state,anchor,root)?;
            if capacity.encode(body)?!=pin.prepared.body {continue;}
            if selected.replace(index).is_some() {return Err(Error::Duplicate);}
        }
        selected.ok_or(Error::WrongAnchor)
    }
}

impl VerifiedPrefix {
    /// A new P pin can originate only in the independently verified prefix.
    /// Ordinary assembler work supplies actual fees/reward/work context first;
    /// this narrowly supported successor appends only genuine Join15 wrappers.
    fn prepare_next_join(&self,host:&ModelHost,license:Hash,worker:Hash,
        timestamp:u64,ticket:u64,operation:Vec<u8>)
        -> crate::execution::Result<(Candidate,BlockBody,ModelPrepared)> {
        let anchor=FinalizedAnchor {height:self.parent.height,block:self.parent.block,
            ..host.fixture.parent.clone()};
        let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
            &self.state,anchor,self.root)?;
        capacity.preflight_lists(&[],std::slice::from_ref(&operation))?;
        let positive=crate::assembler_v2::prepare_with_history(crate::assembler_v2::Request {
            parent:&self.parent,state:&self.state,pool:&tests::Empty,license,worker,
            timestamp,ticket,operations:&[] },&self.history)
            .map_err(|_|crate::execution::ExecutionError::Codec(Error::WrongOperation))?;
        let mut body=positive.body;body.operations=vec![operation];
        let mut candidate=positive.candidate;candidate.state_root=[0;32];
        candidate.body_root=capacity.root(&body)?;
        let joins=host.verify_pins(&self.state,&self.parent,&body)?;
        if joins.len()!=1 || self.admitted_joins.checked_add(joins.len())
            .is_none_or(|n|n>host.max_joins()) {return Err(Error::Capacity.into());}
        let pin=Rc::new(PreparationPin {parent:ParentPin::capture(&self.parent),root:self.root,
            candidate:candidate.clone(),ticket,body:capacity.encode(&body)?,joins});
        let execution={
            let _p=Lease::install(Mode::Prepare(pin.clone()))?;
            self.state.prepare_candidate_with_history_v2(CandidatePreparation {
                parent:&self.parent,candidate:&candidate,ticket_sequence:ticket,body:&body},&self.history)?
        };
        let prepared=ModelPrepared {pin,computed_root:execution.root,records:execution.state.records()?};
        Ok((candidate,body,prepared))
    }

    fn replay(&self)->Result<Lease> {
        let pins=self.rows.iter().map(|row|ExecutionPin {
            prepared:row.execution.prepared.clone(),computed_root:row.execution.computed_root,
            header:row.execution.header.clone(),authority:row.execution.authority.clone()
        }).collect();
        Lease::install(Mode::Replay(ReplayPins {pins}))
    }

    /// Reopening independently verifies the complete supplied prefix again,
    /// then requires actual native DB replay plus exact retained bytes and tip.
    /// The scope allows only signed X entries: unrelated unsigned work refuses.
    fn with_reverified_store<T>(host:&ModelHost,path:&std::path::Path,
        raw_rows:&[Vec<u8>],inspect:impl FnOnce(&CanonicalStore)->T)
        -> std::result::Result<T,crate::finality_v2::StoreError> {
        use crate::finality_v2::StoreError;
        crate::submission_archive_protection::check(path,false)
            .map_err(StoreError::SubmissionPool)?;
        let verified=Self::verify(host,raw_rows).map_err(StoreError::Verification)?;
        let _lease=verified.replay()?;
        let store=CanonicalStore::open_trusted_genesis(path,&host.fixture.parent,
            &host.fixture.state,host.fixture.root,super::super::test_value_x509::T_REF,[255;32])?;
        let (tip,state)=store.load()?;
        if tip.height!=verified.parent.height || tip.block!=verified.parent.block
            || tip.root!=verified.root || tip.target!=verified.parent.target
            || Some(tip.timestamp)!=verified.parent.ancestor_timestamps.last().copied()
            || state.records()?!=verified.state.records()? {
            return Err(StoreError::Integrity);
        }
        for row in &verified.rows {
            if store.certified_envelope_bytes(row.finalized.height,row.finalized.block)?
                .as_ref()!=Some(&row.exact_envelope) {return Err(StoreError::Integrity);}
        }
        Ok(inspect(&store))
    }

    /// Bytes are untrusted. Only the private fixed independently verified
    /// Genesis fixture supplies initial authority and class/rule/root/PCR data.
    /// A malformed later row returns no usable prefix or historical grant.
    fn verify(host: &ModelHost, raw_rows: &[Vec<u8>])
        -> std::result::Result<Self, IngressError> {
        Self::verify_suffix(host, None, raw_rows)
    }

    /// Consume an already checked private prefix and verify precisely one new
    /// untrusted row. Reopen still calls verify from private Genesis for every row.
    fn append(self, host: &ModelHost, raw: Vec<u8>)
        -> std::result::Result<Self, IngressError> {
        Self::verify_suffix(host, Some(self), &[raw])
    }

    // Both full replay and checked append traverse the identical native row loop.
    // No supplied State/root constructor or externally installed replay grant.
    fn verify_suffix(host: &ModelHost, prior: Option<Self>, raw_rows: &[Vec<u8>])
        -> std::result::Result<Self, IngressError> {
        let prior_rows=prior.as_ref().map_or(0,|p|p.rows.len());
        if prior_rows.checked_add(raw_rows.len()).is_none_or(|n|n>host.max_rows()) {
            return Err(Error::Capacity.into());
        }
        let mut aggregate=prior.as_ref().map_or(0,|p|p.aggregate_raw_bytes);
        for raw in raw_rows {
            if raw.len() > crate::body_capacity_v3::MAX_ENVELOPE_BYTES {
                return Err(Error::Oversize.into());
            }
            aggregate = aggregate.checked_add(raw.len()).ok_or(Error::Oversize)?;
            if aggregate > MAX_PREFIX_RAW_BYTES {
                return Err(Error::Oversize.into());
            }
        }
        let fixed = &host.fixture.parent;
        let t0 = super::super::test_value_x509::T_REF;
        let (mut state,mut root,mut anchor,mut target,mut times,mut timestamps,
            mut history,mut rows,mut admitted_joins)=match prior {
            None=>{
                let state=host.fixture.state.clone();
                if state.root()?!=host.fixture.root {return Err(Error::WrongAnchor.into());}
                let mut history=History::default();history.insert_anchor(0,fixed.block)?;
                (state,host.fixture.root,fixed.clone(),[255;32],VecDeque::from([t0]),
                    vec![t0],history,Vec::new(),0usize)
            }
            Some(p)=>{
                if p.origin_anchor!=fixed.id() || p.origin_root!=host.fixture.root
                    || p.profile_max_rows!=host.max_rows() || p.profile_max_joins!=host.max_joins()
                    || p.parent.genesis!=fixed.genesis || p.parent.fingerprint!=fixed.fingerprint
                    || p.parent.t0!=t0 || p.parent.height as usize!=p.rows.len()
                    || p.timestamps.len()!=p.rows.len()+1 || p.state.root()?!=p.root
                    || p.rows.last().is_some_and(|r|r.finalized.block!=p.parent.block
                        || r.finalized.height!=p.parent.height || r.resulting_root!=p.root)
                    || p.aggregate_raw_bytes>MAX_PREFIX_RAW_BYTES {
                    return Err(Error::WrongAnchor.into());
                }
                let anchor=FinalizedAnchor {height:p.parent.height,block:p.parent.block,..fixed.clone()};
                (p.state,p.root,anchor,p.parent.target,p.parent.ancestor_timestamps.into_iter().collect(),
                    p.timestamps,p.history,p.rows,p.admitted_joins)
            }
        };
        for raw in raw_rows {
            let height = anchor.height.checked_add(1).ok_or(Error::InvalidCounter)?;
            let parent = WorkParent { genesis: fixed.genesis,
                fingerprint: fixed.fingerprint, block: anchor.block,
                height: anchor.height, t0, target,
                ancestor_timestamps: times.iter().copied().collect() };
            if !crate::pow::window_ends_at_parent(&parent.ancestor_timestamps,
                *timestamps.last().ok_or(Error::WrongAnchor)?) {
                return Err(Error::WrongAnchor.into());
            }
            // This capability is derived only from the prior independently
            // authenticated transition, never matching caller State/root pairs.
            let capacity = crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
                &state, anchor.clone(), root)?;
            let block = BlockEnvelope::decode_with_capacity(raw, &capacity)?;
            let c = &block.header.candidate;
            if c.height != height || c.parent != anchor.block
                || c.genesis != fixed.genesis || c.fingerprint != fixed.fingerprint
                || c.target != target || c.body_root != capacity.root(&block.body)? {
                return Err(Error::WrongAnchor.into());
            }
            // HeightAuthority authenticates exact native keys/eligibility and
            // weights from this independently reconstructed old-parent state.
            let authority = HeightAuthority::from_state(&state, anchor.clone(), root)?;
            history.insert(height, authority.clone());
            for referenced in crate::op_envelope_v1::referenced_heights(&block.body) {
                if referenced >= height || history.anchor(referenced).is_none() {
                    return Err(Error::WrongAnchor.into());
                }
            }
            let mut candidate = c.clone();
            candidate.state_root = [0; 32];
            let ticket = block.authority.work.ticket_sequence;
            state.work_context_v2(&parent, &candidate)?;
            // Only exact Join15 items receive independent witness pins. Every
            // other operation still traverses unchanged full native execution;
            // no rotation/recovery/caller-history exception is created here.
            let mut join_items = Vec::new();
            for operation in &block.body.operations {
                if !crate::trading_host_v1::operation(operation)?
                    && crate::blocks::operation_kind(operation)? == 15 {
                    join_items.push(operation.clone());
                }
            }
            let joins = if join_items.is_empty() { Vec::new() } else {
                let join_projection = BlockBody { height: block.body.height,
                    reward_owner: block.body.reward_owner, fees: block.body.fees,
                    transactions: Vec::new(), operations: join_items };
                host.verify_pins(&state, &parent, &join_projection)?
            };
            admitted_joins = admitted_joins.checked_add(joins.len()).ok_or(Error::Capacity)?;
            if admitted_joins > host.max_joins() {
                return Err(Error::Capacity.into());
            }
            let preparation = Rc::new(PreparationPin { parent: ParentPin::capture(&parent),
                root, candidate: candidate.clone(), ticket,
                body: capacity.encode(&block.body)?, joins });
            // P binds unsigned preparation only. Its lifetime ends before X;
            // no shared ambient eligibility grant spans these two stages.
            let prepared = {
                let _p = Lease::install(Mode::Prepare(preparation.clone()))?;
                state.prepare_candidate_with_history_v2(CandidatePreparation {
                    parent: &parent, candidate: &candidate,
                    ticket_sequence: ticket, body: &block.body }, &history)?
            };
            if prepared.root != c.state_root {
                return Err(Error::WrongAnchor.into());
            }
            let prepared_records = prepared.state.records()?;
            let (context, _, node) = state.work_context_v2(&parent, c)?;
            block.authority.verify(&block.header, &context, &node)?;
            if !crate::pow::meets_target(&block.header.digest(), &c.target) {
                return Err(Error::InvalidCounter.into());
            }
            let pin = ExecutionPin { prepared: preparation,
                computed_root: prepared.root, header: block.header.encode(),
                authority: block.authority.encode()? };
            let result = {
                let _x = Lease::install(Mode::Execute(ExecutionPin {
                    prepared: pin.prepared.clone(), computed_root: pin.computed_root,
                    header: pin.header.clone(), authority: pin.authority.clone() }))?;
                // Actual native execution AND every Decision/certificate/old
                // parent quorum field, not a caller signature-valid assertion.
                block.verify_execute_with_history(&state, &parent, &authority, &history)?
            };
            if result.root != prepared.root || result.state.records()? != prepared_records {
                return Err(Error::WrongAnchor.into());
            }
            let finalized = block.certificate.decision.anchor();
            if finalized.height != height || finalized.block != block.block_hash() {
                return Err(Error::WrongAnchor.into());
            }
            let timestamp = c.timestamp;
            let start = if height.is_multiple_of(60) {
                *timestamps.get((height - 60) as usize).ok_or(Error::WrongAnchor)?
            } else { timestamp };
            target = crate::pow::target_after_height(height, target, start, timestamp)?;
            root = result.root;
            state = result.state;
            anchor = finalized.clone();
            history.insert_anchor(height, anchor.block)?;
            timestamps.push(timestamp);
            times.push_back(timestamp);
            if times.len() > 11 { times.pop_front(); }
            // No row is retained as verified until actual execution and exact
            // certificate both succeed. No externally installed replay scope.
            rows.push(VerifiedRow { exact_envelope: raw.clone(), execution: pin,
                finalized, resulting_root: root });
        }
        let parent = WorkParent { genesis: fixed.genesis, fingerprint: fixed.fingerprint,
            block: anchor.block, height: anchor.height, t0, target,
            ancestor_timestamps: times.into_iter().collect() };
        Ok(Self { rows, state, root, parent, history, admitted_joins, timestamps,
            aggregate_raw_bytes:aggregate,origin_anchor:fixed.id(),origin_root:host.fixture.root,
            profile_max_rows:host.max_rows(),profile_max_joins:host.max_joins() })
    }
}

#[path="native16_capacity_tests.rs"]
mod capacity_tests;

#[path="native16_canonical_chain_tests.rs"]
mod canonical_chain_tests;
#[path="native_current_scope_tests.rs"]
mod current_scope_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical_store_v2::Preparation, pow::WorkAuthority};

    pub(super) struct Empty;
    impl crate::op_envelope_v1::PendingReferences for Empty {}
    impl crate::assembler_v2::PendingSource for Empty {
        fn pending_items_at(&self, _: &FinalizedAnchor, _: &State)
            -> std::result::Result<Vec<crate::submission_v1::Submission>, String> { Ok(vec![]) }
    }

    fn genuine_signed_certified_join(host: &mut ModelHost) -> (Vec<u8>, Hash, Hash) {
        let (join, outer) = super::super::foundation_tests::genuine_join(host, 1);
        let mut unique = [0; 16]; mutiny_crypto_v2::fill_os_random(&mut unique).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "build8-public-private-prefix-{}", hex::encode(unique)));
        assert!(crate::submission_pool_v1::private_directory(&directory).unwrap());
        let t0 = super::super::super::test_value_x509::T_REF;
        let chain = CanonicalStore::open_trusted_genesis(&directory.join("canonical.sqlite"),
            &host.fixture.parent, &host.fixture.state, host.fixture.root, t0, [255;32]).unwrap();
        let binding = host.fixture.state.licenses_v2.assignments().next().unwrap().enrollment.binding.clone();
        let positive = chain.prepare_pending(Preparation { expected_parent: &host.fixture.parent,
            pool: &Empty, license: binding.license, worker: binding.worker_id,
            timestamp: t0+1, ticket: 1, operations: &[] }).unwrap();
        let mut body = positive.body; body.operations = vec![outer];
        let cap = chain.body_capacity(&host.fixture.parent).unwrap();
        let mut candidate = positive.candidate;
        candidate.state_root = [0;32]; candidate.body_root = cap.root(&body).unwrap();
        let prepared = host.prepare_exact(&chain, &candidate, 1, &body).unwrap();
        candidate.state_root = prepared.computed_root;
        let epoch = crate::pow::mining_epoch(candidate.timestamp, t0).unwrap();
        let (license, _) = host.fixture.state.licenses_v2.active(
            binding.license, binding.worker_id, epoch).unwrap();
        let mut work = Authority { work: WorkAuthority { candidate: candidate.clone(),
            assignment_sequence: license.assignment_sequence, ticket_sequence: 1,
            coordinator: crate::work_authority_v2::node_identity(
                &host.fixture.node_key.public().descriptor(1).unwrap()).unwrap(),
            nonce_start: 0, nonce_end: 100, epoch },
            node_descriptor: host.fixture.node_key.public().descriptor(1).unwrap(),
            signature: super::super::super::zero() };
        work.sign(&host.fixture.node_key).unwrap();
        let header = WorkHeader { candidate, authority: work.id().unwrap(), nonce: 1 };
        let executed = host.execute_exact(&prepared, &chain, &header, &work, &body).unwrap();
        let old = HeightAuthority::from_state(&host.fixture.state,
            host.fixture.parent.clone(), host.fixture.root).unwrap();
        let voter = &old.voters[&host.fixture.node];
        assert!(!voter.weight().unwrap().is_zero());
        let decision = crate::certificates::Decision { network: old.parent.network,
            genesis: old.parent.genesis, fingerprint: old.parent.fingerprint,
            purpose: 2, height: 1, mining_epoch: epoch, continuity_period: 0,
            round: 0, step: 3, previous_finalized_anchor: old.parent.id(),
            parent: old.parent.block, block: header.block_hash(), state: executed.root,
            membership: old.membership, reputation: old.reputation, attestation: old.attestation };
        let mut vote = crate::continuity_v2::Vote { decision: decision.clone(), nil: false,
            node: host.fixture.node, hardware_generation: voter.hardware_generation,
            key_generation: voter.key_generation, sequence: 1, tpm_identity: voter.tpm_identity(),
            profile: voter.profile, signature: super::super::super::zero() };
        vote.sign(&host.fixture.continuity).unwrap();
        let certificate = crate::continuity_v2::Certificate { decision: decision.clone(), votes: vec![vote] };
        certificate.verify_quorum(&decision, &old.parent, &old.voters).unwrap();
        let block = BlockEnvelope { header, body, authority: work, certificate };
        let raw = block.encode_with_capacity(&cap).unwrap();
        assert_eq!(chain.load().unwrap().0.height, 0);
        // This is actual signed native execution and a real parent quorum, but
        // has not been canonically installed. No reopen/native16 claim follows.
        (raw, executed.root, join.binding.admission.node)
    }

    #[test]
    fn verified_prefix_requires_actual_genuine_join_execution_and_parent_quorum() {
        let mut host = ModelHost::new();
        let (raw, root, node) = genuine_signed_certified_join(&mut host);
        let verified = VerifiedPrefix::verify(&host, &[raw.clone()]).unwrap();
        assert_eq!(verified.rows.len(), 1);
        assert_eq!(verified.rows[0].exact_envelope, raw);
        assert_eq!(verified.rows[0].resulting_root, root);
        assert_eq!(verified.root, root);
        assert_eq!(verified.parent.height, 1);
        assert_eq!(verified.admitted_joins, 1);
        assert!(verified.state.membership_v2.get(node).is_some());
        assert_eq!(verified.state.continuity.as_ref().unwrap().members.len(), 2);
        assert_eq!(verified.history.anchor(1), Some(verified.parent.block));
        // Current foundation still refuses non-Genesis Store grants; merely
        // verifying this prefix does not install a replay permission or scope.
        assert!(ACTIVE.with(|slot| slot.borrow().is_none()));

        // Install through the ACTUAL CanonicalStore with only the independently
        // checked historical X pin, then reopen by re-verifying the full prefix.
        let mut unique=[0;16];mutiny_crypto_v2::fill_os_random(&mut unique).unwrap();
        let directory=std::env::temp_dir().join(format!(
            "build8-public-private-prefix-store-{}",hex::encode(unique)));
        assert!(crate::submission_pool_v1::private_directory(&directory).unwrap());
        let path=directory.join("canonical.sqlite");
        let t0=super::super::super::test_value_x509::T_REF;
        let mut chain=CanonicalStore::open_trusted_genesis(&path,&host.fixture.parent,
            &host.fixture.state,host.fixture.root,t0,[255;32]).unwrap();
        let capacity=chain.body_capacity(&host.fixture.parent).unwrap();
        let block=BlockEnvelope::decode_with_capacity(&raw,&capacity).unwrap();
        {
            let _scope=verified.replay().unwrap();
            assert!(chain.commit(&block).unwrap());
            assert_eq!(chain.certified_envelope_bytes(1,block.block_hash()).unwrap(),Some(raw.clone()));
            assert_eq!(chain.load().unwrap().1.records().unwrap(),verified.state.records().unwrap());
            // Replay cannot act as an unsigned preparation grant, even when
            // every candidate/body field came from a formerly valid P stage.
            let mut unsigned=block.header.candidate.clone();unsigned.state_root=[0;32];
            assert!(matches!(host.fixture.state.prepare_candidate_with_history_v2(
                CandidatePreparation {parent:&verified.rows[0].execution.prepared.parent.as_work_parent(),
                    candidate:&unsigned,ticket_sequence:1,body:&block.body},&verified.history),
                Err(crate::execution::ExecutionError::Codec(Error::WrongOperation))));
        }
        assert!(ACTIVE.with(|slot|slot.borrow().is_none()));
        drop(chain);
        VerifiedPrefix::with_reverified_store(&host,&path,&[raw.clone()],|reopened| {
            let (tip,state)=reopened.load().unwrap();
            assert_eq!(tip.height,1);assert_eq!(tip.root,root);
            assert_eq!(state.records().unwrap(),verified.state.records().unwrap());
            assert_eq!(reopened.certified_envelope_bytes(1,tip.block).unwrap(),Some(raw.clone()));
        }).unwrap();
        assert!(ACTIVE.with(|slot|slot.borrow().is_none()));
        assert!(VerifiedPrefix::with_reverified_store(&host,&path,&[],|_|()).is_err());
        assert!(ACTIVE.with(|slot|slot.borrow().is_none()));
        // Two registry records are not two eligible/nonzero voting slots, a
        // physical fleet, normal shipping admission or actual TPM activation.
    }

    #[test]
    fn verified_prefix_rejects_forged_certificate_and_duplicate_later_row_without_grants() {
        let mut host = ModelHost::new();
        let (raw, _, _) = genuine_signed_certified_join(&mut host);
        assert!(VerifiedPrefix::verify(&host, &[raw.clone()]).is_ok());
        let capacity = crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
            &host.fixture.state, host.fixture.parent.clone(), host.fixture.root).unwrap();
        let mut forged = BlockEnvelope::decode_with_capacity(&raw, &capacity).unwrap();
        forged.certificate.votes[0].signature = super::super::super::zero();
        let altered = forged.encode_with_capacity(&capacity).unwrap();
        assert!(VerifiedPrefix::verify(&host, &[altered]).is_err());
        assert!(ACTIVE.with(|slot| slot.borrow().is_none()));
        assert!(VerifiedPrefix::verify(&host, &[raw.clone(), raw.clone()]).is_err());
        assert!(ACTIVE.with(|slot| slot.borrow().is_none()));
        assert!(VerifiedPrefix::verify(&host, &[Vec::new(), raw]).is_err());
        assert!(ACTIVE.with(|slot| slot.borrow().is_none()));
    }
}

// Resource-intensive TEST maximum control is independently selected and reviewed.
#[path = "native1024_capacity_tests.rs"]
mod maximum_capacity_tests;
