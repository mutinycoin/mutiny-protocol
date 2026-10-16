//! Explicit hybrid licensed execution candidate. This stage supports hybrid
//! payments/rotation, Worker assignment, participation/refresh/exit and hybrid
//! bond/evidence settlement. Unmigrated operations still fail closed; this
//! module is not a production finality installer.
use crate::{
    Error, Hash, NETWORK_ID,
    blocks::BlockBody,
    execution::{CandidatePreparation, Execution, ExecutionError, Result, State, WorkParent},
    license_assignment_v2::Assignment,
    pow::{Candidate, WorkContext, WorkHeader, mining_epoch, validate_timestamp},
    work_authority_v2::Authority,
};

/// The caller supplies authenticated canonical ancestry. Store construction is
/// descending and replay construction ascending: under the nondecreasing chain
/// rule the finalized parent's timestamp is the maximum, never a list position.
/// This adds coverage checks for A2 admission, not an operation time authority.
pub(crate) fn admission_parent_time(parent: &WorkParent) -> crate::Result<u64> {
    let covered = parent.height.checked_add(1).ok_or(Error::InvalidCounter)?;
    let window = &parent.ancestor_timestamps;
    if parent.t0 == 0
        || window.len() != covered.min(11) as usize
        || window.iter().any(|t| *t < parent.t0)
        || (covered <= 11 && window.iter().copied().min() != Some(parent.t0))
    {
        return Err(Error::InvalidCounter);
    }
    window.iter().copied().max().ok_or(Error::InvalidCounter)
}

#[cfg(test)]
mod a2_parent_time_tests {
    use super::*;
    fn parent(height: u64, timestamps: Vec<u64>) -> WorkParent {
        WorkParent { genesis: [1;32], fingerprint: [2;32], block: [3;32],
            height, t0: 100, target: [4;32], ancestor_timestamps: timestamps }
    }
    #[test]
    fn finalized_parent_time_is_order_independent_and_handles_genesis() {
        assert_eq!(admission_parent_time(&parent(0, vec![100])), Ok(100));
        assert_eq!(admission_parent_time(&parent(2, vec![100, 102, 109])), Ok(109));
        assert_eq!(admission_parent_time(&parent(2, vec![109, 102, 100])), Ok(109));
        assert_eq!(admission_parent_time(&parent(11, (101..112).collect())), Ok(111));
    }
    #[test]
    fn incomplete_or_inconsistent_parent_window_cannot_supply_admission_time() {
        for bad in [parent(0, vec![]), parent(0, vec![101]),
            parent(2, vec![100,109]), parent(2, vec![101,102,109]),
            parent(2, vec![99,100,109]), parent(u64::MAX, vec![100])] {
            assert_eq!(admission_parent_time(&bad), Err(Error::InvalidCounter));
        }
    }
}

impl State {
    fn require_hybrid_execution_state(&self) -> Result<()> {
        // Never silently preserve an old authority model while certifying a
        // hybrid transition. These components need their explicit migration.
        if !self.licenses.records()?.is_empty()
            || self.licenses_v2.is_empty()
            || !self.admission.is_empty()?
            || !self.membership.records()?.is_empty()
            || !self.bonds.records()?.is_empty()
            || !self.penalties.records()?.is_empty()
        {
            return Err(ExecutionError::UnsupportedOperation);
        }
        if self.continuity.is_none()
            && (!self.continuity_keys_v2.is_empty()
                || !self.membership_v2.is_empty()
                || self.accounting != Default::default()
                || !self.bonds_v2.is_empty()
                || !self.penalties_v2.is_empty())
        {
            return Err(ExecutionError::UnsupportedOperation);
        }
        Ok(())
    }

    /// Exact coordinator descriptor is obtained from the canonical assignment,
    /// never supplied as authority by a peer. Due epoch activation is tentative.
    pub fn work_context_v2(
        &self,
        parent: &WorkParent,
        c: &Candidate,
    ) -> Result<(WorkContext, Hash, Vec<u8>)> {
        self.work_context_v2_inner(parent, c, None)
    }
    fn work_context_v2_inner(
        &self,
        parent: &WorkParent,
        c: &Candidate,
        replayed: Option<&crate::canonical_store_v2::ReplayParent<'_>>,
    ) -> Result<(WorkContext, Hash, Vec<u8>)> {
        self.require_hybrid_execution_state()?;
        // A finalized terminal A2 transition permanently refuses prospective work.
        // Historical replay/export still uses its authenticated nonterminal parent.
        if self.endorsement_revocations_v1.terminal_no_quorum() {
            return Err(Error::NoQuorum.into());
        }
        if self.continuity.is_some() {
            if let Some(proof) = replayed {
                proof.check(self, parent).map_err(|_| ExecutionError::UnsupportedOperation)?;
                proof.authority().map_err(|_| ExecutionError::UnsupportedOperation)?;
            } else {
            crate::votes_v2::HeightAuthority::from_state(
                self,
                crate::anchors::FinalizedAnchor {
                    network: NETWORK_ID,
                    genesis: parent.genesis,
                    fingerprint: parent.fingerprint,
                    height: parent.height,
                    block: parent.block,
                },
                self.root()?,
            )
            .map_err(|_| ExecutionError::UnsupportedOperation)?;
            }
        }
        if c.network != NETWORK_ID
            || c.genesis != parent.genesis
            || c.fingerprint != parent.fingerprint
            || c.parent != parent.block
            || parent.height.checked_add(1) != Some(c.height)
            || c.target != parent.target
            || c.target == [0; 32]
        {
            return Err(Error::WrongAnchor.into());
        }
        validate_timestamp(
            c.height,
            c.timestamp,
            parent.t0,
            &parent.ancestor_timestamps,
        )?;
        let epoch = mining_epoch(c.timestamp, parent.t0)?;
        let mut book = self.licenses_v2.clone();
        book.activate_due(epoch)?;
        let (license, worker) = book.active(c.license, c.worker, epoch)?;
        if self
            .node_key_history_v2
            .is_retired_descriptor(&worker.assignment.node_descriptor)
        {
            return Err(Error::WrongGeneration.into());
        }
        let b = &worker.assignment.enrollment.binding;
        if license.genesis != parent.genesis
            || b.genesis != parent.genesis
            || b.fingerprint != parent.fingerprint
        {
            return Err(Error::WrongAnchor.into());
        }
        Ok((
            WorkContext {
                genesis: parent.genesis,
                fingerprint: parent.fingerprint,
                parent: parent.block,
                parent_height: parent.height,
                t0: parent.t0,
                target: parent.target,
                license: license.id,
                worker: c.worker,
                coordinator: b.coordinator,
                assignment_sequence: license.assignment_sequence,
                last_accepted_ticket: worker.last_accepted_ticket,
                ancestor_timestamps: parent.ancestor_timestamps.clone(),
            },
            license.owner,
            worker.assignment.node_descriptor.clone(),
        ))
    }

    /// Pure proposal preparation. The numeric ticket and complete execution
    /// enter post-state before the work authority signs its StateRoot. No
    /// current AuthorityID/signature is stored, avoiding a root/signature cycle.
    pub fn prepare_candidate_v2(&self, input: CandidatePreparation<'_>) -> Result<Execution> {
        self.prepare_candidate_with_history_v2(input, &Default::default())
    }
    /// The history map must come from locally authenticated canonical E-1
    /// states, never from a peer's asserted evidence authority.
    pub fn prepare_candidate_with_history_v2(
        &self,
        input: CandidatePreparation<'_>,
        history: &crate::evidence_history_v2::History,
    ) -> Result<Execution> {
        self.prepare_candidate_with_recovery_v2(input, history, None)
    }
    pub(crate) fn prepare_candidate_with_recovery_v2(
        &self,
        input: CandidatePreparation<'_>,
        history: &crate::evidence_history_v2::History,
        recovery: Option<&crate::recovery_transition_v2::Prepared>,
    ) -> Result<Execution> {
        self.prepare_candidate_with_replay_v2(input, history, recovery, None)
    }
    pub(crate) fn prepare_candidate_with_replay_v2(
        &self,
        input: CandidatePreparation<'_>,
        history: &crate::evidence_history_v2::History,
        recovery: Option<&crate::recovery_transition_v2::Prepared>,
        replayed: Option<&crate::canonical_store_v2::ReplayParent<'_>>,
    ) -> Result<Execution> {
        // P and nested X re-execution bind the complete body and authenticated
        // parent before Join sees an inner carrier. No host => ordinary behavior.
        #[cfg(test)]
        let _modelled_prepare_entry = crate::endorsement_revocation_v1::native16_test_host::enter_prepare(
            self, &input, recovery.is_some(),
        )?;
        if recovery.is_some() && replayed.is_some() { return Err(Error::WrongAnchor.into()); }
        let CandidatePreparation {
            parent,
            candidate: c,
            ticket_sequence,
            body,
        } = input;
        if let Some(recovery) = recovery {
            let anchor = recovery.parent();
            if (
                anchor.genesis,
                anchor.fingerprint,
                anchor.height,
                anchor.block,
            ) != (
                parent.genesis,
                parent.fingerprint,
                parent.height,
                parent.block,
            ) || self.root()? != recovery.canonical_parent_root()
            {
                return Err(Error::WrongAnchor.into());
            }
        }
        let (_, owner, _) = self.work_context_v2_inner(parent, c, replayed)?;
        let owned_capacity;
        let capacity = if let Some(proof) = replayed {
            proof.check(self, parent)?;
            proof.capacity()
        } else {
            owned_capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(self,
            crate::anchors::FinalizedAnchor { network:NETWORK_ID, genesis:parent.genesis,
                fingerprint:parent.fingerprint,height:parent.height,block:parent.block }, self.root()?)?;
            &owned_capacity
        };
        if body.height != c.height || capacity.root(body)? != c.body_root {
            return Err(Error::WrongAnchor.into());
        }
        let epoch = mining_epoch(c.timestamp, parent.t0)?;
        let mut next = self.clone();
        next.licenses_v2.activate_due(epoch)?;
        // Crossed expiries and award boundaries are processed chronologically from the parent's
        // canonical state, before this block's transactions, subsidy or fees can exist.
        next.advance_dividends(epoch)?;
        let mut lifecycle = body.clone();
        lifecycle.transactions.clear();
        lifecycle.fees = 0;
        lifecycle.operations.clear();
        let mut creates = Vec::new();
        // Declared fees of the funded BondCreates (design 1.c): decoded, never trusted. They join
        // the block's fee total before the payment phase builds the coinbase; the bond-create
        // phase verifies every one of them (V9), so a lie fails the whole block.
        let mut create_fees = 0u64;
        let mut trades = Vec::new();
        let mut claims = Vec::new();
        for raw in &body.operations {
            if crate::trading_host_v1::operation(raw)? {
                trades.push(raw.clone());
                continue;
            }
            match crate::blocks::operation_kind(raw)? {
                // Unit-test builds of this crate ONLY: the TEST-ONLY envelope carrier is checked
                // here (op_envelope_v1::carrier); it is never a production item kind.
                #[cfg(test)]
                crate::op_envelope_v1::carrier::KIND => {
                    crate::op_envelope_v1::carrier::check(raw, parent, history, &next)?;
                    continue;
                }
                10 => {}
                11 | 12 | 13 | 14 | 15 | 16 | 17 | 19 | 20 | 21 | 22 | 25 if self.continuity.is_some() => {
                    lifecycle.operations.push(raw.clone());
                    continue;
                }
                crate::bond_create_v3::OPERATION_KIND if self.continuity.is_some() => {
                    let create = crate::bond_create_v3::FundedBondCreate::decode(raw)?;
                    create_fees = create_fees
                        .checked_add(create.unsigned.fee)
                        .ok_or(ExecutionError::Overflow)?;
                    creates.push(create);
                    continue;
                }
                crate::dividend_claim_v1::OPERATION_KIND => {
                    claims.push(raw.clone());
                    continue;
                }
                _ => return Err(ExecutionError::UnsupportedOperation),
            }
            // Owner authority is the committed parent WalletBook, not a wallet
            // rotation created by transactions in this same candidate.
            next.licenses_v2.schedule(
                Assignment::decode(raw).map_err(|_| ExecutionError::UnsupportedOperation)?,
                parent.genesis,
                parent.fingerprint,
                c.height,
                epoch,
                &self.wallets,
            )?;
        }
        next.licenses_v2
            .prepare_ticket(c.license, c.worker, epoch, ticket_sequence)?;
        let trading_parent = crate::anchors::FinalizedAnchor {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            height: parent.height,
            block: parent.block,
        };
        let (next, trade_fees) = crate::trading_host_v1::execute(self, next, &trading_parent, history, &trades)?;
        // Claims execute after trades, so a same-block License transfer makes the previous
        // owner's claim stale and lets the new owner claim; both are then followed by payments.
        let next = crate::dividend_claim_v1::execute(
            next,
            &claims,
            parent.genesis,
            parent.fingerprint,
            c.height,
            epoch,
        )?;
        let extra_fees = trade_fees
            .checked_add(create_fees)
            .ok_or(ExecutionError::Overflow)?;
        let mut executed = next.execute_hybrid_payment_phase(
            parent.genesis,
            parent.fingerprint,
            parent.block,
            owner,
            body,
            extra_fees,
            history,
            &capacity,
        )?;
        if self.continuity.is_some() {
            let anchor = crate::anchors::FinalizedAnchor {
                network: NETWORK_ID,
                genesis: parent.genesis,
                fingerprint: parent.fingerprint,
                height: parent.height,
                block: parent.block,
            };
            let parameters = self.protocol_records.get(&crate::genesis_v2::parameters_key())
                .map(|raw| crate::genesis_v2::Parameters::decode(raw).map_err(|_| crate::Error::Codec)).transpose()?;
            let selected = parameters.as_ref().map(crate::endorsement_revocation_v1::enabled)
                .transpose()?.unwrap_or(false);
            let admission_reference_time = if selected {
                Some(admission_parent_time(parent)?)
            } else { None };
            let result = match recovery {
                Some(recovery) => recovery.transition_components_at(&lifecycle, history,
                    admission_reference_time, c.timestamp)?,
                None => crate::continuity_lifecycle_v2::transition_in_parent_at(
                    match replayed {
                        Some(proof) => crate::parent_context_v2::ParentContext::replayed(self, &anchor, proof)?,
                        None => crate::parent_context_v2::ParentContext::canonical(self, &anchor, self.root()?)?,
                    },
                    &lifecycle,
                    history,
                    admission_reference_time,
                    Some(c.timestamp),
                )?,
            };
            executed.state.accounting = result.accounting;
            executed.state.continuity = Some(result.registry);
            executed.state.membership_v2 = result.membership;
            executed.state.bonds_v2 = result.bonds;
            executed.state.continuity_keys_v2 = result.keys;
            executed.state.retired_continuity_v2 = result.retired;
            executed.state.endorsement_dependencies_v1 = result.endorsement_dependencies;
            executed.state.endorsement_revocations_v1 = result.endorsement_revocations;
            executed.state.node_key_history_v2 = result.node_history;
            executed.state.penalties_v2 = result.penalties;
            executed.bond_command_outcomes = result.command_outcomes;
            for (point, coin) in result.payouts {
                if executed.state.coins.insert(point, coin).is_some() {
                    return Err(ExecutionError::Duplicate);
                }
            }
            let economic_parent = recovery.map_or(self, |r| r.components());
            crate::bond_create_v3::apply_bond_creates_v3(
                economic_parent,
                &anchor,
                history,
                &creates,
                &mut executed.state,
            )?;
            if let Some(recovery) = recovery {
                executed.state.recovery_history_v2 = recovery.prospective_history().clone();
            }
            executed.root = executed.state.root()?;
        }
        Ok(executed)
    }

    /// Checks hybrid work authorization and repeats deterministic preparation.
    /// The caller must separately establish PoW and hybrid certified finality
    /// before atomically installing the returned state.
    pub fn execute_licensed_v2(
        &self,
        parent: &WorkParent,
        header: &WorkHeader,
        authority: &Authority,
        body: &BlockBody,
    ) -> Result<Execution> {
        self.execute_licensed_with_history_v2(
            parent,
            header,
            authority,
            body,
            &Default::default(),
        )
    }
    pub fn execute_licensed_with_history_v2(
        &self,
        parent: &WorkParent,
        header: &WorkHeader,
        authority: &Authority,
        body: &BlockBody,
        history: &crate::evidence_history_v2::History,
    ) -> Result<Execution> {
        self.execute_licensed_with_replay_v2(parent, header, authority, body, history, None)
    }
    pub(crate) fn execute_licensed_with_replay_v2(
        &self,
        parent: &WorkParent,
        header: &WorkHeader,
        authority: &Authority,
        body: &BlockBody,
        history: &crate::evidence_history_v2::History,
        replayed: Option<&crate::canonical_store_v2::ReplayParent<'_>>,
    ) -> Result<Execution> {
        // X separately binds the actual signed header/authority/whole body.
        // An unsigned P lease cannot enter signed execution.
        #[cfg(test)]
        let _modelled_execute_entry = crate::endorsement_revocation_v1::native16_test_host::enter_execute(
            self, parent, header, authority, body,
        )?;
        let (context, _, node) = self.work_context_v2_inner(parent, &header.candidate, replayed)?;
        authority.verify(header, &context, &node)?;
        let executed = self.prepare_candidate_with_replay_v2(
            CandidatePreparation {
                parent,
                candidate: &header.candidate,
                ticket_sequence: authority.work.ticket_sequence,
                body,
            },
            history,
            None,
            replayed,
        )?;
        if executed.root != header.candidate.state_root {
            return Err(Error::WrongAnchor.into());
        }
        Ok(executed)
    }
}
