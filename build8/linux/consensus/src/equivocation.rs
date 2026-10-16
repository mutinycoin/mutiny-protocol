//! Objective contradictory voting assertions, authenticated by canonical E-1
//! authority. This never establishes candidate validity or finalized history.
use crate::{
    Error, Hash, NETWORK_ID, Result,
    anchors::FinalizedAnchor,
    domain_hash,
    recovery::{ContinuityState, Member},
    votes::Vote,
};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct HistoricalAuthority {
    pub parent: FinalizedAnchor,
    pub registry: ContinuityState,
}
/// Populated from authenticated canonical history, never from evidence bytes.
pub type EvidenceHistory = BTreeMap<u64, HistoricalAuthority>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub a: Vote,
    pub b: Vote,
}
fn identity(v: &Vote) -> Hash {
    domain_hash(
        b"MUTINY-BUILD8-EQUIVOCATION-VOTE-ID-V1",
        &v.unsigned_bytes(),
    )
}
impl Evidence {
    pub fn new(a: Vote, b: Vote) -> Result<Self> {
        if identity(&a) == identity(&b) {
            return Err(Error::Duplicate);
        }
        Ok(if identity(&a) < identity(&b) {
            Self { a, b }
        } else {
            Self { a: b, b: a }
        })
    }
    pub fn id(&self) -> Hash {
        let mut raw = identity(&self.a).to_vec();
        raw.extend(identity(&self.b));
        domain_hash(b"MUTINY-BUILD8-EQUIVOCATION-ID-V1", &raw)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if identity(&self.a) >= identity(&self.b) {
            return Err(Error::NonCanonical);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(17)
            .unwrap()
            .bytes(&self.a.encode())
            .unwrap()
            .bytes(&self.b.encode())
            .unwrap();
        let raw = e.into_writer();
        crate::blocks::canonical(&raw, 4096)?;
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 4096)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("equivocation");
            if d.array()? != Some(4) || d.u8()? != 1 || d.u8()? != 17 {
                return Err(bad());
            }
            Ok(Self {
                a: Vote::decode(d.bytes()?).map_err(|_| bad())?,
                b: Vote::decode(d.bytes()?).map_err(|_| bad())?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn validate(
        &self,
        inclusion: &FinalizedAnchor,
        historical: &HistoricalAuthority,
    ) -> Result<Member> {
        self.encode()?;
        let height = inclusion.height.checked_add(1).ok_or(Error::Overflow)?;
        let e = self.a.decision.height;
        if !crate::bonds::actionable(e, height) {
            return Err(Error::InvalidCounter);
        }
        historical
            .parent
            .validate_context(inclusion.genesis, inclusion.fingerprint)?;
        if historical.parent.height.checked_add(1) != Some(e)
            || historical.registry.genesis != inclusion.genesis
            || historical.registry.fingerprint != inclusion.fingerprint
        {
            return Err(Error::WrongAnchor);
        }
        let (membership, reputation, attestation) = historical.registry.roots()?;
        let voters = historical.registry.voters()?;
        for v in [&self.a, &self.b] {
            let d = &v.decision;
            d.verify_parent(&historical.parent)?;
            if d.network != NETWORK_ID
                || d.purpose != 2
                || !matches!(d.step, 2 | 3)
                || d.continuity_period != (e - 1) / 60
                || d.membership != membership
                || d.reputation != reputation
                || d.attestation != attestation
            {
                return Err(Error::WrongAnchor);
            }
            if v.nil {
                if d.block != [0; 32] || d.state != [0; 32] || d.mining_epoch != 0 {
                    return Err(Error::NonCanonical);
                }
            } else if d.block == [0; 32] || d.state == [0; 32] {
                return Err(Error::NonCanonical);
            }
            let member = historical
                .registry
                .members
                .iter()
                .find(|m| m.node == v.node)
                .ok_or(Error::UnknownSigner)?;
            let voter = voters.get(&v.node).ok_or(Error::UnknownSigner)?;
            if !member.physical
                || !member.eligible
                || member.generation != v.key_version
                || voter.weight.is_zero()
                || voter.key_version != v.key_version
            {
                return Err(Error::WrongGeneration);
            }
            let sig = Signature::from_slice(&v.signature).map_err(|_| Error::BadSignature)?;
            if sig.normalize_s().is_some() {
                return Err(Error::NonCanonical);
            }
            VerifyingKey::from_sec1_bytes(&voter.public_key)
                .map_err(|_| Error::BadSignature)?
                .verify_prehash(&v.signing_digest(), &sig)
                .map_err(|_| Error::BadSignature)?;
        }
        if self.a.node != self.b.node
            || self.a.key_version != self.b.key_version
            || self.a.decision.round != self.b.decision.round
            || self.a.decision.step != self.b.decision.step
            || (self.a.nil == self.b.nil
                && self.a.decision.block == self.b.decision.block
                && self.a.decision.state == self.b.decision.state
                && self.a.decision.mining_epoch == self.b.decision.mining_epoch)
        {
            return Err(Error::WrongOperation);
        }
        historical
            .registry
            .members
            .iter()
            .find(|m| m.node == self.a.node)
            .cloned()
            .ok_or(Error::UnknownSigner)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub evidence: Evidence,
    pub inclusion: u64,
    pub parent: FinalizedAnchor,
    pub member: Member,
}
impl Settlement {
    pub fn key(&self) -> Hash {
        domain_hash(
            b"MUTINY-BUILD8-EQUIVOCATION-RECORD-KEY-V1",
            &self.evidence.id(),
        )
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if !crate::bonds::actionable(self.evidence.a.decision.height, self.inclusion)
            || self.parent.height.checked_add(1) != Some(self.evidence.a.decision.height)
            || self.member.node != self.evidence.a.node
            || self.member.generation != self.evidence.a.key_version
        {
            return Err(Error::WrongAnchor);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.evidence.id())
            .unwrap()
            .u64(self.inclusion)
            .unwrap()
            .bytes(&self.parent.encode())
            .unwrap()
            .bytes(&self.member.encode())
            .unwrap()
            .bytes(&self.evidence.encode()?)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 8192)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("equivocation settlement");
            if d.array()? != Some(6) || d.u8()? != 1 {
                return Err(bad());
            }
            let id: Hash = d.bytes()?.try_into().map_err(|_| bad())?;
            let inclusion = d.u64()?;
            let parent = FinalizedAnchor::decode(d.bytes()?).map_err(|_| bad())?;
            let member = crate::recovery::decode_member(d.bytes()?).map_err(|_| bad())?;
            let evidence = Evidence::decode(d.bytes()?).map_err(|_| bad())?;
            if id != evidence.id() {
                return Err(bad());
            }
            Ok(Self {
                evidence,
                inclusion,
                parent,
                member,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PenaltyBook {
    pub events: BTreeMap<Hash, Settlement>,
}
impl PenaltyBook {
    pub fn tombstoned(&self, lineage: Hash, generation: u64) -> bool {
        self.events
            .values()
            .any(|s| s.member.lineage == lineage && s.member.generation == generation)
    }
    pub fn revoked(&self, lineage: Hash) -> bool {
        self.events.values().any(|s| s.member.lineage == lineage)
    }
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.events.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        self.events
            .iter()
            .map(|(id, s)| {
                if *id != s.evidence.id() {
                    return Err(Error::WrongAnchor);
                }
                Ok((s.key(), s.encode()?))
            })
            .collect()
    }
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        let mut result = Self::default();
        for (key, raw) in records {
            let s = Settlement::decode(raw)?;
            if *key != s.key() || result.events.insert(s.evidence.id(), s).is_some() {
                return Err(Error::Duplicate);
            }
        }
        result.records()?;
        Ok(result)
    }
}
pub(crate) fn is_record(key: Hash, raw: &[u8]) -> bool {
    Settlement::decode(raw).is_ok_and(|s| s.key() == key)
}

impl crate::execution::State {
    pub(crate) fn apply_equivocations(
        &self,
        parent: &FinalizedAnchor,
        body: &crate::blocks::BlockBody,
        history: &EvidenceHistory,
        next: &mut Self,
    ) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for raw in &body.operations {
            if crate::blocks::operation_kind(raw)? != 17 {
                continue;
            }
            let evidence = Evidence::decode(raw)?;
            let id = evidence.id();
            if !seen.insert(id) || self.penalties.events.contains_key(&id) {
                return Err(Error::Duplicate);
            }
            let authority = history
                .get(&evidence.a.decision.height)
                .ok_or(Error::WrongAnchor)?;
            let offending = evidence.validate(parent, authority)?;
            let current = next
                .continuity
                .as_mut()
                .ok_or(Error::UnqualifiedPhysical)?
                .members
                .iter_mut()
                .find(|m| m.lineage == offending.lineage)
                .ok_or(Error::UnknownSigner)?;
            current.eligible = false; // P/A/S/H and numeric D are not overwritten.
            if let Some(control) = next.membership.controls.get_mut(&current.node) {
                control.exit_boundary = None;
                control.admission_boundary = None;
            }
            next.accounting.freshness.remove(&current.node);
            // Preserve any earlier rotation record: the settlement below is the
            // permanent offending-generation tombstone and distinct lineage event.
            next.bonds.burn_exposed(
                offending.lineage,
                evidence.a.decision.height,
                body.height,
                id,
            )?;
            next.penalties.events.insert(
                id,
                Settlement {
                    evidence,
                    inclusion: body.height,
                    parent: authority.parent.clone(),
                    member: offending,
                },
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bonds::{BondLot, EVIDENCE_HEIGHTS, LOCK_HEIGHTS, LotStatus, MINIMUM_ATOMS},
        certificates::Decision,
        execution::State,
        recovery::Anchor,
        reputation::History,
    };
    use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
    fn sign(v: &mut Vote, key: &SigningKey) {
        let sig: Signature = key.sign_prehash(&v.signing_digest()).unwrap();
        v.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
    }
    fn fixture(e: u64) -> (HistoricalAuthority, FinalizedAnchor, Vote, Vote, SigningKey) {
        let key = SigningKey::from_bytes((&[9; 32]).into()).unwrap();
        let parent = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: e - 1,
            block: [3; 32],
        };
        let member = Member {
            lineage: [4; 32],
            node: [5; 32],
            hardware: [6; 32],
            generation: 0,
            voting_key: key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            attestation: [7; 32],
            history: History::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        };
        let registry = ContinuityState::bootstrap(
            parent.genesis,
            parent.fingerprint,
            Anchor {
                height: e - 1,
                tip: parent.block,
                state_root: [8; 32],
                registry_root: [9; 32],
            },
            [10; 32],
            vec![member],
        )
        .unwrap();
        let (membership, reputation, attestation) = registry.roots().unwrap();
        let mut a = Vote {
            nil: false,
            node: [5; 32],
            key_version: 0,
            signature: [0; 64],
            decision: Decision {
                network: NETWORK_ID,
                genesis: parent.genesis,
                fingerprint: parent.fingerprint,
                purpose: 2,
                height: e,
                mining_epoch: 1,
                continuity_period: (e - 1) / 60,
                round: 0,
                step: 2,
                previous_finalized_anchor: parent.id(),
                parent: parent.block,
                block: [11; 32],
                state: [12; 32],
                membership,
                reputation,
                attestation,
            },
        };
        sign(&mut a, &key);
        let mut b = a.clone();
        b.decision.block = [13; 32];
        sign(&mut b, &key);
        let inclusion = FinalizedAnchor {
            height: e,
            block: [14; 32],
            ..parent.clone()
        };
        (
            HistoricalAuthority { parent, registry },
            inclusion,
            a,
            b,
            key,
        )
    }
    #[test]
    fn historical_context_and_signature_validation_rejects_signed_invalid_votes() {
        let (history, parent, a, b, key) = fixture(60);
        let evidence = Evidence::new(a.clone(), b.clone()).unwrap();
        evidence.validate(&parent, &history).unwrap();
        assert_eq!(Evidence::new(b.clone(), a.clone()).unwrap(), evidence);
        assert_eq!(
            Evidence::decode(&evidence.encode().unwrap()).unwrap(),
            evidence
        );
        assert!(Evidence::new(a.clone(), a.clone()).is_err());
        for field in 0..17 {
            let mut bad = b.clone();
            match field {
                0 => bad.decision.network ^= 1,
                1 => bad.decision.genesis[0] ^= 1,
                2 => bad.decision.fingerprint[0] ^= 1,
                3 => bad.node[0] ^= 1,
                4 => bad.key_version += 1,
                5 => bad.decision.height += 1,
                6 => bad.decision.round += 1,
                7 => bad.decision.step = 3,
                8 => bad.decision.purpose = 1,
                9 => bad.decision.membership[0] ^= 1,
                10 => bad.decision.reputation[0] ^= 1,
                11 => bad.decision.attestation[0] ^= 1,
                12 => bad.decision.previous_finalized_anchor[0] ^= 1,
                13 => bad.decision.parent[0] ^= 1,
                14 => bad.decision.continuity_period += 1,
                15 => bad.decision.state = [0; 32],
                _ => bad.nil = true,
            }
            sign(&mut bad, &key); // Even a valid TPM signature cannot rescue invalid context.
            assert!(
                Evidence::new(a.clone(), bad)
                    .unwrap()
                    .validate(&parent, &history)
                    .is_err(),
                "field {field}"
            );
        }
        let mut bad = b.clone();
        bad.signature[0] ^= 1;
        assert!(
            Evidence::new(a.clone(), bad)
                .unwrap()
                .validate(&parent, &history)
                .is_err()
        );
        let mut wrong_key = history.clone();
        wrong_key.registry.members[0].voting_key = SigningKey::from_bytes((&[10; 32]).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        assert!(evidence.validate(&parent, &wrong_key).is_err());
        let mut nil = b;
        nil.nil = true;
        nil.decision.block = [0; 32];
        nil.decision.state = [0; 32];
        nil.decision.mining_epoch = 0;
        sign(&mut nil, &key);
        Evidence::new(a, nil)
            .unwrap()
            .validate(&parent, &history)
            .unwrap();
        assert!(Evidence::decode(&[0x84, 1, 11, 0x40, 0x40]).is_err()); // ACKs are not voting evidence.
        assert!(Evidence::decode(&[]).is_err()); // Absence is not evidence.
    }
    #[test]
    fn inclusive_window_retires_offending_generation_revokes_descendant_and_preserves_d() {
        let e = 60 + LOCK_HEIGHTS;
        let (history, mut parent, a, b, _) = fixture(e);
        let proof = Evidence::new(a, b).unwrap();
        for age in [1, EVIDENCE_HEIGHTS] {
            parent.height = e + age - 1;
            proof.validate(&parent, &history).unwrap();
        }
        for h in [e - 1, e, e + EVIDENCE_HEIGHTS + 1] {
            parent.height = h - 1;
            assert!(proof.validate(&parent, &history).is_err());
        }
        let h = e + EVIDENCE_HEIGHTS;
        parent.height = h - 1;
        let mut current = history.registry.clone();
        current.members[0].generation = 1;
        current.members[0].hardware = [99; 32];
        current.members[0].voting_key = SigningKey::from_bytes((&[10; 32]).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        current.members[0].history.penalties = 7.into();
        let mut state = State {
            continuity: Some(current),
            ..Default::default()
        };
        let mut lot = BondLot {
            id: [20; 32],
            node: [5; 32],
            lineage: [4; 32],
            owner: ed25519_dalek::SigningKey::from_bytes(&[61; 32])
                .verifying_key()
                .to_bytes(),
            atoms: MINIMUM_ATOMS,
            created_height: 60,
            sequence: 0,
            unbond_height: None,
            settled_height: None,
            status: LotStatus::Active,
            evidence: [0; 32],
        };
        lot.start_unbond(e, 1).unwrap();
        state.bonds.lots.insert(lot.id, lot.clone());
        let new = BondLot {
            id: [21; 32],
            created_height: e,
            unbond_height: None,
            sequence: 0,
            status: LotStatus::Active,
            ..lot
        };
        state.bonds.lots.insert(new.id, new);
        let body = crate::blocks::BlockBody {
            height: h,
            reward_owner: [0; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![proof.encode().unwrap()],
        };
        let authorities = [(e, history)].into_iter().collect();
        let mut next = state.clone();
        state
            .apply_equivocations(&parent, &body, &authorities, &mut next)
            .unwrap();
        let member = &next.continuity.as_ref().unwrap().members[0];
        assert_eq!(member.generation, 1);
        assert!(!member.eligible);
        assert_eq!(member.history.penalties, 7.into());
        assert!(next.penalties.revoked([4; 32]));
        assert!(next.penalties.tombstoned([4; 32], 0));
        assert!(!next.penalties.tombstoned([4; 32], 1));
        assert_eq!(next.penalties.events[&proof.id()].member.generation, 0);
        assert_eq!(next.bonds.lots[&[20; 32]].status, LotStatus::Burned);
        assert_eq!(next.bonds.lots[&[21; 32]].status, LotStatus::Active);
        assert_eq!(
            PenaltyBook::from_records(&next.penalties.records().unwrap()).unwrap(),
            next.penalties
        );
        assert!(state.continuity.as_ref().unwrap().members[0].eligible);
        let original = state.clone();
        let mut late = state.clone();
        parent.height = h;
        let late_body = crate::blocks::BlockBody {
            height: h + 1,
            ..body
        };
        assert!(
            state
                .apply_equivocations(&parent, &late_body, &authorities, &mut late)
                .is_err()
        );
        assert_eq!(late, original);
    }
}
