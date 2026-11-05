use crate::{
    Error, Hash, NETWORK_ID, Result, domain_hash,
    reputation::{History, concentration, quorum},
};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder};
use primitive_types::U256;

pub const RECOVERY_DOMAIN: &[u8] = b"MUTINY-BUILD8-BOOTSTRAP-RECOVERY-V1";
pub const MAX_CERTIFICATE_BYTES: usize = 4096;

pub fn continuity_meta_key() -> Hash {
    domain_hash(b"MUTINY-BUILD8-CONTINUITY-META-KEY-V1", &[])
}
pub(crate) fn decode_member(raw: &[u8]) -> Result<Member> {
    if raw.len() > 16 * 1024 {
        return Err(Error::Oversize);
    }
    let mut d = Decoder::new(raw);
    let m = (|| -> std::result::Result<Member, minicbor::decode::Error> {
        fn h(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
            d.bytes()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("hash"))
        }
        if d.array()? != Some(11) || d.u8()? != 1 {
            return Err(minicbor::decode::Error::message("member"));
        }
        let lineage = h(&mut d)?;
        let node = h(&mut d)?;
        let hardware = h(&mut d)?;
        let generation = d.u64()?;
        let voting_key = d
            .bytes()?
            .try_into()
            .map_err(|_| minicbor::decode::Error::message("key"))?;
        let attestation = h(&mut d)?;
        let physical = d.bool()?;
        let eligible = d.bool()?;
        let genesis_member = d.bool()?;
        if d.array()? != Some(6) {
            return Err(minicbor::decode::Error::message("history"));
        }
        let p = d.u64()?;
        let a = d.u64()?;
        let s = d.u64()?;
        let history_h = d.u64()?;
        let penalties = U256::from_big_endian(&h(&mut d)?);
        let count = d
            .array()?
            .ok_or(minicbor::decode::Error::message("bonds"))?;
        if count > 64 {
            return Err(minicbor::decode::Error::message("bonds"));
        }
        let mut bonds = vec![];
        for _ in 0..count {
            if d.array()? != Some(2) {
                return Err(minicbor::decode::Error::message("bond"));
            }
            bonds.push(crate::reputation::Bond {
                atoms: d.u64()?,
                age: crate::reputation::ContinuityPeriod(d.u64()?),
            });
        }
        Ok(Member {
            lineage,
            node,
            hardware,
            generation,
            voting_key,
            attestation,
            physical,
            eligible,
            genesis_member,
            history: History {
                p,
                a,
                s,
                h: history_h,
                penalties,
                bonds,
            },
        })
    })()
    .map_err(|_| Error::Codec)?;
    if d.position() != raw.len() {
        return Err(Error::NonCanonical);
    }
    Ok(m)
}
pub(crate) fn is_member_record(key: Hash, raw: &[u8]) -> bool {
    decode_member(raw)
        .is_ok_and(|m| domain_hash(b"MUTINY-BUILD8-CONTINUITY-MEMBER-KEY-V1", &m.node) == key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub height: u64,
    pub tip: Hash,
    pub state_root: Hash,
    pub registry_root: Hash,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub anchor: Anchor,
    pub sequence: u64,
    pub lineage: Hash,
    pub old_generation: u64,
    pub new_node: Hash,
    pub new_hardware: Hash,
    pub attestation: Hash,
    pub new_voting_key: [u8; 33],
    pub operation: u8,
    pub reason: u8,
    pub ceremony_commitment: Hash,
}

impl Recovery {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        // Vec<u8> writing is infallible. Integers are emitted minimally by minicbor.
        e.array(19)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u64(self.anchor.height)
            .unwrap()
            .bytes(&self.anchor.tip)
            .unwrap()
            .bytes(&self.anchor.state_root)
            .unwrap()
            .bytes(&self.anchor.registry_root)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .bytes(&self.lineage)
            .unwrap()
            .u64(self.old_generation)
            .unwrap()
            .bytes(&self.new_node)
            .unwrap()
            .bytes(&self.new_hardware)
            .unwrap()
            .bytes(&self.attestation)
            .unwrap()
            .bytes(&self.new_voting_key)
            .unwrap()
            .u8(self.operation)
            .unwrap()
            .u8(self.reason)
            .unwrap()
            .bytes(&self.ceremony_commitment)
            .unwrap()
            .u8(1)
            .unwrap(); // Attestation policy version, not self-reported physical status.
        e.into_writer()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(bytes);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            if d.array()? != Some(19) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("schema"));
            }
            let network = d.u32()?;
            let genesis = hash(&mut d)?;
            let fingerprint = hash(&mut d)?;
            let height = d.u64()?;
            let tip = hash(&mut d)?;
            let state_root = hash(&mut d)?;
            let registry_root = hash(&mut d)?;
            let sequence = d.u64()?;
            let lineage = hash(&mut d)?;
            let old_generation = d.u64()?;
            let new_node = hash(&mut d)?;
            let new_hardware = hash(&mut d)?;
            let attestation = hash(&mut d)?;
            let new_voting_key = d
                .bytes()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("key size"))?;
            let operation = d.u8()?;
            let reason = d.u8()?;
            let ceremony_commitment = hash(&mut d)?;
            if old_generation == u64::MAX || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("generation/policy"));
            }
            Ok(Self {
                network,
                genesis,
                fingerprint,
                anchor: Anchor {
                    height,
                    tip,
                    state_root,
                    registry_root,
                },
                sequence,
                lineage,
                old_generation,
                new_node,
                new_hardware,
                attestation,
                new_voting_key,
                operation,
                reason,
                ceremony_commitment,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != bytes.len() || value.encode() != bytes {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn digest(&self) -> Hash {
        domain_hash(RECOVERY_DOMAIN, &self.encode())
    }
}
fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("hash size"))
}

pub fn loss_commitment(lost: &[(Hash, u64)]) -> Result<Hash> {
    if lost.is_empty() || lost.len() > 1024 {
        return Err(Error::Capacity);
    }
    if lost.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Error::NonCanonical);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(lost.len() as u64).unwrap();
    for (lineage, generation) in lost {
        e.array(2)
            .unwrap()
            .bytes(lineage)
            .unwrap()
            .u64(*generation)
            .unwrap();
    }
    Ok(domain_hash(
        b"MUTINY-BUILD8-SUPERVISED-HARDWARE-LOSS-V1",
        &e.into_writer(),
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub body: Recovery,
    pub signature: [u8; 64],
}
impl Certificate {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&self.body.encode())
            .unwrap()
            .bytes(&self.signature)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(bytes);
        if d.array().map_err(|_| Error::Codec)? != Some(2) {
            return Err(Error::Codec);
        }
        let body = Recovery::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let signature = d
            .bytes()
            .map_err(|_| Error::Codec)?
            .try_into()
            .map_err(|_| Error::Codec)?;
        let c = Self { body, signature };
        if d.position() != bytes.len() || c.encode() != bytes {
            return Err(Error::NonCanonical);
        }
        Ok(c)
    }
}

/// Production integration MUST supply verified supervised physical admission.
/// There is deliberately no default implementation and no "physical=true" bypass.
pub trait PhysicalAdmissionVerifier {
    fn verify_replacement(&self, body: &Recovery) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub lineage: Hash,
    pub node: Hash,
    pub hardware: Hash,
    pub generation: u64,
    pub voting_key: [u8; 33],
    pub attestation: Hash,
    pub history: History,
    pub physical: bool,
    pub eligible: bool,
    pub genesis_member: bool,
}
impl Member {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(11)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.lineage)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .bytes(&self.hardware)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.voting_key)
            .unwrap()
            .bytes(&self.attestation)
            .unwrap()
            .bool(self.physical)
            .unwrap()
            .bool(self.eligible)
            .unwrap()
            .bool(self.genesis_member)
            .unwrap()
            .array(6)
            .unwrap()
            .u64(self.history.p)
            .unwrap()
            .u64(self.history.a)
            .unwrap()
            .u64(self.history.s)
            .unwrap()
            .u64(self.history.h)
            .unwrap()
            .bytes(&self.history.penalties.to_big_endian())
            .unwrap()
            .array(self.history.bonds.len() as u64)
            .unwrap();
        for b in &self.history.bonds {
            e.array(2)
                .unwrap()
                .u64(b.atoms)
                .unwrap()
                .u64(b.age.0)
                .unwrap();
        }
        e.into_writer()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContinuityState {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub anchor: Anchor,
    pub recovery_authority: [u8; 32],
    recovery_enabled: bool,
    decentralized_activated: bool,
    recovery_sequence: u64,
    last_recovery: Option<Hash>,
    pub first_period_committed: bool,
    pub members: Vec<Member>,
}
impl ContinuityState {
    /// Canonical state records omit current block/StateRoot metadata to avoid
    /// cycles. The executor restores anchor metadata from validated chain state.
    pub fn state_records(&self) -> Result<std::collections::BTreeMap<Hash, Vec<u8>>> {
        self.weights()?;
        let mut meta = Encoder::new(Vec::new());
        meta.array(9)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.recovery_authority)
            .unwrap()
            .bool(self.recovery_enabled)
            .unwrap()
            .bool(self.decentralized_activated)
            .unwrap()
            .u64(self.recovery_sequence)
            .unwrap();
        if let Some(last) = self.last_recovery {
            meta.bytes(&last).unwrap();
        } else {
            meta.null().unwrap();
        }
        meta.bool(self.first_period_committed).unwrap();
        let mut records =
            std::collections::BTreeMap::from([(continuity_meta_key(), meta.into_writer())]);
        for m in &self.members {
            records.insert(
                domain_hash(b"MUTINY-BUILD8-CONTINUITY-MEMBER-KEY-V1", &m.node),
                m.encode(),
            );
        }
        Ok(records)
    }
    pub fn from_state_records(records: &std::collections::BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        if records.len() > 1025 {
            return Err(Error::Capacity);
        }
        let raw = records.get(&continuity_meta_key()).ok_or(Error::Codec)?;
        let mut d = Decoder::new(raw);
        let mut value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            fn h(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
                d.bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("hash"))
            }
            if d.array()? != Some(9) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("registry"));
            }
            let genesis = h(&mut d)?;
            let fingerprint = h(&mut d)?;
            let recovery_authority = h(&mut d)?;
            let recovery_enabled = d.bool()?;
            let decentralized_activated = d.bool()?;
            let recovery_sequence = d.u64()?;
            let last_recovery = if d.datatype()? == minicbor::data::Type::Null {
                d.null()?;
                None
            } else {
                Some(h(&mut d)?)
            };
            let first_period_committed = d.bool()?;
            Ok(Self {
                genesis,
                fingerprint,
                recovery_authority,
                recovery_enabled,
                decentralized_activated,
                recovery_sequence,
                last_recovery,
                first_period_committed,
                members: vec![],
                anchor: Anchor {
                    height: 0,
                    tip: [0; 32],
                    state_root: [0; 32],
                    registry_root: [0; 32],
                },
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || (value.decentralized_activated && value.recovery_enabled) {
            return Err(Error::NonCanonical);
        }
        for (key, raw) in records {
            if *key == continuity_meta_key() {
                continue;
            }
            let m = decode_member(raw)?;
            if domain_hash(b"MUTINY-BUILD8-CONTINUITY-MEMBER-KEY-V1", &m.node) != *key {
                return Err(Error::WrongAnchor);
            }
            value.members.push(m);
        }
        value.members.sort_by_key(|m| m.node);
        if value.state_records()? != *records {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn bootstrap(
        genesis: Hash,
        fingerprint: Hash,
        anchor: Anchor,
        recovery_authority: [u8; 32],
        members: Vec<Member>,
    ) -> Result<Self> {
        if members.len() > 1024 {
            return Err(Error::Capacity);
        }
        let state = Self {
            genesis,
            fingerprint,
            anchor,
            recovery_authority,
            recovery_enabled: true,
            decentralized_activated: false,
            recovery_sequence: 0,
            last_recovery: None,
            first_period_committed: false,
            members,
        };
        state.weights()?;
        Ok(state)
    }
    pub fn recovery_enabled(&self) -> bool {
        self.recovery_enabled && !self.decentralized_activated
    }
    pub fn sequence(&self) -> u64 {
        self.recovery_sequence
    }
    pub(crate) fn last_recovery(&self) -> Option<Hash> {
        self.last_recovery
    }
    /// Tentative hybrid replacement after full parent/material authorization.
    /// Does not install a recovery or change any historical canonical anchor.
    pub(crate) fn stage_hybrid_recovery(
        &self,
        material: &crate::recovery_replacement_v2::Replacement,
    ) -> Result<Self> {
        let a = &material.binding.admission;
        if !self.recovery_enabled()
            || self.recovery_sequence.checked_add(1) != Some(material.sequence)
        {
            return Err(Error::RecoveryDisabled);
        }
        material
            .parent
            .validate_context(self.genesis, self.fingerprint)?;
        let mut next = self.clone();
        let member = next
            .members
            .iter_mut()
            .find(|m| m.lineage == material.lineage && m.node == material.old_node)
            .ok_or(Error::InvalidLineage)?;
        if !member.physical
            || !member.eligible
            || member.generation != material.old_hardware_generation
            || member.generation.checked_add(1) != Some(a.hardware_generation)
        {
            return Err(Error::WrongGeneration);
        }
        let profile = crate::tpm::TpmProfile::decode(&a.profile)?;
        member.node = a.node;
        member.hardware = profile.hardware;
        member.generation = a.hardware_generation;
        member.voting_key = crate::tpm::public_key(&profile.voting_public, false)?;
        member.attestation = profile.commitment()?;
        member.history.h = 0;
        next.recovery_sequence = material.sequence;
        next.last_recovery = Some(material.commitment()?);
        next.members.sort_by_key(|m| m.node);
        next.weights()?;
        Ok(next)
    }
    pub fn mode(&self) -> &'static str {
        if self.decentralized_activated {
            "DECENTRALIZED"
        } else {
            "BOOTSTRAP_CENTRALIZED"
        }
    }
    pub fn weights(&self) -> Result<Vec<U256>> {
        let mut nodes = std::collections::BTreeSet::new();
        let mut lineages = std::collections::BTreeSet::new();
        let mut hardware = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeSet::new();
        if self.members.len() > 1024 {
            return Err(Error::Capacity);
        }
        for member in &self.members {
            if !nodes.insert(member.node) || !lineages.insert(member.lineage) {
                return Err(Error::Duplicate);
            }
            if member.physical
                && member.eligible
                && (!hardware.insert(member.hardware) || !keys.insert(member.voting_key))
            {
                return Err(Error::Duplicate);
            }
        }
        self.members
            .iter()
            .map(|m| {
                m.history.voting_weight(
                    m.physical,
                    m.eligible,
                    m.genesis_member,
                    self.first_period_committed,
                )
            })
            .collect()
    }
    /// Registry authority is computed from committed typed records, never from
    /// weights supplied by an incoming vote/certificate. Physical flags still
    /// require the external verified admission boundary on every transition.
    pub fn voters(&self) -> Result<std::collections::BTreeMap<Hash, crate::certificates::Voter>> {
        let weights = self.weights()?;
        Ok(self
            .members
            .iter()
            .zip(weights)
            .map(|(m, weight)| {
                (
                    m.node,
                    crate::certificates::Voter {
                        key_version: m.generation,
                        public_key: m.voting_key,
                        weight,
                    },
                )
            })
            .collect())
    }
    /// Round-/signer-independent roots. The current chain anchor is intentionally
    /// excluded: inserting current StateRoot/BlockHash here would create a cycle.
    pub fn roots(&self) -> Result<(Hash, Hash, Hash)> {
        self.weights()?;
        let mut members: Vec<_> = self.members.iter().collect();
        members.sort_by_key(|m| m.node);
        let mut membership = Encoder::new(Vec::new());
        membership
            .array(10)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.recovery_authority)
            .unwrap()
            .bool(self.recovery_enabled)
            .unwrap()
            .bool(self.decentralized_activated)
            .unwrap()
            .u64(self.recovery_sequence)
            .unwrap();
        if let Some(last) = self.last_recovery {
            membership.bytes(&last).unwrap();
        } else {
            membership.null().unwrap();
        }
        membership
            .bool(self.first_period_committed)
            .unwrap()
            .array(members.len() as u64)
            .unwrap();
        let mut reputation = Encoder::new(Vec::new());
        reputation.array(members.len() as u64).unwrap();
        let mut attestation = Encoder::new(Vec::new());
        attestation.array(members.len() as u64).unwrap();
        for member in members {
            membership
                .array(10)
                .unwrap()
                .u8(1)
                .unwrap()
                .bytes(&member.lineage)
                .unwrap()
                .bytes(&member.node)
                .unwrap()
                .bytes(&member.hardware)
                .unwrap()
                .u64(member.generation)
                .unwrap()
                .bytes(&member.voting_key)
                .unwrap()
                .bytes(&member.attestation)
                .unwrap()
                .bool(member.physical)
                .unwrap()
                .bool(member.eligible)
                .unwrap()
                .bool(member.genesis_member)
                .unwrap();
            let h = &member.history;
            reputation
                .array(8)
                .unwrap()
                .u8(1)
                .unwrap()
                .bytes(&member.lineage)
                .unwrap()
                .u64(h.p)
                .unwrap()
                .u64(h.a)
                .unwrap()
                .u64(h.s)
                .unwrap()
                .u64(h.h)
                .unwrap()
                .bytes(&h.penalties.to_big_endian())
                .unwrap()
                .array(h.bonds.len() as u64)
                .unwrap();
            for bond in &h.bonds {
                reputation
                    .array(2)
                    .unwrap()
                    .u64(bond.atoms)
                    .unwrap()
                    .u64(bond.age.0)
                    .unwrap();
            }
            attestation
                .array(3)
                .unwrap()
                .bytes(&member.node)
                .unwrap()
                .u64(member.generation)
                .unwrap()
                .bytes(&member.attestation)
                .unwrap();
        }
        Ok((
            domain_hash(
                b"MUTINY-BUILD8-MEMBERSHIP-ROOT-V1",
                &membership.into_writer(),
            ),
            domain_hash(
                b"MUTINY-BUILD8-REPUTATION-ROOT-V1",
                &reputation.into_writer(),
            ),
            domain_hash(
                b"MUTINY-BUILD8-ATTESTATION-ROOT-V1",
                &attestation.into_writer(),
            ),
        ))
    }
    pub fn metrics(&self) -> Result<crate::reputation::Concentration> {
        let independent = self
            .members
            .iter()
            .filter(|m| m.physical && m.eligible)
            .map(|m| m.hardware)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        concentration(&self.weights()?, independent)
    }
    /// Called only after ordinary consensus has verified signatures/locks and
    /// durable commit. Indices here identify already cryptographically verified
    /// old-set signers; this pure state transition is not a vote verifier.
    pub fn activate_decentralized(&mut self, old_set_signers: &[usize]) -> Result<()> {
        if !quorum(&self.weights()?, old_set_signers)? {
            return Err(Error::NoQuorum);
        }
        if !self.metrics()?.survival_redundancy_met {
            return Err(Error::RedundancyNotMet);
        }
        self.decentralized_activated = true;
        self.recovery_enabled = false;
        Ok(())
    }
    /// Tentative certified-block effect. The enclosing executor must validate the
    /// block certificate against this parent registry before installing state.
    pub fn stage_activation_from_parent(&mut self, parent: &Self) -> Result<()> {
        if self.genesis != parent.genesis || self.fingerprint != parent.fingerprint {
            return Err(Error::WrongAnchor);
        }
        if !parent.recovery_enabled() {
            return Err(Error::RecoveryDisabled);
        }
        if !parent.metrics()?.survival_redundancy_met {
            return Err(Error::RedundancyNotMet);
        }
        self.decentralized_activated = true;
        self.recovery_enabled = false;
        Ok(())
    }
    pub fn apply_recovery(
        &mut self,
        c: &Certificate,
        admission: &impl PhysicalAdmissionVerifier,
        supervised_lost_generations: &[(Hash, u64)],
        existing_valid_descendant: bool,
    ) -> Result<()> {
        if !self.recovery_enabled() {
            return Err(Error::RecoveryDisabled);
        }
        let b = &c.body;
        if b.network != NETWORK_ID {
            return Err(Error::WrongNetwork);
        }
        if b.genesis != self.genesis {
            return Err(Error::WrongGenesis);
        }
        if b.fingerprint != self.fingerprint {
            return Err(Error::WrongFingerprint);
        }
        if existing_valid_descendant {
            return Err(Error::ExistingFinality);
        }
        if b.anchor != self.anchor {
            return Err(Error::WrongAnchor);
        }
        if b.sequence
            != self
                .recovery_sequence
                .checked_add(1)
                .ok_or(Error::Overflow)?
        {
            return Err(Error::StaleSequence);
        }
        if self.last_recovery == Some(b.digest()) {
            return Err(Error::ConflictingRecovery);
        }
        if b.operation != 1 || b.reason != 1 {
            return Err(Error::WrongOperation);
        }
        if b.ceremony_commitment != loss_commitment(supervised_lost_generations)? {
            return Err(Error::WrongOperation);
        }
        VerifyingKey::from_bytes(&self.recovery_authority)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(&b.digest(), &Signature::from_bytes(&c.signature))
            .map_err(|_| Error::BadSignature)?;
        let i = self
            .members
            .iter()
            .position(|m| m.lineage == b.lineage)
            .ok_or(Error::InvalidLineage)?;
        let old = &self.members[i];
        if old.generation != b.old_generation {
            return Err(Error::WrongGeneration);
        }
        if !old.physical || !old.eligible {
            return Err(Error::UnqualifiedPhysical);
        }
        if !supervised_lost_generations.contains(&(old.lineage, old.generation)) {
            return Err(Error::WrongGeneration);
        }
        let mut lost = std::collections::BTreeSet::new();
        for &(lineage, generation) in supervised_lost_generations {
            if !lost.insert((lineage, generation)) {
                return Err(Error::Duplicate);
            }
            if !self.members.iter().any(|m| {
                m.lineage == lineage && m.generation == generation && m.physical && m.eligible
            }) {
                return Err(Error::WrongGeneration);
            }
        }
        let surviving: Vec<_> = self
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| !lost.contains(&(m.lineage, m.generation)))
            .map(|(i, _)| i)
            .collect();
        if quorum(&self.weights()?, &surviving)? {
            return Err(Error::NormalQuorumAvailable);
        }
        if self.members.iter().any(|m| {
            m.hardware == b.new_hardware || m.node == b.new_node || m.voting_key == b.new_voting_key
        }) {
            return Err(Error::Duplicate);
        }
        admission.verify_replacement(b)?;
        let generation = old.generation.checked_add(1).ok_or(Error::Overflow)?;
        // Commit atomically in the enclosing durable state transaction. No UTXO,
        // block-history, amount, bond-age or penalty mutation exists in this API.
        let m = &mut self.members[i];
        m.node = b.new_node;
        m.hardware = b.new_hardware;
        m.generation = generation;
        m.voting_key = b.new_voting_key;
        m.attestation = b.attestation;
        m.history.h = 0;
        self.recovery_sequence = b.sequence;
        self.last_recovery = Some(b.digest());
        Ok(())
    }
}
