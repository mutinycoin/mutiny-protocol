//! Hybrid coordinator failure detector. Never BFT authority or participation.
//! Authority/root inputs must come from the same authenticated canonical parent.
use crate::continuity_v2::{MAX_CERTIFICATE_BYTES, MAX_VOTE_BYTES, MAX_VOTERS, SUITE_ID};
pub use crate::liveness::{EXPIRY_MS, REFRESH_MS, WorkState};
use crate::{Error, Hash, Result, certificates::Decision, votes_v2::HeightAuthority};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature};
use primitive_types::U256;
use std::collections::VecDeque;

fn request(authority: &HeightAuthority, root: Hash, challenge: Hash) -> Result<Decision> {
    authority
        .parent
        .validate_context(authority.parent.genesis, authority.parent.fingerprint)?;
    if root == [0; 32] || challenge == [0; 32] {
        return Err(Error::WrongAnchor);
    }
    let p = &authority.parent;
    let height = p.height.checked_add(1).ok_or(Error::Overflow)?;
    Ok(Decision {
        network: p.network,
        genesis: p.genesis,
        fingerprint: p.fingerprint,
        purpose: 3,
        height,
        mining_epoch: 0,
        continuity_period: (height - 1) / 60,
        round: 0,
        step: 0,
        previous_finalized_anchor: p.id(),
        parent: p.block,
        block: challenge,
        state: root,
        membership: authority.membership,
        reputation: authority.reputation,
        attestation: authority.attestation,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub node: Hash,
    pub hardware_generation: u64,
    pub key_generation: u64,
    /// Snapshot of the existing durable voter sequence, not a new BFT vote.
    /// Zero is valid before the first vote. Replay protection is the coordinator's
    /// fresh outstanding challenge and its local issuance deadline.
    pub vote_sequence: u64,
    pub tpm_identity: Hash,
    pub profile: Hash,
    pub signature: HybridSignature,
}
impl Fragment {
    pub fn unsigned(&self, decision: &Decision) -> Result<Vec<u8>> {
        if self.node == [0; 32]
            || self.hardware_generation == 0
            || self.key_generation == 0
            || self.tpm_identity == [0; 32]
            || self.profile == [0; 32]
            || decision.purpose != 3
            || decision.step != 0
            || decision.round != 0
            || decision.mining_epoch != 0
            || decision.block == [0; 32]
            || decision.state == [0; 32]
        {
            return Err(Error::WrongOperation);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(2)
            .unwrap()
            .u16(SUITE_ID)
            .unwrap()
            .bytes(&decision.encode())
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.hardware_generation)
            .unwrap()
            .u64(self.key_generation)
            .unwrap()
            .u64(self.vote_sequence)
            .unwrap()
            .bytes(&self.tpm_identity)
            .unwrap()
            .bytes(&self.profile)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_VOTE_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    /// Low-level synthetic/offline helper; production custody must separately
    /// check exclusive counter/journal ownership and exact current parent.
    pub fn sign(&mut self, decision: &Decision, key: &HybridKey) -> Result<()> {
        self.signature = key
            .sign(Domain::ContinuityWorkProbe, &self.unsigned(decision)?)
            .map_err(|_| Error::BadSignature)?;
        Ok(())
    }
    pub fn verify(
        &self,
        decision: &Decision,
        authority: &HeightAuthority,
        root: Hash,
    ) -> Result<U256> {
        let weight = self.validate_authority(decision, authority, root)?;
        authority
            .voters
            .get(&self.node)
            .ok_or(Error::UnknownSigner)?
            .public
            .verify(
                Domain::ContinuityWorkProbe,
                &self.unsigned(decision)?,
                &self.signature,
            )
            .map_err(|_| Error::BadSignature)?;
        Ok(weight)
    }
    pub(crate) fn validate_authority(
        &self,
        decision: &Decision,
        authority: &HeightAuthority,
        root: Hash,
    ) -> Result<U256> {
        self.unsigned(decision)?;
        if decision != &request(authority, root, decision.block)? {
            return Err(Error::WrongAnchor);
        }
        let voter = authority
            .voters
            .get(&self.node)
            .ok_or(Error::UnknownSigner)?;
        let weight = voter.weight()?;
        if weight.is_zero()
            || self.hardware_generation != voter.hardware_generation
            || self.key_generation != voter.key_generation
            || self.tpm_identity != voter.tpm_identity()
            || self.profile != voter.profile
        {
            return Err(Error::UnqualifiedPhysical);
        }
        Ok(weight)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub decision: Decision,
    pub fragments: Vec<Fragment>,
}
impl Proof {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.fragments.is_empty() || self.fragments.len() > MAX_VOTERS {
            return Err(Error::Capacity);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .u16(SUITE_ID)
            .unwrap()
            .bytes(&self.decision.encode())
            .unwrap()
            .array(self.fragments.len() as u64)
            .unwrap();
        let mut previous = None;
        for f in &self.fragments {
            f.unsigned(&self.decision)?;
            if previous.is_some_and(|p| p >= f.node) {
                return Err(Error::NonCanonical);
            }
            previous = Some(f.node);
            e.array(8)
                .unwrap()
                .bytes(&f.node)
                .unwrap()
                .u64(f.hardware_generation)
                .unwrap()
                .u64(f.key_generation)
                .unwrap()
                .u64(f.vote_sequence)
                .unwrap()
                .bytes(&f.tpm_identity)
                .unwrap()
                .bytes(&f.profile)
                .unwrap()
                .bytes(&f.signature.ed448)
                .unwrap()
                .bytes(&f.signature.fndsa)
                .unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_CERTIFICATE_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_CERTIFICATE_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(4)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u16().map_err(|_| Error::Codec)? != SUITE_ID
        {
            return Err(Error::Codec);
        }
        let decision = Decision::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let n = d
            .array()
            .map_err(|_| Error::Codec)?
            .ok_or(Error::NonCanonical)?;
        if n == 0 || n > MAX_VOTERS as u64 {
            return Err(Error::Capacity);
        }
        let mut fragments = Vec::with_capacity(n as usize);
        for _ in 0..n {
            if d.array().map_err(|_| Error::Codec)? != Some(8) {
                return Err(Error::Codec);
            }
            fragments.push(Fragment {
                node: fixed(&mut d)?,
                hardware_generation: d.u64().map_err(|_| Error::Codec)?,
                key_generation: d.u64().map_err(|_| Error::Codec)?,
                vote_sequence: d.u64().map_err(|_| Error::Codec)?,
                tpm_identity: fixed(&mut d)?,
                profile: fixed(&mut d)?,
                signature: HybridSignature {
                    ed448: fixed(&mut d)?,
                    fndsa: fixed(&mut d)?,
                },
            });
        }
        let proof = Self {
            decision,
            fragments,
        };
        if d.position() != raw.len() || proof.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(proof)
    }
    pub fn verify(&self, authority: &HeightAuthority, root: Hash) -> Result<()> {
        self.encode()?;
        if self.decision != request(authority, root, self.decision.block)? {
            return Err(Error::WrongAnchor);
        }
        let weights = authority
            .weights()
            .map_err(|_| Error::UnqualifiedPhysical)?;
        let total = weights.values().try_fold(U256::zero(), |s, w| {
            s.checked_add(*w).ok_or(Error::Overflow)
        })?;
        if total.is_zero() {
            return Err(Error::UnqualifiedPhysical);
        }
        let signed = self.fragments.iter().try_fold(U256::zero(), |s, f| {
            s.checked_add(f.verify(&self.decision, authority, root)?)
                .ok_or(Error::Overflow)
        })?;
        if signed.checked_mul(U256::from(3)).ok_or(Error::Overflow)?
            <= total.checked_mul(U256::from(2)).ok_or(Error::Overflow)?
        {
            return Err(Error::NoQuorum);
        }
        Ok(())
    }
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}

pub struct WorkGate {
    authority: HeightAuthority,
    root: Hash,
    pending: VecDeque<(u64, Decision)>,
    last_probe: Option<u64>,
    accepted_issue: Option<u64>,
    last_clock: u64,
    run: bool,
    valid_context: bool,
}
impl WorkGate {
    pub fn new(authority: HeightAuthority, root: Hash, now: u64) -> Result<Self> {
        authority
            .weights()
            .map_err(|_| Error::UnqualifiedPhysical)?;
        request(&authority, root, [1; 32])?;
        Ok(Self {
            authority,
            root,
            pending: VecDeque::new(),
            last_probe: None,
            accepted_issue: None,
            last_clock: now,
            run: false,
            valid_context: true,
        })
    }
    fn clock(&mut self, now: u64) -> Result<()> {
        if now < self.last_clock {
            self.accepted_issue = None;
            self.pending.clear();
            self.last_probe = None;
            return Err(Error::InvalidCounter);
        }
        self.last_clock = now;
        self.pending.retain(|(issued, _)| now - *issued < EXPIRY_MS);
        Ok(())
    }
    pub fn set_run(&mut self, run: bool) {
        self.run = run;
    }
    pub fn state(&mut self, now: u64) -> Result<WorkState> {
        self.clock(now)?;
        Ok(if !self.run {
            WorkState::Stopped
        } else if self.valid_context
            && self
                .accepted_issue
                .is_some_and(|issued| now - issued < EXPIRY_MS)
        {
            WorkState::Running
        } else {
            WorkState::WaitingQuorum
        })
    }
    pub fn request(&mut self, now: u64, challenge: Hash) -> Result<Option<Decision>> {
        self.clock(now)?;
        if !self.valid_context {
            return Err(Error::WrongAnchor);
        }
        if self.last_probe.is_some_and(|old| now - old < REFRESH_MS) {
            return Ok(None);
        }
        if challenge == [0; 32] || self.pending.iter().any(|(_, d)| d.block == challenge) {
            return Err(Error::Duplicate);
        }
        if self.pending.len() >= 3 {
            return Err(Error::Capacity);
        }
        let d = request(&self.authority, self.root, challenge)?;
        self.pending.push_back((now, d.clone()));
        self.last_probe = Some(now);
        Ok(Some(d))
    }
    pub fn accept(&mut self, now: u64, proof: &Proof) -> Result<()> {
        self.clock(now)?;
        if !self.valid_context {
            return Err(Error::WrongAnchor);
        }
        let issued = self
            .pending
            .iter()
            .find(|(_, d)| d == &proof.decision)
            .map(|(i, _)| *i)
            .ok_or(Error::WrongAnchor)?;
        proof.verify(&self.authority, self.root)?;
        self.accepted_issue = Some(self.accepted_issue.map_or(issued, |old| old.max(issued)));
        Ok(())
    }
    pub fn work_lease(&mut self, now: u64, context: &crate::pow::WorkContext) -> Result<u64> {
        if self.state(now)? != WorkState::Running {
            return Err(Error::WrongAnchor);
        }
        let p = &self.authority.parent;
        if context.genesis != p.genesis
            || context.fingerprint != p.fingerprint
            || context.parent != p.block
            || context.parent_height != p.height
        {
            return Err(Error::WrongAnchor);
        }
        Ok(EXPIRY_MS - (now - self.accepted_issue.ok_or(Error::WrongAnchor)?))
    }
    pub fn parent_changed(
        &mut self,
        authority: HeightAuthority,
        root: Hash,
        now: u64,
    ) -> Result<()> {
        self.valid_context = false;
        self.clock(now)?;
        // Clear the existing lease before validation so a failed replacement
        // cannot leave an earlier authority usable.
        self.accepted_issue = None;
        self.pending.clear();
        self.last_probe = None;
        let run = self.run;
        let mut next = Self::new(authority, root, now)?;
        next.run = run;
        *self = next;
        Ok(())
    }
}
