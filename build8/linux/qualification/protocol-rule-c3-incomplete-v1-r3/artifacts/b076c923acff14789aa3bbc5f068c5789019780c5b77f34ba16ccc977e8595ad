//! Bounded hybrid probe exchange state; caller supplies authenticated peer IDs
//! and the exact canonical parent authority. No network or private-key access.
use mutiny_consensus_v8::{
    Error, Hash,
    certificates::Decision,
    continuity_v2::MAX_VOTERS,
    liveness_v2::{EXPIRY_MS, Fragment, Proof, WorkGate},
    votes_v2::HeightAuthority,
};
use std::collections::BTreeMap;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Hybrid work probes: {e:?}")
}
struct Remote {
    decision: Decision,
    issued: u64,
    response: Option<Proof>,
}
#[derive(Default)]
pub struct WorkProbes {
    context: Option<(Hash, Hash)>,
    last_clock: u64,
    own: Option<(Decision, u64)>,
    fragments: BTreeMap<Hash, Fragment>,
    peers: BTreeMap<Hash, Remote>,
}
impl WorkProbes {
    fn synchronize(&mut self, authority: &HeightAuthority, root: Hash, now: u64) -> Result<()> {
        if now < self.last_clock {
            let last_clock = self.last_clock;
            *self = Self {
                last_clock,
                ..Self::default()
            };
            return Err("Probe clock regressed".into());
        }
        self.last_clock = now;
        let context = (authority.parent.id(), root);
        if self.context != Some(context) {
            *self = Self {
                context: Some(context),
                last_clock: now,
                ..Self::default()
            };
        }
        self.peers.retain(|_, p| now - p.issued < EXPIRY_MS);
        if self
            .own
            .as_ref()
            .is_some_and(|(_, issued)| now - *issued >= EXPIRY_MS)
        {
            self.own = None;
            self.fragments.clear();
        }
        Ok(())
    }
    fn validate(d: &Decision, a: &HeightAuthority, root: Hash) -> Result<()> {
        let expected = WorkGate::new(a.clone(), root, 0)
            .map_err(err)?
            .request(0, d.block)
            .map_err(err)?
            .ok_or("Missing challenge")?;
        if *d != expected {
            return Err("Probe does not bind current parent".into());
        }
        Ok(())
    }
    pub fn begin(
        &mut self,
        decision: Decision,
        a: &HeightAuthority,
        root: Hash,
        now: u64,
    ) -> Result<()> {
        self.synchronize(a, root, now)?;
        Self::validate(&decision, a, root)?;
        // Duplicate delivery never renews the local expiry.
        if self.own.as_ref().map(|(d, _)| d) != Some(&decision) {
            self.own = Some((decision, now));
            self.fragments.clear();
        }
        Ok(())
    }
    pub fn queue(
        &mut self,
        peer: Hash,
        decision: Decision,
        a: &HeightAuthority,
        root: Hash,
        now: u64,
    ) -> Result<()> {
        self.synchronize(a, root, now)?;
        if peer == [0; 32] {
            return Err("Unauthenticated peer identity".into());
        }
        Self::validate(&decision, a, root)?;
        if let Some(old) = self.peers.get(&peer) {
            if old.decision == decision {
                return Ok(());
            }
            if now - old.issued < 1000 {
                return Err("Peer probe rate bound".into());
            }
        } else if self.peers.len() >= 32 {
            return Err("Peer probe capacity".into());
        }
        self.peers.insert(
            peer,
            Remote {
                decision,
                issued: now,
                response: None,
            },
        );
        Ok(())
    }
    /// At most one local and two remote signing requests per service tick.
    pub fn pending(
        &mut self,
        node: Hash,
        a: &HeightAuthority,
        root: Hash,
        now: u64,
    ) -> Result<Vec<(Option<Hash>, Decision)>> {
        self.synchronize(a, root, now)?;
        let mut out = Vec::new();
        if !self.fragments.contains_key(&node) {
            if let Some((d, _)) = &self.own {
                out.push((None, d.clone()));
            }
        }
        out.extend(
            self.peers
                .iter()
                .filter(|(_, p)| p.response.is_none())
                .take(2)
                .map(|(id, p)| (Some(*id), p.decision.clone())),
        );
        Ok(out)
    }
    fn valid_fragment(
        proof: &Proof,
        expected: &Decision,
        a: &HeightAuthority,
        root: Hash,
    ) -> Result<()> {
        // Remote cache stores ONE fragment per peer, never 32 full quorum sets.
        if proof.fragments.len() != 1 || proof.decision != *expected {
            return Err("Not one exact probe fragment".into());
        }
        match proof.verify(a, root) {
            Ok(()) | Err(Error::NoQuorum) => Ok(()),
            Err(e) => Err(err(e)),
        }
    }
    pub fn signed(
        &mut self,
        peer: Option<Hash>,
        proof: Proof,
        a: &HeightAuthority,
        root: Hash,
        now: u64,
    ) -> Result<()> {
        self.synchronize(a, root, now)?;
        if let Some(peer) = peer {
            let remote = self
                .peers
                .get_mut(&peer)
                .ok_or("Unknown or expired peer probe")?;
            Self::valid_fragment(&proof, &remote.decision, a, root)?;
            remote.response = Some(proof);
        } else {
            let expected = &self.own.as_ref().ok_or("No outstanding local challenge")?.0;
            Self::valid_fragment(&proof, expected, a, root)?;
            let fragment = proof.fragments.into_iter().next().ok_or("Empty fragment")?;
            if !self.fragments.contains_key(&fragment.node) && self.fragments.len() >= MAX_VOTERS {
                return Err("Probe signer capacity".into());
            }
            self.fragments.entry(fragment.node).or_insert(fragment);
        }
        Ok(())
    }
    pub fn response(
        &mut self,
        peer: Hash,
        a: &HeightAuthority,
        root: Hash,
        now: u64,
    ) -> Result<Option<Proof>> {
        self.synchronize(a, root, now)?;
        Ok(self.peers.get(&peer).and_then(|p| p.response.clone()))
    }
    pub fn quorum(&mut self, a: &HeightAuthority, root: Hash, now: u64) -> Result<Option<Proof>> {
        self.synchronize(a, root, now)?;
        let Some((decision, _)) = &self.own else {
            return Ok(None);
        };
        if self.fragments.is_empty() {
            return Ok(None);
        }
        let proof = Proof {
            decision: decision.clone(),
            fragments: self.fragments.values().cloned().collect(),
        };
        match proof.verify(a, root) {
            Ok(()) => Ok(Some(proof)),
            Err(Error::NoQuorum) => Ok(None),
            Err(e) => Err(err(e)),
        }
    }
}
