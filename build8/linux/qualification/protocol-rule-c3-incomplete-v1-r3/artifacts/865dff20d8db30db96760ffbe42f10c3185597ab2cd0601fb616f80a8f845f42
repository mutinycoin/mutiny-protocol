//! Bounded purpose-3 work-liveness requests and verified signature fragments.
//! This service has no BFT lock, counter mutation or participation credit.
use mutiny_consensus_v8::{
    Error, Hash,
    certificates::{Certificate, Decision, Signer},
    liveness::WorkGate,
    votes::HeightAuthority,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Work probes: {e:?}")
}
struct Remote {
    decision: Decision,
    response: Option<Certificate>,
    accepted: Instant,
}
#[derive(Default)]
pub struct WorkProbes {
    context: Option<(Hash, Hash)>,
    own: Option<Decision>,
    fragments: BTreeMap<Hash, Signer>,
    peers: BTreeMap<Hash, Remote>,
}
impl WorkProbes {
    pub fn synchronize(&mut self, authority: &HeightAuthority, root: Hash) {
        let context = (authority.parent.id(), root);
        if self.context != Some(context) {
            *self = Self {
                context: Some(context),
                ..Self::default()
            };
        }
    }
    fn validate(decision: &Decision, authority: &HeightAuthority, root: Hash) -> Result<()> {
        let expected = WorkGate::new(authority.clone(), root, 0)
            .map_err(err)?
            .request(0, decision.block)
            .map_err(err)?
            .ok_or("Missing probe")?;
        if &expected != decision {
            return Err("Work probe is not exact current-parent purpose-3/step-0 request".into());
        }
        Ok(())
    }
    pub fn begin(
        &mut self,
        decision: Decision,
        authority: &HeightAuthority,
        root: Hash,
    ) -> Result<()> {
        self.synchronize(authority, root);
        Self::validate(&decision, authority, root)?;
        if self.own.as_ref() != Some(&decision) {
            self.own = Some(decision);
            self.fragments.clear();
        }
        Ok(())
    }
    pub fn own(&self) -> Option<&Decision> {
        self.own.as_ref()
    }
    pub fn queue(
        &mut self,
        peer: Hash,
        decision: Decision,
        authority: &HeightAuthority,
        root: Hash,
    ) -> Result<()> {
        self.synchronize(authority, root);
        Self::validate(&decision, authority, root)?;
        if let Some(old) = self.peers.get(&peer) {
            if old.decision == decision {
                return Ok(());
            }
            if old.accepted.elapsed() < Duration::from_secs(1) {
                return Err("Work probe refresh rate bound".into());
            }
        } else if self.peers.len() >= 32 {
            return Err("Work probe peer capacity".into());
        }
        self.peers.insert(
            peer,
            Remote {
                decision,
                response: None,
                accepted: Instant::now(),
            },
        );
        Ok(())
    }
    pub fn response(&self, peer: Hash) -> Option<&Certificate> {
        self.peers.get(&peer).and_then(|p| p.response.as_ref())
    }
    /// A local tick may sign its own challenge plus at most two peer requests.
    pub fn pending(&self, node: Hash) -> Vec<(Option<Hash>, Decision)> {
        let mut pending = Vec::new();
        if !self.fragments.contains_key(&node) {
            if let Some(own) = &self.own {
                pending.push((None, own.clone()));
            }
        }
        for (peer, request) in self
            .peers
            .iter()
            .filter(|(_, p)| p.response.is_none())
            .take(2)
        {
            pending.push((Some(*peer), request.decision.clone()));
        }
        pending
    }
    fn valid_fragment(
        fragment: &Certificate,
        expected: &Decision,
        authority: &HeightAuthority,
    ) -> Result<()> {
        if fragment.signers.is_empty() || authority.voters.values().all(|v| v.weight.is_zero()) {
            return Err("No weighted probe signer".into());
        }
        // With a positive total, NoQuorum is returned only after every included
        // signature has been checked. It means a valid partial, not authority.
        match fragment.verify_quorum(expected, &authority.voters) {
            Ok(()) | Err(Error::NoQuorum) => Ok(()),
            Err(error) => Err(err(error)),
        }
    }
    pub fn receive(
        &mut self,
        fragment: &Certificate,
        authority: &HeightAuthority,
        root: Hash,
    ) -> Result<()> {
        self.synchronize(authority, root);
        let expected = self
            .own
            .as_ref()
            .ok_or("No outstanding local work challenge")?;
        Self::valid_fragment(fragment, expected, authority)?;
        for signer in &fragment.signers {
            self.fragments
                .entry(signer.node)
                .or_insert_with(|| signer.clone());
        }
        Ok(())
    }
    pub fn signed(
        &mut self,
        peer: Option<Hash>,
        fragment: Certificate,
        authority: &HeightAuthority,
        root: Hash,
    ) -> Result<()> {
        if let Some(peer) = peer {
            self.synchronize(authority, root);
            let request = self
                .peers
                .get_mut(&peer)
                .ok_or("Expired peer work challenge")?;
            Self::valid_fragment(&fragment, &request.decision, authority)?;
            request.response = Some(fragment);
            Ok(())
        } else {
            self.receive(&fragment, authority, root)
        }
    }
    pub fn quorum(&self, authority: &HeightAuthority) -> Result<Option<Certificate>> {
        let Some(expected) = self.own.as_ref() else {
            return Ok(None);
        };
        let certificate = Certificate {
            decision: expected.clone(),
            signers: self.fragments.values().cloned().collect(),
        };
        match certificate.verify_quorum(expected, &authority.voters) {
            Ok(()) => Ok(Some(certificate)),
            Err(Error::NoQuorum) => Ok(None),
            Err(error) => Err(err(error)),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::{NETWORK_ID, anchors::FinalizedAnchor, certificates::Voter};
    use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    #[test]
    fn only_exact_liveness_context_and_valid_partial_signatures_accumulate() {
        let keys = [
            SigningKey::from_bytes((&[51; 32]).into()).unwrap(),
            SigningKey::from_bytes((&[52; 32]).into()).unwrap(),
        ];
        let authority = HeightAuthority {
            parent: FinalizedAnchor {
                network: NETWORK_ID,
                genesis: [1; 32],
                fingerprint: [2; 32],
                height: 0,
                block: [3; 32],
            },
            membership: [4; 32],
            reputation: [5; 32],
            attestation: [6; 32],
            voters: keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    (
                        [i as u8; 32],
                        Voter {
                            key_version: 1,
                            public_key: k
                                .verifying_key()
                                .to_encoded_point(true)
                                .as_bytes()
                                .try_into()
                                .unwrap(),
                            weight: 1u64.into(),
                        },
                    )
                })
                .collect(),
        };
        let root = [7; 32];
        let decision = WorkGate::new(authority.clone(), root, 0)
            .unwrap()
            .request(0, [8; 32])
            .unwrap()
            .unwrap();
        let mut pool = WorkProbes::default();
        pool.begin(decision.clone(), &authority, root).unwrap();
        assert!(pool.quorum(&authority).unwrap().is_none());
        let mut bad = decision.clone();
        bad.purpose = 2;
        bad.step = 2;
        assert!(pool.queue([9; 32], bad, &authority, root).is_err());
        pool.queue([9; 32], decision.clone(), &authority, root)
            .unwrap();
        assert!(pool.response([9; 32]).is_none());
        let fragment = |index: usize| {
            let signature: Signature = keys[index]
                .sign_prehash(&decision.signing_digest([index as u8; 32], 1))
                .unwrap();
            Certificate {
                decision: decision.clone(),
                signers: vec![Signer {
                    node: [index as u8; 32],
                    key_version: 1,
                    signature: signature
                        .normalize_s()
                        .unwrap_or(signature)
                        .to_bytes()
                        .into(),
                }],
            }
        };
        let mut invalid = fragment(0);
        invalid.signers[0].signature[0] ^= 1;
        assert!(pool.receive(&invalid, &authority, root).is_err());
        pool.receive(&fragment(0), &authority, root).unwrap();
        assert!(pool.quorum(&authority).unwrap().is_none());
        pool.receive(&fragment(0), &authority, root).unwrap();
        assert!(pool.quorum(&authority).unwrap().is_none());
        pool.receive(&fragment(1), &authority, root).unwrap();
        assert_eq!(pool.quorum(&authority).unwrap().unwrap().signers.len(), 2);
        pool.signed(Some([9; 32]), fragment(0), &authority, root)
            .unwrap();
        assert!(pool.response([9; 32]).is_some());
        let mut next = authority.clone();
        next.parent.height = 1;
        next.parent.block = [10; 32];
        pool.synchronize(&next, root);
        assert!(pool.own().is_none());
        assert!(pool.response([9; 32]).is_none());
        assert!(pool.receive(&fragment(0), &next, root).is_err());
    }
}
