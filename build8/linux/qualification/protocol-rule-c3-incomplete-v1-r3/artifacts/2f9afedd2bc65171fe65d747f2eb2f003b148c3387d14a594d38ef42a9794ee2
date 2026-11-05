//! Authenticated round selection, separate from candidate custody and BFT votes.
//!
//! Sealed construction (Architect decision 6; independent review MINOR-3). Outside this module a
//! proposal can be read, decoded from the wire, compared or altered (an alteration voids its
//! signature), but never newly signed: `signature`, `sign`, `body` and `digest` are private, so no
//! other module can write a `RoundProposal` literal (functional update syntax included) or compute
//! its signing payload, and such code does not compile. The ONLY way to obtain a NEW signed
//! proposal is `RoundProposal::signed`, which consumes a `local_proposer::Offer`: the proposer's
//! selection, which only `local_proposer.rs` can build, once, inside `LocalProposer::propose`,
//! after it selected a verified proof of lock, the held lock or a candidate eligible under the
//! voter's own qualified clock. `node/tests/proposal_construction_paths_v1.rs` pins the seal.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder, data::Type};
use mutiny_consensus_v8::{
    Hash, anchors::FinalizedAnchor, blocks::canonical, canonical_store::CanonicalStore,
    domain_hash, membership::NodeControl,
};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Round proposal: {e:?}")
}
pub const MAX_WIRE: usize = 512;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundProposal {
    pub parent: FinalizedAnchor,
    pub round: u64,
    pub proposer: Hash,
    pub generation: u64,
    pub block: Hash,
    pub pol_round: Option<u64>,
    /// Private, as are `sign`, `body` and `digest`: see the module documentation.
    signature: [u8; 64],
}
impl RoundProposal {
    /// The ONLY constructor of a NEW signed proposal. `offer` is the proposer's selection, which
    /// only `LocalProposer::propose` can build (see the module documentation).
    pub(crate) fn signed(
        parent: FinalizedAnchor,
        round: u64,
        proposer: Hash,
        generation: u64,
        offer: crate::local_proposer::Offer,
        key: &SigningKey,
    ) -> Self {
        let mut proposal = Self {
            parent,
            round,
            proposer,
            generation,
            block: offer.block(),
            pol_round: offer.pol_round(),
            signature: [0; 64],
        };
        proposal.sign(key);
        proposal
    }
    fn body(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(7)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.parent.encode())
            .unwrap()
            .u64(self.round)
            .unwrap()
            .bytes(&self.proposer)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.block)
            .unwrap();
        if let Some(r) = self.pol_round {
            e.u64(r).unwrap();
        } else {
            e.null().unwrap();
        }
        e.into_writer()
    }
    fn digest(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-ROUND-PROPOSAL-V1", &self.body())
    }
    fn sign(&mut self, key: &SigningKey) {
        self.signature = key.sign(&self.digest()).to_bytes();
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&self.body())
            .unwrap()
            .bytes(&self.signature)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, MAX_WIRE).map_err(err)?;
        let mut outer = Decoder::new(raw);
        if outer.array().map_err(err)? != Some(2) {
            return Err("Proposal envelope".into());
        }
        let body = outer.bytes().map_err(err)?;
        canonical(body, MAX_WIRE).map_err(err)?;
        let signature = outer
            .bytes()
            .map_err(err)?
            .try_into()
            .map_err(|_| "Proposal signature width")?;
        let mut d = Decoder::new(body);
        if d.array().map_err(err)? != Some(7) || d.u8().map_err(err)? != 1 {
            return Err("Proposal version".into());
        }
        let value = Self {
            parent: FinalizedAnchor::decode(d.bytes().map_err(err)?).map_err(err)?,
            round: d.u64().map_err(err)?,
            proposer: d
                .bytes()
                .map_err(err)?
                .try_into()
                .map_err(|_| "Proposer width")?,
            generation: d.u64().map_err(err)?,
            block: d
                .bytes()
                .map_err(err)?
                .try_into()
                .map_err(|_| "Block width")?,
            pol_round: if d.datatype().map_err(err)? == Type::Null {
                d.null().map_err(err)?;
                None
            } else {
                Some(d.u64().map_err(err)?)
            },
            signature,
        };
        if value.encode() != raw {
            return Err("Noncanonical proposal".into());
        }
        Ok(value)
    }
    fn verify(
        &self,
        parent: &FinalizedAnchor,
        selected: (u64, Hash),
        control: &NodeControl,
    ) -> Result<()> {
        if &self.parent != parent
            || selected != (self.round, self.proposer)
            || control.node != self.proposer
            || control.generation != self.generation
            || self.pol_round.is_some_and(|r| r >= self.round)
        {
            return Err("Proposal parent/round/proposer/generation".into());
        }
        VerifyingKey::from_bytes(&control.node_authentication)
            .map_err(err)?
            .verify_strict(&self.digest(), &Signature::from_bytes(&self.signature))
            .map_err(err)
    }
    /// `selected` must come from the local canonical proposer schedule, never
    /// from the peer. Proof-of-lock votes and candidate execution are separately
    /// checked by VoterActor before any local Continuity vote can be signed.
    pub fn verify_current(&self, chain: &mut CanonicalStore, selected: (u64, Hash)) -> Result<()> {
        if chain.integrity_halted().map_err(err)? {
            return Err("Canonical integrity halt".into());
        }
        let (tip, state) = chain.load_effective().map_err(err)?;
        let (parent, _) = chain.execution_parent(tip.height).map_err(err)?;
        let authority =
            mutiny_consensus_v8::voter_actor::authority(&parent, &state).map_err(err)?;
        let voter = authority
            .voters
            .get(&self.proposer)
            .ok_or("Unknown proposer")?;
        if voter.weight.is_zero() || voter.key_version != self.generation {
            return Err("Ineligible proposer".into());
        }
        let control = state
            .membership
            .controls
            .get(&self.proposer)
            .ok_or("Missing proposer control")?;
        self.verify(&authority.parent, selected, control)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_proposer_authentication_binds_parent_round_key_and_pol() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let parent = FinalizedAnchor {
            network: mutiny_consensus_v8::NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 59,
            block: [3; 32],
        };
        let control = NodeControl {
            node: [4; 32],
            generation: 1,
            owner: key.verifying_key().to_bytes(),
            node_authentication: key.verifying_key().to_bytes(),
            sequence: 0,
            exit_boundary: None,
            admitted_height: 0,
            admission_boundary: None,
            hardware_since_height: 0,
        };
        let mut proposal = RoundProposal {
            parent: parent.clone(),
            round: 2,
            proposer: control.node,
            generation: 1,
            block: [5; 32],
            pol_round: Some(1),
            signature: [0; 64],
        };
        proposal.sign(&key);
        let wire = proposal.encode();
        assert!(wire.len() <= MAX_WIRE);
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/ROUND-PROPOSAL-VECTORS-V1.json"
        ))
        .unwrap();
        assert_eq!(hex::encode(&wire), vectors["wire"]);
        assert_eq!(hex::encode(proposal.digest()), vectors["digest"]);
        assert_eq!(
            hex::encode(key.verifying_key().to_bytes()),
            vectors["public"]
        );
        for case in vectors["negative"].as_array().unwrap() {
            let bytes = hex::decode(case.as_str().unwrap()).unwrap();
            if let Ok(value) = RoundProposal::decode(&bytes) {
                assert!(value.verify(&parent, (2, control.node), &control).is_err());
            }
        }
        assert_eq!(RoundProposal::decode(&wire).unwrap(), proposal);
        proposal
            .verify(&parent, (2, control.node), &control)
            .unwrap();
        assert!(
            proposal
                .verify(&parent, (3, control.node), &control)
                .is_err()
        );
        assert!(proposal.verify(&parent, (2, [9; 32]), &control).is_err());
        for mutation in 0..8 {
            let mut bad = proposal.clone();
            match mutation {
                0 => bad.parent.genesis[0] ^= 1,
                1 => bad.parent.fingerprint[0] ^= 1,
                2 => bad.parent.block[0] ^= 1,
                3 => bad.block[0] ^= 1,
                4 => bad.generation += 1,
                5 => bad.signature[0] ^= 1,
                6 => bad.pol_round = Some(2),
                _ => bad.parent.network ^= 1,
            }
            assert!(bad.verify(&parent, (2, control.node), &control).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(RoundProposal::decode(&trailing).is_err());
        assert!(RoundProposal::decode(&vec![0; MAX_WIRE + 1]).is_err());
    }
}
