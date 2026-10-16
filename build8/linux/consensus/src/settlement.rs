//! Independently checkable payment evidence relative to a locally authenticated
//! parent. A proof server must never supply its own trusted voter set or target.
//! Candidate codec only: canonical runtime/chain-authentication migration remains.
use crate::{
    Error, Hash, NETWORK_ID, Result,
    anchors::FinalizedAnchor,
    continuity_v2::{Certificate, MAX_CERTIFICATE_BYTES, ParentVoter},
    pow::{WorkHeader, meets_target, mining_epoch},
    state_proof::{MAX_UTXO_PROOF, verify_utxo},
    transactions::OutPoint,
    hybrid_transaction_v2::Transaction,
};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;
pub const MAX_SETTLEMENT_BYTES: usize =
    MAX_CERTIFICATE_BYTES + 16 * 1024 + 512 + MAX_UTXO_PROOF + 256;
/// Must come from sealed Genesis + locally verified canonical history. Neither
/// the transport identity nor the settlement envelope authenticates these inputs.
pub struct AuthenticatedParent<'a> {
    pub anchor: &'a FinalizedAnchor,
    pub registry: &'a BTreeMap<Hash, ParentVoter>,
    pub membership: Hash,
    pub reputation: Hash,
    pub attestation: Hash,
    pub target: Hash,
    pub genesis_timestamp: u64,
    pub ancestor_timestamps: &'a [u64],
}
pub struct ExpectedPayment {
    pub transaction: Hash,
    pub output_index: u32,
    pub destination: Hash,
    pub atoms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementProof {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub transaction: Vec<u8>,
    pub header: WorkHeader,
    pub certificate: Certificate,
    pub output_index: u32,
    pub state_proof: Vec<u8>,
}
#[derive(Debug)]
pub struct VerifiedPayment {
    transaction: Hash,
    destination: Hash,
    atoms: u64,
    created_height: u64,
    proof_anchor: FinalizedAnchor,
}
impl VerifiedPayment {
    pub fn transaction(&self) -> Hash {
        self.transaction
    }
    pub fn destination(&self) -> Hash {
        self.destination
    }
    pub fn atoms(&self) -> u64 {
        self.atoms
    }
    pub fn created_height(&self) -> u64 {
        self.created_height
    }
    pub fn proof_anchor(&self) -> &FinalizedAnchor {
        &self.proof_anchor
    }
}
impl SettlementProof {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.transaction.len() > 16 * 1024 || self.state_proof.len() > MAX_UTXO_PROOF {
            return Err(Error::Oversize);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.transaction)
            .unwrap()
            .bytes(&self.header.encode())
            .unwrap()
            .bytes(&self.certificate.encode()?)
            .unwrap()
            .u32(self.output_index)
            .unwrap()
            .bytes(&self.state_proof)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_SETTLEMENT_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_SETTLEMENT_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(9) || d.u8().map_err(|_| Error::Codec)? != 1
        {
            return Err(Error::Codec);
        }
        fn h(d: &mut Decoder<'_>) -> Result<Hash> {
            d.bytes()
                .map_err(|_| Error::Codec)?
                .try_into()
                .map_err(|_| Error::Codec)
        }
        let network = d.u32().map_err(|_| Error::Codec)?;
        let genesis = h(&mut d)?;
        let fingerprint = h(&mut d)?;
        let transaction = d.bytes().map_err(|_| Error::Codec)?;
        if transaction.len() > 16 * 1024 {
            return Err(Error::Oversize);
        }
        let header = WorkHeader::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let certificate = Certificate::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let output_index = d.u32().map_err(|_| Error::Codec)?;
        let state_proof = d.bytes().map_err(|_| Error::Codec)?;
        if state_proof.len() > MAX_UTXO_PROOF {
            return Err(Error::Oversize);
        }
        let p = Self {
            network,
            genesis,
            fingerprint,
            transaction: transaction.to_vec(),
            header,
            certificate,
            output_index,
            state_proof: state_proof.to_vec(),
        };
        if d.position() != raw.len() || p.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(p)
    }
    pub fn verify(
        &self,
        parent: &AuthenticatedParent<'_>,
        expected: &ExpectedPayment,
    ) -> Result<VerifiedPayment> {
        self.encode()?;
        parent
            .anchor
            .validate_context(self.genesis, self.fingerprint)?;
        if self.network != NETWORK_ID
            || expected.atoms == 0
            || expected.output_index != self.output_index
        {
            return Err(Error::WrongAnchor);
        }
        let c = &self.header.candidate;
        if c.network != self.network
            || c.genesis != self.genesis
            || c.fingerprint != self.fingerprint
            || c.parent != parent.anchor.block
            || parent.anchor.height.checked_add(1) != Some(c.height)
            || c.target != parent.target
            || parent.target == [0; 32]
            || !meets_target(&self.header.digest(), &parent.target)
        {
            return Err(Error::WrongAnchor);
        }
        crate::pow::validate_timestamp(
            c.height,
            c.timestamp,
            parent.genesis_timestamp,
            parent.ancestor_timestamps,
        )?;
        let mut decision = self.certificate.decision.clone();
        decision.network = self.network;
        decision.genesis = self.genesis;
        decision.fingerprint = self.fingerprint;
        decision.purpose = 2;
        decision.height = c.height;
        decision.mining_epoch = mining_epoch(c.timestamp, parent.genesis_timestamp)?;
        decision.continuity_period = (c.height - 1) / 60;
        decision.step = 3;
        decision.previous_finalized_anchor = parent.anchor.id();
        decision.parent = parent.anchor.block;
        decision.block = self.header.block_hash();
        decision.state = c.state_root;
        decision.membership = parent.membership;
        decision.reputation = parent.reputation;
        decision.attestation = parent.attestation;
        self.certificate
            .verify_quorum(&decision, parent.anchor, parent.registry)?;
        let operation = Transaction::decode(&self.transaction).map_err(|_| Error::Codec)?;
        if operation.context() != (self.network, self.genesis, self.fingerprint)
            || operation.id().map_err(|_| Error::Codec)? != expected.transaction
        {
            return Err(Error::WrongAnchor);
        }
        let output = operation
            .outputs()
            .get(self.output_index as usize)
            .ok_or(Error::WrongAnchor)?;
        if output.owner != expected.destination || output.atoms != expected.atoms {
            return Err(Error::WrongAnchor);
        }
        let anchor = decision.anchor();
        let point = OutPoint {
            transaction: expected.transaction,
            index: self.output_index,
        };
        let coin = verify_utxo(
            &self.state_proof,
            &anchor,
            c.state_root,
            &point,
            expected.destination,
        )?
        .ok_or(Error::WrongAnchor)?;
        // The signed inclusion window: a Transfer's created/expiry heights, a funded rotation's
        // envelope first/last heights.
        let (first, last) = operation.window();
        if coin.coinbase
            || coin.output.atoms != expected.atoms
            || coin.created_height < first
            || coin.created_height > last
        {
            return Err(Error::WrongAnchor);
        }
        // A later certified checkpoint can prove an older still-unspent output.
        // Expiry constrains inclusion, not the height of a subsequent proof.
        operation.verify_signatures(self.genesis,self.fingerprint,coin.created_height)
            .map_err(|_| Error::BadSignature)?;
        Ok(VerifiedPayment {
            transaction: expected.transaction,
            destination: expected.destination,
            atoms: expected.atoms,
            created_height: coin.created_height,
            proof_anchor: anchor,
        })
    }
}
