//! Hybrid owner-or-node authorized exit. The verifier grants no same-block weight
//! change and does not itself install the existing period-boundary transition.
use crate::{
    Error, Hash, NETWORK_ID, Result, anchors::FinalizedAnchor, wallet_authority_v1::WalletBook,
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
pub const MAX_EXIT_BYTES: usize = 4096;

/// Independently resolved canonical parent control; never supplied by the
/// untrusted operation. Node transport authority and Continuity keys differ.
pub struct ParentControl<'a> {
    pub node: Hash,
    pub hardware_generation: u64,
    pub sequence: u64,
    pub owner_address: Hash,
    pub node_descriptor: &'a [u8],
    pub exit_pending: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub height: u64,
    pub parent_anchor: Hash,
    pub node: Hash,
    pub hardware_generation: u64,
    pub sequence: u64,
    pub authorizer: Vec<u8>,
    pub signature: HybridSignature,
}
impl Exit {
    fn signer(&self) -> Result<(PublicKey, Domain)> {
        let (key, _) = PublicKey::decode_descriptor(&self.authorizer).map_err(|_| Error::Codec)?;
        let domain = match key.role {
            Role::WalletOwner => Domain::ContinuityExitOwner,
            Role::Node => Domain::ContinuityExitNode,
            _ => return Err(Error::BadSignature),
        };
        Ok((key, domain))
    }
    pub fn body(&self) -> Result<Vec<u8>> {
        self.signer()?;
        if self.genesis == [0; 32]
            || self.fingerprint == [0; 32]
            || self.parent_anchor == [0; 32]
            || self.node == [0; 32]
            || self.height == 0
            || self.hardware_generation == 0
            || self.sequence == 0
        {
            return Err(Error::InvalidCounter);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(11)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(14)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .bytes(&self.parent_anchor)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.hardware_generation)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .bytes(&self.authorizer)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn sign(&mut self, key: &HybridKey) -> Result<()> {
        let (public, domain) = self.signer()?;
        if key.public() != &public {
            return Err(Error::BadSignature);
        }
        self.signature = key
            .sign(domain, &self.body()?)
            .map_err(|_| Error::BadSignature)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(14)
            .unwrap()
            .bytes(&self.body()?)
            .unwrap()
            .bytes(&self.signature.ed448)
            .unwrap()
            .bytes(&self.signature.fndsa)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_EXIT_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_EXIT_BYTES)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 5)?;
        if d.u8().map_err(|_| Error::Codec)? != 2 || d.u8().map_err(|_| Error::Codec)? != 14 {
            return Err(Error::Codec);
        }
        let body = d.bytes().map_err(|_| Error::Codec)?;
        let signature = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let mut b = Decoder::new(body);
        array(&mut b, 11)?;
        if b.u8().map_err(|_| Error::Codec)? != 2
            || b.u8().map_err(|_| Error::Codec)? != 14
            || b.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let exit = Self {
            genesis: fixed(&mut b)?,
            fingerprint: fixed(&mut b)?,
            height: b.u64().map_err(|_| Error::Codec)?,
            parent_anchor: fixed(&mut b)?,
            node: fixed(&mut b)?,
            hardware_generation: b.u64().map_err(|_| Error::Codec)?,
            sequence: b.u64().map_err(|_| Error::Codec)?,
            authorizer: b.bytes().map_err(|_| Error::Codec)?.to_vec(),
            signature,
        };
        if d.position() != raw.len() || b.position() != body.len() || exit.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(exit)
    }
    pub fn verify(
        &self,
        parent: &FinalizedAnchor,
        control: &ParentControl<'_>,
        wallets: &WalletBook,
    ) -> Result<()> {
        self.encode()?;
        parent.validate_context(self.genesis, self.fingerprint)?;
        if parent.height.checked_add(1) != Some(self.height)
            || parent.id() != self.parent_anchor
            || self.node != control.node
        {
            return Err(Error::WrongAnchor);
        }
        if self.hardware_generation != control.hardware_generation {
            return Err(Error::WrongGeneration);
        }
        if control.exit_pending || control.sequence.checked_add(1) != Some(self.sequence) {
            return Err(Error::StaleSequence);
        }
        let (public, domain) = self.signer()?;
        match public.role {
            Role::WalletOwner => wallets.authorize(control.owner_address, &self.authorizer)?,
            Role::Node => {
                let (expected, _) = PublicKey::decode_descriptor(control.node_descriptor)
                    .map_err(|_| Error::Codec)?;
                if expected.role != Role::Node || self.authorizer != control.node_descriptor {
                    return Err(Error::BadSignature);
                }
            }
            _ => return Err(Error::BadSignature),
        }
        public
            .verify(domain, &self.body()?, &self.signature)
            .map_err(|_| Error::BadSignature)
    }
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(|_| Error::Codec)? != Some(n) {
        return Err(Error::Codec);
    }
    Ok(())
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
