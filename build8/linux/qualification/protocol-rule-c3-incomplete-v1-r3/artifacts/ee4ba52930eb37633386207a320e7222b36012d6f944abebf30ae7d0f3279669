//! Irreversible activation is authorized by the ordinary parent-set block
//! certificate. No wallet signature or current-block reputation substitutes.
use crate::{Error, Hash, Result, anchors::FinalizedAnchor, recovery::ContinuityState};
use minicbor::{Decoder, Encoder};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecentralizedActivation {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub height: u64,
    pub parent: Hash,
    pub membership: Hash,
    pub reputation: Hash,
}
impl DecentralizedActivation {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(10)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(13)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .array(3)
            .unwrap()
            .bytes(&self.parent)
            .unwrap()
            .bytes(&self.membership)
            .unwrap()
            .bytes(&self.reputation)
            .unwrap()
            .array(0)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 512 {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(raw);
        let v = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            fn h(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
                d.bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("hash"))
            }
            if d.array()? != Some(10) || d.u8()? != 1 || d.u8()? != 13 {
                return Err(minicbor::decode::Error::message("activation"));
            }
            let network = d.u32()?;
            let genesis = h(&mut d)?;
            let fingerprint = h(&mut d)?;
            if h(&mut d)? != genesis || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("singleton"));
            }
            let height = d.u64()?;
            if d.array()? != Some(3) {
                return Err(minicbor::decode::Error::message("payload"));
            }
            let parent = h(&mut d)?;
            let membership = h(&mut d)?;
            let reputation = h(&mut d)?;
            if d.array()? != Some(0) {
                return Err(minicbor::decode::Error::message("authority"));
            }
            Ok(Self {
                network,
                genesis,
                fingerprint,
                height,
                parent,
                membership,
                reputation,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || v.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(v)
    }
    pub fn validate(&self, parent: &FinalizedAnchor, registry: &ContinuityState) -> Result<()> {
        parent.validate_context(self.genesis, self.fingerprint)?;
        let roots = registry.roots()?;
        if self.network != parent.network
            || parent.height.checked_add(1) != Some(self.height)
            || self.parent != parent.id()
            || self.membership != roots.0
            || self.reputation != roots.1
        {
            return Err(Error::WrongAnchor);
        }
        if !registry.recovery_enabled() {
            return Err(Error::RecoveryDisabled);
        }
        if !registry.metrics()?.survival_redundancy_met {
            return Err(Error::RedundancyNotMet);
        }
        Ok(())
    }
}
