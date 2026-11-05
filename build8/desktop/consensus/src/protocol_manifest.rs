//! Pre-Genesis protocol-rule manifest. Instance identities are not inputs.
use crate::{Error, Hash, NETWORK_ID, Result, blocks::canonical, domain_hash};
use minicbor::{Decoder, Encoder};
pub const DOMAIN: &[u8] = b"MUTINY-BUILD8-PROTOCOL-FINGERPRINT-V1";
pub const MAX_MANIFEST: usize = 128 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleManifest {
    pub commitments: Vec<(Vec<u8>, Hash)>,
}
impl RuleManifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.commitments.is_empty() || self.commitments.len() > 512 {
            return Err(Error::Capacity);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .array(self.commitments.len() as u64)
            .unwrap();
        let mut last: Option<&[u8]> = None;
        for (name, hash) in &self.commitments {
            if name.is_empty()
                || name.len() > 128
                || !name.iter().all(|b| b.is_ascii_graphic())
                || last.is_some_and(|l| l >= name.as_slice())
            {
                return Err(Error::NonCanonical);
            }
            last = Some(name);
            e.array(2)
                .unwrap()
                .bytes(name)
                .unwrap()
                .bytes(hash)
                .unwrap();
        }
        Ok(e.into_writer())
    }
    pub fn fingerprint(&self) -> Result<Hash> {
        Ok(domain_hash(DOMAIN, &self.encode()?))
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, MAX_MANIFEST)?;
        let mut d = Decoder::new(raw);
        let parsed = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("rule manifest");
            if d.array()? != Some(3) || d.u8()? != 1 || d.u32()? != NETWORK_ID {
                return Err(bad());
            }
            let count = d.array()?.ok_or_else(bad)?;
            if count == 0 || count > 512 {
                return Err(bad());
            }
            let mut commitments = Vec::with_capacity(count as usize);
            for _ in 0..count {
                if d.array()? != Some(2) {
                    return Err(bad());
                }
                let name = d.bytes()?;
                if name.len() > 128 {
                    return Err(bad());
                }
                commitments.push((name.to_vec(), d.bytes()?.try_into().map_err(|_| bad())?));
            }
            Ok(Self { commitments })
        })()
        .map_err(|_| Error::Codec)?;
        if parsed.encode() != Ok(raw.to_vec()) {
            return Err(Error::NonCanonical);
        }
        Ok(parsed)
    }
}
