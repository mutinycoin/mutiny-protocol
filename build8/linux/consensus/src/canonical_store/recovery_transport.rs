//! Public, bounded transport for an already owner-authorized supervised
//! recovery. Receipt never creates a recovery authorization or TPM custody.
use super::*;
use minicbor::{Decoder, Encoder};
pub const MAX_RECOVERY_ENVELOPE: usize = 256 * 1024;
pub struct RecoveryEnvelope {
    pub certificate: crate::recovery::Certificate,
    pub losses: Vec<(Hash, u64)>,
    pub witness: crate::recovery_material::RecoveryMaterial,
}
impl RecoveryEnvelope {
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        if crate::recovery::loss_commitment(&self.losses)?
            != self.certificate.body.ceremony_commitment
        {
            return Err(Error::NonCanonical);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.certificate.encode())
            .unwrap()
            .array(self.losses.len() as u64)
            .unwrap();
        for (lineage, generation) in &self.losses {
            e.array(2)
                .unwrap()
                .bytes(lineage)
                .unwrap()
                .u64(*generation)
                .unwrap();
        }
        e.bytes(&self.witness.encode()?).unwrap();
        let bytes = e.into_writer();
        crate::blocks::canonical(&bytes, MAX_RECOVERY_ENVELOPE)?;
        Ok(bytes)
    }
    pub fn decode(raw: &[u8]) -> crate::Result<Self> {
        crate::blocks::canonical(raw, MAX_RECOVERY_ENVELOPE)?;
        let mut d = Decoder::new(raw);
        let (certificate, losses, witness) =
            (|| -> std::result::Result<_, minicbor::decode::Error> {
                let bad = || minicbor::decode::Error::message("recovery envelope");
                if d.array()? != Some(4) || d.u8()? != 1 {
                    return Err(bad());
                }
                let certificate = d.bytes()?.to_vec();
                let count = d.array()?.ok_or_else(bad)?;
                if count == 0 || count > 1024 {
                    return Err(bad());
                }
                let mut losses = Vec::new();
                for _ in 0..count {
                    if d.array()? != Some(2) {
                        return Err(bad());
                    }
                    losses.push((d.bytes()?.try_into().map_err(|_| bad())?, d.u64()?));
                }
                Ok((certificate, losses, d.bytes()?.to_vec()))
            })()
            .map_err(|_| Error::Codec)?;
        let value = Self {
            certificate: crate::recovery::Certificate::decode(&certificate)?,
            losses,
            witness: crate::recovery_material::RecoveryMaterial::decode(&witness)?,
        };
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
impl CanonicalStore {
    pub fn recovery_envelope(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let head: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT block FROM chain_history WHERE height=?1",
                [height.to_be_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(block) = head else {
            return Err(ChainError::StaleParent);
        };
        let row:Option<(Vec<u8>,Vec<u8>,Vec<u8>)>=self.db.query_row(
            "SELECT CASE WHEN length(certificate)<=4096 THEN certificate END,
            CASE WHEN length(losses)<=65536 THEN losses END,base_block FROM recovery_overlay WHERE base_height=?1",
            [height.to_be_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((certificate, losses, base_block)) = row else {
            return Ok(None);
        };
        if block != base_block {
            return Err(ChainError::Integrity);
        }
        let witness:Vec<u8>=self.db.query_row("SELECT CASE WHEN length(witness)<=16384 THEN witness END FROM recovery_material WHERE base_height=?1",
            [height.to_be_bytes().as_slice()],|r|r.get(0))?;
        // Reuse the exact canonical loss-list bytes already checked at commit.
        crate::blocks::canonical(&losses, 65536)?;
        let mut d = Decoder::new(&losses);
        let parse = (|| -> std::result::Result<Vec<(Hash, u64)>, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("loss list");
            let n = d.array()?.ok_or_else(bad)?;
            if n == 0 || n > 1024 {
                return Err(bad());
            }
            let mut items = Vec::new();
            for _ in 0..n {
                if d.array()? != Some(2) {
                    return Err(bad());
                }
                items.push((d.bytes()?.try_into().map_err(|_| bad())?, d.u64()?));
            }
            Ok(items)
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != losses.len() {
            return Err(Error::NonCanonical.into());
        }
        let envelope = RecoveryEnvelope {
            certificate: crate::recovery::Certificate::decode(&certificate)?,
            losses: parse,
            witness: crate::recovery_material::RecoveryMaterial::decode(&witness)?,
        };
        if envelope.certificate.body.anchor.height != height
            || envelope.certificate.body.anchor.tip.as_slice() != block
        {
            return Err(ChainError::Integrity);
        }
        Ok(Some(envelope.encode()?))
    }
    pub fn accept_recovery_envelope(&mut self, raw: &[u8]) -> Result<bool> {
        let envelope = RecoveryEnvelope::decode(raw)?;
        let (head, _) = self.load()?;
        if envelope.certificate.body.anchor.height != head.height
            || envelope.certificate.body.anchor.tip != head.block
        {
            return Err(ChainError::StaleParent);
        }
        self.accept_admitted_bootstrap_recovery(
            &envelope.certificate,
            &envelope.witness,
            &envelope.losses,
        )
    }
}
