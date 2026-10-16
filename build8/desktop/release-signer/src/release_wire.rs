//! Bounded candidate wire codec. Qualification only; not a production suite lock.
use super::*;
use minicbor::Decoder;

fn array(d: &mut Decoder<'_>, count: u64) -> Result<()> {
    check(
        d.array().map_err(|_| "array")? == Some(count),
        "array shape",
    )
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| "bytes")?
        .try_into()
        .map_err(|_| "bytes length")
}
fn canonical(input: &[u8], encoded: Vec<u8>, d: &Decoder<'_>) -> Result<()> {
    check(
        d.position() == input.len() && input == encoded,
        "noncanonical/trailing bytes",
    )
}
impl Custodian {
    pub(crate) fn decode(input: &[u8]) -> Result<Self> {
        check(input.len() <= 1900, "custodian bound")?;
        let mut d = Decoder::new(input);
        array(&mut d, 6)?;
        check(d.u8().map_err(|_| "version")? == 1, "version")?;
        let c = Self {
            role: d.u8().map_err(|_| "role")?,
            generation: d.u64().map_err(|_| "generation")?,
            suite: d.u16().map_err(|_| "suite")?,
            ed: fixed::<57>(&mut d)?.to_vec(),
            fndsa: fixed::<1793>(&mut d)?.to_vec(),
        };
        canonical(input, c.bytes()?, &d)?;
        Ok(c)
    }
}
impl Policy {
    pub fn decode(input: &[u8]) -> Result<Self> {
        check(input.len() <= 5800, "policy bound")?;
        let mut d = Decoder::new(input);
        array(&mut d, 6)?;
        check(d.u8().map_err(|_| "version")? == 1, "version")?;
        check(d.u32().map_err(|_| "network")? == NETWORK, "network")?;
        let generation = d.u64().map_err(|_| "generation")?;
        let synthetic = d.bool().map_err(|_| "synthetic marker")?;
        check(d.u8().map_err(|_| "threshold")? == 2, "threshold")?;
        array(&mut d, 3)?;
        let mut custodians = Vec::with_capacity(3);
        for _ in 0..3 {
            custodians.push(Custodian::decode(
                d.bytes().map_err(|_| "custodian bytes")?,
            )?);
        }
        let p = Self {
            generation,
            synthetic,
            custodians,
        };
        canonical(input, p.bytes()?, &d)?;
        Ok(p)
    }
}
impl Manifest {
    pub fn decode(input: &[u8]) -> Result<Self> {
        check(input.len() <= 512, "manifest bound")?;
        let mut d = Decoder::new(input);
        array(&mut d, 16)?;
        check(d.u8().map_err(|_| "version")? == 2, "version")?;
        let network = d.u32().map_err(|_| "network")?;
        let compatibility_len = d.array().map_err(|_| "compatibility")?;
        let genesis = match (compatibility_len, d.u8().map_err(|_| "compatibility tag")?) {
            (Some(1), 0) => None,
            (Some(2), 1) => Some(fixed::<32>(&mut d)?),
            _ => return Err("compatibility shape"),
        };
        let fingerprint = fixed::<32>(&mut d)?;
        let board = fixed::<32>(&mut d)?;
        let application = d.u64().map_err(|_| "application")?;
        let security = d.u64().map_err(|_| "security")?;
        let length = d.u32().map_err(|_| "length")?;
        array(&mut d, 2)?;
        check(d.u8().map_err(|_| "image algorithm")? == 2, "SHA-512 image commitment required")?;
        let image = fixed::<64>(&mut d)?;
        check(
            d.u8().map_err(|_| "target")? == 1,
            "inactive application required",
        )?;
        let m = Self {
            network,
            genesis,
            fingerprint,
            board,
            application,
            security,
            length,
            image,
            schema_min: d.u16().map_err(|_| "schema")?,
            schema_max: d.u16().map_err(|_| "schema")?,
            policy: fixed::<32>(&mut d)?,
            policy_generation: d.u64().map_err(|_| "policy generation")?,
            rollback: d.u64().map_err(|_| "rollback")?,
            flags: d.u32().map_err(|_| "flags")?,
        };
        canonical(input, m.bytes()?, &d)?;
        Ok(m)
    }
}
impl Approval {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.payload()?;
        check(
            self.ed.len() == 114 && self.fndsa.len() == 1280,
            "signature lengths",
        )?;
        let mut e = Encoder::new(Vec::new());
        e.array(8)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.policy)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.custodian)
            .unwrap()
            .bytes(&self.manifest)
            .unwrap()
            .u16(self.suite)
            .unwrap()
            .bytes(&self.ed)
            .unwrap()
            .bytes(&self.fndsa)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn decode(input: &[u8]) -> Result<Self> {
        check(input.len() <= 1600, "approval bound")?;
        let mut d = Decoder::new(input);
        array(&mut d, 8)?;
        check(d.u8().map_err(|_| "version")? == 1, "version")?;
        let a = Self {
            policy: fixed::<32>(&mut d)?,
            generation: d.u64().map_err(|_| "generation")?,
            custodian: fixed::<32>(&mut d)?,
            manifest: fixed::<64>(&mut d)?,
            suite: d.u16().map_err(|_| "suite")?,
            ed: fixed::<114>(&mut d)?.to_vec(),
            fndsa: fixed::<1280>(&mut d)?.to_vec(),
        };
        canonical(input, a.bytes()?, &d)?;
        Ok(a)
    }
}
