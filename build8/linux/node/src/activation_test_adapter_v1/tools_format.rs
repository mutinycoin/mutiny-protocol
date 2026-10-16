//! tpm2-tools 5.7 credential container: BE magic, version1, two BE u16 blobs.
//! Encoding only; all credential cryptography stays in the pinned upstream tool.
//! Source contract: upstream commit c6e182cf690ca0022b77fe7d3c174659917a7e7e,
//! tools/tpm2_makecredential.c:39-83, lib/files.c:549-569.
use super::{Error, Result};
use mutiny_consensus_v8::activation_attestation_v1::EncryptedCredential;
const MAGIC: [u8; 4] = [0xba, 0xdc, 0xc0, 0xde];
pub const MAX_CONTAINER: usize = 8 + 2 + 4096 + 2 + 4096;
// tss 4.1.3 arrays: TPM2B_ID_OBJECT contains TPMS_ID_OBJECT (132 bytes),
// TPM2B_ENCRYPTED_SECRET contains TPMU_ENCRYPTED_SECRET (512 bytes).
// These are tool-dispatch limits, not a change to the private wire envelope.
const NATIVE_CREDENTIAL_MAX: usize = 132;
const NATIVE_SEED_MAX: usize = 512;
pub const NATIVE_CONTAINER_MAX: usize = 12 + NATIVE_CREDENTIAL_MAX + NATIVE_SEED_MAX;
pub fn native_bounds(value: &EncryptedCredential) -> Result<()> {
    if value.credential().is_empty() || value.encrypted_seed().is_empty()
        || value.credential().len()>NATIVE_CREDENTIAL_MAX
        || value.encrypted_seed().len()>NATIVE_SEED_MAX {return Err(Error::Bounds);}
    Ok(())
}
/// Refuse native array overflow before encoding/copying into a child input.
pub fn encode_native(value: &EncryptedCredential) -> Result<Vec<u8>> {
    native_bounds(value)?; encode(value)
}
/// Bound the producer output before allocation into owned encrypted components.
pub fn decode_native(raw: &[u8]) -> Result<EncryptedCredential> {
    if raw.len()>NATIVE_CONTAINER_MAX {return Err(Error::Bounds);}
    // Check individual lengths before decode performs its owned allocations.
    if raw.len()<12 {return Err(Error::Codec);}
    let a=u16::from_be_bytes([raw[8],raw[9]]) as usize;
    if a==0 || a>NATIVE_CREDENTIAL_MAX {return Err(Error::Bounds);}
    let at=10+a;
    let size=raw.get(at..at+2).ok_or(Error::Codec)?;
    let b=u16::from_be_bytes([size[0],size[1]]) as usize;
    if b==0 || b>NATIVE_SEED_MAX {return Err(Error::Bounds);}
    decode(raw)
}

pub fn encode(value: &EncryptedCredential) -> Result<Vec<u8>> {
    let a=value.credential(); let b=value.encrypted_seed();
    if a.is_empty() || b.is_empty() || a.len()>4096 || b.len()>4096 {return Err(Error::Bounds);}
    let mut raw=Vec::with_capacity(12+a.len()+b.len());
    raw.extend_from_slice(&MAGIC); raw.extend_from_slice(&1u32.to_be_bytes());
    raw.extend_from_slice(&(a.len() as u16).to_be_bytes()); raw.extend_from_slice(a);
    raw.extend_from_slice(&(b.len() as u16).to_be_bytes()); raw.extend_from_slice(b); Ok(raw)
}
pub fn decode(raw: &[u8]) -> Result<EncryptedCredential> {
    if raw.len()<12 || raw.len()>MAX_CONTAINER {return Err(Error::Bounds);}
    if raw[..4]!=MAGIC || raw[4..8]!=1u32.to_be_bytes() {return Err(Error::Codec);}
    let mut at=8;
    fn blob<'a>(raw:&'a [u8],at:&mut usize)->Result<&'a [u8]>{
        let size=raw.get(*at..*at+2).ok_or(Error::Codec)?;
        let n=u16::from_be_bytes(size.try_into().map_err(|_|Error::Codec)?) as usize;
        *at+=2; if n==0 || n>4096{return Err(Error::Bounds);}
        let value=raw.get(*at..*at+n).ok_or(Error::Codec)?; *at+=n; Ok(value)
    }
    let a=blob(raw,&mut at)?; let b=blob(raw,&mut at)?;
    if at!=raw.len(){return Err(Error::Codec);}
    EncryptedCredential::new(a.to_vec(),b.to_vec()).map_err(|_|Error::Bounds)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dispatch_native_bounds_preserve_workflow_envelope_and_refuse_before_child(){
        let maximum=EncryptedCredential::new(vec![3;132],vec![4;512]).unwrap();
        let raw=encode_native(&maximum).unwrap();
        assert_eq!(raw.len(),NATIVE_CONTAINER_MAX);
        assert_eq!(encode_native(&decode_native(&raw).unwrap()).unwrap(),raw);
        for value in [EncryptedCredential::new(vec![3;133],vec![4;1]).unwrap(),
            EncryptedCredential::new(vec![3;1],vec![4;513]).unwrap()] {
            let raw=encode(&value).unwrap();
            assert!(decode(&raw).is_ok());
            assert_eq!(native_bounds(&value),Err(Error::Bounds));
            assert_eq!(encode_native(&value),Err(Error::Bounds));
            assert!(matches!(decode_native(&raw),Err(Error::Bounds)));
        }
        for end in 0..raw.len(){assert!(decode_native(&raw[..end]).is_err());}
        let mut trailing=raw;trailing.push(0);assert!(decode_native(&trailing).is_err());
    }
    #[test]
    fn credential_container_exact_roundtrip_and_every_truncation(){
        let value=EncryptedCredential::new(vec![3;68],vec![4;256]).unwrap();
        let raw=encode(&value).unwrap(); let decoded=decode(&raw).unwrap();
        assert_eq!(encode(&decoded).unwrap(),raw);
        for n in 0..raw.len(){assert!(decode(&raw[..n]).is_err());}
        let mut extra=raw.clone(); extra.push(0); assert!(decode(&extra).is_err());
        let mut bad=raw.clone(); bad[7]=2; assert!(decode(&bad).is_err());
        bad=raw; bad[8..10].copy_from_slice(&4097u16.to_be_bytes()); assert!(decode(&bad).is_err());
    }
}
