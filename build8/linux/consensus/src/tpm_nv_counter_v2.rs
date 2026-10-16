//! Existing NV counter read evidence, a LOCAL custody implementation artifact.
//! A valid signature authenticates these bytes against the supplied AK profile;
//! it does not qualify an EK, physical lineage, reset/deletion policy or provider.
//! No TPM operation, counter mutation, key creation or installation occurs here.
use super::{Reader,TpmProfile,public_key,signature};
use crate::{Error,Hash,Result};
use p256::ecdsa::{VerifyingKey,signature::Verifier};
use sha2::{Digest,Sha256};
#[cfg(test)]
#[path="../tests/support/software_tpm.rs"] mod software;

/// Numerically authenticated observation only, never a qualification capability.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Observation {
    pub counter:u64,
    pub index:u32,
    pub attributes:u32,
    pub clock:u64,
    pub reset_count:u32,
    pub restart_count:u32,
    pub safe:bool,
    pub firmware_version:u64,
}

/// `public` is exactly the selected existing TPM2B_NV_PUBLIC, including its
/// length prefix. `message` is the raw TPMS_ATTEST, not another TPM2B container.
/// `signature_bytes` uses the already supported TPMT_SIGNATURE P256/SHA256 form.
/// The selected public hash and challenge must come from the installed owner;
/// this public verifier grants no authority to select either trust input.
pub fn verify(profile:&TpmProfile,selected_public_sha256:Hash,public:&[u8],
    challenge:Hash,message:&[u8],signature_bytes:&[u8])->Result<Observation>{
    if selected_public_sha256==[0;32] || challenge==[0;32]
        || public.len()>80 || message.len()>256 || signature_bytes.len()>128 {
        return Err(Error::Oversize);
    }
    if <[u8;32]>::from(Sha256::digest(public))!=selected_public_sha256 {
        return Err(Error::WrongAnchor);
    }
    let mut boxed=Reader::new(public);let area=boxed.blob()?;boxed.end()?;
    let mut nv=Reader::new(area);
    let index=nv.u32()?;
    if index>>24!=1 || nv.u16()?!=0xb {return Err(Error::Codec);}
    let attributes=nv.u32()?;
    let policy=nv.blob()?;
    // TPM2_NT_COUNTER is 1, in the four-bit type field. Other NV types are not
    // monotonic counter objects. No locally invented hierarchy/delete policy.
    if attributes&0xf0!=0x10 || attributes&0x01f00300!=0 || attributes&0x08000000!=0
        || !matches!(policy.len(),0|32) || nv.u16()?!=8 {
        return Err(Error::UnqualifiedPhysical);
    }
    nv.end()?;
    let mut name=[0u8;34];name[..2].copy_from_slice(&0xbu16.to_be_bytes());
    name[2..].copy_from_slice(&Sha256::digest(area));
    // Existing admitted-profile certification and restricted AK validation.
    profile.verify_certified_key()?;
    let key=VerifyingKey::from_sec1_bytes(&public_key(&profile.ak_public,true)?)
        .map_err(|_|Error::BadSignature)?;
    key.verify(message,&signature(signature_bytes)?).map_err(|_|Error::BadSignature)?;
    let mut r=Reader::new(message);
    if r.u32()?!=0xff544347 || r.u16()?!=0x8014
        || r.blob()?!=profile.qualified_signer || r.blob()?!=challenge {
        return Err(Error::WrongAnchor);
    }
    let clock=u64::from_be_bytes(r.take(8)?.try_into().map_err(|_|Error::Codec)?);
    let reset_count=r.u32()?;let restart_count=r.u32()?;
    let safe=match r.take(1)?[0]{0=>false,1=>true,_=>return Err(Error::Codec)};
    let firmware_version=u64::from_be_bytes(r.take(8)?.try_into().map_err(|_|Error::Codec)?);
    if r.blob()?!=name || r.u16()?!=0 {return Err(Error::WrongAnchor);}
    let contents=r.blob()?;
    if contents.len()!=8 {return Err(Error::Codec);}
    let counter=u64::from_be_bytes(contents.try_into().map_err(|_|Error::Codec)?);
    r.end()?;
    Ok(Observation{counter,index,attributes,clock,reset_count,restart_count,safe,firmware_version})
}

#[cfg(test)]
mod modeled_controls {
    use super::*;
    use p256::ecdsa::{Signature,signature::Signer};
    fn blob(raw:&[u8])->Vec<u8>{let mut b=(raw.len() as u16).to_be_bytes().to_vec();b.extend(raw);b}
    fn public(kind:u32)->Vec<u8>{
        let mut b=0x01500020u32.to_be_bytes().to_vec();b.extend(0xbu16.to_be_bytes());
        b.extend((0x20060000|kind).to_be_bytes());b.extend(blob(&[]));b.extend(8u16.to_be_bytes());blob(&b)
    }
    fn statement(profile:&TpmProfile,public:&[u8],challenge:Hash,value:u64)->Vec<u8>{
        let mut b=0xff544347u32.to_be_bytes().to_vec();b.extend(0x8014u16.to_be_bytes());
        b.extend(blob(&profile.qualified_signer));b.extend(blob(&challenge));b.extend([0;16]);
        b.push(1);b.extend([0;8]);let mut name=vec![0,0xb];name.extend(Sha256::digest(&public[2..]));
        b.extend(blob(&name));b.extend(0u16.to_be_bytes());b.extend(blob(&value.to_be_bytes()));b
    }
    fn sign(message:&[u8])->Vec<u8>{
        let key=software::seeded_key(software::AK_SEED_LABEL);
        let s:Signature=key.sign(message);let raw=s.to_bytes();let mut b=vec![0,0x18,0,0xb];
        b.extend(blob(&raw[..32]));b.extend(blob(&raw[32..]));b
    }
    #[test]
    fn modeled_signed_exact_counter_nonce_and_name_binding(){
        let t=software::TestTpm::new();let public=public(0x10);let pin=Sha256::digest(&public).into();
        let nonce=[7;32];let m=statement(t.profile(),&public,nonce,45);let sig=sign(&m);
        assert_eq!(verify(t.profile(),pin,&public,nonce,&m,&sig).unwrap().counter,45);
        assert!(verify(t.profile(),pin,&public,[8;32],&m,&sig).is_err());
        let mut wrong=public.clone();wrong[5]^=1;
        assert!(verify(t.profile(),Sha256::digest(&wrong).into(),&wrong,nonce,&m,&sig).is_err());
        let mut tampered=m.clone();*tampered.last_mut().unwrap()^=1;
        assert!(verify(t.profile(),pin,&public,nonce,&tampered,&sig).is_err());
    }
    #[test]
    fn modeled_counter_type_complete_framing_and_signed_wrong_offset_refusal(){
        let t=software::TestTpm::new();let nonce=[7;32];
        let raw=public(0);let m=statement(t.profile(),&raw,nonce,45);
        assert!(verify(t.profile(),Sha256::digest(&raw).into(),&raw,nonce,&m,&sign(&m)).is_err());
        // Reserved fields and CLEAR_STCLEAR are invalid for a counter public
        // area even when a software AK genuinely signs its exact selected Name.
        for invalid in [0x100,0x00100000,0x01000000,0x08000000] {
            let raw=public(0x10|invalid);let m=statement(t.profile(),&raw,nonce,45);
            assert!(verify(t.profile(),Sha256::digest(&raw).into(),&raw,nonce,&m,&sign(&m)).is_err());
        }
        let raw=public(0x10);let pin=Sha256::digest(&raw).into();let m=statement(t.profile(),&raw,nonce,45);
        for n in [0,1,m.len()-1]{assert!(verify(t.profile(),pin,&raw,nonce,&m[..n],&sign(&m)).is_err());}
        let mut trailing=m.clone();trailing.push(0);
        assert!(verify(t.profile(),pin,&raw,nonce,&trailing,&sign(&trailing)).is_err());
        let mut offset=m.clone();let at=offset.len()-12;offset[at+1]=1;
        assert!(verify(t.profile(),pin,&raw,nonce,&offset,&sign(&offset)).is_err());
    }
}
