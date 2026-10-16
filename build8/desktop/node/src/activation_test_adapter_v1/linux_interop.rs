//! Explicitly invoked interoperability controls; NOT a default test or factory.
//! Requires separately authorized disposable TEST TPM objects and an audited
//! static deployment. No provisioning, clearing, auth change, NV write or signing.
//! No call is made by source preparation or ordinary Node/test initialization.
use super::{linux_tools::{ToolPin,SoftwareMakeCredential,EmptyAuthEndpoint},Error,Result};
use mutiny_consensus_v8::activation_attestation_v1::{MakeCredential,EncryptedCredential};
use std::path::PathBuf;
use zeroize::Zeroizing;
pub struct TestInput {
    pub tool:PathBuf,pub tool_sha256:[u8;32],pub ak_handle:u32,pub ek_handle:u32,
    pub ak_public:Vec<u8>,pub ek_public:Vec<u8>,pub different_ek_public:Vec<u8>,
}
/// Public outcome only; returned secrets, their hashes and tool output are absent.
pub struct InteropReceipt {pub tool_sha256:[u8;32],pub positive_roundtrips:u32,
    pub activation_command_refusals:u32,pub pre_dispatch_refusals:u32}
pub fn run_explicit_test(input:TestInput)->Result<InteropReceipt>{
    if input.ek_public==input.different_ek_public{return Err(Error::Context);}
    // Distinct valid key identity, not merely another encoding/template.
    let actual=mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(&input.ek_public).map_err(|_|Error::Context)?;
    let other=mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(&input.different_ek_public).map_err(|_|Error::Context)?;
    if actual.key.identity().map_err(|_|Error::Context)?==other.key.identity().map_err(|_|Error::Context)? {
        return Err(Error::Context);
    }
    let name=mutiny_consensus_v8::provenance::ak_name(&input.ak_public).map_err(|_|Error::Context)?;
    let mut maker=SoftwareMakeCredential::test_only(ToolPin::open_static_test(&input.tool,input.tool_sha256)?);
    let endpoint=EmptyAuthEndpoint::test_only(ToolPin::open_static_test(&input.tool,input.tool_sha256)?,
        input.ak_handle,input.ek_handle,input.ak_public,input.ek_public.clone())?;
    let mut secret=Zeroizing::new([0;32]);
    mutiny_crypto_v2::fill_os_random(secret.as_mut()).map_err(|_|Error::Response)?;
    if *secret==[0;32]{return Err(Error::Response);}
    let first=maker.make_credential(&input.ek_public,&name,&secret).map_err(|_|Error::ToolIo)?;
    if *endpoint.activate(&name,&first)?!=*secret{return Err(Error::Response);}
    let second=maker.make_credential(&input.ek_public,&name,&secret).map_err(|_|Error::ToolIo)?;
    if (first.credential(),first.encrypted_seed())==(second.credential(),second.encrypted_seed()){
        return Err(Error::Response);
    }
    if *endpoint.activate(&name,&second)?!=*secret{return Err(Error::Response);}
    let mut wrong_name=name;wrong_name[2]^=1;
    let wrong_ak=maker.make_credential(&input.ek_public,&wrong_name,&secret).map_err(|_|Error::ToolIo)?;
    // Correct actual AK argument with ciphertext for a DIFFERENT Name reaches
    // real TPM crypto, rather than merely exercising the local name preflight.
    if !matches!(endpoint.activate(&name,&wrong_ak),Err(Error::ActivationRejected)){return Err(Error::Response);}
    let wrong_ek=maker.make_credential(&input.different_ek_public,&name,&secret).map_err(|_|Error::ToolIo)?;
    if !matches!(endpoint.activate(&name,&wrong_ek),Err(Error::ActivationRejected)){return Err(Error::Response);}
    let mut corrupt=first.credential().to_vec();*corrupt.last_mut().ok_or(Error::Bounds)?^=1;
    let corrupt=EncryptedCredential::new(corrupt,first.encrypted_seed().to_vec()).map_err(|_|Error::Bounds)?;
    if !matches!(endpoint.activate(&name,&corrupt),Err(Error::ActivationRejected)){return Err(Error::Response);}
    if !matches!(endpoint.activate(&wrong_name,&first),Err(Error::Endpoint)){return Err(Error::Response);}
    // Restore a genuine crypto positive AFTER all negatives. A broken endpoint
    // cannot make every negative look like a useful unsafe-acceptance control.
    if *endpoint.activate(&name,&first)?!=*secret{return Err(Error::Response);}
    Ok(InteropReceipt{tool_sha256:input.tool_sha256,positive_roundtrips:3,
        activation_command_refusals:3,pre_dispatch_refusals:1})
}
