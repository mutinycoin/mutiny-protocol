//! Explicit software-simulator Policy-A interoperability controls, NOT an
//! automatic test, factory, hardware discovery or provisioning path. Caller
//! owns/pins disposable local simulator process/ports and exact software-only
//! public objects. No MakeCredential/TPM call occurs during source preparation.
use super::{linux_tools::{ToolPin,SoftwareMakeCredential,PolicySecretSimulatorEndpoint},Error,Result};
use mutiny_consensus_v8::activation_attestation_v1::{MakeCredential,EncryptedCredential};
use std::path::PathBuf;
use zeroize::Zeroizing;
pub struct PolicyInput {
    pub tool:PathBuf,pub tool_sha256:[u8;32],pub simulator_port:u16,
    pub ak_handle:u32,pub ek_handle:u32,pub ak_public:Vec<u8>,pub ek_public:Vec<u8>,pub different_ek_public:Vec<u8>,
}
/// Public counts only. Neither secret bytes nor their hashes are returned.
pub struct PolicyReceipt {pub tool_sha256:[u8;32],pub positive_roundtrips:u32,
    pub activation_command_refusals:u32,pub pre_dispatch_refusals:u32}
pub fn run_explicit_software(input:PolicyInput)->Result<PolicyReceipt>{
    let actual=mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(&input.ek_public).map_err(|_|Error::Context)?;
    let other=mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(&input.different_ek_public).map_err(|_|Error::Context)?;
    if actual.key.identity().map_err(|_|Error::Context)?==other.key.identity().map_err(|_|Error::Context)?{return Err(Error::Context);}
    let name=mutiny_consensus_v8::provenance::ak_name(&input.ak_public).map_err(|_|Error::Context)?;
    let mut maker=SoftwareMakeCredential::test_only(ToolPin::open_static_test(&input.tool,input.tool_sha256)?);
    let mut endpoint=PolicySecretSimulatorEndpoint::test_only(ToolPin::open_static_test(&input.tool,input.tool_sha256)?,
        input.simulator_port,input.ak_handle,input.ek_handle,input.ak_public,input.ek_public.clone())?;
    let mut secret=Zeroizing::new([0;32]);mutiny_crypto_v2::fill_os_random(secret.as_mut()).map_err(|_|Error::Response)?;
    if *secret==[0;32]{return Err(Error::Response);}
    let first=maker.make_credential(&input.ek_public,&name,&secret).map_err(|_|Error::ToolIo)?;
    if *endpoint.activate(&name,&first)?!=*secret{return Err(Error::Response);}
    let second=maker.make_credential(&input.ek_public,&name,&secret).map_err(|_|Error::ToolIo)?;
    if (first.credential(),first.encrypted_seed())==(second.credential(),second.encrypted_seed()){return Err(Error::Response);}
    if *endpoint.activate(&name,&second)?!=*secret{return Err(Error::Response);}
    let mut wrong_name=name;wrong_name[2]^=1;
    let wrong_ak=maker.make_credential(&input.ek_public,&wrong_name,&secret).map_err(|_|Error::ToolIo)?;
    if !matches!(endpoint.activate(&name,&wrong_ak),Err(Error::ActivationRejected)){return Err(Error::Response);}
    let wrong_ek=maker.make_credential(&input.different_ek_public,&name,&secret).map_err(|_|Error::ToolIo)?;
    if !matches!(endpoint.activate(&name,&wrong_ek),Err(Error::ActivationRejected)){return Err(Error::Response);}
    let mut corrupt=first.credential().to_vec();*corrupt.last_mut().ok_or(Error::Bounds)?^=1;
    let corrupt=EncryptedCredential::new(corrupt,first.encrypted_seed().to_vec()).map_err(|_|Error::Bounds)?;
    if !matches!(endpoint.activate(&name,&corrupt),Err(Error::ActivationRejected)){return Err(Error::Response);}
    if !matches!(endpoint.activate(&wrong_name,&first),Err(Error::Endpoint)){return Err(Error::Response);}
    // Positive after all refusals uses SAME original objects/context. This is
    // not simulator process restart, restored state, physical TPM or factory.
    if *endpoint.activate(&name,&first)?!=*secret{return Err(Error::Response);}
    Ok(PolicyReceipt{tool_sha256:input.tool_sha256,positive_roundtrips:3,
        activation_command_refusals:3,pre_dispatch_refusals:1})
}
