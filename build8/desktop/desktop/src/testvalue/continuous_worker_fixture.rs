//! EXTERNAL SOURCE ONLY. One fixed PUBLIC SOFTWARE TEST Worker possession key.
//! Narrow provenance port: desktop/src/wallet_host_fixture_licenses.rs worker/sign
//! Worker-proof section; no owner HybridKey, owner signature or provisioning API.
//! This cannot qualify a physical TPM or grant license ownership/mining weight.
use mutiny_crypto_v2::enrollment::Binding;
use std::ffi::{c_char,c_void};
pub const WORKER_FIXTURE_MARKER:&str="MUTINY-W15-NONSHIPPING-PUBLIC-SOFTWARE-WORKER-POSSESSION-V1";
const PUBLIC_SEED:[u8;57]=[0x71;57];
unsafe extern "C" {
    fn ossl_ed448_public_from_private(ctx:*mut c_void,out:*mut u8,seed:*const u8,prop:*const c_char)->i32;
    fn ossl_ed448_sign(ctx:*mut c_void,out:*mut u8,msg:*const u8,n:usize,pk:*const u8,sk:*const u8,domain:*const u8,domain_n:usize,ph:u8,prop:*const c_char)->i32;
}
pub fn public()->Result<[u8;57],String>{
    let mut out=[0;57];if unsafe{ossl_ed448_public_from_private(std::ptr::null_mut(),out.as_mut_ptr(),PUBLIC_SEED.as_ptr(),std::ptr::null())}!=1{return Err("Public software Worker fixture derivation failed".into());}Ok(out)
}
pub fn possession(binding:&Binding)->Result<[u8;114],String>{
    if binding.worker_public!=public()?{return Err("Exact fixed public TEST Worker required".into());}
    let intent=binding.possession_intent().map_err(|e|format!("{e:?}"))?;
    let mut signature=[0;114];
    if unsafe{ossl_ed448_sign(std::ptr::null_mut(),signature.as_mut_ptr(),intent.as_ptr(),intent.len(),binding.worker_public.as_ptr(),PUBLIC_SEED.as_ptr(),std::ptr::null(),0,0,std::ptr::null())}!=1{return Err("Public software Worker possession failed".into());}
    binding.verify_worker_possession(&signature).map_err(|e|format!("{e:?}"))?;Ok(signature)
}
