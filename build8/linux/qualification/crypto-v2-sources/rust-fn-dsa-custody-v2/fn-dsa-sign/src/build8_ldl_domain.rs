// ISOLATED BUILD8 SIGNER CANDIDATE: key-only initial LDL domain preflight.
use super::flr::FLR;

fn bits(x: FLR) -> u64 { u64::from_le_bytes(x.encode()) }
fn abs_bits(x: FLR) -> u64 { bits(x) & 0x7fff_ffff_ffff_ffff }
// Preserve the reviewed predicate boundary: inlining introduced zero-dependent
// branches in the linked V1 preflight. Recheck this in final target artifacts.
#[inline(never)]
fn supported_input(x: FLR) -> bool {
    let b=abs_bits(x); let e=b>>52;
    (b==0) | ((e!=0) & (e!=2047))
}

// Sufficient exact-product domain predicate, before invoking emulated multiply.
// Its upper restriction (<2^1023) is much wider than all proven Gram/LDL bounds.
// Rejects subnormals/NaNs/infinities as inputs, including when paired with zero.
// Preserve the reviewed predicate boundary: inlining introduced zero-dependent
// branches in the linked V1 preflight. Recheck this in final target artifacts.
#[inline(never)]
fn product_supported(x: FLR, y: FLR) -> bool {
    let inputs_valid=supported_input(x) & supported_input(y);
    let xb=abs_bits(x); let yb=abs_bits(y);
    let xm=(xb & ((1u64<<52)-1)) | (1u64<<52);
    let ym=(yb & ((1u64<<52)-1)) | (1u64<<52);
    let product=(xm as u128)*(ym as u128);
    let carry=(product>>105) as i32;
    let exponent=(xb>>52) as i32+(yb>>52) as i32-2046+carry;
    inputs_valid & ((xb==0) | (yb==0) | ((exponent>=-1022) & (exponent<=1022)))
}

fn initial_preflight(a:FLR, cr:FLR, ci:FLR, b:FLR)->Option<(FLR,FLR,FLR)> {
    // Bounds follow from the separately reviewed degree-1024 import/basis
    // preconditions. Invalid input fails; no sample/value is clamped.
    if [a,cr,ci,b].into_iter().any(|v|!supported_input(v)) { return None; }
    if bits(a)>>63!=0 || bits(b)>>63!=0 { return None; }
    let lo=abs_bits(FLR::scaled(1,-7));
    if abs_bits(a)<=lo || abs_bits(a)>=abs_bits(FLR::scaled(1,24)) { return None; }
    if abs_bits(b)<=lo || abs_bits(b)>=abs_bits(FLR::scaled(1,34)) { return None; }
    let cmax=abs_bits(FLR::scaled(1,29));
    if abs_bits(cr)>=cmax || abs_bits(ci)>=cmax { return None; }
    let inv=FLR::ONE/a;
    if !product_supported(cr,inv) || !product_supported(ci,inv) { return None; }
    let mr=cr*inv; let mi=ci*inv;
    if !product_supported(mr,cr) || !product_supported(mi,ci) { return None; }
    let z=mr*cr+mi*ci;
    let d=b-z;
    if !supported_input(z) || !supported_input(d) || bits(d)>>63!=0 || abs_bits(d)==0 { return None; }
    Some((mr,-mi,d))
}


// Qualification scope is the Build8 degree-1024 integer backend. Other upstream
// degrees remain outside this guard's claimed profile; no production use implied.
pub(super) fn initial_ldl_domain(logn:u32,gram:&[FLR])->bool {
    if logn!=10 {return true;}
    let n=1usize<<logn;
    if gram.len()<3*n {return false;}
    let a=&gram[..n];let c=&gram[n..2*n];let b=&gram[2*n..3*n];
    for i in 0..n/2 {
        if initial_preflight(a[i],c[i],c[i+n/2],b[i]).is_none() {return false;}
    }
    true
}
