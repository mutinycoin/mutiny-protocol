// ISOLATED QUALIFICATION ONLY. Not included in the main pinned library.
use super::*;
use flr::FLR;

fn bits(x: FLR) -> u64 { u64::from_le_bytes(x.encode()) }
fn abs_bits(x: FLR) -> u64 { bits(x) & 0x7fff_ffff_ffff_ffff }
fn supported_input(x: FLR) -> bool {
    let b=abs_bits(x); let e=b>>52;
    (b==0) | ((e!=0) & (e!=2047))
}

// Sufficient exact-product domain predicate, before invoking emulated multiply.
// Its upper restriction (<2^1023) is much wider than all proven Gram/LDL bounds.
// Rejects subnormals/NaNs/infinities as inputs, including when paired with zero.
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
    assert!(supported_input(z) && supported_input(d));
    Some((mr,-mi,d))
}

#[test]
fn build8_preflight_product_domain_boundaries() {
    // Synthetic IEEE-754 patterns only. Native multiply is an independent
    // normal-result oracle here; these are not secret production operands.
    let mantissas=[0,1,(1u64<<51)-1,1u64<<51,(1u64<<52)-2,(1u64<<52)-1];
    let mut checked=0usize;
    for ex in 1i32..=2046 {
        for sum in [1023i32,1024,1025,2046,3067,3068,3069,3070] {
            let ey=sum-ex;
            if !(1..=2046).contains(&ey) {continue;}
            for mx in mantissas { for my in mantissas {
                let xb=((ex as u64)<<52)|mx; let yb=((ey as u64)<<52)|my;
                let x=FLR::decode(&xb.to_le_bytes()).unwrap();
                let y=FLR::decode(&yb.to_le_bytes()).unwrap();
                if product_supported(x,y) {
                    let native=f64::from_bits(xb)*f64::from_bits(yb);
                    assert!(native.is_normal());
                    assert_eq!(bits(x*y),native.to_bits());
                }
                checked+=1;
            }}
        }
    }
    for bad in [1u64,0x000f_ffff_ffff_ffff,0x7ff0_0000_0000_0000,0x7ff8_0000_0000_0001] {
        let x=FLR::decode(&bad.to_le_bytes()).unwrap();
        assert!(!product_supported(x,FLR::ZERO));
        assert!(!product_supported(FLR::ONE,x));
    }
    assert!(product_supported(FLR::NZERO,FLR::ONE));
    assert!(checked>300_000);
}

#[test]
fn build8_preflight_rejects_before_unsupported_product() {
    let tiny=FLR::scaled(1,-600);
    assert!(product_supported(tiny,FLR::ONE));
    assert!(!product_supported(tiny,tiny));
    assert!(initial_preflight(FLR::ONE,tiny,FLR::ZERO,FLR::ONE).is_none());
    assert!(initial_preflight(FLR::scaled(1,23),FLR::scaled(1,-1010),FLR::ZERO,FLR::ONE).is_none());
    let signed=initial_preflight(FLR::ONE,FLR::scaled(-1,-2),FLR::scaled(1,-2),FLR::ONE).unwrap();
    assert_eq!(bits(signed.0),bits(FLR::scaled(-1,-2)));
    assert_eq!(bits(signed.1),bits(FLR::scaled(-1,-2)));
    assert_eq!(bits(signed.2),bits(FLR::scaled(7,-3)));
    let x=initial_preflight(FLR::ONE,FLR::ZERO,FLR::NZERO,FLR::ONE).unwrap();
    assert_eq!(abs_bits(x.0),0);assert_eq!(abs_bits(x.1),0);assert_eq!(bits(x.2),bits(FLR::ONE));
}

#[test]
fn build8_preflight_synthetic_key_gram_equivalence() {
    use fn_dsa_kgen::{KeyPairGenerator,KeyPairGenerator1024};
    struct PublicSeed { seed:[u8;32], used:bool }
    impl CryptoRng for PublicSeed {}
    impl RngCore for PublicSeed {
        fn next_u32(&mut self)->u32 {panic!("seed contract")}
        fn next_u64(&mut self)->u64 {panic!("seed contract")}
        fn fill_bytes(&mut self,dst:&mut[u8]) {
            assert!(!self.used);assert_eq!(dst.len(),32);
            dst.copy_from_slice(&self.seed);self.used=true;
        }
        fn try_fill_bytes(&mut self,dst:&mut[u8])->Result<(),RngError> {self.fill_bytes(dst);Ok(())}
    }
    // One public 32-byte seed per key, consumed by the existing key generator.
    // No private material or detailed secret-derived traces are printed.
    for index in 0u8..16 {
        let mut seed=[0xA7u8;32];seed[0]=index;seed[1]=0xB8;
        let mut rng=PublicSeed{seed,used:false};
        let mut secret=[0u8;2369];let mut public=[0u8;1793];
        KeyPairGenerator1024::default().keygen(10,&mut rng,&mut secret,&mut public);
        let key=SigningKey1024::decode(&secret).unwrap();
        let (b00,rest)=key.basis.split_at(1024);
        let (b01,rest)=rest.split_at(1024);let (b10,b11)=rest.split_at(1024);
        let mut a=[FLR::ZERO;1024];let mut c=a;let mut b=a;let mut t=a;
        a.copy_from_slice(b00);poly::poly_mulownadj_fft(10,&mut a);
        t.copy_from_slice(b01);poly::poly_mulownadj_fft(10,&mut t);poly::poly_add(10,&mut a,&t);
        c.copy_from_slice(b00);poly::poly_muladj_fft(10,&mut c,b10);
        t.copy_from_slice(b01);poly::poly_muladj_fft(10,&mut t,b11);poly::poly_add(10,&mut c,&t);
        b.copy_from_slice(b10);poly::poly_mulownadj_fft(10,&mut b);
        t.copy_from_slice(b11);poly::poly_mulownadj_fft(10,&mut t);poly::poly_add(10,&mut b,&t);
        let before_c=c;let before_b=b;
        let mut expected=[(FLR::ZERO,FLR::ZERO,FLR::ZERO);512];
        for i in 0..512 {expected[i]=initial_preflight(a[i],c[i],c[i+512],b[i]).unwrap();}
        // Compare only after every preflight passed, so no unsupported path is
        // executed even if this synthetic corpus were to expose one.
        poly::poly_LDL_fft(10,&a,&mut c,&mut b);
        for i in 0..512 {
            assert_eq!((bits(c[i]),bits(c[i+512]),bits(b[i])),
                (bits(expected[i].0),bits(expected[i].1),bits(expected[i].2)));
            assert!(initial_preflight(a[i],FLR::scaled(1,-600),before_c[i+512],before_b[i]).is_none());
        }
        secret.zeroize();seed.zeroize();
    }
}

#[test]
fn build8_preflight_integrated_basis_fault_returns_no_signature() {
    use fn_dsa_kgen::{KeyPairGenerator,KeyPairGenerator1024};
    struct FixedSeed { seed:[u8;40], used:bool }
    impl CryptoRng for FixedSeed {}
    impl RngCore for FixedSeed {
        fn next_u32(&mut self)->u32 {panic!("seed contract")}
        fn next_u64(&mut self)->u64 {panic!("seed contract")}
        fn fill_bytes(&mut self,dst:&mut[u8]) {
            assert!(!self.used);assert!(dst.len()==32 || dst.len()==40);
            dst.copy_from_slice(&self.seed[..dst.len()]);self.used=true;
        }
        fn try_fill_bytes(&mut self,dst:&mut[u8])->Result<(),RngError>{self.fill_bytes(dst);Ok(())}
    }
    let mut rng=FixedSeed{seed:[0xB8;40],used:false};
    let mut secret=[0u8;2369];let mut public=[0u8;1793];
    KeyPairGenerator1024::default().keygen(10,&mut rng,&mut secret,&mut public);
    let mut key=SigningKey1024::decode(&secret).unwrap();
    key.basis.fill(FLR::ZERO); // Synthetic memory-fault injection only.
    let mut srng=FixedSeed{seed:[0xA7;40],used:false};let mut sig=[0xA5u8;1280];
    assert!(key.sign(&mut srng,&DOMAIN_NONE,&HASH_ID_RAW,b"public fault fixture",&mut sig).is_none());
    assert_eq!(sig,[0xA5u8;1280]);
    secret.zeroize();
}
