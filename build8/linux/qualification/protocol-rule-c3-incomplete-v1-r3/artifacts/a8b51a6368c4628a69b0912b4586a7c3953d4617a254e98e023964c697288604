use crate::{Error, Result};
use zeroize::Zeroizing;
unsafe extern "C" {
    fn ossl_x448_public_from_private(out: *mut u8, private: *const u8);
    fn ossl_x448(out: *mut u8, private: *const u8, peer: *const u8) -> i32;
    fn build8_transport_mlkem1024_keypair_derand(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    fn build8_transport_mlkem1024_enc_derand(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        seed: *const u8,
    ) -> i32;
    fn build8_transport_mlkem1024_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}
pub(crate) fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0u8; N]);
    mutiny_crypto_v2::fill_os_random(out.as_mut()).map_err(|_| Error::Crypto)?;
    Ok(out)
}
pub(crate) struct X448 {
    private: Zeroizing<[u8; 56]>,
    pub public: [u8; 56],
}
impl X448 {
    pub fn generate() -> Result<Self> {
        mutiny_crypto_v2::protect_process().map_err(|_| Error::Crypto)?;
        let private = random()?;
        let mut public = [0u8; 56];
        unsafe { ossl_x448_public_from_private(public.as_mut_ptr(), private.as_ptr()) };
        Ok(Self { private, public })
    }
    pub fn agree(&self, peer: &[u8; 56]) -> Result<Zeroizing<[u8; 56]>> {
        let mut out = Zeroizing::new([0u8; 56]);
        if unsafe { ossl_x448(out.as_mut_ptr(), self.private.as_ptr(), peer.as_ptr()) } != 1 {
            return Err(Error::Crypto);
        }
        if out.iter().fold(0u8, |a, b| a | b) == 0 {
            return Err(Error::Crypto);
        }
        Ok(out)
    }
}
pub(crate) struct Kem {
    private: Zeroizing<[u8; 3168]>,
    pub public: [u8; 1568],
}
impl Kem {
    pub fn generate() -> Result<Self> {
        mutiny_crypto_v2::protect_process().map_err(|_| Error::Crypto)?;
        let seed = random::<64>()?;
        let mut private = Zeroizing::new([0u8; 3168]);
        let mut public = [0u8; 1568];
        if unsafe {
            build8_transport_mlkem1024_keypair_derand(
                public.as_mut_ptr(),
                private.as_mut_ptr(),
                seed.as_ptr(),
            )
        } != 0
        {
            return Err(Error::Crypto);
        }
        Ok(Self { private, public })
    }
    pub fn decapsulate(&self, ct: &[u8; 1568]) -> Result<Zeroizing<[u8; 32]>> {
        let mut out = Zeroizing::new([0u8; 32]);
        if unsafe {
            build8_transport_mlkem1024_dec(out.as_mut_ptr(), ct.as_ptr(), self.private.as_ptr())
        } != 0
        {
            return Err(Error::Crypto);
        }
        Ok(out)
    }
}
pub(crate) fn encapsulate(pk: &[u8; 1568]) -> Result<([u8; 1568], Zeroizing<[u8; 32]>)> {
    let seed = random::<32>()?;
    let mut ct = [0u8; 1568];
    let mut ss = Zeroizing::new([0u8; 32]);
    if unsafe {
        build8_transport_mlkem1024_enc_derand(
            ct.as_mut_ptr(),
            ss.as_mut_ptr(),
            pk.as_ptr(),
            seed.as_ptr(),
        )
    } != 0
    {
        return Err(Error::Crypto);
    }
    Ok((ct, ss))
}
