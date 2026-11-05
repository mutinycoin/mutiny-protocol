//! Ed448-only Worker authentication under a dedicated session domain.
//! Worker private signing remains device-local; this module only verifies.
use crate::{Error, Result};
use sha2::{Digest, Sha512};
pub const WORKER_SESSION_DOMAIN: &[u8] = b"MUTINY-BUILD8-WORKER-SESSION-POSSESSION-V2";

pub fn intent(transcript: &[u8; 64]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(WORKER_SESSION_DOMAIN);
    h.update([0]);
    h.update(transcript);
    h.finalize().into()
}
pub fn verify(public: &[u8; 57], transcript: &[u8; 64], signature: &[u8; 114]) -> Result<()> {
    let message = intent(transcript);
    if unsafe {
        crate::build8_qual_ed448_verify(
            public.as_ptr(),
            57,
            signature.as_ptr(),
            114,
            message.as_ptr(),
            64,
        )
    } != 1
    {
        return Err(Error::Signature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_fixture_worker_session_signature_is_not_enrollment_or_other_context() {
        let seed = [42u8; 57]; // Public synthetic test seed; never production provisioning.
        let mut public = [0u8; 57];
        let mut signature = [0u8; 114];
        let transcript = [19; 64];
        assert_eq!(
            unsafe {
                crate::ossl_ed448_public_from_private(
                    std::ptr::null_mut(),
                    public.as_mut_ptr(),
                    seed.as_ptr(),
                    std::ptr::null(),
                )
            },
            1
        );
        let message = intent(&transcript);
        assert_eq!(
            unsafe {
                crate::ossl_ed448_sign(
                    std::ptr::null_mut(),
                    signature.as_mut_ptr(),
                    message.as_ptr(),
                    64,
                    public.as_ptr(),
                    seed.as_ptr(),
                    std::ptr::null(),
                    0,
                    0,
                    std::ptr::null(),
                )
            },
            1
        );
        verify(&public, &transcript, &signature).unwrap();
        for i in 0..64 {
            let mut wrong = transcript;
            wrong[i] ^= 1;
            assert!(verify(&public, &wrong, &signature).is_err());
        }
        let mut wrong = signature;
        wrong[0] ^= 1;
        assert!(verify(&public, &transcript, &wrong).is_err());
        assert!(verify(&[0; 57], &transcript, &signature).is_err());
        let mut h = Sha512::new();
        h.update(crate::enrollment::POSSESSION_DOMAIN);
        h.update([0]);
        h.update(transcript);
        let other: [u8; 64] = h.finalize().into();
        assert_eq!(
            unsafe {
                crate::build8_qual_ed448_verify(
                    public.as_ptr(),
                    57,
                    signature.as_ptr(),
                    114,
                    other.as_ptr(),
                    64,
                )
            },
            0
        );
        let mut enrollment_signature = [0; 114];
        assert_eq!(
            unsafe {
                crate::ossl_ed448_sign(
                    std::ptr::null_mut(),
                    enrollment_signature.as_mut_ptr(),
                    other.as_ptr(),
                    64,
                    public.as_ptr(),
                    seed.as_ptr(),
                    std::ptr::null(),
                    0,
                    0,
                    std::ptr::null(),
                )
            },
            1
        );
        assert!(verify(&public, &transcript, &enrollment_signature).is_err());
        if let Ok(path) = std::env::var("BUILD8_PUBLIC_WORKER_AUTH_VECTOR") {
            let vector = serde_json::json!({"synthetic_only":true,"production_authorized":false,
                "public":hex::encode(public),"transcript":hex::encode(transcript),
                "intent":hex::encode(message),"signature":hex::encode(signature)});
            use std::io::Write;
            std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap()
                .write_all(serde_json::to_string_pretty(&vector).unwrap().as_bytes()).unwrap();
        }
    }
}
