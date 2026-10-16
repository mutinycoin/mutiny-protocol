//! Windows DPAPI protect/unprotect for the V2 vault (outer custody layer).
//!
//! Moved out of the retired V1 wallet module so that V2 custody no longer reaches into V1 code.
//! DPAPI authenticates the ciphertext and binds it to the current Windows user. The caller's
//! `entropy` is DPAPI "optional entropy" (the V2 vault passes its identity-bound context); it is
//! never a stored password verifier. Inputs and entropy are bounded, the UI is forbidden, and the
//! plaintext returned by Windows is copied into a zeroizing buffer before the Windows allocation
//! is wiped and freed.
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, &'static str>;
const MAX_INPUT: usize = 65536;
const MAX_ENTROPY: usize = 256;

#[cfg(windows)]
pub(crate) fn dpapi(input: &[u8], entropy: &[u8], encrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    if input.is_empty() || input.len() > MAX_INPUT || entropy.len() > MAX_ENTROPY {
        return Err("Wallet protection input exceeds its bound");
    }
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};
    use zeroize::Zeroize;
    let i = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr() as *mut u8,
    };
    let e = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut o = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // All pointers remain valid for the call. Windows owns the output allocation.
    unsafe {
        let ok = if encrypt {
            CryptProtectData(
                &i,
                std::ptr::null(),
                &e,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut o,
            )
        } else {
            CryptUnprotectData(
                &i,
                std::ptr::null_mut(),
                &e,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut o,
            )
        };
        if ok == 0 {
            return Err(
                "Wallet protection failed: wrong password, damaged data, or different Windows account",
            );
        }
        let bytes = std::slice::from_raw_parts_mut(o.pbData, o.cbData as usize);
        let result = Zeroizing::new(bytes.to_vec());
        bytes.zeroize();
        LocalFree(o.pbData.cast());
        Ok(result)
    }
}
// Outside Windows there is no DPAPI: custody storage is refused, as custody_acl_v2 does.
#[cfg(not(windows))]
pub(crate) fn dpapi(_: &[u8], _: &[u8], _: bool) -> Result<Zeroizing<Vec<u8>>> {
    Err("Desktop V2 custody storage requires qualified Windows ACL/DPAPI")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    // Public, non-secret test inputs only; DPAPI CurrentUser protects them for this test process.
    const PLAIN: &[u8] = b"PUBLIC TEST PLAINTEXT, NOT A WALLET";
    const ENTROPY: &[u8] = b"PUBLIC TEST ENTROPY CONTEXT";
    #[test]
    fn round_trip_binds_entropy_and_rejects_corruption() {
        let protected = dpapi(PLAIN, ENTROPY, true).unwrap();
        assert_ne!(protected.as_slice(), PLAIN);
        assert!(!protected.windows(PLAIN.len()).any(|window| window == PLAIN));
        assert_eq!(dpapi(&protected, ENTROPY, false).unwrap().as_slice(), PLAIN);
        // The entropy is part of the binding: a different context cannot unprotect the blob.
        assert!(dpapi(&protected, b"PUBLIC OTHER ENTROPY CONTEXT", false).is_err());
        assert!(dpapi(&protected, b"", false).is_err());
        // Any damaged ciphertext is rejected, never partially decrypted.
        for position in [0, protected.len() / 2, protected.len() - 1] {
            let mut damaged = protected.to_vec();
            damaged[position] ^= 1;
            assert!(
                dpapi(&damaged, ENTROPY, false).is_err(),
                "accepted damage at byte {position}"
            );
        }
        assert!(dpapi(&protected[..protected.len() - 1], ENTROPY, false).is_err());
    }
    #[test]
    fn inputs_are_bounded_before_any_windows_call() {
        assert!(dpapi(&[], ENTROPY, true).is_err());
        assert!(dpapi(&vec![1; MAX_INPUT + 1], ENTROPY, true).is_err());
        assert!(dpapi(PLAIN, &vec![1; MAX_ENTROPY + 1], true).is_err());
        assert!(dpapi(&[], ENTROPY, false).is_err());
        assert!(dpapi(&vec![1; MAX_INPUT + 1], ENTROPY, false).is_err());
        // The bounds themselves are accepted.
        assert!(dpapi(PLAIN, &vec![7; MAX_ENTROPY], true).is_ok());
    }
}
