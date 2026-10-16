//! Wallet creation only. Restore never calls a platform entropy provider.
use crate::{Error, Result, random};
use sha2::Sha512;
use zeroize::Zeroizing;

const SALT: &[u8] = b"MUTINY-BUILD8-WALLET-ENTROPY-EXTRACT-V1\0";
const INFO: &[u8] = b"MUTINY-BUILD8-WALLET-BIP39-ENTROPY-V1\0";

fn extract(os: &[u8; 32], tpm: Option<&[u8; 32]>) -> Result<Zeroizing<[u8; 32]>> {
    // Fixed encoding: version || mandatory OS || TPM-presence || TPM-or-zero.
    let mut input = Zeroizing::new([0u8; 66]);
    input[0] = 1;
    input[1..33].copy_from_slice(os);
    if let Some(tpm) = tpm {
        input[33] = 1;
        input[34..].copy_from_slice(tpm);
    }
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha512>::new(Some(SALT), input.as_ref())
        .expand(INFO, output.as_mut())
        .map_err(|_| Error::Entropy)?;
    Ok(output)
}

// Provider returns a complete TPM response, never a pointer or an unbounded Vec.
fn collect(
    mut submit: impl FnMut(u8, &mut [u8; 44]) -> Result<usize>,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut output = Zeroizing::new([0u8; 32]);
    let mut used = 0;
    for _ in 0..64 {
        let mut response = Zeroizing::new([0u8; 44]);
        let remaining = 32 - used;
        let n = submit(remaining as u8, &mut response)?;
        if !(12..=44).contains(&n)
            || response[0..2] != [0x80, 1]
            || u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize != n
            || response[6..10] != [0, 0, 0, 0]
        {
            return Err(Error::Entropy);
        }
        let count = u16::from_be_bytes(response[10..12].try_into().unwrap()) as usize;
        if count > remaining || count + 12 != n {
            return Err(Error::Entropy);
        }
        output[used..used + count].copy_from_slice(&response[12..n]);
        used += count;
        if used == 32 {
            return Ok(output);
        }
    }
    Err(Error::Entropy)
}

#[cfg(windows)]
fn supplemental() -> Result<Option<Zeroizing<[u8; 32]>>> {
    use std::ffi::c_void;
    unsafe extern "C" {
        fn build8_wallet_tpm_open(out: *mut *mut c_void) -> i32;
        fn build8_wallet_tpm_random(
            context: *mut c_void,
            count: u32,
            out: *mut u8,
            length: *mut u32,
        ) -> i32;
        fn build8_wallet_tpm_close(context: *mut c_void);
    }
    struct Context(*mut c_void);
    impl Drop for Context {
        fn drop(&mut self) {
            unsafe { build8_wallet_tpm_close(self.0) };
        }
    }
    let mut pointer = std::ptr::null_mut();
    match unsafe { build8_wallet_tpm_open(&mut pointer) } {
        0 => return Ok(None),
        1 if !pointer.is_null() => {}
        _ => return Err(Error::Entropy),
    }
    let context = Context(pointer);
    collect(|count, out| {
        let mut length = 44;
        if unsafe {
            build8_wallet_tpm_random(context.0, count.into(), out.as_mut_ptr(), &mut length)
        } != 1
        {
            return Err(Error::Entropy);
        }
        Ok(length as usize)
    })
    .map(Some)
}
#[cfg(not(windows))]
fn supplemental() -> Result<Option<Zeroizing<[u8; 32]>>> {
    // Non-Windows creation is limited to explicit qualification builds.
    if cfg!(any(test, feature = "qualification")) {
        Ok(None)
    } else {
        Err(Error::Entropy)
    }
}

fn gather(
    os: impl FnOnce() -> Result<Zeroizing<[u8; 32]>>,
    tpm: impl FnOnce() -> Result<Option<Zeroizing<[u8; 32]>>>,
) -> Result<Zeroizing<[u8; 32]>> {
    let os = os()?; // Mandatory and first: TPM alone can never create a wallet.
    let tpm = tpm()?;
    extract(&os, tpm.as_deref())
}
pub(super) fn entropy() -> Result<Zeroizing<[u8; 32]>> {
    gather(random::<32>, supplemental)
}

#[cfg(feature = "qualification")]
pub(super) fn qualify_provider() -> Result<bool> {
    let os = random::<32>()?;
    let tpm = supplemental()?;
    let present = tpm.is_some();
    let _conditioned = extract(&os, tpm.as_deref())?;
    Ok(present) // No raw or conditioned entropy leaves this function.
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(out: &mut [u8; 44], bytes: &[u8]) -> usize {
        let n = 12 + bytes.len();
        out[..2].copy_from_slice(&[0x80, 1]);
        out[2..6].copy_from_slice(&(n as u32).to_be_bytes());
        out[10..12].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
        out[12..n].copy_from_slice(bytes);
        n
    }
    #[test]
    fn tpm_partial_reads_are_bounded_and_exact() {
        let mut calls = 0;
        let entropy = collect(|remaining, out| {
            calls += 1;
            assert_eq!(remaining, 33 - calls);
            Ok(response(out, &[calls]))
        })
        .unwrap();
        assert_eq!(calls, 32);
        assert_eq!(&entropy[..], &(1..=32).collect::<Vec<u8>>());
        let mut calls = 0;
        assert!(
            collect(|_, out| {
                calls += 1;
                Ok(response(out, &[]))
            })
            .is_err()
        );
        assert_eq!(calls, 64);
    }
    #[test]
    fn tpm_malformed_or_failed_responses_abort() {
        for field in [0, 1, 2, 5, 6, 9, 10, 11] {
            assert!(
                collect(|_, out| {
                    let n = response(out, &[7; 32]);
                    out[field] ^= 1;
                    Ok(n)
                })
                .is_err()
            );
        }
        for length in [0, 10, 11, 13, 43, 45, usize::MAX] {
            assert!(
                collect(|_, out| {
                    response(out, &[7; 32]);
                    Ok(length)
                })
                .is_err()
            );
        }
        let mut calls = 0;
        assert!(
            collect(|_, out| {
                calls += 1;
                Ok(response(out, &[7; 31]))
            })
            .is_err()
        );
        assert_eq!(calls, 2); // Second response exceeds the one remaining byte.
        assert!(collect(|_, _| Err(Error::Entropy)).is_err());
    }
    #[test]
    fn os_is_mandatory_and_tpm_failure_has_no_fallback() {
        assert!(gather(|| Err(Error::Entropy), || panic!("TPM cannot replace OS")).is_err());
        assert!(gather(|| Ok(Zeroizing::new([1; 32])), || Err(Error::Entropy)).is_err());
        assert!(gather(|| Ok(Zeroizing::new([1; 32])), || Ok(None)).is_ok());
    }
    #[test]
    fn extractor_public_vector_and_provider_separation() {
        let os = [1; 32];
        let tpm = [2; 32];
        let both = extract(&os, Some(&tpm)).unwrap();
        // Independent Python hashlib/HMAC vector, public fixed bytes only.
        assert_eq!(
            hex::encode(both.as_ref()),
            "b19db45ff320ac004312b0582faf6669b0fdf2a659860274f0bfa30d03cc2c69"
        );
        assert_ne!(*both, *extract(&os, None).unwrap());
        assert_ne!(
            *extract(&os, Some(&[0; 32])).unwrap(),
            *extract(&os, None).unwrap()
        );
        assert_ne!(*both, *extract(&tpm, Some(&os)).unwrap());
        let mnemonic = bip39::Mnemonic::from_entropy(both.as_ref()).unwrap();
        assert_eq!(mnemonic.word_count(), 24);
        assert_eq!(mnemonic.to_entropy(), both.to_vec());
    }
}
