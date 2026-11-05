//! Portable encrypted custody. The only private export is an authenticated,
//! password-encrypted envelope. File permissions/atomic storage belong to the UI.
use super::*;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInPlace};

const LIMIT: usize = 8192;
fn password_key(password: &str, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    private_job(|| {
        let params = argon2::Params::new(65536, 3, 1, Some(32)).map_err(|_| Error::Custody)?;
        let mut blocks = Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
        let mut key = Zeroizing::new([0; 32]);
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into_with_memory(
                password.as_bytes(),
                salt,
                key.as_mut(),
                blocks.as_mut_slice(),
            )
            .map_err(|_| Error::Custody)?;
        Ok(key)
    })
}
fn header(
    public: &PublicKey,
    generation: u64,
    salt: &[u8; 32],
    nonce: &[u8; 24],
    context: &[u8],
) -> Result<Vec<u8>> {
    if generation == 0 || context.len() > 256 {
        return Err(Error::Encoding);
    }
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(8)
        .unwrap()
        .str("MUTINY-HYBRID-ENCRYPTED-CUSTODY-V1")
        .unwrap()
        .u8(public.role as u8)
        .unwrap()
        .u64(generation)
        .unwrap()
        .bytes(&public.ed448)
        .unwrap()
        .bytes(&public.fndsa)
        .unwrap()
        .bytes(salt)
        .unwrap()
        .bytes(nonce)
        .unwrap()
        .bytes(context)
        .unwrap();
    Ok(e.into_writer())
}
impl HybridKey {
    pub fn seal(&self, password: &str, generation: u64) -> Result<Vec<u8>> {
        self.seal_for(password, generation, &[])
    }
    pub fn seal_for(&self, password: &str, generation: u64, context: &[u8]) -> Result<Vec<u8>> {
        if password.chars().count() < 12 || password.len() > 4096 {
            return Err(Error::Password);
        }
        let salt = random::<32>()?;
        let nonce = random::<24>()?;
        let aad = header(&self.public, generation, &salt, &nonce, context)?;
        let key = password_key(password, &salt)?;
        // Retain erasing ownership throughout encryption, including errors.
        // Reserve the tag capacity before any private bytes enter the buffer.
        let mut plaintext = Zeroizing::new(Vec::with_capacity(2426 + 16));
        plaintext.extend_from_slice(self.ed_seed.as_ref());
        plaintext.extend_from_slice(&self.fn_secret);
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| Error::Custody)?
            .encrypt_in_place(XNonce::from_slice(nonce.as_ref()), &aad, &mut *plaintext)
            .map_err(|_| Error::Custody)?;
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&aad)
            .unwrap()
            .bytes(&plaintext)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn open(expected_role: Role, password: &str, encoded: &[u8]) -> Result<(Self, u64)> {
        Self::open_for(expected_role, password, &[], encoded)
    }
    pub fn open_for(
        expected_role: Role,
        password: &str,
        context: &[u8],
        encoded: &[u8],
    ) -> Result<(Self, u64)> {
        expected_role.private_allowed()?;
        protect_process()?;
        if encoded.len() > LIMIT || password.len() > 4096 || context.len() > 256 {
            return Err(Error::Encoding);
        }
        let mut d = minicbor::Decoder::new(encoded);
        if d.array().map_err(|_| Error::Encoding)? != Some(2) {
            return Err(Error::Encoding);
        }
        let aad = d.bytes().map_err(|_| Error::Encoding)?;
        let ciphertext = d.bytes().map_err(|_| Error::Encoding)?;
        if d.position() != encoded.len() || ciphertext.len() != 2426 + 16 || aad.len() > 2304 {
            return Err(Error::Encoding);
        }
        let mut h = minicbor::Decoder::new(aad);
        if h.array().map_err(|_| Error::Encoding)? != Some(8)
            || h.str().map_err(|_| Error::Encoding)? != "MUTINY-HYBRID-ENCRYPTED-CUSTODY-V1"
            || h.u8().map_err(|_| Error::Encoding)? != expected_role as u8
        {
            return Err(Error::Role);
        }
        let generation = h.u64().map_err(|_| Error::Encoding)?;
        let public = PublicKey {
            role: expected_role,
            ed448: h
                .bytes()
                .map_err(|_| Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
            fndsa: h
                .bytes()
                .map_err(|_| Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
        };
        let salt: [u8; 32] = h
            .bytes()
            .map_err(|_| Error::Encoding)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        let nonce: [u8; 24] = h
            .bytes()
            .map_err(|_| Error::Encoding)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        if h.bytes().map_err(|_| Error::Encoding)? != context {
            return Err(Error::Role);
        }
        if h.position() != aad.len() || header(&public, generation, &salt, &nonce, context)? != aad
        {
            return Err(Error::Encoding);
        }
        let mut canonical = minicbor::Encoder::new(Vec::new());
        canonical
            .array(2)
            .unwrap()
            .bytes(aad)
            .unwrap()
            .bytes(ciphertext)
            .unwrap();
        if canonical.into_writer() != encoded {
            return Err(Error::Encoding);
        }
        public.validate()?;
        let key = password_key(password, &salt)?;
        // Authenticate and decrypt inside an already erasing owner. Never
        // receive plaintext through the allocating AEAD convenience API.
        let mut plain = Zeroizing::new(ciphertext.to_vec());
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| Error::Custody)?
            .decrypt_in_place(XNonce::from_slice(&nonce), aad, &mut *plain)
            .map_err(|_| Error::Custody)?;
        if plain.len() != 2426 {
            return Err(Error::Custody);
        }
        let mut ed_seed = Zeroizing::new([0; 57]);
        ed_seed.copy_from_slice(&plain[..57]);
        let key = Self {
            ed_seed,
            fn_secret: Zeroizing::new(plain[57..].to_vec()),
            public,
        };
        private_job(|| key.checked_fn().map(|_| ()))?;
        let mut ed = [0; 57];
        if unsafe {
            ossl_ed448_public_from_private(
                std::ptr::null_mut(),
                ed.as_mut_ptr(),
                key.ed_seed.as_ptr(),
                std::ptr::null(),
            )
        } != 1
            || ed != key.public.ed448
        {
            return Err(Error::Key);
        }
        Ok((key, generation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{Aead, Payload};

    #[test]
    fn in_place_custody_preserves_previous_envelope_compatibility() {
        let original = HybridKey::generate(Role::Release).unwrap();
        let password = "PUBLIC COMPATIBILITY PASSWORD";
        let salt = [31u8; 32];
        let nonce = [32u8; 24];
        let context = b"PUBLIC SYNTHETIC CUSTODY CONTEXT";
        let aad = header(original.public(), 9, &salt, &nonce, context).unwrap();
        let key = password_key(password, &salt).unwrap();
        let mut secret = Zeroizing::new(Vec::with_capacity(2426));
        secret.extend_from_slice(original.ed_seed.as_ref());
        secret.extend_from_slice(&original.fn_secret);
        // Historical allocating API is test-only. Its ciphertext must remain
        // readable by the new in-place path, under the same authenticated header.
        let encrypted = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .unwrap()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &secret,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&aad)
            .unwrap()
            .bytes(&encrypted)
            .unwrap();
        let legacy = e.into_writer();
        let (restored, generation) =
            HybridKey::open_for(Role::Release, password, context, &legacy).unwrap();
        assert_eq!(generation, 9);
        assert_eq!(restored.public(), original.public());
        assert!(restored.ed_seed.as_ref() == original.ed_seed.as_ref());
        assert!(restored.fn_secret.as_slice() == original.fn_secret.as_slice());

        let current = original.seal_for(password, 10, context).unwrap();
        let mut d = minicbor::Decoder::new(&current);
        assert_eq!(d.array().unwrap(), Some(2));
        let aad = d.bytes().unwrap();
        let ciphertext = d.bytes().unwrap();
        let mut h = minicbor::Decoder::new(aad);
        assert_eq!(h.array().unwrap(), Some(8));
        h.str().unwrap();
        h.u8().unwrap();
        h.u64().unwrap();
        h.bytes().unwrap();
        h.bytes().unwrap();
        let salt: [u8; 32] = h.bytes().unwrap().try_into().unwrap();
        let nonce = h.bytes().unwrap();
        let key = password_key(password, &salt).unwrap();
        let decoded = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(key.as_ref())
                .unwrap()
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .unwrap(),
        );
        assert!(decoded.as_slice() == secret.as_slice());
    }
}
