//! Candidate hybrid wallet custody. No filesystem/default-wallet lookup, no
//! legacy-key import, no private-key export and no production-gate bypass.
use mutiny_consensus_v8::{Hash, state_proof::VerifiedWalletAuthority};
use mutiny_crypto_v2::{HybridKey, NETWORK, PublicKey, Role, WALLET_CRYPTO_SUITE_ID};
use mutiny_wallet_core_v8::{
    KeySigner, Refusal, SignerIdentity, SigningGate, ops::rotation::RotationSigner,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::time::Duration;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, &'static str>;
const MAX_VAULT: usize = 32 * 1024;
/// The custody gate as a pure function, so a test build can prove what every non-test build
/// does: it refuses unless the shared production qualification constant is true. A test build
/// is the only other way through. No other input opens it.
pub(crate) const fn gate_closed(test_build: bool, production_qualified: bool) -> bool {
    !test_build && !production_qualified
}
// Compile-time pin of the gate's logic itself (the constant is pinned by a test below).
const _: () = assert!(gate_closed(false, false) && !gate_closed(true, false));
const _: () = assert!(!gate_closed(false, true) && !gate_closed(true, true));
pub(crate) fn ready() -> Result<()> {
    if gate_closed(
        cfg!(test) || cfg!(feature = "testvalue-window"),
        mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED,
    ) {
        return Err("Hybrid wallet production qualification is incomplete");
    }
    mutiny_crypto_v2::protect_process().map_err(|_| "Wallet process protection failed")
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub version: u8,
    pub network: u32,
    pub suite: u16,
    pub generation: u64,
    pub authority_id: String,
    pub address_id: String,
    pub owner_ed448: String,
    pub owner_fndsa1024: String,
    pub owner_descriptor: String,
}
fn hash(raw: &str) -> Result<Hash> {
    hex::decode(raw)
        .map_err(|_| "Invalid wallet identity")?
        .try_into()
        .map_err(|_| "Invalid wallet identity")
}
impl Identity {
    fn from_key(key: &HybridKey, generation: u64, authority: Hash) -> Result<Self> {
        let p = key.public();
        if p.role != Role::WalletOwner {
            return Err("Wrong wallet custody role");
        }
        let id = Self {
            version: 2,
            network: NETWORK,
            suite: WALLET_CRYPTO_SUITE_ID,
            generation,
            authority_id: hex::encode(authority),
            address_id: hex::encode(
                p.address_id(generation)
                    .map_err(|_| "Invalid wallet generation")?,
            ),
            owner_ed448: hex::encode(p.ed448),
            owner_fndsa1024: hex::encode(p.fndsa),
            owner_descriptor: hex::encode(
                p.descriptor(generation)
                    .map_err(|_| "Invalid wallet descriptor")?,
            ),
        };
        id.validate()?;
        Ok(id)
    }
    fn validate(&self) -> Result<PublicKey> {
        if self.version != 2
            || self.network != NETWORK
            || self.suite != WALLET_CRYPTO_SUITE_ID
            || self.generation == 0
            || self.owner_descriptor.len() > 8192
            || self.owner_ed448.len() != 114
            || self.owner_fndsa1024.len() != 3586
        {
            return Err("Invalid hybrid wallet identity");
        }
        let raw = hex::decode(&self.owner_descriptor).map_err(|_| "Invalid wallet descriptor")?;
        let (key, generation) =
            PublicKey::decode_descriptor(&raw).map_err(|_| "Invalid wallet descriptor")?;
        if key.role != Role::WalletOwner
            || generation != self.generation
            || hex::encode(key.ed448) != self.owner_ed448
            || hex::encode(key.fndsa) != self.owner_fndsa1024
            || key
                .address_id(generation)
                .map_err(|_| "Invalid wallet address")?
                != hash(&self.address_id)?
            || hash(&self.authority_id)? == [0; 32]
            || (generation == 1 && self.authority_id != self.address_id)
        {
            return Err("Hybrid wallet identity mismatch");
        }
        Ok(key)
    }
    fn context(&self) -> Result<[u8; 64]> {
        self.validate()?;
        let mut h = Sha512::new();
        h.update(b"MUTINY-BUILD8-DESKTOP-WALLET-CUSTODY-V2\0");
        h.update(serde_json::to_vec(self).map_err(|_| "Wallet identity encoding failed")?);
        Ok(h.finalize().into())
    }
    /// The wallet-core signing identity this vault identity names (its current descriptor and
    /// generation, and the generation-one AddressID of its authority: public data only): an
    /// ORDINARY identity. The Treasury profile comes only from wallet-core's `profile::declare`,
    /// which checks this machine's runtime declaration against the verified chain.
    pub fn signer_identity(&self) -> Result<SignerIdentity> {
        self.validate()?;
        let descriptor =
            hex::decode(&self.owner_descriptor).map_err(|_| "Invalid wallet descriptor")?;
        let identity = SignerIdentity::new(&descriptor, Some(hash(&self.authority_id)?))
            .map_err(|_| "Invalid wallet identity")?;
        if hex::encode(identity.address()) != self.address_id
            || identity.generation() != self.generation
        {
            return Err("Hybrid wallet identity mismatch");
        }
        Ok(identity)
    }
    /// Whether `identity` names exactly this vault identity (its descriptor, generation, address
    /// and authority), whatever profile and roles it carries.
    fn names(&self, identity: &SignerIdentity) -> Result<()> {
        let own = self.signer_identity()?;
        if identity.descriptor() != own.descriptor()
            || identity.generation() != own.generation()
            || identity.address() != own.address()
            || identity.authority() != own.authority()
        {
            return Err("The signing identity is not this vault's");
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vault {
    version: u8,
    identity: Identity,
    windows_protected_ciphertext: String,
}
/// The PUBLIC identity a sealed vault envelope names, read without any password and without
/// opening either encryption layer (the identity is stored beside the ciphertext, as `unlock`
/// reads it). Validated exactly as `unlock` validates it; nothing secret is touched.
pub fn envelope_identity(raw: &[u8]) -> Result<Identity> {
    if raw.len() > MAX_VAULT {
        return Err("Wallet envelope exceeds its bound");
    }
    let vault: Vault = serde_json::from_slice(raw).map_err(|_| "Invalid hybrid wallet envelope")?;
    if vault.version != 2 || vault.windows_protected_ciphertext.len() > 16384 {
        return Err("Invalid hybrid wallet version or size");
    }
    vault.identity.validate()?;
    Ok(vault.identity)
}
pub struct Session {
    key: HybridKey,
    identity: Identity,
}
impl Session {
    pub fn create() -> Result<(Self, Zeroizing<String>)> {
        ready()?;
        let phrase = mutiny_crypto_v2::create_wallet_phrase()
            .map_err(|_| "Qualified wallet entropy unavailable")?;
        let session = Self::restore_initial(&phrase)?;
        Ok((session, phrase))
    }
    pub fn restore_initial(phrase: &str) -> Result<Self> {
        ready()?;
        let key = HybridKey::wallet_restore(phrase, Role::WalletOwner)
            .map_err(|_| "Wallet recovery failed")?;
        let address = key
            .public()
            .address_id(1)
            .map_err(|_| "Wallet identity failed")?;
        let identity = Identity::from_key(&key, 1, address)?;
        Ok(Self { key, identity })
    }
    pub fn restore_current(phrase: &str, authority: &VerifiedWalletAuthority) -> Result<Self> {
        ready()?;
        let descriptor = authority
            .descriptor()
            .ok_or("Current wallet authority is not registered")?;
        let (_, generation) =
            PublicKey::decode_descriptor(descriptor).map_err(|_| "Invalid verified descriptor")?;
        let key = HybridKey::wallet_restore(phrase, Role::WalletOwner)
            .map_err(|_| "Wallet recovery failed")?;
        if key
            .public()
            .descriptor(generation)
            .map_err(|_| "Wallet identity failed")?
            != descriptor
        {
            return Err("Recovery phrase does not control the verified current wallet");
        }
        let identity = Identity::from_key(
            &key,
            generation,
            authority.authority().ok_or("Missing wallet authority")?,
        )?;
        Ok(Self { key, identity })
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Hand the unlocked key to wallet-core's `KeySigner` behind `gate` (phase 7: the desktop's own
    /// payment signer is retired). The session is CONSUMED: from here on the key exists only inside
    /// the signer, which erases it on `lock`, on idle expiry and on drop, and which signs only through
    /// `Signer::authorize(plan, approval, view)` (reviewed plan, single-use approval, independent
    /// verification). There is no other way from a vault session to a signature.
    /// `identity` is this vault identity's signing identity: the ordinary one
    /// (`Identity::signer_identity`) or what `profile::declare` returned for it.
    pub fn into_signer(
        self,
        gate: SigningGate,
        identity: SignerIdentity,
        idle_limit: Duration,
    ) -> std::result::Result<KeySigner, Refusal> {
        ready().map_err(|_| Refusal::GateClosed)?;
        self.identity
            .names(&identity)
            .map_err(|_| Refusal::InvalidDescriptor)?;
        KeySigner::with_identity(self.key, identity, gate, idle_limit)
    }
    /// The two-key session of a wallet rotation: the CURRENT key (this unlocked session) and the
    /// NEW key (the clean restore of the new phrase) move into wallet-core's `RotationSigner`, which
    /// erases both together on `lock`, idle expiry and drop and authorizes the rotation only.
    /// `identity` as for [`Session::into_signer`].
    pub fn into_rotation_signer(
        self,
        new: RestoredKey,
        gate: SigningGate,
        identity: SignerIdentity,
        idle_limit: Duration,
    ) -> std::result::Result<RotationSigner, Refusal> {
        ready().map_err(|_| Refusal::GateClosed)?;
        self.identity
            .names(&identity)
            .map_err(|_| Refusal::InvalidDescriptor)?;
        if identity.generation().checked_add(1) != Some(new.generation) {
            return Err(Refusal::InvalidDescriptor);
        }
        RotationSigner::new(self.key, identity, new.key, gate, idle_limit)
    }
    /// The vault session of a ROTATED wallet once its rotation is confirmed: the new key from the
    /// clean restore of its phrase, which must produce exactly the descriptor the verified chain now
    /// records as the authority's current one. Used by the vault replacement only.
    pub fn restore_rotated(
        new: RestoredKey,
        authority: Hash,
        verified_current: &[u8],
    ) -> Result<Self> {
        ready()?;
        let RestoredKey {
            key,
            generation,
            descriptor,
        } = new;
        if descriptor != verified_current {
            return Err("Recovery phrase does not control the verified current wallet");
        }
        let identity = Identity::from_key(&key, generation, authority)?;
        Ok(Self { key, identity })
    }
    pub fn seal(&self, password: &str) -> Result<Vec<u8>> {
        ready()?;
        let context = self.identity.context()?;
        let encrypted = self
            .key
            .seal_for(password, self.identity.generation, &context)
            .map_err(|_| "Wallet encryption failed")?;
        let protected = crate::dpapi_v2::dpapi(&encrypted, &context, true)
            .map_err(|_| "Windows wallet protection failed")?;
        let raw = serde_json::to_vec(&Vault {
            version: 2,
            identity: self.identity.clone(),
            windows_protected_ciphertext: hex::encode(protected.as_slice()),
        })
        .map_err(|_| "Wallet encoding failed")?;
        if raw.len() > MAX_VAULT {
            return Err("Wallet envelope exceeds its bound");
        }
        Ok(raw)
    }
    pub fn unlock(raw: &[u8], password: &str) -> Result<Self> {
        ready()?;
        if raw.len() > MAX_VAULT || password.len() > 4096 {
            return Err("Wallet envelope exceeds its bound");
        }
        let vault: Vault =
            serde_json::from_slice(raw).map_err(|_| "Invalid hybrid wallet envelope")?;
        if vault.version != 2 || vault.windows_protected_ciphertext.len() > 16384 {
            return Err("Invalid hybrid wallet version or size");
        }
        let public = vault.identity.validate()?;
        let context = vault.identity.context()?;
        let protected = hex::decode(&vault.windows_protected_ciphertext)
            .map_err(|_| "Invalid protected wallet")?;
        let encrypted = crate::dpapi_v2::dpapi(&protected, &context, false)
            .map_err(|_| "Windows wallet protection failed")?;
        let (key, generation) =
            HybridKey::open_for(Role::WalletOwner, password, &context, &encrypted)
                .map_err(|_| "Wallet unlock failed")?;
        if key.public() != &public || generation != vault.identity.generation {
            return Err("Encrypted wallet identity mismatch");
        }
        Ok(Self {
            key,
            identity: vault.identity,
        })
    }
}
/// The NEW key of a wallet rotation, restored from the phrase the person wrote down: holding one means
/// the clean restore produced exactly `descriptor` at `generation`. The key is erased on drop and is
/// never shown, serialised or logged (`Debug` is redacted).
pub struct RestoredKey {
    key: HybridKey,
    generation: u64,
    descriptor: Vec<u8>,
}
impl RestoredKey {
    /// Restore `phrase` and, when `expected` is given (the descriptor of the key a rotation names),
    /// require the result at `generation` (two or more) to be exactly that descriptor.
    pub fn restore(phrase: &str, generation: u64, expected: Option<&[u8]>) -> Result<Self> {
        ready()?;
        if generation < 2 {
            return Err("A rotated key has generation two or more");
        }
        if phrase.len() > 4096 {
            return Err("Recovery phrase exceeds its bound");
        }
        let key = HybridKey::wallet_restore(phrase, Role::WalletOwner)
            .map_err(|_| "Wallet recovery failed")?;
        let descriptor = key
            .public()
            .descriptor(generation)
            .map_err(|_| "Wallet identity failed")?;
        if expected.is_some_and(|expected| expected != descriptor.as_slice()) {
            return Err("The restored phrase does not produce the expected new key");
        }
        Ok(Self {
            key,
            generation,
            descriptor,
        })
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// The public descriptor the restore produced.
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }
    /// The new key's address at its generation.
    pub fn address(&self) -> Result<Hash> {
        self.key
            .public()
            .address_id(self.generation)
            .map_err(|_| "Invalid wallet generation")
    }
    /// `ops::rotation::descriptor_fingerprint` of the restored descriptor: the evidence that
    /// `RotationRequest::with_restore_verified` binds into the rotation plan.
    pub fn fingerprint(&self) -> Hash {
        mutiny_wallet_core_v8::ops::rotation::descriptor_fingerprint(&self.descriptor)
    }
}
impl std::fmt::Debug for RestoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoredKey")
            .field("generation", &self.generation)
            .field("key", &"<redacted>")
            .finish()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotated_wallet_restore_requires_authenticated_current_hybrid_identity() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/wallet-authority-proof-public-v1.json"
        ))
        .unwrap();
        let bytes = |name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
        let anchor =
            mutiny_consensus_v8::anchors::FinalizedAnchor::decode(&bytes("context")).unwrap();
        let authority = mutiny_consensus_v8::state_proof::verify_wallet_authority(
            &bytes("address_proof"),
            &bytes("current_proof"),
            &anchor,
            bytes("root").try_into().unwrap(),
            bytes("address").try_into().unwrap(),
        )
        .unwrap();
        assert!(
            Session::restore_current(&format!("{}art", "abandon ".repeat(23)), &authority).is_err()
        );
        let current =
            Session::restore_current(&format!("{}vote", "zoo ".repeat(23)), &authority).unwrap();
        assert_eq!(current.identity().generation, 2);
        assert_eq!(
            current.identity().authority_id,
            v["address"].as_str().unwrap()
        );
        assert_eq!(
            current.identity().owner_descriptor,
            v["current_descriptor"].as_str().unwrap()
        );
        assert_ne!(
            current.identity().authority_id,
            current.identity().address_id
        );
        let raw = current.seal("PUBLIC ROTATED PASSWORD").unwrap();
        let identity = current.identity().clone();
        drop(current);
        assert_eq!(
            Session::unlock(&raw, "PUBLIC ROTATED PASSWORD")
                .unwrap()
                .identity(),
            &identity
        );
    }
    #[test]
    fn hybrid_vault_dpapi_password_identity_binding_lock_and_clean_restore() {
        // Public BIP39 zero-entropy fixture; no installed wallet is accessed.
        let phrase = format!("{}art", "abandon ".repeat(23));
        let session = Session::restore_initial(&phrase).unwrap();
        let identity = session.identity().clone();
        let raw = session.seal("PUBLIC TEST PASSWORD ONLY").unwrap();
        assert!(
            !raw.windows(phrase.len())
                .any(|part| part == phrase.as_bytes())
        );
        drop(session);
        let unlocked = Session::unlock(&raw, "PUBLIC TEST PASSWORD ONLY").unwrap();
        assert_eq!(unlocked.identity(), &identity);
        assert_eq!(
            Session::restore_initial(&phrase).unwrap().identity(),
            &identity
        );
        assert!(Session::unlock(&raw, "wrong password").is_err());
        let mut altered: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        altered["identity"]["generation"] = 2.into();
        assert!(
            Session::unlock(
                &serde_json::to_vec(&altered).unwrap(),
                "PUBLIC TEST PASSWORD ONLY"
            )
            .is_err()
        );
        let mut altered: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        altered["version"] = 1.into();
        assert!(
            Session::unlock(
                &serde_json::to_vec(&altered).unwrap(),
                "PUBLIC TEST PASSWORD ONLY"
            )
            .is_err()
        );
        assert!(Session::unlock(&vec![0; MAX_VAULT + 1], "PUBLIC TEST PASSWORD ONLY").is_err());
        assert!(Session::restore_initial("not a valid recovery phrase").is_err());
    }
    // Asserting a constant is the point: it is the tripwire for the shared production constant.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn production_gate_refuses_every_non_test_build_while_unqualified() {
        // 1. The shared production constant is still false. Setting it true is a deliberate
        //    Architect decision that must come with a review of this gate; asserting the
        //    constant makes that flip impossible to miss (this test fails first).
        assert!(!mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED);
        // 2. The exact branch ready() evaluates, for a non-test build and the real constant.
        assert!(gate_closed(
            false,
            mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED
        ));
        // 3. While the constant is false only a test build passes; a non-test build passes
        //    only once the constant is true.
        assert!(!gate_closed(
            true,
            mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED
        ));
        assert!(!gate_closed(false, true));
        // 4. ready() really is that branch: its source evaluates gate_closed with cfg!(test)
        //    and the shared constant (the needle is split so this test cannot match itself).
        let needle = [
            "ifgate_closed(cfg!(te",
            "st)||cfg!(feature=\"testvalue-window\"),mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED,)",
        ].concat();
        let code: String = include_str!("wallet_v2.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert_eq!(code.matches(&needle).count(), 1);
        // 5. This is a test build, so ready() passes the gate (process protection is applied).
        assert!(ready().is_ok());
    }
    #[test]
    fn a_vault_session_moves_its_key_into_a_wallet_core_signer_and_nowhere_else() {
        // Public BIP39 zero-entropy fixture; no installed wallet is accessed.
        let session = Session::restore_initial(&format!("{}art", "abandon ".repeat(23))).unwrap();
        let expected = session.identity().signer_identity().unwrap();
        assert_eq!(
            hex::encode(expected.address()),
            session.identity().address_id
        );
        assert_eq!(expected.authority(), expected.address(), "generation one");
        assert_eq!(
            expected.profile(),
            mutiny_wallet_core_v8::WalletProfile::Ordinary
        );
        // Another wallet's identity is refused: the signer always names the vault's own key.
        let stranger = Session::restore_initial(&format!("{}vote", "zoo ".repeat(23)))
            .unwrap()
            .identity()
            .signer_identity()
            .unwrap();
        assert_eq!(
            Session::restore_initial(&format!("{}art", "abandon ".repeat(23)))
                .unwrap()
                .into_signer(
                    SigningGate::test_value().unwrap(),
                    stranger,
                    Duration::from_secs(300),
                )
                .unwrap_err(),
            Refusal::InvalidDescriptor
        );
        let signer = session
            .into_signer(
                SigningGate::test_value().unwrap(),
                expected.clone(),
                Duration::from_secs(300),
            )
            .unwrap();
        assert_eq!(mutiny_wallet_core_v8::Signer::identity(&signer), &expected);
        let shown = format!("{signer:?}");
        assert!(
            shown.contains("<redacted>") && !shown.contains("abandon"),
            "{shown}"
        );
        assert!(!signer.is_locked());
        signer.lock();
        assert!(signer.is_locked());
        assert_eq!(signer.touch().unwrap_err(), Refusal::Locked);
    }
    #[test]
    fn the_rotation_session_needs_the_clean_restore_of_exactly_the_named_new_key() {
        let current = format!("{}art", "abandon ".repeat(23));
        let new = format!("{}vote", "zoo ".repeat(23));
        let named = HybridKey::wallet_restore(&new, Role::WalletOwner)
            .unwrap()
            .public()
            .descriptor(2)
            .unwrap();
        let other = HybridKey::wallet_restore(&current, Role::WalletOwner)
            .unwrap()
            .public()
            .descriptor(2)
            .unwrap();
        // A phrase that restores another key, generation one, or an invalid phrase: refused.
        assert!(RestoredKey::restore(&new, 2, Some(&other)).is_err());
        assert!(RestoredKey::restore(&new, 1, None).is_err());
        assert!(RestoredKey::restore("not a valid recovery phrase", 2, None).is_err());
        let restored = RestoredKey::restore(&new, 2, Some(&named)).unwrap();
        assert_eq!(restored.descriptor(), named.as_slice());
        assert_eq!(
            restored.fingerprint(),
            mutiny_wallet_core_v8::ops::rotation::descriptor_fingerprint(&named)
        );
        assert!(!format!("{restored:?}").contains("zoo"));
        // The NEW key must be the next generation of the session's identity.
        let session = Session::restore_initial(&current).unwrap();
        let ordinary = session.identity().signer_identity().unwrap();
        let wrong = RestoredKey::restore(&new, 3, None).unwrap();
        assert_eq!(
            session
                .into_rotation_signer(
                    wrong,
                    SigningGate::test_value().unwrap(),
                    ordinary.clone(),
                    Duration::from_secs(300)
                )
                .unwrap_err(),
            Refusal::InvalidDescriptor
        );
        let session = Session::restore_initial(&current).unwrap();
        let rotation = session
            .into_rotation_signer(
                restored,
                SigningGate::test_value().unwrap(),
                ordinary,
                Duration::from_secs(300),
            )
            .unwrap();
        assert_eq!(rotation.proposed_descriptor(), named.as_slice());
        assert!(format!("{rotation:?}").contains("<redacted>"));
        rotation.lock();
        assert!(rotation.is_locked());
        // The replacement session must be exactly the chain's current descriptor.
        let authority = HybridKey::wallet_restore(&current, Role::WalletOwner)
            .unwrap()
            .public()
            .address_id(1)
            .unwrap();
        let again = RestoredKey::restore(&new, 2, Some(&named)).unwrap();
        assert!(Session::restore_rotated(again, authority, &other).is_err());
        let again = RestoredKey::restore(&new, 2, Some(&named)).unwrap();
        let replaced = Session::restore_rotated(again, authority, &named).unwrap();
        assert_eq!(replaced.identity().generation, 2);
        assert_eq!(replaced.identity().authority_id, hex::encode(authority));
        assert_eq!(replaced.identity().owner_descriptor, hex::encode(&named));
    }
}
