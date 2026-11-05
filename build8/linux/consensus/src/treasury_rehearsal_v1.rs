//! D2 Treasury ceremony REHEARSAL logic: proof verification against TRUSTED expectations, Treasury
//! succession (canonical lineage authenticated against a trusted StateRoot, or the exact pinned rotation
//! plan at a trusted chain and height), the read-only audit of an admitted proof, the rehearsal Genesis
//! manifest builder and post-freeze recomputation against an independently approved final manifest. The
//! durable single-use admission store is [`crate::treasury_admission_v1`].
//!
//! SIMULATED / TEST-VALUE ONLY. Public data only: this module never touches a secret, builds
//! without any custody feature and cannot create or restore a wallet key. It cannot emit a
//! production-class manifest: the builder accepts only `Class::TestValue`, and a proof is only
//! accepted in the rehearsal phase. Production remains Architect-controlled (Q9).
//!
//! Trusted expectations (Architect order, section 7). A proof is compared with values that come from
//! TRUSTED ceremony configuration ([`CeremonyConfig`]: network, phase and class, the Treasury record,
//! the ceremony context and, for succession, the trusted chain identity and height, the pinned
//! rotation-plan identity and the canonical StateRoot) and never from the proof itself, so a proof whose
//! own fields are internally consistent but differ from the expectation is refused. A generation-two key
//! that signs the Treasury's PUBLIC identifiers (authority and record hash) proves no succession: a
//! generation N >= 2 descriptor is accepted only as the current descriptor of the Treasury authority in
//! canonical state whose records reproduce the trusted StateRoot ([`Expect::canonical_current`]) or as
//! the proposed descriptor of the exact pinned rotation plan, valid at the trusted height on the trusted
//! chain and signed by the Treasury record's generation-one key and by the new key
//! ([`Expect::authorized_rotation`]); any other descriptor is `UnauthorizedSuccessor`.
//!
//! Nonces. [`verify_proof`] is read-only and consumes nothing. The FIRST ADMISSION consumes the nonce
//! durably and atomically in ONE identified store ([`AdmissionStore::admit`]); audits
//! ([`audit_recorded`], [`build_manifest`], [`verify_frozen`]) re-validate the SAME recorded proof and
//! write nothing; [`verify_frozen`] also requires the store the approved manifest names.
//!
//! Non-circularity. The Treasury record is inside the Genesis Parameters and therefore inside
//! the GenesisID, so the proof's challenge binds a rehearsal/ceremony context and the Treasury
//! record hash, never the GenesisID. After the freeze the GenesisID is recomputed, a ceremony context
//! equal to it is refused, and the recorded pre-freeze proof is verified again against the Treasury
//! extracted from the frozen bytes ([`verify_frozen`]). The proof establishes Treasury KEY CONTROL
//! only; every other Genesis field is checked against the independently approved final manifest.
use crate::{
    Hash, domain_hash,
    blocks::GenesisDescriptor,
    execution::State,
    genesis_inputs::{GenesisProfile, Parameters, dividend_state},
    protocol_manifest::RuleManifest,
    treasury_admission_v1::AdmissionStore,
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{
    HybridSignature, NETWORK, PublicKey, Role,
    treasury_proof_v1::{self as proof, Challenge, Phase, ProofError},
};
use std::collections::BTreeSet;

pub const MANIFEST_SCHEMA: &str = "MUTINY-D2-REHEARSAL-GENESIS-MANIFEST-V1";
pub const CLASS_NAME: &str = "TEST-VALUE";
pub const EVIDENCE_LABEL: &str = "SIMULATED-REHEARSAL-NOT-PRODUCTION";
pub const LABELS: &str = "Implemented != Qualified; Offline != Physical; TEST-VALUE != production";
const CONTEXT_DOMAIN: &[u8] = b"MUTINY-BUILD8-TREASURY-REHEARSAL-CONTEXT-V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Production class, production phase or a production manifest was requested.
    ProductionRefused,
    Proof(ProofError),
    /// The proof's phase differs from the phase of the trusted expected context.
    WrongPhase,
    ClassMismatch,
    /// The trusted configuration names a network other than the protocol network.
    WrongNetwork,
    WrongContext,
    /// The ceremony context equals the GenesisID that the proof must precede.
    ContextIsGenesisId,
    TreasuryMismatch,
    AlteredDescriptor,
    /// A generation N >= 2 descriptor that is not the successor named by canonical lineage or by the
    /// exact authorized rotation plan (an impostor successor).
    UnauthorizedSuccessor,
    /// The supplied canonical state or rotation plan establishes no successor of this Treasury (also:
    /// the trusted configuration lacks the root, chain or plan identity the evidence needs).
    SuccessionUnproven,
    Replay,
    /// The presented proof is not the proof recorded at its first admission.
    NotAdmitted,
    Denylisted,
    Codec,
    FrozenMismatch,
    /// The frozen Genesis differs from the independently approved final manifest.
    ManifestMismatch,
    /// The admission store belongs to another ceremony (context or Treasury record).
    StoreBinding,
    /// The admission store could not be read or written; nothing was admitted.
    Store,
    /// The rotation plan is not the exact plan the trusted configuration pins by `Rotation::identity`.
    PlanNotAuthorized,
    /// The rotation plan's network, genesis or fingerprint differs from the trusted chain identity.
    WrongChain,
    /// The trusted height lies outside the plan's validity window `[created_height, expiry_height]`.
    PlanOutOfWindow,
    /// A full Genesis descriptor was supplied but the approved manifest names no GenesisID.
    GenesisIdNotApproved,
    /// The admission store is not the store the approved manifest names (its store id differs).
    WrongStore,
}
impl From<ProofError> for Refusal {
    fn from(e: ProofError) -> Self {
        match e {
            ProofError::ProductionRefused => Self::ProductionRefused,
            other => Self::Proof(other),
        }
    }
}
pub type Outcome<T> = std::result::Result<T, Refusal>;

/// Human line for the class, exactly as an operator must see it.
pub fn class_display(class: Class) -> String {
    match class {
        Class::Production => "CLASS: PRODUCTION (1)".to_string(),
        Class::TestValue => "CLASS: TEST-VALUE (2)".to_string(),
    }
}

/// Public rehearsal/ceremony context from a public label: SHA-256(CONTEXT_DOMAIN || 0x00 || label),
/// label 4 to 64 bytes, each an ASCII graphic character (0x21..=0x7E; no space). It is chosen
/// BEFORE any Genesis exists and never depends on a GenesisID.
pub fn ceremony_context(label: &str) -> Outcome<Hash> {
    if !(4..=64).contains(&label.len()) || !label.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Refusal::Codec);
    }
    Ok(domain_hash(CONTEXT_DOMAIN, label.as_bytes()))
}

pub fn record_sha256(treasury: &Treasury) -> Outcome<Hash> {
    Ok(proof::sha256(&treasury.encode().map_err(|_| Refusal::Codec)?))
}

/// The rehearsal rule manifest (Q8): one extra commitment name, so its fingerprint differs from
/// any production rule set and a production loader rejects a rehearsal artifact structurally.
pub fn rehearsal_rules() -> RuleManifest {
    RuleManifest {
        commitments: vec![(
            b"d2-rehearsal-test-value-treasury-v1".to_vec(),
            domain_hash(b"MUTINY-D2-REHEARSAL-RULES-V1", CLASS_NAME.as_bytes()),
        )],
    }
}

// ---------------------------------------------------------------------------------- denylist

/// SHA-256(ed448 || fndsa) of public fixture keys and the default rehearsal labels (generation
/// independent). A descriptor of any of these keys can never be a production Treasury.
pub const KNOWN_PUBLIC_KEY_SHA256_HEX: [&str; 5] = [
    // abandon x23 + art (public fixture)
    "312c357eff3da94304ebf80e9410ac09a1e2f19c20823feae20dc7babf7ea6f4",
    // zoo x23 + vote (public fixture)
    "9de5c4e47c8948a614a55af2f4405222cd33cf06d229421e6d4588e0e3913371",
    // legal winner ... title (public fixture)
    "5fc8f215509e725ce4f77a658e64422f795b5cef59d70f47e5b9d81f45388fe6",
    // default rehearsal labels d2-rehearsal-k1 / d2-rehearsal-k2 (publicly derivable)
    "c18bba190032fcb8b99491f4aa47074e4c84e49e1d91ea2da38c7e7b4d178911",
    "72ab3182f4eee62866a2184ffd01e198685b2ec65a3c656245343ec64b676cb7",
];
pub fn key_sha256(public: &PublicKey) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(public.ed448);
    h.update(public.fndsa);
    h.finalize().into()
}
#[derive(Clone, Debug, Default)]
pub struct Denylist {
    extra: BTreeSet<Hash>,
}
impl Denylist {
    /// Add operator-supplied public key hashes (one lowercase hex SHA-256 per line, `#` comments).
    pub fn with_hex_lines(mut self, text: &str) -> Outcome<Self> {
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let raw = hex::decode(line).map_err(|_| Refusal::Codec)?;
            self.extra.insert(raw.try_into().map_err(|_| Refusal::Codec)?);
        }
        Ok(self)
    }
    pub fn contains(&self, public: &PublicKey) -> bool {
        let h = key_sha256(public);
        self.extra.contains(&h) || KNOWN_PUBLIC_KEY_SHA256_HEX.iter().any(|k| hex::decode(k).is_ok_and(|b| b == h))
    }
}

// ------------------------------------------------------------------- trusted expectations

/// The ceremony context (challenge field 13) the verifier EXPECTS, from trusted configuration only.
/// Fields are private: a rehearsal value is always derived from its label, a production value is
/// always the exact configured one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedContext {
    phase: Phase,
    value: Hash,
    label: Option<String>,
}
impl ExpectedContext {
    /// REHEARSAL: the value derived from a public label by [`ceremony_context`].
    pub fn rehearsal(label: &str) -> Outcome<Self> {
        Ok(Self { phase: Phase::Rehearsal, value: ceremony_context(label)?, label: Some(label.to_string()) })
    }
    /// PRODUCTION: the exact 32-byte value supplied by trusted, Architect-approved ceremony
    /// configuration. Its construction is an OPEN DEFINITION (PROPOSED in
    /// docs/TREASURY-PROOF-OF-CONTROL-SCHEMA-V1.md section 6.2; needs Architect confirmation): this
    /// code implements only the checking side ([`check_ceremony_context`]) and never derives it.
    pub fn production_supplied(value: Hash) -> Outcome<Self> {
        if value == [0; 32] {
            return Err(Refusal::Codec);
        }
        Ok(Self { phase: Phase::Production, value, label: None })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn value(&self) -> Hash {
        self.value
    }
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

/// The trusted chain that succession evidence must belong to, and the trusted height at which it is
/// evaluated (a rotation plan must be valid at this height). Part of the trusted configuration; never
/// read from a plan, a state export or a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedChain {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub height: u64,
}

/// Trusted ceremony configuration: the approved inputs a verifier EXPECTS. It is built from the
/// approved ceremony inputs, never from a proof. The phase is the expected context's phase and the
/// class is the Treasury record's class byte; they must agree (phase 1 / class 2, phase 2 / class 1).
/// Succession inputs are optional and are required only by the expectation that uses them: the
/// trusted chain and the pinned plan identity by [`Expect::authorized_rotation`], the canonical
/// StateRoot by [`Expect::canonical_current`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyConfig {
    network: u32,
    treasury: Treasury,
    context: ExpectedContext,
    chain: Option<TrustedChain>,
    plan_identity: Option<Hash>,
    state_root: Option<Hash>,
}
impl CeremonyConfig {
    pub fn new(network: u32, treasury: Treasury, context: ExpectedContext) -> Outcome<Self> {
        if network != NETWORK {
            return Err(Refusal::WrongNetwork);
        }
        if treasury.class() as u8 != context.phase().required_class() {
            return Err(Refusal::ClassMismatch);
        }
        Ok(Self { network, treasury, context, chain: None, plan_identity: None, state_root: None })
    }
    /// REHEARSAL configuration: a TEST-VALUE Treasury record and a label-derived context.
    pub fn rehearsal(network: u32, treasury: Treasury, context_label: &str) -> Outcome<Self> {
        Self::new(network, treasury, ExpectedContext::rehearsal(context_label)?)
    }
    /// The trusted chain identity and height that succession evidence is evaluated against.
    pub fn with_trusted_chain(mut self, chain: TrustedChain) -> Outcome<Self> {
        if chain.network != self.network {
            return Err(Refusal::WrongNetwork);
        }
        if chain.genesis == [0; 32] || chain.fingerprint == [0; 32] {
            return Err(Refusal::Codec);
        }
        self.chain = Some(chain);
        Ok(self)
    }
    /// The identity (`Rotation::identity`) of the exact authorized rotation plan.
    pub fn with_authorized_plan(mut self, identity: Hash) -> Outcome<Self> {
        if identity == [0; 32] {
            return Err(Refusal::Codec);
        }
        self.plan_identity = Some(identity);
        Ok(self)
    }
    /// The authenticated canonical StateRoot that canonical lineage records must reproduce.
    pub fn with_canonical_root(mut self, root: Hash) -> Outcome<Self> {
        if root == [0; 32] {
            return Err(Refusal::Codec);
        }
        self.state_root = Some(root);
        Ok(self)
    }
    pub fn network(&self) -> u32 {
        self.network
    }
    pub fn phase(&self) -> Phase {
        self.context.phase()
    }
    pub fn class(&self) -> Class {
        self.treasury.class()
    }
    pub fn treasury(&self) -> &Treasury {
        &self.treasury
    }
    pub fn context(&self) -> &ExpectedContext {
        &self.context
    }
    pub fn trusted_chain(&self) -> Option<TrustedChain> {
        self.chain
    }
    pub fn authorized_plan(&self) -> Option<Hash> {
        self.plan_identity
    }
    pub fn canonical_root(&self) -> Option<Hash> {
        self.state_root
    }
}

/// The complete expectation for one proof: the trusted configuration plus the key generation and the
/// SHA-256 of the exact descriptor of that generation, established by the Treasury record itself
/// (generation one), by canonical state that reproduces the trusted StateRoot or by the exact pinned
/// rotation plan. There is no constructor that takes a descriptor from the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expect {
    config: CeremonyConfig,
    generation: u64,
    descriptor_sha256: Hash,
}
impl Expect {
    /// Generation one: the exact descriptor sealed in the trusted Treasury record.
    pub fn genesis_key(config: &CeremonyConfig) -> Self {
        Self { config: config.clone(), generation: 1, descriptor_sha256: proof::sha256(config.treasury.descriptor()) }
    }
    /// Canonical lineage: the CURRENT descriptor of the Treasury authority in the canonical state given
    /// by `records`, which must reproduce the trusted StateRoot of the configuration under the
    /// canonical state decoder (`State::from_records`: state-tree root, typed records, canonical
    /// round trip). A state that carries a Treasury record must carry exactly the trusted one. Only the
    /// current key proves control; a retired generation is a wrong key version.
    pub fn canonical_current(config: &CeremonyConfig, records: &[(Hash, Vec<u8>)]) -> Outcome<Self> {
        let root = config.state_root.ok_or(Refusal::SuccessionUnproven)?;
        let state = State::from_records(records, root).map_err(|_| Refusal::SuccessionUnproven)?;
        let treasury = &config.treasury;
        if state.dividends.treasury().is_some_and(|t| t != treasury) {
            return Err(Refusal::SuccessionUnproven);
        }
        let current = state.wallets.current(treasury.authority()).ok_or(Refusal::SuccessionUnproven)?;
        let (public, generation) = PublicKey::decode_descriptor(current).map_err(|_| Refusal::SuccessionUnproven)?;
        if public.role != Role::WalletOwner || (generation == 1 && current != treasury.descriptor()) {
            return Err(Refusal::SuccessionUnproven);
        }
        Ok(Self { config: config.clone(), generation, descriptor_sha256: proof::sha256(current) })
    }
    /// The exact pinned rotation plan. Order: (1) the plan's unsigned body is well formed (proposed
    /// generation = current generation + 1, two different keys, the protocol network, non-zero chain
    /// identity and authority, a window of at most the expiry horizon) and its identity
    /// (`Rotation::identity`) equals the pinned identity (`PlanNotAuthorized`); (2) its network, genesis
    /// and fingerprint equal the trusted chain (`WrongChain`); (3) its authority is the Treasury
    /// authority and its current descriptor is the record's generation-one descriptor; (4) the trusted
    /// height lies in `[created_height, expiry_height]` (`PlanOutOfWindow`); (5) the current-key
    /// authorization under `WalletRotate` and the new-key possession under `WalletRotatePossession` both
    /// verify. The plan's canonical inclusion is canonical execution's business.
    pub fn authorized_rotation(config: &CeremonyConfig, plan: &Rotation) -> Outcome<Self> {
        let chain = config.chain.ok_or(Refusal::SuccessionUnproven)?;
        let pinned = config.plan_identity.ok_or(Refusal::SuccessionUnproven)?;
        let treasury = &config.treasury;
        let identity = plan.identity().map_err(|_| Refusal::SuccessionUnproven)?;
        if identity != pinned {
            return Err(Refusal::PlanNotAuthorized);
        }
        if plan.network != chain.network || plan.genesis != chain.genesis || plan.fingerprint != chain.fingerprint {
            return Err(Refusal::WrongChain);
        }
        if plan.authority != treasury.authority() || plan.current.as_slice() != treasury.descriptor() {
            return Err(Refusal::SuccessionUnproven);
        }
        if chain.height < plan.created_height || chain.height > plan.expiry_height {
            return Err(Refusal::PlanOutOfWindow);
        }
        let verified = plan
            .verify(chain.genesis, chain.fingerprint, chain.height, treasury.authority(), treasury.descriptor())
            .map_err(|_| Refusal::SuccessionUnproven)?;
        let proposed = verified.proposed_descriptor();
        let (_, generation) = PublicKey::decode_descriptor(proposed).map_err(|_| Refusal::SuccessionUnproven)?;
        Ok(Self { config: config.clone(), generation, descriptor_sha256: proof::sha256(proposed) })
    }
    pub fn config(&self) -> &CeremonyConfig {
        &self.config
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn descriptor_sha256(&self) -> Hash {
        self.descriptor_sha256
    }
}

/// Challenge field 13 against the TRUSTED expected context. A rehearsal expectation accepts only a
/// rehearsal-phase proof carrying the label-derived value; a production expectation accepts only a
/// production-phase proof carrying exactly the configured value (checking side only; production
/// proofs are refused elsewhere while production is unqualified). The context is never a GenesisID:
/// when the GenesisID is known (after the freeze) a context equal to it is refused.
pub fn check_ceremony_context(expected: &ExpectedContext, challenge: &Challenge, genesis_id: Option<&Hash>) -> Outcome<()> {
    if challenge.phase != expected.phase() {
        return Err(Refusal::WrongPhase);
    }
    if challenge.ceremony_context != expected.value() {
        return Err(Refusal::WrongContext);
    }
    if genesis_id.is_some_and(|id| *id == challenge.ceremony_context) {
        return Err(Refusal::ContextIsGenesisId);
    }
    Ok(())
}

// ------------------------------------------------------------------------------ verifier

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProof {
    pub class: Class,
    pub generation: u64,
    pub descriptor_sha256: Hash,
    pub record_sha256: Hash,
    pub address_id: Hash,
    pub treasury_authority: Hash,
    pub context: Hash,
    pub nonce: Hash,
}

/// The normative input stage (schema section 7.0): first the strict challenge decode (section 3),
/// then the two-component signature serialization (A.6). Every later check sees typed values.
pub fn decode_proof(challenge_bytes: &[u8], signature_bytes: &[u8]) -> Outcome<(Challenge, HybridSignature)> {
    let challenge = Challenge::decode(challenge_bytes)?;
    let signature = proof::signature_from_bytes(signature_bytes)?;
    Ok((challenge, signature))
}

/// READ-ONLY verification of a proof of control for `descriptor` (the exact bytes of the proven
/// generation) against the TRUSTED expectation. It never consumes a nonce: the first admission does
/// that durably ([`AdmissionStore::admit`]); audits re-validate a recorded proof through
/// [`audit_recorded`]. Order: strict decode, production refusal, class, network, phase and context,
/// key version, Treasury binding, expected descriptor (succession), descriptor identity, denylist,
/// then BOTH signatures.
pub fn verify_proof(
    expect: &Expect,
    descriptor: &[u8],
    challenge_bytes: &[u8],
    signature: &HybridSignature,
    denylist: &Denylist,
) -> Outcome<VerifiedProof> {
    let challenge = Challenge::decode(challenge_bytes)?;
    let config = &expect.config;
    // Production is refused whatever the configuration says, before any other comparison.
    if challenge.phase == Phase::Production || config.phase() == Phase::Production {
        return Err(Refusal::ProductionRefused);
    }
    // Class of the trusted record, class and phase of the challenge must all agree on TEST-VALUE.
    if config.class() != Class::TestValue || challenge.class != config.class() as u8 {
        return Err(Refusal::ClassMismatch);
    }
    // The strict decoder admits only the protocol network; the trusted configuration must name it.
    if config.network() != NETWORK {
        return Err(Refusal::WrongNetwork);
    }
    check_ceremony_context(config.context(), &challenge, None)?;
    if challenge.generation != expect.generation {
        return Err(Refusal::Proof(ProofError::WrongKeyVersion));
    }
    let treasury = &config.treasury;
    if challenge.treasury_record_sha256 != record_sha256(treasury)? || challenge.treasury_authority != treasury.authority() {
        return Err(Refusal::TreasuryMismatch);
    }
    // The descriptor must be the one the trusted lineage names for this generation: the record's own
    // descriptor at generation one, the canonical or authorized successor otherwise.
    if proof::sha256(descriptor) != expect.descriptor_sha256 || (expect.generation == 1 && descriptor != treasury.descriptor()) {
        return Err(if expect.generation == 1 { Refusal::AlteredDescriptor } else { Refusal::UnauthorizedSuccessor });
    }
    let public = challenge.check_descriptor(descriptor)?;
    if denylist.contains(&public) && config.class() == Class::Production {
        return Err(Refusal::Denylisted);
    }
    challenge.verify(descriptor, signature)?;
    Ok(VerifiedProof {
        class: config.class(),
        generation: challenge.generation,
        descriptor_sha256: challenge.descriptor_sha256,
        record_sha256: challenge.treasury_record_sha256,
        address_id: challenge.address_id,
        treasury_authority: challenge.treasury_authority,
        context: challenge.ceremony_context,
        nonce: challenge.nonce,
    })
}

/// READ-ONLY audit of the SAME recorded proof: `store` must hold exactly these challenge, descriptor
/// and signature bytes under the challenge's nonce (`NotAdmitted` otherwise), and the proof must still
/// verify against the trusted expectation. Writes nothing (it takes the store by shared reference);
/// repeatable.
pub fn audit_recorded(
    store: &AdmissionStore,
    expect: &Expect,
    descriptor: &[u8],
    challenge_bytes: &[u8],
    signature: &HybridSignature,
    denylist: &Denylist,
) -> Outcome<VerifiedProof> {
    store.check_binding(&expect.config)?;
    let challenge = Challenge::decode(challenge_bytes)?;
    let recorded = store.recorded(&challenge.nonce)?.ok_or(Refusal::NotAdmitted)?;
    if recorded.challenge != challenge_bytes || recorded.descriptor != descriptor || recorded.signature != proof::signature_to_bytes(signature) {
        return Err(Refusal::NotAdmitted);
    }
    verify_proof(expect, descriptor, challenge_bytes, signature, denylist)
}

/// Build the challenge for `descriptor` (generation N) under the trusted configuration.
pub fn build_challenge(config: &CeremonyConfig, descriptor: &[u8], nonce: Hash) -> Outcome<Challenge> {
    if config.phase() != Phase::Rehearsal || config.class() != Class::TestValue {
        return Err(Refusal::ProductionRefused);
    }
    let treasury = &config.treasury;
    Ok(Challenge::new(descriptor, Phase::Rehearsal, treasury.authority(), record_sha256(treasury)?, config.context.value(), nonce)?)
}

/// Run the ceremony-level negative controls (procedure 5.4) against a valid proof. Returns each
/// control and whether it was rejected; a verifier is only acceptable when every control rejects.
/// When the unmodified proof is not accepted, only that failed control is returned.
pub fn negative_controls(expect: &Expect, descriptor: &[u8], challenge_bytes: &[u8], signature: &HybridSignature) -> Vec<(&'static str, bool)> {
    let deny = Denylist::default();
    let rejected = |e: &Expect, d: &[u8], c: &[u8], s: &HybridSignature| verify_proof(e, d, c, s, &deny).is_err();
    let mut results = Vec::new();
    // Control: the unmodified proof is accepted (so the negatives are not vacuous). Every later control
    // needs a valid proof (a challenge of at least 253 bytes and a descriptor of at least 1,903 bytes).
    let control = verify_proof(expect, descriptor, challenge_bytes, signature, &deny).is_ok();
    results.push(("control: unmodified proof accepted", control));
    if !control {
        return results;
    }
    let flip = |raw: &[u8], at: usize| {
        let mut v = raw.to_vec();
        let at = at.min(v.len() - 1);
        v[at] ^= 0x01;
        v
    };
    results.push(("flip one bit of the payload", rejected(expect, descriptor, &flip(challenge_bytes, challenge_bytes.len() - 5), signature)));
    let mut s = signature.clone();
    s.ed448[3] ^= 1;
    results.push(("flip one bit of the Ed448 component", rejected(expect, descriptor, challenge_bytes, &s)));
    let mut s = signature.clone();
    s.fndsa[40] ^= 1;
    results.push(("flip one bit of the FN-DSA component", rejected(expect, descriptor, challenge_bytes, &s)));
    let mut s = signature.clone();
    s.fndsa = [0; 1280];
    results.push(("only the Ed448 component present", rejected(expect, descriptor, challenge_bytes, &s)));
    let mut s = signature.clone();
    s.ed448 = [0; 114];
    results.push(("only the FN-DSA component present", rejected(expect, descriptor, challenge_bytes, &s)));
    let mut altered = descriptor.to_vec();
    let mid = altered.len() / 2;
    altered[mid] ^= 0x40;
    results.push(("altered descriptor byte", rejected(expect, &altered, challenge_bytes, signature)));
    let wrong_generation = Expect { generation: expect.generation.wrapping_add(1), ..expect.clone() };
    results.push(("wrong key version expected", rejected(&wrong_generation, descriptor, challenge_bytes, signature)));
    let other_context = ExpectedContext { phase: Phase::Rehearsal, value: domain_hash(b"other-context", &[]), label: Some("other-context".to_string()) };
    let wrong_context = Expect { config: CeremonyConfig { context: other_context, ..expect.config.clone() }, ..expect.clone() };
    results.push(("wrong ceremony context expected", rejected(&wrong_context, descriptor, challenge_bytes, signature)));
    let mut trailing = challenge_bytes.to_vec();
    trailing.push(0);
    results.push(("trailing byte after the payload", rejected(expect, descriptor, &trailing, signature)));
    if let Ok(mut c) = Challenge::decode(challenge_bytes) {
        c.profile = "MUTINY-FNDSA1024-OTHER-V1".into();
        results.push(("wrong cryptographic profile", rejected(expect, descriptor, &c.encode_unchecked(), signature)));
        let mut c = Challenge::decode(challenge_bytes).unwrap();
        c.phase = Phase::Production;
        c.class = proof::CLASS_PRODUCTION;
        results.push(("relabelled as a production proof", rejected(expect, descriptor, &c.encode_unchecked(), signature)));
        let mut c = Challenge::decode(challenge_bytes).unwrap();
        c.class = proof::CLASS_PRODUCTION;
        results.push(("class/phase mismatch", rejected(expect, descriptor, &c.encode_unchecked(), signature)));
    }
    let other_descriptor = Expect { descriptor_sha256: domain_hash(b"other-descriptor", &[]), ..expect.clone() };
    results.push(("descriptor is not the trusted descriptor of this generation", rejected(&other_descriptor, descriptor, challenge_bytes, signature)));
    let other_network = Expect { config: CeremonyConfig { network: expect.config.network ^ 1, ..expect.config.clone() }, ..expect.clone() };
    results.push(("wrong network expected", rejected(&other_network, descriptor, challenge_bytes, signature)));
    // Replay through a scratch in-memory admission store with the same semantics as the durable one.
    let replay = AdmissionStore::in_memory(&expect.config).is_ok_and(|mut store| {
        store.admit(expect, descriptor, challenge_bytes, signature, &deny).is_ok()
            && store.admit(expect, descriptor, challenge_bytes, signature, &deny) == Err(Refusal::Replay)
    });
    results.push(("replay of an accepted challenge", replay));
    results
}

// -------------------------------------------------------------------------------- manifest

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub text: String,
    pub parameters: Vec<u8>,
}

fn h(raw: &[u8]) -> String {
    hex::encode(raw)
}
/// A JSON string literal (RFC 8259): quote, backslash and control characters are escaped, so no
/// caller-supplied text (for example a rehearsal label, which may contain `"` or `\`) can change the
/// structure of the manifest.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Build the REHEARSAL Genesis manifest for the generation-one TEST-VALUE Treasury of the trusted
/// configuration, from a proof that was ADMITTED (recorded in `store`, which may be read-only; the
/// build consumes nothing). Deterministic: the output is a pure function of the inputs and the store
/// id. Refuses any class but TEST-VALUE, whatever the keys: a production-class manifest cannot be
/// produced here. `signature` is included so a reader can re-verify from the manifest alone.
#[allow(clippy::too_many_arguments)]
pub fn build_manifest(
    expect: &Expect,
    descriptor: &[u8],
    challenge_bytes: &[u8],
    signature: &HybridSignature,
    initial_target: Hash,
    rules: &RuleManifest,
    denylist: &Denylist,
    store: &AdmissionStore,
) -> Outcome<Manifest> {
    let config = &expect.config;
    if config.class() != Class::TestValue || config.phase() != Phase::Rehearsal {
        return Err(Refusal::ProductionRefused);
    }
    if expect.generation != 1 {
        return Err(Refusal::Proof(ProofError::WrongKeyVersion));
    }
    let verified = audit_recorded(store, expect, descriptor, challenge_bytes, signature, denylist)?;
    let treasury = config.treasury.clone();
    let context = config.context.value();
    let context_label = json_string(config.context.label().unwrap_or(""));
    let parameters = Parameters { initial_target, rules: rules.clone(), treasury: Some(treasury.clone()) };
    let parameters_bytes = parameters.encode().map_err(|_| Refusal::Codec)?;
    // Class gating exactly as the Genesis profiles enforce it.
    let accepted_by_test = dividend_state(&parameters, GenesisProfile::Test).is_ok();
    let rejected_by_production = dividend_state(&parameters, GenesisProfile::Production).is_err();
    if !accepted_by_test || !rejected_by_production {
        return Err(Refusal::ClassMismatch);
    }
    let record = treasury.encode().map_err(|_| Refusal::Codec)?;
    let names: Vec<String> = rules.commitments.iter().map(|(n, _)| json_string(&String::from_utf8_lossy(n))).collect();
    let text = format!(
        "{{\n  \"schema\": \"{MANIFEST_SCHEMA}\",\n  \"class\": \"{CLASS_NAME}\",\n  \"class_byte\": {},\n  \"class_line\": \"{}\",\n  \"evidence\": \"{EVIDENCE_LABEL}\",\n  \"labels\": \"{LABELS}\",\n  \"production_security_qualified\": false,\n  \"production_class_manifest\": \"IMPOSSIBLE-FROM-REHEARSAL-KEYS\",\n  \"admission_store_id\": \"{}\",\n  \"treasury\": {{\n    \"key_generation\": 1,\n    \"descriptor_hex\": \"{}\",\n    \"descriptor_sha256\": \"{}\",\n    \"authority_address_id\": \"{}\",\n    \"record_hex\": \"{}\",\n    \"record_sha256\": \"{}\"\n  }},\n  \"proof_of_control\": {{\n    \"domain\": \"MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1\",\n    \"phase\": \"REHEARSAL\",\n    \"components_required\": \"ED448+FNDSA1024\",\n    \"ceremony_context_label\": {context_label},\n    \"ceremony_context\": \"{}\",\n    \"nonce\": \"{}\",\n    \"challenge_hex\": \"{}\",\n    \"signature_hex\": \"{}\"\n  }},\n  \"genesis_parameters\": {{\n    \"initial_target_hex\": \"{}\",\n    \"rule_commitment_names\": [{}],\n    \"rule_fingerprint\": \"{}\",\n    \"parameters_sha256\": \"{}\",\n    \"parameters_len\": {},\n    \"test_profile_accepts\": {accepted_by_test},\n    \"production_profile_rejects\": {rejected_by_production}\n  }},\n  \"non_circular_binding\": \"the proof binds the ceremony context and the Treasury record hash and never the GenesisID; the GenesisID is checked after the freeze by recomputation\"\n}}\n",
        Class::TestValue as u8,
        class_display(Class::TestValue),
        h(&store.store_id()),
        h(descriptor),
        h(&verified.descriptor_sha256),
        h(&verified.treasury_authority),
        h(&record),
        h(&verified.record_sha256),
        h(&context),
        h(&verified.nonce),
        h(challenge_bytes),
        h(&proof::signature_to_bytes(signature)),
        h(&initial_target),
        names.join(", "),
        h(&rules.fingerprint().map_err(|_| Refusal::Codec)?),
        h(&proof::sha256(&parameters_bytes)),
        parameters_bytes.len(),
    );
    Ok(Manifest { text, parameters: parameters_bytes })
}

// ------------------------------------------------------------------- post-freeze recompute

/// The independently approved final Genesis manifest values the frozen bytes must equal. The proof of
/// control establishes Treasury KEY CONTROL only; approval of the other Genesis fields comes from this
/// independently supplied manifest, never from the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedManifest {
    pub class: Class,
    pub descriptor_sha256: Hash,
    pub record_sha256: Hash,
    /// SHA-256 of the exact approved Genesis Parameters bytes.
    pub parameters_sha256: Hash,
    /// The approved GenesisID. MANDATORY when the frozen input is a full Genesis descriptor (then the
    /// recomputed GenesisID must equal it); an approval that names one cannot be checked against
    /// Parameters bytes alone.
    pub genesis_id: Option<Hash>,
    /// The id of the admission store that recorded the approved proof.
    pub admission_store_id: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenReport {
    pub class: Class,
    pub descriptor_sha256: Hash,
    pub record_sha256: Hash,
    pub treasury_authority: Hash,
    pub parameters_sha256: Hash,
    /// Present only when the full Genesis descriptor was supplied (then it equals the approved one).
    pub genesis_id: Option<Hash>,
}

/// Post-freeze verification by recomputation; READ-ONLY and repeatable. `frozen` is either the frozen
/// Parameters bytes or a full Genesis descriptor. Order: (1) generation one; (2) the challenge decodes
/// and is not production; (3) the frozen input decodes (and its GenesisID is recomputed); (4) a Genesis
/// descriptor requires an approval that names the GenesisID (`GenesisIdNotApproved`); (5) the Treasury
/// extracted from the FROZEN bytes is exactly the trusted Treasury (`FrozenMismatch`); (6) the frozen
/// bytes equal the independently approved manifest: class, descriptor hash, record hash, Parameters
/// hash and the GenesisID when the approval names one (`ManifestMismatch`); (7) the store is the one
/// the approval names (`WrongStore`); (8) the ceremony context is the expected one and not the
/// recomputed GenesisID; (9) the proof is the one RECORDED at admission and still verifies.
#[allow(clippy::too_many_arguments)]
pub fn verify_frozen(
    frozen: &[u8],
    is_genesis_descriptor: bool,
    expect: &Expect,
    approved: &ApprovedManifest,
    store: &AdmissionStore,
    challenge_bytes: &[u8],
    signature: &HybridSignature,
) -> Outcome<FrozenReport> {
    if expect.generation != 1 {
        return Err(Refusal::Proof(ProofError::WrongKeyVersion));
    }
    let challenge = Challenge::decode(challenge_bytes)?;
    if challenge.phase == Phase::Production || expect.config.phase() == Phase::Production {
        return Err(Refusal::ProductionRefused);
    }
    let (parameters_bytes, genesis_id) = if is_genesis_descriptor {
        let d = GenesisDescriptor::decode(frozen).map_err(|_| Refusal::Codec)?;
        let id = d.id().map_err(|_| Refusal::Codec)?;
        (d.parameters, Some(id))
    } else {
        (frozen.to_vec(), None)
    };
    if is_genesis_descriptor && approved.genesis_id.is_none() {
        return Err(Refusal::GenesisIdNotApproved);
    }
    let parameters = Parameters::decode(&parameters_bytes).map_err(|_| Refusal::Codec)?;
    let treasury = parameters.treasury.ok_or(Refusal::FrozenMismatch)?;
    if &treasury != expect.config.treasury() {
        return Err(Refusal::FrozenMismatch);
    }
    let parameters_sha256 = proof::sha256(&parameters_bytes);
    if approved.class != treasury.class()
        || approved.descriptor_sha256 != proof::sha256(treasury.descriptor())
        || approved.record_sha256 != record_sha256(&treasury)?
        || approved.parameters_sha256 != parameters_sha256
        || approved.genesis_id.is_some_and(|id| genesis_id != Some(id))
    {
        return Err(Refusal::ManifestMismatch);
    }
    if store.store_id() != approved.admission_store_id {
        return Err(Refusal::WrongStore);
    }
    check_ceremony_context(expect.config.context(), &challenge, genesis_id.as_ref())?;
    let verified = audit_recorded(store, expect, treasury.descriptor(), challenge_bytes, signature, &Denylist::default())?;
    Ok(FrozenReport {
        class: treasury.class(),
        descriptor_sha256: verified.descriptor_sha256,
        record_sha256: verified.record_sha256,
        treasury_authority: verified.treasury_authority,
        parameters_sha256,
        genesis_id,
    })
}

/// Print-ready decoded Treasury block of any Genesis Parameters (rehearsal or not).
pub fn inspect_parameters(parameters_bytes: &[u8]) -> Outcome<String> {
    let p = Parameters::decode(parameters_bytes).map_err(|_| Refusal::Codec)?;
    match p.treasury {
        None => Ok("TREASURY: ABSENT (version 2 parameters)".to_string()),
        Some(t) => Ok(format!(
            "{}\ndescriptor_sha256 {}\nrecord_sha256 {}\nauthority_address_id {}",
            class_display(t.class()),
            h(&proof::sha256(t.descriptor())),
            h(&record_sha256(&t)?),
            h(&t.authority())
        )),
    }
}
