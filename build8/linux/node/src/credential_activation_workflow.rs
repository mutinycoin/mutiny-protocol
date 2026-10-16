//! Path B local credential-activation workflow. PROPOSED / UNQUALIFIED.
//!
//! This source is not registered into the shipping launcher. It neither mints a
//! physical-admission capability nor changes canonical state. A local recovered
//! secret is meaningful only with a vetted MakeCredential adapter, qualified TPM
//! classes and an approved verifier trust model. A public transcript is not that
//! proof. See PATH-B-CREDENTIAL-ACTIVATION-WORKFLOW-20261005.md.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    admission_v2::{Expected, Policy},
    attestation_witness::{AttestationWitness, WitnessContext, verify_witness},
    ek_chain::CertificateSyntax,
    genesis_v2::Parameters,
    test_value_root_alias_v1::WitnessPolicy,
    endorsement_identity::{committed_identities, parse_ek_public_area},
    node_admission_v2::Binding,
    provenance::{AdmissionClass, ak_name},
    tpm::{TpmProfile, public_key},
    wallet_authority_v1::WalletBook,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const SECRET_DOMAIN: &[u8] = b"MUTINY-BUILD8-ACTIVATION-SECRET-V1";
const MAX_ENCRYPTED_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    CandidateBinding,
    CandidateProfile,
    PublicWitness,
    Classes,
    Context,
    Provider,
    Randomness,
    Capacity,
    Adapter,
    EncryptedBounds,
    UnknownAttempt,
    ResponseClasses,
    SecretMismatch,
    Elapsed,
    Expired,
    DeadlineOverflow,
}
type Result<T> = std::result::Result<T, Failure>;

/// Transition discriminator, not a new consensus operation or authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Genesis,
    Join,
    KeyRotation,
    HardwareReplacement,
    Recovery,
}

/// Owner-supplied own-canonical context. Digests here are bindings, not evidence
/// that a class is qualified or a verifier is authorized. The provider below
/// must authenticate their meaning. No execution-location field exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub network: u32,
    pub admission_class: AdmissionClass,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub parent: Hash,
    pub purpose: Purpose,
    pub authorized_transition: Hash,
    pub identity_classes: Hash,
    pub verifier_policy: Hash,
}
impl Anchor {
    fn check(&self) -> Result<()> {
        if self.network != NETWORK_ID
            || [self.genesis, self.fingerprint, self.authorized_transition,
                self.identity_classes, self.verifier_policy].contains(&[0; 32])
            || (self.purpose != Purpose::Genesis && self.parent == [0; 32])
            || (self.purpose == Purpose::Genesis && self.parent != [0; 32])
        {
            return Err(Failure::Context);
        }
        Ok(())
    }
}

/// Immutable public scope, compared in full, not supplied by a peer as current
/// authority. The SHA-256 wire checksum binds exact public bytes only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub anchor: Anchor,
    pub node: Hash,
    pub hardware_generation: u64,
    pub key_generation: u64,
    pub binding_wire_sha256: Hash,
    pub profile_commitment: Hash,
    pub ak_name: [u8; 34],
}

struct Endorsement {
    identity: Hash,
    public_area: Vec<u8>,
}
/// Complete native typed material and public certificate witness verification.
/// This is not a physical-equivalence or admission capability.
pub struct Candidate {
    scope: Scope,
    endorsements: Vec<Endorsement>,
}
impl Candidate {
    pub fn validate(
        binding: &Binding,
        policy: &Policy,
        expected: &Expected,
        wallets: &WalletBook,
        anchor: Anchor,
        witness_raw: &[u8],
        witness_context: &WitnessContext<'_>,
        syntax: &dyn CertificateSyntax,
    ) -> Result<Self> {
        Self::validate_inner(binding,policy,expected,wallets,anchor,witness_raw,witness_context,syntax,None)
    }

    /// Trusted immutable Genesis Parameters, not applicant-selected aliases.
    /// The actual Parameters fingerprint must match the already signed binding
    /// and local anchor before its selected certificate policy is used. The
    /// historical validate API above keeps its direct-DER behavior unchanged.
    pub fn validate_with_parameters(
        binding: &Binding, policy: &Policy, expected: &Expected,
        wallets: &WalletBook, anchor: Anchor, witness_raw: &[u8],
        parameters: &Parameters, reference_time: u64, syntax: &dyn CertificateSyntax,
    ) -> Result<Self> {
        let witness_policy=parameters.witness_policy().map_err(|_|Failure::PublicWitness)?;
        let fingerprint=parameters.fingerprint().map_err(|_|Failure::Context)?;
        if fingerprint!=binding.admission.fingerprint || fingerprint!=anchor.fingerprint
            || fingerprint!=policy.fingerprint
            || policy.endorsement_roots!=parameters.roots.roots.keys().copied().collect()
        {
            return Err(Failure::Context);
        }
        let context=witness_policy.context(reference_time);
        Self::validate_inner(binding,policy,expected,wallets,anchor,witness_raw,&context,syntax,Some(&witness_policy))
    }
    fn validate_inner(
        binding: &Binding, policy: &Policy, expected: &Expected,
        wallets: &WalletBook, anchor: Anchor, witness_raw: &[u8],
        witness_context: &WitnessContext<'_>, syntax: &dyn CertificateSyntax,
        selected_policy: Option<&WitnessPolicy>,
    ) -> Result<Self> {
        anchor.check()?;
        // Do not bypass existing typed authorization or either hybrid half.
        // Scope/sealing authorization is still a separate canonical check.
        binding.verify(policy, expected, wallets, witness_context.chain.class)
            .map_err(|_| Failure::CandidateBinding)?;
        let profile = TpmProfile::decode(&binding.admission.profile)
            .map_err(|_| Failure::CandidateProfile)?;
        public_key(&profile.ak_public, true).map_err(|_| Failure::CandidateProfile)?;
        let name = ak_name(&profile.ak_public).map_err(|_| Failure::CandidateProfile)?;
        let statement = profile.provenance.as_ref().ok_or(Failure::PublicWitness)?;
        if name != statement.ak_name {
            return Err(Failure::CandidateProfile);
        }
        match selected_policy {
            Some(derived)=>mutiny_consensus_v8::attestation_witness::verify_witness_with_policy(
                statement,Some(witness_raw),derived,witness_context.chain.reference_time,syntax),
            None=>verify_witness(statement,Some(witness_raw),witness_context,syntax),
        }.map_err(|_|Failure::PublicWitness)?;
        let witness = AttestationWitness::decode(witness_raw).map_err(|_| Failure::PublicWitness)?;
        let ids = committed_identities(&profile);
        if ids.is_empty() || ids.len() != witness.endorsements.len()
            || ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len()
        {
            return Err(Failure::Classes);
        }
        // In particular no marked TEST-VALUE profile becomes Production here;
        // binding.verify already enforces the committed class's profile rule.
        if witness_context.chain.class == AdmissionClass::Production && profile.is_test_value() {
            return Err(Failure::CandidateProfile);
        }
        if anchor.genesis != binding.admission.genesis
            || anchor.fingerprint != binding.admission.fingerprint
            || anchor.admission_class != witness_context.chain.class
            || anchor.identity_classes != witness_context.identity_classes.commitment()
        {
            return Err(Failure::Context);
        }
        let scope = Scope {
            anchor,
            node: binding.admission.node,
            hardware_generation: binding.admission.hardware_generation,
            key_generation: binding.admission.key_generation,
            binding_wire_sha256: Sha256::digest(binding.encode().map_err(|_| Failure::CandidateBinding)?).into(),
            profile_commitment: profile.commitment().map_err(|_| Failure::CandidateProfile)?,
            ak_name: name,
        };
        let mut endorsements = Vec::with_capacity(ids.len());
        for (identity, ev) in ids.into_iter().zip(witness.endorsements) {
            // Independent exact public-key consistency, not physical aliasing.
            let area = parse_ek_public_area(&ev.ek_public_area).map_err(|_| Failure::Classes)?;
            if area.key.identity().map_err(|_| Failure::Classes)? != identity {
                return Err(Failure::Classes);
            }
            endorsements.push(Endorsement { identity, public_area: ev.ek_public_area });
        }
        Ok(Self { scope, endorsements })
    }
    pub fn scope(&self) -> &Scope { &self.scope }
}

/// TRUSTED LOCAL ADAPTER boundary, not an applicant-supplied implementation.
/// A production implementation must be independently vetted/pinned and perform
/// actual MakeCredential using these exact inputs, never a public fixed return.
/// It must not log, persist or return the raw secret. No TPM command is executed
/// by this module, and no production implementation is supplied in this tranche.
pub trait MakeCredential {
    fn make_credential(
        &mut self,
        ek_public_area: &[u8],
        ak_name: &[u8; 34],
        private_secret: &[u8; 32],
    ) -> Result<EncryptedCredential>;
}

/// Encrypted challenge only. No Debug or serialization shortcut for private
/// enrollment channels. Constructor enforces bounds before local retention.
pub struct EncryptedCredential {
    credential: Vec<u8>,
    seed: Vec<u8>,
}
impl EncryptedCredential {
    pub fn new(credential: Vec<u8>, seed: Vec<u8>) -> Result<Self> {
        if credential.is_empty() || seed.is_empty()
            || credential.len() > MAX_ENCRYPTED_BYTES || seed.len() > MAX_ENCRYPTED_BYTES
        {
            return Err(Failure::EncryptedBounds);
        }
        Ok(Self { credential, seed })
    }
    pub fn credential(&self) -> &[u8] { &self.credential }
    pub fn encrypted_seed(&self) -> &[u8] { &self.seed }
}

/// Provider must validate own-chain current context, revocation, complete class
/// qualification and the exact transition's authorization. No peer response,
/// nonzero hash, cached admission or public witness alone satisfies this contract.
/// The result still cannot authorize post-sealing unilateral hardware admission.
pub trait CurrentContext {
    fn current_for(&mut self, scope: &Scope) -> Result<Anchor>;
}

pub struct Challenge {
    pub class_index: u8,
    pub ek_identity: Hash,
    pub encrypted: EncryptedCredential,
}
/// A fresh session identifier is random public routing metadata, not an identity.
pub struct Exchange {
    pub session: Hash,
    pub scope: Scope,
    pub challenges: Vec<Challenge>,
}

/// Raw returned private value, delivered through the authenticated private
/// enrollment channel. No Clone, Debug or serialization; Drop zeroizes it.
pub struct RecoveryResponse {
    class_index: u8,
    secret: Zeroizing<[u8; 32]>,
}
impl RecoveryResponse {
    /// Transfer an already protected buffer; caller must also protect/erase any
    /// transport receive buffer. No raw by-value array convenience API exists.
    pub fn new(class_index: u8, raw_secret: Zeroizing<[u8; 32]>) -> Self {
        Self { class_index, secret: raw_secret }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicClassObservation {
    pub ek_identity: Hash,
    pub credential_sha256: Hash,
    pub encrypted_seed_sha256: Hash,
}
/// Public local observation only. NOT an admission proof/capability and no
/// physical uniqueness assertion. A malicious verifier can fabricate its own
/// observations because it chooses the secrets. No private result is retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalObservation {
    pub session: Hash,
    pub scope: Scope,
    pub classes: Vec<PublicClassObservation>,
}
struct PendingClass {
    expected_commitment: Hash,
    public: PublicClassObservation,
}
struct Pending {
    scope: Scope,
    classes: Vec<PendingClass>,
    deadline: Duration,
}

/// Trusted LOCAL elapsed source, never applicant/peer time or a wall clock.
/// This governs challenge freshness only, not consensus admission/active-key
/// timing or physical host clock qualification. Failure poisons this workflow.
pub trait ElapsedClock {
    fn elapsed(&mut self) -> Result<Duration>;
}
struct ProcessElapsed { origin: Instant }
impl ElapsedClock for ProcessElapsed {
    fn elapsed(&mut self) -> Result<Duration> {
        Instant::now().checked_duration_since(self.origin).ok_or(Failure::Elapsed)
    }
}

/// Bounded local pending map. Crash/restart forgets attempts and requires new
/// challenges. It does not reserve a canonical lineage or expire active keys.
pub struct Workflow {
    capacity: usize,
    pending: BTreeMap<Hash, Pending>,
    lifetime: Duration,
    clock: Box<dyn ElapsedClock>,
    last_elapsed: Option<Duration>,
    poisoned_elapsed: bool,
}
impl Workflow {
    /// Caller selects a finite positive LOCAL freshness limit. No consensus
    /// window is selected here and no unlimited/disabled expiry mode exists.
    pub fn new(local_pending_capacity: usize, local_lifetime: Duration) -> Result<Self> {
        Self::with_elapsed_source(local_pending_capacity, local_lifetime,
            Box::new(ProcessElapsed { origin: Instant::now() }))
    }
    pub fn with_elapsed_source(
        local_pending_capacity: usize, local_lifetime: Duration, clock: Box<dyn ElapsedClock>,
    ) -> Result<Self> {
        if local_pending_capacity == 0 { return Err(Failure::Capacity); }
        if local_lifetime.is_zero() { return Err(Failure::DeadlineOverflow); }
        Ok(Self { capacity: local_pending_capacity, pending: BTreeMap::new(),
            lifetime: local_lifetime, clock, last_elapsed: None, poisoned_elapsed: false })
    }
    pub fn pending_count(&self) -> usize { self.pending.len() }
    fn now(&mut self) -> Result<Duration> {
        if self.poisoned_elapsed { return Err(Failure::Elapsed); }
        match self.clock.elapsed() {
            Ok(now) if self.last_elapsed.is_none_or(|last| now >= last) => {
                self.last_elapsed = Some(now);
                Ok(now)
            }
            _ => {
                // Pending challenge commitments authorize nothing after a lost
                // time basis. Restart requires entirely new random challenges.
                self.poisoned_elapsed = true;
                self.pending.clear();
                Err(Failure::Elapsed)
            }
        }
    }

    pub fn begin(
        &mut self,
        candidate: &Candidate,
        provider: &mut dyn CurrentContext,
        adapter: &mut dyn MakeCredential,
    ) -> Result<Exchange> {
        let started = self.now()?;
        self.pending.retain(|_, pending| started < pending.deadline);
        let deadline = started.checked_add(self.lifetime).ok_or(Failure::DeadlineOverflow)?;
        if self.pending.len() >= self.capacity { return Err(Failure::Capacity); }
        if candidate.endorsements.is_empty()
            || candidate.endorsements.len() > mutiny_consensus_v8::endorsement_identity::MAX_IDENTITY_CLASSES
            || candidate.endorsements.iter().map(|e| e.identity).collect::<BTreeSet<_>>().len()
                != candidate.endorsements.len()
        {
            return Err(Failure::Classes);
        }
        candidate.scope.anchor.check()?;
        if provider.current_for(&candidate.scope)? != candidate.scope.anchor {
            return Err(Failure::Context);
        }
        let mut session = [0u8; 32];
        getrandom::getrandom(&mut session).map_err(|_| Failure::Randomness)?;
        if session == [0; 32] || self.pending.contains_key(&session) {
            return Err(Failure::Randomness);
        }
        let mut challenges = Vec::with_capacity(candidate.endorsements.len());
        let mut classes = Vec::with_capacity(candidate.endorsements.len());
        let mut commitments = BTreeSet::new();
        for (i, endorsement) in candidate.endorsements.iter().enumerate() {
            let mut secret = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(secret.as_mut()).map_err(|_| Failure::Randomness)?;
            if *secret == [0; 32] { return Err(Failure::Randomness); }
            let expected_commitment = secret_commitment(&secret);
            if !commitments.insert(expected_commitment) { return Err(Failure::Randomness); }
            let encrypted = adapter.make_credential(
                &endorsement.public_area, &candidate.scope.ak_name, &secret,
            )?;
            // Keep this boundary even if adapter internals change later.
            if encrypted.credential.is_empty() || encrypted.seed.is_empty()
                || encrypted.credential.len() > MAX_ENCRYPTED_BYTES || encrypted.seed.len() > MAX_ENCRYPTED_BYTES
            {
                return Err(Failure::EncryptedBounds);
            }
            classes.push(PendingClass {
                expected_commitment,
                public: PublicClassObservation {
                    ek_identity: endorsement.identity,
                    credential_sha256: Sha256::digest(&encrypted.credential).into(),
                    encrypted_seed_sha256: Sha256::digest(&encrypted.seed).into(),
                },
            });
            challenges.push(Challenge { class_index: i as u8, ek_identity: endorsement.identity, encrypted });
        }
        // No partial pending insertion if a class adapter or context check fails.
        if provider.current_for(&candidate.scope)? != candidate.scope.anchor {
            return Err(Failure::Context);
        }
        if self.now()? >= deadline { return Err(Failure::Expired); }
        self.pending.insert(session, Pending { scope: candidate.scope.clone(), classes, deadline });
        Ok(Exchange { session, scope: candidate.scope.clone(), challenges })
    }

    pub fn complete(
        &mut self,
        session: Hash,
        exact_scope: &Scope,
        responses: Vec<RecoveryResponse>,
        provider: &mut dyn CurrentContext,
    ) -> Result<LocalObservation> {
        // Consume BEFORE checking anything. Wrong responses are never an oracle
        // granting repeated guesses, and never leave a partially accepted class.
        let pending = self.pending.remove(&session).ok_or(Failure::UnknownAttempt)?;
        if self.now()? >= pending.deadline { return Err(Failure::Expired); }
        if pending.scope != *exact_scope || provider.current_for(&pending.scope)? != pending.scope.anchor {
            return Err(Failure::Context);
        }
        if responses.len() != pending.classes.len() { return Err(Failure::ResponseClasses); }
        for (i, (response, expected)) in responses.iter().zip(&pending.classes).enumerate() {
            if usize::from(response.class_index) != i { return Err(Failure::ResponseClasses); }
            if secret_commitment(&response.secret) != expected.expected_commitment {
                return Err(Failure::SecretMismatch);
            }
        }
        if provider.current_for(&pending.scope)? != pending.scope.anchor { return Err(Failure::Context); }
        if self.now()? >= pending.deadline { return Err(Failure::Expired); }
        Ok(LocalObservation {
            session,
            scope: pending.scope,
            classes: pending.classes.into_iter().map(|c| c.public).collect(),
        })
    }
    /// Explicit local cancellation after disconnect/context invalidation; no
    /// effect on canonical member history, keys, reputation, penalty or money.
    pub fn cancel(&mut self, session: Hash) -> bool { self.pending.remove(&session).is_some() }
}
fn secret_commitment(secret: &[u8; 32]) -> Hash {
    mutiny_consensus_v8::domain_hash(SECRET_DOMAIN, secret)
}

#[cfg(test)]
mod software_only_controls {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    struct ModeledElapsed(Rc<Cell<Option<Duration>>>);
    impl ElapsedClock for ModeledElapsed {
        fn elapsed(&mut self) -> Result<Duration> {
            self.0.get().ok_or(Failure::Elapsed)
        }
    }
    fn timed_workflow(capacity: usize, lifetime: Duration, at: Duration)
        -> (Workflow, Rc<Cell<Option<Duration>>>)
    {
        let elapsed = Rc::new(Cell::new(Some(at)));
        let workflow = Workflow::with_elapsed_source(capacity, lifetime,
            Box::new(ModeledElapsed(elapsed.clone()))).unwrap();
        (workflow, elapsed)
    }
    fn modeled_workflow(capacity: usize) -> Workflow {
        timed_workflow(capacity, Duration::from_secs(60), Duration::ZERO).0
    }

    // These synthetic public areas are intentionally NOT native valid EKs/AKs.
    // This private constructor exercises bounded workflow mechanics only. It
    // cannot call Candidate::validate or establish class/physical qualification.
    fn modeled_candidate(n: usize) -> Candidate {
        Candidate {
            scope: Scope {
                anchor: Anchor {
                    network: NETWORK_ID, admission_class: AdmissionClass::LegacyTest,
                    genesis: [1; 32], fingerprint: [2; 32],
                    parent: [3; 32], purpose: Purpose::Join,
                    authorized_transition: [4; 32], identity_classes: [5; 32], verifier_policy: [6; 32],
                },
                node: [7; 32], hardware_generation: 1, key_generation: 1,
                binding_wire_sha256: [8; 32], profile_commitment: [9; 32], ak_name: [10; 34],
            },
            endorsements: (0..n).map(|i| Endorsement {
                identity: [i as u8 + 11; 32], public_area: vec![i as u8 + 11; 8],
            }).collect(),
        }
    }
    struct ModeledContext {
        anchor: Anchor,
        calls: usize,
        change_on: Option<usize>,
        refuse_on: Option<usize>,
    }
    impl CurrentContext for ModeledContext {
        fn current_for(&mut self, _: &Scope) -> Result<Anchor> {
            self.calls += 1;
            if self.refuse_on == Some(self.calls) { return Err(Failure::Provider); }
            let mut anchor = self.anchor.clone();
            if self.change_on == Some(self.calls) { anchor.parent = [99; 32]; }
            Ok(anchor)
        }
    }
    // TEST-VALUE only: no real MakeCredential mathematics/TPM interaction.
    // Captured ephemeral values never printed or serialized. This mock is NOT
    // a production cryptographic adapter or physical-activation qualification.
    #[derive(Default)]
    struct ModeledAdapter {
        responses: Vec<RecoveryResponse>,
        expected_inputs: Vec<(Vec<u8>, [u8; 34])>,
        fail_on: Option<usize>,
        calls: usize,
    }
    impl MakeCredential for ModeledAdapter {
        fn make_credential(&mut self, ek: &[u8], name: &[u8; 34], secret: &[u8; 32]) -> Result<EncryptedCredential> {
            self.calls += 1;
            if self.fail_on == Some(self.calls) { return Err(Failure::Adapter); }
            self.expected_inputs.push((ek.to_vec(), *name));
            self.responses.push(RecoveryResponse::new((self.calls - 1) as u8, Zeroizing::new(*secret)));
            EncryptedCredential::new(vec![self.calls as u8; 20], vec![self.calls as u8 + 20; 64])
        }
    }
    fn setup(n: usize) -> (Workflow, Candidate, ModeledContext, ModeledAdapter) {
        let candidate = modeled_candidate(n);
        let context = ModeledContext { anchor: candidate.scope.anchor.clone(), calls: 0, change_on: None, refuse_on: None };
        (modeled_workflow(2), candidate, context, ModeledAdapter::default())
    }
    fn result_error<T>(result: Result<T>) -> Failure {
        match result { Err(e) => e, Ok(_) => panic!("unexpected modeled acceptance") }
    }

    struct AdvancingContext {
        context: ModeledContext,
        clock: Rc<Cell<Option<Duration>>>,
        on_call: usize,
        value: Option<Duration>,
    }
    impl CurrentContext for AdvancingContext {
        fn current_for(&mut self, scope: &Scope) -> Result<Anchor> {
            let result = self.context.current_for(scope);
            if self.context.calls == self.on_call { self.clock.set(self.value); }
            result
        }
    }

    #[test]
    fn software_model_elapsed_deadline_is_exclusive_and_consumes_expired_attempt() {
        for seconds in [9, 10, 11] {
            let (_, c, mut p, mut a) = setup(1);
            let (mut w, clock) = timed_workflow(1, Duration::from_secs(10), Duration::ZERO);
            let e = w.begin(&c, &mut p, &mut a).unwrap();
            clock.set(Some(Duration::from_secs(seconds)));
            let result = w.complete(e.session, &e.scope, std::mem::take(&mut a.responses), &mut p);
            if seconds < 10 { assert!(result.is_ok()); }
            else { assert_eq!(result_error(result), Failure::Expired); }
            assert_eq!(w.pending_count(), 0);
            assert_eq!(result_error(w.complete(e.session, &e.scope, vec![], &mut p)), Failure::UnknownAttempt);
        }
    }
    #[test]
    fn software_model_elapsed_post_issue_and_post_completion_rechecked() {
        for call in [2, 4] {
            let (_, c, p, mut a) = setup(1);
            let (mut w, clock) = timed_workflow(1, Duration::from_secs(10), Duration::ZERO);
            let mut p = AdvancingContext { context: p, clock, on_call: call,
                value: Some(Duration::from_secs(10)) };
            if call == 2 {
                assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::Expired);
            } else {
                let e = w.begin(&c, &mut p, &mut a).unwrap();
                assert_eq!(result_error(w.complete(e.session, &e.scope,
                    std::mem::take(&mut a.responses), &mut p)), Failure::Expired);
            }
            assert_eq!(w.pending_count(), 0);
        }
    }
    #[test]
    fn software_model_expired_capacity_removed_without_reusable_reply() {
        let (_, c, mut p, mut a) = setup(1);
        let (mut w, clock) = timed_workflow(1, Duration::from_secs(10), Duration::ZERO);
        let old = w.begin(&c, &mut p, &mut a).unwrap();
        clock.set(Some(Duration::from_secs(10)));
        let mut next_adapter = ModeledAdapter::default();
        let next = w.begin(&c, &mut p, &mut next_adapter).unwrap();
        assert_eq!(w.pending_count(), 1);
        assert_eq!(result_error(w.complete(old.session, &old.scope,
            std::mem::take(&mut a.responses), &mut p)), Failure::UnknownAttempt);
        assert!(w.complete(next.session, &next.scope,
            std::mem::take(&mut next_adapter.responses), &mut p).is_ok());
    }
    #[test]
    fn software_model_elapsed_unavailable_or_backwards_poison_all_pending() {
        for fault in [None, Some(Duration::from_secs(4))] {
            let (_, c, mut p, mut a) = setup(1);
            let (mut w, clock) = timed_workflow(2, Duration::from_secs(10), Duration::from_secs(5));
            let first = w.begin(&c, &mut p, &mut a).unwrap();
            let mut other_adapter = ModeledAdapter::default();
            let other = w.begin(&c, &mut p, &mut other_adapter).unwrap();
            clock.set(fault);
            assert_eq!(result_error(w.complete(first.session, &first.scope,
                std::mem::take(&mut a.responses), &mut p)), Failure::Elapsed);
            assert_eq!(w.pending_count(), 0);
            clock.set(Some(Duration::from_secs(6)));
            assert_eq!(result_error(w.begin(&c, &mut p, &mut other_adapter)), Failure::Elapsed);
            assert_eq!(result_error(w.complete(other.session, &other.scope,
                std::mem::take(&mut other_adapter.responses), &mut p)), Failure::UnknownAttempt);
        }
    }
    #[test]
    fn software_model_elapsed_post_provider_loss_refuses_observation() {
        for call in [2, 4] {
            let (_, c, p, mut a) = setup(1);
            let (mut w, clock) = timed_workflow(1, Duration::from_secs(10), Duration::ZERO);
            let mut p = AdvancingContext { context: p, clock, on_call: call, value: None };
            if call == 2 {
                assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::Elapsed);
            } else {
                let e = w.begin(&c, &mut p, &mut a).unwrap();
                assert_eq!(result_error(w.complete(e.session, &e.scope,
                    std::mem::take(&mut a.responses), &mut p)), Failure::Elapsed);
            }
            assert_eq!(w.pending_count(), 0);
        }
    }
    #[test]
    fn software_model_elapsed_checked_overflow_and_zero_limit_refuse_before_adapter() {
        assert_eq!(result_error(Workflow::new(1, Duration::ZERO)), Failure::DeadlineOverflow);
        assert_eq!(result_error(Workflow::new(0, Duration::from_secs(1))), Failure::Capacity);
        let (_, c, mut p, mut a) = setup(1);
        let (mut w, _) = timed_workflow(1, Duration::from_secs(1), Duration::MAX);
        assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::DeadlineOverflow);
        assert_eq!(w.pending_count(), 0);
        assert_eq!(a.calls, 0);
        assert_eq!(p.calls, 0);
    }

    #[test]
    fn software_model_complete_classes_one_shot_exact_adapter_inputs() {
        let (mut w, c, mut p, mut a) = setup(2);
        let exchange = w.begin(&c, &mut p, &mut a).unwrap();
        assert_eq!(w.pending_count(), 1);
        assert_eq!(exchange.challenges.len(), 2);
        for (i, (ek, name)) in a.expected_inputs.iter().enumerate() {
            assert_eq!(ek, &c.endorsements[i].public_area);
            assert_eq!(name, &c.scope.ak_name);
        }
        let observed = w.complete(exchange.session, &exchange.scope, std::mem::take(&mut a.responses), &mut p).unwrap();
        assert_eq!(observed.scope, c.scope);
        assert_eq!(observed.classes.len(), 2);
        assert_eq!(w.pending_count(), 0);
        assert_eq!(result_error(w.complete(exchange.session, &exchange.scope, vec![], &mut p)), Failure::UnknownAttempt);
    }
    #[test]
    fn software_model_each_public_context_substitution_consumes_attempt() {
        // Independently vary each field, including exact wire hash/tuple
        // generation and transition context. None can reinterpret a recovery.
        for field in 0..16 {
            let (mut w, c, mut p, mut a) = setup(1);
            let e = w.begin(&c, &mut p, &mut a).unwrap();
            let mut wrong = e.scope.clone();
            match field {
                0 => wrong.anchor.network ^= 1,
                1 => wrong.anchor.genesis = [31; 32],
                2 => wrong.anchor.fingerprint = [32; 32],
                3 => wrong.anchor.parent = [33; 32],
                4 => wrong.anchor.purpose = Purpose::Recovery,
                5 => wrong.anchor.authorized_transition = [35; 32],
                6 => wrong.anchor.identity_classes = [36; 32],
                7 => wrong.anchor.verifier_policy = [37; 32],
                8 => wrong.node = [38; 32],
                9 => wrong.hardware_generation += 1,
                10 => wrong.key_generation += 1,
                11 => wrong.binding_wire_sha256 = [41; 32],
                12 => wrong.profile_commitment = [42; 32],
                13 => wrong.ak_name = [43; 34],
                14 => wrong.anchor.purpose = Purpose::KeyRotation,
                _ => wrong.anchor.admission_class = AdmissionClass::Production,
            }
            assert_eq!(result_error(w.complete(e.session, &wrong, std::mem::take(&mut a.responses), &mut p)), Failure::Context);
            assert_eq!(w.pending_count(), 0);
        }
    }
    #[test]
    fn software_model_wrong_secret_consumes_whole_attempt() {
        let (mut w, c, mut p, mut a) = setup(2);
        let e = w.begin(&c, &mut p, &mut a).unwrap();
        a.responses[1].secret[0] ^= 1;
        assert_eq!(result_error(w.complete(e.session, &e.scope, std::mem::take(&mut a.responses), &mut p)), Failure::SecretMismatch);
        assert_eq!(w.pending_count(), 0);
    }
    #[test]
    fn software_model_cross_attempt_recovery_cannot_substitute_fresh_challenge() {
        let (mut w, c, mut p, mut a) = setup(1);
        let first = w.begin(&c, &mut p, &mut a).unwrap();
        let mut second_adapter = ModeledAdapter::default();
        let second = w.begin(&c, &mut p, &mut second_adapter).unwrap();
        assert_ne!(first.session, second.session);
        assert_eq!(result_error(w.complete(second.session, &second.scope, std::mem::take(&mut a.responses), &mut p)), Failure::SecretMismatch);
        assert_eq!(w.pending_count(), 1);
        assert!(w.cancel(first.session));
    }
    #[test]
    fn software_model_partial_or_wrong_class_order_never_completes() {
        for fault in 0..3 {
            let (mut w, c, mut p, mut a) = setup(2);
            let e = w.begin(&c, &mut p, &mut a).unwrap();
            match fault {
                0 => { a.responses.pop(); }
                1 => a.responses.swap(0, 1),
                _ => a.responses[1].class_index = 0,
            }
            assert_eq!(result_error(w.complete(e.session, &e.scope, std::mem::take(&mut a.responses), &mut p)), Failure::ResponseClasses);
            assert_eq!(w.pending_count(), 0);
        }
    }
    #[test]
    fn software_model_current_context_pre_and_post_issue_required() {
        for call in [1, 2] {
            let (mut w, c, mut p, mut a) = setup(2);
            p.change_on = Some(call);
            assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::Context);
            assert_eq!(w.pending_count(), 0);
            if call == 1 { assert_eq!(a.calls, 0); }
        }
    }
    #[test]
    fn software_model_current_context_pre_and_post_complete_required() {
        for call in [3, 4] {
            let (mut w, c, mut p, mut a) = setup(2);
            let e = w.begin(&c, &mut p, &mut a).unwrap();
            p.change_on = Some(call);
            assert_eq!(result_error(w.complete(e.session, &e.scope, std::mem::take(&mut a.responses), &mut p)), Failure::Context);
            assert_eq!(w.pending_count(), 0);
        }
    }
    #[test]
    fn software_model_provider_refusal_never_leaves_pending_partial() {
        for call in [1, 2, 3, 4] {
            let (mut w, c, mut p, mut a) = setup(2);
            p.refuse_on = Some(call);
            if call <= 2 {
                assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::Provider);
            } else {
                let e = w.begin(&c, &mut p, &mut a).unwrap();
                assert_eq!(result_error(w.complete(e.session, &e.scope, std::mem::take(&mut a.responses), &mut p)), Failure::Provider);
            }
            assert_eq!(w.pending_count(), 0);
        }
    }
    #[test]
    fn software_model_adapter_partial_failure_never_inserts_pending() {
        let (mut w, c, mut p, mut a) = setup(2);
        a.fail_on = Some(2);
        assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::Adapter);
        assert_eq!(w.pending_count(), 0);
        assert_eq!(a.calls, 2);
    }
    #[test]
    fn software_model_local_capacity_preserves_first_pending_attempt() {
        let (_, c, mut p, mut a) = setup(1);
        let mut w = modeled_workflow(1);
        let e = w.begin(&c, &mut p, &mut a).unwrap();
        assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::Capacity);
        assert_eq!(a.calls, 1);
        assert_eq!(w.pending_count(), 1);
        assert!(w.complete(e.session, &e.scope, std::mem::take(&mut a.responses), &mut p).is_ok());
    }
    #[test]
    fn software_model_cancel_restart_cannot_resume_old_response() {
        let (mut w, c, mut p, mut a) = setup(1);
        let e = w.begin(&c, &mut p, &mut a).unwrap();
        assert!(w.cancel(e.session));
        assert!(!w.cancel(e.session));
        let mut restarted = modeled_workflow(2);
        assert_eq!(result_error(restarted.complete(e.session, &e.scope, std::mem::take(&mut a.responses), &mut p)), Failure::UnknownAttempt);
    }
    #[test]
    fn software_model_duplicate_or_incomplete_identity_set_refused() {
        for n in [0, 5] {
            let (mut w, c, mut p, mut a) = setup(n);
            assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::Classes);
            assert_eq!(a.calls, 0);
        }
        let (mut w, mut c, mut p, mut a) = setup(2);
        c.endorsements[1].identity = c.endorsements[0].identity;
        assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::Classes);
    }
    #[test]
    fn software_model_encrypted_bounds_refuse_empty_and_oversized() {
        for (c, s) in [(vec![], vec![1]), (vec![1], vec![]), (vec![1; MAX_ENCRYPTED_BYTES + 1], vec![1])]
        {
            assert_eq!(result_error(EncryptedCredential::new(c, s)), Failure::EncryptedBounds);
        }
    }
    #[test]
    fn software_model_genesis_parent_scope_has_no_join_fallback() {
        let (mut w, mut c, mut p, mut a) = setup(1);
        c.scope.anchor.purpose = Purpose::Genesis;
        p.anchor = c.scope.anchor.clone();
        assert_eq!(result_error(w.begin(&c, &mut p, &mut a)), Failure::Context);
        c.scope.anchor.parent = [0; 32];
        p.anchor = c.scope.anchor.clone();
        assert!(w.begin(&c, &mut p, &mut a).is_ok());
    }
}
