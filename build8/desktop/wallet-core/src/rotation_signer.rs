//! The two-key signing session of a wallet rotation, [`RotationSigner`] (re-exported as
//! `ops::rotation::RotationSigner`, its public path).
//!
//! It holds private keys, so it lives outside the rotation handler module (Order W4: no handler
//! module holds a key). Moved unchanged from `ops/rotation.rs`, except that both keys are sealed
//! (`capability::SealedKey`) the moment the constructor receives them.
use crate::{
    authorize::{
        Approval, GateMode, SignedOperation, Signer, SignerIdentity, SigningGate, run_authorization,
    },
    capability::{KeyRing, SealedKey},
    context::ChainView,
    ops::rotation::{REASON_SESSION_KIND, check_keys},
    plan::{OperationKind, OperationPlan},
    refusal::Refusal,
    units,
};
use mutiny_consensus_v8::Hash;
use mutiny_crypto_v2::{HybridKey, Role};
use std::{
    fmt,
    sync::Mutex,
    time::{Duration, Instant},
};

struct SessionKeys {
    current: SealedKey,
    proposed: SealedKey,
}

struct SessionState {
    keys: Option<SessionKeys>,
    last_activity: Instant,
}

/// A signer that holds BOTH keys of one wallet rotation: the authority's current key (the
/// authorization) and the new key (the possession proof, and the funding inputs of the rotating
/// authority). Both keys are erased together on [`lock`](Self::lock), on idle expiry and on drop;
/// they are held SEALED (`capability::SealedKey`), never appear in `Debug` output or a refusal, and
/// reach a signature only through the shared
/// authorization pipeline (gate, approval, binding, per-slot authority, independent verification),
/// with the domains `domain_for` lists for `WalletRotation`. Constructing one needs a
/// [`SigningGate`], which does not exist in a shipping build while production qualification is
/// incomplete. It authorizes the wallet rotation and nothing else.
pub struct RotationSigner {
    identity: SignerIdentity,
    proposed_descriptor: Vec<u8>,
    proposed_address: Hash,
    gate: SigningGate,
    idle_limit: Duration,
    state: Mutex<SessionState>,
}

impl RotationSigner {
    /// A session for rotating the authority `identity` names (its CURRENT key is `current`) to
    /// `proposed`, at the next generation. A host may shorten the idle limit, never lengthen it:
    /// anything above `DEFAULT_IDLE_LIMIT` is clamped to it (fixes of the independent wallet
    /// review, MINOR-6).
    pub fn new(
        current: HybridKey,
        identity: SignerIdentity,
        proposed: HybridKey,
        gate: SigningGate,
        idle_limit: Duration,
    ) -> Result<Self, Refusal> {
        if current
            .public()
            .descriptor(identity.generation())
            .map_err(|_| Refusal::InvalidDescriptor)?
            != identity.descriptor()
        {
            return Err(Refusal::InvalidDescriptor);
        }
        if proposed.public().role != Role::WalletOwner {
            return Err(Refusal::InvalidDescriptor);
        }
        let generation = identity
            .generation()
            .checked_add(1)
            .ok_or(Refusal::Overflow)?;
        check_keys(
            current.public(),
            identity.generation(),
            proposed.public(),
            generation,
        )?;
        let proposed_descriptor = proposed
            .public()
            .descriptor(generation)
            .map_err(|_| Refusal::InvalidDescriptor)?;
        let proposed_address = proposed
            .public()
            .address_id(generation)
            .map_err(|_| Refusal::InvalidDescriptor)?;
        Ok(Self {
            identity,
            proposed_descriptor,
            proposed_address,
            gate,
            idle_limit: idle_limit.min(crate::authorize::DEFAULT_IDLE_LIMIT),
            state: Mutex::new(SessionState {
                keys: Some(SessionKeys {
                    current: SealedKey::seal(current),
                    proposed: SealedKey::seal(proposed),
                }),
                last_activity: Instant::now(),
            }),
        })
    }

    /// Test constructor: a session behind the TEST-VALUE gate with the default idle limit.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn for_test(
        current: HybridKey,
        identity: SignerIdentity,
        proposed: HybridKey,
    ) -> Result<Self, Refusal> {
        Self::new(
            current,
            identity,
            proposed,
            SigningGate::test_value()?,
            crate::authorize::DEFAULT_IDLE_LIMIT,
        )
    }

    /// The new key's descriptor at the next generation (public).
    pub fn proposed_descriptor(&self) -> &[u8] {
        &self.proposed_descriptor
    }

    /// The new key's address at the next generation (public).
    pub fn proposed_address(&self) -> Hash {
        self.proposed_address
    }

    /// Erase both keys now. Every later authorization is `Locked`.
    pub fn lock(&self) {
        self.guard().keys = None;
    }

    /// The key state. A poisoned lock (a panic while signing) erases both keys and is reported as
    /// locked: fail closed.
    fn guard(&self) -> std::sync::MutexGuard<'_, SessionState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.keys = None;
                guard
            }
        }
    }

    pub fn is_locked(&self) -> bool {
        let state = self.guard();
        state.keys.is_none() || state.last_activity.elapsed() >= self.idle_limit
    }

    /// Record user input. Input at or after the idle limit cannot revive the session.
    pub fn touch(&self) -> Result<(), Refusal> {
        let mut state = self.guard();
        let now = Instant::now();
        if state.keys.is_some()
            && now.saturating_duration_since(state.last_activity) >= self.idle_limit
        {
            state.keys = None;
        }
        if state.keys.is_none() {
            return Err(Refusal::Locked);
        }
        state.last_activity = now;
        Ok(())
    }

    pub fn gate_mode(&self) -> GateMode {
        self.gate.mode()
    }

    /// [`Signer::authorize`] with an explicit clock. Test builds only.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn authorize_at(
        &self,
        plan: OperationPlan,
        approval: Approval,
        view: &ChainView<'_>,
        now: Instant,
    ) -> Result<SignedOperation, Refusal> {
        self.authorize_with(plan, approval, view, now)
    }

    fn authorize_with(
        &self,
        plan: OperationPlan,
        approval: Approval,
        view: &ChainView<'_>,
        now: Instant,
    ) -> Result<SignedOperation, Refusal> {
        let mut state = self.guard();
        if state.keys.is_some()
            && now.saturating_duration_since(state.last_activity) >= self.idle_limit
        {
            state.keys = None;
        }
        let SessionState {
            keys,
            last_activity,
        } = &mut *state;
        let keys = keys.as_ref().ok_or(Refusal::Locked)?;
        if plan.kind() != OperationKind::WalletRotation {
            return Err(Refusal::InvalidRequest(REASON_SESSION_KIND));
        }
        let result = run_authorization(
            &self.gate,
            &self.identity,
            KeyRing::pair(&keys.current, &keys.proposed),
            plan,
            approval,
            view,
            now,
        );
        if result.is_ok() {
            *last_activity = now;
        }
        result
    }
}

impl Signer for RotationSigner {
    fn identity(&self) -> &SignerIdentity {
        &self.identity
    }

    fn authorize(
        &self,
        plan: OperationPlan,
        approval: Approval,
        view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        self.authorize_with(plan, approval, view, Instant::now())
    }
}

impl fmt::Debug for RotationSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotationSigner")
            .field("identity", &self.identity)
            .field("new_address", &units::short_hex(&self.proposed_address))
            .field("gate", &self.gate.mode())
            .field("locked", &self.is_locked())
            .field("keys", &"<redacted>")
            .finish()
    }
}
