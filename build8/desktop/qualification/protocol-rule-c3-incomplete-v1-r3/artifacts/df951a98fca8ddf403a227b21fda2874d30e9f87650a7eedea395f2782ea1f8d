//! Dedicated native dividend claim operation (Stage C). Status: NATIVE logic.
//!
//! A claim is a block OPERATION of its own class (candidate kind 23). It is not a Transfer, has
//! no fee input or fee field, and carries no outputs of its own: the protocol derives the exact
//! payment and any Treasury change. Because the class is structural, a claim cannot make any
//! unrelated transfer, trading operation or batch fee-exempt.
//!
//! Option B reserve construction: reserved value stays in canonical Treasury coins. A valid
//! claim authorizes the protocol to spend exactly `amount` of those coins, selected
//! deterministically (oldest Treasury address first, then OutPoint order), to the claimant's
//! signed destination, with change returned to the SAME Treasury address as the last coin
//! consumed. The claimant's BOTH_REQUIRED (Ed448 + FN-DSA-1024) signature binds the network,
//! Genesis, award, License, amount, destination, claim sequence and validity window. No Treasury
//! signature is involved or accepted. The destination is never the zero address (Order of
//! 4 October 2026, decision P3): `ClaimBody::decode` and `check` refuse it with
//! `ClaimError::Destination`; a zero address is never converted into a burn.
//!
//! Claims are partial and unlimited in number: any positive amount up to the remaining
//! entitlement. Replay protection is the per-(award, License) claim sequence kept in the award
//! record. Resource protection is structural and uses ONLY the existing canonical block limits:
//! a claim operation has a fixed maximum size (`MAX_OPERATION`, the same 16 KiB per-operation
//! limit every operation class has), the block body is bounded in bytes and items, so the number
//! of claims in a block (each verifies one hybrid signature) is bounded by the block body size.
//! This module defines NO separate per-block claim count. (Nonce, 2 Oct 2026: an earlier draft
//! carried a `MAX_CLAIMS_PER_BLOCK = 32` constant that was a test construction, not an existing
//! canonical limit; it was removed so that a test ceiling cannot become a consensus parameter.)
//! Cheap checks run before any signature verification, and `admit` is the bounded read-only
//! submission check a relay must use before queueing a claim.
use crate::{
    Hash, NETWORK_ID, domain_hash,
    dividends_v1::{Claim, DivError},
    execution::{ExecutionError, State},
    transactions::{Coin, EXPIRY_HORIZON, OutPoint, Output},
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey};
use std::collections::{BTreeMap, BTreeSet};

/// Candidate operation kind. Not a historical wire identifier.
pub const OPERATION_KIND: u8 = 23;
const BODY_VERSION: u8 = 1;
const MAX_OPERATION: usize = 16 * 1024;
const MAX_DESCRIPTOR: usize = 4096;
const SIGNATURE_BYTES: usize = 114 + 1280;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimError {
    Codec,
    Context,
    Window,
    UnknownLicense,
    /// The signer is not the License's current owner authority (wrong owner or stale generation).
    StaleOwner,
    Signature,
    Dividend(DivError),
    /// No sufficient Treasury coin set exists although the ledger says the value is reserved.
    Backing,
    Duplicate,
    Overflow,
    /// Dividend claims need an active Treasury identity.
    Inactive,
    /// The destination is the zero address (Order P3): refused, never an implicit burn.
    Destination,
}

impl From<DivError> for ClaimError {
    fn from(e: DivError) -> Self {
        Self::Dividend(e)
    }
}
impl From<ClaimError> for ExecutionError {
    fn from(e: ClaimError) -> Self {
        ExecutionError::Dividend(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimBody {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub created_height: u64,
    pub expiry_height: u64,
    pub award_epoch: u64,
    pub license: Hash,
    pub amount: u64,
    pub destination: Hash,
    /// Claim number for this (award, License): must equal the number of earlier successful
    /// claims recorded in the award. It is the replay counter and also keeps claim ids unique.
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedClaim {
    pub body: ClaimBody,
    pub descriptor: Vec<u8>,
    pub signature: HybridSignature,
}

impl ClaimBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(11)
            .unwrap()
            .u8(BODY_VERSION)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u64(self.created_height)
            .unwrap()
            .u64(self.expiry_height)
            .unwrap()
            .u64(self.award_epoch)
            .unwrap()
            .bytes(&self.license)
            .unwrap()
            .u64(self.amount)
            .unwrap()
            .bytes(&self.destination)
            .unwrap()
            .u64(self.sequence)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self, ClaimError> {
        crate::blocks::canonical(raw, 1024).map_err(|_| ClaimError::Codec)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(bad_cbor)? != Some(11) || d.u8().map_err(bad_cbor)? != BODY_VERSION {
            return Err(ClaimError::Codec);
        }
        let hash = |d: &mut Decoder<'_>| -> Result<Hash, ClaimError> {
            d.bytes().map_err(bad_cbor)?.try_into().map_err(|_| ClaimError::Codec)
        };
        let body = Self {
            network: d.u32().map_err(bad_cbor)?,
            genesis: hash(&mut d)?,
            fingerprint: hash(&mut d)?,
            created_height: d.u64().map_err(bad_cbor)?,
            expiry_height: d.u64().map_err(bad_cbor)?,
            award_epoch: d.u64().map_err(bad_cbor)?,
            license: hash(&mut d)?,
            amount: d.u64().map_err(bad_cbor)?,
            destination: hash(&mut d)?,
            sequence: d.u64().map_err(bad_cbor)?,
        };
        if d.position() != raw.len() || body.encode() != raw {
            return Err(ClaimError::Codec);
        }
        // P3 (Lane P design 4.1 row 10): a zero destination is unrepresentable on the wire.
        if body.destination == [0; 32] {
            return Err(ClaimError::Destination);
        }
        Ok(body)
    }
    /// Unique claim identity: replay protection and the funding OutPoint namespace.
    pub fn id(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-DIVIDEND-CLAIM-ID-V1", &self.encode())
    }
}

impl SignedClaim {
    /// Signed content. Its CBOR shape (array of three, leading label) cannot be confused with a
    /// Transfer signing payload (array of two), so the shared wallet-transaction domain is safe.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .bytes(b"MUTINY-BUILD8-DIVIDEND-CLAIM-INTENT-V1")
            .unwrap()
            .bytes(&self.body.encode())
            .unwrap()
            .bytes(&self.descriptor)
            .unwrap();
        e.into_writer()
    }
    pub fn id(&self) -> Hash {
        self.body.id()
    }
    pub fn sign(body: ClaimBody, descriptor: Vec<u8>, key: &HybridKey) -> Result<Self, ClaimError> {
        let (public, _) = PublicKey::decode_descriptor(&descriptor).map_err(|_| ClaimError::Codec)?;
        if key.public() != &public {
            return Err(ClaimError::StaleOwner);
        }
        let mut claim = Self {
            body,
            descriptor,
            signature: HybridSignature { ed448: [0; 114], fndsa: [0; 1280] },
        };
        claim.signature = key
            .sign(Domain::Transaction, &claim.signing_payload())
            .map_err(|_| ClaimError::Signature)?;
        Ok(claim)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut sig = Vec::with_capacity(SIGNATURE_BYTES);
        sig.extend_from_slice(&self.signature.ed448);
        sig.extend_from_slice(&self.signature.fndsa);
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(OPERATION_KIND)
            .unwrap()
            .bytes(&self.body.encode())
            .unwrap()
            .bytes(&self.descriptor)
            .unwrap()
            .bytes(&sig)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self, ClaimError> {
        crate::blocks::canonical(raw, MAX_OPERATION).map_err(|_| ClaimError::Codec)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(bad_cbor)? != Some(5)
            || d.u8().map_err(bad_cbor)? != 2
            || d.u8().map_err(bad_cbor)? != OPERATION_KIND
        {
            return Err(ClaimError::Codec);
        }
        let body = ClaimBody::decode(d.bytes().map_err(bad_cbor)?)?;
        let descriptor = d.bytes().map_err(bad_cbor)?.to_vec();
        let sig = d.bytes().map_err(bad_cbor)?;
        if descriptor.len() > MAX_DESCRIPTOR || sig.len() != SIGNATURE_BYTES || d.position() != raw.len() {
            return Err(ClaimError::Codec);
        }
        let signature = HybridSignature {
            ed448: sig[..114].try_into().map_err(|_| ClaimError::Codec)?,
            fndsa: sig[114..].try_into().map_err(|_| ClaimError::Codec)?,
        };
        let claim = Self { body, descriptor, signature };
        if claim.encode() != raw {
            return Err(ClaimError::Codec);
        }
        Ok(claim)
    }
    /// Cryptographic check only. Owner authority and ledger rules are checked by `execute`.
    pub fn verify_signature(&self) -> Result<(), ClaimError> {
        let (public, _) = PublicKey::decode_descriptor(&self.descriptor).map_err(|_| ClaimError::Codec)?;
        public
            .verify(Domain::Transaction, &self.signing_payload(), &self.signature)
            .map_err(|_| ClaimError::Signature)
    }
}

/// Typed recognition used by block-body validation: the claim class is exactly kind 23.
pub fn is_claim(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten() == Some(5) && d.u8().ok() == Some(2) && d.u8().ok() == Some(OPERATION_KIND)
}

/// Monetary fee of the claim class. Structurally zero: a claim has no fee field or input and the
/// claimant receives exactly the authorized amount.
pub const CLAIM_FEE: u64 = 0;

fn bad_cbor<E>(_: E) -> ClaimError {
    ClaimError::Codec
}

impl State {
    /// Every address of the Treasury wallet authority, oldest generation first. The
    /// generation-one address is always included even before the WalletBook registers it.
    pub fn treasury_owner_order(&self) -> Vec<Hash> {
        let Some(treasury) = self.dividends.treasury() else {
            return Vec::new();
        };
        let authority = treasury.authority();
        let mut owners = self.wallets.addresses_of(authority);
        if !owners.iter().any(|(_, a)| *a == authority) {
            owners.push((1, authority));
        }
        owners.sort();
        owners.dedup_by_key(|(_, a)| *a);
        owners.into_iter().map(|(_, a)| a).collect()
    }
    /// The addresses of `treasury_owner_order` as a set: the owner set that reserve backing counts.
    pub fn treasury_owner_set(&self) -> BTreeSet<Hash> {
        self.treasury_owner_order().into_iter().collect()
    }
    /// Cross-record validation of the dividend component, including reserve backing. Invoked for
    /// every StateRoot computation, so no execution path can leave a reserve unbacked.
    pub(crate) fn validate_dividends(&self) -> crate::Result<()> {
        let licenses: BTreeSet<Hash> = self.licenses_v2.license_pairs().into_iter().map(|(id, _)| id).collect();
        self.dividends.validate(&self.coins, &self.treasury_owner_set(), &licenses)
    }
    /// TEST-VALUE setup only (test builds or the explicit fixture feature): run the same boundary
    /// processing at Genesis so a test chain can start with an award already outstanding. Refuses
    /// unless the Treasury is TEST-VALUE class.
    #[cfg(any(test, feature = "dividend-test-fixtures"))]
    pub fn fixture_advance_dividends(&mut self, epoch: u64) -> crate::Result<()> {
        self.dividends.fixture_guard()?;
        self.advance_dividends(epoch)
    }
    /// Process crossed expiry and award boundaries from canonical parent state, before the
    /// block applies any transaction, subsidy or fee.
    pub(crate) fn advance_dividends(&mut self, epoch: u64) -> crate::Result<()> {
        if !self.dividends.is_active() {
            return Ok(());
        }
        let backing = crate::dividend_state_v1::DividendState::backing(&self.coins, &self.treasury_owner_set())?;
        let triples = self.licenses_v2.license_activation_triples();
        self.dividends.advance(epoch, backing, &triples)?;
        Ok(())
    }
}

/// Execute every claim operation of a block, in block order, on the tentative state.
/// `epoch` is the ACTUAL epoch of the containing block. Any failure rejects the whole block:
/// the caller discards the tentative state.
pub(crate) fn execute(
    mut state: State,
    operations: &[Vec<u8>],
    genesis: Hash,
    fingerprint: Hash,
    height: u64,
    epoch: u64,
) -> Result<State, ClaimError> {
    if operations.is_empty() {
        return Ok(state);
    }
    if !state.dividends.is_active() {
        return Err(ClaimError::Inactive);
    }
    for raw in operations {
        let claim = SignedClaim::decode(raw)?;
        apply(&mut state, &claim, genesis, fingerprint, height, epoch)?;
    }
    Ok(state)
}

/// Everything a validated claim needs in order to be applied.
pub(crate) struct Checked {
    id: Hash,
    plan: Plan,
    ledger_claim: Claim,
    view: crate::dividends_v1::LicenseView,
}

/// Read-only validation. Cheap structural, context, window, ownership and entitlement checks
/// run first; the hybrid signature is verified only after they pass; Treasury coin selection
/// comes last. Nothing is modified.
pub(crate) fn check(
    state: &State,
    claim: &SignedClaim,
    genesis: Hash,
    fingerprint: Hash,
    height: u64,
    epoch: u64,
) -> Result<Checked, ClaimError> {
    let checked = check_state(state, claim, genesis, fingerprint, height, epoch)?;
    claim.verify_signature()?;
    Ok(checked)
}
pub(crate) fn check_state(
    state: &State,
    claim: &SignedClaim,
    genesis: Hash,
    fingerprint: Hash,
    height: u64,
    epoch: u64,
) -> Result<Checked, ClaimError> {
    let b = &claim.body;
    if !state.dividends.is_active() {
        return Err(ClaimError::Inactive);
    }
    if b.network != NETWORK_ID || b.genesis != genesis || b.fingerprint != fingerprint {
        return Err(ClaimError::Context);
    }
    // P3: refused here too, for a claim that did not come through `ClaimBody::decode`.
    if b.destination == [0; 32] {
        return Err(ClaimError::Destination);
    }
    if height < b.created_height
        || height > b.expiry_height
        || b.expiry_height - b.created_height > EXPIRY_HORIZON
    {
        return Err(ClaimError::Window);
    }
    let license = state.licenses_v2.license(b.license).ok_or(ClaimError::UnknownLicense)?;
    if license.genesis != genesis {
        return Err(ClaimError::UnknownLicense);
    }
    let owner = license.owner;
    let activation = state.licenses_v2.dividend_activation_epoch(b.license);
    let view = state.dividends.view(b.license, owner, activation);
    let ledger_claim = Claim {
        award_epoch: b.award_epoch,
        license: b.license,
        claimant: owner,
        amount: b.amount,
        sequence: b.sequence,
    };
    // Entitlement, status, window, sequence and amount against the ACTUAL block epoch.
    state.dividends.check_claim_ledger(&ledger_claim, &view, epoch)?;
    // Current owner authority only: wrong owners and stale key generations fail here.
    state.wallets.authorize(owner, &claim.descriptor).map_err(|_| ClaimError::StaleOwner)?;
    let order = state.treasury_owner_order();
    let plan = plan_spend(&state.coins, &order, b.amount)?;
    let id = claim.id();
    for index in [0u32, 1] {
        if state.coins.contains_key(&OutPoint { transaction: id, index }) {
            return Err(ClaimError::Duplicate);
        }
    }
    Ok(Checked { id, plan, ledger_claim, view })
}

/// Bounded submission check for a relay or assembler: decode (hard size bound) and fully
/// validate against the supplied state for the expected next block, without applying. A relay
/// must also bound how many claims it queues; the only consensus bound is the block body limit.
pub fn admit(
    state: &State,
    raw: &[u8],
    genesis: Hash,
    fingerprint: Hash,
    height: u64,
    epoch: u64,
) -> Result<(), ClaimError> {
    if raw.len() > MAX_OPERATION {
        return Err(ClaimError::Codec);
    }
    let claim = SignedClaim::decode(raw)?;
    check(state, &claim, genesis, fingerprint, height, epoch).map(|_| ())
}

/// Fully validate one claim and then apply it. All fallible checks, including the ledger's own
/// atomic claim, complete before any coin is touched.
pub(crate) fn apply(
    state: &mut State,
    claim: &SignedClaim,
    genesis: Hash,
    fingerprint: Hash,
    height: u64,
    epoch: u64,
) -> Result<(), ClaimError> {
    let b = &claim.body;
    let checked = check(state, claim, genesis, fingerprint, height, epoch)?;
    // Ledger claim is itself atomic; from here only infallible coin updates remain.
    state.dividends.claim_ledger(&checked.ledger_claim, &checked.view, epoch)?;
    let id = checked.id;
    let plan = checked.plan;
    for point in &plan.inputs {
        state.coins.remove(point);
    }
    state.coins.insert(
        OutPoint { transaction: id, index: 0 },
        Coin { output: Output { owner: b.destination, atoms: b.amount }, created_height: height, coinbase: false },
    );
    if plan.change > 0 {
        state.coins.insert(
            OutPoint { transaction: id, index: 1 },
            Coin {
                output: Output { owner: plan.change_owner, atoms: plan.change },
                created_height: height,
                coinbase: false,
            },
        );
    }
    Ok(())
}

pub struct Plan {
    pub inputs: Vec<OutPoint>,
    pub change_owner: Hash,
    pub change: u64,
}

/// Deterministic Treasury coin selection: owners oldest first, then OutPoint order; stops as
/// soon as `amount` is covered. Change belongs to the last coin's owner, so value never moves
/// between Treasury generations.
pub fn plan_spend(
    coins: &BTreeMap<OutPoint, Coin>,
    owners: &[Hash],
    amount: u64,
) -> Result<Plan, ClaimError> {
    let rank: BTreeMap<Hash, usize> = owners.iter().enumerate().map(|(i, a)| (*a, i)).collect();
    let mut candidates: Vec<(usize, &OutPoint, &Coin)> = coins
        .iter()
        .filter(|(_, c)| !c.coinbase)
        .filter_map(|(p, c)| rank.get(&c.output.owner).map(|r| (*r, p, c)))
        .collect();
    candidates.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let mut inputs = Vec::new();
    let mut total = 0u64;
    for (_, point, coin) in candidates {
        total = total.checked_add(coin.output.atoms).ok_or(ClaimError::Overflow)?;
        inputs.push(point.clone());
        if total >= amount {
            return Ok(Plan { inputs, change_owner: coin.output.owner, change: total - amount });
        }
    }
    Err(ClaimError::Backing)
}

#[cfg(test)]
mod zero_destination_tests {
    use super::*;
    use crate::{
        dividend_state_v1::DividendState,
        treasury_v1::{Class, Treasury},
    };
    use mutiny_crypto_v2::{HybridKey, Role};

    /// `check` refuses a zero destination by itself, for a claim built in memory that never went
    /// through `ClaimBody::decode` (Lane P design 4.1 row 10; Order P3). TEST-VALUE keys from
    /// public mnemonics.
    #[test]
    fn check_refuses_a_zero_destination_without_the_codec() {
        let treasury = HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
        let owner = HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner).unwrap();
        let state = State {
            dividends: DividendState::genesis(
                Treasury::new(Class::TestValue, treasury.public().descriptor(1).unwrap()).unwrap(),
            ),
            ..Default::default()
        };
        let body = |destination: Hash| ClaimBody {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            created_height: 1,
            expiry_height: 100,
            award_epoch: 131_072,
            license: [3; 32],
            amount: 5,
            destination,
            sequence: 0,
        };
        let descriptor = owner.public().descriptor(1).unwrap();
        let zero = SignedClaim::sign(body([0; 32]), descriptor.clone(), &owner).unwrap();
        zero.verify_signature().unwrap();
        assert_eq!(check(&state, &zero, [1; 32], [2; 32], 5, 131_073).err(), Some(ClaimError::Destination));
        // The same claim to a real destination passes this point and fails later (no License).
        let real = SignedClaim::sign(body([4; 32]), descriptor, &owner).unwrap();
        assert_eq!(check(&state, &real, [1; 32], [2; 32], 5, 131_073).err(), Some(ClaimError::UnknownLicense));
        // The codec refuses the zero destination as well.
        assert_eq!(SignedClaim::decode(&zero.encode()).err(), Some(ClaimError::Destination));
        assert_eq!(ClaimBody::decode(&body([0; 32]).encode()).err(), Some(ClaimError::Destination));
    }
}
