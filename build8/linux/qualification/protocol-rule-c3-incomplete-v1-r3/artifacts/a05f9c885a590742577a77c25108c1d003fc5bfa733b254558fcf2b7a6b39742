//! Explicit hybrid transaction envelopes: the hybrid Transfer (array(9)) and the funded
//! wallet-rotation bundle (array(7), tag 25, `funded_rotation_v2`). A wallet rotation is never a
//! free-standing state change: it exists only inside its funded bundle, where the rotation and its
//! funding are one item with one id, verified and applied by one function (Lane P design 3.1).
//! The retired `[2, 21, rotation, transfer]` wrapper (array(4)) no longer decodes
//! (`TxError::Codec`); there is no fallback to it and no V1/Ed25519 decoding fallback.
use crate::{
    Hash,
    anchors::FinalizedAnchor,
    evidence_history_v2::History,
    execution::State,
    funded_rotation_v2::FundedRotation,
    op_envelope_v1::Envelope,
    transactions::{MAX_TX_BYTES, OutPoint, Output, TxError},
    transactions_v2::Transfer,
    wallet_authority_v1::WalletBook,
};
use minicbor::Decoder;
type Result<T> = std::result::Result<T, TxError>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transaction {
    Transfer(Transfer),
    FundedRotation(FundedRotation),
}
pub struct VerifiedTransaction {
    pub(crate) id: Hash,
    pub(crate) fee: u64,
    pub(crate) inputs: Vec<OutPoint>,
    pub(crate) outputs: Vec<Output>,
    pub(crate) wallets: WalletBook,
}
/// Where a transaction is validated: the locally authenticated PARENT anchor (the inclusion height
/// is `parent.height + 1`) and the History whose anchors resolve an operation-envelope reference
/// older than the parent. Only the local canonical store may supply those anchors; a caller
/// without them passes `History::default()`, and then only a reference to the parent itself can
/// verify (fail closed, design 1.a.3).
#[derive(Clone, Copy)]
pub struct Inclusion<'a> {
    pub parent: &'a FinalizedAnchor,
    pub history: &'a History,
}
impl Inclusion<'_> {
    /// The inclusion height `parent.height + 1`.
    pub fn height(&self) -> Result<u64> {
        self.parent.height.checked_add(1).ok_or(TxError::Overflow)
    }
}
impl Transaction {
    /// Cryptographic/context checks for a transaction whose output is already
    /// authenticated by certified state. This alone does not prove input-state
    /// ownership or current wallet authority; execution must use `verify` with the
    /// authenticated state. `height` is the transaction's authenticated inclusion height.
    pub fn verify_signatures(&self, genesis: Hash, fingerprint: Hash, height: u64) -> Result<()> {
        let raw = self.encode()?;
        let (network, tx_genesis, tx_fingerprint) = self.context();
        if network != crate::NETWORK_ID || tx_genesis != genesis || tx_fingerprint != fingerprint {
            return Err(TxError::Binding);
        }
        let (first, last) = self.window();
        if height < first {
            return Err(TxError::Future);
        }
        if height > last {
            return Err(TxError::Expired);
        }
        match self {
            Self::Transfer(t) => t.verify_signatures()?,
            Self::FundedRotation(r) => r.verify_signatures()?,
        }
        if self.fee() < raw.len() as u64 {
            return Err(TxError::Fee);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let raw = match self {
            Self::Transfer(t) => t.encode()?,
            Self::FundedRotation(r) => r.encode()?,
        };
        if raw.len() > MAX_TX_BYTES {
            return Err(TxError::Bounds);
        }
        Ok(raw)
    }
    /// Dispatches on the outer array length (9 Transfer, 7 funded rotation) after the version 2;
    /// the funded rotation then requires tag 25. Everything else, including the retired
    /// `[2, 21, rotation, transfer]` wrapper, is `TxError::Codec`.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_TX_BYTES).map_err(|_| TxError::Codec)?;
        let mut d = Decoder::new(raw);
        let count = d.array().map_err(|_| TxError::Codec)?;
        if d.u8().map_err(|_| TxError::Codec)? != 2 {
            return Err(TxError::Codec);
        }
        let decoded = match count {
            Some(9) => Self::Transfer(Transfer::decode(raw)?),
            Some(7) => Self::FundedRotation(FundedRotation::decode(raw)?),
            _ => return Err(TxError::Codec),
        };
        if decoded.encode()? != raw {
            return Err(TxError::Codec);
        }
        Ok(decoded)
    }
    /// Replay identity and output namespace. The funded rotation's id is
    /// `domain_hash(MUTINY-BUILD8-FUNDED-ROTATION-ID-V2, unsigned)` (signatures excluded); the
    /// retired FUNDED-WALLET-ROTATION-ID-V1 over `[rotation identity, transfer id]` is gone.
    pub fn id(&self) -> Result<Hash> {
        match self {
            Self::Transfer(t) => t.id(),
            Self::FundedRotation(r) => r.id(),
        }
    }
    /// The declared fee.
    pub fn fee(&self) -> u64 {
        match self {
            Self::Transfer(t) => t.fee,
            Self::FundedRotation(r) => r.unsigned.fee,
        }
    }
    /// `(network, genesis, fingerprint)` the transaction is bound to.
    pub fn context(&self) -> (u32, Hash, Hash) {
        match self {
            Self::Transfer(t) => (t.network, t.genesis, t.fingerprint),
            Self::FundedRotation(r) => (crate::NETWORK_ID, r.unsigned.genesis, r.unsigned.fingerprint),
        }
    }
    /// The signed inclusive height window: `(created_height, expiry_height)` of a Transfer,
    /// `(first_height, last_height)` of a funded rotation's envelope.
    pub fn window(&self) -> (u64, u64) {
        match self {
            Self::Transfer(t) => (t.created_height, t.expiry_height),
            Self::FundedRotation(r) => (r.unsigned.envelope.first_height, r.unsigned.envelope.last_height),
        }
    }
    /// Every input OutPoint, in encoding order.
    pub fn inputs(&self) -> Vec<OutPoint> {
        match self {
            Self::Transfer(t) => t.inputs.iter().map(|i| i.point.clone()).collect(),
            Self::FundedRotation(r) => r.unsigned.inputs.iter().map(|(p, _)| p.clone()).collect(),
        }
    }
    /// The outputs; output `i` is created at `OutPoint{id, i}`.
    pub fn outputs(&self) -> &[Output] {
        match self {
            Self::Transfer(t) => &t.outputs,
            Self::FundedRotation(r) => &r.unsigned.outputs,
        }
    }
    /// The operation envelope, if the transaction carries one (only the funded rotation does).
    pub fn envelope(&self) -> Option<&Envelope> {
        match self {
            Self::Transfer(_) => None,
            Self::FundedRotation(r) => Some(&r.unsigned.envelope),
        }
    }
    /// The wallet authority a funded rotation rotates (the pool's authority resource).
    pub fn rotation_authority(&self) -> Option<Hash> {
        match self {
            Self::Transfer(_) => None,
            Self::FundedRotation(r) => Some(r.unsigned.authority),
        }
    }
    /// Complete verification as if included at `at.height()` against `state` (the running state of
    /// the payment phase, or the finalized tip state for admission). Transfers verify exactly as
    /// before; a funded rotation runs the 9 steps of design 3.5 (`FundedRotation::verify`).
    pub fn verify(&self, at: &Inclusion<'_>, state: &State) -> Result<VerifiedTransaction> {
        let raw = self.encode()?;
        let t = match self {
            Self::Transfer(t) => t,
            Self::FundedRotation(r) => return r.verify(at, state),
        };
        let height = at.height()?;
        let mut next = state.wallets.clone();
        let fee = t.verify(at.parent.genesis, at.parent.fingerprint, height, &state.coins, &next)?;
        // Existing 1 atom per complete canonical signed transaction byte.
        if fee < raw.len() as u64 {
            return Err(TxError::Fee);
        }
        for input in &t.inputs {
            let (key, generation) =
                mutiny_crypto_v2::PublicKey::decode_descriptor(&input.descriptor)
                    .map_err(|_| TxError::Codec)?;
            let id = key.address_id(generation).map_err(|_| TxError::Owner)?;
            if generation == 1 && next.current(id).is_none() {
                next.register(&input.descriptor)
                    .map_err(|_| TxError::Owner)?;
            }
        }
        Ok(VerifiedTransaction {
            id: self.id()?,
            fee,
            inputs: t.inputs.iter().map(|i| i.point.clone()).collect(),
            outputs: t.outputs.clone(),
            wallets: next,
        })
    }
}
