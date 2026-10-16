#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Overflow,
    InvalidCounter,
    Capacity,
    Duplicate,
    UnknownSigner,
    Codec,
    NonCanonical,
    Oversize,
    WrongNetwork,
    WrongGenesis,
    WrongFingerprint,
    WrongAnchor,
    StaleSequence,
    WrongGeneration,
    BadSignature,
    WrongOperation,
    RecoveryDisabled,
    NormalQuorumAvailable,
    UnqualifiedPhysical,
    InvalidLineage,
    ConflictingRecovery,
    ExistingFinality,
    NoQuorum,
    RedundancyNotMet,
    /// Order A9: V1 is not a Production Genesis implementation (`genesis_inputs::V1_PRODUCTION_REFUSAL`).
    V1NotProductionGenesis,
    /// Order of 4 Oct 2026, decision A8: in the Production class the ceremony-scoped admission
    /// authority admits no hardware after sealing (`admission_scope`).
    AdmissionAuthorityEnded,
    /// An operation-envelope rule (`op_envelope_v1`) refused an item that reports this error
    /// type (the bond commands, kinds 19 and 20).
    Envelope(crate::op_envelope_v1::EnvelopeError),
}
pub type Result<T> = std::result::Result<T, Error>;
