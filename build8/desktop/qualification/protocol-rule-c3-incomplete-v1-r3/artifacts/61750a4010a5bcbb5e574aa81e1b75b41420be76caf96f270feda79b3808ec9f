//! Compile-time launch fence while the final hybrid stack is under qualification.
//! Configuration, environment variables and a legacy sealed fixture cannot
//! promote an unfinished implementation to production.
pub const HYBRID_RUNTIME_QUALIFIED: bool = false;
pub const FINAL_GENESIS_RULES_LOCKED: bool = false;
pub const CLOSED_REASON: &str =
    "Build8 production launch/custody initialization is closed: hybrid runtime, cryptographic qualification and final Genesis rule lock are incomplete";
pub fn require_production_ready() -> Result<(), String> {
    if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED
        || !HYBRID_RUNTIME_QUALIFIED
        || !FINAL_GENESIS_RULES_LOCKED
    {
        return Err(CLOSED_REASON.into());
    }
    Ok(())
}
