//! Architect-locked native unit mapping and fee floors.
//!
//! Authority: ARCHITECT-DECISION-LOCK-RESTART-ORDER-V1 (2 Oct 2026), sections 2 and 3.
//! One STRIKE is one native atom. One MUT is 100,000,000 STRIKES. All native consensus
//! accounting is integer. This is a denomination mapping, not an exchange rate or second asset.
//! Status: NATIVE unit/fee arithmetic only. It is not wired into admission or execution.

/// One STRIKE is exactly one native atom.
pub const ATOMS_PER_STRIKE: u64 = 1;
/// One MUT is exactly 100,000,000 STRIKES.
pub const STRIKES_PER_MUT: u64 = 100_000_000;
/// Floor for applicable on-chain trading/value operations, in STRIKES.
pub const MINIMUM_TRADE_FEE_STRIKES: u64 = 240;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitError {
    Overflow,
}

/// Whole MUT to STRIKES (== native atoms). Checked; never saturates.
pub fn mut_to_strikes(whole_mut: u64) -> Result<u64, UnitError> {
    whole_mut.checked_mul(STRIKES_PER_MUT).ok_or(UnitError::Overflow)
}

/// STRIKES to native atoms. Identity under the locked mapping, kept explicit and checked.
pub fn strikes_to_atoms(strikes: u64) -> Result<u64, UnitError> {
    strikes.checked_mul(ATOMS_PER_STRIKE).ok_or(UnitError::Overflow)
}

/// Splits STRIKES into (whole MUT, fractional STRIKES). Exact; no rounding.
pub fn split_strikes(strikes: u64) -> (u64, u64) {
    (strikes / STRIKES_PER_MUT, strikes % STRIKES_PER_MUT)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeClass {
    /// Applicable on-chain trading/value operation: greater of 240 STRIKES and the canonical fee.
    Trading,
    /// Dividend claim: explicit fee-exempt path. The 240 floor does not apply, no hidden
    /// Treasury fee is taken, and the exact claim amount is never reduced by a fee.
    DividendClaim,
}

/// Required fee in STRIKES. `canonical_requirement` is the separately locked canonical/admission
/// requirement (for example the 1-atom-per-byte rule) and is computed by its own code.
pub fn required_fee(class: FeeClass, canonical_requirement: u64) -> u64 {
    match class {
        FeeClass::Trading => canonical_requirement.max(MINIMUM_TRADE_FEE_STRIKES),
        FeeClass::DividendClaim => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_is_exact_and_matches_the_native_subsidy() {
        assert_eq!(ATOMS_PER_STRIKE, 1);
        assert_eq!(STRIKES_PER_MUT, 100_000_000);
        assert_eq!(mut_to_strikes(1).unwrap(), crate::transactions::SUBSIDY);
        assert_eq!(mut_to_strikes(0).unwrap(), 0);
        assert_eq!(strikes_to_atoms(123_456_789).unwrap(), 123_456_789);
        assert_eq!(split_strikes(250_000_001), (2, 50_000_001));
        assert_eq!(split_strikes(99_999_999), (0, 99_999_999));
        assert_eq!(split_strikes(100_000_000), (1, 0));
    }

    #[test]
    fn conversion_overflows_are_errors_not_saturation() {
        let max_whole = u64::MAX / STRIKES_PER_MUT;
        assert!(mut_to_strikes(max_whole).is_ok());
        assert_eq!(mut_to_strikes(max_whole + 1), Err(UnitError::Overflow));
        assert_eq!(mut_to_strikes(u64::MAX), Err(UnitError::Overflow));
    }

    #[test]
    fn trading_fee_is_max_of_floor_and_canonical_at_every_boundary() {
        assert_eq!(required_fee(FeeClass::Trading, 0), 240);
        assert_eq!(required_fee(FeeClass::Trading, 1), 240);
        assert_eq!(required_fee(FeeClass::Trading, 239), 240);
        assert_eq!(required_fee(FeeClass::Trading, 240), 240);
        assert_eq!(required_fee(FeeClass::Trading, 241), 241);
        assert_eq!(required_fee(FeeClass::Trading, u64::MAX), u64::MAX);
    }

    #[test]
    fn dividend_claims_use_the_explicit_fee_exempt_path() {
        for canonical in [0, 1, 239, 240, 10_000] {
            assert_eq!(required_fee(FeeClass::DividendClaim, canonical), 0);
        }
    }
}
