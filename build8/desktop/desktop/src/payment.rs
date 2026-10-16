//! Exact decimal MUT amount parsing for the amount-entry screens. Since phase 7 the whole wallet
//! has ONE parser: wallet-core's `units::parse_mut` (ASCII digits, at most eight decimals, no sign,
//! exponent, separator or whitespace, positive, overflow refused). This module keeps the desktop's
//! entry point and its tests, which now assert the same properties through wallet-core's parser.
type Result<T> = std::result::Result<T, String>;

/// Parse MUT without floating point, rounding or exponent notation.
pub fn parse_amount(text: &str) -> Result<u64> {
    mutiny_wallet_core_v8::units::parse_mut(text).map_err(|refusal| refusal.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decimal_amounts_are_exact_and_bounded() {
        assert_eq!(parse_amount("1.00000001").unwrap(), 100000001);
        for bad in ["0", "-1", "1e2", ".1", "1.", "1.000000001", "184467440738"] {
            assert!(parse_amount(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn the_largest_representable_amount_is_exact_and_one_atom_more_is_refused() {
        assert_eq!(parse_amount("184467440737.09551615").unwrap(), u64::MAX);
        assert!(parse_amount("184467440737.09551616").is_err());
        assert_eq!(parse_amount("0.00000001").unwrap(), 1);
        for bad in [
            "",
            ".",
            " 1",
            "1 ",
            "+1",
            "1,5",
            "0.00000000",
            "1..5",
            "1.5.2",
        ] {
            assert!(parse_amount(bad).is_err(), "{bad:?}");
        }
    }
}
