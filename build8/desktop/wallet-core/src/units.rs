//! Amount parsing and formatting, and approximate block-time conversion.
//!
//! One STRIKE is one native atom; one MUT is 100,000,000 STRIKES (the Architect-locked mapping in
//! `mutiny_consensus_v8::native_units_v1`). Everything here is integer arithmetic: there is no
//! floating point, no rounding and no exponent notation anywhere in an amount path.
//!
//! Durations derived from block heights are APPROXIMATE (Q11): the protocol counts certified
//! blocks and epochs, never wall time. Every caller must label them "approximate".
use crate::refusal::Refusal;
use mutiny_consensus_v8::native_units_v1::STRIKES_PER_MUT;

/// Native atoms (STRIKES) per MUT.
pub const ATOMS_PER_MUT: u64 = STRIKES_PER_MUT;
/// Target block interval used ONLY for approximate durations (never for any validity rule).
pub const TARGET_BLOCK_SECONDS: u64 = 60;
/// Seconds per epoch of block timestamps (`(timestamp - t0) / 60`).
pub const EPOCH_SECONDS: u64 = 60;

/// `N.dddddddd MUT` with exactly eight decimals.
pub fn format_mut(atoms: u64) -> String {
    format!("{}.{:08} MUT", atoms / ATOMS_PER_MUT, atoms % ATOMS_PER_MUT)
}

/// Like [`format_mut`] for sums that may exceed `u64` (for example a total debit).
pub fn format_mut_wide(atoms: u128) -> String {
    let unit = u128::from(ATOMS_PER_MUT);
    format!("{}.{:08} MUT", atoms / unit, atoms % unit)
}

/// `N STRIKES`, the same quantity in the trading unit.
pub fn format_strikes(atoms: u64) -> String {
    format!("{atoms} STRIKES")
}

/// `N.dddddddd MUT (N STRIKES)`: the form used in reviews so both units are visible.
pub fn format_amount(atoms: u64) -> String {
    format!("{} ({})", format_mut(atoms), format_strikes(atoms))
}

/// Parse a typed MUT amount: ASCII digits, optionally one `.` and 1 to 8 decimal digits.
/// No sign, no whitespace, no exponent, no separators; the result must be positive.
pub fn parse_mut(text: &str) -> Result<u64, Refusal> {
    let bad = Refusal::InvalidAmount;
    let (whole_text, fraction_text) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (text, None),
    };
    if whole_text.is_empty() || !whole_text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad);
    }
    let fraction_digits = fraction_text.unwrap_or("");
    if fraction_text.is_some() && fraction_digits.is_empty() {
        return Err(bad);
    }
    if fraction_digits.len() > 8 || !fraction_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad);
    }
    let whole: u64 = whole_text.parse().map_err(|_| Refusal::Overflow)?;
    let fraction: u64 = if fraction_digits.is_empty() {
        0
    } else {
        fraction_digits
            .parse()
            .map_err(|_| Refusal::InvalidAmount)?
    };
    // `8 - len` is in 0..=8, so the scale never overflows.
    let scaled = fraction * 10u64.pow(8 - fraction_digits.len() as u32);
    let atoms = whole
        .checked_mul(ATOMS_PER_MUT)
        .and_then(|value| value.checked_add(scaled))
        .ok_or(Refusal::Overflow)?;
    if atoms == 0 {
        return Err(bad);
    }
    Ok(atoms)
}

/// `about 2 h 24 min` style text for a number of target-interval blocks. The caller adds the
/// word "approximate" and the basis; this function never claims precision.
pub fn approx_blocks(blocks: u64) -> String {
    approx_seconds(blocks.saturating_mul(TARGET_BLOCK_SECONDS))
}

/// The same for a number of epochs.
pub fn approx_epochs(epochs: u64) -> String {
    approx_seconds(epochs.saturating_mul(EPOCH_SECONDS))
}

fn approx_seconds(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    if seconds < MINUTE {
        return "less than 1 min".into();
    }
    if seconds < HOUR {
        return format!("about {} min", seconds / MINUTE);
    }
    if seconds < DAY {
        let (hours, minutes) = (seconds / HOUR, (seconds % HOUR) / MINUTE);
        return if minutes == 0 {
            format!("about {hours} h")
        } else {
            format!("about {hours} h {minutes} min")
        };
    }
    let (days, hours) = (seconds / DAY, (seconds % DAY) / HOUR);
    if hours == 0 {
        format!("about {days} days")
    } else {
        format!("about {days} days {hours} h")
    }
}

/// The last eight hexadecimal characters of a 32-byte identifier: the typed re-entry check shown
/// next to every address that is not this wallet's own (Q10).
pub fn last8_hex(id: &[u8; 32]) -> String {
    hex::encode(&id[28..])
}

/// Compact `aaaaaaaa..bbbbbbbb` form of an identifier for tables and `Debug` output.
pub fn short_hex(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        return hex::encode(bytes);
    }
    format!(
        "{}..{}",
        hex::encode(&bytes[..4]),
        hex::encode(&bytes[bytes.len() - 4..])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting_is_exact() {
        assert_eq!(format_mut(0), "0.00000000 MUT");
        assert_eq!(format_mut(1), "0.00000001 MUT");
        assert_eq!(format_mut(150_000_000), "1.50000000 MUT");
        assert_eq!(format_mut(u64::MAX), "184467440737.09551615 MUT");
        assert_eq!(
            format_mut_wide(u128::from(u64::MAX) * 2),
            "368934881474.19103230 MUT"
        );
        assert_eq!(
            format_amount(150_000_000),
            "1.50000000 MUT (150000000 STRIKES)"
        );
    }

    #[test]
    fn parse_accepts_only_plain_positive_decimals() {
        assert_eq!(parse_mut("1"), Ok(100_000_000));
        assert_eq!(parse_mut("0.00000001"), Ok(1));
        assert_eq!(parse_mut("12.5"), Ok(1_250_000_000));
        assert_eq!(parse_mut("007.050"), Ok(705_000_000));
        assert_eq!(parse_mut("184467440737.09551615"), Ok(u64::MAX));
        for text in [
            "",
            ".",
            "1.",
            ".5",
            "0",
            "0.0",
            "0.00000000",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1e3",
            "1,5",
            "1.123456789",
            "1..2",
            "1.2.3",
            "0x10",
            "١",
            "1_000",
        ] {
            assert!(parse_mut(text).is_err(), "{text:?} must be refused");
        }
        assert_eq!(parse_mut("184467440737.09551616"), Err(Refusal::Overflow));
        assert_eq!(parse_mut("184467440738"), Err(Refusal::Overflow));
        assert_eq!(parse_mut("99999999999999999999999"), Err(Refusal::Overflow));
    }

    #[test]
    fn parse_then_format_round_trips() {
        for atoms in [
            1u64,
            99_999_999,
            100_000_000,
            123_456_789,
            1_000_000_000_000,
        ] {
            let text = format_mut(atoms);
            let number = text.trim_end_matches(" MUT");
            assert_eq!(parse_mut(number), Ok(atoms));
        }
    }

    #[test]
    fn approximate_durations_are_coarse_and_labelled_by_the_caller() {
        assert_eq!(approx_blocks(0), "less than 1 min");
        assert_eq!(approx_blocks(1), "about 1 min");
        assert_eq!(approx_blocks(144), "about 2 h 24 min");
        assert_eq!(approx_blocks(60), "about 1 h");
        assert_eq!(approx_blocks(43_200), "about 30 days");
        assert_eq!(approx_blocks(259_200), "about 180 days");
        assert_eq!(approx_epochs(65_536), "about 45 days 12 h");
        assert!(approx_blocks(u64::MAX).starts_with("about "));
    }

    #[test]
    fn identifier_helpers() {
        let id = [0xab; 32];
        assert_eq!(last8_hex(&id), "abababab");
        assert_eq!(short_hex(&id), "abababab..abababab");
        assert_eq!(short_hex(&[1, 2]), "0102");
    }
}
