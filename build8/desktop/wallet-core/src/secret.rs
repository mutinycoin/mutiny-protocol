//! The only secret value type in the wallet core that is not a signing key.
//!
//! A hash-lock PREIMAGE is secret until the claim discloses it on chain. It is a fresh
//! operating-system random value held in its own record, NEVER derived from the wallet phrase or
//! any key (Q13): a derivation would create the linkage between the wallet and an external swap
//! that the Bitcoin Treasury custody lock forbids.
//!
//! The type has no `Clone`, no `Display`, no `PartialEq`, no serialisation and a redacted `Debug`.
//! Its bytes are erased on drop and are readable only inside this crate.
use crate::refusal::Refusal;
use mutiny_consensus_v8::Hash;
use std::fmt;
use zeroize::Zeroizing;

/// A 32-byte hash-lock preimage.
pub struct Preimage(Zeroizing<[u8; 32]>);

impl Preimage {
    /// Take ownership of preimage bytes the caller obtained elsewhere (for example from the
    /// counterparty's disclosure or from the wallet's own preimage record).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A fresh preimage from the operating system's randomness. There is no fallback: an entropy
    /// failure is an error, never a constant.
    pub fn generate() -> Result<Self, Refusal> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        mutiny_crypto_v2::fill_os_random(bytes.as_mut())
            .map_err(|_| Refusal::EntropyUnavailable)?;
        Ok(Self(bytes))
    }

    /// The public hash condition (`SHA-256(preimage)`) that locks funds to this preimage. Safe to
    /// show and to share; it reveals nothing about the preimage.
    pub fn condition(&self) -> Hash {
        mutiny_consensus_v8::trading_v1::preimage_hash(&self.0)
    }

    /// Crate-internal access for the one place the preimage is placed in a claim.
    #[allow(dead_code)]
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Preimage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Preimage(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted_and_condition_is_the_consensus_hash() {
        let preimage = Preimage::from_bytes([0xab; 32]);
        let shown = format!("{preimage:?}");
        assert_eq!(shown, "Preimage(<redacted>)");
        assert!(!shown.to_lowercase().contains("ab"));
        assert_eq!(
            preimage.condition(),
            mutiny_consensus_v8::trading_v1::preimage_hash(&[0xab; 32])
        );
    }

    #[test]
    fn generated_preimages_are_fresh() {
        let (a, b) = (Preimage::generate().unwrap(), Preimage::generate().unwrap());
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.condition(), [0; 32]);
    }

    /// The preimage source is pinned (the independent wallet review's survivor D1, here for the
    /// core's own generator): `generate` is exactly crypto-v2's operating-system randomness, with no
    /// fallback and nothing derived; and 64 fresh values are pairwise distinct with every one of the
    /// 256 bit positions taking both values (a constant, a counter or a short cycle fails; a uniform
    /// source fails with probability below 2^-55).
    #[test]
    fn the_preimage_source_is_the_operating_systems_randomness() {
        let source = include_str!("secret.rs");
        let start = source
            .find("    pub fn generate() -> Result<Self, Refusal> {")
            .unwrap();
        let end = start + source[start..].find("\n    }\n").unwrap();
        let lines: Vec<&str> = source[start..end].lines().map(str::trim).collect();
        assert_eq!(
            lines,
            [
                "pub fn generate() -> Result<Self, Refusal> {",
                "let mut bytes = Zeroizing::new([0u8; 32]);",
                "mutiny_crypto_v2::fill_os_random(bytes.as_mut())",
                ".map_err(|_| Refusal::EntropyUnavailable)?;",
                "Ok(Self(bytes))",
            ]
        );
        let values: Vec<[u8; 32]> = (0..64)
            .map(|_| *Preimage::generate().unwrap().expose())
            .collect();
        let distinct: std::collections::BTreeSet<[u8; 32]> = values.iter().copied().collect();
        assert_eq!(distinct.len(), values.len(), "a preimage repeated");
        for bit in 0..256 {
            let ones = values
                .iter()
                .filter(|value| value[bit / 8] >> (bit % 8) & 1 == 1)
                .count();
            assert!(ones > 0 && ones < values.len(), "bit {bit} never varies");
        }
    }
}
