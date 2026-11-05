//! Checksummed, class-distinguishing TEXT encoding of a 32-byte address identifier (Order W2).
//! Specification: `docs/ADDRESS-FORMAT-V1.md`. Status: PROPOSED, NOT frozen.
//!
//! An AddressID is what a transaction signs and what consensus compares; the string this module
//! produces is ONLY an encoding of those 32 bytes for a person to read, copy and type. Nothing signs
//! the string, nothing stores it in place of the bytes, and a decoded string yields exactly the 32
//! bytes that were encoded (full-address validation: every character and the checksum are checked,
//! nothing is truncated, completed or guessed).
//!
//! # The format
//!
//! `<prefix> 1 <52 data characters> <6 checksum characters>`, lowercase only:
//!
//! * the data characters are the 32 bytes as 52 five-bit groups, most significant bit first, the
//!   last group completed with four ZERO bits, written with the BIP-173 alphabet [`CHARSET`];
//! * the checksum is the BCH code of BIP-173 (generator [`GENERATOR`]) with the bech32m constant of
//!   BIP-350 ([`CHECKSUM_CONSTANT`]), computed over the expanded prefix and the data characters: any
//!   error in up to four characters is detected, and a random string passes with probability
//!   about 2^-30;
//! * the prefix names the CLASS the verified chain declares (see [`prefix`]).
//!
//! # What the prefix tells a reader, and what it cannot
//!
//! The prefix is [`PREFIX_PRODUCTION`] (`mut`) when the verified chain's Treasury record is
//! production class, [`PREFIX_TEST_VALUE`] (`tmut`) when it is TEST-VALUE class, and
//! [`PREFIX_UNDECLARED`] (`umut`) when the chain declares no class (no Treasury record). The class
//! is read from the VERIFIED view only (`ChainView::class`); a build or a configuration never
//! chooses it, and a chain that declares nothing is never labelled production or TEST-VALUE.
//!
//! * Distinguishable from the string alone: the class the ENCODING wallet's verified chain
//!   declared, and this network (all three prefixes exist for `NETWORK_ID` 0x4d555401 only; a
//!   compile-time assertion below fails if the network identifier changes). A decoder refuses a
//!   string whose prefix is not the one of ITS verified chain's class ([`AddressError::WrongPrefix`]),
//!   so a TEST-VALUE address (whose key may be a public test key) cannot be entered into a
//!   production wallet by accident, and the reverse.
//! * NOT distinguishable: two chains of the same class (two TEST-VALUE chains, or a production
//!   chain and its re-run) - Genesis is not encoded; and the identifier itself is the same on every
//!   chain of this network, because it is derived from the key's descriptor and the network
//!   identifier only. A string proves nothing about who made it: anyone can encode any 32 bytes
//!   under any prefix. The checksum detects accidents; it is not authentication.
//!
//! # Decoding is strict
//!
//! [`decode_any`] checks, in this order, and stops at the first failure: not empty; at most
//! [`MAX_LENGTH`] characters; every character printable ASCII (33 to 126, so no space, control or
//! non-ASCII character, and nothing is trimmed); one case only, and that case lowercase (an
//! all-uppercase string, which BIP-350 permits for QR codes, is refused rather than silently
//! lower-cased); a separator; a known prefix; data characters from [`CHARSET`] only; at least the six
//! checksum characters; the bech32m checksum (a string with a valid BIP-173 bech32 checksum instead
//! is its own error); exactly 52 data groups; zero padding bits. [`decode`] then requires the prefix
//! of the expected class. Every failure is a distinct [`AddressError`] with a stable code.
//!
//! The 64-character hexadecimal form is kept as an explicit LEGACY and diagnostic path
//! ([`parse_legacy_hex`], [`legacy_hex`]); it carries no checksum and no class.
use crate::{context::ChainClass, context::ChainView, refusal::Refusal};
use mutiny_consensus_v8::Hash;
use std::fmt;

/// The 32-character data alphabet of BIP-173: the character for value `v` is `CHARSET[v]`.
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// The bech32m checksum constant of BIP-350 (a BIP-173 bech32 checksum uses 1 instead).
pub const CHECKSUM_CONSTANT: u32 = 0x2bc8_30a3;
/// The constant of a BIP-173 bech32 checksum: a string that verifies with it is refused here.
pub const ORIGINAL_VARIANT_CONSTANT: u32 = 1;
/// The coefficients of the BCH generator of BIP-173 (`bech32_polymod`).
pub const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];
/// The BIP-173 limit on the length of a whole string.
pub const MAX_LENGTH: usize = 90;
/// The separator between the prefix and the data part (the LAST `1` of the string).
pub const SEPARATOR: u8 = b'1';
/// Five-bit groups that carry 32 bytes: 256 bits, completed with four zero bits to 260.
pub const DATA_GROUPS: usize = 52;
/// Characters of the checksum.
pub const CHECKSUM_LENGTH: usize = 6;
/// The prefix of an address on a chain whose Treasury record is production class.
pub const PREFIX_PRODUCTION: &str = "mut";
/// The prefix of an address on a chain whose Treasury record is TEST-VALUE class.
pub const PREFIX_TEST_VALUE: &str = "tmut";
/// The prefix of an address on a chain that declares no class (no Treasury record).
pub const PREFIX_UNDECLARED: &str = "umut";
/// The name of this text format (registered in `spec/DOMAIN-REGISTRY-V1.json`, PROPOSED-UNFROZEN).
pub const FORMAT: &str = "MUTINY-BUILD8-ADDRESS-TEXT-V1";

// The prefixes are defined for this network identifier only. A different network needs its own
// prefixes (and vectors), so a change of either constant must fail the build here.
const _: () = assert!(
    mutiny_consensus_v8::NETWORK_ID == 0x4d55_5401,
    "address prefixes are defined for network 0x4d555401 only"
);
const _: () = assert!(
    mutiny_crypto_v2::NETWORK == 0x4d55_5401,
    "address prefixes are defined for network 0x4d555401 only"
);

/// Why a string is not an address of the expected class. Every variant has a stable code
/// ([`AddressError::code`]); none carries the string itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressError {
    /// Nothing was entered.
    Empty,
    /// More than [`MAX_LENGTH`] characters.
    TooLong { length: usize },
    /// A byte that is not printable ASCII (space, control, non-ASCII), or a data character
    /// outside [`CHARSET`]; `position` is its byte offset.
    InvalidCharacter { position: usize },
    /// Upper- and lowercase letters together.
    MixedCase,
    /// Uppercase letters only: the canonical form is lowercase and nothing is lower-cased here.
    Uppercase,
    /// No separator `1`.
    MissingSeparator,
    /// The prefix (possibly empty) is none of the three of this network.
    UnknownPrefix,
    /// A prefix of this network, but of another chain class than the verified chain's.
    WrongPrefix {
        expected: &'static str,
        found: &'static str,
    },
    /// Fewer characters after the separator than the checksum alone needs.
    TooShort,
    /// The bech32m checksum does not verify.
    InvalidChecksum,
    /// The checksum verifies as a BIP-173 bech32 checksum, not as bech32m.
    ChecksumVariant,
    /// Fewer than [`DATA_GROUPS`] data characters.
    PayloadTooShort { groups: usize },
    /// More than [`DATA_GROUPS`] data characters (extra data).
    PayloadTooLong { groups: usize },
    /// The four padding bits of the last data character are not zero (a non-canonical encoding of
    /// the 32 bytes).
    NonCanonicalPadding,
    /// LEGACY hexadecimal input that is not exactly 64 characters.
    LegacyHexLength { length: usize },
    /// LEGACY hexadecimal input with a character outside `0-9a-f` (uppercase is not accepted).
    LegacyHexCharacter { position: usize },
}

impl AddressError {
    /// Stable machine code (the vectors in `tests/golden/address-format-v1.json` use it).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "EMPTY",
            Self::TooLong { .. } => "TOO_LONG",
            Self::InvalidCharacter { .. } => "INVALID_CHARACTER",
            Self::MixedCase => "MIXED_CASE",
            Self::Uppercase => "UPPERCASE",
            Self::MissingSeparator => "MISSING_SEPARATOR",
            Self::UnknownPrefix => "UNKNOWN_PREFIX",
            Self::WrongPrefix { .. } => "WRONG_PREFIX",
            Self::TooShort => "TOO_SHORT",
            Self::InvalidChecksum => "INVALID_CHECKSUM",
            Self::ChecksumVariant => "CHECKSUM_VARIANT",
            Self::PayloadTooShort { .. } => "PAYLOAD_TOO_SHORT",
            Self::PayloadTooLong { .. } => "PAYLOAD_TOO_LONG",
            Self::NonCanonicalPadding => "NON_CANONICAL_PADDING",
            Self::LegacyHexLength { .. } => "LEGACY_HEX_LENGTH",
            Self::LegacyHexCharacter { .. } => "LEGACY_HEX_CHARACTER",
        }
    }
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "no address was entered"),
            Self::TooLong { length } => {
                write!(f, "{length} characters is longer than any address")
            }
            Self::InvalidCharacter { position } => {
                write!(
                    f,
                    "the character at position {position} cannot appear in an address"
                )
            }
            Self::MixedCase => write!(f, "upper- and lowercase letters are mixed"),
            Self::Uppercase => write!(f, "the address must be entered in lowercase"),
            Self::MissingSeparator => write!(f, "the separator character 1 is missing"),
            Self::UnknownPrefix => write!(f, "the prefix is not a Mutiny address prefix"),
            Self::WrongPrefix { expected, found } => write!(
                f,
                "this is a {found} address, but this chain's addresses start with {expected}"
            ),
            Self::TooShort => write!(f, "the address is too short to carry a checksum"),
            Self::InvalidChecksum => write!(f, "the checksum does not match: a character is wrong"),
            Self::ChecksumVariant => write!(
                f,
                "the checksum uses the original BIP-173 constant; this format uses the BIP-350 constant"
            ),
            Self::PayloadTooShort { groups } | Self::PayloadTooLong { groups } => write!(
                f,
                "the address carries {groups} data characters instead of {DATA_GROUPS}"
            ),
            Self::NonCanonicalPadding => write!(f, "the last data character is not canonical"),
            Self::LegacyHexLength { length } => write!(
                f,
                "a hexadecimal address identifier has 64 characters, not {length}"
            ),
            Self::LegacyHexCharacter { position } => write!(
                f,
                "the character at position {position} is not a lowercase hexadecimal digit"
            ),
        }
    }
}

impl std::error::Error for AddressError {}

/// The prefix of addresses on a chain of `class` (the class the verified chain declares).
pub fn prefix(class: ChainClass) -> &'static str {
    match class {
        ChainClass::Production => PREFIX_PRODUCTION,
        ChainClass::TestValue => PREFIX_TEST_VALUE,
        ChainClass::Undeclared => PREFIX_UNDECLARED,
    }
}

/// The chain class a prefix names, if it is one of this network's.
pub fn class_of_prefix(text: &str) -> Option<ChainClass> {
    match text {
        PREFIX_PRODUCTION => Some(ChainClass::Production),
        PREFIX_TEST_VALUE => Some(ChainClass::TestValue),
        PREFIX_UNDECLARED => Some(ChainClass::Undeclared),
        _ => None,
    }
}

/// BIP-173 `bech32_polymod` over five-bit values.
fn polymod(values: &[u8]) -> u32 {
    let mut check: u32 = 1;
    for value in values {
        let top = check >> 25;
        check = ((check & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (bit, coefficient) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                check ^= coefficient;
            }
        }
    }
    check
}

/// BIP-173 `bech32_hrp_expand`: the high three bits of every prefix byte, a zero, the low five bits.
fn expand_prefix(prefix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() * 2 + 1);
    out.extend(prefix.iter().map(|byte| byte >> 5));
    out.push(0);
    out.extend(prefix.iter().map(|byte| byte & 31));
    out
}

/// The polymod residue of a prefix and a data part that ends with its checksum: [`CHECKSUM_CONSTANT`]
/// for a valid bech32m string, [`ORIGINAL_VARIANT_CONSTANT`] for a valid BIP-173 bech32 string.
pub fn residue(prefix: &str, values: &[u8]) -> u32 {
    let mut all = expand_prefix(prefix.as_bytes());
    all.extend_from_slice(values);
    polymod(&all)
}

/// The six checksum values (BIP-350 `bech32_create_checksum` with the bech32m constant).
fn checksum(prefix: &str, data: &[u8]) -> [u8; CHECKSUM_LENGTH] {
    let mut all = expand_prefix(prefix.as_bytes());
    all.extend_from_slice(data);
    all.extend_from_slice(&[0; CHECKSUM_LENGTH]);
    let residue = polymod(&all) ^ CHECKSUM_CONSTANT;
    let mut out = [0u8; CHECKSUM_LENGTH];
    for (index, value) in out.iter_mut().enumerate() {
        *value = ((residue >> (5 * (CHECKSUM_LENGTH - 1 - index))) & 31) as u8;
    }
    out
}

/// The 52 five-bit groups of 32 bytes, most significant bit first, padded with four zero bits.
fn to_groups(bytes: &Hash) -> [u8; DATA_GROUPS] {
    let mut out = [0u8; DATA_GROUPS];
    let mut next = 0;
    let (mut accumulator, mut bits) = (0u32, 0u32);
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[next] = ((accumulator >> bits) & 31) as u8;
            next += 1;
        }
        accumulator &= (1 << bits) - 1;
    }
    // 256 = 51 * 5 + 1: one bit is left, completed with four zero bits.
    out[next] = ((accumulator << (5 - bits)) & 31) as u8;
    out
}

/// The 32 bytes of exactly 52 groups whose four padding bits are zero.
fn from_groups(groups: &[u8]) -> Result<Hash, AddressError> {
    if groups.len() < DATA_GROUPS {
        return Err(AddressError::PayloadTooShort {
            groups: groups.len(),
        });
    }
    if groups.len() > DATA_GROUPS {
        return Err(AddressError::PayloadTooLong {
            groups: groups.len(),
        });
    }
    let mut out = [0u8; 32];
    let mut next = 0;
    let (mut accumulator, mut bits) = (0u32, 0u32);
    for group in groups {
        accumulator = (accumulator << 5) | u32::from(*group);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[next] = ((accumulator >> bits) & 0xff) as u8;
            next += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    // 260 = 32 * 8 + 4: exactly four bits remain and they must be zero.
    if bits != 4 || accumulator != 0 {
        return Err(AddressError::NonCanonicalPadding);
    }
    Ok(out)
}

/// The address `address` as text, with the prefix of `class`. The PRIMARY display form.
pub fn encode(address: &Hash, class: ChainClass) -> String {
    let prefix = prefix(class);
    let data = to_groups(address);
    let check = checksum(prefix, &data);
    let mut out = String::with_capacity(prefix.len() + 1 + DATA_GROUPS + CHECKSUM_LENGTH);
    out.push_str(prefix);
    out.push(char::from(SEPARATOR));
    out.extend(
        data.iter()
            .chain(check.iter())
            .map(|value| char::from(CHARSET[usize::from(*value)])),
    );
    out
}

/// The address as text with the prefix of `view`'s VERIFIED class.
pub fn encode_for(address: &Hash, view: &ChainView<'_>) -> String {
    encode(address, view.class())
}

/// Decode a string with any of this network's prefixes, strictly (see the module documentation
/// for the order of the checks), and say which class its prefix names.
pub fn decode_any(text: &str) -> Result<(ChainClass, Hash), AddressError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(AddressError::Empty);
    }
    if bytes.len() > MAX_LENGTH {
        return Err(AddressError::TooLong {
            length: bytes.len(),
        });
    }
    if let Some(position) = bytes.iter().position(|byte| !(33..=126).contains(byte)) {
        return Err(AddressError::InvalidCharacter { position });
    }
    let lower = bytes.iter().any(u8::is_ascii_lowercase);
    let upper = bytes.iter().any(u8::is_ascii_uppercase);
    if lower && upper {
        return Err(AddressError::MixedCase);
    }
    if upper {
        return Err(AddressError::Uppercase);
    }
    let separator = bytes
        .iter()
        .rposition(|byte| *byte == SEPARATOR)
        .ok_or(AddressError::MissingSeparator)?;
    // Everything up to the separator is printable ASCII (checked above), so this is a char boundary.
    let prefix = &text[..separator];
    let class = class_of_prefix(prefix).ok_or(AddressError::UnknownPrefix)?;
    let data_part = &bytes[separator + 1..];
    let mut values = Vec::with_capacity(data_part.len());
    for (offset, byte) in data_part.iter().enumerate() {
        let value = CHARSET
            .iter()
            .position(|candidate| candidate == byte)
            .ok_or(AddressError::InvalidCharacter {
                position: separator + 1 + offset,
            })?;
        values.push(value as u8);
    }
    if values.len() < CHECKSUM_LENGTH {
        return Err(AddressError::TooShort);
    }
    match residue(prefix, &values) {
        CHECKSUM_CONSTANT => {}
        ORIGINAL_VARIANT_CONSTANT => return Err(AddressError::ChecksumVariant),
        _ => return Err(AddressError::InvalidChecksum),
    }
    let address = from_groups(&values[..values.len() - CHECKSUM_LENGTH])?;
    Ok((class, address))
}

/// Decode a string that must carry the prefix of `class`: the PRIMARY import form.
pub fn decode(text: &str, class: ChainClass) -> Result<Hash, AddressError> {
    let (found, address) = decode_any(text)?;
    if found != class {
        return Err(AddressError::WrongPrefix {
            expected: prefix(class),
            found: prefix(found),
        });
    }
    Ok(address)
}

/// [`decode`] against `view`'s VERIFIED class, as a wallet refusal (`ADDRESS_ENCODING`).
pub fn decode_for(text: &str, view: &ChainView<'_>) -> Result<Hash, Refusal> {
    decode(text, view.class()).map_err(Refusal::AddressEncoding)
}

/// LEGACY and diagnostic form: the 64 lowercase hexadecimal characters of the identifier. No
/// checksum, no class.
pub fn legacy_hex(address: &Hash) -> String {
    hex::encode(address)
}

/// Parse the LEGACY form: exactly 64 characters `0-9a-f` (no prefix, no whitespace, no uppercase).
/// Kept as an explicit diagnostic path; the checksummed form is the primary import.
pub fn parse_legacy_hex(text: &str) -> Result<Hash, AddressError> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Err(AddressError::LegacyHexLength {
            length: bytes.len(),
        });
    }
    if let Some(position) = bytes
        .iter()
        .position(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(AddressError::LegacyHexCharacter { position });
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).map_err(|_| AddressError::LegacyHexLength {
        length: bytes.len(),
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Five-bit values of a generic bech32 data part (BIP-173 alphabet, lowercase).
    fn values_of(data: &str) -> Vec<u8> {
        data.bytes()
            .map(|byte| CHARSET.iter().position(|c| *c == byte).unwrap() as u8)
            .collect()
    }

    /// The residue of a whole generic bech32 string (checksums are defined over the lowercase form).
    fn generic_residue(text: &str) -> u32 {
        let lower = text.to_ascii_lowercase();
        let separator = lower.rfind('1').unwrap();
        residue(&lower[..separator], &values_of(&lower[separator + 1..]))
    }

    /// The valid bech32m strings published in BIP-350: independent evidence for the generator, the
    /// prefix expansion and the bech32m constant.
    const BIP350_VALID: [&str; 7] = [
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];

    /// The valid bech32 strings published in BIP-173 (constant 1): bech32, not bech32m.
    const BIP173_VALID: [&str; 5] = [
        "A12UEL5L",
        "a12uel5l",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl",
    ];

    #[test]
    fn the_published_bip350_and_bip173_strings_verify_with_their_constants() {
        for text in BIP350_VALID {
            assert_eq!(generic_residue(text), CHECKSUM_CONSTANT, "{text}");
        }
        for text in BIP173_VALID {
            assert_eq!(generic_residue(text), ORIGINAL_VARIANT_CONSTANT, "{text}");
        }
    }

    /// A string of this format with an arbitrary data part and a checksum computed under `constant`.
    fn assemble(prefix: &str, data: &[u8], constant: u32) -> String {
        let mut all = expand_prefix(prefix.as_bytes());
        all.extend_from_slice(data);
        all.extend_from_slice(&[0; CHECKSUM_LENGTH]);
        let residue = polymod(&all) ^ constant;
        let mut out = format!("{prefix}1");
        for value in data {
            out.push(char::from(CHARSET[usize::from(*value)]));
        }
        for index in 0..CHECKSUM_LENGTH {
            let value = (residue >> (5 * (CHECKSUM_LENGTH - 1 - index))) & 31;
            out.push(char::from(CHARSET[value as usize]));
        }
        out
    }

    fn sample_ids() -> Vec<Hash> {
        let mut counting = [0u8; 32];
        for (index, byte) in counting.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut alternating = [0u8; 32];
        for (index, byte) in alternating.iter_mut().enumerate() {
            *byte = if index % 2 == 0 { 0xa5 } else { 0x5a };
        }
        vec![
            [0; 32],
            [0xff; 32],
            counting,
            alternating,
            [0x80; 32],
            [0x01; 32],
        ]
    }

    const CLASSES: [ChainClass; 3] = [
        ChainClass::Production,
        ChainClass::TestValue,
        ChainClass::Undeclared,
    ];

    #[test]
    fn every_identifier_round_trips_under_every_class_and_the_form_is_canonical() {
        for id in sample_ids() {
            for class in CLASSES {
                let text = encode(&id, class);
                let prefix = prefix(class);
                assert_eq!(
                    text.len(),
                    prefix.len() + 1 + DATA_GROUPS + CHECKSUM_LENGTH,
                    "{text}"
                );
                assert!(text.starts_with(&format!("{prefix}1")), "{text}");
                assert!(!text.bytes().any(|b| b.is_ascii_uppercase()), "{text}");
                assert_eq!(decode(&text, class), Ok(id), "{text}");
                assert_eq!(decode_any(&text), Ok((class, id)), "{text}");
                assert_eq!(
                    residue(prefix, &values_of(&text[prefix.len() + 1..])),
                    CHECKSUM_CONSTANT
                );
                assert_eq!(parse_legacy_hex(&legacy_hex(&id)), Ok(id));
            }
        }
        // The three prefixes are distinct and none is the prefix part of another's string.
        assert_ne!(PREFIX_PRODUCTION, PREFIX_TEST_VALUE);
        assert_ne!(PREFIX_PRODUCTION, PREFIX_UNDECLARED);
        assert_ne!(PREFIX_TEST_VALUE, PREFIX_UNDECLARED);
        for class in CLASSES {
            assert_eq!(class_of_prefix(prefix(class)), Some(class));
        }
        assert_eq!(class_of_prefix("bc"), None);
        assert_eq!(class_of_prefix(""), None);
        assert_eq!(class_of_prefix("MUT"), None, "prefixes are lowercase");
    }

    #[test]
    fn the_same_identifier_reads_differently_under_each_class_and_a_prefix_edit_breaks_the_checksum()
     {
        let id = sample_ids()[2];
        let production = encode(&id, ChainClass::Production);
        let test_value = encode(&id, ChainClass::TestValue);
        assert_ne!(
            production[3..],
            test_value[4..],
            "the checksum covers the prefix"
        );
        // Each class refuses the others' strings by prefix.
        assert_eq!(
            decode(&test_value, ChainClass::Production),
            Err(AddressError::WrongPrefix {
                expected: "mut",
                found: "tmut"
            })
        );
        assert_eq!(
            decode(&production, ChainClass::TestValue),
            Err(AddressError::WrongPrefix {
                expected: "tmut",
                found: "mut"
            })
        );
        assert_eq!(
            decode(&production, ChainClass::Undeclared),
            Err(AddressError::WrongPrefix {
                expected: "umut",
                found: "mut"
            })
        );
        // Editing only the prefix of a valid string does not produce a valid string of the other
        // class: the checksum covers the prefix.
        let edited = format!("t{production}");
        assert_eq!(decode_any(&edited), Err(AddressError::InvalidChecksum));
        let stripped = &test_value[1..];
        assert_eq!(decode_any(stripped), Err(AddressError::InvalidChecksum));
    }

    #[test]
    fn every_single_substitution_and_adjacent_transposition_is_detected() {
        for class in CLASSES {
            let id = sample_ids()[3];
            let text = encode(&id, class);
            let start = prefix(class).len() + 1;
            let bytes = text.as_bytes();
            let mut checked = 0;
            for position in start..bytes.len() {
                for candidate in CHARSET {
                    if *candidate == bytes[position] {
                        continue;
                    }
                    let mut changed = bytes.to_vec();
                    changed[position] = *candidate;
                    let changed = String::from_utf8(changed).unwrap();
                    assert!(decode(&changed, class).is_err(), "{changed}");
                    checked += 1;
                }
            }
            assert_eq!(checked, (DATA_GROUPS + CHECKSUM_LENGTH) * 31);
            for position in start..bytes.len() - 1 {
                if bytes[position] == bytes[position + 1] {
                    continue;
                }
                let mut swapped = bytes.to_vec();
                swapped.swap(position, position + 1);
                let swapped = String::from_utf8(swapped).unwrap();
                assert!(decode(&swapped, class).is_err(), "{swapped}");
            }
        }
    }

    #[test]
    fn every_rejection_class_has_its_own_typed_error() {
        let id = sample_ids()[2];
        let good = encode(&id, ChainClass::TestValue);
        let class = ChainClass::TestValue;
        let data = to_groups(&id).to_vec();
        let mut short = data.clone();
        short.pop();
        let mut long = data.clone();
        long.push(0);
        let mut padded = data.clone();
        *padded.last_mut().unwrap() |= 1;
        let mixed = format!("{}{}", &good[..10].to_ascii_uppercase(), &good[10..]);
        let cases: Vec<(String, AddressError)> = vec![
            (String::new(), AddressError::Empty),
            (
                format!("tmut1{}", "q".repeat(86)),
                AddressError::TooLong { length: 91 },
            ),
            (
                format!(" {good}"),
                AddressError::InvalidCharacter { position: 0 },
            ),
            (
                format!("{good}\n"),
                AddressError::InvalidCharacter {
                    position: good.len(),
                },
            ),
            (
                format!("tmut1{}", "\u{e9}"),
                AddressError::InvalidCharacter { position: 5 },
            ),
            (
                format!("{}b{}", &good[..10], &good[11..]),
                AddressError::InvalidCharacter { position: 10 },
            ),
            (mixed, AddressError::MixedCase),
            (good.to_ascii_uppercase(), AddressError::Uppercase),
            ("tmutqqqqqqqqq".to_string(), AddressError::MissingSeparator),
            (
                assemble("bc", &data, CHECKSUM_CONSTANT),
                AddressError::UnknownPrefix,
            ),
            (
                assemble("", &data, CHECKSUM_CONSTANT),
                AddressError::UnknownPrefix,
            ),
            (
                assemble("mut", &data, CHECKSUM_CONSTANT),
                AddressError::WrongPrefix {
                    expected: "tmut",
                    found: "mut",
                },
            ),
            ("tmut1qqqqq".to_string(), AddressError::TooShort),
            (
                format!(
                    "{}{}",
                    &good[..good.len() - 1],
                    if good.ends_with('q') { 'p' } else { 'q' }
                ),
                AddressError::InvalidChecksum,
            ),
            (
                assemble("tmut", &data, ORIGINAL_VARIANT_CONSTANT),
                AddressError::ChecksumVariant,
            ),
            (
                assemble("tmut", &short, CHECKSUM_CONSTANT),
                AddressError::PayloadTooShort { groups: 51 },
            ),
            (
                assemble("tmut", &long, CHECKSUM_CONSTANT),
                AddressError::PayloadTooLong { groups: 53 },
            ),
            (
                assemble("tmut", &padded, CHECKSUM_CONSTANT),
                AddressError::NonCanonicalPadding,
            ),
        ];
        let mut codes = std::collections::BTreeSet::new();
        for (text, expected) in &cases {
            assert_eq!(decode(text, class).as_ref(), Err(expected), "{text:?}");
            assert!(!expected.to_string().is_empty());
            codes.insert(expected.code());
        }
        for (text, expected) in [
            ("0".repeat(63), AddressError::LegacyHexLength { length: 63 }),
            ("0".repeat(65), AddressError::LegacyHexLength { length: 65 }),
            (
                format!("{}A", "0".repeat(63)),
                AddressError::LegacyHexCharacter { position: 63 },
            ),
            (
                format!("g{}", "0".repeat(63)),
                AddressError::LegacyHexCharacter { position: 0 },
            ),
        ] {
            assert_eq!(parse_legacy_hex(&text), Err(expected), "{text}");
            codes.insert(expected.code());
        }
        // Sixteen classes, sixteen distinct codes.
        assert_eq!(codes.len(), 16, "{codes:?}");
        // The decoded address is the full identifier: never a prefix match or a completion.
        assert_eq!(decode(&good, class), Ok(id));
        assert!(decode(&good[..good.len() - 1], class).is_err());
    }

    #[test]
    fn the_check_order_is_the_documented_one() {
        // A string that is both too long and mixed-case reports the length first; an uppercase string
        // with an unknown prefix reports the case first; a wrong-class string with a bad checksum
        // reports the checksum (the class is compared only for a well-formed address).
        let long_mixed = format!("Tmut1{}", "q".repeat(86));
        assert_eq!(
            decode_any(&long_mixed),
            Err(AddressError::TooLong { length: 91 })
        );
        assert_eq!(decode_any("BC1QQQQQQ"), Err(AddressError::Uppercase));
        let production = encode(&[7; 32], ChainClass::Production);
        let broken = format!(
            "{}{}",
            &production[..production.len() - 1],
            if production.ends_with('q') { 'p' } else { 'q' }
        );
        assert_eq!(
            decode(&broken, ChainClass::TestValue),
            Err(AddressError::InvalidChecksum)
        );
    }
}
