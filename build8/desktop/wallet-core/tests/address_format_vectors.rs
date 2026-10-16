//! The public address-format vectors (Order W2): `tests/golden/address-format-v1.json`.
//!
//! TEST-VALUE and PROPOSED: the format is not frozen (`docs/ADDRESS-FORMAT-V1.md`), and the
//! identifiers are fixed byte patterns or the addresses of the public TEST-VALUE keys of
//! `support/synthetic.rs` (the BIP-39 test phrases), never production keys.
//!
//! `the_published_vectors_decode_and_encode_exactly` is the decoder test the vectors are for; the
//! ignored `print_address_format_vectors` is the generator that wrote the file (run it with
//! `cargo test --offline --locked --test address_format_vectors -- --ignored --nocapture` and
//! replace the file with its output when the format changes deliberately).
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_wallet_core_v8::{
    ChainClass,
    address_format::{
        self, AddressError, CHARSET, CHECKSUM_CONSTANT, CHECKSUM_LENGTH, FORMAT,
        ORIGINAL_VARIANT_CONSTANT, PREFIX_PRODUCTION, PREFIX_TEST_VALUE, PREFIX_UNDECLARED,
    },
};
use serde_json::{Value, json};

const VECTORS: &str = include_str!("golden/address-format-v1.json");
const REGISTRY: &str = include_str!("../../spec/DOMAIN-REGISTRY-V1.json");

fn class_name(class: ChainClass) -> &'static str {
    match class {
        ChainClass::Production => "production",
        ChainClass::TestValue => "test-value",
        ChainClass::Undeclared => "undeclared",
    }
}

fn class_of(name: &str) -> ChainClass {
    match name {
        "production" => ChainClass::Production,
        "test-value" => ChainClass::TestValue,
        "undeclared" => ChainClass::Undeclared,
        other => panic!("unknown class {other}"),
    }
}

fn hash_of(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

/// A string of this format with an arbitrary data part and a checksum under `constant`, built from
/// the public `residue` (BIP-350 `bech32_create_checksum`: the residue of the data followed by six
/// zero values, XOR the constant).
fn assemble(prefix: &str, data: &[u8], constant: u32) -> String {
    let mut padded = data.to_vec();
    padded.extend_from_slice(&[0; CHECKSUM_LENGTH]);
    let residue = address_format::residue(prefix, &padded) ^ constant;
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

/// The five-bit data values of an encoded address (without its checksum).
fn data_of(encoded: &str) -> Vec<u8> {
    let separator = encoded.rfind('1').unwrap();
    let values: Vec<u8> = encoded[separator + 1..]
        .bytes()
        .map(|byte| CHARSET.iter().position(|c| *c == byte).unwrap() as u8)
        .collect();
    values[..values.len() - CHECKSUM_LENGTH].to_vec()
}

fn generate() -> Value {
    use synthetic::{address, key_a, key_b, key_c};
    let mut counting = [0u8; 32];
    for (index, byte) in counting.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let ids: Vec<(&str, [u8; 32])> = vec![
        ("all zero bytes", [0; 32]),
        ("all 0xff bytes", [0xff; 32]),
        ("bytes 0x00 to 0x1f", counting),
        (
            "TEST-VALUE key A (all-abandon phrase), generation 1",
            address(&key_a(), 1),
        ),
        (
            "TEST-VALUE key B (all-zoo phrase), generation 1",
            address(&key_b(), 1),
        ),
        (
            "TEST-VALUE key C (legal-winner phrase), generation 1",
            address(&key_c(), 1),
        ),
        ("TEST-VALUE key A, generation 2", address(&key_a(), 2)),
    ];
    let classes = [
        ChainClass::Production,
        ChainClass::TestValue,
        ChainClass::Undeclared,
    ];
    let mut valid = Vec::new();
    for (what, id) in &ids {
        for class in classes {
            valid.push(json!({
                "what": what,
                "class": class_name(class),
                "address_hex": hex::encode(id),
                "encoded": address_format::encode(id, class),
            }));
        }
    }
    let id = ids[3].1;
    let good = address_format::encode(&id, ChainClass::TestValue);
    let data = data_of(&good);
    let mut short = data.clone();
    short.pop();
    let mut long = data.clone();
    long.push(0);
    let mut padded = data.clone();
    *padded.last_mut().unwrap() |= 1;
    let last = if good.ends_with('q') { 'p' } else { 'q' };
    let mut invalid: Vec<(String, &str, &str, &str)> = vec![
        (String::new(), "test-value", "EMPTY", "nothing entered"),
        (
            format!("tmut1{}", "q".repeat(86)),
            "test-value",
            "TOO_LONG",
            "91 characters, beyond the BIP-173 limit of 90",
        ),
        (
            format!(" {good}"),
            "test-value",
            "INVALID_CHARACTER",
            "a leading space: nothing is trimmed",
        ),
        (
            format!("{good}\n"),
            "test-value",
            "INVALID_CHARACTER",
            "a trailing line feed: nothing is trimmed",
        ),
        (
            "tmut1\u{e9}".to_string(),
            "test-value",
            "INVALID_CHARACTER",
            "a non-ASCII character",
        ),
        (
            format!("{}b{}", &good[..10], &good[11..]),
            "test-value",
            "INVALID_CHARACTER",
            "a data character outside the BIP-173 alphabet (b)",
        ),
        (
            format!("{}{}", good[..10].to_ascii_uppercase(), &good[10..]),
            "test-value",
            "MIXED_CASE",
            "upper- and lowercase mixed",
        ),
        (
            good.to_ascii_uppercase(),
            "test-value",
            "UPPERCASE",
            "the all-uppercase form is not accepted (no normalisation)",
        ),
        (
            "tmutqqqqqqqqq".to_string(),
            "test-value",
            "MISSING_SEPARATOR",
            "no separator 1",
        ),
        (
            assemble("bc", &data, CHECKSUM_CONSTANT),
            "test-value",
            "UNKNOWN_PREFIX",
            "a valid bech32m string under a foreign prefix",
        ),
        (
            assemble("", &data, CHECKSUM_CONSTANT),
            "test-value",
            "UNKNOWN_PREFIX",
            "an empty prefix",
        ),
        (
            address_format::encode(&id, ChainClass::Production),
            "test-value",
            "WRONG_PREFIX",
            "a valid production-class address entered on a TEST-VALUE chain",
        ),
        (
            address_format::encode(&id, ChainClass::TestValue),
            "production",
            "WRONG_PREFIX",
            "a valid TEST-VALUE address entered on a production chain",
        ),
        (
            address_format::encode(&id, ChainClass::Undeclared),
            "production",
            "WRONG_PREFIX",
            "a valid class-not-declared address entered on a production chain",
        ),
        (
            "tmut1qqqqq".to_string(),
            "test-value",
            "TOO_SHORT",
            "fewer characters than the checksum alone",
        ),
        (
            format!("{}{last}", &good[..good.len() - 1]),
            "test-value",
            "INVALID_CHECKSUM",
            "the last checksum character changed",
        ),
        (
            format!("t{}", address_format::encode(&id, ChainClass::Production)),
            "test-value",
            "INVALID_CHECKSUM",
            "a production address with only its prefix edited to tmut",
        ),
        (
            assemble("tmut", &data, ORIGINAL_VARIANT_CONSTANT),
            "test-value",
            "CHECKSUM_VARIANT",
            "a BIP-173 bech32 checksum instead of bech32m",
        ),
        (
            assemble("tmut", &short, CHECKSUM_CONSTANT),
            "test-value",
            "PAYLOAD_TOO_SHORT",
            "51 data characters with a valid checksum",
        ),
        (
            assemble("tmut", &long, CHECKSUM_CONSTANT),
            "test-value",
            "PAYLOAD_TOO_LONG",
            "53 data characters with a valid checksum (extra data)",
        ),
        (
            assemble("tmut", &padded, CHECKSUM_CONSTANT),
            "test-value",
            "NON_CANONICAL_PADDING",
            "non-zero padding bits in the last data character, valid checksum",
        ),
    ];
    invalid.sort_by(|a, b| a.2.cmp(b.2).then(a.0.cmp(&b.0)));
    let invalid: Vec<Value> = invalid
        .into_iter()
        .map(|(encoded, class, error, why)| {
            json!({ "encoded": encoded, "class": class, "error": error, "why": why })
        })
        .collect();
    json!({
        "format": FORMAT,
        "status": "PROPOSED-UNFROZEN: not frozen until the Architect approves docs/ADDRESS-FORMAT-V1.md",
        "evidence": "TEST-VALUE public vectors: fixed byte patterns and the addresses of public BIP-39 test-phrase keys; no production key",
        "encoding": "prefix || '1' || 52 data characters (the 32 bytes as 5-bit groups, most significant bit first, 4 zero padding bits) || 6 checksum characters; BIP-173 alphabet and generator; BIP-350 bech32m constant",
        "bech32m_constant": "0x2bc830a3",
        "charset": std::str::from_utf8(CHARSET).unwrap(),
        "prefixes": {
            "production": PREFIX_PRODUCTION,
            "test-value": PREFIX_TEST_VALUE,
            "undeclared": PREFIX_UNDECLARED,
        },
        "valid": valid,
        "invalid": invalid,
        "legacy_hex_valid": [
            { "text": hex::encode(id), "address_hex": hex::encode(id) },
        ],
        "legacy_hex_invalid": [
            { "text": "0".repeat(63), "error": "LEGACY_HEX_LENGTH" },
            { "text": format!("{}A", "0".repeat(63)), "error": "LEGACY_HEX_CHARACTER" },
            { "text": format!("0x{}", "0".repeat(62)), "error": "LEGACY_HEX_CHARACTER" },
        ],
        "bip350_bech32m_valid": [
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ],
        "bip173_bech32_valid": [
            "A12UEL5L",
            "a12uel5l",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl",
        ],
    })
}

#[test]
#[ignore = "prints tests/golden/address-format-v1.json"]
fn print_address_format_vectors() {
    println!(
        "=====address-format-v1.json\n{}\n=====end",
        serde_json::to_string_pretty(&generate()).unwrap()
    );
}

/// The residue of a generic bech32 string (BIP checksums are defined over the lowercase form).
fn generic_residue(text: &str) -> u32 {
    let lower = text.to_ascii_lowercase();
    let separator = lower.rfind('1').unwrap();
    let values: Vec<u8> = lower[separator + 1..]
        .bytes()
        .map(|byte| CHARSET.iter().position(|c| *c == byte).unwrap() as u8)
        .collect();
    address_format::residue(&lower[..separator], &values)
}

#[test]
fn the_published_vectors_decode_and_encode_exactly() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["format"], FORMAT);
    assert!(
        vectors["status"]
            .as_str()
            .unwrap()
            .starts_with("PROPOSED-UNFROZEN")
    );
    assert_eq!(
        vectors["bech32m_constant"],
        format!("0x{CHECKSUM_CONSTANT:08x}")
    );
    assert_eq!(vectors["charset"], std::str::from_utf8(CHARSET).unwrap());
    assert_eq!(vectors["prefixes"]["production"], PREFIX_PRODUCTION);
    assert_eq!(vectors["prefixes"]["test-value"], PREFIX_TEST_VALUE);
    assert_eq!(vectors["prefixes"]["undeclared"], PREFIX_UNDECLARED);

    let valid = vectors["valid"].as_array().unwrap();
    assert_eq!(valid.len(), 21, "seven identifiers under three classes");
    for vector in valid {
        let class = class_of(vector["class"].as_str().unwrap());
        let id = hash_of(vector["address_hex"].as_str().unwrap());
        let encoded = vector["encoded"].as_str().unwrap();
        assert_eq!(address_format::decode(encoded, class), Ok(id), "{encoded}");
        assert_eq!(address_format::decode_any(encoded), Ok((class, id)));
        assert_eq!(address_format::encode(&id, class), encoded);
        assert!(encoded.starts_with(&format!("{}1", address_format::prefix(class))));
    }

    let invalid = vectors["invalid"].as_array().unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for vector in invalid {
        let class = class_of(vector["class"].as_str().unwrap());
        let encoded = vector["encoded"].as_str().unwrap();
        let expected = vector["error"].as_str().unwrap();
        let error: AddressError = address_format::decode(encoded, class).unwrap_err();
        assert_eq!(error.code(), expected, "{encoded:?}: {}", vector["why"]);
        seen.insert(expected);
    }
    // Every rejection class of the decoder has at least one vector.
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [
            "CHECKSUM_VARIANT",
            "EMPTY",
            "INVALID_CHARACTER",
            "INVALID_CHECKSUM",
            "MISSING_SEPARATOR",
            "MIXED_CASE",
            "NON_CANONICAL_PADDING",
            "PAYLOAD_TOO_LONG",
            "PAYLOAD_TOO_SHORT",
            "TOO_LONG",
            "TOO_SHORT",
            "UNKNOWN_PREFIX",
            "UPPERCASE",
            "WRONG_PREFIX",
        ]
    );

    for vector in vectors["legacy_hex_valid"].as_array().unwrap() {
        assert_eq!(
            address_format::parse_legacy_hex(vector["text"].as_str().unwrap()),
            Ok(hash_of(vector["address_hex"].as_str().unwrap()))
        );
    }
    for vector in vectors["legacy_hex_invalid"].as_array().unwrap() {
        let error = address_format::parse_legacy_hex(vector["text"].as_str().unwrap()).unwrap_err();
        assert_eq!(error.code(), vector["error"].as_str().unwrap());
    }
    for text in vectors["bip350_bech32m_valid"].as_array().unwrap() {
        assert_eq!(
            generic_residue(text.as_str().unwrap()),
            CHECKSUM_CONSTANT,
            "{text}"
        );
    }
    for text in vectors["bip173_bech32_valid"].as_array().unwrap() {
        assert_eq!(
            generic_residue(text.as_str().unwrap()),
            ORIGINAL_VARIANT_CONSTANT,
            "{text}"
        );
    }
}

/// The file is exactly what the generator writes (so a vector cannot be edited by hand without the
/// generator, and a change of the implementation cannot pass without regenerating the file).
#[test]
fn the_vector_file_is_the_generators_output() {
    let generated = serde_json::to_string_pretty(&generate()).unwrap();
    assert!(
        VECTORS.trim_end() == generated,
        "tests/golden/address-format-v1.json differs from the generator; if the change is deliberate, replace it with:\n{generated}"
    );
}

/// The text format is registered once, PROPOSED and unfrozen, with its specification.
#[test]
fn the_format_is_registered_as_proposed_and_unfrozen() {
    let registry: Value = serde_json::from_str(REGISTRY).unwrap();
    let entries: Vec<&Value> = registry["domains"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["ascii"] == FORMAT)
        .collect();
    assert_eq!(entries.len(), 1, "{FORMAT} registered exactly once");
    assert_eq!(entries[0]["status"], "PROPOSED-UNFROZEN");
    assert_eq!(entries[0]["doc"], "wallet-core/docs/ADDRESS-FORMAT-V1.md");
    let body = entries[0]["body"].as_str().unwrap();
    for needle in ["0x2bc830a3", "mut", "tmut", "umut", "52"] {
        assert!(body.contains(needle), "{needle}");
    }
}
