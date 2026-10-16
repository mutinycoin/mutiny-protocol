//! The Bitcoin custody boundary of the wallet core (phase 6). BTC custody stays external and under the
//! Architect's sole control; the wallet never builds, parses or signs a Bitcoin transaction or PSBT,
//! holds no Bitcoin key, script, txid or address type, and never verifies Bitcoin evidence. What
//! this file pins (the dependency graph itself is pinned by `build_independence.rs`):
//!
//!  1. No public type of the crate (requests, plans, reviews, partial containers, outbox records,
//!     Treasury types) has a field typed as a Bitcoin key, script, txid, address or PSBT: a source
//!     scan of every `pub struct` / `pub enum` field and every public function signature, plus
//!     compile-time structural checks of the types that carry the two INTEGER Bitcoin offer terms
//!     (satoshis and a network code). Bitcoin-named identifiers in code are an exact allow-list of
//!     those integer terms.
//!  2. No wallet-core API accepts an unsigned Bitcoin transaction: no public function takes a
//!     Bitcoin-typed parameter, and `OperationRequest` has no Bitcoin variant.
//!  3. Hash-lock preimages are fresh operating-system random values: black-box freshness (two
//!     identical wallets produce different preimages; nothing equals a key-derived value), and a
//!     source check that the only constructors are OS randomness or a copy of a stored preimage,
//!     with no derivation call anywhere near them. (Bit-level statistics run as a unit test inside
//!     the crate, where the preimage bytes are readable: `ops::treasury` tests.)
//!  4. Treasury reviews say they change MUT authority only and do not touch Bitcoin custody, and
//!     never print key material.
//!  5. A Treasury offer naming a Bitcoin network outside 1..=3 is refused (0, mainnet, by the wallet
//!     and by consensus; 4 and above cannot even be encoded).
//!  6. The lock file has no Bitcoin crate besides the `bitcoin_hashes` hash library.
//!
//! NATIVE, TEST-VALUE; public test keys only.
#[path = "support/treasury_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;

use kit::{FreezeTerms, TRADING_TREASURY};
use mutiny_consensus_v8::{
    Hash,
    dividend_state_v1::DividendState,
    trading_v1::{self, NativeError, OfferBody, OfferTerms, SignedOffer, Strikes},
    treasury_v1::{Class, Treasury},
};
use mutiny_wallet_core_v8::{
    ops::{
        conditional::{HashLinkedOffer, MemoryPreimageStore, PreimageStore},
        treasury::{self, TradingTreasury},
    },
    profile::{TreasuryDeclaration, TreasuryStanding},
    *,
};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

// ---------------------------------------------------------------------------------------------
// Source scanning helpers
// ---------------------------------------------------------------------------------------------

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Source code with comments, string literals and character literals removed: what remains is
/// code-shaped text only (review text legitimately says "Bitcoin custody").
fn code_only(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 0usize;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        // Raw strings r"..." and r#"..."#, and byte strings b"..." / br"...".
        if (c == 'r' || (c == 'b' && next == Some('r')))
            && !chars
                .get(i.wrapping_sub(1))
                .is_some_and(|p| p.is_alphanumeric() || *p == '_')
        {
            let start = if c == 'b' { i + 2 } else { i + 1 };
            let mut j = start;
            let mut hashes = 0;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) == Some(&'"') {
                j += 1;
                loop {
                    if j >= chars.len() {
                        break;
                    }
                    if chars[j] == '"' && (0..hashes).all(|k| chars.get(j + 1 + k) == Some(&'#')) {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                out.push_str("\"\"");
                i = j;
                continue;
            }
        }
        if c == '"' {
            let mut j = i + 1;
            while j < chars.len() {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '"' {
                    break;
                }
                j += 1;
            }
            out.push_str("\"\"");
            i = j + 1;
            continue;
        }
        if c == '\'' {
            // A character literal ('a', '\n', '"'), not a lifetime ('a in generics).
            if next == Some('\\') {
                let mut j = i + 2;
                while j < chars.len() && chars[j] != '\'' {
                    j += 1;
                }
                out.push_str("' '");
                i = j + 1;
                continue;
            }
            if chars.get(i + 2) == Some(&'\'') {
                out.push_str("' '");
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// The production part of a source file: everything before its `#[cfg(test)]` module.
fn production_part(code: &str) -> &str {
    code.find("#[cfg(test)]\nmod tests")
        .map_or(code, |at| &code[..at])
}

/// Lowercase sub-words of an identifier: split on `_` and on lower-to-upper case changes.
fn subwords(identifier: &str) -> Vec<String> {
    let mut words = Vec::new();
    for part in identifier.split('_') {
        let mut word = String::new();
        let mut previous_lower = false;
        for c in part.chars() {
            if c.is_uppercase() && previous_lower && !word.is_empty() {
                words.push(word.to_lowercase());
                word.clear();
            }
            previous_lower = c.is_lowercase() || c.is_ascii_digit();
            word.push(c);
        }
        if !word.is_empty() {
            words.push(word.to_lowercase());
        }
    }
    words
}

fn identifiers(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in code.chars() {
        if c.is_alphanumeric() || c == '_' {
            current.push(c);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Sub-words that only Bitcoin code would use.
const BITCOIN_WORDS: &[&str] = &[
    "bitcoin",
    "btc",
    "psbt",
    "satoshi",
    "satoshis",
    "secp256k1",
    "segwit",
    "taproot",
    "bech32",
    "xpub",
    "xprv",
    "wif",
    "scriptpubkey",
    "scriptsig",
    "miniscript",
    "bdk",
    "electrum",
];

/// The only Bitcoin-named identifiers allowed in the crate's code: the two INTEGER offer terms, the
/// accepted network codes, a code-to-name lookup and three text constants.
const ALLOWED: &[&str] = &[
    "bitcoin_satoshis",
    "bitcoin_network",
    "bitcoin_network_name",
    "TREASURY_BITCOIN_NETWORKS",
    "NO_BITCOIN",
    "REASON_BITCOIN_MAINNET",
];

fn is_bitcoin_word(identifier: &str) -> bool {
    subwords(identifier)
        .iter()
        .any(|word| BITCOIN_WORDS.contains(&word.as_str()))
}

fn sources() -> Vec<(String, String)> {
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let name = path
                .strip_prefix(root().join("src"))
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (name, code_only(&fs::read_to_string(&path).unwrap()))
        })
        .collect()
}

/// The bodies `{ ... }` of every `pub struct NAME` and `pub enum NAME` in `code`.
fn public_type_bodies(code: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for keyword in ["pub struct ", "pub enum "] {
        for (at, _) in code.match_indices(keyword) {
            let rest = &code[at + keyword.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let Some(open) = rest.find(['{', ';', '(']) else {
                continue;
            };
            let delimiter = rest[open..].chars().next().unwrap();
            if delimiter == ';' {
                out.push((name, String::new()));
                continue;
            }
            let (open_char, close_char) = if delimiter == '{' {
                ('{', '}')
            } else {
                ('(', ')')
            };
            let mut depth = 0usize;
            let mut end = open;
            for (offset, c) in rest[open..].char_indices() {
                if c == open_char {
                    depth += 1;
                } else if c == close_char {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
            }
            out.push((name, rest[open + 1..end].to_string()));
        }
    }
    out
}

/// (request, field, type) of every request struct declared through `request! { Name { .. } }`.
fn request_fields(code: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (at, _) in code.match_indices("request! {") {
        let rest = &code[at + "request! {".len()..];
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let open = rest.find('{').unwrap();
        let close = rest[open..].find('}').unwrap() + open;
        for declaration in rest[open + 1..close].split(',') {
            if let Some((field, ty)) = declaration.split_once(':') {
                let field = identifiers(field).last().cloned().unwrap_or_default();
                out.push((name.clone(), field, ty.trim().to_string()));
            }
        }
    }
    out
}

/// The signatures (up to the body) of every public function in `code`.
fn public_fn_signatures(code: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (at, _) in code.match_indices("pub fn ") {
        let rest = &code[at + "pub fn ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let end = rest.find(['{', ';']).unwrap_or(rest.len());
        out.push((name, rest[..end].to_string()));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// 1. No Bitcoin-typed field
// ---------------------------------------------------------------------------------------------

#[test]
fn bitcoin_named_identifiers_in_code_are_exactly_the_integer_offer_terms() {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for (name, code) in sources() {
        for identifier in identifiers(production_part(&code)) {
            if is_bitcoin_word(&identifier) {
                assert!(
                    ALLOWED.contains(&identifier.as_str()),
                    "{name}: a Bitcoin-named identifier outside the allow-list: {identifier}"
                );
                found.insert(identifier);
            }
        }
    }
    // The allow-list is not stale: each entry is really used.
    assert_eq!(
        found,
        ALLOWED
            .iter()
            .map(|s| s.to_string())
            .collect::<BTreeSet<_>>()
    );
    // And the detector detects.
    for word in [
        "BitcoinTransaction",
        "psbt_bytes",
        "TxScriptPubKey",
        "btc_key",
        "Secp256k1Key",
    ] {
        assert!(
            is_bitcoin_word(word) || subwords(word).contains(&"script".to_string()),
            "{word}"
        );
    }
    assert!(!is_bitcoin_word("descriptor_hash"));
    assert!(!is_bitcoin_word("description"));
}

#[test]
fn no_public_type_has_a_bitcoin_typed_field_beyond_the_integer_offer_terms() {
    let mut integer_terms = Vec::new();
    let mut scanned = 0usize;
    for (file, code) in sources() {
        let production = production_part(&code);
        for (type_name, body) in public_type_bodies(production) {
            scanned += 1;
            assert!(!is_bitcoin_word(&type_name), "{file}: type {type_name}");
            // Field and variant declarations: `name: Type` pairs and bare types.
            for declaration in body.split(',') {
                let declaration = declaration.trim();
                let (field, ty) = match declaration.split_once(':') {
                    Some((field, ty)) if !field.contains('(') && !field.contains('{') => {
                        (field.trim().trim_start_matches("pub ").trim(), ty.trim())
                    }
                    _ => ("", declaration),
                };
                let field_name = identifiers(field).last().cloned().unwrap_or_default();
                let type_words: Vec<String> = identifiers(ty);
                for word in &type_words {
                    assert!(
                        !is_bitcoin_word(word),
                        "{file}: {type_name}.{field_name} has a Bitcoin-typed component {word}"
                    );
                    for banned in ["Script", "Txid", "Psbt", "Witness", "PrivateKey", "Xpub"] {
                        assert_ne!(word, banned, "{file}: {type_name}.{field_name}");
                    }
                }
                if is_bitcoin_word(&field_name) {
                    // Only the two integer offer terms may carry a Bitcoin name, as integers.
                    let ty = ty.trim_end_matches('}').trim();
                    assert!(
                        (field_name == "bitcoin_satoshis" && ty == "u64")
                            || (field_name == "bitcoin_network" && ty == "u8"),
                        "{file}: {type_name}.{field_name}: {ty}"
                    );
                    integer_terms.push(format!("{type_name}.{field_name}: {ty}"));
                }
            }
        }
    }
    assert!(scanned > 50, "the scan reads the public types ({scanned})");
    // The request structs, declared through the `request!` macro in plan.rs.
    let plan = code_only(&fs::read_to_string(root().join("src/plan.rs")).unwrap());
    let fields = request_fields(&plan);
    assert!(fields.len() >= 14, "{fields:?}");
    for (request, field, ty) in &fields {
        for word in identifiers(field).iter().chain(identifiers(ty).iter()) {
            assert!(!is_bitcoin_word(word), "{request}.{field}: {ty}");
        }
    }
    let treasury: Vec<(String, String)> = fields
        .iter()
        .filter(|(request, _, _)| request.starts_with("Treasury"))
        .map(|(request, field, ty)| (format!("{request}.{field}"), ty.clone()))
        .collect();
    assert_eq!(
        treasury,
        vec![
            (
                "TreasuryRotateRequest.new_descriptor".to_string(),
                "Blob".to_string()
            ),
            (
                "TreasuryRotateRequest.new_key_restore_verified".to_string(),
                "bool".to_string()
            ),
            (
                "TreasuryRotateRequest.restore_verified_fingerprint".to_string(),
                "Option<Hash>".to_string()
            ),
            (
                "TreasuryRotateRequest.restore_authority".to_string(),
                "Option<Hash>".to_string()
            ),
            (
                "TreasuryRotateRequest.validity_blocks".to_string(),
                "u64".to_string()
            ),
            (
                "TreasuryRotateRequest.treasury".to_string(),
                "Option<Hash>".to_string()
            ),
            (
                "TreasuryFreezeOfferRequest.prepared_offer".to_string(),
                "Blob".to_string()
            ),
        ]
    );
    assert_eq!(
        integer_terms,
        vec![
            "HashLinkedOffer.bitcoin_satoshis: u64".to_string(),
            "HashLinkedOffer.bitcoin_network: u8".to_string(),
        ],
        "the only Bitcoin-named fields are the two integer terms of an imported offer"
    );
}

/// Compile-time structural checks: a new field, or another type for an existing one, stops this
/// file from compiling.
#[allow(dead_code)]
fn structural_checks(
    offer: &HashLinkedOffer,
    terms: &OfferTerms,
    rotate: &TreasuryRotateRequest,
    freeze: &TreasuryFreezeOfferRequest,
    trading: &TradingTreasury,
    declaration: &TreasuryDeclaration,
    standing: &TreasuryStanding,
) {
    // Exhaustive: every field of an imported hash-linked offer, typed.
    let HashLinkedOffer {
        id,
        maker,
        nonce,
        created,
        expiry,
        maker_side,
        amount,
        bitcoin_satoshis,
        bitcoin_network,
    } = offer;
    let _: (&Hash, &Hash, &Hash, &u64, &u64, &u8, &u64, &u64, &u8) = (
        id,
        maker,
        nonce,
        created,
        expiry,
        maker_side,
        amount,
        bitcoin_satoshis,
        bitcoin_network,
    );
    // The consensus offer terms: the Bitcoin terms are integers.
    if let OfferTerms::HashLinked {
        amount,
        bitcoin_satoshis,
        bitcoin_network,
    } = terms
    {
        let _: (&Strikes, &u64, &u8) = (amount, bitcoin_satoshis, bitcoin_network);
    }
    // The Treasury requests (non-exhaustive outside the crate: the source scan covers new fields).
    let TreasuryRotateRequest {
        new_descriptor,
        validity_blocks,
        treasury,
        ..
    } = rotate;
    let _: (&Blob, &u64, &Option<Hash>) = (new_descriptor, validity_blocks, treasury);
    let TreasuryFreezeOfferRequest { prepared_offer, .. } = freeze;
    let _: &Blob = prepared_offer;
    // The public Treasury types, exhaustively.
    let TradingTreasury {
        id,
        generation,
        address,
        descriptor_hash,
        effective_height,
    } = trading;
    let _: (&Hash, &u64, &Hash, &Hash, &u64) =
        (id, generation, address, descriptor_hash, effective_height);
    let TreasuryDeclaration {
        genesis,
        chain_class,
        authority,
        destination_of,
    } = declaration;
    let _: (&Hash, &ChainClass, &bool, &Option<Hash>) =
        (genesis, chain_class, authority, destination_of);
    let TreasuryStanding {
        authority,
        destinations,
    } = standing;
    let _: (&bool, &Vec<Hash>) = (authority, destinations);
}

// ---------------------------------------------------------------------------------------------
// 2. No API accepts a Bitcoin transaction
// ---------------------------------------------------------------------------------------------

#[test]
fn no_public_function_takes_a_bitcoin_typed_parameter_and_requests_have_no_bitcoin_variant() {
    let mut functions = 0usize;
    for (file, code) in sources() {
        for (name, signature) in public_fn_signatures(production_part(&code)) {
            functions += 1;
            let after_name = &signature[signature.find('(').unwrap_or(signature.len())..];
            let parameters = after_name.split("->").next().unwrap_or("");
            for word in identifiers(parameters) {
                assert!(
                    !is_bitcoin_word(&word),
                    "{file}: fn {name} takes a Bitcoin-typed parameter ({word})"
                );
            }
            if is_bitcoin_word(&name) {
                assert_eq!(
                    (name.as_str(), parameters.contains("code: u8")),
                    ("bitcoin_network_name", true),
                    "{file}: the only Bitcoin-named function maps an integer code to a name"
                );
            }
            for word in subwords(&name) {
                assert!(
                    !["psbt", "transaction_bitcoin", "sighash"].contains(&word.as_str()),
                    "{file}: fn {name}"
                );
            }
        }
    }
    assert!(
        functions > 100,
        "the scan reads the public functions ({functions})"
    );
    // The request enum: every variant is a MUT operation or the cancellation.
    let plan_code = code_only(&fs::read_to_string(root().join("src/plan.rs")).unwrap());
    let body = public_type_bodies(&plan_code)
        .into_iter()
        .find(|(name, _)| name == "OperationRequest")
        .unwrap()
        .1;
    let variants: Vec<String> = body
        .split(',')
        .filter_map(|v| identifiers(v).first().cloned())
        .collect();
    assert_eq!(
        variants,
        [
            "Payment",
            "WalletRotation",
            "DividendClaim",
            "LicenseDvp",
            "HashLock",
            "ConditionalClaim",
            "ConditionalRefund",
            "FiatLock",
            "FiatRelease",
            "BondCreate",
            "BondUnbond",
            "BondWithdraw",
            "TreasuryRotate",
            "TreasuryFreezeOffer",
            "MakerOffer",
            "WorkerAssignment",
            "Cancel",
        ]
    );
    // No Bitcoin bytes are recognised as any operation: a typical unsigned Bitcoin transaction
    // (version 2, one input, one output, locktime) is refused as unknown by every entry point.
    let world = treasury_world(100);
    let view = world.view();
    let mut bitcoin_like = vec![0x02, 0, 0, 0, 0x01];
    bitcoin_like.extend([0x11; 32]);
    bitcoin_like.extend([0, 0, 0, 0, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01]);
    bitcoin_like.extend(50_000u64.to_le_bytes());
    bitcoin_like.extend([0x16, 0x00, 0x14]);
    bitcoin_like.extend([0x22; 20]);
    bitcoin_like.extend([0, 0, 0, 0]);
    let me = identity(&key_b()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: Some(TRADING_TREASURY),
    });
    assert_eq!(
        explain(&bitcoin_like, &view, &me).unwrap_err(),
        Refusal::UnknownOperation
    );
    assert_eq!(
        adopt(&bitcoin_like, &view, &me).unwrap_err(),
        Refusal::UnknownOperation
    );
    assert_eq!(
        SignedOperation::import(&bitcoin_like, &view).unwrap_err(),
        Refusal::UnknownOperation
    );
    for request in [
        OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(
            bitcoin_like.clone(),
        ))),
        OperationRequest::TreasuryRotate(TreasuryRotateRequest::new(Blob::new(
            bitcoin_like.clone(),
        ))),
    ] {
        assert!(plan(&request, &view, &me).is_err());
    }
}

// ---------------------------------------------------------------------------------------------
// 3. Preimages: fresh OS randomness, never derived from a key
// ---------------------------------------------------------------------------------------------

#[test]
fn identical_wallets_produce_different_preimages_and_none_equals_a_key_derived_value() {
    let mut conditions = BTreeSet::new();
    // Two "identical wallets": the same key, the same store type, created the same way.
    for _ in 0..2 {
        let mut store = MemoryPreimageStore::new();
        for _ in 0..200 {
            assert!(
                conditions.insert(store.create().unwrap()),
                "a repeated preimage"
            );
        }
    }
    assert_eq!(conditions.len(), 400);
    // Generated directly as well.
    for _ in 0..200 {
        assert!(conditions.insert(Preimage::generate().unwrap().condition()));
    }
    // None equals a value derived from this wallet's public key material.
    let key = key_b();
    let derived: Vec<Hash> = [
        address(&key, 1).to_vec(),
        descriptor(&key, 1),
        key.public().ed448.to_vec(),
        key.public().fndsa.to_vec(),
    ]
    .into_iter()
    .flat_map(|material| {
        [
            trading_v1::preimage_hash(&{
                let mut first = [0u8; 32];
                let n = material.len().min(32);
                first[..n].copy_from_slice(&material[..n]);
                first
            }),
            mutiny_consensus_v8::domain_hash(b"preimage", &material),
        ]
    })
    .collect();
    for value in derived {
        assert!(!conditions.contains(&value));
    }
}

#[test]
fn preimages_are_constructed_only_from_os_randomness_or_a_stored_copy() {
    let mut constructors: BTreeSet<String> = BTreeSet::new();
    for (file, code) in sources() {
        let production = production_part(&code);
        // No key-derivation machinery anywhere in the wallet core.
        for word in identifiers(production) {
            let lower = word.to_lowercase();
            for banned in [
                "hkdf",
                "pbkdf2",
                "argon2",
                "scrypt",
                "derive_key",
                "derive_preimage",
            ] {
                assert!(!lower.contains(banned), "{file}: {word}");
            }
        }
        for (at, _) in production.match_indices("Preimage::") {
            let call: String = production[at + "Preimage::".len()..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if call.is_empty() {
                continue;
            }
            let context = &production[at..(at + 80).min(production.len())];
            constructors.insert(format!("{file}: {call}"));
            if call == "from_bytes" {
                // Outside the tests, a preimage is copied only from one this wallet already holds.
                assert!(
                    context.contains("from_bytes(*preimage.expose())"),
                    "{file}: {context}"
                );
            }
            // Nothing that touches a key or a phrase sits next to a preimage constructor.
            let window_start = at.saturating_sub(400);
            let window = &production[window_start..(at + 400).min(production.len())];
            for word in identifiers(window) {
                assert!(
                    ![
                        "HybridKey",
                        "wallet_restore",
                        "phrase",
                        "seed",
                        "KeySigner",
                        "KindSigner"
                    ]
                    .contains(&word.as_str()),
                    "{file}: {word} near a preimage constructor"
                );
            }
        }
    }
    assert_eq!(
        constructors,
        BTreeSet::from([
            "ops/conditional.rs: from_bytes".to_string(),
            "ops/conditional.rs: generate".to_string(),
        ]),
        "preimages are made only by OS randomness and copied only from the wallet's own store"
    );
    // The one generator reads operating-system randomness and nothing else.
    let secret = code_only(&fs::read_to_string(root().join("src/secret.rs")).unwrap());
    let production = production_part(&secret);
    let generate = &production[production.find("pub fn generate()").unwrap()..];
    let generate = &generate[..generate.find("\n    }").unwrap()];
    assert!(generate.contains("mutiny_crypto_v2::fill_os_random(bytes.as_mut())"));
    for word in identifiers(generate) {
        assert!(
            ![
                "HybridKey",
                "wallet_restore",
                "phrase",
                "seed",
                "derive",
                "hash",
                "sha2"
            ]
            .contains(&word.as_str()),
            "secret.rs generate: {word}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 4. Treasury reviews: MUT authority only, no key material
// ---------------------------------------------------------------------------------------------

fn treasury_world(head: u64) -> World {
    let mut world = World::new(head);
    world
        .state
        .wallets
        .register(&descriptor(&key_b(), 1))
        .unwrap();
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&key_b(), 1)).unwrap());
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xd1, 0);
    let context = kit::context_of(&world.anchor);
    for (key, raw) in
        trading_v1::treasury_genesis_records(&context, TRADING_TREASURY, descriptor(&key_b(), 1))
            .unwrap()
    {
        world.state.protocol_records.insert(key, raw);
    }
    world
}

fn longest_hex_run(text: &str) -> usize {
    let mut best = 0;
    let mut run = 0;
    for c in text.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

fn freeze_terms() -> FreezeTerms {
    FreezeTerms {
        treasury: TRADING_TREASURY,
        generation: 1,
        address: address(&key_b(), 1),
        trade: [0x21; 32],
        contract: [0x22; 32],
        wallet_descriptor: descriptor(&key_b(), 1),
    }
}

#[test]
fn treasury_reviews_say_mut_authority_only_and_print_no_key_material() {
    let mut world = treasury_world(100);
    // TEST-only signed state model of an earlier R1. This is a review/Bitcoin-boundary
    // fixture; certified history and own-replay confirmation are exercised by e2e_treasury.
    let mut r1 = mutiny_consensus_v8::wallet_rotation_v1::Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: TRADING_TREASURY,
        current: descriptor(&key_b(), 1),
        proposed: descriptor(&key_c(), 2),
        created_height: 99,
        expiry_height: 200,
        authorization: kit::zero(),
        possession: kit::zero(),
    };
    r1.sign(&key_b(), &key_c()).unwrap();
    world
        .state
        .wallets
        .apply(&r1, world.anchor.genesis, world.anchor.fingerprint, 99)
        .unwrap();
    let view = world.view();
    let me = SignerIdentity::from_public(key_c().public(), 2, Some(TRADING_TREASURY))
        .unwrap()
        .with_treasury_roles_for_test(TreasuryRoles {
            authority: true,
            destination_of: Some(TRADING_TREASURY),
        });
    let rotation = plan(
        &OperationRequest::TreasuryRotate(
            TreasuryRotateRequest::new(Blob::new(descriptor(&key_c(), 2))).with_verified_restore(
                TRADING_TREASURY,
                trading_v1::descriptor_hash(&descriptor(&key_c(), 2)),
            ),
        ),
        &view,
        &me,
    )
    .unwrap();
    let maker = key_c();
    let offer = kit::treasury_offer_at_generation(
        &maker,
        2,
        TRADING_TREASURY,
        kit::context_of(&world.anchor),
        100,
        140,
        10_000,
        900,
        1,
        2,
    );
    let freeze = plan(
        &OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(
            kit::proposal(
                &view,
                &FreezeTerms {
                    wallet_descriptor: descriptor(&key_c(), 2),
                    ..freeze_terms()
                },
                &offer,
            ),
        ))),
        &view,
        &me,
    )
    .unwrap();
    let public_material: Vec<String> = [&key_b(), &key_c(), &key_a(), &maker]
        .iter()
        .flat_map(|key| {
            [
                hex::encode(key.public().ed448),
                hex::encode(&key.public().fndsa[..64]),
            ]
        })
        .chain([
            hex::encode(&descriptor(&key_b(), 1)[..48]),
            hex::encode(&descriptor(&key_c(), 2)[..48]),
        ])
        .collect();
    for (name, planned, statements) in [
        (
            "rotation",
            &rotation,
            &[
                "changes MUT Treasury authority and destination ONLY",
                "It does not touch Bitcoin custody",
                "I understand this changes MUT Treasury authority only and does not touch Bitcoin custody",
            ][..],
        ),
        (
            "freeze",
            &freeze,
            &[
                "authorizes the MUT destination of a Treasury offer ONLY",
                "Signs no Bitcoin transaction",
                "Bitcoin settlement not verified by this wallet",
                "I understand this changes MUT Treasury authority only and does not touch Bitcoin custody",
            ][..],
        ),
    ] {
        let reviewed = review(planned, &view).unwrap();
        let text = reviewed.render_text();
        for statement in statements {
            assert!(text.contains(statement), "{name}: {statement}");
        }
        // Hashes and addresses are 64 hex characters; a key or a descriptor would be far longer.
        assert!(
            longest_hex_run(&text) <= 64,
            "{name}: {}",
            longest_hex_run(&text)
        );
        for material in &public_material {
            assert!(
                !text.contains(material.as_str()),
                "{name} prints key material"
            );
        }
        for row in reviewed.rows() {
            assert!(longest_hex_run(&row.value) <= 64, "{name}: {}", row.label);
        }
        let debug = format!("{reviewed:?} {planned:?}");
        assert!(longest_hex_run(&debug) < 64, "{name} Debug");
        assert!(debug.len() < 2_000, "{name} Debug is bounded");
    }
    // The signed results print nothing of the signature or the key in Debug either.
    let signer = KeySigner::with_identity(
        key_c(),
        me.clone(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    let reviewed = review(&rotation, &view).unwrap();
    let signed = signer
        .authorize(rotation, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let shown = format!("{signed:?} {signer:?}");
    assert!(longest_hex_run(&shown) < 64, "{shown}");
    assert!(shown.contains("<redacted>"));
}

// ---------------------------------------------------------------------------------------------
// 5. Bitcoin network codes of a Treasury offer
// ---------------------------------------------------------------------------------------------

#[test]
fn a_treasury_offer_is_accepted_only_for_bitcoin_network_codes_one_to_three() {
    let world = treasury_world(100);
    let view = world.view();
    let me = identity(&key_b()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: Some(TRADING_TREASURY),
    });
    let maker = kit::maker_key();
    let context = kit::context_of(&world.anchor);
    for code in 0u8..=255 {
        let body = OfferBody {
            context: context.clone(),
            maker_descriptor: maker.public().descriptor(1).unwrap(),
            maker_wallet: maker.public().address_id(1).unwrap(),
            destination: maker.public().address_id(1).unwrap(),
            condition: None,
            max_fee: Strikes(100_000),
            nonce: [code; 32],
            created: 100,
            expiry: 140,
            maker_side: 1,
            terms: OfferTerms::HashLinked {
                amount: Strikes(10_000),
                bitcoin_satoshis: 900,
                bitcoin_network: code,
            },
        };
        match code {
            0..=3 => {
                let offer = SignedOffer::sign(body, &maker).unwrap();
                let consensus = kit::prepare_freeze(&view, &freeze_terms(), &offer);
                let wallet_body = kit::freeze_body(
                    &context,
                    view.anchor(),
                    view.state_root(),
                    &freeze_terms(),
                    &offer.body,
                );
                let proposal =
                    treasury::freeze_proposal(&wallet_body, &kit::offer_import(&offer)).unwrap();
                let planned = plan(
                    &OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(
                        Blob::new(proposal),
                    )),
                    &view,
                    &me,
                );
                if code == 0 {
                    assert_eq!(consensus.unwrap_err(), NativeError::Bounds, "mainnet");
                    assert_eq!(
                        planned.unwrap_err(),
                        Refusal::TreasuryOfferTerms(treasury::REASON_BITCOIN_MAINNET)
                    );
                } else {
                    assert!(consensus.is_ok(), "code {code}");
                    assert!(planned.is_ok(), "code {code}");
                }
            }
            _ => {
                // Not encodable: no maker can sign it, and no body can carry it.
                assert!(body.encode().is_err(), "code {code}");
                assert!(SignedOffer::sign(body, &maker).is_err(), "code {code}");
            }
        }
    }
    assert_eq!(treasury::TREASURY_BITCOIN_NETWORKS, [1, 2, 3]);
}

// ---------------------------------------------------------------------------------------------
// 6. The lock file
// ---------------------------------------------------------------------------------------------

#[test]
fn the_lock_file_has_no_bitcoin_crate_but_the_hash_library() {
    let lock = fs::read_to_string(root().join("Cargo.lock")).unwrap();
    let names: Vec<&str> = lock
        .lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .map(|rest| rest.trim_end_matches('"'))
        .collect();
    assert!(names.len() > 50);
    for name in &names {
        let lower = name.to_lowercase();
        if lower.contains("bitcoin") {
            assert_eq!(*name, "bitcoin_hashes", "a Bitcoin crate in the lock file");
        }
        for banned in [
            "secp256k1",
            "psbt",
            "miniscript",
            "bdk",
            "electrum",
            "bitcoincore",
            "rust-bitcoin",
        ] {
            assert!(!lower.contains(banned), "{name}");
        }
    }
}
