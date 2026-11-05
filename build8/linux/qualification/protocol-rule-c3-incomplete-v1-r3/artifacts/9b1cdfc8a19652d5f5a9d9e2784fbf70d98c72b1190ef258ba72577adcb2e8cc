//! Unit tests of the canonical maker-offer codec (P7, Lane P design 8.2, 8.3; AM-6). TEST-VALUE keys
//! only: published BIP39 test phrases (wallet owner) and fresh random Transport keys (legacy forms).
//! The settlement checks of `verify_offer` are exercised through REAL blocks in
//! `consensus/tests/maker_offer_v2.rs`.
use super::legacy::{self, LegacyForm};
use super::*;
use crate::trading_v1::Context;

fn wallet() -> HybridKey {
    HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner).unwrap()
}
fn context() -> Context {
    Context {
        network: crate::NETWORK_ID,
        genesis: [11; 32],
        fingerprint: [12; 32],
    }
}
fn body(key: &HybridKey) -> OfferBody {
    OfferBody {
        context: context(),
        maker_descriptor: key.public().descriptor(1).unwrap(),
        maker_wallet: key.public().address_id(1).unwrap(),
        maker_side: 0,
        nonce: [31; 32],
        created: 5,
        expiry: 50,
        terms: OfferTerms::HashLinked {
            amount: Strikes(50_000),
            bitcoin_satoshis: 10_000,
            bitcoin_network: 3,
        },
        destination: key.public().address_id(1).unwrap(),
        condition: Some([7; 32]),
        max_fee: Strikes(20_000),
    }
}

#[test]
fn offer_body_v2_has_the_design_layout_and_decodes_strictly() {
    let key = wallet();
    let b = body(&key);
    let raw = b.encode().unwrap();
    // array(13), NAMESPACE bytes, version 2.
    assert_eq!(raw[0], 0x8d);
    let mut d = Decoder::new(&raw);
    assert_eq!(d.array().unwrap(), Some(13));
    assert_eq!(d.bytes().unwrap(), NAMESPACE);
    assert_eq!(d.u8().unwrap(), OFFER_BODY_VERSION);
    assert_eq!(OFFER_BODY_VERSION, 2);
    assert_eq!(OfferBody::decode(&raw).unwrap(), b);
    // The maker triple sits at position 6 as [descriptor, wallet, side].
    d.u32().unwrap();
    d.bytes().unwrap();
    d.bytes().unwrap();
    assert_eq!(d.array().unwrap(), Some(3));
    assert_eq!(d.bytes().unwrap(), b.maker_descriptor.as_slice());
    assert_eq!(d.bytes().unwrap(), b.maker_wallet);
    assert_eq!(d.u8().unwrap(), 0);
    // A null condition is a CBOR null, and decodes back to None.
    let mut none = b.clone();
    none.condition = None;
    let raw_none = none.encode().unwrap();
    assert_eq!(raw_none[raw_none.len() - 4], 0xf6, "null before max_fee (u64 20000 = 0x19 4e 20)");
    assert_eq!(OfferBody::decode(&raw_none).unwrap(), none);
    // Trailing bytes and a non-shortest integer are refused.
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(OfferBody::decode(&trailing), Err(Error::Codec));
    let mut long = raw.clone();
    let n = long.len();
    // max_fee 20000 = 0x19 0x4e 0x20 -> 0x1a 0x00 0x00 0x4e 0x20 (non-shortest)
    assert_eq!(&long[n - 3..], &[0x19, 0x4e, 0x20]);
    long.truncate(n - 3);
    long.extend_from_slice(&[0x1a, 0, 0, 0x4e, 0x20]);
    assert_eq!(OfferBody::decode(&long), Err(Error::Codec));
    // The id derivation is unchanged: hash("offer", body).
    assert_eq!(b.id().unwrap(), hash(b"offer", &raw));
    assert_eq!(b.maker().unwrap(), hash(b"trade-identity", &b.maker_descriptor));
}

#[test]
fn offer_body_encode_refuses_each_invalid_field() {
    let key = wallet();
    let cases: Vec<(&str, Box<dyn Fn(&mut OfferBody)>, Error)> = vec![
        ("created after expiry", Box::new(|b| b.created = 51), Error::Bounds),
        ("maker side 2", Box::new(|b| b.maker_side = 2), Error::Bounds),
        ("zero maker wallet", Box::new(|b| b.maker_wallet = [0; 32]), Error::Bounds),
        ("zero destination", Box::new(|b| b.destination = [0; 32]), Error::Bounds),
        (
            "condition on License terms",
            Box::new(|b| {
                b.terms = OfferTerms::License {
                    license: [3; 32],
                    generation: 1,
                    price: Strikes(9),
                }
            }),
            Error::Bounds,
        ),
        (
            "zero amount",
            Box::new(|b| {
                b.terms = OfferTerms::HashLinked {
                    amount: Strikes(0),
                    bitcoin_satoshis: 1,
                    bitcoin_network: 3,
                }
            }),
            Error::Bounds,
        ),
        (
            "Transport descriptor",
            Box::new(|b| {
                b.maker_descriptor = HybridKey::generate(Role::Transport)
                    .unwrap()
                    .public()
                    .descriptor(1)
                    .unwrap()
            }),
            Error::Authority,
        ),
    ];
    for (name, change, expected) in cases {
        let mut b = body(&key);
        change(&mut b);
        assert_eq!(b.encode(), Err(expected), "{name}");
    }
    // A License offer without a condition is valid.
    let mut ok = body(&key);
    ok.condition = None;
    ok.terms = OfferTerms::License {
        license: [3; 32],
        generation: 1,
        price: Strikes(9),
    };
    OfferBody::decode(&ok.encode().unwrap()).unwrap();
}

/// Design 8.2 "version: only version-2 bodies settle; version-1 bodies fail OfferBinding".
#[test]
fn version_one_body_is_refused_with_offer_binding() {
    let key = wallet();
    let raw = body(&key).encode().unwrap();
    let mut v1 = raw.clone();
    let at = 1 + 2 + NAMESPACE.len(); // array byte, bytes header (0x58 len), NAMESPACE
    assert_eq!(v1[at], 2);
    v1[at] = 1;
    assert_eq!(OfferBody::decode(&v1), Err(Error::OfferBinding));
    let mut v3 = raw;
    v3[at] = 3;
    assert_eq!(OfferBody::decode(&v3), Err(Error::Codec));
}

#[test]
fn maker_offer_is_the_one_labelled_wire_object_signed_by_the_wallet_key() {
    let key = wallet();
    let offer = MakerOffer::sign(body(&key), &key).unwrap();
    offer.verify().unwrap();
    let raw = offer.encode().unwrap();
    let mut d = Decoder::new(&raw);
    assert_eq!(d.array().unwrap(), Some(4));
    assert_eq!(d.bytes().unwrap(), MAKER_OFFER_LABEL);
    assert_eq!(MAKER_OFFER_LABEL, b"MUTINY-BUILD8-MAKER-OFFER-V2");
    assert_eq!(decode_maker_offer(&raw).unwrap(), offer);
    // The label is a BYTE string: the same object with a text label is refused.
    let mut text = raw.clone();
    let i = raw.windows(MAKER_OFFER_LABEL.len()).position(|w| w == MAKER_OFFER_LABEL).unwrap();
    // 28 bytes: header 0x58 0x1c (byte string) -> 0x78 0x1c (text string).
    assert_eq!(&text[i - 2..i], &[0x58, MAKER_OFFER_LABEL.len() as u8]);
    text[i - 2] = 0x78;
    assert_eq!(MakerOffer::decode(&text), Err(Error::Codec));
    // Another key cannot sign for the descriptor; a changed body breaks the signature.
    let other =
        HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
    assert_eq!(MakerOffer::sign(body(&key), &other), Err(Error::Authority));
    let mut changed = offer.clone();
    changed.body.max_fee = Strikes(20_001);
    assert_eq!(changed.verify(), Err(Error::Signature));
    // Domain separation (AM-6): the same payload signed under the wallet's Transaction domain, or
    // under TradeFill, is not an offer signature.
    let payload = signature_payload(OFFER_SIGNATURE_LABEL, &offer.body.encode().unwrap());
    for domain in [Domain::Transaction, Domain::TradeFill] {
        let mut forged = offer.clone();
        forged.signature = key.sign(domain, &payload).unwrap();
        assert_eq!(forged.verify(), Err(Error::Signature), "{domain:?}");
    }
    assert_eq!(Domain::TradeOffer.bytes(), b"MUTINY-BUILD8-TRADE-OFFER-V1");
    assert_eq!(Domain::TradeFill.bytes(), b"MUTINY-BUILD8-TRADE-FILL-V1");
}

/// Design 8.3 / 14.7 `legacy_forms_verify_only_under_cfg`: both retired version-1 forms decode
/// and verify through the adapters (test builds only), and neither
/// is accepted by any version-2 decoder, so neither can settle or be re-encoded canonically.
#[test]
fn legacy_forms_verify_only_under_cfg() {
    let transport = HybridKey::generate(Role::Transport).unwrap();
    let descriptor = transport.public().descriptor(1).unwrap();
    let terms = OfferTerms::HashLinked {
        amount: Strikes(50_000),
        bitcoin_satoshis: 10_000,
        bitcoin_network: 3,
    };
    let mut e = Encoder::new(Vec::new());
    e.array(11)
        .unwrap()
        .bytes(NAMESPACE)
        .unwrap()
        .u8(1)
        .unwrap()
        .u32(crate::NETWORK_ID)
        .unwrap()
        .bytes(&[11; 32])
        .unwrap()
        .bytes(&[12; 32])
        .unwrap()
        .bytes(&descriptor)
        .unwrap()
        .bytes(&[31; 32])
        .unwrap()
        .u64(1)
        .unwrap()
        .u64(10)
        .unwrap()
        .u8(0)
        .unwrap();
    terms.encode(&mut e).unwrap();
    let v1 = e.into_writer();
    let signature = transport
        .sign(
            Domain::TransportInitiator,
            &signature_payload(OFFER_SIGNATURE_LABEL, &v1),
        )
        .unwrap();
    // Form A: the wallet container with a TEXT label.
    let mut a = Encoder::new(Vec::new());
    a.array(4)
        .unwrap()
        .str(legacy::WALLET_CONTAINER_LABEL)
        .unwrap()
        .bytes(&v1)
        .unwrap()
        .bytes(&signature.ed448)
        .unwrap()
        .bytes(&signature.fndsa)
        .unwrap();
    let form_a = a.into_writer();
    // Form B: the version-1 consensus OfferProof with an all-zero fill.
    let proof = |fill: u8| {
        let mut b = Encoder::new(Vec::new());
        b.array(5)
            .unwrap()
            .bytes(&v1)
            .unwrap()
            .bytes(&signature.ed448)
            .unwrap()
            .bytes(&signature.fndsa)
            .unwrap()
            .bytes(&[fill; 114])
            .unwrap()
            .bytes(&[fill; 1280])
            .unwrap();
        b.into_writer()
    };
    let form_b = proof(0);
    let read_a = legacy::import_and_verify(&form_a).unwrap();
    assert_eq!(read_a.form(), LegacyForm::WalletContainer);
    assert_eq!(read_a.terms(), &terms);
    assert_eq!(read_a.window(), (1, 10));
    assert_eq!(read_a.context(), &context());
    let read_b = legacy::import_and_verify(&form_b).unwrap();
    assert_eq!(read_b.form(), LegacyForm::ZeroFillProof);
    // A filled version-1 proof is not an importable offer.
    assert_eq!(legacy::decode_zero_fill_proof(&proof(1)), Err(Error::OfferBinding));
    // A tampered signature fails verification.
    let mut bad = form_a.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert_eq!(legacy::import_and_verify(&bad), Err(Error::Signature));
    // Non-canonical container (trailing byte) is refused.
    let mut trailing = form_a.clone();
    trailing.push(0);
    assert!(legacy::decode_wallet_container(&trailing).is_err());
    // No version-2 decoder accepts any legacy form: never settle-valid, never a second encoding.
    assert_eq!(OfferBody::decode(&v1), Err(Error::OfferBinding));
    assert_eq!(MakerOffer::decode(&form_a), Err(Error::Codec));
    assert_eq!(MakerOffer::decode(&form_b), Err(Error::Codec));
    assert_eq!(OfferProof::decode(&form_b), Err(Error::Codec));
    assert_eq!(OfferProof::decode(&form_a), Err(Error::Codec));
    assert!(decode_maker_offer(&form_a).is_err());
}
