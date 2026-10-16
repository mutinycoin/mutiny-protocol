//! Crate-internal unit tests of the funded wallet-rotation bundle (Lane P design section 3; WP-R):
//! the crate-private WalletBook primitives that only the bundle uses (`apply_verified_rotation`,
//! `authority_of`), the defense-in-depth sponsor rule of step 5 that the codec rule otherwise
//! shadows, the signing payload shapes and the envelope hook. The public-API, pool and REAL-BLOCK
//! tests are in `consensus/tests/funded_rotation_v2.rs`. Keys are labelled-seed TEST-VALUE wallet
//! keys (`rehearsal_keys_v1`): public by construction, never production identities.
use super::*;
use crate::wallet_authority_v1::WalletBook;
use mutiny_crypto_v2::rehearsal_keys_v1::Credential;

fn key(label: &str) -> Credential {
    Credential::from_label(label, 1).unwrap()
}
fn desc(c: &Credential, generation: u64) -> Vec<u8> {
    c.key().public().descriptor(generation).unwrap()
}
fn addr(c: &Credential, generation: u64) -> Hash {
    c.key().public().address_id(generation).unwrap()
}
fn envelope() -> Envelope {
    Envelope {
        first_height: 11,
        last_height: 20,
        reference_height: 10,
        reference_block: [0xab; 32],
        preconditions: vec![],
    }
}
fn unsigned(old: &Credential, new: &Credential, sponsor: Option<(Hash, Vec<u8>)>) -> UnsignedRotation {
    let mut inputs = vec![(OutPoint { transaction: [1; 32], index: 0 }, Payer::RotatingAuthority)];
    if sponsor.is_some() {
        inputs.push((OutPoint { transaction: [2; 32], index: 0 }, Payer::Sponsor));
    }
    UnsignedRotation {
        genesis: [7; 32],
        fingerprint: [8; 32],
        envelope: envelope(),
        authority: addr(old, 1),
        current_descriptor: desc(old, 1),
        proposed_descriptor: desc(new, 2),
        sponsor,
        fee: 20_000,
        inputs,
        outputs: vec![Output { owner: addr(new, 2), atoms: 1_000 }],
    }
}

#[test]
fn apply_verified_rotation_is_compare_and_replace_and_keeps_every_book_invariant() {
    let (a, b, c) = (key("wp-r-unit-a"), key("wp-r-unit-b"), key("wp-r-unit-c"));
    let mut book = WalletBook::default();
    let id = book.register(&desc(&a, 1)).unwrap();
    assert_eq!(id, addr(&a, 1));
    let before = book.clone();
    // Unknown authority, wrong current descriptor, generation skip: refused, book untouched.
    assert_eq!(
        book.apply_verified_rotation(addr(&c, 1), &desc(&c, 1), &desc(&b, 2)),
        Err(Error::UnknownSigner)
    );
    assert_eq!(
        book.apply_verified_rotation(id, &desc(&a, 2), &desc(&b, 3)),
        Err(Error::WrongGeneration),
        "compare-and-replace: `current` must BE the current descriptor"
    );
    assert_eq!(
        book.apply_verified_rotation(id, &desc(&a, 1), &desc(&b, 3)),
        Err(Error::WrongGeneration),
        "the generation advances by exactly one"
    );
    assert_eq!(book, before);
    // Success: the current descriptor is replaced, the new address keeps the authority.
    book.apply_verified_rotation(id, &desc(&a, 1), &desc(&b, 2)).unwrap();
    assert_eq!(book.current(id), Some(desc(&b, 2).as_slice()));
    let records = book.records().expect("validate holds after the rotation");
    assert_eq!(WalletBook::from_records(&records).unwrap(), book);
    // The old address resolves to the CURRENT descriptor only: the retired key no longer authorizes.
    assert!(book.authorize(addr(&a, 1), &desc(&b, 2)).is_ok());
    assert_eq!(book.authorize(addr(&a, 1), &desc(&a, 1)), Err(Error::WrongGeneration));
    // Replay of the same transition and a competing transition of the same generation both fail.
    let rotated = book.clone();
    assert_eq!(
        book.apply_verified_rotation(id, &desc(&a, 1), &desc(&b, 2)),
        Err(Error::WrongGeneration)
    );
    assert_eq!(
        book.apply_verified_rotation(id, &desc(&a, 1), &desc(&c, 2)),
        Err(Error::WrongGeneration)
    );
    assert_eq!(book, rotated);
    // A proposed address that already exists in another lineage is a duplicate.
    let other = book.register(&desc(&c, 1)).unwrap();
    let with_other = book.clone();
    assert_eq!(
        book.apply_verified_rotation(other, &desc(&c, 1), &desc(&b, 2)),
        Err(Error::Duplicate)
    );
    assert_eq!(book, with_other);
    // A non-WalletOwner proposed descriptor is refused by the descriptor rule.
    let node = mutiny_crypto_v2::HybridKey::generate(mutiny_crypto_v2::Role::Node).unwrap();
    assert_eq!(
        book.apply_verified_rotation(other, &desc(&c, 1), &node.public().descriptor(2).unwrap()),
        Err(Error::WrongOperation)
    );
    assert_eq!(book, with_other);
}

#[test]
fn authority_of_resolves_every_lineage_address_and_an_unregistered_address_to_itself() {
    let (a, b) = (key("wp-r-unit-a"), key("wp-r-unit-b"));
    let mut book = WalletBook::default();
    let id = book.register(&desc(&a, 1)).unwrap();
    book.apply_verified_rotation(id, &desc(&a, 1), &desc(&b, 2)).unwrap();
    assert_eq!(book.authority_of(addr(&a, 1)), id);
    assert_eq!(book.authority_of(addr(&b, 2)), id, "a later generation keeps the lineage identity");
    assert_eq!(book.authority_of([0x5a; 32]), [0x5a; 32], "unregistered: generation-one direct ownership");
}

/// Design 3.5 step 5 refuses a sponsor whose wallet authority IS the rotating authority. Through the
/// public API that case is already unrepresentable (codec rule: the sponsor descriptor differs from
/// both rotation descriptors), so this calls step 5 directly on values that bypass the codec: the
/// mutant "accept sponsor == rotating authority" in `check_sponsor` must fail here.
#[test]
fn step_five_refuses_a_sponsor_of_the_rotating_lineage_even_without_the_codec_rule() {
    let (a, b, s) = (key("wp-r-unit-a"), key("wp-r-unit-b"), key("wp-r-unit-s"));
    let mut book = WalletBook::default();
    let id = book.register(&desc(&a, 1)).unwrap();
    // The authority itself as sponsor (its own address and current descriptor).
    let own = unsigned(&a, &b, Some((id, desc(&a, 1))));
    assert_eq!(own.validate(), Err(TxError::Bounds), "the codec rule refuses it first");
    assert_eq!(own.check_sponsor(&book), Err(TxError::Owner));
    // After a rotation: an OLD address of the lineage, authorized by its current descriptor.
    let mut rotated = book.clone();
    rotated.apply_verified_rotation(id, &desc(&a, 1), &desc(&b, 2)).unwrap();
    let mut old_address = unsigned(&a, &b, Some((addr(&a, 1), desc(&b, 2))));
    old_address.authority = id;
    assert!(rotated.authorize(addr(&a, 1), &desc(&b, 2)).is_ok(), "the sponsor would be authorized");
    assert_eq!(old_address.check_sponsor(&rotated), Err(TxError::Owner));
    // A different wallet is a legitimate sponsor; an unauthorized descriptor is not.
    assert_eq!(unsigned(&a, &b, Some((addr(&s, 1), desc(&s, 1)))).check_sponsor(&book), Ok(()));
    assert_eq!(
        unsigned(&a, &b, Some((addr(&s, 1), desc(&b, 1)))).check_sponsor(&book),
        Err(TxError::Owner)
    );
}

fn shape(raw: &[u8]) -> Vec<Type> {
    let mut d = Decoder::new(raw);
    let n = d.array().unwrap().unwrap();
    let mut types = Vec::new();
    for _ in 0..n {
        types.push(d.datatype().unwrap());
        d.skip().unwrap();
    }
    assert_eq!(d.position(), raw.len());
    types
}

#[test]
fn signing_payloads_have_the_designed_labels_and_shapes() {
    let commitment = [0x5c; 32];
    let f0 = funding_payload(&commitment, Payer::RotatingAuthority);
    let f1 = funding_payload(&commitment, Payer::Sponsor);
    assert_eq!(shape(&f0), vec![Type::Bytes, Type::Bytes, Type::U8]);
    assert_ne!(f0, f1, "the payer tag is signed");
    let mut d = Decoder::new(&f1);
    d.array().unwrap();
    assert_eq!(d.bytes().unwrap(), FUNDING_LABEL);
    assert_eq!(d.bytes().unwrap(), commitment);
    assert_eq!(d.u8().unwrap(), 1);
    for (payload, label) in [
        (authorize_payload(&commitment), AUTHORIZE_LABEL),
        (possession_payload(&commitment), POSSESSION_LABEL),
    ] {
        assert_eq!(shape(&payload), vec![Type::Bytes, Type::Bytes]);
        let mut d = Decoder::new(&payload);
        d.array().unwrap();
        assert_eq!(d.bytes().unwrap(), label);
        assert_eq!(d.bytes().unwrap(), commitment);
    }
    for (label, text) in [
        (COMMITMENT_DOMAIN, "MUTINY-BUILD8-FUNDED-ROTATION-COMMITMENT-V2"),
        (ID_DOMAIN, "MUTINY-BUILD8-FUNDED-ROTATION-ID-V2"),
        (AUTHORIZE_LABEL, "MUTINY-BUILD8-FUNDED-ROTATION-AUTHORIZE-V2"),
        (POSSESSION_LABEL, "MUTINY-BUILD8-FUNDED-ROTATION-POSSESSION-V2"),
        (FUNDING_LABEL, "MUTINY-BUILD8-FUNDED-ROTATION-FUNDING-V2"),
    ] {
        assert_eq!(label, text.as_bytes());
    }
}

#[test]
fn envelope_hook_reads_only_a_tag_25_transaction() {
    let (a, b) = (key("wp-r-unit-a"), key("wp-r-unit-b"));
    let zero = HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
    let tx = FundedRotation {
        unsigned: unsigned(&a, &b, None),
        authorize: zero.clone(),
        possession: zero.clone(),
        authority_funding: Some(zero),
        sponsor_funding: None,
    };
    let raw = tx.encode().unwrap();
    assert_eq!(envelope_of(&raw), Some(envelope()));
    assert_eq!(crate::op_envelope_v1::transaction_envelope(&raw), Some(envelope()));
    let partial = PartialRotation::new(tx.unsigned.clone()).encode().unwrap();
    assert_eq!(envelope_of(&partial), None, "a partial object is not a transaction");
    let mut other_tag = raw.clone();
    other_tag[2] = 21;
    assert_eq!(envelope_of(&other_tag), None);
    assert_eq!(envelope_of(&[]), None);
}
