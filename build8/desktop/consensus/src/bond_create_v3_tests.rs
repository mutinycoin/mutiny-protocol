//! Unit tests of the funded BondCreate codec, identities, payloads, signatures and partial object
//! (Lane P design 2.2, 1.b; AM-9 m6). State and real-block rules are tested through real blocks in
//! `consensus/tests/funded_bond_create_v1.rs`. TEST-VALUE: public BIP39 fixture keys only.
use super::*;
use crate::op_envelope_v1::Precondition;
use mutiny_crypto_v2::{HybridKey, Role};

fn owner() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap()
}
fn stranger() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner).unwrap()
}
fn envelope() -> Envelope {
    Envelope {
        first_height: 8,
        last_height: 20,
        reference_height: 7,
        reference_block: [0x77; 32],
        preconditions: vec![],
    }
}
fn point(seed: u8, index: u32) -> OutPoint {
    OutPoint {
        transaction: [seed; 32],
        index,
    }
}
fn unsigned(key: &HybridKey) -> UnsignedBondCreate {
    let address = key.public().address_id(1).unwrap();
    UnsignedBondCreate {
        genesis: [1; 32],
        fingerprint: [2; 32],
        envelope: envelope(),
        owner: address,
        owner_descriptor: key.public().descriptor(1).unwrap(),
        node: [3; 32],
        node_generation: 1,
        nonce: [4; 32],
        principal: MINIMUM_ATOMS,
        fee: 20_000,
        inputs: vec![point(5, 0), point(5, 1), point(6, 0)],
        change: Some(Output {
            owner: address,
            atoms: 7,
        }),
    }
}
/// Writes the unsigned layout WITHOUT any validation, so tests can craft refused bytes.
fn raw_unsigned(u: &UnsignedBondCreate, network: u32, version: u8, kind: u8) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(13)
        .unwrap()
        .u8(version)
        .unwrap()
        .u8(kind)
        .unwrap()
        .u32(network)
        .unwrap()
        .bytes(&u.genesis)
        .unwrap()
        .bytes(&u.fingerprint)
        .unwrap();
    e.array(5)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(u.envelope.first_height)
        .unwrap()
        .u64(u.envelope.last_height)
        .unwrap();
    e.array(2)
        .unwrap()
        .u64(u.envelope.reference_height)
        .unwrap()
        .bytes(&u.envelope.reference_block)
        .unwrap();
    e.array(0).unwrap();
    e.bytes(&u.owner).unwrap().bytes(&u.owner_descriptor).unwrap();
    e.array(3)
        .unwrap()
        .bytes(&u.node)
        .unwrap()
        .u64(u.node_generation)
        .unwrap()
        .bytes(&u.nonce)
        .unwrap();
    e.u64(u.principal)
        .unwrap()
        .u64(u.fee)
        .unwrap()
        .array(u.inputs.len() as u64)
        .unwrap();
    for p in &u.inputs {
        e.array(2).unwrap().bytes(&p.transaction).unwrap().u32(p.index).unwrap();
    }
    match &u.change {
        Some(c) => {
            e.array(2).unwrap().bytes(&c.owner).unwrap().u64(c.atoms).unwrap();
        }
        None => {
            e.null().unwrap();
        }
    }
    e.into_writer()
}
fn wrap(unsigned: &[u8], create: Option<&HybridSignature>, funding: Option<&HybridSignature>) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(5).unwrap().u8(2).unwrap().u8(24).unwrap().bytes(unsigned).unwrap();
    put_signature(&mut e, &create.cloned());
    put_signature(&mut e, &funding.cloned());
    e.into_writer()
}

#[test]
fn canonical_layout_round_trips_and_names_kind_24() {
    let key = owner();
    let u = unsigned(&key);
    let raw = u.encode().unwrap();
    assert_eq!(raw, raw_unsigned(&u, NETWORK_ID, 2, 24), "exact design 2.2 field order");
    assert_eq!(UnsignedBondCreate::decode(&raw).unwrap(), u);
    let signed = FundedBondCreate::sign(u.clone(), &key).unwrap();
    let op = signed.encode().unwrap();
    assert_eq!(op.len(), u.signed_len().unwrap(), "signed_len is known before signing");
    assert_eq!(FundedBondCreate::decode(&op).unwrap(), signed);
    assert_eq!(crate::blocks::operation_kind(&op), Ok(OPERATION_KIND));
    assert_eq!(envelope_of(&op), Some(u.envelope.clone()));
    assert_eq!(crate::op_envelope_v1::operation_envelope(&op), Some(u.envelope.clone()));
    signed.verify_signatures().unwrap();
    // The outer operation and the nested body are both canonical-checked.
    crate::blocks::canonical(&op, MAX_OPERATION_BYTES).unwrap();
    crate::blocks::canonical(&raw, MAX_OPERATION_BYTES).unwrap();
    // Diagnostics preserve context/counts without serializing descriptors or signature arrays.
    for shown in [format!("{u:?}"), format!("{signed:?}")] {
        assert!(shown.contains("owner_descriptor_bytes:"));
        assert!(shown.contains("inputs: 3"));
        assert!(shown.contains("node_generation: 1"));
        assert!(!shown.contains(&format!("{:?}", u.owner_descriptor)));
        assert!(!shown.contains(&format!("{:?}", signed.create.ed448)));
        assert!(!shown.contains(&format!("{:?}", signed.funding.fndsa)));
        assert!(!shown.contains(&format!("{:?}", u.node)));
        assert!(shown.len() < 1200, "native diagnostics must stay compact");
    }
    let shown = format!("{signed:?}");
    assert!(shown.contains("create_present: true"));
    assert!(shown.contains("funding_present: true"));
    assert_eq!(u.encode().unwrap(), raw, "Debug leaves canonical body unchanged");
    assert_eq!(signed.encode().unwrap(), op, "Debug leaves canonical operation unchanged");
}

#[test]
fn below_minimum_and_zero_change_unrepresentable() {
    let key = owner();
    let base = unsigned(&key);
    let cases: Vec<(Box<dyn Fn(&mut UnsignedBondCreate)>, BondError)> = vec![
        (Box::new(|u| u.principal = MINIMUM_ATOMS - 1), BondError::Bounds),
        (
            Box::new(|u| u.change.as_mut().unwrap().owner = [0; 32]),
            BondError::ZeroDestination,
        ),
        (Box::new(|u| u.change.as_mut().unwrap().atoms = 0), BondError::Bounds),
        (Box::new(|u| u.inputs.clear()), BondError::Bounds),
        (Box::new(|u| u.inputs.reverse()), BondError::Bounds),
        (Box::new(|u| u.inputs[1] = u.inputs[0].clone()), BondError::Bounds),
        (
            Box::new(|u| u.inputs = (0..=MAX_INPUTS as u32).map(|i| point(9, i)).collect()),
            BondError::Bounds,
        ),
        (Box::new(|u| u.node = [0; 32]), BondError::Bounds),
        (Box::new(|u| u.owner = [0; 32]), BondError::Bounds),
        (Box::new(|u| u.genesis = [0; 32]), BondError::Bounds),
        (Box::new(|u| u.fingerprint = [0; 32]), BondError::Bounds),
        (Box::new(|u| u.node_generation = 0), BondError::Bounds),
        (
            Box::new(|u| u.owner_descriptor = HybridKey::generate(Role::Node).unwrap().public().descriptor(1).unwrap()),
            BondError::Descriptor,
        ),
        (Box::new(|u| u.owner_descriptor = vec![0x80]), BondError::Descriptor),
        (
            Box::new(|u| u.envelope.reference_height = u.envelope.first_height),
            BondError::Envelope(EnvelopeError::WindowOrder),
        ),
    ];
    for (n, (edit, expected)) in cases.iter().enumerate() {
        let mut u = base.clone();
        edit(&mut u);
        // Unrepresentable: it can be neither encoded (so never signed) nor decoded.
        assert_eq!(u.encode(), Err(*expected), "case {n} encode");
        assert_eq!(u.commitment(), Err(*expected), "case {n} commitment");
        assert_eq!(u.signing_intents(), Err(*expected), "case {n} intents");
        let crafted = raw_unsigned(&u, NETWORK_ID, 2, 24);
        assert_eq!(UnsignedBondCreate::decode(&crafted), Err(*expected), "case {n} decode");
        assert_eq!(FundedBondCreate::decode(&wrap(&crafted, None, None)), Err(*expected), "case {n} op");
    }
    // Legitimate zero fields stay legal: a zero nonce, no change at all (null), a zero fee value
    // in the codec (the fee rule is V9, not V1).
    let mut legit = base.clone();
    legit.nonce = [0; 32];
    legit.change = None;
    legit.fee = 0;
    assert_eq!(UnsignedBondCreate::decode(&legit.encode().unwrap()).unwrap(), legit);
    // Exactly 128 inputs is the bound itself.
    let mut max = base.clone();
    max.inputs = (0..MAX_INPUTS as u32).map(|i| point(9, i)).collect();
    let signed = FundedBondCreate::sign(max, &owner()).unwrap();
    let op = signed.encode().unwrap();
    assert!(op.len() < MAX_OPERATION_BYTES, "128 inputs fit the 16 KiB item bound: {}", op.len());
}

#[test]
fn structure_and_canonical_form_are_enforced() {
    let key = owner();
    let u = unsigned(&key);
    let raw = u.encode().unwrap();
    // Wrong network, version, kind.
    for (network, version, kind) in [(NETWORK_ID + 1, 2, 24), (NETWORK_ID, 1, 24), (NETWORK_ID, 3, 24), (NETWORK_ID, 2, 18)] {
        assert_eq!(
            UnsignedBondCreate::decode(&raw_unsigned(&u, network, version, kind)),
            Err(BondError::Codec)
        );
    }
    // Trailing byte, indefinite outer array, non-minimal integer (principal 0x1b + 8 bytes is
    // minimal for 10^10; re-encode the version 2 as 0x18 0x02).
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(UnsignedBondCreate::decode(&trailing), Err(BondError::NonCanonical));
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&raw[1..]);
    indefinite.push(0xff);
    assert!(matches!(
        UnsignedBondCreate::decode(&indefinite),
        Err(BondError::NonCanonical | BondError::Codec)
    ));
    assert_eq!(raw[1], 0x02);
    let mut non_minimal = vec![raw[0], 0x18, 0x02];
    non_minimal.extend_from_slice(&raw[2..]);
    assert_eq!(UnsignedBondCreate::decode(&non_minimal), Err(BondError::NonCanonical));
    for n in 0..raw.len() {
        assert!(UnsignedBondCreate::decode(&raw[..n]).is_err(), "prefix {n}");
    }
    // The complete operation: both slots present, each exactly [bytes(114), bytes(1280)].
    let signed = FundedBondCreate::sign(u.clone(), &key).unwrap();
    let op = signed.encode().unwrap();
    assert_eq!(
        FundedBondCreate::decode(&wrap(&raw, Some(&signed.create), None)),
        Err(BondError::MissingSignature(Slot::Funding))
    );
    assert_eq!(
        FundedBondCreate::decode(&wrap(&raw, None, Some(&signed.funding))),
        Err(BondError::MissingSignature(Slot::Create))
    );
    let mut short = Encoder::new(Vec::new());
    short.array(5).unwrap().u8(2).unwrap().u8(24).unwrap().bytes(&raw).unwrap();
    short.array(2).unwrap().bytes(&[0; 113]).unwrap().bytes(&[0; 1280]).unwrap();
    put_signature(&mut short, &Some(signed.funding.clone()));
    assert_eq!(FundedBondCreate::decode(&short.into_writer()), Err(BondError::Codec));
    let mut op_trailing = op.clone();
    op_trailing.push(0);
    assert_eq!(FundedBondCreate::decode(&op_trailing), Err(BondError::NonCanonical));
    for n in [0, 1, 4, op.len() / 2, op.len() - 1] {
        assert!(FundedBondCreate::decode(&op[..n]).is_err());
    }
    // A nested body that is not canonical is refused even though the outer walker cannot see it.
    assert_eq!(
        FundedBondCreate::decode(&wrap(&non_minimal, Some(&signed.create), Some(&signed.funding))),
        Err(BondError::NonCanonical)
    );
    // Over the 16 KiB item bound.
    let mut huge = u.clone();
    huge.owner_descriptor = vec![0; MAX_DESCRIPTOR_BYTES + 1];
    assert_eq!(huge.encode(), Err(BondError::Descriptor));
    assert_eq!(
        FundedBondCreate::decode(&vec![0x80; MAX_OPERATION_BYTES + 1]),
        Err(BondError::Oversize)
    );
}

#[test]
fn commitment_identity_and_lot_identity_are_functions_of_the_unsigned_bytes() {
    let key = owner();
    let u = unsigned(&key);
    let signed = FundedBondCreate::sign(u.clone(), &key).unwrap();
    let (commitment, id) = (u.commitment().unwrap(), u.id().unwrap());
    assert_eq!(commitment, domain_hash(COMMITMENT_DOMAIN, &u.encode().unwrap()));
    assert_eq!(id, domain_hash(ID_DOMAIN, &u.encode().unwrap()));
    assert_ne!(commitment, id, "distinct domains for what is signed and what names outputs");
    // Signatures are not inputs of either: a second signing gives other bytes, the same ids.
    let again = FundedBondCreate::sign(u.clone(), &key).unwrap();
    assert_eq!(again.id().unwrap(), id);
    assert_eq!(again.unsigned.commitment().unwrap(), commitment);
    // The lot id is UNCHANGED: [2, NetworkID, genesis, node, owner, nonce] under BOND-ID-V2, and
    // ignores funding, window and fee.
    let mut e = Encoder::new(Vec::new());
    e.array(6).unwrap().u8(2).unwrap().u32(NETWORK_ID).unwrap();
    e.bytes(&u.genesis).unwrap().bytes(&u.node).unwrap().bytes(&u.owner).unwrap().bytes(&u.nonce).unwrap();
    assert_eq!(signed.lot_id(), domain_hash(b"MUTINY-BUILD8-BOND-ID-V2", &e.into_writer()));
    let mut other = u.clone();
    other.inputs = vec![point(8, 0)];
    other.fee += 1;
    other.envelope.last_height += 1;
    other.change = None;
    assert_eq!(other.lot_id(), u.lot_id());
    assert_ne!(other.commitment().unwrap(), commitment);
    assert_ne!(other.id().unwrap(), id);
}

#[test]
fn signing_intents_are_the_two_labelled_payloads_under_their_role_domains() {
    let key = owner();
    let u = unsigned(&key);
    let c = u.commitment().unwrap();
    let intents = u.signing_intents().unwrap();
    assert_eq!(intents.len(), 2);
    assert_eq!((intents[0].slot, intents[0].domain), (Slot::Create, Domain::BondCreate));
    assert_eq!((intents[1].slot, intents[1].domain), (Slot::Funding, Domain::Transaction));
    let mut e = Encoder::new(Vec::new());
    e.array(2).unwrap().bytes(b"MUTINY-BUILD8-FUNDED-BOND-CREATE-AUTHORIZE-V1").unwrap().bytes(&c).unwrap();
    assert_eq!(intents[0].payload, e.into_writer());
    let mut e = Encoder::new(Vec::new());
    e.array(3).unwrap().bytes(b"MUTINY-BUILD8-FUNDED-BOND-CREATE-FUNDING-V1").unwrap().bytes(&c).unwrap().u8(0).unwrap();
    assert_eq!(intents[1].payload, e.into_writer());
    // Shapes: the funding payload is array(3) whose third item is an unsigned integer (the
    // dividend-claim payload is array(3) of byte strings, the transfer input array(2)); the role
    // payload is array(2) of two byte strings (the retired kind-18 body was array(10)).
    let mut d = Decoder::new(&intents[1].payload);
    assert_eq!(d.array().unwrap(), Some(3));
    d.bytes().unwrap();
    d.bytes().unwrap();
    assert_eq!(d.datatype().unwrap(), Type::U8);
    let mut d = Decoder::new(&intents[0].payload);
    assert_eq!(d.array().unwrap(), Some(2));
    // The owner signs exactly these intents.
    let signed = FundedBondCreate::sign(u.clone(), &key).unwrap();
    let public = key.public();
    public.verify(intents[0].domain, &intents[0].payload, &signed.create).unwrap();
    public.verify(intents[1].domain, &intents[1].payload, &signed.funding).unwrap();
}

#[test]
fn every_reviewed_field_is_bound_by_both_signatures() {
    let key = owner();
    let u = unsigned(&key);
    let signed = FundedBondCreate::sign(u.clone(), &key).unwrap();
    let mutants: Vec<Box<dyn Fn(&mut UnsignedBondCreate)>> = vec![
        Box::new(|u| u.genesis[0] ^= 1),
        Box::new(|u| u.fingerprint[0] ^= 1),
        Box::new(|u| u.envelope.first_height += 1),
        Box::new(|u| u.envelope.last_height += 1),
        Box::new(|u| u.envelope.reference_block[0] ^= 1),
        Box::new(|u| u.envelope.reference_height -= 1),
        Box::new(|u| {
            u.envelope.preconditions = vec![Precondition::TreasuryHead { treasury: [8; 32], generation: 1, address: [8; 32] }]
        }),
        Box::new(|u| u.owner[0] ^= 1),
        Box::new(|u| u.node[0] ^= 1),
        Box::new(|u| u.node_generation += 1),
        Box::new(|u| u.nonce[0] ^= 1),
        Box::new(|u| u.principal += 1),
        Box::new(|u| u.fee += 1),
        Box::new(|u| u.inputs[2].index += 9),
        Box::new(|u| {
            u.inputs.pop();
        }),
        Box::new(|u| u.inputs.push(point(200, 0))),
        Box::new(|u| u.change.as_mut().unwrap().atoms += 1),
        Box::new(|u| u.change.as_mut().unwrap().owner[0] ^= 1),
        Box::new(|u| u.change = None),
    ];
    for (n, mutate) in mutants.iter().enumerate() {
        let mut bad = signed.clone();
        mutate(&mut bad.unsigned);
        assert_ne!(bad.unsigned.commitment().unwrap(), signed.unsigned.commitment().unwrap(), "{n}");
        assert_eq!(bad.verify_signatures(), Err(BondError::Signature(Slot::Create)), "mutant {n}");
        let mut funding_only = bad.clone();
        funding_only.create = FundedBondCreate::sign(bad.unsigned.clone(), &key).unwrap().create;
        assert_eq!(funding_only.verify_signatures(), Err(BondError::Signature(Slot::Funding)), "mutant {n}");
    }
    // A changed owner descriptor (another key's descriptor) invalidates both as well.
    let mut other_key = signed.clone();
    other_key.unsigned.owner_descriptor = stranger().public().descriptor(1).unwrap();
    assert_eq!(other_key.verify_signatures(), Err(BondError::Signature(Slot::Create)));
}

#[test]
fn signatures_cannot_be_swapped_lifted_or_made_by_another_key() {
    let key = owner();
    let u = unsigned(&key);
    let signed = FundedBondCreate::sign(u.clone(), &key).unwrap();
    signed.verify_signatures().unwrap();
    let mut swapped = signed.clone();
    std::mem::swap(&mut swapped.create, &mut swapped.funding);
    assert_eq!(swapped.verify_signatures(), Err(BondError::Signature(Slot::Create)));
    let mut zero_funding = signed.clone();
    zero_funding.funding = HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
    assert_eq!(zero_funding.verify_signatures(), Err(BondError::Signature(Slot::Funding)));
    // A funding signature of ANOTHER composite (other inputs) cannot be lifted onto this one.
    let mut other = u.clone();
    other.inputs = vec![point(77, 0)];
    let lifted_from = FundedBondCreate::sign(other, &key).unwrap();
    let mut lifted = signed.clone();
    lifted.funding = lifted_from.funding.clone();
    assert_eq!(lifted.verify_signatures(), Err(BondError::Signature(Slot::Funding)));
    // A third party cannot sign for the owner's descriptor.
    let mut forged = PartialBondCreate::new(u.clone());
    assert_eq!(forged.sign(Slot::Create, &stranger()), Err(BondError::Signature(Slot::Create)));
    let stranger_sig = stranger()
        .sign(Domain::BondCreate, &authorize_payload(&u.commitment().unwrap()))
        .unwrap();
    assert_eq!(forged.attach(Slot::Create, stranger_sig), Err(BondError::Signature(Slot::Create)));
    // A create signature over the retired kind-18-style body bytes is not a create signature.
    let retired = key.sign(Domain::BondCreate, &u.encode().unwrap()).unwrap();
    let mut retired_op = signed.clone();
    retired_op.create = retired;
    assert_eq!(retired_op.verify_signatures(), Err(BondError::Signature(Slot::Create)));
}

#[test]
fn partial_object_exchanges_any_subset_of_signatures() {
    let key = owner();
    let u = unsigned(&key);
    let empty = PartialBondCreate::new(u.clone());
    let raw = empty.encode().unwrap();
    let shown = format!("{empty:?}");
    assert!(shown.contains("create_present: false"));
    assert!(shown.contains("funding_present: false"));
    assert_eq!(empty.encode().unwrap(), raw, "Debug leaves absent proof slots unchanged");
    assert_eq!(PartialBondCreate::decode(&raw).unwrap(), empty);
    assert_eq!(raw, wrap(&u.encode().unwrap(), None, None));
    empty.verify_provided_signatures().unwrap();
    assert_eq!(empty.clone().complete(), Err(BondError::MissingSignature(Slot::Create)));
    assert_eq!(FundedBondCreate::decode(&raw), Err(BondError::MissingSignature(Slot::Create)));
    // Funding first, by file exchange: the partial keeps a canonical encoding at every step.
    let mut partial = empty.clone();
    partial.sign(Slot::Funding, &key).unwrap();
    let raw = partial.encode().unwrap();
    let shown = format!("{partial:?}");
    assert!(shown.contains("create_present: false"));
    assert!(shown.contains("funding_present: true"));
    assert!(!shown.contains(&format!("{:?}", partial.funding.as_ref().unwrap().ed448)));
    assert_eq!(partial.encode().unwrap(), raw, "Debug leaves partial proof slots unchanged");
    assert_eq!(PartialBondCreate::decode(&raw).unwrap(), partial);
    partial.verify_provided_signatures().unwrap();
    assert_eq!(partial.clone().complete(), Err(BondError::MissingSignature(Slot::Create)));
    let signature = FundedBondCreate::sign(u.clone(), &key).unwrap().create;
    let mut tampered = signature.clone();
    tampered.ed448[3] ^= 1;
    assert_eq!(partial.attach(Slot::Create, tampered), Err(BondError::Signature(Slot::Create)));
    partial.attach(Slot::Create, signature).unwrap();
    let complete = partial.clone().complete().unwrap();
    assert_eq!(complete.encode().unwrap(), partial.encode().unwrap(), "complete partial = operation");
    complete.verify_signatures().unwrap();
    // A provided but invalid signature is reported even in a partial object.
    let mut bad = empty.clone();
    bad.funding = Some(HybridSignature { ed448: [1; 114], fndsa: [1; 1280] });
    assert_eq!(bad.verify_provided_signatures(), Err(BondError::Signature(Slot::Funding)));
}

#[test]
fn declared_fees_sum_only_kind_24_items_with_checked_arithmetic() {
    let key = owner();
    let mut a = unsigned(&key);
    a.fee = 30_000;
    let mut b = unsigned(&key);
    b.nonce = [9; 32];
    b.fee = 12_345;
    let a = FundedBondCreate::sign(a, &key).unwrap().encode().unwrap();
    let b = FundedBondCreate::sign(b, &key).unwrap().encode().unwrap();
    let other = crate::op_envelope_v1::carrier::encode(&envelope());
    assert_eq!(declared_fees(&[a.clone(), other.clone(), b.clone()]), Ok(42_345));
    assert_eq!(declared_fees(&[]), Ok(0));
    let mut big = unsigned(&key);
    big.fee = u64::MAX;
    let big = FundedBondCreate::sign(big, &key).unwrap().encode().unwrap();
    assert_eq!(declared_fees(&[a, big]), Err(BondError::Overflow));
    // A kind-24 item that does not decode (here: no signatures) is reported, not skipped.
    let unsigned_only = PartialBondCreate::new(unsigned(&key)).encode().unwrap();
    assert_eq!(crate::blocks::operation_kind(&unsigned_only), Ok(OPERATION_KIND));
    assert_eq!(declared_fees(&[b, unsigned_only]), Err(BondError::MissingSignature(Slot::Create)));
    assert_eq!(envelope_of(&other), None);
}

#[test]
fn envelope_extraction_reads_only_valid_kind_24_and_command_v3_items() {
    let key = owner();
    let u = unsigned(&key);
    let signed = FundedBondCreate::sign(u.clone(), &key).unwrap().encode().unwrap();
    assert_eq!(envelope_of(&signed), Some(u.envelope.clone()));
    let partial = PartialBondCreate::new(u.clone()).encode().unwrap();
    assert_eq!(envelope_of(&partial), Some(u.envelope.clone()), "the envelope only, as design 1.a.3");
    let mut truncated = signed.clone();
    truncated.truncate(40);
    assert_eq!(envelope_of(&truncated), None);
    assert_eq!(envelope_of(&[0x80]), None);
    assert_eq!(crate::bond_ops_v2::envelope_of(&signed), None);
    let body = crate::blocks::BlockBody {
        height: 9,
        reward_owner: [1; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![signed],
    };
    assert_eq!(
        crate::op_envelope_v1::referenced_heights(&body),
        std::collections::BTreeSet::from([7])
    );
}
