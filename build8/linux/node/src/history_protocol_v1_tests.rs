use super::*;

fn a(height: u64) -> FinalizedAnchor {
    FinalizedAnchor { network: 1, genesis: [1;32], fingerprint: [2;32], height, block: [3;32] }
}
fn request() -> HistoryRequest {
    HistoryRequest { sequence: 1, saved_anchor: a(0), max_blocks: 64,
        max_candidate_bytes: MAX_CANDIDATE_BYTES, max_candidate_entries: 6 }
}
fn entry(kind: ObjectKind, height: u64, id: u8) -> HistoryEntry {
    HistoryEntry { kind, height, object_id: [id;32], encoded_length: 1 }
}
fn page(status: HistoryStatus) -> HistoryPage {
    let r = request();
    HistoryPage { request_object_id: r.object_id().unwrap(), status, from_anchor: a(0),
        offered_through_anchor: Some(a(1)), observed_tip_anchor: Some(a(1)),
        entries: vec![entry(ObjectKind::CertifiedBlock, 1, 4)] }
}
fn anchor_golden() -> Vec<u8> {
    // Literal independent anchor vector: [1,1,h01,h02,0,h03].
    hex::decode(concat!("8601015820",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "58200202020202020202020202020202020202020202020202020202020202020202",
        "0058200303030303030303030303030303030303030303030303030303030303030303")).unwrap()
}

#[test]
fn request_exact_canonical_vector_and_existing_object_identity() {
    let r = request();
    let mut expected = hex::decode("860101586a").unwrap();
    expected.extend(anchor_golden());
    expected.extend(hex::decode("18401a0040000006").unwrap());
    assert_eq!(r.encode().unwrap(), expected);
    assert_eq!(HistoryRequest::decode(&expected).unwrap(), r);
    assert_eq!(r.object_id().unwrap(), object_id(ObjectKind::HistoryRequestV1,&expected).unwrap());
    assert_ne!(r.object_id().unwrap(), object_id(ObjectKind::CertifiedBlock,&expected).unwrap());
}

#[test]
fn busy_exact_canonical_vector_has_no_authoritative_tip_or_entries() {
    let value = HistoryPage { request_object_id: [9;32], status: HistoryStatus::Busy,
        from_anchor: a(0), offered_through_anchor: None, observed_tip_anchor: None, entries: vec![] };
    let mut expected = hex::decode(concat!("87015820",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "02586a")).unwrap();
    expected.extend(anchor_golden());
    expected.extend(hex::decode("f6f680").unwrap());
    assert_eq!(value.encode().unwrap(), expected);
    assert_eq!(HistoryPage::decode(&expected).unwrap(),value);
    assert_eq!(value.object_id().unwrap(),object_id(ObjectKind::HistoryPageV1,&expected).unwrap());
}

#[test]
fn request_maxima_minima_and_canonical_refusals() {
    let mut r = request();
    r.sequence = u32::MAX;
    r.saved_anchor.network = u32::MAX;
    r.saved_anchor.height = u64::MAX;
    let raw = r.encode().unwrap();
    assert!(raw.len() <= MAX_REQUEST_BYTES);
    assert_eq!(HistoryRequest::decode(&raw).unwrap(),r);
    for bad in 0..7 {
        let mut r = request();
        match bad { 0=>r.sequence=0, 1=>r.max_blocks=0, 2=>r.max_blocks=65,
            3=>r.max_candidate_bytes=0, 4=>r.max_candidate_bytes=MAX_CANDIDATE_BYTES+1,
            5=>r.max_candidate_entries=0, _=>r.max_candidate_entries=7 }
        assert_eq!(r.encode(),Err(HistoryError::Bounds));
    }
    let good = request().encode().unwrap();
    let mut bad = good.clone(); bad.push(0);
    assert_eq!(HistoryRequest::decode(&bad),Err(HistoryError::NonCanonical));
    let mut bad = good.clone(); bad[1]=2;
    assert_eq!(HistoryRequest::decode(&bad),Err(HistoryError::Version));
    let mut bad = good.clone(); bad.splice(2..3,[0x18,1]);
    assert_eq!(HistoryRequest::decode(&bad),Err(HistoryError::NonCanonical));
    for bad in [vec![0x9f], vec![0x85], vec![0xa6], vec![0x86,0x01,0x00],
        vec![0x86,0x01,0x01,0x5b,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff],
        vec![0;MAX_REQUEST_BYTES+1]] {
        assert!(HistoryRequest::decode(&bad).is_err());
    }
    // Noncanonical nested anchor must fail even when its enclosing bytes are canonical.
    let mut bad = good; bad[4]+=1; bad.splice(6..7,[0x18,1]);
    assert!(HistoryRequest::decode(&bad).is_err());
}

#[test]
fn all_statuses_roundtrip_and_obey_distinct_anchor_shapes() {
    for status in [HistoryStatus::More,HistoryStatus::AtSnapshotTip,HistoryStatus::Busy,
        HistoryStatus::CheckpointRejected,HistoryStatus::EvidenceUnavailable,
        HistoryStatus::NodeUnavailable,HistoryStatus::BoundsRejected,HistoryStatus::Page] {
        let mut p = page(status);
        match status {
            HistoryStatus::More => p.observed_tip_anchor=Some(a(2)),
            HistoryStatus::AtSnapshotTip => {
                p.entries.clear(); p.offered_through_anchor=Some(a(0)); p.observed_tip_anchor=Some(a(0));
            }
            HistoryStatus::Page => {},
            _ => { p.entries.clear();p.offered_through_anchor=None;p.observed_tip_anchor=None; }
        }
        assert_eq!(p.validate_for(&request()),Ok(()));
        assert_eq!(HistoryPage::decode(&p.encode().unwrap()).unwrap(),p);
        if !status.is_success() {
            p.observed_tip_anchor=Some(a(0)); assert!(p.encode().is_err());
        }
    }
    let mut p=page(HistoryStatus::AtSnapshotTip); assert!(p.encode().is_err());
    p.entries.clear(); assert!(p.encode().is_err());
    p.offered_through_anchor=Some(a(0));p.observed_tip_anchor=Some(a(0));
    assert!(p.encode().is_ok());
}

#[test]
fn ordered_whole_groups_only_and_arithmetic_never_wraps() {
    let mut p=page(HistoryStatus::Page);
    p.entries=vec![entry(ObjectKind::RecoveryEvidence,0,4),entry(ObjectKind::CertifiedBlock,1,5),
        entry(ObjectKind::RecoveryEvidence,1,6),entry(ObjectKind::CertifiedBlock,2,7),
        entry(ObjectKind::RecoveryEvidence,2,8),entry(ObjectKind::CertifiedBlock,3,9)];
    p.offered_through_anchor=Some(a(3));p.observed_tip_anchor=Some(a(3));
    assert_eq!(p.validate_for(&request()),Ok(()));
    assert_eq!(HistoryPage::decode(&p.encode().unwrap()).unwrap(),p);
    for bad in 0..8 {
        let mut q=p.clone();
        match bad {
            0=>{q.entries.pop();}, // Orphan recovery.
            1=>q.entries[1].height=2, // Gap.
            2=>q.entries[2].height=0, // Wrong recovery parent.
            3=>q.entries[1].kind=ObjectKind::RecoveryEvidence, // Repeated recovery.
            4=>q.entries[3].object_id=q.entries[1].object_id,
            5=>q.entries[0].kind=ObjectKind::SignedTransaction,
            6=>q.offered_through_anchor.as_mut().unwrap().height=4,
            _=>q.entries.push(entry(ObjectKind::CertifiedBlock,4,10)),
        }
        assert!(q.validate().is_err(),"case {bad}");
    }
    let mut q=page(HistoryStatus::Page);q.from_anchor=a(u64::MAX);
    q.offered_through_anchor=Some(a(0));q.observed_tip_anchor=Some(a(0));
    assert!(q.validate().is_err());
}

#[test]
fn correlation_context_and_receiver_caps_are_mandatory() {
    let p=page(HistoryStatus::Page);
    for bad in 0..8 {
        let mut q=p.clone(); let mut r=request();
        match bad {
            0=>q.request_object_id=[10;32],
            1=>q.from_anchor.block=[10;32],
            2=>q.offered_through_anchor.as_mut().unwrap().genesis=[10;32],
            3=>q.observed_tip_anchor.as_mut().unwrap().fingerprint=[10;32],
            4=>q.offered_through_anchor.as_mut().unwrap().network=2,
            5=>{r.max_candidate_bytes=1;q.entries[0].encoded_length=2;q.request_object_id=r.object_id().unwrap();},
            6=>{q.entries[0].object_id=[0;32];},
            _=>{q.entries[0].encoded_length=0;},
        }
        assert!(q.validate_for(&r).is_err(),"case {bad}");
    }
    let mut q=p.clone();q.entries=vec![entry(ObjectKind::RecoveryEvidence,0,4),entry(ObjectKind::CertifiedBlock,1,5)];
    let mut r=request();r.max_candidate_entries=1;q.request_object_id=r.object_id().unwrap();
    assert_eq!(q.validate_for(&r),Err(HistoryError::Bounds));
    r=request();r.max_blocks=1;q.request_object_id=r.object_id().unwrap();
    q.entries=vec![entry(ObjectKind::CertifiedBlock,1,4),entry(ObjectKind::CertifiedBlock,2,5)];
    q.offered_through_anchor=Some(a(2));q.observed_tip_anchor=Some(a(2));
    assert_eq!(q.validate_for(&r),Err(HistoryError::Bounds));
}

#[test]
fn pages_reject_noncanonical_trailing_oversize_and_huge_array_counts() {
    let good=page(HistoryStatus::Page).encode().unwrap();
    let mut bad=good.clone();bad.push(0);
    assert_eq!(HistoryPage::decode(&bad),Err(HistoryError::NonCanonical));
    let mut bad=good.clone();bad.splice(1..2,[0x18,1]);
    assert_eq!(HistoryPage::decode(&bad),Err(HistoryError::NonCanonical));
    let mut bad=good.clone();bad[1]=2;
    assert_eq!(HistoryPage::decode(&bad),Err(HistoryError::Version));
    assert_eq!(HistoryPage::decode(&vec![0;MAX_PAGE_BYTES+1]),Err(HistoryError::Bounds));
    // Construct a complete header followed by an impossible count and no entries.
    let mut e=Encoder::new(Vec::new());
    e.array(7).unwrap().u8(1).unwrap().bytes(&[9;32]).unwrap().u8(7).unwrap()
        .bytes(&a(0).encode()).unwrap().bytes(&a(1).encode()).unwrap()
        .bytes(&a(1).encode()).unwrap().array(u64::MAX).unwrap();
    assert_eq!(HistoryPage::decode(&e.into_writer()),Err(HistoryError::Bounds));
    let mut bad=good;bad[36]=8; // Status is after array/version/bstr32.
    assert!(HistoryPage::decode(&bad).is_err());
}

#[test]
fn per_kind_lengths_and_actual_have_match_are_checked() {
    let mut e=entry(ObjectKind::RecoveryEvidence,0,4);
    e.encoded_length=256*1024;
    assert_eq!(e.validate(),Ok(()));
    e.encoded_length+=1;assert_eq!(e.validate(),Err(HistoryError::Bounds));
    e=entry(ObjectKind::CertifiedBlock,1,5);e.encoded_length=2*1024*1024;
    assert_eq!(e.validate(),Ok(()));
    e.encoded_length+=1;assert_eq!(e.validate(),Err(HistoryError::Bounds));
    e=entry(ObjectKind::CertifiedBlock,1,5);
    let offer=Offer { id:e.object_id,kind:e.kind,length:1 };
    assert!(e.matches_offer(&offer));
    for bad in [Offer {id:[6;32],..offer.clone()},Offer {kind:ObjectKind::RecoveryEvidence,..offer.clone()},
        Offer {length:2,..offer.clone()}] { assert!(!e.matches_offer(&bad)); }
    let mut p=page(HistoryStatus::Page);
    p.entries=vec![entry(ObjectKind::CertifiedBlock,1,4),entry(ObjectKind::CertifiedBlock,2,5),entry(ObjectKind::CertifiedBlock,3,6)];
    p.offered_through_anchor=Some(a(3));p.observed_tip_anchor=Some(a(3));
    for e in &mut p.entries {e.encoded_length=2*1024*1024;}
    assert_eq!(p.validate(),Err(HistoryError::Bounds));
}
