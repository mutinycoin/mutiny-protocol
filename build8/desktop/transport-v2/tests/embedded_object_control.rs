use mutiny_transport_v2::{
    Metadata,
    objects::{Bitmap, ObjectKind, Offer},
};
#[repr(C)]
#[derive(Clone, Copy)]
struct Meta {
    kind: u8,
    object: [u8; 32],
    fragment: u16,
    count: u16,
    hops: u8,
}
#[repr(C)]
struct Bits {
    start: u16,
    count: u16,
    packed: [u8; 135],
}
unsafe extern "C" {
    fn b8_object_offer_parse(
        m: *const Meta,
        p: *const u8,
        n: usize,
        k: *mut u8,
        l: *mut u32,
    ) -> i32;
    fn b8_object_offer_encode(id: *const u8, k: u8, n: u32, h: u8, m: *mut Meta, p: *mut u8)
    -> i32;
    fn b8_object_bitmap_parse(p: *const u8, n: usize, t: u16, b: *mut Bits) -> i32;
    fn b8_object_bitmap_encode(b: *const Bits, t: u16, p: *mut u8, n: *mut usize) -> i32;
}
fn cmeta(m: &Metadata) -> Meta {
    Meta {
        kind: m.kind,
        object: m.object,
        fragment: m.fragment,
        count: m.count,
        hops: m.hops,
    }
}
fn check_offer(m: &Metadata, p: &[u8]) {
    let (mut k, mut n) = (255, u32::MAX);
    let ok = unsafe { b8_object_offer_parse(&cmeta(m), p.as_ptr(), p.len(), &mut k, &mut n) } == 0;
    let rust = Offer::parse(m, p);
    assert_eq!(ok, rust.is_ok());
    if let Ok(o) = rust {
        assert_eq!((k, n), (o.kind as u8, o.length as u32));
    } else {
        assert_eq!((k, n), (0, 0));
    }
}
#[test]
fn offers_match_host_boundaries_and_malformed_fields() {
    for kind in [
        ObjectKind::SignedTransaction,
        ObjectKind::SettlementProof,
        ObjectKind::CertifiedBlock,
        ObjectKind::ContinuityVote,
        ObjectKind::WorkProbeRequest,
        ObjectKind::WorkProbeFragment,
        ObjectKind::RecoveryEvidence,
        ObjectKind::BlockProposal,
        ObjectKind::SignedOperation,
        ObjectKind::StatusQuery,
        ObjectKind::StatusReport,
        ObjectKind::A2BlockProposal,
        ObjectKind::A2EvidenceOperation,
    ] {
        for length in [1, 139, 140, 141, kind.max_bytes() - 1, kind.max_bytes()] {
            for hops in [0, 16] {
                let o = Offer {
                    id: [17; 32],
                    kind,
                    length,
                };
                let (m, p) = o.have(hops).unwrap();
                check_offer(&m, &p);
                let mut cm = cmeta(&m);
                let mut cp = [0xa5; 6];
                assert_eq!(
                    unsafe {
                        b8_object_offer_encode(
                            o.id.as_ptr(),
                            kind as u8,
                            length as u32,
                            hops,
                            &mut cm,
                            cp.as_mut_ptr(),
                        )
                    },
                    0
                );
                assert_eq!(cp.as_slice(), p);
                assert_eq!(
                    (cm.kind, cm.object, cm.fragment, cm.count, cm.hops),
                    (m.kind, m.object, m.fragment, m.count, m.hops)
                );
                for bit in 0..48 {
                    let mut bad = p.clone();
                    bad[bit / 8] ^= 1 << (bit % 8);
                    check_offer(&m, &bad);
                }
                for n in 0..6 {
                    check_offer(&m, &p[..n]);
                }
                let mut bad = m.clone();
                bad.hops = 17;
                check_offer(&bad, &p);
                bad = m.clone();
                bad.fragment = 1;
                check_offer(&bad, &p);
                bad = m.clone();
                bad.object = [0; 32];
                check_offer(&bad, &p);
                bad = m.clone();
                bad.kind = 2;
                check_offer(&bad, &p);
                bad = m.clone();
                bad.count = 0;
                check_offer(&bad, &p);
            }
        }
    }
    for (k, n, h) in [
        (0, 1, 0),
        (14, 1, 0),
        (12, 270872, 0),
        (13, 196609, 0),
        (12, 0, 0),
        (13, u32::MAX, 0),
        (9, 16385, 0),
        (10, 4097, 0),
        (11, 16385, 0),
        (8, 74258, 0),
        (7, 262145, 0),
        (5, 513, 0),
        (6, 4097, 0),
        (1, 0, 0),
        (1, 16385, 0),
        (1, u32::MAX, 0),
        (1, 1, 17),
    ] {
        let mut m = Meta {
            kind: 9,
            object: [9; 32],
            fragment: 9,
            count: 9,
            hops: 9,
        };
        let mut p = [9; 6];
        assert_ne!(
            unsafe { b8_object_offer_encode([1; 32].as_ptr(), k, n, h, &mut m, p.as_mut_ptr()) },
            0
        );
        assert_eq!(
            (m.kind, m.object, m.fragment, m.count, m.hops),
            (0, [0; 32], 0, 0, 0)
        );
        assert_eq!(p, [0; 6]);
    }
}
fn check_bitmap(p: &[u8], total: u16) {
    let mut c = Bits {
        start: 9,
        count: 9,
        packed: [9; 135],
    };
    let ok = unsafe { b8_object_bitmap_parse(p.as_ptr(), p.len(), total, &mut c) } == 0;
    let rust = Bitmap::parse(p, total);
    assert_eq!(ok, rust.is_ok(), "total={total}, payload={p:?}");
    if let Ok(b) = rust {
        assert_eq!(c.start, b.start);
        assert_eq!(c.count as usize, b.bits.len());
        for (i, bit) in b.bits.iter().enumerate() {
            assert_eq!(c.packed[i / 8] >> (i % 8) & 1, u8::from(*bit));
        }
        assert!(c.packed[b.bits.len().div_ceil(8)..].iter().all(|x| *x == 0));
        let mut out = [9; 140];
        let mut n = 999;
        assert_eq!(
            unsafe { b8_object_bitmap_encode(&c, total, out.as_mut_ptr(), &mut n) },
            0
        );
        assert_eq!(&out[..n], p);
        assert!(out[n..].iter().all(|x| *x == 0));
    } else {
        assert_eq!((c.start, c.count, c.packed), (0, 0, [0; 135]));
    }
}
#[test]
fn all_bitmap_lengths_and_deterministic_malformed_corpus_match_host() {
    for n in 1..=1080 {
        let b = Bitmap {
            start: 16384 - n,
            bits: (0..n).map(|i| i % 3 == 0).collect(),
        };
        let p = b.encode(16384).unwrap();
        check_bitmap(&p, 16384);
        check_bitmap(&p, 16383);
        check_bitmap(&p, 0);
        check_bitmap(&p, 16385);
        if n % 8 != 0 {
            let mut bad = p.clone();
            *bad.last_mut().unwrap() |= 128;
            check_bitmap(&bad, 16384);
        }
    }
    let mut seed = 0x12345678u32;
    for i in 0..50000 {
        let mut p = vec![0u8; i % 142];
        for b in &mut p {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        if i % 2 == 0 && !p.is_empty() {
            p[0] = 2;
        }
        check_bitmap(&p, (seed % 17000) as u16);
    }
    for (start, count, total) in [
        (0, 0, 1),
        (0, 1081, 16384),
        (65535, 1, 16384),
        (16384, 1, 16384),
        (0, 1, 0),
        (0, 1, 16385),
    ] {
        let b = Bits {
            start,
            count,
            packed: [0; 135],
        };
        let mut p = [9; 140];
        let mut n = 99;
        assert_ne!(
            unsafe { b8_object_bitmap_encode(&b, total, p.as_mut_ptr(), &mut n) },
            0
        );
        assert_eq!((p, n), ([0; 140], 0));
    }
}
