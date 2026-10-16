use mutiny_transport_v2::{
    Error,
    handshake_frames::{Kind, Reassembler, fragment},
};
use std::ffi::c_void;
unsafe extern "C" {
    fn b8_handshake_size() -> usize;
    fn b8_handshake_alignment() -> usize;
    fn b8_handshake_init(s: *mut c_void, tag: *const u8, peers: *const u8, count: usize) -> i32;
    fn b8_handshake_clear(s: *mut c_void);
    fn b8_handshake_expire(s: *mut c_void, now: u64);
    fn b8_handshake_pending(s: *const c_void) -> usize;
    fn b8_handshake_receive(
        s: *mut c_void,
        now: u64,
        expected: u8,
        frame: *const u8,
        length: usize,
        peer: *mut u8,
        message: *mut u8,
        n: *mut usize,
    ) -> i32;
    fn b8_handshake_fragment(
        tag: *const u8,
        peer: *const u8,
        id: *const u8,
        kind: u8,
        message: *const u8,
        length: usize,
        index: u8,
        out: *mut u8,
        n: *mut usize,
    ) -> i32;
}
struct CReceiver(Vec<u64>);
impl CReceiver {
    fn new(peers: &[[u8; 32]]) -> Self {
        Self::with_tag([1; 16], peers)
    }
    fn with_tag(tag: [u8; 16], peers: &[[u8; 32]]) -> Self {
        unsafe {
            assert!(b8_handshake_alignment() <= std::mem::align_of::<u64>());
            let mut s = Self(vec![0; b8_handshake_size().div_ceil(8)]);
            assert_eq!(
                b8_handshake_init(
                    s.0.as_mut_ptr().cast(),
                    tag.as_ptr(),
                    peers.as_ptr().cast(),
                    peers.len()
                ),
                0
            );
            s
        }
    }
    fn receive(
        &mut self,
        kind: Kind,
        frame: &[u8],
        now: u64,
    ) -> Result<Option<([u8; 32], Vec<u8>)>, Error> {
        let mut peer = [0xa5; 32];
        let mut raw = [0xa5; 3050];
        let mut n = 999;
        let status = unsafe {
            b8_handshake_receive(
                self.0.as_mut_ptr().cast(),
                now,
                kind as u8,
                frame.as_ptr(),
                frame.len(),
                peer.as_mut_ptr(),
                raw.as_mut_ptr(),
                &mut n,
            )
        };
        if status != 0 {
            assert_eq!(n, 0);
            assert_eq!(peer, [0; 32]);
            assert_eq!(raw, [0; 3050]);
            return Err(match status {
                1 => Error::Encoding,
                2 => Error::Context,
                6 => Error::Limit,
                _ => panic!("unexpected error {status}"),
            });
        }
        if n == 0 {
            assert_eq!(peer, [0; 32]);
            assert_eq!(raw, [0; 3050]);
            Ok(None)
        } else {
            assert!(n <= 3050);
            Ok(Some((peer, raw[..n].to_vec())))
        }
    }
    fn pending(&self) -> usize {
        unsafe { b8_handshake_pending(self.0.as_ptr().cast()) }
    }
}

#[test]
fn completed_c_framing_still_requires_hybrid_handshake_and_finished() {
    use mutiny_crypto_v2::{HybridKey, Role};
    use mutiny_transport_v2::{
        Context, Endpoint, InitiatorPending, Metadata, ingress::ResponderIngress,
    };
    fn deliver(
        r: &mut CReceiver,
        tag: [u8; 16],
        sender: [u8; 32],
        kind: Kind,
        raw: &[u8],
    ) -> Vec<u8> {
        let frames = fragment(tag, sender, kind, raw).unwrap();
        for f in frames.iter().skip(1).rev() {
            assert!(r.receive(kind, f, 0).unwrap().is_none());
            assert!(r.receive(kind, f, 0).unwrap().is_none());
        }
        let (peer, bytes) = r.receive(kind, &frames[0], 0).unwrap().unwrap();
        assert_eq!(peer, sender);
        assert_eq!(bytes, raw);
        bytes
    }
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let ae = Endpoint::pinned(a.public().clone(), 1).unwrap();
    let be = Endpoint::pinned(b.public().clone(), 1).unwrap();
    let (aid, bid) = (ae.id(), be.id());
    let ctx = Context::pinned([1; 32], [2; 32], ae, be).unwrap();
    let tag = ctx.network_tag();
    let mut ar = CReceiver::with_tag(tag, &[bid]);
    let mut br = CReceiver::with_tag(tag, &[aid]);
    let mut gate = ResponderIngress::new(vec![ctx.clone()]).unwrap();
    let (i, hello) = InitiatorPending::start(ctx.clone(), &a).unwrap();
    let h = deliver(&mut br, tag, aid, Kind::Hello, &hello);
    let response = gate.accept(aid, &b, &h).unwrap();
    let r = deliver(&mut ar, tag, bid, Kind::Response, &response);
    let (i, finish) = i.accept(&a, &r).unwrap();
    let f = deliver(&mut br, tag, aid, Kind::ClientFinish, &finish);
    let (mut receiver, finish) = gate.finish(aid, &f).unwrap();
    let f = deliver(&mut ar, tag, bid, Kind::ServerFinish, &finish);
    let mut sender = i.finish(&f).unwrap();
    let meta = Metadata {
        kind: 3,
        object: [7; 32],
        fragment: 0,
        count: 1,
        hops: 0,
    };
    let wire = sender.seal(&meta, b"public integration fixture").unwrap();
    assert_eq!(
        receiver.open(&wire).unwrap().1,
        b"public integration fixture"
    );
    let (i, hello) = InitiatorPending::start(ctx, &a).unwrap();
    let h = deliver(&mut br, tag, aid, Kind::Hello, &hello);
    let mut response = gate.accept(aid, &b, &h).unwrap();
    response[1800] ^= 1;
    let bad = deliver(&mut ar, tag, bid, Kind::Response, &response);
    assert!(
        i.accept(&a, &bad).is_err(),
        "unauthenticated C reassembly cannot make a corrupt signature authoritative"
    );
}
impl Drop for CReceiver {
    fn drop(&mut self) {
        unsafe { b8_handshake_clear(self.0.as_mut_ptr().cast()) };
        assert!(self.0.iter().all(|n| *n == 0));
    }
}
#[test]
fn exact_c_handshake_frames_match_rust_for_every_phase() {
    for (kind, length) in [
        (Kind::Hello, 1822),
        (Kind::Response, 3050),
        (Kind::ClientFinish, 1410),
        (Kind::ServerFinish, 16),
    ] {
        let raw: Vec<_> = (0..length).map(|n| (n % 251) as u8).collect();
        let frames = fragment([1; 16], [2; 32], kind, &raw).unwrap();
        let mut rust = Reassembler::new([1; 16], vec![[2; 32]]).unwrap();
        let mut c = CReceiver::new(&[[2; 32]]);
        for (i, f) in frames.iter().enumerate() {
            let mut out = [0; 255];
            let mut n = 0;
            assert_eq!(
                unsafe {
                    b8_handshake_fragment(
                        [1u8; 16].as_ptr(),
                        [2u8; 32].as_ptr(),
                        f[50..66].as_ptr(),
                        kind as u8,
                        raw.as_ptr(),
                        raw.len(),
                        i as u8,
                        out.as_mut_ptr(),
                        &mut n,
                    )
                },
                0
            );
            assert_eq!(&out[..n], f);
        }
        for f in frames.iter().skip(1).rev() {
            assert_eq!(c.receive(kind, f, 0), rust.receive(kind, f));
            assert_eq!(c.receive(kind, f, 0), rust.receive(kind, f));
            let mut conflict = f.clone();
            conflict[69] ^= 1;
            let before = c.0.clone();
            assert_eq!(c.receive(kind, &conflict, 0), rust.receive(kind, &conflict));
            assert_eq!(before, c.0);
        }
        assert_eq!(
            c.receive(kind, &frames[0], 0),
            rust.receive(kind, &frames[0])
        );
        assert_eq!(c.pending(), 0);
        for pos in [0, 1, 2, 18, 66, 67, 68] {
            let mut bad = frames[0].clone();
            bad[pos] ^= 128;
            assert_eq!(c.receive(kind, &bad, 0), rust.receive(kind, &bad));
            assert_eq!(c.pending(), 0);
        }
        for len in 0..frames[0].len() {
            assert_eq!(
                c.receive(kind, &frames[0][..len], 0),
                rust.receive(kind, &frames[0][..len])
            );
        }
    }
}
#[test]
fn c_handshake_capacity_conflicts_and_timeout_do_not_extend_flights() {
    let peers: Vec<_> = (1..=5).map(|i| [i; 32]).collect();
    let mut c = CReceiver::new(&peers);
    let all: Vec<_> = peers
        .iter()
        .map(|peer| fragment([1; 16], *peer, Kind::Hello, &vec![0; 1822]).unwrap())
        .collect();
    for f in &all[..4] {
        assert!(c.receive(Kind::Hello, &f[0], 0).unwrap().is_none());
    }
    assert_eq!(c.pending(), 4);
    assert_eq!(c.receive(Kind::Hello, &all[4][0], 0), Err(Error::Limit));
    let mut conflict = all[0][0].clone();
    conflict[50] ^= 1;
    assert_eq!(
        c.receive(Kind::Hello, &conflict, 599999),
        Err(Error::Context)
    );
    assert!(
        c.receive(Kind::Hello, &all[0][0], 600000)
            .unwrap()
            .is_none()
    );
    unsafe { b8_handshake_expire(c.0.as_mut_ptr().cast(), 600000) };
    assert_eq!(c.pending(), 4);
    unsafe { b8_handshake_expire(c.0.as_mut_ptr().cast(), 600001) };
    assert_eq!(c.pending(), 0);
    assert!(
        c.receive(Kind::Hello, &all[4][0], 600001)
            .unwrap()
            .is_none()
    );
    assert_eq!(c.pending(), 1);
    let mut s = vec![0u64; unsafe { b8_handshake_size() }.div_ceil(8)];
    for peers in [vec![], vec![[0; 32]], vec![[1; 32]; 2], vec![[1; 32]; 65]] {
        assert_eq!(
            unsafe {
                b8_handshake_init(
                    s.as_mut_ptr().cast(),
                    [1u8; 16].as_ptr(),
                    peers.as_ptr().cast(),
                    peers.len(),
                )
            },
            2
        );
        assert!(s.iter().all(|n| *n == 0));
    }
}
