use super::*;
use std::ffi::c_void;

#[repr(C)]
#[derive(Default)]
struct CMeta {
    kind: u8,
    object: [u8; 32],
    fragment: u16,
    count: u16,
    hops: u8,
}
type Open =
    unsafe extern "C" fn(*mut c_void, *const u8, *const u8, *const u8, usize, *mut u8) -> i32;
unsafe extern "C" {
    fn b8_frame_aead_init(key: *mut c_void, raw: *const u8) -> i32;
    fn b8_frame_aead_clear(key: *mut c_void);
    fn b8_frame_mbedtls_open(
        key: *mut c_void,
        nonce: *const u8,
        aad: *const u8,
        cipher: *const u8,
        n: usize,
        plain: *mut u8,
    ) -> i32;
    fn b8_frame_mbedtls_seal(
        key: *mut c_void,
        nonce: *const u8,
        aad: *const u8,
        plain: *const u8,
        n: usize,
        cipher: *mut u8,
    ) -> i32;
    fn b8_frame_mbedtls_chacha20_self_test(verbose: i32) -> i32;
    fn b8_frame_mbedtls_poly1305_self_test(verbose: i32) -> i32;
    fn b8_frame_mbedtls_chachapoly_self_test(verbose: i32) -> i32;
    fn b8_frame_receiver_size() -> usize;
    fn b8_frame_receiver_alignment() -> usize;
    fn b8_frame_receiver_init(
        s: *mut c_void,
        tag: *const u8,
        id: *const u8,
        prefix: *const u8,
        direction: u8,
        now: u64,
    ) -> i32;
    fn b8_frame_receive(
        s: *mut c_void,
        now: u64,
        frame: *const u8,
        length: usize,
        open: Open,
        provider: *mut c_void,
        meta: *mut CMeta,
        out: *mut u8,
        n: *mut usize,
    ) -> i32;
    fn b8_frame_receiver_clear(s: *mut c_void);
    fn b8_frame_sender_size() -> usize;
    fn b8_frame_sender_alignment() -> usize;
    fn b8_frame_sender_init(
        s: *mut c_void,
        tag: *const u8,
        id: *const u8,
        prefix: *const u8,
        direction: u8,
        now: u64,
    ) -> i32;
    fn b8_frame_sender_clear(s: *mut c_void);
    fn b8_frame_seal(
        s: *mut c_void,
        now: u64,
        meta: *const CMeta,
        plain: *const u8,
        length: usize,
        encrypt: Open,
        provider: *mut c_void,
        frame: *mut u8,
        n: *mut usize,
    ) -> i32;
}
unsafe extern "C" fn encrypt(
    provider: *mut c_void,
    nonce: *const u8,
    aad: *const u8,
    plain: *const u8,
    n: usize,
    out: *mut u8,
) -> i32 {
    unsafe {
        if !provider.is_null() {
            std::ptr::write_bytes(out, 0xa5, n + 16);
            return 0;
        }
        let cipher = ChaCha20Poly1305::new((&[1u8; 32]).into())
            .encrypt(
                Nonce::from_slice(std::slice::from_raw_parts(nonce, 12)),
                Payload {
                    msg: std::slice::from_raw_parts(plain, n),
                    aad: std::slice::from_raw_parts(aad, 99),
                },
            )
            .unwrap();
        std::ptr::copy_nonoverlapping(cipher.as_ptr(), out, cipher.len());
        1
    }
}
unsafe extern "C" fn decrypt(
    _: *mut c_void,
    nonce: *const u8,
    aad: *const u8,
    cipher: *const u8,
    n: usize,
    out: *mut u8,
) -> i32 {
    // Public fixed traffic key, never a production provider. Poison provisional
    // output on failure to prove that the C layer does not expose it.
    unsafe {
        let data = ChaCha20Poly1305::new((&[1u8; 32]).into()).decrypt(
            Nonce::from_slice(std::slice::from_raw_parts(nonce, 12)),
            Payload {
                msg: std::slice::from_raw_parts(cipher, n),
                aad: std::slice::from_raw_parts(aad, 99),
            },
        );
        match data {
            Ok(data) => {
                std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
                1
            }
            Err(_) => {
                std::ptr::write_bytes(out, 0xa5, 140);
                0
            }
        }
    }
}
struct Receiver(Vec<u64>);
impl Receiver {
    fn new(tag: &[u8; 16]) -> Self {
        unsafe {
            assert!(b8_frame_receiver_alignment() <= std::mem::align_of::<u64>());
            let mut s = Self(vec![0; b8_frame_receiver_size().div_ceil(8)]);
            assert_eq!(
                b8_frame_receiver_init(
                    s.0.as_mut_ptr().cast(),
                    tag.as_ptr(),
                    [5u8; 32].as_ptr(),
                    [3u8; 4].as_ptr(),
                    1,
                    100
                ),
                0
            );
            s
        }
    }
    fn receive_at(&mut self, frame: &[u8], now: u64) -> Result<Vec<u8>> {
        self.receive_with(frame, now, decrypt, std::ptr::null_mut())
    }
    fn receive_with(
        &mut self,
        frame: &[u8],
        now: u64,
        open: Open,
        provider: *mut c_void,
    ) -> Result<Vec<u8>> {
        let before = self.0.clone();
        let mut out = [0xa5; 140];
        let mut n = 999;
        let mut m = CMeta::default();
        let status = unsafe {
            b8_frame_receive(
                self.0.as_mut_ptr().cast(),
                now,
                frame.as_ptr(),
                frame.len(),
                open,
                provider,
                &mut m,
                out.as_mut_ptr(),
                &mut n,
            )
        };
        if status == 0 {
            assert!((1..=140).contains(&n));
            assert_eq!(m.kind, frame[1]);
            assert_eq!(m.object.as_slice(), &frame[60..92]);
            assert_eq!(
                m.fragment,
                u16::from_be_bytes(frame[92..94].try_into().unwrap())
            );
            assert_eq!(
                m.count,
                u16::from_be_bytes(frame[94..96].try_into().unwrap())
            );
            assert_eq!(m.hops, frame[96]);
            return Ok(out[..n].to_vec());
        }
        assert_eq!(self.0, before, "rejection mutated receive state");
        assert_eq!(n, 0);
        assert_eq!(out, [0; 140]);
        assert_eq!(m.object, [0; 32]);
        assert_eq!(m.kind, 0);
        Err(match status {
            1 => Error::Encoding,
            2 => Error::Context,
            3 => Error::Crypto,
            4 => Error::Expired,
            5 => Error::Replay,
            6 => Error::Limit,
            _ => panic!("unknown status"),
        })
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        unsafe { b8_frame_receiver_clear(self.0.as_mut_ptr().cast()) };
        assert!(self.0.iter().all(|n| *n == 0));
    }
}

#[test]
fn bounded_c_receiver_matches_rust_and_independent_python_frames() {
    let (mut sender, mut rust) = super::tests::pair();
    let mut c = Receiver::new(&sender.context.tag);
    let m = Metadata {
        kind: 3,
        object: [7; 32],
        fragment: 0,
        count: 1,
        hops: 2,
    };
    let frames: Vec<_> = (1..=260)
        .map(|n| sender.seal(&m, &[(n % 251) as u8; 140]).unwrap())
        .collect();
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../qualification/embedded-frame-public-vectors-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["synthetic"], true);
    for v in fixture["vectors"].as_array().unwrap() {
        assert_eq!(
            frames[v["sequence"].as_u64().unwrap() as usize - 1],
            hex::decode(v["frame"].as_str().unwrap()).unwrap()
        );
    }
    for at in 0..255 {
        for bit in 0..8 {
            let mut bad = frames[259].clone();
            bad[at] ^= 1 << bit;
            assert_eq!(
                c.receive_at(&bad, 100).unwrap_err(),
                rust.open(&bad).unwrap_err()
            );
        }
    }
    for length in 0..255 {
        assert_eq!(
            c.receive_at(&frames[0][..length], 100).unwrap_err(),
            rust.open(&frames[0][..length]).unwrap_err()
        );
    }
    // Exact 63/64/127/128 replay boundaries and forward shifts in both halves.
    for seq in [
        129, 2, 1, 65, 66, 128, 129, 193, 130, 194, 260, 133, 132, 259, 260,
    ] {
        assert_eq!(
            c.receive_at(&frames[seq - 1], 100),
            rust.open(&frames[seq - 1]).map(|(_, p)| p)
        );
    }
    let mut c = Receiver::new(&sender.context.tag);
    assert_eq!(c.receive_at(&frames[0], 99), Err(Error::Expired));
    assert!(c.receive_at(&frames[0], 3_600_100).is_ok());
    assert_eq!(c.receive_at(&frames[1], 3_600_101), Err(Error::Expired));
}

#[test]
fn bounded_c_receiver_object_budget_matches_rust() {
    let (mut sender, mut rust) = super::tests::pair();
    let mut c = Receiver::new(&sender.context.tag);
    for n in 1u16..=256 {
        let mut object = [0; 32];
        object[..2].copy_from_slice(&n.to_be_bytes());
        let m = Metadata {
            kind: 3,
            object,
            fragment: 0,
            count: 1,
            hops: 0,
        };
        let f = sender.seal(&m, b"x").unwrap();
        assert_eq!(c.receive_at(&f, 100), rust.open(&f).map(|(_, p)| p));
    }
    // Test-only direct counter access creates one otherwise valid extra object.
    sender.tx_objects.clear();
    let m = Metadata {
        kind: 3,
        object: [7; 32],
        fragment: 0,
        count: 1,
        hops: 0,
    };
    let f = sender.seal(&m, b"x").unwrap();
    assert_eq!(c.receive_at(&f, 100), Err(Error::Limit));
    assert_eq!(rust.open(&f), Err(Error::Limit));
}

#[test]
fn bounded_c_sender_matches_rust_and_never_reuses_failed_nonce() {
    let (mut rust, mut receiver) = super::tests::pair();
    let meta = Metadata {
        kind: 3,
        object: [7; 32],
        fragment: 0,
        count: 1,
        hops: 2,
    };
    let cm = CMeta {
        kind: meta.kind,
        object: meta.object,
        fragment: 0,
        count: 1,
        hops: 2,
    };
    unsafe {
        assert!(b8_frame_sender_alignment() <= std::mem::align_of::<u64>());
        let mut state = vec![0u64; b8_frame_sender_size().div_ceil(8)];
        assert_eq!(
            b8_frame_sender_init(
                state.as_mut_ptr().cast(),
                rust.context.tag.as_ptr(),
                [5u8; 32].as_ptr(),
                [3u8; 4].as_ptr(),
                0,
                100
            ),
            0
        );
        let mut packet = [0xa5; 255];
        let mut n = 999;
        for length in 1..=140 {
            let plain = vec![length as u8; length];
            assert_eq!(
                b8_frame_seal(
                    state.as_mut_ptr().cast(),
                    100,
                    &cm,
                    plain.as_ptr(),
                    length,
                    encrypt,
                    std::ptr::null_mut(),
                    packet.as_mut_ptr(),
                    &mut n
                ),
                0
            );
            assert_eq!(&packet[..n], rust.seal(&meta, &plain).unwrap());
            assert_eq!(receiver.open(&packet[..n]).unwrap().1, plain);
        }
        let before = state.clone();
        assert_eq!(
            b8_frame_seal(
                state.as_mut_ptr().cast(),
                100,
                &cm,
                [0u8; 141].as_ptr(),
                141,
                encrypt,
                std::ptr::null_mut(),
                packet.as_mut_ptr(),
                &mut n
            ),
            1
        );
        assert_eq!(before, state);
        assert_eq!(n, 0);
        assert_eq!(packet, [0; 255]);
        let mut failure_marker = 1u8;
        assert_eq!(
            b8_frame_seal(
                state.as_mut_ptr().cast(),
                100,
                &cm,
                [9u8].as_ptr(),
                1,
                encrypt,
                (&mut failure_marker as *mut u8).cast(),
                packet.as_mut_ptr(),
                &mut n
            ),
            3
        );
        assert_ne!(before, state);
        assert_eq!(n, 0);
        assert_eq!(packet, [0; 255]);
        // Consume the corresponding Rust sequence without transmitting it.
        rust.seal(&meta, &[9]).unwrap();
        assert_eq!(
            b8_frame_seal(
                state.as_mut_ptr().cast(),
                100,
                &cm,
                [8u8].as_ptr(),
                1,
                encrypt,
                std::ptr::null_mut(),
                packet.as_mut_ptr(),
                &mut n
            ),
            0
        );
        assert_eq!(&packet[..n], rust.seal(&meta, &[8]).unwrap());
        assert_eq!(u64::from_be_bytes(packet[52..60].try_into().unwrap()), 142);
        b8_frame_sender_clear(state.as_mut_ptr().cast());
        assert!(state.iter().all(|n| *n == 0));
    }
}

#[test]
fn actual_c_aead_matches_rust_rejects_tampering_and_clears_keys() {
    unsafe {
        assert_eq!(b8_frame_mbedtls_chacha20_self_test(0), 0);
        assert_eq!(b8_frame_mbedtls_poly1305_self_test(0), 0);
        assert_eq!(b8_frame_mbedtls_chachapoly_self_test(0), 0);
        // C key struct is exactly 32 bytes plus one u32 initialization marker.
        let mut key = [0u32; 9];
        assert_eq!(
            b8_frame_aead_init(key.as_mut_ptr().cast(), [1u8; 32].as_ptr()),
            1
        );
        let original = key;
        assert_eq!(
            b8_frame_aead_init(key.as_mut_ptr().cast(), key.as_ptr().cast()),
            1
        );
        assert_eq!(
            key, original,
            "aliased initialization must retain the exact traffic key"
        );
        let (mut rust, mut rust_receiver) = super::tests::pair();
        let mut receiver = Receiver::new(&rust.context.tag);
        let mut state = vec![0u64; b8_frame_sender_size().div_ceil(8)];
        assert_eq!(
            b8_frame_sender_init(
                state.as_mut_ptr().cast(),
                rust.context.tag.as_ptr(),
                [5u8; 32].as_ptr(),
                [3u8; 4].as_ptr(),
                0,
                100
            ),
            0
        );
        let meta = Metadata {
            kind: 3,
            object: [7; 32],
            fragment: 0,
            count: 1,
            hops: 2,
        };
        let cm = CMeta {
            kind: meta.kind,
            object: meta.object,
            fragment: 0,
            count: 1,
            hops: 2,
        };
        let mut packet = [0u8; 255];
        let mut n = 0;
        for length in 1..=140 {
            let plain = vec![length as u8; length];
            let wire = rust.seal(&meta, &plain).unwrap();
            assert_eq!(
                b8_frame_seal(
                    state.as_mut_ptr().cast(),
                    100,
                    &cm,
                    plain.as_ptr(),
                    length,
                    b8_frame_mbedtls_seal,
                    key.as_mut_ptr().cast(),
                    packet.as_mut_ptr(),
                    &mut n
                ),
                0
            );
            assert_eq!(wire, &packet[..n]);
            if length == 140 {
                for at in 0..wire.len() {
                    for bit in 0..8 {
                        let mut bad = wire.clone();
                        bad[at] ^= 1 << bit;
                        assert!(
                            receiver
                                .receive_with(
                                    &bad,
                                    100,
                                    b8_frame_mbedtls_open,
                                    key.as_mut_ptr().cast()
                                )
                                .is_err()
                        );
                    }
                }
            }
            assert_eq!(
                receiver
                    .receive_with(&wire, 100, b8_frame_mbedtls_open, key.as_mut_ptr().cast())
                    .unwrap(),
                plain
            );
            assert_eq!(rust_receiver.open(&packet[..n]).unwrap().1, plain);
        }
        let wire = rust
            .seal(&meta, b"wrong traffic key cannot authenticate")
            .unwrap();
        assert_eq!(
            b8_frame_aead_init(key.as_mut_ptr().cast(), [2u8; 32].as_ptr()),
            1
        );
        assert_eq!(
            receiver.receive_with(&wire, 100, b8_frame_mbedtls_open, key.as_mut_ptr().cast()),
            Err(Error::Crypto)
        );
        b8_frame_aead_clear(key.as_mut_ptr().cast());
        assert_eq!(key, [0; 9]);
        assert_eq!(
            receiver.receive_with(&wire, 100, b8_frame_mbedtls_open, key.as_mut_ptr().cast()),
            Err(Error::Crypto)
        );
        b8_frame_sender_clear(state.as_mut_ptr().cast());
        assert!(state.iter().all(|n| *n == 0));
    }
}
