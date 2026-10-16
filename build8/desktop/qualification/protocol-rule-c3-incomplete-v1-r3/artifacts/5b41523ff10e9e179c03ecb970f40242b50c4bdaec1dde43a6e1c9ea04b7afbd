//! C/MbedTLS interoperability with public constant Rust/Python frame vectors.
use super::*;
#[repr(C)]
struct Raw {
    context: [u8; 64],
    id: [u8; 32],
    tx: [u8; 32],
    rx: [u8; 32],
    tp: [u8; 4],
    rp: [u8; 4],
    confirmed: u64,
    last: u64,
    next_tx: u64,
    next_rx: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    effective: u64,
    until: u64,
    active: u32,
    worker: u8,
}
unsafe extern "C" {
    fn b8_worker_channel_size() -> usize;
    fn b8_worker_channel_alignment() -> usize;
    fn b8_worker_channel_clear(s: *mut Raw);
    fn b8_worker_channel_expire(
        s: *mut Raw,
        c: *const u8,
        height: u64,
        epoch: u64,
        now: u64,
    ) -> i32;
    fn b8_worker_channel_init(
        s: *mut Raw,
        c: *const u8,
        id: *const u8,
        tx: *const u8,
        rx: *const u8,
        tp: *const u8,
        rp: *const u8,
        worker: u8,
        confirmed: u64,
        now: u64,
        effective: u64,
        until: u64,
    ) -> i32;
    fn b8_worker_seal(
        s: *mut Raw,
        c: *const u8,
        height: u64,
        epoch: u64,
        now: u64,
        p: *const u8,
        n: usize,
        o: *mut u8,
        cap: usize,
        w: *mut usize,
    ) -> i32;
    fn b8_worker_open(
        s: *mut Raw,
        c: *const u8,
        height: u64,
        epoch: u64,
        now: u64,
        p: *const u8,
        n: usize,
        o: *mut u8,
        cap: usize,
        w: *mut usize,
    ) -> i32;
}
impl Drop for Raw {
    fn drop(&mut self) {
        unsafe { b8_worker_channel_clear(self) }
    }
}
fn new(worker: bool) -> Raw {
    new_with(&[7; 64], worker, 0, 0)
}
/// A channel for ContextID `context` with the binding's effective epoch and
/// valid_until_height (`until`), confirmed and initialized at 100 ms.
fn new_with(context: &[u8; 64], worker: bool, effective: u64, until: u64) -> Raw {
    assert_eq!(
        unsafe { b8_worker_channel_size() },
        std::mem::size_of::<Raw>()
    );
    assert_eq!(
        unsafe { b8_worker_channel_alignment() },
        std::mem::align_of::<Raw>()
    );
    let k = derive(&[1; 56], &[2; 32], &[3; 64], worker).unwrap();
    let mut raw: Raw = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            b8_worker_channel_init(
                &mut raw,
                context.as_ptr(),
                k.id.as_ptr(),
                k.tx.as_ptr(),
                k.rx.as_ptr(),
                k.tx_prefix.as_ptr(),
                k.rx_prefix.as_ptr(),
                u8::from(worker),
                100,
                100,
                effective,
                until,
            )
        },
        1
    );
    raw
}
fn fixtures() -> Vec<(Vec<u8>, Vec<u8>)> {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/worker-session-frames-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["public_constants_only"], true);
    f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                hex::decode(r["plaintext"].as_str().unwrap()).unwrap(),
                hex::decode(r["frame"].as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn idle_channel_timer_erases_keys_on_expiry_or_authority_loss() {
    for mode in 0..5 {
        let mut channel = new(true);
        let mut context = [7; 64];
        let mut height = 1;
        let mut epoch = 0;
        assert_eq!(
            unsafe {
                b8_worker_channel_expire(&mut channel, context.as_ptr(), height, epoch, 3_600_099)
            },
            1
        );
        let now = match mode {
            0 => 3_600_100,
            1 => 3_600_098,
            2 => {
                context[0] ^= 1;
                3_600_099
            }
            3 => {
                height = 0;
                3_600_099
            }
            _ => {
                channel.effective = 2;
                epoch = 1;
                3_600_099
            }
        };
        assert_eq!(
            unsafe { b8_worker_channel_expire(&mut channel, context.as_ptr(), height, epoch, now) },
            0
        );
        assert_eq!(channel.active, 0);
        assert_eq!(channel.tx, [0; 32]);
        assert_eq!(channel.rx, [0; 32]);
        assert_eq!(channel.tp, [0; 4]);
        assert_eq!(channel.rp, [0; 4]);
    }
    // The recorded valid_until_height (`until`) is the assignment's inclusion deadline, not a
    // session expiry (Order Q17; amendment AM-7): the idle timer keeps the channel past it.
    let mut channel = new(true);
    channel.until = 1;
    assert_eq!(
        unsafe { b8_worker_channel_expire(&mut channel, [7; 64].as_ptr(), 2, 0, 3_600_099) },
        1
    );
    assert_ne!(channel.active, 0);
    assert_ne!(channel.tx, [0; 32]);
    assert_ne!(channel.rx, [0; 32]);
}
#[test]
fn mbedtls_worker_frames_match_rust_python_exact_wire_and_bounds() {
    let mut worker = new(true);
    let mut node = new(false);
    for (plain, frame) in fixtures() {
        let mut encrypted = vec![0xA5; MAX_FRAME_BYTES];
        let mut written = 99;
        assert_eq!(
            unsafe {
                b8_worker_seal(
                    &mut worker,
                    [7; 64].as_ptr(),
                    1,
                    0,
                    101,
                    plain.as_ptr(),
                    plain.len(),
                    encrypted.as_mut_ptr(),
                    encrypted.len(),
                    &mut written,
                )
            },
            1
        );
        assert_eq!(&encrypted[..written], frame);
        let mut out = vec![0xA5; MAX_PAYLOAD];
        written = 99;
        assert_eq!(
            unsafe {
                b8_worker_open(
                    &mut node,
                    [7; 64].as_ptr(),
                    1,
                    0,
                    101,
                    frame.as_ptr(),
                    frame.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                )
            },
            1
        );
        assert_eq!(&out[..written], plain);
        assert!(out[written..].iter().all(|x| *x == 0));
    }
}
#[test]
fn mbedtls_worker_hostile_input_closes_and_erases_without_delivery() {
    let frame = &fixtures()[0].1;
    for index in [0, 1, 2, 34, 42, 44, frame.len() - 1] {
        let mut node = new(false);
        let mut bad = frame.clone();
        bad[index] ^= 1;
        let mut out = vec![0xA5; MAX_PAYLOAD];
        let mut written = 99;
        assert_eq!(
            unsafe {
                b8_worker_open(
                    &mut node,
                    [7; 64].as_ptr(),
                    1,
                    0,
                    101,
                    bad.as_ptr(),
                    bad.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                )
            },
            0
        );
        assert_eq!(written, 0);
        assert_eq!(node.active, 0);
        assert!(out.iter().all(|x| *x == 0));
        assert_eq!(node.tx, [0; 32]);
        assert_eq!(node.rx, [0; 32]);
    }
    for n in [0, 1, 43, 44, 60] {
        let mut node = new(false);
        let mut out = vec![0xA5; MAX_PAYLOAD];
        let mut written = 99;
        assert_eq!(
            unsafe {
                b8_worker_open(
                    &mut node,
                    [7; 64].as_ptr(),
                    1,
                    0,
                    101,
                    frame.as_ptr(),
                    n,
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                )
            },
            0
        );
        assert_eq!(written, 0);
        assert_eq!(node.active, 0);
    }
    let mut node = new(false);
    let mut out = vec![0; MAX_PAYLOAD];
    let mut written = 0;
    assert_eq!(
        unsafe {
            b8_worker_open(
                &mut node,
                [7; 64].as_ptr(),
                1,
                0,
                101,
                frame.as_ptr(),
                frame.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        1
    );
    assert_eq!(
        unsafe {
            b8_worker_open(
                &mut node,
                [7; 64].as_ptr(),
                1,
                0,
                102,
                frame.as_ptr(),
                frame.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        0
    );
    assert_eq!(written, 0);
    assert_eq!(node.active, 0);
}
#[test]
fn mbedtls_worker_lifecycle_counter_and_alias_boundaries_fail_closed() {
    let frame = &fixtures()[0].1;
    for (context, height, epoch, now, effective, until) in [
        ([8; 64], 1, 0, 101, 0, 0),
        ([7; 64], 0, 0, 101, 0, 0),
        ([7; 64], 1, 1, 101, 2, 0),
        ([7; 64], 1, 0, 99, 0, 0),
        ([7; 64], 1, 0, 3600100, 0, 0),
    ] {
        let mut node = new(false);
        node.effective = effective;
        node.until = until;
        let mut out = vec![0xA5; MAX_PAYLOAD];
        let mut written = 99;
        assert_eq!(
            unsafe {
                b8_worker_open(
                    &mut node,
                    context.as_ptr(),
                    height,
                    epoch,
                    now,
                    frame.as_ptr(),
                    frame.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                )
            },
            0
        );
        assert_eq!(written, 0);
        assert_eq!(node.active, 0);
    }
    // Past the recorded valid_until_height the channel still delivers (amendment AM-7).
    let mut node = new(false);
    node.until = 2;
    let mut out = vec![0xA5; MAX_PAYLOAD];
    let mut written = 99;
    assert_eq!(
        unsafe {
            b8_worker_open(
                &mut node,
                [7; 64].as_ptr(),
                3,
                0,
                101,
                frame.as_ptr(),
                frame.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        1
    );
    assert_eq!(&out[..written], &fixtures()[0].0[..]);
    let mut worker = new(true);
    let mut node = new(false);
    worker.next_tx = MAX_FRAMES;
    node.next_rx = MAX_FRAMES;
    let mut out = vec![0; MAX_FRAME_BYTES];
    let mut written = 0;
    assert_eq!(
        unsafe {
            b8_worker_seal(
                &mut worker,
                [7; 64].as_ptr(),
                1,
                0,
                101,
                b"x".as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        1
    );
    let mut plain = [0; 1];
    let mut pn = 0;
    assert_eq!(
        unsafe {
            b8_worker_open(
                &mut node,
                [7; 64].as_ptr(),
                1,
                0,
                101,
                out.as_ptr(),
                written,
                plain.as_mut_ptr(),
                1,
                &mut pn,
            )
        },
        1
    );
    assert_eq!(plain, *b"x");
    assert_eq!(pn, 1);
    assert_eq!(
        unsafe {
            b8_worker_seal(
                &mut worker,
                [7; 64].as_ptr(),
                1,
                0,
                102,
                b"x".as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        0
    );
    let mut node = new(false);
    let mut alias = frame.clone();
    let mut n = 99;
    assert_eq!(
        unsafe {
            b8_worker_open(
                &mut node,
                [7; 64].as_ptr(),
                1,
                0,
                101,
                alias.as_ptr(),
                alias.len(),
                alias.as_mut_ptr(),
                alias.len(),
                &mut n,
            )
        },
        0
    );
    assert_eq!(node.active, 0);
    let mut worker = new(true);
    worker.tx_bytes = MAX_BYTES;
    assert_eq!(
        unsafe {
            b8_worker_seal(
                &mut worker,
                [7; 64].as_ptr(),
                1,
                0,
                101,
                b"x".as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        },
        0
    );
    assert_eq!(worker.active, 0);
}
/// Order Q17; P-LANE-DESIGN-V1 11.2 (b); amendment AM-7: the embedded C channel and the Rust
/// `worker_context_v2::Context::matches_current` agree on REAL ContextIDs. An active
/// assignment's session is not ended at its valid_until_height (passed to the C init as
/// `until`); a current binding with a later assignment generation (stale sequence: the License
/// was reassigned or sold) or another owner has another ContextID, and both sides end the
/// session at the first check, before and after that height, the C side erasing its keys.
#[test]
fn c_and_rust_keep_an_active_session_past_valid_until_height_and_close_on_authority_change() {
    use crate::worker_context_v2::Context;
    use sha2::Digest;
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/enrollment-v2-public-fixture-v3.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic"], true);
    let mut active =
        Binding::decode(&hex::decode(f["unsigned"].as_str().unwrap()).unwrap()).unwrap();
    let node = mutiny_crypto_v2::HybridKey::generate(mutiny_crypto_v2::Role::Node)
        .unwrap()
        .public()
        .clone();
    let mut identity = sha2::Sha256::new();
    identity.update(b"MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2\0");
    identity.update(node.descriptor(1).unwrap());
    active.coordinator = identity.finalize().into();
    active.assignment_generation = 2;
    active.configuration_generation = 2;
    active.effective_epoch = 3;
    active.valid_until_height = 60;
    let pinned = Context::pinned(&active, &node, 1).unwrap();
    let id = pinned.id();
    for height in [1, 59, 60, 61, 1_000, u64::MAX] {
        let mut worker = new_with(&id, true, 3, 60);
        let mut peer = new_with(&id, false, 3, 60);
        assert_eq!(
            unsafe { b8_worker_channel_expire(&mut worker, id.as_ptr(), height, 3, 101) },
            1,
            "height {height}"
        );
        let mut frame = vec![0; MAX_FRAME_BYTES];
        let mut written = 0;
        assert_eq!(
            unsafe {
                b8_worker_seal(
                    &mut worker,
                    id.as_ptr(),
                    height,
                    3,
                    102,
                    b"work".as_ptr(),
                    4,
                    frame.as_mut_ptr(),
                    frame.len(),
                    &mut written,
                )
            },
            1,
            "height {height}"
        );
        let mut plain = [0; 4];
        let mut n = 0;
        assert_eq!(
            unsafe {
                b8_worker_open(
                    &mut peer,
                    id.as_ptr(),
                    height,
                    3,
                    102,
                    frame.as_ptr(),
                    written,
                    plain.as_mut_ptr(),
                    4,
                    &mut n,
                )
            },
            1,
            "height {height}"
        );
        assert_eq!(&plain, b"work");
        assert!(pinned.matches_current(&active, &node, 1, height, 3), "height {height}");
        // Before the effective epoch both sides refuse, whatever the height.
        let mut early = new_with(&id, true, 3, 60);
        assert_eq!(
            unsafe { b8_worker_channel_expire(&mut early, id.as_ptr(), height, 2, 101) },
            0,
            "height {height}"
        );
        assert!(!pinned.matches_current(&active, &node, 1, height, 2), "height {height}");
    }
    let mut reassigned = active.clone();
    reassigned.assignment_generation = 3;
    let mut other_owner = active.clone();
    other_owner.owner_descriptor = [0x5a; 32];
    for (current, label) in [(&reassigned, "stale sequence"), (&other_owner, "other owner")] {
        let changed = Context::pinned(current, &node, 1).unwrap().id();
        assert_ne!(changed, id, "{label}");
        for height in [30, 60, 61, 1_000] {
            let mut channel = new_with(&id, true, 3, 60);
            assert_eq!(
                unsafe { b8_worker_channel_expire(&mut channel, changed.as_ptr(), height, 3, 101) },
                0,
                "{label} at height {height}"
            );
            assert_eq!(channel.active, 0, "{label}");
            assert_eq!(channel.tx, [0; 32], "{label}");
            assert_eq!(channel.rx, [0; 32], "{label}");
            assert!(
                !pinned.matches_current(current, &node, 1, height, 3),
                "{label} at height {height}"
            );
        }
    }
}
