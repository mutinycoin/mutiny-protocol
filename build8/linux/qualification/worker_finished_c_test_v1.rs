unsafe extern "C" {
    fn b8_worker_finished_v2(k: *const u8, p: *const u8, t: *const u8, s: u8, o: *mut u8) -> i32;
    fn b8_worker_verify_finished_v2(
        k: *const u8,
        p: *const u8,
        t: *const u8,
        s: u8,
        tag: *const u8,
        n: usize,
    ) -> i32;
}
#[test]
fn worker_finished_matches_independent_python_and_rejects_wrong_direction_or_transcript() {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("worker-finished-public-v1.json")).unwrap();
    assert_eq!(f["public_constants_only"], true);
    let bytes = |n: &str| hex::decode(f[n].as_str().unwrap()).unwrap();
    let th = bytes("transcript");
    for sender in 0..2u8 {
        let k = bytes(if sender == 0 { "worker_tx" } else { "node_tx" });
        let p = bytes(if sender == 0 {
            "worker_prefix"
        } else {
            "node_prefix"
        });
        let expected = bytes(if sender == 0 {
            "worker_finished"
        } else {
            "node_finished"
        });
        let mut out = [0xa5; 80];
        assert_eq!(
            unsafe {
                b8_worker_finished_v2(
                    k.as_ptr(),
                    p.as_ptr(),
                    th.as_ptr(),
                    sender,
                    out.as_mut_ptr().add(32),
                )
            },
            1
        );
        assert_eq!(&out[32..48], expected);
        assert_eq!(&out[..32], &[0xa5; 32]);
        assert_eq!(&out[48..], &[0xa5; 32]);
        let verify = |key: &[u8], prefix: &[u8], th: &[u8], s: u8, tag: &[u8]| unsafe {
            b8_worker_verify_finished_v2(
                key.as_ptr(),
                prefix.as_ptr(),
                th.as_ptr(),
                s,
                tag.as_ptr(),
                tag.len(),
            )
        };
        assert_eq!(verify(&k, &p, &th, sender, &expected), 1);
        assert_eq!(verify(&k, &p, &th, 1 - sender, &expected), 0);
        for at in 0..64 {
            let mut wrong = th.clone();
            wrong[at] ^= 1;
            assert_eq!(verify(&k, &p, &wrong, sender, &expected), 0);
        }
        for at in 0..16 {
            let mut wrong = expected.clone();
            wrong[at] ^= 1;
            assert_eq!(verify(&k, &p, &th, sender, &wrong), 0);
        }
        for n in [0, 1, 15] {
            assert_eq!(verify(&k, &p, &th, sender, &expected[..n]), 0);
        }
        let mut long = expected.clone();
        long.push(0);
        assert_eq!(verify(&k, &p, &th, sender, &long), 0);
        let mut wrong = k.clone();
        wrong[0] ^= 1;
        assert_eq!(verify(&wrong, &p, &th, sender, &expected), 0);
        let mut wrong = p.clone();
        wrong[0] ^= 1;
        assert_eq!(verify(&k, &wrong, &th, sender, &expected), 0);
        let mut invalid = [0xa5; 16];
        assert_eq!(
            unsafe {
                b8_worker_finished_v2(k.as_ptr(), p.as_ptr(), th.as_ptr(), 2, invalid.as_mut_ptr())
            },
            0
        );
        assert_eq!(invalid, [0; 16]);
    }
}
