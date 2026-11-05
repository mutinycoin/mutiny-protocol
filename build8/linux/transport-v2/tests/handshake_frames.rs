use mutiny_crypto_v2::{HybridKey, Role};
use mutiny_transport_v2::{
    handshake_frames::{Kind, Reassembler, fragment},
    ingress::ResponderIngress,
    *,
};
fn deliver(
    r: &mut Reassembler,
    tag: [u8; 16],
    sender: [u8; 32],
    kind: Kind,
    bytes: &[u8],
) -> (Vec<u8>, usize, usize) {
    let frames = fragment(tag, sender, kind, bytes).unwrap();
    let n = frames.len();
    let wire = frames.iter().map(Vec::len).sum();
    // Delay first fragment and reverse all others. Duplicate delivery is harmless.
    for frame in frames.iter().skip(1).rev() {
        assert!(r.receive(kind, frame).unwrap().is_none());
        assert!(r.receive(kind, frame).unwrap().is_none());
    }
    let (id, result) = r.receive(kind, &frames[0]).unwrap().unwrap();
    assert_eq!(id, sender);
    assert_eq!(result, bytes);
    (result, n, wire)
}
#[test]
fn all_hybrid_handshake_flights_fit_radio_frames_without_relaxing_authentication() {
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let ae = Endpoint::pinned(a.public().clone(), 1).unwrap();
    let be = Endpoint::pinned(b.public().clone(), 1).unwrap();
    let (aid, bid) = (ae.id(), be.id());
    let ctx = Context::pinned([1; 32], [2; 32], ae, be).unwrap();
    let tag = ctx.network_tag();
    let mut ar = Reassembler::new(tag, vec![bid]).unwrap();
    let mut br = Reassembler::new(tag, vec![aid]).unwrap();
    let mut gate = ResponderIngress::new(vec![ctx.clone()]).unwrap();
    let (i, hello) = InitiatorPending::start(ctx.clone(), &a).unwrap();
    let (h, n1, w1) = deliver(&mut br, tag, aid, Kind::Hello, &hello);
    let response = gate.accept(aid, &b, &h).unwrap();
    let (r, n2, w2) = deliver(&mut ar, tag, bid, Kind::Response, &response);
    let (i, finish) = i.accept(&a, &r).unwrap();
    let (f, n3, w3) = deliver(&mut br, tag, aid, Kind::ClientFinish, &finish);
    let (mut receiver, finish) = gate.finish(aid, &f).unwrap();
    let (f, n4, w4) = deliver(&mut ar, tag, bid, Kind::ServerFinish, &finish);
    let mut sender = i.finish(&f).unwrap();
    let meta = Metadata {
        kind: 3,
        object: [4; 32],
        fragment: 0,
        count: 1,
        hops: 1,
    };
    let wire = sender.seal(&meta, b"public qualification object").unwrap();
    assert_eq!(
        receiver.open(&wire).unwrap().1,
        b"public qualification object"
    );
    // Fragment transport alone can reconstruct a tampered response, but cannot
    // turn that message into an authenticated session.
    let (i, h) = InitiatorPending::start(ctx, &a).unwrap();
    let mut response = gate.accept(aid, &b, &h).unwrap();
    response[1800] ^= 1;
    let (bad, _, _) = deliver(&mut ar, tag, bid, Kind::Response, &response);
    assert!(i.accept(&a, &bad).is_err());
    let report = serde_json::json!({"schema":"BUILD8-HYBRID-HANDSHAKE-FRAGMENTS-V1","result":"BOUNDED_FRAGMENTS_HYBRID_AUTHENTICATION_PASS",
        "synthetic":true,"flights":[n1,n2,n3,n4],"unique_datagrams":n1+n2+n3+n4,"unique_wire_bytes":w1+w2+w3+w4,
        "max_datagram_bytes":255,"tampered_signature_rejected":true,"radio_used":false,"production_qualified":false,
        "airtime":"Not measured; retransmissions and radio-specific overhead are additional."});
    if std::env::var("BUILD8_EXPORT_PUBLIC_TRANSPORT").as_deref() == Ok("1") {
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/handshake-fragments-v1.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    }
}
