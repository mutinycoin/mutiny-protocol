use mutiny_crypto_v2::{Domain, HybridKey, Role};
use mutiny_transport_v2::*;
use std::sync::OnceLock;
fn keys() -> &'static (HybridKey, HybridKey) {
    static KEYS: OnceLock<(HybridKey, HybridKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        (
            HybridKey::generate(Role::Transport).unwrap(),
            HybridKey::generate(Role::Transport).unwrap(),
        )
    })
}
fn context() -> Context {
    let (a, b) = keys();
    Context::pinned(
        [1; 32],
        [2; 32],
        Endpoint::pinned(a.public().clone(), 1).unwrap(),
        Endpoint::pinned(b.public().clone(), 1).unwrap(),
    )
    .unwrap()
}
fn session() -> (Session, Session) {
    let (a, b) = keys();
    let ctx = context();
    let (i, h) = InitiatorPending::start(ctx.clone(), a).unwrap();
    let (r, response) = ResponderPending::accept(ctx, b, &h).unwrap();
    let (i, finish) = i.accept(a, &response).unwrap();
    let (r, tag) = r.finish(&finish).unwrap();
    let i = i.finish(&tag).unwrap();
    assert_eq!(i.id(), r.id());
    (i, r)
}
#[test]
fn public_handshake_wire_export_when_requested() {
    let (a, b) = keys();
    let ctx = context();
    let (i, hello) = InitiatorPending::start(ctx.clone(), a).unwrap();
    let (r, response) = ResponderPending::accept(ctx, b, &hello).unwrap();
    let (i, finish) = i.accept(a, &response).unwrap();
    let (r, tag) = r.finish(&finish).unwrap();
    let i = i.finish(&tag).unwrap();
    assert_eq!(i.id(), r.id());
    if std::env::var("BUILD8_EXPORT_PUBLIC_SESSION").as_deref() == Ok("1") {
        let public = serde_json::json!({"schema":"BUILD8-SYNTHETIC-PUBLIC-SESSION-WIRE-V1","synthetic":true,
            "initiator_descriptor":hex::encode(a.public().descriptor(1).unwrap()),
            "responder_descriptor":hex::encode(b.public().descriptor(1).unwrap()),
            "hello":hex::encode(hello),"response":hex::encode(response),
            "client_finished":hex::encode(finish),"server_finished":hex::encode(tag),"session_id":hex::encode(i.id())});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/session-public-wire-v1.json");
        std::fs::write(path, serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    }
}
fn meta() -> Metadata {
    Metadata {
        kind: 3,
        object: [7; 32],
        fragment: 0,
        count: 3,
        hops: 2,
    }
}
#[test]
fn complete_session_metadata_authentication_reorder_replay_and_restart() {
    let (mut i, mut r) = session();
    let m = meta();
    let f1 = i.seal(&m, &[6; 140]).unwrap();
    assert_eq!(f1.len(), 255);
    let f2 = i
        .seal(&m, b"same canonical signed object, opaque to relay")
        .unwrap();
    for at in 0..f1.len() {
        let mut bad = f1.clone();
        bad[at] ^= 1;
        assert!(r.open(&bad).is_err(), "accepted altered byte {at}");
    }
    for len in 0..f1.len() {
        assert!(r.open(&f1[..len]).is_err());
    }
    let mut trailing = f1.clone();
    trailing.push(0);
    assert!(r.open(&trailing).is_err());
    assert_eq!(
        r.open(&f2).unwrap().1,
        b"same canonical signed object, opaque to relay"
    );
    assert_eq!(r.open(&f1).unwrap(), (m.clone(), vec![6; 140]));
    assert_eq!(r.open(&f1).unwrap_err(), Error::Replay);
    assert!(i.open(&f1).is_err());
    let back = r.seal(&m, b"reverse direction").unwrap();
    assert_eq!(i.open(&back).unwrap().1, b"reverse direction");
    let (mut ni, mut nr) = session();
    assert_ne!(i.id(), ni.id());
    assert!(nr.open(&f1).is_err());
    let fresh = ni.seal(&m, b"new keys").unwrap();
    assert!(r.open(&fresh).is_err());
    assert!(nr.open(&fresh).is_ok());
    let oldest = i.seal(&m, b"will age out").unwrap();
    for _ in 0..128 {
        let f = i.seal(&m, b"advance").unwrap();
        r.open(&f).unwrap();
    }
    assert_eq!(r.open(&oldest).unwrap_err(), Error::Replay);
    assert!(i.seal(&m, &[]).is_err());
    assert!(i.seal(&m, &[0; 141]).is_err());
}
#[test]
fn both_hybrid_signatures_context_key_confirmation_and_role_separation() {
    let (a, b) = keys();
    let ctx = context();
    assert!(InitiatorPending::start(ctx.clone(), b).is_err());
    let (i, h) = InitiatorPending::start(ctx.clone(), a).unwrap();
    let (_, mut response) = ResponderPending::accept(ctx.clone(), b, &h).unwrap();
    response[1656] ^= 1;
    assert!(i.accept(a, &response).is_err());
    let (i, h) = InitiatorPending::start(ctx.clone(), a).unwrap();
    let (_, mut response) = ResponderPending::accept(ctx.clone(), b, &h).unwrap();
    response[1770] ^= 1;
    assert!(i.accept(a, &response).is_err());
    let (i, h) = InitiatorPending::start(ctx.clone(), a).unwrap();
    let (r, response) = ResponderPending::accept(ctx.clone(), b, &h).unwrap();
    let (_, mut finish) = i.accept(a, &response).unwrap();
    finish[1394] ^= 1;
    assert!(r.finish(&finish).is_err());
    let (i, h) = InitiatorPending::start(ctx.clone(), a).unwrap();
    let (r, response) = ResponderPending::accept(ctx.clone(), b, &h).unwrap();
    let (i, finish) = i.accept(a, &response).unwrap();
    let (_, mut tag) = r.finish(&finish).unwrap();
    tag[0] ^= 1;
    assert!(i.finish(&tag).is_err());
    let (_, h) = InitiatorPending::start(ctx.clone(), a).unwrap();
    // Every immutable context byte is checked before any peer key material is used.
    for at in 0..166 {
        let mut bad = h.clone();
        bad[at] ^= 1;
        assert!(ResponderPending::accept(ctx.clone(), b, &bad).is_err());
    }
    for len in [0, 165, 1810, h.len() - 1] {
        assert!(ResponderPending::accept(ctx.clone(), b, &h[..len]).is_err());
    }
    let mut bad = h.clone();
    bad[198..254].fill(0);
    assert!(ResponderPending::accept(ctx.clone(), b, &bad).is_err());
    assert!(a.sign(Domain::Transaction, b"no wallet authority").is_err());
    assert!(
        a.sign(Domain::ContinuityVote, b"no continuity authority")
            .is_err()
    );
    assert!(
        a.sign(Domain::ReleaseApproval, b"no firmware authority")
            .is_err()
    );
    let s = a
        .sign(Domain::TransportInitiator, b"role-specific transcript")
        .unwrap();
    assert!(
        a.public()
            .verify(Domain::TransportResponder, b"role-specific transcript", &s)
            .is_err()
    );
    let mut false_owner = a.public().clone();
    false_owner.role = Role::WalletOwner;
    assert!(
        false_owner
            .verify(Domain::Transaction, b"role-specific transcript", &s)
            .is_err()
    );
    assert!(Endpoint::pinned(false_owner, 1).is_err());
}
