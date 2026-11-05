//! External-crate positive API compilation fixture, UNCOMPILED here.
//! This target creates no key, connection, store, or proof.
use mutinyd_v8::{hybrid_peer_admission_v2::PeerLink,
    hybrid_peer_error_v2::PeerResult,history_service_v1::VerifiedHistoryReclaim};

#[test]
fn public_direct_reclaim_consumes_the_opaque_verified_proof() {
    let consume:fn(&mut PeerLink,VerifiedHistoryReclaim)->PeerResult<()>
        =PeerLink::history_reclaim_verified;
    let _=consume;
}
