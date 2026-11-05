//! Invoked by the integrated certified rotation fixture; synthetic envelopes only.
use super::*;
use mutiny_consensus_v8::anchors::FinalizedAnchor;
use std::os::unix::fs::PermissionsExt;

pub(crate) fn before_install(
    chain: &CanonicalStore,
    operation: &NodeKeyRotate,
    directory: &Path,
    old_encrypted: &[u8],
    proposed_encrypted: &[u8],
    password: &str,
) -> std::path::PathBuf {
    let proposed = directory.join("proposed");
    std::fs::create_dir(&proposed).unwrap();
    std::fs::set_permissions(&proposed, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(publish(chain, operation, &proposed, old_encrypted, password).is_err());
    assert!(
        publish(
            chain,
            operation,
            &proposed,
            proposed_encrypted,
            "wrong synthetic password"
        )
        .is_err()
    );
    for field in 0..5 {
        let mut bad = operation.clone();
        match field {
            0 => bad.authorization.ed448[0] ^= 1,
            1 => bad.authorization.fndsa[0] ^= 1,
            2 => bad.possession.ed448[0] ^= 1,
            3 => bad.possession.fndsa[0] ^= 1,
            _ => bad.sequence += 1,
        }
        assert!(publish(chain, &bad, &proposed, proposed_encrypted, password).is_err());
    }
    assert_eq!(std::fs::read_dir(&proposed).unwrap().count(), 0);
    let context = publish(chain, operation, &proposed, proposed_encrypted, password).unwrap();
    let (_, generation) = PublicKey::decode_descriptor(&operation.proposed).unwrap();
    assert_eq!(
        crate::continuity_generation_store_v2::read_node(&proposed, context, generation).unwrap(),
        proposed_encrypted
    );
    assert!(publish(chain, operation, &proposed, proposed_encrypted, password).is_err());
    assert!(
        crate::node_custody_v2::EncryptedNodeKey::unlock_generation_file(
            chain,
            &operation.parent,
            operation.node,
            &proposed,
            password
        )
        .is_err()
    );
    proposed
}

pub(crate) fn after_install(
    chain: &CanonicalStore,
    operation: &NodeKeyRotate,
    anchor: &FinalizedAnchor,
    proposed: &Path,
    encrypted: &[u8],
    password: &str,
) {
    assert!(
        crate::node_custody_v2::EncryptedNodeKey::unlock_generation_file(
            chain,
            anchor,
            operation.node,
            proposed,
            password
        )
        .is_ok()
    );
    assert!(publish(chain, operation, proposed, encrypted, password).is_err());
    assert_eq!(std::fs::read_dir(proposed).unwrap().count(), 1);
}
