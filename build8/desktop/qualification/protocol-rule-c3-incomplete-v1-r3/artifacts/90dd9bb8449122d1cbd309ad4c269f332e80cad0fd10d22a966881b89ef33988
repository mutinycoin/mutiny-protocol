//! Linux-only publication of an already encrypted proposed Node generation.
//! This grants no signer, changes no canonical state and generates no keys.
#![cfg(target_os = "linux")]
use mutiny_consensus_v8::{
    Hash, canonical_store_v2::CanonicalStore, node_key_rotate_v2::NodeKeyRotate,
};
use mutiny_crypto_v2::{HybridKey, PublicKey, Role};
use std::path::Path;
type Result<T> = std::result::Result<T, String>;

fn validate(chain: &CanonicalStore, operation: &NodeKeyRotate) -> Result<Hash> {
    let pins = chain
        .current_node_authority(&operation.parent, operation.node)
        .map_err(|_| "Proposed Node generation has no current authority")?;
    let (parent, state, _) = chain
        .execution_parent(operation.parent.height)
        .map_err(|_| "Proposed Node generation parent unavailable")?;
    if parent.block != operation.parent.block
        || parent.genesis != operation.parent.genesis
        || parent.fingerprint != operation.parent.fingerprint
    {
        return Err("Proposed Node generation parent mismatch".into());
    }
    operation
        .verify(&operation.parent, &pins.control(), &state.wallets)
        .map_err(|_| "Proposed Node rotation authorization invalid")?;
    let current = chain
        .current_node_authority(&operation.parent, operation.node)
        .map_err(|_| "Node authority changed during preparation")?;
    if current.context() != pins.context() {
        return Err("Node generation changed during preparation".into());
    }
    mutiny_consensus_v8::node_authority_v2::custody_context(
        operation.parent.genesis,
        operation.parent.fingerprint,
        operation.node,
        operation.hardware_generation,
        &operation.proposed,
    )
    .map_err(|_| "Proposed Node custody context invalid".into())
}

/// Validate both rotation signatures and proposed encrypted key possession,
/// then publish create-only with file+directory synchronization. The return value
/// is public AAD, not authority. Only later canonical installation allows the
/// ordinary EncryptedNodeKey::unlock_generation_file path to use this envelope.
/// Failure may leave a complete encrypted file; never auto-delete or overwrite.
/// Full consensus transition validation still occurs at candidate execution.
pub fn publish(
    chain: &CanonicalStore,
    operation: &NodeKeyRotate,
    directory: &Path,
    encrypted: &[u8],
    password: &str,
) -> Result<Hash> {
    let context = validate(chain, operation)?;
    let (key, generation) = HybridKey::open_for(Role::Node, password, &context, encrypted)
        .map_err(|_| "Proposed Node envelope authentication failed")?;
    if key
        .public()
        .descriptor(generation)
        .map_err(|_| "Node descriptor")?
        != operation.proposed
    {
        return Err("Proposed Node envelope generation mismatch".into());
    }
    let (_, expected_generation) = PublicKey::decode_descriptor(&operation.proposed)
        .map_err(|_| "Proposed Node descriptor invalid")?;
    drop(key);
    if validate(chain, operation)? != context {
        return Err("Proposed Node context changed before publication".into());
    }
    crate::continuity_generation_store_v2::publish_node(
        directory,
        context,
        expected_generation,
        encrypted,
    )
    .map_err(str::to_owned)?;
    if validate(chain, operation)? != context {
        return Err("Proposed Node context changed during publication".into());
    }
    Ok(context)
}

#[cfg(test)]
#[path = "node_generation_preparation_v2_tests.rs"]
pub(crate) mod tests;
