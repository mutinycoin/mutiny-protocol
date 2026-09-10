// Mutiny Protocol V1.0 domain-separation registry.
// Exact ASCII bytes; no NUL terminators.

pub const GENESIS_ID: &[u8] = b"MUTINY-GENESIS-ID-V1";
pub const CONSENSUS_PARAMS: &[u8] = b"MUTINY-CONSENSUS-PARAMS-V1";
pub const EPOCH_SEED: &[u8] = b"MUTINY-EPOCH-SEED-V1";
pub const TICKET_SEED: &[u8] = b"MUTINY-TICKET-SEED-V1";
pub const ARGON2_SALT: &[u8] = b"MUTINY-ARGON2-SALT-V1";
pub const BLOCK_SIGN: &[u8] = b"MUTINY-BLOCK-SIGN-V1";
pub const BLOCK_ID: &[u8] = b"MUTINY-BLOCK-ID-V1";
pub const TX_ID: &[u8] = b"MUTINY-TX-ID-V1";
pub const WTX_ID: &[u8] = b"MUTINY-WTX-ID-V1";
pub const TX_SIGN: &[u8] = b"MUTINY-TX-SIGN-V1";
pub const ADDRESS: &[u8] = b"MUTINY-ADDRESS-V1";
pub const TX_LEAF: &[u8] = b"MUTINY-TX-LEAF-V1";
pub const TX_NODE: &[u8] = b"MUTINY-TX-NODE-V1";
pub const PROTOCOL_OP_ID: &[u8] = b"MUTINY-PROTOCOL-OP-ID-V1";
pub const PROTOCOL_OP_LEAF: &[u8] = b"MUTINY-PROTOCOL-OP-LEAF-V1";
pub const PROTOCOL_OP_NODE: &[u8] = b"MUTINY-PROTOCOL-OP-NODE-V1";
pub const PROTOCOL_OPS_EMPTY: &[u8] = b"MUTINY-PROTOCOL-OPS-EMPTY-V1";
pub const STATE_ROOT: &[u8] = b"MUTINY-STATE-ROOT-V1";
pub const META_ROOT: &[u8] = b"MUTINY-META-ROOT-V1";
pub const UTXO_KEY: &[u8] = b"MUTINY-UTXO-KEY-V1";
pub const UTXO_LEAF: &[u8] = b"MUTINY-UTXO-LEAF-V1";
pub const LICENSE_LEAF: &[u8] = b"MUTINY-LICENSE-LEAF-V1";
pub const EXTERNAL_PAYMENT_LEAF: &[u8] = b"MUTINY-EXTERNAL-PAYMENT-LEAF-V1";
pub const PROTOCOL_STATE_LEAF: &[u8] = b"MUTINY-PROTOCOL-STATE-LEAF-V1";
pub const SMT_EMPTY_LEAF: &[u8] = b"MUTINY-SMT-EMPTY-LEAF-V1";
pub const SMT_NODE: &[u8] = b"MUTINY-SMT-NODE-V1";
pub const LICENSE_ID: &[u8] = b"MUTINY-LICENSE-ID-V1";
pub const BTC_PAYMENT_ID: &[u8] = b"MUTINY-BTC-PAYMENT-ID-V1";
pub const NODE_ID: &[u8] = b"MUTINY-NODE-ID-V1";
pub const P2P_CHECKSUM: &[u8] = b"MUTINY-P2P-CHECKSUM-V1";
pub const PUNISHMENT_EVIDENCE_ID: &[u8] = b"MUTINY-PUNISHMENT-EVIDENCE-ID-V1";
pub const MUT_PAYMENT_ID: &[u8] = b"MUTINY-MUT-PAYMENT-ID-V1";
pub const PROTOCOL_STATE_KEY: &[u8] = b"MUTINY-PROTOCOL-STATE-KEY-V1";
pub const PROTOCOL_OP_SIGN: &[u8] = b"MUTINY-PROTOCOL-OP-SIGN-V1";
pub const ANCHOR_ENTROPY: &[u8] = b"MUTINY-ANCHOR-ENTROPY-V1";
pub const MUT_LICENSE_MANIFEST: &[u8] = b"MUTINY-MUT-LICENSE-MANIFEST-V1";
pub const BLOCK_TEMPLATE_ID: &[u8] = b"MUTINY-BLOCK-TEMPLATE-ID-V1";
pub const P2P_HANDSHAKE: &[u8] = b"MUTINY-P2P-HANDSHAKE-V1";
pub const P2P_HELLO_SIGN: &[u8] = b"MUTINY-P2P-HELLO-SIGN-V1";
pub const P2P_ACK_SIGN: &[u8] = b"MUTINY-P2P-ACK-SIGN-V1";
pub const LORA_ORIGIN_TAG: &[u8] = b"MUTINY-LORA-ORIGIN-TAG-V1";
pub const LORA_OBJECT: &[u8] = b"MUTINY-LORA-OBJECT-V1";
pub const LORA_MESSAGE_ID: &[u8] = b"MUTINY-LORA-MESSAGE-ID-V1";
pub const TREASURY_ID: &[u8] = b"MUTINY-TREASURY-ID-V1";
pub const BTC_MANIFEST: &[u8] = b"MUTINY-BTC-MANIFEST-V1";
pub const BOOTSTRAP_MANIFEST: &[u8] = b"MUTINY-BOOTSTRAP-MANIFEST-V1";
pub const BOOTSTRAP_COMMITMENT: &[u8] = b"MUTINY-BOOTSTRAP-COMMITMENT-V1";
pub const PROTOCOL_FINGERPRINT: &[u8] = b"MUTINY-PROTOCOL-FINGERPRINT-V1";

pub const ALL_DOMAINS: [&[u8]; 48] = [
    GENESIS_ID,
    CONSENSUS_PARAMS,
    EPOCH_SEED,
    TICKET_SEED,
    ARGON2_SALT,
    BLOCK_SIGN,
    BLOCK_ID,
    TX_ID,
    WTX_ID,
    TX_SIGN,
    ADDRESS,
    TX_LEAF,
    TX_NODE,
    PROTOCOL_OP_ID,
    PROTOCOL_OP_LEAF,
    PROTOCOL_OP_NODE,
    PROTOCOL_OPS_EMPTY,
    STATE_ROOT,
    META_ROOT,
    UTXO_KEY,
    UTXO_LEAF,
    LICENSE_LEAF,
    EXTERNAL_PAYMENT_LEAF,
    PROTOCOL_STATE_LEAF,
    SMT_EMPTY_LEAF,
    SMT_NODE,
    LICENSE_ID,
    BTC_PAYMENT_ID,
    NODE_ID,
    P2P_CHECKSUM,
    PUNISHMENT_EVIDENCE_ID,
    MUT_PAYMENT_ID,
    PROTOCOL_STATE_KEY,
    PROTOCOL_OP_SIGN,
    ANCHOR_ENTROPY,
    MUT_LICENSE_MANIFEST,
    BLOCK_TEMPLATE_ID,
    P2P_HANDSHAKE,
    P2P_HELLO_SIGN,
    P2P_ACK_SIGN,
    LORA_ORIGIN_TAG,
    LORA_OBJECT,
    LORA_MESSAGE_ID,
    TREASURY_ID,
    BTC_MANIFEST,
    BOOTSTRAP_MANIFEST,
    BOOTSTRAP_COMMITMENT,
    PROTOCOL_FINGERPRINT,
];

pub fn sorted_domains() -> Vec<&'static [u8]> {
    let mut out = ALL_DOMAINS.to_vec();
    out.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn registry_is_exactly_48_unique_domains() {
        assert_eq!(ALL_DOMAINS.len(), 48);
        let set: BTreeSet<Vec<u8>> = ALL_DOMAINS.iter().map(|d| d.to_vec()).collect();
        assert_eq!(set.len(), 48);
    }

    #[test]
    fn domains_are_ascii_and_have_no_nul() {
        for domain in ALL_DOMAINS {
            assert!(domain.is_ascii());
            assert!(!domain.contains(&0));
        }
    }
}
