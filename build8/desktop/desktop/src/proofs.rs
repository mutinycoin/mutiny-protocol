//! Wallet proof verification only. The sync/finality layer must authenticate
//! the supplied anchor before calling this API. A node response cannot pin it.
use mutiny_consensus_v8::{
    Error, Hash, Result,
    anchors::FinalizedAnchor,
    pow::{MAX_HEADER_BYTES, WorkHeader},
    state_proof::verify_utxo,
    transactions::{Coin, OutPoint},
};

pub fn utxo_at_finalized_header(
    header: &[u8],
    authenticated: &FinalizedAnchor,
    proof: &[u8],
    point: &OutPoint,
    owner: Hash,
) -> Result<Option<Coin>> {
    if header.len() > MAX_HEADER_BYTES {
        return Err(Error::Oversize);
    }
    let header = WorkHeader::decode(header)?;
    let c = &header.candidate;
    if c.network != authenticated.network
        || c.genesis != authenticated.genesis
        || c.fingerprint != authenticated.fingerprint
        || c.height != authenticated.height
        || header.block_hash() != authenticated.block
    {
        return Err(Error::WrongAnchor);
    }
    verify_utxo(proof, authenticated, c.state_root, point, owner)
}

/// The caller authenticates finality independently; this binds both wallet
/// authority witnesses to that exact block's committed StateRoot.
pub fn wallet_authority_at_finalized_header(
    header: &[u8],
    authenticated: &FinalizedAnchor,
    address_proof: &[u8],
    current_proof: &[u8],
    address: Hash,
) -> Result<mutiny_consensus_v8::state_proof::VerifiedWalletAuthority> {
    if header.len() > MAX_HEADER_BYTES {
        return Err(Error::Oversize);
    }
    let header = WorkHeader::decode(header)?;
    let c = &header.candidate;
    if c.network != authenticated.network
        || c.genesis != authenticated.genesis
        || c.fingerprint != authenticated.fingerprint
        || c.height != authenticated.height
        || header.block_hash() != authenticated.block
    {
        return Err(Error::WrongAnchor);
    }
    mutiny_consensus_v8::state_proof::verify_wallet_authority(
        address_proof,
        current_proof,
        authenticated,
        c.state_root,
        address,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_python_wallet_proof_and_untrusted_header_rejection() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/STATE-PROOF-V2-TYPED-VECTORS-V1.json"
        ))
        .unwrap();
        let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let anchor = FinalizedAnchor::decode(&bytes(&v["context"])).unwrap();
        let header = bytes(&v["header"]);
        let owner: Hash = bytes(&v["owner"]).try_into().unwrap();
        let point = OutPoint {
            transaction: bytes(&v["utxo_transaction"]).try_into().unwrap(),
            index: 0,
        };
        let p = v["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["key"] == v["utxo_key"])
            .unwrap();
        let proof = bytes(&p["proof"]);
        let coin = utxo_at_finalized_header(&header, &anchor, &proof, &point, owner)
            .unwrap()
            .unwrap();
        assert_eq!(coin.output.atoms, 100_000_000);
        assert_eq!(coin.created_height, 1);
        assert!(coin.coinbase);
        let mut wrong = WorkHeader::decode(&header).unwrap();
        wrong.candidate.state_root[0] ^= 1;
        assert!(utxo_at_finalized_header(&wrong.encode(), &anchor, &proof, &point, owner).is_err());
        let mut wrong_anchor = anchor.clone();
        wrong_anchor.height += 1;
        assert!(utxo_at_finalized_header(&header, &wrong_anchor, &proof, &point, owner).is_err());
        let absent = OutPoint {
            transaction: [0; 32],
            index: 0,
        };
        assert!(
            utxo_at_finalized_header(&header, &anchor, &bytes(&v["absent_proof"]), &absent, owner)
                .unwrap()
                .is_none()
        );
        assert!(
            utxo_at_finalized_header(&header, &anchor, &bytes(&v["absent_proof"]), &point, owner)
                .is_err()
        );
    }
}
