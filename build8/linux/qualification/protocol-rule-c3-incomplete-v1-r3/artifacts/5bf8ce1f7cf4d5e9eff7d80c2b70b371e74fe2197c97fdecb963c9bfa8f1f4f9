//! Bounded typed profiles over the single canonical StateProofV2 codec.
//! These functions consume independently authenticated context/root; they do
//! not establish finality or trust a root supplied by the proof server.
use crate::{
    Error, Hash, Result,
    anchors::FinalizedAnchor,
    state_tree::StateProof,
    transactions::{Coin, OutPoint},
};

// Seven-field canonical UTXO record, with every integer at its largest width:
// array + version + tx + index + owner + atoms + height + bool = 94 bytes.
pub const MAX_UTXO_RECORD: usize = 94;
pub const MAX_UTXO_PROOF: usize = 9 * 1024;

pub const MAX_WALLET_RECORD: usize = 4 * 1024;
pub const MAX_WALLET_PROOF: usize = MAX_UTXO_PROOF + MAX_WALLET_RECORD;
/// Constructible only after inclusion/absence checks against independently
/// authenticated context/root. A server's bare descriptor cannot create this.
pub struct VerifiedWalletAuthority {
    address: Hash,
    current: Option<(Hash, Vec<u8>)>,
    context: FinalizedAnchor,
    root: Hash,
}
impl VerifiedWalletAuthority {
    pub fn descriptor(&self) -> Option<&[u8]> {
        self.current.as_ref().map(|(_, raw)| raw.as_slice())
    }
    pub fn authority(&self) -> Option<Hash> {
        self.current.as_ref().map(|(id, _)| *id)
    }
    pub fn context(&self) -> &FinalizedAnchor {
        &self.context
    }
    pub fn root(&self) -> Hash {
        self.root
    }
    pub fn authorize(&self, raw: &[u8]) -> Result<()> {
        use mutiny_crypto_v2::{PublicKey, Role};
        let (key, generation) = PublicKey::decode_descriptor(raw).map_err(|_| Error::Codec)?;
        if key.role != Role::WalletOwner {
            return Err(Error::WrongOperation);
        }
        if let Some((_, current)) = &self.current {
            if current != raw {
                return Err(Error::WrongGeneration);
            }
        } else if generation != 1
            || key.address_id(generation).map_err(|_| Error::Codec)? != self.address
        {
            return Err(Error::WrongGeneration);
        }
        Ok(())
    }
}
/// The second proof must be empty only when the queried address is absent.
/// Otherwise it proves the exact current authority record referenced by the
/// first, at the same finalized context and StateRoot.
pub fn verify_wallet_authority(
    address_proof: &[u8],
    current_proof: &[u8],
    context: &FinalizedAnchor,
    root: Hash,
    address: Hash,
) -> Result<VerifiedWalletAuthority> {
    use crate::wallet_authority_v1::{address_key, current_key, parse};
    use mutiny_crypto_v2::{PublicKey, Role};
    let proof = StateProof::decode_bounded(address_proof, MAX_WALLET_PROOF, MAX_WALLET_RECORD)?;
    let current = if let Some(raw) = proof.verify(context, root, address_key(address))? {
        let (kind, id, old) = parse(raw)?;
        let (old_key, old_generation) =
            PublicKey::decode_descriptor(&old).map_err(|_| Error::Codec)?;
        if kind != 31
            || old_key.role != Role::WalletOwner
            || old_key
                .address_id(old_generation)
                .map_err(|_| Error::Codec)?
                != address
            || (old_generation == 1 && id != address)
        {
            return Err(Error::WrongAnchor);
        }
        let proof = StateProof::decode_bounded(current_proof, MAX_WALLET_PROOF, MAX_WALLET_RECORD)?;
        let raw = proof
            .verify(context, root, current_key(id))?
            .ok_or(Error::UnknownSigner)?;
        let (kind, found, descriptor) = parse(raw)?;
        let (key, generation) =
            PublicKey::decode_descriptor(&descriptor).map_err(|_| Error::Codec)?;
        if kind != 30 || found != id || key.role != Role::WalletOwner || generation < old_generation
        {
            return Err(Error::WrongAnchor);
        }
        Some((id, descriptor))
    } else {
        if !current_proof.is_empty() {
            return Err(Error::NonCanonical);
        }
        None
    };
    Ok(VerifiedWalletAuthority {
        address,
        current,
        context: context.clone(),
        root,
    })
}

pub fn utxo_key(point: &OutPoint) -> Hash {
    crate::state_records::coin_key(point)
}

/// Inclusion returns the authenticated coin; absence returns None. Absence
/// applies only to this outpoint, and never proves the wallet's total balance.
pub fn verify_utxo(
    raw: &[u8],
    context: &FinalizedAnchor,
    root: Hash,
    point: &OutPoint,
    owner: Hash,
) -> Result<Option<Coin>> {
    let proof = StateProof::decode_bounded(raw, MAX_UTXO_PROOF, MAX_UTXO_RECORD)?;
    let Some(record) = proof.verify(context, root, utxo_key(point))? else {
        return Ok(None);
    };
    let (found, coin) = crate::state_records::coin(record).ok_or(Error::Codec)?;
    if &found != point
        || coin.output.owner != owner
        || coin.output.atoms == 0
        || coin.created_height > context.height
    {
        return Err(Error::WrongAnchor);
    }
    Ok(Some(coin))
}
