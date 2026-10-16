//! Bounded single-request handler for the authenticated node transport.
//! The caller supplies its pinned finalized anchor; the response does not create
//! trust. Network framing, connection deadlines and concurrency stay outside.
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{
    Error, Hash,
    anchors::FinalizedAnchor,
    blocks::canonical,
    canonical_store::{CanonicalStore, ChainError},
    state_proof::{MAX_UTXO_PROOF, MAX_UTXO_RECORD, MAX_WALLET_PROOF, MAX_WALLET_RECORD},
    state_tree::{MAX_PROOF, MAX_RECORD},
};
pub const MAX_REQUEST: usize = 192;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofProfile {
    General = 0,
    Utxo = 1,
    WalletAuthority = 2,
}
impl ProofProfile {
    pub fn limits(self) -> (usize, usize) {
        match self {
            Self::General => (MAX_PROOF, MAX_RECORD),
            Self::Utxo => (MAX_UTXO_PROOF, MAX_UTXO_RECORD),
            Self::WalletAuthority => (MAX_WALLET_PROOF, MAX_WALLET_RECORD),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub anchor: FinalizedAnchor,
    pub key: Hash,
    pub profile: ProofProfile,
}
impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.anchor.encode())
            .unwrap()
            .bytes(&self.key)
            .unwrap()
            .u8(self.profile as u8)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> mutiny_consensus_v8::Result<Self> {
        canonical(raw, MAX_REQUEST)?;
        let mut d = Decoder::new(raw);
        let parsed = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("state proof request");
            if d.array()? != Some(4) || d.u8()? != 2 {
                return Err(bad());
            }
            let anchor = FinalizedAnchor::decode(d.bytes()?).map_err(|_| bad())?;
            let key = d.bytes()?.try_into().map_err(|_| bad())?;
            let profile = match d.u8()? {
                0 => ProofProfile::General,
                1 => ProofProfile::Utxo,
                2 => ProofProfile::WalletAuthority,
                _ => return Err(bad()),
            };
            Ok(Self {
                anchor,
                key,
                profile,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if parsed.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(parsed)
    }
}
/// One key per request; no recursive query, server-chosen root, or unbounded
/// batch. The canonical store reads at most 257 compressed index nodes and one
/// bounded record in a transaction, then independently verifies its own proof.
pub fn respond(store: &mut CanonicalStore, raw: &[u8]) -> Result<Vec<u8>, ChainError> {
    let request = Request::decode(raw)?;
    let proof = store.state_proof(&request.anchor, request.key)?;
    let (maximum, record_maximum) = request.profile.limits();
    if proof
        .record
        .as_ref()
        .is_some_and(|r| r.len() > record_maximum)
    {
        return Err(Error::Oversize.into());
    }
    let raw = proof.encode()?;
    if raw.len() > maximum {
        return Err(Error::Oversize.into());
    }
    Ok(raw)
}
/// Hybrid canonical store path. The request codec is unchanged: proof format
/// V2 already binds the exact finalized anchor and has explicit typed bounds.
pub fn respond_hybrid(
    store: &mutiny_consensus_v8::canonical_store_v2::CanonicalStore,
    raw: &[u8],
) -> Result<Vec<u8>, mutiny_consensus_v8::finality_v2::StoreError> {
    let request = Request::decode(raw)?;
    let proof = store.state_proof(&request.anchor, request.key)?;
    let (maximum, record_maximum) = request.profile.limits();
    if proof
        .record
        .as_ref()
        .is_some_and(|r| r.len() > record_maximum)
    {
        return Err(Error::Oversize.into());
    }
    let raw = proof.encode()?;
    if raw.len() > maximum {
        return Err(Error::Oversize.into());
    }
    Ok(raw)
}

#[cfg(test)]
mod hybrid_tests {
    use super::*;
    #[test]
    fn hybrid_store_proofs_bind_current_finality_and_typed_limits() {
        use mutiny_consensus_v8::{
            block_envelope_v2::BlockEnvelope,
            canonical_store_v2::CanonicalStore,
            execution::State,
            state_proof::{utxo_key, verify_utxo},
            state_tree::StateTree,
            transactions::OutPoint,
        };
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        assert_eq!(f["production_authorized"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let records: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let state = State::from_records(&records, root).unwrap();
        let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
        let envelope = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
        let txid: Hash = raw(&f["transaction_id"]).try_into().unwrap();
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "build8-public-hybrid-proof-{}.sqlite",
            hex::encode(nonce)
        ));
        assert!(!path.exists());
        let mut chain =
            CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, [255; 32])
                .unwrap();
        chain.commit(&envelope).unwrap();
        let anchor = envelope.certificate.decision.anchor();
        let point = OutPoint {
            transaction: txid,
            index: 0,
        };
        let request = Request {
            anchor: anchor.clone(),
            key: utxo_key(&point),
            profile: ProofProfile::Utxo,
        };
        let proof = respond_hybrid(&chain, &request.encode()).unwrap();
        assert_eq!(
            verify_utxo(
                &proof,
                &anchor,
                envelope.header.candidate.state_root,
                &point,
                [94; 32]
            )
            .unwrap()
            .unwrap()
            .output
            .atoms,
            95000
        );
        let (_, post) = chain.load().unwrap();
        let mut tree = StateTree::default();
        for (key, value) in post.records().unwrap() {
            tree.insert(key, value).unwrap();
        }
        assert_eq!(
            proof,
            tree.proof(anchor.clone(), request.key).encode().unwrap()
        );
        let mut stale = request.clone();
        stale.anchor = genesis;
        assert!(respond_hybrid(&chain, &stale.encode()).is_err());
        let mut wrong = request.clone();
        wrong.anchor.genesis[0] ^= 1;
        assert!(respond_hybrid(&chain, &wrong.encode()).is_err());
        let mut trailing = request.encode();
        trailing.push(0);
        assert!(respond_hybrid(&chain, &trailing).is_err());
        let oversized = post
            .records()
            .unwrap()
            .into_iter()
            .find(|(_, raw)| raw.len() > MAX_UTXO_RECORD)
            .unwrap()
            .0;
        let wrong_type = Request {
            anchor: anchor.clone(),
            key: oversized,
            profile: ProofProfile::Utxo,
        };
        assert!(respond_hybrid(&chain, &wrong_type.encode()).is_err());
        let absent = OutPoint {
            transaction: [0; 32],
            index: 0,
        };
        let absence = Request {
            anchor: anchor.clone(),
            key: utxo_key(&absent),
            profile: ProofProfile::Utxo,
        };
        let proof = respond_hybrid(&chain, &absence.encode()).unwrap();
        assert!(
            verify_utxo(
                &proof,
                &anchor,
                envelope.header.candidate.state_root,
                &absent,
                [94; 32]
            )
            .unwrap()
            .is_none()
        );
        assert!(
            verify_utxo(
                &proof,
                &anchor,
                envelope.header.candidate.state_root,
                &point,
                [94; 32]
            )
            .is_err()
        );
        drop(chain);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn hybrid_wallet_authority_proofs_survive_restart_with_typed_bounds() {
        use mutiny_consensus_v8::{canonical_store_v2::CanonicalStore, execution::State};
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        assert_eq!(f["production_authorized"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let records: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let mut initial = State::from_records(&records, root).unwrap();
        let anchor = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
        let wallet: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/wallet-rotation-public-v1.json"
        ))
        .unwrap();
        let wallet_descriptor = hex::decode(wallet["current"].as_str().unwrap()).unwrap();
        let wallet_id = initial.wallets.register(&wallet_descriptor).unwrap();

        let root = initial.root().unwrap();
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "build8-hybrid-wallet-proof-{}.sqlite",
            hex::encode(nonce)
        ));
        assert!(!path.exists());
        let open = || {
            CanonicalStore::open_trusted_genesis(&path, &anchor, &initial, root, 1000, [255; 32])
        };
        let store = open().unwrap();
        let wallet_request = Request {
            anchor: anchor.clone(),
            key: mutiny_consensus_v8::wallet_authority_v1::address_key(wallet_id),
            profile: ProofProfile::WalletAuthority,
        };
        assert_eq!(
            Request::decode(&wallet_request.encode()).unwrap(),
            wallet_request
        );
        let address_proof = respond_hybrid(&store, &wallet_request.encode()).unwrap();
        let current_request = Request {
            key: mutiny_consensus_v8::wallet_authority_v1::current_key(wallet_id),
            ..wallet_request.clone()
        };
        let current_proof = respond_hybrid(&store, &current_request.encode()).unwrap();
        let verified = mutiny_consensus_v8::state_proof::verify_wallet_authority(
            &address_proof,
            &current_proof,
            &anchor,
            root,
            wallet_id,
        )
        .unwrap();
        verified.authorize(&wallet_descriptor).unwrap();
        let too_small = Request {
            profile: ProofProfile::Utxo,
            ..wallet_request.clone()
        };
        assert!(respond_hybrid(&store, &too_small.encode()).is_err());
        let mut unknown = wallet_request.encode();
        *unknown.last_mut().unwrap() = 3;
        assert!(Request::decode(&unknown).is_err());

        drop(store);
        let store = open().unwrap();
        assert_eq!(
            respond_hybrid(&store, &wallet_request.encode()).unwrap(),
            address_proof
        );
        assert_eq!(
            respond_hybrid(&store, &current_request.encode()).unwrap(),
            current_proof
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::{
        NETWORK_ID, blocks::GenesisDescriptor, execution::State, genesis::GenesisIdentity,
        licenses::BindWorker, state_tree::StateProof,
    };
    #[test]
    fn canonical_snapshot_only_bounded_query_and_restart_rebuild() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
        ))
        .unwrap();
        let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let descriptor = GenesisDescriptor::decode(&bytes(&v["descriptor_hex"])).unwrap();
        let identity = GenesisIdentity::new(descriptor.clone()).unwrap();
        let bindings: Vec<_> = v["cases"][0]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| BindWorker::decode(&bytes(&b["binding_hex"])).unwrap())
            .collect();
        let initial = State {
            licenses: identity.bind_workers(&bindings).unwrap(),
            ..State::default()
        };
        let path = std::env::temp_dir().join(format!(
            "build8-proof-service-{}.sqlite",
            std::process::id()
        ));
        assert!(!path.exists());
        let mut store =
            CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, [255; 32]).unwrap();
        let (tip, _) = store.load().unwrap();
        let anchor = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: identity.id(),
            fingerprint: descriptor.fingerprint,
            height: 0,
            block: tip.block,
        };
        let key = initial.records().unwrap()[0].0;
        let request = Request {
            anchor: anchor.clone(),
            key,
            profile: ProofProfile::General,
        };
        let raw = respond(&mut store, &request.encode()).unwrap();
        StateProof::decode(&raw)
            .unwrap()
            .verify(&anchor, tip.root, key)
            .unwrap();
        let mut stale = request.clone();
        stale.anchor.height = 1;
        assert!(respond(&mut store, &stale.encode()).is_err());
        let mut trailing = request.encode();
        trailing.push(0);
        assert!(respond(&mut store, &trailing).is_err());
        assert!(respond(&mut store, &[0; MAX_REQUEST + 1]).is_err());
        let absent = Request {
            key: [0; 32],
            profile: ProofProfile::Utxo,
            ..request.clone()
        };
        let p = respond(&mut store, &absent.encode()).unwrap();
        assert!(
            StateProof::decode(&p)
                .unwrap()
                .verify(&anchor, tip.root, absent.key)
                .unwrap()
                .is_none()
        );
        drop(store);
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute("DELETE FROM state_merkle_nodes", []).unwrap();
        drop(db);
        let mut store =
            CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, [255; 32]).unwrap();
        assert_eq!(respond(&mut store, &request.encode()).unwrap(), raw);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
