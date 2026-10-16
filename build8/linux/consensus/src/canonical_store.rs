//! Atomic successor-block/state/mempool persistence. Historical conflict proofs,
//! lifecycle-derived authority, checkpoints/pruning and production node services
//! remain separate integration gates. Never feed peer-chosen expected authority.
use crate::{
    Error, Hash,
    anchors::FinalizedAnchor,
    block_envelope::BlockEnvelope,
    blocks::GenesisDescriptor,
    certificates::{Decision, Voter},
    execution::{ExecutionError, State, WorkParent},
    mempool::{MAX_PENDING_BYTES, Mempool, PoolError},
    pow::target_after_height,
};
pub mod recovery_transport;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
pub mod checkpoint;
pub mod evidence_pool;
#[derive(Debug)]
pub enum ChainError {
    EvidenceCapacity,
    Storage(rusqlite::Error),
    Invalid(Error),
    Execution(ExecutionError),
    Pool(PoolError),
    WrongGenesis,
    StaleParent,
    Integrity,
    Finality(crate::finality::FinalityError),
}
impl From<rusqlite::Error> for ChainError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<Error> for ChainError {
    fn from(e: Error) -> Self {
        Self::Invalid(e)
    }
}
impl From<ExecutionError> for ChainError {
    fn from(e: ExecutionError) -> Self {
        Self::Execution(e)
    }
}
impl From<PoolError> for ChainError {
    fn from(e: PoolError) -> Self {
        Self::Pool(e)
    }
}
type Result<T> = std::result::Result<T, ChainError>;
/// The historical store is not a fallback for hybrid authority. In particular,
/// its Ed25519 recovery overlay must never mutate a state containing V2 roles.
fn require_legacy_state(state: &State) -> Result<()> {
    if state.wallets.public_descriptors().next().is_some()
        || !state.licenses_v2.is_empty()
        || !state.continuity_keys_v2.is_empty()
        || !state.membership_v2.is_empty()
        || state.admission_policy_v2.is_some()
        || state.recovery_authority_v2.is_some()
        || !state.recovery_history_v2.is_empty()
        || !state.node_key_history_v2.is_empty()
        || !state.retired_continuity_v2.is_empty()
        || !state.bonds_v2.is_empty()
        || !state.penalties_v2.is_empty()
    {
        return Err(ExecutionError::UnsupportedOperation.into());
    }
    Ok(())
}
#[cfg(test)]
mod hybrid_fence_tests {
    use super::*;
    #[test]
    fn legacy_store_rejects_hybrid_genesis_load_and_recovery_before_mutation() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(fixture["synthetic_only"], true);
        assert_eq!(fixture["production_authorized"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&fixture["root"]).try_into().unwrap();
        let records: Vec<_> = fixture["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let hybrid = State::from_records(&records, root).unwrap();
        let owner = hybrid
            .continuity_keys_v2
            .bindings()
            .next()
            .unwrap()
            .owner_descriptor()
            .to_vec();
        let mut wallet = crate::wallet_authority_v1::WalletBook::default();
        wallet.register(&owner).unwrap();
        let policy = crate::admission_policy_v2::Record::new(crate::admission_v2::Policy {
            genesis: hybrid.continuity.as_ref().unwrap().genesis,
            fingerprint: hybrid.continuity.as_ref().unwrap().fingerprint,
            owner_descriptor: owner,
            endorsement_roots: [[1; 32]].into_iter().collect(),
        })
        .unwrap();
        assert!(require_legacy_state(&State::default()).is_ok());
        for one in [
            State {
                wallets: wallet,
                ..State::default()
            },
            State {
                licenses_v2: hybrid.licenses_v2.clone(),
                ..State::default()
            },
            State {
                continuity_keys_v2: hybrid.continuity_keys_v2.clone(),
                ..State::default()
            },
            State {
                membership_v2: hybrid.membership_v2.clone(),
                ..State::default()
            },
            State {
                admission_policy_v2: Some(policy),
                ..State::default()
            },
        ] {
            assert!(matches!(
                require_legacy_state(&one),
                Err(ChainError::Execution(ExecutionError::UnsupportedOperation))
            ));
        }
        let old: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
        ))
        .unwrap();
        let descriptor = GenesisDescriptor::decode(&raw(&old["descriptor_hex"])).unwrap();
        let mut random = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "build8-legacy-hybrid-fence-{}.sqlite",
            hex::encode(random)
        ));
        assert!(!path.exists());
        assert!(matches!(
            CanonicalStore::open_trusted_genesis(&path, &descriptor, &hybrid, [255; 32]),
            Err(ChainError::Execution(ExecutionError::UnsupportedOperation))
        ));
        assert!(!path.exists(), "rejection must precede database creation");
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE chain_state(key BLOB PRIMARY KEY,value BLOB NOT NULL)")
            .unwrap();
        for (key, value) in &records {
            db.execute(
                "INSERT INTO chain_state VALUES(?1,?2)",
                params![key.as_slice(), value],
            )
            .unwrap();
        }
        assert!(matches!(
            state(&db, root),
            Err(ChainError::Execution(ExecutionError::UnsupportedOperation))
        ));
        let changes = db.total_changes();
        let mut current = hybrid.clone();
        let head = Tip {
            height: 0,
            block: [1; 32],
            root,
            next_target: [255; 32],
            timestamp: 1000,
        };
        assert!(matches!(
            apply_accepted_recovery(&db, &head, &mut current),
            Err(ChainError::Execution(ExecutionError::UnsupportedOperation))
        ));
        assert_eq!(db.total_changes(), changes);
        assert!(
            current == hybrid,
            "recovery fence must leave complete state unchanged"
        );
    }
}
fn evidence_history(
    db: &Connection,
    body: &crate::blocks::BlockBody,
    genesis: Hash,
    fingerprint: Hash,
) -> Result<crate::equivocation::EvidenceHistory> {
    let mut result = crate::equivocation::EvidenceHistory::new();
    for raw in &body.operations {
        if crate::blocks::operation_kind(raw)? != 17 {
            continue;
        }
        let proof = crate::equivocation::Evidence::decode(raw)?;
        let e = proof.a.decision.height;
        if !crate::bonds::actionable(e, body.height) {
            return Err(Error::InvalidCounter.into());
        }
        if result.contains_key(&e) {
            continue;
        }
        let head = history_tip(db, e - 1)?;
        let mut state = historical_state(db, &head)?;
        apply_accepted_recovery(db, &head, &mut state)?;
        let parent = FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis,
            fingerprint,
            height: e - 1,
            block: head.block,
        };
        let registry = state.continuity.ok_or(Error::UnqualifiedPhysical)?;
        result.insert(
            e,
            crate::equivocation::HistoricalAuthority { parent, registry },
        );
    }
    Ok(result)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tip {
    pub height: u64,
    pub block: Hash,
    pub root: Hash,
    pub next_target: Hash,
    pub timestamp: u64,
}
fn hash(raw: Vec<u8>) -> Result<Hash> {
    raw.try_into().map_err(|_| ChainError::Integrity)
}
fn counter(raw: Vec<u8>) -> Result<u64> {
    Ok(u64::from_be_bytes(
        raw.try_into().map_err(|_| ChainError::Integrity)?,
    ))
}
fn tip(db: &Connection) -> Result<Tip> {
    type Row = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let (height,block,root,target,timestamp):Row=db.query_row("SELECT height,block,root,next_target,timestamp FROM chain_history ORDER BY height DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    Ok(Tip {
        height: counter(height)?,
        block: hash(block)?,
        root: hash(root)?,
        next_target: hash(target)?,
        timestamp: counter(timestamp)?,
    })
}
fn state(db: &Connection, root: Hash) -> Result<State> {
    let mut statement = db.prepare("SELECT key,value FROM chain_state ORDER BY key")?;
    let mut records = Vec::new();
    for row in statement.query_map([], |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
    })? {
        let (key, value) = row?;
        records.push((hash(key)?, value));
        if records.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity.into());
        }
    }
    let loaded = State::from_records(&records, root)?;
    require_legacy_state(&loaded)?;
    Ok(loaded)
}
fn history_tip(db: &Connection, height: u64) -> Result<Tip> {
    type Row = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let (block, root, target, timestamp): Row = db.query_row(
        "SELECT block,root,next_target,timestamp FROM chain_history WHERE height=?1",
        [height.to_be_bytes().as_slice()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    Ok(Tip {
        height,
        block: hash(block)?,
        root: hash(root)?,
        next_target: hash(target)?,
        timestamp: counter(timestamp)?,
    })
}
fn historical_state(db: &Connection, parent: &Tip) -> Result<State> {
    let current = tip(db)?;
    let mut records: BTreeMap<_, _> = state(db, current.root)?.records()?.into_iter().collect();
    let mut q =
        db.prepare("SELECT key,previous FROM chain_undo WHERE height>?1 ORDER BY height DESC,key")?;
    for row in q.query_map([parent.height.to_be_bytes().as_slice()], |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<Vec<u8>>>(1)?))
    })? {
        let (key, old) = row?;
        let key = hash(key)?;
        if let Some(value) = old {
            records.insert(key, value);
        } else {
            records.remove(&key);
        }
    }
    let loaded = State::from_records(&records.into_iter().collect::<Vec<_>>(), parent.root)?;
    require_legacy_state(&loaded)?;
    Ok(loaded)
}
fn apply_accepted_recovery(db: &Connection, head: &Tip, current: &mut State) -> Result<()> {
    require_legacy_state(current)?;
    type OverlayRow = (Vec<u8>, Vec<u8>, Vec<u8>);
    let row: Option<OverlayRow> = db
        .query_row(
            "SELECT base_block,certificate,losses FROM recovery_overlay WHERE base_height=?1",
            [head.height.to_be_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((block, raw, loss_bytes)) = row else {
        return Ok(());
    };
    if block != head.block {
        return Err(ChainError::Integrity);
    }
    let cert = crate::recovery::Certificate::decode(&raw)?;
    if current.penalties.revoked(cert.body.lineage) {
        return Err(Error::WrongGeneration.into());
    }
    let mut d = minicbor::Decoder::new(&loss_bytes);
    let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
    if n > 1024 {
        return Err(Error::Capacity.into());
    }
    let mut losses = vec![];
    for _ in 0..n {
        if d.array().map_err(|_| Error::Codec)? != Some(2) {
            return Err(Error::Codec.into());
        }
        let lineage = d
            .bytes()
            .map_err(|_| Error::Codec)?
            .try_into()
            .map_err(|_| Error::Codec)?;
        losses.push((lineage, d.u64().map_err(|_| Error::Codec)?));
    }
    if d.position() != loss_bytes.len() {
        return Err(Error::NonCanonical.into());
    }
    // This private path replays only an already accepted local database record.
    // Incoming proofs MUST use accept_bootstrap_recovery's physical verifier.
    // Registry/certificate/signature/anchor/loss checks are repeated on restart.
    struct AcceptedPhysical;
    impl crate::recovery::PhysicalAdmissionVerifier for AcceptedPhysical {
        fn verify_replacement(&self, _: &crate::recovery::Recovery) -> crate::Result<()> {
            Ok(())
        }
    }
    let registry = current
        .continuity
        .as_mut()
        .ok_or(Error::UnqualifiedPhysical)?;
    registry.anchor = crate::recovery::Anchor {
        height: head.height,
        tip: head.block,
        state_root: head.root,
        registry_root: registry.roots()?.0,
    };
    let witness: Option<Vec<u8>> = db
        .query_row(
            "SELECT witness FROM recovery_material WHERE base_height=?1",
            [head.height.to_be_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    let witness = witness
        .map(|raw| crate::recovery_material::RecoveryMaterial::decode(&raw))
        .transpose()?;
    // Replay re-verifies the material (carry_recovery_material) under the state's class; a
    // Production-class state never replays a witness-less recovery.
    if current.admission.policy.is_some() != witness.is_some()
        || (witness.is_none()
            && current.admission_class()? == crate::provenance::AdmissionClass::Production)
    {
        return Err(Error::UnqualifiedPhysical.into());
    }
    let before = witness.as_ref().map(|_| current.clone());
    current
        .continuity
        .as_mut()
        .ok_or(Error::UnqualifiedPhysical)?
        .apply_recovery(&cert, &AcceptedPhysical, &losses, false)?;
    if let (Some(before), Some(witness)) = (before, witness) {
        before.carry_recovery_material(&cert, &witness, current)?;
    }
    Ok(())
}
pub struct CanonicalStore {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
    t0: u64,
    path: PathBuf,
    genesis_anchor: FinalizedAnchor,
}
impl CanonicalStore {
    /// Apply local finite capacity before opening other long-lived writers.
    /// Genesis initialization is already bounded by its validated input size.
    pub fn configure_storage_budget(&mut self, bytes: u64) -> Result<()> {
        crate::storage_budget::configure(&self.path, bytes)?;
        crate::storage_budget::apply(&self.db)?;
        Ok(())
    }
    pub fn integrity_halted(&self) -> Result<bool> {
        Ok(self
            .db
            .query_row("SELECT halted FROM integrity WHERE id=1", [], |r| r.get(0))?)
    }
    pub fn block_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let value: Option<Option<Vec<u8>>> = self
            .db
            .query_row(
                "SELECT envelope FROM chain_history WHERE height=?1",
                [height.to_be_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(value.flatten())
    }
    pub fn transaction_status(&self, id: Hash) -> Result<Option<crate::mempool::Status>> {
        Ok(Mempool::open(
            &self.path,
            self.genesis,
            self.fingerprint,
            MAX_PENDING_BYTES,
        )?
        .status(id)?)
    }
    /// Full-chain entry point: derive certificate context and weights from the
    /// authenticated parent registry. Peer-selected authority is never accepted.
    pub fn commit_integrated<V: crate::freshness::PhysicalAttestationVerifier>(
        &mut self,
        block: &BlockEnvelope,
        physical: &BTreeMap<Hash, crate::freshness::PhysicalMember>,
        verifier: &V,
    ) -> Result<bool> {
        let (head, current) = self.load_effective()?;
        if block.header.candidate.height > 0 && block.header.candidate.height <= head.height {
            return self.inspect_integrated_history(block, physical, verifier);
        }
        if head.height.checked_add(1) != Some(block.header.candidate.height)
            || head.block != block.header.candidate.parent
        {
            return Err(ChainError::StaleParent);
        }
        let registry = current
            .continuity
            .as_ref()
            .ok_or(Error::UnqualifiedPhysical)?;
        let (membership, reputation, attestation) = registry.roots()?;
        let c = &block.header.candidate;
        let expected = Decision {
            network: crate::NETWORK_ID,
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            purpose: 2,
            height: c.height,
            mining_epoch: crate::pow::mining_epoch(c.timestamp, self.t0)?,
            continuity_period: (c.height - 1) / 60,
            round: block.certificate.decision.round,
            step: 3,
            previous_finalized_anchor: FinalizedAnchor {
                network: crate::NETWORK_ID,
                genesis: self.genesis,
                fingerprint: self.fingerprint,
                height: head.height,
                block: head.block,
            }
            .id(),
            parent: head.block,
            block: block.block_hash(),
            state: c.state_root,
            membership,
            reputation,
            attestation,
        };
        self.commit_with_attestation(block, &expected, &registry.voters()?, physical, verifier)
    }
    /// The complete Genesis artifact/state, parameters and physical admissions
    /// must already be independently qualified and sealed by the ceremony. This
    /// component verifies consistency, not completeness of opaque lifecycle data.
    pub fn open_trusted_genesis(
        path: &Path,
        descriptor: &GenesisDescriptor,
        initial: &State,
        initial_target: Hash,
    ) -> Result<Self> {
        Self::open_genesis_inner(path, descriptor, initial, initial_target, false)
    }
    fn open_genesis_inner(
        path: &Path,
        descriptor: &GenesisDescriptor,
        initial: &State,
        initial_target: Hash,
        importing: bool,
    ) -> Result<Self> {
        require_legacy_state(initial)?;
        if !importing && checkpoint::import_marker(path).exists() {
            return Err(ChainError::Integrity);
        }
        if !importing && path.exists() {
            let existing =
                Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let initialized:bool=existing.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='chain_history')",[],|r|r.get(0))?;
            if !initialized {
                return Err(ChainError::Integrity);
            }
        }
        if !initial.coins.is_empty()
            || initial_target == [0; 32]
            || initial.licenses.licenses.len() != 12
            || initial.licenses.workers.len() != 12
            || !initial.licenses.pending.is_empty()
        {
            return Err(ChainError::WrongGenesis);
        }
        let genesis = descriptor.id()?;
        if initial.licenses.licenses.values().any(|l| {
            l.genesis != genesis || l.owner != descriptor.owner || l.issuance != descriptor.purchase
        }) {
            return Err(ChainError::WrongGenesis);
        }
        if let Some(registry) = &initial.continuity {
            if initial.admission.policy.is_some() {
                initial
                    .admission
                    .physical_context(registry, initial.admission_class()?)?;
            }
            if registry.genesis != genesis
                || registry.fingerprint != descriptor.fingerprint
                || registry.recovery_authority != descriptor.recovery
                || registry.first_period_committed
                || initial.accounting.slots != crate::participation::PeriodSlots::default()
            {
                return Err(ChainError::WrongGenesis);
            }
            for m in &registry.members {
                if m.physical
                    && m.eligible
                    && !initial.accounting.freshness.get(&m.node).is_some_and(|r| {
                        r.committed_height == 0 && r.eligible(m.node, m.generation, m.voting_key, 1)
                    })
                {
                    return Err(ChainError::WrongGenesis);
                }
            }
        }
        let root = initial.root()?;
        let block = descriptor.block_hash(root)?;
        let genesis_anchor = FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis,
            fingerprint: descriptor.fingerprint,
            height: 0,
            block,
        };
        drop(
            crate::finality::FinalityLedger::open(path, &genesis_anchor)
                .map_err(ChainError::Finality)?,
        );
        drop(Mempool::open(
            path,
            genesis,
            descriptor.fingerprint,
            MAX_PENDING_BYTES,
        )?);
        let mut db = Connection::open(path)?;
        crate::storage_budget::apply(&db)?;
        let import_table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='checkpoint_import')",[],|r|r.get(0))?;
        if import_table {
            let complete: bool = db.query_row(
                "SELECT complete FROM checkpoint_import WHERE id=1",
                [],
                |r| r.get(0),
            )?;
            if !complete && !importing {
                return Err(ChainError::Integrity);
            }
        }
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS chain_history(height BLOB PRIMARY KEY CHECK(length(height)=8),block BLOB NOT NULL,root BLOB NOT NULL,next_target BLOB NOT NULL,timestamp BLOB NOT NULL,anchor BLOB NOT NULL,envelope BLOB);
            CREATE TABLE IF NOT EXISTS chain_state(key BLOB PRIMARY KEY CHECK(length(key)=32),value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS recovery_overlay(base_height BLOB PRIMARY KEY,base_block BLOB NOT NULL,certificate BLOB NOT NULL,losses BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS recovery_material(base_height BLOB PRIMARY KEY,witness BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS incoming_equivocation(id BLOB PRIMARY KEY CHECK(length(id)=32),wire BLOB NOT NULL,offense BLOB NOT NULL CHECK(length(offense)=8),status INTEGER NOT NULL CHECK(status IN(0,1,2)));
            CREATE TABLE IF NOT EXISTS chain_undo(height BLOB NOT NULL,key BLOB NOT NULL,previous BLOB,PRIMARY KEY(height,key));")?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<(Vec<u8>, Vec<u8>)> = t
            .query_row(
                "SELECT block,next_target FROM chain_history WHERE height=?1",
                [0u64.to_be_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((b, target)) = stored {
            if b != block || target != initial_target {
                return Err(ChainError::WrongGenesis);
            }
        } else {
            let anchor = FinalizedAnchor {
                network: crate::NETWORK_ID,
                genesis,
                fingerprint: descriptor.fingerprint,
                height: 0,
                block,
            };
            t.execute(
                "INSERT INTO chain_history VALUES(?1,?2,?3,?4,?5,?6,NULL)",
                params![
                    0u64.to_be_bytes().as_slice(),
                    block.as_slice(),
                    root.as_slice(),
                    initial_target.as_slice(),
                    descriptor.timestamp.to_be_bytes().as_slice(),
                    anchor.encode()
                ],
            )?;
            for (key, value) in initial.records()? {
                t.execute(
                    "INSERT INTO chain_state VALUES(?1,?2)",
                    params![key.as_slice(), value],
                )?;
            }
            Mempool::reconcile_in(&t, 0, block, &BTreeSet::new(), &initial.coins)?;
        }
        crate::state_tree::index::install(&t)?;
        let head = tip(&t)?;
        let records = state(&t, head.root)?.records()?;
        let anchor = FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis,
            fingerprint: descriptor.fingerprint,
            height: head.height,
            block: head.block,
        };
        crate::state_tree::index::publish(&t, &records, &anchor, head.root, &[], true)?;
        t.commit()?;
        Ok(Self {
            db,
            genesis,
            fingerprint: descriptor.fingerprint,
            t0: descriptor.timestamp,
            path: path.to_path_buf(),
            genesis_anchor,
        })
    }
    /// Serve only the specifically requested finalized state. The derived index
    /// and canonical record are read together, and the resulting proof is checked.
    pub fn state_proof(
        &mut self,
        expected: &FinalizedAnchor,
        key: Hash,
    ) -> Result<crate::state_tree::StateProof> {
        if self.integrity_halted()? {
            return Err(ChainError::Integrity);
        }
        let t = self.db.transaction()?;
        let head = tip(&t)?;
        let anchor = FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            height: head.height,
            block: head.block,
        };
        if &anchor != expected {
            return Err(ChainError::StaleParent);
        }
        let proof = crate::state_tree::index::prove(&t, &anchor, head.root, key)?;
        t.commit()?;
        Ok(proof)
    }
    pub fn load(&mut self) -> Result<(Tip, State)> {
        let t = self.db.transaction()?;
        let head = tip(&t)?;
        let loaded = state(&t, head.root)?;
        t.commit()?;
        Ok((head, loaded))
    }
    /// The historical StateRoot is unchanged by bootstrap recovery. Effective
    /// authority includes a separately accepted recovery proof at that anchor.
    pub fn load_effective(&mut self) -> Result<(Tip, State)> {
        let t = self.db.transaction()?;
        let head = tip(&t)?;
        let mut loaded = state(&t, head.root)?;
        apply_accepted_recovery(&t, &head, &mut loaded)?;
        t.commit()?;
        Ok((head, loaded))
    }
    /// Authenticated historical parent for restart reconciliation. The root is
    /// reconstructed and checked before separately accepted recovery overlays.
    pub fn execution_parent(&mut self, height: u64) -> Result<(WorkParent, State)> {
        let t = self.db.transaction()?;
        let head = history_tip(&t, height)?;
        let mut loaded = historical_state(&t, &head)?;
        apply_accepted_recovery(&t, &head, &mut loaded)?;
        let timestamps = {
            let mut q = t.prepare("SELECT timestamp FROM chain_history WHERE height<=?1 ORDER BY height DESC LIMIT 11")?;
            q.query_map([height.to_be_bytes().as_slice()], |r| {
                r.get::<_, Vec<u8>>(0)
            })?
            .map(|r| counter(r?))
            .collect::<Result<Vec<_>>>()?
        };
        if !crate::pow::window_ends_at_parent(&timestamps, head.timestamp) {
            return Err(ChainError::Integrity);
        }
        t.commit()?;
        Ok((
            WorkParent {
                genesis: self.genesis,
                fingerprint: self.fingerprint,
                block: head.block,
                height,
                t0: self.t0,
                target: head.next_target,
                ancestor_timestamps: timestamps,
            },
            loaded,
        ))
    }
    /// Historical authorities for exactly the evidence heights in this body.
    /// Each state is reconstructed and checked against canonical history.
    pub fn evidence_history(
        &mut self,
        body: &crate::blocks::BlockBody,
    ) -> Result<crate::equivocation::EvidenceHistory> {
        let t = self.db.transaction()?;
        let result = evidence_history(&t, body, self.genesis, self.fingerprint)?;
        t.commit()?;
        Ok(result)
    }
    fn inspect_integrated_history<V: crate::freshness::PhysicalAttestationVerifier>(
        &mut self,
        block: &BlockEnvelope,
        physical: &BTreeMap<Hash, crate::freshness::PhysicalMember>,
        verifier: &V,
    ) -> Result<bool> {
        let height = block.header.candidate.height;
        let t = self.db.transaction()?;
        let parent_head = history_tip(&t, height - 1)?;
        let mut historical = historical_state(&t, &parent_head)?;
        apply_accepted_recovery(&t, &parent_head, &mut historical)?;
        let registry = historical
            .continuity
            .as_ref()
            .ok_or(Error::UnqualifiedPhysical)?;
        let (membership, reputation, attestation) = registry.roots()?;
        let voters = registry.voters()?;
        let parent_anchor = FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            height: height - 1,
            block: parent_head.block,
        };
        let mut expected = block.certificate.decision.clone();
        expected.network = crate::NETWORK_ID;
        expected.genesis = self.genesis;
        expected.fingerprint = self.fingerprint;
        expected.height = height;
        expected.parent = parent_head.block;
        expected.previous_finalized_anchor = parent_anchor.id();
        expected.membership = membership;
        expected.reputation = reputation;
        expected.attestation = attestation;
        // Header/body/execution validation below independently constrains all
        // remaining decision fields, including block/state/epoch/purpose/step.
        let timestamps = {
            let mut q=t.prepare("SELECT timestamp FROM chain_history WHERE height<=?1 ORDER BY height DESC LIMIT 11")?;
            q.query_map([(height - 1).to_be_bytes().as_slice()], |r| {
                r.get::<_, Vec<u8>>(0)
            })?
            .map(|r| counter(r?))
            .collect::<Result<Vec<_>>>()?
        };
        if !crate::pow::window_ends_at_parent(&timestamps, parent_head.timestamp) {
            return Err(ChainError::Integrity);
        }
        let parent = WorkParent {
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            block: parent_head.block,
            height: height - 1,
            t0: self.t0,
            target: parent_head.next_target,
            ancestor_timestamps: timestamps,
        };
        let (context, owner) = historical.work_context(&parent, &block.header.candidate)?;
        block.verify_evidence(&context, owner, &expected, &voters)?;
        let history = evidence_history(&t, &block.body, self.genesis, self.fingerprint)?;
        historical.execute_with_history(
            crate::execution::LicensedExecution {
                parent: &parent,
                header: &block.header,
                authority: &block.authority,
                signature: &block.authority_signature,
                body: &block.body,
            },
            physical,
            verifier,
            &history,
        )?;
        t.commit()?;
        self.inspect_history_proof(&block.certificate, &expected, &voters)
    }
    /// Explicit supervised bootstrap ceremony, never an ordinary owner vote.
    /// Physical verification happens before accepting/persisting this proof.
    pub fn accept_bootstrap_recovery<A: crate::recovery::PhysicalAdmissionVerifier>(
        &mut self,
        certificate: &crate::recovery::Certificate,
        admission: &A,
        losses: &[(Hash, u64)],
    ) -> Result<bool> {
        self.accept_recovery_inner(certificate, admission, losses, None)
    }
    /// Native verified public replacement evidence, committed in the same
    /// transaction as the existing supervised recovery certificate.
    pub fn accept_admitted_bootstrap_recovery(
        &mut self,
        certificate: &crate::recovery::Certificate,
        witness: &crate::recovery_material::RecoveryMaterial,
        losses: &[(Hash, u64)],
    ) -> Result<bool> {
        let (_, state) = self.load_effective()?;
        let class = state.admission_class()?;
        let policy = state.admission.policy.ok_or(Error::UnqualifiedPhysical)?;
        struct Native<'a>(
            &'a crate::recovery_material::RecoveryMaterial,
            &'a crate::admission::AdmissionPolicy,
            crate::provenance::AdmissionClass,
        );
        impl crate::recovery::PhysicalAdmissionVerifier for Native<'_> {
            fn verify_replacement(&self, b: &crate::recovery::Recovery) -> crate::Result<()> {
                self.0.verify(b, self.1, self.2)
            }
        }
        self.accept_recovery_inner(
            certificate,
            &Native(witness, &policy, class),
            losses,
            Some(witness),
        )
    }
    fn accept_recovery_inner<A: crate::recovery::PhysicalAdmissionVerifier>(
        &mut self,
        certificate: &crate::recovery::Certificate,
        admission: &A,
        losses: &[(Hash, u64)],
        witness: Option<&crate::recovery_material::RecoveryMaterial>,
    ) -> Result<bool> {
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let halted: bool =
            t.query_row("SELECT halted FROM integrity WHERE id=1", [], |r| r.get(0))?;
        if halted {
            return Err(ChainError::Integrity);
        }
        let head = tip(&t)?;
        let raw = certificate.encode();
        let existing: Option<Vec<u8>> = t
            .query_row(
                "SELECT certificate FROM recovery_overlay WHERE base_height=?1",
                [head.height.to_be_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == raw {
                let saved: Option<Vec<u8>> = t
                    .query_row(
                        "SELECT witness FROM recovery_material WHERE base_height=?1",
                        [head.height.to_be_bytes().as_slice()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if saved != witness.map(|w| w.encode()).transpose()? {
                    return Err(Error::ConflictingRecovery.into());
                }
                return Ok(false);
            }
            return Err(Error::ConflictingRecovery.into());
        }
        let mut current = state(&t, head.root)?;
        // A caller-supplied verifier decides only for a policy-less Legacy/Test state; a
        // Production-class state always has a policy and requires the native witness.
        if current.admission.policy.is_some() != witness.is_some()
            || (witness.is_none()
                && current.admission_class()? == crate::provenance::AdmissionClass::Production)
        {
            return Err(Error::UnqualifiedPhysical.into());
        }
        let registry = current
            .continuity
            .as_mut()
            .ok_or(Error::UnqualifiedPhysical)?;
        if current.penalties.revoked(certificate.body.lineage) {
            return Err(Error::WrongGeneration.into());
        }
        registry.anchor = crate::recovery::Anchor {
            height: head.height,
            tip: head.block,
            state_root: head.root,
            registry_root: registry.roots()?.0,
        };
        // Known accepted descendants/conflicts may not be erased by recovery.
        let descendant: bool = t.query_row(
            "SELECT EXISTS(SELECT 1 FROM finality_evidence WHERE height>?1)",
            [head.height.to_be_bytes().as_slice()],
            |r| r.get(0),
        )?;
        let before = witness.map(|_| current.clone());
        current
            .continuity
            .as_mut()
            .ok_or(Error::UnqualifiedPhysical)?
            .apply_recovery(certificate, admission, losses, descendant)?;
        if let (Some(before), Some(witness)) = (before, witness) {
            before.carry_recovery_material(certificate, witness, &mut current)?;
        }
        let mut encoded = minicbor::Encoder::new(Vec::new());
        encoded.array(losses.len() as u64).unwrap();
        for (lineage, generation) in losses {
            encoded
                .array(2)
                .unwrap()
                .bytes(lineage)
                .unwrap()
                .u64(*generation)
                .unwrap();
        }
        t.execute(
            "INSERT INTO recovery_overlay VALUES(?1,?2,?3,?4)",
            params![
                head.height.to_be_bytes().as_slice(),
                head.block.as_slice(),
                raw,
                encoded.into_writer()
            ],
        )?;
        if let Some(witness) = witness {
            t.execute(
                "INSERT INTO recovery_material VALUES(?1,?2)",
                params![head.height.to_be_bytes().as_slice(), witness.encode()?],
            )?;
        }
        t.commit()?;
        Ok(true)
    }
    /// Admission reads the exact canonical UTXO view under the same writer lock
    /// used by commits, eliminating stale-view admission races.
    pub fn admit(
        &mut self,
        transfer: &crate::transactions::Transfer,
    ) -> Result<crate::mempool::Status> {
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let halted: bool =
            t.query_row("SELECT halted FROM integrity WHERE id=1", [], |r| r.get(0))?;
        if halted {
            return Err(ChainError::Integrity);
        }
        let head = tip(&t)?;
        let mut current = state(&t, head.root)?;
        apply_accepted_recovery(&t, &head, &mut current)?;
        let height = head.height.checked_add(1).ok_or(Error::Overflow)?;
        let status = Mempool::admit_in(
            &t,
            transfer,
            height,
            &current.coins,
            self.genesis,
            self.fingerprint,
            MAX_PENDING_BYTES,
        )?;
        t.commit()?;
        Ok(status)
    }
    /// Expected decision/registry must already be independently validated for
    /// that historical height. Conflicting proof and integrity halt persist in
    /// the same database consulted by every subsequent canonical commit.
    pub fn inspect_history_proof(
        &mut self,
        certificate: &crate::certificates::Certificate,
        expected: &Decision,
        registry: &BTreeMap<Hash, Voter>,
    ) -> Result<bool> {
        let exists: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM chain_history WHERE height=?1)",
            [expected.height.to_be_bytes().as_slice()],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(ChainError::StaleParent);
        }
        let mut ledger = crate::finality::FinalityLedger::open(&self.path, &self.genesis_anchor)
            .map_err(ChainError::Finality)?;
        ledger
            .record_certificate(certificate, expected, registry)
            .map_err(ChainError::Finality)
    }
    /// Insert only the immediate successor, or recognize alternate proof for the
    /// exact current block. Conflicting/older proofs go to the verified-history
    /// integrity-halt path, never through this successor-only mutation API.
    pub fn commit_successor(
        &mut self,
        block: &BlockEnvelope,
        expected: &Decision,
        registry: &BTreeMap<Hash, Voter>,
    ) -> Result<bool> {
        self.commit_with_attestation(
            block,
            expected,
            registry,
            &BTreeMap::new(),
            &crate::execution::RejectAttestation,
        )
    }
    fn commit_with_attestation<V: crate::freshness::PhysicalAttestationVerifier>(
        &mut self,
        block: &BlockEnvelope,
        expected: &Decision,
        registry: &BTreeMap<Hash, Voter>,
        physical: &BTreeMap<Hash, crate::freshness::PhysicalMember>,
        verifier: &V,
    ) -> Result<bool> {
        block.encode()?;
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let halted: bool =
            t.query_row("SELECT halted FROM integrity WHERE id=1", [], |r| r.get(0))?;
        if halted {
            return Err(ChainError::Integrity);
        }
        let head = tip(&t)?;
        if block.header.candidate.height == head.height && block.block_hash() == head.block {
            let raw: Vec<u8> = t.query_row(
                "SELECT envelope FROM chain_history WHERE height=?1",
                [head.height.to_be_bytes().as_slice()],
                |r| r.get(0),
            )?;
            let old = BlockEnvelope::decode(&raw)?;
            let mut decision = old.certificate.decision.clone();
            decision.round = block.certificate.decision.round;
            if expected != &decision
                || block.header != old.header
                || block.body != old.body
                || block.authority != old.authority
                || block.authority_signature != old.authority_signature
            {
                return Err(ChainError::Integrity);
            }
            block.certificate.verify_quorum(&decision, registry)?;
            return Ok(false);
        }
        if block.header.candidate.parent != head.block
            || head.height.checked_add(1) != Some(block.header.candidate.height)
        {
            return Err(ChainError::StaleParent);
        }
        let mut current = state(&t, head.root)?;
        let previous: BTreeMap<_, _> = current.records()?.into_iter().collect();
        apply_accepted_recovery(&t, &head, &mut current)?;
        if let Some(committed) = &current.continuity {
            let roots = committed.roots()?;
            if roots
                != (
                    expected.membership,
                    expected.reputation,
                    expected.attestation,
                )
            {
                return Err(Error::WrongAnchor.into());
            }
            let voters = committed.voters()?;
            if voters.len() != registry.len()
                || voters.iter().any(|(node, v)| {
                    registry.get(node).is_none_or(|r| {
                        r.key_version != v.key_version
                            || r.public_key != v.public_key
                            || r.weight != v.weight
                    })
                })
            {
                return Err(Error::WrongAnchor.into());
            }
        }
        let timestamps = {
            // Bounded by the parent (the tip) so a row above it can never enter the window.
            let mut s = t.prepare(
                "SELECT timestamp FROM chain_history WHERE height<=?1 ORDER BY height DESC LIMIT 11",
            )?;
            s.query_map([head.height.to_be_bytes().as_slice()], |r| r.get::<_, Vec<u8>>(0))?
                .map(|r| counter(r?))
                .collect::<Result<Vec<_>>>()?
        };
        if !crate::pow::window_ends_at_parent(&timestamps, head.timestamp) {
            return Err(ChainError::Integrity);
        }
        let parent = WorkParent {
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            block: head.block,
            height: head.height,
            t0: self.t0,
            target: head.next_target,
            ancestor_timestamps: timestamps,
        };
        let (context, owner) = current.work_context(&parent, &block.header.candidate)?;
        block.verify_evidence(&context, owner, expected, registry)?;
        let history = evidence_history(&t, &block.body, self.genesis, self.fingerprint)?;
        let executed = current.execute_with_history(
            crate::execution::LicensedExecution {
                parent: &parent,
                header: &block.header,
                authority: &block.authority,
                signature: &block.authority_signature,
                body: &block.body,
            },
            physical,
            verifier,
            &history,
        )?;
        let height = block.header.candidate.height;
        let timestamp = block.header.candidate.timestamp;
        let start = if height.is_multiple_of(60) {
            counter(t.query_row(
                "SELECT timestamp FROM chain_history WHERE height=?1",
                [(height - 60).to_be_bytes().as_slice()],
                |r| r.get(0),
            )?)?
        } else {
            timestamp
        };
        let next_target = target_after_height(height, head.next_target, start, timestamp)?;
        let next: BTreeMap<_, _> = executed.state.records()?.into_iter().collect();
        for key in previous.keys().filter(|k| !next.contains_key(*k)) {
            t.execute(
                "INSERT INTO chain_undo VALUES(?1,?2,?3)",
                params![
                    height.to_be_bytes().as_slice(),
                    key.as_slice(),
                    previous[key]
                ],
            )?;
            t.execute("DELETE FROM chain_state WHERE key=?1", [key.as_slice()])?;
        }
        for (key, value) in &next {
            if previous.get(key) != Some(value) {
                t.execute(
                    "INSERT INTO chain_undo VALUES(?1,?2,?3)",
                    params![
                        height.to_be_bytes().as_slice(),
                        key.as_slice(),
                        previous.get(key)
                    ],
                )?;
                t.execute("INSERT INTO chain_state VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key.as_slice(),value])?;
            }
        }
        Mempool::reconcile_in(
            &t,
            height,
            block.block_hash(),
            &executed.transaction_ids,
            &executed.state.coins,
        )?;
        t.execute(
            "INSERT INTO finalized VALUES(?1,?2)",
            params![height.to_be_bytes().as_slice(), expected.anchor().encode()],
        )?;
        t.execute(
            "INSERT INTO finality_evidence VALUES(?1,?2,?3)",
            params![
                height.to_be_bytes().as_slice(),
                block.block_hash().as_slice(),
                block.certificate.encode()?
            ],
        )?;
        t.execute(
            "INSERT INTO chain_history VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                height.to_be_bytes().as_slice(),
                block.block_hash().as_slice(),
                executed.root.as_slice(),
                next_target.as_slice(),
                timestamp.to_be_bytes().as_slice(),
                expected.anchor().encode(),
                block.encode()?
            ],
        )?;
        evidence_pool::reconcile(&t, height, &executed.state)?;
        let removed: Vec<_> = previous
            .keys()
            .filter(|k| !next.contains_key(*k))
            .copied()
            .collect();
        let records: Vec<_> = next.into_iter().collect();
        crate::state_tree::index::publish(
            &t,
            &records,
            &expected.anchor(),
            executed.root,
            &removed,
            false,
        )?;
        t.commit()?;
        Ok(true)
    }
}
