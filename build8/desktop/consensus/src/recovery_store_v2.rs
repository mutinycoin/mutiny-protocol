//! Local accepted-recovery journal. Entries are public proofs, not replacement
//! canonical parent states. Every read is revalidated against its actual parent.
use crate::{
    Hash, anchors::FinalizedAnchor, execution::State, finality_v2::StoreError,
    recovery_transition_v2::Prepared,
};
use rusqlite::{Connection, OptionalExtension};

pub(crate) fn raw(db: &Connection, height: u64) -> Result<Option<(Hash, Vec<u8>)>, StoreError> {
    let row: Option<(Vec<u8>, Vec<u8>)> = db.query_row(
        "SELECT CASE WHEN typeof(commitment)='blob' AND length(commitment)=32 THEN commitment ELSE NULL END,CASE WHEN typeof(record)='blob' AND length(record) BETWEEN 1 AND 262144 THEN record ELSE NULL END FROM accepted_recovery_v2 WHERE height=?1",
        [height.to_be_bytes().as_slice()], |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?;
    row.map(|(commitment, record)| {
        Ok((
            commitment.try_into().map_err(|_| StoreError::Integrity)?,
            record,
        ))
    })
    .transpose()
}

pub(crate) fn prepared(
    db: &Connection,
    state: &State,
    parent: &FinalizedAnchor,
    root: Hash,
    genesis_time: u64,
) -> Result<Option<Prepared>, StoreError> {
    let Some((commitment, bytes)) = raw(db, parent.height)? else {
        return Ok(None);
    };
    let authority = state
        .recovery_authority_v2
        .as_ref()
        .ok_or(StoreError::Integrity)?;
    let (record, witness) = crate::recovery_public_v3::item(&bytes, state, authority)?;
    if record.material.commitment()? != commitment {
        return Err(StoreError::Integrity);
    }
    // A successor may already exist during historical replay. Its authority is
    // checked against this proof by the caller; acceptance itself excludes any
    // pre-existing descendant while holding the canonical write transaction.
    let reference_time = if witness.is_some() {
        Some(parent_time(db, parent, root, genesis_time)?)
    } else { None };
    Ok(Some(Prepared::verify_with_public_witness(state, parent, root, record, false,
        witness.as_deref().zip(reference_time))?))
}

/// The enclosing store has authenticated/replayed this canonical chain. Bind
/// the exact parent row and finalized anchor to the independently retained
/// header hash/time (or immutable trusted Genesis t0), never a projected registry.
pub(crate) fn parent_time(db: &Connection, parent: &FinalizedAnchor, root: Hash,
    genesis_time: u64) -> Result<u64, StoreError> {
    let (block, stored_root, time): (Vec<u8>, Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT CASE WHEN length(block)=32 THEN block END,CASE WHEN length(root)=32 THEN root END,CASE WHEN length(timestamp)=8 THEN timestamp END FROM canonical_v2 WHERE height=?1",
        [parent.height.to_be_bytes().as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    if block != parent.block || stored_root != root { return Err(StoreError::WrongParent); }
    let time = u64::from_be_bytes(time.try_into().map_err(|_| StoreError::Integrity)?);
    let anchor: Vec<u8> = db.query_row(
        "SELECT CASE WHEN length(anchor) BETWEEN 1 AND 256 THEN anchor END FROM finalized_v2 WHERE height=?1",
        [parent.height.to_be_bytes().as_slice()], |r| r.get(0))?;
    if anchor != parent.encode() { return Err(StoreError::Integrity); }
    if parent.height == 0 {
        if time != genesis_time || genesis_time == 0 { return Err(StoreError::Integrity); }
    } else {
        let raw: Vec<u8> = db.query_row(
            "SELECT CASE WHEN length(envelope) BETWEEN 1 AND ?3 THEN envelope END FROM evidence_v2 WHERE height=?1 AND block=?2",
            rusqlite::params![parent.height.to_be_bytes().as_slice(), parent.block.as_slice(),
                crate::body_capacity_v3::MAX_ENVELOPE_BYTES as u64], |r| r.get(0))?;
        // Header-only structural decoding; the enclosing store already authenticated/replayed
        // the complete retained envelope under its canonical parent's capacity and certificate.
        let header = crate::block_envelope_v2::BlockEnvelope::untrusted_header(&raw)?;
        let c = &header.candidate;
        if header.block_hash() != parent.block || c.height != parent.height
            || c.network != parent.network || c.genesis != parent.genesis
            || c.fingerprint != parent.fingerprint || c.state_root != root
            || c.timestamp != time { return Err(StoreError::Integrity); }
    }
    Ok(time)
}

/// Recheck the exact row under the finality write transaction. A proof accepted
/// during slow envelope verification must not let stale ordinary authority win.
pub(crate) fn require_unchanged(
    db: &Connection,
    height: u64,
    expected: Option<&(Hash, Vec<u8>)>,
) -> Result<(), StoreError> {
    if raw(db, height)?.as_ref() != expected {
        return Err(StoreError::WrongParent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journal_guard_rejects_stale_ordinary_and_recovery_contexts() {
        // Storage/race guard only. These deliberately non-cryptographic bytes
        // cannot pass prepared(); full signed replay is tested separately.
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(crate::store_schema_v2::CANONICAL[0].1)
            .unwrap();
        require_unchanged(&db, 0, None).unwrap();
        let expected = ([1; 32], vec![2; 12]);
        db.execute(
            "INSERT INTO accepted_recovery_v2 VALUES(?1,?2,?3)",
            rusqlite::params![
                0u64.to_be_bytes().as_slice(),
                expected.0.as_slice(),
                &expected.1
            ],
        )
        .unwrap();
        assert!(require_unchanged(&db, 0, None).is_err());
        require_unchanged(&db, 0, Some(&expected)).unwrap();
        db.execute(
            "UPDATE accepted_recovery_v2 SET commitment=?1",
            [[3u8; 32].as_slice()],
        )
        .unwrap();
        assert!(require_unchanged(&db, 0, Some(&expected)).is_err());
        db.execute("DELETE FROM accepted_recovery_v2", []).unwrap();
        assert!(require_unchanged(&db, 0, Some(&expected)).is_err());
        require_unchanged(&db, 0, None).unwrap();
    }
}
