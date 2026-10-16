//! Disposable local lookup. Its root is NEVER loaded from disk. The caller
//! builds it from verified retained objects at each open. No consensus root,
//! external authentication, receipt validation, or rollback protection is implied.
use crate::{
    Hash,
    submission_pool_v1::{PoolError, Result},
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::path::Path;

const SCHEMA: &str = "CREATE TABLE nodes(key BLOB PRIMARY KEY CHECK(length(key)=34),value BLOB NOT NULL CHECK(length(value) IN(40,132)))";
const DOMAIN: &[u8] = b"MUTINY-BUILD8-LOCAL-ARCHIVE-LOOKUP-V1";
pub(crate) struct Lookup {
    db: Connection,
    root: Option<([u8; 34], Hash)>,
    valid: bool,
}
fn hash(tag: u8, depth: usize, a: &[u8], b: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update([tag]);
    h.update((depth as u16).to_be_bytes());
    h.update(a);
    h.update(b);
    h.finalize().into()
}
fn bit(id: &Hash, depth: usize) -> bool {
    id[depth / 8] & (0x80 >> (depth % 8)) != 0
}
fn shared(a: &Hash, b: &Hash) -> usize {
    for d in 0..256 {
        if bit(a, d) != bit(b, d) {
            return d;
        }
    }
    256
}
fn key(id: Hash, depth: usize) -> [u8; 34] {
    let mut out = [0; 34];
    out[..2].copy_from_slice(&(depth as u16).to_be_bytes());
    out[2..].copy_from_slice(&id);
    for n in depth..256 {
        out[2 + n / 8] &= !(0x80 >> (n % 8));
    }
    out
}
impl Lookup {
    /// The file is derived, explicitly rebuilt, and contains no raw preimages.
    /// Wrong schemas refuse; only our exact derived table is cleared.
    pub(crate) fn rebuild(path: &Path) -> Result<Self> {
        crate::submission_archive_protection::check(path, false)?;
        let db = Connection::open(path)?;
        let objects: u64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if objects == 0 {
            db.execute_batch(SCHEMA)?;
        }
        let actual: String = db.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='nodes'",
            [],
            |r| r.get(0),
        )?;
        let count: u64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if actual != SCHEMA || count != 2 {
            return Err(PoolError::Integrity);
        }
        let mode: String = db.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        if mode != "delete" {
            return Err(PoolError::Integrity);
        }
        db.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA page_size=4096;",
        )?;
        db.execute("DELETE FROM nodes", [])?;
        Ok(Self {
            db,
            root: None,
            valid: true,
        })
    }
    fn walk(&self, id: Hash) -> Result<(Option<(u64, Hash)>, Vec<([u8; 34], Vec<u8>)>)> {
        if !self.valid {
            return Err(PoolError::Integrity);
        }
        let Some((mut at, mut expected)) = self.root else {
            return Ok((None, Vec::new()));
        };
        let mut path = Vec::with_capacity(256);
        let mut previous = None;
        for _ in 0..=256 {
            let d = u16::from_be_bytes(at[..2].try_into().unwrap()) as usize;
            let prefix: Hash = at[2..].try_into().unwrap();
            if d > 256 || key(prefix, d) != at || previous.is_some_and(|p| d <= p) {
                return Err(PoolError::Integrity);
            }
            let raw: Vec<u8> = self.db.query_row(
                "SELECT CASE WHEN length(value) IN(40,132) THEN value ELSE NULL END FROM nodes WHERE key=?1",
                [at.as_slice()], |r| r.get(0))?;
            if hash(if d == 256 { 2 } else { 1 }, d, &at, &raw) != expected
                || raw.len() != if d == 256 { 40 } else { 132 }
            {
                return Err(PoolError::Integrity);
            }
            path.push((at, raw.clone()));
            // The authenticated prefix proves absence outside this subtree;
            // unreachable derived records cannot supply an unauthenticated ID.
            if shared(&prefix, &id) < d {
                return Ok((None, path));
            }
            if d == 256 {
                return Ok((
                    Some((
                        u64::from_be_bytes(raw[..8].try_into().unwrap()),
                        raw[8..].try_into().unwrap(),
                    )),
                    path,
                ));
            }
            for offset in [0, 66] {
                let child: [u8; 34] = raw[offset..offset + 34].try_into().unwrap();
                let cd = u16::from_be_bytes(child[..2].try_into().unwrap()) as usize;
                let cp: Hash = child[2..].try_into().unwrap();
                if cd <= d
                    || cd > 256
                    || shared(&prefix, &cp) < d
                    || bit(&cp, d) != (offset == 66)
                    || key(cp, cd) != child
                {
                    return Err(PoolError::Integrity);
                }
            }
            let offset = if bit(&id, d) { 66 } else { 0 };
            at = raw[offset..offset + 34].try_into().unwrap();
            expected = raw[offset + 34..offset + 66].try_into().unwrap();
            previous = Some(d);
        }
        Err(PoolError::Integrity)
    }
    pub(crate) fn get(&self, id: Hash) -> Result<Option<(u64, Hash)>> {
        Ok(self.walk(id)?.0)
    }
    pub(crate) fn insert(&mut self, id: Hash, shard: u64, digest: Hash) -> Result<()> {
        let (existing, mut path) = self.walk(id)?;
        if existing.is_some() {
            return Err(PoolError::Integrity);
        }
        let mut raw = shard.to_be_bytes().to_vec();
        raw.extend(digest);
        let leaf_key = key(id, 256);
        let leaf_hash = hash(2, 256, &leaf_key, &raw);
        // Mark unusable before mutation; any storage failure requires a reopen
        // and a complete verified rebuild, never a partially updated root.
        self.valid = false;
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO nodes VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![leaf_key.as_slice(), raw],
        )?;
        let mut changed = (leaf_key, leaf_hash);
        if let Some((old_key, old_raw)) = path.pop() {
            let old_depth = u16::from_be_bytes(old_key[..2].try_into().unwrap()) as usize;
            let old_prefix: Hash = old_key[2..].try_into().unwrap();
            let divergence = shared(&old_prefix, &id);
            if divergence >= old_depth {
                return Err(PoolError::Integrity);
            }
            let old_hash = hash(
                if old_depth == 256 { 2 } else { 1 },
                old_depth,
                &old_key,
                &old_raw,
            );
            let (left, right) = if bit(&id, divergence) {
                ((old_key, old_hash), changed)
            } else {
                (changed, (old_key, old_hash))
            };
            let branch_key = key(id, divergence);
            let mut value = left.0.to_vec();
            value.extend(left.1);
            value.extend(right.0);
            value.extend(right.1);
            let branch_hash = hash(1, divergence, &branch_key, &value);
            tx.execute("INSERT INTO nodes VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![branch_key.as_slice(), value])?;
            changed = (branch_key, branch_hash);
        }
        for (at, mut value) in path.into_iter().rev() {
            let d = u16::from_be_bytes(at[..2].try_into().unwrap()) as usize;
            let offset = if bit(&id, d) { 66 } else { 0 };
            value[offset..offset + 34].copy_from_slice(&changed.0);
            value[offset + 34..offset + 66].copy_from_slice(&changed.1);
            let digest = hash(1, d, &at, &value);
            tx.execute(
                "UPDATE nodes SET value=?2 WHERE key=?1",
                params![at.as_slice(), value],
            )?;
            changed = (at, digest);
        }
        tx.commit()?;
        self.root = Some(changed);
        self.valid = true;
        Ok(())
    }
    pub(crate) fn invalidate(&mut self) {
        self.valid = false;
    }
}

/// All nine immutable archived columns, not only the unsigned operation ID.
pub(crate) fn row_digest(db: &Connection, id: Hash) -> Result<Hash> {
    let mut query = db.prepare(
        "SELECT id,class,kind,raw,first,last,wire,sig_ok,status FROM entries WHERE id=?1",
    )?;
    let mut rows = query.query([id.as_slice()])?;
    let row = rows.next()?.ok_or(PoolError::Integrity)?;
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update([3]);
    for col in 0..9 {
        match row.get_ref(col)? {
            rusqlite::types::ValueRef::Integer(n) => {
                h.update([0]);
                h.update(n.to_be_bytes());
            }
            rusqlite::types::ValueRef::Blob(b) if b.len() <= 16384 => {
                h.update([1]);
                h.update((b.len() as u64).to_be_bytes());
                h.update(b);
            }
            _ => return Err(PoolError::Integrity),
        }
    }
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (std::path::PathBuf, Lookup) {
        let base = std::env::temp_dir().join(format!(
            "mutiny-lookup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(crate::submission_pool_v1::private_directory(&base).unwrap());
        let path = base.join("lookup.sqlite");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(&path).unwrap());
        let lookup = Lookup::rebuild(&path).unwrap();
        (base, lookup)
    }
    #[test]
    fn compressed_membership_absence_boundaries_and_tamper_are_authenticated() {
        let (base, mut lookup) = fixture();
        let mut last = [0; 32];
        last[31] = 1;
        let ids = [[0; 32], last, [0xff; 32], [0x80; 32], [0x40; 32]];
        for (n, id) in ids.iter().enumerate() {
            lookup.insert(*id, n as u64, [n as u8; 32]).unwrap();
        }
        for (n, id) in ids.iter().enumerate() {
            assert_eq!(lookup.get(*id).unwrap(), Some((n as u64, [n as u8; 32])));
        }
        assert_eq!(lookup.get([0x20; 32]).unwrap(), None);
        assert!(matches!(
            lookup.insert(ids[0], 99, [9; 32]),
            Err(PoolError::Integrity)
        ));
        assert_eq!(
            lookup.get(ids[0]).unwrap(),
            Some((0, [0; 32])),
            "duplicate refusal must preserve the existing authenticated mapping and leave it usable"
        );
        let count: u64 = lookup
            .db
            .query_row("SELECT count(*) FROM nodes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, ids.len() as u64 * 2 - 1);
        let root = lookup.root.unwrap().0;
        let original: Vec<u8> = lookup
            .db
            .query_row(
                "SELECT value FROM nodes WHERE key=?1",
                [root.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        let mut altered = original.clone();
        altered[35] ^= 1;
        lookup
            .db
            .execute(
                "UPDATE nodes SET value=?2 WHERE key=?1",
                params![root.as_slice(), altered],
            )
            .unwrap();
        assert!(lookup.get(ids[0]).is_err());
        assert!(lookup.get([0x20; 32]).is_err());
        lookup
            .db
            .execute(
                "UPDATE nodes SET value=?2 WHERE key=?1",
                params![root.as_slice(), original],
            )
            .unwrap();
        lookup
            .db
            .execute(
                "DELETE FROM nodes WHERE key=?1",
                [key(ids[0], 256).as_slice()],
            )
            .unwrap();
        assert!(lookup.get(ids[0]).is_err()); // deletion cannot produce false Unknown.
        // The other half of the tree still has intact nodes, but an explicitly invalidated
        // process snapshot must not authenticate even those rows until verified rebuild.
        lookup.invalidate();
        assert!(lookup.get(ids[2]).is_err());
        drop(lookup);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn derived_schema_mismatch_is_refused_and_unknown_table_evidence_is_preserved() {
        let (base, lookup) = fixture();
        let path = base.join("lookup.sqlite");
        lookup.db.execute_batch("CREATE TABLE unexpected_public_test(value BLOB NOT NULL); INSERT INTO unexpected_public_test VALUES(X'010203');").unwrap();
        drop(lookup);
        assert!(matches!(Lookup::rebuild(&path), Err(PoolError::Integrity)));
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT value FROM unexpected_public_test", [], |r| r
                .get::<_, Vec<u8>>(0))
                .unwrap(),
            vec![1, 2, 3]
        );
        eprintln!(
            "retained refused derived-schema PUBLIC TEST fixture {}",
            base.display()
        );
    }
    #[test]
    fn derived_lookup_scale_records_are_two_n_minus_one_and_query_work_is_bounded() {
        let (base, mut lookup) = fixture();
        let start = std::time::Instant::now();
        let ids: Vec<Hash> = (0u64..4096)
            .map(|n| hash(4, 0, &n.to_be_bytes(), b"PUBLIC-TEST-ALGORITHM-ONLY"))
            .collect();
        for (n, id) in ids.iter().enumerate() {
            lookup.insert(*id, n as u64 / 256, [n as u8; 32]).unwrap();
            if [64, 256, 1024, 4096].contains(&(n + 1)) {
                let begin = std::time::Instant::now();
                let mut max = 0;
                for (i, chosen) in ids[..=n].iter().enumerate().step_by(((n + 1) / 64).max(1)) {
                    let (record, path) = lookup.walk(*chosen).unwrap();
                    max = max.max(path.len());
                    assert_eq!(record, Some((i as u64 / 256, [i as u8; 32])));
                    assert!(path.len() <= 257);
                }
                let count: u64 = lookup
                    .db
                    .query_row("SELECT count(*) FROM nodes", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, (n as u64 + 1) * 2 - 1);
                println!(
                    "ALGORITHM-ONLY SCALE rows={} nodes={} elapsed_ms={} query64_ms={} max_nodes={}",
                    n + 1,
                    count,
                    start.elapsed().as_millis(),
                    begin.elapsed().as_millis(),
                    max
                );
            }
        }
        drop(lookup);
        std::fs::remove_dir_all(base).unwrap();
    }
}
