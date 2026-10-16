//! Derived persistent Patricia index. Every publication is in the caller's
//! canonical SQLite transaction, and every served proof checks the pinned root.
//! Rebuild is deterministic; the index never supplies chain authority.
use super::*;
use rusqlite::{OptionalExtension, Transaction, params};
type Id = [u8; 34];
type IndexResult<T> = std::result::Result<T, crate::canonical_store::ChainError>;
#[derive(Clone)]
struct Cached {
    depth: usize,
    key: Hash,
    hash: Hash,
    children: Option<(Id, Id, Hash, Hash)>,
}
fn id(key: &Hash, depth: usize) -> Id {
    let mut out = [0; 34];
    out[..2].copy_from_slice(&(depth as u16).to_be_bytes());
    out[2..].copy_from_slice(key);
    for d in depth..256 {
        out[2 + d / 8] &= !(0x80 >> (d % 8));
    }
    out
}
fn node_id(n: &Node) -> Id {
    id(&n.key, n.depth)
}
fn invalid<T>() -> IndexResult<T> {
    Err(Error::WrongAnchor.into())
}
impl Cached {
    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u16(self.depth as u16)
            .unwrap()
            .bytes(&self.key)
            .unwrap()
            .bytes(&self.hash)
            .unwrap();
        if let Some((l, r, lh, rh)) = &self.children {
            e.array(2).unwrap().bytes(l).unwrap().bytes(r).unwrap();
            e.array(2).unwrap().bytes(lh).unwrap().bytes(rh).unwrap();
        } else {
            e.null().unwrap().null().unwrap();
        }
        e.into_writer()
    }
    fn decode(raw: &[u8], expected: Id) -> IndexResult<Self> {
        canonical(raw, 256)?;
        let mut d = Decoder::new(raw);
        let parse = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("derived index");
            if d.array()? != Some(5) {
                return Err(bad());
            }
            let depth = d.u16()? as usize;
            let key = d.bytes()?.try_into().map_err(|_| bad())?;
            let hash = d.bytes()?.try_into().map_err(|_| bad())?;
            let children = if d.datatype()? == Type::Null {
                d.null()?;
                d.null()?;
                None
            } else {
                if d.array()? != Some(2) {
                    return Err(bad());
                }
                let l = d.bytes()?.try_into().map_err(|_| bad())?;
                let r = d.bytes()?.try_into().map_err(|_| bad())?;
                if d.array()? != Some(2) {
                    return Err(bad());
                }
                let lh = d.bytes()?.try_into().map_err(|_| bad())?;
                let rh = d.bytes()?.try_into().map_err(|_| bad())?;
                Some((l, r, lh, rh))
            };
            Ok(Self {
                depth,
                key,
                hash,
                children,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if parse.depth > 256
            || id(&parse.key, parse.depth) != expected
            || parse.encode() != raw
            || (parse.depth == 256) != parse.children.is_none()
        {
            return invalid();
        }
        if let Some((l, r, lh, rh)) = parse.children {
            let ld = u16::from_be_bytes(l[..2].try_into().unwrap()) as usize;
            let rd = u16::from_be_bytes(r[..2].try_into().unwrap()) as usize;
            if ld <= parse.depth
                || rd <= parse.depth
                || ld > 256
                || rd > 256
                || branch(lh, rh) != parse.hash
            {
                return invalid();
            }
        }
        Ok(parse)
    }
}
fn load(db: &Transaction<'_>, key: Id) -> IndexResult<Cached> {
    let raw: Vec<u8> = db.query_row(
        "SELECT value FROM state_merkle_nodes WHERE id=?1 AND length(value)<=256",
        [key.as_slice()],
        |r| r.get(0),
    )?;
    Cached::decode(&raw, key)
}
fn save(db: &Transaction<'_>, node: &Node) -> IndexResult<()> {
    let cached = Cached {
        depth: node.depth,
        key: node.key,
        hash: node.hash,
        children: node
            .children
            .as_ref()
            .map(|(l, r, lh, rh)| (node_id(l), node_id(r), *lh, *rh)),
    };
    let key = node_id(node);
    let raw = cached.encode();
    let old: Option<Vec<u8>> = db
        .query_row(
            "SELECT value FROM state_merkle_nodes WHERE id=?1 AND length(value)<=256",
            [key.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    if old.as_deref() == Some(raw.as_slice()) {
        return Ok(());
    }
    if let Some((l, r, _, _)) = &node.children {
        save(db, l)?;
        save(db, r)?;
    }
    db.execute("INSERT INTO state_merkle_nodes VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET value=excluded.value",params![key.as_slice(),raw])?;
    Ok(())
}
fn contains(node: &Node, wanted: Id) -> bool {
    let depth = u16::from_be_bytes(wanted[..2].try_into().unwrap()) as usize;
    let key: Hash = wanted[2..].try_into().unwrap();
    if node.depth > depth || shared(&node.key, &key) < node.depth {
        return false;
    }
    if node.depth == depth {
        return node_id(node) == wanted;
    }
    if let Some((l, r, _, _)) = &node.children {
        contains(if bit(&key, node.depth) { r } else { l }, wanted)
    } else {
        false
    }
}
pub fn install(db: &Transaction<'_>) -> IndexResult<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS state_merkle_nodes(id BLOB PRIMARY KEY CHECK(length(id)=34),value BLOB NOT NULL) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS state_merkle_tip(singleton INTEGER PRIMARY KEY CHECK(singleton=1),anchor BLOB NOT NULL,root BLOB NOT NULL,count INTEGER NOT NULL,tree BLOB);")?;
    Ok(())
}
/// Records are canonical executor output. Removed keys identify obsolete paths;
/// only changed paths are written. Rebuild discards all derived nodes first.
pub fn publish(
    db: &Transaction<'_>,
    records: &[(Hash, Vec<u8>)],
    anchor: &FinalizedAnchor,
    expected: Hash,
    removed: &[Hash],
    rebuild: bool,
) -> IndexResult<()> {
    let mut tree = StateTree::default();
    for (k, r) in records {
        tree.insert(*k, r.clone())?;
    }
    if tree.root() != expected {
        return invalid();
    }
    let mut obsolete = std::collections::BTreeSet::new();
    if rebuild {
        db.execute("DELETE FROM state_merkle_nodes", [])?;
    } else {
        let root: Option<Option<Vec<u8>>> = db
            .query_row(
                "SELECT tree FROM state_merkle_tip WHERE singleton=1 AND (tree IS NULL OR length(tree)=34)",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(Some(root)) = root {
            let root: Id = root.try_into().map_err(|_| Error::Codec)?;
            for key in removed {
                let mut at = root;
                for _ in 0..=256 {
                    let node = load(db, at)?;
                    obsolete.insert(at);
                    if shared(&node.key, key) < node.depth {
                        break;
                    }
                    match node.children {
                        Some((l, r, _, _)) => at = if bit(key, node.depth) { r } else { l },
                        None => break,
                    }
                }
            }
        }
    }
    if let Some(root) = &tree.root {
        save(db, root)?;
    }
    for candidate in obsolete {
        if !tree.root.as_ref().is_some_and(|n| contains(n, candidate)) {
            db.execute(
                "DELETE FROM state_merkle_nodes WHERE id=?1",
                [candidate.as_slice()],
            )?;
        }
    }
    let root = tree.root.as_ref().map(|n| node_id(n).to_vec());
    db.execute("INSERT INTO state_merkle_tip VALUES(1,?1,?2,?3,?4) ON CONFLICT(singleton) DO UPDATE SET anchor=excluded.anchor,root=excluded.root,count=excluded.count,tree=excluded.tree",
        params![anchor.encode(),expected.as_slice(),records.len() as u64,root])?;
    Ok(())
}
/// A bounded path read from a single transaction. The caller pins canonical
/// authority; local index corruption cannot authenticate a forged response.
pub fn prove(
    db: &Transaction<'_>,
    anchor: &FinalizedAnchor,
    root: Hash,
    key: Hash,
) -> IndexResult<StateProof> {
    prove_from_records(
        db,
        anchor,
        root,
        key,
        "SELECT value FROM chain_state WHERE key=?1 AND length(value)<=262144",
    )
}
/// Same index and proof codec, with the explicitly selected hybrid canonical
/// record table. Table selection is never supplied by a request or peer.
pub fn prove_v2(
    db: &Transaction<'_>,
    anchor: &FinalizedAnchor,
    root: Hash,
    key: Hash,
) -> IndexResult<StateProof> {
    prove_from_records(
        db,
        anchor,
        root,
        key,
        "SELECT value FROM state_v2 WHERE key=?1 AND length(value)<=262144",
    )
}
fn prove_from_records(
    db: &Transaction<'_>,
    anchor: &FinalizedAnchor,
    root: Hash,
    key: Hash,
    record_query: &str,
) -> IndexResult<StateProof> {
    type Meta = (Vec<u8>, Vec<u8>, u64, Option<Vec<u8>>);
    let (stored, stored_root, count, tree): Meta = db.query_row(
        "SELECT anchor,root,count,tree FROM state_merkle_tip WHERE singleton=1 AND length(anchor)<=128 AND length(root)=32 AND count BETWEEN 0 AND 10000000 AND (tree IS NULL OR length(tree)=34)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    if stored != anchor.encode() || stored_root != root || count > MAX_RECORDS as u64 {
        return invalid();
    }
    let mut siblings = std::collections::BTreeMap::new();
    if let Some(at) = tree {
        let mut at: Id = at.try_into().map_err(|_| Error::Codec)?;
        let mut previous = None;
        for _ in 0..=256 {
            let node = load(db, at)?;
            if previous.is_some_and(|d| node.depth <= d) {
                return invalid();
            }
            previous = Some(node.depth);
            let divergence = shared(&node.key, &key);
            if divergence < node.depth {
                siblings.insert(
                    divergence,
                    lift(node.hash, &node.key, node.depth, divergence + 1),
                );
                break;
            }
            if let Some((l, r, lh, rh)) = node.children {
                if bit(&key, node.depth) {
                    siblings.insert(node.depth, lh);
                    at = r;
                } else {
                    siblings.insert(node.depth, rh);
                    at = l;
                }
            } else {
                break;
            }
        }
    } else if count != 0 {
        return invalid();
    }
    let record: Option<Vec<u8>> = db
        .query_row(record_query, [key.as_slice()], |r| r.get(0))
        .optional()?;
    let mut proof = StateProof {
        context: anchor.clone(),
        count,
        key,
        record,
        bitmap: [0; 32],
        siblings: Vec::new(),
    };
    for (d, h) in siblings {
        if h != defaults()[d + 1] {
            proof.bitmap[d / 8] |= 0x80 >> (d % 8);
            proof.siblings.push(h);
        }
    }
    proof.verify(anchor, root, key)?;
    Ok(proof)
}
