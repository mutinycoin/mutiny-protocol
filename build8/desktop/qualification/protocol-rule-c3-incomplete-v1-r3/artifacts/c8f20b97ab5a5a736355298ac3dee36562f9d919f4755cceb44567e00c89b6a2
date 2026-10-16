//! Local capacity policy, never a consensus validity or pruning rule. A full
//! database fails its transaction; it cannot discard required history to grow.
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
type Result<T> = rusqlite::Result<T>;
fn invalid() -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}

/// Configure before opening any other connection. The persistent policy is
/// immutable through this API; every writer reapplies it on open.
pub fn configure(path: &Path, byte_limit: u64) -> Result<()> {
    let db = Connection::open(path)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    let size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let pages = byte_limit.checked_div(size).ok_or_else(invalid)?;
    let used: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
    if pages < 256 || pages > 4_294_967_294 || used > pages {
        return Err(invalid());
    }
    db.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS local_storage_budget(id INTEGER PRIMARY KEY CHECK(id=1),
        page_size INTEGER NOT NULL, max_pages INTEGER NOT NULL);",
    )?;
    let old: Option<(u64, u64)> = db
        .query_row(
            "SELECT page_size,max_pages FROM local_storage_budget WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some(old) = old {
        if old != (size, pages) {
            return Err(invalid());
        }
    } else {
        db.execute(
            "INSERT INTO local_storage_budget VALUES(1,?1,?2)",
            (size, pages),
        )?;
    }
    apply(&db)
}

/// Legacy qualification stores without a policy are retained unchanged. The
/// configured process entry point must install a finite policy before open.
pub fn apply(db: &Connection) -> Result<()> {
    let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='local_storage_budget')",[],|r|r.get(0))?;
    if !exists {
        return Ok(());
    }
    let (size, pages): (u64, u64) = db.query_row(
        "SELECT page_size,max_pages FROM local_storage_budget WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let actual_size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    if size != actual_size || pages < 256 || pages > 4_294_967_294 {
        return Err(invalid());
    }
    db.pragma_update(None, "max_page_count", pages)?;
    let actual: u64 = db.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
    if actual != pages {
        return Err(invalid());
    }
    Ok(())
}
