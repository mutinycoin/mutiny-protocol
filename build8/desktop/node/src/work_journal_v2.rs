//! Local operational work journal, separate from canonical state and voter custody.
//! Reserve commits before signing; finish commits before delivery. Restoring an
//! old database is not detected by a hardware counter; canonical ticket floors
//! must be supplied by the caller. No production service uses this component yet.
use mutiny_consensus_v8::{Hash, NETWORK_ID, blocks::BlockBody, work_authority_v2::Authority};
use mutiny_crypto_v2::{Domain, PublicKey, Role};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
type Result<T> = std::result::Result<T, String>;
const APP: i64 = 0x4d574a32;
const IDENTITY: &str = "CREATE TABLE identity(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL,nonce BLOB NOT NULL CHECK(length(nonce)=32))";
const TICKETS: &str = "CREATE TABLE tickets(worker BLOB PRIMARY KEY CHECK(length(worker)=32),ticket BLOB NOT NULL CHECK(length(ticket)=8),reservation BLOB NOT NULL CHECK(length(reservation)=32),offer BLOB,body BLOB)";
#[cfg(test)]
thread_local! {static CRASH:std::cell::Cell<u8>=const {std::cell::Cell::new(0)};}
fn checkpoint(_point: u8) {
    #[cfg(test)]
    if CRASH.with(|p| p.get() == _point) {
        std::process::exit(91);
    }
}
fn err(_: rusqlite::Error) -> String {
    "Work journal storage failure".into()
}
pub struct Journal {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
    descriptor: Vec<u8>,
    nonce: Hash,
    body_codec: crate::journal_body_codec_v1::Codec,
}
/// The fields are private and no deserializer can manufacture a reservation.
pub struct Reservation {
    journal: Hash,
    nonce: Hash,
    worker: Hash,
    ticket: u64,
}
impl Reservation {
    pub fn worker(&self) -> Hash {
        self.worker
    }
    pub fn ticket(&self) -> u64 {
        self.ticket
    }
}
impl Journal {
    pub(crate) fn uses_a2(&self) -> bool { self.body_codec.is_successor() }
    /// Refuse a caller's incompatible canonical context before reserving a ticket.
    pub fn matches_context(&self, genesis: Hash, fingerprint: Hash, descriptor: &[u8]) -> bool {
        self.genesis == genesis && self.fingerprint == fingerprint && self.descriptor == descriptor
    }
    pub fn initialize(
        path: &Path,
        genesis: Hash,
        fingerprint: Hash,
        descriptor: &[u8],
    ) -> Result<Self> {
        Self::open_inner(path, genesis, fingerprint, descriptor, true, None)
    }
    pub fn reopen(
        path: &Path,
        genesis: Hash,
        fingerprint: Hash,
        descriptor: &[u8],
    ) -> Result<Self> {
        Self::open_inner(path, genesis, fingerprint, descriptor, false, None)
    }
    /// Explicit schema3. Old schema2 is neither widened nor migrated.
    pub fn open_a2(
        runtime: &crate::hybrid_runtime_v2::HybridRuntime,
        path: &Path,
        descriptor: &[u8],
        initialize: bool,
    ) -> Result<Self> {
        let (genesis,fingerprint) = runtime.network_context();
        Self::open_inner(path,genesis,fingerprint,descriptor,initialize,Some(runtime))
    }
    fn open_inner(
        path: &Path,
        genesis: Hash,
        fingerprint: Hash,
        descriptor: &[u8],
        initialize: bool,
        runtime: Option<&crate::hybrid_runtime_v2::HybridRuntime>,
    ) -> Result<Self> {
        let body_codec = match runtime {
            Some(runtime) => crate::journal_body_codec_v1::Codec::successor(runtime)?,
            None => crate::journal_body_codec_v1::Codec::legacy(),
        };
        let expected_version = if body_codec.is_successor() { 3 } else { 2 };
        let expected_app = if body_codec.is_successor() { 0x4d574a33 } else { APP };
        let (key, _) = PublicKey::decode_descriptor(descriptor).map_err(|_| "Node descriptor")?;
        if key.role != Role::Node || genesis == [0; 32] || fingerprint == [0; 32] {
            return Err("Work journal context".into());
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(expected_version as u8)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&genesis)
            .unwrap()
            .bytes(&fingerprint)
            .unwrap()
            .bytes(descriptor)
            .unwrap();
        let context = e.into_writer();
        if initialize && body_codec.is_successor() {
            std::fs::OpenOptions::new().write(true).create_new(true).open(path)
                .map_err(|_| "A2 work journal create-new")?;
        }
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if initialize {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let mut db = Connection::open_with_flags(path, flags).map_err(err)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(err)?;
        let app: i64 = db
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(err)?;
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(err)?;
        let count: i64 = db
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(err)?;
        if (initialize && (app != 0 || version != 0 || count != 0))
            || (!initialize && (app != expected_app || version != expected_version || count != 3))
        {
            return Err("Work journal initialization/schema mismatch".into());
        }
        let page: u64 = db
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .map_err(err)?;
        let limit = (64u64 * 1024 * 1024).checked_div(page).ok_or("Page size")?;
        let used: u64 = db
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .map_err(err)?;
        if limit < 256 || used > limit {
            return Err("Work journal capacity".into());
        }
        db.pragma_update(None, "max_page_count", limit)
            .map_err(err)?;
        let applied: u64 = db
            .pragma_query_value(None, "max_page_count", |r| r.get(0))
            .map_err(err)?;
        if applied != limit {
            return Err("Work journal capacity policy".into());
        }
        db.execute_batch(
            "PRAGMA trusted_schema=OFF;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;",
        )
        .map_err(err)?;
        let t = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        if initialize {
            let mut nonce = [0; 32];
            mutiny_crypto_v2::fill_os_random(&mut nonce).map_err(|_| "OS entropy")?;
            t.execute_batch(IDENTITY).map_err(err)?;
            t.execute_batch(TICKETS).map_err(err)?;
            t.execute(
                "INSERT INTO identity VALUES(1,?1,?2)",
                params![&context, nonce.as_slice()],
            )
            .map_err(err)?;
            t.pragma_update(None, "application_id", expected_app).map_err(err)?;
            t.pragma_update(None, "user_version", expected_version).map_err(err)?;
        }
        for (name, sql) in [("identity", IDENTITY), ("tickets", TICKETS)] {
            let actual:String=t.query_row("SELECT CASE WHEN length(CAST(sql AS BLOB))<=1024 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=?1",[name],|r|r.get(0)).map_err(err)?;
            if actual != sql {
                return Err("Work journal schema changed".into());
            }
        }
        let (stored,nonce):(Vec<u8>,Vec<u8>)=t.query_row("SELECT CASE WHEN length(context)<=4096 THEN context ELSE NULL END,CASE WHEN length(nonce)=32 THEN nonce ELSE NULL END FROM identity WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(err)?;
        if stored != context || nonce == [0; 32] {
            return Err("Work journal identity".into());
        }
        let nonce: Hash = nonce.try_into().map_err(|_| "Work journal nonce")?;
        let workers: u64 = t
            .query_row("SELECT count(*) FROM tickets", [], |r| r.get(0))
            .map_err(err)?;
        if workers > 4096 {
            return Err("Work journal local worker capacity".into());
        }
        t.commit().map_err(err)?;
        let mut journal = Self {
            db,
            genesis,
            fingerprint,
            descriptor: descriptor.to_vec(),
            nonce,
            body_codec,
        };
        if let Some(runtime) = runtime { journal.refresh_capacities(runtime)?; }
        journal.audit()?;
        Ok(journal)
    }
    fn refresh_capacities(&mut self,runtime: &crate::hybrid_runtime_v2::HybridRuntime) -> Result<()> {
        if !self.body_codec.is_successor() { return Ok(()); }
        let offers = {
            let mut q = self.db.prepare("SELECT CASE WHEN length(offer)<=8192 THEN offer ELSE NULL END FROM tickets WHERE offer IS NOT NULL LIMIT 4097").map_err(err)?;
            q.query_map([],|r|r.get::<_,Vec<u8>>(0)).map_err(err)?
                .collect::<std::result::Result<Vec<_>,_>>().map_err(err)?
        };
        if offers.len() > 4096 { return Err("Work journal local worker capacity".into()); }
        let authorities = offers.into_iter().map(|raw| Authority::decode(&raw).map_err(|_| "Stored authority".to_string())).collect::<Result<Vec<_>>>()?;
        let parents = authorities.iter().map(|a|a.work.candidate.parent).collect();
        self.body_codec.retain_parents(&parents);
        for authority in authorities { self.body_codec.bind(runtime,&authority)?; }
        Ok(())
    }
    pub(crate) fn bind_body_capacity(&mut self,runtime: &crate::hybrid_runtime_v2::HybridRuntime,authority: &Authority) -> Result<()> {
        self.refresh_capacities(runtime)?;
        self.body_codec.bind(runtime,authority)
    }
    fn audit(&self) -> Result<()> {
        let mut q=self.db.prepare("SELECT CASE WHEN length(worker)=32 THEN worker ELSE NULL END,CASE WHEN length(ticket)=8 THEN ticket ELSE NULL END,CASE WHEN length(reservation)=32 THEN reservation ELSE NULL END,CASE WHEN length(offer)<=8192 THEN offer ELSE NULL END,CASE WHEN length(body)<=?1 THEN body ELSE NULL END,length(offer),length(body) FROM tickets").map_err(err)?;
        let mut rows = q.query([self.body_codec.limit()]).map_err(err)?;
        while let Some(r) = rows.next().map_err(err)? {
            let worker: Vec<u8> = r.get(0).map_err(err)?;
            let ticket: Vec<u8> = r.get(1).map_err(err)?;
            let nonce: Vec<u8> = r.get(2).map_err(err)?;
            let offer: Option<Vec<u8>> = r.get(3).map_err(err)?;
            let body: Option<Vec<u8>> = r.get(4).map_err(err)?;
            let ol: Option<u64> = r.get(5).map_err(err)?;
            let bl: Option<u64> = r.get(6).map_err(err)?;
            let ticket = u64::from_be_bytes(ticket.try_into().map_err(|_| "Ticket encoding")?);
            if worker == [0; 32]
                || nonce == [0; 32]
                || ticket == 0
                || ol.is_some() != offer.is_some()
                || bl.is_some() != body.is_some()
            {
                return Err("Work journal record".into());
            }
            match (offer, body) {
                (None, None) => {}
                (Some(a), Some(b)) => {
                    let a = Authority::decode(&a).map_err(|_| "Stored authority")?;
                    let b = self.body_codec.decode(&a,&b)?;
                    self.validate(&a, &b)?;
                    if a.work.candidate.worker.as_slice() != worker
                        || a.work.ticket_sequence != ticket
                    {
                        return Err("Stored ticket mismatch".into());
                    }
                }
                _ => return Err("Partial stored offer".into()),
            }
        }
        Ok(())
    }
    pub fn reserve(&mut self, worker: Hash, canonical_floor: u64) -> Result<Reservation> {
        if worker == [0; 32] {
            return Err("Empty Worker".into());
        }
        let mut nonce = [0; 32];
        mutiny_crypto_v2::fill_os_random(&mut nonce).map_err(|_| "OS entropy")?;
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let previous:Option<Vec<u8>>=t.query_row("SELECT CASE WHEN length(ticket)=8 THEN ticket ELSE NULL END FROM tickets WHERE worker=?1",[worker.as_slice()],|r|r.get(0)).optional().map_err(err)?;
        if previous.is_none() {
            let n: u64 = t
                .query_row("SELECT count(*) FROM tickets", [], |r| r.get(0))
                .map_err(err)?;
            if n >= 4096 {
                return Err("Work journal local worker capacity".into());
            }
        }
        let old = previous
            .map(|v| {
                v.try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| "Ticket encoding")
            })
            .transpose()?
            .unwrap_or(0);
        let ticket = old
            .max(canonical_floor)
            .checked_add(1)
            .ok_or("Ticket exhausted")?;
        t.execute("INSERT INTO tickets VALUES(?1,?2,?3,NULL,NULL) ON CONFLICT(worker) DO UPDATE SET ticket=excluded.ticket,reservation=excluded.reservation,offer=NULL,body=NULL",params![worker.as_slice(),ticket.to_be_bytes().as_slice(),nonce.as_slice()]).map_err(err)?;
        checkpoint(1);
        t.commit().map_err(err)?;
        checkpoint(2);
        Ok(Reservation {
            journal: self.nonce,
            nonce,
            worker,
            ticket,
        })
    }
    fn validate(&self, a: &Authority, b: &BlockBody) -> Result<()> {
        a.encode().map_err(|_| "Work bounds")?;
        self.body_codec.encode(a,b)?;
        if a.node_descriptor != self.descriptor
            || a.work.candidate.genesis != self.genesis
            || a.work.candidate.fingerprint != self.fingerprint
            || a.work.candidate.network != NETWORK_ID
            || b.height != a.work.candidate.height
            || self.body_codec.root(a,b)? != a.work.candidate.body_root
        {
            return Err("Work journal offer context".into());
        }
        let (key, _) =
            PublicKey::decode_descriptor(&self.descriptor).map_err(|_| "Node descriptor")?;
        key.verify(
            Domain::NodeWork,
            &a.unsigned().map_err(|_| "Work encoding")?,
            &a.signature,
        )
        .map_err(|_| "Work signature".into())
    }
    /// Only a fully signed offer is published. Repeated identical finish is
    /// harmless; replacement under the same reservation is rejected.
    pub fn finish(
        &mut self,
        reservation: &Reservation,
        a: &Authority,
        b: &BlockBody,
    ) -> Result<()> {
        if reservation.journal != self.nonce
            || reservation.worker != a.work.candidate.worker
            || reservation.ticket != a.work.ticket_sequence
        {
            return Err("Reservation context".into());
        }
        self.validate(a, b)?;
        let offer = a.encode().map_err(|_| "Work encoding")?;
        let body = self.body_codec.encode(a,b)?;
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let existing:(Vec<u8>,Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>,Option<u64>,Option<u64>)=t.query_row("SELECT CASE WHEN length(ticket)=8 THEN ticket ELSE NULL END,CASE WHEN length(reservation)=32 THEN reservation ELSE NULL END,CASE WHEN length(offer)<=8192 THEN offer ELSE NULL END,CASE WHEN length(body)<=?2 THEN body ELSE NULL END,length(offer),length(body) FROM tickets WHERE worker=?1",params![reservation.worker.as_slice(),self.body_codec.limit()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).map_err(err)?;
        if existing.0 != reservation.ticket.to_be_bytes() || existing.1 != reservation.nonce {
            return Err("Reservation superseded".into());
        }
        if existing.2.is_some() != existing.4.is_some()
            || existing.3.is_some() != existing.5.is_some()
        {
            return Err("Oversized stored offer".into());
        }
        match (existing.2, existing.3) {
            (None, None) => {
                t.execute(
                    "UPDATE tickets SET offer=?1,body=?2 WHERE worker=?3",
                    params![offer, body, reservation.worker.as_slice()],
                )
                .map_err(err)?;
            }
            (Some(old), Some(previous)) if old == offer && previous == body => {}
            _ => return Err("Reservation already finalized or corrupt".into()),
        }
        t.commit().map_err(err)?;
        Ok(())
    }
    pub fn lookup(&self, worker: Hash) -> Result<Option<(Authority, BlockBody)>> {
        let row:Option<(Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>,Option<u64>,Option<u64>)>=self.db.query_row(
            "SELECT CASE WHEN length(ticket)=8 THEN ticket ELSE NULL END,CASE WHEN length(offer)<=8192 THEN offer ELSE NULL END,CASE WHEN length(body)<=?2 THEN body ELSE NULL END,length(offer),length(body) FROM tickets WHERE worker=?1",
            params![worker.as_slice(),self.body_codec.limit()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(err)?;
        let Some((ticket, offer, body, ol, bl)) = row else {
            return Ok(None);
        };
        if offer.is_some() != ol.is_some() || body.is_some() != bl.is_some() {
            return Err("Oversized stored offer".into());
        }
        match (offer, body) {
            (None, None) => Ok(None),
            (Some(a), Some(b)) => {
                let a = Authority::decode(&a).map_err(|_| "Stored authority")?;
                let b = self.body_codec.decode(&a,&b)?;
                self.validate(&a, &b)?;
                if a.work.candidate.worker != worker
                    || a.work.ticket_sequence.to_be_bytes().as_slice() != ticket
                {
                    return Err("Stored ticket mismatch".into());
                }
                Ok(Some((a, b)))
            }
            _ => Err("Partial stored offer".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path() -> std::path::PathBuf {
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        std::env::temp_dir().join(format!(
            "build8-synthetic-work-journal-{}.sqlite",
            hex::encode(nonce)
        ))
    }
    #[test]
    fn child_reservation_crash() {
        let Ok(raw) = std::env::var("BUILD8_SYNTHETIC_WORK_JOURNAL_CHILD") else {
            return;
        };
        let p = std::path::PathBuf::from(raw);
        assert_eq!(p.parent().unwrap(), std::env::temp_dir());
        assert!(
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("build8-synthetic-work-journal-")
        );
        let descriptor =
            hex::decode(std::env::var("BUILD8_SYNTHETIC_WORK_DESCRIPTOR").unwrap()).unwrap();
        assert!(descriptor.len() <= 2048);
        let point: u8 = std::env::var("BUILD8_SYNTHETIC_WORK_CRASH_POINT")
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=2).contains(&point));
        let mut journal = Journal::reopen(&p, [1; 32], [2; 32], &descriptor).unwrap();
        CRASH.with(|v| v.set(point));
        journal.reserve([3; 32], 0).unwrap();
        panic!("crash point not reached");
    }
    #[test]
    fn real_process_interruption_consumes_only_committed_ticket() {
        let key = mutiny_crypto_v2::HybridKey::generate(Role::Node).unwrap();
        let descriptor = key.public().descriptor(1).unwrap();
        drop(key);
        for point in 1u8..=2 {
            let p = path();
            drop(Journal::initialize(&p, [1; 32], [2; 32], &descriptor).unwrap());
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "work_journal_v2::tests::child_reservation_crash",
                    "--nocapture",
                ])
                .env("BUILD8_SYNTHETIC_WORK_JOURNAL_CHILD", &p)
                .env("BUILD8_SYNTHETIC_WORK_DESCRIPTOR", hex::encode(&descriptor))
                .env("BUILD8_SYNTHETIC_WORK_CRASH_POINT", point.to_string())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(91));
            let mut journal = Journal::reopen(&p, [1; 32], [2; 32], &descriptor).unwrap();
            assert!(journal.lookup([3; 32]).unwrap().is_none());
            assert_eq!(
                journal.reserve([3; 32], 0).unwrap().ticket(),
                u64::from(point)
            );
            drop(journal);
            std::fs::remove_file(p).unwrap();
        }
    }
    #[test]
    fn partial_oversized_and_schema_corruption_fail_closed() {
        let key = mutiny_crypto_v2::HybridKey::generate(Role::Node).unwrap();
        let descriptor = key.public().descriptor(1).unwrap();
        drop(key);
        for sql in [
            "UPDATE tickets SET offer=x'00'",
            "UPDATE tickets SET offer=zeroblob(8193),body=x'00'",
            "UPDATE tickets SET body=zeroblob(65537),offer=x'00'",
            "DROP TABLE tickets",
        ] {
            let p = path();
            let mut journal = Journal::initialize(&p, [1; 32], [2; 32], &descriptor).unwrap();
            journal.reserve([3; 32], 0).unwrap();
            let fault = Connection::open(&p).unwrap();
            fault.execute_batch(sql).unwrap();
            drop(fault);
            assert!(journal.lookup([3; 32]).is_err());
            drop(journal);
            assert!(Journal::reopen(&p, [1; 32], [2; 32], &descriptor).is_err());
            std::fs::remove_file(p).unwrap();
        }
    }
}
