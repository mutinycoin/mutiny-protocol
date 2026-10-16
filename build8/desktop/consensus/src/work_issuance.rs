//! Durable operational work issuance. Canonical execution must produce both
//! parent context; the preparation callback executes using the reserved ticket.
//! Issuance is not a
//! canonical state mutation, a finality certificate, or a reward.
use crate::{Hash, blocks::BlockBody, liveness::WorkGate, pow::*};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Work issuance: {e:?}")
}

pub struct IssuedWork {
    pub authority: WorkAuthority,
    pub signature: [u8; 64],
    pub context: WorkContext,
    pub body: BlockBody,
}
impl IssuedWork {
    /// Payload of a coordinator-authenticated session frame. The request nonce
    /// prevents a delayed offer from granting a fresh lifetime after reconnect.
    pub fn offer(&self, request: Hash, lifetime_ms: u64) -> Result<Vec<u8>> {
        if request == [0; 32] || lifetime_ms == 0 || lifetime_ms > 60000 {
            return Err("Work offer request/lifetime".into());
        }
        self.validate()?;
        let c = &self.context;
        let mut raw = vec![5];
        raw.extend(request);
        raw.extend(self.authority.epoch.to_be_bytes());
        raw.extend(lifetime_ms.to_be_bytes());
        for h in [
            c.genesis,
            c.fingerprint,
            c.parent,
            c.license,
            c.worker,
            c.coordinator,
            c.target,
        ] {
            raw.extend(h);
        }
        for n in [
            c.parent_height
                .checked_add(1)
                .ok_or("Work height overflow")?,
            c.t0,
            c.assignment_sequence,
            c.last_accepted_ticket,
        ] {
            raw.extend(n.to_be_bytes());
        }
        let envelope = self.authority.envelope(&self.signature);
        raw.extend((envelope.len() as u16).to_be_bytes());
        raw.extend(envelope);
        Ok(raw)
    }
    fn validate(&self) -> Result<()> {
        if self.body.height != self.authority.candidate.height
            || self.body.root().map_err(err)? != self.authority.candidate.body_root
        {
            return Err("Issued body mismatch".into());
        }
        validate_authority(
            &WorkHeader {
                candidate: self.authority.candidate.clone(),
                authority: self.authority.id(),
                nonce: self.authority.nonce_start,
            },
            &self.authority,
            &self.signature,
            &self.context,
        )
        .map_err(err)
    }
}
pub struct WorkIssuanceStore {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
    coordinator: Hash,
}
pub struct IssueRequest {
    pub candidate: Candidate,
    pub context: WorkContext,
    pub now_ms: u64,
    pub unix_ms: u64,
}
impl WorkIssuanceStore {
    pub fn open(path: &Path, genesis: Hash, fingerprint: Hash, coordinator: Hash) -> Result<Self> {
        if [genesis, fingerprint, coordinator].contains(&[0; 32]) {
            return Err("Empty issuance identity".into());
        }
        let mut db = Connection::open(path).map_err(err)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS work_identity(id INTEGER PRIMARY KEY CHECK(id=1),genesis BLOB NOT NULL,fingerprint BLOB NOT NULL,coordinator BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS work_tickets(worker BLOB PRIMARY KEY CHECK(length(worker)=32),ticket BLOB NOT NULL CHECK(length(ticket)=8));
            CREATE TABLE IF NOT EXISTS issued_work(id BLOB PRIMARY KEY CHECK(length(id)=32),worker BLOB NOT NULL UNIQUE,ticket BLOB NOT NULL CHECK(length(ticket)=8),authority BLOB NOT NULL,context BLOB NOT NULL,body BLOB NOT NULL,UNIQUE(worker,ticket));").map_err(err)?;
        let t = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        t.execute(
            "INSERT OR IGNORE INTO work_identity VALUES(1,?1,?2,?3)",
            params![
                genesis.as_slice(),
                fingerprint.as_slice(),
                coordinator.as_slice()
            ],
        )
        .map_err(err)?;
        let identity: (Vec<u8>, Vec<u8>, Vec<u8>) = t
            .query_row(
                "SELECT genesis,fingerprint,coordinator FROM work_identity WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(err)?;
        if identity != (genesis.to_vec(), fingerprint.to_vec(), coordinator.to_vec()) {
            return Err("Issuance database identity mismatch".into());
        }
        // BE fixed-width ticket comparison remains valid above SQLite i64::MAX.
        let invalid:bool=t.query_row("SELECT EXISTS(SELECT 1 FROM issued_work i LEFT JOIN work_tickets t ON t.worker=i.worker WHERE t.worker IS NULL OR i.ticket<>t.ticket) OR EXISTS(SELECT 1 FROM work_tickets t LEFT JOIN issued_work i ON i.worker=t.worker WHERE i.worker IS NULL)",[],|r|r.get(0)).map_err(err)?;
        if invalid {
            return Err("Issuance ticket high-water integrity".into());
        }
        t.commit().map_err(err)?;
        Ok(Self {
            db,
            genesis,
            fingerprint,
            coordinator,
        })
    }
    /// Reserve and persist a new ticket before returning its signed authority.
    /// `unix_ms` comes from the node's checked production clock. The candidate
    /// timestamp must be in its current epoch. `now_ms` is monotonic and shared
    /// with WorkGate. Device expiry starts at its own request, not receipt.
    /// `final_clock` must obtain a fresh qualified reading after pure preparation;
    /// refusal rolls ticket selection back before any signing or durable writes.
    pub fn issue(
        &mut self,
        request: IssueRequest,
        key: &SigningKey,
        gate: &mut WorkGate,
        prepare: impl FnOnce(u64, &Candidate) -> Result<(Hash, BlockBody)>,
        final_clock: impl FnOnce() -> Result<(u64, u64)>,
    ) -> Result<(IssuedWork, u64)> {
        let IssueRequest {
            mut candidate,
            context,
            now_ms,
            unix_ms,
        } = request;
        if context.genesis != self.genesis
            || context.fingerprint != self.fingerprint
            || context.coordinator != self.coordinator
            || key.verifying_key().to_bytes() != self.coordinator
        {
            return Err("Issuance coordinator/context mismatch".into());
        }
        let lease = gate.work_lease(now_ms, &context).map_err(err)?;
        let epoch = mining_epoch(candidate.timestamp, context.t0).map_err(err)?;
        let genesis_ms = context
            .t0
            .checked_mul(1000)
            .ok_or("Genesis time overflow")?;
        let elapsed = unix_ms.checked_sub(genesis_ms).ok_or("Before Genesis")?;
        if elapsed / 60000 != epoch {
            return Err("Candidate MiningEpoch is not current".into());
        }
        let lifetime = lease.min(60000 - elapsed % 60000);
        if lifetime == 0 {
            return Err("No remaining work lease".into());
        }
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let previous: Option<Vec<u8>> = t
            .query_row(
                "SELECT ticket FROM work_tickets WHERE worker=?1",
                [context.worker.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let previous = previous
            .map(|v| {
                v.try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| "Invalid ticket high-water")
            })
            .transpose()?
            .unwrap_or(0);
        let ticket = previous
            .max(context.last_accepted_ticket)
            .checked_add(1)
            .ok_or("Ticket exhausted")?;
        // Ticket consumption is part of the candidate StateRoot. Execute AFTER
        // selecting the durable sequence, before signing or returning authority.
        let (state_root, body) = prepare(ticket, &candidate)?;
        candidate.state_root = state_root;
        let authority = WorkAuthority {
            candidate,
            assignment_sequence: context.assignment_sequence,
            ticket_sequence: ticket,
            coordinator: self.coordinator,
            nonce_start: 0,
            nonce_end: u64::MAX,
            epoch,
        };
        // The IMMEDIATE transaction above has only selected a ticket and run
        // pure preparation. Nothing durable was reserved or consumed. Expensive
        // preparation cannot authorize signing from the earlier cached clock.
        let (decision_now, decision_unix) = final_clock()?;
        let decision_lease = gate.work_lease(decision_now, &context).map_err(err)?;
        let decision_elapsed = decision_unix
            .checked_sub(genesis_ms)
            .ok_or("Before Genesis")?;
        if decision_elapsed / 60000 != epoch {
            return Err("Candidate MiningEpoch is not current".into());
        }
        let lifetime = decision_lease.min(60000 - decision_elapsed % 60000);
        if lifetime == 0 {
            return Err("No remaining work lease".into());
        }
        let signature = key.sign(&authority.id()).to_bytes();
        let issued = IssuedWork {
            authority,
            signature,
            context,
            body,
        };
        issued.validate()?;
        let encoded_context = encode_context(&issued.context);
        // Coordinator permits a new request only after the device presents its
        // durable accounting checkpoint and has no pending result. Retain one
        // current authority/body per Worker; ticket high-water is never deleted.
        t.execute(
            "DELETE FROM issued_work WHERE worker=?1",
            [issued.context.worker.as_slice()],
        )
        .map_err(err)?;
        t.execute(
            "INSERT INTO issued_work VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                issued.authority.id().as_slice(),
                issued.context.worker.as_slice(),
                ticket.to_be_bytes().as_slice(),
                issued.authority.envelope(&issued.signature),
                encoded_context,
                issued.body.encode().map_err(err)?
            ],
        )
        .map_err(err)?;
        t.execute("INSERT INTO work_tickets VALUES(?1,?2) ON CONFLICT(worker) DO UPDATE SET ticket=excluded.ticket",params![issued.context.worker.as_slice(),ticket.to_be_bytes().as_slice()]).map_err(err)?;
        t.commit().map_err(err)?;
        Ok((issued, lifetime))
    }
    /// Retain issuance records across restart and work retirement so the exact
    /// durable device outbox can receive its original accounting receipt.
    /// No pruning or implicit rebuilding of ticket high-water marks is allowed.
    pub fn lookup(&self, id: Hash, worker: Hash) -> Result<IssuedWork> {
        let (authority, context, body): (Vec<u8>, Vec<u8>, Vec<u8>) = self
            .db
            .query_row(
                "SELECT authority,context,body FROM issued_work WHERE id=?1 AND worker=?2",
                params![id.as_slice(), worker.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(err)?;
        let (authority, signature) = WorkAuthority::from_envelope(&authority).map_err(err)?;
        let context = decode_context(&context)?;
        let body = BlockBody::decode(&body).map_err(err)?;
        if authority.id() != id
            || context.worker != worker
            || context.genesis != self.genesis
            || context.fingerprint != self.fingerprint
            || context.coordinator != self.coordinator
        {
            return Err("Stored issuance context mismatch".into());
        }
        let issued = IssuedWork {
            authority,
            signature,
            context,
            body,
        };
        issued.validate()?;
        Ok(issued)
    }
}
fn encode_context(c: &WorkContext) -> Vec<u8> {
    let mut raw = Vec::with_capacity(344);
    raw.push(1);
    for h in [
        c.genesis,
        c.fingerprint,
        c.parent,
        c.target,
        c.license,
        c.worker,
        c.coordinator,
    ] {
        raw.extend(h);
    }
    for n in [
        c.parent_height,
        c.t0,
        c.assignment_sequence,
        c.last_accepted_ticket,
    ] {
        raw.extend(n.to_be_bytes());
    }
    raw.push(c.ancestor_timestamps.len() as u8);
    for n in &c.ancestor_timestamps {
        raw.extend(n.to_be_bytes());
    }
    raw
}
fn decode_context(raw: &[u8]) -> Result<WorkContext> {
    if raw.len() < 258
        || raw.len() > 346
        || raw[0] != 1
        || raw[257] > 11
        || raw.len() != 258 + 8 * usize::from(raw[257])
    {
        return Err("Stored work context encoding".into());
    }
    let hash = |at| -> Hash { raw[at..at + 32].try_into().unwrap() };
    let number = |at| u64::from_be_bytes(raw[at..at + 8].try_into().unwrap());
    Ok(WorkContext {
        genesis: hash(1),
        fingerprint: hash(33),
        parent: hash(65),
        target: hash(97),
        license: hash(129),
        worker: hash(161),
        coordinator: hash(193),
        parent_height: number(225),
        t0: number(233),
        assignment_sequence: number(241),
        last_accepted_ticket: number(249),
        ancestor_timestamps: (258..raw.len()).step_by(8).map(number).collect(),
    })
}
