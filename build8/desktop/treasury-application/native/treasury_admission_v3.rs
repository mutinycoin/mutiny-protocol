//! SOURCE-ONLY Linux native Treasury consumer; not registered or compiled.
//! Existing proof/schema/domain and Production refusal are preserved. An owned
//! native session persists through every read, external callback and commit.
//! Actual current-service reconciliation remains the continuity owner's gate.
#![cfg(target_os = "linux")]
use crate::{Hash, treasury_rehearsal_v3::{self as rehearsal, CeremonyConfig,
    Denylist, Expect, Outcome, Refusal, VerifiedProof}};
use mutiny_crypto_v2::{HybridSignature, PublicKey, treasury_proof_v1::{self as proof, Challenge}};
use rusqlite::{Connection, TransactionBehavior, params};
use std::{num::NonZeroU64, path::Path, sync::OnceLock};
use crate::treasury_bounded_readers::{ExpectedSchema, ReadWindow};
use crate::treasury_storage_owner::Storage;
use crate::protected_owner::{Owner, Error as NativeError};

pub const STORE_SCHEMA: &str = "MUTINY-D2-TREASURY-ADMISSION-STORE-V3";
const BINDING_SQL: &str = "CREATE TABLE store_binding(id INTEGER PRIMARY KEY CHECK(id=1), schema TEXT NOT NULL, \
    context BLOB NOT NULL CHECK(typeof(context)='blob' AND length(context)=32), \
    record_sha256 BLOB NOT NULL CHECK(typeof(record_sha256)='blob' AND length(record_sha256)=32), \
    store_id BLOB NOT NULL CHECK(typeof(store_id)='blob' AND length(store_id)=32))";
const ADMISSIONS_SQL: &str = "CREATE TABLE admissions(nonce BLOB PRIMARY KEY CHECK(typeof(nonce)='blob' AND length(nonce)=32), \
    challenge BLOB NOT NULL CHECK(typeof(challenge)='blob'), descriptor BLOB NOT NULL CHECK(typeof(descriptor)='blob'), \
    signature BLOB NOT NULL CHECK(typeof(signature)='blob' AND length(signature)=1394)) WITHOUT ROWID";
const ISSUED_SQL: &str = "CREATE TABLE issued(nonce BLOB PRIMARY KEY CHECK(typeof(nonce)='blob' AND length(nonce)=32), challenge BLOB NOT NULL CHECK(typeof(challenge)='blob'), descriptor BLOB NOT NULL CHECK(typeof(descriptor)='blob'), consumed INTEGER NOT NULL CHECK(typeof(consumed)='integer' AND consumed IN(0,1))) WITHOUT ROWID";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreIdentity(Hash);
impl StoreIdentity {
    pub fn from_trusted_id(id: Hash) -> Outcome<Self> {
        if id == [0; 32] { Err(Refusal::WrongStore) } else { Ok(Self(id)) }
    }
    pub fn store_id(self) -> Hash { self.0 }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issuance { pub challenge: Vec<u8>, pub descriptor: Vec<u8>, pub consumed: bool }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission { pub nonce: Hash, pub challenge: Vec<u8>, pub descriptor: Vec<u8>, pub signature: Vec<u8> }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Durability { pub synchronous: i64, pub journal_mode: String, pub query_only: bool, pub read_only: bool }

/// Mandatory LOCAL storage limits. No consensus timing/fee/profile defaults.
/// This configuration does not certify a filesystem or authorize Production.
#[derive(Clone, Copy)]
pub struct LocalStoragePolicy { file_cap: i64, vm_steps: NonZeroU64 }
impl LocalStoragePolicy {
    pub fn new(file_cap: i64, vm_steps: NonZeroU64) -> Outcome<Self> {
        if !(1..=32 * 1024 * 1024).contains(&file_cap) { return Err(Refusal::Store); }
        Ok(Self { file_cap, vm_steps })
    }
}
pub struct AdmissionStore {
    storage: Storage,
    context: Hash, record_sha256: Hash, store_id: Hash, writable: bool,
    policy: LocalStoragePolicy,
}
fn sql<T>(value: rusqlite::Result<T>) -> Outcome<T> { value.map_err(|_| Refusal::Store) }
fn native(_: NativeError) -> Refusal { Refusal::Store }
fn require_test_value(config: &CeremonyConfig) -> Outcome<()> {
    if config.phase() != proof::Phase::Rehearsal || config.class() != crate::treasury_v1::Class::TestValue {
        return Err(Refusal::ProductionRefused);
    }
    Ok(())
}
fn binding(config: &CeremonyConfig) -> Outcome<(Hash, Hash)> {
    Ok((config.context().value(), rehearsal::record_sha256(config.treasury())?))
}
fn expected_objects() -> Outcome<&'static Vec<ExpectedSchema>> {
    static EXPECTED: OnceLock<Vec<ExpectedSchema>> = OnceLock::new();
    if let Some(value) = EXPECTED.get() { return Ok(value); }
    // Trusted literal schema in a new scratch object. No restored schema enters
    // this expected set; application file schema is bounded before collection.
    let db = sql(Connection::open_in_memory())?;
    sql(db.execute_batch(&format!("{BINDING_SQL};\n{ISSUED_SQL};\n{ADMISSIONS_SQL};")))?;
    let found = {
        let mut query = sql(db.prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY name"))?;
        sql(sql(query.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))))?.collect())?
    };
    Ok(EXPECTED.get_or_init(|| found))
}
fn validate_reader(reader: &ReadWindow<'_>, context: Hash, record: Hash, id: Hash) -> Outcome<()> {
    let (label, c, r, found) = reader.binding(STORE_SCHEMA)?;
    if label != STORE_SCHEMA || c != context || r != record { return Err(Refusal::StoreBinding); }
    if found != id || id == [0;32] { return Err(Refusal::WrongStore); }
    Ok(())
}
fn durability(db: &Connection) -> Outcome<Durability> {
    Ok(Durability {
        synchronous: sql(db.pragma_query_value(None, "synchronous", |r| r.get(0)))?,
        journal_mode: crate::treasury_bounded_readers::journal_mode(db)?,
        query_only: sql(db.pragma_query_value(None, "query_only", |r| r.get::<_,i64>(0)))? != 0,
        read_only: sql(db.is_readonly(rusqlite::MAIN_DB))?,
    })
}
fn require_durability(db: &Connection, writable: bool) -> Outcome<()> {
    let d = durability(db)?;
    if sql(db.pragma_query_value(None,"trusted_schema",|r|r.get::<_,i64>(0)))? != 0
        || d.journal_mode != "delete"
        || (writable && (d.synchronous != 3 || d.query_only || d.read_only))
        || (!writable && (!d.query_only || !d.read_only)) { return Err(Refusal::Store); }
    Ok(())
}
fn checked(nonce: Hash, challenge: Vec<u8>, descriptor: Vec<u8>, signature: Vec<u8>) -> Outcome<Admission> {
    let decoded = Challenge::decode(&challenge).map_err(|_| Refusal::Store)?;
    if decoded.nonce != nonce || proof::signature_from_bytes(&signature).is_err() { return Err(Refusal::Store); }
    Ok(Admission { nonce, challenge, descriptor, signature })
}
fn issued_reader(reader: &ReadWindow<'_>, nonce: &Hash, context: Hash, record: Hash) -> Outcome<Option<Issuance>> {
    reader.issued(nonce)?.map(|(challenge, descriptor, consumed)| {
        let c = Challenge::decode(&challenge).map_err(|_| Refusal::Store)?;
        if c.nonce != *nonce || c.ceremony_context != context || c.treasury_record_sha256 != record
            || c.phase != proof::Phase::Rehearsal || ![0,1].contains(&consumed)
            || c.check_descriptor(&descriptor).is_err() { return Err(Refusal::Store); }
        match (consumed, reader.recorded(nonce)?) {
            (0,None) => {},
            (1,Some((ref a, ref d, ref s))) if a == &challenge && d == &descriptor
                && checked(*nonce,a.clone(),d.clone(),s.clone()).is_ok() => {},
            _ => return Err(Refusal::Store),
        }
        Ok(Issuance { challenge, descriptor, consumed: consumed == 1 })
    }).transpose()
}
fn recorded_reader(reader: &ReadWindow<'_>, nonce: &Hash, context: Hash, record: Hash) -> Outcome<Option<Admission>> {
    reader.recorded(nonce)?.map(|(challenge, descriptor, signature)| {
        let row = checked(*nonce,challenge,descriptor,signature)?;
        let issued = issued_reader(reader,nonce,context,record)?.ok_or(Refusal::Store)?;
        if !issued.consumed || issued.challenge != row.challenge || issued.descriptor != row.descriptor {
            return Err(Refusal::Store);
        }
        Ok(row)
    }).transpose()
}
fn complete_records(reader: &ReadWindow<'_>, context: Hash, record: Hash)
    -> Outcome<Vec<crate::treasury_continuity_v1::PublicRecord>> {
    // Check every admitted association as well as every issued row; this rejects
    // orphan admissions rather than mistaking absent service rows for authority.
    let admitted = reader.admissions()?;
    for (nonce,c,d,s) in &admitted {
        let nonce: Hash = nonce.as_slice().try_into().map_err(|_| Refusal::Store)?;
        let row = recorded_reader(reader,&nonce,context,record)?.ok_or(Refusal::Store)?;
        if row.challenge != *c || row.descriptor != *d || row.signature != *s { return Err(Refusal::Store); }
    }
    let mut result = Vec::new();
    let mut consumed_count = 0usize;
    for nonce in reader.nonces()? {
        let nonce: Hash = nonce.try_into().map_err(|_| Refusal::Store)?;
        let issued = issued_reader(reader,&nonce,context,record)?.ok_or(Refusal::Store)?;
        let challenge = Challenge::decode(&issued.challenge)?;
        let signature = if issued.consumed {
            consumed_count += 1;
            Some(recorded_reader(reader,&nonce,context,record)?.ok_or(Refusal::Store)?.signature)
        } else { None };
        result.push(crate::treasury_continuity_v1::PublicRecord {
            generation: challenge.generation, nonce, challenge: issued.challenge,
            descriptor: issued.descriptor, signature,
        });
    }
    if consumed_count != admitted.len() { return Err(Refusal::Store); }
    Ok(result)
}
impl AdmissionStore {
    /// Exact NEW-only native object in an existing protected directory. Native
    /// VFS uses the fixed state.sqlite leaf; no arbitrary-path compatibility.
    /// New failed files are retained. Explicit close must succeed before the
    /// newly generated ID is returned; drop is never durability evidence.
    pub fn create_native(dir: &Path, config: &CeremonyConfig, policy: LocalStoragePolicy) -> Outcome<StoreIdentity> {
        require_test_value(config)?;
        let (context,record_sha256) = binding(config)?;
        let mut owner = Owner::new_only(dir,policy.file_cap).map_err(native)?;
        let mut id = [0;32];
        while id == [0;32] { mutiny_crypto_v2::fill_os_random(&mut id).map_err(|_| Refusal::Store)?; }
        owner.mutate_typed(native,|db,boundary,slot| {
            require_durability(db,true)?;
            let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let initial = ReadWindow::open_empty(&tx,slot,policy.vm_steps)?;
            boundary.status().map_err(native)?;
            sql(tx.execute_batch(&format!("{BINDING_SQL};\n{ISSUED_SQL};\n{ADMISSIONS_SQL};")))?;
            sql(tx.execute("INSERT INTO store_binding VALUES(1,?1,?2,?3,?4)",
                params![STORE_SCHEMA,context.as_slice(),record_sha256.as_slice(),id.as_slice()]))?;
            drop(initial);
            let reader = ReadWindow::open(&tx,expected_objects()?,slot,policy.vm_steps)?;
            validate_reader(&reader,context,record_sha256,id)?;
            drop(reader);
            boundary.status().map_err(native)?;
            sql(tx.commit())?;
            boundary.status().map_err(native)
        })?;
        owner.close().map_err(|(_,error)|native(error))?;
        Ok(StoreIdentity(id))
    }
    pub fn open_native(dir: &Path, config: &CeremonyConfig, expected: StoreIdentity,
        policy: LocalStoragePolicy) -> Outcome<Self> {
        Self::open_native_with(dir,config,expected,policy,true)
    }
    pub fn open_native_read_only(dir: &Path, config: &CeremonyConfig, expected: StoreIdentity,
        policy: LocalStoragePolicy) -> Outcome<Self> {
        Self::open_native_with(dir,config,expected,policy,false)
    }
    fn open_native_with(dir: &Path,config: &CeremonyConfig,expected: StoreIdentity,
        policy: LocalStoragePolicy,writable: bool) -> Outcome<Self> {
        require_test_value(config)?;
        let (context,record_sha256) = binding(config)?;
        // Inspect exact owned object READ_ONLY. No path drop/reopen gap. Initial
        // unknown/hot journal refuses; actual protected pager recovery remains
        // a separately required source/native acceptance tranche.
        let mut owner = Owner::existing_only(dir,policy.file_cap,true).map_err(native)?;
        owner.inspect_typed(native,|db,slot| {
            require_durability(db,false)?;
            let reader = ReadWindow::open(db,expected_objects()?,slot,policy.vm_steps)?;
            validate_reader(&reader,context,record_sha256,expected.0)?;
            complete_records(&reader,context,record_sha256).map(|_| ())
        })?;
        if writable {
            owner.promote_after_binding(native,|db,slot| {
                let reader = ReadWindow::open(db,expected_objects()?,slot,policy.vm_steps)?;
                validate_reader(&reader,context,record_sha256,expected.0)?;
                complete_records(&reader,context,record_sha256).map(|_| ())
            })?;
        }
        owner.inspect_typed(native,|db,_|require_durability(db,writable))?;
        Ok(Self { storage: Storage::from_native_candidate(owner), context, record_sha256,
            store_id: expected.0, writable, policy })
    }
    pub fn check_binding(&self, config: &CeremonyConfig) -> Outcome<()> {
        require_test_value(config)?;
        let (context,record) = binding(config)?;
        if (context,record) != (self.context,self.record_sha256) { return Err(Refusal::StoreBinding); }
        self.storage.read(|db,slot| {
            let reader = ReadWindow::open(db,expected_objects()?,slot,self.policy.vm_steps)?;
            validate_reader(&reader,context,record,self.store_id)
        })
    }
    pub fn is_read_only(&self) -> bool { !self.writable }
    pub fn store_id(&self) -> Hash { self.store_id }
    pub fn durability(&self) -> Outcome<Durability> { self.storage.read(|db,_|durability(db)) }
    /// Trusted continuity-owner external calls only. Immutable borrow retains
    /// the exact native object throughout current-query/ConfirmLocal delivery.
    /// Preserve the caller's semantic error; this is no authentication factory.
    pub(crate) fn guarded_external<R,E>(&self,map:fn(Refusal)->E,
        action:impl FnOnce()->Result<R,E>)->Result<R,E>{
        self.storage.status().map_err(map)?;
        let result=action();
        self.storage.status().map_err(map)?;
        result
    }
    pub fn close(self) -> Result<(),(Self,Refusal)> {
        let Self { storage,context,record_sha256,store_id,writable,policy } = self;
        storage.close().map_err(|(storage,error)|
            (Self { storage,context,record_sha256,store_id,writable,policy },error))
    }
    pub fn issue(&mut self, expect: &Expect, descriptor: &[u8], denylist: &Denylist) -> Outcome<Challenge> {
        self.issue_with_reservation(expect,descriptor,denylist,|_,_|Ok(()))
    }
    pub(crate) fn issue_with_reservation(&mut self, expect: &Expect, descriptor: &[u8], denylist: &Denylist,
        mut reserve: impl FnMut(&Challenge,&[u8])->Outcome<()>) -> Outcome<Challenge> {
        self.check_binding(expect.config())?;
        if !self.writable { return Err(Refusal::Store); }
        rehearsal::check_issuance_descriptor(expect,descriptor)?;
        let (public,_) = PublicKey::decode_descriptor(descriptor)
            .map_err(|_|Refusal::Proof(proof::ProofError::DescriptorInvalid))?;
        if denylist.contains(&public) { return Err(Refusal::Denylisted); }
        let (context,record,id,steps) = (self.context,self.record_sha256,self.store_id,self.policy.vm_steps);
        self.storage.write(|db,boundary,slot| {
            let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let reader = ReadWindow::open(&tx,expected_objects()?,slot,steps)?;
            validate_reader(&reader,context,record,id)?;
            if complete_records(&reader,context,record)?.len() >= 2048 { return Err(Refusal::Store); }
            let mut nonce = [0;32];
            while nonce == [0;32] { mutiny_crypto_v2::fill_os_random(&mut nonce).map_err(|_|Refusal::Store)?; }
            let challenge = rehearsal::build_challenge(expect.config(),descriptor,nonce)?;
            let bytes = challenge.encode()?;
            // Keep the exact schema-first SQLite snapshot and native pins alive
            // across the adopted irreversible service boundary.
            #[cfg(test)] native_store_controls::before_external();
            boundary.check()?;
            reserve(&challenge,descriptor)?;
            boundary.check()?;
            if sql(tx.execute("INSERT INTO issued VALUES(?1,?2,?3,0)",params![nonce.as_slice(),bytes,descriptor]))? != 1 {
                return Err(Refusal::Store);
            }
            drop(reader);
            #[cfg(test)] native_store_controls::before_commit();
            boundary.check()?;
            sql(tx.commit())?;
            boundary.check()?;
            Ok(challenge)
        })
    }
    pub fn issued(&self, nonce: &Hash) -> Outcome<Option<Issuance>> {
        self.storage.read(|db,slot| {
            let reader = ReadWindow::open(db,expected_objects()?,slot,self.policy.vm_steps)?;
            validate_reader(&reader,self.context,self.record_sha256,self.store_id)?;
            issued_reader(&reader,nonce,self.context,self.record_sha256)
        })
    }
    pub fn verify_issued(&self,expect: &Expect,descriptor: &[u8],challenge_bytes: &[u8],signature: &HybridSignature,
        denylist: &Denylist) -> Outcome<VerifiedProof> {
        self.check_binding(expect.config())?;
        let verified = rehearsal::verify_crypto_bound(expect,descriptor,challenge_bytes,signature,denylist)?;
        self.storage.read(|db,slot| {
            let reader = ReadWindow::open(db,expected_objects()?,slot,self.policy.vm_steps)?;
            validate_reader(&reader,self.context,self.record_sha256,self.store_id)?;
            let issued = issued_reader(&reader,&verified.nonce,self.context,self.record_sha256)?.ok_or(Refusal::UnknownChallenge)?;
            if issued.challenge != challenge_bytes || issued.descriptor != descriptor { return Err(Refusal::IssuanceMismatch); }
            if issued.consumed && recorded_reader(&reader,&verified.nonce,self.context,self.record_sha256)?
                .ok_or(Refusal::Store)?.signature != proof::signature_to_bytes(signature) { return Err(Refusal::NotAdmitted); }
            Ok(verified)
        })
    }
    pub fn admit(&mut self,expect: &Expect,descriptor: &[u8],challenge_bytes: &[u8],signature: &HybridSignature,
        denylist: &Denylist) -> Outcome<VerifiedProof> {
        self.admit_with_consumption(expect,descriptor,challenge_bytes,signature,denylist,|_|Ok(()))
    }
    pub(crate) fn admit_with_consumption(&mut self,expect: &Expect,descriptor: &[u8],challenge_bytes: &[u8],
        signature: &HybridSignature,denylist: &Denylist,mut consume: impl FnMut(&VerifiedProof)->Outcome<()>) -> Outcome<VerifiedProof> {
        self.check_binding(expect.config())?;
        if !self.writable { return Err(Refusal::Store); }
        let verified = rehearsal::verify_crypto_bound(expect,descriptor,challenge_bytes,signature,denylist)?;
        let (context,record,id,steps) = (self.context,self.record_sha256,self.store_id,self.policy.vm_steps);
        self.storage.write(|db,boundary,slot| {
            let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let reader = ReadWindow::open(&tx,expected_objects()?,slot,steps)?;
            validate_reader(&reader,context,record,id)?;
            complete_records(&reader,context,record)?;
            let issued = issued_reader(&reader,&verified.nonce,context,record)?.ok_or(Refusal::UnknownChallenge)?;
            if issued.challenge != challenge_bytes || issued.descriptor != descriptor { return Err(Refusal::IssuanceMismatch); }
            if issued.consumed { return Err(Refusal::Replay); }
            #[cfg(test)] native_store_controls::before_external();
            boundary.check()?;
            consume(&verified)?;
            boundary.check()?;
            if sql(tx.execute("UPDATE issued SET consumed=1 WHERE nonce=?1 AND consumed=0",[verified.nonce.as_slice()]))? != 1 { return Err(Refusal::Store); }
            if sql(tx.execute("INSERT INTO admissions VALUES(?1,?2,?3,?4)",params![verified.nonce.as_slice(),challenge_bytes,
                descriptor,proof::signature_to_bytes(signature).as_slice()]))? != 1 { return Err(Refusal::Store); }
            drop(reader);
            #[cfg(test)] native_store_controls::before_commit();
            boundary.check()?;
            sql(tx.commit())?;
            boundary.check()?;
            Ok(verified)
        })
    }
    pub fn recorded(&self,nonce: &Hash) -> Outcome<Option<Admission>> {
        self.storage.read(|db,slot| {
            let reader = ReadWindow::open(db,expected_objects()?,slot,self.policy.vm_steps)?;
            validate_reader(&reader,self.context,self.record_sha256,self.store_id)?;
            recorded_reader(&reader,nonce,self.context,self.record_sha256)
        })
    }
    pub fn admissions(&self) -> Outcome<Vec<Admission>> {
        self.storage.read(|db,slot| {
            let reader = ReadWindow::open(db,expected_objects()?,slot,self.policy.vm_steps)?;
            validate_reader(&reader,self.context,self.record_sha256,self.store_id)?;
            reader.admissions()?.into_iter().map(|(nonce,_,_,_)| {
                let nonce: Hash = nonce.try_into().map_err(|_|Refusal::Store)?;
                recorded_reader(&reader,&nonce,self.context,self.record_sha256)?.ok_or(Refusal::Store)
            }).collect()
        })
    }
    pub(crate) fn continuity_records(&self) -> Outcome<Vec<crate::treasury_continuity_v1::PublicRecord>> {
        self.storage.read(|db,slot| {
            let reader = ReadWindow::open(db,expected_objects()?,slot,self.policy.vm_steps)?;
            validate_reader(&reader,self.context,self.record_sha256,self.store_id)?;
            complete_records(&reader,self.context,self.record_sha256)
        })
    }
    /// Trusted exact current service records plus independently trusted historical
    /// expectations; signature authentication precedes any repairing transaction.
    /// This API cannot erase service history or thaw a caller-selected DB copy.
    pub(crate) fn reconcile_continuity_records(&mut self,config: &CeremonyConfig,
        records: &[(Expect,crate::treasury_continuity_v1::PublicRecord)],denylist: &Denylist) -> Outcome<()> {
        self.check_binding(config)?;
        if !self.writable || records.len() > 2048 { return Err(Refusal::Store); }
        let mut expected = std::collections::BTreeMap::new();
        for (expect,record) in records {
            if binding(expect.config())? != binding(config)? || record.challenge.len() > 512
                || record.descriptor.len() > 2048 || record.generation != expect.generation() || record.nonce == [0;32] {
                return Err(Refusal::StoreBinding);
            }
            let challenge = Challenge::decode(&record.challenge)?;
            if challenge.nonce != record.nonce || challenge.generation != record.generation { return Err(Refusal::IssuanceMismatch); }
            if let Some(signature) = &record.signature {
                let signature = proof::signature_from_bytes(signature)?;
                rehearsal::verify_crypto_bound(expect,&record.descriptor,&record.challenge,&signature,denylist)?;
            } else {
                rehearsal::check_issuance_descriptor(expect,&record.descriptor)?;
                let (public,_) = PublicKey::decode_descriptor(&record.descriptor).map_err(|_|Refusal::Store)?;
                if denylist.contains(&public) { return Err(Refusal::Denylisted); }
                if rehearsal::build_challenge(expect.config(),&record.descriptor,record.nonce)?.encode()? != record.challenge {
                    return Err(Refusal::IssuanceMismatch);
                }
            }
            if expected.insert(record.nonce,record).is_some() { return Err(Refusal::Store); }
        }
        let (context,record,id,steps) = (self.context,self.record_sha256,self.store_id,self.policy.vm_steps);
        self.storage.write(|db,boundary,slot| {
            let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            let reader = ReadWindow::open(&tx,expected_objects()?,slot,steps)?;
            validate_reader(&reader,context,record,id)?;
            let existing = complete_records(&reader,context,record)?;
            for local in &existing {
                let exact = expected.get(&local.nonce).ok_or(Refusal::IssuanceMismatch)?;
                if local.challenge != exact.challenge || local.descriptor != exact.descriptor
                    || (local.signature.is_some() && local.signature != exact.signature) { return Err(Refusal::IssuanceMismatch); }
            }
            let existing: std::collections::BTreeMap<_,_> = existing.into_iter().map(|r|(r.nonce,r)).collect();
            boundary.check()?;
            for (nonce,public) in expected {
                if !existing.contains_key(&nonce) {
                    if sql(tx.execute("INSERT INTO issued VALUES(?1,?2,?3,0)",params![nonce.as_slice(),public.challenge,public.descriptor]))? != 1 { return Err(Refusal::Store); }
                }
                if let Some(signature) = &public.signature {
                    if existing.get(&nonce).is_none_or(|local|local.signature.is_none()) {
                        if sql(tx.execute("UPDATE issued SET consumed=1 WHERE nonce=?1 AND consumed=0",[nonce.as_slice()]))? != 1 { return Err(Refusal::Store); }
                        if sql(tx.execute("INSERT INTO admissions VALUES(?1,?2,?3,?4)",params![nonce.as_slice(),public.challenge,public.descriptor,signature]))? != 1 { return Err(Refusal::Store); }
                    }
                }
            }
            drop(reader);
            #[cfg(test)] native_store_controls::before_commit();
            boundary.check()?;
            sql(tx.commit())?;
            boundary.check()
        })
    }
}

#[cfg(test)]
#[path="../controls/native_store_controls.rs"]
mod native_store_controls;
