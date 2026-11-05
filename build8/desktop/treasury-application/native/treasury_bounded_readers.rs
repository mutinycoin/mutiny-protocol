//! UNCOMPILED typed readers for the trusted native Treasury Store integration.
//! These guards precede every String/Vec allocation. CHECK declarations and
//! SQLite database integrity do not establish valid lengths/types/counts.
//! Logical exact-context/binding/hybrid proof/association validation still runs
//! after these bounded reads, inside the caller's same native-owner closure.
use crate::{Hash,treasury_rehearsal_v3::{Outcome,Refusal}};
use rusqlite::{Connection,Transaction,OptionalExtension,types::ValueRef,ffi};
use std::{cell::Cell,num::NonZeroU64,ffi::{c_void,c_int}};
fn storage<T>(x:rusqlite::Result<T>)->Outcome<T>{x.map_err(|_|Refusal::Store)}
pub(crate) type Issued=(Vec<u8>,Vec<u8>,i64);
pub(crate) type Recorded=(Vec<u8>,Vec<u8>,Vec<u8>);
pub(crate) type AdmissionRow=(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>);
/// The exact expected schema comes from trusted Root expected_objects(),
/// constructed by THIS pinned SQLite from the existing three literal tables.
pub(crate) type ExpectedSchema=(String,String,String);
/// Stored exactly once beside the actual native owner's Connection. This is
/// a LOCAL resource-registration slot; it grants no storage/admission authority.
/// Its private construction is not a public caller boolean or raw-handle API.
pub(crate) struct WorkSlot { handle:*mut ffi::sqlite3,active:Cell<bool> }
impl WorkSlot {
    pub(crate) fn for_owned_connection(db:&Connection)->Self{
        Self{handle:unsafe{db.handle()},active:Cell::new(false)}
    }
}
pub(crate) struct VmBudget<'a>{ db:&'a Connection,slot:&'a WorkSlot,remaining:Box<Cell<u64>> }
unsafe extern "C" fn progress(data:*mut c_void)->c_int{
    if data.is_null(){return 1;}
    let remaining=unsafe{&*data.cast::<Cell<u64>>()};
    match remaining.get(){0=>1,n=>{remaining.set(n-1);0}}
}
impl<'a> VmBudget<'a>{
    pub(crate) fn install(db:&'a Connection,slot:&'a WorkSlot,steps:NonZeroU64)->Outcome<Self>{
        if slot.handle!=unsafe{db.handle()} || slot.active.replace(true){return Err(Refusal::Store);}
        let remaining=Box::new(Cell::new(steps.get()));
        // Native Owner gives this trusted reader exclusive connection use.
        // No other handler may coexist; product integration owns this slot.
        unsafe{ffi::sqlite3_progress_handler(db.handle(),1,Some(progress),
            (&*remaining as *const Cell<u64>).cast_mut().cast())};
        Ok(Self{db,slot,remaining})
    }
}
impl Drop for VmBudget<'_>{
    fn drop(&mut self){
        // Clear BEFORE Box disposal and BEFORE read-transaction rollback.
        // Resource exhaustion must not leave an interrupting dangling handler.
        unsafe{ffi::sqlite3_progress_handler(self.db.handle(),0,None,std::ptr::null_mut())};
        self.slot.active.set(false);
    }
}
pub(crate) struct ReadWindow<'a> {
    db:&'a Connection,
    // Declaration order deliberately drops handler before owned transaction.
    _budget:VmBudget<'a>,_snapshot:Option<Transaction<'a>>,
}
impl<'a> ReadWindow<'a> {
    /// NEW-only trusted initializer. No application rows/schema strings are
    /// read before exact empty sqlite_schema is established in this snapshot.
    /// The mandatory local budget remains installed across literal DDL/INSERT.
    pub(crate) fn open_empty(db:&'a Connection,slot:&'a WorkSlot,
                            existing_local_step_budget:NonZeroU64)->Outcome<Self>{
        let budget=VmBudget::install(db,slot,existing_local_step_budget)?;
        let snapshot=if db.is_autocommit(){Some(storage(db.unchecked_transaction())?)}else{None};
        let reader=Self{db,_budget:budget,_snapshot:snapshot};
        if reader.scalar("SELECT count(*) FROM sqlite_schema")?!=0{return Err(Refusal::StoreBinding);}
        Ok(reader)
    }
    pub(crate) fn open(db:&'a Connection,expected:&[ExpectedSchema],slot:&'a WorkSlot,
                      existing_local_step_budget:NonZeroU64)->Outcome<Self>{
        // Mandatory explicit LOCAL work budget: no consensus TTL/number/default.
        // Integration must supply its existing approved storage-work budget.
        // Nested trusted readers reuse the outer transaction rather than BEGIN.
        let budget=VmBudget::install(db,slot,existing_local_step_budget)?;
        let snapshot=if db.is_autocommit(){Some(storage(db.unchecked_transaction())?)}else{None};
        let reader=Self{db,_budget:budget,_snapshot:snapshot};
        reader.schema_bounds()?;
        // Only sqlite_schema has been queried so far. Exact type/name/SQL
        // validation MUST precede any issued/admissions/store_binding query.
        let objects=reader.schema_objects()?;
        if objects.len()!=expected.len() || objects.iter().zip(expected).any(|(a,b)|
            a.0!=b.0 || a.1!=b.1 || a.2.as_deref()!=Some(b.2.as_str())){
            return Err(Refusal::Store);
        }
        reader.row_bounds()?;Ok(reader)
    }
    fn scalar(&self,sql:&str)->Outcome<i64>{storage(self.db.query_row(sql,[],|r|r.get(0)))}
    fn schema_bounds(&self)->Outcome<()>{
        if !(0..=16).contains(&self.scalar("SELECT count(*) FROM sqlite_schema")?){return Err(Refusal::Store);}
        if self.scalar("SELECT count(*) FROM sqlite_schema WHERE typeof(type)!='text' OR length(CAST(type AS blob))>32 OR typeof(name)!='text' OR length(CAST(name AS blob))>128 OR (sql IS NOT NULL AND (typeof(sql)!='text' OR length(CAST(sql AS blob))>4096))")?!=0{return Err(Refusal::Store);}
        Ok(())
    }
    fn row_bounds(&self)->Outcome<()>{
        if !(0..=2048).contains(&self.scalar("SELECT count(*) FROM issued")?) || !(0..=2048).contains(&self.scalar("SELECT count(*) FROM admissions")?){return Err(Refusal::Store);}
        if self.scalar("SELECT count(*) FROM issued WHERE typeof(nonce)!='blob' OR length(nonce)!=32 OR typeof(challenge)!='blob' OR length(challenge) NOT BETWEEN 1 AND 512 OR typeof(descriptor)!='blob' OR length(descriptor) NOT BETWEEN 1 AND 2048 OR typeof(consumed)!='integer' OR consumed NOT IN(0,1)")?!=0{return Err(Refusal::Store);}
        if self.scalar("SELECT count(*) FROM admissions WHERE typeof(nonce)!='blob' OR length(nonce)!=32 OR typeof(challenge)!='blob' OR length(challenge) NOT BETWEEN 1 AND 512 OR typeof(descriptor)!='blob' OR length(descriptor) NOT BETWEEN 1 AND 2048 OR typeof(signature)!='blob' OR length(signature)!=1394")?!=0{return Err(Refusal::Store);}
        Ok(())
    }
    pub(crate) fn binding(&self,label:&str)->Outcome<(String,Vec<u8>,Vec<u8>,Vec<u8>)>{
        if self.scalar("SELECT count(*) FROM store_binding")?!=1{return Err(Refusal::StoreBinding);}
        let invalid:i64=storage(self.db.query_row("SELECT count(*) FROM store_binding WHERE typeof(id)!='integer' OR id!=1 OR typeof(schema)!='text' OR length(CAST(schema AS blob))!=?1 OR typeof(context)!='blob' OR length(context)!=32 OR typeof(record_sha256)!='blob' OR length(record_sha256)!=32 OR typeof(store_id)!='blob' OR length(store_id)!=32",[label.len() as i64],|r|r.get(0)))?;
        if invalid!=0{return Err(Refusal::StoreBinding);}
        storage(self.db.query_row("SELECT schema,context,record_sha256,store_id FROM store_binding WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))))
    }
    pub(crate) fn schema_objects(&self)->Outcome<Vec<(String,String,Option<String>)>>{
        let mut q=storage(self.db.prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY name"))?;
        storage(storage(q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))))?.collect())
    }
    pub(crate) fn issued(&self,nonce:&Hash)->Outcome<Option<Issued>>{
        storage(self.db.query_row("SELECT challenge,descriptor,consumed FROM issued WHERE nonce=?1",[nonce.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())
    }
    pub(crate) fn recorded(&self,nonce:&Hash)->Outcome<Option<Recorded>>{
        storage(self.db.query_row("SELECT challenge,descriptor,signature FROM admissions WHERE nonce=?1",[nonce.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())
    }
    pub(crate) fn admissions(&self)->Outcome<Vec<AdmissionRow>>{
        let mut q=storage(self.db.prepare("SELECT nonce,challenge,descriptor,signature FROM admissions ORDER BY nonce"))?;
        storage(storage(q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))))?.collect())
    }
    pub(crate) fn nonces(&self)->Outcome<Vec<Vec<u8>>>{
        let mut q=storage(self.db.prepare("SELECT nonce FROM issued ORDER BY nonce"))?;
        storage(storage(q.query_map([],|r|r.get(0)))?.collect())
    }
}
pub(crate) fn journal_mode(db:&Connection)->Outcome<String>{
    storage(db.query_row("PRAGMA journal_mode",[],|r|{
        let raw=r.get_ref(0)?;
        match raw {
            ValueRef::Text(bytes) if bytes.len()<=8 => std::str::from_utf8(bytes).map(str::to_owned).map_err(|e|rusqlite::Error::FromSqlConversionFailure(0,rusqlite::types::Type::Text,Box::new(e))),
            _=>Err(rusqlite::Error::InvalidQuery),
        }
    }))
}

#[cfg(test)]
#[path="../controls/schema_first_reader_controls.rs"]
mod schema_first_reader_controls;
