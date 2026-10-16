//! Separate NativeOwnerTest signing mode. PUBLIC SOFTWARE TEST ONLY.
//! Nested beneath continuous_test_signer_store; fixed Wallet Store is unchanged.
//! Unique context/application/schema prevents either mode reopening the other.
//! Software counter is NOT TPM monotonicity or protected-domain antirollback.
use super::*;
use mutiny_consensus_v8::{canonical_store_v2::CanonicalStore,counter_store::MonotonicCounter,counter_voter_v2::CounterSigningBackend,activation_attestation_v1::PrivateSignPermit};
use mutiny_crypto_v2::HybridSignature;
use rusqlite::OptionalExtension;
// Qualified custody has an opaque lifetime owner. Existing cfg(test) storage
// controls remain explicitly isolated component coverage, never application
// eligibility. The ordinary NativeOwner driver has no component constructor.
#[derive(Clone)]
enum NativeExecution{
 #[cfg(all(target_arch="x86_64",feature="native-owner-test"))]
 Qualified(super::super::own_native_receiver::ProviderExecution),
 #[cfg(test)] IsolatedComponent,
 #[allow(dead_code)] Refused,
}
impl NativeExecution{fn require(&self,b:&Binding)->Result<()>{match self{
 #[cfg(all(target_arch="x86_64",feature="native-owner-test"))]
 Self::Qualified(owner)=>owner.require(&b.source,&b.campaign),
 #[cfg(test)] Self::IsolatedComponent=>Ok(()),
 Self::Refused=>Err("Native application execution owner unavailable".into()),
}}}
fn open_native_key(db:&Connection,b:&Binding,ctx:&[u8;64],role:Role,execution:&NativeExecution)->Result<HybridKey>{
 let index=match role{Role::Node=>6,Role::Continuity=>4,_=>return Err("Native signer role".into())};
 let sealed:Vec<u8>=db.query_row("SELECT CASE WHEN typeof(envelope)='blob' AND length(envelope) BETWEEN 1 AND 32768 THEN envelope ELSE NULL END FROM test_signer_keys WHERE role=?1",[index],|r|r.get(0)).map_err(err)?;
 execution.require(b)?;let inner=dpapi(&sealed,ctx,false).map_err(err)?;
 execution.require(b)?;let(k,g)=HybridKey::open_for(role,TEST_PASSWORD,ctx,&inner).map_err(err)?;
 let(p,expected_generation)=b.expected(role)?;
 if k.public()!=&p||g!=expected_generation{return Err("Native signer ciphertext descriptor/generation mismatch".into());}
 let domain=if role==Role::Node{Domain::NodeAdmissionPossession}else{Domain::ContinuityPossession};
 execution.require(b)?;let proof=k.sign(domain,ctx).map_err(err)?;
 p.verify(domain,ctx,&proof).map_err(err)?;execution.require(b)?;Ok(k)
}
const MODE:&str="MUTINY-W15-NATIVE-OWNER-TEST-ONLY-V2";
const TABLES:[(&str,&str);4]=[
 ("native_owner_context","CREATE TABLE native_owner_context(id INTEGER PRIMARY KEY CHECK(id=1),mode TEXT NOT NULL CHECK(mode='NativeOwnerTest'),context BLOB NOT NULL CHECK(length(context)=64),counter BLOB NOT NULL CHECK(length(counter)=8))"),
 ("test_signer_keys","CREATE TABLE test_signer_keys(role INTEGER PRIMARY KEY CHECK(role IN (4,6)),envelope BLOB NOT NULL CHECK(length(envelope) BETWEEN 1 AND 32768))"),
 ("native_owner_votes","CREATE TABLE native_owner_votes(sequence BLOB PRIMARY KEY CHECK(length(sequence)=8),body BLOB NOT NULL CHECK(length(body) BETWEEN 1 AND 4096),signed BLOB CHECK(signed IS NULL OR length(signed) BETWEEN 1 AND 4096))"),
 ("native_owner_work","CREATE TABLE native_owner_work(ticket BLOB PRIMARY KEY CHECK(length(ticket)=8),body BLOB NOT NULL CHECK(length(body) BETWEEN 1 AND 8192),candidate_body BLOB NOT NULL CHECK(length(candidate_body)=32),signed BLOB CHECK(signed IS NULL OR length(signed) BETWEEN 1 AND 8192))"),
];
#[derive(Clone,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalPin{pub mode:String,pub counter:u64,pub records:u64,pub work_records:u64,pub commitment:Hash}
pub(crate) struct NativeOwnerStore{keys:Keys,db:PinnedConnection,context:[u8;64],binding:Binding,lease:DatabasePin,guard:Guard,path:std::path::PathBuf,user:Vec<u8>,execution:NativeExecution}
/// Read-only journal observation after the backend is owned by VotingRuntime.
/// No private keys, write connection, guard takeover or arbitrary SQL API.
pub(crate) struct JournalObserver{db:PinnedConnection,lease:DatabasePin,context:[u8;64],binding:Binding,execution:NativeExecution}
impl JournalObserver{
 pub(crate) fn journal_pin(&mut self)->Result<JournalPin>{self.execution.require(&self.binding)?;self.db.status()?;self.lease.recheck()?;let tx=self.db.transaction_with_behavior(TransactionBehavior::Deferred).map_err(err)?;let pin=NativeOwnerStore::snapshot(&tx,&self.context)?;tx.commit().map_err(err)?;self.lease.recheck()?;Ok(pin)}
 /// Read-only sequence suggestion. The live backend independently rechecks its
 /// durable next slot and current canonical authorization before reservation.
 pub(crate) fn next_work_ticket(&mut self)->Result<u64>{self.execution.require(&self.binding)?;self.db.status()?;self.lease.recheck()?;let tx=self.db.transaction_with_behavior(TransactionBehavior::Deferred).map_err(err)?;NativeOwnerStore::snapshot(&tx,&self.context)?;let raw:Option<Vec<u8>>=tx.query_row("SELECT max(ticket) FROM native_owner_work",[],|r|r.get(0)).map_err(err)?;let last=match raw{Some(bytes)=>u64::from_be_bytes(bytes.try_into().map_err(|_|"NativeOwnerTest observed ticket extent")?),None=>0};let next=last.checked_add(1).ok_or("NativeOwnerTest observed tickets exhausted")?;tx.commit().map_err(err)?;self.lease.recheck()?;Ok(next)}
}
fn native_context(binding:&Binding)->Result<[u8;64]>{let mut h=Sha512::new();h.update(MODE.as_bytes());h.update(binding.context()?);Ok(h.finalize().into())}
fn validate(db:&Connection,context:&[u8;64])->Result<u64>{
 let(app,version):(u32,u32)=(db.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(err)?,db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(err)?);
 if app!=0x574e5432||version!=2||db.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get::<_,u64>(0)).map_err(err)?!=6{return Err("NativeOwnerTest exact schema/mode; no migration".into());}
 // BLOB primary key contributes the exact SQLite autoindex, unlike INTEGER PK.
 for(name,sql)in TABLES{let actual:String=db.query_row("SELECT CASE WHEN typeof(sql)='text' AND length(CAST(sql AS BLOB))<=1024 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=?1 AND tbl_name=?1",[name],|r|r.get(0)).map_err(err)?;if actual!=sql{return Err("NativeOwnerTest foreign schema".into());}}
 let(ctx,raw):(Vec<u8>,Vec<u8>)=db.query_row("SELECT CASE WHEN mode='NativeOwnerTest' AND typeof(context)='blob' AND length(context)=64 THEN context ELSE NULL END,CASE WHEN typeof(counter)='blob' AND length(counter)=8 THEN counter ELSE NULL END FROM native_owner_context WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(err)?;
 if ctx!=context||db.query_row("SELECT count(*) FROM native_owner_context",[],|r|r.get::<_,u64>(0)).map_err(err)?!=1||db.query_row("SELECT count(*) FROM test_signer_keys",[],|r|r.get::<_,u64>(0)).map_err(err)?!=2{return Err("NativeOwnerTest exact initialized identity".into());}
 if db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='index' AND name='sqlite_autoindex_native_owner_votes_1' AND tbl_name='native_owner_votes' AND sql IS NULL",[],|r|r.get::<_,u64>(0)).map_err(err)?!=1{return Err("NativeOwnerTest exact autoindex".into());}
 if db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='index' AND name='sqlite_autoindex_native_owner_work_1' AND tbl_name='native_owner_work' AND sql IS NULL",[],|r|r.get::<_,u64>(0)).map_err(err)?!=1{return Err("NativeOwnerTest exact work autoindex".into());}
 let tip=u64::from_be_bytes(raw.try_into().map_err(|_|"NativeOwnerTest counter extent")?);
 let invalid:u64=db.query_row("SELECT count(*) FROM native_owner_votes WHERE typeof(sequence)!='blob' OR length(sequence)!=8 OR typeof(body)!='blob' OR length(body) NOT BETWEEN 1 AND 4096 OR (signed IS NOT NULL AND (typeof(signed)!='blob' OR length(signed) NOT BETWEEN 1 AND 4096)) OR sequence> ?1",[tip.to_be_bytes().as_slice()],|r|r.get(0)).map_err(err)?;
 let work_invalid:u64=db.query_row("SELECT count(*) FROM native_owner_work WHERE typeof(ticket)!='blob' OR length(ticket)!=8 OR ticket=zeroblob(8) OR typeof(body)!='blob' OR length(body) NOT BETWEEN 1 AND 8192 OR typeof(candidate_body)!='blob' OR length(candidate_body)!=32 OR (signed IS NOT NULL AND (typeof(signed)!='blob' OR length(signed) NOT BETWEEN 1 AND 8192))",[],|r|r.get(0)).map_err(err)?;
 if invalid!=0||work_invalid!=0{return Err("NativeOwnerTest journal malformed/ahead counter".into());}Ok(tip)
}
impl NativeOwnerStore{
 #[cfg(test)]
 pub(crate) fn initialize_before_h0(path:&Path,guard_path:&Path,user:&[u8],binding:Binding,node:&HybridKey,continuity:&HybridKey)->Result<Self>{Self::initialize_inner(path,guard_path,user,binding,node,continuity,NativeExecution::IsolatedComponent)}
 #[cfg(all(target_arch="x86_64",feature="native-owner-test"))]
 pub(crate) fn initialize_qualified_before_h0(execution:super::super::own_native_receiver::ProviderExecution,path:&Path,guard_path:&Path,user:&[u8],binding:Binding,node:&HybridKey,continuity:&HybridKey)->Result<Self>{Self::initialize_inner(path,guard_path,user,binding,node,continuity,NativeExecution::Qualified(execution))}
 fn initialize_inner(path:&Path,guard_path:&Path,user:&[u8],binding:Binding,node:&HybridKey,continuity:&HybridKey,execution:NativeExecution)->Result<Self>{
  execution.require(&binding)?;
  let guard=Guard::existing(guard_path,user)?;let lease=DatabasePin::open(path,user)?;
  if guard.native_id_hash()?!=binding.native_guard_identity||lease.native_id_hash()!=binding.native_custody_identity{return Err("NativeOwnerTest native identity".into());}
  let leaf=OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path).map_err(err)?;lease.check_opened(&leaf)?;private_leaf(&leaf,user)?;
  if leaf.metadata().map_err(err)?.len()!=0{return Err("NativeOwnerTest NEW empty leaf only".into());}
  let context=native_context(&binding)?;let mut db=open_existing(path,user,guard.quarantine.clone())?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
  if tx.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get::<_,u64>(0)).map_err(err)?!=0{return Err("NativeOwnerTest no overwrite".into());}
  for(_,sql)in TABLES{tx.execute_batch(sql).map_err(err)?;}tx.pragma_update(None,"application_id",0x574e5432u32).map_err(err)?;tx.pragma_update(None,"user_version",2u32).map_err(err)?;
  tx.execute("INSERT INTO native_owner_context VALUES(1,'NativeOwnerTest',?1,?2)",params![context.as_slice(),0u64.to_be_bytes().as_slice()]).map_err(err)?;
  for(role,key,index)in[(Role::Node,node,6),(Role::Continuity,continuity,4)]{let(p,g)=binding.expected(role)?;if key.public()!=&p{return Err("NativeOwnerTest generated role differs".into());}execution.require(&binding)?;let inner=key.seal_for(TEST_PASSWORD,g,&context).map_err(err)?;execution.require(&binding)?;let protected=dpapi(&inner,&context,true).map_err(err)?;execution.require(&binding)?;if protected.len()>MAX_ENVELOPE{return Err("NativeOwnerTest sealed extent".into());}tx.execute("INSERT INTO test_signer_keys VALUES(?1,?2)",params![index,protected.as_slice()]).map_err(err)?;}
  tx.commit().map_err(err)?;db.close_checked()?;lease.recheck()?;drop(lease);drop(guard);
  Self::open_existing(path,guard_path,user,binding,None,execution)
 }
 fn open_existing(path:&Path,guard_path:&Path,user:&[u8],binding:Binding,expected:Option<&JournalPin>,execution:NativeExecution)->Result<Self>{execution.require(&binding)?;
  let guard=Guard::existing(guard_path,user)?;let lease=DatabasePin::open(path,user)?;
  if guard.native_id_hash()?!=binding.native_guard_identity||lease.native_id_hash()!=binding.native_custody_identity{return Err("NativeOwnerTest original native identities required".into());}
  let leaf=OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path).map_err(err)?;lease.check_opened(&leaf)?;private_leaf(&leaf,user)?;
  let context=native_context(&binding)?;let read=PinnedConnection::open(path,user,true,guard.quarantine.clone())?;read.execute_batch("PRAGMA trusted_schema=OFF").map_err(err)?;validate(&read,&context)?;
  // Authenticate exact expected mode and journal on READ_ONLY before any
  // writable SQLite open/journal reconciliation; a mismatch cannot repair state.
  if let Some(pin)=expected{if &Self::snapshot(&read,&context)?!=pin{return Err("NativeOwnerTest read-only mode/journal differs; no reset".into());}}
  let keys=Keys{node:open_native_key(&read,&binding,&context,Role::Node,&execution)?,continuity:open_native_key(&read,&binding,&context,Role::Continuity,&execution)?};read.close_checked()?;lease.recheck()?;
  let db=open_existing(path,user,guard.quarantine.clone())?;validate(&db,&context)?;let store=Self{keys,db,context,binding,lease,guard,path:path.into(),user:user.to_vec(),execution};
  if let Some(pin)=expected{if &store.journal_pin()?!=pin{return Err("NativeOwnerTest exact mode/journal reopen mismatch; no reset".into());}}Ok(store)
 }
 #[cfg(test)]
 pub(crate) fn reopen_existing(path:&Path,guard:&Path,user:&[u8],binding:Binding,expected:&JournalPin)->Result<Self>{Self::open_existing(path,guard,user,binding,Some(expected),NativeExecution::IsolatedComponent)}
 #[cfg(all(target_arch="x86_64",feature="native-owner-test"))]
 pub(crate) fn reopen_qualified_existing(execution:super::super::own_native_receiver::ProviderExecution,path:&Path,guard:&Path,user:&[u8],binding:Binding,expected:&JournalPin)->Result<Self>{Self::open_existing(path,guard,user,binding,Some(expected),NativeExecution::Qualified(execution))}
 pub(crate) fn possession_before_h0(&self)->Result<(Vec<u8>,Vec<u8>)>{
  self.db.status()?;
  let before=self.journal_pin()?;if before.counter!=0||before.records!=0||before.work_records!=0{return Err("NativeOwnerTest initial providers already used; no reset".into());}
  let mut proofs=Vec::new();for(role,domain,key)in[(Role::Node,Domain::NodeAdmissionPossession,&self.keys.node),(Role::Continuity,Domain::ContinuityPossession,&self.keys.continuity)]{let(pk,_)=self.binding.expected(role)?;self.execution.require(&self.binding)?;let sig=key.sign(domain,&self.context).map_err(err)?;pk.verify(domain,&self.context,&sig).map_err(err)?;let mut raw=sig.ed448.to_vec();raw.extend_from_slice(&sig.fndsa);proofs.push(raw);}
  if self.journal_pin()?!=before{return Err("NativeOwnerTest initial possession changed journal".into());}Ok((proofs.remove(0),proofs.remove(0)))
 }
 pub(crate) fn possession_context(&self)->[u8;64]{self.context}
 pub(crate) fn journal_observer(&self)->Result<JournalObserver>{
  self.db.status()?;
  self.lease.recheck()?;let lease=DatabasePin::open(&self.path,&self.user)?;if lease.native_id_hash()!=self.lease.native_id_hash(){return Err("NativeOwnerTest journal observer original identity".into());}
  let leaf=OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&self.path).map_err(err)?;lease.check_opened(&leaf)?;private_leaf(&leaf,&self.user)?;
  let db=PinnedConnection::open(&self.path,&self.user,true,self.guard.quarantine.clone())?;db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;").map_err(err)?;lease.recheck()?;self.lease.recheck()?;let mut observer=JournalObserver{db,lease,context:self.context,binding:self.binding.clone(),execution:self.execution.clone()};observer.journal_pin()?;Ok(observer)
 }
 pub(crate) fn journal_pin(&self)->Result<JournalPin>{self.execution.require(&self.binding)?;self.db.status()?;self.lease.recheck()?;let pin=Self::snapshot(&self.db,&self.context)?;self.lease.recheck()?;Ok(pin)}
 fn snapshot(db:&Connection,context:&[u8;64])->Result<JournalPin>{
  let counter=validate(db,context)?;let records:u64=db.query_row("SELECT count(*) FROM native_owner_votes",[],|r|r.get(0)).map_err(err)?;let work_records:u64=db.query_row("SELECT count(*) FROM native_owner_work",[],|r|r.get(0)).map_err(err)?;
  // Finite test storage cap reuses the existing fixed campaign's 384*10 budget;
  // exhaustion refuses without reset and has no protocol threshold meaning.
  if records>MAX_HEIGHT*10||work_records>MAX_HEIGHT*10{return Err("NativeOwnerTest finite journal exhausted".into());}
  let mut h=sha2::Sha256::new();h.update(MODE.as_bytes());h.update(context);h.update(counter.to_be_bytes());let mut stmt=db.prepare("SELECT sequence,body,signed FROM native_owner_votes ORDER BY sequence").map_err(err)?;let mut rows=stmt.query([]).map_err(err)?;let mut seen=0;
  while let Some(row)=rows.next().map_err(err)?{seen+=1;if seen>records{return Err("NativeOwnerTest snapshot changed".into());}let sequence=row.get_ref(0).map_err(err)?.as_blob().map_err(err)?;let body=row.get_ref(1).map_err(err)?.as_blob().map_err(err)?;if sequence.len()!=8||!(1..=MAX_COMMIT).contains(&body.len()){return Err("NativeOwnerTest row extent".into());}h.update(sequence);h.update((body.len()as u64).to_be_bytes());h.update(body);match row.get_ref(2).map_err(err)?{rusqlite::types::ValueRef::Null=>h.update([0]),rusqlite::types::ValueRef::Blob(raw)if(1..=MAX_COMMIT).contains(&raw.len())=>{h.update([1]);h.update((raw.len()as u64).to_be_bytes());h.update(raw)},_=>return Err("NativeOwnerTest signed extent".into())}}
  if seen!=records{return Err("NativeOwnerTest snapshot count".into());}drop(rows);drop(stmt);
  h.update(b"NODE-WORK-RESERVATIONS-V2");h.update(work_records.to_be_bytes());let mut stmt=db.prepare("SELECT ticket,body,candidate_body,signed FROM native_owner_work ORDER BY ticket").map_err(err)?;let mut rows=stmt.query([]).map_err(err)?;let mut seen=0;
  while let Some(row)=rows.next().map_err(err)?{seen+=1;if seen>work_records{return Err("NativeOwnerTest work snapshot changed".into());}let ticket=row.get_ref(0).map_err(err)?.as_blob().map_err(err)?;let body=row.get_ref(1).map_err(err)?.as_blob().map_err(err)?;let candidate_body=row.get_ref(2).map_err(err)?.as_blob().map_err(err)?;if ticket.len()!=8||!(1..=8192).contains(&body.len())||candidate_body.len()!=32{return Err("NativeOwnerTest work row extent".into());}h.update(ticket);h.update((body.len()as u64).to_be_bytes());h.update(body);h.update(candidate_body);match row.get_ref(3).map_err(err)?{rusqlite::types::ValueRef::Null=>h.update([0]),rusqlite::types::ValueRef::Blob(raw)if(1..=8192).contains(&raw.len())=>{h.update([1]);h.update((raw.len()as u64).to_be_bytes());h.update(raw)},_=>return Err("NativeOwnerTest signed work extent".into())}}
  if seen!=work_records{return Err("NativeOwnerTest work snapshot count".into());}Ok(JournalPin{mode:"NativeOwnerTest".into(),counter,records,work_records,commitment:h.finalize().into()})
 }
 pub(crate) fn backend(self,chain:CanonicalStore,chain_pin:DatabasePin,genesis:FinalizedAnchor)->Result<Backend>{
  chain_pin.recheck()?;if genesis.height!=0||genesis.genesis!=self.binding.genesis||genesis.fingerprint!=self.binding.fingerprint{return Err("NativeOwnerTest exact own Genesis".into());}
  let backend=Backend{store:self,chain,chain_pin,genesis};backend.authority()?;Ok(backend)
 }
}
pub(crate) struct Backend{store:NativeOwnerStore,chain:CanonicalStore,chain_pin:DatabasePin,genesis:FinalizedAnchor}
impl Backend{
 pub(crate) fn journal_pin(&self)->Result<JournalPin>{self.store.journal_pin()}
 fn authority(&self)->Result<mutiny_consensus_v8::votes_v2::HeightAuthority>{self.store.execution.require(&self.store.binding)?;self.store.db.status()?;self.store.lease.recheck()?;self.chain_pin.recheck()?;let(head,_)=self.chain.load().map_err(err)?;let parent=FinalizedAnchor{height:head.height,block:head.block,..self.genesis.clone()};let a=self.chain.current_authority(&parent).map_err(err)?;let node=mutiny_consensus_v8::node_admission_v2::node_id(self.store.binding.genesis,&self.store.binding.node_descriptor).map_err(err)?;let voter=a.voters.get(&node).ok_or("NativeOwnerTest current own voter missing")?;let(public,generation)=self.store.binding.expected(Role::Continuity)?;if voter.public!=public||voter.key_generation!=generation||voter.hardware_generation==0||voter.weight().map_err(err)?.is_zero(){return Err("NativeOwnerTest original current authority".into());}self.chain_pin.recheck()?;Ok(a)}
 fn work_context(&self,work:&mutiny_consensus_v8::work_authority_v2::Authority,body:&mutiny_consensus_v8::blocks::BlockBody)->Result<(mutiny_consensus_v8::pow::WorkContext,Hash)>{
  let own=self.authority()?;let node=mutiny_consensus_v8::node_admission_v2::node_id(self.store.binding.genesis,&self.store.binding.node_descriptor).map_err(err)?;
  if work.node_descriptor!=self.store.binding.node_descriptor{return Err("NativeOwnerTest exact original Node work descriptor".into());}
  self.chain.validate_node_work(&own.parent,node,work,body).map_err(err)?;
  let(parent,state,_)=self.chain.execution_parent(own.parent.height).map_err(err)?;let(context,_,descriptor)=state.work_context_v2(&parent,&work.work.candidate).map_err(err)?;
  if descriptor!=self.store.binding.node_descriptor{return Err("NativeOwnerTest independently current Node work authority".into());}
  let encoded=self.chain.body_capacity(&own.parent).map_err(err)?.encode(body).map_err(err)?;let commitment=sha2::Sha256::digest(&encoded).into();self.chain_pin.recheck()?;self.store.lease.recheck()?;Ok((context,commitment))
 }
 pub(crate) fn next_work_ticket(&self)->Result<u64>{self.authority()?;self.store.journal_pin()?;let raw:Option<Vec<u8>>=self.store.db.query_row("SELECT max(ticket) FROM native_owner_work",[],|r|r.get(0)).map_err(err)?;let last=match raw{Some(bytes)=>u64::from_be_bytes(bytes.try_into().map_err(|_|"NativeOwnerTest work ticket extent")?),None=>0};last.checked_add(1).ok_or("NativeOwnerTest work tickets exhausted".into())}
 /// A typed unsigned current-parent authority and body only. No raw Node signer.
 /// Reservation and result commit precede acknowledgment; exact retry retains
 /// the same logical ticket and conflicting bytes never get another signature.
 pub(crate) fn sign_work_authority(&mut self,mut work:mutiny_consensus_v8::work_authority_v2::Authority,body:&mutiny_consensus_v8::blocks::BlockBody)->Result<mutiny_consensus_v8::work_authority_v2::Authority>{
  let(context,candidate_body)=self.work_context(&work,body)?;let unsigned=work.unsigned().map_err(err)?;
  if unsigned.is_empty()||unsigned.len()>8192||work.work.ticket_sequence==0{return Err("NativeOwnerTest bounded nonzero work reservation".into());}let ticket=work.work.ticket_sequence;let next=self.next_work_ticket()?;
  let tx=self.store.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;let old:Option<(Vec<u8>,Vec<u8>,Option<Vec<u8>>)>=tx.query_row("SELECT CASE WHEN typeof(body)='blob' AND length(body) BETWEEN 1 AND 8192 THEN body ELSE NULL END,CASE WHEN typeof(candidate_body)='blob' AND length(candidate_body)=32 THEN candidate_body ELSE NULL END,CASE WHEN signed IS NULL OR (typeof(signed)='blob' AND length(signed) BETWEEN 1 AND 8192) THEN signed ELSE NULL END FROM native_owner_work WHERE ticket=?1",[ticket.to_be_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(err)?;
  let cached=if let Some((prior,prior_body,signed))=old{if prior!=unsigned||prior_body!=candidate_body{return Err("NativeOwnerTest work ticket conflicting content".into());}signed}else{
   let last:Option<Vec<u8>>=tx.query_row("SELECT max(ticket) FROM native_owner_work",[],|r|r.get(0)).map_err(err)?;let actual_next=match last{Some(raw)=>u64::from_be_bytes(raw.try_into().map_err(|_|"NativeOwnerTest ticket extent")?).checked_add(1).ok_or("NativeOwnerTest ticket exhausted")?,None=>1};
   if ticket!=next||ticket!=actual_next||tx.query_row("SELECT count(*) FROM native_owner_work",[],|r|r.get::<_,u64>(0)).map_err(err)?>=MAX_HEIGHT*10{return Err("NativeOwnerTest exact next work ticket/finite journal required".into());}
   tx.execute("INSERT INTO native_owner_work VALUES(?1,?2,?3,NULL)",params![ticket.to_be_bytes().as_slice(),&unsigned,candidate_body.as_slice()]).map_err(err)?;None
  };tx.commit().map_err(err)?;
  let header=mutiny_consensus_v8::pow::WorkHeader{candidate:work.work.candidate.clone(),authority:work.id().map_err(err)?,nonce:work.work.nonce_start};
  if let Some(raw)=cached{let old=mutiny_consensus_v8::work_authority_v2::Authority::decode(&raw).map_err(err)?;if old.unsigned().map_err(err)?!=unsigned{return Err("NativeOwnerTest cached work content".into());}old.verify(&header,&context,&self.store.binding.node_descriptor).map_err(err)?;self.store.lease.recheck()?;return Ok(old);}
  let(current,current_body)=self.work_context(&work,body)?;if current_body!=candidate_body{return Err("NativeOwnerTest work body changed before key entry".into());}
  // Current own chain/role, guarded provider and exact reservation checked again
  // immediately before the private Domain::NodeWork operation.
  self.store.lease.recheck()?;self.chain_pin.recheck()?;self.store.execution.require(&self.store.binding)?;work.sign(&self.store.keys.node).map_err(err)?;work.verify(&header,&current,&self.store.binding.node_descriptor).map_err(err)?;let signed=work.encode().map_err(err)?;
  let tx=self.store.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;if tx.execute("UPDATE native_owner_work SET signed=?1 WHERE ticket=?2 AND body=?3 AND candidate_body=?4 AND signed IS NULL",params![signed,ticket.to_be_bytes().as_slice(),unsigned,candidate_body.as_slice()]).map_err(err)?!=1{return Err("NativeOwnerTest signed work CAS; no return".into());}tx.commit().map_err(err)?;self.store.lease.recheck()?;self.chain_pin.recheck()?;Ok(work)
 }
}
impl MonotonicCounter for Backend{
 fn read(&mut self)->Result<u64>{self.store.execution.require(&self.store.binding)?;self.store.db.status()?;self.store.lease.recheck()?;validate(&self.store.db,&self.store.context)}
 fn increment(&mut self)->Result<()>{
  self.authority()?;self.store.lease.recheck()?;let tx=self.store.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;let old=validate(&tx,&self.store.context)?;let next=old.checked_add(1).ok_or("NativeOwnerTest counter exhausted")?;
  if tx.execute("UPDATE native_owner_context SET counter=?1 WHERE id=1 AND counter=?2",params![next.to_be_bytes().as_slice(),old.to_be_bytes().as_slice()]).map_err(err)?!=1{return Err("NativeOwnerTest durable counter CAS".into());}tx.commit().map_err(err)?;self.store.lease.recheck()?;Ok(())
 }
}
impl CounterSigningBackend for Backend{
 fn public_key(&self)->&PublicKey{self.store.keys.continuity.public()}
 fn sign_vote(&mut self,_:&[u8])->Result<HybridSignature>{Err("NativeOwnerTest requires actual opaque custody permit".into())}
 fn sign_reserved_vote(&mut self,message:&[u8],permit:&PrivateSignPermit)->Result<HybridSignature>{
  let mut vote=mutinyd_v8::activation_private_owner_v1::decode_reserved_vote(message).map_err(err)?;
  self.authority()?;let authority=self.chain.validate_unsigned_vote_at_current_parent(&vote).map_err(err)?;
  let node=mutiny_consensus_v8::node_admission_v2::node_id(self.store.binding.genesis,&self.store.binding.node_descriptor).map_err(err)?;
  if vote.node!=node||vote.sequence==0||vote.sequence!=self.read()?{return Err("NativeOwnerTest exact durable counter/node".into());}
  permit.check_at_custody_entry(node,Some(mutiny_consensus_v8::activation_attestation_v1::rule_commitment()),message).map_err(err)?;
  let tx=self.store.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;let old:Option<(Vec<u8>,Option<Vec<u8>>)>=tx.query_row("SELECT CASE WHEN typeof(body)='blob' AND length(body) BETWEEN 1 AND 4096 THEN body ELSE NULL END,CASE WHEN signed IS NULL OR (typeof(signed)='blob' AND length(signed) BETWEEN 1 AND 4096) THEN signed ELSE NULL END FROM native_owner_votes WHERE sequence=?1",[vote.sequence.to_be_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(err)?;
  let cached=if let Some((body,signed))=old{if body!=message{return Err("NativeOwnerTest conflicting exact reservation".into());}signed}else{if tx.query_row("SELECT count(*) FROM native_owner_votes",[],|r|r.get::<_,u64>(0)).map_err(err)?>=MAX_HEIGHT*10{return Err("NativeOwnerTest finite reservation budget exhausted".into());}tx.execute("INSERT INTO native_owner_votes VALUES(?1,?2,NULL)",params![vote.sequence.to_be_bytes().as_slice(),message]).map_err(err)?;None};tx.commit().map_err(err)?;
  if let Some(raw)=cached{let old=Vote::decode(&raw).map_err(err)?;if old.unsigned().map_err(err)?!=message{return Err("NativeOwnerTest cached content".into());}old.verify(&authority.parent,authority.roots(),&authority.voters).map_err(err)?;return Ok(old.signature);}
  // Re-fetch independently owned current authority after durable reservation;
  // opaque permit expiry is checked at the actual private key operation below.
  self.authority()?;let authority=self.chain.validate_unsigned_vote_at_current_parent(&vote).map_err(err)?;
  if vote.sequence!=self.read()?{return Err("NativeOwnerTest counter changed before key entry".into());}
  self.store.execution.require(&self.store.binding)?;
  permit.check_at_custody_entry(node,Some(mutiny_consensus_v8::activation_attestation_v1::rule_commitment()),message).map_err(err)?;
  vote.sign(&self.store.keys.continuity).map_err(err)?;vote.verify(&authority.parent,authority.roots(),&authority.voters).map_err(err)?;
  let raw=vote.encode().map_err(err)?;let tx=self.store.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
  if tx.execute("UPDATE native_owner_votes SET signed=?1 WHERE sequence=?2 AND body=?3 AND signed IS NULL",params![raw,vote.sequence.to_be_bytes().as_slice(),message]).map_err(err)?!=1{return Err("NativeOwnerTest signature CAS; no return".into());}tx.commit().map_err(err)?;self.store.lease.recheck()?;self.chain_pin.recheck()?;Ok(vote.signature)
 }
}
impl mutinyd_v8::hybrid_voter_v2::NodeWorkSigningBackend for Backend{
 fn sign_current_node_work(&mut self,work:mutiny_consensus_v8::work_authority_v2::Authority,body:&mutiny_consensus_v8::blocks::BlockBody)->Result<mutiny_consensus_v8::work_authority_v2::Authority>{self.sign_work_authority(work,body)}
}
#[cfg(test)] mod tests{
 use super::*;
 use std::result::Result;
 use super::super::{licenses,tpm};
 use super::super::super::process_auth::VerifiedProcess;
 include!("../../../consensus/tests/support/dividend_rig.rs");
 fn setup()->(std::path::PathBuf,Vec<u8>,Binding,Fixture){
  super::super::install_sqlite_close_boundary_at_process_entry().unwrap();
  let mut nonce=[0;16];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();let root=std::env::temp_dir().join(format!("w15-native-owner-mode-{}",hex::encode(nonce)));assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());let user=VerifiedProcess::observe_created_process(std::process::id()).unwrap().user_sid;
  let path=root.join("native-owner.sqlite");let guard=root.join("native-owner.guard");create_new_private_leaf(&path,&user).unwrap();create_new_private_leaf(&guard,&user).unwrap();let f=fixture();let b=Binding{campaign:[11;32],source:[12;32],genesis:f.genesis.genesis,fingerprint:f.genesis.fingerprint,initial_root:f.state.root().unwrap(),original_store_identities:[15;32],native_custody_identity:DatabasePin::open(&path,&user).unwrap().native_id_hash(),native_guard_identity:DatabasePin::open(&guard,&user).unwrap().native_id_hash(),node_descriptor:f.coordinator.public().descriptor(1).unwrap(),continuity_descriptor:f.continuity.public().descriptor(1).unwrap()};(root,user,b,f)
 }
 #[test] fn native_mode_existing_only_reopen_binds_providers_and_refuses_fixed_mode(){
  let(root,user,b,f)=setup();let path=root.join("native-owner.sqlite");let guard=root.join("native-owner.guard");assert!(NativeOwnerStore::reopen_existing(&path,&guard,&user,b.clone(),&JournalPin{mode:"NativeOwnerTest".into(),counter:0,records:0,work_records:0,commitment:[0;32]}).is_err());assert_eq!(std::fs::metadata(&path).unwrap().len(),0);
  let store=NativeOwnerStore::initialize_before_h0(&path,&guard,&user,b.clone(),&f.coordinator,&f.continuity).unwrap();let pin=store.journal_pin().unwrap();let(node,continuity)=store.possession_before_h0().unwrap();let context=store.possession_context();for(raw,key,domain)in[(node,f.coordinator.public(),Domain::NodeAdmissionPossession),(continuity,f.continuity.public(),Domain::ContinuityPossession)]{let signature=HybridSignature{ed448:raw[..114].try_into().unwrap(),fndsa:raw[114..].try_into().unwrap()};key.verify(domain,&context,&signature).unwrap();}drop(store);
  let before=std::fs::read(&path).unwrap();assert!(super::super::Store::reopen_existing(&path,&guard,&user,b.clone(),0).is_err());assert_eq!(std::fs::read(&path).unwrap(),before);let mut wrong=pin.clone();wrong.counter=1;assert!(NativeOwnerStore::reopen_existing(&path,&guard,&user,b.clone(),&wrong).is_err());assert_eq!(std::fs::read(&path).unwrap(),before);let reopened=NativeOwnerStore::reopen_existing(&path,&guard,&user,b,&pin).unwrap();assert_eq!(reopened.journal_pin().unwrap(),pin);
 }
 #[test] fn native_counter_persists_across_actual_provider_reopen_and_direct_signing_refuses(){
  let(root,user,b,f)=setup();let path=root.join("native-owner.sqlite");let guard=root.join("native-owner.guard");let store=NativeOwnerStore::initialize_before_h0(&path,&guard,&user,b.clone(),&f.coordinator,&f.continuity).unwrap();let mut observer=store.journal_observer().unwrap();let chain_path=root.join("actual-own-chain.sqlite");let chain=CanonicalStore::open_trusted_genesis(&chain_path,&f.genesis,&f.state,f.state.root().unwrap(),T0,[255;32]).unwrap();let chain_pin=DatabasePin::open(&chain_path,&user).unwrap();let mut backend=store.backend(chain,chain_pin,f.genesis.clone()).unwrap();assert_eq!(backend.read().unwrap(),0);backend.increment().unwrap();assert_eq!(backend.read().unwrap(),1);assert_eq!(observer.journal_pin().unwrap(),backend.journal_pin().unwrap());assert_eq!(observer.next_work_ticket().unwrap(),1);assert!(backend.sign_vote(b"arbitrary signing refused").is_err());let pin=backend.journal_pin().unwrap();assert_eq!(pin.counter,1);assert_eq!(pin.records,0);drop(backend);
  let store=NativeOwnerStore::reopen_existing(&path,&guard,&user,b,&pin).unwrap();let chain=CanonicalStore::open_trusted_genesis(&chain_path,&f.genesis,&f.state,f.state.root().unwrap(),T0,[255;32]).unwrap();let chain_pin=DatabasePin::open(&chain_path,&user).unwrap();let mut backend=store.backend(chain,chain_pin,f.genesis).unwrap();assert_eq!(backend.read().unwrap(),1);assert_eq!(backend.journal_pin().unwrap(),pin);
  // Native protected file/DPAPI/model counter only. Real activation, owner
  // durable reservation/retry and exact live permit require the driver campaign.
 }
}
