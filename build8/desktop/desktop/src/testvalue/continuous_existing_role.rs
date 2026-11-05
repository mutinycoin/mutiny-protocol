//! EXTERNAL SOURCE ONLY / UNCOMPILED. Existing original campaign Controller.
//! No Session::restore*, save_initial, fixture, new role/owner key or signing API.
use super::{control_codec::{Role,Context,Head},image_pin::{ImagePin,DatabasePin},process_auth::VerifiedProcess,continuous_passive::{VaultPin,PointPin,QueuedPin}};
use crate::{wallet_controller_v2::{Controller,VaultRoot},store_v2::Store,verified_sync_v2::Replica};
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,execution::State,canonical_store_v2::CanonicalStore,mempool_v2::Mempool};
use std::path::Path;
type Result<T>=std::result::Result<T,String>;
pub(super) const MARKER:&str="MUTINY-W15-NONSHIPPING-ORIGINAL-CONTROLLER-REOPEN-V1";
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
#[derive(Clone)] // Public immutable, externally committed checkpoint only.
pub(super) struct RolePins{pub saved:VaultPin,pub head:Head,pub marker_sha256:Hash,pub canonical_native:Hash,pub side_native:[Hash;4]}
pub(super) struct ExistingRole {pub controller:Controller,pub files:Vec<ImagePin>,pub dbs:Vec<DatabasePin>,pub expected:RolePins}
/// The native main caller keeps this owner OUTSIDE the App, and drops it only
/// AFTER both client worker joins. Closing a viewport cannot release original
/// ancestor/database pins while a worker still uses the original Controller.
pub(super) struct RoleLifetime {files:Vec<ImagePin>,dbs:Vec<DatabasePin>}
impl RoleLifetime {pub(super) fn recheck(&self)->Result<()>{for f in &self.files{f.recheck()?;}for d in &self.dbs{d.recheck()?;}Ok(())}}
impl ExistingRole {
 /// NEW campaign clients open only the already initialized exact H0 vaults.
 /// The service durably retained all originals BEFORE publishing H0; this path
 /// has no Session restore, save_initial, fixture or key creation fallback.
 pub(super) fn open_bootstrapped(root:&VaultRoot,role:Role,c:Context,genesis:&FinalizedAnchor,initial:&State,owner:&VerifiedProcess)->Result<(Controller,RoleLifetime)>{
  if genesis.height!=0||genesis.genesis!=c.genesis||genesis.fingerprint!=c.fingerprint{return Err("Exact original H0 client context required".into());}
  let marker=ImagePin::open(&root.path().join("NEW-CONTINUOUS-TEST-ROLE.marker"),&owner.identity().user_sid)?;
  let m:serde_json::Value=serde_json::from_slice(&marker.read_bounded(2048)?).map_err(err)?;
  if m["format"]!=super::role_vault::ROLE_VAULT_MARKER||m["role"]!=role as u8||m["campaign"]!=hex::encode(c.campaign)||m["source"]!=hex::encode(c.source)||m["h0"]!=hex::encode(c.h0)||m["genesis"]!=hex::encode(c.genesis)||m["fingerprint"]!=hex::encode(c.fingerprint)||m["original_launch16"]!=false||m["production_authorized"]!=false{return Err("Exact bootstrapped original role marker required".into());}
  let mut dbs=super::continuous_passive::preflight_side(root,c,genesis.network,owner)?;
  let chain_path=root.path().join("public-chain.sqlite");let (held,read)=super::continuous_passive::held_db(&chain_path,owner,0x4d554632,4)?;
  let n:i64=read.query_row("SELECT count(*) FROM finalized_v2",[],|r|r.get(0)).map_err(err)?;
  if n!=1{return Err("New-role opener accepts exactly initialized H0, not a later historical role".into());}drop(read);dbs.push(held);
  let store=Store::open(&root.vault()).map_err(err)?;let status=store.status().map_err(str::to_owned)?.ok_or("Bootstrapped original ciphertext/pointers absent; never initialize")?;
  let tag=match role{Role::WalletA=>78,Role::WalletC=>79,Role::Treasury=>80};
  let point=mutiny_consensus_v8::transactions::OutPoint{transaction:[tag;32],index:0};
  let authority=initial.coins.get(&point).ok_or("Exact H0 role funding marker missing")?.output.owner;
  let descriptor=initial.wallets.current(authority).ok_or("Exact H0 role authority missing")?;
  if status.revision!=1||status.active.generation!=1||status.active.authority_id!=hex::encode(authority)||status.active.owner_descriptor!=hex::encode(descriptor)||status.staged.is_some()||status.superseded.is_some(){return Err("Exact original initial vault identity/pointers required; no rekey".into());}drop(store);
  let root_hash=initial.root().map_err(err)?;let chain=CanonicalStore::open_trusted_genesis(&chain_path,genesis,initial,root_hash,1000,[255;32]).map_err(err)?;
  let (h,state)=chain.load().map_err(err)?;if h.height!=0||h.block!=genesis.block||h.root!=root_hash||state.root().map_err(err)?!=root_hash{return Err("Initialized original H0 replay differs".into());}
  let declaration=super::role_vault::declaration(role,c,&state)?;let pool=Mempool::open(&root.path().join("public-payment-pool.sqlite"),c.genesis,c.fingerprint,65536).map_err(err)?;
  let mut controller=Controller::open(root,Replica::from_pinned_chain(chain)?,pool,declaration)?;
  if controller.identity().is_some(){return Err("Bootstrapped original Controller must be LOCKED; real Unlock widget required".into());}
  let held=RoleLifetime{files:vec![marker],dbs};held.recheck()?;owner.recheck()?;Ok((controller,held))
 }
 pub(super) fn into_runtime(self)->Result<(Controller,RoleLifetime,RolePins)>{
  let Self{controller,files,dbs,expected}=self;
  let held=RoleLifetime{files,dbs};held.recheck()?;Ok((controller,held,expected))
 }
 pub(super) fn open(root:&VaultRoot,role:Role,c:Context,genesis:&FinalizedAnchor,initial:&State,pins:RolePins,owner:&VerifiedProcess)->Result<Self>{
  if pins.saved.role!=role as u8||root.path()!=pins.saved.client_root.join("role-vault")||pins.marker_sha256==[0;32]||pins.canonical_native==[0;32]||pins.side_native.contains(&[0;32])
   ||pins.saved.queued.is_empty()||pins.saved.queued.len()>4096||pins.saved.preimage_conditions.is_empty()||pins.saved.preimage_conditions.len()>4096||pins.saved.payment_wire_commitments.len()>64||pins.saved.reserved_inputs.len()>4096
   ||genesis.height!=0||genesis.genesis!=c.genesis||genesis.fingerprint!=c.fingerprint||!(1..=384).contains(&pins.head.height)||pins.head.block==[0;32]||pins.head.root==[0;32]{return Err("Original initialized role/nonempty continuity pins required".into());}
  owner.recheck()?;
  let marker=ImagePin::open(&root.path().join("NEW-CONTINUOUS-TEST-ROLE.marker"),&owner.identity().user_sid)?;
  if marker.hash()!=pins.marker_sha256{return Err("Original native role marker bytes differ".into());}
  let m:serde_json::Value=serde_json::from_slice(&marker.read_bounded(2048)?).map_err(err)?;
  if m["format"]!=super::role_vault::ROLE_VAULT_MARKER||m["role"]!=role as u8||m["campaign"]!=hex::encode(c.campaign)||m["source"]!=hex::encode(c.source)||m["h0"]!=hex::encode(c.h0)||m["genesis"]!=hex::encode(c.genesis)||m["fingerprint"]!=hex::encode(c.fingerprint)||m["original_launch16"]!=false||m["production_authorized"]!=false{return Err("Original exact role/context marker required".into());}
  // Existing qualified passive helper: all FOUR initialized side files checked
  // read-only BEFORE Controller/Store/Mempool writable constructors. No reset.
  let mut dbs=super::continuous_passive::preflight_side(root,c,genesis.network,owner)?;
  if dbs.len()!=4||dbs.iter().zip(pins.side_native).any(|(held,expected)|held.native_id_hash()!=expected){return Err("Original four role native side identities differ".into());}
  let chain_path=root.path().join("public-chain.sqlite");
  let (canonical,read)=super::continuous_passive::held_db(&chain_path,owner,0x4d554632,4)?;
  if canonical.native_id_hash()!=pins.canonical_native{return Err("Original own canonical native identity differs".into());}
  let count:i64=read.query_row("SELECT count(*) FROM sqlite_schema",[],|r|r.get(0)).map_err(err)?;
  let tables:i64=read.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('finalized_v2','integrity_v2','evidence_v2','canonical_v2','state_v2','undo_v2','confirmations_v2','state_merkle_nodes','state_merkle_tip','accepted_recovery_v2','operation_index_v2')",[],|r|r.get(0)).map_err(err)?;
  if count!=20||tables!=11{return Err("Original initialized own canonical schema required".into());}drop(read);dbs.push(canonical);
  let store=Store::open(&root.vault()).map_err(err)?;
  let status=store.status().map_err(str::to_owned)?.ok_or("Original vault pointer missing; never initialize")?;
  if status.revision!=pins.saved.revision||status.active!=pins.saved.active||status.staged!=pins.saved.staged||status.superseded!=pins.saved.superseded{return Err("Original active/staged/superseded pointers differ".into());}drop(store);
  let initial_root=initial.root().map_err(err)?;State::from_records(&initial.records().map_err(err)?,initial_root).map_err(err)?;
  let chain=CanonicalStore::open_trusted_genesis(&chain_path,genesis,initial,initial_root,1000,[255;32]).map_err(err)?;
  let (head,current)=chain.load().map_err(err)?;
  if head.height!=pins.head.height||head.block!=pins.head.block||head.root!=pins.head.root||current.root().map_err(err)?!=pins.head.root{return Err("Actual original own Genesis replay differs".into());}
  let authority=super::control_files::hash(&pins.saved.active.authority_id)?;let descriptor=hex::decode(&pins.saved.active.owner_descriptor).map_err(err)?;
  let(public,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(&descriptor).map_err(err)?;
  if public.role!=mutiny_crypto_v2::Role::WalletOwner||generation!=pins.saved.active.generation||initial.wallets.current(authority).is_none()||current.wallets.current(authority)!=Some(descriptor.as_slice()){return Err("Original retained vault current canonical authority differs".into());}
  let declaration=super::role_vault::declaration(role,c,&current)?;
  let pool=Mempool::open(&root.path().join("public-payment-pool.sqlite"),c.genesis,c.fingerprint,65536).map_err(err)?;
  let mut controller=Controller::open(root,Replica::from_pinned_chain(chain)?,pool,declaration)?;
  if controller.identity().is_some(){return Err("Existing role must start LOCKED; actual Unlock widget required".into());}
  owner.recheck()?;marker.recheck()?;for pin in &dbs{pin.recheck()?;}
  Ok(Self{controller,files:vec![marker],dbs,expected:pins})
 }
}
/// Read-only post-Unlock/Reverify callback. Never calls unlock/review/authorize.
/// The actual current raw widget must have unlocked the retained ciphertext first.
pub(super) fn verify_after_actual_unlock(wallet:&mut Controller,pins:&RolePins)->Result<serde_json::Value>{
 if wallet.identity()!=Some(&pins.saved.active){return Err("Actual raw Unlock must restore exact original current identity".into());}
 let s=wallet.vault_status()?.ok_or("Existing vault pointer missing")?;
 if s.revision!=pins.saved.revision||s.active!=pins.saved.active||s.staged!=pins.saved.staged||s.superseded!=pins.saved.superseded{return Err("Original vault revision/pointers changed".into());}
 let mut queued=wallet.queued_operations()?.into_iter().map(|(q,status)|QueuedPin{id:q.id,kind:q.kind.title().into(),complete:q.complete,status}).collect::<Vec<_>>();queued.sort_by_key(|q|q.id);
 let mut expected=pins.saved.queued.clone();expected.sort_by_key(|q|q.id);if queued!=expected{return Err("Original nonempty protected outbox differs".into());}
 let mut conditions=wallet.preimage_conditions()?;conditions.sort();let mut expected=pins.saved.preimage_conditions.clone();expected.sort();if conditions!=expected||conditions.is_empty(){return Err("Original sealed condition commitments differ or empty".into());}
 let mut payment=wallet.pending_for_transport()?.iter().map(|raw|mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,raw)).collect::<Vec<_>>();payment.sort();let mut expected=pins.saved.payment_wire_commitments.clone();expected.sort();if payment!=expected{return Err("Original exact pending payment byte commitments differ".into());}
 let mut reserved=pins.saved.reserved_inputs.clone();reserved.sort();
 let own=wallet.with_view(|v|->Result<serde_json::Value>{
  let authority=super::control_files::hash(&pins.saved.active.authority_id)?;let descriptor=hex::decode(&pins.saved.active.owner_descriptor).map_err(err)?;
  if v.anchor().height!=pins.head.height||v.anchor().block!=pins.head.block||v.state_root()!=pins.head.root||v.state().wallets.current(authority)!=Some(descriptor.as_slice()){return Err("Actual Controller own canonical head/current signer differs".into());}
  let mut actual=v.reserved().iter().map(|p|PointPin{transaction:p.transaction,index:p.index}).collect::<Vec<_>>();actual.sort();if actual!=reserved{return Err("Original reserved inputs differ; never clear/rebuild by assertion".into());}
  Ok(serde_json::json!({"height":v.anchor().height,"block":hex::encode(v.anchor().block),"root":hex::encode(v.state_root()),"reserved_inputs":actual}))
 })??;
 Ok(serde_json::json!({"format":MARKER,"actual_existing_controller":own,"revision":s.revision,"active":s.active,"staged":s.staged,"superseded":s.superseded,"outbox_count":queued.len(),"sealed_condition_count":conditions.len(),"payment_wire_commitments":payment.iter().map(hex::encode).collect::<Vec<_>>(),"new_genesis":false,"new_key":false,"confirmation_from_snapshot":false}))
}