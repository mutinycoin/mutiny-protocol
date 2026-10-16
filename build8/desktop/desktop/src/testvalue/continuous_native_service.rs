//! EXTERNAL SOURCE ONLY: a NEW, nonshipping continuous public TEST campaign.
//! Never opens, repairs, copies or regenerates the original Launch16 fixture.
//! Action paths have no wallet Controller, Session, approval or wallet-signing API.
//! Construction briefly uses public TEST fixture owner keys solely for initial descriptors;
//! those temporaries are dropped before the service worker starts. Coordinator/continuity
//! Node/Continuity are durably encrypted before H0. No private role key is exported.
use super::control_codec::{Action, Context, Head, Role as ClientRole};
use super::control_reply::{Code, Refusal};
use mutinyd_v8::{hybrid_runtime_v2::{HybridRuntime,WorkRequest},hybrid_peer_admission_v2::PeerLink,
    hybrid_dispatch_v2::{self,DispatchEvent}};
use mutiny_transport_v2::{object_link::Event,objects::{ObjectKind,Offer}};
use std::{path::{Path,PathBuf},io::Write,time::{Instant,Duration},sync::atomic::{AtomicBool,AtomicU64,Ordering}};
use sha2::Digest;
#[path="../wallet_host_fixture_licenses.rs"] mod licenses;
#[path="../wallet_host_fixture_tpm.rs"] mod tpm;
include!("../../../consensus/tests/support/dividend_rig.rs");
type Result<T,E=String>=std::result::Result<T,E>;
pub const SERVICE_MARKER:&str="MUTINY-W15-NONSHIPPING-CONTINUOUS-SERVICE-V1";
static INSTANCE:AtomicBool=AtomicBool::new(false);
static EPOCH:AtomicU64=AtomicU64::new(0);
fn clock()->u64{at(EPOCH.load(Ordering::SeqCst))}
// Failed pre-commit assembly must not silently move the simulated TEST clock.
// Once the real certifier advances, preserve that epoch even if another store
// installation fails; head disagreement then stops the service without success.
struct ClockAttempt { prior:u64, committed:bool }
impl ClockAttempt {
    fn begin(epoch:u64)->Self { Self{prior:EPOCH.swap(epoch,Ordering::SeqCst),committed:false} }
    fn committed(&mut self){self.committed=true;}
}
impl Drop for ClockAttempt { fn drop(&mut self){if !self.committed{EPOCH.store(self.prior,Ordering::SeqCst);}} }
struct Instance;
impl Instance{fn claim()->Result<Self>{INSTANCE.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).map_err(|_|"One live software TEST certifier per process")?;Ok(Self)}}
impl Drop for Instance{fn drop(&mut self){INSTANCE.store(false,Ordering::SeqCst);}}
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
fn create(path:&Path,raw:&[u8])->Result<()> {
    let mut file=std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(err)?;
    file.write_all(raw).map_err(err)?;file.sync_all().map_err(err)
}
fn until(deadline:Instant)->Result<Instant>{if Instant::now()>=deadline{return Err("Native action deadline; preserve partial state".into());}Ok(deadline.min(Instant::now()+Duration::from_millis(100)))}
pub struct Channel{pub role:ClientRole,pub peer:PeerLink, have:Option<Offer>, accepted:Option<(Offer,Hash,u8)>}
struct PublicFixture {genesis:FinalizedAnchor,license:Hash,backup_license:Hash}
pub struct Service {
    fixture:PublicFixture,provider:super::test_signer_store::Store,initial:State,root:Hash,certifier:CanonicalStore,
    pub local:HybridRuntime,pub remote:HybridRuntime,
    channels:Vec<Channel>,base:PathBuf,context:Context,buyer_authority:Hash,worker_published:bool,owner_sid:Vec<u8>,original_pins:Vec<super::image_pin::DatabasePin>,original_caches:Option<super::existing_cache::ExistingCaches>,original_six:Option<super::existing_six::ExistingSix>,original_initial:Option<super::existing_six::InitialSix>,initial_role_holds:Vec<super::initial_bootstrap::RoleHolds>,reopen_files:Vec<super::image_pin::ImagePin>,client_roots:[PathBuf;3],cache_holds:Vec<super::cache_snapshot::Held>,
    // Drop key-owning fixture BEFORE releasing the process-wide simulated clock lease.
    _instance:Instance,
}
impl Service {
    /// Caller supplies a NEW protected parent and externally reviewed campaign/source IDs.
    /// Initial public vectors belong only to this new identity/context campaign.
    pub(super) fn prepare_before_h0(base:&Path,campaign:Hash,source:Hash,client_roots:&[PathBuf;3],owner:&super::process_auth::VerifiedProcess,source_git:&str,source_manifest:super::continuous_passive::PathPin,roots_plan:super::continuous_passive::PathPin)->Result<super::initial_bootstrap::Prepared>{
        let user=&owner.identity().user_sid;owner.recheck()?;
        if !base.is_absolute()||campaign==[0;32]||source==[0;32]{return Err("New absolute TEST service root and nonzero external pins required".into());}
        super::initial_bootstrap::absent(base)?;
        let _preparation_instance=Instance::claim()?;
        if !mutiny_consensus_v8::submission_pool_v1::private_directory(base).map_err(err)?{return Err("Service root not created by this invocation".into());}
        let mut f=fixture();let a=owner_key();let c=second_key();let t=treasury_key();
        for k in [&a,&c,&t]{if f.state.wallets.current(addr(k,1)).is_none(){f.state.wallets.register(&desc(k,1)).map_err(err)?;}}
        f.state.coins.clear();
        for(tag,k)in[(78,&a),(79,&c),(80,&t)]{f.state.coins.insert(OutPoint{transaction:[tag;32],index:0},Coin{output:Output{owner:addr(k,1),atoms:50_000_000_000},created_height:0,coinbase:false});}
        f.state.dividends=DividendState::genesis(Treasury::new(Class::TestValue,desc(&t,1)).map_err(err)?);
        f.genesis.block=mutiny_consensus_v8::domain_hash(b"MUTINY-W15-NEW-CONTINUOUS-TEST-H0-V1",&campaign);
        let ctx=mutiny_consensus_v8::trading_v1::Context{network:f.genesis.network,genesis:f.genesis.genesis,fingerprint:f.genesis.fingerprint};
        f.state.protocol_records.extend(mutiny_consensus_v8::trading_v1::treasury_genesis_records(&ctx,addr(&t,1),desc(&t,1)).map_err(err)?);
        let initial=f.state.clone();let root=initial.root().map_err(err)?;
        State::from_records(&initial.records().map_err(err)?,root).map_err(err)?;
        // Public state only: no coordinator/continuity/private TPM or wallet keys serialized.
        let public=serde_json::to_vec_pretty(&serde_json::json!({"format":SERVICE_MARKER,"classification":"NEW PUBLIC SOFTWARE TEST-VALUE; not physical TPM or original Launch16", "campaign":hex::encode(campaign),"source":hex::encode(source),"genesis":hex::encode(f.genesis.encode()),"root":hex::encode(root),"records":initial.records().map_err(err)?})).map_err(err)?;
        // Public H0 is NOT written until original providers are durably retained below.
        let context=Context{campaign,source,h0:sha2::Sha256::digest(&public).into(),genesis:f.genesis.genesis,fingerprint:f.genesis.fingerprint};
        let open=|name:&str|CanonicalStore::open_trusted_genesis(&base.join(name),&f.genesis,&initial,root,T0,[255;32]).map_err(err);
        let certifier=open("certifier.sqlite")?;
        let runtime=|name:&str|HybridRuntime::from_pinned_chain_with_clock(open(&format!("{name}-chain.sqlite"))?,Mempool::open(&base.join(format!("{name}-payment.sqlite")),f.genesis.genesis,f.genesis.fingerprint,64*1024*1024).map_err(err)?,clock).map_err(err);
        EPOCH.store(0,Ordering::SeqCst);let local=runtime("local-node")?;let remote=runtime("remote-node")?;
        let buyer_authority=addr(&c,1);
        drop((a,c,t));
                // NEW synthetic role custody bootstrap only, never on existing reopen.
        // These are fixed PUBLIC TEST owner phrases. Drop each unlocked Controller
        // before service worker launch; service never owns their signing sessions.
        let mut original_pins=Vec::new();let mut canonical_paths=vec![base.join("certifier.sqlite"),base.join("local-node-chain.sqlite"),base.join("remote-node-chain.sqlite")];
        for (role,client) in [ClientRole::WalletA,ClientRole::WalletC,ClientRole::Treasury].into_iter().zip(client_roots){
            super::initial_bootstrap::absent(client)?;
            if !client.is_absolute(){return Err("Future bootstrap client roots must all be NEW absolute paths".into());}
            if !mutiny_consensus_v8::submission_pool_v1::private_directory(client).map_err(err)?{return Err("This bootstrap must own NEW client directory".into());}
            let vault=crate::wallet_controller_v2::VaultRoot::new(&client.join("role-vault")).map_err(err)?;
            let wallet=super::role_vault::open(&vault,role,context,&f.genesis,&initial)?;drop(wallet);
            canonical_paths.push(vault.path().join("public-chain.sqlite"));
        }
        let mut ids=sha2::Sha256::new();ids.update(super::existing_six::MARKER.as_bytes());
        for path in &canonical_paths{let pin=super::image_pin::DatabasePin::open(path,user)?;ids.update(pin.native_id_hash());original_pins.push(pin);}
        let key_path=base.join("synthetic-signers.sqlite");let guard_path=base.join("synthetic-certifier.guard");
        super::test_signer_store::create_new_private_leaf(&key_path,user)?;super::test_signer_store::create_new_private_leaf(&guard_path,user)?;
        let binding=super::test_signer_store::Binding{campaign,source,genesis:context.genesis,fingerprint:context.fingerprint,initial_root:root,original_store_identities:ids.finalize().into(),native_custody_identity:super::image_pin::DatabasePin::open(&key_path,user)?.native_id_hash(),native_guard_identity:super::image_pin::DatabasePin::open(&guard_path,user)?.native_id_hash(),node_descriptor:f.coordinator.public().descriptor(1).map_err(err)?,continuity_descriptor:f.continuity.public().descriptor(1).map_err(err)?};
        let provider=super::test_signer_store::Store::initialize_before_h0(&key_path,&guard_path,user,binding,&f.coordinator,&f.continuity)?;
        // Preparation persists original synthetic providers and exact initialized
        // state, but NEVER publishes H0, Ready, a viewport or worker. Same-process
        // DPAPI readback below is preparation only, not fresh-process acceptance.
        let license=f.license;let backup_license=f.backup_license;let initial_block=f.genesis.block;
        let draft_path=base.join(super::initial_bootstrap::DRAFT);create(&draft_path,&public)?;
        let draft=super::image_pin::ImagePin::open(&draft_path,user)?;
        let mut cache_values=Vec::new();let mut cache_leases=Vec::new();
        for(path,submission)in [(base.join("local-node-payment.sqlite"),false),(base.join("local-node-payment.submissions.sqlite"),true),(base.join("remote-node-payment.sqlite"),false),(base.join("remote-node-payment.submissions.sqlite"),true)]{
            let(snapshot,held)=super::cache_snapshot::Snapshot::observe(&path,submission,user)?;
            super::initial_bootstrap::initial_cache_empty(&snapshot)?;cache_values.push(snapshot);cache_leases.push(held);
        }
        let mut roles=Vec::new();let mut role_leases=Vec::new();
        for(i,role)in [ClientRole::WalletA,ClientRole::WalletC,ClientRole::Treasury].into_iter().enumerate(){let(saved,held)=super::initial_bootstrap::InitialRole::observe(&client_roots[i],role,context,&f.genesis,&initial,owner)?;roles.push(saved);role_leases.push(held);}
        let result=super::initial_bootstrap::Prepared{format:super::initial_bootstrap::MARKER.into(),preparing_process:owner.identity().clone(),context:super::shutdown::pin_context(context),source_git:source_git.into(),source_manifest,roots_plan,
            service_root:base.into(),client_roots:client_roots.clone(),draft:super::initial_bootstrap::object(&draft,&draft_path),canonical_paths:canonical_paths.try_into().map_err(|_|"Six initial paths")?,canonical_native:original_pins.iter().map(|p|p.native_id_hash()).collect::<Vec<_>>().try_into().map_err(|_|"Six initial native identities")?,initial_block,
            provider:super::shutdown::ProviderPin::observed(&provider.binding_pin(),provider.journal_pin()?),caches:cache_values.try_into().map_err(|_|"Four initial caches")?,roles:roles.try_into().map_err(|_|"Three initial roles")?,license,backup_license,buyer_authority};
        result.validate()?;draft.recheck()?;for h in &cache_leases{h.recheck()?;}for h in &role_leases{h.recheck()?;}for p in &original_pins{p.recheck()?;}owner.recheck()?;
        super::initial_bootstrap::absent(&base.join("continuous-h0-public.json"))?;
        super::initial_bootstrap::absent(&base.join(super::initial_bootstrap::PROOF))?;
        // No private material in result. Actual process exit is independently
        // observed and required by fresh reopen; dropping here is not that proof.
        drop((provider,f,certifier,local,remote));Ok(result)
    }
    /// Exact fresh-process existing-only initialization proof BEFORE public H0.
    /// Does not call fixture, key generation, wallet restore or save_initial.
    pub(super) fn reopen_before_h0(prepared:&super::initial_bootstrap::HeldPrepared,owner:&super::process_auth::VerifiedProcess)->Result<Self>{
        let p=&prepared.value;let context=p.context.context();let base=&p.service_root;let user=&owner.identity().user_sid;
        p.require_fresh_service(owner.identity())?;prepared.recheck()?;
        super::initial_bootstrap::absent(&base.join("continuous-h0-public.json"))?;super::initial_bootstrap::absent(&base.join(super::initial_bootstrap::PROOF))?;
        let instance=Instance::claim()?;let(genesis,initial,root)=prepared.initial()?;
        // ALL SIX existing canonical leaves inspected without writable opens.
        let mut originals=super::existing_six::InitialSix::inspect(p.canonical_paths.clone(),p.canonical_native,p.initial_block,root,user,&genesis,&initial)?;
        let cache_pins=std::array::from_fn(|i|super::existing_cache::CachePin{path:p.caches[i].main.path.clone(),native_id:p.caches[i].main.native_id,submission:p.caches[i].submission,pending:std::collections::BTreeMap::new()});
        let original_caches=super::existing_cache::ExistingCaches::preflight(&cache_pins,user,context.genesis,context.fingerprint)?;
        let mut cache_holds=Vec::new();for snapshot in &p.caches{cache_holds.push(snapshot.preflight(user)?);super::initial_bootstrap::initial_cache_empty(snapshot)?;}
        let mut initial_role_holds=Vec::new();for(i,role)in [ClientRole::WalletA,ClientRole::WalletC,ClientRole::Treasury].into_iter().enumerate(){initial_role_holds.push(p.roles[i].preflight(role,context,&genesis,&initial,owner)?);}
        // Existing-only encrypted provider open checks exact native IDs, protected
        // ACLs, DPAPI/context/descriptors, exclusive guard and both possession domains.
        let provider=super::test_signer_store::Store::reopen_existing(&base.join("synthetic-signers.sqlite"),&base.join("synthetic-certifier.guard"),user,p.binding(),0)?;
        if provider.journal_pin()?!=p.provider.journal||provider.binding_pin().original_store_identities!=originals.original_identity_commitment{return Err("Prepared original journal/identity commitment changed; never reset".into());}
        originals.open_replay(&genesis,&initial)?;
        let authority=mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(&initial,genesis.clone(),root).map_err(err)?;let node=mutiny_consensus_v8::node_admission_v2::node_id(context.genesis,provider.node_descriptor()).map_err(err)?;
        provider.verify_current_parent_voter(authority.voters.get(&node).ok_or("Original fresh Node provider is not actual initial certifier voter")?)?;
        if initial.licenses_v2.license(p.license).is_none()||initial.licenses_v2.license(p.backup_license).is_none()||initial.wallets.current(p.buyer_authority).is_none(){return Err("Original license/backup/buyer unavailable".into());}
        let certifier=originals.chains.remove(0);let local_chain=originals.chains.remove(0);let remote_chain=originals.chains.remove(0);EPOCH.store(0,Ordering::SeqCst);
        let local=HybridRuntime::from_pinned_chain_with_clock(local_chain,Mempool::open(&cache_pins[0].path,context.genesis,context.fingerprint,64*1024*1024).map_err(err)?,clock).map_err(err)?;
        let remote=HybridRuntime::from_pinned_chain_with_clock(remote_chain,Mempool::open(&cache_pins[2].path,context.genesis,context.fingerprint,64*1024*1024).map_err(err)?,clock).map_err(err)?;
        let (node_possession,continuity_possession)=provider.possession_before_h0()?;
        let proof=super::initial_bootstrap::FreshProof{format:super::initial_bootstrap::FRESH_MARKER.into(),prepared_sha256:prepared.sha,preparing_process:p.preparing_process.clone(),reopened_process:owner.identity().clone(),context:p.context.clone(),node_possession,continuity_possession,journal:provider.journal_pin()?,canonical_native:p.canonical_native};proof.verify(p,prepared.sha)?;
        // Repeat every actual before/after pin/journal/snapshot before publishing.
        originals.recheck()?;original_caches.recheck()?;for hold in &initial_role_holds{hold.recheck()?;}for snapshot in &p.caches{snapshot.preflight(user)?.recheck()?;}prepared.recheck()?;owner.recheck()?;
        let proof_path=base.join(super::initial_bootstrap::PROOF);let proof_raw=serde_json::to_vec_pretty(&proof).map_err(err)?;super::initial_bootstrap::create_public(&proof_path,&proof_raw)?;
        let proof_pin=super::image_pin::ImagePin::open(&proof_path,user)?;if proof_pin.read_bounded(128*1024)?!=proof_raw{return Err("Fresh provider receipt readback differs; preserve partial, H0 absent".into());}
        // Only this actual, distinct reopened process can publish public H0. A
        // partial proof or initialization attempt never overwrites/retries outputs.
        p.require_fresh_service(owner.identity())?;prepared.recheck()?;if provider.journal_pin()?!=p.provider.journal{return Err("Initial provider journal changed before H0 publication".into());}
        let public=prepared.draft_bytes()?;let h0_path=base.join("continuous-h0-public.json");create(&h0_path,&public)?;let h0=super::image_pin::ImagePin::open(&h0_path,user)?;if h0.hash()!=context.h0{return Err("Published original H0 differs; preserve partial".into());}
        let result=Self{fixture:PublicFixture{genesis,license:p.license,backup_license:p.backup_license},provider,initial,root,certifier,local,remote,channels:Vec::new(),base:base.into(),context,buyer_authority:p.buyer_authority,worker_published:false,owner_sid:user.to_vec(),original_pins:Vec::new(),original_caches:Some(original_caches),original_six:None,original_initial:Some(originals),initial_role_holds,reopen_files:vec![proof_pin,h0],client_roots:p.client_roots.clone(),cache_holds,_instance:instance};
        result.head()?;result.publish_observed_head()?;Ok(result)
    }
    /// Existing-only handoff. These pins are assembled only by the immutable,
    /// externally SHA-pinned native launcher, never the pipe request codec.
    /// The method reads retained H0/source; does not call fixture/new/save_initial.
    pub(super) fn reopen_existing(base:&Path,context:Context,source_manifest:&Path,source_git:&str,
        license:Hash,backup_license:Hash,six:super::existing_six::SixPins,
        caches:[super::existing_cache::CachePin;4],cache_snapshots:[super::cache_snapshot::Snapshot;4],user:&[u8],
        custody_path:&Path,guard_path:&Path,binding:super::test_signer_store::Binding,
        buyer_authority:Hash,worker_published:bool,expected_journal:super::test_signer_store::JournalPin)->Result<Self>{
        if !base.is_absolute()||base.join("continuous-h0-public.json")==source_manifest||license==backup_license||license==[0;32]||backup_license==[0;32]||buyer_authority==[0;32]
            ||source_git.len()!=40||!source_git.bytes().all(|b|b.is_ascii_hexdigit())
            ||[context.campaign,context.source,context.h0,context.genesis,context.fingerprint].contains(&[0;32])
            ||custody_path!=base.join("synthetic-signers.sqlite")||guard_path!=base.join("synthetic-certifier.guard") {
            return Err("Exact original live service paths/context/source required".into());
        }
        let instance=Instance::claim()?;
        let h0=super::image_pin::ImagePin::open(&base.join("continuous-h0-public.json"),user)?;
        let manifest=super::image_pin::ImagePin::open(source_manifest,user)?;
        if h0.hash()!=context.h0||manifest.hash()!=context.source{return Err("Original pinned H0/source bytes differ".into());}
        let m:serde_json::Value=serde_json::from_slice(&manifest.read_bounded(16*1024*1024)?).map_err(err)?;
        if m["head"]!=source_git||m["files"].as_array().is_none_or(|f|f.is_empty()||f.len()>4096){return Err("Original complete source/Git required".into());}
        #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)]
        struct RetainedH0{format:String,classification:String,campaign:String,source:String,genesis:String,root:String,records:Vec<(Hash,Vec<u8>)>}
        let public:RetainedH0=serde_json::from_slice(&h0.read_bounded(8*1024*1024)?).map_err(err)?;
        if public.format!=SERVICE_MARKER||public.classification.is_empty()||public.campaign!=hex::encode(context.campaign)||public.source!=hex::encode(context.source)
            ||public.genesis.len()>8192||public.records.is_empty()||public.records.len()>4096||public.records.iter().map(|(_,r)|r.len()).sum::<usize>()>8*1024*1024 {
            return Err("Original bounded public H0 context required".into());
        }
        let genesis=FinalizedAnchor::decode(&hex::decode(public.genesis).map_err(err)?).map_err(err)?;
        let root=super::control_files::hash(&public.root)?;
        let initial=State::from_records(&public.records,root).map_err(err)?;
        if genesis.height!=0||genesis.genesis!=context.genesis||genesis.fingerprint!=context.fingerprint
            ||binding.campaign!=context.campaign||binding.source!=context.source||binding.genesis!=context.genesis||binding.fingerprint!=context.fingerprint||binding.initial_root!=root {
            return Err("Original exact Genesis/provider context differs".into());
        }
        let expected_service=[base.join("certifier.sqlite"),base.join("local-node-chain.sqlite"),base.join("remote-node-chain.sqlite")];
        if six.paths[..3]!=expected_service||caches[0].path!=base.join("local-node-payment.sqlite")||caches[2].path!=base.join("remote-node-payment.sqlite")
            ||caches[1].path!=caches[0].path.with_extension("submissions.sqlite")||caches[3].path!=caches[2].path.with_extension("submissions.sqlite")
            ||caches[0].submission||!caches[1].submission||caches[2].submission||!caches[3].submission {
            return Err("Original service canonical/cache ordering differs".into());
        }
        // Every canonical/cache file initialized and native held BEFORE any
        // corresponding writable API. The provider performs its own existing-only
        // initialized/confidentiality/schema/ciphertext/possession/journal checks.
        let mut originals=super::existing_six::ExistingSix::preflight_then_replay(six,user,&genesis,&initial,root)?;
        let original_caches=super::existing_cache::ExistingCaches::preflight(&caches,user,context.genesis,context.fingerprint)?;
        if binding.original_store_identities!=originals.original_identity_commitment{return Err("Provider bound to other original six stores".into());}
        let mut cache_holds=Vec::new();
        for (expected,snapshot) in caches.iter().zip(&cache_snapshots){
            if snapshot.main.path!=expected.path||snapshot.main.native_id!=expected.native_id||snapshot.submission!=expected.submission{return Err("Exact whole-cache snapshot/native/context pairing differs".into());}
            cache_holds.push(snapshot.preflight(user)?);
        }
        let client_roots=std::array::from_fn(|i|originals.pins.paths[i+3].parent().and_then(Path::parent).expect("validated six role path").to_path_buf());
        let height=originals.pins.height;
        let provider=super::test_signer_store::Store::reopen_existing(custody_path,guard_path,user,binding,height)?;
        if provider.journal_pin()?!=expected_journal{return Err("Original retained pending journal differs from external shutdown snapshot".into());}
        provider.ticket_for_parent(height)?; // Pending exact journal is retained; no reset.
        originals.recheck()?;original_caches.recheck()?;h0.recheck()?;manifest.recheck()?;
        let (head,state)=originals.chains[0].load().map_err(err)?;
        if state.licenses_v2.license(license).is_none()||state.licenses_v2.license(backup_license).is_none()||initial.wallets.current(buyer_authority).is_none(){return Err("Original primary/backup/buyer identities absent".into());}
        let parent=FinalizedAnchor{network:genesis.network,genesis:genesis.genesis,fingerprint:genesis.fingerprint,height:head.height,block:head.block};
        let authority=mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(&state,parent,state.root().map_err(err)?).map_err(err)?;
        let node=mutiny_consensus_v8::node_admission_v2::node_id(context.genesis,provider.node_descriptor()).map_err(err)?;
        let voter=authority.voters.get(&node).ok_or("Original admitted certifier no longer an active parent voter")?;
        provider.verify_current_parent_voter(voter)?;
        // Restore exact canonical mining epoch. No new clock epoch inferred.
        let epoch=mutiny_consensus_v8::pow::mining_epoch(head.timestamp,T0).map_err(err)?;
        EPOCH.store(epoch,Ordering::SeqCst);
        let certifier=originals.chains.remove(0);let local_chain=originals.chains.remove(0);let remote_chain=originals.chains.remove(0);
        let local_pool=Mempool::open(&caches[0].path,context.genesis,context.fingerprint,64*1024*1024).map_err(err)?;
        let remote_pool=Mempool::open(&caches[2].path,context.genesis,context.fingerprint,64*1024*1024).map_err(err)?;
        let local=HybridRuntime::from_pinned_chain_with_clock(local_chain,local_pool,clock).map_err(err)?;
        let remote=HybridRuntime::from_pinned_chain_with_clock(remote_chain,remote_pool,clock).map_err(err)?;
        let result=Self{fixture:PublicFixture{genesis,license,backup_license},provider,initial,root,certifier,local,remote,channels:Vec::new(),base:base.into(),context,buyer_authority,worker_published,
            owner_sid:user.to_vec(),original_pins:Vec::new(),original_caches:Some(original_caches),original_six:Some(originals),original_initial:None,initial_role_holds:Vec::new(),reopen_files:vec![h0,manifest],client_roots,cache_holds,_instance:instance};
        result.head()?;result.publish_observed_head()?;Ok(result)
        // Caller still must reopen actual initialized three Controllers, compare
        // nonempty queue/conditions/pointers/reserved inputs, obtain genuine raw
        // Lock/Unlock/Reverify and fresh process/role handshake before workflow credit.
    }
    /// Actual serialized worker boundary only. No key/ciphertext/preimage export.
    /// The external supervisor must separately observe natural process closure.
    pub(super) fn shutdown_snapshot(&self,completed_between_actions:bool)->Result<super::shutdown::ServiceSnapshot>{
        let head=self.head()?;let actual=super::process_auth::VerifiedProcess::observe_created_process(std::process::id())?;
        let owner=super::process_auth::VerifiedProcess::open(&actual)?;owner.recheck()?;
        let paths=[self.base.join("certifier.sqlite"),self.base.join("local-node-chain.sqlite"),self.base.join("remote-node-chain.sqlite"),
            self.client_roots[0].join("role-vault/public-chain.sqlite"),self.client_roots[1].join("role-vault/public-chain.sqlite"),self.client_roots[2].join("role-vault/public-chain.sqlite")];
        let mut native=Vec::new();
        for path in &paths{let pin=super::image_pin::DatabasePin::open(path,&self.owner_sid)?;
            let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(err)?;
            db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN;").map_err(err)?;
            // Native snapshot still is not an own-Genesis finality substitute.
            // Reopen repeats full six replays before any mutable handoff.
            let n:i64=db.query_row("SELECT count(*) FROM canonical_v2 WHERE height=?1 AND typeof(block)='blob' AND length(block)=32 AND typeof(root)='blob' AND length(root)=32 AND block=?2 AND root=?3 AND height=(SELECT max(height) FROM canonical_v2) AND height=(SELECT max(height) FROM finalized_v2)",rusqlite::params![head.height.to_be_bytes().as_slice(),head.block.as_slice(),head.root.as_slice()],|r|r.get(0)).map_err(err)?;
            if n!=1{return Err("All six actual original heads must agree before restart checkpoint".into());}
            drop(db);pin.recheck()?;native.push(pin.native_id_hash());
        }
        let canonical_native:[Hash;6]=native.try_into().map_err(|_|"Six actual native snapshot identities")?;
        let cache_paths=[self.base.join("local-node-payment.sqlite"),self.base.join("local-node-payment.submissions.sqlite"),self.base.join("remote-node-payment.sqlite"),self.base.join("remote-node-payment.submissions.sqlite")];
        let mut caches=Vec::new();let mut holds=Vec::new();
        for (i,p) in cache_paths.iter().enumerate(){let (snapshot,held)=super::cache_snapshot::Snapshot::observe(p,i%2==1,&self.owner_sid)?;caches.push(snapshot);holds.push(held);}
        let mut wires=Vec::new();let mut names=std::collections::BTreeSet::new();let mut observed=0;
        for entry in std::fs::read_dir(&self.base).map_err(err)?{observed+=1;if observed>2048{return Err("Finite service public membership quota".into());}
            let entry=entry.map_err(err)?;let name=entry.file_name().into_string().map_err(|_|"Service public filename Unicode")?;
            let Some(id_hex)=name.strip_prefix("wire-").and_then(|n|n.strip_suffix(".bin"))else{continue;};
            if id_hex.len()!=64||!id_hex.bytes().all(|b|b.is_ascii_hexdigit())||!names.insert(name.clone())||names.len()>64{return Err("Exact bounded exported wire names required".into());}
            let id=super::control_files::hash(id_hex)?;let p=entry.path();let held=super::image_pin::ImagePin::open(&p,&self.owner_sid)?;let raw=held.read_bounded(16384)?;
            let candidates=[0,1].into_iter().filter_map(|list|mutiny_consensus_v8::operation_index_v2::operation_id(list,&raw).ok().filter(|(_,actual)|*actual==id).map(|(kind,_)|(list,kind))).collect::<Vec<_>>();
            if candidates.len()!=1{return Err("Exact raw canonical operation list/kind/ID differs".into());}
            let (list,kind)=candidates[0];let commitment=mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,&raw);
            wires.push((list,kind,id,p,held.hash(),commitment));held.recheck()?;
        }
        wires.sort_by_key(|(_,_,id,_,_,_)|*id);if wires.is_empty(){return Err("No actual exported raw wire to authenticate own replay".into());}
        let ids=wires.iter().map(|(_,_,id,_,_,_)|*id).collect::<Vec<_>>();
        let records=self.certifier.verified_operation_records_many(&ids).map_err(err)?;let mut confirmed=Vec::new();
        for (list,kind,id,path,sha,commitment) in wires {
            let matching=records.get(&id).ok_or("Own replay result missing requested ID")?.iter().filter(|r|r.list==list&&r.kind==kind&&r.wire==commitment&&r.height<=head.height).collect::<Vec<_>>();
            if matching.len()>1{return Err("Ambiguous canonical inclusion record".into());}
            if let Some(r)=matching.first(){confirmed.push(super::continuous_passive::WirePin{list,kind,id,wire:super::continuous_passive::PathPin{path,sha256:sha},own_commitment:commitment,height:r.height});}
        }
        if confirmed.is_empty(){return Err("Own Genesis replay has no matching finalized exported raw operation".into());}
        let mut transport_rows=Vec::new();let mut transport_holds=Vec::new();
        for role in 1..=3{let path=self.base.join(format!("role{role}-native-transport-{}-{}.sqlite",actual.pid,actual.start_filetime));let (row,held)=super::cache_snapshot::Object::observe_transport(&path,&self.owner_sid)?;transport_rows.push(row);transport_holds.push(held);}
        for held in &transport_holds{held.recheck()?;}
        let provider=super::shutdown::ProviderPin::observed(&self.provider.binding_pin(),self.provider.journal_pin()?);
        for held in &holds{held.recheck()?;}owner.recheck()?;
        Ok(super::shutdown::ServiceSnapshot{format:super::shutdown::MARKER.into(),context:super::shutdown::pin_context(self.context),actual_process:actual,completed_between_actions,
            observed_head:super::continuous_passive::HeadPin{height:head.height,block:head.block,root:head.root},canonical_paths:paths,canonical_native,transports:transport_rows.try_into().map_err(|_|"Three actual original service transport caches")?,caches:caches.try_into().map_err(|_|"Four observed cache snapshots")?,provider,
            license:self.fixture.license,backup_license:self.fixture.backup_license,buyer_authority:self.buyer_authority,worker_published:self.worker_published,own_replay_confirmed:confirmed})
    }
    pub fn context(&self)->Context{self.context}
    pub fn initial(&self)->(&FinalizedAnchor,&State){(&self.fixture.genesis,&self.initial)}
    pub fn attach(&mut self,role:ClientRole,mut peer:PeerLink)->Result<()> {
        if self.channels.iter().any(|c|c.role==role)||self.channels.len()==3{return Err("Duplicate/extra role transport refused".into());}
        let ok=peer.with_current(|l|l.matches_network(self.context.genesis,self.context.fingerprint))?;
        if !ok{return Err("Role transport network differs from pinned campaign".into());}
        self.channels.push(Channel{role,peer,have:None,accepted:None});Ok(())
    }
    pub fn head(&self)->Result<Head>{
        for pin in &self.original_pins{pin.recheck()?;}
        if let Some(six)=&self.original_six{six.native_recheck()?;}
        if let Some(six)=&self.original_initial{six.native_recheck()?;}for held in &self.initial_role_holds{held.recheck()?;}
        if let Some(caches)=&self.original_caches{caches.recheck()?;}
        for pin in &self.reopen_files{pin.recheck()?;}for held in &self.cache_holds{held.recheck()?;}
        let(stored,state)=self.certifier.load().map_err(err)?;let root=state.root().map_err(err)?;
        let parent=FinalizedAnchor{network:self.fixture.genesis.network,genesis:self.context.genesis,fingerprint:self.context.fingerprint,height:stored.height,block:stored.block};
        if root!=stored.root||parent!=self.remote.head().map_err(err)?||parent!=self.local.head().map_err(err)?{return Err("Partial service stores disagree; no success reply".into());}
        Ok(Head{height:parent.height,block:parent.block,root})
    }
    fn publish_observed_head(&self)->Result<()> {
        let h=self.head()?;
        if h.height>384{return Err("Local published history exceeds campaign action quota".into());}
        let mut ctx=Vec::with_capacity(160);
        for hash in [self.context.campaign,self.context.source,self.context.h0,self.context.genesis,self.context.fingerprint]{ctx.extend_from_slice(&hash);}
        let actual=super::process_auth::VerifiedProcess::observe_created_process(std::process::id())?;
        let held=super::process_auth::VerifiedProcess::open(&actual)?;held.recheck()?;
        let raw=serde_json::to_vec_pretty(&serde_json::json!({"format":"MUTINY-W15-NONSHIPPING-HOST-OBSERVATION-V1","pid":actual.pid,"start_filetime":actual.start_filetime,"image_sha256":hex::encode(actual.image_sha256),"context_sha256":hex::encode(sha2::Sha256::digest(&ctx)),"height":h.height,"block":hex::encode(h.block),"root":hex::encode(h.root),"confirmed":false})).map_err(err)?;
        create(&self.base.join(format!("host-observed-{}-{}-{:08}.json",actual.pid,actual.start_filetime,h.height)),&raw)?;held.recheck()?;Ok(())
    }
    /// Public software-device possession only. No owner key or owner signature
    /// enters this method; the actual current buyer signs solely in its widgets.
    /// One fixed fresh Worker is defined for this bounded post-sale campaign.
    fn publish_fresh_worker_offer(&mut self)->Result<()> {
        if self.worker_published{return Ok(());}
        let (head,state)=self.certifier.load().map_err(err)?;
        if head.height==0{return Ok(());}
        let license=state.licenses_v2.license(self.fixture.license).ok_or("Primary TEST license missing")?;
        let initial_owner=self.initial.licenses_v2.license(self.fixture.license).ok_or("Initial primary license missing")?.owner;
        if license.owner==initial_owner||license.active_worker.is_some()||state.licenses_v2.pending_assignment(license.id).is_some(){return Ok(());}
        let Some(owner_raw)=state.wallets.current(self.buyer_authority)else{return Err("Actual buyer authority missing".into());};
        if state.wallets.authorize(license.owner,owner_raw).is_err(){return Ok(());}
        let(owner,owner_generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(owner_raw).map_err(err)?;
        let node_id=mutiny_consensus_v8::node_admission_v2::node_id(self.context.genesis,self.provider.node_descriptor()).map_err(err)?;
        let node=state.membership_v2.get(node_id).ok_or("Actual admitted TEST node missing")?;
        let node_raw=node.current_node_descriptor();
        let (_,configuration_generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(node_raw).map_err(err)?;
        let epoch=mutiny_consensus_v8::pow::mining_epoch(head.timestamp,T0).map_err(err)?;
        let terms=mutiny_consensus_v8::license_assignment_v2::DeliveryTerms::at(license,head.height.checked_add(1).ok_or("Worker delivery height overflow")?,epoch).map_err(err)?;
        let mut binding=mutiny_crypto_v2::enrollment::Binding{
            genesis:self.context.genesis,fingerprint:self.context.fingerprint,license:license.id,
            owner_descriptor:mutiny_crypto_v2::enrollment::owner_descriptor_id(&owner,owner_generation).map_err(err)?,owner_generation,
            worker_public:super::worker_fixture::public()?,worker_id:[0;32],
            coordinator:mutiny_consensus_v8::work_authority_v2::node_identity(node_raw).map_err(err)?,configuration_generation,
            device_mac:[2,0,0,0,0,0x71],assignment_generation:terms.assignment_generation,
            effective_epoch:terms.effective_epoch,valid_until_height:terms.min_valid_until_height,
        };
        binding.worker_id=binding.derived_worker_id();
        let possession=super::worker_fixture::possession(&binding)?;
        let public=serde_json::to_vec_pretty(&serde_json::json!({
            "format":super::worker_fixture::WORKER_FIXTURE_MARKER,
            "classification":"Fixed PUBLIC SOFTWARE TEST Worker; no physical TPM qualification or provisioning; no owner signature",
            "source":hex::encode(self.context.source),"campaign":hex::encode(self.context.campaign),
            "parent_height":head.height,"parent_block":hex::encode(head.block),"parent_root":hex::encode(head.root),
            "license":hex::encode(license.id),"owner_address":hex::encode(license.owner),"buyer_authority":hex::encode(self.buyer_authority),
            "binding_cbor_hex":hex::encode(binding.bytes().map_err(err)?),"node_descriptor_hex":hex::encode(node_raw),
            "worker_possession_hex":hex::encode(possession),"owner_signature_provided":false,"confirmed":false,
        })).map_err(err)?;
        create(&self.base.join(format!("fresh-worker-public-{:08}.json",head.height)),&public)?;
        self.worker_published=true;Ok(())
    }
    fn record_certified(&self,height:u64,raw:&[u8])->Result<()> {
        let path=self.base.join(format!("certified-{height:08}.bin"));
        match std::fs::symlink_metadata(&path){
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>create(&path,raw),
            Ok(_)=>{let hash:Hash=sha2::Sha256::digest(raw).into();let pin=super::image_pin::ImagePin::open(&path,&self.owner_sid)?;if pin.hash()!=hash{return Err("Retained certified byte hash differs".into());}
                if pin.read_bounded(8*1024*1024)?!=raw{return Err("Retained pending certified bytes differ; never overwrite".into());}Ok(())},
            Err(e)=>Err(err(e)),
        }
    }
    fn record_wire(&self,id:Hash,raw:&[u8])->Result<()> {
        let p=self.base.join(format!("wire-{}.bin",hex::encode(id)));
        if p.exists(){let meta=p.symlink_metadata().map_err(err)?;
            use std::os::windows::fs::MetadataExt;
            if !meta.is_file()||meta.file_attributes()&0x400!=0||meta.len()>16384||std::fs::read(&p).map_err(err)?!=raw{return Err("Existing public wire differs; preserved".into());}Ok(())
        }else{create(&p,raw)}
    }
    fn turn_channel(runtime:&mut HybridRuntime,channel:&mut Channel,deadline:Instant)->Result<()> {
        if let Some(frame)=channel.peer.with_current(|l|l.send_one())?.map_err(err)?{channel.peer.send(&frame,until(deadline)?)?;}
        if !channel.peer.wait_for_frame(until(deadline)?)?{return Ok(());}
        let received=channel.peer.receive(until(deadline)?)?;
        let event=hybrid_dispatch_v2::dispatch_peer(runtime,&mut channel.peer,received).map_err(err)?;
        match event{
            DispatchEvent::Transport(Event::Offered(ref offer)) if matches!(offer.kind,ObjectKind::SignedTransaction|ObjectKind::SignedOperation)=>{
                if channel.have.is_some()||channel.accepted.is_some(){return Err("One in-flight native object per authenticated role".into());}channel.have=Some(offer.clone());
            }
            DispatchEvent::TransactionAccepted{ref offer,id,..} if channel.have.as_ref()==Some(offer)=>{
                // Legacy SignedTransaction requires an explicit durable transport ACK.
                // It has no settlement/finality authority.
                let count: u16=offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD).try_into().map_err(err)?;
                if count>mutiny_transport_v2::objects::MAX_BITMAP_BITS{return Err("Native transaction ACK exceeds one supported window".into());}
                let frame=channel.peer.with_current(|l|l.receipt(&offer.id,0,count,0))?.map_err(err)?;
                channel.peer.send(&frame,until(deadline)?)?;
                channel.accepted=Some((offer.clone(),id,0));
            }
            DispatchEvent::OperationAccepted{ref offer,id,..} if channel.have.as_ref()==Some(offer)=>{channel.accepted=Some((offer.clone(),id,1));}
            DispatchEvent::Transport(_)=>{},
            _=>return Err("Unexpected role peer semantic event".into()),
        }
        if channel.accepted.is_none(){if let Some(offer)=&channel.have{if let Some(request)=channel.peer.with_current(|l|l.next_missing_request(&offer.id,0,false))?.map_err(err)?{channel.peer.send(&request.frame,until(deadline)?)?;}}}
        Ok(())
    }
    // Called on the same service worker between local RPC polls. History servicing
    // continues while UI clients independently replay; no canonical confirmation inferred.
    pub fn turn(&mut self,deadline:Instant)->Result<()> {
        for c in &mut self.channels{Self::turn_channel(&mut self.remote,c,deadline)?;}Ok(())
    }
    fn pump(&mut self,role:ClientRole,list:u8,kind:u8,id:Hash,commit:Hash,n:u32,deadline:Instant)->Result<()> {
        if !(1..=16384).contains(&n){return Err("Submission allocation bound".into());}
        let channel=self.channels.iter_mut().find(|c|c.role==role).ok_or("No authenticated role transport")?;
        let mut accepted=false;
        for _ in 0..8192 {
            if let Some((offer,actual,actual_list))=&channel.accepted {
                if *actual!=id||*actual_list!=list||offer.length!=n as usize||offer.kind!=if list==0{ObjectKind::SignedTransaction}else{ObjectKind::SignedOperation}{return Err("Actual accepted peer item differs from request".into());}
                accepted=true;break;
            }
            Self::turn_channel(&mut self.remote,channel,deadline)?;
        }
        if !accepted{return Err("Native fragment turn quota exceeded".into());}
        channel.accepted.take();channel.have.take();
        let (actual_list,raw)=self.remote.exact_submission_bytes(id).map_err(err)?.ok_or("Durable native pool missing exact object")?;
        let(actual_kind,actual_id)=mutiny_consensus_v8::operation_index_v2::operation_id(actual_list,&raw).map_err(err)?;
        if actual_list!=list||actual_kind!=kind||actual_id!=id||raw.len()!=n as usize||mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-OPERATION-WIRE-V1",&raw)!=commit{return Err("Durable native object differs from signed request commitment".into());}
        self.record_wire(id,&raw)
    }
    fn certify(&mut self,next_epoch:bool,ids:&[Hash],deadline:Instant)->Result<()> {
        until(deadline)?;self.head()?;let(stored,state)=self.certifier.load().map_err(err)?;
        let parent=self.remote.head().map_err(err)?;
        let timestamp=stored.timestamp;
        let old_epoch=mutiny_consensus_v8::pow::mining_epoch(timestamp,T0).map_err(err)?;
        let epoch=old_epoch.checked_add(u64::from(next_epoch)).ok_or("Epoch overflow")?;
        let timestamp=at(epoch).max(timestamp.checked_add(1).ok_or("Timestamp overflow")?);
        if mutiny_consensus_v8::pow::mining_epoch(timestamp,T0).map_err(err)?!=epoch{return Err("Current epoch lacks another monotonic inclusion timestamp; explicit next-epoch control required".into());}
        let mut book=state.licenses_v2.clone();book.activate_due(epoch).map_err(err)?;
        let selected=[self.fixture.license,self.fixture.backup_license].into_iter().find_map(|license|{
            let worker=book.license(license)?.active_worker?;
            book.active(license,worker,epoch).ok().map(|_|(license,worker))
        });
        let (license,worker)=selected.ok_or("No actual active TEST Worker; require genuine assignment/activation")?;
        let mut clock_attempt=ClockAttempt::begin(epoch);
        let ticket=self.provider.ticket_for_parent(parent.height)?;
        let prepared=self.remote.prepare(WorkRequest{expected_parent:&parent,license,worker,timestamp,ticket,operations:&[]}).map_err(err)?;
        let mut actual=prepared.body.transactions.iter().map(|r|(0,r)).chain(prepared.body.operations.iter().map(|r|(1,r))).map(|(l,r)|mutiny_consensus_v8::operation_index_v2::operation_id(l,r).map(|(_,i)|i).map_err(err)).collect::<Result<Vec<_>>>()?;
        actual.sort_unstable();if actual!=ids{return Err("Actual assembler object set differs; canonical commit not attempted".into());}
        until(deadline)?;
        let block=super::certifier_provider::certify_existing(prepared,&mut self.provider,&self.certifier,&parent,&state)?;let raw=block.encode().map_err(err)?;
        self.record_certified(parent.height.checked_add(1).ok_or("Height overflow")?,&raw)?;
        until(deadline)?;
        match self.certifier.commit(&block){
            Ok(true)=>clock_attempt.committed(),
            Ok(false)=>return Err("Real certifier did not advance".into()),
            Err(error)=>{
                // Restore only if the actual stored canonical parent is still
                // known unchanged. An uncertain/advanced durable outcome must
                // retain the attempted epoch and fail closed with its evidence.
                let unchanged=self.certifier.load().is_ok_and(|(h,_)|h.height==stored.height&&h.block==stored.block&&h.root==stored.root);
                if !unchanged{clock_attempt.committed();}
                return Err(format!("Real certifier commit refused or uncertain: {error:?}"));
            }
        }
        self.remote.install(&raw).map_err(err)?;self.local.install(&raw).map_err(err)?;
        // Original provider durable ticket/locks remain; no RAM counter reset/increment.
        self.head()?;self.publish_observed_head()?;self.publish_fresh_worker_offer()?;until(deadline)?;Ok(())
    }
    fn advertise(&mut self,height:u64,block:Hash,deadline:Instant)->Result<()> {
        let actual=self.certifier.canonical_block(height).map_err(err)?.ok_or("No actual certified block")?;
        if actual.header.block_hash()!=block{return Err("Requested certified identity differs from own history".into());}
        let raw=actual.encode().map_err(err)?;
        if self.channels.len()!=3{return Err("All three pinned role peers required before history advertisement".into());}
        for channel in &mut self.channels{
            let(_,frame)=channel.peer.with_current(|l|l.enqueue(ObjectKind::CertifiedBlock,&raw,0))?.map_err(err)?;
            channel.peer.send(&frame,until(deadline)?)?;
        }Ok(()) // Actual HAVE sent, NOT installation/finality. Client own replay remains mandatory.
    }
    pub fn execute(&mut self,role:ClientRole,action:&Action,deadline:Instant)->std::result::Result<Code,(Refusal,String)> {
        match action{
            Action::Head=>self.head().map(|_|Code::Observed).map_err(|e|(Refusal::ParentChanged,e)),
            Action::Pump{list,kind,id,wire_commitment,raw_bytes}=>self.pump(role,*list,*kind,*id,*wire_commitment,*raw_bytes,deadline).map(|_|Code::ExactDurableAdmission).map_err(|e|(Refusal::NativeAdmission,e)),
            Action::Certify{next_epoch,ids}=>self.certify(*next_epoch,ids,deadline).map(|_|Code::Observed).map_err(|e|(Refusal::NativeAssembly,e)),
            Action::Advertise{height,block}=>self.advertise(*height,*block,deadline).map(|_|Code::ActualHistoryAdvertised).map_err(|e|(Refusal::HistoryInstall,e)),
        }
    }
}


#[cfg(test)]
mod simulated_clock_scope_tests {
    use super::*;
    #[test]
    fn precommit_attempt_restores_clock_but_committed_or_uncertain_attempt_preserves_it(){
        let _lease=Instance::claim().unwrap();let prior=EPOCH.swap(17,Ordering::SeqCst);
        {let _failed=ClockAttempt::begin(18);assert_eq!(EPOCH.load(Ordering::SeqCst),18);}
        assert_eq!(EPOCH.load(Ordering::SeqCst),17);
        {let mut committed=ClockAttempt::begin(19);committed.committed();}
        assert_eq!(EPOCH.load(Ordering::SeqCst),19);
        // No state/root/head/finality proof is fabricated by this clock-only unit.
        EPOCH.store(prior,Ordering::SeqCst);
    }
}