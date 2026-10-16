//! EXTERNAL SOURCE ONLY / UNCOMPILED. Immutable externally pinned PUBLIC checkpoint.
//! No key material, creation fallback, request codec authority or finality by assertion.
//! Existing service/Controller openers independently replay and compare all originals.
use super::{bootstrap::{ContextPin},control_codec::{Context,Head,Role},
    continuous_passive::{VaultPin,PathPin,WirePin},
    process_auth::{Identity,VerifiedProcess,historical_process_closed},
    image_pin::ImagePin};
use mutiny_consensus_v8::Hash;
use std::{path::{Path,PathBuf},collections::{BTreeMap,BTreeSet}};
use sha2::{Digest,Sha256};
type Result<T>=std::result::Result<T,String>;
pub(super) const MARKER:&str="MUTINY-W15-NONSHIPPING-IMMUTABLE-LIVE-RESTART-SPEC-V1";
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
fn absolute(p:&Path)->bool{p.is_absolute()&&p.to_str().is_some_and(|s|s.len()<=4096&&!s.is_empty())
    &&!p.components().any(|c|matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir))}

#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleResume {pub saved:VaultPin,pub marker_sha256:Hash,
    pub canonical_native:Hash,pub side_native:[Hash;4]}
impl RoleResume {
    pub(super) fn native_pins(&self)->super::existing_role::RolePins{
        super::existing_role::RolePins{saved:self.saved.clone(),head:Head{height:0,block:[0;32],root:[0;32]},
            marker_sha256:self.marker_sha256,canonical_native:self.canonical_native,side_native:self.side_native}
    }
}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CacheEntry {pub id:Hash,pub wire_commitment:Hash}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CacheResume {pub path:PathBuf,pub native_id:Hash,pub submission:bool,
    pub pending:Vec<CacheEntry>}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderResume {
    pub initial_root:Hash,pub original_store_identities:Hash,
    pub native_custody_identity:Hash,pub native_guard_identity:Hash,
    pub node_descriptor:Vec<u8>,pub continuity_descriptor:Vec<u8>,
    pub journal:super::test_signer_store::JournalPin,
}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestartSpec {
    pub format:String,pub source_git:String,pub source_manifest:PathPin,pub h0:PathPin,
    pub programs:[PathPin;2],pub context:ContextPin,pub service_root:PathBuf,
    pub previous_processes:[Identity;4], // Original service then exact A/C/T client processes.
    pub height:u64,pub block:Hash,pub root:Hash,pub canonical_native:[Hash;6],
    pub transports:[super::cache_snapshot::Object;6],pub caches:[CacheResume;4],pub cache_snapshots:[super::cache_snapshot::Snapshot;4],pub roles:[RoleResume;3],pub confirmed:Vec<WirePin>,
    pub provider:ProviderResume,pub license:Hash,pub backup_license:Hash,
    pub buyer_authority:Hash,pub worker_published:bool,
}
impl RestartSpec {
    pub(super) fn validate(&self)->Result<()> {
        let c=self.context.context();
        if self.format!=MARKER||self.source_git.len()!=40||!self.source_git.bytes().all(|b|b.is_ascii_hexdigit())
            ||!(1..=384).contains(&self.height)||self.confirmed.is_empty()||self.confirmed.len()>64
            ||[c.campaign,c.source,c.h0,c.genesis,c.fingerprint,self.block,self.root,self.license,self.backup_license,self.buyer_authority].contains(&[0;32])
            ||self.license==self.backup_license||!absolute(&self.service_root)
            ||self.h0.path!=self.service_root.join("continuous-h0-public.json")||self.h0.sha256!=c.h0
            ||self.source_manifest.sha256!=c.source||self.canonical_native.contains(&[0;32]){
            return Err("Exact retained original context/head/source/H0/identity checkpoint required".into());
        }
        let mut paths=BTreeSet::new();
        for p in std::iter::once(&self.source_manifest).chain(std::iter::once(&self.h0)).chain(self.programs.iter()).chain(self.confirmed.iter().map(|w|&w.wire)){
            if !absolute(&p.path)||p.sha256==[0;32]||!paths.insert(p.path.clone()){
                return Err("Distinct exact public path/hash commitments required".into());
            }
        }
        if self.canonical_native[3..]!=self.roles.iter().map(|r|r.canonical_native).collect::<Vec<_>>()
            ||self.canonical_native.iter().collect::<BTreeSet<_>>().len()!=6{
            return Err("Six original canonical/native role identities differ or alias".into());
        }
        let mut pids=BTreeSet::new();
        for (i,p) in self.previous_processes.iter().enumerate(){
            let image=&self.programs[if i==3{1}else{0}];
            if p.pid==0||p.start_filetime==0||p.image_sha256!=image.sha256||p.image_path!=image.path
                ||!pids.insert((p.pid,p.start_filetime)){return Err("Original process tuple/program checkpoint differs".into());}
        }
        for (i,transport) in self.transports.iter().enumerate(){
            let previous=&self.previous_processes[if i<3{0}else{i-2}];
            let expected=if i<3{self.service_root.join(format!("role{}-native-transport-{}-{}.sqlite",i+1,previous.pid,previous.start_filetime))}
                else{self.roles[i-3].saved.client_root.join(format!("native-transport-{}-{}.sqlite",previous.pid,previous.start_filetime))};
            if transport.path!=expected||transport.native_id==[0;32]||transport.rows==[0;32]{return Err("Six exact previous-process transport-cache path/native/row pins required".into());}
        }
        let mut role_roots=BTreeSet::new();
        for (role,r) in [1,2,3].into_iter().zip(&self.roles){
            if r.saved.role!=role||!absolute(&r.saved.client_root)||!role_roots.insert(r.saved.client_root.clone())
                ||r.saved.client_root.starts_with(&self.service_root)||self.service_root.starts_with(&r.saved.client_root)
                ||r.saved.revision<1||r.saved.queued.is_empty()||r.saved.queued.len()>4096
                ||r.saved.preimage_conditions.is_empty()||r.saved.preimage_conditions.len()>4096
                ||r.saved.payment_wire_commitments.len()>64||r.saved.reserved_inputs.len()>4096
                ||r.marker_sha256==[0;32]||r.canonical_native==[0;32]||r.side_native.contains(&[0;32]){
                return Err("Exact original nonempty role vault/native/queue pins required".into());
            }
            let mut ids=BTreeSet::new();
            if r.saved.queued.iter().any(|q|q.id==[0;32]||q.kind.is_empty()||q.kind.len()>128||q.status.len()>256||!ids.insert(q.id)){
                return Err("Retained outbox has invalid/duplicate public IDs".into());
            }
            if [Some(&r.saved.active),r.saved.staged.as_ref(),r.saved.superseded.as_ref()].into_iter().flatten()
                .any(|id|id.generation==0||id.owner_descriptor.is_empty()||id.owner_descriptor.len()>32768||id.authority_id.len()!=64||id.address_id.len()!=64){
                return Err("Original bounded vault pointers required".into());
            }
        }
        let roots=role_roots.into_iter().collect::<Vec<_>>();
        if roots.iter().enumerate().any(|(i,p)|roots.iter().skip(i+1).any(|q|p.starts_with(q)||q.starts_with(p))){
            return Err("Original role directories overlap".into());
        }
        let expected_cache=[self.service_root.join("local-node-payment.sqlite"),self.service_root.join("local-node-payment.submissions.sqlite"),
            self.service_root.join("remote-node-payment.sqlite"),self.service_root.join("remote-node-payment.submissions.sqlite")];
        for (i,cache) in self.caches.iter().enumerate(){
            if cache.path!=expected_cache[i]||cache.native_id==[0;32]||cache.submission!=(i%2==1)||cache.pending.len()>4096
                ||cache.pending.iter().any(|p|p.id==[0;32]||p.wire_commitment==[0;32])
                ||cache.pending.windows(2).any(|p|p[0].id>=p[1].id){return Err("Exact ordered retained cache/native/pending commitments required".into());}
        }
        for (cache,snapshot) in self.caches.iter().zip(&self.cache_snapshots){
            if snapshot.main.path!=cache.path||snapshot.main.native_id!=cache.native_id||snapshot.main.rows==[0;32]||snapshot.submission!=cache.submission||snapshot.members.len()>34||snapshot.members.windows(2).any(|m|m[0].path>=m[1].path)||snapshot.members.iter().any(|m|m.native_id==[0;32]||m.rows==[0;32]||m.path.parent()!=Some(cache.path.with_extension("submission-archive").as_path()))||(!snapshot.submission&&(!snapshot.members.is_empty()||snapshot.archive_native.is_some())){
                return Err("Exact whole retained cache/archive/reservation pins required".into());
            }
        }
        let mut ids=BTreeSet::new();
        for w in &self.confirmed{
            if w.list>1||w.id==[0;32]||w.own_commitment==[0;32]||w.height==0||w.height>self.height||!ids.insert(w.id){
                return Err("Unique bounded exact canonical wire/list/height pins required".into());
            }
        }
        let provider=&self.provider;
        if [provider.initial_root,provider.original_store_identities,provider.native_custody_identity,provider.native_guard_identity,provider.journal.commitment].contains(&[0;32])
            ||provider.journal.tip>3840||provider.journal.commits>384||provider.journal.works>384{
            return Err("Bounded exact retained original signer journal/context pins required".into());
        }
        for (descriptor,role) in [(&provider.node_descriptor,mutiny_crypto_v2::Role::Node),(&provider.continuity_descriptor,mutiny_crypto_v2::Role::Continuity)]{
            if descriptor.is_empty()||descriptor.len()>32768{return Err("Original provider descriptor width bound".into());}
            let (p,g)=mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor).map_err(err)?;
            if p.role!=role||g==0{return Err("Original provider role/generation differs".into());}
        }
        Ok(())
    }
    pub(super) fn role_pins(&self,role:Role)->super::existing_role::RolePins{
        let mut p=self.roles[role as usize-1].native_pins();p.head=Head{height:self.height,block:self.block,root:self.root};p
    }
    pub(super) fn six_pins(&self)->super::existing_six::SixPins{
        let paths=[self.service_root.join("certifier.sqlite"),self.service_root.join("local-node-chain.sqlite"),self.service_root.join("remote-node-chain.sqlite"),
            self.roles[0].saved.client_root.join("role-vault/public-chain.sqlite"),self.roles[1].saved.client_root.join("role-vault/public-chain.sqlite"),self.roles[2].saved.client_root.join("role-vault/public-chain.sqlite")];
        super::existing_six::SixPins{paths,native_ids:self.canonical_native,height:self.height,block:self.block,root:self.root,
            confirmed:self.confirmed.iter().map(|w|(w.list,w.id,w.own_commitment,w.height)).collect(),
            retained_queue_ids:self.roles.iter().flat_map(|r|r.saved.queued.iter().map(|q|q.id)).collect::<BTreeSet<_>>().into_iter().collect()}
    }
    pub(super) fn cache_pins(&self)->[super::existing_cache::CachePin;4]{
        std::array::from_fn(|i|{let c=&self.caches[i];super::existing_cache::CachePin{path:c.path.clone(),native_id:c.native_id,submission:c.submission,
            pending:c.pending.iter().map(|p|(p.id,p.wire_commitment)).collect::<BTreeMap<_,_>>()}})
    }
    pub(super) fn binding(&self)->super::test_signer_store::Binding{
        let p=&self.provider;let c=self.context.context();
        super::test_signer_store::Binding{campaign:c.campaign,source:c.source,genesis:c.genesis,fingerprint:c.fingerprint,
            initial_root:p.initial_root,original_store_identities:p.original_store_identities,native_custody_identity:p.native_custody_identity,
            native_guard_identity:p.native_guard_identity,node_descriptor:p.node_descriptor.clone(),continuity_descriptor:p.continuity_descriptor.clone()}
    }
}
pub(super) struct HeldRestart {pub spec:RestartSpec,_files:Vec<(PathBuf,ImagePin)>,_transports:Vec<super::image_pin::DatabasePin>}
/// Keep immutable original public pins alive until the service and its keys drop.
/// Caller retains this owner through the native worker's actual natural join.
pub(super) struct HeldService {pub service:super::native_service::Service,pub restart:HeldRestart}
impl HeldRestart {
    pub(super) fn read(path:&Path,sha:Hash,owner:&VerifiedProcess,context:Context,source_git:&str,manifest:&Path)->Result<Self>{
        if !absolute(path)||sha==[0;32]{return Err("Exact immutable restart path/hash required".into());}
        owner.recheck()?;let pin=ImagePin::open(path,&owner.identity().user_sid)?;
        if pin.hash()!=sha{return Err("Externally committed restart checkpoint differs".into());}
        let spec:RestartSpec=serde_json::from_slice(&pin.read_bounded(2*1024*1024)?).map_err(err)?;spec.validate()?;
        let c=spec.context.context();
        if c!=context||spec.source_git!=source_git||spec.source_manifest.path!=manifest{
            return Err("Original immutable launcher source/context differs".into());
        }
        for previous in &spec.previous_processes{historical_process_closed(previous)?;}
        let mut files=vec![(path.to_path_buf(),pin)];
        for public in std::iter::once(&spec.source_manifest).chain(std::iter::once(&spec.h0)).chain(spec.programs.iter()).chain(spec.confirmed.iter().map(|w|&w.wire)){
            let held=ImagePin::open(&public.path,&owner.identity().user_sid)?;
            if held.hash()!=public.sha256{return Err("Original pinned public source/H0/program/raw wire changed".into());}
            files.push((public.path.clone(),held));
        }
        for w in &spec.confirmed{
            let held=&files.iter().find(|(path,_)|path==&w.wire.path).ok_or("Held original exported raw wire absent")?.1;
            let raw=held.read_bounded(16384)?;
            let (kind,id)=mutiny_consensus_v8::operation_index_v2::operation_id(w.list,&raw).map_err(err)?;
            let commitment=mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,&raw);
            if id!=w.id||kind!=w.kind||commitment!=w.own_commitment||Hash::from(Sha256::digest(&raw))!=w.wire.sha256{
                return Err("Exact exported canonical operation bytes/list/kind/ID/commitment differ".into());
            }
        }
        let mut transports=Vec::new();for old in &spec.transports{transports.push(old.transport_preflight(&owner.identity().user_sid)?);}
        owner.recheck()?;for (_,f) in &files{f.recheck()?;}Ok(Self{spec,_files:files,_transports:transports})
    }
    pub(super) fn recheck(&self)->Result<()>{for (_,f) in &self._files{f.recheck()?;}for t in &self._transports{t.recheck()?;}Ok(())}
    pub(super) fn open_original_service(self,owner:&VerifiedProcess)->Result<HeldService>{
        self.recheck()?;owner.recheck()?;
        let p=&self.spec;let c=p.context.context();
        let service=super::native_service::Service::reopen_existing(&p.service_root,c,&p.source_manifest.path,&p.source_git,
            p.license,p.backup_license,p.six_pins(),p.cache_pins(),p.cache_snapshots.clone(),&owner.identity().user_sid,
            &p.service_root.join("synthetic-signers.sqlite"),&p.service_root.join("synthetic-certifier.guard"),
            p.binding(),p.buyer_authority,p.worker_published,p.provider.journal.clone())?;
        self.recheck()?;owner.recheck()?;Ok(HeldService{service,restart:self})
    }
}

#[cfg(test)]
mod structure_model_tests {
    use super::*;
    // PUBLIC structure model only. No TPM, opened files, genuine replay or custody claim.
    pub(super) fn model()->RestartSpec {
        let active=crate::wallet_v2::Identity{version:2,network:mutiny_crypto_v2::NETWORK,
            suite:mutiny_crypto_v2::WALLET_CRYPTO_SUITE_ID,generation:1,authority_id:hex::encode([1;32]),
            address_id:hex::encode([2;32]),owner_ed448:String::new(),owner_fndsa1024:String::new(),owner_descriptor:"00".into()};
        let role=|role:u8|RoleResume{saved:VaultPin{role,client_root:PathBuf::from(format!(r"C:\PUBLIC-MODEL\role{role}")),
            revision:1,active:active.clone(),staged:None,superseded:None,
            queued:vec![super::super::continuous_passive::QueuedPin{id:[role;32],kind:"Retained model".into(),complete:false,status:"Pending".into()}],
            preimage_conditions:vec![[4;32]],payment_wire_commitments:vec![],reserved_inputs:vec![]},
            marker_sha256:[role+20;32],canonical_native:[role+3;32],side_native:[[role+30;32];4]};
        let service_root=PathBuf::from(r"C:\PUBLIC-MODEL\service");
        let programs=[PathPin{path:PathBuf::from(r"C:\PUBLIC-MODEL\wallet.exe"),sha256:[6;32]},
            PathPin{path:PathBuf::from(r"C:\PUBLIC-MODEL\treasury.exe"),sha256:[7;32]}];
        let previous_processes=std::array::from_fn(|i|{let image=&programs[if i==3{1}else{0}];Identity{
            pid:100+i as u32,start_filetime:1000+i as u64,session:1,authentication_luid:(1,0),user_sid:vec![1;12],
            image_path:image.path.clone(),image_sha256:image.sha256}});
        let cache=|i:usize|CacheResume{path:service_root.join(match i{0=>"local-node-payment.sqlite",1=>"local-node-payment.submissions.sqlite",2=>"remote-node-payment.sqlite",_=>"remote-node-payment.submissions.sqlite"}),
            native_id:[40+i as u8;32],submission:i%2==1,pending:vec![CacheEntry{id:[5;32],wire_commitment:[55;32]}]};
        let node=mutiny_crypto_v2::HybridKey::generate(mutiny_crypto_v2::Role::Node).unwrap();
        let continuity=mutiny_crypto_v2::HybridKey::generate(mutiny_crypto_v2::Role::Continuity).unwrap();
        RestartSpec{format:MARKER.into(),source_git:"d1997eef228ce92b97d633afcfb6aac180b6b1d2".into(),
            source_manifest:PathPin{path:PathBuf::from(r"C:\PUBLIC-MODEL\SOURCE.json"),sha256:[9;32]},
            h0:PathPin{path:service_root.join("continuous-h0-public.json"),sha256:[10;32]},programs,
            context:ContextPin{campaign:[8;32],source:[9;32],h0:[10;32],genesis:[11;32],fingerprint:[12;32]},
            transports:std::array::from_fn(|i|{let p=&previous_processes[if i<3{0}else{i-2}];super::super::cache_snapshot::Object{path:if i<3{service_root.join(format!("role{}-native-transport-{}-{}.sqlite",i+1,p.pid,p.start_filetime))}else{role(i as u8-2).saved.client_root.join(format!("native-transport-{}-{}.sqlite",p.pid,p.start_filetime))},native_id:[100+i as u8;32],rows:[110+i as u8;32]}}),previous_processes,height:2,block:[13;32],root:[14;32],canonical_native:[[1;32],[2;32],[3;32],[4;32],[5;32],[6;32]],
            cache_snapshots:std::array::from_fn(|i|{let c=cache(i);super::super::cache_snapshot::Snapshot{main:super::super::cache_snapshot::Object{path:c.path,native_id:c.native_id,rows:[81;32]},submission:c.submission,archive_native:None,members:vec![]}}),caches:std::array::from_fn(cache),roles:[role(1),role(2),role(3)],
            confirmed:vec![WirePin{list:0,kind:1,id:[15;32],wire:PathPin{path:PathBuf::from(r"C:\PUBLIC-MODEL\wire.bin"),sha256:[16;32]},own_commitment:[17;32],height:1}],
            provider:ProviderResume{initial_root:[60;32],original_store_identities:[61;32],native_custody_identity:[62;32],native_guard_identity:[63;32],
                node_descriptor:node.public().descriptor(1).unwrap(),continuity_descriptor:continuity.public().descriptor(1).unwrap(),
                journal:super::super::test_signer_store::JournalPin{tip:20,commits:2,works:2,commitment:[64;32]}},
            license:[70;32],backup_license:[71;32],buyer_authority:[72;32],worker_published:false,service_root}
    }
    #[test]
    fn checkpoint_structure_model_positive_and_exact_native_cache_pointer_negatives(){
        let good=model();good.validate().unwrap();
        for fault in 0..12{let mut p=good.clone();match fault{
            0=>p.context.h0=[0;32],1=>p.h0.sha256=[99;32],2=>p.source_manifest.sha256=[99;32],
            3=>p.height=0,4=>p.canonical_native[3]=[99;32],5=>p.canonical_native[1]=p.canonical_native[0],
            6=>p.roles[0].saved.queued.clear(),7=>p.roles[0].saved.preimage_conditions.clear(),
            8=>p.roles[1].saved.client_root=p.roles[0].saved.client_root.clone(),9=>p.caches[0].path=PathBuf::from(r"C:\OTHER\pool.sqlite"),
            10=>p.caches[1].submission=false,_=>p.roles[0].side_native[1]=[0;32]
        }assert!(p.validate().is_err(),"structure fault{fault}");}
    }
    #[test]
    fn checkpoint_structure_model_retains_nonempty_wire_journal_and_old_process_bindings(){
        let good=model();good.validate().unwrap();
        for fault in 0..12{let mut p=good.clone();match fault{
            0=>p.previous_processes[0].start_filetime=0,1=>p.previous_processes[0].image_sha256=[99;32],
            2=>p.previous_processes[1]=p.previous_processes[0].clone(),3=>p.provider.native_guard_identity=[0;32],
            4=>p.provider.native_custody_identity=[0;32],5=>p.provider.journal.commitment=[0;32],
            6=>p.provider.node_descriptor=p.provider.continuity_descriptor.clone(),7=>p.confirmed.clear(),
            8=>p.confirmed.push(p.confirmed[0].clone()),9=>p.confirmed[0].height=3,
            10=>p.caches[0].pending.push(p.caches[0].pending[0].clone()),_=>p.roles[0].saved.active.generation=0
        }assert!(p.validate().is_err(),"structure fault{fault}");}
    }
    #[test]
    fn native_missing_restart_checkpoint_refuses_without_creating_files_or_replacing_process_identity(){
        let actual=VerifiedProcess::observe_created_process(std::process::id()).unwrap();
        let owner=VerifiedProcess::open(&actual).unwrap();
        assert!(historical_process_closed(&actual).is_err(),"A live original tuple cannot be labelled closed");
        let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root=std::env::temp_dir().join(format!("w15-restart-missing-{}-{nonce}",std::process::id()));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
        let path=root.join("missing-public-checkpoint.json");
        let c=Context{campaign:[1;32],source:[2;32],h0:[3;32],genesis:[4;32],fingerprint:[5;32]};
        assert!(HeldRestart::read(&path,[6;32],&owner,c,"d1997eef228ce92b97d633afcfb6aac180b6b1d2",&root.join("SOURCE.json")).is_err());
        assert!(matches!(std::fs::symlink_metadata(&path),Err(e) if e.kind()==std::io::ErrorKind::NotFound));
        assert_eq!(std::fs::read_dir(&root).unwrap().count(),0);
        assert_eq!(owner.identity(),&actual);owner.recheck().unwrap();
        // Preserve the NEW empty native TEST fixture directory. No deletion/ACL repair.
    }
}

#[cfg(test)] pub(super) fn model_for_shutdown_assembly()->RestartSpec{structure_model_tests::model()}
