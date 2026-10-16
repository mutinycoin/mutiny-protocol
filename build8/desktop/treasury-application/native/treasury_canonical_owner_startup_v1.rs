//! Private native startup/recovery path. The CanonicalStore reference supplies
//! fully replayed current and retained generations; no raw State, proof, or
//! caller generation flag can substitute. The normal Provider factory is off.
use super::*;
use crate::{canonical_store_v2::CanonicalStore,treasury_lineage_v3::CanonicalTreasury,
    treasury_admission_v3::{StoreIdentity,LocalStoragePolicy},
    treasury_rehearsal_v3::TrustedChain};
use std::path::Path;

fn lineage_config(base:&CeremonyConfig,cap:&CanonicalTreasury)->Result<CeremonyConfig,Error>{
    let anchor=cap.anchor();let pinned=base.trusted_chain().ok_or(Error::Context)?;
    if base.phase()!=proof::Phase::Rehearsal || base.class()!=crate::treasury_v1::Class::TestValue
        || base.network()!=anchor.network || base.treasury()!=cap.treasury()
        || pinned.network!=anchor.network || pinned.genesis!=anchor.genesis
        || pinned.fingerprint!=anchor.fingerprint{return Err(Error::Context);}
    Ok(base.clone().with_trusted_chain(TrustedChain{network:anchor.network,genesis:anchor.genesis,
        fingerprint:anchor.fingerprint,height:anchor.height})?.with_canonical_root(cap.root())?)
}
fn current_same(chain:&CanonicalStore,expected:&CanonicalTreasury)->Result<(),Refusal>{
    let current=chain.treasury_lineage().map_err(|_|Refusal::SuccessionUnproven)?;
    if current.anchor()!=expected.anchor() || current.root()!=expected.root()
        || current.treasury()!=expected.treasury()
        || current.current_generation()!=expected.current_generation()
        || current.descriptor(current.current_generation())!=expected.descriptor(expected.current_generation()){
        return Err(Refusal::SuccessionUnproven);
    }
    Ok(())
}
fn expectations(base:&CeremonyConfig,cap:&CanonicalTreasury)
    ->Result<(CeremonyConfig,Expect,BTreeMap<u64,Expect>),Error>{
    let config=lineage_config(base,cap)?;
    let current=Expect::from_canonical_lineage(&config,cap,cap.current_generation())?;
    let mut history=BTreeMap::new();
    for generation in cap.generations(){history.insert(generation,Expect::from_canonical_lineage(&config,cap,generation)?);}
    Ok((config,current,history))
}
pub(crate) struct CanonicalOwner<'a,P:Provider>{
    inner:Owner<P>,chain:&'a CanonicalStore,base:CeremonyConfig,startup_refusal:Option<Error>,
}
impl<'a,P:Provider> CanonicalOwner<'a,P>{
    /// Native existing-only open using an independently trusted StoreIdentity.
    /// Startup is frozen until a fresh authenticated latest service snapshot,
    /// full historical BOTH audit and exact local records all agree.
    pub(crate) fn open_native(dir:&Path,id:StoreIdentity,policy:LocalStoragePolicy,
        chain:&'a CanonicalStore,base:CeremonyConfig,provider:P,scope:Scope,denylist:Denylist)->Result<Self,Error>{
        let cap=chain.treasury_lineage().map_err(|_|Error::History)?;
        let(config,current,historical)=expectations(&base,&cap)?;
        binding_matches(&config,&scope)?;
        if provider.scope()!=&scope || id.store_id()!=scope.store{return Err(Error::Context);}
        let store=AdmissionStore::open_native(dir,&config,id,policy)?;
        let mut inner=Owner{store,provider,scope,config,current,historical,denylist,history:Vec::new(),sequence:0,frozen:true};
        let startup_refusal=match inner.refresh(false){
            Ok(_)=>match current_same(chain,&cap){Ok(())=>{inner.frozen=false;None},Err(e)=>Some(Error::Native(e))},
            Err(e)=>Some(e),
        };
        Ok(Self{inner,chain,base,startup_refusal})
    }
    pub(crate) fn frozen(&self)->bool{self.inner.frozen()}
    pub(crate) fn sequence(&self)->u64{self.inner.sequence()}
    pub(crate) fn startup_refusal(&self)->Option<Error>{self.startup_refusal}
    fn install_lineage(&mut self)->Result<CanonicalTreasury,Error>{
        self.inner.frozen=true;
        let cap=self.chain.treasury_lineage().map_err(|_|Error::History)?;
        let(config,current,historical)=expectations(&self.base,&cap)?;
        binding_matches(&config,&self.inner.scope)?;
        self.inner.store.check_binding(&config)?;
        // New lineage must retain every old generation with exact descriptor.
        // Height/root change changes the audit context, never historical keys.
        if self.inner.historical.iter().any(|(g,old)|historical.get(g)
            .is_none_or(|new|new.descriptor_sha256()!=old.descriptor_sha256())){return Err(Error::History);}
        self.inner.config=config;self.inner.current=current;self.inner.historical=historical;
        Ok(cap)
    }
    pub(crate) fn issue(&mut self,descriptor:&[u8])->Result<Challenge,Error>{
        if self.inner.frozen{return Err(Error::Frozen);}
        let cap=self.install_lineage()?;
        self.inner.refresh(false)?;current_same(self.chain,&cap)?;self.inner.frozen=false;
        let chain=self.chain;
        let result=self.inner.issue_guarded(descriptor,||current_same(chain,&cap));
        // Two stores have no shared transaction. Refuse publication if the
        // canonical parent advanced during reserve/local commit/confirmation;
        // completed external history is retained and explicit repair stays possible.
        if let Err(e)=current_same(chain,&cap){self.inner.frozen=true;return Err(e.into());}
        result
    }
    pub(crate) fn admit(&mut self,descriptor:&[u8],challenge:&[u8],signature:&HybridSignature)->Result<VerifiedProof,Error>{
        if self.inner.frozen{return Err(Error::Frozen);}
        let cap=self.install_lineage()?;
        self.inner.refresh(false)?;current_same(self.chain,&cap)?;self.inner.frozen=false;
        let chain=self.chain;
        let result=self.inner.admit_guarded(descriptor,challenge,signature,||current_same(chain,&cap));
        if let Err(e)=current_same(chain,&cap){self.inner.frozen=true;return Err(e.into());}
        result
    }
    /// Explicit recovery: exact authenticated service history is cryptographically
    /// audited under all retained canonical descriptors BEFORE local repair.
    pub(crate) fn reconcile(&mut self)->Result<(),Error>{
        let cap=self.install_lineage()?;self.inner.refresh(true)?;
        current_same(self.chain,&cap)?;
        self.inner.reconcile()?;
        // If the canonical chain advanced during repair, keep both workflows
        // frozen. External completed operations remain retained, never undone.
        if let Err(e)=current_same(self.chain,&cap){self.inner.frozen=true;return Err(e.into());}
        self.startup_refusal=None;Ok(())
    }
    pub(crate) fn close(self)->Result<(),(Self,Error)>{
        let Self{inner,chain,base,startup_refusal}=self;
        let Owner{store,provider,scope,config,current,historical,denylist,history,sequence,frozen}=inner;
        store.close().map_err(|(store,error)|{
            let inner=Owner{store,provider,scope,config,current,historical,denylist,history,sequence,frozen};
            (Self{inner,chain,base,startup_refusal},error.into())
        })
    }
    /// Final application close: an uncertain native storage owner stays held,
    /// without Drop retry; authenticated transport custody is still erased.
    pub(crate) fn close_final(self)->Result<(),Error>{
        match self.close(){
            Ok(())=>Ok(()),
            Err((retained,error))=>{
                let Self{inner,..}=retained;
                let Owner{store,provider,..}=inner;
                drop(provider);std::mem::forget(store);Err(error)
            }
        }
    }
}
/// Repeatable authenticated historical audit. Native local database stays RO;
/// no reconciliation, reservation, consumption, or ConfirmLocal is attempted.
pub(crate) fn audit_native<P:Provider>(dir:&Path,id:StoreIdentity,policy:LocalStoragePolicy,
    chain:&CanonicalStore,base:&CeremonyConfig,provider:&mut P,scope:&Scope,denylist:&Denylist)
    ->Result<Vec<VerifiedProof>,Error>{
    let cap=chain.treasury_lineage().map_err(|_|Error::History)?;
    let(config,_,history)=expectations(base,&cap)?;binding_matches(&config,scope)?;
    if id.store_id()!=scope.store || provider.scope()!=scope{return Err(Error::Context);}
    let store=AdmissionStore::open_native_read_only(dir,&config,id,policy)?;
    let result=(||{
        let nonce=random_id()?;
        let snapshot=store.guarded_external(Error::from,||provider.current(nonce).map_err(Error::from))?;
        if snapshot.scope()!=scope || snapshot.request_nonce()!=nonce{return Err(Error::Context);}
        PublicSnapshot::new(scope.clone(),nonce,snapshot.sequence(),snapshot.pending_operation(),snapshot.operations().to_vec())?;
        if snapshot.pending_operation().is_some(){return Err(Error::ReconciliationRequired);}
        let exact=final_records(snapshot.operations())?;
        if store.continuity_records()?!=exact{return Err(Error::ReconciliationRequired);}
        let mut proofs=Vec::new();
        for record in exact{
            let expected=history.get(&record.generation).ok_or(Error::History)?;
            let challenge=Challenge::decode(&record.challenge).map_err(Refusal::from)?;
            if challenge.nonce!=record.nonce || challenge.generation!=record.generation{return Err(Error::History);}
            match record.signature {
                Some(raw)=>{let sig=proof::signature_from_bytes(&raw).map_err(Refusal::from)?;
                    proofs.push(native::audit_recorded(&store,expected,&record.descriptor,&record.challenge,&sig,denylist)?);},
                None=>{native::check_issuance_descriptor(expected,&record.descriptor)?;
                    if native::build_challenge(expected.config(),&record.descriptor,record.nonce)?.encode().map_err(Refusal::from)?!=record.challenge{return Err(Error::History);}}
            }
        }
        current_same(chain,&cap)?;Ok(proofs)
    })();
    // Explicit native close failure is evidence, even if all proof checks passed.
    if let Err((_retained,error))=store.close(){return Err(error.into());}
    result
}

#[cfg(test)] #[path="../controls/native_canonical_owner_controls.rs"] mod tests;
