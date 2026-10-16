//! EXTERNAL SOURCE ONLY. NEW campaign role vault, never original custody copying.
//! Fixed public gen2 vectors are distinct; production identity/rotation rules unchanged.
use super::{control_codec::Role,public_roles::PublicRole,control_codec::Context};
use crate::{wallet_controller_v2::{Controller,VaultRoot},wallet_v2::{Session,RestoredKey},store_v2::Store,verified_sync_v2::Replica};
use mutiny_consensus_v8::{anchors::FinalizedAnchor,execution::State,canonical_store_v2::CanonicalStore,mempool_v2::Mempool,treasury_v1::Class};
use mutiny_wallet_core_v8::{ChainClass,profile::TreasuryDeclaration};
use std::io::Write;
pub const ROLE_VAULT_MARKER:&str="MUTINY-W15-NONSHIPPING-NEW-ROLE-VAULT-V1";
pub fn public(role:Role)->PublicRole{match role{Role::WalletA=>PublicRole::Ordinary,Role::WalletC=>PublicRole::Buyer,Role::Treasury=>PublicRole::Treasury}}
pub fn open(root:&VaultRoot,role:Role,context:Context,genesis:&FinalizedAnchor,initial:&State)->Result<Controller,String>{
    if genesis.genesis!=context.genesis||genesis.fingerprint!=context.fingerprint||initial.dividends.treasury().map(|t|t.class())!=Some(Class::TestValue){return Err("Only exact new campaign public TEST-VALUE initial context".into());}
    // Verify all six addresses and three current2 descriptors before creating a
    // new role vault. No common gen2 descriptor collision is hidden by state edits.
    let mut addresses=std::collections::BTreeSet::new();
    for r in [Role::WalletA,Role::WalletC,Role::Treasury]{
        let p=public(r);let first=Session::restore_initial(&p.initial_phrase()).map_err(str::to_owned)?;
        if !addresses.insert(first.identity().address_id.clone()){return Err("Public initial role collision".into());}
        let authority=hex::decode(&first.identity().authority_id).map_err(|_|"Public authority hex")?.try_into().map_err(|_|"Public authority width")?;
        let next=RestoredKey::restore(p.rotation_phrase(),2,None).map_err(str::to_owned)?;let descriptor=next.descriptor().to_vec();
        RestoredKey::restore(p.rotation_phrase(),2,Some(&descriptor)).map_err(str::to_owned)?;
        let rotated=Session::restore_rotated(next,authority,&descriptor).map_err(str::to_owned)?;
        if rotated.identity().authority_id!=first.identity().authority_id||!addresses.insert(rotated.identity().address_id.clone()){return Err("Public current2 role collision/lineage mismatch".into());}
    }
    let marker=root.path().join("NEW-CONTINUOUS-TEST-ROLE.marker");
    let expected=serde_json::to_vec(&serde_json::json!({"format":ROLE_VAULT_MARKER,"role":role as u8,"campaign":hex::encode(context.campaign),"source":hex::encode(context.source),"h0":hex::encode(context.h0),"genesis":hex::encode(context.genesis),"fingerprint":hex::encode(context.fingerprint),"original_launch16":false,"production_authorized":false})).map_err(|e|e.to_string())?;
    if root.path().exists(){
        // Existing original paths lack this exact new campaign marker and refuse.
        // The bounded reader holds actual native marker/ancestor identities.
        if super::control_files::read_bounded(&marker,2048)?!=expected{return Err("Existing root belongs to another campaign/role; preserved".into());}
    }else{
        if !mutiny_consensus_v8::submission_pool_v1::private_directory(root.path()).map_err(|e|format!("{e:?}"))?{return Err("New role root not owned by this invocation".into());}
        let mut file=std::fs::OpenOptions::new().create_new(true).write(true).open(&marker).map_err(|e|e.to_string())?;
        file.write_all(&expected).map_err(|e|e.to_string())?;file.sync_all().map_err(|e|e.to_string())?;
    }
    let root_hash=initial.root().map_err(|e|format!("{e:?}"))?;
    let chain=CanonicalStore::open_trusted_genesis(&root.path().join("public-chain.sqlite"),genesis,initial,root_hash,1000,[255;32]).map_err(|e|format!("{e:?}"))?;
    let replica=Replica::from_pinned_chain(chain)?;let (_,verified)=replica.verified()?;
    if verified.dividends.treasury().map(|t|t.class())!=Some(Class::TestValue){return Err("Verified own chain is not TEST-VALUE".into());}
    let p=public(role);let first=Session::restore_initial(&p.initial_phrase()).map_err(str::to_owned)?;
    let authority=hex::decode(&first.identity().authority_id).map_err(|_|"Public role authority hex")?.try_into().map_err(|_|"Public authority width")?;
    let next=RestoredKey::restore(p.rotation_phrase(),2,None).map_err(str::to_owned)?;let descriptor=next.descriptor().to_vec();
    let rotated=Session::restore_rotated(next,authority,&descriptor).map_err(str::to_owned)?;
    let mut store=Store::open(&root.vault()).map_err(|e|e.to_string())?;
    if let Some(status)=store.status().map_err(str::to_owned)?{
        let known=|id:&crate::wallet_v2::Identity|id==first.identity()||id==rotated.identity();
        if !known(&status.active)||status.staged.as_ref().is_some_and(|id|!known(id))||status.superseded.as_ref().is_some_and(|id|!known(id))||(status.active.generation==2&&verified.wallets.current(authority).unwrap_or(&[])!=descriptor){return Err("Existing new-role vault does not match exact own public lineage; preserved".into());}
    }else{store.save_initial(&first,super::chain::PASSWORD).map_err(str::to_owned)?;}
    drop(store);
    let pool=Mempool::open(&root.path().join("public-payment-pool.sqlite"),genesis.genesis,genesis.fingerprint,65536).map_err(|e|format!("{e:?}"))?;
    let declaration=declaration(role,context,&verified)?;
    let mut controller=Controller::open(root,replica,pool,declaration)?;controller.unlock(super::chain::PASSWORD)?;Ok(controller)
}

/// Both explicit existing requested Treasury roles for this exact canonical T.
/// This is host configuration only; Controller unlock repeats profile::declare
/// against its actual own replay/current descriptor/destination before signing.
pub fn declaration(role:Role,context:Context,verified:&State)->Result<Option<TreasuryDeclaration>,String>{
    if role!=Role::Treasury{return Ok(None);}
    let t=verified.dividends.treasury().ok_or("Canonical Genesis Treasury missing")?;
    if t.class()!=Class::TestValue{return Err("Only exact PUBLIC TEST Treasury declaration".into());}
    let treasury=t.authority();
    let native=mutiny_consensus_v8::trading_v1::Context{network:mutiny_consensus_v8::NETWORK_ID,genesis:context.genesis,fingerprint:context.fingerprint};
    mutiny_consensus_v8::trading_v1::treasury_current(verified,&native,treasury).map_err(|e|format!("{e:?}"))?;
    Ok(Some(TreasuryDeclaration::new(context.genesis,ChainClass::TestValue).with_authority().with_destination_of(treasury)))
}
