//! SOURCE ONLY UNCOMPILED. Replace RAM fixture certify_at in future campaigns.
//! Existing original provider and own replayed canonical state are mandatory.
use super::test_signer_store::Store;
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,assembler_v2::Prepared,
 canonical_store_v2::CanonicalStore,execution::State,pow::{WorkAuthority,WorkHeader},
 work_authority_v2::Authority,certificates::Decision,continuity_v2::{Vote,Certificate},block_envelope_v2::BlockEnvelope};
use mutiny_crypto_v2::HybridSignature;
type Result<T>=std::result::Result<T,String>;
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
fn empty()->HybridSignature{HybridSignature{ed448:[0;114],fndsa:[0;1280]}}
pub(super) fn certify_existing(prepared:Prepared,provider:&mut Store,chain:&CanonicalStore,parent:&FinalizedAnchor,state:&State)->Result<BlockEnvelope>{
 let candidate=&prepared.candidate;
 let (ctx,node_raw)=chain.current_work_context(parent,candidate.license,candidate.worker,candidate.timestamp).map_err(err)?;
 if node_raw!=provider.node_descriptor(){return Err("Actual current coordinator does not match retained original provider".into());}
 let (own,actual)=chain.load().map_err(err)?;
 if own.height!=parent.height||own.block!=parent.block||actual.root().map_err(err)?!=state.root().map_err(err)?{return Err("Actual own parent changed before retained provider use".into());}
 let ticket=provider.ticket_for_parent(parent.height)?;
 let mut authority=Authority{work:WorkAuthority{candidate:candidate.clone(),assignment_sequence:ctx.assignment_sequence,ticket_sequence:ticket,coordinator:ctx.coordinator,nonce_start:0,nonce_end:100,epoch:mutiny_consensus_v8::pow::mining_epoch(candidate.timestamp,ctx.t0).map_err(err)?},node_descriptor:node_raw,signature:empty()};
 let header=WorkHeader{candidate:prepared.candidate.clone(),authority:authority.id().map_err(err)?,nonce:1};
 // Same bounded public fixture work parameters, not a general mining engine.
 // Canonical commit still verifies real work/certificate/execution independently.
 authority=provider.sign_work(authority,&header,&ctx)?;
 let fresh=chain.current_work_context(parent,header.candidate.license,header.candidate.worker,header.candidate.timestamp).map_err(err)?;
 authority.verify(&header,&fresh.0,&fresh.1).map_err(err)?;
 let heights=mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(state,parent.clone(),state.root().map_err(err)?).map_err(err)?;
 let node=mutiny_consensus_v8::node_admission_v2::node_id(parent.genesis,provider.node_descriptor()).map_err(err)?;
 let voter=heights.voters.get(&node).ok_or("Retained original node is not an actual parent voter")?;
 let roots=[heights.membership,heights.reputation,heights.attestation];
 let d=Decision{network:parent.network,genesis:parent.genesis,fingerprint:parent.fingerprint,purpose:2,height:header.candidate.height,mining_epoch:authority.work.epoch,continuity_period:(header.candidate.height.checked_sub(1).ok_or("Height zero")?)/60,round:0,step:3,previous_finalized_anchor:parent.id(),parent:parent.block,block:header.block_hash(),state:prepared.execution.root,membership:roots[0],reputation:roots[1],attestation:roots[2]};
 let vote=Vote{decision:d.clone(),nil:false,node,hardware_generation:voter.hardware_generation,key_generation:voter.key_generation,sequence:header.candidate.height.checked_mul(10).ok_or("Sequence overflow")?,tpm_identity:voter.tpm_identity(),profile:voter.profile,signature:empty()};
 let vote=provider.sign_fixed_commit(vote,parent,roots,voter)?;
 let (latest,_)=chain.load().map_err(err)?;
 if latest.height!=parent.height||latest.block!=parent.block||latest.root!=own.root{return Err("Actual own parent changed after durable signing; reservations retained".into());}
 Ok(BlockEnvelope{header,body:prepared.body,authority,certificate:Certificate{decision:d,votes:vec![vote]}})
}