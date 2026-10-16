//! Private A-only QUALIFY_STARTUP registration. Protected Root evidence is the
//! authority; receipt strings, candidate metadata and class names are not.
//! This does not perform verification/extraction/install or confer providers.
use crate::{Result,need,sha,hash,policy::{Pin,strict,hexn},own_native_files::{PublicClass,PublicObjectSpec}};
use serde::{Serialize,Deserialize};
use serde_json::Value;
use std::path::PathBuf;
pub(crate) const PATH:&str=r"C:\Windows\System32\VCRUNTIME140.dll";
pub(crate) const CLASS:&str="InstalledSystem32Vcruntime";
pub(crate) const POLICY:&str="A_ONLY_QUALIFY_STARTUP_SYSTEM_VCRUNTIME140_MICROSOFT_AMD64_V1";
pub(crate) const PERMISSIONS:&str="SYSTEM_ADMIN_FULL_USERS_APPS_READ_INHERITED5_V1";
const SYSTEM:&str="010100000000000512000000";
#[derive(Clone,Debug,Serialize,Deserialize)]#[serde(deny_unknown_fields)]
struct NativeTuple{path:String,bytes:u64,sha256:String,volume:u64,file_id:String,links:u32,owner_sid_hex:String,dacl_sha256:String}
impl NativeTuple{
 fn valid(&self)->Result<()>{strict(&self.path)?;need((64..=134217728).contains(&self.bytes)&&self.volume!=0&&(1..=64).contains(&self.links),"CRT evidence native tuple bounds")?;
  hexn::<32>(&self.sha256)?;hexn::<16>(&self.file_id)?;hexn::<32>(&self.dacl_sha256)?;
  need((16..=136).contains(&self.owner_sid_hex.len())&&self.owner_sid_hex.len()%2==0,"CRT evidence SID bound")?;
  let sid=hex::decode(&self.owner_sid_hex).map_err(|_|"CRT evidence SID hex")?;
  need(sid[0]==1&&sid[1]<=15&&sid.len()==8+4*sid[1] as usize,"CRT evidence SID extent")?;Ok(())
 }
 fn same(&self,other:&Self)->Result<()>{need(serde_json::to_value(self).map_err(|e|e.to_string())?==serde_json::to_value(other).map_err(|e|e.to_string())?,"CRT exact evidence native tuple binding")}
}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Package{original_url:String,resolved_url:String,native:NativeTuple,version:[u32;4],architecture:String}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Payload{native:NativeTuple,version:[u32;4],architecture:String,machine:u16,pe_magic:u16,package_sha256:String,msi_sha256:String,cab_sha256:String,member_identifier:String}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Stream{name:String,bytes:u64,retained:u64,sha256:String,eof:bool,hash_complete:bool,overflow:bool,null_drain:bool,error:Value,output_error:Value}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Execution{exit:u32,natural:bool,primary:Value,closure_errors:Vec<Value>,streams:Vec<Stream>}
impl Execution{fn checked(&self)->Result<()>{
 need(self.exit==0&&self.natural&&self.primary.is_null()&&self.closure_errors.is_empty()&&self.streams.len()==2,"CRT verifier original execution/closure")?;
 for(s,name)in self.streams.iter().zip(["stdout","stderr"]){hexn::<32>(&s.sha256)?;
  need(s.name==name&&s.bytes==s.retained&&s.bytes<=16777216&&s.eof&&s.hash_complete&&!s.overflow&&!s.null_drain&&s.error.is_null()&&s.output_error.is_null(),"CRT verifier complete original streams")?;
 }Ok(())
}}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Certificate{der_hex:String,der_sha256:String,subject_common_name:String,subject_organization:String}
fn chain(rows:&[Certificate])->Result<()>{
 need((2..=16).contains(&rows.len()),"CRT full certificate chain required")?;
 let mut seen=std::collections::BTreeSet::new();
 for row in rows{
  need((64..=65536).contains(&row.der_hex.len())&&row.der_hex.len()%2==0&&row.der_hex.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"CRT actual DER bounded lowercase bytes")?;
  let der=hex::decode(&row.der_hex).map_err(|_|"CRT certificate DER")?;hexn::<32>(&row.der_sha256)?;
  need(sha(&der)==row.der_sha256&&seen.insert(row.der_sha256.as_str()),"CRT exact unique certificate DER")?;
  need(!row.subject_common_name.is_empty()&&row.subject_common_name.len()<=1024&&row.subject_organization.len()<=1024,"CRT certificate subject bound")?;
 }
 need(rows[0].subject_organization=="Microsoft Corporation"&&rows.last().unwrap().subject_organization=="Microsoft Corporation","CRT Microsoft signer and trust-chain root identity")?;
 Ok(())
}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Signature{signature_index:u32,windows_trust_status:u32,state_close_status:u32,microsoft_publisher_authenticated:bool,signer_chain:Vec<Certificate>,timestamp_status:String,timestamp_chain:Vec<Certificate>}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct SignatureReceipt{schema:String,subject:NativeTuple,verifier:NativeTuple,policy:String,execution:Execution,verification_time_utc:String,secondary_signature_count:u32,wintrust_source_sha256:String,wintrust_runtime:NativeTuple,wintrust_execution:Execution,signatures:Vec<Signature>}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Container{native:NativeTuple,parent_sha256:String,architecture:String}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Mapping{file_identifier:String,file_name:String,file_version:[u32;4],sequence:u32,media_last_sequence:u32,cabinet:String,member_identifier:String,duplicate_matches:u32,external_continuation:bool,traversal:bool,complete_member:bool}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Extraction{schema:String,package:NativeTuple,extractor:NativeTuple,passive:bool,installer_executed:bool,primary:Value,closure_errors:Vec<Value>,msi:Container,cab:Container,file_mapping:Mapping,payload:NativeTuple}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Registration{
 scope:String,policy_version:String,operation:String,compiled_source_sha256:String,
 producer:Pin,harness:NativeTuple,compiler_toolset_version:[u32;4],compiler_build_receipt_sha256:String,
 abi_proof_sha256:String,abi_results_sha256:String,installed:Pin,installed_version:[u32;4],permissions_policy:String,
 package:Package,payload:Payload,signature_receipt_utf8:String,signature_receipt_sha256:String,
 extraction_receipt_utf8:String,extraction_receipt_sha256:String,current_installation_state:String,
 historical_installation_event:String,providers_allowed:bool,production_enabled:bool,
}
/// Internal validated, non-serde capability. Only the protected-registration
/// parser can create one. The exact Root evidence original remains held by
/// Policy throughout factory/module/file use and is rechecked at every entry.
#[derive(Clone,Debug)]
pub(crate) struct Authority{installed:PublicObjectSpec,source:[u8;32],producer:[u8;32],registration:[u8;32]}
impl Authority{
 pub(crate) fn require_spec(&self,s:&PublicObjectSpec)->Result<()>{
  let p=&self.installed;
  need(s.class==PublicClass::InstalledSystem32Vcruntime&&s.path==PathBuf::from(PATH)&&s.path==p.path
   &&s.bytes==p.bytes&&s.sha256==p.sha256&&s.volume==p.volume&&s.file_id==p.file_id&&s.links==p.links
   &&s.owner_sid==p.owner_sid&&s.dacl_sha256==p.dacl_sha256,"CRT registered exact original declaration")
 }
 pub(crate) fn require_context(&self,source:&[u8;32],producer:&[u8;32])->Result<()>{
  need(&self.source==source&&&self.producer==producer&&self.registration!=[0;32],"CRT registered immutable source/build context")
 }
}
fn official(url:&str)->bool{
 if url.is_empty()||url.len()>4096||!url.is_ascii()||url.bytes().any(|b|b<=32)||url.contains('\\')||url.contains('@'){return false}
 ["https://aka.ms/","https://download.microsoft.com/","https://downloads.microsoft.com/","https://download.visualstudio.microsoft.com/"].iter().any(|p|url.starts_with(p))
}
fn receipt<T:serde::de::DeserializeOwned>(text:&str,digest:&str)->Result<T>{
 need((64..=8388608).contains(&text.len()),"CRT complete protected receipt bound")?;hexn::<32>(digest)?;
 need(sha(text.as_bytes())==digest,"CRT entire protected receipt digest")?;
 serde_json::from_str(text).map_err(|e|e.to_string())
}
/// Caller supplies bytes from the existing exact OWN protected JSON originals,
/// never peer data or diagnostic text. No tool/publisher status is manufactured.
pub(crate) fn authenticate(raw:&[u8],source:&[u8;32],producer:&Pin,artifact:&Value,abi_proof:&[u8],abi_results:&[u8])->Result<Authority>{
 need((64..=16777216).contains(&raw.len()),"CRT protected registration extent")?;
 let r:Registration=serde_json::from_slice(raw).map_err(|e|format!("CRT strict registration missing/schema: {e}"))?;
 need(r.scope=="ROOT_REGISTERED_A_ONLY_INSTALLED_VCRUNTIME140_PROVENANCE_V1"&&r.policy_version==POLICY&&r.operation=="QUALIFY_STARTUP"
  &&!r.providers_allowed&&!r.production_enabled,"CRT A-only provider-free registered policy")?;
 need(r.compiled_source_sha256==hex::encode(source)&&serde_json::to_value(&r.producer).map_err(|e|e.to_string())?==serde_json::to_value(producer).map_err(|e|e.to_string())?,
  "CRT exact registered compiled source/producer tuple")?;
 r.harness.valid()?;hexn::<32>(&r.compiler_build_receipt_sha256)?;
 need(r.compiler_toolset_version==[14,44,35207,0]&&artifact["compiler_build_receipt_sha256"]==r.compiler_build_receipt_sha256,
  "CRT exact selected compiler build/toolset binding")?;
 need(r.abi_proof_sha256==sha(abi_proof)&&r.abi_results_sha256==sha(abi_results),"CRT exact actual ABI receipts")?;
 let proof:Value=serde_json::from_slice(abi_proof).map_err(|e|e.to_string())?;
 let results:Value=serde_json::from_slice(abi_results).map_err(|e|e.to_string())?;
 need(proof["scope"]=="ROOT_ADMITTED_TEST1001_ACTUAL_RUST_NTDLL_ABI"&&proof["source_sha256"]==r.compiled_source_sha256
  &&proof["results_sha256"]==r.abi_results_sha256&&proof["harness"]==serde_json::to_value(&r.harness).map_err(|e|e.to_string())?
  &&results["controls_passed"]==true,"CRT same-source tested harness/ABI binding")?;
 let commands=results["commands"].as_array().ok_or("CRT actual ABI commands absent")?;
 need(commands.len()==4&&commands.iter().all(|c|c["native"]["image"]==r.harness.path&&c["exit"]==0&&c["natural"]==true),
  "CRT actual tested harness original command identity")?;
 need(r.installed.object_class==CLASS&&r.installed.path==PATH&&r.installed.owner_sid_hex==SYSTEM&&r.installed.links==1
  &&r.permissions_policy==PERMISSIONS,"CRT exact installed SYSTEM class/path/approved permissions")?;
 let installed=r.installed.spec()?;
 need(r.package.architecture=="X64"&&official(&r.package.original_url)&&official(&r.package.resolved_url)
  &&r.package.version[0]==14&&r.package.version>=r.compiler_toolset_version,"CRT authentic official compatible v14 package selection")?;
 r.package.native.valid()?;r.payload.native.valid()?;
 need(r.payload.architecture=="AMD64"&&r.payload.machine==0x8664&&r.payload.pe_magic==0x20b&&r.payload.version==r.installed_version&&r.payload.version[0]==14&&r.payload.version>=r.compiler_toolset_version
  &&r.payload.native.bytes==r.installed.bytes&&r.payload.native.sha256==r.installed.sha256
  &&r.payload.package_sha256==r.package.native.sha256,"CRT exact AMD64 authenticated package payload/installed byte equality")?;
 let signature:SignatureReceipt=receipt(&r.signature_receipt_utf8,&r.signature_receipt_sha256)?;
 need(signature.schema=="ROOT_VERIFIED_MICROSOFT_OFFICIAL_REDIST_PACKAGE_V1"&&signature.policy=="WINDOWS_AUTHENTICODE_PA_ALL",
  "CRT actual Microsoft Authenticode policy receipt")?;
 signature.subject.same(&r.package.native)?;signature.verifier.valid()?;
 need(PathBuf::from(&signature.verifier.path).file_name().and_then(|p|p.to_str()).is_some_and(|p|p.eq_ignore_ascii_case("signtool.exe")),
  "CRT exact selected SignTool original")?;
 signature.execution.checked()?;
 need(!signature.verification_time_utc.is_empty()&&signature.verification_time_utc.len()<=128&&(1..=8).contains(&signature.signatures.len()),
  "CRT actual verification time/signature set")?;
 hexn::<32>(&signature.wintrust_source_sha256)?;signature.wintrust_runtime.valid()?;signature.wintrust_execution.checked()?;
 need(signature.secondary_signature_count<8&&signature.signatures.len()==1+signature.secondary_signature_count as usize,"CRT actual complete primary/secondary signature count")?;
 for(index,s)in signature.signatures.iter().enumerate(){
  need(s.signature_index==index as u32&&s.state_close_status==0,"CRT original per-signature index/checked WinTrust state close")?;
  need(s.windows_trust_status==0&&s.microsoft_publisher_authenticated,"CRT actual Windows-trusted Microsoft publisher required")?;chain(&s.signer_chain)?;
  match s.timestamp_status.as_str(){
   "VALID_AUTHENTICODE_TIMESTAMP"=>chain(&s.timestamp_chain)?,
   "NOT_PRESENT"=>need(s.timestamp_chain.is_empty(),"CRT absent timestamp has no invented chain")?,
   _=>return Err("CRT actual timestamp trust status missing/unsupported".into())
  }
 }
 let extraction:Extraction=receipt(&r.extraction_receipt_utf8,&r.extraction_receipt_sha256)?;
 need(extraction.schema=="ROOT_PASSIVE_MICROSOFT_AMD64_VCRUNTIME140_EXTRACTION_V1"&&extraction.passive&&!extraction.installer_executed
  &&extraction.primary.is_null()&&extraction.closure_errors.is_empty(),"CRT complete passive extraction/checked closure")?;
 extraction.package.same(&r.package.native)?;extraction.extractor.valid()?;extraction.msi.native.valid()?;extraction.cab.native.valid()?;
 extraction.payload.same(&r.payload.native)?;
 need(extraction.msi.parent_sha256==r.package.native.sha256&&extraction.msi.architecture=="AMD64"
  &&extraction.cab.parent_sha256==extraction.msi.native.sha256&&extraction.cab.architecture=="AMD64"
  &&r.payload.msi_sha256==extraction.msi.native.sha256&&r.payload.cab_sha256==extraction.cab.native.sha256,
  "CRT passive package/MSI/CAB/member hash chain")?;
 let m=&extraction.file_mapping;
 need(!m.file_identifier.is_empty()&&m.file_identifier.len()<=256&&m.file_name.eq_ignore_ascii_case("vcruntime140.dll")
  &&m.file_version==r.payload.version&&m.sequence>0&&m.sequence<=m.media_last_sequence&&!m.cabinet.is_empty()&&m.cabinet.len()<=1024
  &&m.member_identifier==r.payload.member_identifier&&!m.member_identifier.is_empty()&&m.member_identifier.len()<=256
  &&m.duplicate_matches==1&&!m.external_continuation&&!m.traversal&&m.complete_member,"CRT exact complete File/Media/member mapping")?;
 need(r.current_installation_state=="CURRENT_ORIGINAL_AUTHENTICATED_PAYLOAD_CORRESPONDENCE"&&r.historical_installation_event=="UNKNOWN",
  "CRT current correspondence with historical installer UNKNOWN")?;
 Ok(Authority{installed,source:*source,producer:hexn(&producer.sha256)?,registration:hash(raw)})
}
#[cfg(test)]
mod official_cdn_url_value_controls {
 use super::official;
 // URL values only: no publisher/trust/provenance/native-file authority.
 #[test]
 fn actual_official_visualstudio_cdn_url_value_accepted(){
  assert!(official("https://download.visualstudio.microsoft.com/download/pr/c1bd4f2c-3672-468e-8480-7ed419dbb641/90E48ADE404E4576D023ABFA374F323555F233982A8805EA9AC63DCA9491A16B/VC_redist.x64.exe"));
  for url in ["https://aka.ms/vs/17/release/vc_redist.x64.exe","https://download.microsoft.com/example","https://downloads.microsoft.com/example"]{assert!(official(url));}
 }
 #[test]
 fn lookalike_visualstudio_cdn_hosts_value_refused(){
  for url in ["https://download.visualstudio.microsoft.com.evil.example/VC_redist.x64.exe","https://download-visualstudio.microsoft.com/VC_redist.x64.exe","https://evil.download.visualstudio.microsoft.com/VC_redist.x64.exe"]{assert!(!official(url),"lookalike host {url}");}
 }
 #[test]
 fn invalid_visualstudio_cdn_authority_values_refused(){
  for url in ["http://download.visualstudio.microsoft.com/VC_redist.x64.exe","https://download.visualstudio.microsoft.com@evil.example/VC_redist.x64.exe","https://evil.example/https://download.visualstudio.microsoft.com/VC_redist.x64.exe","https://download.visualstudio.microsoft.com\\VC_redist.x64.exe","https://download.visualstudio.microsoft.com/VC redist.x64.exe"]{assert!(!official(url),"invalid authority/value {url}");}
 }
}
#[cfg(test)]#[path="installed_vcruntime_controls.rs"] mod controls;
