//! TEST controls use genuine separately Root-held registration/context originals.
//! No healthy synthetic package/signature record or installer history is created.
use super::*;
use crate::{policy::{Recipe,SID},own_native_files::OriginalPublicFile,own_native_token,image_pin::native_handle_owner::NativeFile};
use serde::Deserialize;
use std::{cell::Cell,io::{Read,Seek,SeekFrom},path::Path};
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Plan{
 scope:String,source_sha256:String,execution_authorized:bool,
 producer:Pin,harness:Pin,registration:Pin,capture:Pin,artifact:Pin,abi_proof:Pin,abi_results:Pin,installed:Pin,
}
fn read_plan(leaf:&str,env:&str,cap:u64)->Result<Vec<u8>>{
 let own=std::env::current_exe().map_err(|e|e.to_string())?;
 let expected_path=own.parent().ok_or("CRT TEST harness directory")?.join("evidence").join(leaf);
 let selected=std::env::var(env).map_err(|_|"Root-selected CRT TEST control absent")?;strict(&selected)?;
 need(Path::new(&selected)==expected_path,"exact fixed CRT TEST control path")?;
 let expected=std::env::var(format!("{env}_SHA256")).map_err(|_|"Root-selected CRT TEST control digest absent")?;hexn::<32>(&expected)?;
 let mut original=NativeFile::open(Path::new(&selected),0x80000000|0x20000|0x80,1,0x200000)?;
 let primary:Result<Vec<u8>>=(||{
  let file=original.file()?;let size=file.metadata().map_err(|e|e.to_string())?.len();need((64..=cap).contains(&size),"CRT TEST control extent")?;
  let mut bytes=Vec::with_capacity(size as usize);let mut reader=file;reader.by_ref().take(size+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
  need(bytes.len() as u64==size&&file.metadata().map_err(|e|e.to_string())?.len()==size&&sha(&bytes)==expected,"CRT TEST exact control bytes")?;Ok(bytes)
 })();let close=original.close_checked();
 match(primary,close){(Ok(bytes),Ok(()))=>Ok(bytes),(primary,close)=>Err(format!("CRT TEST control read={:?}; checkedclose={close:?}",primary.as_ref().err()))}
}
struct Context{plan:Plan,records:Vec<OriginalPublicFile>,raw:Vec<u8>,source:[u8;32],artifact:Value,proof:Vec<u8>,results:Vec<u8>,token:own_native_token::OwnTokenFacts}
impl Context{
 fn open()->Result<Self>{
  let plan:Plan=serde_json::from_slice(&read_plan("crt-class-test-plan.json","MUTINY_TEST1001_CRT_CLASS_PLAN",131072)?).map_err(|e|e.to_string())?;
  let source=std::env::var("MUTINY_TEST1001_ABI_SOURCE_SHA256").map_err(|_|"closed same-source CRT TEST context absent")?;
  need(plan.scope=="ROOT_ADMITTED_A_ONLY_CRT_CLASS_TESTS_REAL_PROVENANCE_V1"&&plan.execution_authorized&&plan.source_sha256==source,"Root real CRT TEST context/grant")?;
  let token=own_native_token::observe_own()?;need(token.user_sid==SID&&!token.restricted&&!token.app_container&&!token.elevated,"unchanged ordinary TEST1001 CRT control token")?;
  let own=std::env::current_exe().map_err(|e|e.to_string())?;
  need(Path::new(&plan.harness.path)==own&&plan.harness.object_class=="OwnTestImage"&&plan.producer.object_class=="OwnTestImage"
   &&plan.installed.object_class==CLASS&&plan.installed.path==PATH,"Root exact current CRT TEST harness/producer/installed roles")?;
  let mut context=Self{plan,records:Vec::with_capacity(7),raw:Vec::new(),source:hexn(&source)?,artifact:Value::Null,proof:Vec::new(),results:Vec::new(),token};
  let operation:Result<()>=(||{
   let root=own.parent().unwrap().join("evidence");
   let pins=[context.plan.registration.clone(),context.plan.capture.clone(),context.plan.artifact.clone(),context.plan.abi_proof.clone(),context.plan.abi_results.clone(),context.plan.harness.clone(),context.plan.producer.clone()];
   let mut bytes=Vec::with_capacity(7);let mut total=0u64;let mut seen=std::collections::BTreeSet::new();
   for(index,pin)in pins.into_iter().enumerate(){
    need(pin.object_class=="OwnTestImage"&&seen.insert(pin.path.clone())&&(index>=5||Path::new(&pin.path).parent()==Some(root.as_path())),"exact finite protected CRT TEST public records")?;
    total=total.checked_add(pin.bytes).ok_or("CRT TEST byte budget overflow")?;need(total<=268435456,"CRT TEST finite original byte budget")?;
    let record=OriginalPublicFile::open_declared(pin.spec()?,&context.token.user_sid)?;
    context.records.push(record);
    let file=context.records.last().unwrap().original_file()?;let mut reader=file;reader.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;let mut data=Vec::with_capacity(pin.bytes as usize);
    reader.by_ref().take(pin.bytes+1).read_to_end(&mut data).map_err(|e|e.to_string())?;
    need(data.len() as u64==pin.bytes&&sha(&data)==pin.sha256,"CRT TEST retained original full bytes")?;bytes.push(data);
   }
   context.raw=bytes.remove(0);let capture=bytes.remove(0);
   need(hash(&capture)==context.source,"CRT TEST actual full source capture")?;
   context.artifact=serde_json::from_slice(&bytes.remove(0)).map_err(|e|e.to_string())?;
   context.proof=bytes.remove(0);context.results=bytes.remove(0);
   let authority=context.authenticate(&context.raw)?;authority.require_spec(&context.plan.installed.spec()?)?;
   context.recheck()
  })();
  if let Err(primary)=operation{let close=context.close();return Err(format!("CRT TEST pristine real provenance acquisition={primary}; close={close:?}"));}
  Ok(context)
 }
 fn authenticate(&self,raw:&[u8])->Result<Authority>{authenticate(raw,&self.source,&self.plan.producer,&self.artifact,&self.proof,&self.results)}
 fn recheck(&self)->Result<()>{for record in &self.records{record.recheck()?;}need(own_native_token::observe_own()?==self.token,"CRT TEST exact context token continuity")}
 fn close(&mut self)->Result<()>{let mut errors=Vec::new();for record in self.records.iter_mut().rev(){if let Err(e)=record.recheck(){errors.push(e)}if let Err(e)=record.close_checked(){errors.push(e)}}self.records.clear();need(errors.is_empty(),&format!("CRT TEST independent original closures {errors:?}"))}
}
fn with_context(operation:impl FnOnce(&mut Context)->Result<()>){
 let mut c=Context::open().expect("genuine Root retained registration/pristine context, never synthetic PASS");
 let primary=operation(&mut c);let recheck=c.recheck();let close=c.close();
 assert!(primary.is_ok()&&recheck.is_ok()&&close.is_ok(),"real CRT control={primary:?}; recheck={recheck:?}; close={close:?}");
}
fn changed(path:&[&str],value:Value){
 with_context(|c|{
  let mut record:Value=serde_json::from_slice(&c.raw).map_err(|e|e.to_string())?;let mut selected=&mut record;
  for key in &path[..path.len()-1]{selected=&mut selected[*key];}selected[path[path.len()-1]]=value;
  let bytes=serde_json::to_vec(&record).map_err(|e|e.to_string())?;
  need(c.authenticate(&bytes).is_err(),"changed real CRT provenance must be refused")
 });
}
#[test]fn actual_registered_installed_crt_original_positive(){
 with_context(|c|{
  let authority=c.authenticate(&c.raw)?;let mut original=OriginalPublicFile::open_registered(c.plan.installed.spec()?,&c.token.user_sid,Some(&authority))?;
  let primary=original.recheck();let close=original.close_checked();
  need(primary.is_ok()&&close.is_ok(),&format!("actual installed CRT check={primary:?}; close={close:?}"))?;
  println!("MUTINY_A_ONLY_CRT_REAL_PROVENANCE_AND_ORIGINAL_CHECKED_NO_FACTORY");Ok(())
 });
}
#[test]fn missing_provenance_authority_refused(){
 with_context(|c|{match OriginalPublicFile::open_declared(c.plan.installed.spec()?,&c.token.user_sid){
  Err(e)=>need(e=="Installed CRT protected provenance authority required","exact missing CRT authority refusal"),
  Ok(mut unexpected)=>{let close=unexpected.close_checked();Err(format!("CRT missing authority accepted; close={close:?}"))}
 }})
}
#[test]fn missing_registration_schema_refused(){with_context(|c|need(c.authenticate(b"{}").is_err(),"missing actual registration must refuse"));}
#[test]fn mismatched_registered_source_refused(){changed(&["compiled_source_sha256"],Value::String("01".repeat(32)));}
#[test]fn mismatched_registered_owner_refused(){changed(&["installed","owner_sid_hex"],Value::String("01020000000000052000000020020000".into()));}
#[test]fn alternate_registered_dll_path_refused(){changed(&["installed","path"],Value::String(r"C:\Windows\System32\ucrtbase.dll".into()));}
#[test]fn mismatched_registered_hash_refused(){changed(&["installed","sha256"],Value::String("01".repeat(32)));}
#[test]fn incompatible_package_version_refused(){changed(&["package","version"],serde_json::json!([14,43,1,0]));}
#[test]fn unauthenticated_signature_receipt_refused(){changed(&["signature_receipt_sha256"],Value::String("01".repeat(32)));}
#[test]fn mismatched_passive_extraction_receipt_refused(){changed(&["extraction_receipt_sha256"],Value::String("01".repeat(32)));}
fn changed_receipt(field:&str,digest:&str,operation:impl FnOnce(&mut Value),reason:&str){
 with_context(|c|{
  let mut record:Value=serde_json::from_slice(&c.raw).map_err(|e|e.to_string())?;
  let mut receipt:Value=serde_json::from_str(record[field].as_str().ok_or("pristine receipt text")?).map_err(|e|e.to_string())?;
  operation(&mut receipt);let malicious=serde_json::to_string(&receipt).map_err(|e|e.to_string())?;
  record[digest]=Value::String(sha(malicious.as_bytes()));record[field]=Value::String(malicious);
  let bytes=serde_json::to_vec(&record).map_err(|e|e.to_string())?;
  match c.authenticate(&bytes){Err(actual)=>need(actual==reason,"specific malicious provenance check refusal"),Ok(_)=>Err("malicious receipt unexpectedly authenticated".into())}
 });
}
#[test]fn actual_windows_signature_failure_value_refused(){
 changed_receipt("signature_receipt_utf8","signature_receipt_sha256",|r|r["signatures"][0]["windows_trust_status"]=serde_json::json!(2148204800u32),
  "CRT actual Windows-trusted Microsoft publisher required");
}
#[test]fn mismatched_passive_payload_tuple_value_refused(){
 changed_receipt("extraction_receipt_utf8","extraction_receipt_sha256",|r|r["payload"]["sha256"]=Value::String("01".repeat(32)),
  "CRT exact evidence native tuple binding");
}
#[test]fn mismatched_registered_identity_refused(){
 with_context(|c|{let authority=c.authenticate(&c.raw)?;let mut spec=c.plan.installed.spec()?;spec.file_id[0]^=1;need(authority.require_spec(&spec).is_err(),"exact installed native identity mismatch refuses")})
}
#[test]fn mismatched_registered_permissions_refused(){
 with_context(|c|{let authority=c.authenticate(&c.raw)?;let mut spec=c.plan.installed.spec()?;spec.dacl_sha256[0]^=1;need(authority.require_spec(&spec).is_err(),"exact installed native permission witness mismatch refuses")})
}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct MissingPlan{scope:String,source_sha256:String,execution_authorized:bool,recipe_sha256:String,own:Pin}
#[test]fn actual_policy_missing_crt_registration_never_enters_activation(){
 let plan:MissingPlan=serde_json::from_slice(&read_plan("crt-missing-registration-test-plan.json","MUTINY_TEST1001_CRT_POLICY_NEGATIVE_PLAN",131072).unwrap()).unwrap();
 let own=std::env::current_exe().unwrap();let source=std::env::var("MUTINY_TEST1001_ABI_SOURCE_SHA256").unwrap();
 need(plan.scope=="ROOT_ADMITTED_ACTUAL_POLICY_MISSING_CRT_REGISTRATION_NEGATIVE_V1"&&plan.execution_authorized&&plan.source_sha256==source
  &&plan.own.path==own.to_str().unwrap()&&own.file_name().and_then(|p|p.to_str())==Some("mutiny-wallet-root-native-test.exe"),"Root exact TEST-only mainbasename alias/negative plan").unwrap();
 let token=own_native_token::observe_own().unwrap();need(token.user_sid==SID&&!token.restricted&&!token.app_container&&!token.elevated,"actual Policy negative TEST1001 token").unwrap();
 let mut pristine=OriginalPublicFile::open_declared(plan.own.spec().unwrap(),&token.user_sid).unwrap();
 let recipe_path=own.parent().unwrap().join("ROOT-NATIVE-TEST-BOOTSTRAP.json");
 // Root retains this exact recipe original. A checked native read proves the
 // selected fixture actually asks for the new class with registration absent.
 let mut file=NativeFile::open(&recipe_path,0x80000000|0x20000|0x80,1,0x200000).unwrap();
 let primary:Result<Recipe>=(||{
  let reader=file.file()?;let mut reader=reader;let mut bytes=Vec::new();reader.by_ref().take(524289).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
  need((64..=524288).contains(&bytes.len())&&sha(&bytes)==plan.recipe_sha256,"exact Root missing-registration recipe bytes")?;
  serde_json::from_slice(&bytes).map_err(|e|e.to_string())
 })();let close=file.close_checked();assert!(primary.is_ok()&&close.is_ok(),"recipe={:?}; close={close:?}",primary.as_ref().err());let recipe=primary.unwrap();
 need(recipe.operation=="QUALIFY_STARTUP"&&recipe.installed_crt_registration_path.is_none()&&recipe.anchor_output.is_none()
  &&recipe.producer_objects.iter().filter(|p|p.object_class==CLASS&&p.path==PATH).count()==1
  &&recipe.producer_objects.iter().any(|p|serde_json::to_value(p).ok()==serde_json::to_value(&plan.own).ok()),"genuine missing CRT registration fixture selection").unwrap();
 let hooks=&crate::bootstrap::targeted_startup_policy_failure_controls::arm_negative_trace;
 hooks().unwrap();let continuation=Cell::new(0usize);
 let outcome=crate::bootstrap::crt_test_after_acquisition(crate::policy::Policy::acquire,|mut policy|{
  continuation.set(continuation.get()+1);let close=policy.close_checked();Err::<(),String>(format!("missing CRT registration acquired unexpectedly; close={close:?}"))
 });
 let counts=crate::bootstrap::targeted_startup_policy_failure_controls::negative_trace_counts();
 let checked=pristine.recheck();let close=pristine.close_checked();let known=crate::owned::known();
 assert_eq!(counts,(1,0));assert_eq!(continuation.get(),0);
 assert_eq!(outcome,Err("Installed CRT provenance refused Installed CRT requires exactly one A-only QUALIFY_STARTUP registration; no anchor/provider operation; independent closure=[]".into()));
 assert_eq!(crate::bootstrap::targeted_startup_policy_failure_controls::crt_recipe_close_trace().unwrap(),Some((plan.recipe_sha256.clone(),true)));
 assert!(checked.is_ok()&&close.is_ok()&&known.is_ok()&&own_native_token::observe_own().unwrap()==token,"negative independent close/context");
 println!("MUTINY_A_ONLY_CRT_ACTUAL_POLICY_MISSING_REGISTRATION_REFUSED acquire=1 continuation=0 factory=0");
}
