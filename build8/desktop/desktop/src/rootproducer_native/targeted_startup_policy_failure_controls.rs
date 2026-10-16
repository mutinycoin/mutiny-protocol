//! NONSHIPPING actual Policy entry negative, isolated Root-selected TEST alias.
//! No real factory/channel/Job/provider entry, normal artifact admission or reset.
#![cfg(all(test,windows,target_arch="x86_64",feature="testvalue-window"))]
use super::after_original_acquisition;
use crate::{Result,need,sha,policy::{Policy,Recipe,Pin,SID,DECISION,strict,hexn},
 own_native_files::OriginalPublicFile,own_native_token,image_pin::native_handle_owner::NativeFile};
use serde::Deserialize;
use serde_json::Value;
use std::{cell::Cell,io::Read,path::Path,sync::atomic::{AtomicBool,AtomicUsize,Ordering}};
static ARMED:AtomicBool=AtomicBool::new(false);
static ACQUISITION_ENTRIES:AtomicUsize=AtomicUsize::new(0);
static FACTORY_BOUNDARY_ENTRIES:AtomicUsize=AtomicUsize::new(0);
// Both hooks are called at the actual Policy acquisition/factory sites. They
// are entirely cfg(TEST) and inert for every other entry/control. No reset.
pub(crate) fn acquisition_entered(){if ARMED.load(Ordering::Acquire){ACQUISITION_ENTRIES.fetch_add(1,Ordering::AcqRel);}}
pub(crate) fn factory_boundary()->Result<()>{
 if ARMED.load(Ordering::Acquire){
  FACTORY_BOUNDARY_ENTRIES.fetch_add(1,Ordering::AcqRel);
  return Err("TEST actual Policy negative reached factory boundary; real factory prevented".into());
 }Ok(())
}
// Additional exact TEST selector uses the actual acquisition/factory hooks.
// Fresh process only: counters and arming are never reset.
pub(crate) fn arm_negative_trace()->Result<()>{
 need(!ARMED.swap(true,Ordering::AcqRel)&&ACQUISITION_ENTRIES.load(Ordering::Acquire)==0&&FACTORY_BOUNDARY_ENTRIES.load(Ordering::Acquire)==0,"fresh once-only actual Policy negative trace")
}
static CRT_RECIPE_CLOSE:std::sync::Mutex<Option<(String,bool)>>=std::sync::Mutex::new(None);
pub(crate) fn crt_recipe_closed(sha256:&str,checked:bool)->Result<()>{
 if ARMED.load(Ordering::Acquire){
  let mut trace=CRT_RECIPE_CLOSE.lock().map_err(|_|"actual CRT recipe-close trace poisoned")?;
  need(trace.is_none(),"actual CRT recipe-close trace consumed once")?;
  *trace=Some((sha256.to_owned(),checked));
 }Ok(())
}
pub(crate) fn crt_recipe_close_trace()->Result<Option<(String,bool)>>{
 Ok(CRT_RECIPE_CLOSE.lock().map_err(|_|"actual CRT recipe-close trace poisoned")?.clone())
}
pub(crate) fn negative_trace_counts()->(usize,usize){
 (ACQUISITION_ENTRIES.load(Ordering::Acquire),FACTORY_BOUNDARY_ENTRIES.load(Ordering::Acquire))
}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Control{
 scope:String,source_sha256:String,fixture_action_authorized:bool,
 expected_own:Pin,pristine_recipe_utf8:String,pristine_recipe_sha256:String,negative_recipe_sha256:String,
}
fn read_selected(path:&Path,cap:u64,expected:&str)->Result<Vec<u8>>{
 hexn::<32>(expected)?;
 let mut original=NativeFile::open(path,0x80000000|0x20000|0x80,1,0x200000)?;
 let primary:Result<Vec<u8>>=(||{
  let file=original.file()?;let length=file.metadata().map_err(|e|e.to_string())?.len();
  need((64..=cap).contains(&length),"finite Root-selected negative TEST data extent")?;
  let mut bytes=Vec::with_capacity(length as usize);let mut reader=file;
  reader.by_ref().take(length+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
  need(bytes.len() as u64==length&&file.metadata().map_err(|e|e.to_string())?.len()==length&&sha(&bytes)==expected,
   "entire exact Root-selected negative TEST original data")?;Ok(bytes)
 })();
 let close=original.close_checked();
 match(primary,close){(Ok(bytes),Ok(()))=>Ok(bytes),(primary,close)=>Err(format!("negative TEST data read={:?}; independent close={close:?}",primary.as_ref().err()))}
}
fn selected(own:&Path)->Result<(Control,Recipe,String)>{
 let root=own.parent().ok_or("isolated TEST harness parent")?;
 let selected_path=std::env::var("MUTINY_TEST1001_POLICY_NEGATIVE_PLAN").map_err(|_|"Root-held actual Policy negative control absent")?;
 strict(&selected_path)?;
 need(Path::new(&selected_path)==root.join("evidence").join("policy-negative-test-plan.json"),
  "fixed isolated actual Policy negative public control path")?;
 let selected_sha=std::env::var("MUTINY_TEST1001_POLICY_NEGATIVE_PLAN_SHA256").map_err(|_|"Root-held actual Policy negative control hash absent")?;
 let control:Control=serde_json::from_slice(&read_selected(Path::new(&selected_path),2097152,&selected_sha)?).map_err(|e|e.to_string())?;
 let source=std::env::var("MUTINY_TEST1001_ABI_SOURCE_SHA256").map_err(|_|"closed same-source TEST artifact context absent")?;
 hexn::<32>(&source)?;
 need(control.scope=="ROOT_ADMITTED_TEST1001_ACTUAL_POLICY_OWN_HASH_NEGATIVE_ONLY"&&control.fixture_action_authorized&&control.source_sha256==source,
  "separate same-source Root actual Policy TEST grant")?;
 need(control.expected_own.path==own.to_str().ok_or("exact TEST alias ASCII")?
  &&control.expected_own.object_class=="OwnTestImage"&&control.expected_own.links==1,
  "exact current known original TEST alias witness/class")?;
 need((64..=524288).contains(&control.pristine_recipe_utf8.len())&&sha(control.pristine_recipe_utf8.as_bytes())==control.pristine_recipe_sha256,
  "Root-selected entire pristine public recipe context")?;
 let pristine:Recipe=serde_json::from_str(&control.pristine_recipe_utf8).map_err(|e|e.to_string())?;
 need(pristine.scope=="SOURCE_OWNED_NATIVE_TEST_ROOT_BOOTSTRAP_V5"&&pristine.decision_sha256==DECISION
  &&pristine.operation=="QUALIFY_STARTUP"&&!pristine.producer_objects.is_empty(),
  "actual unmodified Policy recipe domain and provider-free operation")?;
 need(pristine.child_objects.is_empty()&&pristine.child_image.is_none()&&pristine.provider_manifest_path.is_none()
  &&pristine.application.is_none()&&pristine.anchor_output.is_none(),
  "isolated acquisition negative has no child/provider/application/anchor")?;
 need(serde_json::to_value(&pristine.producer_objects[0]).map_err(|e|e.to_string())?
  ==serde_json::to_value(&control.expected_own).map_err(|e|e.to_string())?,
  "first actual declared input is pristine current own TEST original")?;
 need(pristine.evidence_inputs.iter().filter(|p|p.path==pristine.producer_capture_path&&p.sha256==source).count()==1,
  "same-source actual public capture witness retained in recipe declaration")?;
 let mut wrong=hexn::<32>(&control.expected_own.sha256)?;wrong[0]^=1;let wrong=hex::encode(wrong);
 hexn::<32>(&wrong)?;
 let mut expected:Value=serde_json::to_value(&pristine).map_err(|e|e.to_string())?;
 expected["producer_objects"][0]["sha256"]=Value::String(wrong.clone());
 let negative_bytes=read_selected(&root.join("ROOT-NATIVE-TEST-BOOTSTRAP.json"),524288,&control.negative_recipe_sha256)?;
 let negative:Recipe=serde_json::from_slice(&negative_bytes).map_err(|e|e.to_string())?;
 need(serde_json::to_value(&negative).map_err(|e|e.to_string())?==expected,
  "actual fixed recipe differs solely in first expected own SHA byte")?;
 Ok((control,negative,wrong))
}
fn run()->Result<()>{
 let own=std::env::current_exe().map_err(|e|e.to_string())?;strict(own.to_str().ok_or("actual TEST alias ASCII")?)?;
 need(own.file_name().and_then(|n|n.to_str())==Some("mutiny-wallet-root-native-test.exe"),
  "actual Policy keeps exact main basename; isolated TEST alias required")?;
 let before=own_native_token::observe_own()?;
 need(before.user_sid==SID&&!before.app_container&&!before.restricted&&!before.elevated,
  "actual unchanged ordinary TEST1001 Policy profile")?;
 let(control,_negative,wrong)=selected(&own)?;
 // Pristine construction is outside the intended refusal. Setup/class/security
 // errors cannot count as a negative-control pass. This retains the correct
 // own original while Policy independently checks the deliberate wrong SHA.
 let mut pristine=OriginalPublicFile::open_declared(control.expected_own.spec()?,&before.user_sid)?;
 let continuation=Cell::new(0usize);
 let operation:Result<()>=(||{
  pristine.recheck()?;
  need(ACQUISITION_ENTRIES.load(Ordering::Acquire)==0&&FACTORY_BOUNDARY_ENTRIES.load(Ordering::Acquire)==0
   &&ARMED.compare_exchange(false,true,Ordering::AcqRel,Ordering::Acquire).is_ok(),
   "one fresh process/no previous actual Policy negative trace; no reset")?;
  let actual=after_original_acquisition(Policy::acquire,|mut policy|{
   continuation.set(continuation.get()+1);
   let close=policy.close_checked();
   Err::<(),String>(format!("wrong own SHA unexpectedly acquired actual Policy; independent close={close:?}"))
  });
  let entries=ACQUISITION_ENTRIES.load(Ordering::Acquire);let factories=FACTORY_BOUNDARY_ENTRIES.load(Ordering::Acquire);
  need(entries==1&&continuation.get()==0&&factories==0,
   &format!("actual Policy acquisition/continuation/factory trace refused {entries}/{}/{factories}",continuation.get()))?;
  need(actual==Err("Own public original=Own public original full SHA/EOF refusal; closure=Ok(())".into()),
   &format!("only actual first own SHA refusal accepted; different basename/profile/recipe/class/admission/cleanup error fails: {actual:?}"))?;
  pristine.recheck()?;crate::owned::known()?;
  need(own_native_token::observe_own()?==before,"actual process/token unchanged through real Policy negative")?;Ok(())
 })();
 let checked=pristine.recheck();let close=pristine.close_checked();let known=crate::owned::known();
 let after=own_native_token::observe_own();
 need(checked.is_ok()&&close.is_ok()&&known.is_ok()&&after.as_ref()==Ok(&before),
  &format!("actual Policy negative independent original closure/context refused: recheck={checked:?}; close={close:?}; known={known:?}; token={after:?}; original={operation:?}"))?;
 operation?;
 println!("MUTINY_TESTVALUE_ACTUAL_POLICY_OWN_SHA_REFUSED acquire_entries=1 continuation_entries=0 factory_boundary_entries=0 recipe_sha256={} pristine_own_sha256={} negative_own_sha256={}",
  control.negative_recipe_sha256,control.expected_own.sha256,wrong);
 println!("MUTINY_TESTVALUE_ACTUAL_POLICY_NEGATIVE_OWN_PROFILE {:?}",before);Ok(())
}
#[test]fn actual_policy_wrong_own_sha_never_enters_startup_or_factory(){run().unwrap();}
