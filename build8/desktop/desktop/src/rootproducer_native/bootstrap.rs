//! Operative source-owned native TEST composite. Outer retains originals before
//! its fresh suspended inner. The native original OS peer binds local policy.
//! No external issuer recursion, raw signer, production source or reset.
use crate::{Result,need,sha,policy::{Policy,DECISION},pipe::{Channel,Parent},job::Job,own_native_modules::OwnLoadedModules,own_native_files::OriginalPublicFile};
use serde_json::{Value,json};
use std::{collections::BTreeMap,path::{Path,PathBuf}};
#[repr(C)]struct Time{low:u32,high:u32}
#[link(name="kernel32")]unsafe extern "system"{fn GetSystemTimeAsFileTime(time:*mut Time);}
fn filetime()->u64{let mut t=Time{low:0,high:0};unsafe{GetSystemTimeAsFileTime(&mut t)};(t.high as u64)<<32|t.low as u64}
struct Outer{policy:Policy,channel:Option<Channel>,job:Option<Job>,held_before:u64}
impl Outer{
 fn execute(&mut self)->Result<(Value,Value)>{
  self.policy.require()?;need(self.held_before>0,"actual precreation original custody time")?;
  let name=format!(r"\\.\pipe\Mutiny-NativeRoot-Startup-{}-{}",self.policy.recipe.campaign,crate::instance()?);
  self.channel=Some(Channel::server(name,&self.policy.token.user_sid)?);
  let c=self.channel.as_mut().unwrap();
  let env=BTreeMap::from([("SystemRoot".into(),r"C:\Windows".into()),("WINDIR".into(),r"C:\Windows".into()),("MUTINY_NATIVE_ROOT_STARTUP_PIPE".into(),c.name().into())]);
  let cwd=Path::new(&self.policy.own).parent().and_then(|p|p.to_str()).ok_or("own directory")?;
  self.job=Some(Job::prepare(&self.policy.own,&["--native-root-inner".into()],cwd,&env,&self.policy.recipe.output_prefix)?);
  let job=self.job.as_mut().unwrap();self.policy.require()?;let held=self.held_before;
  job.start_suspended(|created|{self.policy.require()?;let(child,_)=created.peer()?;need(held<child.process_start_filetime,"original startup inputs held before child's actual creation")?;crate::same_role(&self.policy.token,child)})?;
  c.connect(||self.policy.require())?;
  let require=||{self.policy.require()?;c.require_child(job)};
  need(c.read(&require)?==b"NATIVE_ROOT_STARTUP_REQUEST","single actual native startup request")?;
  let(child,_)=job.peer()?;
  let envelope=crate::json_bytes(&json!({"scope":"SOURCE_OWNED_NATIVE_TEST_ORIGINAL_STARTUP_V5","decision_sha256":DECISION,"recipe_sha256":sha(&self.policy.raw),"startup_inputs_sha256":self.policy.startup_hash()?,"precreation_hold_filetime":self.held_before,"parent":crate::token_json(&self.policy.token),"child":crate::token_json(child)}),65536)?;
  c.send("NATIVE_ROOT_STARTUP_ENVELOPE_BYTES",&envelope,&require)?;
  need(c.read(&require)?==b"NATIVE_ROOT_STARTUP_ENVELOPE_RECEIVED","exact startup acknowledgement")?;
  drop(require);c.begin_startup_operation()?;
  let require=||{self.policy.require()?;c.require_child(job)};
  let result=c.receive("NATIVE_ROOT_OPERATION_OUTCOME_BYTES",65536,&require)?;
  let actual:Value=serde_json::from_slice(&result).map_err(|e|e.to_string())?;
  need(actual["operation"]==self.policy.recipe.operation&&actual["recipe_sha256"]==sha(&self.policy.raw)&&actual["natural_operation_success"]==true,"exact finite original native operation outcome")?;
  c.write(format!("NATIVE_ROOT_OPERATION_OUTCOME_ACK {}",sha(&result)).as_bytes(),&require)?;
  self.policy.require()?;let closure=job.natural_close()?;self.policy.require()?;
  let mut errors=Vec::new();if let Err(e)=c.close_checked(){errors.push(e)}if let Err(e)=self.policy.close_checked(){errors.push(e)}
  need(errors.is_empty(),&format!("native outer independent original closures {errors:?}"))?;crate::owned::known()?;Ok((actual,closure))
 }
}
fn output_boundary(p:&Policy)->Result<()>{crate::policy::strict(&p.recipe.output_prefix)?;let prefix=Path::new(&p.recipe.output_prefix);need(prefix.parent()==Path::new(&p.own).parent()&&prefix.file_name().and_then(|s|s.to_str()).is_some_and(|s|s.starts_with("native-root-")&&s.len()<=96),"finite create-new producer receipt namespace beside original image")}
fn after_original_acquisition<T,U>(acquire:impl FnOnce()->Result<T>,continuation:impl FnOnce(T)->Result<U>)->Result<U>{
 let original=acquire()?;continuation(original)
}
#[cfg(all(test,feature="testvalue-window"))]
pub(crate) fn crt_test_after_acquisition<T,U>(acquire:impl FnOnce()->Result<T>,continuation:impl FnOnce(T)->Result<U>)->Result<U>{
 after_original_acquisition(acquire,continuation)
}
pub(crate) fn outer()->Result<()>{
 after_original_acquisition(Policy::acquire, |p|{output_boundary(&p)?;
 let prefix=p.recipe.output_prefix.clone();let startup=p.startup_hash()?;let own_sha=p.own_pin()?.sha256.clone();let operation=p.recipe.operation.clone();let source=hex::encode(p.source);
 // Allocate the complete invocation graph before any owned process creation.
 let mut graph=Box::new(Outer{policy:p,channel:None,job:None,held_before:filetime()});
 // The graph lives outside the local unwind boundary. Unwinding execute does
 // not run its field destructors before we retain every original owner.
 match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||graph.execute())){
  Ok(Ok((actual,closure)))=>{
   let (path,receipt)=if operation=="QUALIFY_STARTUP"{(format!("{prefix}-startup-controls-closed.json"),json!({"scope":"SOURCE_OWNED_NATIVE_TEST_STARTUP_CONTROLS_CLOSED_V5","decision_sha256":DECISION,"startup_inputs_sha256":startup,"compiled_source_sha256":source,"producer_image_sha256":own_sha,"producer_kind":"monolithic_native_test_root","operative_payload_role":"same_native_executable","raw_exit":0,"natural_active_process_zero":true,"channel_complete":true,"independent_close_errors":[],"controls":actual["controls"],"outer_original_job":closure,"qualified_roles":["outer_source_controller","fresh_owned_inner"],"clr_qualified":false,"private_cow_execution_proven":false,"normal_shipping":false,"provider_read":false,"runtime_eligible":false}))}
   else{(format!("{prefix}-operation-closed.json"),json!({"scope":"SOURCE_OWNED_NATIVE_TEST_OPERATION_CLOSED_V5","operation":operation,"outcome":actual,"outer_original_job":closure,"runtime_eligible":false}))};
   crate::write_new(&path,&crate::json_bytes(&receipt,65536)?)
  },
  Ok(Err(error))=>{crate::owned::mark_unknown();let _=Box::leak(graph);Err(format!("original native outer graph UNKNOWN/refused, retained with no retry/reset: {error}"))},
  Err(payload)=>{crate::owned::mark_unknown();let _=Box::leak(graph);std::mem::forget(payload);Err("original native outer unwind; complete graph retained UNKNOWN".into())}
 }
 })
}
struct Inner{policy:Policy,channel:Channel,parent:Parent,authenticated:bool}
impl Inner{
 fn require(&self)->Result<()>{need(self.authenticated,"private original native startup channel not authenticated")?;self.policy.require()?;self.parent.require(&self.channel)?;crate::same_role(&self.policy.token,self.parent.facts())}
 fn qualify(&self)->Result<Value>{
  self.require()?;let p=&self.policy;let mut controls=Vec::new();controls.push(json!({"name":"actual_owned_native_startup_and_same_backing","actual_passed":1}));
  let paths=p.recipe.producer_objects.iter().map(|z|PathBuf::from(&z.path)).collect::<Vec<_>>();
  let mut pristine=OwnLoadedModules::observe_declared(&paths,Path::new(&p.own))?;
  let operation:Result<()>=(||{
   pristine.recheck()?;
   let missing=pristine.observations().iter().find(|m|m.path!=PathBuf::from(&p.own)).ok_or("actual non-own loaded module needed for negative")?.path.clone();
   let wrong=paths.iter().filter(|z|**z!=missing).cloned().collect::<Vec<_>>();
   match OwnLoadedModules::observe_declared(&wrong,Path::new(&p.own)){
    Err(e) if e.starts_with("Own unknown module metadata; no unknown file opened:")=>{},
    Err(e)=>return Err(format!("unexpected module acquisition/semantic refusal: {e}")),
    Ok(mut unexpected)=>{let close=unexpected.close_checked();return Err(format!("unknown roster unexpectedly accepted; close={close:?}"))}
   }pristine.recheck()
  })();let close=pristine.close_checked();
  need(operation.is_ok()&&close.is_ok(),&format!("exact unknown roster refusal={operation:?}; pristine closure={close:?}"))?;
  controls.push(json!({"name":"actual_unknown_roster_refused","actual_passed":1}));
  // Pristine construction is outside the intended hash-refusal catch. Neither
  // acquisition/security errors nor an uncertain close earn this control.
  let pin=p.own_pin()?.spec()?;let mut original=OriginalPublicFile::open_declared(pin.clone(),&p.token.user_sid)?;
  let operation:Result<()>=(||{
   original.recheck()?;let mut wrong=pin;wrong.sha256[0]^=1;
   match OriginalPublicFile::open_declared(wrong,&p.token.user_sid){
    Err(e) if e=="Own public original=Own public original full SHA/EOF refusal; closure=Ok(())"=>{},
    Err(e)=>return Err(format!("wrong-hash construction/acquisition/cleanup failure: {e}")),
    Ok(mut unexpected)=>{let close=unexpected.close_checked();return Err(format!("wrong hash unexpectedly accepted; close={close:?}"))}
   }original.recheck()
  })();let close=original.close_checked();
  need(operation.is_ok()&&close.is_ok(),&format!("exact wrong-hash refusal={operation:?}; pristine close={close:?}"))?;
  controls.push(json!({"name":"actual_wrong_original_tuple_refused","actual_passed":1}));self.require()?;Ok(json!({"controls":controls}))
 }
 fn execute(&mut self)->Result<()> {
  self.policy.require()?;self.parent.require(&self.channel)?;
  let pre=||{self.policy.require()?;self.parent.require(&self.channel)};
  self.channel.write(b"NATIVE_ROOT_STARTUP_REQUEST",&pre)?;
  let raw=self.channel.receive("NATIVE_ROOT_STARTUP_ENVELOPE_BYTES",65536,&pre)?;
  let envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
  need(envelope["scope"]=="SOURCE_OWNED_NATIVE_TEST_ORIGINAL_STARTUP_V5"&&envelope["decision_sha256"]==DECISION&&envelope["recipe_sha256"]==sha(&self.policy.raw)&&envelope["startup_inputs_sha256"]==self.policy.startup_hash()?&&envelope["parent"]==crate::token_json(self.parent.facts())&&envelope["child"]==crate::token_json(&self.policy.token)&&envelope["precreation_hold_filetime"].as_u64().is_some_and(|t|t>0&&t<self.policy.token.process_start_filetime),"original native parent/child/custody/policy binding")?;
  self.authenticated=true;self.require()?;
  self.channel.write(b"NATIVE_ROOT_STARTUP_ENVELOPE_RECEIVED",||self.require())?;self.channel.begin_startup_operation()?;
  let result=if self.policy.recipe.operation=="QUALIFY_STARTUP"{self.qualify()?}else{
   let startup=self.policy.admit_startup()?;self.require()?;
   if self.policy.recipe.operation=="FORM_CHILD_ANCHOR"{
    let bytes=crate::launch::anchor(&self.policy)?;let output=self.policy.recipe.anchor_output.as_deref().ok_or("fresh anchor output required")?;
    crate::policy::strict(output)?;need(Path::new(output).parent()==Path::new(&self.policy.own).parent()&&Path::new(output).extension().and_then(|s|s.to_str())==Some("rs"),"finite create-new native anchor beside original A")?;
    crate::write_new(output,&bytes)?;self.require()?;json!({"scope":"SOURCE_OWNED_NATIVE_TEST_CHILD_ANCHOR_CANDIDATE","producer_image":self.policy.own_pin()?,"producer_payload_same_original":true,"producer_kind":"monolithic_native_test_root","path":output,"bytes":bytes.len(),"sha256":sha(&bytes),"runtime_eligible":false})
   }else{crate::launch::run(&self.policy,&startup)?}
  };
  self.require()?;
  let outcome=json!({"operation":self.policy.recipe.operation,"recipe_sha256":sha(&self.policy.raw),"natural_operation_success":true,"controls":result.get("controls"),"result":result});let bytes=crate::json_bytes(&outcome,65536)?;
  self.channel.send("NATIVE_ROOT_OPERATION_OUTCOME_BYTES",&bytes,||self.require())?;
  need(self.channel.read(||self.require())?==format!("NATIVE_ROOT_OPERATION_OUTCOME_ACK {}",sha(&bytes)).as_bytes(),"exact original outcome acknowledgement; lost ACK UNKNOWN")?;
  self.require()?;let mut errors=Vec::new();if let Err(e)=self.channel.close_checked(){errors.push(e)}if let Err(e)=self.parent.close_checked(){errors.push(e)}if let Err(e)=self.policy.close_checked(){errors.push(e)}
  need(errors.is_empty(),&format!("native inner independent original closures {errors:?}"))?;crate::owned::known()
 }
}
pub(crate) fn inner()->Result<()>{
 after_original_acquisition(Policy::acquire, |p|{output_boundary(&p)?;
 let name=std::env::var("MUTINY_NATIVE_ROOT_STARTUP_PIPE").map_err(|_|"original native startup route absent")?;
 let channel=Channel::client(name,&p.token.user_sid)?;let parent=Parent::acquire(&channel,&p.own)?;
 crate::same_role(&p.token,parent.facts())?;need(parent.facts().pid!=p.token.pid&&parent.facts().process_start_filetime<p.token.process_start_filetime,"genuine earlier original native parent")?;
 let mut graph=Box::new(Inner{policy:p,channel,parent,authenticated:false});
 match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||graph.execute())){Ok(Ok(()))=>Ok(()),Ok(Err(error))=>{crate::owned::mark_unknown();let _=Box::leak(graph);Err(format!("original native inner/channel/policy graph UNKNOWN/refused, retained: {error}"))},Err(payload)=>{crate::owned::mark_unknown();let _=Box::leak(graph);std::mem::forget(payload);Err("original native inner unwind; complete graph retained UNKNOWN".into())}}
 })
}

#[cfg(test)]
#[path="targeted_startup_boundary_value_controls.rs"] mod targeted_startup_boundary_value_controls;

#[cfg(all(test,feature="testvalue-window"))]
#[path="targeted_startup_policy_failure_controls.rs"] pub(crate) mod targeted_startup_policy_failure_controls;
