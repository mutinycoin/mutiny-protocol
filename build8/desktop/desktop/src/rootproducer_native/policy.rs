//! Source-owned TEST bootstrap boundary. This is not a production provider.
//! Retained originals, finite public data and independently reviewed actual
//! artifact/ABI/startup admissions are evaluated before constructing an owner.
use crate::{Result,need,sha,hash,pipe,pe,own_native_token::{self,OwnTokenFacts},own_native_files::{OriginalPublicFile,PublicObjectSpec,PublicClass},own_native_facade::{AdmittedTestInputs,OwnExecutionLease},image_pin::native_handle_owner::NativeFile};
use serde::{Deserialize,Serialize};use serde_json::{Value,json};
use std::{collections::{BTreeMap,BTreeSet},path::{Path,PathBuf},io::{Read,Seek,SeekFrom},mem::{size_of,zeroed},os::windows::io::AsRawHandle};
use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle,GetFileInformationByHandleEx,BY_HANDLE_FILE_INFORMATION,FILE_ID_INFO,FileIdInfo};
pub(crate) const DECISION:&str="0f853c55d14c2065a153f4cb9cd58408be8cc94d47f9ac71274846148bd5e079";
// No runtime principal override, union, fallback or production owner selection.
#[cfg(all(feature="asus-native-test-principal",not(debug_assertions)))]
compile_error!("ASUS native TEST principal requires isolated debug qualification profile");
#[cfg(not(feature="asus-native-test-principal"))]
pub(crate) const SID:[u8;28]=[1,5,0,0,0,0,0,5,21,0,0,0,175,69,68,154,43,152,171,101,195,166,27,194,233,3,0,0];
#[cfg(feature="asus-native-test-principal")]
pub(crate) const SID:[u8;28]=[1,5,0,0,0,0,0,5,21,0,0,0,50,227,236,27,1,62,174,79,19,207,22,167,237,3,0,0];
#[derive(Clone,Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub(crate) struct Pin{pub path:String,pub bytes:u64,pub sha256:String,pub volume:u64,pub file_id:String,pub links:u32,pub owner_sid_hex:String,pub dacl_sha256:String,pub object_class:String}
impl Pin{pub(crate) fn spec(&self)->Result<PublicObjectSpec>{strict(&self.path)?;need(self.path.len()<=1006&&(64..=134217728).contains(&self.bytes),"exact bounded original declaration")?;let class=match self.object_class.as_str(){"OwnTestImage"=>PublicClass::OwnTestImage,"System32Dll"=>PublicClass::System32Dll,"InstalledSystem32Vcruntime"=>PublicClass::InstalledSystem32Vcruntime,_=>return Err("selected exact original class".into())};Ok(PublicObjectSpec{path:PathBuf::from(&self.path),class,bytes:self.bytes,sha256:hexn(&self.sha256)?,volume:self.volume,file_id:hexn(&self.file_id)?,links:self.links,owner_sid:hex::decode(&self.owner_sid_hex).map_err(|_|"selected SID hex")?,dacl_sha256:hexn(&self.dacl_sha256)?})}}
#[derive(Clone,Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub(crate) struct Action{pub kind:String,pub image:String,pub arguments:Vec<String>,pub working_directory:String}
#[derive(Clone,Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub(crate) struct Plan{pub schema:String,pub ordinary_sid:String,pub unresolved:Vec<String>,pub inputs:Vec<Pin>,pub absences:Vec<String>,pub action:Action,pub output_prefix:String,pub child_environment:BTreeMap<String,String>}
#[derive(Serialize,Deserialize)]#[serde(deny_unknown_fields)]pub(crate) struct Recipe{
 pub scope:String,pub decision_sha256:String,pub operation:String,pub campaign:String,
 pub producer_objects:Vec<Pin>,pub evidence_inputs:Vec<Pin>,pub absences:Vec<String>,
 pub producer_capture_path:String,pub producer_admission_path:String,pub producer_abi_path:String,pub producer_abi_results_path:String,
 pub startup_admission_path:Option<String>,pub startup_controls_path:Option<String>,
 pub installed_crt_registration_path:Option<String>,
 pub child_objects:Vec<Pin>,pub child_image:Option<String>,pub child_capture_path:Option<String>,pub provider_manifest_path:Option<String>,pub child_admission_path:Option<String>,pub child_abi_path:Option<String>,pub child_abi_results_path:Option<String>,pub application_context_path:Option<String>,pub application:Option<Plan>,pub anchor_output:Option<String>,pub output_prefix:String,
}
pub(crate) fn hexn<const N:usize>(s:&str)->Result<[u8;N]>{need(s.len()==N*2&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"canonical fixed lowercase hex")?;let value:[u8;N]=hex::decode(s).map_err(|_|"hex")?.try_into().map_err(|_|"hex width")?;need(value!=[0;N],"nonzero selected digest/identity")?;Ok(value)}
pub(crate) fn strict(s:&str)->Result<()>{let b=s.as_bytes();need((4..=4096).contains(&b.len())&&b[0].is_ascii_uppercase()&&b[1]==b':'&&b[2]==b'\\'&&s.is_ascii()&&!b.iter().any(|b|*b<32)&&!s.contains('/'),"canonical literal local drive path")?;for p in s[3..].split('\\'){let stem=p.split('.').next().unwrap_or("").to_ascii_uppercase();need(!p.is_empty()&&p!="."&&p!=".."&&!p.ends_with(['.',' '])&&!p.contains(':')&&!["CON","PRN","AUX","NUL","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9","LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"].contains(&stem.as_str()),"literal source-owned path components")?}Ok(())}
fn read(f:&std::fs::File,cap:u64)->Result<Vec<u8>>{let mut f=f;f.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;let mut out=Vec::new();let mut buffer=[0u8;65536];loop{let n=f.read(&mut buffer).map_err(|e|e.to_string())?;if n==0{break}need(out.len() as u64+n as u64<=cap,"bounded original read before allocation")?;out.extend_from_slice(&buffer[..n])}Ok(out)}
pub(crate) fn text<'a>(v:&'a Value,k:&str)->Result<&'a str>{v.get(k).and_then(Value::as_str).ok_or_else(||format!("exact admission text {k}"))}
pub(crate) fn array<'a>(v:&'a Value,k:&str,cap:usize)->Result<&'a Vec<Value>>{let rows=v.get(k).and_then(Value::as_array).ok_or_else(||format!("exact admission array {k}"))?;need(rows.len()<=cap,"admission array bound")?;Ok(rows)}
fn tuple(v:&Value,p:&Pin)->Result<()>{for(k,s)in [("path",p.path.as_str()),("sha256",p.sha256.as_str()),("file_id",p.file_id.as_str())]{need(text(v,k)?==s,"actual admitted original tuple")?}need(v["bytes"]==p.bytes&&v["volume"]==p.volume&&v["links"]==1,"actual admitted original size/volume/link")}
pub(crate) struct Held{pub(crate) pin:Pin,owner:OriginalPublicFile,bytes:Vec<u8>}
impl Held{fn open(pin:Pin,user:&[u8])->Result<Self>{Self::open_registered(pin,user,None)}fn open_registered(pin:Pin,user:&[u8],authority:Option<&crate::installed_vcruntime::Authority>)->Result<Self>{let mut owner=OriginalPublicFile::open_registered(pin.spec()?,user,authority)?;let acquisition:Result<Vec<u8>>=(||{let bytes=read(owner.original_file()?,pin.bytes)?;need(bytes.len() as u64==pin.bytes&&sha(&bytes)==pin.sha256,"entire held original content")?;Ok(bytes)})();match acquisition{Ok(bytes)=>Ok(Self{pin,owner,bytes}),Err(e)=>{let close=owner.close_checked();Err(format!("retained original acquisition={e}; close={close:?}"))}}}fn recheck(&self)->Result<()>{self.owner.recheck()}fn close(&mut self)->Result<()>{self.owner.close_checked()}}
struct Absence{path:String,parent:NativeFile}
impl Absence{fn open(path:&str)->Result<Self>{strict(path)?;let parent=Path::new(path).parent().ok_or("absence parent")?;let native=NativeFile::open(parent,0x20000|0x80|1,3,0x200000|0x02000000)?;let a=Self{path:path.into(),parent:native};a.recheck()?;Ok(a)}fn recheck(&self)->Result<()>{self.parent.raw()?;match NativeFile::open(Path::new(&self.path),0x80|0x20000,1,0x200000){Ok(mut exists)=>{let close=exists.close_checked();Err(format!("required redirect/activation absence exists; close={close:?}"))},Err(e)=>{need(e=="TEST owned native open refused: 2",&format!("only exact original not-found absence; {e}"))}}}fn close(&mut self)->Result<()>{self.parent.close_checked()}}
pub(crate) struct Policy{pub(crate) recipe:Recipe,pub(crate) raw:Vec<u8>,recipe_original:Held,pub(crate) own:String,pub(crate) token:OwnTokenFacts,held:Vec<Held>,absences:Vec<Absence>,pub(crate) producer_pe:pe::Capsule,pub(crate) source:[u8;32],pub(crate) campaign:[u8;32],pub(crate) lease:Option<OwnExecutionLease>,installed_crt:Option<crate::installed_vcruntime::Authority>,closed:bool}
impl Policy{
 pub(crate) fn acquire()->Result<Self>{
  #[cfg(all(test,feature="testvalue-window"))]
  crate::bootstrap::targeted_startup_policy_failure_controls::acquisition_entered();
  let own=std::env::current_exe().map_err(|e|e.to_string())?.to_str().ok_or("native A ASCII image")?.to_owned();strict(&own)?;need(Path::new(&own).file_name().and_then(|s|s.to_str())==Some("mutiny-wallet-root-native-test.exe"),"fresh monolithic native A target; no old managed identity")?;
  let token=own_native_token::observe_own()?;need(token.user_sid==SID&&!token.app_container&&!token.restricted&&!token.elevated,"actual approved ordinary TEST1001 native role")?;
  let recipe_path=Path::new(&own).parent().unwrap().join("ROOT-NATIVE-TEST-BOOTSTRAP.json");let mut initial=NativeFile::open(&recipe_path,0x80000000|0x20000|0x80,1,0x200000)?;
  let capture:Result<Held>=(||{let file=initial.file()?;let mut old:BY_HANDLE_FILE_INFORMATION=unsafe{zeroed()};let mut id:FILE_ID_INFO=unsafe{zeroed()};need(unsafe{GetFileInformationByHandle(file.as_raw_handle(),&mut old)}!=0&&unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),FileIdInfo,(&mut id as *mut FILE_ID_INFO).cast(),size_of::<FILE_ID_INFO>() as u32)}!=0&&old.nNumberOfLinks==1&&old.dwFileAttributes&0x410==0,"source-owned original protected public recipe metadata")?;let (owner,dacl)=pipe::security(file.as_raw_handle(),1,&token.user_sid,true)?;let bytes=read(file,524288)?;need(bytes.len()>=64,"source-owned recipe byte minimum")?;let pin=Pin{path:recipe_path.to_str().ok_or("recipe ASCII")?.into(),bytes:bytes.len() as u64,sha256:sha(&bytes),volume:id.VolumeSerialNumber,file_id:hex::encode(id.FileId.Identifier),links:1,owner_sid_hex:hex::encode(owner),dacl_sha256:hex::encode(dacl),object_class:"OwnTestImage".into()};let held=Held::open(pin,&token.user_sid)?;need(held.bytes==bytes,"same first retained source-owned recipe original")?;Ok(held)})();let close=initial.close_checked();let mut original=match(capture,close){(Ok(h),Ok(()))=>h,(a,b)=>return Err(format!("original source-owned recipe={:?}; consuming initial close={b:?}",a.as_ref().err()))};
  let recipe:Recipe=serde_json::from_slice(&original.bytes).map_err(|e|e.to_string())?;need(recipe.scope=="SOURCE_OWNED_NATIVE_TEST_ROOT_BOOTSTRAP_V5"&&recipe.decision_sha256==DECISION&&["QUALIFY_STARTUP","FORM_CHILD_ANCHOR","TEST_PREPARE","TEST_REOPEN"].contains(&recipe.operation.as_str()),"four finite native source-owned TEST operations")?;let campaign=hexn(&recipe.campaign)?;
  need((2..=512).contains(&recipe.producer_objects.len())&&recipe.evidence_inputs.len()<=64&&recipe.child_objects.len()<=512&&recipe.absences.len()<=128,"finite original policy sets")?;
  // Finite data inputs contain only explicitly selected public records. A
  // recipe cannot cause provider, private capture or signer-file acquisition.
  let own_dir=Path::new(&own).parent().unwrap();let evidence_dir=own_dir.join("evidence");let mut evidence=BTreeSet::from([recipe.producer_capture_path.as_str(),recipe.producer_admission_path.as_str(),recipe.producer_abi_path.as_str(),recipe.producer_abi_results_path.as_str()]);for p in [&recipe.startup_admission_path,&recipe.startup_controls_path,&recipe.child_capture_path,&recipe.provider_manifest_path,&recipe.child_admission_path,&recipe.child_abi_path,&recipe.child_abi_results_path,&recipe.application_context_path,&recipe.installed_crt_registration_path]{if let Some(p)=p.as_deref(){evidence.insert(p);}}
  for path in &evidence{strict(path)?;need(Path::new(path).parent()==Some(evidence_dir.as_path())&&Path::new(path).extension().and_then(|s|s.to_str())==Some("json"),"only exact public JSON records in own evidence directory")?;}
  let mut record_seen=BTreeSet::new();for p in &recipe.evidence_inputs{need(p.object_class=="OwnTestImage"&&evidence.contains(p.path.as_str())&&record_seen.insert(p.path.as_str()),"exact finite public evidence roles, no unrelated custody files")?;}need(record_seen==evidence,"every selected evidence record has one pinned original")?;
  need(recipe.producer_objects.iter().all(|p|p.path==own&&p.object_class=="OwnTestImage"||p.path!=own&&(p.object_class=="System32Dll"||p.object_class==crate::installed_vcruntime::CLASS)),"producer native role membership before acquisition")?;
  if recipe.operation=="QUALIFY_STARTUP"||recipe.operation=="FORM_CHILD_ANCHOR"{need(recipe.child_objects.is_empty()&&recipe.child_image.is_none()&&recipe.child_capture_path.is_none()&&recipe.provider_manifest_path.is_none()&&recipe.child_admission_path.is_none()&&recipe.child_abi_path.is_none()&&recipe.child_abi_results_path.is_none()&&recipe.application_context_path.is_none()&&recipe.application.is_none(),"startup qualification/anchor require no child artifact, provider or private inputs")?;}else{let child=recipe.child_image.as_deref().ok_or("actual admitted TEST child image required")?;strict(child)?;need(Path::new(child).file_name().and_then(|p|p.to_str())==Some("mutiny-wallet-v8-testvalue.exe")&&recipe.child_objects.iter().all(|p|p.path==child&&p.object_class=="OwnTestImage"||p.path!=child&&p.object_class=="System32Dll"),"only actual public child application and System32 native objects before acquisition")?;}
  // The one new class is A-only and provider-free. Its protected registration,
  // source/artifact/ABI records are acquired and authenticated before opening
  // the installed CRT original; all existing class routes keep their order.
  let crt_rows=recipe.producer_objects.iter().filter(|p|p.object_class==crate::installed_vcruntime::CLASS).collect::<Vec<_>>();
  let mut held:Vec<Held>=Vec::new();let mut budget=0u64;let mut installed_crt=None;
  if !crt_rows.is_empty()||recipe.installed_crt_registration_path.is_some(){
   let acquisition:Result<crate::installed_vcruntime::Authority>=(||{
    need(recipe.operation=="QUALIFY_STARTUP"&&crt_rows.len()==1&&recipe.installed_crt_registration_path.is_some()
     &&recipe.anchor_output.is_none(),"Installed CRT requires exactly one A-only QUALIFY_STARTUP registration; no anchor/provider operation")?;
    let registration_path=recipe.installed_crt_registration_path.as_deref().unwrap();
    let paths=[recipe.producer_capture_path.as_str(),recipe.producer_admission_path.as_str(),recipe.producer_abi_path.as_str(),recipe.producer_abi_results_path.as_str(),registration_path];
    let mut prefetched=BTreeSet::new();
    for path in paths{
     need(prefetched.insert(path),"Installed CRT registration has distinct exact evidence roles")?;
     let pin=recipe.evidence_inputs.iter().find(|p|p.path==path).ok_or("Installed CRT selected protected evidence absent")?;
     budget=budget.checked_add(pin.bytes).ok_or("whole input overflow")?;need(budget<=2147483648,"whole original policy byte budget")?;
     held.push(Held::open(pin.clone(),&token.user_sid)?);
    }
    let find=|path:&str|held.iter().find(|h|h.pin.path==path).ok_or("Installed CRT retained evidence absent");
    let source=hash(&find(&recipe.producer_capture_path)?.bytes);
    let artifact:Value=serde_json::from_slice(&find(&recipe.producer_admission_path)?.bytes).map_err(|e|e.to_string())?;
    let own_pin=recipe.producer_objects.iter().find(|p|p.path==own&&p.object_class=="OwnTestImage").ok_or("Installed CRT own producer declaration absent")?;
    need(artifact["scope"]=="ROOT_ADMITTED_NATIVE_TEST_ROOT_PRODUCER_ARTIFACT"&&artifact["compiled_source_sha256"]==hex::encode(source)
     &&artifact["profile_test"]==false&&artifact["normal_shipping"]==false&&artifact["target_name"]=="mutiny-wallet-root-native-test",
     "Installed CRT actual ordinary native TEST producer artifact context")?;tuple(&artifact,own_pin)?;features(&artifact)?;
    let authority=crate::installed_vcruntime::authenticate(&find(registration_path)?.bytes,&source,own_pin,&artifact,
     &find(&recipe.producer_abi_path)?.bytes,&find(&recipe.producer_abi_results_path)?.bytes)?;
    authority.require_spec(&crt_rows[0].spec()?)?;Ok(authority)
   })();
   match acquisition{
    Ok(authority)=>installed_crt=Some(authority),
    Err(primary)=>{
     let mut errors=Vec::new();for h in held.iter_mut().rev(){if let Err(e)=h.close(){errors.push(e)}}
     let recipe_close=original.close();
     #[cfg(all(test,feature="testvalue-window"))]
     if let Err(e)=crate::bootstrap::targeted_startup_policy_failure_controls::crt_recipe_closed(&original.pin.sha256,recipe_close.is_ok()){errors.push(e)}
     if let Err(e)=recipe_close{errors.push(e)}
     if !errors.is_empty(){crate::owned::mark_unknown();}
     return Err(format!("Installed CRT provenance refused {primary}; independent closure={errors:?}"));
    }
   }
  }
  // Prefetch has its independent before-allocation bound; this loop retains
  // the original total declared-role byte accounting, including duplicates.
  budget=0;let mut seen=held.iter().map(|h|h.pin.path.to_ascii_lowercase()).collect::<BTreeSet<_>>();for p in recipe.producer_objects.iter().chain(recipe.evidence_inputs.iter()).chain(recipe.child_objects.iter()){budget=budget.checked_add(p.bytes).ok_or("whole input overflow")?;need(budget<=2147483648,"whole original policy byte budget")?;if seen.insert(p.path.to_ascii_lowercase()){need(seen.len()<=512,"whole original input count cap before acquisition")?;held.push(Held::open_registered(p.clone(),&token.user_sid,installed_crt.as_ref())?)}else{need(held.iter().any(|h|h.pin.path==p.path&&serde_json::to_vec(&h.pin).ok()==serde_json::to_vec(p).ok()),"duplicate roles must name same exact original")?}}
  need(recipe.producer_objects.iter().filter(|p|p.path==own&&p.object_class=="OwnTestImage"&&p.links==1).count()==1&&recipe.producer_objects.iter().all(|p|p.path==own||p.object_class=="System32Dll"||p.object_class==crate::installed_vcruntime::CLASS),"monolithic native producer own and System32 only")?;
  let mut objects=Vec::new();for p in &recipe.producer_objects{objects.push(pe::parse(&p.path,&held.iter().find(|h|h.pin.path==p.path).ok_or("original producer input")?.bytes)?)}let producer_pe=pe::capsule(objects,&own)?;let source=hash(&held.iter().find(|h|h.pin.path==recipe.producer_capture_path).ok_or("held producer full capture")?.bytes);
  let mut absences=Vec::new();need(recipe.absences.contains(&(own.clone()+".local")),"native own .local absence selected before child creation")?;for p in &recipe.absences{need(!absences.iter().any(|a:&Absence|a.path.eq_ignore_ascii_case(p)),"unique activation absences")?;need(held.iter().any(|h|Path::new(&h.pin.path).parent()==Path::new(p).parent()),"absence parent held through exact original input ancestors")?;absences.push(Absence::open(p)?)}
  let mut owner=Self{raw:original.bytes.clone(),recipe,recipe_original:original,own,token,held,absences,producer_pe,source,campaign,lease:None,installed_crt,closed:false};let admission=owner.admit_producer();if let Err(e)=admission{let close=owner.close_checked();return Err(format!("native producer admission={e}; closure={close:?}"))}Ok(owner)
 }
 pub(crate) fn bytes(&self,path:&str)->Result<&[u8]>{let h=self.held.iter().find(|h|h.pin.path==path).ok_or_else(||format!("not retained selected evidence {path}"))?;h.recheck()?;Ok(&h.bytes)}
 pub(crate) fn record(&self,path:&str)->Result<Value>{let b=self.bytes(path)?;need(b.len()<=16777216,"actual evidence aggregate bound")?;serde_json::from_slice(b).map_err(|e|e.to_string())}
 pub(crate) fn own_pin(&self)->Result<&Pin>{self.recipe.producer_objects.iter().find(|p|p.path==self.own).ok_or("actual native issuer original".to_string())}
 fn admit_producer(&mut self)->Result<()>{let capture=self.record(&self.recipe.producer_capture_path)?;complete_capture(&capture)?;let a=self.record(&self.recipe.producer_admission_path)?;need(text(&a,"scope")?=="ROOT_ADMITTED_NATIVE_TEST_ROOT_PRODUCER_ARTIFACT"&&a["compiled_source_sha256"]==hex::encode(self.source)&&a["producer_kind"]=="monolithic_native_test_root"&&a["operative_payload_role"]=="same_native_executable"&&a["payload_distinct_file"]==false&&a["profile_test"]==false&&a["normal_shipping"]==false&&a["target_name"]=="mutiny-wallet-root-native-test","fresh actual native producer source/artifact admission")?;tuple(&a,self.own_pin()?)?;features(&a)?;verify_abi(self,&self.recipe.producer_abi_path,&self.recipe.producer_abi_results_path,&hex::encode(self.source),&self.producer_pe)?;
  let(slots,exports)=self.producer_pe.native_inputs()?;let inputs=AdmittedTestInputs{own_image:PathBuf::from(&self.own),original_objects:self.recipe.producer_objects.iter().map(Pin::spec).collect::<Result<Vec<_>>>()?,installed_crt:self.installed_crt.clone(),complete_slots:slots,full_parsed_exports:exports,selected_comparator_direct_rva:self.producer_pe.comparator()?,source_sha256:self.source,immutable_campaign:self.campaign,expected_primary_token:self.token.clone()};
  // This private source-owned factory has just evaluated originals, complete
  // PE context, actual admitted same-source ABI and the original own token.
  #[cfg(all(test,feature="testvalue-window"))]
  crate::bootstrap::targeted_startup_policy_failure_controls::factory_boundary()?;
  self.lease=Some(unsafe{OwnExecutionLease::open_admitted_test(inputs)}?);self.require()
 }
 pub(crate) fn require(&self)->Result<()>{crate::owned::known()?;if let Some(authority)=self.installed_crt.as_ref(){need(self.recipe.operation=="QUALIFY_STARTUP","Installed CRT authority cannot enter provider/anchor operations")?;authority.require_context(&self.source,&hexn::<32>(&self.own_pin()?.sha256)?)?;}need(!self.closed&&own_native_token::observe_own()?==self.token,"same native producer process/complete primary token")?;self.recipe_original.recheck()?;for h in &self.held{h.recheck()?}for a in &self.absences{a.recheck()?}self.lease.as_ref().ok_or("genuine native own qualification owner absent")?.require_custody_context(&self.source,&self.campaign)}
 pub(crate) fn startup_hash(&self)->Result<String>{Ok(sha(&serde_json::to_vec(&self.recipe.producer_objects).map_err(|e|e.to_string())?))}
 pub(crate) fn admit_startup(&self)->Result<Value>{self.require()?;let a=self.record(self.recipe.startup_admission_path.as_deref().ok_or("actual independently selected native startup admission required")?)?;let controls_path=self.recipe.startup_controls_path.as_deref().ok_or("actual closed native startup controls required")?;let c=self.record(controls_path)?;need(a["scope"]=="ROOT_ADMITTED_SOURCE_OWNED_NATIVE_TEST_PRODUCER_STARTUP_V5"&&a["decision_sha256"]==DECISION&&a["startup_inputs_sha256"]==self.startup_hash()?&&a["controls_sha256"]==sha(self.bytes(controls_path)?)&&a["compiled_source_sha256"]==hex::encode(self.source),"actual reviewed native startup admission domains")?;tuple(&a["producer_image"],self.own_pin()?)?;need(c["scope"]=="SOURCE_OWNED_NATIVE_TEST_STARTUP_CONTROLS_CLOSED_V5"&&c["startup_inputs_sha256"]==self.startup_hash()?&&c["compiled_source_sha256"]==hex::encode(self.source)&&c["producer_image_sha256"]==self.own_pin()?.sha256&&c["raw_exit"]==0&&c["natural_active_process_zero"]==true&&c["channel_complete"]==true&&array(&c,"independent_close_errors",128)?.is_empty()&&c["producer_kind"]=="monolithic_native_test_root"&&c["clr_qualified"]==false,"actual original closed native control job/channel")?;let job=&c["outer_original_job"];need(job["raw_exit"]==0&&job["natural_active_process_zero"]==true&&job["image"]==self.own&&job["job_assignment_before_execution"]==true&&job["inherited_handle_count"]==3&&array(job,"close_errors",128)?.is_empty(),"actual retained native startup job original closure")?;let streams=array(job,"streams",2)?;need(streams.len()==2,"both actual startup original drains")?;for stream in streams{need(stream["eof"]==true&&stream["hash_complete"]==true&&stream["overflow"]==false&&stream["null_drain"]==false&&array(stream,"errors",128)?.is_empty(),"actual native startup entire streams and capture closure")?;}let rows=array(&c,"controls",3)?;let names=["actual_owned_native_startup_and_same_backing","actual_unknown_roster_refused","actual_wrong_original_tuple_refused"];need(rows.len()==3,"exact three native startup controls")?;for(row,name)in rows.iter().zip(names){need(row["name"]==name&&row["actual_passed"]==1,"actual genuine closed native controls")?}Ok(a)}
 pub(crate) fn close_checked(&mut self)->Result<()>{if self.closed{return Ok(())}self.closed=true;let mut errors=Vec::new();if let Some(mut l)=self.lease.take(){if let Err(e)=l.close_checked(){errors.push(e)}}for h in self.held.iter_mut().rev(){if let Err(e)=h.close(){errors.push(e)}}for a in self.absences.iter_mut().rev(){if let Err(e)=a.close(){errors.push(e)}}if let Err(e)=self.recipe_original.close(){errors.push(e)}if !errors.is_empty(){crate::owned::mark_unknown()}need(errors.is_empty(),&format!("native producer independent original closures {errors:?}"))}
}
impl Drop for Policy{fn drop(&mut self){if !self.closed{let _=self.close_checked();}}}
pub(crate) fn features(a:&Value)->Result<()>{
 #[cfg(not(feature="asus-native-test-principal"))]
 {let f=array(a,"features",2)?;need(f.len()==2&&f.iter().filter(|s|*s=="native-owner-test").count()==1&&f.iter().filter(|s|*s=="testvalue-window").count()==1,"exact two native TEST features")}
 #[cfg(feature="asus-native-test-principal")]
 {let f=array(a,"features",3)?;need(f.len()==3&&["native-owner-test","testvalue-window","asus-native-test-principal"].iter().all(|name|f.iter().filter(|s|s.as_str()==Some(*name)).count()==1),"exact three ASUS native TEST features")}
}
pub(crate) const CURRENT_CAPTURE_LOCK_COUNT:usize=17;
fn capture_lock_path(path:&str)->bool{path.rsplit(['/', '\\']).next().is_some_and(|name|name.eq_ignore_ascii_case("Cargo.lock"))}
pub(crate) fn complete_capture(c:&Value)->Result<()>{for key in ["head","tree","source"]{need(!text(c,key)?.is_empty()&&text(c,key)?.len()<=4096,"full compiled source identity")?}need(text(c,"head")?.len()==40&&text(c,"head")?.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()),"actual full source HEAD")?;let rows=array(c,"current_files",4096)?;need(rows.len()>=2454,"complete current source including GUI and native successor")?;let mut seen=BTreeSet::new();for row in rows{let p=text(row,"path")?;need(!p.is_empty()&&p.len()<=4096&&seen.insert(p.to_ascii_lowercase())&&row["bytes"].as_u64().is_some(),"complete unique source row")?;hexn::<32>(text(row,"sha256")?)?;}let locks=array(c,"locks",CURRENT_CAPTURE_LOCK_COUNT)?;need(locks.len()==CURRENT_CAPTURE_LOCK_COUNT,"exact current 17 lock domain")?;let mut lockseen=BTreeSet::new();for lock in locks{let p=text(lock,"path")?;need(capture_lock_path(p)&&lockseen.insert(p.to_ascii_lowercase())&&rows.iter().any(|r|r["path"]==lock["path"]&&r["bytes"]==lock["bytes"]&&r["sha256"]==lock["sha256"]),"each exact lock is a full captured source row")?}let captured_locks=rows.iter().filter_map(|row|row["path"].as_str().filter(|p|capture_lock_path(p)).map(str::to_ascii_lowercase)).collect::<BTreeSet<_>>();need(captured_locks.len()==CURRENT_CAPTURE_LOCK_COUNT&&captured_locks==lockseen,"every current Cargo.lock captured and declared exactly once")?;Ok(())}
fn profile(s:&str,t:&OwnTokenFacts)->Result<()>{need(s.len()<=4096,"bounded actual Rust token profile")?;for(label,value)in [("user_sid",format!("{:?}",t.user_sid)),("integrity_sid",format!("{:?}",t.integrity_sid)),("session",t.session.to_string()),("elevation_type",t.elevation_type.to_string()),("elevated",t.elevated.to_string()),("restricted","false".into()),("app_container","false".into())]{let pattern=format!("{label}: {value}");need(s.matches(&format!("{label}: ")).count()==1&&(s.contains(&format!("{pattern}, "))||s.ends_with(&format!("{pattern} }}"))),"actual Rust ABI exact original TEST token/profile")?}Ok(())}
pub(crate) fn verify_abi(p:&Policy,proof_path:&str,result_path:&str,source:&str,pe:&pe::Capsule)->Result<()>{let proof=p.record(proof_path)?;let r=p.record(result_path)?;let nt=p.held.iter().find(|h|h.pin.path==r"C:\Windows\System32\ntdll.dll").ok_or("held ABI ntdll")?;need(proof["scope"]=="ROOT_ADMITTED_TEST1001_ACTUAL_RUST_NTDLL_ABI"&&proof["source_sha256"]==source&&proof["results_sha256"]==sha(p.bytes(result_path)?)&&proof["ntdll_sha256"]==nt.pin.sha256&&proof["ntdll_file_id"]==nt.pin.file_id&&proof["ntdll_volume"]==nt.pin.volume&&proof["comparator_direct_rva"]==pe.comparator()?,"actual independently admitted same-source ABI and exact direct comparator")?;need(r["scope"]=="RUST_TEST1001_NATIVE_ABI_EVIDENCE_CANDIDATE"&&r["controls_passed"]==true&&r.get("primary").is_some_and(Value::is_null)&&array(&r,"closure_errors",128)?.is_empty(),"actual closed Rust ABI outcomes")?;let commands=array(&r,"commands",4)?;need(commands.len()==4,"actual LIST plus three selector commands")?;for command in commands{need(command["exit"]==0&&command["natural"]==true&&command.get("primary").is_some_and(Value::is_null)&&array(command,"closure_errors",128)?.is_empty(),"actual ABI natural command")?;let streams=array(command,"streams",2)?;need(streams.len()==2,"actual ABI both full streams")?;for stream in streams{need(stream["eof"]==true&&stream["hash_complete"]==true&&stream["overflow"]==false&&stream["null_drain"]==false&&stream.get("error").is_some_and(Value::is_null)&&stream.get("output_error").is_some_and(Value::is_null),"actual ABI whole streams without null drain")?}}let names=["own_native_modules::abi_controls::actual_rust_selected_original_ntdll_positive","own_native_modules::abi_controls::actual_rust_distinct_original_object_nonzero_refused","own_native_modules::abi_controls::actual_rust_genuinely_absent_comparator_export_refused"];let controls=array(&r,"controls",3)?;need(controls.len()==3,"actual three ABI experiments")?;for(c,n)in controls.iter().zip(names){need(c["name"]==n&&c["actual_passed"]==1&&c["failed"]==0&&c["ignored"]==0,"actual genuine ABI selector result")?;profile(text(c,"actual_own_profile")?,&p.token)?}Ok(())}

#[cfg(all(test,feature="testvalue-window"))]
mod complete_capture_lock_domain_controls{
 use super::{complete_capture,CURRENT_CAPTURE_LOCK_COUNT};
 use serde_json::{Value,json};
 // Public synthetic values only. No authentication, original file, token,
 // Policy acquisition, owner, provider, process or runtime admission.
 const LOCK_PATHS:[&str;17]=[
  "clock-native-nts/Cargo.lock","consensus/Cargo.lock","crypto-v2/Cargo.lock",
  "desktop/Cargo.lock","node/Cargo.lock",
  "qualification/crypto-v2-sources/kdf-custody-v1/Cargo.lock",
  "qualification/crypto-v2-sources/kdf-custody-v1/hkdf/Cargo.lock",
  "qualification/crypto-v2-sources/kdf-custody-v1/sha2/Cargo.lock",
  "qualification/crypto-v2-sources/rust-fn-dsa-custody-v2/Cargo.lock",
  "qualification/native-nts-observer-v1/Cargo.lock",
  "qualification/treasury-continuity-service-v1/Cargo.lock",
  "qualification/worker-runtime-probe-v2/Cargo.lock","release-signer/Cargo.lock",
  "transport-v2/Cargo.lock","treasury-application/Cargo.lock",
  "treasury-sqlite-provider/Cargo.lock","wallet-core/Cargo.lock",
 ];
 fn fixture()->Value{
  let locks=LOCK_PATHS.iter().map(|path|json!({"path":path,"bytes":1,"sha256":"11".repeat(32)})).collect::<Vec<_>>();
  let mut rows=locks.clone();
  for index in rows.len()..2556{rows.push(json!({"path":format!("synthetic/file-{index}.rs"),"bytes":1,"sha256":"11".repeat(32)}));}
  json!({"head":"a".repeat(40),"tree":"b".repeat(40),"source":r"D:\synthetic\public-current17","current_files":rows,"locks":locks})
 }
 #[test]
 fn exact_current_seventeen_lock_domain_is_accepted(){
  let capture=fixture();
  assert_eq!(capture["current_files"].as_array().unwrap().len(),2556);
  assert_eq!(capture["locks"].as_array().unwrap().len(),CURRENT_CAPTURE_LOCK_COUNT);
  assert!(complete_capture(&capture).is_ok());
 }
 #[test]
 fn missing_clock_lock_from_sixteen_lock_selection_is_refused(){
  let mut capture=fixture();capture["locks"].as_array_mut().unwrap().remove(0);
  assert!(complete_capture(&capture).is_err());
 }
 #[test]
 fn eighteenth_declared_lock_is_refused(){
  let mut capture=fixture();let extra=json!({"path":"synthetic-extra/Cargo.lock","bytes":1,"sha256":"11".repeat(32)});
  capture["current_files"].as_array_mut().unwrap().push(extra.clone());
  capture["locks"].as_array_mut().unwrap().push(extra);
  assert!(complete_capture(&capture).is_err());
 }
 #[test]
 fn duplicate_lock_replacing_one_current_role_is_refused(){
  let mut capture=fixture();let duplicate=capture["locks"][0].clone();capture["locks"][16]=duplicate;
  assert!(complete_capture(&capture).is_err());
 }
 #[test]
 fn selected_lock_digest_mismatch_is_refused(){
  let mut capture=fixture();capture["locks"][0]["sha256"]=json!("22".repeat(32));
  assert!(complete_capture(&capture).is_err());
 }
 #[test]
 fn selected_lock_byte_extent_mismatch_is_refused(){
  let mut capture=fixture();capture["locks"][0]["bytes"]=json!(2);
  assert!(complete_capture(&capture).is_err());
 }
 #[test]
 fn trimming_clock_lock_from_both_arrays_still_refuses_legacy_sixteen(){
  let mut capture=fixture();capture["locks"].as_array_mut().unwrap().remove(0);
  capture["current_files"].as_array_mut().unwrap().remove(0);
  assert_eq!(capture["current_files"].as_array().unwrap().len(),2555);
  assert!(complete_capture(&capture).is_err());
 }
 #[test]
 fn undeclared_eighteenth_current_file_lock_is_refused(){
  let mut capture=fixture();capture["current_files"].as_array_mut().unwrap().push(json!({"path":"synthetic-extra/Cargo.lock","bytes":1,"sha256":"11".repeat(32)}));
  assert!(complete_capture(&capture).is_err());
 }
 #[test]
 fn unrelated_full_source_row_cannot_replace_a_cargo_lock(){
  let mut capture=fixture();let unrelated=capture["current_files"][17].clone();capture["locks"][0]=unrelated;
  assert!(complete_capture(&capture).is_err());
 }
}

#[cfg(all(test,feature="asus-native-test-principal"))]
mod asus_principal_admission_controls{
 use super::{features,SID};use serde_json::json;
 #[test]fn exact_asus_feature_admission_accepts_only_three_selected_features(){
  assert!(features(&json!({"features":["native-owner-test","testvalue-window","asus-native-test-principal"]})).is_ok());
  for f in [json!(["native-owner-test","testvalue-window"]),json!(["native-owner-test","testvalue-window","asus-native-test-principal","extra"]),json!(["native-owner-test","testvalue-window","testvalue-window"]) ]{assert!(features(&json!({"features":f})).is_err());}
 }
 #[test]fn laptop_principal_is_not_also_admitted_by_asus_fixture(){
  let laptop=[1,5,0,0,0,0,0,5,21,0,0,0,175,69,68,154,43,152,171,101,195,166,27,194,233,3,0,0];
  assert_ne!(SID,laptop);assert_eq!(crate::pipe::sid_text(),"S-1-5-21-468509490-1336819201-2803289875-1005");
 }
}