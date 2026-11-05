//! Private NONSHIPPING RootLaunch receiver. Only the compiled trusted issuer
//! plus its actual OS pipe/process/original/token can author registration.
//! Endpoint/CLI/wire DTO alone cannot select it. Missing actual trusted anchor
//! refuses before provider effects. Root's unsafe TCB remains explicit.
#![cfg(all(windows,target_arch="x86_64",feature="native-owner-test"))]
use super::{own_native_token::{self,OwnTokenFacts,Luid},own_native_files::{PublicObjectSpec,PublicClass,OriginalPublicFile},
 own_native_modules::{OwnLoadedModules,CompleteSlot,RequestedSymbol,ParsedRequestedExport},
 own_native_facade::AdmittedTestInputs,own_native_receiver::{RootSelectedDriverInput,NativeRunOwner},process_auth::Identity};
use serde_json::Value;
use std::{collections::{BTreeMap,BTreeSet},path::PathBuf,sync::atomic::{AtomicBool,Ordering}};
#[path="continuous_root_launch_peer.rs"] mod peer;
#[path="continuous_root_launch_registration.rs"] mod registration;
type Result<T>=std::result::Result<T,String>;
/// Exact issuer original selected by Root in generated, reviewed source. It is
/// not deserializable and has no runtime configuration or environment setter.
struct RootLaunchAnchor{parent:PublicObjectSpec,payload:PublicObjectSpec,user:Vec<u8>}
impl RootLaunchAnchor{
 fn from_compiled_root(parent:PublicObjectSpec,payload:PublicObjectSpec,user:Vec<u8>)->Result<Self>{
  key(&parent.path)?;if parent.class!=PublicClass::OwnTestImage||parent.links!=1||!(64..=134217728).contains(&parent.bytes)
   ||parent.sha256==[0;32]||parent.file_id==[0;16]||parent.dacl_sha256==[0;32]||user.len()<8||user.len()>68||user[0]!=1||user.len()!=8+4*user[1] as usize||parent.owner_sid!=user{
   return Err("Complete compiled trusted Root issuer original required".into());}
  key(&payload.path)?;if payload.class!=PublicClass::OwnTestImage||payload.links!=1||!(64..=134217728).contains(&payload.bytes)||payload.sha256==[0;32]||payload.file_id==[0;16]||payload.owner_sid!=user||payload.dacl_sha256==[0;32]{return Err("Compiled operative Root managed payload original required".into());}Ok(Self{parent,payload,user})
 }
}
fn constant_bytes(text:&str)->Result<Vec<u8>>{if text.len()>136||text.len()%2!=0||!text.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err("Compiled Root byte constant".into());}hex::decode(text).map_err(|e|e.to_string())}
fn constant_hex<const N:usize>(text:&str)->Result<[u8;N]>{constant_bytes(text)?.try_into().map_err(|_|"Compiled Root constant width".into())}
/// Only the independent trusted Root selection assembly can supply this type.
/// It is deliberately not Deserialize, Clone or an ambient installation bool.
pub(super) struct RootLaunchRegistration{
 peer:Identity,parent_token:OwnTokenFacts,parent_original:PublicObjectSpec,
 originals:Vec<PublicObjectSpec>,own_image:PathBuf,compiled_source:[u8;32],source:[u8;32],campaign:[u8;32],
 abi_proof_sha256:[u8;32],abi_results_sha256:[u8;32],comparator_rva:u32,pipe_name:String,
}
impl RootLaunchRegistration{
 /// # Safety
 /// Caller is the trusted Root launcher-selection receiver, independently
 /// authenticated before any public CLI dispatch. It has evaluated actual
 /// closed Rust ABI results, selected original PE input provenance and exact
 /// trusted parent artifact/source/role. Root-owned GuardSession/native facts
 /// remain held. Values may be received ONLY from that authenticated issuer,
 /// then complete live OWN context is checked before constructing the owner.
 /// Untrusted Wallet/public pipe DTOs, GUI, CLI, PID-only lookup, receipt hash
 /// and eligibility flags never meet this obligation. Incomplete input refuses.
 pub(super) unsafe fn from_root_selected_context(peer:Identity,parent_token:OwnTokenFacts,parent_original:PublicObjectSpec,
  originals:Vec<PublicObjectSpec>,own_image:PathBuf,compiled_source:[u8;32],provider_manifest_sha256:[u8;32],campaign:[u8;32],abi_proof_sha256:[u8;32],
  abi_results_sha256:[u8;32],comparator_rva:u32,pipe_name:String)->Result<Self>{
  if originals.len()<2||originals.len()>512||compiled_source==[0;32]||provider_manifest_sha256==[0;32]||campaign==[0;32]||abi_proof_sha256==[0;32]
   ||abi_results_sha256==[0;32]||comparator_rva<4096||peer.pid==0||peer.start_filetime==0
   ||peer.pid!=parent_token.pid||peer.start_filetime!=parent_token.process_start_filetime
   ||peer.user_sid!=parent_token.user_sid||peer.session!=parent_token.session
   ||peer.authentication_luid!=(parent_token.authentication_id.low,parent_token.authentication_id.high)
   ||peer.image_path!=parent_original.path||peer.image_sha256!=parent_original.sha256
   ||parent_original.class!=PublicClass::OwnTestImage||parent_original.links!=1||parent_token.restricted||parent_token.app_container{
   return Err("Complete independently trusted Root launch context required".into());}
  let prefix=format!(r"\\.\pipe\Mutiny-RootLaunch-{}-",hex::encode(campaign));
  if !pipe_name.starts_with(&prefix)||pipe_name.len()!=prefix.len()+32
   ||!pipe_name[prefix.len()..].bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()){
   return Err("Exact selected Root local endpoint".into());}
  let mut seen=BTreeSet::new();let mut bytes=0u64;
  for spec in &originals{if !seen.insert(key(&spec.path)?)||!(64..=134217728).contains(&spec.bytes){return Err("Root original universe uniqueness/size".into());}
   bytes=bytes.checked_add(spec.bytes).ok_or("Root original byte overflow")?;if bytes>536870912{return Err("Root selected whole byte cap".into());}}
  if originals.iter().filter(|s|s.path==own_image&&s.class==PublicClass::OwnTestImage&&s.links==1).count()!=1
   ||originals.iter().filter(|s|s.path==PathBuf::from(r"C:\Windows\System32\ntdll.dll")&&s.class==PublicClass::System32Dll).count()!=1{
   return Err("Exact Root selected own image/comparator".into());}
  Ok(Self{peer,parent_token,parent_original,originals,own_image,compiled_source,source:provider_manifest_sha256,campaign,abi_proof_sha256,abi_results_sha256,comparator_rva,pipe_name})
 }
}
fn key(path:&std::path::Path)->Result<String>{let text=path.to_str().ok_or("Root ASCII native path")?;
 if !path.is_absolute()||text.len()>4096||!text.is_ascii()||text.bytes().any(|c|c<32)||text.contains('\0'){
  return Err("Root absolute native path bound".into());}Ok(text.replace('/',"\\").to_ascii_lowercase())}
fn s<'a>(v:&'a Value,k:&str,cap:usize)->Result<&'a str>{let text=v.get(k).and_then(Value::as_str).ok_or_else(||format!("Root field {k}"))?;
 if text.len()>cap||!text.is_ascii()||text.bytes().any(|b|b<32){return Err(format!("Root text bound {k}"));}Ok(text)}
fn n(v:&Value,k:&str)->Result<u64>{v.get(k).and_then(Value::as_u64).ok_or_else(||format!("Root unsigned field {k}"))}
fn b(v:&Value,k:&str)->Result<bool>{v.get(k).and_then(Value::as_bool).ok_or_else(||format!("Root boolean field {k}"))}
fn array<'a>(v:&'a Value,k:&str,cap:usize)->Result<&'a Vec<Value>>{let a=v.get(k).and_then(Value::as_array).ok_or_else(||format!("Root array {k}"))?;if a.len()>cap{return Err(format!("Root array bound {k}"));}Ok(a)}
fn hash<const N:usize>(v:&Value,k:&str)->Result<[u8;N]>{let text=s(v,k,N*2)?;if text.len()!=N*2||!text.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c)){return Err("Root exact lowercase hex".into());}hex::decode(text).map_err(|e|e.to_string())?.try_into().map_err(|_|"Root exact hex width".into())}
fn u32n(v:&Value,k:&str)->Result<u32>{n(v,k)?.try_into().map_err(|_|format!("Root u32 field {k}"))}
fn i32n(v:&Value,k:&str)->Result<i32>{v.get(k).and_then(Value::as_i64).ok_or("Root signed field")?.try_into().map_err(|_|"Root i32 width".into())}
fn sid(v:&Value,k:&str)->Result<Vec<u8>>{let text=s(v,k,136)?;let bytes=hex::decode(text).map_err(|_|"Root SID hex")?;
 if bytes.len()<8||bytes.len()>68||bytes[0]!=1||bytes[1]>15||bytes.len()!=8+4*bytes[1] as usize{return Err("Root bounded binary SID".into());}Ok(bytes)}
fn token(v:&Value)->Result<OwnTokenFacts>{Ok(OwnTokenFacts{pid:u32n(v,"pid")?,process_start_filetime:n(v,"process_start_filetime")?,user_sid:sid(v,"user_sid_hex")?,
 token_id:Luid{low:u32n(v,"token_id_low")?,high:i32n(v,"token_id_high")?},authentication_id:Luid{low:u32n(v,"authentication_id_low")?,high:i32n(v,"authentication_id_high")?},modified_id:Luid{low:u32n(v,"modified_id_low")?,high:i32n(v,"modified_id_high")?},session:u32n(v,"session")?,elevation_type:u32n(v,"elevation_type")?,elevated:b(v,"elevated")?,integrity_sid:sid(v,"integrity_sid_hex")?,restricted:b(v,"restricted")?,app_container:b(v,"app_container")?})}
fn sum(text:&mut usize,count:usize)->Result<()>{*text=text.checked_add(count).ok_or("Root aggregate text overflow")?;if *text>16777216{return Err("Root aggregate declaration text cap".into());}Ok(())}
fn symbol(v:&Value,text:&mut usize)->Result<RequestedSymbol>{match(v.get("Name"),v.get("Ordinal")){
 (Some(Value::String(name)),Some(Value::Null)) if !name.is_empty()&&name.len()<=4096&&name.is_ascii()&&name.bytes().all(|c|(33..127).contains(&c))=>{sum(text,name.len())?;Ok(RequestedSymbol::Named(name.clone()))},
 (Some(Value::Null),Some(ordinal))=>{let ordinal=ordinal.as_u64().ok_or("Root ordinal")?;if ordinal==0||ordinal>65535{return Err("Root ordinal width".into());}Ok(RequestedSymbol::Ordinal(ordinal as u16))},
 _=>Err("Root exact named/ordinal symbol".into())}}
fn verify_abi(v:&Value,registration:&RootLaunchRegistration)->Result<()>{
 let proof_hex=s(v,"abi_proof_bytes_hex",4194304)?;let result_hex=s(v,"abi_results_bytes_hex",4194304)?;
 if proof_hex.len()%2!=0||result_hex.len()%2!=0{return Err("Root ABI original buffer hex width".into());}
 let proof_bytes=hex::decode(proof_hex).map_err(|_|"Root ABI original proof buffer")?;let result_bytes=hex::decode(result_hex).map_err(|_|"Root ABI original results buffer")?;
 use sha2::{Digest,Sha256};
 // Exact selected record digests are evaluated together with actual outcomes;
 // they do not supply authority independently of this authenticated Root peer.
 if <[u8;32]>::from(Sha256::digest(&proof_bytes))!=registration.abi_proof_sha256
  ||<[u8;32]>::from(Sha256::digest(&result_bytes))!=registration.abi_results_sha256{
  return Err("Root selected original ABI record buffers changed".into());}
 let proof:Value=serde_json::from_slice(&proof_bytes).map_err(|e|e.to_string())?;let result:Value=serde_json::from_slice(&result_bytes).map_err(|e|e.to_string())?;
 let proof=&proof;let result=&result;
 if s(proof,"scope",128)?!="ROOT_ADMITTED_TEST1001_ACTUAL_RUST_NTDLL_ABI"||hash::<32>(proof,"source_sha256")?!=registration.compiled_source
  ||u32n(proof,"comparator_direct_rva")?!=registration.comparator_rva
  ||s(result,"scope",128)?!="RUST_TEST1001_NATIVE_ABI_EVIDENCE_CANDIDATE"||!b(result,"controls_passed")?
  ||!result.get("primary").is_some_and(Value::is_null)||!array(result,"closure_errors",128)?.is_empty(){return Err("Actual admitted Root Rust ABI outcomes required".into());}
 let nt=registration.originals.iter().find(|p|p.path==PathBuf::from(r"C:\Windows\System32\ntdll.dll")).ok_or("Selected ntdll absent")?;
 if hash::<32>(proof,"ntdll_sha256")?!=nt.sha256||hash::<16>(proof,"ntdll_file_id")?!=nt.file_id||n(proof,"ntdll_volume")?!=nt.volume{return Err("Root comparator original profile mismatch".into());}
 let commands=array(result,"commands",4)?;if commands.len()!=4{return Err("Actual LIST plus3 native ABI commands".into());}
 for command in commands{if n(command,"exit")?!=0||!b(command,"natural")?||!command.get("primary").is_some_and(Value::is_null)||!array(command,"closure_errors",128)?.is_empty(){return Err("Root ABI original command/closure".into());}
  let streams=array(command,"streams",2)?;if streams.len()!=2{return Err("Root ABI both streams".into());}for stream in streams{if !b(stream,"eof")?||!b(stream,"hash_complete")?||b(stream,"overflow")?||b(stream,"null_drain")?||!stream.get("error").is_some_and(Value::is_null)||!stream.get("output_error").is_some_and(Value::is_null){return Err("Root ABI full natural streams".into());}}}
 let controls=array(result,"controls",3)?;let names=["own_native_modules::abi_controls::actual_rust_selected_original_ntdll_positive","own_native_modules::abi_controls::actual_rust_distinct_original_object_nonzero_refused","own_native_modules::abi_controls::actual_rust_genuinely_absent_comparator_export_refused"];
 if controls.len()!=3{return Err("Three actual Rust ABI controls".into());}for(control,name)in controls.iter().zip(names){if s(control,"name",256)?!=name||n(control,"actual_passed")?!=1||n(control,"failed")?!=0||n(control,"ignored")?!=0{return Err("Root actual genuine ABI control mismatch".into());}}
 Ok(())
}
fn decode_complete(v:&Value,r:&RootLaunchRegistration,modules:&OwnLoadedModules,own_token:&OwnTokenFacts)->Result<AdmittedTestInputs>{
 if s(v,"scope",128)?!="AUTHENTICATED_ROOT_TEST1001_LIVE_CHILD_SELECTION"||hash::<32>(v,"compiled_source_capture_sha256")?!=r.compiled_source||hash::<32>(v,"provider_source_manifest_sha256")?!=r.source||hash::<32>(v,"campaign")?!=r.campaign
  ||PathBuf::from(s(v,"own_image",4096)?)!=r.own_image||PathBuf::from(s(v,"parent_image",4096)?)!=r.peer.image_path||hash::<32>(v,"parent_image_sha256")?!=r.peer.image_sha256
  ||token(v.get("parent_token").ok_or("Root parent token absent")?)?!=r.parent_token||token(v.get("child_token").ok_or("Root actual child token absent")?)?!=*own_token
  ||u32n(v,"comparator_direct_rva")?!=r.comparator_rva{return Err("Root live selected process/source/campaign context differs".into());}
 verify_abi(v,r)?;
 let selected=array(v,"original_objects",512)?;let mut objects=Vec::with_capacity(selected.len());let mut selected_paths=BTreeSet::new();
 let actual:BTreeSet<_>=modules.observations().iter().map(|p|key(&p.path)).collect::<Result<_>>()?;
 for row in selected{let path=PathBuf::from(s(row,"path",4096)?);let k=key(&path)?;if !selected_paths.insert(k.clone())||!actual.contains(&k){return Err("Root selection contains absent/duplicate OWN module".into());}
  let original=r.originals.iter().find(|p|p.path==path).ok_or("Root unknown native original; no file opened")?;
  let class=match s(row,"object_class",64)?{"OwnTestImage"=>PublicClass::OwnTestImage,"System32Dll"=>PublicClass::System32Dll,_=>return Err("Root original class".into())};
  if n(row,"bytes")?!=original.bytes||hash::<32>(row,"sha256")?!=original.sha256||n(row,"volume")?!=original.volume||hash::<16>(row,"file_id")?!=original.file_id
   ||u32n(row,"links")?!=original.links||sid(row,"owner_sid_hex")?!=original.owner_sid||hash::<32>(row,"dacl_sha256")?!=original.dacl_sha256||class!=original.class{return Err("Root original native tuple differs from independently selected universe".into());}objects.push(original.clone());
 }
 if selected_paths!=actual{return Err("Root selection does not cover complete OWN roster".into());}
 let pe=v.get("pe").ok_or("Root complete PE context absent")?;let parsed=array(pe,"Objects",512)?;if parsed.len()!=objects.len(){return Err("Root complete original PE roster".into());}
 let mut paths=BTreeSet::new();let mut slots=Vec::new();let mut exports=Vec::new();let mut text=0usize;let mut unique_slots=BTreeSet::new();let mut unique_exports=BTreeSet::new();
 for module in parsed{let path=PathBuf::from(s(module,"Path",4096)?);let k=key(&path)?;sum(&mut text,k.len())?;if !paths.insert(k.clone())||!selected_paths.contains(&k){return Err("Root PE table original membership".into());}
  let original=objects.iter().find(|p|p.path==path).ok_or("Root PE original path")?;let image=u32n(module,"ImageBytes")?;
  if hash::<32>(module,"Sha256")?!=original.sha256||n(module,"FileBytes")?!=original.bytes||modules.observations().iter().find(|m|m.path==path).ok_or("OWN original extent")?.image_bytes!=image{return Err("Root PE bytes/OWN image extent mismatch".into());}
  for import in array(module,"Imports",65536)?{let library=s(import,"Module",260)?;let delayed=match s(import,"Kind",16)?{"IMPORT"=>false,"DELAY_IMPORT"=>true,_=>return Err("Root complete import kind".into())};let start=u32n(import,"IatRva")?;
   for(i,item)in array(import,"Symbols",65536)?.iter().enumerate(){if slots.len()>=131072{return Err("Root complete slot cap before allocation".into());}sum(&mut text,k.len())?;sum(&mut text,library.len())?;let sym=symbol(item,&mut text)?;let rva=start.checked_add((i as u32).checked_mul(8).ok_or("Root slot offset")?).ok_or("Root IAT overflow")?;
    if rva<4096||rva%8!=0||rva as u64+8>image as u64||!unique_slots.insert((k.clone(),rva)){return Err("Root exact whole IAT slot range/uniqueness".into());}
    slots.push(CompleteSlot{importer:path.clone(),original_library:library.into(),original_symbol:sym,iat_rva:rva,delayed});}
  }
  for export in array(module,"Exports",65536)?{let ordinal=u32n(export,"Ordinal")?;if ordinal==0||ordinal>65535{return Err("Root export ordinal".into());}let rva=u32n(export,"Rva")?;
   let forwarder=match export.get("Forwarder"){Some(Value::Null)=>None,Some(Value::String(f)) if f.len()<=4367&&f.is_ascii()=>Some(f.as_str()),_=>return Err("Root export forwarder bound".into())};
   let names=array(export,"Names",65536)?;if exports.len().checked_add(names.len()).and_then(|n|n.checked_add(1)).is_none_or(|n|n>262144){return Err("Root export aggregate cap before temporary symbols".into());}
   let mut symbols=vec![RequestedSymbol::Ordinal(ordinal as u16)];for name in names{let name=name.as_str().ok_or("Root export name")?;if name.is_empty()||name.len()>4096||!name.is_ascii()||name.bytes().any(|c|!(33..127).contains(&c)){return Err("Root parsed export label".into());}sum(&mut text,name.len())?;symbols.push(RequestedSymbol::Named(name.into()));}
   for symbol in symbols{if exports.len()>=262144{return Err("Root requested-export cap before retaining next".into());}sum(&mut text,k.len())?;if let Some(f)=forwarder{sum(&mut text,f.len())?;}let identity=match &symbol{RequestedSymbol::Named(name)=>format!("N:{name}"),RequestedSymbol::Ordinal(n)=>format!("O:{n}")};if !unique_exports.insert((k.clone(),identity)){return Err("Root parsed export ambiguity".into());}exports.push(ParsedRequestedExport{module:path.clone(),symbol,rva,forwarder:forwarder.map(str::to_owned)});}
  }
 }
 if paths!=selected_paths{return Err("Root whole parsed importer/export projection missing".into());}
 let original_own=objects.iter().find(|p|p.path==r.own_image).ok_or("Root own artifact absent")?;if hash::<32>(v,"own_sha256")?!=original_own.sha256{return Err("Root own actual artifact differs".into());}
 Ok(AdmittedTestInputs{own_image:r.own_image.clone(),original_objects:objects,complete_slots:slots,full_parsed_exports:exports,selected_comparator_direct_rva:r.comparator_rva,source_sha256:r.source,immutable_campaign:r.campaign,expected_primary_token:own_token.clone()})
}
/// Root-authenticated registration is already bound to this held channel.
/// All table context below comes from the selected producer, not CLI or a
/// separately opened endpoint which could substitute another issuer.
fn dispatch_from_selected_root(registration:RootLaunchRegistration,cancel:&AtomicBool,initial:peer::RootChannel)->Result<()>{
 let mut initial=initial;
 if cancel.load(Ordering::Acquire){let closure=initial.close_checked();return Err(format!("Root launch cancelled before effects; original close={closure:?}"));}
 let token_before=match own_native_token::observe_own(){Ok(v)=>v,Err(e)=>{let closure=initial.close_checked();return Err(format!("Root own token={e}; original channel close={closure:?}"));}};let paths:Vec<_>=registration.originals.iter().map(|p|p.path.clone()).collect();
 let mut modules=match OwnLoadedModules::observe_declared(&paths,&registration.own_image){Ok(v)=>v,Err(e)=>{let closure=initial.close_checked();return Err(format!("Root own module observation={e}; original channel close={closure:?}"));}};let mut originals=Vec::new();let mut channel=Some(initial);let mut admitted=None;
 let operation: Result<()>=(||{
  let pipe=channel.as_mut().unwrap();pipe.require_peer(cancel)?;
  for module in modules.observations(){let path=module.path.to_str().ok_or("Root OWN metadata path")?;pipe.write(format!("ROOT_OWN_PATH {path}").as_bytes(),cancel)?;}pipe.write(b"ROOT_OWN_ROSTER_END",cancel)?;
  let bytes=pipe.read_capsule(cancel)?;let value:Value=serde_json::from_slice(&bytes).map_err(|e|format!("Bounded complete Root capsule refused {e}"))?;
  let input=decode_complete(&value,&registration,&modules,&token_before)?;
  // All original table context was authored by the authenticated Root policy
  // from held original bytes. Re-hold every original before the actual native
  // requested-symbol/IAT check and before any backing comparator invocation.
  for spec in &input.original_objects{originals.push(OriginalPublicFile::open_declared(spec.clone(),&token_before.user_sid)?);}
  let bindings=unsafe{modules.resolve_requested_imports(&input.complete_slots,&input.full_parsed_exports)}?;modules.require_declared_bindings(&bindings)?;modules.require_selected_comparator(registration.comparator_rva)?;
  for original in &originals{original.recheck()?;}modules.recheck()?;pipe.require_peer(cancel)?;
  if own_native_token::observe_own()?!=token_before{return Err("Root OWN token changed before opaque selection".into());}
  let selected=unsafe{RootSelectedDriverInput::from_authenticated_launch(input)};admitted=Some(NativeRunOwner::receive(selected)?);
  Ok(())
 })();
 // Close all independent pre-admission originals/references once. No provider
 // runs after a cancellation, EOF, peer drift or unknown original close.
 let mut errors=Vec::new();for original in originals.iter_mut().rev(){if let Err(e)=original.close_checked(){errors.push(e);}}if let Err(e)=modules.close_checked(){errors.push(e);}
 if operation.is_ok()&&errors.is_empty(){if let Some(pipe)=channel.as_mut(){if let Err(e)=pipe.write(b"ROOT_LIVE_OWNER_ACCEPTED",cancel){errors.push(e);}}}
 if let Some(pipe)=channel.as_mut(){if let Err(e)=pipe.close_checked(){errors.push(e);}}
 match(operation,errors.is_empty(),admitted){(Ok(()),true,Some(owner))=>super::own_native_receiver::dispatch_received(owner),
  (primary,_,owner)=>{let closure=owner.map(NativeRunOwner::close_after_driver);Err(format!("Root factory refused: primary={primary:?}; independent={errors:?}; owner_close={closure:?}"))}}
}
fn receive_selected_root(cancel:&AtomicBool)->Result<()>{
 // The generated source names only the independently selected issuer. The
 // endpoint environment value chooses routing and confers zero authority.
 let anchor=registration::selected()?;let name=std::env::var("MUTINY_ROOT_LAUNCH_PIPE").map_err(|_|"Root endpoint routing hint absent")?;
 let prefix=r"\\.\pipe\Mutiny-RootLaunch-";if !name.starts_with(prefix)||name.len()!=prefix.len()+64+1+32||name.as_bytes()[prefix.len()+64]!=b'-'||!name[prefix.len()..prefix.len()+64].bytes().chain(name[prefix.len()+65..].bytes()).all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err("Root exact bounded routing hint".into());}
 let mut channel=peer::RootChannel::open_anchor(&anchor.parent,&anchor.payload,&anchor.user,&name,cancel)?;
 let operation=(||{let(parent,parent_token)=channel.authenticated_context(cancel)?;channel.write(b"ROOT_REGISTRATION_REQUEST",cancel)?;let bytes=channel.read_capsule_limit(cancel,2097152)?;
  if bytes.len()>2097152{return Err("Bounded authenticated Root registration".into());}let v:Value=serde_json::from_slice(&bytes).map_err(|e|format!("Root registration parse {e}"))?;
  if s(&v,"scope",128)?!="AUTHENTICATED_ROOT_TEST1001_SELECTED_REGISTRATION"{return Err("Root selected registration scope".into());}
  let mut originals=Vec::new();for row in array(&v,"original_objects",512)?{let class=match s(row,"object_class",64)?{"OwnTestImage"=>PublicClass::OwnTestImage,"System32Dll"=>PublicClass::System32Dll,_=>return Err("Authenticated Root original class".into())};
   originals.push(PublicObjectSpec{path:PathBuf::from(s(row,"path",1006)?),class,bytes:n(row,"bytes")?,sha256:hash::<32>(row,"sha256")?,volume:n(row,"volume")?,file_id:hash::<16>(row,"file_id")?,links:u32n(row,"links")?,owner_sid:sid(row,"owner_sid_hex")?,dacl_sha256:hash::<32>(row,"dacl_sha256")?});}
  channel.require_peer(cancel)?;
  // This unsafe caller obligation is fulfilled by compiled exact issuer
  // provenance plus actual pipe/process/original/token authentication and the
  // producer's private before-creation admission. Wire fields alone cannot
  // enter this branch from another program or an unselected original.
  unsafe{RootLaunchRegistration::from_root_selected_context(parent,parent_token,anchor.parent,originals,PathBuf::from(s(&v,"own_image",1006)?),hash::<32>(&v,"compiled_source_capture_sha256")?,hash::<32>(&v,"provider_source_manifest_sha256")?,hash::<32>(&v,"campaign")?,hash::<32>(&v,"abi_proof_sha256")?,hash::<32>(&v,"abi_results_sha256")?,u32n(&v,"comparator_direct_rva")?,name)}
 })();match operation{Ok(selected)=>dispatch_from_selected_root(selected,cancel,channel),Err(primary)=>{let closure=channel.close_checked();Err(format!("Root registration refused={primary}; original channel close={closure:?}"))}}
}
/// Actual early receiver dispatch. An absent generated trusted issuer refuses
/// before provider effects; Root may form/adopt the real finite anchor once its
/// exact producer artifact is qualified. This is no runtime bool/None seam.
pub(super) fn run_if_requested()->Option<Result<()>>{
 if !std::env::args().nth(1).is_some_and(|s|s.starts_with("--native-owner-test-")){return None;}
 Some(receive_selected_root(&AtomicBool::new(false)))
}
