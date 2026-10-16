//! Finite retained-byte PE64 formation. No file lookup, load or ABI admission.
//! JSON uses unchanged RootLaunch3 declaration fields consumed by current B.
use crate::{Result,need};
use serde::Serialize;
use std::{collections::BTreeSet,path::PathBuf};
use crate::own_native_modules::{CompleteSlot,RequestedSymbol,ParsedRequestedExport};
#[derive(Clone,Serialize)]#[allow(non_snake_case)]pub(crate) struct Symbol{pub Name:Option<String>,pub Ordinal:Option<u16>}
#[derive(Clone,Serialize)]#[allow(non_snake_case)]pub(crate) struct Import{pub Module:String,pub Kind:String,pub IatRva:u32,pub Symbols:Vec<Symbol>}
#[derive(Clone,Serialize)]#[allow(non_snake_case)]pub(crate) struct Export{pub Ordinal:u32,pub Rva:u32,pub Names:Vec<String>,pub Forwarder:Option<String>}
#[derive(Clone,Serialize)]#[allow(non_snake_case)]pub(crate) struct Section{pub Name:String,pub Rva:u32,pub VirtualBytes:u32,pub Raw:u32,pub RawBytes:u32,pub Flags:u32}
#[derive(Clone,Serialize)]#[allow(non_snake_case)]pub(crate) struct Object{pub Path:String,pub Sha256:String,pub FileBytes:u64,pub ImageBytes:u32,pub Sections:Vec<Section>,pub Imports:Vec<Import>,pub Exports:Vec<Export>}
#[derive(Clone,Serialize)]#[allow(non_snake_case)]pub(crate) struct Slot{pub Importer:String,pub RequestedModule:String,pub Kind:String,pub Name:Option<String>,pub Ordinal:Option<u16>,pub IatRva:u32}
#[derive(Clone,Serialize)]#[allow(non_snake_case)]pub(crate) struct Capsule{pub Scope:&'static str,pub Objects:Vec<Object>,pub Slots:Vec<Slot>,pub OwnImage:String,pub NativeContextAdmitted:bool,pub SelectedComparatorAbiAdmitted:bool,pub RuntimeEligible:bool}
fn span(b:&[u8],at:usize,n:usize)->Result<&[u8]>{b.get(at..at.checked_add(n).ok_or("PE offset overflow")?).ok_or("PE physical extent".into())}
fn u16r(b:&[u8],p:usize)->Result<u16>{Ok(u16::from_le_bytes(span(b,p,2)?.try_into().unwrap()))}
fn u32r(b:&[u8],p:usize)->Result<u32>{Ok(u32::from_le_bytes(span(b,p,4)?.try_into().unwrap()))}
fn u64r(b:&[u8],p:usize)->Result<u64>{Ok(u64::from_le_bytes(span(b,p,8)?.try_into().unwrap()))}
struct Image<'a>{b:&'a[u8],headers:u32,size:u32,sections:Vec<Section>,dirs:[(u32,u32);16],text:usize,symbols:usize}
impl Image<'_>{
 fn map(&self,rva:u32,n:usize)->Result<usize>{need(n>0&&(rva as u64).checked_add(n as u64).is_some_and(|e|e<=self.size as u64),"PE image RVA bound")?;let mut found=None;
  if (rva as u64)+n as u64<=self.headers as u64{found=Some(rva as usize)}
  for s in &self.sections{if rva>=s.Rva&&(rva as u64)+n as u64<=s.Rva as u64+s.RawBytes as u64{need(found.is_none(),"overlapping physically backed PE RVA")?;found=Some(s.Raw as usize+(rva-s.Rva) as usize)}}
  let p=found.ok_or("PE RVA is virtual-only or unmapped")?;span(self.b,p,n)?;Ok(p)
 }
 fn text(&mut self,rva:u32,cap:usize,end:Option<u32>)->Result<String>{let mut out=Vec::new();for i in 0..cap{let at=rva.checked_add(i as u32).ok_or("PE string RVA overflow")?;need(end.is_none_or(|e|at<e),"PE forwarder directory bound")?;let byte=self.b[self.map(at,1)?];if byte==0{need(!out.is_empty(),"PE empty symbol")?;self.text=self.text.checked_add(out.len()).ok_or("PE text overflow")?;need(self.text<=16777216,"PE aggregate text cap")?;return String::from_utf8(out).map_err(|_|"PE ASCII".into())}need((33..=126).contains(&byte),"PE ASCII name")?;out.push(byte)}Err("PE bounded string terminator absent".into())}
 fn thunks(&mut self,rva:u32)->Result<Vec<Symbol>>{need(rva!=0,"PE original import name table required")?;let mut out=Vec::new();for i in 0..65536u32{let at=rva.checked_add(i.checked_mul(8).ok_or("PE thunk multiplication")?).ok_or("PE thunk overflow")?;let value=u64r(self.b,self.map(at,8)?)?;if value==0{return Ok(out)}self.symbols+=1;need(self.symbols<=131072,"PE aggregate import symbols")?;
   if value>>63==1{need(value&0x7fff_ffff_ffff_0000==0&&value as u16!=0,"PE exact import ordinal")?;out.push(Symbol{Name:None,Ordinal:Some(value as u16)})}
   else{need(value<=u32::MAX as u64,"PE import by-name RVA")?;let name=self.text((value as u32).checked_add(2).ok_or("PE hint RVA")?,4096,None)?;out.push(Symbol{Name:Some(name),Ordinal:None})}}
  Err("PE thunk terminator cap".into())
 }
}
fn header(b:&[u8])->Result<Image<'_>>{need((64..=134217728).contains(&b.len())&&u16r(b,0)?==0x5a4d,"PE MZ/byte cap")?;let nt=u32r(b,0x3c)? as usize;need(nt>=64&&u32r(b,nt)?==0x4550&&u16r(b,nt+4)?==0x8664,"PE exact x64 signature")?;let count=u16r(b,nt+6)? as usize;let optional=u16r(b,nt+20)? as usize;need((1..=96).contains(&count)&&optional>=240&&u16r(b,nt+24)?==0x20b,"PE64 headers")?;span(b,nt+24,optional)?;
 let size=u32r(b,nt+24+56)?;let headers=u32r(b,nt+24+60)?;need((4096..=536870912).contains(&size)&&headers>=64&&headers as usize<=b.len()&&headers<=size,"PE image/header size")?;need(u32r(b,nt+24+108)?==16,"PE complete sixteen directories")?;
 let mut dirs=[(0,0);16];for(i,d)in dirs.iter_mut().enumerate(){*d=(u32r(b,nt+24+112+i*8)?,u32r(b,nt+24+116+i*8)?);need((d.0==0)==(d.1==0),"PE complete directory pair")?}
 let table=nt+24+optional;span(b,table,count*40)?;let mut sections=Vec::with_capacity(count);
 for i in 0..count{let p=table+i*40;let raw=span(b,p,8)?;let end=raw.iter().position(|x|*x==0).unwrap_or(8);need(raw[..end].iter().all(|x|(32..=126).contains(x)),"PE section ASCII")?;let s=Section{Name:String::from_utf8(raw[..end].to_vec()).map_err(|_|"PE section name")?,VirtualBytes:u32r(b,p+8)?,Rva:u32r(b,p+12)?,RawBytes:u32r(b,p+16)?,Raw:u32r(b,p+20)?,Flags:u32r(b,p+36)?};need(s.Rva as u64+s.VirtualBytes.max(s.RawBytes) as u64<=size as u64,"PE section image bound")?;if s.RawBytes>0{span(b,s.Raw as usize,s.RawBytes as usize)?;}sections.push(s)}
 Ok(Image{b,headers,size,sections,dirs,text:0,symbols:0})
}
pub(crate) fn parse(path:&str,bytes:&[u8])->Result<Object>{let mut h=header(bytes)?;let mut imports=Vec::new();
 for d in [1usize,13]{let(rva,width)=h.dirs[d];if rva==0{continue}let step=if d==1{20usize}else{32};need(width as usize>=step&&width as usize<=1048576,"PE descriptor directory cap")?;let start=h.map(rva,width as usize)?;let mut ended=false;
  for p in (start..start+width as usize).step_by(step){need(p+step<=start+width as usize,"PE complete descriptor width")?;let block=span(bytes,p,step)?;if block.iter().all(|x|*x==0){ended=true;break}let(name,iat,thunk)=if d==1{(u32r(bytes,p+12)?,u32r(bytes,p+16)?,u32r(bytes,p)?)}else{need(u32r(bytes,p)?==1,"PE RVA-based delay descriptor only")?;(u32r(bytes,p+4)?,u32r(bytes,p+12)?,u32r(bytes,p+16)?)};
   need(imports.len()<512&&iat>=4096&&iat%8==0,"PE import module/IAT cap")?;let module=h.text(name,260,None)?;need(!module.contains(['\\','/',':',' '])&&module!="."&&module!="..","PE bare requested module")?;let symbols=h.thunks(thunk)?;h.map(iat,(symbols.len()+1)*8)?;imports.push(Import{Module:module,Kind:if d==1{"IMPORT"}else{"DELAY_IMPORT"}.into(),IatRva:iat,Symbols:symbols});}
  need(ended,"PE descriptor terminator inside exact directory")?;
 }
 let mut exports=Vec::new();let(er,ew)=h.dirs[0];if er!=0{need(ew>=40&&ew<=16777216,"PE export directory bound")?;let p=h.map(er,40)?;let base=u32r(bytes,p+16)?;let count=u32r(bytes,p+20)? as usize;let names=u32r(bytes,p+24)? as usize;need(count<=65536&&names<=65536&&names<=262144,"PE export counts")?;let funcs=h.map(u32r(bytes,p+28)?,count.max(1)*4)?;let name_table=if names==0{0}else{h.map(u32r(bytes,p+32)?,names*4)?};let ords=if names==0{0}else{h.map(u32r(bytes,p+36)?,names*2)?};let mut labels=vec![Vec::<String>::new();count];let mut unique=BTreeSet::new();
  for i in 0..names{let index=u16r(bytes,ords+i*2)? as usize;need(index<count,"PE named export index")?;let name=h.text(u32r(bytes,name_table+i*4)?,4096,None)?;need(unique.insert(name.clone()),"PE named export ambiguity")?;labels[index].push(name)}
  for i in 0..count{let rva=u32r(bytes,funcs+i*4)?;if rva==0{need(labels[i].is_empty(),"PE named empty export")?;continue}let ordinal=base.checked_add(i as u32).ok_or("PE ordinal overflow")?;need(ordinal>0&&ordinal<=65535,"Root wire export ordinal contract")?;let forwarder=if rva>=er&&(rva as u64)<er as u64+ew as u64{Some(h.text(rva,4367,Some(er.checked_add(ew).ok_or("PE forwarder end")?))?)}else{need(rva>=4096&&rva<h.size,"PE direct export bound")?;None};exports.push(Export{Ordinal:ordinal,Rva:rva,Names:std::mem::take(&mut labels[i]),Forwarder:forwarder});}
 }
 Ok(Object{Path:path.into(),Sha256:crate::sha(bytes),FileBytes:bytes.len() as u64,ImageBytes:h.size,Sections:h.sections,Imports:imports,Exports:exports})
}
pub(crate) fn capsule(objects:Vec<Object>,own:&str)->Result<Capsule>{need(!objects.is_empty()&&objects.len()<=512,"PE exact bounded universe")?;let mut paths=BTreeSet::new();let mut slots=Vec::new();let mut exports=0usize;let mut text=0usize;let mut bytes=0u64;
 for object in &objects{need(paths.insert(object.Path.to_ascii_lowercase()),"PE universe duplicate")?;bytes=bytes.checked_add(object.FileBytes).ok_or("PE aggregate byte overflow")?;need(bytes<=536870912,"PE aggregate byte cap")?;exports=exports.checked_add(object.Exports.len()).ok_or("PE aggregate exports")?;need(exports<=262144,"PE aggregate exports cap")?;for e in &object.Exports{for n in &e.Names{text=text.checked_add(n.len()).ok_or("PE export-name text overflow")?}text=text.checked_add(e.Forwarder.as_ref().map_or(0,String::len)).ok_or("PE forwarder text overflow")?;need(text<=16777216,"PE whole import/export text cap")?}let mut seen=BTreeSet::new();
  for import in &object.Imports{for(i,s)in import.Symbols.iter().enumerate(){need(slots.len()<131072,"PE whole normal/delayed slot cap")?;let rva=import.IatRva.checked_add((i as u32).checked_mul(8).ok_or("PE slot multiplication")?).ok_or("PE slot addition")?;need(seen.insert(rva)&&rva as u64+8<=object.ImageBytes as u64,"PE slot uniqueness/extent")?;text=text.checked_add(object.Path.len()+import.Module.len()+s.Name.as_ref().map_or(0,String::len)).ok_or("PE text overflow")?;need(text<=16777216,"PE whole reference text cap")?;slots.push(Slot{Importer:object.Path.clone(),RequestedModule:import.Module.clone(),Kind:import.Kind.clone(),Name:s.Name.clone(),Ordinal:s.Ordinal,IatRva:rva})}}
 }
 need(paths.contains(&own.to_ascii_lowercase()),"PE actual own image in universe")?;
 Ok(Capsule{Scope:"COMPLETE_HELD_PE_DECLARATIONS_NOT_NATIVE_CONTEXT_OR_ABI_ADMISSION",Objects:objects,Slots:slots,OwnImage:own.into(),NativeContextAdmitted:false,SelectedComparatorAbiAdmitted:false,RuntimeEligible:false})
}
impl Capsule{
 pub(crate) fn project(&self,paths:&[String])->Result<Self>{need(!paths.is_empty()&&paths.len()<=512,"actual child roster cap")?;let wanted:BTreeSet<_>=paths.iter().map(|s|s.to_ascii_lowercase()).collect();need(wanted.len()==paths.len()&&wanted.contains(&self.OwnImage.to_ascii_lowercase()),"complete unique actual child roster")?;let known:BTreeSet<_>=self.Objects.iter().map(|o|o.Path.to_ascii_lowercase()).collect();need(wanted.is_subset(&known),"unknown child roster refused before corresponding file open")?;capsule(self.Objects.iter().filter(|o|wanted.contains(&o.Path.to_ascii_lowercase())).cloned().collect(),&self.OwnImage)}
 pub(crate) fn native_inputs(&self)->Result<(Vec<CompleteSlot>,Vec<ParsedRequestedExport>)>{let mut slots=Vec::new();for s in &self.Slots{slots.push(CompleteSlot{importer:PathBuf::from(&s.Importer),original_library:s.RequestedModule.clone(),original_symbol:match(&s.Name,s.Ordinal){(Some(n),None)=>RequestedSymbol::Named(n.clone()),(None,Some(n))=>RequestedSymbol::Ordinal(n),_=>return Err("one requested import symbol".into())},iat_rva:s.IatRva,delayed:s.Kind=="DELAY_IMPORT"})}
  let mut exports=Vec::new();for o in &self.Objects{for e in &o.Exports{need(exports.len().checked_add(e.Names.len()+1).is_some_and(|n|n<=262144),"whole expanded export cap")?;exports.push(ParsedRequestedExport{module:PathBuf::from(&o.Path),symbol:RequestedSymbol::Ordinal(e.Ordinal as u16),rva:e.Rva,forwarder:e.Forwarder.clone()});for n in &e.Names{exports.push(ParsedRequestedExport{module:PathBuf::from(&o.Path),symbol:RequestedSymbol::Named(n.clone()),rva:e.Rva,forwarder:e.Forwarder.clone()})}}}Ok((slots,exports))
 }
 pub(crate) fn comparator(&self)->Result<u32>{let object=self.Objects.iter().find(|o|o.Path==r"C:\Windows\System32\ntdll.dll").ok_or("exact original ntdll declaration")?;let matches:Vec<_>=object.Exports.iter().filter(|e|e.Names.iter().any(|n|n=="NtAreMappedFilesTheSame")).collect();need(matches.len()==1&&matches[0].Forwarder.is_none(),"one physical direct comparator export")?;Ok(matches[0].Rva)}
}
