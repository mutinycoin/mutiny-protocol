//! EXTERNAL SOURCE ONLY. Bounded, explicitly launched NONSHIPPING pipe-control peer.
//! No vault, wallet Controller, economic request, signing or certified-history API.
//! Its actual different process is pinned by the parent control, never by this receipt.
use super::{process_auth::{Identity,VerifiedProcess},image_pin::ImagePin,
    pipe_io::{ClientPipe,Deadline},control_codec::{self,Role},control_reply};
use std::{io::{Read,Write},path::Path};
pub const PROBE_MARKER:&str="MUTINY-W15-NONSHIPPING-NATIVE-PIPE-CONTROL-PEER-V1";
type Result<T>=std::result::Result<T,String>;
#[derive(serde::Deserialize,serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {pub format:String,pub server:Identity,pub campaign:[u8;32],pub pipe_role:u8,
    pub raw_request_hex:String,pub reconnect_once:bool,pub malformed_control:bool}
fn role(n:u8)->Result<Role>{match n{1=>Ok(Role::WalletA),2=>Ok(Role::WalletC),3=>Ok(Role::Treasury),_=>Err("Native probe role bound".into())}}
fn read_input(path:&Path,hash:[u8;32],owner:&VerifiedProcess)->Result<Input>{
    let held=ImagePin::open(path,&owner.identity().user_sid)?;
    if held.hash()!=hash{return Err("Externally pinned native probe input differs".into());}
    let raw=held.read_bounded(8192)?;
    if raw.len()>8192{return Err("Native probe input allocation bound".into());}held.recheck()?;
    let input:Input=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    if input.format!=PROBE_MARKER||input.campaign==[0;32]||input.raw_request_hex.len()>4096{return Err("Native probe fixed format/allocation bound".into());}Ok(input)
}
pub fn run(path:&Path,pin:[u8;32])->Result<serde_json::Value>{
    let own_identity=VerifiedProcess::observe_created_process(std::process::id())?;
    let own=VerifiedProcess::open(&own_identity)?;
    let input=read_input(path,pin,&own)?;let pipe_role=role(input.pipe_role)?;
    let raw=hex::decode(&input.raw_request_hex).map_err(|_|"Native probe request hex")?;
    let mut replies=Vec::new();
    for attempt in 0..=u8::from(input.reconnect_once){
        let pipe=ClientPipe::open(input.campaign,pipe_role,VerifiedProcess::open(&input.server)?,&own,&Deadline::new())?;
        if input.malformed_control{
            // Only this fixed public negative control can emit malformed local
            // messages. Native OS process binding still surrounds every IO.
            pipe.native_negative_probe(&raw,&Deadline::new())?;
            return Err("Malformed local control unexpectedly got an accepted reply".into());
        }
        if raw.len()<control_codec::HEADER_BYTES{return Err("Native probe typed request too short".into());}
        let mut header=control_codec::decode_header(&raw[..control_codec::HEADER_BYTES]).map_err(|e|format!("{e:?}"))?;
        header.sequence=header.sequence.checked_add(attempt as u64).ok_or("Native probe sequence overflow")?;
        let request=control_codec::decode_payload(header,&raw[control_codec::HEADER_BYTES..]).map_err(|e|format!("{e:?}"))?;
        if !matches!(request.action,control_codec::Action::Head){return Err("Native control peer accepts ONLY nonfinality Head observations".into());}
        let reply=pipe.exchange(&request,&Deadline::new())?;
        if reply.code!=control_reply::Code::Observed||reply.refusal!=control_reply::Refusal::None{return Err("Native Head probe did not return an actual observation".into());}
        replies.push(serde_json::json!({"sequence":reply.sequence,"head":reply.observed_head.height,"code":reply.code as u8,"confirmed":false}));
        drop(pipe); // Deliberate real disconnect, with local sequence retained.
        if input.reconnect_once&&attempt==0{std::thread::sleep(std::time::Duration::from_millis(100));}
    }
    Ok(serde_json::json!({"format":PROBE_MARKER,"actual_native_process":own_identity,"replies":replies,"finality_authority":false}))
}
pub fn run_if_requested()->Option<Result<()>>{
    let args=std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_none_or(|v|v!="--continuous-native-peer"){return None;}
    Some((||{
        let [_,flag,path,pin_flag,pin]=args.as_slice()else{return Err("Explicit native control peer input/hash only".into());};
        if flag!="--input"||pin_flag!="--input-sha"{return Err("Native control peer argument identity".into());}
        let path=std::path::PathBuf::from(path);let pin=super::control_files::hash(pin.to_str().ok_or("Native input hash Unicode")?)?;
        let output=path.parent().ok_or("Native input parent")?.join(format!("native-peer-result-{}.json",std::process::id()));
        let result=run(&path,pin);let value=match &result{Ok(v)=>v.clone(),Err(e)=>serde_json::json!({"format":PROBE_MARKER,"pid":std::process::id(),"refusal":e,"confirmed":false})};
        let mut file=std::fs::OpenOptions::new().create_new(true).write(true).open(output).map_err(|e|e.to_string())?;
        file.write_all(&serde_json::to_vec_pretty(&value).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;file.sync_all().map_err(|e|e.to_string())?;
        result.map(|_|())
    })())
}
