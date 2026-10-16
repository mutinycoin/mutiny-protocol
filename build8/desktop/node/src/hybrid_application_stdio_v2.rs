//! Explicit unsigned TEST application entry through the shipping process.
//! Reconstruct genuine V2 Genesis/public evidence before opening any database.
//! Custody/signing lives in the separately selected protected TEST worker; this
//! frontend contains no keys, fixture generator, initialization fallback or TPM.
use crate::{genesis_artifact_v2::{TrustV2,VerifiedGenesisV2,MAX_ARTIFACT},
    hybrid_runtime_v2::{HybridRuntime,WorkRequest},hybrid_application_v2::{Application,A2Services},
    a2_operation_pool_v1::Context,candidate_journal_v3::Record};
use mutiny_consensus_v8::{Hash,genesis_v2::{Approved,GenesisClass},protocol_manifest::RuleManifest,
    canonical_store_v2::CanonicalStore,mempool_v2::Mempool,anchors::FinalizedAnchor};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::{path::Path,io::{Read,BufRead,BufReader,Write},sync::Arc};
type Result<T>=std::result::Result<T,String>;
fn fail(e:impl std::fmt::Debug)->String{format!("{e:?}")}
// Transport representation budgets derive solely from existing native limits.
// The fixed JSON allowance bounds IDs/field names/scalars; it grants no protocol capacity.
const JSON_ALLOWANCE:usize=4096;
const LINE_LIMIT:usize=2*mutiny_consensus_v8::body_capacity_v3::MAX_ENVELOPE_BYTES+JSON_ALLOWANCE;
fn bytes_bounded(v:&Value,limit:usize)->Result<Vec<u8>>{
    let text=v.as_str().ok_or("hex required")?;
    if text.len()>limit.checked_mul(2).ok_or("hex bound overflow")?||text.len()%2!=0{return Err("encoded object bound".into());}
    hex::decode(text).map_err(fail)
}
fn bytes(v:&Value)->Result<Vec<u8>>{bytes_bounded(v,MAX_ARTIFACT)}
fn command_limit(method:&str)->Result<usize>{
    use mutiny_consensus_v8::body_capacity_v3 as capacity;
    let native=match method {
        "install"=>capacity::MAX_ENVELOPE_BYTES,
        "candidate_preserve"=>crate::candidate_journal_v3::MAX_BYTES,
        "a2_submit"=>capacity::MAX_A2_OPERATION_BYTES,
        "prepare"=>capacity::MAX_BODY_BYTES,
        "status"|"a2_archive"|"a2_archived"|"a2_pending"=>0,
        _=>return Err("unknown hybrid application method".into())
    };
    // JSON quotes+comma for every possible native item, independent of
    // constructible evidence size or CBOR item-prefix amortization.
    let array_overhead=if method=="prepare" {3*capacity::MAX_ITEMS+2} else {0};
    Ok(native*2+JSON_ALLOWANCE+array_overhead)
}
fn hash(v:&Value)->Result<Hash>{bytes_bounded(v,32)?.try_into().map_err(|_|"hash length".into())}
fn number(v:&Value)->Result<u64>{v.as_u64().ok_or("unsigned integer required".into())}
fn path(v:&Value)->Result<&Path>{Ok(Path::new(v.as_str().ok_or("path required")?))}
fn read_pinned(p:&Path,pin:Hash,limit:usize)->Result<Vec<u8>>{
    let mut raw=Vec::new();std::fs::File::open(p).map_err(fail)?.take(limit as u64+1).read_to_end(&mut raw).map_err(fail)?;
    if raw.len()>limit||<[u8;32]>::from(Sha256::digest(&raw))!=pin{return Err("public input bound/hash".into());}
    Ok(raw)
}
pub fn run(config_path:&Path,config_pin:Hash)->Result<()> {
    let raw=read_pinned(config_path,config_pin,MAX_ARTIFACT)?;
    let config:Value=serde_json::from_slice(&raw).map_err(fail)?;
    if serde_json::to_vec(&config).map_err(fail)?!=raw||config["schema"]!="BUILD8-HYBRID-TEST-APPLICATION-V1" {
        return Err("canonical explicit TEST application configuration required".into());
    }
    let fields=["schema","artifact","artifact_sha256","genesis_block_hash","approved_manifest",
        "initial_target","public_evidence","public_evidence_sha256","chain","mempool","a2_pool",
        "candidate_journal","candidate_budget","initialize_caches","test_timestamp"];
    let object=config.as_object().ok_or("configuration object")?;
    if object.len()!=fields.len()||fields.iter().any(|key|!object.contains_key(*key)){return Err("configuration fields".into());}
    let trust=TrustV2 {artifact_sha256:hash(&config["artifact_sha256"])?,genesis_block_hash:hash(&config["genesis_block_hash"])?,
        approved:Approved {manifest:RuleManifest::decode(&bytes(&config["approved_manifest"])?).map_err(fail)?,
            class:GenesisClass::TestValue,initial_target:hash(&config["initial_target"])?}};
    let artifact=read_pinned(path(&config["artifact"])?,trust.artifact_sha256,MAX_ARTIFACT)?;
    let evidence=read_pinned(path(&config["public_evidence"])?,hash(&config["public_evidence_sha256"])?,
        mutiny_consensus_v8::admission_evidence_v1::MAX_BUNDLE)?;
    let verified=VerifiedGenesisV2::verify_with_public_evidence(&artifact,&trust,&evidence)?;
    if verified.genesis.class!=GenesisClass::TestValue{return Err("TEST application class".into());}
    // Exact configuration pin supplies the explicit software TEST clock; no
    // default clock, qualified UTC eligibility or protocol expiry is invented.
    let timestamp=number(&config["test_timestamp"])?;
    if timestamp<verified.genesis.t0{return Err("TEST epoch precedes Genesis".into());}
    let initialize=config["initialize_caches"].as_bool().ok_or("explicit cache mode")?;
    if initialize {
        if path(&config["chain"])?.exists()||path(&config["mempool"])?.exists(){return Err("new application stores required".into());}
    } else if !path(&config["chain"])?.is_file()||!path(&config["mempool"])?.is_file(){return Err("existing application stores required".into());}
    let anchor=verified.genesis.anchor();
    let chain=CanonicalStore::open_trusted_genesis(path(&config["chain"])?,&anchor,&verified.genesis.state,
        verified.genesis.root,verified.genesis.t0,verified.genesis.target).map_err(fail)?;
    let pool=Mempool::open(path(&config["mempool"])?,anchor.genesis,anchor.fingerprint,
        mutiny_consensus_v8::submission_pool_v1::MAX_BYTES).map_err(fail)?;
    let runtime=HybridRuntime::from_pinned_chain_with_time_source(chain,pool,Arc::new(move||timestamp)).map_err(fail)?;
    let budget=usize::try_from(number(&config["candidate_budget"])?).map_err(fail)?;
    let services=A2Services::open(&runtime,path(&config["a2_pool"])?,path(&config["candidate_journal"])?,budget,initialize)?;
    let mut app=Application::from_existing(runtime,services)?;
    let stdin=std::io::stdin();let mut reader=BufReader::new(stdin.lock());let mut output=std::io::stdout().lock();
    loop {
        let mut raw=Vec::new();let n=Read::by_ref(&mut reader).take(LINE_LIMIT as u64+1).read_until(b'\n',&mut raw).map_err(fail)?;
        if n==0{break;}if n>LINE_LIMIT||raw.last()!=Some(&b'\n'){return Err("hybrid application request bound".into());}
        let request:Value=serde_json::from_slice(&raw).map_err(fail)?;
        let method=request["method"].as_str().ok_or("method required")?;
        if n>command_limit(method)?{return Err("command representation bound".into());}
        let result=match execute(&mut app,&request) {Ok(value)=>json!({"id":request["id"],"result":value}),
            Err(error)=>json!({"id":request["id"],"error":error})};
        writeln!(output,"{result}").map_err(fail)?;output.flush().map_err(fail)?;
    }
    Ok(())
}
fn execute(app:&mut Application,v:&Value)->Result<Value>{
    let method=v["method"].as_str().ok_or("method required")?;
    if method=="status"{return Ok(json!({"head":hex::encode(app.head()?.encode()),"signing_enabled":false,"production_enabled":false}));}
    if method=="install"{
        let installed=app.install(&bytes_bounded(&v["envelope"],mutiny_consensus_v8::body_capacity_v3::MAX_ENVELOPE_BYTES)?)?;
        return Ok(json!({"inserted":installed.canonical.inserted,"finalized":hex::encode(installed.canonical.finalized.encode()),
            "pending_cache":format!("{:?}",installed.canonical.pending),"a2_cache":installed.a2_cache}));
    }
    if method=="a2_archive"{let(_,services)=app.parts();return Ok(json!({"archived":services.archive(hash(&v["digest"])?,v["reason"].as_str().ok_or("reason required")?)?}));}
    if method=="a2_archived"{let(_,services)=app.parts();return Ok(match services.archived(hash(&v["digest"])?)? {
        Some((wire,reason))=>json!({"wire":hex::encode(wire),"reason":reason}),None=>Value::Null});}
    if method=="candidate_preserve"{let(runtime,services)=app.parts();let record=Record::decode(runtime,&bytes_bounded(&v["record"],crate::candidate_journal_v3::MAX_BYTES)?)?;
        services.preserve(runtime,&record)?;return Ok(json!({"preserved":true}));}
    let parent=FinalizedAnchor::decode(&bytes_bounded(&v["parent"],128)?).map_err(fail)?;
    let context=Context {parent:&parent,license:hash(&v["license"])?,worker:hash(&v["worker"])?,timestamp:number(&v["timestamp"])?,ticket:number(&v["ticket"])?};
    match method {
        "a2_submit"=>{let(runtime,services)=app.parts();Ok(json!({"digest":hex::encode(services.submit(runtime,&context,&bytes_bounded(&v["operation"],mutiny_consensus_v8::body_capacity_v3::MAX_A2_OPERATION_BYTES)?)?)}))},
        "a2_pending"=>{let(runtime,services)=app.parts();Ok(match services.pending(runtime,&context)?{Some(raw)=>json!(hex::encode(raw)),None=>Value::Null})},
        "prepare"=>{
            let list=v["operations"].as_array().ok_or("operation array")?;if list.len()>mutiny_consensus_v8::body_capacity_v3::MAX_ITEMS{return Err("operation count".into());}
            let mut total=0usize;
            for item in list {
                let text=item.as_str().ok_or("operation hex")?;
                if text.len()%2!=0||text.len()>2*mutiny_consensus_v8::body_capacity_v3::MAX_A2_OPERATION_BYTES{return Err("operation encoded bound".into());}
                total=total.checked_add(text.len()/2).ok_or("operation aggregate overflow")?;
                if total>mutiny_consensus_v8::body_capacity_v3::MAX_BODY_BYTES{return Err("operation aggregate bound".into());}
            }
            let operations=list.iter().map(|v|bytes_bounded(v,mutiny_consensus_v8::body_capacity_v3::MAX_A2_OPERATION_BYTES)).collect::<Result<Vec<_>>>()?;
            let prepared=app.prepare(WorkRequest {expected_parent:&parent,license:context.license,worker:context.worker,
                timestamp:context.timestamp,ticket:context.ticket,operations:&operations})?;
            // Candidate body is encoded only under actual authenticated parent
            // capacity. This frontend reports no signature or canonical PASS.
            let runtime=app.runtime();let capacity=runtime.chain.body_capacity(&parent).map_err(fail)?;
            let c=&prepared.candidate;
            Ok(json!({"candidate":{"network":c.network,"genesis":hex::encode(c.genesis),"fingerprint":hex::encode(c.fingerprint),
                "parent":hex::encode(c.parent),"height":c.height,"timestamp":c.timestamp,"body_root":hex::encode(c.body_root),
                "state_root":hex::encode(c.state_root),"license":hex::encode(c.license),"worker":hex::encode(c.worker),"target":hex::encode(c.target)},
                "body":hex::encode(capacity.encode(&prepared.body).map_err(fail)?)}))
        },
        _=>Err("unknown hybrid application method".into()),
    }
}
