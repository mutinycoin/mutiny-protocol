//! Shared nonshipping child-output recorder. Scripted failures are models;
//! actual child receipts separately establish native process/pipe closure.
use std::io::{Read, Write};
use sha2::{Digest, Sha256};

pub trait DurableOutput: Write {
    fn sync_output(&mut self) -> std::io::Result<()>;
}
impl DurableOutput for std::fs::File {
    fn sync_output(&mut self) -> std::io::Result<()> { self.sync_all() }
}

pub fn drain(mut pipe: impl Read, mut file: impl DurableOutput) -> serde_json::Value {
    let mut total=0u64; let mut kept=0u64; let mut hash=Sha256::new();
    let mut errors=Vec::<String>::new(); let mut logging=true;
    let mut complete=false; let mut limit=false; let mut buf=[0u8;65536];
    loop {
        match pipe.read(&mut buf) {
            Ok(0)=>{complete=true;break;},
            Ok(n)=>{
                hash.update(&buf[..n]);
                total=match total.checked_add(n as u64) {
                    Some(v)=>v, None=>{errors.push("byte count overflow".into());u64::MAX}
                };
                let room=(64*1024*1024u64).saturating_sub(kept);
                let take=room.min(n as u64) as usize;
                if logging && take>0 {
                    let mut written=0usize;
                    while written<take {
                        match file.write(&buf[written..take]) {
                            Ok(n) if n>0 && n<=take-written=>{written+=n;kept+=n as u64;},
                            Err(ref e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
                            _=>{logging=false;errors.push("public output write refused; natural drain continues".into());break;},
                        }
                    }
                }
                if total>64*1024*1024 {limit=true;}
            },
            Err(ref e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
            Err(_)=>{errors.push("owned pipe read error; EOF not established".into());break;},
        }
    }
    // Tail observation never promotes an incomplete first read/hash to success.
    let mut tail_bytes=0u64; let mut tail_eof=false; let mut tail_error=false;
    let read_failed=!complete;
    if read_failed {
        loop {
            match pipe.read(&mut buf) {
                Ok(0)=>{tail_eof=true;break;},
                Ok(n)=>{tail_bytes=tail_bytes.saturating_add(n as u64);},
                Err(ref e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
                Err(_)=>{tail_error=true;errors.push("null-tail read error; drainage UNKNOWN".into());break;},
            }
        }
    }
    if file.sync_output().is_err(){errors.push("public output sync refused".into());}
    serde_json::json!({"total_bytes":total,"retained_bytes":kept,
        "total_sha256":hex::encode(hash.finalize()),"retention_limit":64*1024*1024u64,
        "limit_exceeded":limit,"eof":complete,"hash_complete":complete,
        "stream_status":if read_failed {"ERROR_UNKNOWN"} else {"EOF_OBSERVED"},
        "null_tail_attempted":read_failed,"null_tail_bytes":tail_bytes,
        "null_tail_eof":tail_eof,"null_tail_error":tail_error,"errors":errors})
}
