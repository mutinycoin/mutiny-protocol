//! EXTERNAL SOURCE ONLY. Bounded public metadata helpers for the new campaign.
//! No original replay mode, vault provision, custody copy or wallet authority.
use std::path::Path;
use super::{image_pin::ImagePin,process_auth::VerifiedProcess};
type Result<T>=std::result::Result<T,String>;
pub fn hash(text:&str)->Result<[u8;32]>{
    if text.len()!=64||!text.bytes().all(|c|c.is_ascii_hexdigit()){return Err("Exact32byte public hash hex required".into());}
    hex::decode(text).map_err(|_|"Public hash hex")?.try_into().map_err(|_|"Public hash width".into())
}
pub fn read_bounded(path:&Path,limit:u64)->Result<Vec<u8>>{
    let current=VerifiedProcess::open(&VerifiedProcess::observe_created_process(std::process::id())?)?;
    let file=ImagePin::open(path,&current.identity().user_sid)?;
    let raw=file.read_bounded(limit)?;current.recheck()?;Ok(raw)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn fixed_hash_width_and_full_consumption_refuse_whitespace_and_extensions(){
        assert_eq!(hash(&"ab".repeat(32)).unwrap(),[0xab;32]);
        for bad in ["ab".repeat(31),"ab".repeat(33),format!("{} ","ab".repeat(32)),"gg".repeat(32)]{assert!(hash(&bad).is_err());}
    }
}
