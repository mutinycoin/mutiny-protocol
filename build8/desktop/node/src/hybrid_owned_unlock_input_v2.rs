//! Owned bounded unlock input for the INTERNAL existing-role factory.
//! This codec cannot authenticate a native channel; only its installed native
//! issuer may supply a reader after exact peer/process/role/input checks.
//! Secrets never enter a public command, JSON log, path or serialized output.
use std::io::Read;
use zeroize::{Zeroizing,Zeroize};
type Result<T>=std::result::Result<T,String>;
const MAGIC:&[u8;16]=b"BUILD8-UNLOCK-V1";
const MAX_PASSWORD:usize=4096; // Existing crypto-v2 custody open_for bound.

/// The factory derives this exact hash from its own canonical role/generation
/// context and the native-held selected ciphertext commitments. It is public
/// request context, never a qualification grant or a caller-provided password.
pub(crate) struct UnlockBinding(pub(crate) [u8;32]);
pub(crate) struct OwnedPasswords {
    node:Zeroizing<String>,continuity:Zeroizing<String>,
}
impl OwnedPasswords {
    /// Read ONLY on the retained private worker from its exclusively owned,
    /// already authenticated native input. No stdin/environment/path fallback.
    /// The framing declares both lengths before any variable secret allocation.
    pub(crate) fn read_existing(reader:&mut impl Read,expected:&UnlockBinding)->Result<Self> {
        let mut header=[0u8;52];
        reader.read_exact(&mut header).map_err(|_|"owned unlock header unavailable")?;
        if &header[..16]!=MAGIC || header[16..48]!=expected.0 || expected.0==[0;32] {
            return Err("owned unlock exact context mismatch".into());
        }
        let node_len=u16::from_be_bytes(header[48..50].try_into().map_err(|_|"unlock node length")?) as usize;
        let continuity_len=u16::from_be_bytes(header[50..52].try_into().map_err(|_|"unlock continuity length")?) as usize;
        if node_len>MAX_PASSWORD || continuity_len>MAX_PASSWORD {
            return Err("owned unlock password bounds".into());
        }
        fn one(reader:&mut impl Read,n:usize)->Result<Zeroizing<String>> {
            let mut raw=Zeroizing::new(vec![0u8;n]);
            reader.read_exact(&mut raw).map_err(|_|"owned unlock secret incomplete")?;
            let text=std::str::from_utf8(&raw).map_err(|_|"owned unlock secret UTF8")?;
            // Wrap the destination BEFORE copying. An invalid UTF8 failure
            // never abandons an owned nonzero Vec inside FromUtf8Error.
            let mut value=Zeroizing::new(String::new());
            value.try_reserve_exact(n).map_err(|_|"owned unlock secret allocation")?;
            value.push_str(text);raw.zeroize();Ok(value)
        }
        let node=one(reader,node_len)?;
        let continuity=one(reader,continuity_len)?;
        // Dedicated one-shot input: the authenticated producer closes its write
        // side after this exact frame. Native caller owns I/O cancellation and
        // must independently settle/close its endpoint; this probe is not that
        // lifecycle receipt. Refuse a concatenated/trailing secret frame.
        let mut extra=Zeroizing::new([0u8;1]);
        loop {match reader.read(&mut extra[..]) {
            Ok(0)=>break,Ok(_)=>return Err("owned unlock trailing bytes".into()),
            Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>{},
            Err(_)=>return Err("owned unlock completion unknown".into()),
        }}
        Ok(Self{node,continuity})
    }
    /// Borrow exclusively for existing-role decryption. The factory drops this
    /// owner after both open_for calls; no clone/export/Debug/Serialize API exists.
    pub(crate) fn node(&self)->&str{&self.node}
    pub(crate) fn continuity(&self)->&str{&self.continuity}
}

#[cfg(test)]
mod modeled_controls {
    use super::*;
    fn frame(context:[u8;32],a:&[u8],b:&[u8])->Vec<u8>{
        let mut v=MAGIC.to_vec();v.extend(context);v.extend((a.len() as u16).to_be_bytes());
        v.extend((b.len() as u16).to_be_bytes());v.extend(a);v.extend(b);v
    }
    #[test]
    fn modeled_exact_role_context_and_lengths_before_secret_read(){
        let mut exact=std::io::Cursor::new(frame([7;32],b"PUBLIC TEST node",b"PUBLIC TEST continuity"));
        let p=OwnedPasswords::read_existing(&mut exact,&UnlockBinding([7;32])).unwrap();
        assert_eq!(p.node(),"PUBLIC TEST node");assert_eq!(p.continuity(),"PUBLIC TEST continuity");
        let mut wrong=std::io::Cursor::new(frame([8;32],b"PUBLIC TEST node",b"PUBLIC TEST continuity"));
        assert!(OwnedPasswords::read_existing(&mut wrong,&UnlockBinding([7;32])).is_err());
        assert_eq!(wrong.position(),52);
        let mut too_long=frame([7;32],b"",b"");too_long[48..50].copy_from_slice(&4097u16.to_be_bytes());
        let mut too_long=std::io::Cursor::new(too_long);
        assert!(OwnedPasswords::read_existing(&mut too_long,&UnlockBinding([7;32])).is_err());
        assert_eq!(too_long.position(),52);
    }
    #[test]
    fn modeled_partial_second_secret_and_invalid_utf8_refuse(){
        let full=frame([7;32],b"PUBLIC TEST node",b"PUBLIC TEST continuity");
        let mut cut=std::io::Cursor::new(&full[..full.len()-1]);
        assert!(OwnedPasswords::read_existing(&mut cut,&UnlockBinding([7;32])).is_err());
        let mut invalid=std::io::Cursor::new(frame([7;32],&[0xff],b"PUBLIC TEST continuity"));
        assert!(OwnedPasswords::read_existing(&mut invalid,&UnlockBinding([7;32])).is_err());
        let mut trailing=full.clone();trailing.push(1);let mut trailing=std::io::Cursor::new(trailing);
        assert!(OwnedPasswords::read_existing(&mut trailing,&UnlockBinding([7;32])).is_err());
    }
}
