use sha2::{Digest,Sha512};
use zeroize::Zeroizing;
fn bytes(v:&serde_json::Value)->Vec<u8>{v.as_str().unwrap().as_bytes().chunks_exact(2).map(|b|u8::from_str_radix(std::str::from_utf8(b).unwrap(),16).unwrap()).collect()}
#[test]
fn python_sha512_vectors_cover_short_long_and_multiblock_inputs(){
    let v:serde_json::Value=serde_json::from_str(include_str!("../../pbkdf2-public-vectors-v1.json")).unwrap();
    assert_eq!(v["synthetic_only"],true);assert_eq!(v["production_authorized"],false);
    for c in v["cases"].as_array().unwrap(){
        let size=c["length"].as_u64().unwrap() as usize;
        let mut out=Zeroizing::new([0u8;128]);
        pbkdf2::pbkdf2_hmac::<Sha512>(&bytes(&c["password"]),&bytes(&c["salt"]),c["rounds"].as_u64().unwrap() as u32,&mut out[..size]);
        assert_eq!(Sha512::digest(&out[..size]).as_slice(),bytes(&c["output_sha512"]));
    }
}
#[test]
fn known_public_24_word_mnemonics_match_existing_bip39_exactly(){
    for phrase in [format!("{}art","abandon ".repeat(23)),format!("{}vote","zoo ".repeat(23))]{
        let m=bip39::Mnemonic::parse_in(bip39::Language::English,&phrase).unwrap();
        let expected=Zeroizing::new(m.to_seed(""));
        let mut actual=Zeroizing::new([0u8;64]);
        pbkdf2::pbkdf2_hmac::<Sha512>(m.to_string().as_bytes(),b"mnemonic",2048,actual.as_mut());
        assert_eq!(actual.as_slice(),expected.as_slice());
    }
}
