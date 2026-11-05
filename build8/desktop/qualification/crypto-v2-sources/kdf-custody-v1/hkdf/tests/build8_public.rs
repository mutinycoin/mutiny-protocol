use hkdf::Hkdf;
use sha2::Sha512;
fn bytes(value: &serde_json::Value)->Vec<u8> {
    value.as_str().unwrap().as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect()
}
#[test]
fn independent_public_sha512_vectors_and_oversize_rejection() {
    let v:serde_json::Value=serde_json::from_str(include_str!("../../hkdf-sha512-public-vectors-v1.json")).unwrap();
    assert_eq!(v["synthetic_only"],true);assert_eq!(v["production_authorized"],false);
    for c in v["cases"].as_array().unwrap() {
        let ikm=bytes(&c["ikm"]);let salt=if c["salt"].is_null(){None}else{Some(bytes(&c["salt"]))};let info=bytes(&c["info"]);
        let mut output=vec![0;c["length"].as_u64().unwrap() as usize];
        Hkdf::<Sha512>::new(salt.as_deref(),&ikm).expand(&info,&mut output).unwrap();
        assert_eq!(output,bytes(&c["output"]));
        let (prk,kdf)=Hkdf::<Sha512>::extract(salt.as_deref(),&ikm);
        assert_eq!(prk.as_slice(),bytes(&c["prk"]));
        kdf.expand_multi_info(&[&info[..4],&info[4..]],&mut output).unwrap();
        assert_eq!(output,bytes(&c["output"]));
    }
    let mut excessive=vec![0xa5;16321];
    assert!(Hkdf::<Sha512>::new(None,b"PUBLIC-INPUT").expand(b"PUBLIC-INFO",&mut excessive).is_err());
    assert!(excessive.iter().all(|x|*x==0xa5));
}
