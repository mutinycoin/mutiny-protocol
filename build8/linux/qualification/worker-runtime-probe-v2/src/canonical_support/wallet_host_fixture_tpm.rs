// Copied public software TPM test helpers; no physical device access.
// Consensus-test copy of desktop/src/wallet_host_fixture_tpm.rs (desktop/ is owned by another
// stream and is not edited here), extended with the version-2 `provenance` field. With None the
// profile stays version 1 (Legacy/Test class), byte-identical to the desktop helper output.
use mutiny_consensus_v8::tpm::{TpmProfile, encode_quote};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
pub fn blob(x: &[u8]) -> Vec<u8> {
    let mut b = (x.len() as u16).to_be_bytes().to_vec();
    b.extend(x);
    b
}
pub fn public(key: &SigningKey, restricted: bool) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(0x23u16.to_be_bytes());
    b.extend(0xbu16.to_be_bytes());
    b.extend((if restricted { 0x50472u32 } else { 0x40472u32 }).to_be_bytes());
    b.extend(blob(&[]));
    for x in [0x10u16, 0x18, 0xb, 3, 0x10] {
        b.extend(x.to_be_bytes());
    }
    let p = key.verifying_key().to_encoded_point(false);
    b.extend(blob(p.x().unwrap()));
    b.extend(blob(p.y().unwrap()));
    blob(&b)
}
pub fn header(kind: u16, signer: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut b = 0xff544347u32.to_be_bytes().to_vec();
    b.extend(kind.to_be_bytes());
    b.extend(blob(signer));
    b.extend(blob(challenge));
    b.extend([0; 25]);
    b
}
pub fn signature(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let s: Signature = key.sign(message);
    let raw = s.to_bytes();
    let mut b = vec![0, 0x18, 0, 0xb];
    b.extend(blob(&raw[..32]));
    b.extend(blob(&raw[32..]));
    b
}
pub fn profile(ak: &SigningKey) -> TpmProfile {
    profile_identity(ak, 10, 12)
}
pub fn profile_identity(ak: &SigningKey, identity_seed: u8, hardware: u8) -> TpmProfile {
    let identity = SigningKey::from_bytes((&[identity_seed; 32]).into()).unwrap();
    let voting_public = public(&identity, false);
    let mut signer = vec![0, 0xb];
    signer.extend([11; 32]);
    let mut name = vec![0, 0xb];
    name.extend(Sha256::digest(&voting_public[2..]));
    let mut certify_message = header(0x8017, &signer, &[0, 255, 85, 170]);
    certify_message.extend(blob(&name));
    certify_message.extend(blob(&signer));
    let certify_signature = signature(ak, &certify_message);
    TpmProfile {
        hardware: [hardware; 32],
        ak_public: public(ak, true),
        voting_public,
        qualified_signer: signer,
        pcr_bitmap: [1, 0, 0],
        pcr_digest: [13; 32],
        certify_message,
        certify_signature,
        admission_trust_manifest: [14; 32],
        provenance: None,
    }
}
pub fn quote(ak: &SigningKey, p: &TpmProfile, challenge: [u8; 32]) -> Vec<u8> {
    let mut m = header(0x8018, &p.qualified_signer, &challenge);
    m.extend(1u32.to_be_bytes());
    m.extend(0xbu16.to_be_bytes());
    m.push(3);
    m.extend(p.pcr_bitmap);
    m.extend(blob(&p.pcr_digest));
    encode_quote(&m, &signature(ak, &m)).unwrap()
}
