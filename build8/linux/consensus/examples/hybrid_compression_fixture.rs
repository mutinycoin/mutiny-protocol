//! PUBLIC synthetic benchmark output only. No production wallet or stored key.
use mutiny_consensus_v8::{transactions::{OutPoint,Output},transactions_v2::{Transfer,Input},NETWORK_ID};
use mutiny_crypto_v2::{HybridKey,Role};
use sha2::{Digest,Sha256};
fn main(){
    assert_eq!(std::env::args().skip(1).collect::<Vec<_>>(),["--synthetic-1000"]);
    let key=HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).expect("public synthetic mnemonic fixture");
    for i in 0u64..1000 {
        let mut tx=Transfer{network:NETWORK_ID,genesis:[1;32],fingerprint:[2;32],created_height:100,expiry_height:200,fee:10_000+i,
            inputs:vec![Input::unsigned(OutPoint{transaction:[8;32],index:0},key.public(),1).unwrap()],
            outputs:vec![Output{owner:Sha256::digest(i.to_be_bytes()).into(),atoms:990_000-i}]};
        let start=std::time::Instant::now();tx.sign_input(0,&key).unwrap();let micros=start.elapsed().as_micros();
        println!("{}",serde_json::json!({"synthetic":true,"case":i,"sign_microseconds":micros,
            "fndsa":hex::encode(tx.inputs[0].signature.fndsa),"transaction":hex::encode(tx.encode().unwrap())}));
    }
}
