use mutiny_consensus_v8::{
    Error, NETWORK_ID,
    anchors::FinalizedAnchor,
    certificates::Decision,
    continuity_v2::{ParentVoter, Vote},
    equivocation_v2::{Evidence, HistoricalAuthority},
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use primitive_types::U256;
use std::collections::BTreeMap;
#[test]
fn hybrid_offense_uses_historical_authority_and_exact_evidence_window() {
    let key = HybridKey::generate(Role::Continuity).unwrap();
    let tpm = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let voter = ParentVoter {
        lineage: [19;32],
        admitted: true,
        physical: true,
        eligible: true,
        revoked: false,
        hardware_generation: 1,
        key_generation: 1,
        tpm_public: tpm,
        profile: [8; 32],
        public: key.public().clone(),
        reputation: U256::one(),
    };
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 59,
        block: [3; 32],
    };
    let decision = Decision {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        purpose: 2,
        height: 60,
        mining_epoch: 59,
        continuity_period: 0,
        round: 4,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: [4; 32],
        state: [5; 32],
        membership: [6; 32],
        reputation: [7; 32],
        attestation: [8; 32],
    };
    let mut a = Vote {
        decision,
        nil: false,
        node: [9; 32],
        hardware_generation: 1,
        key_generation: 1,
        sequence: 10,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    a.sign(&key).unwrap();
    let mut b = a.clone();
    b.decision.block = [11; 32];
    b.decision.state = [12; 32];
    b.sequence += 1;
    b.sign(&key).unwrap();
    let registry = BTreeMap::from([(a.node, voter)]);
    let history = HistoricalAuthority {
        parent: &parent,
        roots: [[6; 32], [7; 32], [8; 32]],
        registry: &registry,
    };
    let evidence = Evidence::new(a.clone(), b.clone()).unwrap();
    let inverse = Evidence::new(b.clone(), a.clone()).unwrap();
    assert_eq!(evidence, inverse);
    let encoded = evidence.encode().unwrap();
    if std::env::var("BUILD8_EXPORT_PUBLIC_EQUIVOCATION").as_deref()==Ok("1") {
        let f=serde_json::json!({"schema":"BUILD8-SYNTHETIC-HYBRID-EQUIVOCATION-V2","synthetic":true,"production_authorized":false,
            "evidence":hex::encode(&encoded),"evidence_id":hex::encode(evidence.id().unwrap()),"parent_anchor":hex::encode(parent.encode()),
            "continuity_descriptor":hex::encode(key.public().descriptor(1).unwrap()),"tpm_public":hex::encode(tpm),"inclusion_height":61});
        std::fs::write(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../qualification/equivocation-public-v2.json"),serde_json::to_vec_pretty(&f).unwrap()).unwrap();
    }
    assert!(encoded.len() < 16384);
    assert_eq!(Evidence::decode(&encoded).unwrap(), evidence);
    let inclusion = |height: u64| FinalizedAnchor {
        height: height - 1,
        block: [44; 32],
        ..parent.clone()
    };
    {
        use mutiny_consensus_v8::{penalties_v2::{Book,Settlement},execution::State};
        let settlement=Settlement::new(&evidence,&inclusion(43260),&history).unwrap();
        assert_eq!(settlement.inclusion_height(),43260);
        assert_eq!(settlement.offense_height(),60);
        assert_eq!(Settlement::decode(settlement.encode()).unwrap(),settlement);
        let mut book=Book::default();book.insert(settlement.clone()).unwrap();
        assert!(book.insert(settlement.clone()).is_err());
        assert!(book.revoked([19;32]));assert!(book.tombstoned([19;32],1));
        assert!(!book.tombstoned([19;32],2));assert!(!book.revoked([20;32]));
        assert_eq!(Book::from_records(&book.records().unwrap()).unwrap(),book);
        assert!(Settlement::new(&evidence,&inclusion(43261),&history).is_err());
        let mut trailing=settlement.encode().to_vec();trailing.push(0);
        assert!(Settlement::decode(&trailing).is_err());
        let mut bad=settlement.encode().to_vec();let n=bad.len();bad[n-500]^=1;
        assert!(Settlement::decode(&bad).is_err());
        let mut state=State::default();state.penalties_v2=book;
        let root=state.root().unwrap();assert_eq!(State::from_records(&state.records().unwrap(),root).unwrap(),state);
        state.protocol_records.insert([30;32],settlement.encode().to_vec());assert!(state.root().is_err());
    }
    for height in [61, 43260] {
        let offense = evidence.validate(&inclusion(height), &history).unwrap();
        assert_eq!(offense.node(), a.node);
        assert_eq!(offense.lineage(), [19;32]);
        assert_eq!(offense.height(), 60);
        assert_eq!(offense.hardware_generation(), 1);
        assert_eq!(offense.key_generation(), 1);
        assert_eq!(offense.evidence_id(), evidence.id().unwrap());
    }
    {
        use mutiny_consensus_v8::{bond_ops_v2::{Operation,Action,settle_commands},bonds_v2::{Lot,Book},op_envelope_v1::Envelope,
            bonds::{BondLot,LotStatus,MINIMUM_ATOMS,LOCK_HEIGHTS,EVIDENCE_HEIGHTS},penalties_v2,
            wallet_authority_v1::WalletBook};
        let owner=HybridKey::wallet_restore(&format!("{}art","abandon ".repeat(23)),Role::WalletOwner).unwrap();
        let descriptor=owner.public().descriptor(1).unwrap();let mut wallets=WalletBook::default();
        let address=wallets.register(&descriptor).unwrap();
        let u=1+LOCK_HEIGHTS;let h=u+EVIDENCE_HEIGHTS;
        let past=FinalizedAnchor{height:u-1,..parent.clone()};
        let mut av=a.clone();av.decision.height=u;av.decision.continuity_period=(u-1)/60;
        av.decision.mining_epoch=u-1;av.decision.previous_finalized_anchor=past.id();av.sign(&key).unwrap();
        let mut bv=av.clone();bv.decision.block=[31;32];bv.sequence+=1;bv.sign(&key).unwrap();
        let offense=Evidence::new(av,bv).unwrap();
        let historical=HistoricalAuthority{parent:&past,roots:history.roots,registry:&registry};
        let current=inclusion(h);
        let proof=penalties_v2::Settlement::new(&offense,&current,&historical).unwrap();
        let mut lot=Lot(BondLot{id:[41;32],node:a.node,lineage:[19;32],owner:address,atoms:MINIMUM_ATOMS,
            created_height:1,sequence:0,unbond_height:None,settled_height:None,status:LotStatus::Active,evidence:[0;32]});
        lot.start_unbond(u,1).unwrap();
        let books=Book{lots:[(lot.0.id,lot.clone())].into_iter().collect()};
        let penalties=penalties_v2::Book::default();
        // Bond command body version 3 (Lane P design 5.1): the signed window holds exactly h and
        // references the inclusion parent; the settlement height is the actual h.
        let mut command=Operation{genesis:parent.genesis,fingerprint:parent.fingerprint,
            envelope:Envelope{first_height:h,last_height:h,reference_height:current.height,reference_block:current.block,preconditions:vec![]},
            owner:address,authorizer:descriptor,action:Action::Withdraw{lot:lot.0.id,sequence:2},
            signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};
        command.sign(&owner).unwrap();
        let paid=settle_commands(&current,&Default::default(),&wallets,&books,&penalties,&[command.clone()],&[]).unwrap();
        assert_eq!(paid.payouts.values().next().unwrap().output.owner,address);
        assert_eq!(paid.payouts.values().next().unwrap().output.atoms,MINIMUM_ATOMS);
        let burned=settle_commands(&current,&Default::default(),&wallets,&books,&penalties,&[command.clone()],&[proof.clone()]).unwrap();
        assert!(burned.payouts.is_empty());assert_eq!(burned.burned,MINIMUM_ATOMS as u128);
        assert!(burned.penalties.revoked([19;32]));assert!(burned.penalties.tombstoned([19;32],1));
        assert!(!burned.penalties.tombstoned([19;32],2));
        assert_eq!(burned.bonds.lots[&lot.0.id].0.status,LotStatus::Burned);
        assert_eq!(books.lots[&lot.0.id],lot);assert!(penalties.is_empty());
        if std::env::var_os("BUILD8_EXPORT_SETTLEMENT_PUBLIC_V1").is_some() {
            let voter=&registry[&a.node];
            let mut encoded_voter=minicbor::Encoder::new(Vec::new());
            encoded_voter.array(7).unwrap().bytes(&voter.lineage).unwrap()
                .u64(voter.hardware_generation).unwrap().u64(voter.key_generation).unwrap()
                .bytes(&voter.tpm_public).unwrap().bytes(&voter.profile).unwrap()
                .bytes(&voter.public.descriptor(voter.key_generation).unwrap()).unwrap()
                .bytes(&voter.reputation.to_big_endian()).unwrap();
            let (point,coin)=paid.payouts.iter().next().unwrap();
            let fixture=serde_json::json!({
                "synthetic_only":true,"production_authorized":false,
                "settlement":hex::encode(proof.encode()),
                "inclusion_parent":hex::encode(current.encode()),
                "historical_parent":hex::encode(past.encode()),
                "historical_roots":history.roots.map(hex::encode),
                "historical_node":hex::encode(a.node),
                "historical_voter":hex::encode(encoded_voter.into_writer()),
                "owner_descriptor":hex::encode(&command.authorizer),
                "parent_lot":hex::encode(lot.encode().unwrap()),
                "withdraw":hex::encode(command.encode().unwrap()),
                "burned_lot":hex::encode(burned.bonds.lots[&lot.0.id].encode().unwrap()),
                "paid_lot":hex::encode(paid.bonds.lots[&lot.0.id].encode().unwrap()),
                "burned_atoms":burned.burned as u64,"burned_payout_count":burned.payouts.len(),
                "revoked_lineage":hex::encode(voter.lineage),"offending_generation":voter.hardware_generation,
                "payout":{"transaction":hex::encode(point.transaction),"index":point.index,
                    "owner":hex::encode(coin.output.owner),"atoms":coin.output.atoms,
                    "created_height":coin.created_height,"coinbase":coin.coinbase}
            });
            let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../qualification/hybrid-settlement-public-v1.json");
            assert!(!path.exists(),"public fixture must not be overwritten");
            std::fs::write(path,serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
        }
        assert!(settle_commands(&current,&Default::default(),&wallets,&books,&penalties,&[command.clone(),command.clone()],&[]).is_err());
        assert!(settle_commands(&current,&Default::default(),&wallets,&books,&penalties,&[],&[proof.clone(),proof.clone()]).is_err());
        let mut bad=command.clone();bad.signature.ed448[0]^=1;
        // Slashing does not bypass owner/economic validity of a supplied command.
        assert!(settle_commands(&current,&Default::default(),&wallets,&books,&penalties,&[bad],&[proof.clone()]).is_err());
        assert!(settle_commands(&inclusion(h+1),&Default::default(),&wallets,&books,&penalties,&[],&[proof]).is_err());
        assert!(penalties_v2::Settlement::new(&offense,&inclusion(h+1),&historical).is_err());
    }
    for height in [59, 60, 43261] {
        assert!(evidence.validate(&inclusion(height), &history).is_err());
    }
    assert_eq!(
        Evidence::new(a.clone(), a.clone()).unwrap_err(),
        Error::Duplicate
    );
    let mut resigned = a.clone();
    resigned.sign(&key).unwrap();
    assert_eq!(
        Evidence::new(a.clone(), resigned).unwrap_err(),
        Error::Duplicate
    );
    let mut same_payload = a.clone();
    same_payload.sequence += 1;
    same_payload.sign(&key).unwrap();
    assert!(
        Evidence::new(a.clone(), same_payload)
            .unwrap()
            .validate(&inclusion(61), &history)
            .is_err()
    );
    for field in 0..14 {
        let mut bad = b.clone();
        match field {
            0 => bad.decision.round += 1,
            1 => bad.decision.step = 2,
            2 => bad.decision.network ^= 1,
            3 => bad.decision.genesis[0] ^= 1,
            4 => bad.decision.fingerprint[0] ^= 1,
            5 => bad.node[0] ^= 1,
            6 => bad.hardware_generation += 1,
            7 => bad.key_generation += 1,
            8 => bad.decision.previous_finalized_anchor[0] ^= 1,
            9 => bad.profile[0] ^= 1,
            10 => bad.tpm_identity[0] ^= 1,
            11 => bad.decision.membership[0] ^= 1,
            12 => bad.decision.height += 1,
            _ => bad.decision.purpose = 1,
        }
        bad.sign(&key).unwrap();
        assert!(
            Evidence::new(a.clone(), bad)
                .unwrap()
                .validate(&inclusion(61), &history)
                .is_err(),
            "field {field}"
        );
    }
    for half in 0..2 {
        let mut bad = b.clone();
        if half == 0 {
            bad.signature.ed448[0] ^= 1
        } else {
            bad.signature.fndsa[500] ^= 1
        }
        assert!(
            Evidence::new(a.clone(), bad)
                .unwrap()
                .validate(&inclusion(61), &history)
                .is_err()
        );
    }
    // A current descendant registry cannot authenticate a retired generation's
    // offense; the original historical authority remains sufficient.
    let mut descendant = registry.clone();
    descendant.get_mut(&a.node).unwrap().hardware_generation = 2;
    assert!(
        evidence
            .validate(
                &inclusion(61),
                &HistoricalAuthority {
                    registry: &descendant,
                    ..history
                }
            )
            .is_err()
    );
    evidence.validate(&inclusion(61), &history).unwrap();
    for state in 0..3 {
        let mut wrong = registry.clone();
        let v = wrong.get_mut(&a.node).unwrap();
        match state {
            0 => v.physical = false,
            1 => v.revoked = true,
            _ => v.reputation = U256::zero(),
        }
        assert!(
            evidence
                .validate(
                    &inclusion(61),
                    &HistoricalAuthority {
                        registry: &wrong,
                        ..history
                    }
                )
                .is_err()
        );
    }
    let mut nil = b.clone();
    nil.nil = true;
    nil.decision.block = [0; 32];
    nil.decision.state = [0; 32];
    nil.decision.mining_epoch = 0;
    nil.sign(&key).unwrap();
    Evidence::new(a, nil)
        .unwrap()
        .validate(&inclusion(61), &history)
        .unwrap();
    let report = serde_json::json!({"schema":"BUILD8-HYBRID-EQUIVOCATION-V2","result":"PASS","evidence_bytes":encoded.len(),
        "synthetic":true,"runtime_activated":false,"penalty_state_mutated":false});
    if std::env::var("BUILD8_EXPORT_PUBLIC_REPORTS").as_deref() == Ok("1") {
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/equivocation-hybrid-v2.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    }
}
