//! Candidate V2 application's hybrid observation receipt (wire version 3).
//! A receipt acknowledges operational accounting, never canonical finality.
//! Constructing/verifying an Intent does not establish historical work validity,
//! durable acceptance, current signing authority, or candidate retention.
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash, pow::WorkHeader};
use mutiny_crypto_v2::{Domain, HybridSignature, PublicKey};
pub const BODY_BYTES: usize = 278;
pub const RECEIPT_BYTES: usize = BODY_BYTES + 114 + 1280;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    body: [u8; BODY_BYTES],
    public: PublicKey,
}
impl Intent {
    /// Only positive observations exist in this codec. The caller supplies its
    /// durably authenticated checkpoint; untrusted Worker totals are not input.
    pub fn accepted(
        header: &WorkHeader,
        sequence: u64,
        previous: Hash,
        prior_total: u64,
        expected_node_descriptor: &[u8],
    ) -> Result<Self> {
        let coordinator = crate::work_authority_v2::node_identity(expected_node_descriptor)?;
        let (public, _) =
            PublicKey::decode_descriptor(expected_node_descriptor).map_err(|_| Error::Codec)?;
        let c = &header.candidate;
        if c.network != NETWORK_ID {
            return Err(Error::WrongNetwork);
        }
        if [
            c.genesis,
            c.fingerprint,
            c.license,
            c.worker,
            header.authority,
        ]
        .contains(&[0; 32])
        {
            return Err(Error::WrongAnchor);
        }
        if sequence == 0 || (sequence == 1) != (previous == [0; 32]) || prior_total >= sequence {
            return Err(Error::InvalidCounter);
        }
        let total = prior_total.checked_add(1).ok_or(Error::Overflow)?;
        let work = header.work_bytes();
        if work.len() > 544 {
            return Err(Error::Oversize);
        }
        let result = domain_hash(b"MUTINY-BUILD8-OBSERVATION-RESULT-V1", &work);
        let mut chain_body = sequence.to_be_bytes().to_vec();
        chain_body.extend(previous);
        chain_body.extend(result);
        chain_body.push(1);
        chain_body.extend(total.to_be_bytes());
        let chain = domain_hash(b"MUTINY-BUILD8-OBSERVATION-CHAIN-V1", &chain_body);
        let mut raw = vec![3];
        raw.extend(NETWORK_ID.to_be_bytes());
        for h in [
            c.genesis,
            c.fingerprint,
            c.license,
            c.worker,
            result,
            coordinator,
        ] {
            raw.extend(h);
        }
        raw.extend(sequence.to_be_bytes());
        raw.extend(previous);
        raw.push(1);
        raw.extend(total.to_be_bytes());
        raw.extend(chain);
        Ok(Self {
            body: raw.try_into().map_err(|_| Error::Codec)?,
            public,
        })
    }
    pub fn body(&self) -> &[u8; BODY_BYTES] {
        &self.body
    }
    pub fn sequence(&self) -> u64 {
        u64::from_be_bytes(self.body[197..205].try_into().unwrap())
    }
    pub fn total(&self) -> u64 {
        u64::from_be_bytes(self.body[238..246].try_into().unwrap())
    }
    pub fn chain(&self) -> Hash {
        self.body[246..278].try_into().unwrap()
    }
    /// Fixed-domain signature verification followed by exact wire encoding.
    /// Callers must not publish before durable accounting/candidate retention.
    pub fn finish(&self, signature: &HybridSignature) -> Result<Vec<u8>> {
        self.public
            .verify(Domain::NodeObservation, &self.body, signature)
            .map_err(|_| Error::BadSignature)?;
        let mut raw = self.body.to_vec();
        raw.extend(signature.ed448);
        raw.extend(signature.fndsa);
        Ok(raw)
    }
    /// Expected identity, result and checkpoint are constructed independently.
    /// No peer-provided descriptor, receipt body or version selects authority.
    pub fn verify(&self, raw: &[u8]) -> Result<()> {
        if raw.len() != RECEIPT_BYTES || raw[..BODY_BYTES] != self.body {
            return Err(Error::Codec);
        }
        let signature = HybridSignature {
            ed448: raw[BODY_BYTES..BODY_BYTES + 114]
                .try_into()
                .map_err(|_| Error::Codec)?,
            fndsa: raw[BODY_BYTES + 114..]
                .try_into()
                .map_err(|_| Error::Codec)?,
        };
        self.public
            .verify(Domain::NodeObservation, &self.body, &signature)
            .map_err(|_| Error::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_crypto_v2::{HybridKey, Role};
    fn header() -> WorkHeader {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        crate::block_envelope_v2::BlockEnvelope::decode(
            &hex::decode(f["envelope"].as_str().unwrap()).unwrap(),
        )
        .unwrap()
        .header
    }
    #[test]
    fn hybrid_observation_receipt_exact_context_dual_signatures_and_domain() {
        let key = HybridKey::generate(Role::Node).unwrap();
        let descriptor = key.public().descriptor(1).unwrap();
        let header = header();
        let intent = Intent::accepted(&header, 1, [0; 32], 0, &descriptor).unwrap();
        let signature = key.sign(Domain::NodeObservation, intent.body()).unwrap();
        let raw = intent.finish(&signature).unwrap();
        assert_eq!(raw.len(), 1672);
        assert_eq!((intent.sequence(), intent.total()), (1, 1));
        intent.verify(&raw).unwrap();
        for cut in [0, 1, 246, 278, 310, 392, 1671] {
            assert!(intent.verify(&raw[..cut]).is_err());
        }
        let mut extra = raw.clone();
        extra.push(0);
        assert!(intent.verify(&extra).is_err());
        for (start, end) in [(278, 392), (392, 1672)] {
            let mut partial = raw.clone();
            partial[start..end].fill(0);
            assert!(intent.verify(&partial).is_err());
        }
        for domain in [Domain::NodeWork, Domain::NodeWorkerSession] {
            let wrong = key.sign(domain, intent.body()).unwrap();
            assert!(intent.finish(&wrong).is_err());
        }
        // Every field is signed, including suite/version and the prior chain.
        for index in [0, 1, 5, 37, 69, 101, 133, 165, 197, 205, 237, 238, 246] {
            let mut changed = raw.clone();
            changed[index] ^= 1;
            assert!(intent.verify(&changed).is_err());
        }
        let next = Intent::accepted(&header, 2, intent.chain(), 1, &descriptor).unwrap();
        assert!(next.verify(&raw).is_err());
        let generation = key.public().descriptor(2).unwrap();
        assert!(
            Intent::accepted(&header, 1, [0; 32], 0, &generation)
                .unwrap()
                .verify(&raw)
                .is_err()
        );
        if std::env::var_os("BUILD8_EXPORT_SYNTHETIC_OBSERVATION_RECEIPT").is_some() {
            let value = serde_json::json!({"synthetic_only":true,"production_authorized":false,
                "work":hex::encode(header.work_bytes()),"descriptor":hex::encode(descriptor),
                "body":hex::encode(intent.body()),"receipt":hex::encode(raw),
                "sequence":1,"prior_total":0,"previous":hex::encode([0;32])});
            use std::io::Write;
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/hybrid-observation-receipt-public-v1.json");
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            out.write_all(serde_json::to_string_pretty(&value).unwrap().as_bytes())
                .unwrap();
        }
    }
    #[test]
    fn hybrid_observation_receipt_checkpoint_and_role_fail_closed() {
        let key = HybridKey::generate(Role::Node).unwrap();
        let descriptor = key.public().descriptor(1).unwrap();
        let header = header();
        for (sequence, previous, total) in [
            (0, [0; 32], 0),
            (1, [1; 32], 0),
            (2, [0; 32], 1),
            (1, [0; 32], 1),
            (u64::MAX, [1; 32], u64::MAX),
        ] {
            assert!(Intent::accepted(&header, sequence, previous, total, &descriptor).is_err());
        }
        let mut wrong = key.public().clone();
        wrong.role = Role::Continuity;
        assert!(Intent::accepted(&header, 1, [0; 32], 0, &wrong.descriptor(1).unwrap()).is_err());
        let mut bad = header.clone();
        bad.candidate.network ^= 1;
        assert!(Intent::accepted(&bad, 1, [0; 32], 0, &descriptor).is_err());
        let mut bad = header;
        bad.authority = [0; 32];
        assert!(Intent::accepted(&bad, 1, [0; 32], 0, &descriptor).is_err());
    }
    #[test]
    fn synthetic_worker_accounting_public_vector() {
        use crate::pow::{Candidate, WorkAuthority, WorkContext};
        use crate::work_authority_v2::{Authority, node_identity};
        let key = HybridKey::generate(Role::Node).unwrap();
        let descriptor = key.public().descriptor(1).unwrap();
        let coordinator = node_identity(&descriptor).unwrap();
        let candidate = Candidate {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            parent: [3; 32],
            height: 1,
            timestamp: 1060,
            body_root: [4; 32],
            state_root: [5; 32],
            license: [6; 32],
            worker: [7; 32],
            target: [255; 32],
        };
        let mut authority = Authority {
            work: WorkAuthority {
                candidate: candidate.clone(),
                assignment_sequence: 1,
                ticket_sequence: 1,
                coordinator,
                nonce_start: 0,
                nonce_end: 1000,
                epoch: 1,
            },
            node_descriptor: descriptor.clone(),
            signature: HybridSignature {
                ed448: [0; 114],
                fndsa: [0; 1280],
            },
        };
        authority.sign(&key).unwrap();
        let header = WorkHeader {
            candidate,
            authority: authority.id().unwrap(),
            nonce: 0,
        };
        let context = WorkContext {
            genesis: [1; 32],
            fingerprint: [2; 32],
            parent: [3; 32],
            parent_height: 0,
            t0: 1000,
            target: [255; 32],
            license: [6; 32],
            worker: [7; 32],
            coordinator,
            assignment_sequence: 1,
            last_accepted_ticket: 0,
            ancestor_timestamps: vec![1000],
        };
        authority.verify(&header, &context, &descriptor).unwrap();
        let intent = Intent::accepted(&header, 1, [0; 32], 0, &descriptor).unwrap();
        let receipt = intent
            .finish(&key.sign(Domain::NodeObservation, intent.body()).unwrap())
            .unwrap();
        intent.verify(&receipt).unwrap();
        if std::env::var_os("BUILD8_EXPORT_SYNTHETIC_WORKER_ACCOUNTING").is_some() {
            use std::io::Write;
            let value = serde_json::json!({"synthetic_only":true,"production_authorized":false,
                "scope":"Controller/accounting and exact codecs; synthetic parent state, not historical canonical execution",
                "authority":hex::encode(authority.encode().unwrap()),"work":hex::encode(header.work_bytes()),
                "descriptor":hex::encode(descriptor),"coordinator":hex::encode(coordinator),
                "authority_id":hex::encode(header.authority),"receipt":hex::encode(receipt)});
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/worker-accounting-public-v1.json");
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            out.write_all(serde_json::to_string_pretty(&value).unwrap().as_bytes())
                .unwrap();
        }
    }
    #[test]
    fn synthetic_hybrid_observation_chain_public_codec_vectors() {
        let keys = [
            HybridKey::generate(Role::Node).unwrap(),
            HybridKey::generate(Role::Node).unwrap(),
        ];
        let mut entries = Vec::new();
        let mut previous = [0; 32];
        for sequence in 1..=3u64 {
            let key = &keys[usize::from(sequence > 1)];
            let descriptor = key.public().descriptor(1).unwrap();
            let mut header = header();
            header.nonce = sequence;
            let intent =
                Intent::accepted(&header, sequence, previous, sequence - 1, &descriptor).unwrap();
            let receipt = intent
                .finish(&key.sign(Domain::NodeObservation, intent.body()).unwrap())
                .unwrap();
            intent.verify(&receipt).unwrap();
            entries.push(serde_json::json!({"sequence":sequence,"prior_total":sequence-1,
                "previous":hex::encode(previous),"work":hex::encode(header.work_bytes()),
                "descriptor":hex::encode(&descriptor),"body":hex::encode(intent.body()),"receipt":hex::encode(receipt)}));
            previous = intent.chain();
        }
        if std::env::var_os("BUILD8_EXPORT_SYNTHETIC_OBSERVATION_CHAIN").is_some() {
            use std::io::Write;
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("qualification/hybrid-observation-chain-public-v1.json");
            let value = serde_json::json!({"synthetic_only":true,"production_authorized":false,
                "scope":"Receipt/accounting codec only; not historical WorkAuthority execution or coordinator migration authorization", "entries":entries});
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            out.write_all(serde_json::to_string_pretty(&value).unwrap().as_bytes())
                .unwrap();
        }
    }
}
