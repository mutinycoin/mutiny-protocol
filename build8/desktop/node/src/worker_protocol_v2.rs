//! Typed data inside the confirmed V2 Worker channel. No receipt verifier,
//! signing, PoW acceptance, canonical mutation or legacy authentication path.
//! Dispatch only through worker_active_connections_v2::Connection::dispatch.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    pow::{WORK_DOMAIN, WorkHeader},
};
use mutiny_transport_v2::{Error, Result};
pub const RESULT_MAX: usize = 544;
pub const SUBMISSION_MAX: usize = 41 + RESULT_MAX;
pub const RECEIPT_PACKET_MAX: usize = 4 + 2048 + 1672;
/// Bounded public transport wrapper, not a receipt acceptance decision.
/// Call only after durable candidate-retention release. The device verifies
/// BOTH signatures against its independently retained coordinator/result.
/// Carrying a descriptor permits relay of a genuine historical receipt; its
/// presence never installs current Node authority or resets a checkpoint.
pub(crate) fn receipt_packet(descriptor: &[u8], receipt: &[u8]) -> Result<Vec<u8>> {
    if descriptor.is_empty()
        || descriptor.len() > 2048
        || receipt.len() != 1672
        || receipt[0] != 3
        || receipt[1..5] != NETWORK_ID.to_be_bytes()
    {
        return Err(Error::Encoding);
    }
    let id = mutiny_consensus_v8::work_authority_v2::node_identity(descriptor)
        .map_err(|_| Error::Context)?;
    if receipt[165..197] != id {
        return Err(Error::Context);
    }
    let mut out = Vec::with_capacity(4 + descriptor.len() + receipt.len());
    out.extend([4, 2]);
    out.extend((descriptor.len() as u16).to_be_bytes());
    out.extend(descriptor);
    out.extend(receipt);
    Ok(out)
}
/// Operational offer envelope. Canonical work authority supplies the signed
/// context; the device compares it with independently authenticated local state.
/// No parent/identity authority is installed from this outer envelope.
pub(crate) fn offer(
    authority: &mutiny_consensus_v8::work_authority_v2::Authority,
    nonce: Hash,
    lifetime: u64,
) -> Result<Vec<u8>> {
    if nonce == [0; 32] || lifetime == 0 || lifetime > 60_000 {
        return Err(Error::Context);
    }
    let raw = authority.encode().map_err(|_| Error::Encoding)?;
    if raw.is_empty() || raw.len() > 8192 {
        return Err(Error::Encoding);
    }
    let mut out = Vec::with_capacity(52 + raw.len());
    out.extend([5, 2]);
    out.extend(nonce);
    out.extend(authority.work.epoch.to_be_bytes());
    out.extend(lifetime.to_be_bytes());
    out.extend((raw.len() as u16).to_be_bytes());
    out.extend(raw);
    Ok(out)
}
#[cfg(test)]
#[test]
fn offer_matches_independent_public_wire_vector() {
    let authority: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-work-authority-public-v1.json"
    ))
    .unwrap();
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-work-offer-public-v1.json"
    ))
    .unwrap();
    assert_eq!(authority["synthetic_only"], true);
    assert_eq!(vector["production_authorized"], false);
    let authority = mutiny_consensus_v8::work_authority_v2::Authority::decode(
        &hex::decode(authority["wire"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let nonce = hex::decode(vector["request_nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        offer(&authority, nonce, 1000).unwrap(),
        hex::decode(vector["wire"].as_str().unwrap()).unwrap()
    );
    for lifetime in [0, 60_001, u64::MAX] {
        assert!(offer(&authority, nonce, lifetime).is_err());
    }
    assert!(offer(&authority, [0; 32], 1000).is_err());
}
#[derive(Clone, Copy)]
pub struct Scope {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub license: Hash,
    pub worker: Hash,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    Status {
        run: bool,
        faults: u8,
        accepted_total: Option<u64>,
        state: u8,
    },
    Request {
        nonce: Hash,
        sequence: u64,
        chain: Hash,
    },
    Result(Submission),
}
/// Syntactically canonical, session-scoped data, not an accepted observation.
/// The actor must validate historical hybrid work authority, PoW, checkpoint,
/// ticket and durable candidate handling before producing a hybrid receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct Submission {
    sequence: u64,
    previous: Hash,
    header: WorkHeader,
}
impl Submission {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn previous(&self) -> Hash {
        self.previous
    }
    pub fn header(&self) -> &WorkHeader {
        &self.header
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![2];
        out.extend(self.sequence.to_be_bytes());
        out.extend(self.previous);
        out.extend(self.header.work_bytes());
        out
    }
}
/// Keeps the existing operational data layout; authentication is exclusively
/// the V2 channel and hybrid work-authority path. No Ed25519 verifier is called.
pub fn decode(raw: &[u8], scope: Scope) -> Result<Incoming> {
    if [
        scope.genesis,
        scope.fingerprint,
        scope.license,
        scope.worker,
    ]
    .contains(&[0; 32])
    {
        return Err(Error::Context);
    }
    match raw.first() {
        Some(2) if raw.len() == 12 && raw[1] <= 1 && raw[2] <= 15 && raw[11] <= 5 => {
            let total = u64::from_be_bytes(raw[3..11].try_into().map_err(|_| Error::Encoding)?);
            if raw[2] & 2 != 0 && total != 0 {
                return Err(Error::Encoding);
            }
            Ok(Incoming::Status {
                run: raw[1] == 1,
                faults: raw[2],
                accepted_total: (raw[2] & 2 == 0).then_some(total),
                state: raw[11],
            })
        }
        Some(5) if raw.len() == 73 => {
            let nonce = raw[1..33].try_into().map_err(|_| Error::Encoding)?;
            let sequence = u64::from_be_bytes(raw[33..41].try_into().map_err(|_| Error::Encoding)?);
            let chain = raw[41..73].try_into().map_err(|_| Error::Encoding)?;
            if nonce == [0; 32] || (sequence == 0) != (chain == [0; 32]) {
                return Err(Error::Context);
            }
            Ok(Incoming::Request {
                nonce,
                sequence,
                chain,
            })
        }
        Some(3)
            if raw.len() <= SUBMISSION_MAX + 1
                && raw.len() > 42 + WORK_DOMAIN.len() + 1
                && raw[1] == 2 =>
        {
            let sequence = u64::from_be_bytes(raw[2..10].try_into().map_err(|_| Error::Encoding)?);
            let previous = raw[10..42].try_into().map_err(|_| Error::Encoding)?;
            if sequence == 0 || (sequence == 1) != (previous == [0; 32]) {
                return Err(Error::Context);
            }
            let work = &raw[42..];
            let prefix = WORK_DOMAIN.len() + 1;
            if &work[..WORK_DOMAIN.len()] != WORK_DOMAIN || work[WORK_DOMAIN.len()] != 0 {
                return Err(Error::Encoding);
            }
            let header = WorkHeader::decode(&work[prefix..]).map_err(|_| Error::Encoding)?;
            if header.work_bytes() != work {
                return Err(Error::Encoding);
            }
            let c = &header.candidate;
            if c.network != NETWORK_ID
                || c.genesis != scope.genesis
                || c.fingerprint != scope.fingerprint
                || c.license != scope.license
                || c.worker != scope.worker
            {
                return Err(Error::Context);
            }
            Ok(Incoming::Result(Submission {
                sequence,
                previous,
                header,
            }))
        }
        _ => Err(Error::Encoding),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_packet_has_one_exact_bounded_descriptor_and_no_inbound_authority() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/worker-accounting-public-v1.json"
        ))
        .unwrap();
        let packet: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/worker-observation-packet-public-v1.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        assert_eq!(packet["production_authorized"], false);
        let d = hex::decode(f["descriptor"].as_str().unwrap()).unwrap();
        let r = hex::decode(f["receipt"].as_str().unwrap()).unwrap();
        let expected = hex::decode(packet["packet"].as_str().unwrap()).unwrap();
        assert_eq!(receipt_packet(&d, &r).unwrap(), expected);
        assert!(expected.len() <= RECEIPT_PACKET_MAX);
        for cut in [0, 1, 278, 1671] {
            assert!(receipt_packet(&d, &r[..cut]).is_err());
        }
        let mut long = r.clone();
        long.push(0);
        assert!(receipt_packet(&d, &long).is_err());
        for at in [0, 1, 165, 196] {
            let mut bad = r.clone();
            bad[at] ^= 1;
            assert!(receipt_packet(&d, &bad).is_err());
        }
        assert!(receipt_packet(&[], &r).is_err());
        assert!(receipt_packet(&vec![0; 2049], &r).is_err());
        let mut bad = d.clone();
        bad[0] ^= 1;
        assert!(receipt_packet(&bad, &r).is_err());
        assert!(decode(&expected, scope()).is_err()); // wrong direction
    }
    fn scope() -> Scope {
        Scope {
            genesis: [1; 32],
            fingerprint: [2; 32],
            license: [3; 32],
            worker: [4; 32],
        }
    }
    #[test]
    fn bounded_status_request_and_wrong_direction_messages() {
        let mut status = vec![2, 1, 0];
        status.extend(7u64.to_be_bytes());
        status.push(4);
        assert_eq!(
            decode(&status, scope()).unwrap(),
            Incoming::Status {
                run: true,
                faults: 0,
                accepted_total: Some(7),
                state: 4
            }
        );
        status[2] = 2;
        assert!(decode(&status, scope()).is_err());
        status[3..11].fill(0);
        assert!(matches!(
            decode(&status, scope()),
            Ok(Incoming::Status {
                accepted_total: None,
                ..
            })
        ));
        for cut in 0..status.len() {
            assert!(decode(&status[..cut], scope()).is_err());
        }
        let mut request = vec![5];
        request.extend([8; 32]);
        request.extend([0; 40]);
        assert!(matches!(
            decode(&request, scope()),
            Ok(Incoming::Request { sequence: 0, .. })
        ));
        request[41] = 1;
        assert!(decode(&request, scope()).is_err());
        request[41] = 0;
        request[1..33].fill(0);
        assert!(decode(&request, scope()).is_err());
        for kind in [0, 1, 4, 6, 7, 255] {
            assert!(decode(&vec![kind; 311], scope()).is_err());
        }
        assert!(decode(&vec![3; SUBMISSION_MAX + 2], scope()).is_err());
    }
    #[test]
    fn canonical_result_scope_and_checkpoint_before_any_acceptance() {
        let s = scope();
        let header = WorkHeader {
            candidate: mutiny_consensus_v8::pow::Candidate {
                network: NETWORK_ID,
                genesis: s.genesis,
                fingerprint: s.fingerprint,
                parent: [5; 32],
                height: 1,
                timestamp: 100,
                body_root: [6; 32],
                state_root: [7; 32],
                license: s.license,
                worker: s.worker,
                target: [0xff; 32],
            },
            authority: [8; 32],
            nonce: 9,
        };
        let submission = Submission {
            sequence: 1,
            previous: [0; 32],
            header,
        };
        let mut wire = vec![3];
        wire.extend(submission.encode());
        assert_eq!(decode(&wire, s).unwrap(), Incoming::Result(submission));
        for cut in 0..wire.len() {
            assert!(decode(&wire[..cut], s).is_err());
        }
        for changed in [
            Scope {
                genesis: [9; 32],
                ..s
            },
            Scope {
                fingerprint: [9; 32],
                ..s
            },
            Scope {
                license: [9; 32],
                ..s
            },
            Scope {
                worker: [9; 32],
                ..s
            },
        ] {
            assert!(decode(&wire, changed).is_err());
        }
        let mut bad = wire.clone();
        bad[10] = 1;
        assert!(decode(&bad, s).is_err());
        let mut bad = wire.clone();
        bad[2..10].fill(0);
        assert!(decode(&bad, s).is_err());
        wire.push(0);
        assert!(decode(&wire, s).is_err());
    }
}
