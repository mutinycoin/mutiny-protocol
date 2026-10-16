//! Typed payloads carried by mutually authenticated Worker session frames.
//! Operational status never substitutes for canonical state or a receipt.
use mutiny_consensus_v8::{
    Hash,
    observations::{Receipt, SUBMISSION_MAX, Submission},
    work_issuance::IssuedWork,
};
type Result<T> = std::result::Result<T, String>;
#[derive(Debug, PartialEq, Eq)]
pub enum WorkerMessage {
    Status {
        run: bool,
        faults: u8,
        accepted_total: Option<u64>,
        state: u8,
    },
    Result(Submission),
    Request {
        nonce: Hash,
        sequence: u64,
        chain: Hash,
    },
}
pub fn decode(raw: &[u8]) -> Result<WorkerMessage> {
    match raw.first() {
        Some(2) if raw.len() == 12 && raw[1] <= 1 && raw[2] <= 15 && raw[11] <= 5 => {
            let total = u64::from_be_bytes(raw[3..11].try_into().unwrap());
            if raw[2] & 2 != 0 && total != 0 {
                return Err("Unavailable total must have zero placeholder".into());
            }
            Ok(WorkerMessage::Status {
                run: raw[1] == 1,
                faults: raw[2],
                accepted_total: (raw[2] & 2 == 0).then_some(total),
                state: raw[11],
            })
        }
        Some(3) if raw.len() <= SUBMISSION_MAX + 1 => Ok(WorkerMessage::Result(
            Submission::decode(&raw[1..]).map_err(|e| format!("Result submission: {e:?}"))?,
        )),
        Some(5) if raw.len() == 73 => {
            let nonce: Hash = raw[1..33].try_into().unwrap();
            let sequence = u64::from_be_bytes(raw[33..41].try_into().unwrap());
            let chain: Hash = raw[41..73].try_into().unwrap();
            if nonce == [0; 32] || (sequence == 0) != (chain == [0; 32]) {
                return Err("Work request checkpoint".into());
            }
            Ok(WorkerMessage::Request {
                nonce,
                sequence,
                chain,
            })
        }
        _ => Err("Unknown, malformed or oversized Worker message".into()),
    }
}
pub fn heartbeat() -> [u8; 1] {
    [1]
}
pub fn retire() -> [u8; 1] {
    [7]
}
pub fn waiting_quorum(request: Hash) -> Result<Vec<u8>> {
    if request == [0; 32] {
        return Err("Zero work request".into());
    }
    let mut raw = vec![6];
    raw.extend(request);
    Ok(raw)
}
pub fn offer(work: &IssuedWork, request: Hash, lifetime_ms: u64) -> Result<Vec<u8>> {
    work.offer(request, lifetime_ms)
}
pub fn receipt(receipt: &Receipt) -> Vec<u8> {
    let mut raw = vec![4];
    raw.extend(receipt.encode());
    raw
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_unknown_totals_requests_and_exact_results() {
        let mut status = vec![2, 1, 0];
        status.extend(123u64.to_be_bytes());
        status.push(4);
        assert_eq!(
            decode(&status).unwrap(),
            WorkerMessage::Status {
                run: true,
                faults: 0,
                accepted_total: Some(123),
                state: 4
            }
        );
        status[2] = 2;
        assert!(decode(&status).is_err());
        status[3..11].fill(0);
        assert_eq!(
            decode(&status).unwrap(),
            WorkerMessage::Status {
                run: true,
                faults: 2,
                accepted_total: None,
                state: 4
            }
        );
        for at in [0, 1, 2, 11] {
            let mut bad = status.clone();
            bad[at] = 255;
            assert!(decode(&bad).is_err());
        }
        for cut in 0..status.len() {
            assert!(decode(&status[..cut]).is_err());
        }
        let mut request = vec![5];
        request.extend([9; 32]);
        request.extend([0; 40]);
        assert_eq!(
            decode(&request).unwrap(),
            WorkerMessage::Request {
                nonce: [9; 32],
                sequence: 0,
                chain: [0; 32]
            }
        );
        request[1..].fill(0);
        assert!(decode(&request).is_err());
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/OBSERVATION-FIXTURE-V2.json"
        ))
        .unwrap();
        let mut result = vec![3];
        result.extend(hex::decode(fixture["submission_hex"].as_str().unwrap()).unwrap());
        let WorkerMessage::Result(header) = decode(&result).unwrap() else {
            panic!("result")
        };
        assert_eq!(header.encode(), result[1..]);
        for cut in 0..result.len() {
            assert!(decode(&result[..cut]).is_err());
        }
        result.push(0);
        assert!(decode(&result).is_err());
        let decoded =
            Receipt::decode(&hex::decode(fixture["receipt_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(receipt(&decoded).len(), 311);
        assert_eq!(heartbeat(), [1]);
        assert_eq!(retire(), [7]);
        assert_eq!(waiting_quorum([1; 32]).unwrap().len(), 33);
    }
}
