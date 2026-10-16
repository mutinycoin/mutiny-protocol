#![cfg(feature = "legacy-v0-test-fixtures")]
use mutiny_consensus_v8::{
    Hash, NETWORK_ID, anchors::FinalizedAnchor, bft::Step, certificates::Voter, voter::*,
    votes::HeightAuthority,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
use std::path::PathBuf;
struct TestSigner {
    key: SigningKey,
    journal: PathBuf,
    locks: PathBuf,
    calls: usize,
    fail: bool,
}
impl GuardedSigner for TestSigner {
    fn public_key(&self) -> [u8; 33] {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }
    fn sign_reserved(
        &mut self,
        _context: Hash,
        message: &[u8],
        digest: Hash,
    ) -> Result<[u8; 64], String> {
        self.calls += 1;
        let db = rusqlite::Connection::open(&self.journal).unwrap();
        let reserved: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM votes WHERE message=?1)",
                [message],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            reserved,
            "TPM must never be invoked before durable reservation"
        );
        let db = rusqlite::Connection::open(&self.locks).unwrap();
        let revision: Vec<u8> = db
            .query_row("SELECT revision FROM bft_state", [], |r| r.get(0))
            .unwrap();
        assert!(u64::from_be_bytes(revision.try_into().unwrap()) > 0);
        if self.fail {
            return Err("simulated backend interruption; reservation remains".into());
        }
        let s: Signature = self.key.sign_prehash(&digest).unwrap();
        Ok(s.normalize_s().unwrap_or(s).to_bytes().into())
    }
}
#[test]
fn signing_is_reserved_before_backend_and_restart_reuses_persisted_signature() {
    let dir = std::env::temp_dir();
    let locks = dir.join(format!(
        "build8-durable-voter-lock-{}.sqlite",
        std::process::id()
    ));
    let journal = dir.join(format!(
        "build8-durable-voter-journal-{}.sqlite",
        std::process::id()
    ));
    assert!(!locks.exists() && !journal.exists());
    let key = SigningKey::from_bytes((&[30; 32]).into()).unwrap();
    let public = key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let authority = || HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 0,
            block: [3; 32],
        },
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
        voters: [(
            [7; 32],
            Voter {
                key_version: 1,
                public_key: public,
                weight: U256::one(),
            },
        )]
        .into_iter()
        .collect(),
    };
    let mut signer = TestSigner {
        key,
        journal: journal.clone(),
        locks: locks.clone(),
        calls: 0,
        fail: true,
    };
    {
        let mut first = DurableVoter::open(&locks, &journal, authority(), [7; 32]).unwrap();
        let mut stale = DurableVoter::open(&locks, &journal, authority(), [7; 32]).unwrap();
        assert!(matches!(
            first.sign(Step::Prevote, None, None, &mut signer),
            Err(VoterError::Backend)
        ));
        assert!(stale.sign(Step::Prevote, None, None, &mut signer).is_err());
        assert_eq!(signer.calls, 1);
    }
    signer.fail = false;
    let signed;
    {
        let mut restarted = DurableVoter::open(&locks, &journal, authority(), [7; 32]).unwrap();
        signed = restarted
            .sign(Step::Prevote, None, None, &mut signer)
            .unwrap();
        assert_eq!(signer.calls, 2);
        let duplicate = restarted
            .sign(Step::Prevote, None, None, &mut signer)
            .unwrap();
        assert_eq!(duplicate, signed);
        assert_eq!(signer.calls, 2);
    }
    {
        let mut restarted = DurableVoter::open(&locks, &journal, authority(), [7; 32]).unwrap();
        assert_eq!(
            restarted
                .sign(Step::Prevote, None, None, &mut signer)
                .unwrap(),
            signed
        );
        assert_eq!(signer.calls, 2);
    }
    {
        let mut wrong = authority();
        wrong.membership = [99; 32];
        let mut restarted = DurableVoter::open(&locks, &journal, wrong, [7; 32]).unwrap();
        assert!(
            restarted
                .sign(Step::Prevote, None, None, &mut signer)
                .is_err()
        );
        assert_eq!(signer.calls, 2);
    }
    std::fs::remove_file(locks).unwrap();
    std::fs::remove_file(journal).unwrap();
}
