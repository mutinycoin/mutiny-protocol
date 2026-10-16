//! Isolated public cache process-exit faults. No live queue or device access.
use mutiny_transport_v2::objects::{Bitmap, ObjectKind, ObjectQueue, object_id};
use std::{path::PathBuf, process::Command};
#[path="../../consensus/tests/support/public_child_capture.rs"]
mod public_child_capture;
const PEER: [u8; 32] = [93; 32];
fn bytes() -> Vec<u8> {
    (0..32769).map(|i| (i % 251 + 1) as u8).collect()
}
#[test]
fn public_queue_fault_child() {
    let Some(path) = std::env::var_os("BUILD8_PUBLIC_QUEUE_FAULT_PATH") else {
        return;
    };
    public_child_capture::enter_public_child();
    let path = PathBuf::from(path);
    assert!(path.is_absolute());
    assert_eq!(path.file_name().unwrap(), "public-queue.sqlite");
    let mode = std::env::var("BUILD8_PUBLIC_QUEUE_FAULT_MODE").unwrap();
    if mode == "uncommitted" {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA cache_size=4; PRAGMA cache_spill=ON; BEGIN IMMEDIATE; UPDATE fragments SET attempts=8,acked=1,data=zeroblob(length(data));").unwrap();
        let journal = PathBuf::from(format!("{}-journal", path.display()));
        assert!(journal.metadata().unwrap().len() > 4096);
        // No destructor/connection close: leave a real hot rollback journal.
        std::process::exit(31);
    } else if mode == "committed" {
        let mut queue = ObjectQueue::open(&path, PEER).unwrap();
        let id = object_id(ObjectKind::SettlementProof, &bytes()).unwrap();
        assert!(
            queue
                .next_fragment(
                    &id,
                    &Bitmap {
                        start: 0,
                        bits: vec![true]
                    },
                    0
                )
                .unwrap()
                .is_some()
        );
        // Reservation is already committed; returned frame is deliberately lost.
        std::process::exit(32);
    } else {
        panic!("unknown public fault mode")
    }
}
#[test]
fn hot_journal_recovers_and_committed_retry_survives_process_exit() {
    let directory = std::env::temp_dir().join(format!(
        "build8-public-queue-crash-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&directory).unwrap());
    let path = directory.join("public-queue.sqlite");
    let mut queue = ObjectQueue::open(&path, PEER).unwrap();
    let public = bytes();
    let offer = queue.enqueue(ObjectKind::SettlementProof, &public).unwrap();
    let wanted = Bitmap {
        start: 0,
        bits: vec![true],
    };
    for _ in 0..7 {
        assert!(
            queue
                .next_fragment(&offer.id, &wanted, 0)
                .unwrap()
                .is_some()
        );
    }
    drop(queue);
    let run = |mode: &str, code: i32| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "public_queue_fault_child", "--nocapture"])
            .env("BUILD8_PUBLIC_QUEUE_FAULT_PATH", &path)
            .env("BUILD8_PUBLIC_QUEUE_FAULT_MODE", mode);
        public_child_capture::capture_public_child(command,&directory,code,&format!("queue-fault-{mode}"));
    };
    run("uncommitted", 31);
    let journal = PathBuf::from(format!("{}-journal", path.display()));
    assert!(journal.exists());
    let queue = ObjectQueue::open(&path, PEER).unwrap();
    assert_eq!(queue.read_complete(&offer.id).unwrap(), public);
    assert_eq!(
        queue.acknowledged(&offer.id, 0, 1).unwrap().bits,
        vec![false]
    );
    drop(queue);
    run("committed", 32);
    let mut queue = ObjectQueue::open(&path, PEER).unwrap();
    assert!(
        queue
            .next_fragment(&offer.id, &wanted, 0)
            .unwrap()
            .is_none()
    );
    assert_eq!(queue.read_complete(&offer.id).unwrap(), public);
    assert_eq!(
        queue.acknowledged(&offer.id, 0, 1).unwrap().bits,
        vec![false]
    );
    drop(queue);
    assert!(!journal.exists());
    println!("PRESERVED_PUBLIC_QUEUE_CRASH_EVIDENCE={}",directory.display());
}
