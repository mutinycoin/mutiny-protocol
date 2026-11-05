use mutiny_consensus_v8::{Hash, rollback::*};
use sha2::{Digest, Sha256};
#[derive(Default)]
struct FakeNv {
    tip: Hash,
    writes: usize,
    fail_after_write: bool,
}
impl PersistentAnchor for FakeNv {
    fn read(&mut self) -> Result<Hash, String> {
        Ok(self.tip)
    }
    fn extend(&mut self, event: Hash) -> Result<(), String> {
        self.tip = Sha256::digest([self.tip.as_slice(), event.as_slice()].concat()).into();
        self.writes += 1;
        if self.fail_after_write {
            Err("power interruption after NV write".into())
        } else {
            Ok(())
        }
    }
}
#[test]
fn interrupted_nv_extension_recovers_but_disk_rollback_cannot_reset_hardware() {
    let path = std::env::temp_dir().join(format!(
        "build8-anchor-journal-{}.sqlite",
        std::process::id()
    ));
    assert!(!path.exists());
    let mut nv = FakeNv::default();
    {
        let journal = AnchorJournal::open(&path, [1; 32], &mut nv).unwrap();
        drop(journal);
    }
    let old = std::fs::read(&path).unwrap();
    {
        let mut j = AnchorJournal::open(&path, [1; 32], &mut nv).unwrap();
        nv.fail_after_write = true;
        assert!(matches!(
            j.protect(b"reserved vote A", &mut nv),
            Err(AnchorError::Backend)
        ));
    }
    assert_eq!(nv.writes, 1);
    {
        let mut j = AnchorJournal::open(&path, [1; 32], &mut nv).unwrap();
        assert!(matches!(
            j.protect(b"different vote B", &mut nv),
            Err(AnchorError::PendingDifferentReservation)
        ));
        nv.fail_after_write = false;
        j.protect(b"reserved vote A", &mut nv).unwrap();
        j.protect(b"reserved vote A", &mut nv).unwrap();
        assert_eq!(nv.writes, 1);
        j.protect(b"next reserved vote B", &mut nv).unwrap();
    }
    assert_eq!(nv.writes, 2);
    std::fs::write(&path, old).unwrap(); // restore simulated old disk only
    {
        let mut j = AnchorJournal::open(&path, [1; 32], &mut nv).unwrap();
        assert!(matches!(
            j.protect(b"conflicting restored vote", &mut nv),
            Err(AnchorError::Rollback)
        ));
    }
    assert_eq!(nv.writes, 2);
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        AnchorJournal::open(&path, [1; 32], &mut nv),
        Err(AnchorError::Rollback)
    ));
    std::fs::remove_file(path).unwrap();
}
