use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
fn base() -> super::test_dir::TestDir {
    super::test_dir::TestDir::new("synthetic-public")
}
fn target(p: &Path, g: u64) -> std::path::PathBuf {
    p.join(name([1; 32], g).unwrap().to_str().unwrap())
}
#[test]
fn publishes_exact_bounded_generation_without_overwrite() {
    let p = base();
    publish(&p, [1; 32], 1, b"PUBLIC SYNTHETIC ENVELOPE").unwrap();
    assert_eq!(read(&p, [1; 32], 1).unwrap(), b"PUBLIC SYNTHETIC ENVELOPE");
    assert!(publish(&p, [1; 32], 1, b"replacement").is_err());
    assert_eq!(read(&p, [1; 32], 1).unwrap(), b"PUBLIC SYNTHETIC ENVELOPE");
    assert!(publish(&p, [0; 32], 1, b"fixture").is_err());
    assert!(publish(&p, [1; 32], 0, b"fixture").is_err());
    assert!(publish(&p, [1; 32], 2, &[]).is_err());
    assert!(publish(&p, [1; 32], 2, &vec![0; LIMIT + 1]).is_err());
    publish(&p, [1; 32], 2, &vec![42; LIMIT]).unwrap();
    assert_eq!(read(&p, [1; 32], 2).unwrap(), vec![42; LIMIT]);
    assert!(read(&p, [2; 32], 1).is_err());
    assert!(read(&p, [1; 32], 3).is_err());
    assert!(std::fs::read_dir(&p).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pending-")
    }));
}
#[test]
fn rejects_unsafe_paths_and_existing_objects() {
    let p = base();
    let other = base();
    publish(&other, [1; 32], 1, b"PUBLIC OLD").unwrap();
    symlink(target(&other, 1), target(&p, 1)).unwrap();
    assert!(publish(&p, [1; 32], 1, b"new").is_err());
    assert!(read(&p, [1; 32], 1).is_err());
    assert_eq!(read(&other, [1; 32], 1).unwrap(), b"PUBLIC OLD");
    std::fs::create_dir(target(&p, 2)).unwrap();
    assert!(publish(&p, [1; 32], 2, b"new").is_err());
    let linked = p.join("linked");
    symlink(&other, &linked).unwrap();
    assert!(publish(&linked, [1; 32], 3, b"new").is_err());
    std::fs::hard_link(target(&other, 1), target(&p, 3)).unwrap();
    assert!(read(&p, [1; 32], 3).is_err());
    assert!(read(&other, [1; 32], 1).is_err());
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(publish(&p, [1; 32], 4, b"new").is_err());
    assert!(publish(Path::new("relative"), [1; 32], 1, b"new").is_err());
    assert!(publish(&other.join(".."), [1; 32], 1, b"new").is_err());
}
#[test]
fn trusted_search_only_ancestor_needs_no_directory_listing_access() {
    let p = base();
    let ancestor = p.join("search-only");
    let private = ancestor.join("private");
    std::fs::create_dir(&ancestor).unwrap();
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o111)).unwrap();
    publish(&private, [1; 32], 1, b"PUBLIC SEARCH-ONLY ANCESTOR").unwrap();
    assert_eq!(read(&private, [1; 32], 1).unwrap(), b"PUBLIC SEARCH-ONLY ANCESTOR");
    assert_eq!(std::fs::metadata(&ancestor).unwrap().permissions().mode() & 0o777, 0o111);
    // Opening with O_PATH must not bypass the unchanged replaceable-ancestor rule.
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o733)).unwrap();
    assert_eq!(publish(&private, [1; 32], 2, b"PUBLIC REFUSED"), Err("unsafe ancestor"));
    assert_eq!(read(&private, [1; 32], 1), Err("unsafe ancestor"));
    // Restore only this test-created directory for successful fixture cleanup.
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
}
#[test]
fn child_publication_crash() {
    let Ok(raw) = std::env::var("BUILD8_SYNTHETIC_STORE_CHILD") else {
        return;
    };
    let p = std::path::PathBuf::from(raw).canonicalize().unwrap();
    assert_eq!(
        p.parent().unwrap(),
        std::env::temp_dir()
            .canonicalize()
            .unwrap()
    );
    assert!(
        p.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("build8-synthetic-public-")
    );
    let point = std::env::var("BUILD8_SYNTHETIC_STORE_POINT")
        .unwrap()
        .parse::<u8>()
        .unwrap();
    assert!((1..=4).contains(&point));
    CRASH.with(|v| v.set(point));
    publish(&p, [1; 32], 2, b"PUBLIC NEW COMPLETE").unwrap();
    panic!("crash point not reached");
}
#[test]
fn process_interruption_never_replaces_old_or_publishes_partial_target() {
    for point in 1..=4 {
        let p = base();
        publish(&p, [1; 32], 1, b"PUBLIC OLD COMPLETE").unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "continuity_generation_store_v2::tests::child_publication_crash",
                "--nocapture",
            ])
            .env("BUILD8_SYNTHETIC_STORE_CHILD", p.path())
            .env("BUILD8_SYNTHETIC_STORE_POINT", point.to_string())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(91));
        assert_eq!(read(&p, [1; 32], 1).unwrap(), b"PUBLIC OLD COMPLETE");
        if point < 3 {
            assert!(!target(&p, 2).exists());
            publish(&p, [1; 32], 2, b"PUBLIC NEW COMPLETE").unwrap();
        } else {
            assert!(publish(&p, [1; 32], 2, b"replacement").is_err());
        }
        assert_eq!(read(&p, [1; 32], 2).unwrap(), b"PUBLIC NEW COMPLETE");
    }
}

#[test]
fn node_namespace_never_substitutes_continuity_file() {
    let p = base();
    publish(&p, [1; 32], 1, b"PUBLIC CONTINUITY").unwrap();
    assert!(read_node(&p, [1; 32], 1).is_err());
    publish_node(&p, [1; 32], 1, b"PUBLIC NODE").unwrap();
    assert_eq!(read_node(&p, [1; 32], 1).unwrap(), b"PUBLIC NODE");
    assert_eq!(read(&p, [1; 32], 1).unwrap(), b"PUBLIC CONTINUITY");
    assert!(publish_node(&p, [1; 32], 1, b"replacement").is_err());
    let missing = p.join(
        name_for(Namespace::Node, [1; 32], 2)
            .unwrap()
            .to_str()
            .unwrap(),
    );
    symlink(target(&p, 1), &missing).unwrap();
    assert!(read_node(&p, [1; 32], 2).is_err());
    assert!(publish_node(&p, [1; 32], 2, b"replacement").is_err());
}
