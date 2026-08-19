use std::fs;
use std::path::Path;

#[test]
fn backup_failpoints_are_semantic_and_platform_neutral() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = fs::read_to_string(root.join("src/recent_root_backup_files.rs"))
        .expect("backup file source");
    let points = fs::read_to_string(root.join("src/recent_root_backup_failpoint.rs"))
        .expect("failpoint source");
    for phase in [
        "after-private-create",
        "after-snapshot",
        "after-file-durable",
        "after-publish",
        "after-publish-durable",
    ] {
        assert!(points.contains(phase), "missing {phase}");
    }
    assert!(files.contains("#[cfg(windows)]"));
    assert_eq!(files.matches("hit(AFTER_PUBLISH)").count(), 2);
    assert_eq!(files.matches("hit(AFTER_PUBLISH_DURABLE)").count(), 2);
    for legacy in ["after-chmod", "after-link", "after-parent-sync"] {
        assert!(!files.contains(legacy), "legacy {legacy}");
    }
}
