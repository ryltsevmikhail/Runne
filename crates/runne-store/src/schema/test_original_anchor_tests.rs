use super::*;

fn fresh(path: &Path) -> ManagedConnection {
    let connection = open_managed_connection(path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection
}

#[test]
fn anchor_outlives_original_connection_and_matches_reader() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("original.sqlite");
    let original = fresh(&path);
    let anchor = original.retain_test_original_anchor().unwrap();
    drop(original);
    let reader = open_managed_connection(&path, ConnectionMode::Reader).unwrap();
    anchor.verify_reader(&reader).unwrap();
    assert_eq!(reader.query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get::<_, i64>(0)).unwrap(), CURRENT_SCHEMA_VERSION);
}

#[test]
fn matching_contents_do_not_replace_original_inode() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("original.sqlite");
    let original = fresh(&path);
    let anchor = original.retain_test_original_anchor().unwrap();
    drop(original);
    std::fs::rename(&path, root.path().join("retained-original.sqlite")).unwrap();
    drop(fresh(&path));
    let replacement = open_managed_connection(&path, ConnectionMode::Reader).unwrap();
    assert!(anchor.verify().is_err());
    assert!(anchor.verify_reader(&replacement).is_err());
}

#[test]
fn independent_database_and_writer_are_not_original_reader() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("original.sqlite");
    let original = fresh(&path);
    let anchor = original.retain_test_original_anchor().unwrap();
    assert!(anchor.verify_reader(&original).is_err());
    drop(original);
    let other = root.path().join("other.sqlite");
    drop(fresh(&other));
    let different = open_managed_connection(&other, ConnectionMode::Reader).unwrap();
    assert!(anchor.verify_reader(&different).is_err());
}

#[test]
fn identityless_shared_writer_cannot_issue_original_anchor() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("shared.sqlite");
    let shared = open_test_shared_writer(&path).unwrap();
    assert!(shared.retain_test_original_anchor().is_err());
}
