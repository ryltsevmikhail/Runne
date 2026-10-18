use std::path::PathBuf;

use runne_store::ProjectTrustStore;

use super::support::{AUTHORITY, canonical};

#[test]
fn unknown_schema3_object_is_rejected_without_rewrite() {
    let root = tempfile::tempdir().unwrap();
    let path = canonical(root.path(), "catalog-tamper.sqlite");
    drop(ProjectTrustStore::open(&path, AUTHORITY).unwrap());
    let sidecar = PathBuf::from(format!("{}.project-trust", path.display()));
    let connection = rusqlite::Connection::open(&sidecar).unwrap();
    connection
        .execute(
            "CREATE TABLE rogue_object (id INTEGER PRIMARY KEY) STRICT",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(ProjectTrustStore::open(&path, AUTHORITY).is_err());
    let connection = rusqlite::Connection::open(&sidecar).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert!(
        connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE name='rogue_object'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .is_ok()
    );
}
