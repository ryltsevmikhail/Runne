use super::{Connection, LocalStore};

#[test]
fn v1_and_v2_databases_migrate_to_the_exact_v5_schema() {
    for (version, projects) in [(1, false), (2, true)] {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join(format!("v{version}.sqlite3"));
        let connection = Connection::open(&path).expect("create historical database");
        connection
            .execute_batch(
                "CREATE TABLE settings (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1) STRICT;",
            )
            .expect("v1 schema");
        if projects {
            connection
                .execute_batch(
                    "CREATE TABLE projects (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE, last_opened_at INTEGER NOT NULL) STRICT;",
                )
                .expect("v2 projects");
        }
        connection
            .pragma_update(None, "user_version", version)
            .expect("historical version");
        drop(connection);

        let store = LocalStore::open(&path).expect("migrate historical database");
        assert_eq!(store.diagnostics().expect("diagnostics").schema_version, 5);
        drop(store);
        let connection = Connection::open(path).expect("inspect v5");
        let meta: (i64, i64) = connection
            .query_row("SELECT singleton, schema_version FROM meta", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("v5 meta");
        assert_eq!(meta, (1, 5));
    }
}
