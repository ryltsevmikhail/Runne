// Durable identity of admitted workspace roots; existing data remains untouched.
const MIGRATION_V70: &str = "
CREATE TABLE workspace_root_identities (
 runtime_authority_id TEXT NOT NULL CHECK(length(runtime_authority_id) BETWEEN 1 AND 256),
 principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
 workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16),
 filesystem_identity_digest BLOB NOT NULL CHECK(length(filesystem_identity_digest)=32),
 root_version INTEGER NOT NULL CHECK(root_version>0),
 PRIMARY KEY(runtime_authority_id,principal_id,workspace_id),
 UNIQUE(runtime_authority_id,principal_id,filesystem_identity_digest),
 FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id)
);";
const V70_TRIGGERS: &[(&str, &str)] = &[
    (
        "workspace_root_identities_immutable",
        "CREATE TRIGGER workspace_root_identities_immutable BEFORE UPDATE ON workspace_root_identities WHEN NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.principal_id!=OLD.principal_id OR NEW.workspace_id!=OLD.workspace_id OR NEW.root_version<=OLD.root_version BEGIN SELECT RAISE(ABORT,'workspace root identity is immutable'); END",
    ),
    (
        "workspace_root_identities_no_delete",
        "CREATE TRIGGER workspace_root_identities_no_delete BEFORE DELETE ON workspace_root_identities BEGIN SELECT RAISE(ABORT,'workspace root identity is retained'); END",
    ),
];
const V70_FENCES: &[(&str, &str)] = &[
    (
        "schema_v12_fence_workspace_root_identities_insert",
        "CREATE TRIGGER \"schema_v12_fence_workspace_root_identities_insert\" AFTER INSERT ON \"workspace_root_identities\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_workspace_root_identities_update",
        "CREATE TRIGGER \"schema_v12_fence_workspace_root_identities_update\" AFTER UPDATE ON \"workspace_root_identities\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_workspace_root_identities_delete",
        "CREATE TRIGGER \"schema_v12_fence_workspace_root_identities_delete\" AFTER DELETE ON \"workspace_root_identities\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

fn apply_v70_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    if !v69_matches(&tx, 69)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    tx.execute_batch(MIGRATION_V70)?;
    for (_, sql) in V70_TRIGGERS.iter().chain(V70_FENCES) {
        tx.execute_batch(sql)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(70)", [])?;
    if !v70_matches(&tx, 70)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    tx.commit()
}

fn v70_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 70 | 71)
        || !v69_matches(connection, version)?
        || !table_sql_matches_migration(connection, "workspace_root_identities", MIGRATION_V70)?
    {
        return Ok(false);
    }
    for (name, sql) in V70_TRIGGERS.iter().chain(V70_FENCES) {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v70_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("workspace_root_identities");
    triggers.extend_from_slice(V70_TRIGGERS);
    triggers.extend_from_slice(V70_FENCES);
}

#[cfg(test)]
mod terminal_root_schema_tests {
    use super::*;
    #[test]
    fn additive_root_identity_migration_preserves_v69_and_rejects_drift() {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 69).unwrap();
        assert!(v69_matches(&connection, 69).unwrap());
        let rows: i64 = connection
            .query_row("SELECT count(*) FROM schema_version", [], |row| row.get(0))
            .unwrap();
        apply_v70_migration(&connection).unwrap();
        assert!(v70_matches(&connection, 70).unwrap());
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM schema_version", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            rows + 1
        );
        connection
            .execute_batch("DROP TRIGGER workspace_root_identities_no_delete")
            .unwrap();
        assert!(!v70_matches(&connection, 70).unwrap());
    }
}
