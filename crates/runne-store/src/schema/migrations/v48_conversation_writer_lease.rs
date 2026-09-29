pub(super) const MIGRATION_V48: &str = r#"
CREATE TABLE conversation_writer_leases (
 conversation_id BLOB PRIMARY KEY CHECK(length(conversation_id)=16),
 owner_principal TEXT NOT NULL CHECK(length(owner_principal) BETWEEN 1 AND 256),
 fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
 taken_at_unix INTEGER NOT NULL CHECK(taken_at_unix >= 0)
);
"#;

pub(super) fn apply_v48_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V48)?;
    tx.execute("INSERT INTO schema_version(version) VALUES(48)", [])?;
    tx.commit()
}

pub(super) fn v48_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 48 {
        return Ok(false);
    }
    if !v47_matches(connection, version)? {
        return Ok(false);
    }
    let expected = MIGRATION_V48
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with("CREATE TABLE conversation_writer_leases"))
        .expect("V48 lease DDL is frozen");
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='conversation_writer_leases'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(actual.is_some_and(|sql| normalize_ddl(&sql) == normalize_ddl(expected)))
}
