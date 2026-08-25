pub(super) const MIGRATION_V22: &str = r#"
ALTER TABLE process_registry
    ADD COLUMN intent_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK(length(intent_digest) = 32);
"#;

pub(super) fn apply_v22_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V22)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (22)", [])?;
    transaction.commit()
}

pub(super) fn v22_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 22
        || !replay_promotion_snapshot_schema::v20_catalog_matches(connection, true, false)?
    {
        return Ok(false);
    }
    let has_intent_digest = connection
        .prepare("PRAGMA table_info(process_registry)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<SqliteResult<Vec<_>>>()?
        .iter()
        .any(|name| name == "intent_digest");
    Ok(has_intent_digest)
}
