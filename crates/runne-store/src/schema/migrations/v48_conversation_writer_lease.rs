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
    if !matches!(version, 48..=63) {
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
    if actual.is_none_or(|sql| normalize_ddl(&sql) != normalize_ddl(expected)) {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(
        marker,
        (48, 1, 47, 1157)
            | (48, 1, 48, 1176)
            | (49, 1, 48, 1206)
            | (49, 1, 49, 1225)
            | (50, 1, 49, 1256)
            | (50, 1, 50, 1275)
            | (51, 1, 50, 1307)
            | (51, 1, 51, 1326)
            | (52, 1, 51, 1359)
            | (52, 1, 52, 1378)
            | (53, 1, 52, 1412)
            | (53, 1, 53, 1431)
            | (54, 1, 53, 1466)
            | (54, 1, 54, 1485)
            | (55, 1, 54, 1521)
            | (55, 1, 55, 1540)
            | (56, 1, 55, 1577)
            | (56, 1, 56, 1596)
            | (57, 1, 56, 1634)
            | (57, 1, 57, 1653)
            | (58, 1, 57, 1692)
            | (58, 1, 58, 1711)
            | (59, 1, 58, 1751)
            | (59, 1, 59, 1770)
            | (60, 1, 59, 1811)
            | (60, 1, 60, 1830)
            | (61, 1, 60, 1872)
            | (61, 1, 61, 1891)
            | (62, 1, 61, 1934)
            | (62, 1, 62, 1953)
            | (63, 1, 62, 1997)
            | (63, 1, 63, 2016)
            | (64, 1, 63, 2061)
            | (64, 1, 64, 2080)
    ))
}
