pub(super) const MIGRATION_V50: &str = r#"
CREATE TABLE provider_terminal_dispositions (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16),
 disposition INTEGER NOT NULL CHECK(disposition IN (1,2,3,4)),
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_accounting_settlements(dispatch_attempt_id)
);
CREATE TRIGGER provider_terminal_dispositions_immutable BEFORE UPDATE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END;
CREATE TRIGGER provider_terminal_dispositions_no_delete BEFORE DELETE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END;
"#;

pub(super) fn apply_v50_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V50)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("provider_terminal_dispositions", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(50)", [])?;
    tx.commit()
}

pub(super) fn v50_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 50 || !v49_matches(connection, 50)? {
        return Ok(false);
    }
    v50_disposition_objects_match(connection)
}

pub(super) fn v50_base_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 51..=71) {
        return Ok(false);
    }
    if !v49_matches(connection, version)? {
        return Ok(false);
    }
    if version >= 55 {
        let matches = v55_disposition_objects_match(connection)?;
        return Ok(matches);
    }
    v50_disposition_objects_match(connection)
}

fn v50_disposition_objects_match(connection: &Connection) -> SqliteResult<bool> {
    let expected = MIGRATION_V50
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with("CREATE TABLE provider_terminal_dispositions "))
        .expect("V50 disposition DDL is frozen");
    let actual: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_terminal_dispositions'",
        [], |row| row.get(0),
    ).optional()?;
    if actual.is_none_or(|sql| normalize_ddl(&sql) != normalize_ddl(expected)) {
        return Ok(false);
    }
    for (name, expected) in [
        (
            "provider_terminal_dispositions_immutable",
            "CREATE TRIGGER provider_terminal_dispositions_immutable BEFORE UPDATE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END",
        ),
        (
            "provider_terminal_dispositions_no_delete",
            "CREATE TRIGGER provider_terminal_dispositions_no_delete BEFORE DELETE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END",
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(expected)) {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) = v12_fence_trigger("provider_terminal_dispositions", operation);
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [&name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(&expected)) {
            return Ok(false);
        }
    }
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_terminal_dispositions d
         LEFT JOIN provider_accounting_settlements s USING(dispatch_attempt_id)
         LEFT JOIN provider_dispatch_attempts a ON a.attempt_id=d.dispatch_attempt_id
         WHERE s.dispatch_attempt_id IS NULL OR a.attempt_id IS NULL
           OR a.settlement_digest!=s.settlement_digest
           OR NOT (
             (d.disposition=1 AND (
               (a.state=4 AND EXISTS(SELECT 1 FROM provider_terminal_outbox o
                 WHERE o.dispatch_attempt_id=d.dispatch_attempt_id
                   AND o.settlement_digest=s.settlement_digest AND o.state=1
                   AND o.receipt_digest IS NULL AND o.applied_at IS NULL))
               OR (a.state=5 AND EXISTS(SELECT 1 FROM provider_terminal_outbox o
                 WHERE o.dispatch_attempt_id=d.dispatch_attempt_id
                   AND o.settlement_digest=s.settlement_digest AND o.state=2
                   AND o.receipt_digest IS NOT NULL AND o.applied_at IS NOT NULL))
             ))
             OR (d.disposition IN (2,3,4) AND a.state=5
               AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox o
                 WHERE o.dispatch_attempt_id=d.dispatch_attempt_id))
           )",
        [],
        |row| row.get(0),
    )?;
    Ok(invalid == 0)
}
