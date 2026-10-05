fn restore_v36_accounting_for_fixture(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")?;
    for (table, current, old) in [
        (
            "provider_execution_admissions",
            "max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros >= 0), currency TEXT NOT NULL CHECK(length(currency) = 3 AND (max_cost_micros > 0 OR currency = 'XXX'))",
            "max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros > 0), currency TEXT NOT NULL CHECK(length(currency) = 3)",
        ),
        (
            "provider_budget_reservations",
            "amount INTEGER NOT NULL CHECK(amount > 0 OR (dimension = 2 AND amount = 0))",
            "amount INTEGER NOT NULL CHECK(amount > 0)",
        ),
    ] {
        let source: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        let objects: Vec<String> = connection
            .prepare("SELECT sql FROM sqlite_master WHERE tbl_name=?1 AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type,name")?
            .query_map([table], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let old_table = format!("{table}_v37");
        connection.execute(&format!("ALTER TABLE {table} RENAME TO {old_table}"), [])?;
        if source.matches(current).count() != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let rewritten = source.replace(current, old);
        connection.execute_batch(&rewritten)?;
        connection.execute(
            &format!("INSERT INTO {table} SELECT * FROM {old_table}"),
            [],
        )?;
        connection.execute(&format!("DROP TABLE {old_table}"), [])?;
        for sql in objects {
            connection.execute_batch(&sql)?;
        }
    }
    connection.execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;")?;
    Ok(())
}

fn admission_fields(path: &std::path::Path) -> (Vec<u8>, Vec<u8>, i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT dispatch_attempt_id, authority_id, authority_revision, issued_at
             FROM provider_execution_admissions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

fn admission_counts(path: &std::path::Path) -> (i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_execution_admissions),
                    (SELECT COUNT(*) FROM provider_online_dispatch_claim_providers)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}
