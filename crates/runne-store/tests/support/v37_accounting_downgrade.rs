use rusqlite::{Connection, Result as SqliteResult, Transaction, TransactionBehavior};

const ADMISSIONS: &str = "provider_execution_admissions";
const RESERVATIONS: &str = "provider_budget_reservations";

/// Rebuild the two V37 tables with their V36 checks while preserving rows and
/// table-bound objects.  Historical fixture tests remove later schema markers
/// but still start from a current database, so dropping only the markers does
/// not create a valid V36 database.
pub fn restore_v36_accounting(connection: &Connection) -> SqliteResult<()> {
    connection.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")?;
    let result = (|| {
        let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
        restore_table(
            &tx,
            ADMISSIONS,
            "max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros >= 0), currency TEXT NOT NULL CHECK(length(currency) = 3 AND (max_cost_micros > 0 OR currency = 'XXX'))",
            "max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros > 0), currency TEXT NOT NULL CHECK(length(currency) = 3)",
        )?;
        restore_table(
            &tx,
            RESERVATIONS,
            "amount INTEGER NOT NULL CHECK(amount > 0 OR (dimension = 2 AND amount = 0))",
            "amount INTEGER NOT NULL CHECK(amount > 0)",
        )?;
        tx.execute("DELETE FROM schema_version WHERE version >= 37", [])?;
        tx.commit()
    })();
    let restore =
        connection.execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;");
    result.and(restore)
}

fn restore_table(
    tx: &Transaction<'_>,
    table: &str,
    current_fragment: &str,
    old_fragment: &str,
) -> SqliteResult<()> {
    let source: String = tx.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    let objects = table_objects(tx, table)?;
    let old = format!("{table}_v37");
    tx.execute(&format!("ALTER TABLE {table} RENAME TO {old}"), [])?;
    let rewritten = source.replace(current_fragment, old_fragment);
    if rewritten == source || !rewritten.contains(old_fragment) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    tx.execute_batch(&rewritten)?;
    tx.execute(&format!("INSERT INTO {table} SELECT * FROM {old}"), [])?;
    tx.execute(&format!("DROP TABLE {old}"), [])?;
    for (_, _, sql) in objects {
        tx.execute_batch(&sql)?;
    }
    Ok(())
}

fn table_objects(tx: &Transaction<'_>, table: &str) -> SqliteResult<Vec<(String, String, String)>> {
    tx.prepare(
        "SELECT type, name, sql FROM sqlite_master
         WHERE tbl_name = ?1 AND type IN ('index', 'trigger') AND sql IS NOT NULL
         ORDER BY type, name",
    )?
    .query_map([table], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
    .collect()
}
