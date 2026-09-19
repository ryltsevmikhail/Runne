use rusqlite::{Connection, Result as SqliteResult, Transaction, TransactionBehavior};

const TABLE: &str = "task_run_workspace_lineage";
const FENCES: [&str; 3] = [
    "schema_v12_fence_task_run_workspace_lineage_insert",
    "schema_v12_fence_task_run_workspace_lineage_update",
    "schema_v12_fence_task_run_workspace_lineage_delete",
];

/// Rebuilds `task_run_workspace_lineage` with the historical V18 shape.
///
/// Downgrade fixtures that roll a freshly migrated database back below the
/// lineage-origin migration must restore the exact V18 CHECK constraint the
/// historical validators pin. The V18 DDL is derived from the live table by
/// reverting the submit-origin extension, and the V12 fence triggers are
/// preserved verbatim from the database itself.
pub fn restore_v18_lineage(connection: &Connection) -> SqliteResult<()> {
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [TABLE],
        |row| row.get(0),
    )?;
    let v18 = actual
        .replace(
            &format!("CREATE TABLE \"{TABLE}\""),
            &format!("CREATE TABLE {TABLE}"),
        )
        .replace(
            "origin_operation INTEGER NOT NULL CHECK(origin_operation IN (1, 18, 20))",
            "origin_operation INTEGER NOT NULL CHECK(origin_operation IN (1, 18))",
        );
    if v18 == actual {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut fences = String::new();
    for name in FENCES {
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            [name],
            |row| row.get(0),
        )?;
        fences.push_str(&trigger);
        fences.push(';');
    }
    let temporary = v18.replacen(
        &format!("CREATE TABLE {TABLE}"),
        &format!("CREATE TABLE {TABLE}_v18"),
        1,
    );
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(&format!(
        "{temporary};
         INSERT INTO {TABLE}_v18 SELECT * FROM {TABLE};
         DROP TABLE {TABLE};
         {v18};
         INSERT INTO {TABLE} SELECT * FROM {TABLE}_v18;
         DROP TABLE {TABLE}_v18;"
    ))?;
    // Dropping the old table removed its fence triggers; reinstall the
    // captured ones on the rebuilt table.
    transaction.execute_batch(&fences)?;
    transaction.commit()
}
