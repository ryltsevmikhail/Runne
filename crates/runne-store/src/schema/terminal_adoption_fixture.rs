/// Reconstructs the historical V69 boundary only for an owned synthetic fixture.
/// Existing authority and history rows are preserved; all newer tool/root rows must be empty.
///
/// # Errors
/// Rejects a non-V71 source, nonempty newer tables, or failed exact historical validation.
#[doc(hidden)]
pub fn rewind_empty_terminal_schema_for_test(connection: &Connection) -> SqliteResult<()> {
    if !v71_matches(connection, 71)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    for table in [
        "workspace_root_identities",
        "taskrun_tool_budgets",
        "taskrun_tool_invocations",
        "taskrun_provider_round_bindings",
    ] {
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        if count != 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    connection.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")?;
    let result = (|| {
        let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
        for (name, _) in V71_TRIGGERS {
            tx.execute_batch(&format!("DROP TRIGGER {name}"))?;
        }
        rebuild_table(
            &tx,
            "taskrun_tool_invocations",
            V71_NEW_TARGET,
            V71_OLD_TARGET,
        )?;
        for table in [
            "taskrun_tool_invocations",
            "taskrun_provider_round_bindings",
        ] {
            rebuild_table(
                &tx,
                table,
                "round_index BETWEEN 0 AND 32",
                "round_index BETWEEN 0 AND 2",
            )?;
        }
        rebuild_table(&tx, "taskrun_tool_budgets", V71_NEW_BUDGET, V71_OLD_BUDGET)?;
        tx.execute_batch("DROP TABLE workspace_root_identities; DELETE FROM schema_version WHERE version IN (70,71);")?;
        if !v69_matches(&tx, 69)? {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.commit()
    })();
    let restore =
        connection.execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;");
    result.and(restore)
}
