//! Test-only schema surgery helpers for disposable fixtures.
//!
//! Fixtures that downgrade a freshly migrated database to an older released
//! marker must restore every table those historical validators pin. These
//! helpers rebuild tables from the frozen migration DDL — never handwritten
//! SQL — preserve all rows, and reinstall the V12 fence triggers that a
//! `DROP TABLE` removes.

use rusqlite::{Connection, Result as SqliteResult, Transaction, TransactionBehavior};

/// Rebuilds `task_run_workspace_lineage` with the frozen V18 DDL.
///
/// Used by downgrade fixtures (e.g. `upgraded_v25_for_provider`) so the
/// historical V25 structure validators see the exact lineage shape they pin;
/// all rows are preserved and the V12 fence triggers are reinstalled.
pub(crate) fn restore_v18_taskrun_lineage_for_test(connection: &Connection) -> SqliteResult<()> {
    let lineage_ddl = super::project_workspace_schema::MIGRATION_V18
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with("CREATE TABLE task_run_workspace_lineage "))
        .expect("V18 taskrun lineage DDL is frozen");
    let temporary = lineage_ddl.replace(
        "CREATE TABLE task_run_workspace_lineage",
        "CREATE TABLE task_run_workspace_lineage_v18",
    );
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(&format!(
        "{temporary};
         INSERT INTO task_run_workspace_lineage_v18 SELECT * FROM task_run_workspace_lineage;
         DROP TABLE task_run_workspace_lineage;
         {lineage_ddl};
         INSERT INTO task_run_workspace_lineage SELECT * FROM task_run_workspace_lineage_v18;
         DROP TABLE task_run_workspace_lineage_v18;"
    ))?;
    for operation in ["insert", "update", "delete"] {
        transaction
            .execute_batch(&super::v12_fence_trigger("task_run_workspace_lineage", operation).1)?;
    }
    transaction.commit()
}
