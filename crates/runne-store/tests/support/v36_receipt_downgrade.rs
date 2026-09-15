use rusqlite::{Connection, Result as SqliteResult, Transaction, TransactionBehavior};

const TABLE: &str = "project_workspace_command_receipts";
const GLOBAL_COMMAND: &str = "CREATE TRIGGER global_command_id_from_command_receipts BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id = NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END";
const GLOBAL_PROJECT: &str = "CREATE TRIGGER global_command_id_from_project_workspace_receipts BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id = NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END";

pub fn restore_v18_receipt(connection: &Connection) -> SqliteResult<()> {
    let actual: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [TABLE],
        |row| row.get(0),
    )?;
    let v18 = actual
        .replace(
            "CREATE TABLE \"project_workspace_command_receipts\"",
            "CREATE TABLE project_workspace_command_receipts",
        )
        .replace(
            "operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 8)",
            "operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 7)",
        );
    if v18 == actual {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let temporary = v18.replacen(
        "CREATE TABLE project_workspace_command_receipts",
        "CREATE TABLE project_workspace_command_receipts_v18",
        1,
    );
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(&format!(
        "DROP TRIGGER global_command_id_from_command_receipts;
         DROP TRIGGER global_command_id_from_project_workspace_receipts;
         {temporary};
         INSERT INTO project_workspace_command_receipts_v18 SELECT * FROM project_workspace_command_receipts;
         DROP TABLE project_workspace_command_receipts;
         {v18};
         INSERT INTO project_workspace_command_receipts SELECT * FROM project_workspace_command_receipts_v18;
         DROP TABLE project_workspace_command_receipts_v18;"
    ))?;
    for operation in ["insert", "update", "delete"] {
        transaction.execute_batch(&format!(
            "CREATE TRIGGER \"schema_v12_fence_{TABLE}_{operation}\" AFTER {} ON \"{TABLE}\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
            operation.to_ascii_uppercase(),
        ))?;
    }
    transaction.execute_batch(GLOBAL_COMMAND)?;
    transaction.execute_batch(GLOBAL_PROJECT)?;
    transaction.commit()
}
