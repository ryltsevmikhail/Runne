use runne_application::commands::CommandOutcome;
use runne_application::ports::{AggregateScope, OperationTag};
use rusqlite::{Transaction, params};

use crate::codec::{
    CommandOutcomeCodec, IdempotencyScopeCodec, StoreCodec, TextGenerationReceiptCodec,
};

pub(super) fn backfill_taskrun_lineage(transaction: &Transaction<'_>) -> rusqlite::Result<()> {
    let mut statement = transaction.prepare(
        "SELECT command_id, idempotency_scope_bytes, command_outcome FROM command_receipts",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);

    for (command_id, scope_bytes, outcome_bytes) in rows {
        let scope = IdempotencyScopeCodec
            .decode(&scope_bytes)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let lineage = match scope.operation {
            OperationTag::CreateTaskRun => {
                let AggregateScope::NewTaskRun { workspace_id, .. } = scope.aggregate_scope else {
                    return Err(rusqlite::Error::InvalidQuery);
                };
                let CommandOutcome::TaskRunCreated { taskrun_id, .. } = CommandOutcomeCodec
                    .decode(&outcome_bytes)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                else {
                    return Err(rusqlite::Error::InvalidQuery);
                };
                Some((taskrun_id.into_bytes(), workspace_id.into_bytes(), 1_i64))
            }
            OperationTag::GenerateConversationText => {
                let AggregateScope::ExistingConversation { conversation_id } =
                    scope.aggregate_scope
                else {
                    return Err(rusqlite::Error::InvalidQuery);
                };
                let receipt = TextGenerationReceiptCodec
                    .decode(&outcome_bytes)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                if receipt.conversation_id != conversation_id {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Some((
                    receipt.taskrun_id.into_bytes(),
                    receipt.workspace_id.into_bytes(),
                    18_i64,
                ))
            }
            _ => None,
        };
        let Some((taskrun_id, workspace_id, operation)) = lineage else {
            continue;
        };
        let stream_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM aggregate_streams
             WHERE aggregate_type = 1 AND aggregate_id = ?1)",
            [taskrun_id],
            |row| row.get(0),
        )?;
        if !stream_exists {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.execute(
            "INSERT INTO task_run_workspace_lineage
             (taskrun_id, workspace_id, project_id, classification,
              origin_command_id, origin_operation)
             VALUES (?1, ?2, NULL, 'legacy_unbound', ?3, ?4)",
            params![taskrun_id, workspace_id, command_id, operation],
        )?;
    }
    Ok(())
}
