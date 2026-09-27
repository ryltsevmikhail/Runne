use runne_application::ports::ProjectWorkspaceRepositoryError as Error;
use rusqlite::Transaction;

type AuditRow = (
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
);

pub(super) fn ensure_all_taskrun_streams_have_lineage(
    transaction: &Transaction<'_>,
) -> Result<(), Error> {
    let missing: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM aggregate_streams stream
                LEFT JOIN task_run_workspace_lineage workspace_lineage
                  ON workspace_lineage.taskrun_id=stream.aggregate_id
                LEFT JOIN text_only_taskrun_lineage text_lineage
                  ON text_lineage.taskrun_id=stream.aggregate_id
                WHERE stream.aggregate_type=1
                  AND workspace_lineage.taskrun_id IS NULL
                  AND text_lineage.taskrun_id IS NULL
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| Error::Unavailable)?;
    if missing {
        return Err(Error::InvariantViolation);
    }
    super::lineage::validate_all_text_only_taskrun_lineage(transaction)
        .map_err(|_| Error::InvariantViolation)?;
    let mut statement = transaction
        .prepare(
            "SELECT stream.aggregate_id, lineage.workspace_id, lineage.project_id,
                    lineage.classification, lineage.origin_command_id,
                    lineage.origin_operation, history.project_id,
                    history.principal_id, history.classification,
                    workspace.project_id, workspace.principal_id
             FROM aggregate_streams stream
             LEFT JOIN task_run_workspace_lineage lineage
               ON lineage.taskrun_id = stream.aggregate_id
             LEFT JOIN workspace_identity_history history
               ON history.workspace_id = lineage.workspace_id
             LEFT JOIN workspaces workspace
               ON workspace.workspace_id = lineage.workspace_id
             WHERE stream.aggregate_type = 1
               AND lineage.taskrun_id IS NOT NULL
             ORDER BY stream.aggregate_id",
        )
        .map_err(|_| Error::Unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
            ))
        })
        .map_err(|_| Error::Unavailable)?
        .collect::<rusqlite::Result<Vec<AuditRow>>>()
        .map_err(|_| Error::Unavailable)?;
    for row in rows {
        if !valid_row(row) {
            return Err(Error::InvariantViolation);
        }
    }
    Ok(())
}

fn valid_row(row: AuditRow) -> bool {
    if row.0.len() != 16
        || row.1.as_ref().is_none_or(|value| value.len() != 16)
        || row.4.as_ref().is_none_or(|value| value.len() != 16)
        || !matches!(row.5, Some(1 | 18 | 20))
    {
        return false;
    }
    match (
        row.2,
        row.3.as_deref(),
        row.6,
        row.7,
        row.8.as_deref(),
        row.9,
        row.10,
    ) {
        (
            Some(project),
            Some("canonical"),
            Some(history),
            Some(owner),
            Some("canonical"),
            Some(workspace_project),
            Some(workspace_owner),
        ) => {
            project.len() == 16
                && project == history
                && project == workspace_project
                && owner == workspace_owner
                && !owner.is_empty()
        }
        (None, Some("legacy_unbound"), None, None, Some("legacy_unbound"), None, None) => true,
        _ => false,
    }
}
