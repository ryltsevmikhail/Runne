use super::UnlaunchedRow;

type UnlaunchedInvocation = (
    String,
    i64,
    bool,
    bool,
    bool,
    Vec<u8>,
    Vec<u8>,
    Option<i64>,
    Option<String>,
    Option<i64>,
);
pub(super) type BudgetIdentity = (Vec<u8>, Vec<u8>, Vec<u8>, i64);

pub(super) fn read_unlaunched_row(
    db: &rusqlite::Connection,
    task_id: &[u8; 16],
) -> Option<UnlaunchedRow> {
    use rusqlite::OptionalExtension as _;

    let invocation: Option<UnlaunchedInvocation> = db
        .query_row(
            "SELECT state,local_stop_state,release_started,managed_area_identity IS NOT NULL,
                    result_digest IS NOT NULL,approval_id,attempt_id,claim_fence,claim_node_id,claim_node_epoch
             FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [task_id.as_slice()],
            |row| {
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
                ))
            },
        )
        .optional()
        .expect("read D2 invocation for exact approval binding");
    let (state, local_stop, release, area, result, approval_id, attempt_id, fence, node, epoch) =
        invocation?;
    let approval_text = uuid::Uuid::from_slice(&approval_id).ok()?.to_string();
    let attempt_text = uuid::Uuid::from_slice(&attempt_id).ok()?.to_string();
    let approval: Option<(String, Option<String>, i64)> = db
        .query_row(
            "SELECT task_run_id,attempt_id,state FROM approvals WHERE approval_id=?1",
            [approval_text],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .expect("read approval by exact UUID");
    let (approval_task, approval_attempt, approval_state) = approval?;
    if approval_task != uuid::Uuid::from_bytes(*task_id).to_string()
        || approval_attempt.as_deref() != Some(attempt_text.as_str())
    {
        return None;
    }
    Some((
        state,
        local_stop,
        release,
        area,
        result,
        approval_state,
        fence,
        node,
        epoch,
    ))
}

pub(super) fn assert_claim_assignment(
    database: &std::path::Path,
    task_id: &[u8; 16],
    row: &UnlaunchedRow,
) {
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only D2 exact assignment view");
    let assignment: (i64, Vec<u8>, i64) = db
        .query_row(
            "SELECT fence,node_id,node_epoch FROM taskrun_assignments WHERE taskrun_id=?1 ORDER BY fence DESC LIMIT 1",
            [task_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("durable D2 assignment");
    if row.0 == "claimed" {
        assert_eq!(row.6, Some(assignment.0));
        assert_eq!(
            row.7.as_deref(),
            Some(
                uuid::Uuid::from_slice(&assignment.1)
                    .unwrap()
                    .to_string()
                    .as_str()
            )
        );
        assert_eq!(row.8, Some(assignment.2));
    } else {
        assert_eq!((row.6, row.7.as_ref(), row.8), (None, None, None));
    }
}

pub(super) fn expected_effects_used(state: &str) -> u32 {
    u32::from(state == "claimed")
}

pub(super) fn read_budget_identity(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) -> Option<BudgetIdentity> {
    use rusqlite::OptionalExtension as _;
    let id = uuid::Uuid::parse_str(&task.to_string()).ok()?.into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    db.query_row(
        "SELECT reservation_id,reservation_digest,attempt_id,fence FROM taskrun_tool_budgets WHERE taskrun_id=?1",
        [id.as_slice()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional().ok().flatten()
}

pub(super) fn budget_effects_used(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) -> Option<u32> {
    use rusqlite::OptionalExtension as _;
    let id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only D2 budget view");
    db.query_row(
        "SELECT effects_used FROM taskrun_tool_budgets WHERE taskrun_id=?1",
        [id.as_slice()],
        |row| row.get(0),
    )
    .optional()
    .expect("read optional D2 budget")
}
