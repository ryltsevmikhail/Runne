use super::*;
use rusqlite::{Connection, OptionalExtension};
pub(crate) const LEGACY_POLICY: &str = "d2-safe-tool-loop-budget-v1";
pub(crate) const CODING_POLICY: &str = "coding-tool-loop-budget-v1";
pub(crate) const CODING_PROFILE: &str = "runne-deepseek-responses-tools/1";
pub(crate) const CODING_LIMIT: u32 = 32;

pub(crate) fn coding_origin(
    connection: &Connection,
    task: TaskRunId,
) -> Result<bool, ToolInvocationStoreError> {
    let origin = super::super::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
        connection, task,
    )
    .map_err(|_| ToolInvocationStoreError::CorruptData)?
    .ok_or(ToolInvocationStoreError::CorruptData)?;
    Ok(origin.input.selected_profile().is_some_and(|profile| {
        profile.profile_id() == CODING_PROFILE && profile.profile_digest() != &[0; 32]
    }))
}

pub(crate) fn limits(
    connection: &Connection,
    task: TaskRunId,
) -> Result<(u32, u32), ToolInvocationStoreError> {
    let row: Option<(String,i64,i64,i64,i64)> = connection.query_row("SELECT policy_revision,effects_limit,continuations_limit,effects_used,continuations_used FROM taskrun_tool_budgets WHERE taskrun_id=?1",[task.as_bytes()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).optional().map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let Some((policy, effects, continuations, effects_used, continuations_used)) = row else {
        return Err(ToolInvocationStoreError::InvalidState);
    };
    let expected = match policy.as_str() {
        LEGACY_POLICY => 2,
        CODING_POLICY if coding_origin(connection, task)? => i64::from(CODING_LIMIT),
        _ => return Err(ToolInvocationStoreError::CorruptData),
    };
    if effects != expected
        || continuations != expected
        || !(0..=expected).contains(&effects_used)
        || !(0..=expected).contains(&continuations_used)
    {
        return Err(ToolInvocationStoreError::CorruptData);
    }
    Ok((expected as u32, expected as u32))
}

pub(crate) fn verify_origin_policy(
    connection: &Connection,
    task: TaskRunId,
) -> Result<(), ToolInvocationStoreError> {
    let expected = if coding_origin(connection, task)? {
        CODING_POLICY
    } else {
        LEGACY_POLICY
    };
    let actual: String = connection
        .query_row(
            "SELECT policy_revision FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            [task.as_bytes()],
            |r| r.get(0),
        )
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if actual != expected {
        return Err(ToolInvocationStoreError::CorruptData);
    }
    limits(connection, task).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_limit_cannot_be_widened_and_coding_requires_durable_origin() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE taskrun_tool_budgets(taskrun_id BLOB, policy_revision TEXT,effects_limit INTEGER,continuations_limit INTEGER,effects_used INTEGER,continuations_used INTEGER)").unwrap();
        let task = TaskRunId::from_bytes([1; 16]);
        connection
            .execute(
                "INSERT INTO taskrun_tool_budgets VALUES(?1,?2,2,2,1,1)",
                rusqlite::params![task.as_bytes(), LEGACY_POLICY],
            )
            .unwrap();
        assert_eq!(limits(&connection, task).unwrap(), (2, 2));
        connection
            .execute(
                "UPDATE taskrun_tool_budgets SET effects_limit=32,continuations_limit=32",
                [],
            )
            .unwrap();
        assert!(limits(&connection, task).is_err());
        connection
            .execute(
                "UPDATE taskrun_tool_budgets SET policy_revision=?1",
                [CODING_POLICY],
            )
            .unwrap();
        assert!(
            limits(&connection, task).is_err(),
            "no verified submit receipt means no coding budget"
        );
    }
}

pub(crate) fn is_tool_profile(id: &str) -> bool {
    matches!(
        id,
        "runne-linux-agent-tools-v1" | "runne-deepseek-responses-tools/1"
    )
}
