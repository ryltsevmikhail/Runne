use super::*;

/// Distinguishes a genuine D2 workflow cancellation from ordinary cancellation
/// receipts before the D2 proof validator requires D2-only claim evidence.
pub(super) fn is_d2_cancellation(
    connection: &Connection,
    taskrun_id: TaskRunId,
    selected_d2_profile: bool,
    canonical_d2_cycle: bool,
) -> Result<bool, CommitError> {
    let markers: (i64, i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM taskrun_tool_budgets WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM taskrun_provider_round_bindings WHERE taskrun_id=?1)",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| invalid())?;
    let has_d2_markers = markers != (0, 0, 0);
    if !selected_d2_profile {
        return if has_d2_markers {
            Err(invalid())
        } else {
            Ok(false)
        };
    }
    Ok(has_d2_markers || canonical_d2_cycle)
}

fn invalid() -> CommitError {
    super::super::super::parse_helpers::storage_failure(
        runne_application::ports::StorageFailureKind::IntegrityViolation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_d2_origin_with_canonical_cycle_selects_d2_validator() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE taskrun_tool_budgets(taskrun_id BLOB NOT NULL);
                 CREATE TABLE taskrun_tool_invocations(taskrun_id BLOB NOT NULL);
                 CREATE TABLE taskrun_provider_round_bindings(taskrun_id BLOB NOT NULL);",
            )
            .unwrap();
        let taskrun_id = TaskRunId::from_bytes([0x71; 16]);

        assert!(!is_d2_cancellation(&connection, taskrun_id, false, false).unwrap());
        assert!(!is_d2_cancellation(&connection, taskrun_id, true, false).unwrap());
        assert!(is_d2_cancellation(&connection, taskrun_id, true, true).unwrap());
        assert!(!is_d2_cancellation(&connection, taskrun_id, false, true).unwrap());

        connection
            .execute(
                "INSERT INTO taskrun_tool_budgets(taskrun_id) VALUES(?1)",
                [taskrun_id.as_bytes()],
            )
            .unwrap();
        assert!(is_d2_cancellation(&connection, taskrun_id, true, true).unwrap());
        assert!(is_d2_cancellation(&connection, taskrun_id, true, false).unwrap());
        assert!(is_d2_cancellation(&connection, taskrun_id, false, false).is_err());
    }
}
