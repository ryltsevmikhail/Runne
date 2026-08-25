fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
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
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
    ))
}

fn summary(
    row: Row,
) -> Result<ApprovalSummary, runne_application::ports::ProjectWorkspaceRepositoryError> {
    let state = state(row.13)?;
    ApprovalSummary::try_new(
        parse_id::<ApprovalId>(&row.0)?,
        parse_id::<TaskRunId>(&row.1)?,
        row.2.as_deref().map(parse_id::<AttemptId>).transpose()?,
        parse_id::<InvocationId>(&row.3)?,
        row.5,
        row.6,
        row.7.as_slice().try_into().map_err(|_| {
            runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation
        })?,
        row.8,
        row.9,
        row.11,
        row.12,
    )
    .map(|value| value.with_state(state))
    .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation)
}

fn parse_id<T: std::str::FromStr>(
    value: &str,
) -> Result<T, runne_application::ports::ProjectWorkspaceRepositoryError> {
    value
        .parse()
        .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation)
}

fn state(
    value: i64,
) -> Result<ApprovalState, runne_application::ports::ProjectWorkspaceRepositoryError> {
    match value {
        1 => Ok(ApprovalState::Pending),
        2 => Ok(ApprovalState::Approved),
        3 => Ok(ApprovalState::Denied),
        4 => Ok(ApprovalState::Expired),
        5 => Ok(ApprovalState::Cancelled),
        _ => Err(runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation),
    }
}

fn map_query_error(
    value: runne_application::ports::ProjectWorkspaceRepositoryError,
) -> ApprovalHostError {
    match value {
        runne_application::ports::ProjectWorkspaceRepositoryError::NotFound => {
            ApprovalHostError::NotFound
        }
        runne_application::ports::ProjectWorkspaceRepositoryError::Forbidden => {
            ApprovalHostError::Forbidden
        }
        runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable => {
            ApprovalHostError::Unavailable
        }
        _ => ApprovalHostError::InvariantViolation,
    }
}

fn map_command_error(
    value: runne_application::ports::ProjectWorkspaceRepositoryError,
) -> ApprovalHostError {
    match value {
        runne_application::ports::ProjectWorkspaceRepositoryError::NotFound => {
            ApprovalHostError::NotFound
        }
        runne_application::ports::ProjectWorkspaceRepositoryError::Forbidden => {
            ApprovalHostError::Forbidden
        }
        runne_application::ports::ProjectWorkspaceRepositoryError::Conflict => {
            ApprovalHostError::Conflict
        }
        runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable => {
            ApprovalHostError::Unavailable
        }
        _ => ApprovalHostError::InvariantViolation,
    }
}
