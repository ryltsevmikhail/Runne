use runne_application::ports::ProjectWorkspaceRepositoryError;
use rusqlite::{Transaction, params};

pub(super) fn expire_pending(
    transaction: &Transaction<'_>,
    principal_id: Option<&str>,
    approval_id: Option<&str>,
) -> Result<(), ProjectWorkspaceRepositoryError> {
    let now = unix_millis();
    match (principal_id, approval_id) {
        (Some(principal_id), None) => transaction
            .execute(
                "UPDATE approvals
                 SET state = 4, request_version = request_version + 1, updated_at = ?1
                 WHERE principal_id = ?2 AND state = 1 AND expires_at <= ?1",
                params![now, principal_id],
            )
            .map(|_| ())
            .map_err(|_| ProjectWorkspaceRepositoryError::Unavailable),
        (Some(principal_id), Some(approval_id)) => transaction
            .execute(
                "UPDATE approvals
                 SET state = 4, request_version = request_version + 1, updated_at = ?1
                 WHERE approval_id = ?2 AND principal_id = ?3 AND state = 1 AND expires_at <= ?1",
                params![now, approval_id, principal_id],
            )
            .map(|_| ())
            .map_err(|_| ProjectWorkspaceRepositoryError::Unavailable),
        _ => Err(ProjectWorkspaceRepositoryError::InvariantViolation),
    }
}

pub(super) fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}
