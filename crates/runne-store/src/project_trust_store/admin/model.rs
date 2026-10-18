use std::time::{SystemTime, UNIX_EPOCH};

use runne_application::project_trust::admin::{AdminError, ManagedPolicyRoleState};
use rusqlite::OptionalExtension;

pub(super) const ROLE_ACTIVE: i64 = 1;
pub(super) const ROLE_REVOKED: i64 = 2;
pub(super) const COMMAND_PENDING: i64 = 1;
pub(super) const COMMAND_COMMITTED: i64 = 2;
pub(super) const COMMAND_CANCELLED: i64 = 3;
pub(super) const COMMAND_EXPIRED: i64 = 4;
pub(super) const COMMAND_INVALIDATED: i64 = 5;

pub(super) fn now_unix_ms() -> Result<i64, AdminError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_millis()).ok())
        .filter(|value| *value > 0)
        .ok_or(AdminError::Unavailable)
}

pub(super) fn decode_role(
    value: i64,
    generation: i64,
) -> Result<ManagedPolicyRoleState, AdminError> {
    let generation = u64::try_from(generation).map_err(|_| AdminError::Unavailable)?;
    if generation == 0 {
        return Err(AdminError::Unavailable);
    }
    match value {
        ROLE_ACTIVE => Ok(ManagedPolicyRoleState::Active { generation }),
        ROLE_REVOKED => Ok(ManagedPolicyRoleState::Revoked { generation }),
        _ => Err(AdminError::Unavailable),
    }
}

pub(super) fn query_role(
    connection: &rusqlite::Connection,
) -> Result<Option<(i64, i64)>, AdminError> {
    connection
        .query_row(
            "SELECT status, generation FROM managed_policy_administrator WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| AdminError::Unavailable)
}
