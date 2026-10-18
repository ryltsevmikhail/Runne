use runne_application::project_trust::admin::{
    AdminError, CurrentPolicyAdmin, ManagedPolicyRoleState,
};
use rusqlite::params;

use super::{
    identity::AdminIdentity,
    model::{COMMAND_PENDING, ROLE_ACTIVE, ROLE_REVOKED, decode_role, now_unix_ms},
    persistence::transact,
    validation::validate_current_role,
};
use crate::project_trust_store::ProjectTrustStore;

pub(super) fn revoke(
    store: &ProjectTrustStore,
    current: &CurrentPolicyAdmin<'_>,
) -> Result<ManagedPolicyRoleState, AdminError> {
    let identity = AdminIdentity::from_current(current);
    transact(store, |transaction| {
        let Some((registered, status, generation)) = AdminIdentity::load_registered(transaction)?
        else {
            return Err(AdminError::Rejected);
        };
        if registered != identity || !registered.matches_current(current) {
            return Err(AdminError::Rejected);
        }
        if status == ROLE_REVOKED {
            return decode_role(status, generation);
        }
        if status != ROLE_ACTIVE {
            return Err(AdminError::Unavailable);
        }
        let now = now_unix_ms()?;
        if now >= current.binding().session_expires_at_unix_ms() {
            return Err(AdminError::Expired);
        }
        let (_, active_generation) = validate_current_role(
            transaction,
            current,
            Some(u64::try_from(generation).map_err(|_| AdminError::Unavailable)?),
        )?;
        let next_generation = active_generation
            .checked_add(1)
            .ok_or(AdminError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE project_trust SET revision=revision+1, updated_at=strftime('%s','now')",
                [],
            )
            .map_err(|_| AdminError::Unavailable)?;
        let project_count: i64 = transaction
            .query_row("SELECT count(*) FROM project_trust", [], |row| row.get(0))
            .map_err(|_| AdminError::Unavailable)?;
        if i64::try_from(changed).ok() != Some(project_count) {
            return Err(AdminError::Unavailable);
        }
        transaction
            .execute(
                "UPDATE managed_policy_admin_commands SET state=5 WHERE state=?1",
                params![COMMAND_PENDING],
            )
            .map_err(|_| AdminError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE managed_policy_administrator
             SET status=?1, generation=?2 WHERE id=1 AND status=?3 AND generation=?4",
                params![
                    ROLE_REVOKED,
                    i64::try_from(next_generation).map_err(|_| AdminError::Unavailable)?,
                    ROLE_ACTIVE,
                    i64::try_from(active_generation).map_err(|_| AdminError::Unavailable)?
                ],
            )
            .map_err(|_| AdminError::Unavailable)?;
        if changed != 1 {
            return Err(AdminError::Conflict);
        }
        Ok(ManagedPolicyRoleState::Revoked {
            generation: next_generation,
        })
    })
}
