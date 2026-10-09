use runne_application::project_trust::admin::{
    AdminError, CurrentPolicyAdmin, ManagedPolicyCommandState,
};
use rusqlite::params;

use super::{
    command_rows::load_command,
    identity::AdminIdentity,
    model::{
        COMMAND_CANCELLED, COMMAND_COMMITTED, COMMAND_EXPIRED, COMMAND_INVALIDATED,
        COMMAND_PENDING, ROLE_ACTIVE, now_unix_ms, query_role,
    },
    persistence::transact,
    receipts::load_receipt,
};
use crate::project_trust_store::ProjectTrustStore;

pub(super) fn cancel(
    store: &ProjectTrustStore,
    current: &CurrentPolicyAdmin<'_>,
    command_id: &[u8; 16],
    semantic_digest: &[u8; 32],
) -> Result<ManagedPolicyCommandState, AdminError> {
    let identity = AdminIdentity::from_current(current);
    transact(store, |transaction| {
        let row = load_command(transaction, command_id)?.ok_or(AdminError::Rejected)?;
        if row.subject != identity.stable_digest
            || row.authority != identity.authority_id
            || row.lineage != identity.lineage_id
            || row.digest != *semantic_digest
        {
            return Err(AdminError::Conflict);
        }
        match row.state {
            COMMAND_COMMITTED => Ok(ManagedPolicyCommandState::Committed(
                load_receipt(transaction, command_id, &identity, Some(&row.digest))?
                    .ok_or(AdminError::Unavailable)?,
            )),
            COMMAND_CANCELLED => Ok(ManagedPolicyCommandState::Cancelled),
            COMMAND_EXPIRED => Ok(ManagedPolicyCommandState::Expired),
            COMMAND_INVALIDATED => Ok(ManagedPolicyCommandState::Invalidated),
            COMMAND_PENDING => {
                let now = now_unix_ms()?;
                if now >= row.expires || now >= current.binding().session_expires_at_unix_ms() {
                    set_state(transaction, command_id, COMMAND_EXPIRED)?;
                    return Ok(ManagedPolicyCommandState::Expired);
                }
                let current_binding =
                    runne_application::project_trust::admin::policy_admin_session_binding_digest(
                        current.binding(),
                    );
                let role = query_role(transaction)?;
                let valid_generation = role.is_some_and(|(status, generation)| {
                    status == ROLE_ACTIVE && generation == row.generation && generation > 0
                });
                if !valid_generation || row.launch != current_binding {
                    set_state(transaction, command_id, COMMAND_INVALIDATED)?;
                    return Ok(ManagedPolicyCommandState::Invalidated);
                }
                set_state(transaction, command_id, COMMAND_CANCELLED)?;
                Ok(ManagedPolicyCommandState::Cancelled)
            }
            _ => Err(AdminError::Unavailable),
        }
    })
}

fn set_state(
    connection: &rusqlite::Connection,
    command_id: &[u8; 16],
    state: i64,
) -> Result<(), AdminError> {
    let changed = connection
        .execute(
            "UPDATE managed_policy_admin_commands SET state=?2 WHERE command_id=?1 AND state=?3",
            params![command_id.as_slice(), state, COMMAND_PENDING],
        )
        .map_err(|_| AdminError::Unavailable)?;
    if changed != 1 {
        return Err(AdminError::Conflict);
    }
    Ok(())
}
