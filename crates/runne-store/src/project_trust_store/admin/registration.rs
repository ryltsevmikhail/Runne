use runne_application::project_trust::admin::{
    AdminError, CurrentPolicyAdmin, ManagedPolicyRoleState, VerifiedPolicyAdminBootstrap,
};

use super::{
    identity::AdminIdentity,
    model::{ROLE_ACTIVE, decode_role, now_unix_ms},
    persistence::transact,
};
use crate::project_trust_store::ProjectTrustStore;

pub(super) fn register(
    store: &ProjectTrustStore,
    current: &CurrentPolicyAdmin<'_>,
    bootstrap: &VerifiedPolicyAdminBootstrap,
) -> Result<ManagedPolicyRoleState, AdminError> {
    let identity = AdminIdentity::from_registration(current, bootstrap)?;
    transact(store, |transaction| {
        match AdminIdentity::load_registered(transaction)? {
            None => {
                let now = now_unix_ms()?;
                if now >= current.binding().session_expires_at_unix_ms() {
                    return Err(AdminError::Expired);
                }
                identity.insert(transaction, 1, now)?;
                Ok(ManagedPolicyRoleState::Active { generation: 1 })
            }
            Some((registered, status, generation)) if registered == identity => {
                let state = decode_role(status, generation)?;
                if status != ROLE_ACTIVE {
                    return Err(AdminError::Conflict);
                }
                Ok(state)
            }
            Some(_) => Err(AdminError::Conflict),
        }
    })
}

pub(super) fn read_state(
    store: &ProjectTrustStore,
    current: &CurrentPolicyAdmin<'_>,
) -> Result<ManagedPolicyRoleState, AdminError> {
    transact(store, |transaction| {
        let identity = AdminIdentity::from_current(current);
        let Some((registered, status, generation)) = AdminIdentity::load_registered(transaction)?
        else {
            return Err(AdminError::Rejected);
        };
        if !registered.matches_current(current) || registered != identity {
            return Err(AdminError::Rejected);
        }
        decode_role(status, generation)
    })
}
