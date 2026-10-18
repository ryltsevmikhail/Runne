use runne_application::project_trust::admin::{
    AdminError, AuthenticatedPolicyAdminSubject, ManagedPolicyAdminReceipt,
    policy_admin_stable_identity_digest,
};

use super::{identity::AdminIdentity, persistence::transact, receipts::load_receipt};
use crate::project_trust_store::ProjectTrustStore;

pub(super) fn readback(
    store: &ProjectTrustStore,
    subject: &AuthenticatedPolicyAdminSubject<'_>,
    command_id: &[u8; 16],
) -> Result<Option<ManagedPolicyAdminReceipt>, AdminError> {
    let identity = AdminIdentity::from_subject(subject, *subject.installation_provenance());
    if identity.stable_digest != policy_admin_stable_identity_digest(subject) {
        return Err(AdminError::Rejected);
    }
    transact(store, |transaction| {
        let Some((registered, _, _)) = AdminIdentity::load_registered(transaction)? else {
            return Ok(None);
        };
        if !registered.matches_subject(subject) || registered.provenance != identity.provenance {
            return Err(AdminError::Rejected);
        }
        load_receipt(transaction, command_id, &identity, None)
    })
}
