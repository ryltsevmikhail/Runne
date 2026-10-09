#[path = "admin/cancel.rs"]
mod cancel;
#[path = "admin/command_rows.rs"]
mod command_rows;
#[path = "admin/commands.rs"]
mod commands;
#[path = "admin/commit.rs"]
mod commit;
#[path = "admin/identity.rs"]
mod identity;
#[path = "admin/model.rs"]
mod model;
#[path = "admin/persistence.rs"]
mod persistence;
#[path = "admin/readback.rs"]
mod readback;
#[path = "admin/receipts.rs"]
mod receipts;
#[path = "admin/registration.rs"]
mod registration;
#[path = "admin/revoke.rs"]
mod revoke;
#[path = "admin/validation.rs"]
mod validation;

use runne_application::project_trust::admin::{
    AdminError, AuthenticatedPolicyAdminSubject, CurrentPolicyAdmin, ManagedPolicyAdminReceipt,
    ManagedPolicyCommandState, ManagedPolicyCommandV1, ManagedPolicyRoleState,
    ReservedManagedPolicyCommandV1, VerifiedManagedPolicyConsentV1, VerifiedPolicyAdminBootstrap,
};

use super::ProjectTrustStore;

impl ProjectTrustStore {
    /// Registers the one protected administrator; exact repeats are idempotent.
    pub fn register_admin(
        &self,
        current: &CurrentPolicyAdmin<'_>,
        bootstrap: &VerifiedPolicyAdminBootstrap,
    ) -> Result<ManagedPolicyRoleState, AdminError> {
        registration::register(self, current, bootstrap)
    }

    /// Reads current registry generation inside the authenticated session callback.
    pub fn admin_role_state(
        &self,
        current: &CurrentPolicyAdmin<'_>,
    ) -> Result<ManagedPolicyRoleState, AdminError> {
        registration::read_state(self, current)
    }

    /// Reserves the exact pending six-rule command without changing T1 revision.
    pub fn reserve_admin_command(
        &self,
        current: &CurrentPolicyAdmin<'_>,
        command: &ManagedPolicyCommandV1,
    ) -> Result<ManagedPolicyCommandState, AdminError> {
        commands::reserve(self, current, command)
    }

    /// Atomically consumes native consent, updates rules and same T1 revision, and stores receipt.
    pub fn commit_admin_command(
        &self,
        current: &CurrentPolicyAdmin<'_>,
        command: &ReservedManagedPolicyCommandV1,
        consent: &VerifiedManagedPolicyConsentV1,
    ) -> Result<ManagedPolicyCommandState, AdminError> {
        commit::commit(self, current, command, consent)
    }

    /// Cancels one exact command; a committed command returns its original receipt.
    pub fn cancel_admin_command(
        &self,
        current: &CurrentPolicyAdmin<'_>,
        command_id: &[u8; 16],
        semantic_digest: &[u8; 32],
    ) -> Result<ManagedPolicyCommandState, AdminError> {
        cancel::cancel(self, current, command_id, semantic_digest)
    }

    /// Reads an immutable receipt for the authenticated stable subject only.
    pub fn readback_admin_receipt(
        &self,
        subject: &AuthenticatedPolicyAdminSubject<'_>,
        command_id: &[u8; 16],
    ) -> Result<Option<ManagedPolicyAdminReceipt>, AdminError> {
        readback::readback(self, subject, command_id)
    }

    /// Revokes the singleton role, invalidates pending commands and fans out project revisions.
    pub fn revoke_admin(
        &self,
        current: &CurrentPolicyAdmin<'_>,
    ) -> Result<ManagedPolicyRoleState, AdminError> {
        revoke::revoke(self, current)
    }
}
