//! One SQLite owner for selected modes, command receipts, and native challenges.

mod ceremony_v2;
mod challenge;
mod clock;
mod command;
mod identity;
mod managed_identity;
mod model;
mod receipt_codec;

#[cfg(test)]
#[path = "permission_modes/tests_v2.rs"]
mod tests_v2;

pub use model::{
    ClosedRulesManagedIdentityV2, LegacyRecordIdentityV1, ManagedIdentityChallengeBindingV2,
    ManagedIdentityMetadata, PermissionModeSelectionManagedIdentity,
};
pub use model::{
    FullAccessChallengeRequest, IssuedFullAccessChallenge, IssuedFullAccessChallengeContext,
    NativeModeConfirmationRequestV2, PermissionModeAuthorityContext,
    PermissionModeCeremonyStatusV2, PermissionModeSelectionSnapshot, PermissionModeStoreError,
    ProtectedNativeLaunchContext,
};

use runne_application::permission_modes::{
    ModeSelection, PermissionModeChangeReceipt, PermissionScope, SetPermissionModeCommand,
};

use super::StoreTransaction;

impl StoreTransaction {
    /// Begins or resolves one all-mode native-confirmation ceremony.
    ///
    /// Stable duplicate lookup happens before fresh Store, managed-policy, or
    /// protected-launch snapshots. The returned nonce is for trusted native
    /// confirmation code only and has redacted Debug output.
    pub fn begin_permission_mode_confirmation_v2(
        &self,
        request: NativeModeConfirmationRequestV2,
        authority: &PermissionModeAuthorityContext<'_>,
    ) -> Result<PermissionModeCeremonyStatusV2, PermissionModeStoreError> {
        command::begin_confirmation_v2(self, request, authority)
    }

    /// Reads exact command status without reconstructing native or T1 proofs.
    pub fn load_permission_mode_confirmation_status_v2(
        &self,
        scope: &runne_application::permission_modes::PermissionScope,
        authenticated_principal: &runne_api::ApiPrincipalId,
        command_id: runne_domain::id::CommandId,
    ) -> Result<Option<PermissionModeCeremonyStatusV2>, PermissionModeStoreError> {
        command::load_confirmation_status_v2(self, scope, authenticated_principal, command_id)
    }

    /// Cancels one pending ceremony using the same writer as commit/expiry.
    pub fn cancel_permission_mode_confirmation_v2(
        &self,
        scope: &runne_application::permission_modes::PermissionScope,
        authenticated_principal: &runne_api::ApiPrincipalId,
        command_id: runne_domain::id::CommandId,
    ) -> Result<Option<PermissionModeCeremonyStatusV2>, PermissionModeStoreError> {
        command::cancel_confirmation_v2(self, scope, authenticated_principal, command_id)
    }

    /// Discovers bounded pending mode requests for the current protected owner.
    pub fn discover_permission_mode_native_pending_v2(
        &self,
        principal: &runne_api::ApiPrincipalId,
        launch: &ProtectedNativeLaunchContext,
        after: Option<runne_domain::id::CommandId>,
    ) -> Result<runne_api::PermissionModeNativePendingPageV2, PermissionModeStoreError> {
        ceremony_v2::native_pending(self, principal, launch, after)
    }

    /// Resolves one MAC-addressed native request against its current owner.
    pub fn discover_permission_mode_native_pending_command_v2(
        &self,
        principal: &runne_api::ApiPrincipalId,
        launch: &ProtectedNativeLaunchContext,
        command_id: runne_domain::id::CommandId,
    ) -> Result<Option<runne_api::PermissionModeNativePendingV2>, PermissionModeStoreError> {
        ceremony_v2::native_pending_command(self, principal, launch, command_id)
    }

    /// Consumes native all-mode confirmation and changes selection atomically.
    pub fn commit_confirmed_permission_mode_v2(
        &self,
        command: SetPermissionModeCommand,
        confirmation: runne_application::permission_modes::VerifiedNativeModeConfirmationV2,
        authority: &PermissionModeAuthorityContext<'_>,
        history: runne_application::permission_modes::PermissionModeHistoryProjection,
    ) -> Result<PermissionModeChangeReceipt, PermissionModeStoreError> {
        command::commit_confirmed_v2(self, command, confirmation, authority, history)
    }

    /// Loads the selected mode for an authenticated, currently owned open workspace.
    ///
    /// A missing row returns ask-always at revision zero.
    pub fn load_permission_mode_selection(
        &self,
        scope: &PermissionScope,
        authenticated_principal: &runne_api::ApiPrincipalId,
    ) -> Result<ModeSelection, PermissionModeStoreError> {
        command::load_selection(self, scope, authenticated_principal)
    }

    /// Loads selected mode and its exact managed-policy snapshot digest.
    pub fn load_permission_mode_selection_snapshot(
        &self,
        scope: &PermissionScope,
        authenticated_principal: &runne_api::ApiPrincipalId,
    ) -> Result<PermissionModeSelectionSnapshot, PermissionModeStoreError> {
        command::load_selection_snapshot(self, scope, authenticated_principal)
    }

    /// Loads a selection with its exact versioned managed-policy identity.
    ///
    /// When no selection exists, the result is AskAlways paired with the
    /// current six-rule snapshot from the caller's held T1 lease.
    pub fn load_permission_mode_selection_with_managed_identity(
        &self,
        scope: &PermissionScope,
        authenticated_principal: &runne_api::ApiPrincipalId,
        authority: &PermissionModeAuthorityContext<'_>,
    ) -> Result<PermissionModeSelectionManagedIdentity, PermissionModeStoreError> {
        command::load_selection_with_managed_identity(
            self,
            scope,
            authenticated_principal,
            authority,
        )
    }

    /// Issues one short-lived, single-use full-access challenge in this Store.
    ///
    /// The caller must hold the current T1 effect lease and obtain the native
    /// launch context from the existing protected launch owner. The returned
    /// nonce is only for that trusted host's signer; it must never enter a
    /// renderer, API response, or general-purpose signing interface.
    pub fn issue_full_access_challenge(
        &self,
        request: FullAccessChallengeRequest,
        authority: &PermissionModeAuthorityContext<'_>,
    ) -> Result<IssuedFullAccessChallenge, PermissionModeStoreError> {
        challenge::issue(self, request, authority)
    }

    /// Atomically consumes full-access proof, CASes selection, invalidates
    /// incompatible pending challenges, and persists the immutable receipt.
    ///
    /// `history` is an application-created, non-authoritative summary. It is
    /// never restored as live native admission or compiler input.
    pub fn commit_permission_mode_change(
        &self,
        command: SetPermissionModeCommand,
        authority: &PermissionModeAuthorityContext<'_>,
        history: runne_application::permission_modes::PermissionModeHistoryProjection,
    ) -> Result<PermissionModeChangeReceipt, PermissionModeStoreError> {
        command::commit(self, command, authority, history)
    }
}
