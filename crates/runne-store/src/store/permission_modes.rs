//! One SQLite owner for selected modes, command receipts, and native challenges.

mod challenge;
mod clock;
mod command;
mod identity;
mod model;
mod receipt_codec;

pub use model::{
    FullAccessChallengeRequest, IssuedFullAccessChallenge, IssuedFullAccessChallengeContext,
    PermissionModeAuthorityContext, PermissionModeSelectionSnapshot, PermissionModeStoreError,
    ProtectedNativeLaunchContext,
};

use runne_application::permission_modes::{
    ModeSelection, PermissionModeChangeReceipt, PermissionScope, SetPermissionModeCommand,
};

use super::StoreTransaction;

impl StoreTransaction {
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
