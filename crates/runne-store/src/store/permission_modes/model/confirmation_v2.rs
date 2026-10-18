use runne_application::permission_modes::{
    NativeModeConfirmationBindingV2, PermissionMode, PermissionModeChangeReceipt, PermissionScope,
    PresetVersion,
};
use runne_domain::id::{CommandId, IdempotencyKey, IntegrityDigest};

use super::super::managed_identity::ClosedRulesManagedIdentityV2;

/// Stable public request identity for any selected permission mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeModeConfirmationRequestV2 {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub scope: PermissionScope,
    pub expected_authorization_revision: u64,
    pub requested_mode: PermissionMode,
    pub preset_version: PresetVersion,
    pub expires_at_unix_ms: Option<i64>,
}

impl NativeModeConfirmationRequestV2 {
    pub fn public_request_digest(&self) -> IntegrityDigest {
        runne_application::permission_modes::native_mode_public_request_digest_v2(
            self.command_id,
            &self.idempotency_key,
            &self.scope,
            self.expected_authorization_revision,
            self.requested_mode,
            self.preset_version,
            self.expires_at_unix_ms,
        )
    }
}

/// Store-issued V2 ceremony, delivered only to trusted native confirmation code.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedNativeModeConfirmationV2 {
    challenge_id: [u8; 16],
    nonce: [u8; 32],
    binding: NativeModeConfirmationBindingV2,
    managed_identity: Box<ClosedRulesManagedIdentityV2>,
}

impl IssuedNativeModeConfirmationV2 {
    pub(crate) fn new(
        challenge_id: [u8; 16],
        nonce: [u8; 32],
        binding: NativeModeConfirmationBindingV2,
        managed_identity: ClosedRulesManagedIdentityV2,
    ) -> Self {
        Self {
            challenge_id,
            nonce,
            binding,
            managed_identity: Box::new(managed_identity),
        }
    }

    pub const fn challenge_id(&self) -> &[u8; 16] {
        &self.challenge_id
    }
    pub const fn nonce_for_native_signing(&self) -> &[u8; 32] {
        &self.nonce
    }
    pub const fn binding(&self) -> &NativeModeConfirmationBindingV2 {
        &self.binding
    }

    /// Exact closed-rule snapshot bound by this issued challenge.
    pub const fn managed_identity(&self) -> &ClosedRulesManagedIdentityV2 {
        &self.managed_identity
    }
}

impl std::fmt::Debug for IssuedNativeModeConfirmationV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedNativeModeConfirmationV2")
            .field("challenge_id", &self.challenge_id)
            .field("nonce", &"<redacted>")
            .field("binding", &self.binding)
            .finish()
    }
}

/// Durable status returned by V2 ceremony begin/read/cancel operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionModeCeremonyStatusV2 {
    Pending(IssuedNativeModeConfirmationV2),
    Committed(PermissionModeChangeReceipt),
    Cancelled,
    Expired,
    Invalidated,
}
