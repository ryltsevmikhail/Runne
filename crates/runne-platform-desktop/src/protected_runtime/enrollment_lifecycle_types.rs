use runne_api::{
    BeginProviderCredentialEnrollment, ProtectedCredentialEnrollmentLifecycleCodec,
    ProviderCredentialOperationSnapshotV2,
};

use super::ProtectedBundledRuntimeError;

/// Native-only metadata accepted by the protected V3 enrollment transcript.
pub struct NativeProtectedCredentialEnrollmentBegin {
    pub(super) command: BeginProviderCredentialEnrollment,
    pub(super) native_confirmation: [u8; 32],
}

impl NativeProtectedCredentialEnrollmentBegin {
    /// # Errors
    ///
    /// Returns a closed failure for an empty native confirmation binding.
    pub fn new(
        command: BeginProviderCredentialEnrollment,
        native_confirmation: [u8; 32],
    ) -> Result<Self, ProtectedBundledRuntimeError> {
        if native_confirmation == [0; 32] {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        Ok(Self {
            command,
            native_confirmation,
        })
    }
}

/// Move-only lifecycle authority retained from Prepared through terminal.
pub struct PreparedProtectedCredentialEnrollment {
    pub(super) codec: ProtectedCredentialEnrollmentLifecycleCodec,
    pub(super) snapshot: ProviderCredentialOperationSnapshotV2,
    pub(super) relay: Option<[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES]>,
    pub(super) relay_taken: bool,
    pub(super) terminal: bool,
}

impl PreparedProtectedCredentialEnrollment {
    #[must_use]
    pub const fn snapshot(&self) -> &ProviderCredentialOperationSnapshotV2 {
        &self.snapshot
    }

    pub const fn take_relay(
        &mut self,
    ) -> Option<[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES]> {
        if self.relay_taken {
            return None;
        }
        self.relay_taken = true;
        self.relay
    }

    #[must_use]
    pub const fn terminal(&self) -> bool {
        self.terminal
    }
}
