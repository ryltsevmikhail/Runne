use super::*;
use crate::application::provider_credential_enrollment::broker::issue::CredentialTicketAuthority;
use crate::application::provider_credential_enrollment::effect_authority::map_store;
use runne_provider::ProviderCredentialEnrollmentStore;

impl DaemonProtectedCredentialEnrollmentSession {
    pub(crate) fn require_durable_terminal(
        &self,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        use runne_provider::CredentialOperationState as State;
        let operation = self
            .control
            .store
            .load_operation(self.operation_id()?)
            .map_err(map_store)?;
        match operation.state() {
            State::Completed
            | State::Failed
            | State::Expired
            | State::Cancelled
            | State::Tombstoned => Ok(()),
            State::Prepared
            | State::Claimed
            | State::NativeEffectObserved
            | State::ReadbackVerified => Err(ProviderCredentialEnrollmentHostError::AccessDenied),
        }
    }

    pub(super) fn take_ticket_authority(
        &mut self,
    ) -> Result<CredentialTicketAuthority, ProviderCredentialEnrollmentHostError> {
        // The retained pair cannot select ordinary issue_ticket_attempt/send_issue.
        // Task 2C-c must atomically issue the qualified attempt and fence first.
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        if self.qualification.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        if self.recovery.started {
            return self
                .recovery
                .ready
                .take()
                .map(Into::into)
                .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.control
            .store
            .load_operation(self.operation_id()?)
            .map(Into::into)
            .map_err(map_store)
    }
    pub(super) fn recovery_continuation(
        &self,
    ) -> Result<
        Option<runne_provider::CredentialBindingDigest>,
        ProviderCredentialEnrollmentHostError,
    > {
        if !self.recovery.started {
            return Ok(None);
        }
        self.recovery
            .ready
            .as_ref()
            .map(|value| Some(value.request().continuation_digest()))
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    pub(super) fn operation_id(
        &self,
    ) -> Result<runne_provider::CredentialOperationId, ProviderCredentialEnrollmentHostError> {
        if self.recovery.started {
            return self
                .recovery
                .operation
                .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.begun
            .as_ref()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
            .and_then(|(_, snapshot)| self.control.handles.resolve(snapshot.operation_handle()))
    }
}
