use super::*;
use crate::application::provider_credential_enrollment::broker::issue::CredentialTicketAuthority;
use crate::application::provider_credential_enrollment::effect_authority::map_store;
use runne_provider::ProviderCredentialEnrollmentStore;

impl DaemonProtectedCredentialEnrollmentSession {
    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    pub(crate) fn is_idle(&self) -> bool {
        self.pending.is_none()
            && self.begun.is_none()
            && self.verified.is_none()
            && !self.recovery.started
    }

    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    pub(crate) fn take_idle_rendezvous(
        &mut self,
    ) -> Result<super::DaemonOwnedUnixBrokerRendezvous, ProviderCredentialEnrollmentHostError> {
        if !self.is_idle() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.rendezvous
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    pub(crate) fn require_durable_terminal(
        &self,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        #[cfg(target_os = "linux")]
        if self.pending.is_none()
            && self.begun.is_none()
            && self.verified.is_none()
            && !self.recovery.started
        {
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        if self.pending.is_none()
            && self.begun.is_none()
            && self.verified.is_none()
            && !self.recovery.started
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        if let Some((command, snapshot)) = &self.verified {
            if !snapshot.state().terminal()
                || snapshot.operation_kind()
                    != runne_api::ProviderCredentialOperationKindV2::VerifyRemote
                || snapshot.provider_id() != command.provider()
            {
                return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
            }
            let provider = runne_provider::ProviderId::new(command.provider().as_str())
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
            let safe = self
                .control
                .store
                .safe_snapshot(&provider)
                .map_err(map_store)?;
            if safe.lifecycle_revision().get() != snapshot.lifecycle_revision()
                || safe.readiness_revision().get() != snapshot.readiness_revision()
                || safe.verification().kind()
                    != Some(runne_provider::CredentialVerificationKind::Remote)
                || safe.verification().result().is_none()
            {
                return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
            }
            return Ok(());
        }
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

    #[cfg_attr(
        not(any(
            test,
            all(
                target_os = "macos",
                target_arch = "aarch64",
                feature = "desktop-protected"
            ),
            all(target_os = "linux", feature = "desktop-protected")
        )),
        expect(
            dead_code,
            reason = "the D1 Linux composition slice selects ticket authority; the macOS flow and tests drive it today"
        )
    )]
    pub(super) fn take_ticket_authority(
        &mut self,
    ) -> Result<CredentialTicketAuthority, ProviderCredentialEnrollmentHostError> {
        if self.verified.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        // The sticky snapshot survives carrier consumption and every failed issue.
        // Qualified sessions cannot select ordinary issue_ticket_attempt/send_issue.
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        if self.qualification_snapshot.is_some() {
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
    #[cfg_attr(
        not(any(
            test,
            all(
                target_os = "macos",
                target_arch = "aarch64",
                feature = "desktop-protected"
            ),
            all(target_os = "linux", feature = "desktop-protected")
        )),
        expect(
            dead_code,
            reason = "the D1 Linux composition slice reads recovery continuation; the macOS flow and tests drive it today"
        )
    )]
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
