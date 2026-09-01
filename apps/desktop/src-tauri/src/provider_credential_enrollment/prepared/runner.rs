use super::*;
use runne_api::{BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2};
use runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin;

impl PreparedCredentialEnrollmentExchange {
    /// Synchronously retains the protected transcript, writer ownership, and
    /// secret until exact terminal readback and bounded reap.
    pub(in crate::provider_credential_enrollment) fn run(
        mut self,
        registry: &CredentialIntentRegistry,
    ) -> Result<(), PreparedCredentialEnrollmentError> {
        let result = self.run_retained(registry);
        if result.is_err() {
            self.runtime_lease.abort_enrollment();
        }
        self.cleanup_armed = false;
        result
    }

    fn run_retained(
        &mut self,
        registry: &CredentialIntentRegistry,
    ) -> Result<(), PreparedCredentialEnrollmentError> {
        self.updater_lease
            .revalidate_confirmed(&self.installed)
            .map_err(|()| PreparedCredentialEnrollmentError)?;
        let intent = self
            .intent
            .take()
            .ok_or(PreparedCredentialEnrollmentError)?;
        let consumed = registry
            .consume(
                intent,
                &self.window,
                self.request.renderer_generation,
                self.request,
                self.intent_session,
                Instant::now(),
            )
            .map_err(|_| PreparedCredentialEnrollmentError)?;
        if self.request.action != ProviderCredentialEnrollmentActionV2::Pair {
            return Err(PreparedCredentialEnrollmentError);
        }
        let command_id = uuid::Uuid::now_v7().to_string();
        let command = BeginProviderCredentialEnrollment::new(
            self.request.action,
            self.request.provider,
            self.request.expected_revision,
            &command_id,
            &command_id,
            consumed.daemon_id(),
        )
        .map_err(|_| PreparedCredentialEnrollmentError)?;
        let begin =
            NativeProtectedCredentialEnrollmentBegin::new(command, self.native_confirmation)
                .map_err(|_| PreparedCredentialEnrollmentError)?;
        let supervisor = self.runtime_lease.supervisor_handle();
        let mut enrollment = supervisor
            .lock()
            .map_err(|_| PreparedCredentialEnrollmentError)?
            .begin_protected_credential_enrollment(begin)
            .map_err(|_| PreparedCredentialEnrollmentError)?;
        if enrollment.snapshot().broker_rendezvous_id().is_none() {
            return Err(PreparedCredentialEnrollmentError);
        }
        let mut handoff = supervisor
            .lock()
            .map_err(|_| PreparedCredentialEnrollmentError)?
            .run_credential_writer_handoff(&self.installed, self.request.writer_handoff_mode())
            .map_err(|_| PreparedCredentialEnrollmentError)?;
        let exchange = (|| {
            supervisor
                .lock()
                .map_err(|_| PreparedCredentialEnrollmentError)?
                .receive_credential_secret_relay(&mut enrollment)
                .map_err(|_| PreparedCredentialEnrollmentError)?;
            let relay = enrollment
                .take_relay()
                .ok_or(PreparedCredentialEnrollmentError)?;
            let secret = self
                .material
                .take()
                .ok_or(PreparedCredentialEnrollmentError)?
                .into_pipe_bytes()
                .into_zeroizing();
            handoff
                .take_pair_secret_relay()
                .ok_or(PreparedCredentialEnrollmentError)?
                .seal_and_write(&relay, secret)
                .map_err(|_| PreparedCredentialEnrollmentError)?;
            supervisor
                .lock()
                .map_err(|_| PreparedCredentialEnrollmentError)?
                .finish_protected_credential_enrollment(&mut enrollment, &relay)
                .map_err(|_| PreparedCredentialEnrollmentError)?;
            (enrollment.terminal() && terminal_is_success(enrollment.snapshot().state()))
                .then_some(())
                .ok_or(PreparedCredentialEnrollmentError)
        })();
        if exchange.is_err()
            && let Ok(mut supervisor) = supervisor.lock()
        {
            let _ = supervisor.stop();
        }
        let reaped = handoff
            .reap_exact_writer()
            .map_err(|_| PreparedCredentialEnrollmentError);
        exchange.and(reaped)
    }
}

pub(super) const fn terminal_is_success(
    state: runne_api::ProviderCredentialOperationStateV2,
) -> bool {
    matches!(
        state,
        runne_api::ProviderCredentialOperationStateV2::Completed
    )
}
