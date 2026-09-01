use runne_api::ProviderCredentialEnrollmentHostError;
use sha2::{Digest as _, Sha256};

use super::{DaemonProtectedCredentialEnrollmentSession, daemon_binding, session_binding};

impl DaemonProtectedCredentialEnrollmentSession {
    pub(crate) fn prepare_claim_measurements(
        &self,
        writer: &runne_platform_desktop::provider_credential_broker::VerifiedWriterMeasurementFacts,
        launch_attempt: [u8; 32],
    ) -> Result<
        (
            runne_provider::CredentialMeasurementSnapshot,
            runne_provider::CredentialBindingDigest,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let installed = self
            .installed_facts
            .as_ref()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if installed.writer() != writer.image()
            || installed.release() != writer.release_tuple()
            || self.facts.release != writer.release_tuple()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let operation = self
            .begun
            .as_ref()
            .and_then(|(_, snapshot)| {
                self.control
                    .handles
                    .resolve(snapshot.operation_handle())
                    .ok()
            })
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let mut continuation = Sha256::new();
        continuation.update(b"gocode/provider-credential-enrollment/continuation/v1\0");
        continuation.update(operation.as_bytes());
        continuation.update(writer.channel());
        continuation.update(writer.process_start());
        continuation.update(writer.writer_kill_public_key());
        let continuation =
            runne_provider::CredentialBindingDigest::from_measured(continuation.finalize().into())
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        let authority = &self.control.measurements;
        let measurements = runne_provider::CredentialMeasurementSnapshot::new(
            authority
                .candidate_source_identity(installed.candidate_source())
                .map_err(map_measurement)?,
            authority
                .release_manifest_digest(installed.target_manifest())
                .map_err(map_measurement)?,
            authority
                .desktop_executable_identity(installed.desktop())
                .map_err(map_measurement)?,
            authority
                .writer_executable_identity(writer.image())
                .map_err(map_measurement)?,
            authority
                .reader_executable_identity(installed.daemon())
                .map_err(map_measurement)?,
            authority
                .contract_bundle_digest(installed.contract())
                .map_err(map_measurement)?,
            authority
                .daemon_authority_id(daemon_binding(&self.facts))
                .map_err(map_measurement)?,
            authority
                .protected_session_id(session_binding(&self.facts))
                .map_err(map_measurement)?,
            authority
                .desktop_supervisor_generation(self.facts.supervisor_generation)
                .map_err(map_measurement)?,
            authority
                .writer_launch_id(launch_attempt)
                .map_err(map_measurement)?,
            authority
                .writer_process_start_identity(writer.process_start())
                .map_err(map_measurement)?,
            authority
                .writer_process_handle_identity(writer.writer_kill_public_key())
                .map_err(map_measurement)?,
            authority
                .broker_channel_binding(writer.channel())
                .map_err(map_measurement)?,
            authority
                .continuation_binding_digest(continuation.as_bytes())
                .map_err(map_measurement)?,
        )
        .map_err(map_measurement)?;
        Ok((measurements, continuation))
    }
}

fn map_measurement(
    _: runne_provider::CredentialEnrollmentError,
) -> ProviderCredentialEnrollmentHostError {
    ProviderCredentialEnrollmentHostError::AccessDenied
}
