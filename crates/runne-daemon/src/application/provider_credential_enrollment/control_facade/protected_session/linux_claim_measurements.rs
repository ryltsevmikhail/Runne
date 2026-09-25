use runne_api::ProviderCredentialEnrollmentHostError;
use sha2::{Digest as _, Sha256};

use super::DaemonProtectedCredentialEnrollmentSession;

impl DaemonProtectedCredentialEnrollmentSession {
    pub(crate) fn prepare_linux_claim_measurements(
        &self,
        installed: &runne_platform_desktop::VerifiedInstalledLinuxEnrollmentMeasurementFacts,
        writer: ([u8; 32], [u8; 32], [u8; 32]),
        channel: [u8; 32],
        launch_attempt: [u8; 32],
    ) -> Result<
        (
            runne_provider::CredentialMeasurementSnapshot,
            runne_provider::CredentialBindingDigest,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        if self.facts.release != installed.release_tuple()
            || writer.1 != installed.writer()
            || channel == [0; 32]
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let operation = self.operation_id()?;
        let continuation = if let Some(value) = self.recovery_continuation()? {
            value
        } else {
            let mut hash = Sha256::new();
            hash.update(b"gocode/provider-credential-enrollment/continuation/v1\0");
            hash.update(operation.as_bytes());
            hash.update(channel);
            hash.update(writer.0);
            hash.update(writer.2);
            runne_provider::CredentialBindingDigest::from_measured(hash.finalize().into())
                .map_err(map_measurement)?
        };
        let authority = &self.control.measurements;
        let measurements = runne_provider::CredentialMeasurementSnapshot::new(
            authority
                .candidate_source_identity(installed.candidate_source())
                .map_err(map_measurement)?,
            authority
                .release_manifest_digest(if self.recovery.started {
                    self.facts.release
                } else {
                    installed.target_manifest()
                })
                .map_err(map_measurement)?,
            authority
                .desktop_executable_identity(installed.desktop())
                .map_err(map_measurement)?,
            authority
                .writer_executable_identity(writer.1)
                .map_err(map_measurement)?,
            authority
                .reader_executable_identity(installed.daemon())
                .map_err(map_measurement)?,
            authority
                .contract_bundle_digest(installed.contract())
                .map_err(map_measurement)?,
            authority
                .daemon_authority_id(super::super::session_facts::daemon_binding(&self.facts))
                .map_err(map_measurement)?,
            authority
                .protected_session_id(super::super::session_facts::session_binding(&self.facts))
                .map_err(map_measurement)?,
            authority
                .desktop_supervisor_generation(self.facts.supervisor_generation)
                .map_err(map_measurement)?,
            authority
                .writer_launch_id(launch_attempt)
                .map_err(map_measurement)?,
            authority
                .writer_process_start_identity(writer.0)
                .map_err(map_measurement)?,
            authority
                .writer_process_handle_identity(writer.2)
                .map_err(map_measurement)?,
            authority
                .broker_channel_binding(channel)
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
