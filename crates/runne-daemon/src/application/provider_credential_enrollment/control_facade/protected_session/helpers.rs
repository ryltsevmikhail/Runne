use super::*;

impl DaemonProtectedCredentialEnrollmentSession {
    pub(super) fn encode_snapshot(
        &mut self,
        snapshot: ProviderCredentialOperationSnapshotV2,
    ) -> Result<Vec<u8>, ProviderCredentialEnrollmentHostError> {
        self.daemon_sequence = self
            .daemon_sequence
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.lifecycle
            .encode_daemon_snapshot(&snapshot, self.daemon_sequence)
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }

    pub(super) fn require_request(
        &self,
        request: &VerifiedProtectedCredentialEnrollmentRequest,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let facts = &self.facts;
        if request.protected_launch_authority_id() != facts.launch_authority
            || request.protected_session_id() != facts.session
            || request.daemon_instance_id() != facts.daemon
            || request.daemon_launch_generation() != facts.launch_generation
            || request.desktop_supervisor_generation() != facts.supervisor_generation
            || request.release_tuple_digest() != facts.release
            || request.tauri_peer_process_evidence_digest() != facts.tauri_peer
            || request.broker_process_evidence_digest() != self.broker_evidence
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(())
    }

    pub(super) fn admission_binding(
        &self,
        request: &VerifiedProtectedCredentialEnrollmentRequest,
    ) -> Result<ProtectedCredentialEnrollmentAdmissionBinding, ProviderCredentialEnrollmentHostError>
    {
        ProtectedCredentialEnrollmentAdmissionBinding::new(
            self.facts.installation,
            self.facts.release,
            session_binding(&self.facts),
            self.facts.supervisor_generation,
            daemon_binding(&self.facts),
            self.facts.database_generation,
            self.facts.tauri_peer,
            request.native_confirmation_digest(),
            request.broker_process_evidence_digest(),
            *uuid::Uuid::now_v7().as_bytes(),
            request.expires_at_unix_millis(),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

impl Drop for DaemonProtectedCredentialEnrollmentSession {
    fn drop(&mut self) {
        for control in &self.http_controls {
            control.clear_http_facts(self.http_session);
        }
    }
}
