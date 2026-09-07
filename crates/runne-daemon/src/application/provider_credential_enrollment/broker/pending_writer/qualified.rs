use super::super::pending_writer::VerifiedMacOsWriterWithDaemonKillCapability;

impl VerifiedMacOsWriterWithDaemonKillCapability {
    /// Signs the qualification-required V2 commitment without unlocking publication.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::application::provider_credential_enrollment::broker) fn sign_writer_session_qualified(
        &mut self,
        receipt: &runne_provider::IssuedCredentialTicketAttempt,
        frame: &runne_provider::CredentialBrokerFrame,
        daemon_start: [u8; 32],
        daemon_image: [u8; 32],
        launch_generation: u64,
        context_sha256: [u8; 32],
        ticket_sha256: [u8; 32],
    ) -> Result<
        (
            runne_provider::SignedCredentialWriterSessionAttestationV2,
            runne_provider::CredentialWriterQualifiedPreludeSigner,
        ),
        runne_api::ProviderCredentialEnrollmentHostError,
    > {
        let issue = runne_provider::CredentialIssueTicketBindingV1::from_issue_ticket(frame)
            .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let runne_provider::CredentialBrokerFrame::IssueTicket { binding, .. } = frame else {
            return Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied);
        };
        let digest = |value| {
            runne_provider::CredentialBindingDigest::from_measured(value)
                .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
        };
        let writer = self.verified_measurement_facts();
        let claims = runne_provider::CredentialWriterSessionAttestationClaimsV1::new(
            runne_provider::CredentialWriterSessionTicketClaimsV1::new(
                receipt.operation().operation_id(),
                receipt.ticket_attempt(),
                issue,
                *binding,
                self.binding.owner,
                self.binding.begin_proof,
                receipt.issued_at_high_water(),
                receipt.expires_at_high_water(),
            )
            .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)?,
            runne_provider::CredentialWriterSessionRuntimeClaimsV1::new(
                digest(self.binding.protected_session)?,
                digest(self.binding.tauri_peer)?,
                digest(self.binding.daemon_authority)?,
                self.binding.database_generation,
                self.binding.supervisor_generation,
                self.binding.release_tuple,
            )
            .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)?,
            runne_provider::CredentialWriterSessionProcessClaimsV1::new(
                digest(self.handoff.digest())?,
                digest(writer.process_start())?,
                digest(writer.image())?,
                digest(writer.writer_kill_public_key())?,
                digest(daemon_start)?,
                digest(daemon_image)?,
            )
            .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)?,
        );
        self.authority.sign_writer_session_qualified(
            claims,
            launch_generation,
            context_sha256,
            ticket_sha256,
        )
    }
}
