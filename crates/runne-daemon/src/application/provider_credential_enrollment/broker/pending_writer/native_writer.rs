use super::*;

impl VerifiedMacOsWriterWithDaemonKillCapability {
    pub(crate) const fn verified_measurement_facts(
        &self,
    ) -> &runne_platform_desktop::provider_credential_broker::VerifiedWriterMeasurementFacts {
        self.kill.verified_measurement_facts()
    }

    pub(in crate::application::provider_credential_enrollment::broker) fn control(
        &mut self,
    ) -> &mut UnixStream {
        self.authority.endpoint_mut()
    }

    pub(in crate::application::provider_credential_enrollment::broker) fn sign_writer_session(
        &mut self,
        receipt: &runne_provider::IssuedCredentialTicketAttempt,
        frame: &runne_provider::CredentialBrokerFrame,
        daemon_start: [u8; 32],
        daemon_image: [u8; 32],
    ) -> Result<
        (
            runne_provider::SignedCredentialWriterSessionAttestationV1,
            runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let issue = runne_provider::CredentialIssueTicketBindingV1::from_issue_ticket(frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let runne_provider::CredentialBrokerFrame::IssueTicket { binding, .. } = frame else {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        };
        let digest = |value| {
            runne_provider::CredentialBindingDigest::from_measured(value)
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
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
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
            runne_provider::CredentialWriterSessionRuntimeClaimsV1::new(
                digest(self.binding.protected_session)?,
                digest(self.binding.tauri_peer)?,
                digest(self.binding.daemon_authority)?,
                self.binding.database_generation,
                self.binding.supervisor_generation,
                self.binding.release_tuple,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
            runne_provider::CredentialWriterSessionProcessClaimsV1::new(
                digest(self.handoff.digest())?,
                digest(writer.process_start())?,
                digest(writer.image())?,
                digest(writer.writer_kill_public_key())?,
                digest(daemon_start)?,
                digest(daemon_image)?,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
        );
        self.authority.sign_writer_session(claims)
    }

    pub(crate) fn matches_bound_operation(
        &self,
        operation_id: runne_provider::CredentialOperationId,
        channel: [u8; 32],
        publication_public_key: [u8; 32],
    ) -> bool {
        self.binding.operation_id == operation_id
            && self.authority.channel_binding() == channel
            && self.authority.publication_public_key() == publication_public_key
            && self.kill.verified_measurement_facts().channel() == channel
            && self
                .kill
                .verified_measurement_facts()
                .publication_public_key()
                == publication_public_key
    }

    pub(crate) fn terminate_exact_writer(
        self,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.kill.terminate_exact_peer().map_err(map_handoff)
    }
}
