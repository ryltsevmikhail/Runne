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
        let inputs = super::attestation_claims::SessionClaimInputs {
            owner: self.binding.owner,
            begin_proof: self.binding.begin_proof,
            protected_session: self.binding.protected_session,
            tauri_peer: self.binding.tauri_peer,
            daemon_authority: self.binding.daemon_authority,
            database_generation: self.binding.database_generation,
            supervisor_generation: self.binding.supervisor_generation,
            release_tuple: self.binding.release_tuple,
            endpoint_handoff_digest: self.handoff.digest(),
            writer_process_start: *self.kill.verified_measurement_facts().process_start(),
            writer_image: *self.kill.verified_measurement_facts().image(),
            writer_kill_public_key: *self
                .kill
                .verified_measurement_facts()
                .writer_kill_public_key(),
        };
        let claims = super::attestation_claims::build_session_claims(
            receipt,
            frame,
            daemon_start,
            daemon_image,
            &inputs,
        )?;
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
