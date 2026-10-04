use runne_application::provider::{
    ProviderRemoteTerminalDisposition, ProviderRemoteTerminalRecord,
};
use runne_provider::{
    ProviderRecoveryOperation, ProviderRemoteOperationProof, ProviderRemoteResponseStatus,
    ProviderRemoteTerminalArtifact,
};

const REMOTE_TERMINAL_AAD: &[u8] = b"GOCODE_PROVIDER_REMOTE_TERMINAL_V1\0";

impl<K, S> RuntimeProviderRemoteIdentityCommitter<K, S>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderRemoteRecoveryStore + ?Sized,
{
    /// Encrypts and durably commits a terminal artifact after the adapter validated it.
    pub(crate) fn persist_remote_terminal_artifact(
        &self,
        expected: ProviderRecoveryBinding,
        artifact: &ProviderRemoteTerminalArtifact,
        proof: &ProviderRemoteOperationProof,
    ) -> Result<(), ProviderRecoveryError> {
        if !matches!(
            proof.operation(),
            ProviderRecoveryOperation::StatusCheck | ProviderRecoveryOperation::RemoteCancel
        ) || proof.binding() != expected
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let snapshot = self
            .store
            .load_remote_attempt(expected.provider_attempt_id())
            .map_err(|_| ProviderRecoveryError::Unavailable)?
            .ok_or(ProviderRecoveryError::Unavailable)?;
        let request = &snapshot.request;
        let binding = &request.binding;
        verify_remote_snapshot(
            expected,
            binding,
            snapshot.response.as_ref(),
            snapshot.terminal.as_ref(),
        )?;
        let response = snapshot
            .response
            .as_ref()
            .ok_or(ProviderRecoveryError::InvalidIdentity)?;
        let material = self
            .keyring
            .load_provider_journal_key(
                secure_ref_from_binding(request.key)
                    .map_err(|_| ProviderRecoveryError::Unavailable)?,
            )
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let id_bytes = open_payload(
            &material,
            &remote_response_id_aad(binding, request.key),
            &response.encrypted_response_id,
        )
        .map_err(|_| ProviderRecoveryError::Unavailable)?;
        if id_bytes.as_slice() != artifact.response_id().as_str().as_bytes() {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        if !proof.matches(expected, proof.operation(), artifact.response_id()) {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let payload = encode_terminal_payload(artifact)?;
        let response_digest: [u8; 32] = sha2::Sha256::digest(&id_bytes).into();
        if let Some(existing) = snapshot.terminal {
            if existing.response_id_digest != response_digest
                || existing.binding != *binding
                || existing.key != request.key
            {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            let old = open_payload(
                &material,
                &remote_terminal_aad(binding, request.key, response_digest, existing.disposition),
                &existing.encrypted_artifact,
            )
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
            return if old.as_slice() == payload.as_slice() {
                Ok(())
            } else {
                Err(ProviderRecoveryError::InvalidIdentity)
            };
        }
        let app_binding = request.binding.clone();
        let disposition = terminal_disposition(artifact.status())?;
        let encrypted = seal_payload_with_nonce(
            &material,
            self.nonce()?,
            &remote_terminal_aad(binding, request.key, response_digest, disposition),
            &payload,
        )
        .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let record = ProviderRemoteTerminalRecord::new(
            app_binding,
            request.key,
            response_digest,
            disposition,
            encrypted,
        )
        .map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
        self.store
            .commit_remote_terminal_artifact_with_proof(&record, proof)
            .map_err(|_| ProviderRecoveryError::Unavailable)
    }

    /// Loads one terminal artifact from a consistent request/ID/artifact snapshot.
    pub fn load_persisted_remote_terminal(
        &self,
        expected: ProviderRecoveryBinding,
    ) -> Result<Option<ProviderRemoteTerminalArtifact>, ProviderRecoveryError> {
        let Some(snapshot) = self
            .store
            .load_remote_attempt(expected.provider_attempt_id())
            .map_err(|_| ProviderRecoveryError::Unavailable)?
        else {
            return Ok(None);
        };
        let request = &snapshot.request;
        let Some(record) = snapshot.terminal else {
            return Ok(None);
        };
        verify_remote_snapshot(
            expected,
            &request.binding,
            snapshot.response.as_ref(),
            Some(&record),
        )?;
        let response = snapshot
            .response
            .as_ref()
            .ok_or(ProviderRecoveryError::InvalidIdentity)?;
        if record.key != request.key
            || record.response_id_digest != *response.encrypted_response_id.plaintext_digest()
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let material = self
            .keyring
            .load_provider_journal_key(
                secure_ref_from_binding(request.key)
                    .map_err(|_| ProviderRecoveryError::Unavailable)?,
            )
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let id = open_payload(
            &material,
            &remote_response_id_aad(&request.binding, request.key),
            &response.encrypted_response_id,
        )
        .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let terminal_plain = Zeroizing::new(
            open_payload(
                &material,
                &remote_terminal_aad(
                    &record.binding,
                    record.key,
                    record.response_id_digest,
                    record.disposition,
                ),
                &record.encrypted_artifact,
            )
            .map_err(|_| ProviderRecoveryError::Unavailable)?,
        );
        decode_terminal_payload(
            &terminal_plain,
            &id,
            record.response_id_digest,
            record.disposition,
        )
    }
}

fn verify_remote_snapshot(
    expected: ProviderRecoveryBinding,
    binding: &runne_application::provider::ProviderRemoteAttemptBinding,
    response: Option<&runne_application::provider::ProviderRemoteIdentityRecord>,
    terminal: Option<&ProviderRemoteTerminalRecord>,
) -> Result<(), ProviderRecoveryError> {
    if binding.dispatch_attempt_id != expected.provider_attempt_id()
        || binding.taskrun_id != expected.task_run_id()
        || binding.taskrun_attempt_id != expected.task_attempt_id()
        || binding.profile_digest != expected.profile_digest()
        || response.is_some_and(|row| row.binding != *binding)
        || terminal.is_some_and(|row| row.binding != *binding)
    {
        return Err(ProviderRecoveryError::InvalidIdentity);
    }
    Ok(())
}
