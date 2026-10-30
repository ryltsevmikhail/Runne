use runne_application::provider::ProviderRemoteAttemptRecord;
pub(crate) fn authenticate_remote_terminal_snapshot_with_keyring<
    K: ProviderJournalKeyring + ?Sized,
>(
    keyring: &K,
    snapshot: &ProviderRemoteAttemptRecord,
    expected: &ProviderRecoveryAttemptIdentity,
    taskrun: runne_domain::id::TaskRunId,
    task_attempt: runne_domain::id::AttemptId,
) -> Result<Option<runne_provider::ProviderRemoteTerminalArtifact>, ProviderRecoveryError> {
    let request = &snapshot.request;
    let binding = &request.binding;
    if binding.taskrun_id != taskrun
        || binding.taskrun_attempt_id != task_attempt
        || binding.provider_id != expected.provider_id().as_str()
        || binding.credential_realm != expected.credential_realm().as_str()
        || binding.profile_id != expected.profile_id()
        || binding.profile_digest != *expected.profile_digest()
        || binding.pricing_digest != *expected.pricing_digest()
        || binding.semantic_digest != *expected.semantic_digest()
        || binding.prepared_digest != *expected.prepared_digest()
        || binding.request_digest != *expected.request_digest()
        || binding.runtime_authority_id != *expected.runtime_authority_id()
        || binding.database_generation != expected.database_generation()
        || binding.runtime_generation != expected.runtime_generation()
        || binding.fencing_token != expected.fencing_token()
    {
        return Err(ProviderRecoveryError::InvalidIdentity);
    }
    let Some(terminal) = snapshot.terminal.as_ref() else {
        return Ok(None);
    };
    let response = snapshot
        .response
        .as_ref()
        .ok_or(ProviderRecoveryError::InvalidIdentity)?;
    if response.binding != *binding
        || terminal.binding != *binding
        || response.key != request.key
        || terminal.key != request.key
        || terminal.response_id_digest != *response.encrypted_response_id.plaintext_digest()
    {
        return Err(ProviderRecoveryError::InvalidIdentity);
    }
    let attempt = ProviderRecoveryBinding::new(
        taskrun,
        task_attempt,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )?;
    let key = keyring
        .load_provider_journal_key(
            secure_ref_from_binding(request.key).map_err(|_| ProviderRecoveryError::Unavailable)?,
        )
        .map_err(|_| ProviderRecoveryError::Unavailable)?;
    let rendered = Zeroizing::new(
        open_payload(
            &key,
            &remote_request_aad(attempt, expected, request.key),
            &request.encrypted_request,
        )
        .map_err(|_| ProviderRecoveryError::Unavailable)?,
    );
    if sha2::Sha256::digest(rendered.as_slice()).as_slice() != expected.request_digest() {
        return Err(ProviderRecoveryError::InvalidIdentity);
    }
    let id = open_payload(
        &key,
        &remote_response_id_aad(binding, request.key),
        &response.encrypted_response_id,
    )
    .map_err(|_| ProviderRecoveryError::Unavailable)?;
    let id = runne_provider::RemoteResponseId::new(
        String::from_utf8(id).map_err(|_| ProviderRecoveryError::InvalidIdentity)?,
    )?;
    if sha2::Sha256::digest(id.as_str().as_bytes()).as_slice() != terminal.response_id_digest {
        return Err(ProviderRecoveryError::InvalidIdentity);
    }
    let payload = Zeroizing::new(
        open_payload(
            &key,
            &remote_terminal_aad(
                binding,
                request.key,
                terminal.response_id_digest,
                terminal.disposition,
            ),
            &terminal.encrypted_artifact,
        )
        .map_err(|_| ProviderRecoveryError::Unavailable)?,
    );
    decode_terminal_payload(
        &payload,
        id.as_str().as_bytes(),
        terminal.response_id_digest,
        terminal.disposition,
    )
}

impl<K, S> RuntimeProviderRemoteIdentityCommitter<K, S>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderRemoteRecoveryStore + ?Sized,
{
    /// Authenticates one caller-snapshot record and returns only a bounded fact DTO.
    /// The caller must keep its DEFERRED read transaction open until this returns.
    pub(crate) fn authenticate_remote_terminal_snapshot(
        &self,
        snapshot: &ProviderRemoteAttemptRecord,
        expected: &ProviderRecoveryAttemptIdentity,
        taskrun: runne_domain::id::TaskRunId,
        task_attempt: runne_domain::id::AttemptId,
    ) -> Result<Option<runne_provider::ProviderRemoteTerminalArtifact>, ProviderRecoveryError> {
        authenticate_remote_terminal_snapshot_with_keyring(
            self.keyring.as_ref(),
            snapshot,
            expected,
            taskrun,
            task_attempt,
        )
    }
}

impl<K, S> runne_application::provider::ProviderRemoteFactAuthenticator
    for RuntimeProviderRemoteIdentityCommitter<K, S>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderRemoteRecoveryStore + ?Sized,
{
    fn authenticate_terminal_snapshot(
        &self,
        snapshot: &ProviderRemoteAttemptRecord,
        expected: &ProviderRecoveryAttemptIdentity,
    ) -> Result<
        Option<runne_application::provider::ProviderRemoteAuthenticatedTerminalFact>,
        ProviderRecoveryError,
    > {
        self.authenticate_remote_terminal_snapshot(
            snapshot,
            expected,
            snapshot.request.binding.taskrun_id,
            snapshot.request.binding.taskrun_attempt_id,
        )?
        .map(|artifact| {
            runne_application::provider::ProviderRemoteAuthenticatedTerminalFact::new(
                artifact.status().clone(),
                artifact.publication_disposition(),
                terminal_output_digest(&artifact),
            )
            .map_err(|_| ProviderRecoveryError::InvalidIdentity)
        })
        .transpose()
    }

    fn verify_stream_settlement_digest(
        &self,
        snapshot: &ProviderRemoteAttemptRecord,
        expected: &ProviderRecoveryAttemptIdentity,
        candidate: runne_application::provider::ProviderRemoteTerminalSettlementDigestCandidate<'_>,
        journal: &[ProviderJournalAppendRequest],
        kind: ProviderTerminalApplicationKind,
    ) -> Result<bool, ProviderRecoveryError> {
        self.authenticate_stream_request(snapshot, expected)?;
        verify_authenticated_stream_settlement(
            self.keyring.as_ref(),
            &snapshot.request.binding,
            candidate,
            journal,
            kind,
        )
    }

    fn authenticate_stream_terminal(
        &self,
        snapshot: &ProviderRemoteAttemptRecord,
        expected: &ProviderRecoveryAttemptIdentity,
        journal: &[ProviderJournalAppendRequest],
        kind: ProviderTerminalApplicationKind,
    ) -> Result<
        Option<runne_application::provider::ProviderRemoteAuthenticatedTerminalFact>,
        ProviderRecoveryError,
    > {
        self.authenticate_stream_request(snapshot, expected)?;
        let assembled = authenticate_stream_journal(
            self.keyring.as_ref(),
            &snapshot.request.binding,
            journal,
            kind,
        )?;
        if assembled.disposition != ProviderTerminalDisposition::Completed {
            return Ok(None);
        }
        runne_application::provider::ProviderRemoteAuthenticatedTerminalFact::new(
            runne_provider::ProviderRemoteResponseStatus::Completed {
                usage: assembled.usage.exact(),
            },
            runne_provider::ProviderRemotePublicationDisposition::Allowed,
            Some(Sha256::digest(&assembled.output).into()),
        )
        .map(Some)
    }

    fn verify_terminal_settlement_digest(
        &self,
        snapshot: &ProviderRemoteAttemptRecord,
        expected: &ProviderRecoveryAttemptIdentity,
        candidate: runne_application::provider::ProviderRemoteTerminalSettlementDigestCandidate<'_>,
    ) -> Result<bool, ProviderRecoveryError> {
        let binding = &snapshot.request.binding;
        let Some(artifact) = self.authenticate_remote_terminal_snapshot(
            snapshot,
            expected,
            binding.taskrun_id,
            binding.taskrun_attempt_id,
        )?
        else {
            return Ok(false);
        };
        let (status, usage) = match artifact.status() {
            runne_provider::ProviderRemoteResponseStatus::Completed { usage: Some(usage) } => (
                runne_application::provider::ProviderRemoteTerminalDisposition::Completed,
                *usage,
            ),
            runne_provider::ProviderRemoteResponseStatus::Failed {
                usage: Some(usage), ..
            } => (
                runne_application::provider::ProviderRemoteTerminalDisposition::Failed,
                *usage,
            ),
            runne_provider::ProviderRemoteResponseStatus::Incomplete {
                usage: Some(usage), ..
            } => (
                runne_application::provider::ProviderRemoteTerminalDisposition::Incomplete,
                *usage,
            ),
            runne_provider::ProviderRemoteResponseStatus::Cancelled { usage: Some(usage) } => (
                runne_application::provider::ProviderRemoteTerminalDisposition::Cancelled,
                *usage,
            ),
            _ => return Ok(false),
        };
        if status != candidate.status || usage != candidate.usage {
            return Ok(false);
        }
        Ok(remote_terminal_settlement_digest(
            snapshot,
            &artifact,
            status,
            usage,
            candidate.charge_micros,
            candidate.currency,
        ) == *candidate.settlement_digest)
    }
}

fn terminal_output_digest(
    artifact: &runne_provider::ProviderRemoteTerminalArtifact,
) -> Option<[u8; 32]> {
    if artifact.publication_disposition()
        != runne_provider::ProviderRemotePublicationDisposition::Allowed
        || !matches!(
            artifact.status(),
            runne_provider::ProviderRemoteResponseStatus::Completed { .. }
        )
    {
        return None;
    }
    artifact
        .output_text()
        .map(|text| sha2::Sha256::digest(text.as_bytes()).into())
}
