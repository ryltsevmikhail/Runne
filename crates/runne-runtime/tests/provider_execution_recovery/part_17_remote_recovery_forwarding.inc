impl runne_application::provider::ProviderRemoteRecoveryStore
    for FailFirstAcknowledgementStore
{
    fn find_remote_attempt(
        &self,
        taskrun: TaskRunId,
        attempt: AttemptId,
    ) -> Result<Option<runne_provider::DispatchAttemptId>, ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::find_remote_attempt(
            self.inner.as_ref(), taskrun, attempt,
        )
    }

    fn find_remote_attempt_history(
        &self,
        taskrun: TaskRunId,
        attempt: AttemptId,
    ) -> Result<Option<runne_provider::DispatchAttemptId>, ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::find_remote_attempt_history(
            self.inner.as_ref(), taskrun, attempt,
        )
    }

    fn load_remote_attempt_history(
        &self,
        taskrun: TaskRunId,
        attempt: AttemptId,
    ) -> Result<
        Option<runne_application::provider::ProviderRemoteAttemptRecord>,
        ProviderExecutionError,
    > {
        runne_application::provider::ProviderRemoteRecoveryStore::load_remote_attempt_history(
            self.inner.as_ref(), taskrun, attempt,
        )
    }

    fn load_remote_call_digest_version(
        &self,
        attempt: runne_provider::DispatchAttemptId,
    ) -> Result<runne_provider::ProviderCallDigestVersion, ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::load_remote_call_digest_version(
            self.inner.as_ref(), attempt,
        )
    }

    fn scan_remote_attempts(
        &self,
        after: Option<runne_provider::DispatchAttemptId>,
        limit: usize,
    ) -> Result<runne_application::provider::ProviderRemoteAttemptPage, ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::scan_remote_attempts(
            self.inner.as_ref(), after, limit,
        )
    }

    fn remote_cancel_requested(
        &self,
        binding: &runne_application::provider::ProviderRemoteAttemptBinding,
    ) -> Result<bool, ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::remote_cancel_requested(
            self.inner.as_ref(), binding,
        )
    }

    fn resolve_remote_attempt_binding(
        &self,
        claim: &runne_provider::ProviderDispatchClaim,
        provider_id: &runne_provider::ProviderId,
        credential_realm: &runne_provider::ProviderId,
        profile_id: &str,
    ) -> Result<runne_application::provider::ProviderRemoteAttemptBinding, ProviderExecutionError>
    {
        runne_application::provider::ProviderRemoteRecoveryStore::resolve_remote_attempt_binding(
            self.inner.as_ref(), claim, provider_id, credential_realm, profile_id,
        )
    }

    fn issue_remote_operation_proof(
        &self,
        binding: &runne_application::provider::ProviderRemoteAttemptBinding,
        response_id: &runne_provider::RemoteResponseId,
        operation: runne_provider::ProviderRecoveryOperation,
    ) -> Result<runne_provider::ProviderRemoteOperationProof, ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::issue_remote_operation_proof(
            self.inner.as_ref(), binding, response_id, operation,
        )
    }

    fn validate_remote_operation_proof(
        &self,
        proof: &runne_provider::ProviderRemoteOperationProof,
        response_id: &runne_provider::RemoteResponseId,
    ) -> Result<(), ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::validate_remote_operation_proof(
            self.inner.as_ref(), proof, response_id,
        )
    }

    fn persist_remote_request(
        &self,
        request: &runne_application::provider::ProviderRemoteRequestIntent,
    ) -> Result<(), ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::persist_remote_request(
            self.inner.as_ref(), request,
        )
    }

    fn commit_remote_response_id(
        &self,
        response: &runne_application::provider::ProviderRemoteIdentityRecord,
    ) -> Result<(), ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::commit_remote_response_id(
            self.inner.as_ref(), response,
        )
    }

    fn load_remote_identity(
        &self,
        attempt: runne_provider::DispatchAttemptId,
    ) -> Result<
        Option<(
            runne_application::provider::ProviderRemoteRequestIntent,
            Option<runne_application::provider::ProviderRemoteIdentityRecord>,
        )>,
        ProviderExecutionError,
    > {
        runne_application::provider::ProviderRemoteRecoveryStore::load_remote_identity(
            self.inner.as_ref(), attempt,
        )
    }

    fn commit_remote_terminal_artifact(
        &self,
        artifact: &runne_application::provider::ProviderRemoteTerminalRecord,
    ) -> Result<(), ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::commit_remote_terminal_artifact(
            self.inner.as_ref(), artifact,
        )
    }

    fn commit_remote_terminal_artifact_with_proof(
        &self,
        artifact: &runne_application::provider::ProviderRemoteTerminalRecord,
        proof: &runne_provider::ProviderRemoteOperationProof,
    ) -> Result<(), ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::commit_remote_terminal_artifact_with_proof(
            self.inner.as_ref(), artifact, proof,
        )
    }

    fn commit_remote_operation_observation(
        &self,
        proof: &runne_provider::ProviderRemoteOperationProof,
        status: runne_provider::ProviderRemoteResponseStatus,
    ) -> Result<(), ProviderExecutionError> {
        runne_application::provider::ProviderRemoteRecoveryStore::commit_remote_operation_observation(
            self.inner.as_ref(), proof, status,
        )
    }

    fn load_remote_terminal_artifact(
        &self,
        attempt: runne_provider::DispatchAttemptId,
    ) -> Result<
        Option<runne_application::provider::ProviderRemoteTerminalRecord>,
        ProviderExecutionError,
    > {
        runne_application::provider::ProviderRemoteRecoveryStore::load_remote_terminal_artifact(
            self.inner.as_ref(), attempt,
        )
    }

    fn load_remote_attempt(
        &self,
        attempt: runne_provider::DispatchAttemptId,
    ) -> Result<
        Option<runne_application::provider::ProviderRemoteAttemptRecord>,
        ProviderExecutionError,
    > {
        runne_application::provider::ProviderRemoteRecoveryStore::load_remote_attempt(
            self.inner.as_ref(), attempt,
        )
    }
}
