fn validate_remote_terminal_source_binding(
    snapshot: &runne_application::provider::ProviderRemoteAttemptRecord,
    request: &runne_runtime::provider_execution::ProviderRemoteTerminalSourceCommit,
) -> Result<(), ProviderExecutionError> {
    let binding = &snapshot.request.binding;
    let response = snapshot
        .response
        .as_ref()
        .ok_or(ProviderExecutionError::TerminalConflict)?;
    let artifact = snapshot
        .terminal
        .as_ref()
        .ok_or(ProviderExecutionError::TerminalConflict)?;
    let matches = binding.taskrun_id == request.taskrun_id()
        && binding.taskrun_attempt_id == request.taskrun_attempt_id()
        && binding.request_digest == *request.request_digest()
        && binding.runtime_authority_id == *request.runtime_authority_id()
        && binding.database_generation == request.database_generation()
        && binding.runtime_generation == request.runtime_generation()
        && binding.fencing_token == request.fencing_token()
        && binding.profile_digest == *request.profile_digest()
        && binding.pricing_digest == *request.pricing_revision_digest()
        && response.encrypted_response_id.plaintext_digest() == request.response_id_digest()
        && artifact.encrypted_artifact.plaintext_digest() == request.artifact_digest()
        && artifact.response_id_digest == *request.response_id_digest()
        && artifact.disposition == request.terminal_status();
    if matches {
        Ok(())
    } else {
        Err(ProviderExecutionError::TerminalConflict)
    }
}
