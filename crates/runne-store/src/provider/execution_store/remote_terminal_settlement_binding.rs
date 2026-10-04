fn verify_remote_terminal_source_binding_tx(
    transaction: &Transaction<'_>,
    request: &runne_runtime::provider_execution::ProviderRemoteTerminalSourceCommit,
    snapshot: &runne_application::provider::ProviderRemoteAttemptRecord,
    authenticate: &dyn Fn(
        &runne_application::provider::ProviderRemoteAttemptRecord,
    ) -> Result<(), ProviderExecutionError>,
) -> Result<
    crate::store::taskrun_submit_origin::VerifiedRemoteTerminalTaskRunSource,
    ProviderExecutionError,
> {
    authenticate(snapshot)?;
    validate_remote_terminal_source_binding(snapshot, request)?;
    let authority = request
        .runtime_authority_id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let verified = crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
        transaction,
        request.attempt_id().as_bytes(),
        &runne_application::ports::RuntimeAuthorityId(authority),
    )
    .map_err(|_| ProviderExecutionError::TerminalConflict)?;
    if verified.taskrun_id != request.taskrun_id()
        || verified.taskrun_attempt_id != request.taskrun_attempt_id()
        || verified.current_taskrun_version < verified.expected_taskrun_version
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(verified)
}
