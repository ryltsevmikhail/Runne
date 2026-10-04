fn remote_artifact_cancel_closure_matches(
    tx: &Connection,
    attempt_id: [u8; 16],
    artifact_digest: &[u8],
    terminal_status: i64,
    verified: &crate::store::taskrun_submit_origin::VerifiedRemoteTerminalTaskRunSource,
    receipt: &runne_application::ports::TextGenerationReceipt,
    validate_global_closures: bool,
) -> Result<bool, ProviderExecutionError> {
    use crate::store::taskrun_submit_origin::RemoteTerminalTaskRunApplicability;
    let RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
        taskrun_state,
        terminal_event_id,
        terminal_version,
        terminal_payload,
        ..
    } = &verified.applicability
    else {
        return Ok(false);
    };
    if *taskrun_state != runne_domain::task_run::TaskRunState::Cancelled
        || terminal_payload.as_ref() != &runne_domain::task_run::TaskRunEvent::CancellationCompleted
        || receipt.taskrun_version != *terminal_version
        || *terminal_event_id == [0; 16]
    {
        return Ok(false);
    }
    let closure_matches: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_remote_artifact_cancel_closures
             WHERE dispatch_attempt_id=?1 AND taskrun_id=?2
               AND taskrun_attempt_id=?3 AND conversation_id=?4
               AND artifact_digest=?5 AND terminal_status=?6
               AND taskrun_terminal_event_id=?7 AND taskrun_terminal_version=?8)",
            params![
                attempt_id.as_slice(),
                verified.taskrun_id.as_bytes(),
                verified.taskrun_attempt_id.as_bytes(),
                verified.conversation_id.as_bytes(),
                artifact_digest,
                terminal_status,
                terminal_event_id.as_slice(),
                i64::try_from(*terminal_version)
                    .map_err(|_| ProviderExecutionError::OutboxConflict)?,
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::OutboxConflict)?;
    if !closure_matches {
        return Ok(false);
    }
    if validate_global_closures
        && !crate::schema::verify_v60_remote_artifact_cancel_closures(tx)
            .map_err(|_| ProviderExecutionError::OutboxConflict)?
    {
        return Ok(false);
    }
    Ok(true)
}
