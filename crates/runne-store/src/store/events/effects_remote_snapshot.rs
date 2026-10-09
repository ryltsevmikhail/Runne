pub(crate) fn load_task_run_effects_snapshot_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    runtime_authority_id: &runne_application::ports::RuntimeAuthorityId,
    taskrun_id: TaskRunId,
    authenticator: Option<&dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
    source1_authenticator: Option<
        &dyn runne_application::provider::ProviderUnknownTerminalFactAuthenticator,
    >,
    successor_eligibility: SuccessorEligibilityV1,
) -> Result<runne_application::ports::TaskRunEffectsReadSnapshot, EventStoreError> {
    let verified = crate::store::test_support_diagnostics::on_error(
        "effects.stream_validation",
        crate::store::taskrun_claim::stream_validate::verify_stream(tx, taskrun_id, None)
            .map_err(|_| EventStoreError::CorruptData),
    )?;
    let taskrun = crate::store::test_support_diagnostics::on_error(
        "effects.taskrun_replay",
        runne_domain::task_run::TaskRun::replay(&verified.events)
            .map_err(|_| EventStoreError::CorruptData),
    )?;
    let stream_version = verified.version;
    let origin = crate::store::test_support_diagnostics::on_error(
        "effects.submit_origin",
        crate::store::taskrun_submit_origin::verify_submitted_v2_origin(
            tx,
            taskrun_id,
            runtime_authority_id,
        )
        .map_err(|_| EventStoreError::CorruptData),
    )?;
    let cancellation_requested = verified
        .events
        .iter()
        .any(|event| event.payload() == &TaskRunEvent::CancellationRequested);
    let (local_command, attempt_id) = match origin {
        Some(origin) if origin.input.local_command().is_some() => {
            let command = origin
                .input
                .local_command()
                .ok_or(EventStoreError::CorruptData)?;
            let row = crate::store::test_support_diagnostics::on_error(
                "effects.local_row",
                local_effect_row(tx, taskrun_id),
            )?;
            if row.0.as_slice() != origin.conversation_id.as_bytes()
                || row.1.as_slice() != origin.workspace_id.as_bytes()
                || row.2.as_slice() != command.intent_digest()
            {
                crate::store::test_support_diagnostics::record("effects.local_binding");
                return Err(EventStoreError::CorruptData);
            }
            let attempt = parse_optional_attempt(row.4)?;
            if attempt.is_some_and(|value| !taskrun.attempt_history().contains(&value)) {
                return Err(EventStoreError::CorruptData);
            }
            if let Some(attempt) = attempt {
                let assigned: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM taskrun_assignments WHERE taskrun_id=?1 AND attempt_id=?2)",
                        params![taskrun_id.as_bytes(), attempt.as_bytes()],
                        |record| record.get(0),
                    )
                    .map_err(|_| EventStoreError::CorruptData)?;
                if !assigned {
                    return Err(EventStoreError::CorruptData);
                }
            }
            let exit_code = row
                .5
                .map(|value| i32::try_from(value).map_err(|_| EventStoreError::CorruptData))
                .transpose()?;
            let head = verified.events.last();
            let terminal_stop_proven = crate::store::terminal_stop_proven(
                tx,
                crate::store::LocalEffectsProofRequest {
                    taskrun_id,
                    attempt,
                    area_identity: row.6.as_deref(),
                    command_digest: command.intent_digest().as_slice(),
                    state: &row.3,
                    stream_version,
                    head_event_id: head.map(|event| *event.event_id()),
                    head_event: head.map(|event| event.payload()),
                },
            );
            let (terminal_stop_proven, policy_stop_proven) =
                crate::store::test_support_diagnostics::on_error(
                    "effects.local_terminal_proof",
                    terminal_stop_proven,
                )?;
            if matches!(
                row.3.as_str(),
                "completed" | "cancelled" | "outcome_unknown"
            ) && !terminal_stop_proven
                && !policy_stop_proven
            {
                crate::store::test_support_diagnostics::record("effects.local_terminal_unproven");
                return Err(EventStoreError::CorruptData);
            }
            let (outcome, stop) = crate::store::test_support_diagnostics::on_error(
                "effects.local_projection",
                project_local_effect(
                    &row.3,
                    attempt,
                    exit_code,
                    row.6.as_deref(),
                    cancellation_requested,
                    terminal_stop_proven,
                    policy_stop_proven,
                ),
            )?;
            (
                Some(LocalCommandEffectV1 {
                    outcome,
                    stop,
                    exit_code,
                }),
                attempt,
            )
        }
        Some(_) => (
            None,
            crate::store::test_support_diagnostics::on_error(
                "effects.latest_attempt",
                latest_validated_attempt(tx, taskrun_id, &taskrun),
            )?,
        ),
        None => {
            if crate::store::test_support_diagnostics::on_error(
                "effects.local_row_optional",
                local_effect_row_optional(tx, taskrun_id),
            )?
            .is_some()
            {
                crate::store::test_support_diagnostics::record("effects.unexpected_local_row");
                return Err(EventStoreError::CorruptData);
            }
            (
                None,
                crate::store::test_support_diagnostics::on_error(
                    "effects.latest_attempt",
                    latest_validated_attempt(tx, taskrun_id, &taskrun),
                )?,
            )
        }
    };
    let local_is_selected = local_command.is_some();
    let source1 = if local_is_selected {
        None
    } else if let (Some(attempt), Some(authenticator)) = (attempt_id, source1_authenticator) {
        let snapshot = crate::provider::load_unknown_effects_snapshot(tx, taskrun_id, attempt)
            .map_err(|_| EventStoreError::CorruptData)?;
        snapshot
            .as_ref()
            .map(|snapshot| authenticator.authenticate_unknown_terminal(snapshot))
            .transpose()
            .map_err(|_| EventStoreError::CorruptData)?
    } else {
        None
    };
    let remote = if local_is_selected {
        None
    } else if let Some(attempt) = attempt_id {
        crate::store::test_support_diagnostics::on_error(
            "effects.remote_snapshot",
            crate::provider::load_remote_effects_snapshot_in_transaction(
                tx,
                runtime_authority_id,
                taskrun_id,
                attempt,
                authenticator,
                successor_eligibility,
            )
            .map_err(|_| EventStoreError::CorruptData),
        )?
    } else {
        None
    };
    if source1.is_some() && remote.is_some() {
        return Err(EventStoreError::CorruptData);
    }
    let effects = TaskRunEffectsV1 {
        taskrun_id,
        stream_version,
        attempt_id,
        cancellation_requested,
        local_command,
        remote: if let Some(fact) = source1.as_ref() {
            project_unknown_source1_effect(fact, cancellation_requested)
        } else {
            project_remote_effect(remote.as_ref(), cancellation_requested, local_is_selected)
        },
        successor: if local_is_selected {
            SuccessorEligibilityV1::NotApplicable
        } else {
            successor_eligibility
        },
    };
    Ok(runne_application::ports::TaskRunEffectsReadSnapshot {
        effects,
        remote,
        source1,
    })
}

include!("effects_remote_snapshot_projection.rs");

include!("effects_remote_snapshot_observation.rs");

include!("effects_remote_snapshot_tests.rs");
