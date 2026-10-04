fn v57_row_events_match_inner(
    connection: &Connection,
    row: &SuccessorRow,
    require_pre_artifact_unknown_proof: bool,
) -> SqliteResult<bool> {
    use crate::codec::{IdempotencyScopeCodec, StoreCodec, TaskRunEventCodec};
    use runne_application::commands::{
        SupersedeUnknownTaskRunInput, UnknownSuccessorAcknowledgmentV1,
    };
    use runne_application::fingerprint::CommandFingerprint;
    use runne_domain::id::{AttemptId, TaskRunId};
    use runne_domain::task_run::TaskRunEvent;

    let taskrun = TaskRunId::from_bytes(
        row.predecessor
            .as_slice()
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    );
    let submit_payload: Vec<u8> = connection.query_row(
        "SELECT payload FROM events WHERE event_id=?1 AND aggregate_type=1
           AND aggregate_id=?2 AND sequence=?3",
        rusqlite::params![row.submit_id, row.successor, row.submit_version],
        |saved| saved.get(0),
    )?;
    let Ok(TaskRunEvent::TaskRunSubmitted {
        conversation_id,
        workspace_id,
        input,
    }) = TaskRunEventCodec.decode(&submit_payload)
    else {
        return Ok(false);
    };
    let Ok(Some(verified_origin)) =
        crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
            connection, taskrun,
        )
    else {
        return Ok(false);
    };
    let predecessor_project = verified_origin.project_id;
    let predecessor_conversation = verified_origin.conversation_id;
    let predecessor_workspace = verified_origin.workspace_id;
    let predecessor_input = verified_origin.input;
    let ack = UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1.digest();
    let Ok(scope) = IdempotencyScopeCodec.decode(&row.scope_bytes) else {
        return Ok(false);
    };
    if row.conversation.as_slice() != conversation_id.as_bytes()
        || row.workspace.as_slice() != workspace_id.as_bytes()
        || predecessor_conversation != conversation_id
        || predecessor_workspace != workspace_id
        || verified_origin.principal_id.0 != row.principal_id
        || verified_origin.conversation_id != conversation_id
        || verified_origin.workspace_id != workspace_id
        || row.origin_kind != "canonical_workspace"
        || row.origin_operation != 24
        || row.project_id.as_deref()
            != predecessor_project
                .as_ref()
                .map(|project| project.as_bytes().as_slice())
        || row
            .project_id
            .as_ref()
            .is_none_or(|project| project.len() != 16)
        || connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_run_workspace_lineage WHERE taskrun_id=?1)",
            [&row.successor],
            |saved| saved.get::<_, bool>(0),
        )?
        || row.predecessor_input_digest.as_slice()
            != CommandFingerprint::for_submit(
                &predecessor_conversation,
                &predecessor_workspace,
                &predecessor_input,
            )
            .as_bytes()
        || row.ack != ack.as_bytes()
        || scope.principal_id.0 != row.principal_id
        || scope.operation != runne_application::ports::OperationTag::SupersedeUnknownTaskRun
        || principal_digest(&row.principal_id) != row.principal_digest.as_slice()
        || row.input_digest.as_slice()
            != CommandFingerprint::for_submit(&conversation_id, &workspace_id, &input).as_bytes()
        || row.receipt_fingerprint != row.command_fingerprint
        || successor_key_digest(&row.idempotency_key) != row.key_digest.as_slice()
    {
        return Ok(false);
    }
    if let Some(provider) = row.provider.as_deref() {
        let (Some(profile), Some(profile_digest), Some(model), Some(revision), Some(model_digest)) = (
            row.profile.as_deref(),
            row.profile_digest.as_deref(),
            row.model.as_deref(),
            row.revision.as_deref(),
            row.model_digest.as_deref(),
        ) else {
            return Ok(false);
        };
        let Ok(provider_id) = runne_provider::ProviderId::new(provider.to_owned()) else {
            return Ok(false);
        };
        let Ok(model_ref) = runne_provider::ModelRef::new(provider_id, model, revision) else {
            return Ok(false);
        };
        if model_ref.digest_v1().as_slice() != model_digest {
            return Ok(false);
        }
        let Some(selected) = input.selected_profile() else {
            return Ok(false);
        };
        if selected.profile_id() != profile
            || selected.profile_digest().as_slice() != profile_digest
        {
            return Ok(false);
        }
        if input.requested_model() != Some(model) {
            return Ok(false);
        }
    } else if row.profile.is_some()
        || row.profile_digest.is_some()
        || row.model.is_some()
        || row.revision.is_some()
        || row.model_digest.is_some()
    {
        return Ok(false);
    }
    let attempt = AttemptId::from_bytes(
        row.attempt
            .as_slice()
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    );
    let expected_version = match row.release_reason.as_str() {
        "user_supersession" => row
            .prior_version
            .and_then(|version| version.checked_sub(1))
            .map(|version| version as u64)
            .ok_or(rusqlite::Error::InvalidQuery)?,
        "terminal_settlement" | "no_effect_release" => row
            .prior_version
            .and_then(|version| u64::try_from(version).ok())
            .ok_or(rusqlite::Error::InvalidQuery)?,
        _ => return Ok(false),
    };
    let command = SupersedeUnknownTaskRunInput {
        predecessor_taskrun_id: taskrun,
        expected_predecessor_version: expected_version,
        acknowledgment: UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1,
    };
    if row.command_fingerprint.as_slice()
        != CommandFingerprint::for_supersede_unknown_task_run(&command).as_bytes()
    {
        return Ok(false);
    }
    if !v57_command_outcome_matches(connection, row)? {
        return Ok(false);
    }
    if crate::store::taskrun_claim::active_attempt_at_verified_version(
        connection,
        taskrun,
        row.current_version.max(0) as u64,
    )
    .is_err()
    {
        return Ok(false);
    }
    if row.submit_version != 1 {
        return Ok(false);
    }
    let queued: Vec<u8> = connection.query_row(
        "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
        rusqlite::params![row.successor, 2_i64],
        |saved| saved.get(0),
    )?;
    if TaskRunEventCodec.decode(&queued).ok() != Some(TaskRunEvent::TaskRunQueued) {
        return Ok(false);
    }
    let successor_version: i64 = connection.query_row(
        "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
        [&row.successor],
        |saved| saved.get(0),
    )?;
    if successor_version < 2 {
        return Ok(false);
    }
    let successor_id = TaskRunId::from_bytes(
        row.successor
            .as_slice()
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    );
    if crate::store::taskrun_claim::active_attempt_at_verified_version(
        connection,
        successor_id,
        successor_version as u64,
    )
    .is_err()
    {
        return Ok(false);
    }
    let (Some(event_id), Some(version)) = (&row.prior_id, row.prior_version) else {
        return Ok(false);
    };
    if row.current_version != version || row.tail_id.as_deref() != Some(event_id.as_slice()) {
        return Ok(false);
    }
    let payload: Vec<u8> = connection.query_row(
        "SELECT payload FROM events WHERE event_id=?1 AND aggregate_type=1
           AND aggregate_id=?2 AND sequence=?3",
        rusqlite::params![event_id, row.predecessor, version],
        |saved| saved.get(0),
    )?;
    match (
        row.release_reason.as_str(),
        TaskRunEventCodec.decode(&payload),
    ) {
        (
            "user_supersession",
            Ok(TaskRunEvent::UserSupersedeUnknown {
                predecessor_attempt_id,
                successor_taskrun_id,
                acknowledgement_digest,
            }),
        ) if predecessor_attempt_id == attempt
            && row.successor.as_slice() == successor_taskrun_id.as_bytes()
            && acknowledgement_digest == ack => {}
        (
            "terminal_settlement",
            Ok(
                TaskRunEvent::TaskRunCompleted { .. }
                | TaskRunEvent::TaskRunFailed { .. }
                | TaskRunEvent::BudgetExhausted
                | TaskRunEvent::PolicyDenied
                | TaskRunEvent::Unrecoverable
                | TaskRunEvent::CancellationCompleted,
            ),
        ) => {}
        (
            "no_effect_release",
            Ok(
                TaskRunEvent::TaskRunFailed { .. }
                | TaskRunEvent::PolicyDenied
                | TaskRunEvent::CancellationCompleted,
            ),
        ) => {}
        _ => return Ok(false),
    }
    if crate::store::taskrun_claim::active_attempt_at_verified_version(
        connection,
        taskrun,
        u64::try_from(version - 1).map_err(|_| rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?
    .is_none_or(|active| active != attempt)
    {
        return Ok(false);
    }
    if require_pre_artifact_unknown_proof && !v57_unknown_terminal_proof(connection, row)? {
        return Ok(false);
    }
    if !v57_marker_matches(connection, row, &taskrun, &attempt, &ack)? {
        return Ok(false);
    }
    v57_release_event_matches(connection, row)
}
