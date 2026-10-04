fn local_no_effect_releases_match(connection: &Connection) -> SqliteResult<bool> {
    let mut statement = connection.prepare(
        "SELECT r.taskrun_id,e.payload FROM taskrun_no_effect_release_receipts r
         JOIN events e ON e.event_id=r.failure_event_id ORDER BY r.taskrun_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (taskrun_id, payload) = row?;
        if !submitted_local_command_origin(connection, &taskrun_id)? {
            continue;
        }
        let Ok(taskrun_bytes) = <[u8; 16]>::try_from(taskrun_id.as_slice()) else {
            return Ok(false);
        };
        let origin =
            match crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
                connection,
                runne_domain::id::TaskRunId::from_bytes(taskrun_bytes),
            ) {
                Ok(Some(origin)) => origin,
                Ok(None) => return Ok(false),
                Err(_) => return Ok(false),
            };
        let Some(command) = origin.input.local_command() else {
            continue;
        };
        let local: Option<LocalNoEffectRow> = connection
            .query_row(
                "SELECT conversation_id,workspace_id,command_digest,attempt_id,node_id,
                        node_epoch,fence,managed_area_identity,state,exit_code,approval_id,
                        executable_digest,workspace_version,admitted_root_version,
                        admitted_root_identity,trust_epoch,trust_revision,
                        source_policy_version,command_policy_version
                 FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
                [&taskrun_id],
                |row| {
                    Ok(LocalNoEffectRow {
                        conversation_id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        command_digest: row.get(2)?,
                        attempt_id: row.get(3)?,
                        node_id: row.get(4)?,
                        node_epoch: row.get(5)?,
                        fence: row.get(6)?,
                        area_identity: row.get(7)?,
                        state: row.get(8)?,
                        exit_code: row.get(9)?,
                        approval_id: row.get(10)?,
                        executable_digest: row.get(11)?,
                        workspace_version: row.get(12)?,
                        root_version: row.get(13)?,
                        root_identity: row.get(14)?,
                        trust_epoch: row.get(15)?,
                        trust_revision: row.get(16)?,
                        source_policy_version: row.get(17)?,
                        command_policy_version: row.get(18)?,
                    })
                },
            )
            .optional()?;
        let Some(local) = local else {
            return Ok(false);
        };
        if local.conversation_id != origin.conversation_id.as_bytes()
            || local.workspace_id != origin.workspace_id.as_bytes()
            || local.command_digest != command.intent_digest()
            || local.attempt_id.is_some()
            || local.node_id.is_some()
            || local.node_epoch.is_some()
            || local.fence.is_some()
            || local.area_identity.is_some()
            || local.exit_code.is_some()
            || !no_effect_terminal_event(&payload)
        {
            return Ok(false);
        }
        let approval_denied = local.state == "denied"
            && approval_matches(connection, &taskrun_id, &origin, &local, true)?;
        let no_effect = local.state == "no_effect_terminal"
            && prelaunch_binding_is_valid(&local)
            && approval_matches(connection, &taskrun_id, &origin, &local, false)?;
        if !approval_denied && !no_effect {
            return Ok(false);
        }
    }
    Ok(true)
}

fn submitted_local_command_origin(
    connection: &Connection,
    taskrun_id: &[u8],
) -> SqliteResult<bool> {
    let payload: Option<Vec<u8>> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [taskrun_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(false);
    };
    Ok(matches!(
        TaskRunEventCodec.decode(&payload),
        Ok(runne_domain::task_run::TaskRunEvent::TaskRunSubmitted { input, .. })
            if input.local_command().is_some()
    ))
}

struct LocalNoEffectRow {
    conversation_id: Vec<u8>,
    workspace_id: Vec<u8>,
    command_digest: Vec<u8>,
    attempt_id: Option<Vec<u8>>,
    node_id: Option<Vec<u8>>,
    node_epoch: Option<i64>,
    fence: Option<i64>,
    area_identity: Option<Vec<u8>>,
    state: String,
    exit_code: Option<i64>,
    approval_id: Option<Vec<u8>>,
    executable_digest: Option<Vec<u8>>,
    workspace_version: Option<i64>,
    root_version: Option<i64>,
    root_identity: Option<Vec<u8>>,
    trust_epoch: Option<i64>,
    trust_revision: Option<i64>,
    source_policy_version: Option<i64>,
    command_policy_version: Option<i64>,
}

fn effect_binding_is_absent(row: &LocalNoEffectRow) -> bool {
    row.executable_digest.is_none()
        && row.workspace_version.is_none()
        && row.root_version.is_none()
        && row.root_identity.is_none()
        && row.trust_epoch.is_none()
        && row.trust_revision.is_none()
        && row.source_policy_version.is_none()
        && row.command_policy_version.is_none()
}

fn prelaunch_binding_is_valid(row: &LocalNoEffectRow) -> bool {
    if effect_binding_is_absent(row) {
        return row.approval_id.is_none();
    }
    let (
        Some(executable),
        Some(workspace),
        Some(root_version),
        Some(root_identity),
        Some(epoch),
        Some(revision),
        Some(source_policy),
        Some(command_policy),
        Some(approval_id),
    ) = (
        row.executable_digest.as_deref(),
        row.workspace_version,
        row.root_version,
        row.root_identity.as_deref(),
        row.trust_epoch,
        row.trust_revision,
        row.source_policy_version,
        row.command_policy_version,
        row.approval_id.as_deref(),
    )
    else {
        return false;
    };
    executable.len() == 32
        && workspace > 0
        && root_version > 0
        && root_identity.len() == 32
        && epoch > 0
        && revision > 0
        && source_policy == 2
        && command_policy == 1
        && uuid::Uuid::from_slice(approval_id)
            .map(|value| !value.is_nil())
            .unwrap_or(false)
}

fn approval_matches(
    connection: &Connection,
    taskrun_id: &[u8],
    origin: &crate::store::taskrun_submit_origin::VerifiedTaskRunSubmitOrigin,
    local: &LocalNoEffectRow,
    denial_required: bool,
) -> SqliteResult<bool> {
    if !prelaunch_binding_is_valid(local) {
        return Ok(false);
    }
    let Some(approval_id) = &local.approval_id else {
        return Ok(!denial_required);
    };
    let taskrun = <[u8; 16]>::try_from(taskrun_id)
        .map(runne_domain::id::TaskRunId::from_bytes)
        .map(|value| value.to_string());
    let Ok(taskrun) = taskrun else {
        return Ok(false);
    };
    let Ok(approval_uuid) = uuid::Uuid::from_slice(approval_id) else {
        return Ok(false);
    };
    let approval: Option<ApprovalRow> = connection
        .query_row(
            "SELECT task_run_id,attempt_id,principal_id,state,decision FROM approvals
             WHERE approval_id=?1 AND action='local_command.execute'",
            [approval_uuid.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((approval_task, attempt, principal, state, decision)) = approval else {
        return Ok(false);
    };
    let state_matches = if denial_required {
        matches!((state, decision), (3, Some(2)) | (4, _) | (5, _))
    } else {
        matches!(
            (state, decision),
            (1, None) | (2, Some(1)) | (3, Some(2)) | (4, _) | (5, _)
        )
    };
    Ok(approval_task == taskrun
        && attempt.is_none()
        && principal == origin.principal_id.0
        && state_matches)
}

type ApprovalRow = (String, Option<String>, String, i64, Option<i64>);

fn no_effect_terminal_event(payload: &[u8]) -> bool {
    matches!(
        TaskRunEventCodec.decode(payload),
        Ok(runne_domain::task_run::TaskRunEvent::TaskRunFailed { ref reason })
            if reason == "dispatch_not_started"
    ) || matches!(
        TaskRunEventCodec.decode(payload),
        Ok(runne_domain::task_run::TaskRunEvent::TaskRunCancelled
            | runne_domain::task_run::TaskRunEvent::CancellationCompleted)
    )
}
