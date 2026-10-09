type LegacyBindingRow = (
    String,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Vec<u8>,
);
type LegacyApprovalRow = (String, Option<String>, String, i64, Option<i64>);
type LegacyTerminalProofRow = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);

struct LegacyBindingFacts {
    state: String,
    origin: crate::store::taskrun_submit_origin::VerifiedTaskRunSubmitOrigin,
}

fn v68_historical_routes(connection: &Connection) -> SqliteResult<Vec<(Vec<u8>, i64, i64)>> {
    let mut statement = connection.prepare(
        "SELECT taskrun_id,state,attempt_id,node_id,node_epoch,fence,executable_digest,
                workspace_version,admitted_root_version,admitted_root_identity,trust_epoch,
                trust_revision,source_policy_version,command_policy_version,approval_id,
                managed_area_identity,stdout,stderr,exit_code,conversation_id,workspace_id,command_digest
         FROM taskrun_local_command_attempts ORDER BY taskrun_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<Vec<u8>>>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<Vec<u8>>>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Option<i64>>(8)?,
            row.get::<_, Option<Vec<u8>>>(9)?,
            row.get::<_, Option<i64>>(10)?,
            row.get::<_, Option<i64>>(11)?,
            row.get::<_, Option<i64>>(12)?,
            row.get::<_, Option<i64>>(13)?,
            row.get::<_, Option<Vec<u8>>>(14)?,
            row.get::<_, Option<Vec<u8>>>(15)?,
            row.get::<_, Vec<u8>>(16)?,
            row.get::<_, Vec<u8>>(17)?,
            row.get::<_, Option<i64>>(18)?,
            row.get::<_, Vec<u8>>(19)?,
            row.get::<_, Vec<u8>>(20)?,
            row.get::<_, Vec<u8>>(21)?,
        ))
    })?;
    let mut routes = Vec::new();
    for row in rows {
        let row = row?;
        let (id, state) = (&row.0, row.1.as_str());
        let clean_preflight = state == "preflight"
            && row.2.is_none()
            && row.3.is_none()
            && row.4.is_none()
            && row.5.is_none()
            && row.6.is_none()
            && row.7.is_none()
            && row.8.is_none()
            && row.9.is_none()
            && row.10.is_none()
            && row.11.is_none()
            && row.12.is_none()
            && row.13.is_none()
            && row.14.is_none()
            && row.15.is_none()
            && row.16.is_empty()
            && row.17.is_empty()
            && row.18.is_none()
            && v68_submitted_origin_matches(connection, id, &row.19, &row.20, &row.21)?
            && v68_has_only_submission_event(connection, id)?;
        if clean_preflight {
            routes.push((row.0, 2, 3));
        } else if v68_legacy_terminal_matches(connection, id, state)? {
            routes.push((row.0, 1, 2));
        } else if v68_legacy_binding_matches(connection, id)? {
            routes.push((row.0, 1, 1));
        } else {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    Ok(routes)
}

fn v68_legacy_binding_matches(connection: &Connection, taskrun_id: &[u8]) -> SqliteResult<bool> {
    let Some(facts) = v68_legacy_binding_facts(connection, taskrun_id)? else {
        return Ok(false);
    };
    Ok(matches!(
        facts.state.as_str(),
        "approval_pending"
            | "approved"
            | "launch_intent"
            | "release_reserved"
            | "running"
            | "cancel_requested"
            | "stop_unconfirmed"
            | "outcome_unknown"
            | "completed"
            | "cancelled"
    ))
}

fn v68_legacy_binding_facts(
    connection: &Connection,
    taskrun_id: &[u8],
) -> SqliteResult<Option<LegacyBindingFacts>> {
    let row: Option<LegacyBindingRow> = connection
        .query_row(
            "SELECT state,conversation_id,workspace_id,executable_digest,workspace_version,
                admitted_root_version,admitted_root_identity,trust_epoch,trust_revision,
                source_policy_version,command_policy_version,approval_id,command_digest
         FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                ))
            },
        )
        .optional()?;
    let Some((
        state,
        conversation,
        workspace,
        executable,
        workspace_version,
        root_version,
        root_identity,
        epoch,
        revision,
        source_policy,
        command_policy,
        approval,
        command_digest,
    )) = row
    else {
        return Ok(None);
    };
    let (
        Some(executable),
        Some(workspace_version),
        Some(root_version),
        Some(root_identity),
        Some(epoch),
        Some(revision),
        Some(2),
        Some(1),
        Some(approval),
    ) = (
        executable,
        workspace_version,
        root_version,
        root_identity,
        epoch,
        revision,
        source_policy,
        command_policy,
        approval,
    )
    else {
        return Ok(None);
    };
    if executable.len() != 32
        || workspace_version <= 0
        || root_version <= 0
        || root_identity.len() != 32
        || epoch <= 0
        || revision <= 0
        || uuid::Uuid::from_slice(&approval).map_or(true, |value| value.is_nil())
    {
        return Ok(None);
    }
    let Ok(id) = <[u8; 16]>::try_from(taskrun_id) else {
        return Ok(None);
    };
    let origin = crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
        connection,
        runne_domain::id::TaskRunId::from_bytes(id),
    );
    let Ok(Some(origin)) = origin else {
        return Ok(None);
    };
    if origin.conversation_id.as_bytes().as_slice() != conversation.as_slice()
        || origin.workspace_id.as_bytes().as_slice() != workspace.as_slice()
        || !origin
            .input
            .local_command()
            .is_some_and(|command| command.intent_digest().as_slice() == command_digest)
    {
        return Ok(None);
    }
    let taskrun = runne_domain::id::TaskRunId::from_bytes(id).to_string();
    let approval_id = uuid::Uuid::from_slice(&approval)
        .expect("validated UUID")
        .to_string();
    let approval_row: Option<LegacyApprovalRow> = connection.query_row(
        "SELECT task_run_id,attempt_id,principal_id,state,decision FROM approvals WHERE approval_id=?1 AND action='local_command.execute'",
        [approval_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).optional()?;
    let Some((approval_task, attempt, principal, approval_state, decision)) = approval_row else {
        return Ok(None);
    };
    let approval_state_matches = matches!(
        (approval_state, decision),
        (1, None) | (2, Some(1)) | (3, Some(2)) | (4, _) | (5, _)
    );
    if !approval_state_matches
        || approval_task != taskrun
        || attempt.is_some()
        || principal != origin.principal_id.0
    {
        return Ok(None);
    }
    Ok(Some(LegacyBindingFacts { state, origin }))
}

fn v68_legacy_terminal_matches(
    connection: &Connection,
    taskrun_id: &[u8],
    state: &str,
) -> SqliteResult<bool> {
    if matches!(state, "denied" | "no_effect_terminal") {
        if !local_no_effect_releases_match(connection)? {
            return Ok(false);
        }
        return connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE taskrun_id=?1)",
            [taskrun_id],
            |row| row.get(0),
        );
    }
    if !matches!(state, "completed" | "cancelled") {
        return Ok(false);
    }
    let proof: Option<LegacyTerminalProofRow> = connection.query_row(
        "SELECT a.attempt_id,a.node_id,a.node_epoch,a.fence,e.payload
         FROM taskrun_local_command_attempts a
         JOIN taskrun_terminal_settlement_receipts t ON t.taskrun_id=a.taskrun_id AND t.fence=a.fence
         JOIN events e ON e.event_id=t.terminal_event_id
         WHERE a.taskrun_id=?1 AND a.attempt_id=t.attempt_id AND a.node_id=t.node_id
           AND a.node_epoch=t.node_epoch",
        [taskrun_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional()?;
    let Some((attempt, node, node_epoch, fence, payload)) = proof else {
        return Ok(false);
    };
    let Ok(event) = TaskRunEventCodec.decode(&payload) else {
        return Ok(false);
    };
    local_terminal_proof_matches(
        connection, taskrun_id, &attempt, &node, node_epoch, fence, &event,
    )
}

include!("taskrun_permission_retained.rs");
