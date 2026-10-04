fn v57_successor_receipts_match(connection: &Connection) -> SqliteResult<bool> {
    v57_successor_receipts_match_for_dispatch(connection, None)
}

fn v57_successor_receipts_match_for_dispatch(
    connection: &Connection,
    dispatch: Option<&[u8]>,
) -> SqliteResult<bool> {
    // The COALESCE/NOT EXISTS forms are deliberate: SQLite's NULL truth table
    // must never turn a missing joined proof into an accepted migration.
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM taskrun_unknown_successor_receipts r
         LEFT JOIN events marker ON marker.event_id=r.generation_superseded_event_id
         LEFT JOIN events submit ON submit.event_id=r.successor_submit_event_id
         LEFT JOIN command_receipts command ON command.command_id=r.command_id
         LEFT JOIN taskrun_assignment_occupations occupation
           ON occupation.taskrun_id=r.predecessor_taskrun_id AND occupation.fence=r.occupation_fence
         LEFT JOIN taskrun_assignments assignment
           ON assignment.taskrun_id=r.predecessor_taskrun_id AND assignment.fence=r.occupation_fence
         WHERE (?1 IS NULL OR r.predecessor_dispatch_attempt_id=?1) AND (
           submit.event_id IS NULL OR command.command_id IS NULL
           OR command.fingerprint!=r.command_fingerprint
           OR submit.aggregate_type!=1 OR submit.aggregate_id!=r.successor_taskrun_id
           OR submit.sequence!=r.successor_submit_version
           OR occupation.taskrun_id IS NULL OR assignment.taskrun_id IS NULL
           OR assignment.attempt_id!=r.predecessor_attempt_id
           OR occupation.state!='released' OR occupation.attempt_id!=r.predecessor_attempt_id
           OR occupation.release_event_id!=r.occupation_release_event_id
           OR r.occupation_release_reason NOT IN ('user_supersession','no_effect_release','terminal_settlement')
           OR (r.occupation_release_reason='user_supersession' AND
               (r.predecessor_event_id IS NULL
                OR occupation.release_event_id!=r.predecessor_event_id
                OR r.occupation_release_version!=r.predecessor_event_version))
           OR (r.occupation_release_reason='terminal_settlement' AND NOT EXISTS(
               SELECT 1 FROM taskrun_terminal_settlement_receipts t
               WHERE t.taskrun_id=r.predecessor_taskrun_id AND t.fence=r.occupation_fence
                 AND t.attempt_id=r.predecessor_attempt_id
                 AND t.terminal_event_id=r.occupation_release_event_id
                 AND t.terminal_version=r.occupation_release_version))
           OR (r.occupation_release_reason='no_effect_release' AND NOT EXISTS(
               SELECT 1 FROM taskrun_no_effect_release_receipts n
               WHERE n.taskrun_id=r.predecessor_taskrun_id AND n.fence=r.occupation_fence
                 AND n.attempt_id=r.predecessor_attempt_id
                 AND n.failure_event_id=r.occupation_release_event_id
                 AND n.new_version=r.occupation_release_version))
           OR (r.generation_superseded_event_id IS NOT NULL AND
               (marker.event_id IS NULL OR marker.aggregate_type!=2
                OR marker.aggregate_id!=r.conversation_id OR marker.sequence!=r.generation_superseded_version))
           OR ((r.generation_superseded_event_id IS NULL) != (r.generation_superseded_version IS NULL))
           OR ((r.predecessor_event_id IS NULL) != (r.predecessor_event_version IS NULL))
           OR (r.predecessor_dispatch_attempt_id IS NOT NULL AND NOT EXISTS(
               SELECT 1 FROM provider_execution_admissions a
               JOIN taskrun_provider_bindings b ON b.attempt_id=r.predecessor_attempt_id
                 AND b.taskrun_id=r.predecessor_taskrun_id
               WHERE a.dispatch_attempt_id=r.predecessor_dispatch_attempt_id
                 AND a.taskrun_id=r.predecessor_taskrun_id
                 AND a.execution_attempt_id=r.predecessor_attempt_id
                 AND a.profile_digest=r.profile_digest
                 AND b.profile_digest=r.profile_digest
                 AND (NOT EXISTS(SELECT 1 FROM provider_remote_request_intents i
                       WHERE i.dispatch_attempt_id=r.predecessor_dispatch_attempt_id)
                      OR EXISTS(SELECT 1 FROM provider_remote_request_intents i
                       WHERE i.dispatch_attempt_id=r.predecessor_dispatch_attempt_id
                         AND i.taskrun_id=r.predecessor_taskrun_id
                         AND i.taskrun_attempt_id=r.predecessor_attempt_id
                         AND i.provider_id=r.provider_id AND i.profile_id=r.profile_id
                         AND i.profile_digest=r.profile_digest
                         AND i.pricing_revision_digest=a.pricing_revision_digest))))
           OR (r.predecessor_dispatch_attempt_id IS NULL AND
               (r.provider_id IS NOT NULL OR r.profile_id IS NOT NULL OR r.profile_digest IS NOT NULL
                OR r.model_id IS NOT NULL OR r.model_revision IS NOT NULL OR r.model_ref_digest IS NOT NULL)))",
        [dispatch],
        |row| row.get(0),
    )?;
    if invalid != 0 {
        return Ok(false);
    }
    v57_successor_events_match_filtered(connection, dispatch, dispatch.is_none())
}

pub(crate) fn v57_successor_witness_matches_for_v62_audit(
    connection: &Connection,
    dispatch: &[u8],
    predecessor: &[u8],
    attempt: &[u8],
) -> SqliteResult<bool> {
    let scoped_match = v57_successor_receipts_match_for_dispatch(connection, Some(dispatch))?;
    let user_supersession: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_unknown_successor_receipts r
         WHERE r.predecessor_dispatch_attempt_id=?1 AND r.predecessor_taskrun_id=?2
           AND r.predecessor_attempt_id=?3 AND r.occupation_release_reason='user_supersession')",
        rusqlite::params![dispatch, predecessor, attempt],
        |row| row.get(0),
    )?;
    if !scoped_match || !user_supersession {
        return Ok(false);
    }
    Ok(true)
}

fn v57_successor_events_match_filtered(
    connection: &Connection,
    dispatch: Option<&[u8]>,
    require_pre_artifact_unknown_proof: bool,
) -> SqliteResult<bool> {
    let mut statement = connection.prepare(
        "SELECT predecessor_taskrun_id,successor_taskrun_id,predecessor_attempt_id,
                predecessor_event_id,predecessor_event_version,generation_superseded_event_id,
                conversation_id,workspace_id,acknowledgement_digest,typed_input_digest,command_fingerprint,
                idempotency_key_digest,provider_id,profile_id,profile_digest,model_id,
                model_revision,model_ref_digest,successor_submit_event_id,successor_submit_version,
                occupation_release_reason,occupation_release_event_id,occupation_release_version,
                command.idempotency_key,command.fingerprint,command.idempotency_scope_bytes,
                r.principal_id,r.principal_digest,r.predecessor_input_digest,
                r.origin_kind,r.project_id,r.origin_operation,
                stream.current_version,stream.last_event_id,command.command_outcome,
                r.generation_superseded_version
         FROM taskrun_unknown_successor_receipts r
         JOIN command_receipts command ON command.command_id=r.command_id
         JOIN aggregate_streams stream ON stream.aggregate_type=1 AND stream.aggregate_id=r.predecessor_taskrun_id
         WHERE (?1 IS NULL OR r.predecessor_dispatch_attempt_id=?1)",
    )?;
    let rows = statement.query_map([dispatch], |row| {
        Ok(SuccessorRow {
            predecessor: row.get(0)?,
            successor: row.get(1)?,
            attempt: row.get(2)?,
            prior_id: row.get(3)?,
            prior_version: row.get(4)?,
            marker_id: row.get(5)?,
            conversation: row.get(6)?,
            workspace: row.get(7)?,
            ack: row.get(8)?,
            input_digest: row.get(9)?,
            command_fingerprint: row.get(10)?,
            key_digest: row.get(11)?,
            provider: row.get(12)?,
            profile: row.get(13)?,
            profile_digest: row.get(14)?,
            model: row.get(15)?,
            revision: row.get(16)?,
            model_digest: row.get(17)?,
            submit_id: row.get(18)?,
            submit_version: row.get(19)?,
            release_reason: row.get(20)?,
            release_id: row.get(21)?,
            release_version: row.get(22)?,
            idempotency_key: row.get(23)?,
            receipt_fingerprint: row.get(24)?,
            scope_bytes: row.get(25)?,
            principal_id: row.get(26)?,
            principal_digest: row.get(27)?,
            predecessor_input_digest: row.get(28)?,
            origin_kind: row.get(29)?,
            project_id: row.get(30)?,
            origin_operation: row.get(31)?,
            current_version: row.get(32)?,
            tail_id: row.get(33)?,
            command_outcome: row.get(34)?,
            marker_version: row.get(35)?,
        })
    })?;
    let mut matched_rows = 0;
    for row in rows {
        let row = row?;
        matched_rows += 1;
        let matches = if require_pre_artifact_unknown_proof {
            v57_row_events_match(connection, &row)?
        } else {
            v57_row_events_match_for_v62_audit(connection, &row)?
        };
        if !matches {
            return Ok(false);
        }
    }
    Ok(require_pre_artifact_unknown_proof || matched_rows == 1)
}

include!("v57_taskrun_unknown_successor_events.rs");
