fn successor_key_digest(key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(b"runne-unknown-successor-idempotency\x01")
        .chain_update((key.len() as u64).to_be_bytes())
        .chain_update(key)
        .finalize()
        .into()
}

fn v57_marker_matches(
    connection: &Connection,
    row: &SuccessorRow,
    predecessor: &runne_domain::id::TaskRunId,
    attempt: &runne_domain::id::AttemptId,
    ack: &runne_domain::id::IntegrityDigest,
) -> SqliteResult<bool> {
    use crate::codec::{ConversationEventCodec, StoreCodec};
    use runne_domain::conversation::ConversationEvent;
    let Some(marker_id) = row.marker_id.as_ref() else {
        let (Some(prior_id), Some(prior_version)) = (row.prior_id.as_ref(), row.prior_version)
        else {
            return Ok(false);
        };
        let position: Option<i64> = connection
            .query_row(
                "SELECT global_position FROM events WHERE event_id=?1 AND aggregate_type=1
                 AND aggregate_id=?2 AND sequence=?3",
                rusqlite::params![prior_id, predecessor.as_bytes(), prior_version],
                |r| r.get(0),
            )
            .optional()?;
        let Some(position) = position else {
            return Ok(false);
        };
        let conversation_id = match <[u8; 16]>::try_from(row.conversation.as_slice()) {
            Ok(bytes) => runne_domain::id::ConversationId::from_bytes(bytes),
            Err(_) => return Ok(false),
        };
        return crate::store::has_no_active_generation_before_global_position(
            connection,
            conversation_id,
            position,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery);
    };
    let payload: Vec<u8> = connection.query_row(
        "SELECT payload FROM events WHERE event_id=?1 AND aggregate_type=2 AND aggregate_id=?2",
        rusqlite::params![marker_id, row.conversation],
        |r| r.get(0),
    )?;
    let Ok(ConversationEvent::GenerationSupersededUnknown {
        taskrun_id,
        attempt_id,
        successor_taskrun_id,
        acknowledgement_digest,
    }) = ConversationEventCodec.decode(&payload)
    else {
        return Ok(false);
    };
    Ok(taskrun_id == *predecessor
        && attempt_id == *attempt
        && row.successor.as_slice() == successor_taskrun_id.as_bytes()
        && acknowledgement_digest == *ack)
}

fn v57_unknown_terminal_proof(connection: &Connection, row: &SuccessorRow) -> SqliteResult<bool> {
    if let Some(dispatch) = connection.query_row(
        "SELECT predecessor_dispatch_attempt_id FROM taskrun_unknown_successor_receipts
         WHERE predecessor_taskrun_id=?1",
        [&row.predecessor],
        |r| r.get::<_, Option<Vec<u8>>>(0),
    )? {
        let valid_prior_proof = connection.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM provider_dispatch_attempts d
               JOIN provider_execution_admissions a ON a.dispatch_attempt_id=d.attempt_id
               JOIN provider_remote_request_intents i ON i.dispatch_attempt_id=d.attempt_id
               WHERE d.attempt_id=?1 AND d.state=6
                 AND a.taskrun_id=?2 AND a.execution_attempt_id=?3
                 AND i.taskrun_id=?2 AND i.taskrun_attempt_id=?3
                 AND i.dispatch_attempt_id=d.attempt_id
                 AND NOT EXISTS(SELECT 1 FROM provider_terminal_dispositions t
                                WHERE t.dispatch_attempt_id=d.attempt_id)
                 AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t
                                WHERE t.dispatch_attempt_id=d.attempt_id))
             OR EXISTS(SELECT 1 FROM provider_terminal_dispositions t
               WHERE t.dispatch_attempt_id=?1 AND t.disposition IN (4,6)
                 AND EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts a
                            WHERE a.dispatch_attempt_id=t.dispatch_attempt_id)
                 AND (t.disposition!=6 OR NOT EXISTS(SELECT 1 FROM provider_terminal_outbox o
                            WHERE o.dispatch_attempt_id=t.dispatch_attempt_id)))
             OR EXISTS(SELECT 1
               FROM provider_remote_terminal_artifacts t
               JOIN provider_remote_request_intents i USING(dispatch_attempt_id)
               JOIN provider_remote_response_bindings r USING(dispatch_attempt_id)
               JOIN provider_execution_admissions a USING(dispatch_attempt_id)
               WHERE t.dispatch_attempt_id=?1 AND t.taskrun_id=?2
                 AND t.taskrun_attempt_id=?3 AND i.taskrun_id=?2
                 AND i.taskrun_attempt_id=?3 AND r.taskrun_id=?2
                 AND r.taskrun_attempt_id=?3 AND a.taskrun_id=?2
                 AND a.execution_attempt_id=?3 AND t.request_digest=i.request_digest
                 AND t.request_digest=r.request_digest
                 AND t.response_id_digest=r.plaintext_digest
                 AND t.profile_digest=i.profile_digest
                 AND t.pricing_revision_digest=i.pricing_revision_digest
                 AND t.runtime_authority_id=i.runtime_authority_id
                 AND t.database_generation=i.database_generation
                 AND t.runtime_generation=i.runtime_generation
                 AND t.fencing_token=i.fencing_token)",
            rusqlite::params![&dispatch, &row.predecessor, &row.attempt],
            |r| r.get::<_, bool>(0),
        )?;
        if valid_prior_proof {
            return Ok(true);
        }
        let current_version: i64 = connection.query_row(
            "SELECT COALESCE(MAX(version),0) FROM schema_version",
            [],
            |r| r.get(0),
        )?;
        if current_version >= 62 {
            return v62_valid_supersession_audit_for_attempt(
                connection,
                &dispatch,
                &row.predecessor,
                &row.attempt,
            );
        }
        return Ok(false);
    }
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_local_command_stop_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND stop_kind='outcome_unknown')
           OR EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2)",
        rusqlite::params![row.predecessor, row.attempt],
        |r| r.get::<_, bool>(0),
    )
}
