fn validate_contiguous_sequence(
    events: &[ReplayEvent],
    expected_first: u64,
) -> Result<(), ReplayError> {
    let mut expected = expected_first;
    for event in events {
        let sequence = u64::try_from(event.sequence)
            .map_err(|_| ReplayError::Integrity("invalid replay aggregate sequence".to_owned()))?;
        if sequence != expected {
            return Err(ReplayError::Integrity(
                "replay aggregate sequence gap".to_owned(),
            ));
        }
        expected = expected.checked_add(1).ok_or_else(|| {
            ReplayError::Integrity("replay aggregate sequence overflow".to_owned())
        })?;
    }
    Ok(())
}

/// Создаёт server-issued proof completion, связанный с immutable session data.
fn build_catch_up_completion_proof(session: &ReplaySession, server_secret: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(16 + session.high_water_ref.len() + 1 + 8);
    message.extend_from_slice(&session.session_id);
    message.extend_from_slice(&session.high_water_ref);
    match session.last_acked_position {
        Some(position) => {
            message.push(1);
            message.extend_from_slice(&position.to_be_bytes());
        }
        None => message.push(0),
    }
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("fixed HMAC key size");
    mac.update(&message);
    mac.finalize().into_bytes().to_vec()
}

impl ReplayStore {
/// NM-06: resolves one open session's delivery scope so the daemon
/// authorization can re-check the project trust revision per delivery.
pub(crate) fn session_delivery_scope_impl(
    &self,
    session_id: &[u8; 16],
) -> Result<Option<(i32, [u8; 16])>, ReplayError> {
    let conn = self
        .conn
        .lock()
        .map_err(|_| ReplayError::Storage("replay store lock poisoned".to_owned()))?;
    let row = conn
        .query_row(
            "SELECT aggregate_type, aggregate_id
             FROM _replay_subscriptions
             WHERE session_id = ?1",
            params![session_id.as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(|error| ReplayError::Storage(error.to_string()))?;
    let (aggregate_type, aggregate_id) = match row {
        Some(row) => row,
        // Unknown session: callers fall through to store handling.
        None => return Ok(None),
    };
    let aggregate_type = i32::try_from(aggregate_type)
        .map_err(|_| ReplayError::Storage("aggregate type out of range".to_owned()))?;
    let aggregate_id: [u8; 16] = aggregate_id
        .try_into()
        .map_err(|_| ReplayError::Storage("aggregate id width".to_owned()))?;
    Ok(Some((aggregate_type, aggregate_id)))
}
}

/// Read a [`ReplaySession`] from a rusqlite row.
fn read_replay_session(row: &rusqlite::Row) -> rusqlite::Result<ReplaySession> {
    let session_id_blob: Vec<u8> = row.get(0)?;
    let principal_id: String = row.get(1)?;
    let session_generation: i64 = row.get(2)?;
    let authority_id_blob: Vec<u8> = row.get(3)?;
    let authorization_epoch: i64 = row.get(4)?;
    let aggregate_type: i32 = row.get(5)?;
    let aggregate_id_blob: Vec<u8> = row.get(6)?;
    let retained_floor: Option<i64> = row.get(7)?;
    let retention_generation: i64 = row.get(8)?;
    let high_water_position: i64 = row.get(9)?;
    let next_page_position: Option<i64> = row.get(10)?;
    let last_delivered_position: Option<i64> = row.get(11)?;
    let last_acked_position: Option<i64> = row.get(12)?;
    let state_str: String = row.get(13)?;
    let high_water_ref: Vec<u8> = row.get(14)?;
    let catch_up_completion: Option<Vec<u8>> = row.get(15)?;
    let live_delivery_id: Option<Vec<u8>> = row.get(16)?;
    let created_at: String = row.get(17)?;

    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&session_id_blob);
    let mut authority_id = [0u8; 16];
    authority_id.copy_from_slice(&authority_id_blob);
    let mut aggregate_id = [0u8; 16];
    aggregate_id.copy_from_slice(&aggregate_id_blob);

    let state = ReplayState::from_db(&state_str).ok_or_else(|| rusqlite::Error::InvalidQuery)?;

    Ok(ReplaySession {
        session_id,
        principal_id,
        session_generation,
        authority_id,
        authorization_epoch,
        aggregate_type,
        aggregate_id,
        retained_floor,
        retention_generation,
        high_water_position,
        next_page_position,
        last_delivered_position,
        last_acked_position,
        state: state.clone(),
        high_water_ref,
        catch_up_completion,
        live_delivery_id,
        created_at,
    })
}

/// Validate authorization binding: principal_id, generation, authority_id, epoch.
fn validate_auth(
    session: &ReplaySession,
    principal_id: &str,
    generation: i64,
    authority_id: &[u8; 16],
    epoch: i64,
) -> Result<(), ReplayError> {
    if session.principal_id != principal_id {
        return Err(ReplayError::Unauthorized("principal mismatch".to_string()));
    }
    if session.session_generation != generation {
        return Err(ReplayError::StaleGeneration);
    }
    if session.authority_id != *authority_id {
        return Err(ReplayError::Unauthorized("authority mismatch".to_string()));
    }
    if session.authorization_epoch != epoch {
        return Err(ReplayError::AuthorizationRevoked);
    }
    Ok(())
}

fn validate_cursor_event(
    conn: &Connection,
    cursor: &ReplayCursor,
    expected_aggregate_type: i32,
    expected_aggregate_id: &[u8; 16],
) -> Result<(), ReplayError> {
    let event = conn
        .query_row(
            "SELECT event_id, aggregate_type, aggregate_id, sequence,
                    global_position, timestamp, sensitivity, schema_version,
                    causation_id, command_id, idempotency_key, actor,
                    payload, integrity_digest, correlation_id,
                    correlation_type, integrity_profile
             FROM events
             WHERE global_position = ?1
               AND aggregate_type = ?2
               AND aggregate_id = ?3",
            params![
                cursor.global_position,
                expected_aggregate_type,
                expected_aggregate_id.as_slice()
            ],
            read_replay_event,
        )
        .optional()
        .map_err(|error| replay_row_error("read cursor event", error))?;
    let Some(event) = event else {
        return Err(ReplayError::CursorInvalid {
            reason: "cursor does not identify a committed event".to_string(),
        });
    };
    let cursor_aggregate_id = match &cursor.aggregate_id {
        runne_domain::id::AggregateId::TaskRun(id) => id.as_bytes(),
        runne_domain::id::AggregateId::Conversation(id) => id.as_bytes(),
        runne_domain::id::AggregateId::Workspace(id) => id.as_bytes(),
    };
    let cursor_sensitivity = match cursor.sensitivity {
        runne_domain::event::Sensitivity::Public => 0,
        runne_domain::event::Sensitivity::Internal => 1,
        runne_domain::event::Sensitivity::Sensitive => 2,
    };
    let scope_matches = matches!(
        &cursor.scope,
        runne_domain::replay::ReplayScope::Aggregate {
            aggregate_type: cursor_type,
            aggregate_id: cursor_id,
        } if i32::from(*cursor_type) == expected_aggregate_type
            && cursor_id == expected_aggregate_id
    );
    if event.event_id.as_slice() != cursor.event_id.as_bytes()
        || event.aggregate_type != expected_aggregate_type
        || event.aggregate_id.as_slice() != cursor_aggregate_id
        || u64::try_from(event.sequence).ok() != Some(cursor.sequence)
        || event.sensitivity != cursor_sensitivity
        || event.event_type != cursor.event_type
        || !scope_matches
    {
        return Err(ReplayError::CursorInvalid {
            reason: "cursor does not identify a committed event".to_string(),
        });
    }
    Ok(())
}

fn read_last_acked_event(
    conn: &Connection,
    session: &ReplaySession,
) -> Result<Option<ReplayEvent>, ReplayError> {
    let Some(position) = session.last_acked_position else {
        return Ok(None);
    };
    conn.query_row(
        "SELECT event_id, aggregate_type, aggregate_id, sequence,
                global_position, timestamp, sensitivity, schema_version,
                causation_id, command_id, idempotency_key, actor,
                payload, integrity_digest, correlation_id,
                correlation_type, integrity_profile
         FROM events
         WHERE global_position = ?1
           AND aggregate_type = ?2
           AND aggregate_id = ?3",
        params![
            position,
            session.aggregate_type,
            session.aggregate_id.as_slice()
        ],
        read_replay_event,
    )
    .optional()
    .map_err(|error| replay_row_error("read acknowledged replay event", error))?
    .ok_or_else(|| ReplayError::Integrity("acknowledged replay event is unavailable".to_owned()))
    .map(Some)
}

fn read_session_event_at(
    conn: &Connection,
    session: &ReplaySession,
    position: i64,
    context: &'static str,
) -> Result<Option<ReplayEvent>, ReplayError> {
    conn.query_row(
        "SELECT event_id, aggregate_type, aggregate_id, sequence,
                global_position, timestamp, sensitivity, schema_version,
                causation_id, command_id, idempotency_key, actor,
                payload, integrity_digest, correlation_id,
                correlation_type, integrity_profile
         FROM events
         WHERE global_position = ?1
           AND aggregate_type = ?2
           AND aggregate_id = ?3",
        params![
            position,
            session.aggregate_type,
            session.aggregate_id.as_slice()
        ],
        read_replay_event,
    )
    .optional()
    .map_err(|error| replay_row_error(context, error))
}

fn next_sequence_after(event: &ReplayEvent) -> Result<u64, ReplayError> {
    u64::try_from(event.sequence)
        .map_err(|_| ReplayError::Integrity("invalid replay aggregate sequence".to_owned()))?
        .checked_add(1)
        .ok_or_else(|| ReplayError::Integrity("replay aggregate sequence overflow".to_owned()))
}

// ── ReplayStore ──────────────────────────────────────────────────────────────

/// SQLite-backed [`ReplayStorePort`] implementation.
///
/// Uses an in-memory or file-backed SQLite connection behind a mutex.
/// All database operations are dispatched through [`tokio::task::spawn_blocking`].
#[derive(Clone)]
pub struct ReplayStore {
    conn: Arc<Mutex<ManagedConnection>>,
}
