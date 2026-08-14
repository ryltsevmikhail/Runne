#[derive(Clone)]
struct InternalResumeFacts {
    principal_id: String,
    session_generation: i64,
    authority_id: [u8; 16],
    authorization_epoch: i64,
    aggregate_type: i32,
    aggregate_id: [u8; 16],
    sequence: u64,
    version: u64,
    baseline_global_position: i64,
    head_event_id: [u8; 16],
    head_integrity_digest: [u8; 32],
    promotion_projection_bytes: Vec<u8>,
    promotion_projection_digest: [u8; 32],
    retained_floor: i64,
    captured_high_water: i64,
    retention_generation: u64,
    retention_manifest_digest: [u8; 32],
}

impl From<gocode_application::ports::ReplayBaselineResumeRequestV2> for InternalResumeFacts {
    fn from(request: gocode_application::ports::ReplayBaselineResumeRequestV2) -> Self {
        Self {
            principal_id: request.principal_id().to_owned(),
            session_generation: request.session_generation(),
            authority_id: *request.authority_id(),
            authorization_epoch: request.authorization_epoch(),
            aggregate_type: request.aggregate_type(),
            aggregate_id: *request.aggregate_id(),
            sequence: request.sequence(),
            version: request.version(),
            baseline_global_position: request.baseline_global_position(),
            head_event_id: *request.head_event_id(),
            head_integrity_digest: *request.head_integrity_digest(),
            promotion_projection_bytes: request.promotion_projection_bytes().to_vec(),
            promotion_projection_digest: *request.promotion_projection_digest(),
            retained_floor: request.retained_floor(),
            captured_high_water: request.captured_high_water(),
            retention_generation: request.retention_generation(),
            retention_manifest_digest: *request.retention_manifest_digest(),
        }
    }
}

impl ReplayStore {
    async fn resume_session_from_baseline_v2_impl(
        &self,
        sealed_request: gocode_application::ports::ReplayBaselineResumeRequestV2,
        lineage_id: &EventLogLineageId,
        server_secret: &[u8; 32],
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<
        (
            ReplaySession,
            Vec<ReplayEvent>,
            ReplayEvent,
            gocode_application::ports::ReplayAcceptedPromotionV2,
        ),
        ReplayError,
    > {
        let request = InternalResumeFacts::from(sealed_request);
        let conn = Arc::clone(&self.conn);
        let lineage_id = *lineage_id;
        let server_secret = *server_secret;
        tokio::task::spawn_blocking(move || {
            let mut conn = conn
                .lock()
                .map_err(|error| ReplayError::Storage(format!("lock poisoned: {error}")))?;
            conn.with_connection_mut(|connection| {
                resume_session_from_internal_facts(
                    connection,
                    request,
                    &lineage_id,
                    &server_secret,
                    delivery_guard,
                )
            })
        })
        .await
        .map_err(|error| ReplayError::Storage(format!("V2 resume join: {error}")))?
    }
}

fn validate_v2_baseline(
    tx: &rusqlite::Transaction<'_>,
    inventory: &RetainedInventory,
    request: &InternalResumeFacts,
    lineage_id: &EventLogLineageId,
    server_secret: &[u8; 32],
    retained_floor: i64,
    high_water: i64,
) -> Result<
    (
        ReplayEvent,
        gocode_application::ports::ReplayAcceptedPromotionV2,
    ),
    ReplayError,
> {
    let next_global_position: i64 = tx
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| ReplayError::Storage(format!("read V2 replay global head: {error}")))?;
    if next_global_position
        != high_water.checked_add(1).ok_or_else(|| {
            ReplayError::Integrity("V2 replay global position overflow".to_owned())
        })?
    {
        return Err(ReplayError::Integrity(
            "V2 replay retained log is missing its committed tail".to_owned(),
        ));
    }
    if inventory.interior_gap.is_some()
        || retained_floor != request.retained_floor
        || retained_floor > request.baseline_global_position
        || high_water < request.captured_high_water
        || request.retention_generation != published_retention_generation(RETENTION_GENERATION)?
        || request.retention_manifest_digest
            != baseline_resume_manifest_digest(
                lineage_id,
                RETENTION_GENERATION,
                retained_floor,
                server_secret,
            )
    {
        return Err(ReplayError::Integrity(
            "V2 replay baseline retention binding changed".to_owned(),
        ));
    }
    let stream_version: i64 = tx.query_row(
        "SELECT current_version FROM aggregate_streams WHERE aggregate_type = ?1 AND aggregate_id = ?2",
        params![request.aggregate_type, request.aggregate_id.as_slice()], |row| row.get(0),
    ).optional().map_err(|error| ReplayError::Storage(format!("V2 resume stream: {error}")))?
        .ok_or_else(|| ReplayError::Integrity("V2 replay stream is unavailable".to_owned()))?;
    if stream_version
        < i64::try_from(request.version)
            .map_err(|_| ReplayError::Integrity("V2 replay version overflow".to_owned()))?
    {
        return Err(ReplayError::Integrity(
            "V2 replay stream predates baseline".to_owned(),
        ));
    }
    let baseline = tx.query_row(
        "SELECT event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version,
                causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile
         FROM events WHERE aggregate_type = ?1 AND aggregate_id = ?2 AND sequence = ?3",
        params![request.aggregate_type, request.aggregate_id.as_slice(), i64::try_from(request.sequence).map_err(|_| ReplayError::Integrity("V2 replay sequence overflow".to_owned()))?], read_replay_event,
    ).optional().map_err(|error| replay_row_error("read V2 baseline event", error))?
        .ok_or_else(|| ReplayError::Integrity("V2 replay baseline event was pruned".to_owned()))?;
    if baseline.global_position != request.baseline_global_position
        || baseline.event_id != request.head_event_id
        || baseline.integrity_digest != request.head_integrity_digest
    {
        return Err(ReplayError::Integrity(
            "V2 replay baseline event changed".to_owned(),
        ));
    }
    let snapshot = crate::store::snapshot::load_unauthenticated_replay_projection(
        tx,
        i64::from(request.aggregate_type),
        &request.aggregate_id,
    )
    .map_err(|_| ReplayError::Integrity("V2 replay snapshot is unavailable".to_owned()))?;
    if snapshot.aggregate_version < request.version {
        return Err(ReplayError::Integrity(
            "V2 replay snapshot predates baseline".to_owned(),
        ));
    }
    if snapshot.aggregate_version == request.version
        && (snapshot.event_sequence != request.sequence
            || snapshot.head_event_id.as_bytes() != &request.head_event_id
            || snapshot.head_integrity_digest.as_bytes() != &request.head_integrity_digest
            || snapshot.head_global_position != request.baseline_global_position)
    {
        return Err(ReplayError::Integrity(
            "V2 replay snapshot does not match baseline".to_owned(),
        ));
    }
    if snapshot.aggregate_version == request.version {
        let (bytes, digest): (Vec<u8>, Vec<u8>) = tx.query_row(
            "SELECT promotion_projection_bytes, promotion_projection_digest FROM aggregate_state_snapshots WHERE aggregate_type = ?1 AND aggregate_id = ?2",
            params![request.aggregate_type, request.aggregate_id.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|error| ReplayError::Storage(format!("read V2 replay promotion snapshot: {error}")))?;
        if bytes.as_slice() != request.promotion_projection_bytes.as_slice()
            || digest.as_slice() != request.promotion_projection_digest
        {
            return Err(ReplayError::Integrity(
                "V2 replay promotion snapshot does not match baseline".to_owned(),
            ));
        }
    }
    let (codec, bytes, digest): (i64, Vec<u8>, Vec<u8>) = tx.query_row(
        "SELECT promotion_codec_version, promotion_projection_bytes, promotion_projection_digest FROM aggregate_state_snapshots WHERE aggregate_type = ?1 AND aggregate_id = ?2",
        params![request.aggregate_type, request.aggregate_id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(|error| ReplayError::Storage(format!("read V2 accepted promotion: {error}")))?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| ReplayError::Integrity("invalid accepted V2 promotion digest".to_owned()))?;
    let accepted = gocode_application::ports::ReplayAcceptedPromotionV2::from_storage(
        gocode_application::ports::ReplayAcceptedPromotionV2Parts {
            codec: u8::try_from(codec).map_err(|_| {
                ReplayError::Integrity("invalid accepted V2 promotion codec".to_owned())
            })?,
            bytes,
            digest,
            sequence: snapshot.event_sequence,
            version: snapshot.aggregate_version,
            global_position: snapshot.head_global_position,
            head_event_id: *snapshot.head_event_id.as_bytes(),
            head_integrity_digest: *snapshot.head_integrity_digest.as_bytes(),
            captured_high_water: high_water,
        },
    )?;
    Ok((baseline, accepted))
}

fn read_v2_resume_events(
    tx: &rusqlite::Transaction<'_>,
    request: &InternalResumeFacts,
    high_water: i64,
) -> Result<Vec<ReplayEvent>, ReplayError> {
    let events = tx.prepare(
        "SELECT event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version,
                causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile
         FROM events WHERE aggregate_type = ?1 AND aggregate_id = ?2 AND global_position > ?3 AND global_position <= ?4
         ORDER BY global_position",
    ).map_err(|error| ReplayError::Storage(format!("prepare V2 replay events: {error}")))?
        .query_map(params![request.aggregate_type, request.aggregate_id.as_slice(), request.baseline_global_position, high_water], read_replay_event)
        .map_err(|error| ReplayError::Storage(format!("query V2 replay events: {error}")))?
        .collect::<Result<Vec<_>, _>>().map_err(|error| replay_row_error("read V2 replay events", error))?;
    validate_contiguous_sequence(
        &events,
        request
            .sequence
            .checked_add(1)
            .ok_or_else(|| ReplayError::Integrity("V2 replay sequence overflow".to_owned()))?,
    )?;
    Ok(events)
}

fn insert_v2_resume_session(
    tx: &rusqlite::Transaction<'_>,
    session: &ReplaySession,
) -> Result<(), ReplayError> {
    let inserted = tx.execute(
        "INSERT INTO _replay_subscriptions (session_id, principal_id, session_generation, authority_id, authorization_epoch,
         aggregate_type, aggregate_id, retained_floor, retention_generation, high_water_position, next_page_position,
         last_delivered_position, last_acked_position, state, high_water_ref, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'catching_up', ?14, datetime('now'))",
        params![session.session_id.as_slice(), session.principal_id, session.session_generation, session.authority_id.as_slice(),
            session.authorization_epoch, session.aggregate_type, session.aggregate_id.as_slice(), session.retained_floor,
            session.retention_generation, session.high_water_position, session.next_page_position,
            session.last_delivered_position, session.last_acked_position, session.high_water_ref],
    ).map_err(|error| ReplayError::Storage(format!("insert V2 replay session: {error}")))?;
    if inserted != 1 {
        return Err(ReplayError::Integrity(
            "V2 replay session insert was not exact".to_owned(),
        ));
    }
    Ok(())
}

fn read_v2_resume_session(
    tx: &rusqlite::Transaction<'_>,
    session_id: &[u8; 16],
) -> Result<ReplaySession, ReplayError> {
    tx.query_row(
        "SELECT session_id, principal_id, session_generation, authority_id, authorization_epoch,
                aggregate_type, aggregate_id, retained_floor, retention_generation, high_water_position,
                next_page_position, last_delivered_position, last_acked_position, state, high_water_ref,
                catch_up_completion, live_delivery_id, created_at FROM _replay_subscriptions WHERE session_id = ?1",
        [session_id.as_slice()], read_replay_session,
    ).map_err(|error| ReplayError::Storage(format!("read V2 replay session: {error}")))
}
