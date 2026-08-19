fn binding_id(
    authenticated: &AuthenticatedRuntimeSession,
    session: &ReplaySession,
) -> Result<ApiReplayBindingId, ReplayHttpFailure> {
    let stable = authenticated.binding.stable();
    let ephemeral = authenticated.binding.ephemeral();
    let session_generation =
        u64::try_from(session.session_generation).map_err(|_| replay_invariant_violation())?;
    let authorization_epoch =
        u64::try_from(session.authorization_epoch).map_err(|_| replay_invariant_violation())?;
    if stable.principal_id().as_str() != session.principal_id
        || ephemeral.launch_generation() != session_generation
        || ephemeral.authorization_epoch() != authorization_epoch
    {
        return Err(replay_authorization_revoked());
    }
    let mut digest = Sha256::new();
    digest.update(b"runne/api-replay-binding/v1\0");
    digest.update(stable.authority_id());
    digest.update(stable.principal_id().as_str().as_bytes());
    digest.update(stable.lineage_id().as_bytes());
    digest.update(stable.profile_id().as_bytes());
    digest.update(stable.schema_hash());
    digest.update(stable.capability_digest());
    digest.update(ephemeral.daemon_instance_id().into_bytes());
    digest.update(ephemeral.launch_generation().to_be_bytes());
    digest.update(ephemeral.session_id());
    digest.update(ephemeral.authorization_epoch().to_be_bytes());
    digest.update(authenticated.binding.certificate_sha256());
    digest.update(session.session_id);
    digest.update(session.retention_generation.to_be_bytes());
    digest.update(&session.high_water_ref);
    let bytes: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&bytes[..16]);
    ApiReplayBindingId::new(id).map_err(|_| replay_invariant_violation())
}

fn validate_api_binding(
    authenticated: &AuthenticatedRuntimeSession,
    session: &ReplaySession,
    event_type: &str,
    binding_id: ApiReplayBindingId,
) -> Result<(), ReplayHttpFailure> {
    let authorization_epoch =
        u64::try_from(session.authorization_epoch).map_err(|_| replay_invariant_violation())?;
    let public_retention_generation = u64::try_from(session.retention_generation)
        .ok()
        .and_then(|generation| generation.checked_add(1))
        .ok_or_else(replay_invariant_violation)?;
    let retention_digest: [u8; 32] = Sha256::digest(&session.high_water_ref).into();
    let retention_manifest =
        ApiRetentionManifest::new(public_retention_generation, retention_digest)
            .map_err(|_| replay_invariant_violation())?;
    let schema =
        ApiReplayEventSchema::new(event_type, 1).map_err(|_| replay_unsupported_schema())?;
    ApiReplayBindingV1::new(
        binding_id,
        authenticated.binding.clone(),
        authorization_epoch,
        authenticated.binding.ephemeral().sensitivity_ceiling(),
        [schema],
        session.session_id,
        retention_manifest,
    )
    .map_err(|_| replay_authorization_revoked())?;
    Ok(())
}

fn wire_event(
    authenticated: &AuthenticatedRuntimeSession,
    session: &ReplaySession,
    event: &ReplayEvent,
) -> Result<StoredReplayEventWire, ReplayHttpFailure> {
    let sensitivity = match event.sensitivity {
        0 => "public",
        1 => "internal",
        2 => "sensitive",
        _ => return Err(replay_invariant_violation()),
    };
    let aggregate_type = match event.aggregate_type {
        1 => "taskRun",
        2 => "conversation",
        _ => return Err(replay_invariant_violation()),
    };
    let correlation_type = match event.correlation_type {
        1 => "taskRun",
        2 => "conversation",
        _ => return Err(replay_invariant_violation()),
    };
    let payload = canonical_payload(event)?;
    let payload_value = serde_json::to_value(&payload).map_err(|_| replay_invariant_violation())?;
    let event_type = payload_value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(replay_unsupported_schema)?
        .to_owned();
    let binding_id = binding_id(authenticated, session)?;
    validate_api_binding(authenticated, session, &event_type, binding_id)?;
    Ok(StoredReplayEventWire {
        event_id: uuid_wire(&event.event_id)?,
        aggregate_type,
        aggregate_id: uuid_wire(&event.aggregate_id)?,
        sequence: event.sequence,
        timestamp_unix_micros: event.timestamp,
        sensitivity,
        schema_version: event.schema_version,
        event_type,
        causation_event_id: event.causation_id.as_ref().map(uuid_wire).transpose()?,
        integrity_digest: hex::encode(event.integrity_digest),
        correlation_id: uuid_wire(&event.correlation_id)?,
        correlation_type,
        payload,
        replay_binding_id: binding_id.to_wire_value(),
    })
}

fn wire_delivery(
    authenticated: &AuthenticatedRuntimeSession,
    session: &ReplaySession,
    event: &ReplayEvent,
    cursor: &ReplayCursor,
) -> Result<DeliveredReplayEventWire, ReplayHttpFailure> {
    Ok(DeliveredReplayEventWire {
        event: wire_event(authenticated, session, event)?,
        cursor: encode_cursor(cursor)?,
    })
}
