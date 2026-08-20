fn promotion_digest(bytes: &[u8], id: &[u8; 16]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gocode.replay.promotion-projection");
    digest.update([0, 1, bytes[5]]);
    digest.update(id);
    digest.update(bytes);
    digest.finalize().into()
}

fn uuid(value: &str) -> Result<[u8; 16], ()> {
    uuid::Uuid::parse_str(value)
        .map(uuid::Uuid::into_bytes)
        .map_err(|_| ())
}

fn hex32(value: &str) -> Result<[u8; 32], ()> {
    hex::decode(value)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

fn v2_taskrun_baseline() -> Result<Value, ()> {
    let id = uuid("018f2e3a-7000-7000-8000-000000000150")?;
    let projection = URL_SAFE_NO_PAD
        .decode("R1JQUAECAY8uOnAAcACAAAAAAAABUAAAACoBAY8uOnAAcACAAAAAAAABUAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .map_err(|_| ())?;
    let mut session = MockRuntime::session();
    session.capabilities = runne_runtime_client::PROTECTED_RUNTIME_CAPABILITIES
        .iter()
        .map(ToString::to_string)
        .collect();
    session.capability_digest = protected_capability_digest(&session.capabilities);
    let binding = runtime_binding(&session)?;
    let issued = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ())?
            .as_millis(),
    )
    .map_err(|_| ())?;
    let mut fields = runne_api::UnauthenticatedReplayRetentionBaselineFieldsV2 {
        schema_version: 2, authority_id: uuid(&session.authority_id)?, principal_id: session.principal_id,
        lineage_id: uuid(&session.event_log_lineage_id)?, runtime_session_binding_digest: binding.canonical_digest(),
        replay_scope_digest: runne_api::canonical_aggregate_replay_scope_digest(runne_api::ApiReplayAggregateKind::TaskRun, &id),
        aggregate_kind: runne_api::ApiReplayAggregateKind::TaskRun, aggregate_id: id,
        sequence: 1, version: 1, baseline_global_position: 1,
        head_event_id: uuid("018f2e3a-7000-7000-8002-000000000151")?, head_integrity_digest: [0x44; 32],
        promotion_codec: 1, promotion_projection_digest: promotion_digest(&projection, &id), promotion_projection_bytes: projection,
        retained_floor: 1, captured_high_water: 1, retention_generation: 1, retention_manifest_digest: [0x45; 32],
        issued_at_unix_ms: issued, expires_at_unix_ms: issued + 20_000, witness_mac: [0; 32],
    };
    let unsigned = runne_api::ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields.clone());
    fields.witness_mac = baseline_mac(&binding, &unsigned)?;
    Ok(baseline_json(&fields))
}

fn resume_taskrun_from_baseline(baseline: &Value) -> Response<Body> {
    let aggregate = baseline["aggregateId"].as_str().expect("taskrun aggregate");
    let aggregate_uuid = uuid::Uuid::from_bytes(
        hex::decode(aggregate)
            .expect("taskrun aggregate bytes")
            .try_into()
            .expect("taskrun aggregate id"),
    )
    .to_string();
    let suffix = json!({
        "eventId":"018f2e3a-7000-7000-8002-000000000153", "aggregateType":"taskRun", "aggregateId":aggregate_uuid,
        "sequence":2, "timestampUnixMicros":2_i64, "sensitivity":"public", "schemaVersion":1,
        "eventType":"taskRun.queued", "causationEventId":null, "integrityDigest":"46".repeat(32),
        "correlationId":aggregate_uuid, "correlationType":"taskRun", "payload":{"type":"taskRun.queued"},
        "replayBindingId":"018f2e3a700070008000000000000121", "cursor": taskrun_cursor(aggregate, "018f2e3a-7000-7000-8002-000000000153", 2),
    });
    let accepted = json!({
        "codec":1,"projectionBytes":baseline["promotionProjectionBytes"],"projectionDigest":baseline["promotionProjectionDigest"],
        "sequence":2,"version":2,"globalPosition":2,"headEventId":"018f2e3a700070008002000000000153",
        "headIntegrityDigest":"46".repeat(32),"capturedHighWater":2,
    });
    Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE,"application/json").header(header::CACHE_CONTROL,"no-store").header("x-request-id",RETENTION_REQUEST_ID).body(Body::from(serde_json::to_vec(&json!({
        "requestId":RETENTION_REQUEST_ID,"sessionId":SESSION_ID,"highWaterRef":"aa","baselineCheckpoint":taskrun_cursor(aggregate, baseline["headEventId"].as_str().expect("head"), 1),"acceptedPromotion":accepted,"events":[suffix],"hasMore":false
    })).expect("taskrun resume JSON"))).expect("taskrun resume response")
}

fn taskrun_cursor(aggregate: &str, event: &str, sequence: u64) -> String {
    let id = hex::decode(aggregate).expect("taskrun id");
    let value = json!({"scope":{"Aggregate":{"aggregate_id":id,"aggregate_type":1}},"event_id":event,"sequence":sequence,"global_position":sequence});
    format!("gocode-replay-cursor-v1.{}", hex::encode(serde_json::to_vec(&value).expect("taskrun cursor")))
}
