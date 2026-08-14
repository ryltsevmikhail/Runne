use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const RETENTION_REQUEST_ID: &str = "018f2e3a-7000-7000-8000-000000000190";

impl MockRuntime {
    fn session() -> RuntimeSessionInfo {
        RuntimeSessionInfo {
            profile_id: "gocode-ui-client/2".to_owned(),
            schema_hash: GOLDEN_BUNDLE_HASH.to_owned(),
            runtime_version: "test".to_owned(),
            capabilities: REQUIRED_RUNTIME_CAPABILITIES
                .iter()
                .map(ToString::to_string)
                .collect(),
            authority_id: AUTHORITY_ID.to_owned(),
            principal_id: "local-owner".to_owned(),
            event_log_lineage_id: LINEAGE_ID.to_owned(),
            daemon_instance_id: INSTANCE_ID.to_owned(),
            launch_generation: 1,
            session_id: SESSION_ID.to_owned(),
            authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".to_owned(),
            certificate_sha256: "11".repeat(32),
            capability_digest: "22".repeat(32),
        }
    }
}

async fn wait_for(counter: &AtomicUsize, notify: &Notify, expected: usize) {
    loop {
        let notified = notify.notified();
        if counter.load(Ordering::SeqCst) >= expected {
            return;
        }
        notified.await;
    }
}

fn retention_v2_response(state: &MockState, aggregate_type: Option<&str>) -> Response<Body> {
    let value = match aggregate_type {
        Some("taskRun") => v2_taskrun_baseline().expect("V2 TaskRun baseline"),
        _ => v2_baseline(state).expect("V2 Conversation baseline"),
    };
    Response::builder()
        .status(StatusCode::GONE)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-request-id", RETENTION_REQUEST_ID)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "code": "replay_retention_gap",
                "requestId": RETENTION_REQUEST_ID,
                "baseline": value,
            }))
            .expect("retention JSON"),
        ))
        .expect("retention response")
}

async fn resume_from_baseline(
    State(state): State<Arc<MockState>>,
    axum::Json(request): axum::Json<Value>,
) -> Response<Body> {
    state.resume_count.fetch_add(1, Ordering::SeqCst);
    state.resume_changed.notify_waiters();
    if state.block_v2_resume.load(Ordering::SeqCst) {
        state.release_v2_resume.notified().await;
    }
    if request["baseline"]["aggregateKind"].as_str() == Some("taskRun") {
        return resume_taskrun_from_baseline(&request["baseline"]);
    }
    let baseline = v2_baseline(&state).expect("V2 baseline");
    let aggregate = baseline["aggregateId"].as_str().expect("aggregate id");
    let conversation = uuid::Uuid::from_bytes(
        hex::decode(aggregate)
            .expect("aggregate bytes")
            .try_into()
            .expect("aggregate ID"),
    )
    .to_string();
    let suffix = suffix_event(&conversation);
    let cursor = baseline_checkpoint_cursor(&baseline);
    let mut accepted = json!({
        "codec": 1,
        "projectionBytes": baseline["promotionProjectionBytes"],
        "projectionDigest": baseline["promotionProjectionDigest"],
        "sequence": 3,
        "version": 3,
        "globalPosition": 3,
        "headEventId": hex::encode(uuid(suffix["eventId"].as_str().expect("suffix id")).expect("suffix bytes")),
        "headIntegrityDigest": suffix["integrityDigest"],
        "capturedHighWater": 3,
    });
    let failure_mode = state.resume_failure_mode.swap(0, Ordering::SeqCst);
    let mut cursor = cursor;
    let mut suffix = suffix;
    match failure_mode {
        1 => "malformed-checkpoint".clone_into(&mut cursor),
        2 => accepted["projectionDigest"] = Value::String("00".repeat(32)),
        3 => suffix["sequence"] = Value::from(4),
        _ => {}
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-request-id", RETENTION_REQUEST_ID)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "requestId": RETENTION_REQUEST_ID,
                "sessionId": SESSION_ID,
                "highWaterRef": "aa",
                "baselineCheckpoint": cursor,
                "acceptedPromotion": accepted,
                "events": [suffix],
                "hasMore": false,
            }))
            .expect("resume JSON"),
        ))
        .expect("resume response")
}

fn v2_baseline(state: &MockState) -> Result<Value, ()> {
    let inner = state.inner.lock().map_err(|_| ())?;
    let conversation = inner.conversation_id.clone().ok_or(())?;
    let workspace = inner.workspace_id.clone().ok_or(())?;
    drop(inner);
    let conversation_id = uuid(&conversation)?;
    let projection =
        gocode_api::test_support::conversation_promotion_bytes(conversation_id, uuid(&workspace)?);
    let digest = promotion_digest(&projection, &conversation_id);
    let mut session = MockRuntime::session();
    session.capabilities = gocode_runtime_client::PROTECTED_RUNTIME_CAPABILITIES
        .iter()
        .map(ToString::to_string)
        .collect();
    session.capability_digest = protected_capability_digest(&session.capabilities);
    let binding = runtime_binding(&session)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ())?;
    let issued = u64::try_from(now.as_millis()).map_err(|_| ())?;
    let mut fields = gocode_api::UnauthenticatedReplayRetentionBaselineFieldsV2 {
        schema_version: 2,
        authority_id: uuid(&session.authority_id)?,
        principal_id: session.principal_id,
        lineage_id: uuid(&session.event_log_lineage_id)?,
        runtime_session_binding_digest: binding.canonical_digest(),
        replay_scope_digest: gocode_api::canonical_aggregate_replay_scope_digest(
            gocode_api::ApiReplayAggregateKind::Conversation,
            &conversation_id,
        ),
        aggregate_kind: gocode_api::ApiReplayAggregateKind::Conversation,
        aggregate_id: conversation_id,
        sequence: 2,
        version: 2,
        baseline_global_position: 2,
        head_event_id: uuid("018f2e3a-7000-7000-8002-000000000002")?,
        head_integrity_digest: [0x22; 32],
        promotion_codec: 1,
        promotion_projection_bytes: projection,
        promotion_projection_digest: digest,
        retained_floor: 1,
        captured_high_water: 2,
        retention_generation: 1,
        retention_manifest_digest: [0x12; 32],
        issued_at_unix_ms: issued,
        expires_at_unix_ms: issued + 20_000,
        witness_mac: [0; 32],
    };
    let unsigned =
        gocode_api::ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields.clone());
    fields.witness_mac = baseline_mac(&binding, &unsigned)?;
    Ok(baseline_json(&fields))
}


fn runtime_binding(
    session: &gocode_runtime_client::RuntimeSessionInfo,
) -> Result<gocode_api::RuntimeSessionBinding, ()> {
    let stable = gocode_api::StableRuntimeBinding::new(
        uuid(&session.authority_id)?,
        gocode_api::ApiPrincipalId::new(session.principal_id.clone()).map_err(|_| ())?,
        gocode_api::EventLogLineageId::from_bytes(uuid(&session.event_log_lineage_id)?),
        session.profile_id.clone(),
        hex32(&session.schema_hash)?,
        hex32(&session.capability_digest)?,
    )
    .map_err(|_| ())?;
    gocode_api::RuntimeSessionBinding::new_with_sensitivity_label(
        stable,
        gocode_api::DaemonInstanceId::from_bytes(uuid(&session.daemon_instance_id)?),
        session.launch_generation,
        uuid(&session.session_id)?,
        session.authorization_epoch,
        &session.sensitivity_ceiling,
        hex32(&session.certificate_sha256)?,
    )
    .map_err(|_| ())
}

fn baseline_mac(
    binding: &gocode_api::RuntimeSessionBinding,
    wire: &gocode_api::ReplayRetentionBaselineWireV2,
) -> Result<[u8; 32], ()> {
    type HmacSha256 = Hmac<Sha256>;
    let mut derive = HmacSha256::new_from_slice(&[0x5a; 32]).map_err(|_| ())?;
    derive.update(gocode_api::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V2);
    derive.update(&binding.canonical_digest());
    let key: [u8; 32] = derive.finalize().into_bytes().into();
    let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| ())?;
    mac.update(&gocode_api::replay_retention_baseline_v2_transcript(wire).map_err(|_| ())?);
    Ok(mac.finalize().into_bytes().into())
}

fn baseline_json(value: &gocode_api::UnauthenticatedReplayRetentionBaselineFieldsV2) -> Value {
    json!({
    "schemaVersion":value.schema_version,"authorityId":hex::encode(value.authority_id),"principalId":value.principal_id,"lineageId":hex::encode(value.lineage_id),"runtimeSessionBindingDigest":hex::encode(value.runtime_session_binding_digest),"replayScopeDigest":hex::encode(value.replay_scope_digest),"aggregateKind":match value.aggregate_kind { gocode_api::ApiReplayAggregateKind::Conversation=>"conversation",gocode_api::ApiReplayAggregateKind::TaskRun=>"taskRun" },"aggregateId":hex::encode(value.aggregate_id),"sequence":value.sequence,"version":value.version,"baselineGlobalPosition":value.baseline_global_position,"headEventId":hex::encode(value.head_event_id),"headIntegrityDigest":hex::encode(value.head_integrity_digest),"promotionCodec":value.promotion_codec,"promotionProjectionBytes":URL_SAFE_NO_PAD.encode(&value.promotion_projection_bytes),"promotionProjectionDigest":hex::encode(value.promotion_projection_digest),"retainedFloor":value.retained_floor,"capturedHighWater":value.captured_high_water,"retentionGeneration":value.retention_generation,"retentionManifestDigest":hex::encode(value.retention_manifest_digest),"issuedAtUnixMs":value.issued_at_unix_ms,"expiresAtUnixMs":value.expires_at_unix_ms,"witnessMac":hex::encode(value.witness_mac) })
}

fn baseline_checkpoint_cursor(baseline: &Value) -> String {
    let aggregate = baseline["aggregateId"].as_str().expect("aggregate id");
    let event = baseline["headEventId"].as_str().expect("event id");
    let id = hex::decode(aggregate).expect("aggregate bytes");
    let cursor = json!({
        "scope":{"Aggregate":{"aggregate_id":id,"aggregate_type":2}},
        "event_id":event,
        "sequence":baseline["sequence"],
        "global_position":baseline["baselineGlobalPosition"],
    });
    format!(
        "gocode-replay-cursor-v1.{}",
        hex::encode(serde_json::to_vec(&cursor).expect("cursor"))
    )
}

fn suffix_event(conversation_id: &str) -> Value {
    let mut event = json!({
        "eventId":"018f2e3a-7000-7000-8002-000000000003",
        "aggregateType":"conversation","aggregateId":conversation_id,"sequence":3,
        "timestampUnixMicros":1_722_330_000_000_003_i64,"sensitivity":"sensitive",
        "schemaVersion":1,"eventType":"conversation.generation.failed","causationEventId":null,
        "integrityDigest":"33".repeat(32),"correlationId":conversation_id,"correlationType":"conversation",
        "payload":{"type":"conversation.generation.failed","taskRunId":"018f2e3a-7000-7000-8000-000000000130","attemptId":"018f2e3a-7000-7000-8000-000000000131","reason":"forced"},
        "replayBindingId":"018f2e3a700070008000000000000121",
    });
    let cursor = event_cursor(&event);
    event
        .as_object_mut()
        .expect("event")
        .insert("cursor".to_owned(), Value::String(cursor));
    event
}
