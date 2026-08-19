const CANONICAL_EVENT_REQUIRED: &[&str] = &[
    "aggregateId",
    "aggregateType",
    "causationEventId",
    "correlationId",
    "correlationType",
    "eventId",
    "eventType",
    "integrityDigest",
    "payload",
    "replayBindingId",
    "schemaVersion",
    "sensitivity",
    "sequence",
    "timestampUnixMicros",
];

fn canonical_event_properties() -> Value {
    json!({
        "aggregateId": uuid_v7_schema(),
        "aggregateType": enum_schema(&["conversation", "taskRun"]),
        "causationEventId": nullable_uuid_v7_schema(),
        "correlationId": uuid_v7_schema(),
        "correlationType": enum_schema(&["conversation", "taskRun"]),
        "eventId": uuid_v7_schema(),
        "eventType": string_schema(128),
        "integrityDigest": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
        "payload": {"$ref": "#/$defs/canonicalReplayPayloadV1"},
        "replayBindingId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
        "schemaVersion": {"const": 1, "type": "integer"},
        "sensitivity": enum_schema(&["public", "internal", "sensitive"]),
        "sequence": positive_integer_schema(),
        "timestampUnixMicros": {"type": "integer"},
    })
}

fn canonical_event_schema() -> Value {
    closed_object(canonical_event_properties(), CANONICAL_EVENT_REQUIRED)
}

fn delivered_replay_event_schema() -> Value {
    let mut properties = canonical_event_properties();
    properties.as_object_mut().unwrap().insert(
        "cursor".to_owned(),
        json!({"maxLength": 8192, "pattern": CURSOR_PATTERN, "type": "string"}),
    );
    let mut required = CANONICAL_EVENT_REQUIRED.to_vec();
    required.push("cursor");
    closed_object(properties, &required)
}

fn replay_retention_baseline_schema() -> Value {
    closed_object(
        json!({
            "schemaVersion": {"const": 1, "type": "integer"},
            "authorityId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
            "principalId": {"maxLength": 256, "minLength": 1, "pattern": "^[^\\u{0000}-\\u{001F}\\u{007F}]+$", "type": "string"},
            "lineageId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
            "runtimeSessionBindingDigest": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "replayScopeDigest": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "aggregateKind": enum_schema(&["conversation", "taskRun"]),
            "aggregateId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
            "sequence": positive_integer_schema(),
            "version": positive_integer_schema(),
            "baselineGlobalPosition": {"maximum": i64::MAX, "minimum": 1, "type": "integer"},
            "projectionCodec": {"const": 1, "type": "integer"},
            "projectionBytes": {"maxLength": 699051, "minLength": 1, "pattern": BASE64_URL_PATTERN, "type": "string"},
            "projectionDigest": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "retainedFloor": {"maximum": i64::MAX, "minimum": 1, "type": "integer"},
            "capturedHighWater": {"maximum": i64::MAX, "minimum": 1, "type": "integer"},
            "retentionGeneration": positive_integer_schema(),
            "retentionWitness": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "issuedAtUnixMs": telemetry_u64_schema(),
            "expiresAtUnixMs": telemetry_u64_schema(),
            "witnessMac": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
        }),
        &[
            "schemaVersion",
            "authorityId",
            "principalId",
            "lineageId",
            "runtimeSessionBindingDigest",
            "replayScopeDigest",
            "aggregateKind",
            "aggregateId",
            "sequence",
            "version",
            "baselineGlobalPosition",
            "projectionCodec",
            "projectionBytes",
            "projectionDigest",
            "retainedFloor",
            "capturedHighWater",
            "retentionGeneration",
            "retentionWitness",
            "issuedAtUnixMs",
            "expiresAtUnixMs",
            "witnessMac",
        ],
    )
}

fn replay_retention_gap_response_schema() -> Value {
    closed_object(
        json!({
            "code": {"const": "replay_retention_gap", "type": "string"},
            "requestId": uuid_v7_schema(),
            "baseline": {"$ref": "#/$defs/replayRetentionBaselineV1"},
        }),
        &["code", "requestId", "baseline"],
    )
}

fn replay_schema() -> Value {
    let mut schema = delivered_replay_event_schema();
    let object = schema.as_object_mut().unwrap();
    object.insert(
        "$defs".to_owned(),
        json!({
            "acknowledgeRequest": closed_object(
                json!({"cursor": {"maxLength": 8192, "pattern": CURSOR_PATTERN, "type": "string"}}),
                &["cursor"],
            ),
            "canonicalReplayPayloadV1": canonical_payload_schema(),
            "deliveredReplayEvent": delivered_replay_event_schema(),
            "acknowledgeResponse": closed_object(
                json!({"acknowledged": {"type": "boolean"}}),
                &["acknowledged"],
            ),
            "completeCatchUpResponse": closed_object(
                json!({
                    "catchUpProof": string_schema(8192),
                    "sessionState": enum_schema(&["catch_up_complete"]),
                }),
                &["catchUpProof", "sessionState"],
            ),
            "continueLiveResponse": closed_object(
                json!({
                    "liveDeliveryId": uuid_v7_schema(),
                    "sessionState": enum_schema(&["live"]),
                }),
                &["liveDeliveryId", "sessionState"],
            ),
            "openSessionRequest": closed_object(
                json!({
                    "aggregateId": uuid_v7_schema(),
                    "aggregateType": enum_schema(&["conversation", "taskRun"]),
                    "fromCursor": {
                        "oneOf": [
                            {"maxLength": 8192, "pattern": CURSOR_PATTERN, "type": "string"},
                            {"type": "null"}
                        ]
                    },
                }),
                &["aggregateId", "aggregateType", "fromCursor"],
            ),
            "openSessionResponse": closed_object(
                json!({
                    "events": {
                        "items": {"$ref": "#/$defs/deliveredReplayEvent"},
                        "type": "array",
                    },
                    "hasMore": {"type": "boolean"},
                    "highWaterRef": string_schema(8192),
                    "sessionId": replay_session_id_schema(),
                }),
                &["events", "hasMore", "highWaterRef", "sessionId"],
            ),
            "replayRetentionBaselineV1": replay_retention_baseline_schema(),
            "resumeFromBaselineRequestV2": closed_object(
                json!({"baseline": {"$ref": "#/$defs/replayRetentionBaselineV2"}}),
                &["baseline"],
            ),
            "replayRetentionBaselineV2": replay_retention_baseline_v2_schema(),
            "resumeFromBaselineResponseV2": resume_from_baseline_response_schema(),
            "retentionGapResponse": replay_retention_gap_response_schema(),
            "retentionGapResponseV2": replay_retention_gap_response_v2_schema(),
            "readPageRequest": closed_object(
                json!({"limit": {"maximum": 256, "minimum": 1, "type": "integer"}}),
                &["limit"],
            ),
            "readPageResponse": closed_object(
                json!({
                    "events": {
                        "items": {"$ref": "#/$defs/deliveredReplayEvent"},
                        "type": "array",
                    },
                    "hasMore": {"type": "boolean"},
                }),
                &["events", "hasMore"],
            ),
        }),
    );
    object.insert("$id".to_owned(), json!("runne://schemas/replay-v1"));
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert("title".to_owned(), json!("Canonical Replay Event V1"));
    schema
}

include!("replay_schema_v2.rs");
