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
    object.insert("$id".to_owned(), json!("gocode://schemas/replay-v1"));
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert("title".to_owned(), json!("Canonical Replay Event V1"));
    schema
}
