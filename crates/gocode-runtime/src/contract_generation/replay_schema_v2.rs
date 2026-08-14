fn replay_retention_baseline_v2_schema() -> Value {
    let mut properties = replay_retention_baseline_schema()["properties"].clone();
    let object = properties.as_object_mut().expect("baseline properties");
    object.insert(
        "schemaVersion".into(),
        json!({"const": 2, "type": "integer"}),
    );
    object.insert("headEventId".into(), lower_hex_schema(16));
    object.insert("headIntegrityDigest".into(), lower_hex_schema(32));
    object.insert(
        "promotionCodec".into(),
        json!({"const": 1, "type": "integer"}),
    );
    object.insert("promotionProjectionBytes".into(), json!({"maxLength": gocode_api::MAX_REPLAY_PROMOTION_PROJECTION_BASE64URL_CHARS, "minLength": 1, "pattern": BASE64_URL_PATTERN, "type": "string"}));
    object.insert("promotionProjectionDigest".into(), lower_hex_schema(32));
    object.insert("retentionManifestDigest".into(), lower_hex_schema(32));
    for key in [
        "projectionCodec",
        "projectionBytes",
        "projectionDigest",
        "retentionWitness",
    ] {
        object.remove(key);
    }
    let mut required = replay_retention_baseline_schema()["required"]
        .as_array()
        .expect("baseline required")
        .iter()
        .filter_map(Value::as_str)
        .filter(|key| {
            ![
                "projectionCodec",
                "projectionBytes",
                "projectionDigest",
                "retentionWitness",
            ]
            .contains(key)
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    required.extend(
        [
            "headEventId",
            "headIntegrityDigest",
            "promotionCodec",
            "promotionProjectionBytes",
            "promotionProjectionDigest",
            "retentionManifestDigest",
        ]
        .map(str::to_owned),
    );
    closed_object(
        properties,
        &required.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

fn accepted_promotion_schema() -> Value {
    closed_object(
        json!({
            "codec": {"const": 1, "type": "integer"},
            "projectionBytes": {"maxLength": gocode_api::MAX_REPLAY_PROMOTION_PROJECTION_BASE64URL_CHARS, "minLength": 1, "pattern": BASE64_URL_PATTERN, "type": "string"},
            "projectionDigest": lower_hex_schema(32), "sequence": positive_integer_schema(),
            "version": positive_integer_schema(), "globalPosition": {"maximum": i64::MAX, "minimum": 1, "type": "integer"},
            "headEventId": lower_hex_schema(16), "headIntegrityDigest": lower_hex_schema(32),
            "capturedHighWater": {"maximum": i64::MAX, "minimum": 1, "type": "integer"},
        }),
        &[
            "codec",
            "projectionBytes",
            "projectionDigest",
            "sequence",
            "version",
            "globalPosition",
            "headEventId",
            "headIntegrityDigest",
            "capturedHighWater",
        ],
    )
}

fn resume_from_baseline_response_schema() -> Value {
    closed_object(
        json!({
            "requestId": uuid_v7_schema(), "sessionId": replay_session_id_schema(),
            "highWaterRef": string_schema(8192), "baselineCheckpoint": string_schema(8192),
            "acceptedPromotion": accepted_promotion_schema(),
            "events": {"items": {"$ref": "#/$defs/deliveredReplayEvent"}, "type": "array"},
            "hasMore": {"type": "boolean"},
        }),
        &[
            "requestId",
            "sessionId",
            "highWaterRef",
            "baselineCheckpoint",
            "acceptedPromotion",
            "events",
            "hasMore",
        ],
    )
}

fn replay_retention_gap_response_v2_schema() -> Value {
    closed_object(
        json!({"code": {"const": "replay_retention_gap", "type": "string"}, "requestId": uuid_v7_schema(), "baseline": {"$ref": "#/$defs/replayRetentionBaselineV2"}}),
        &["code", "requestId", "baseline"],
    )
}

fn lower_hex_schema(bytes: usize) -> Value {
    let pattern = match bytes {
        16 => LOWER_HEX_16_PATTERN,
        32 => LOWER_HEX_32_PATTERN,
        _ => unreachable!("only fixed wire digest widths are used"),
    };
    json!({"pattern": pattern, "type": "string"})
}
