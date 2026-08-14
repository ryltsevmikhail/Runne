fn local_runtime_profile_schema() -> Value {
    let capability_tuple = |capabilities: &[&str]| json!({
        "items": false,
        "maxItems": capabilities.len(),
        "minItems": capabilities.len(),
        "prefixItems": capabilities.iter().map(|capability| json!({"const": capability, "type": "string"})).collect::<Vec<_>>(),
        "type": "array",
    });
    let mut schema = closed_object(
        json!({
            "authorityId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
            "bootstrapSecretPath": {"maxLength": 4096, "minLength": 1, "type": "string"},
            "capabilities": {
                "oneOf": [
                    capability_tuple(BASE_RUNTIME_CAPABILITIES),
                    capability_tuple(PUBLISHED_RUNTIME_CAPABILITIES),
                ],
            },
            "capabilityDigest": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "certificateDerBase64": {"maxLength": 65536, "pattern": "^[A-Za-z0-9+/]+={0,2}$", "type": "string"},
            "certificateSha256": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "daemonInstanceId": uuid_v7_schema(),
            "endpoint": {"pattern": "^https://(?:127\\.0\\.0\\.1|\\[::1\\]):[1-9][0-9]{0,4}$", "type": "string"},
            "eventLogLineageId": uuid_v7_schema(),
            "launchGeneration": positive_integer_schema(),
            "principalId": {"const": "local-owner", "type": "string"},
            "profileId": {"const": BUNDLE_ID, "type": "string"},
            "schemaHash": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "schemaVersion": {"const": 3, "type": "integer"},
            "transportProfileId": {"const": TRANSPORT_PROFILE_ID, "type": "string"},
        }),
        &[
            "authorityId",
            "bootstrapSecretPath",
            "capabilities",
            "capabilityDigest",
            "certificateDerBase64",
            "certificateSha256",
            "daemonInstanceId",
            "endpoint",
            "eventLogLineageId",
            "launchGeneration",
            "principalId",
            "profileId",
            "schemaHash",
            "schemaVersion",
            "transportProfileId",
        ],
    );
    let object = schema.as_object_mut().unwrap();
    object.insert(
        "$id".to_owned(),
        json!("gocode://schemas/local-runtime-profile-v3"),
    );
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert("title".to_owned(), json!("Local Runtime Profile V3"));
    schema
}

fn local_session_schema() -> Value {
    let nonce = json!({
        "maxLength": 43,
        "minLength": 43,
        "pattern": BASE64_URL_PATTERN,
        "type": "string",
    });
    let challenge_id = json!({
        "maxLength": 22,
        "minLength": 22,
        "pattern": BASE64_URL_PATTERN,
        "type": "string",
    });
    let definitions = json!({
        "authenticateRequest": closed_object(
            json!({
                "authority": nonce,
                "challengeId": challenge_id,
                "proof": nonce,
            }),
            &["authority", "challengeId", "proof"],
        ),
        "authenticateResponse": closed_object(
            json!({
                "expiresAtMonotonicMillis": positive_integer_schema(),
                "sessionId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
            }),
            &["expiresAtMonotonicMillis", "sessionId"],
        ),
        "challengeRequest": closed_object(
            json!({"clientNonce": nonce, "serverNonce": nonce}),
            &["clientNonce", "serverNonce"],
        ),
        "challengeResponse": closed_object(
            json!({"challengeId": challenge_id, "serverNonce": nonce}),
            &["challengeId", "serverNonce"],
        ),
    });
    let mut schema = closed_object(
        json!({
            "authenticateRequest": {"$ref": "#/$defs/authenticateRequest"},
            "authenticateResponse": {"$ref": "#/$defs/authenticateResponse"},
            "challengeRequest": {"$ref": "#/$defs/challengeRequest"},
            "challengeResponse": {"$ref": "#/$defs/challengeResponse"},
        }),
        &[
            "authenticateRequest",
            "authenticateResponse",
            "challengeRequest",
            "challengeResponse",
        ],
    );
    let object = schema.as_object_mut().unwrap();
    object.insert("$defs".to_owned(), definitions);
    object.insert("$id".to_owned(), json!("gocode://schemas/local-session-v1"));
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert(
        "title".to_owned(),
        json!("Local Session V1 Golden Exchange"),
    );
    schema
}

fn sse_delivery_schema() -> Value {
    closed_object(
        json!({
            "canonicalEvent": canonical_event_schema(),
            "deliverySequence": positive_integer_schema(),
            "liveDeliveryId": nullable_uuid_v7_schema(),
            "replayCursor": {"maxLength": 8192, "pattern": CURSOR_PATTERN, "type": "string"},
            "replaySessionId": replay_session_id_schema(),
            "transportVersion": {"const": 1, "type": "integer"},
        }),
        &[
            "canonicalEvent",
            "deliverySequence",
            "liveDeliveryId",
            "replayCursor",
            "replaySessionId",
            "transportVersion",
        ],
    )
}

fn sse_schema() -> Value {
    let mut schema = sse_delivery_schema();
    let object = schema.as_object_mut().unwrap();
    object.insert(
        "$defs".to_owned(),
        json!({"canonicalReplayPayloadV1": canonical_payload_schema()}),
    );
    object.insert("$id".to_owned(), json!("gocode://schemas/sse-v1"));
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert("title".to_owned(), json!("Replay SSE Delivery V1"));
    schema
}
