fn local_runtime_profile_schema() -> Value {
    let capability_prefix = PUBLISHED_RUNTIME_CAPABILITIES
        .iter()
        .map(|capability| json!({"const": capability, "type": "string"}))
        .collect::<Vec<_>>();
    let mut schema = closed_object(
        json!({
            "authorityId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
            "bootstrapSecretPath": {"maxLength": 4096, "minLength": 1, "type": "string"},
            "capabilities": {
                "items": false,
                "maxItems": PUBLISHED_RUNTIME_CAPABILITIES.len(),
                "minItems": PUBLISHED_RUNTIME_CAPABILITIES.len(),
                "prefixItems": capability_prefix,
                "type": "array",
            },
            "capabilityDigest": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "certificateDerBase64": {"maxLength": 65536, "pattern": "^[A-Za-z0-9+/]+={0,2}$", "type": "string"},
            "certificateSha256": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "daemonInstanceId": uuid_v7_schema(),
            "endpoint": {"pattern": "^https://(?:127\\.0\\.0\\.1|\\[::1\\]):[1-9][0-9]{0,4}$", "type": "string"},
            "eventLogLineageId": uuid_v7_schema(),
            "executableSha256": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "launchAuthorityId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
            "launchGeneration": positive_integer_schema(),
            "principalId": {"const": "local-owner", "type": "string"},
            "profileId": {"const": BUNDLE_ID, "type": "string"},
            "schemaHash": {"pattern": LOWER_HEX_32_PATTERN, "type": "string"},
            "schemaVersion": {"const": 2, "type": "integer"},
            "sessionId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
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
            "executableSha256",
            "launchAuthorityId",
            "launchGeneration",
            "principalId",
            "profileId",
            "schemaHash",
            "schemaVersion",
            "sessionId",
            "transportProfileId",
        ],
    );
    let object = schema.as_object_mut().unwrap();
    object.insert(
        "$id".to_owned(),
        json!("gocode://schemas/local-runtime-profile-v2"),
    );
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert("title".to_owned(), json!("Local Runtime Profile V2"));
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
    let timestamp = json!({
        "format": "date-time",
        "pattern": "^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{6}Z$",
        "type": "string",
    });
    let wire_version = json!({"const": "3", "type": "string"});
    let key_version = json!({"const": 1, "type": "integer"});
    let definitions = json!({
        "authenticateRequest": closed_object(
            json!({
                "authority": nonce,
                "challengeId": challenge_id,
                "finalProof": nonce,
                "keyVersion": key_version,
                "wireVersion": wire_version,
            }),
            &["authority", "challengeId", "finalProof", "keyVersion", "wireVersion"],
        ),
        "authenticateResponse": closed_object(
            json!({
                "expiresAtMonotonicMillis": positive_integer_schema(),
                "keyVersion": key_version,
                "sessionId": {"pattern": LOWER_HEX_16_PATTERN, "type": "string"},
                "wireVersion": wire_version,
            }),
            &["expiresAtMonotonicMillis", "keyVersion", "sessionId", "wireVersion"],
        ),
        "challengeRequest": closed_object(
            json!({
                "clientNonce": nonce,
                "expiry": timestamp,
                "keyVersion": key_version,
                "notBefore": timestamp,
                "preallocationProof": nonce,
                "wireVersion": wire_version,
            }),
            &["clientNonce", "expiry", "keyVersion", "notBefore", "preallocationProof", "wireVersion"],
        ),
        "challengeResponse": closed_object(
            json!({
                "challengeId": challenge_id,
                "keyVersion": key_version,
                "serverNonce": nonce,
                "wireVersion": wire_version,
            }),
            &["challengeId", "keyVersion", "serverNonce", "wireVersion"],
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
    object.insert("$id".to_owned(), json!("gocode://schemas/local-session-v2"));
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert(
        "title".to_owned(),
        json!("Local Session V2 Golden Exchange"),
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
