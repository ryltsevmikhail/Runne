fn openapi() -> Value {
    let request = |reference: &str| {
        json!({
            "content": {"application/json": {"schema": {"$ref": reference}}},
            "required": true,
        })
    };
    let response = |reference: &str| {
        json!({
            "content": {"application/json": {"schema": {"$ref": reference}}},
            "description": "Canonical response",
        })
    };
    let session_parameter = || {
        json!({
            "in": "path",
            "name": "sessionId",
            "required": true,
            "schema": replay_session_id_schema(),
        })
    };
    json!({
        "info": {
            "title": "GOCODE Local Runtime API",
            "version": "1.0.0",
        },
        "jsonSchemaDialect": DRAFT_2020_12,
        "openapi": "3.1.0",
        "paths": {
            "/v1/local-session/authenticate": {
                "post": {
                    "requestBody": request("schemas/local-session-v1.schema.json#/$defs/authenticateRequest"),
                    "responses": {"200": response("schemas/local-session-v1.schema.json#/$defs/authenticateResponse")},
                }
            },
            "/v1/local-session/challenges": {
                "post": {
                    "requestBody": request("schemas/local-session-v1.schema.json#/$defs/challengeRequest"),
                    "responses": {"200": response("schemas/local-session-v1.schema.json#/$defs/challengeResponse")},
                }
            },
            "/v1/replay/open-session": {
                "post": {
                    "requestBody": request("schemas/replay-v1.schema.json#/$defs/openSessionRequest"),
                    "responses": {"200": response("schemas/replay-v1.schema.json#/$defs/openSessionResponse")},
                }
            },
            "/v1/replay/{sessionId}/acknowledge": {
                "post": {
                    "parameters": [session_parameter()],
                    "requestBody": request("schemas/replay-v1.schema.json#/$defs/acknowledgeRequest"),
                    "responses": {"200": response("schemas/replay-v1.schema.json#/$defs/acknowledgeResponse")},
                }
            },
            "/v1/replay/{sessionId}/close": {
                "post": {
                    "parameters": [session_parameter()],
                    "responses": {"204": {"description": "Replay session closed"}}
                }
            },
            "/v1/replay/{sessionId}/complete-catch-up": {
                "post": {
                    "parameters": [session_parameter()],
                    "responses": {"200": response("schemas/replay-v1.schema.json#/$defs/completeCatchUpResponse")}
                }
            },
            "/v1/replay/{sessionId}/continue-live": {
                "post": {
                    "parameters": [session_parameter()],
                    "responses": {"200": response("schemas/replay-v1.schema.json#/$defs/continueLiveResponse")}
                }
            },
            "/v1/replay/{sessionId}/events": {
                "get": {
                    "parameters": [session_parameter()],
                    "responses": {
                        "200": {
                            "content": {"text/event-stream": {"schema": {"$ref": "schemas/sse-v1.schema.json"}}},
                            "description": "Bounded replay/live SSE",
                        }
                    }
                }
            },
            "/v1/replay/{sessionId}/read-page": {
                "post": {
                    "parameters": [session_parameter()],
                    "requestBody": request("schemas/replay-v1.schema.json#/$defs/readPageRequest"),
                    "responses": {"200": response("schemas/replay-v1.schema.json#/$defs/readPageResponse")},
                }
            },
        },
    })
}

fn local_session_golden() -> Value {
    json!({
        "authenticateRequest": {
            "authority": "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo",
            "challengeId": "AQEBAQEBAQEBAQEBAQEBAQ",
            "proof": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
        },
        "authenticateResponse": {
            "expiresAtMonotonicMillis": 600000,
            "sessionId": "018f2e3a700070008000000000000112",
        },
        "challengeRequest": {
            "clientNonce": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
            "serverNonce": "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
        },
        "challengeResponse": {
            "challengeId": "AQEBAQEBAQEBAQEBAQEBAQ",
            "serverNonce": "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
        },
    })
}

fn replay_conversation_golden() -> Value {
    let payload = CanonicalReplayPayloadV1::from(&ConversationEvent::AssistantMessageAppended {
        message_id: "018f2e3a-7000-7000-8000-000000000115"
            .parse::<MessageId>()
            .expect("golden message UUIDv7"),
        taskrun_id: "018f2e3a-7000-7000-8000-000000000113"
            .parse::<TaskRunId>()
            .expect("golden TaskRun UUIDv7"),
        attempt_id: "018f2e3a-7000-7000-8000-000000000114"
            .parse::<AttemptId>()
            .expect("golden attempt UUIDv7"),
        text: MessageText::new("bounded text").expect("bounded golden text"),
    });
    json!({
        "aggregateId": "018f2e3a-7000-7000-8000-000000000110",
        "aggregateType": "conversation",
        "causationEventId": "018f2e3a-7000-7000-8000-000000000111",
        "correlationId": "018f2e3a-7000-7000-8000-000000000110",
        "correlationType": "conversation",
        "cursor": "gocode-replay-cursor-v1.7b7d",
        "eventId": "018f2e3a-7000-7000-8000-000000000112",
        "eventType": "conversation.message.appended",
        "integrityDigest": integrity_digest_golden(),
        "payload": serde_json::to_value(payload).expect("serialize canonical Conversation payload"),
        "replayBindingId": replay_binding_id_golden(),
        "schemaVersion": 1,
        "sensitivity": "sensitive",
        "sequence": 2,
        "timestampUnixMicros": 1722330000000000_i64,
    })
}

fn replay_taskrun_golden() -> Value {
    let payload = CanonicalReplayPayloadV1::try_from(&TaskRunEvent::AttemptStarted {
        attempt_id: "018f2e3a-7000-7000-8000-000000000114"
            .parse::<AttemptId>()
            .expect("golden attempt UUIDv7"),
    })
    .expect("golden TaskRun payload is public");
    json!({
        "aggregateId": "018f2e3a-7000-7000-8000-000000000113",
        "aggregateType": "taskRun",
        "causationEventId": null,
        "correlationId": "018f2e3a-7000-7000-8000-000000000110",
        "correlationType": "conversation",
        "cursor": "gocode-replay-cursor-v1.7b2261223a317d",
        "eventId": "018f2e3a-7000-7000-8000-000000000116",
        "eventType": "taskRun.attempt.started",
        "integrityDigest": integrity_digest_golden(),
        "payload": serde_json::to_value(payload).expect("serialize canonical TaskRun payload"),
        "replayBindingId": replay_binding_id_golden(),
        "schemaVersion": 1,
        "sensitivity": "public",
        "sequence": 4,
        "timestampUnixMicros": 1722330000000001_i64,
    })
}

fn sse_delivery_golden() -> Value {
    let mut canonical_event = replay_conversation_golden();
    canonical_event
        .as_object_mut()
        .expect("Conversation golden is an object")
        .remove("cursor");
    json!({
        "canonicalEvent": canonical_event,
        "deliverySequence": 1,
        "liveDeliveryId": "018f2e3a-7000-7000-8000-000000000117",
        "replayCursor": "gocode-replay-cursor-v1.7b7d",
        "replaySessionId": "018f2e3a700070008000000000000118",
        "transportVersion": 1,
    })
}

fn replay_binding_id_golden() -> String {
    ApiReplayBindingId::new([
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x21,
    ])
    .expect("golden replay binding identity")
    .to_wire_value()
}

fn integrity_digest_golden() -> String {
    hex::encode(IntegrityDigest::from_bytes([0x11; 32]).as_bytes())
}
