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
    let no_store = || {
        json!({
            "description": "Responses are never stored",
            "schema": {"const": "no-store", "type": "string"},
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
    let mut document = json!({
        "info": {
            "title": "GOCODE Local Runtime API",
            "version": "1.0.0",
        },
        "components": {
            "securitySchemes": {
                "sessionAuth": {"scheme": "GocodeSession", "type": "http"}
            }
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
            "/v1/runtime/operational-telemetry": {
                "get": {
                    "security": [{"sessionAuth": []}],
                    "responses": {
                        "200": {
                            "content": {"application/json": {"schema": {"$ref": "schemas/operational-telemetry-v1.schema.json"}}},
                            "description": "Operational telemetry snapshot",
                            "headers": {"Cache-Control": no_store()},
                        },
                        "400": {"description": "Static bad request response", "headers": {"Cache-Control": no_store()}},
                        "401": {"description": "Static unauthorized response", "headers": {"Cache-Control": no_store()}},
                        "405": {"description": "Static method not allowed response", "headers": {"Cache-Control": no_store()}},
                        "413": {"description": "Static payload too large response", "headers": {"Cache-Control": no_store()}},
                        "503": {"description": "Static unavailable response", "headers": {"Cache-Control": no_store()}},
                    }
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
    });
    project_workspace_openapi(&mut document);
    document
}

fn project_workspace_openapi(document: &mut Value) {
    let schema = "schemas/project-workspace-v1.schema.json#/$defs/";
    let response = |name: &str| json!({"description": "Canonical response", "headers": {"X-Request-Id": {"required": true, "schema": {"pattern": UUID_V7_PATTERN, "type": "string"}}}, "content": {"application/json": {"schema": {"$ref": format!("{schema}{name}")}}}});
    let errors = || json!({"400": response("error"), "401": response("error"), "404": response("error"), "409": response("error"), "413": response("error"), "503": response("error")});
    let operation = |request: Option<&str>, success: &str| { let mut item = json!({"security": [{"sessionAuth": []}], "responses": errors()}); item["responses"]["202"] = response(success); if let Some(request) = request { item["requestBody"] = json!({"required": true, "content": {"application/json": {"schema": {"$ref": format!("{schema}{request}")}}}}); } item };
    let paths = document["paths"].as_object_mut().expect("OpenAPI paths object");
    paths.insert("/v1/projects".into(), json!({"get": {"security": [{"sessionAuth": []}], "responses": {"200": response("projectPage"), "400": response("error"), "401": response("error"), "404": response("error"), "503": response("error")}}, "post": operation(Some("projectCreate"), "projectAck")}));
    paths.insert("/v1/projects/{projectId}".into(), json!({"get": {"security": [{"sessionAuth": []}], "responses": {"200": response("project"), "400": response("error"), "401": response("error"), "404": response("error"), "503": response("error")}}, "delete": operation(Some("existing"), "projectAck")}));
    for operation_name in ["archive", "restore"] { paths.insert(format!("/v1/projects/{{projectId}}/{operation_name}"), json!({"post": operation(Some("existing"), "projectAck")})); }
    paths.insert("/v1/projects/{projectId}/workspaces".into(), json!({"get": {"security": [{"sessionAuth": []}], "responses": {"200": response("workspacePage"), "400": response("error"), "401": response("error"), "404": response("error"), "503": response("error")}}, "post": operation(Some("workspaceCreate"), "workspaceAck")}));
    paths.insert("/v1/workspaces/{workspaceId}".into(), json!({"get": {"security": [{"sessionAuth": []}], "responses": {"200": response("workspace"), "400": response("error"), "401": response("error"), "404": response("error"), "503": response("error")}}}));
    paths.insert("/v1/workspaces/{workspaceId}/open".into(), json!({"post": operation(Some("existing"), "workspaceAck")}));
    paths.insert("/v1/workspaces/{workspaceId}/root-bindings".into(), json!({"post": operation(Some("rootBind"), "workspaceAck")}));
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

fn operational_telemetry_golden() -> Value {
    json!({
        "durable": {
            "accounting": {
                "costMicroUsd": {"limit": 10, "remaining": 5, "reserved": 2, "settled": 3},
                "tokens": {"limit": 10, "remaining": 5, "reserved": 2, "settled": 3},
            },
            "committedProviderEffects": {"activeCount": 0, "expiredActiveCount": 0, "nearestUnexpiredExpiryUnixSeconds": null},
            "meta": {"completeness": "complete", "freshness": "observed_in_current_cycle", "observedAtUnixSeconds": 10},
            "providerApprovalLease": {"activeCount": 0, "expiredActiveCount": 0, "nearestUnexpiredExpiryUnixSeconds": null},
            "providerEffectAuthorities": {"activeCount": 1, "expiredActiveCount": 0, "nearestUnexpiredExpiryUnixSeconds": 11},
            "uncertainAttempts": 0,
        },
        "launchGeneration": 1,
        "observedAtUnixSeconds": 10,
        "recoveryTransient": {
            "counterSaturated": false,
            "droppedEventCount": 0,
            "meta": {"completeness": "complete", "freshness": "observed_in_current_cycle", "observedAtUnixSeconds": 10},
            "observedOutboxRecoveriesInGeneration": 0,
            "status": "lower_bound_since_launch",
        },
        "schemaVersion": 1,
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
