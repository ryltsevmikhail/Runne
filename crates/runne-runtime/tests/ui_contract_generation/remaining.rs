#[test]
fn replay_session_ids_use_the_http_lower_hex_wire_schema_everywhere() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();

    let replay_schema: Value = serde_json::from_slice(
        &fs::read(output.path().join("schemas/replay-v1.schema.json")).unwrap(),
    )
    .unwrap();
    let openapi: Value =
        serde_json::from_slice(&fs::read(output.path().join("openapi.json")).unwrap()).unwrap();
    let expected = serde_json::json!({
        "pattern": "^[0-9a-f]{32}$",
        "type": "string",
    });
    assert_eq!(
        replay_schema["$defs"]["openSessionResponse"]["properties"]["sessionId"],
        expected
    );

    let templated_paths = openapi["paths"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(path, _)| path.contains("{sessionId}"))
        .collect::<Vec<_>>();
    assert_eq!(templated_paths.len(), 6);
    for (path, path_item) in templated_paths {
        for operation in path_item.as_object().unwrap().values() {
            let session_id_schema = operation["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .find(|parameter| parameter["in"] == "path" && parameter["name"] == "sessionId")
                .unwrap_or_else(|| panic!("{path} operation omitted sessionId"))
                .get("schema")
                .unwrap();
            assert_eq!(session_id_schema, &expected, "{path}");
        }
    }
}

#[test]
fn public_taskrun_failure_reason_conversion_is_bounded() {
    assert!(
        CanonicalReplayPayloadV1::try_from(&TaskRunEvent::TaskRunFailed {
            reason: String::new(),
        })
        .is_err()
    );
    assert!(
        CanonicalReplayPayloadV1::try_from(&TaskRunEvent::TaskRunFailed {
            reason: "x".repeat(4097),
        })
        .is_err()
    );
    assert!(
        CanonicalReplayPayloadV1::try_from(&TaskRunEvent::TaskRunFailed {
            reason: "x".repeat(4096),
        })
        .is_ok()
    );
    assert!(
        CanonicalReplayPayloadV1::try_from(&TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Failure {
                reason: String::new(),
            },
        })
        .is_err()
    );
}

#[test]
fn bundle_digest_is_content_only_and_check_never_rewrites() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();

    let bundle_bytes = fs::read(output.path().join("bundle.json")).unwrap();
    let digest = fs::read_to_string(output.path().join("bundle.sha256")).unwrap();
    assert_eq!(
        digest.trim_end(),
        hex::encode(Sha256::digest(&bundle_bytes))
    );
    assert_eq!(digest.trim_end(), PUBLISHED_BUNDLE_HASH);
    let bundle: Value = serde_json::from_slice(&bundle_bytes).unwrap();
    assert_eq!(bundle["apiProfileId"], "gocode-ui-client/2");
    assert_eq!(bundle["transportProfileId"], "gocode-local-runtime/2");
    assert_eq!(
        bundle["publishedCapabilities"],
        serde_json::json!(PUBLISHED_RUNTIME_CAPABILITIES)
    );
    assert_eq!(
        bundle["capabilityCatalog"],
        serde_json::json!(RUNTIME_CAPABILITY_CATALOG)
    );
    let expected_capabilities = serde_json::json!([
        "conversation.create.v1",
        "conversation.generate_text.v1",
        "conversation.list_messages.v1",
        "task_run.get.v1",
        "task_run.cancel.v1",
        "replay.aggregate.open.v1",
        "replay.aggregate.retention_baseline.v1",
        "replay.aggregate.retention_baseline_resume.v2",
        "replay.aggregate.read_page.v1",
        "replay.aggregate.acknowledge.v1",
        "replay.aggregate.complete_catch_up.v1",
        "replay.aggregate.continue_live.v1",
        "replay.aggregate.sse.v1",
        "runtime.operational-telemetry.v1",
        "approval.control.v1",
        "project.list.v1",
        "project.get.v1",
        "project.create.v1",
        "project.archive.v1",
        "project.rename.v1",
        "project.restore.v1",
        "project.delete.v1",
        "workspace.list.v1",
        "workspace.get.v1",
        "workspace.create.v1",
        "workspace.open.v1",
        "workspace.bind_root.v3",
        "workspace.files.read.v1",
        "workspace.changes.read.v1",
        "workspace.editor.open.v1",
    ]);
    assert_eq!(bundle["publishedCapabilities"], expected_capabilities);
    let mut expected_catalog = expected_capabilities.as_array().unwrap().clone();
    expected_catalog.push(serde_json::json!("provider.credential-enrollment.v2"));
    assert_eq!(bundle["capabilityCatalog"], serde_json::Value::Array(expected_catalog));
    assert!(
        !bundle
            .as_object()
            .unwrap()
            .keys()
            .any(|key| key.to_ascii_lowercase().contains("commit"))
    );

    check_ui_contract(output.path()).unwrap();
    let openapi_path = output.path().join("openapi.json");
    let replacement = b"{\"changed\":true}\n";
    fs::write(&openapi_path, replacement).unwrap();
    assert!(check_ui_contract(output.path()).is_err());
    assert_eq!(fs::read(openapi_path).unwrap(), replacement);

    generate_ui_contract(output.path()).unwrap();
    let stale_path = output.path().join("golden/stale.json");
    fs::write(&stale_path, b"{}\n").unwrap();
    assert!(check_ui_contract(output.path()).is_err());
    assert_eq!(fs::read(stale_path).unwrap(), b"{}\n");
}

#[test]
fn operational_telemetry_contract_is_closed_safe_and_advertised() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();
    assert!(RUNTIME_CAPABILITY_CATALOG.contains(&"runtime.operational-telemetry.v1"));
    assert!(GENERATED_ARTIFACT_PATHS.contains(&"golden/operational-telemetry.json"));
    assert!(GENERATED_ARTIFACT_PATHS.contains(&"schemas/operational-telemetry-v1.schema.json"));

    let schema: Value = serde_json::from_slice(
        &fs::read(
            output
                .path()
                .join("schemas/operational-telemetry-v1.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        schema["properties"]["schemaVersion"],
        serde_json::json!({"const": 1, "type": "integer"})
    );
    assert_eq!(schema["properties"]["launchGeneration"]["minimum"], 1);
    assert_eq!(
        schema["properties"]["launchGeneration"]["maximum"],
        u64::MAX
    );
    assert_eq!(schema["properties"]["durable"]["$ref"], "#/$defs/durable");
    assert_eq!(
        schema["$defs"]["sectionMeta"]["properties"]["freshness"]["enum"],
        serde_json::json!(["observed_in_current_cycle", "unavailable"])
    );
    assert_eq!(
        schema["$defs"]["recoveryTransient"]["properties"]["status"]["enum"],
        serde_json::json!([
            "lower_bound_since_launch",
            "truncated_lower_bound_since_launch",
            "unavailable"
        ])
    );
    assert_all_schema_objects_are_closed(&schema);

    let golden: Value = serde_json::from_slice(
        &fs::read(output.path().join("golden/operational-telemetry.json")).unwrap(),
    )
    .unwrap();
    assert_safe_telemetry_golden(&golden);
    assert!(
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap()
            .is_valid(&golden)
    );

    let openapi: Value =
        serde_json::from_slice(&fs::read(output.path().join("openapi.json")).unwrap()).unwrap();
    let responses = &openapi["paths"]["/v1/runtime/operational-telemetry"]["get"]["responses"];
    assert_eq!(
        responses["200"]["content"]["application/json"]["schema"]["$ref"],
        "schemas/operational-telemetry-v1.schema.json"
    );
    for status in ["200", "400", "401", "405", "413", "503"] {
        assert_eq!(
            responses[status]["headers"]["Cache-Control"]["schema"]["const"],
            "no-store"
        );
    }
}

fn assert_all_schema_objects_are_closed(value: &Value) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".to_owned())) {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false))
                );
            }
            for nested in object.values() {
                assert_all_schema_objects_are_closed(nested);
            }
        }
        Value::Array(values) => values.iter().for_each(assert_all_schema_objects_are_closed),
        _ => {}
    }
}

fn assert_safe_telemetry_golden(value: &Value) {
    match value {
        Value::Object(object) => object.values().for_each(assert_safe_telemetry_golden),
        Value::Array(values) => values.iter().for_each(assert_safe_telemetry_golden),
        Value::String(value) => assert!(matches!(
            value.as_str(),
            "observed_in_current_cycle"
                | "unavailable"
                | "complete"
                | "partial"
                | "lower_bound_since_launch"
                | "truncated_lower_bound_since_launch"
        )),
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}
