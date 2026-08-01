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
    assert_eq!(bundle["apiProfileId"], "gocode-ui-client/1");
    assert_eq!(bundle["transportProfileId"], "gocode-local-runtime/2");
    assert_eq!(
        bundle["publishedCapabilities"],
        serde_json::json!(PUBLISHED_RUNTIME_CAPABILITIES)
    );
    assert_eq!(
        bundle["capabilityCatalog"],
        serde_json::json!(RUNTIME_CAPABILITY_CATALOG)
    );
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
