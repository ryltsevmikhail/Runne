#[test]
fn generation_is_deterministic_and_every_json_artifact_is_canonical() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    generate_ui_contract(first.path()).unwrap();
    generate_ui_contract(second.path()).unwrap();

    let expected = GENERATED_ARTIFACT_PATHS
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let first_files = generated_files(first.path());
    assert_eq!(first_files, expected);
    assert_eq!(generated_files(second.path()), expected);

    for relative_path in first_files {
        let first_bytes = fs::read(first.path().join(&relative_path)).unwrap();
        let second_bytes = fs::read(second.path().join(&relative_path)).unwrap();
        assert_eq!(first_bytes, second_bytes, "{}", relative_path.display());
        assert_eq!(
            first_bytes.last(),
            Some(&b'\n'),
            "{}",
            relative_path.display()
        );
        assert!(
            !first_bytes.ends_with(b"\n\n"),
            "{} has more than one trailing newline",
            relative_path.display()
        );
        if relative_path
            .extension()
            .is_some_and(|value| value == "json")
        {
            let value: Value = serde_json::from_slice(&first_bytes).unwrap();
            assert_sorted_json(&value);
        }
    }
}

#[test]
fn schemas_compile_goldens_validate_and_openapi_refs_resolve_locally() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();

    for path in [
        "schemas/local-runtime-profile-v3.schema.json",
        "schemas/local-session-v2.schema.json",
        "schemas/replay-v1.schema.json",
        "schemas/sse-v1.schema.json",
        "schemas/task-run-v1.schema.json",
    ] {
        let schema: Value =
            serde_json::from_slice(&fs::read(output.path().join(path)).unwrap()).unwrap();
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{path} did not compile: {error}"));
    }

    for (schema_path, golden_path) in [
        (
            "schemas/local-session-v2.schema.json",
            "golden/local-session-v2.json",
        ),
        (
            "schemas/replay-v1.schema.json",
            "golden/replay-conversation.json",
        ),
        (
            "schemas/replay-v1.schema.json",
            "golden/replay-taskrun.json",
        ),
        ("schemas/sse-v1.schema.json", "golden/sse-delivery.json"),
    ] {
        let schema: Value =
            serde_json::from_slice(&fs::read(output.path().join(schema_path)).unwrap()).unwrap();
        let validator = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let golden: Value =
            serde_json::from_slice(&fs::read(output.path().join(golden_path)).unwrap()).unwrap();
        assert!(
            validator.is_valid(&golden),
            "{golden_path} does not validate against {schema_path}"
        );
    }

    let openapi_path = output.path().join("openapi.json");
    let openapi: Value = serde_json::from_slice(&fs::read(&openapi_path).unwrap()).unwrap();
    assert_eq!(openapi["openapi"], "3.1.0");
    assert_local_refs_resolve(&openapi_path, &openapi);

    for golden_path in [
        "golden/replay-conversation.json",
        "golden/replay-taskrun.json",
    ] {
        let golden: Value =
            serde_json::from_slice(&fs::read(output.path().join(golden_path)).unwrap()).unwrap();
        assert!(
            golden["integrityDigest"].as_str().is_some(),
            "{golden_path}"
        );
        assert!(
            golden["replayBindingId"].as_str().is_some(),
            "{golden_path}"
        );
    }
    let sse: Value =
        serde_json::from_slice(&fs::read(output.path().join("golden/sse-delivery.json")).unwrap())
            .unwrap();
    assert!(sse["canonicalEvent"]["integrityDigest"].as_str().is_some());
    assert!(sse["canonicalEvent"]["replayBindingId"].as_str().is_some());

    let templated_paths = openapi["paths"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(path, _)| path.contains("{sessionId}"))
        .collect::<Vec<_>>();
    assert_eq!(templated_paths.len(), 6);
    for (path, path_item) in templated_paths {
        for operation in path_item.as_object().unwrap().values() {
            let parameters = operation["parameters"]
                .as_array()
                .unwrap_or_else(|| panic!("{path} operation omitted required path parameters"));
            assert!(parameters.iter().any(|parameter| {
                parameter["in"] == "path"
                    && parameter["name"] == "sessionId"
                    && parameter["required"] == true
            }));
        }
    }
}

#[test]
fn local_runtime_profile_schema_accepts_only_base_or_protected_capabilities() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(
            output
                .path()
                .join("schemas/local-runtime-profile-v3.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let profile = |capabilities: &[&str]| {
        serde_json::json!({
            "authorityId": "018f2e3a700070008000000000000001",
            "bootstrapSecretPath": "/tmp/bootstrap.secret",
            "capabilities": capabilities,
            "capabilityDigest": "00".repeat(32),
            "certificateDerBase64": "AA",
            "certificateSha256": "00".repeat(32),
            "daemonInstanceId": "018f2e3a-7000-7000-8000-000000000002",
            "endpoint": "https://127.0.0.1:43123",
            "eventLogLineageId": "018f2e3a-7000-7000-8000-000000000003",
            "executableSha256": "00".repeat(32),
            "launchAuthorityId": "00".repeat(16),
            "launchGeneration": 1,
            "principalId": "local-owner",
            "profileId": "gocode-ui-client/2",
            "schemaHash": "00".repeat(32),
            "schemaVersion": 3,
            "sessionId": "00".repeat(16),
            "transportProfileId": "gocode-local-runtime/2",
        })
    };
    assert!(validator.is_valid(&profile(BASE_RUNTIME_CAPABILITIES)));
    assert!(validator.is_valid(&profile(PUBLISHED_RUNTIME_CAPABILITIES)));
    assert!(!validator.is_valid(&profile(&BASE_RUNTIME_CAPABILITIES[..20])));
    let mut reordered = BASE_RUNTIME_CAPABILITIES.to_vec();
    reordered.swap(0, 1);
    assert!(!validator.is_valid(&profile(&reordered)));
    let mut extra = BASE_RUNTIME_CAPABILITIES.to_vec();
    extra.push("unsupported.capability.v1");
    assert!(!validator.is_valid(&profile(&extra)));
}
