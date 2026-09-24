#[test]
fn prompted_submit_profile_is_deterministic_additive_and_schema_valid() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    generate_ui_contract_v3(first.path()).unwrap();
    generate_ui_contract_v3(second.path()).unwrap();
    let expected = GENERATED_ARTIFACT_PATHS_V3
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    assert_eq!(generated_files(first.path()), expected);
    assert_eq!(generated_files(second.path()), expected);
    for path in &expected {
        assert_eq!(
            fs::read(first.path().join(path)).unwrap(),
            fs::read(second.path().join(path)).unwrap()
        );
    }

    let bundle: Value =
        serde_json::from_slice(&fs::read(first.path().join("bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["apiProfileId"], "gocode-ui-client/3");
    let capabilities = bundle["publishedCapabilities"].as_array().unwrap();
    assert!(
        capabilities
            .iter()
            .any(|value| value == "task_run.submit.v1")
    );
    assert!(
        capabilities
            .iter()
            .any(|value| value == "task_run.submit.v2")
    );

    let openapi: Value =
        serde_json::from_slice(&fs::read(first.path().join("openapi.json")).unwrap()).unwrap();
    assert!(openapi["paths"].get("/v1/task-runs/submit").is_some());
    assert!(openapi["paths"].get("/v2/task-runs/submit").is_some());
    let schema: Value = serde_json::from_slice(
        &fs::read(first.path().join("schemas/task-run-v2.schema.json")).unwrap(),
    )
    .unwrap();
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let request_schema = &schema["$defs"]["submitRequest"];
    let required = request_schema["required"].as_array().unwrap();
    assert!(required.iter().any(|value| value == "prompt"));
    assert_eq!(
        request_schema["properties"]["prompt"]["x-gocode-maxUtf8Bytes"],
        65_536
    );
    assert_eq!(request_schema["properties"]["prompt"]["pattern"], "\\S");
}

#[test]
fn checked_in_profile_three_matches_generator() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/gocode-ui-client-3");
    check_ui_contract_v3(&root).unwrap();
}
