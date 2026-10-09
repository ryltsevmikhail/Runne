/// Profile 3 adds prompted TaskRun submission while preserving the v1
/// submit operation for clients that still need it.
pub const GENERATED_ARTIFACT_PATHS_V3: &[&str] = &[
    "bundle.json",
    "bundle.sha256",
    "golden/local-session-v2.json",
    "golden/operational-telemetry.json",
    "golden/project-workspace.json",
    "golden/provider-credential-enrollment-v2.json",
    "golden/replay-conversation.json",
    "golden/replay-resume-v2.json",
    "golden/replay-retention-gap-v2.json",
    "golden/replay-retention-gap.json",
    "golden/replay-taskrun.json",
    "golden/sse-delivery.json",
    "golden/workspace-diffs.json",
    "golden/workspace-files.json",
    "openapi.json",
    "schemas/approval-v1.schema.json",
    "schemas/local-runtime-profile-v3.schema.json",
    "schemas/local-session-v2.schema.json",
    "schemas/operational-telemetry-v1.schema.json",
    "schemas/project-workspace-v2.schema.json",
    "schemas/provider-credential-enrollment-v2.schema.json",
    "schemas/provider-credentials-v1.schema.json",
    "schemas/replay-v1.schema.json",
    "schemas/sse-v1.schema.json",
    "schemas/task-run-v1.schema.json",
    "schemas/task-run-v2.schema.json",
    "schemas/workspace-diffs-v1.schema.json",
    "schemas/workspace-editor-v1.schema.json",
    "schemas/workspace-files-v1.schema.json",
];

const TASK_RUN_PROMPT_MAX_UTF8_BYTES: usize = runne_api::MAX_TASK_RUN_PROMPT_BYTES;

/// Writes the deterministic prompted-submit profile under `output`.
pub fn generate_ui_contract_v3(output: &Path) -> Result<(), ContractGenerationError> {
    write_artifacts(output, generated_artifacts_v3()?)
}

/// Verifies the checked-in profile 3 artifacts without modifying them.
pub fn check_ui_contract_v3(target: &Path) -> Result<(), ContractGenerationError> {
    check_generated_artifacts(target, GENERATED_ARTIFACT_PATHS_V3, generate_ui_contract_v3)
}

fn generated_artifacts_v3() -> Result<BTreeMap<&'static str, Vec<u8>>, ContractGenerationError> {
    let mut artifacts = generated_artifacts()?;
    let base_bundle: Value =
        serde_json::from_slice(artifacts.get("bundle.json").expect("v2 bundle exists"))?;
    artifacts.remove("bundle.json");
    artifacts.remove("bundle.sha256");

    let v2_task_schema: Value = serde_json::from_slice(
        artifacts
            .get("schemas/task-run-v1.schema.json")
            .expect("v1 schema exists"),
    )?;
    artifacts.insert(
        "schemas/task-run-v2.schema.json",
        canonical_json(&prompted_task_run_schema(v2_task_schema)?)?,
    );
    artifacts.insert(
        "openapi.json",
        canonical_json(&prompted_openapi(serde_json::from_slice(
            artifacts.get("openapi.json").expect("OpenAPI exists"),
        )?)?)?,
    );
    artifacts.insert(
        "schemas/approval-v1.schema.json",
        canonical_json(&approval_schema_v3(serde_json::from_slice(
            artifacts
                .get("schemas/approval-v1.schema.json")
                .expect("approval schema exists"),
        )?)?)?,
    );
    artifacts.insert(
        "schemas/local-runtime-profile-v3.schema.json",
        canonical_json(&profile_schema_v3(serde_json::from_slice(
            artifacts
                .get("schemas/local-runtime-profile-v3.schema.json")
                .expect("profile schema exists"),
        )?)?)?,
    );

    let mut capability_catalog = capability_values(&base_bundle, "capabilityCatalog");
    insert_after(
        &mut capability_catalog,
        "task_run.submit.v1",
        "task_run.submit.v2",
    );
    let mut published_capabilities = capability_values(&base_bundle, "publishedCapabilities");
    insert_after(
        &mut published_capabilities,
        "task_run.submit.v1",
        "task_run.submit.v2",
    );
    let artifact_digests = artifacts
        .iter()
        .map(|(path, bytes)| json!({ "path": path, "sha256": hex::encode(Sha256::digest(bytes)) }))
        .collect::<Vec<_>>();
    let bundle = json!({
        "apiProfileId": "gocode-ui-client/3",
        "artifactDigests": artifact_digests,
        "capabilityCatalog": capability_catalog,
        "generatorSchemaVersion": GENERATOR_SCHEMA_VERSION,
        "publishedCapabilities": published_capabilities,
        "transportProfileId": TRANSPORT_PROFILE_ID,
    });
    let bytes = canonical_json(&bundle)?;
    artifacts.insert("bundle.json", bytes.clone());
    artifacts.insert(
        "bundle.sha256",
        format!("{}\n", hex::encode(Sha256::digest(bytes))).into_bytes(),
    );
    Ok(artifacts)
}

fn prompted_task_run_schema(mut schema: Value) -> Result<Value, ContractGenerationError> {
    let submit = schema
        .pointer_mut("/$defs/submitRequest")
        .expect("submitRequest exists");
    let properties = submit
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("submitRequest properties exist");
    properties.insert(
        "prompt".into(),
        json!({
            "description": "Required nonblank task prompt, limited to 65,536 UTF-8 bytes.",
            "maxLength": TASK_RUN_PROMPT_MAX_UTF8_BYTES,
            "minLength": 1,
            "pattern": "\\S",
            "type": "string",
            "x-gocode-maxUtf8Bytes": TASK_RUN_PROMPT_MAX_UTF8_BYTES,
        }),
    );
    submit
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .expect("submitRequest required exists")
        .push(json!("prompt"));
    schema["$id"] = json!("gocode://schemas/task-run-v2");
    schema["title"] = json!("TaskRun Snapshot V2");
    Ok(schema)
}

fn prompted_openapi(mut document: Value) -> Result<Value, ContractGenerationError> {
    let paths = document
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .expect("OpenAPI paths exist");
    let mut operation = paths
        .get("/v1/task-runs/submit")
        .expect("v1 submit route exists")
        .clone();
    let body = operation
        .pointer_mut("/post/requestBody")
        .expect("submit body exists");
    body["x-gocode-maxPromptUtf8Bytes"] = json!(TASK_RUN_PROMPT_MAX_UTF8_BYTES);
    body["content"]["application/json"]["schema"]["$ref"] =
        json!("schemas/task-run-v2.schema.json#/$defs/submitRequest");
    paths.insert("/v2/task-runs/submit".into(), operation);
    document["info"]["version"] = json!("3.0.0");
    Ok(document)
}

fn approval_schema_v3(mut schema: Value) -> Result<Value, ContractGenerationError> {
    let approval = schema
        .pointer_mut("/$defs/approval")
        .expect("approval definition exists");
    approval
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("approval properties exist")
        .insert(
            "approvalGeneration".into(),
            json!({"minimum": 1, "type": "integer"}),
        );
    approval
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .expect("approval required fields exist")
        .push(json!("approvalGeneration"));
    Ok(schema)
}

fn profile_schema_v3(mut schema: Value) -> Result<Value, ContractGenerationError> {
    schema["properties"]["profileId"]["const"] = json!("gocode-ui-client/3");
    let choices = schema
        .pointer_mut("/properties/capabilities/oneOf")
        .and_then(Value::as_array_mut)
        .expect("capability variants exist");
    for choice in choices {
        let new_length = {
            let prefix = choice
                .get_mut("prefixItems")
                .and_then(Value::as_array_mut)
                .expect("capability tuple prefix exists");
            let contains_submit_v1 = prefix.iter().any(|entry| {
                entry.get("const").and_then(Value::as_str) == Some("task_run.submit.v1")
            });
            if contains_submit_v1 {
                prefix.insert(4, json!({"const": "task_run.submit.v2", "type": "string"}));
                Some(prefix.len())
            } else {
                None
            }
        };
        if let Some(length) = new_length {
            choice["minItems"] = json!(length);
            choice["maxItems"] = json!(length);
        }
    }
    Ok(schema)
}

fn capability_values(bundle: &Value, key: &str) -> Vec<String> {
    bundle[key]
        .as_array()
        .expect("capability list exists")
        .iter()
        .map(|value| value.as_str().expect("capability string").to_owned())
        .collect()
}

fn insert_after(items: &mut Vec<String>, after: &str, value: &str) {
    let index = items
        .iter()
        .position(|item| item == after)
        .expect("v1 capability exists");
    items.insert(index + 1, value.to_owned());
}

fn write_artifacts(
    output: &Path,
    artifacts: BTreeMap<&'static str, Vec<u8>>,
) -> Result<(), ContractGenerationError> {
    for (relative_path, bytes) in artifacts {
        let path = output.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn check_generated_artifacts(
    target: &Path,
    paths: &[&str],
    generate: fn(&Path) -> Result<(), ContractGenerationError>,
) -> Result<(), ContractGenerationError> {
    let temporary = tempfile::tempdir()?;
    generate(temporary.path())?;
    let expected = paths.iter().map(PathBuf::from).collect::<Vec<_>>();
    let mut checked_in = contract_files(target)?;
    checked_in.retain(|path| path != Path::new("package.json"));
    if checked_in != expected {
        return Err(ContractGenerationError::ArtifactSetMismatch);
    }
    for relative in paths {
        if fs::read(temporary.path().join(relative))?
            != fs::read(target.join(relative))
                .map_err(|_| ContractGenerationError::ByteMismatch((*relative).into()))?
        {
            return Err(ContractGenerationError::ByteMismatch((*relative).into()));
        }
    }
    Ok(())
}
