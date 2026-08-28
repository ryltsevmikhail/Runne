#[test]
fn provider_credential_enrollment_contract_is_closed_safe_and_v2_only() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();
    let schema_path = output
        .path()
        .join("schemas/provider-credential-enrollment-v2.schema.json");
    let schema: Value = serde_json::from_slice(&fs::read(&schema_path).unwrap()).unwrap();
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .expect("enrollment schema compiles");
    for definition in [
        "beginRequest",
        "error",
        "operationResponse",
        "resumeRequest",
        "statusResponse",
        "verifyRequest",
    ] {
        assert_eq!(schema["$defs"][definition]["additionalProperties"], false);
    }
    let golden: Value = serde_json::from_slice(
        &fs::read(
            output
                .path()
                .join("golden/provider-credential-enrollment-v2.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(JSONSchema::compile(&schema).unwrap().is_valid(&golden));
    assert_no_secret_keys(&golden);
    assert!(RUNTIME_CAPABILITY_CATALOG.contains(&"provider.credential-enrollment.v2"));
    assert!(!PUBLISHED_RUNTIME_CAPABILITIES.contains(&"provider.credential-enrollment.v2"));

    let openapi: Value =
        serde_json::from_slice(&fs::read(output.path().join("openapi.json")).unwrap()).unwrap();
    let paths = &openapi["paths"];
    assert_operation(
        &paths["/v2/provider-credential-enrollment"]["post"],
        "schemas/provider-credential-enrollment-v2.schema.json#/$defs/beginRequest",
        "202",
    );
    assert_operation(
        &paths["/v2/provider-credential-enrollment/resume"]["post"],
        "schemas/provider-credential-enrollment-v2.schema.json#/$defs/resumeRequest",
        "200",
    );
    assert_operation(
        &paths["/v2/provider-credential-enrollment/verify"]["post"],
        "schemas/provider-credential-enrollment-v2.schema.json#/$defs/verifyRequest",
        "202",
    );
    let status = &paths["/v2/providers/{provider}/credential-enrollment"]["get"];
    assert_eq!(
        status["parameters"][0]["schema"]["enum"],
        serde_json::json!(["openai", "deepseek"])
    );
    assert_eq!(
        status["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "schemas/provider-credential-enrollment-v2.schema.json#/$defs/statusResponse"
    );
}

fn assert_operation(operation: &Value, request_ref: &str, status: &str) {
    assert_eq!(
        operation["security"],
        serde_json::json!([{"sessionAuth": []}])
    );
    assert_eq!(operation["requestBody"]["required"], true);
    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        request_ref
    );
    assert_eq!(
        operation["responses"][status]["content"]["application/json"]["schema"]["$ref"],
        "schemas/provider-credential-enrollment-v2.schema.json#/$defs/operationResponse"
    );
    for error in ["400", "401", "403", "409", "500", "503"] {
        assert_eq!(
            operation["responses"][error]["content"]["application/json"]["schema"]["$ref"],
            "schemas/provider-credential-enrollment-v2.schema.json#/$defs/error"
        );
    }
}

fn assert_no_secret_keys(value: &Value) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                assert!(
                    ![
                        "credential",
                        "ticket",
                        "secret",
                        "path",
                        "releaseDigest",
                        "nativeError"
                    ]
                    .contains(&key.as_str()),
                    "unsafe golden key: {key}"
                );
                assert_no_secret_keys(nested);
            }
        }
        Value::Array(values) => values.iter().for_each(assert_no_secret_keys),
        _ => {}
    }
}
