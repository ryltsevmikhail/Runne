fn generated_project_workspace_openapi(output: &Path) -> Value {
    generate_ui_contract(output).unwrap();
    serde_json::from_slice(&fs::read(output.join("openapi.json")).unwrap()).unwrap()
}

#[test]
fn project_workspace_openapi_is_structurally_exact_for_all_operations() {
    let output = tempfile::tempdir().unwrap();
    let openapi = generated_project_workspace_openapi(output.path());
    assert_eq!(openapi["openapi"], "3.1.0");
    assert!(openapi["paths"].is_object());
    let read = [
        "200", "400", "401", "404", "405", "409", "413", "500", "503",
    ];
    let mutation = [
        "202", "400", "401", "404", "405", "409", "413", "500", "503",
    ];
    let matrix = [
        ("get", "/v1/projects", "projectPage", None),
        ("post", "/v1/projects", "projectAck", Some("projectCreate")),
        ("get", "/v1/projects/{projectId}", "project", None),
        (
            "delete",
            "/v1/projects/{projectId}",
            "projectAck",
            Some("existing"),
        ),
        (
            "post",
            "/v1/projects/{projectId}/archive",
            "projectAck",
            Some("existing"),
        ),
        (
            "post",
            "/v1/projects/{projectId}/restore",
            "projectAck",
            Some("existing"),
        ),
        (
            "get",
            "/v1/projects/{projectId}/workspaces",
            "workspacePage",
            None,
        ),
        (
            "post",
            "/v1/projects/{projectId}/workspaces",
            "workspaceAck",
            Some("workspaceCreate"),
        ),
        ("get", "/v1/workspaces/{workspaceId}", "workspace", None),
        (
            "post",
            "/v1/workspaces/{workspaceId}/open",
            "workspaceAck",
            Some("existing"),
        ),
        (
            "post",
            "/v1/workspaces/{workspaceId}/root-bindings",
            "workspaceAck",
            Some("rootBind"),
        ),
    ];
    for (method, path, success, request) in matrix {
        let operation = &openapi["paths"][path][method];
        assert!(operation.is_object(), "missing {method} {path}");
        let expected_statuses = if request.is_some() { &mutation } else { &read };
        let statuses = operation["responses"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            statuses, expected_statuses,
            "wrong statuses for {method} {path}"
        );
        let success_status = if request.is_some() { "202" } else { "200" };
        assert_eq!(
            operation["responses"][success_status]["content"]["application/json"]["schema"]["$ref"],
            format!("schemas/project-workspace-v1.schema.json#/$defs/{success}")
        );
        if let Some(request) = request {
            assert_eq!(operation["requestBody"]["x-gocode-maxBodyBytes"], 16384);
            assert_eq!(
                operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
                format!("schemas/project-workspace-v1.schema.json#/$defs/{request}")
            );
            let names = operation["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .map(|parameter| parameter["name"].as_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(names, ["X-Command-Id", "Idempotency-Key"]);
        }
        for status in expected_statuses {
            assert_eq!(
                operation["responses"][status]["headers"]["X-Request-Id"]["required"],
                true
            );
        }
        assert_template_parameters(path, &openapi["paths"][path], operation);
    }
    let operations = openapi["paths"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(path, _)| path.starts_with("/v1/projects") || path.starts_with("/v1/workspaces"))
        .flat_map(|(_, item)| item.as_object().unwrap().iter())
        .filter(|(key, _)| matches!(key.as_str(), "get" | "post" | "delete"))
        .count();
    assert_eq!(operations, 11);
}

fn assert_template_parameters(path: &str, path_item: &Value, operation: &Value) {
    for variable in ["projectId", "workspaceId"] {
        let expected = path.contains(&format!("{{{variable}}}"));
        let present = path_item["parameters"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(operation["parameters"].as_array().into_iter().flatten())
            .any(|parameter| {
                parameter["in"] == "path"
                    && parameter["name"] == variable
                    && parameter["required"] == true
            });
        assert_eq!(present, expected, "{path} variable {variable}");
    }
}

#[test]
fn openapi_cursor_and_idempotency_parameters_are_exact_wire_languages() {
    let output = tempfile::tempdir().unwrap();
    let openapi = generated_project_workspace_openapi(output.path());
    for (path, prefix, hex, length) in [
        ("/v1/projects", "gocode-project-page-v1", 96, 119),
        (
            "/v1/projects/{projectId}/workspaces",
            "gocode-workspace-page-v1",
            128,
            153,
        ),
    ] {
        let parameters = openapi["paths"][path]["get"]["parameters"]
            .as_array()
            .unwrap();
        let cursor = parameters
            .iter()
            .find(|item| item["name"] == "cursor")
            .unwrap();
        assert_eq!(cursor["schema"]["minLength"], length);
        assert_eq!(cursor["schema"]["maxLength"], length);
        assert_eq!(
            cursor["schema"]["pattern"],
            format!("^{prefix}\\.[0-9a-f]{{{hex}}}$")
        );
        let cursor_validator = JSONSchema::options().compile(&cursor["schema"]).unwrap();
        assert!(cursor_validator.is_valid(&Value::String(format!("{prefix}.{}", "a".repeat(hex)))));
        for invalid in [
            format!("{prefix}.{}", "a".repeat(hex - 1)),
            format!("{prefix}.{}", "a".repeat(hex + 1)),
            format!("{prefix}.{}A", "a".repeat(hex - 1)),
            format!("wrong.{}", "a".repeat(hex)),
        ] {
            assert!(!cursor_validator.is_valid(&Value::String(invalid)));
        }
    }
    for path in ["/v1/projects", "/v1/workspaces/{workspaceId}/open"] {
        let parameters = openapi["paths"][path]["post"]["parameters"]
            .as_array()
            .unwrap();
        let key = parameters
            .iter()
            .find(|item| item["name"] == "Idempotency-Key")
            .unwrap();
        assert_eq!(key["schema"]["pattern"], "^[\\u0020-\\u007e]+$");
        assert_eq!(key["schema"]["x-gocode-maxUtf8Bytes"], 256);
        let key_validator = JSONSchema::options().compile(&key["schema"]).unwrap();
        for valid in [" ".to_owned(), "~".to_owned(), "x".repeat(256)] {
            assert!(key_validator.is_valid(&Value::String(valid)));
        }
        for invalid in [
            "\t".to_owned(),
            "\u{7f}".to_owned(),
            "é".to_owned(),
            "x".repeat(257),
        ] {
            assert!(!key_validator.is_valid(&Value::String(invalid)));
        }
    }
}
