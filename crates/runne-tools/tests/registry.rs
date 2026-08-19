use runne_tools::{
    RegisterToolOutcome, SandboxProfile, ToolClass, ToolDefinition, ToolId, ToolRef, ToolRegistry,
    ToolRegistryError, ToolVersion,
};

fn definition(version: &str) -> ToolDefinition {
    ToolDefinition::new(
        ToolId::new("process.exec").unwrap(),
        ToolVersion::new(version).unwrap(),
        ToolClass::BuiltInProcess,
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["executable", "argv"],
            "properties": {
                "executable": {"type": "string", "minLength": 1},
                "argv": {
                    "type": "array",
                    "maxItems": 64,
                    "items": {"type": "string"}
                }
            }
        }),
        SandboxProfile::ProcessRestricted,
    )
    .unwrap()
}

#[test]
fn registry_rejects_duplicate_exact_version_and_resolves_explicit_version() {
    let mut registry = ToolRegistry::new();
    let v1 = definition("1.0.0");

    assert_eq!(
        registry.register(v1.clone()).unwrap(),
        RegisterToolOutcome::Registered
    );
    assert_eq!(
        registry.register(v1.clone()),
        Err(ToolRegistryError::DuplicateTool(v1.tool_ref().clone()))
    );
    assert_eq!(registry.resolve(v1.tool_ref()).unwrap(), &v1);
}

#[test]
fn snapshot_pins_latest_versions_and_does_not_change_after_registration() {
    let mut registry = ToolRegistry::new();
    registry.register(definition("1.0.0")).unwrap();
    let snapshot = registry
        .snapshot(&[ToolId::new("process.exec").unwrap()])
        .unwrap();

    registry.register(definition("2.0.0")).unwrap();

    assert_eq!(
        snapshot.tool_refs(),
        &[ToolRef::new(
            ToolId::new("process.exec").unwrap(),
            ToolVersion::new("1.0.0").unwrap(),
        )]
    );
    assert_eq!(
        registry
            .snapshot(&[ToolId::new("process.exec").unwrap()])
            .unwrap()
            .tool_refs(),
        &[ToolRef::new(
            ToolId::new("process.exec").unwrap(),
            ToolVersion::new("2.0.0").unwrap(),
        )]
    );
}

#[test]
fn definition_rejects_invalid_or_oversized_schema() {
    assert!(
        ToolDefinition::new(
            ToolId::new("invalid").unwrap(),
            ToolVersion::new("1.0.0").unwrap(),
            ToolClass::BuiltInProcess,
            serde_json::json!({"type": 7}),
            SandboxProfile::ProcessRestricted,
        )
        .is_err()
    );
    assert!(
        ToolDefinition::new(
            ToolId::new("oversized").unwrap(),
            ToolVersion::new("1.0.0").unwrap(),
            ToolClass::BuiltInProcess,
            serde_json::json!({"description": "x".repeat(65_536)}),
            SandboxProfile::ProcessRestricted,
        )
        .is_err()
    );
}

#[test]
fn input_is_validated_against_the_exact_snapshot_definition() {
    let mut registry = ToolRegistry::new();
    let tool = definition("1.0.0");
    let tool_ref = tool.tool_ref().clone();
    registry.register(tool).unwrap();

    registry
        .validate_input(
            &tool_ref,
            &serde_json::json!({"executable": "/usr/bin/git", "argv": ["status"]}),
        )
        .unwrap();
    assert_eq!(
        registry.validate_input(
            &tool_ref,
            &serde_json::json!({"executable": "/usr/bin/git", "argv": [], "shell": true}),
        ),
        Err(ToolRegistryError::InputSchemaMismatch)
    );
}

#[test]
fn bounded_identifiers_and_versions_reject_ambiguous_values() {
    assert!(ToolId::new("").is_err());
    assert!(ToolId::new("x".repeat(129)).is_err());
    assert!(ToolVersion::new("latest").is_err());
    assert!(ToolVersion::new("1.0").is_err());
    assert!(ToolVersion::new("1.0.0-alpha").is_err());
}
