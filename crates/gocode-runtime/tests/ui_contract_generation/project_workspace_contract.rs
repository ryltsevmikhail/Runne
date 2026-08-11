fn generated_project_workspace(output: &Path) -> (Value, Value, Value) {
    generate_ui_contract(output).unwrap();
    let schema = serde_json::from_slice(
        &fs::read(output.join("schemas/project-workspace-v1.schema.json")).unwrap(),
    )
    .unwrap();
    let golden =
        serde_json::from_slice(&fs::read(output.join("golden/project-workspace.json")).unwrap())
            .unwrap();
    let openapi = serde_json::from_slice(&fs::read(output.join("openapi.json")).unwrap()).unwrap();
    (schema, golden, openapi)
}

fn project_workspace_validator(schema: &Value) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .expect("ProjectWorkspace schema compiles")
}

#[test]
fn project_workspace_schema_compiles_and_validates_its_root_golden() {
    let output = tempfile::tempdir().unwrap();
    let (schema, golden, _) = generated_project_workspace(output.path());
    assert!(project_workspace_validator(&schema).is_valid(&golden));
}

#[test]
fn display_name_schema_matches_domain_character_policy_and_utf8_annotation() {
    let output = tempfile::tempdir().unwrap();
    let (schema, golden, _) = generated_project_workspace(output.path());
    let validator = project_workspace_validator(&schema);
    let name_schema = &schema["$defs"]["project"]["properties"]["displayName"];
    assert_eq!(name_schema["x-gocode-maxUtf8Bytes"], 256);

    let mut corpus = vec!["Name".to_owned(), "x".repeat(256), "🙂".repeat(64)];
    for (start, end) in [
        (0x00, 0x1f),
        (0x7f, 0x9f),
        (0xad, 0xad),
        (0x600, 0x605),
        (0x61c, 0x61c),
        (0x6dd, 0x6dd),
        (0x70f, 0x70f),
        (0x890, 0x891),
        (0x8e2, 0x8e2),
        (0x180e, 0x180e),
        (0x200b, 0x200f),
        (0x202a, 0x202e),
        (0x2060, 0x2064),
        (0x2066, 0x206f),
        (0xfeff, 0xfeff),
        (0xfff9, 0xfffb),
        (0x110bd, 0x110bd),
        (0x110cd, 0x110cd),
        (0x13430, 0x1343f),
        (0x1bca0, 0x1bca3),
        (0x1d173, 0x1d17a),
        (0xe0001, 0xe0001),
        (0xe0020, 0xe007f),
    ] {
        corpus.extend((start..=end).map(|value| format!("a{}b", char::from_u32(value).unwrap())));
    }
    corpus.push("x".repeat(257));
    corpus.push("🙂".repeat(65));

    for name in corpus {
        let domain =
            gocode_domain::project_workspace::ProjectWorkspaceDisplayName::new(name.clone())
                .is_ok();
        let mut fixture = golden.clone();
        fixture["project"]["displayName"] = Value::String(name.clone());
        let schema_contract = validator.is_valid(&fixture) && name.len() <= 256;
        assert_eq!(
            schema_contract, domain,
            "display-name mismatch for {name:?}"
        );
    }
}

#[test]
fn root_admission_schema_matches_canonical_unpadded_codec_boundaries() {
    let output = tempfile::tempdir().unwrap();
    let (schema, golden, _) = generated_project_workspace(output.path());
    let validator = project_workspace_validator(&schema);
    for bytes in [1_usize, 2, 3, 4093, 4094, 4095, 4096] {
        let encoded_len = (bytes * 4).div_ceil(3);
        let token = format!("gocode-root-admission-v2.{}", "A".repeat(encoded_len));
        let admission = gocode_api::RootHandleAdmission::decode_token(&token).unwrap();
        assert_eq!(admission.encode_token().unwrap(), token);
        let mut fixture = golden.clone();
        fixture["rootBind"]["rootAdmission"] = Value::String(token);
        assert!(
            validator.is_valid(&fixture),
            "codec boundary {bytes} rejected"
        );
    }
    for suffix in ["AA", "AQ", "Ag", "Aw"] {
        assert_canonical_root_token(&validator, &golden, suffix);
    }
    for last in "AEIMQUYcgkosw048".chars() {
        assert_canonical_root_token(&validator, &golden, &format!("AA{last}"));
    }
    for token in [
        "gocode-root-admission-v2.AB",
        "gocode-root-admission-v2.AAB",
        "gocode-root-admission-v2.A",
        "gocode-root-admission-v2.AAAA=",
    ] {
        assert!(gocode_api::RootHandleAdmission::decode_token(token).is_err());
        let mut fixture = golden.clone();
        fixture["rootBind"]["rootAdmission"] = Value::String(token.to_owned());
        assert!(
            !validator.is_valid(&fixture),
            "noncanonical token accepted: {token}"
        );
    }
}

fn assert_canonical_root_token(validator: &JSONSchema, golden: &Value, encoded: &str) {
    let token = format!("gocode-root-admission-v2.{encoded}");
    let admission = gocode_api::RootHandleAdmission::decode_token(&token).unwrap();
    assert_eq!(admission.encode_token().unwrap(), token);
    let mut fixture = golden.clone();
    fixture["rootBind"]["rootAdmission"] = Value::String(token);
    assert!(validator.is_valid(&fixture));
}
