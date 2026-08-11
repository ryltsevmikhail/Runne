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

#[test]
fn page_cursor_schema_matches_the_public_uuidv7_codecs() {
    let output = tempfile::tempdir().unwrap();
    let (schema, golden, _) = generated_project_workspace(output.path());
    let validator = project_workspace_validator(&schema);
    let principal = gocode_api::ApiPrincipalId::new("owner").unwrap();
    let project = "018f47a2-4f8c-7b52-8c35-7a3a14c2d901".parse().unwrap();
    let workspace = "018f47a2-4f8c-7b52-8c35-7a3a14c2d801".parse().unwrap();
    let cursors = [
        (
            "projectPage",
            gocode_api::ProjectPageCursor::new(principal.clone(), project)
                .unwrap()
                .encode_token(),
        ),
        (
            "workspacePage",
            gocode_api::WorkspacePageCursor::new(principal, project, workspace)
                .unwrap()
                .encode_token(),
        ),
    ];
    for (page, token) in cursors {
        let codec_valid = if page == "projectPage" {
            gocode_api::ProjectPageCursor::decode_token(&token).is_ok()
        } else {
            gocode_api::WorkspacePageCursor::decode_token(&token).is_ok()
        };
        assert!(codec_valid);
        let mut fixture = golden.clone();
        fixture[page]["nextCursor"] = Value::String(token.clone());
        assert!(validator.is_valid(&fixture));
        for invalid in cursor_invalid_corpus(&token, page == "workspacePage") {
            let codec_valid = if page == "projectPage" {
                gocode_api::ProjectPageCursor::decode_token(&invalid).is_ok()
            } else {
                gocode_api::WorkspacePageCursor::decode_token(&invalid).is_ok()
            };
            assert!(!codec_valid, "public codec accepted {invalid}");
            fixture[page]["nextCursor"] = Value::String(invalid.clone());
            assert!(!validator.is_valid(&fixture), "schema accepted {invalid}");
        }
    }
}

fn cursor_invalid_corpus(token: &str, workspace: bool) -> Vec<String> {
    let (prefix, payload) = token.split_once('.').unwrap();
    let mut wrong_version = payload.to_owned();
    wrong_version.replace_range(64 + 12..64 + 13, "6");
    let mut wrong_variant = payload.to_owned();
    wrong_variant.replace_range(64 + 16..64 + 17, "7");
    let mut corpus = vec![
        format!("{prefix}.{}", "0".repeat(payload.len())),
        format!("{prefix}.{}", "a".repeat(payload.len())),
        format!("{prefix}.{wrong_version}"),
        format!("{prefix}.{wrong_variant}"),
    ];
    if workspace {
        let mut wrong_version = payload.to_owned();
        wrong_version.replace_range(96 + 12..96 + 13, "6");
        let mut wrong_variant = payload.to_owned();
        wrong_variant.replace_range(96 + 16..96 + 17, "7");
        corpus.extend([
            format!("{prefix}.{wrong_version}"),
            format!("{prefix}.{wrong_variant}"),
        ]);
    }
    corpus
}

fn assert_canonical_root_token(validator: &JSONSchema, golden: &Value, encoded: &str) {
    let token = format!("gocode-root-admission-v2.{encoded}");
    let admission = gocode_api::RootHandleAdmission::decode_token(&token).unwrap();
    assert_eq!(admission.encode_token().unwrap(), token);
    let mut fixture = golden.clone();
    fixture["rootBind"]["rootAdmission"] = Value::String(token);
    assert!(validator.is_valid(&fixture));
}
