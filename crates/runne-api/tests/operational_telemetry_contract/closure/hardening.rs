use std::fs;

use super::resolver;

fn resolve_fixture(
    source: &str,
    files: &[(&str, &str)],
) -> Result<std::collections::BTreeSet<String>, String> {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().join("src/root.rs");
    fs::create_dir_all(root.parent().unwrap().join("root")).unwrap();
    fs::write(&root, source).unwrap();
    for (path, contents) in files {
        let path = workspace.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    resolver::resolve_closure(workspace.path(), &["src/root.rs"])
}

#[test]
fn closure_parser_keeps_lifetimes_labels_and_valid_char_literals_outside_modules() {
    let files = resolve_fixture(
        r#"
            const CHARACTER: char = '\u{2764}';
            const BYTE: u8 = b'\x41';
            'label: loop { break 'label; }
            let _: &'a str;
            mod child;
        "#,
        &[("src/root/child.rs", "")],
    )
    .unwrap();

    assert!(files.contains("src/root/child.rs"));
}

#[test]
fn closure_parser_supports_raw_strings_raw_identifiers_and_raw_paths() {
    let files = resolve_fixture(
        r####"
            const RAW: &str = r###"mod hidden;"###;
            let r#module = 0;
            #[path = r#"placed.rs"#]
            mod child;
        "####,
        &[("src/placed.rs", "")],
    )
    .unwrap();

    assert!(files.contains("src/placed.rs"));
}

#[test]
fn closure_parser_skips_expression_macros_in_const_and_function_bodies() {
    let declarations = super::parser::declarations(
        &super::lexer::tokenize(
            r#"
            const DATA: &[u8] = include_bytes!("payload");
            static ALSO_DATA: &[u8] = { include_bytes!("payload") };
            fn render() { let _ = format!("{}", include_str!("payload")); }
            mod child;
        "#,
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(declarations.len(), 1);
    assert_eq!(declarations[0].name, "child");
}

#[test]
fn closure_parser_rejects_item_position_macros() {
    let error = super::parser::declarations(
        &super::lexer::tokenize("emit_modules! { mod hidden; }").unwrap(),
    )
    .unwrap_err();

    assert!(error.contains("unresolved item-position macro"));
    let error =
        super::parser::declarations(&super::lexer::tokenize("include!(\"hidden.rs\");").unwrap())
            .unwrap_err();
    assert!(error.contains("unresolved item-position macro"));
}

#[test]
fn closure_parser_rejects_ambiguous_and_escaped_path_attributes() {
    let cfg_attr = r#"#[cfg_attr(feature = "feature", path = "hidden.rs")] mod child;"#;
    assert!(resolve_fixture(cfg_attr, &[("src/root/hidden.rs", "")]).is_err());

    let escaped = r#"#[path = "child\x2ers"] mod child;"#;
    assert!(resolve_fixture(escaped, &[(r"src/root/child\x2ers", "")]).is_err());
}

#[test]
fn closure_parser_rejects_unterminated_lexical_constructs() {
    for source in [
        "/*",
        "\"unterminated",
        "r##\"unterminated",
        "mod child {",
        "let π = 0;",
    ] {
        assert!(resolve_fixture(source, &[]).is_err(), "{source}");
    }
}

#[test]
fn closure_parser_allows_non_ascii_only_in_literals_and_comments() {
    let files = resolve_fixture(
        "// ♥\nconst LABEL: &str = \"♥\"; mod child;",
        &[("src/root/child.rs", "")],
    )
    .unwrap();

    assert!(files.contains("src/root/child.rs"));
}

#[test]
fn closure_parser_treats_non_test_cfg_as_production_and_rejects_unknown_attributes() {
    let files = resolve_fixture(
        "#[cfg(feature = \"disabled\")] mod child;",
        &[("src/root/child.rs", "")],
    )
    .unwrap();
    assert!(files.contains("src/root/child.rs"));
    assert!(resolve_fixture("#[expand] struct Hidden;", &[]).is_err());
}

#[test]
fn token_policy_rejects_nested_include_and_unknown_macros_everywhere() {
    for source in [
        "const DATA: &[u8] = include_bytes!(\"payload\");",
        "fn read() { include!(\"payload.rs\"); }",
        "matches!(value, include!(\"payload.rs\"))",
        "matches!(value, Some(unknown_macro!()))",
    ] {
        let error = resolve_fixture(source, &[]).unwrap_err();
        assert!(error.contains("token policy"), "{source}: {error}");
    }
}

#[test]
fn token_policy_rejects_aliases_dynamic_types_errors_and_network() {
    for source in [
        "use serde_json as json;",
        "use std::env as runtime_env;",
        "use tracing as telemetry;",
        "use log as logger;",
        "let value: String;",
        "let values: HashMap<u8, u8>;",
        "let value: Value;",
        "let text = error.to_string();",
        "let client = reqwest::Client::new();",
    ] {
        assert!(resolve_fixture(source, &[]).is_err(), "{source}");
    }
}

#[test]
fn token_policy_ignores_forbidden_words_in_literals_and_comments() {
    let files = resolve_fixture(
        r#"
            // reqwest::Client::new().send(); include!("ignored.rs");
            const MESSAGE: &str = "tracing serde_json::Value response.bytes()";
            mod child;
        "#,
        &[("src/root/child.rs", "")],
    )
    .unwrap();

    assert!(files.contains("src/root/child.rs"));
}
