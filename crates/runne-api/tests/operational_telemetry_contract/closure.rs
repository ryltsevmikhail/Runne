use std::{fs, path::Path};

#[path = "closure/hardening.rs"]
mod hardening;
#[path = "closure/lexer.rs"]
mod lexer;
#[path = "closure/parser.rs"]
mod parser;
#[path = "closure/policy_compatibility_tests.rs"]
mod policy_compatibility_tests;
#[path = "closure/policy_composition.rs"]
mod policy_composition;
#[path = "closure/policy_composition_tests.rs"]
mod policy_composition_tests;
#[path = "closure/policy_fixtures.rs"]
mod policy_fixtures;
#[path = "closure/policy_helpers.rs"]
mod policy_helpers;
#[path = "closure/policy_io.rs"]
mod policy_io;
#[path = "closure/policy_known_shapes_tests.rs"]
mod policy_known_shapes_tests;
#[path = "closure/policy_macros.rs"]
mod policy_macros;
#[path = "closure/policy_permission.rs"]
mod policy_permission;
#[path = "closure/policy_permission_tests.rs"]
mod policy_permission_tests;
#[path = "closure/policy_runtime_client.rs"]
mod policy_runtime_client;
#[path = "closure/policy_startup.rs"]
mod policy_startup;
#[path = "closure/policy_uuid.rs"]
mod policy_uuid;
#[path = "closure/policy_uuid_tests.rs"]
mod policy_uuid_tests;
#[path = "closure/resolver.rs"]
mod resolver;

#[test]
fn closure_helpers_support_nested_cfg_path_and_support_modules() {
    let declarations = parser::declarations(
        &lexer::tokenize(
            r#"
            // mod ignored_line_comment;
            /* mod ignored_block_comment; */
            const IGNORED: &str = "mod ignored_string;";
            mod nested { mod child; }
            #[cfg(test)] mod test_only;
            #[path = "custom.rs"] pub(crate) mod custom;
            pub mod support;
        "#,
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(declarations.len(), 4);
    assert!(
        declarations
            .iter()
            .any(|declaration| declaration.name == "child")
    );
    assert!(declarations.iter().any(|declaration| declaration.cfg_test));
    assert!(
        declarations
            .iter()
            .any(|declaration| declaration.path.as_deref() == Some("custom.rs"))
    );
}

const REQUIRED: &[&str] = &[
    "crates/runne-api/src/operational_telemetry.rs",
    "crates/runne-application/src/provider/operational.rs",
    "crates/runne-observability/src/operational.rs",
    "crates/runne-store/src/provider/operational_telemetry/mod.rs",
    "crates/runne-runtime/src/provider_execution_parts/part_01.rs",
    "crates/runne-runtime/src/provider_execution_parts/part_04.rs",
    "crates/runne-http/src/operational_telemetry.rs",
    "crates/runne-http/src/secure_local_host.rs",
    "crates/runne-http/src/router_parts/production.rs",
    "crates/runne-runtime-client/src/canonical/operational_telemetry.rs",
    "crates/runne-app-core/src/lib_parts/operational_telemetry.rs",
    "crates/runne-app-core/src/lib_parts/operational_telemetry_snapshot.rs",
    "crates/runne-app-core/src/lib_parts/operational_telemetry_state.rs",
    "crates/runne-daemon/src/operational_telemetry.rs",
    "crates/runne-daemon/src/application/http_startup.rs",
    "crates/runne-daemon/src/canonical_provider/composition.rs",
    "crates/runne-daemon/src/canonical_provider/recovery.rs",
];

const FORBIDDEN: &[&str] = &[
    "serde_json::Value",
    "HashMap",
    "BTreeMap",
    "IndexMap",
    "Box<dyn Error",
    "dyn Error",
    "anyhow::",
    "tracing::",
    "log::",
    "println!",
    "eprintln!",
    "dbg!",
    "std::env",
    "response.bytes()",
    "response.text()",
    "response.json()",
    "exporter",
    "pub fn operational_telemetry_router",
];

fn assert_without(source: &str, file: &str, forbidden: &[&str]) {
    for pattern in forbidden {
        assert!(!source.contains(pattern), "{file} contains {pattern}");
    }
}

#[test]
fn recursive_production_telemetry_closure_rejects_dynamic_diagnostic_and_logging_escapes() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let files = resolver::resolve_closure(workspace, REQUIRED)
        .unwrap_or_else(|error| panic!("incomplete production telemetry closure: {error}"));
    for file in REQUIRED {
        assert!(
            files.contains(*file),
            "missing maintained root from closure: {file}"
        );
    }
    for file in &files {
        let source = fs::read_to_string(workspace.join(file)).unwrap();
        assert_without(&source, file, FORBIDDEN);
        if file.starts_with("crates/runne-http/") {
            assert_without(&source, file, &["runne_store", "runne_observability"]);
        }
        if file.starts_with("crates/runne-runtime/src/provider_execution_parts/") {
            assert_without(&source, file, &["runne_store", "runne_observability"]);
        }
        if file.starts_with("crates/runne-app-core/src/lib_parts/operational_telemetry") {
            assert_without(&source, file, &["runne_api::", "runne_runtime::"]);
        }
    }
}

#[test]
fn closure_resolves_nested_path_and_support_modules_but_excludes_cfg_test() {
    let workspace = tempfile::tempdir().unwrap();
    let source = workspace.path().join("src/root.rs");
    fs::create_dir_all(source.parent().unwrap().join("root/nested")).unwrap();
    fs::write(
        &source,
        r#"
            mod nested { mod child; }
            #[cfg(test)] mod test_only;
            #[path = "custom.rs"] pub(crate) mod custom;
            pub mod support;
        "#,
    )
    .unwrap();
    fs::write(source.parent().unwrap().join("root/nested/child.rs"), "").unwrap();
    fs::write(source.parent().unwrap().join("custom.rs"), "").unwrap();
    fs::write(source.parent().unwrap().join("root/support.rs"), "").unwrap();

    let files = resolver::resolve_closure(workspace.path(), &["src/root.rs"]).unwrap();

    assert_eq!(
        files,
        [
            "src/root.rs",
            "src/custom.rs",
            "src/root/nested/child.rs",
            "src/root/support.rs",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}
