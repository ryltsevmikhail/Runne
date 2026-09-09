use std::path::Path;

use super::source_audit::find_production_callers;
use super::source_inventory::inventory_for_manifest;

fn custom_manifest() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/credential_service/qualification/guard_tests/fixtures/custom_target/Cargo.toml")
}

fn inventory_contains(sources: &[super::SourceUnit], suffix: &str) -> bool {
    sources
        .iter()
        .any(|source| source.path.ends_with(Path::new(suffix)))
}

fn finding_contains(sources: &[super::SourceUnit], suffix: &str) -> bool {
    find_production_callers(sources)
        .iter()
        .any(|finding| finding.path.ends_with(Path::new(suffix)))
}

#[test]
fn custom_inventory_follows_a_function_local_macro_include() {
    let sources = inventory_for_manifest(&custom_manifest());
    assert!(inventory_contains(
        &sources,
        "test_fixture/local_qualification.inc"
    ));
    assert!(finding_contains(
        &sources,
        "test_fixture/local_qualification.inc"
    ));
}

#[test]
fn custom_inventory_follows_a_top_level_direct_include() {
    let sources = inventory_for_manifest(&custom_manifest());
    assert!(inventory_contains(
        &sources,
        "test_fixture/direct_qualification.inc"
    ));
    assert!(finding_contains(
        &sources,
        "test_fixture/direct_qualification.inc"
    ));
}

#[test]
fn custom_cargo_target_inventory_follows_path_and_macro_include_edges() {
    let sources = inventory_for_manifest(&custom_manifest());
    assert!(inventory_contains(
        &sources,
        "test_fixture/qualification.inc"
    ));
    assert!(finding_contains(&sources, "test_fixture/qualification.inc"));
}

#[test]
fn custom_inventory_does_not_silently_omit_parameterized_local_macro_include() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "src/credential_service/qualification/guard_tests/fixtures/parameterized_target/Cargo.toml",
    );
    let inventory = std::panic::catch_unwind(|| inventory_for_manifest(&manifest));
    match inventory {
        Ok(sources) => {
            assert!(inventory_contains(
                &sources,
                "test_fixture/parameterized_qualification.inc"
            ));
            assert!(finding_contains(
                &sources,
                "test_fixture/parameterized_qualification.inc"
            ));
        }
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or_default();
            assert!(
                message.contains("ambiguous macro include token flow"),
                "unexpected inventory panic: {message}"
            );
        }
    }
}
