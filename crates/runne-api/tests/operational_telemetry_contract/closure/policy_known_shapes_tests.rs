use super::{lexer, policy_io, resolver};
use std::fs;

const JOURNAL_BOOTSTRAP: &str =
    "crates/runne-daemon/src/canonical_provider/composition/journal_bootstrap.rs";
const MODEL_PIN: &str = "crates/runne-daemon/src/canonical_provider/composition/model_pin.rs";
const SECONDARY_BACKGROUND: &str =
    "crates/runne-daemon/src/canonical_provider/composition/secondary_background.rs";
const SECONDARY_METADATA: &str =
    "crates/runne-daemon/src/canonical_provider/composition/secondary_effects_metadata.rs";

fn audit(path: &str, source: &str) -> Result<(), String> {
    policy_io::audit_tokens(path, &lexer::tokenize(source)?)
}

#[test]
fn known_composition_errors_remain_narrowly_typed() {
    assert!(
        audit(
            JOURNAL_BOOTSTRAP,
            "DaemonError::Bootstrap(error.to_string())",
        )
        .is_ok()
    );
    for (path, source) in [
        (JOURNAL_BOOTSTRAP, "DaemonError::Config(error.to_string())"),
        (
            JOURNAL_BOOTSTRAP,
            "DaemonError::Bootstrap(other.to_string())",
        ),
        (
            "crates/runne-daemon/src/canonical_provider/composition/other.rs",
            "DaemonError::Bootstrap(error.to_string())",
        ),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
    let actual = include_str!(
        "../../../../runne-daemon/src/canonical_provider/composition/journal_bootstrap.rs"
    );
    assert!(audit(JOURNAL_BOOTSTRAP, actual).is_ok());
}

#[test]
fn model_pin_accepts_only_the_selected_identity_vector_literal() {
    assert!(
        audit(
            MODEL_PIN,
            "fn run() { let mut profiles = vec![self.selected_profile_identity()]; }"
        )
        .is_ok(),
        "{:?}",
        audit(
            MODEL_PIN,
            "fn run() { let mut profiles = vec![self.selected_profile_identity()]; }"
        )
    );
    for (path, source) in [
        (
            MODEL_PIN,
            "fn run() { let profiles = vec![other.selected_profile_identity()]; }",
        ),
        (
            MODEL_PIN,
            "fn run() { let profiles = vec![self.selected_profile_identity(), other]; }",
        ),
        (
            MODEL_PIN,
            "fn run() { let profiles = vec![self.other_identity()]; }",
        ),
        (
            "crates/runne-daemon/src/canonical_provider/composition/other.rs",
            "fn run() { let profiles = vec![self.selected_profile_identity()]; }",
        ),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
    let actual =
        include_str!("../../../../runne-daemon/src/canonical_provider/composition/model_pin.rs");
    assert!(audit(MODEL_PIN, actual).is_ok());
}

#[test]
fn secondary_background_accepts_only_its_db_path_and_profile_resource() {
    assert!(
        audit(
            SECONDARY_BACKGROUND,
            "struct SecondaryBackgroundConfig { pub(super) db_path: String, }",
        )
        .is_ok()
    );
    for (path, source) in [
        (
            SECONDARY_BACKGROUND,
            "struct SecondaryBackgroundConfig { pub(super) other: String, }",
        ),
        (
            SECONDARY_BACKGROUND,
            "struct OtherConfig { pub(super) db_path: String, }",
        ),
        (
            SECONDARY_BACKGROUND,
            "struct SecondaryBackgroundConfig { db_path: String, }",
        ),
        (
            "crates/runne-daemon/src/canonical_provider/composition/other.rs",
            "struct SecondaryBackgroundConfig { pub(super) db_path: String, }",
        ),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
    let resource = "../../../../../docs/profiles/openai-responses-background-text-v1.json";
    assert!(
        audit(
            SECONDARY_BACKGROUND,
            &format!("let profile = from_json(include_bytes!(\"{resource}\"));"),
        )
        .is_ok()
    );
    for (path, source) in [
        (
            SECONDARY_BACKGROUND,
            "include_bytes!(\"../../../../../docs/profiles/other.json\");",
        ),
        (
            SECONDARY_BACKGROUND,
            "include_bytes!(\"../../../../../docs/profiles/openai-responses-background-text-v1.json\", extra);",
        ),
        (
            "crates/runne-daemon/src/canonical_provider/composition/other.rs",
            "include_bytes!(\"../../../../../docs/profiles/openai-responses-background-text-v1.json\");",
        ),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
    let actual = include_str!(
        "../../../../runne-daemon/src/canonical_provider/composition/secondary_background.rs"
    );
    assert!(audit(SECONDARY_BACKGROUND, actual).is_ok());
}

#[test]
fn secondary_metadata_accepts_only_its_private_string_fields_and_profile_resource() {
    let fields = "struct SecondaryEffectsMetadata { provider_id: String, credential_realm: String, profile_id: String, db_path: String, }";
    assert!(audit(SECONDARY_METADATA, fields).is_ok());
    for (path, source) in [
        (
            SECONDARY_METADATA,
            "struct OtherMetadata { provider_id: String, }",
        ),
        (
            SECONDARY_METADATA,
            "struct SecondaryEffectsMetadata { other: String, }",
        ),
        (
            SECONDARY_METADATA,
            "struct SecondaryEffectsMetadata { pub provider_id: String, }",
        ),
        (
            SECONDARY_METADATA,
            "struct SecondaryEffectsMetadata { pub(super) db_path: String, }",
        ),
        (
            "crates/runne-daemon/src/canonical_provider/composition/other.rs",
            "struct SecondaryEffectsMetadata { provider_id: String, }",
        ),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }

    let resource = "../../../../../docs/profiles/openai-responses-background-text-v1.json";
    assert!(
        audit(
            SECONDARY_METADATA,
            &format!("const PROFILE: &[u8] = include_bytes!(\"{resource}\");"),
        )
        .is_ok()
    );
    for (path, source) in [
        (
            SECONDARY_METADATA,
            "include_bytes!(\"../../../../../docs/profiles/wrong.json\");",
        ),
        (
            SECONDARY_METADATA,
            "include_bytes!(\"../../../../../docs/profiles/openai-responses-background-text-v1.json\", extra);",
        ),
        (
            "crates/runne-daemon/src/canonical_provider/composition/other.rs",
            "include_bytes!(\"../../../../../docs/profiles/openai-responses-background-text-v1.json\");",
        ),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
    let actual = include_str!(
        "../../../../runne-daemon/src/canonical_provider/composition/secondary_effects_metadata.rs"
    );
    assert!(audit(SECONDARY_METADATA, actual).is_ok());
}

#[test]
fn cfg_test_attributes_are_removed_with_the_test_module() {
    let source =
        "#[cfg(test)] mod tests {} mod production { tracing::warn!(\"must be audited\"); }";
    assert!(audit("src/root.rs", source).is_err());

    let workspace = tempfile::tempdir().unwrap();
    fs::create_dir_all(workspace.path().join("src/root")).unwrap();
    fs::write(
        workspace.path().join("src/root.rs"),
        "#[cfg(test)] mod tests {} mod production;",
    )
    .unwrap();
    fs::write(
        workspace.path().join("src/root/production.rs"),
        "fn production() {}",
    )
    .unwrap();
    let files = resolver::resolve_closure(workspace.path(), &["src/root.rs"]).unwrap();
    assert!(files.contains("src/root/production.rs"));

    for source in [
        "tracing::warn!(\"production\");",
        "let error: Box<dyn Error>;",
        "let client = reqwest::Client::new();",
    ] {
        fs::write(workspace.path().join("src/root/production.rs"), source).unwrap();
        assert!(resolver::resolve_closure(workspace.path(), &["src/root.rs"]).is_err());
    }
}

#[test]
fn path_attributes_outside_inline_modules_use_the_containing_file_directory() {
    let workspace = tempfile::tempdir().unwrap();
    fs::create_dir_all(workspace.path().join("src/composition")).unwrap();
    fs::write(workspace.path().join("src/composition.rs"), "mod service;").unwrap();
    fs::write(
        workspace.path().join("src/composition/service.rs"),
        "#[path = \"secondary_effects_metadata.rs\"] mod metadata;",
    )
    .unwrap();
    fs::write(
        workspace
            .path()
            .join("src/composition/secondary_effects_metadata.rs"),
        "fn metadata() {}",
    )
    .unwrap();

    let files = resolver::resolve_closure(workspace.path(), &["src/composition.rs"]).unwrap();
    assert!(files.contains("src/composition/secondary_effects_metadata.rs"));
}

#[cfg(unix)]
#[test]
fn path_attribute_symlink_cannot_escape_workspace() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir_all(workspace.path().join("src")).unwrap();
    fs::write(
        workspace.path().join("src/root.rs"),
        "#[path = \"external.rs\"] mod external;",
    )
    .unwrap();
    let external = outside.path().join("external.rs");
    fs::write(&external, "fn external() {}").unwrap();
    symlink(external, workspace.path().join("src/external.rs")).unwrap();

    assert!(resolver::resolve_closure(workspace.path(), &["src/root.rs"]).is_err());
}
