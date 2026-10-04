use super::{lexer, policy_io, resolver};
use std::{fs, path::Path};

const START: &str = "crates/runne-daemon/src/application/http_startup/start.rs";
const REPLAY_SETUP: &str = "crates/runne-daemon/src/application/http_startup/replay_setup.rs";
const PROFILE_MODELS: &str = "crates/runne-daemon/src/application/http_startup/profile_models.rs";
const COMPOSITION: &str = "crates/runne-daemon/src/canonical_provider/composition.rs";

fn audit(path: &str, source: &str) -> Result<(), String> {
    policy_io::audit_tokens(path, &lexer::tokenize(source)?)
}

#[test]
fn token_policy_allows_only_split_startup_error_formatting_and_version() {
    assert!(
        audit(
            START,
            r#"fn run() { DaemonError::Bootstrap(format!("start runtime: {error}")); }"#,
        )
        .is_ok()
    );
    assert!(audit(
        START,
        r#"fn run() { DaemonError::Bootstrap(format!("configure replay transport: {error}")); }"#,
    )
    .is_ok());
    assert!(audit(
        REPLAY_SETUP,
        r#"fn run() { DaemonError::Bootstrap(format!("measure retained replay inventory: {error}")); }"#,
    )
    .is_ok());
    assert!(
        audit(
            REPLAY_SETUP,
            "fn run() { DaemonError::Config(error.to_string()); }",
        )
        .is_ok()
    );
    assert!(
        audit(
            START,
            "fn run() { profile::runtime_profile(env!(\"CARGO_PKG_VERSION\")); }",
        )
        .is_ok()
    );

    for (path, source) in [
        (
            START,
            r#"fn run() { DaemonError::Bootstrap(format!("unapproved: {error}")); }"#,
        ),
        (
            START,
            r#"fn run() { OtherError::Bootstrap(format!("start runtime: {error}")); }"#,
        ),
        (
            REPLAY_SETUP,
            "fn run() { OtherError::Config(error.to_string()); }",
        ),
        (REPLAY_SETUP, "fn run() { error.to_string(); }"),
        (
            REPLAY_SETUP,
            "fn run() { profile::runtime_profile(env!(\"CARGO_PKG_VERSION\")); }",
        ),
        (
            START,
            "fn run() { profile::runtime_profile(env!(\"HOME\")); }",
        ),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
}

#[test]
fn token_policy_allows_only_the_known_runtime_controller_shutdown_call() {
    assert!(audit(
        START,
        "fn run() { runtime_controller.shutdown(ShutdownMode::Immediate { timeout: shutdown_timeout }); }",
    )
    .is_ok());
    assert!(audit(
        START,
        "fn run() { runtime_controller.shutdown(ShutdownMode::Immediate { timeout: shutdown_timeout, },); }",
    )
    .is_ok());
    for (path, source) in [
        (
            START,
            "fn run() { arbitrary.shutdown(ShutdownMode::Immediate { timeout: shutdown_timeout }); }",
        ),
        (
            START,
            "fn run() { runtime_controller.shutdown(OtherMode::Immediate { timeout: shutdown_timeout }); }",
        ),
        (
            START,
            "fn run() { runtime_controller.shutdown(ShutdownMode::Immediate { timeout: shutdown_timeout, extra: value, },); }",
        ),
        (
            START,
            "fn run() { runtime_controller.shutdown(ShutdownMode::Immediate { timeout: shutdown_timeout, }, extra); }",
        ),
        (
            "crates/runne-daemon/src/application/http_startup/other.rs",
            "fn run() { runtime_controller.shutdown(ShutdownMode::Immediate { timeout: shutdown_timeout }); }",
        ),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
}

#[test]
fn token_policy_allows_only_selected_profile_model_return_type() {
    assert!(audit(
        PROFILE_MODELS,
        "fn selected_profile_models(x: X) -> (Vec<SelectedProviderProfile>, Vec<(SelectedProviderProfile, String)>) { () }",
    )
    .is_ok());
    for (path, source) in [
        (
            PROFILE_MODELS,
            "fn other(x: X) -> (Vec<SelectedProviderProfile>, Vec<(SelectedProviderProfile, String)>) { () }",
        ),
        (
            PROFILE_MODELS,
            "fn selected_profile_models(x: X) -> Vec<(OtherProfile, String)> { () }",
        ),
        (
            "crates/runne-daemon/src/application/http_startup/other.rs",
            "fn selected_profile_models(x: X) -> (Vec<SelectedProviderProfile>, Vec<(SelectedProviderProfile, String)>) { () }",
        ),
        (PROFILE_MODELS, "fn other() { let value: String; }"),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
    let actual =
        include_str!("../../../../runne-daemon/src/application/http_startup/profile_models.rs");
    assert!(audit(PROFILE_MODELS, actual).is_ok());
}

#[test]
fn token_policy_excludes_only_unambiguous_inline_test_modules() {
    assert!(
        audit(
            "crates/runne-daemon/src/application/http_startup/example.rs",
            "#[cfg(test)] mod tests { tracing::warn!(\"test only\"); } fn production() {}",
        )
        .is_ok()
    );
    assert!(
        audit(
            "crates/runne-daemon/src/application/http_startup/example.rs",
            "fn production() { tracing::warn!(\"production\"); }",
        )
        .is_err()
    );
    assert!(
        audit(
            "crates/runne-daemon/src/application/http_startup/example.rs",
            "#[cfg(test, feature = \"extra\")] mod tests { tracing::warn!(\"ambiguous\"); }",
        )
        .is_err()
    );
    assert!(
        audit(
            "crates/runne-daemon/src/application/http_startup/example.rs",
            "#[cfg_attr(test, cfg(test))] mod tests { tracing::warn!(\"ambiguous\"); }",
        )
        .is_err()
    );
}

fn include_fixture(workspace: &Path, contents: &str) {
    let source = workspace.join(COMPOSITION);
    let included = workspace.join(
        "crates/runne-daemon/src/canonical_provider/composition/secondary_catalog_install.rs",
    );
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::create_dir_all(included.parent().unwrap()).unwrap();
    fs::write(
        source,
        "include!(\"composition/secondary_catalog_install.rs\");",
    )
    .unwrap();
    fs::write(included, contents).unwrap();
}

#[test]
fn resolver_follows_exact_include_and_audits_included_source() {
    let workspace = tempfile::tempdir().unwrap();
    include_fixture(workspace.path(), "fn included_helper() {} ");
    let files = resolver::resolve_closure(workspace.path(), &[COMPOSITION]).unwrap();
    assert!(files.contains(
        "crates/runne-daemon/src/canonical_provider/composition/secondary_catalog_install.rs"
    ));

    for source in [
        "tracing::warn!(\"payload\");",
        "let client = reqwest::Client::new();",
        "let error: Box<dyn Error>;",
    ] {
        let workspace = tempfile::tempdir().unwrap();
        include_fixture(workspace.path(), source);
        assert!(resolver::resolve_closure(workspace.path(), &[COMPOSITION]).is_err());
    }
}

#[test]
fn resolver_rejects_unknown_missing_and_traversing_include_paths() {
    for include in [
        "include!(\"composition/secondary_catalog_install.rs\");",
        "include!(\"composition/missing.rs\");",
        "include!(\"../outside.rs\");",
        "fn body() { include!(\"composition/secondary_catalog_install.rs\"); }",
        "include!(concat!(\"composition/secondary_catalog_install.rs\"));",
    ] {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join(COMPOSITION);
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(source, include).unwrap();
        assert!(resolver::resolve_closure(workspace.path(), &[COMPOSITION]).is_err());
    }
}

#[cfg(unix)]
#[test]
fn resolver_rejects_known_include_symlink_outside_workspace() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let source = workspace.path().join(COMPOSITION);
    let included = workspace.path().join(
        "crates/runne-daemon/src/canonical_provider/composition/secondary_catalog_install.rs",
    );
    let external = outside.path().join("secondary_catalog_install.rs");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::create_dir_all(included.parent().unwrap()).unwrap();
    fs::write(
        source,
        "include!(\"composition/secondary_catalog_install.rs\");",
    )
    .unwrap();
    fs::write(&external, "fn included_helper() {} ").unwrap();
    symlink(external, included).unwrap();

    assert!(resolver::resolve_closure(workspace.path(), &[COMPOSITION]).is_err());
}
