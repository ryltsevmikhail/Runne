use std::path::{Path, PathBuf};

use super::collect_workspace_production_sources;
use super::semantic_graph_acceptance_tests::calls;

pub(super) struct TemporaryWorkspace(PathBuf);

impl TemporaryWorkspace {
    fn new() -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let prefix = format!("runne-observation-guard-{}-{unique}", std::process::id());
        for suffix in 0..u16::MAX {
            let path = std::env::temp_dir().join(format!("{prefix}-{suffix}"));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create {}: {error}", path.display()),
            }
        }
        panic!("cannot allocate temporary workspace")
    }

    pub(super) fn write(&self, relative: &str, source: &str) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryWorkspace {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

pub(super) const CALLER: &str = "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; fn caller() { Pending::capture_current(); }";

pub(super) fn workspace() -> TemporaryWorkspace {
    let workspace = TemporaryWorkspace::new();
    workspace.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/example\"]\nresolver = \"2\"",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"custom/build.rs\"\n[lib]\npath = \"src/lib.rs\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../../identity\" }\n[build-dependencies]\nrunne-macos-process-identity = { path = \"../../identity\" }",
    );
    workspace.write(
        "identity/Cargo.toml",
        "[package]\nname = \"runne-macos-process-identity\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\npath = \"src/lib.rs\"",
    );
    workspace.write(
        "identity/src/lib.rs",
        "pub struct MacOsPendingCredentialServicePackageObservationV1; impl MacOsPendingCredentialServicePackageObservationV1 { pub fn capture_current() -> Self { Self } pub fn verify_exact(&self) {} }",
    );
    workspace.write("crates/example/custom/build.rs", "fn main() {}");
    workspace
}

pub(super) fn cargo_check(workspace: &TemporaryWorkspace) {
    let status = std::process::Command::new("cargo")
        .args(["check", "--offline", "--manifest-path"])
        .arg(workspace.path().join("crates/example/Cargo.toml"))
        .status()
        .unwrap();
    assert!(status.success());
}

pub(super) fn production_sources(workspace: &TemporaryWorkspace) -> Vec<String> {
    let facade = workspace.path().join("crates/example/src/lib.rs");
    collect_workspace_production_sources(workspace.path(), &facade)
}

#[test]
fn inventory_traverses_facade_children_and_custom_build_targets() {
    let workspace = workspace();
    workspace.write("crates/example/src/lib.rs", "mod child;");
    workspace.write("crates/example/src/child.rs", CALLER);
    workspace.write(
        "crates/example/custom/build.rs",
        "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; fn main() { let _ = Pending::capture_current(); }",
    );
    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 2);
}

#[test]
fn inventory_follows_cargo_target_outside_its_package_root() {
    let workspace = workspace();
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"custom/build.rs\"\n[lib]\npath = \"../../shared/lib.rs\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../../identity\" }\n[build-dependencies]\nrunne-macos-process-identity = { path = \"../../identity\" }",
    );
    workspace.write(
        "shared/lib.rs",
        "mod leaf; pub fn production() { leaf::caller(); }",
    );
    workspace.write("shared/leaf.rs", "include!(\"call.inc\");");
    workspace.write(
        "shared/call.inc",
        &CALLER.replacen("fn caller", "pub fn caller", 1),
    );
    workspace.write("crates/example/src/lib.rs", "pub fn facade() {}");

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
    let facade = workspace.path().join("crates/example/src/lib.rs");
    let consumer_snapshot =
        super::collect_workspace_credential_service_consumer_snapshot(workspace.path(), &facade);
    assert!(
        consumer_snapshot
            .graph
            .nodes
            .iter()
            .any(|node| { node.canonical_path.ends_with("shared/call.inc") })
    );
    assert!(
        std::panic::catch_unwind(|| {
            super::assert_workspace_has_no_credential_service_calls(workspace.path(), &facade);
        })
        .is_err(),
        "the selected target's nested source must not be treated as clean"
    );
}

#[test]
fn inventory_follows_cross_file_private_dependency_alias() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "pub(crate) use runne_macos_process_identity as identity; mod child;",
    );
    workspace.write(
        "crates/example/src/child.rs",
        "use super::identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; pub fn production() { let _ = Pending::capture_current(); }",
    );
    cargo_check(&workspace);
    assert!(
        std::panic::catch_unwind(|| {
            super::assert_workspace_has_no_credential_service_calls(
                workspace.path(),
                &workspace.path().join("crates/example/src/lib.rs"),
            );
        })
        .is_err()
    );
}

#[test]
fn inventory_follows_exported_macro_through_cross_file_dependency_alias() {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "helper/src/lib.rs",
        "pub use runne_macos_process_identity as identity; #[macro_use] mod macros;",
    );
    workspace.write(
        "helper/src/macros.rs",
        "#[macro_export] macro_rules! capture { () => { $crate::identity::MacOsPendingCredentialServicePackageObservationV1::capture_current() } }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"../../helper\" }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "pub fn production() { let _ = helper::capture!(); }",
    );
    cargo_check(&workspace);
    assert!(
        std::panic::catch_unwind(|| {
            super::assert_workspace_has_no_credential_service_calls(
                workspace.path(),
                &workspace.path().join("crates/example/src/lib.rs"),
            );
        })
        .is_err()
    );
}

#[test]
fn inventory_follows_cross_file_macro_use_include() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "#[macro_use] mod macros; load!(\"payload.inc\");",
    );
    workspace.write(
        "crates/example/src/macros.rs",
        "macro_rules! load { ($path:literal) => { include!($path); } }",
    );
    workspace.write("crates/example/src/payload.inc", CALLER);
    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn compile_valid_external_glob_reexport_fails_closed() {
    let workspace = TemporaryWorkspace::new();
    workspace.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"consumer\"]\nresolver = \"2\"",
    );
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"",
    );
    workspace.write(
        "helper/src/lib.rs",
        "pub struct HiddenPending; impl HiddenPending { pub fn capture_current() -> Self { Self } }",
    );
    workspace.write(
        "consumer/Cargo.toml",
        "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"../helper\" }",
    );
    let source = "use helper::*; fn production() { let _ = HiddenPending::capture_current(); } fn main() { production(); }";
    workspace.write("consumer/src/main.rs", source);
    let status = std::process::Command::new("cargo")
        .args(["check", "--offline", "--manifest-path"])
        .arg(workspace.path().join("consumer/Cargo.toml"))
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(
        super::analyzer::analyze_source(source),
        super::analyzer::GuardVerdict::Inconclusive(_)
    ));
}

#[test]
fn compile_valid_carriers_and_macro_invocations_are_detected() {
    let workspace = workspace();
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        type Alias = Pending;
        struct Functions { capture: fn() -> Pending }
        fn invoke(capture: fn() -> Pending) -> Pending { capture() }
        macro_rules! capture { ($path:path) => { <$path>::capture_current() } }
        macro_rules! verify { ($pending:expr) => { $pending.verify_exact() } }
        fn production() {
            let functions = Functions { capture: Pending::capture_current };
            let pending = invoke(functions.capture);
            let alias: Alias = pending;
            alias.verify_exact();
            let _ = capture!(Pending);
            let _ = verify!(Pending::capture_current());
        }
    ";
    workspace.write("crates/example/src/lib.rs", source);
    cargo_check(&workspace);
    assert_ne!(super::super::count_credential_service_calls(source), 0);
}
