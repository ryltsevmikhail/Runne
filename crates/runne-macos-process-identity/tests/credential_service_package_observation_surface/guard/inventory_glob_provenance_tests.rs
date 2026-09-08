use super::inventory_tests::{TemporaryWorkspace, cargo_check, workspace};

const TYPE: &str = "MacOsPendingCredentialServicePackageObservationV1";

fn assert_public_gate_rejects(workspace: &TemporaryWorkspace) {
    let facade = workspace.path().join("crates/example/src/lib.rs");
    assert!(
        std::panic::catch_unwind(|| {
            super::assert_workspace_has_no_credential_service_calls(workspace.path(), &facade);
        })
        .is_err(),
        "the public inventory gate must retain this protected consumer"
    );
}

fn protected_use(prefix: &str) -> String {
    format!(
        "use {prefix}::*; pub fn production(pending: {TYPE}) {{ let _ = {TYPE}::capture_current(); pending.verify_exact(); }}"
    )
}

#[test]
fn public_inventory_gate_keeps_glob_reexport_facades() {
    let workspace = workspace();
    workspace.write(
        "facade_one/Cargo.toml",
        "[package]\nname = \"facade-one\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "facade_one/src/lib.rs",
        "pub use runne_macos_process_identity::*;",
    );
    workspace.write(
        "facade_two/Cargo.toml",
        "[package]\nname = \"facade-two\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nfacade_one = { package = \"facade-one\", path = \"../facade_one\" }",
    );
    workspace.write("facade_two/src/lib.rs", "pub use facade_one::*;");
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nfacade_two = { package = \"facade-two\", path = \"../../facade_two\" }",
    );
    workspace.write("crates/example/src/lib.rs", &protected_use("facade_two"));

    cargo_check(&workspace);
    assert_public_gate_rejects(&workspace);
}

#[test]
fn public_inventory_gate_keeps_cross_file_glob_alias_includes() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "pub(crate) use runne_macos_process_identity as identity; pub mod carrier;",
    );
    workspace.write(
        "crates/example/src/carrier.rs",
        "use super::identity::*; include!(\"protected.inc\");",
    );
    workspace.write(
        "crates/example/src/protected.inc",
        &format!(
            "pub fn production(pending: {TYPE}) {{ let _ = {TYPE}::capture_current(); pending.verify_exact(); }}"
        ),
    );

    cargo_check(&workspace);
    assert_public_gate_rejects(&workspace);
}

#[test]
fn public_inventory_gate_keeps_custom_build_dependency_glob() {
    let workspace = workspace();
    workspace.write("crates/example/src/lib.rs", "pub fn clean() {}");
    workspace.write(
        "crates/example/custom/build.rs",
        &format!(
            "use runne_macos_process_identity::*; fn main() {{ let pending = {TYPE}::capture_current(); pending.verify_exact(); }}"
        ),
    );

    cargo_check(&workspace);
    assert_public_gate_rejects(&workspace);
}

#[test]
fn public_inventory_gate_keeps_renamed_and_extern_glob_dependencies() {
    let renamed = workspace();
    renamed.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nidentity = { package = \"runne-macos-process-identity\", path = \"../../identity\" }",
    );
    renamed.write("crates/example/src/lib.rs", &protected_use("identity"));
    cargo_check(&renamed);
    assert_public_gate_rejects(&renamed);

    let extern_alias = workspace();
    extern_alias.write(
        "crates/example/src/lib.rs",
        &format!(
            "extern crate runne_macos_process_identity as identity; {}",
            protected_use("identity")
        ),
    );
    cargo_check(&extern_alias);
    assert_public_gate_rejects(&extern_alias);
}

#[test]
fn public_inventory_gate_keeps_grouped_and_nested_glob_dependencies() {
    let workspace = workspace();
    workspace.write(
        "identity/src/lib.rs",
        "pub struct MacOsPendingCredentialServicePackageObservationV1; impl MacOsPendingCredentialServicePackageObservationV1 { pub fn capture_current() -> Self { Self } pub fn verify_exact(&self) {} } pub mod facade { pub use super::*; }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        &format!(
            "use runne_macos_process_identity::{{self as identity, facade::*}}; pub fn production(pending: {TYPE}) {{ let _ = identity::facade::{TYPE}::capture_current(); pending.verify_exact(); }}"
        ),
    );

    cargo_check(&workspace);
    assert_public_gate_rejects(&workspace);
}

#[test]
fn unrelated_glob_with_matching_type_name_stays_clean() {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"",
    );
    workspace.write(
        "helper/src/lib.rs",
        "pub struct MacOsPendingCredentialServicePackageObservationV1; impl MacOsPendingCredentialServicePackageObservationV1 { pub fn capture_current() -> Self { Self } pub fn verify_exact(&self) {} }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"../../helper\" }\nrunne-macos-process-identity = { path = \"../../identity\" }",
    );
    workspace.write("crates/example/src/lib.rs", &protected_use("helper"));

    cargo_check(&workspace);
    let facade = workspace.path().join("crates/example/src/lib.rs");
    super::assert_workspace_has_no_credential_service_calls(workspace.path(), &facade);
}

#[test]
fn canonical_glob_without_a_protected_use_stays_clean() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "use runne_macos_process_identity::*; pub fn production(_: Option<MacOsPendingCredentialServicePackageObservationV1>) {}",
    );

    cargo_check(&workspace);
    let facade = workspace.path().join("crates/example/src/lib.rs");
    super::assert_workspace_has_no_credential_service_calls(workspace.path(), &facade);
}
