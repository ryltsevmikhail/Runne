use super::inventory_tests::{cargo_check, workspace};

fn assert_public_gate_is_not_clean(workspace: &super::inventory_tests::TemporaryWorkspace) {
    let facade = workspace.path().join("crates/example/src/lib.rs");
    assert!(
        std::panic::catch_unwind(|| {
            super::assert_workspace_has_no_credential_service_calls(workspace.path(), &facade);
        })
        .is_err()
    );
}

#[test]
fn external_item_macro_with_direct_target_dependency_is_not_omitted() {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"",
    );
    workspace.write(
        "helper/src/lib.rs",
        "#[macro_export] macro_rules! emit { () => { pub fn generated() { let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); } } }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"../../helper\" }\nrunne-macos-process-identity = { path = \"../../identity\" }",
    );
    workspace.write("crates/example/src/lib.rs", "helper::emit!();");
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

fn external_macro_workspace(source: &str) -> super::inventory_tests::TemporaryWorkspace {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"",
    );
    workspace.write("helper/src/lib.rs", "#[macro_export] macro_rules! emit { () => {{ let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); }} }");
    workspace.write("crates/example/Cargo.toml", "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"../../helper\" }\nrunne-macos-process-identity = { path = \"../../identity\" }");
    workspace.write("crates/example/src/lib.rs", source);
    workspace
}

fn external_proc_macro_workspace(source: &str) -> super::inventory_tests::TemporaryWorkspace {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\nproc-macro = true",
    );
    workspace.write(
        "helper/src/lib.rs",
        "extern crate proc_macro; use proc_macro::TokenStream; fn generated() -> TokenStream { \"fn generated() { let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); }\".parse().unwrap() } #[proc_macro_attribute] pub fn inject(_: TokenStream, _: TokenStream) -> TokenStream { generated() } #[proc_macro_derive(Inject)] pub fn derive_inject(_: TokenStream) -> TokenStream { generated() }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"../../helper\" }\nrunne-macos-process-identity = { path = \"../../identity\" }",
    );
    workspace.write("crates/example/src/lib.rs", source);
    workspace
}

#[test]
fn glob_imported_external_macro_with_direct_target_dependency_is_not_omitted() {
    let workspace = external_macro_workspace("use helper::*; pub fn production() { emit!(); }");
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn block_imported_external_macro_with_direct_target_dependency_is_not_omitted() {
    let workspace = external_macro_workspace("pub fn production() { use helper::emit; emit!(); }");
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn macro_use_extern_crate_with_direct_target_dependency_is_not_omitted() {
    let workspace = external_macro_workspace(
        "#[macro_use] extern crate helper; pub fn production() { emit!(); }",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn aliased_extern_crate_macro_with_direct_target_dependency_is_not_omitted() {
    let workspace =
        external_macro_workspace("extern crate helper as h; pub fn production() { h::emit!(); }");
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn invoked_local_macro_body_with_external_macro_is_not_omitted() {
    let workspace = external_macro_workspace(
        "macro_rules! wrap { () => { helper::emit!(); } } pub fn production() { wrap!(); }",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn invoked_generated_local_macro_body_with_external_macro_is_not_omitted() {
    let workspace = external_macro_workspace(
        "macro_rules! define { () => { macro_rules! wrap { () => { helper::emit!(); } } wrap!(); } } pub fn production() { define!(); }",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn scoped_local_macro_alias_with_external_macro_is_not_omitted() {
    let workspace = external_macro_workspace(
        "mod macros { macro_rules! wrap { () => { helper::emit!(); } } pub(crate) use wrap as alias; } pub fn production() { macros::alias!(); }",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn chained_local_macro_alias_with_external_macro_is_not_omitted() {
    let workspace = external_macro_workspace(
        "mod macros { macro_rules! wrap { () => { helper::emit!(); } } pub(crate) use wrap as first; pub(crate) use first as alias; } pub fn production() { macros::alias!(); }",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn reexported_local_macro_alias_with_external_macro_is_not_omitted() {
    let workspace = external_macro_workspace(
        "mod macros; pub(crate) use crate::macros::wrap as alias; pub fn production() { alias!(); }",
    );
    workspace.write(
        "crates/example/src/macros.rs",
        "macro_rules! wrap { () => { helper::emit!(); } } pub(crate) use wrap;",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn out_dir_include_with_direct_target_dependency_is_not_omitted() {
    let workspace = workspace();
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../../identity\" }",
    );
    workspace.write(
        "crates/example/build.rs",
        "fn main() { let path = std::path::PathBuf::from(std::env::var(\"OUT_DIR\").unwrap()).join(\"generated.rs\"); std::fs::write(path, \"pub fn generated() { let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); }\").unwrap(); }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn custom_environment_include_with_direct_target_dependency_is_not_omitted() {
    let workspace = workspace();
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../../identity\" }",
    );
    workspace.write(
        "crates/example/build.rs",
        "fn main() { let path = std::path::PathBuf::from(std::env::var(\"OUT_DIR\").unwrap()).join(\"generated.rs\"); std::fs::write(&path, \"pub fn generated() { let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); }\").unwrap(); println!(\"cargo:rustc-env=CUSTOM_GENERATED_PATH={}\", path.display()); }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "include!(env!(\"CUSTOM_GENERATED_PATH\"));",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn dynamic_include_alias_with_direct_target_dependency_is_not_omitted() {
    let workspace = workspace();
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../../identity\" }",
    );
    workspace.write(
        "crates/example/build.rs",
        "fn main() { let path = std::path::PathBuf::from(std::env::var(\"OUT_DIR\").unwrap()).join(\"generated.rs\"); std::fs::write(&path, \"pub fn generated() { let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); }\").unwrap(); println!(\"cargo:rustc-env=CUSTOM_GENERATED_PATH={}\", path.display()); }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "use std::include as load; load!(env!(\"CUSTOM_GENERATED_PATH\"));",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn external_derive_with_direct_target_dependency_is_not_omitted() {
    let workspace = external_proc_macro_workspace("#[derive(helper::Inject)] struct Marker;");
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn glob_imported_external_attribute_with_direct_target_dependency_is_not_omitted() {
    let workspace = external_proc_macro_workspace("use helper::*; #[inject] struct Marker;");
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn cfg_attr_external_derive_with_direct_target_dependency_is_not_omitted() {
    let workspace = external_proc_macro_workspace(
        "#[cfg_attr(not(test), derive(helper::Inject))] struct Marker;",
    );
    cargo_check(&workspace);
    assert_public_gate_is_not_clean(&workspace);
}
