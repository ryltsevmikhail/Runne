use super::{CALLER, calls};
use crate::guard::inventory_tests::{TemporaryWorkspace, cargo_check, workspace};

#[test]
fn renamed_dependency_macro_include_keeps_consumer_source_context() {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2024\"",
    );
    workspace.write(
        "helper/src/lib.rs",
        "#[macro_export] macro_rules! load { () => { include!(\"payload.inc\"); } }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        r#"
            [package]
            name = "example"
            version = "0.1.0"
            edition = "2024"
            [dependencies]
            renamed_helper = { package = "helper", path = "../../helper" }
            runne-macos-process-identity = { path = "../../identity" }
        "#,
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "use renamed_helper::load; load!();",
    );
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn renamed_build_dependency_macro_uses_build_target_context() {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2024\"",
    );
    workspace.write(
        "helper/src/lib.rs",
        "#[macro_export] macro_rules! load { () => { include!(\"payload.inc\"); } }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        r#"
            [package]
            name = "example"
            version = "0.1.0"
            edition = "2024"
            build = "custom/build.rs"
            [build-dependencies]
            renamed_helper = { package = "helper", path = "../../helper" }
            runne-macos-process-identity = { path = "../../identity" }
        "#,
    );
    workspace.write("crates/example/src/lib.rs", "pub fn clean() {}");
    workspace.write(
        "crates/example/custom/build.rs",
        "use renamed_helper::load; load!(); fn main() {}",
    );
    workspace.write("crates/example/custom/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn same_dependency_alias_in_two_consumers_keeps_each_package_identity() {
    let workspace = workspace();
    workspace.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/example\", \"crates/other\"]\nresolver = \"2\"",
    );
    write_exporter(&workspace, "actual-helper", "actual-helper", true);
    write_exporter(&workspace, "decoy-helper", "decoy-helper", false);
    workspace.write(
        "crates/example/Cargo.toml",
        r#"
            [package]
            name = "example"
            version = "0.1.0"
            edition = "2024"
            [dependencies]
            shared = { package = "actual-helper", path = "../../actual-helper" }
            runne-macos-process-identity = { path = "../../identity" }
        "#,
    );
    workspace.write("crates/example/src/lib.rs", "use shared::load; load!();");
    workspace.write("crates/example/src/payload.inc", CALLER);
    workspace.write(
        "crates/other/Cargo.toml",
        r#"
            [package]
            name = "other"
            version = "0.1.0"
            edition = "2024"
            [dependencies]
            shared = { package = "decoy-helper", path = "../../decoy-helper" }
        "#,
    );
    workspace.write("crates/other/src/lib.rs", "use shared::load; load!();");

    cargo_check_workspace(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn dependency_without_rename_uses_library_target_name() {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        r#"
            [package]
            name = "helper-package"
            version = "0.1.0"
            edition = "2024"
            [lib]
            name = "helper_lib"
        "#,
    );
    workspace.write(
        "helper/src/lib.rs",
        "#[macro_export] macro_rules! load { () => { include!(\"payload.inc\"); } }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        r#"
            [package]
            name = "example"
            version = "0.1.0"
            edition = "2024"
            [dependencies]
            helper-package = { path = "../../helper" }
            runne-macos-process-identity = { path = "../../identity" }
        "#,
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "use helper_lib::load; load!();",
    );
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

fn write_exporter(workspace: &TemporaryWorkspace, path: &str, name: &str, includes: bool) {
    workspace.write(
        &format!("{path}/Cargo.toml"),
        &format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\""),
    );
    let body = if includes {
        "include!(\"payload.inc\");"
    } else {
        ""
    };
    workspace.write(
        &format!("{path}/src/lib.rs"),
        &format!("#[macro_export] macro_rules! load {{ () => {{ {body} }} }}"),
    );
}

fn cargo_check_workspace(workspace: &TemporaryWorkspace) {
    let status = std::process::Command::new("cargo")
        .args(["check", "--workspace", "--offline", "--manifest-path"])
        .arg(workspace.path().join("Cargo.toml"))
        .status()
        .expect("cargo check workspace");
    assert!(status.success());
}
