use super::super::analyzer::{GuardVerdict, analyze_source};
use super::super::inventory_tests::{TemporaryWorkspace, cargo_check, workspace};
use super::super::semantic_acceptance_support::assert_compiles;

const PRELUDE: &str = r"
use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
use runne_macos_process_identity::MacOsCredentialServicePackageObservationError as Error;
type Capture = fn() -> Result<Pending, Error>;
";

fn assert_non_clean(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    assert!(
        !matches!(analyze_source(&source), GuardVerdict::Clean),
        "{name}: {:?}",
        analyze_source(&source)
    );
}

#[test]
fn macro_generated_callee_behind_parentheses_fails_closed() {
    assert_non_clean(
        r"macro_rules! generate { () => { fn invoke(callback: Capture) { let _ = callback(); } } }
          generate!();
          fn production() { (invoke)(Pending::capture_current); }",
        "native_p1_parenthesized_generated_callee",
    );
}

#[test]
fn macro_generated_const_behind_single_tail_block_fails_closed() {
    assert_non_clean(
        r"macro_rules! generate { () => { const CAPTURE: Capture = Pending::capture_current; } }
          generate!();
          fn production() { let _ = { CAPTURE }(); }",
        "native_p1_block_generated_const",
    );
}

#[test]
fn macro_generated_callee_behind_reference_fails_closed() {
    assert_non_clean(
        r"macro_rules! generate { () => { fn invoke(callback: Capture) { let _ = callback(); } } }
          generate!();
          fn production() { (&invoke)(Pending::capture_current); }",
        "native_p1_reference_generated_callee",
    );
}

#[test]
fn macro_generated_const_behind_reference_fails_closed() {
    assert_non_clean(
        r"macro_rules! generate { () => { const CAPTURE: Capture = Pending::capture_current; } }
          generate!();
          fn production() { let _ = (&CAPTURE)(); }",
        "native_p1_reference_generated_const",
    );
}

#[test]
fn direct_canonical_glob_import_typed_receiver_fails_closed() {
    let source = r"
use runne_api::VerifiedSignedInstalledReleaseV2 as Release;
use runne_macos_process_identity::*;
fn production(pending: MacOsPendingCredentialServicePackageObservationV1, release: &Release) {
    let _ = pending.verify_exact(release);
}
";
    assert_compiles(source, "native_p1_direct_glob_typed_receiver");
    assert!(
        matches!(analyze_source(source), GuardVerdict::Calls(ref calls) if !calls.is_empty()),
        "native_p1_direct_glob_typed_receiver: {:?}",
        analyze_source(source)
    );
}

#[test]
fn transitive_facade_reexport_is_included_in_public_gate() {
    let workspace = facade_workspace(
        "use facade::Pending; fn production() { let _ = Pending::capture_current(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn qualified_facade_reference_is_included_in_public_gate() {
    let workspace =
        facade_workspace("fn production() { let _ = facade::Pending::capture_current(); }");
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn aliased_facade_reference_is_included_in_public_gate() {
    let workspace = facade_workspace(
        "use facade as provider; fn production() { let _ = provider::Pending::capture_current(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn grouped_self_facade_alias_is_included_in_public_gate() {
    let workspace = facade_workspace(
        "use facade::{self as provider}; fn production() { let _ = provider::Pending::capture_current(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn reexported_grouped_self_facade_alias_is_included_in_public_gate() {
    let workspace = facade_bridge_workspace("pub use facade::{self as provider};");
    workspace.write(
        "crates/example/src/lib.rs",
        "fn production() { let _ = bridge::provider::Pending::capture_current(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn transitive_facade_glob_reexport_is_included_in_public_gate() {
    let workspace = facade_bridge_workspace("pub use facade::*;");
    workspace.write(
        "crates/example/src/lib.rs",
        "fn production() { let _ = bridge::Pending::capture_current(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn exported_macro_body_with_direct_target_call_is_included_in_public_gate() {
    let workspace = workspace();
    write_consumer_manifest(
        &workspace,
        "helper = { path = \"../../helper\" }\nrunne-macos-process-identity = { path = \"../../identity\" }",
    );
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "helper/src/lib.rs",
        "#[macro_export] macro_rules! capture { () => { runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current() } }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "fn production() { let _ = helper::capture!(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn block_local_facade_use_is_included_in_public_gate() {
    let workspace = facade_workspace(
        "fn production() { use facade::Pending; let _ = Pending::capture_current(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn cross_file_private_root_import_is_included_in_public_gate() {
    let workspace = workspace();
    write_consumer_manifest(&workspace, "facade = { path = \"../../facade\" }");
    workspace.write(
        "facade/Cargo.toml",
        "[package]\nname = \"facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "facade/src/lib.rs",
        "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; mod child; pub use child::production;",
    );
    workspace.write(
        "facade/src/child.rs",
        "pub fn production() { let _ = super::Pending::capture_current(); }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "use facade::production; fn invoke() { let _ = production(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn extern_crate_facade_alias_is_included_in_public_gate() {
    let workspace = facade_workspace(
        "extern crate facade as provider; fn production() { let _ = provider::Pending::capture_current(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn cross_crate_macro_consumer_is_included_in_public_gate() {
    let workspace = workspace();
    write_consumer_manifest(&workspace, "helper = { path = \"../../helper\" }");
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "helper/src/lib.rs",
        "pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; #[macro_export] macro_rules! capture { () => { $crate::Pending::capture_current() } }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "use helper::capture; fn production() { let _ = capture!(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn qualified_cross_crate_macro_is_included_in_public_gate() {
    let workspace = workspace();
    write_consumer_manifest(&workspace, "helper = { path = \"../../helper\" }");
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "helper/src/lib.rs",
        "pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; #[macro_export] macro_rules! capture { () => { $crate::Pending::capture_current() } }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "fn production() { let _ = helper::capture!(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

#[test]
fn aliased_cross_crate_macro_is_included_in_public_gate() {
    let workspace = workspace();
    write_consumer_manifest(&workspace, "helper = { path = \"../../helper\" }");
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "helper/src/lib.rs",
        "pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; #[macro_export] macro_rules! capture { () => { $crate::Pending::capture_current() } }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "use helper as provider; fn production() { let _ = provider::capture!(); }",
    );
    assert_public_gate_is_not_clean(&workspace);
}

fn facade_workspace(consumer: &str) -> TemporaryWorkspace {
    let workspace = workspace();
    write_consumer_manifest(&workspace, "facade = { path = \"../../facade\" }");
    workspace.write(
        "facade/Cargo.toml",
        "[package]\nname = \"facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "facade/src/lib.rs",
        "pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;",
    );
    workspace.write("crates/example/src/lib.rs", consumer);
    workspace
}

fn facade_bridge_workspace(bridge: &str) -> TemporaryWorkspace {
    let workspace = workspace();
    write_consumer_manifest(&workspace, "bridge = { path = \"../../bridge\" }");
    workspace.write(
        "facade/Cargo.toml",
        "[package]\nname = \"facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "facade/src/lib.rs",
        "pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;",
    );
    workspace.write(
        "bridge/Cargo.toml",
        "[package]\nname = \"bridge\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nfacade = { path = \"../facade\" }",
    );
    workspace.write("bridge/src/lib.rs", bridge);
    workspace
}

fn write_consumer_manifest(workspace: &TemporaryWorkspace, dependency: &str) {
    workspace.write(
        "crates/example/Cargo.toml",
        &format!("[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\npath = \"src/lib.rs\"\n[dependencies]\n{dependency}"),
    );
}

fn assert_public_gate_is_not_clean(workspace: &TemporaryWorkspace) {
    cargo_check(workspace);
    let facade = workspace.path().join("crates/example/src/lib.rs");
    let result = std::panic::catch_unwind(|| {
        super::super::assert_workspace_has_no_credential_service_calls(workspace.path(), &facade);
    });
    assert!(result.is_err(), "public gate accepted a protected call");
}
