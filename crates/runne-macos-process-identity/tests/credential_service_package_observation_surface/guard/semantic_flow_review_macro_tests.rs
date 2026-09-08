use std::path::PathBuf;

use super::super::analyzer::{GuardVerdict, analyze_source};
use super::super::semantic_acceptance_support::{assert_compiles, link_real_target};

const PRELUDE: &str = r"
use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
use runne_macos_process_identity::MacOsCredentialServicePackageObservationError as Error;
use runne_api::VerifiedSignedInstalledReleaseV2 as Release;
";

#[path = "semantic_flow_review_generated_member_tests.rs"]
mod generated_member_tests;

fn assert_calls(body: &str, name: &str) {
    let source = format!("{PRELUDE}\n{body}");
    assert_compiles(&source, name);
    let verdict = analyze_source(&source);
    assert!(
        matches!(verdict, GuardVerdict::Calls(ref calls) if !calls.is_empty()),
        "{name} must preserve the protected invocation: {verdict:?}"
    );
}

#[test]
fn type_macro_and_opaque_struct_literal_preserve_carriers() {
    assert_calls(
        r"macro_rules! pending_type { () => { Pending } }
        fn production(pending: pending_type!(), release: &Release) {
            let _ = pending.verify_exact(release);
        }",
        "flow_review_type_macro",
    );
    let helper = "pub struct Holder<T> { pub call: T }";
    let consumer = format!(
        "{PRELUDE}\nuse flow_helper::Holder; fn production() {{ let _ = (Holder {{ call: Pending::capture_current }}.call)(); }}"
    );
    assert_compiles_with_helper(helper, &consumer, "flow_review_opaque_struct");
    assert!(matches!(analyze_source(&consumer), GuardVerdict::Calls(_)));
}

#[test]
fn generated_impl_mod_trait_const_and_nested_macro_are_traversed() {
    assert_calls(
        r"struct Runner;
        macro_rules! add_impl { () => { impl Runner { fn production() { let _ = Pending::capture_current(); } } } }
        add_impl!();",
        "flow_review_generated_impl",
    );
    assert_calls(
        r"macro_rules! add_mod { () => { mod generated { fn production() { let _ = super::Pending::capture_current(); } } } }
        add_mod!();",
        "flow_review_generated_mod",
    );
    assert_calls(
        r"macro_rules! add_trait { () => { trait Generated { fn production() { let _ = Pending::capture_current(); } } } }
        add_trait!();",
        "flow_review_generated_trait",
    );
    assert_calls(
        r"macro_rules! add_const { () => { const GENERATED: fn() = || { let _ = Pending::capture_current(); }; } }
        add_const!();",
        "flow_review_generated_const",
    );
    assert_calls(
        r"macro_rules! inner { () => { fn production() { let _ = Pending::capture_current(); } } }
        macro_rules! outer { () => { inner!(); } }
        outer!();",
        "flow_review_generated_nested_macro",
    );
}

#[test]
fn opaque_external_macros_fail_closed_for_empty_block_and_dsl_arguments() {
    let cases = [
        (
            "#[macro_export] macro_rules! emit { () => { pub fn production() {} } }",
            "flow_helper::emit!();",
            "empty",
        ),
        (
            "#[macro_export] macro_rules! emit { ($body:block) => { pub fn production() { $body } } }",
            &format!("{PRELUDE}\nflow_helper::emit!({{ let _ = Pending::capture_current(); }});"),
            "block",
        ),
        (
            "#[macro_export] macro_rules! emit { ($($token:tt)*) => { pub fn production() {} } }",
            "flow_helper::emit!(target => opaque);",
            "dsl",
        ),
    ];
    for (helper, consumer, name) in cases {
        assert_compiles_with_helper(helper, consumer, name);
        assert!(
            matches!(analyze_source(consumer), GuardVerdict::Inconclusive(_)),
            "opaque {name} macro must fail closed"
        );
    }
}

#[test]
fn opaque_callable_consumer_is_inconclusive() {
    let helper = "pub fn invoke<T>(capture: fn() -> T) -> T { capture() }";
    let consumer = format!(
        "{PRELUDE}\nuse flow_helper::invoke; fn production() {{ let _ = invoke(Pending::capture_current); }}"
    );
    assert_compiles_with_helper(helper, &consumer, "flow_review_external_callable");
    assert!(matches!(
        analyze_source(&consumer),
        GuardVerdict::Inconclusive(_)
    ));
}

#[test]
fn local_type_generic_and_generated_definition_controls_stay_clean() {
    let cases = [
        (
            r"macro_rules! scalar_type { () => { u8 } }
            fn production(value: scalar_type!()) { let _ = value; }",
            "flow_review_scalar_type_macro",
        ),
        (
            "fn identity<T>(value: T) -> T { value } fn production() { let _ = identity(42_u8); }",
            "flow_review_generic_non_target",
        ),
        (
            r"macro_rules! inner { () => { fn hidden() { let _ = Pending::capture_current(); } } }
            macro_rules! outer { () => { inner!(); } }
            fn production() {}",
            "flow_review_uninvoked_generated_definition",
        ),
        (
            r"fn unrelated() -> Result<Pending, Error> { loop {} }
            struct Holder<T> { call: T }
            fn production() { let _ = (Holder { call: unrelated }.call)(); }",
            "flow_review_non_target_callable_field",
        ),
    ];
    for (body, name) in cases {
        let source = format!("{PRELUDE}\n{body}");
        assert_compiles(&source, name);
        assert_eq!(analyze_source(&source), GuardVerdict::Clean, "{name}");
    }
}

#[test]
fn cfg_attr_only_flags_expansions_that_may_apply_in_production() {
    let inactive = "#[cfg_attr(test, opaque::inject)] fn production() {}";
    assert_compiles(inactive, "flow_review_inactive_cfg_attr");
    assert_eq!(analyze_source(inactive), GuardVerdict::Clean);

    let symbolic = "#[cfg_attr(feature = \"active\", opaque::inject)] fn production() {}";
    assert_compiles(symbolic, "flow_review_symbolic_cfg_attr");
    assert!(matches!(
        analyze_source(symbolic),
        GuardVerdict::Inconclusive(_)
    ));
}

fn assert_compiles_with_helper(helper: &str, consumer: &str, name: &str) {
    let directory = TempDirectory::new(name);
    let helper_path = directory.0.join("helper.rs");
    let helper_rlib = directory.0.join("libflow_helper.rlib");
    std::fs::write(&helper_path, helper).unwrap();
    let helper_output = std::process::Command::new("rustc")
        .args([
            "--crate-name",
            "flow_helper",
            "--crate-type",
            "rlib",
            "--edition",
            "2024",
        ])
        .arg(&helper_path)
        .arg("-o")
        .arg(&helper_rlib)
        .output()
        .unwrap();
    assert!(
        helper_output.status.success(),
        "helper failed: {}",
        String::from_utf8_lossy(&helper_output.stderr)
    );
    let consumer_path = directory.0.join("consumer.rs");
    std::fs::write(&consumer_path, consumer).unwrap();
    let mut command = std::process::Command::new("rustc");
    command
        .args(["--crate-type", "rlib", "--edition", "2024"])
        .arg(&consumer_path);
    link_real_target(&mut command);
    let output = command
        .arg("--extern")
        .arg(format!("flow_helper={}", helper_rlib.display()))
        .arg("-o")
        .arg(directory.0.join("consumer.rlib"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "consumer {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(name: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "runne-flow-review-{}-{unique}-{name}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
