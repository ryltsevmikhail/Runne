use super::*;

#[test]
fn nested_impl_trait_macros_and_associated_consts_are_analyzed() {
    assert_calls(
        r"struct Runner;
        macro_rules! inner { () => { fn generated() { let _ = Pending::capture_current(); } } }
        macro_rules! outer { () => { impl Runner { inner!(); } } }
        outer!();",
        "flow_review_generated_impl_inner_macro",
    );
    assert_calls(
        r"macro_rules! inner { () => { fn generated() { let _ = Pending::capture_current(); } } }
        macro_rules! outer { () => { trait Generated { inner!(); } } }
        outer!();",
        "flow_review_generated_trait_inner_macro",
    );
    assert_calls(
        r"struct Runner;
        macro_rules! inner { () => { const CAPTURE: fn() = || { let _ = Pending::capture_current(); }; } }
        macro_rules! outer { () => { impl Runner { inner!(); } } }
        outer!();",
        "flow_review_generated_associated_const",
    );
    assert_calls(
        r"struct Runner { pending: Pending }
        macro_rules! inner { () => { fn generated(self, release: &Release) { let _ = self.pending.verify_exact(release); } } }
        macro_rules! outer { () => { impl Runner { #[cfg(not(test))] inner!(); } } }
        outer!();",
        "flow_review_generated_impl_self_type",
    );
}

#[test]
fn generated_member_macro_reference_alone_stays_clean() {
    let source = format!(
        "{PRELUDE}\n{}",
        r"struct Runner;
        macro_rules! inner { () => { const CAPTURE: fn() -> Result<Pending, Error> = Pending::capture_current; } }
        macro_rules! outer { () => { impl Runner { inner!(); } } }
        outer!();"
    );
    assert_compiles(&source, "flow_review_generated_member_reference");
    assert_eq!(analyze_source(&source), GuardVerdict::Clean);
}

#[test]
fn opaque_generated_member_macro_fails_closed() {
    let helper = r"#[macro_export]
        macro_rules! emit { () => { fn generated() { let _ = ::runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); } } }";
    let consumer = format!(
        "{PRELUDE}\nstruct Runner; macro_rules! outer {{ () => {{ impl Runner {{ flow_helper::emit!(); }} }} }} outer!();"
    );
    assert_compiles_with_helper(helper, &consumer, "flow_review_opaque_generated_member");
    assert!(matches!(
        analyze_source(&consumer),
        GuardVerdict::Inconclusive(_)
    ));
}

#[test]
fn generated_member_cfg_excludes_test_only_expansions() {
    let source = format!(
        "{PRELUDE}\n{}",
        r"struct Runner;
        macro_rules! inner { () => { fn generated() { let _ = Pending::capture_current(); } } }
        macro_rules! outer { () => { impl Runner { #[cfg(test)] inner!(); } } }
        outer!();"
    );
    assert_compiles(&source, "flow_review_generated_member_cfg_test");
    assert_eq!(analyze_source(&source), GuardVerdict::Clean);
}

#[test]
fn opaque_attribute_on_generated_member_fails_closed() {
    let directory = TempDirectory::new("flow_review_generated_member_attr");
    let helper = directory.0.join("attr.rs");
    let dylib = directory.0.join("libflow_attr.dylib");
    std::fs::write(
        &helper,
        r#"extern crate proc_macro;
        use proc_macro::TokenStream;
        #[proc_macro_attribute]
        pub fn inject(_: TokenStream, _: TokenStream) -> TokenStream {
            "fn generated() { let _ = ::runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current(); }".parse().unwrap()
        }"#,
    )
    .unwrap();
    let output = std::process::Command::new("rustc")
        .args(["--crate-name", "flow_attr", "--crate-type", "proc-macro"])
        .arg(&helper)
        .arg("-o")
        .arg(&dylib)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let source = format!(
        "{PRELUDE}\nstruct Runner; macro_rules! outer {{ () => {{ impl Runner {{ #[flow_attr::inject] fn placeholder() {{}} }} }} }} outer!();"
    );
    let consumer = directory.0.join("consumer.rs");
    std::fs::write(&consumer, &source).unwrap();
    let mut command = std::process::Command::new("rustc");
    command
        .args(["--crate-type", "rlib", "--edition", "2024"])
        .arg(&consumer);
    link_real_target(&mut command);
    let output = command
        .arg("--extern")
        .arg(format!("flow_attr={}", dylib.display()))
        .arg("-o")
        .arg(directory.0.join("consumer.rlib"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(matches!(
        analyze_source(&source),
        GuardVerdict::Inconclusive(_)
    ));
}
