use super::{find_production_callers, fixture};

#[test]
fn metadata_backed_nested_warning_and_sql_parameter_macros_are_trusted() {
    let mut source = fixture(
        "src/trusted_nested.rs",
        "fn run() { tokio::select! { _ = async {} => { tracing::warn!(\"done\"); } } } macro_rules! bind { () => { rusqlite::params![1] }; } fn query() { bind!(); }",
        false,
    );
    source.trusted_external_roots.extend([
        "tokio".to_owned(),
        "tracing".to_owned(),
        "rusqlite".to_owned(),
    ]);

    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn same_terminal_nested_macro_from_untrusted_root_stays_fail_closed() {
    let mut source = fixture(
        "src/untrusted_nested.rs",
        "fn run() { tokio::select! { _ = async {} => { impostor::warn!(\"done\"); } } } macro_rules! bind { () => { impostor::params![1] }; } fn query() { bind!(); }",
        false,
    );
    source.trusted_external_roots.insert("tokio".to_owned());

    assert_eq!(find_production_callers(&[source]).len(), 2);
}

#[test]
fn nested_full_std_and_core_paths_use_exact_builtin_provenance() {
    let mut source = fixture(
        "src/full_builtin_paths.rs",
        "fn run() { tokio::select! { _ = async {} => { let _ = std::mem::offset_of!(Pair, field); let _ = std::ptr::addr_of_mut!(VALUE); let _ = core::stringify!(safe); } } }",
        false,
    );
    source.trusted_external_roots.insert("tokio".to_owned());

    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn nested_builtin_terminal_from_another_qualified_path_stays_untrusted() {
    let mut source = fixture(
        "src/untrusted_builtin_path.rs",
        "fn run() { tokio::select! { _ = async {} => { let _ = fake::offset_of!(Pair, field); } } }",
        false,
    );
    source.trusted_external_roots.insert("tokio".to_owned());

    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn builtin_full_path_with_shadowed_std_root_stays_fail_closed() {
    let mut source = fixture(
        "src/shadowed_std.rs",
        "use impostor as std; fn run() { tokio::select! { _ = async {} => { let _ = std::mem::offset_of!(Pair, field); } } }",
        false,
    );
    source.trusted_external_roots.insert("tokio".to_owned());

    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn nested_trusted_spelling_with_shadowed_root_stays_fail_closed() {
    let mut source = fixture(
        "src/shadowed_nested.rs",
        "use impostor as tracing; fn run() { tokio::select! { _ = async {} => { tracing::warn!(\"done\"); } } }",
        false,
    );
    source
        .trusted_external_roots
        .extend(["tokio".to_owned(), "tracing".to_owned()]);

    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn bare_warning_and_select_spellings_remain_untrusted_nested_calls() {
    for nested in ["warn!(\"x\");", "select! {}; "] {
        let source_text =
            format!("fn run() {{ tokio::select! {{ _ = async {{}} => {{ {nested} }} }} }}");
        let mut source = fixture("src/bare_nested.rs", &source_text, false);
        source.trusted_external_roots.insert("tokio".to_owned());
        assert_eq!(find_production_callers(&[source]).len(), 1, "{nested}");
    }
}

#[test]
fn literal_include_resolves_an_ordinary_local_macro_definition() {
    let caller = fixture(
        "src/main.rs",
        "include!(\"helpers.rs\"); fn run() { helper!(); }",
        false,
    );
    let helper = fixture(
        "src/helpers.rs",
        "macro_rules! helper { () => { let _value = 1; }; }",
        false,
    );

    assert!(find_production_callers(&[caller, helper]).is_empty());
}

#[test]
fn included_local_macro_with_qualification_stays_detected() {
    let caller = fixture(
        "src/main.rs",
        "include!(\"helpers.rs\"); fn run<T: CredentialServiceQualificationPort>(port: &T) { helper!(port); }",
        false,
    );
    let helper = fixture(
        "src/helpers.rs",
        "macro_rules! helper { ($port:expr) => { $port.qualify() }; }",
        false,
    );

    assert_eq!(find_production_callers(&[caller, helper]).len(), 1);
}

#[test]
fn included_macro_cannot_use_a_root_shadowed_by_its_caller() {
    let mut caller = fixture(
        "src/main.rs",
        "use impostor as tracing; include!(\"helpers.rs\"); fn run() { helper!(); }",
        false,
    );
    caller.trusted_external_roots.insert("tracing".to_owned());
    let mut helper = fixture(
        "src/helpers.rs",
        "macro_rules! helper { () => { tracing::warn!(\"x\"); }; }",
        false,
    );
    helper.trusted_external_roots.insert("tracing".to_owned());

    assert_eq!(find_production_callers(&[caller, helper]).len(), 1);
}

#[test]
fn latest_include_definition_shadows_an_earlier_local_macro() {
    let caller = fixture(
        "src/main.rs",
        "macro_rules! helper { () => {}; } include!(\"helpers.rs\"); fn run() { helper!(); }",
        false,
    );
    let helper = fixture(
        "src/helpers.rs",
        "macro_rules! helper { () => { port.qualify() }; }",
        false,
    );

    assert_eq!(find_production_callers(&[caller, helper]).len(), 1);
}

#[test]
fn latest_local_definition_shadows_an_earlier_include_macro() {
    let caller = fixture(
        "src/main.rs",
        "include!(\"helpers.rs\"); macro_rules! helper { () => { port.qualify() }; } fn run() { helper!(); }",
        false,
    );
    let helper = fixture("src/helpers.rs", "macro_rules! helper { () => {}; }", false);

    assert_eq!(find_production_callers(&[caller, helper]).len(), 1);
}

#[test]
fn conditional_include_can_shadow_a_prior_benign_local_macro() {
    let caller = fixture(
        "src/main.rs",
        "macro_rules! helper { () => {}; } #[cfg(feature = \"optional\")] include!(\"helpers.rs\"); fn run() { helper!(); }",
        false,
    );
    let helper = fixture(
        "src/helpers.rs",
        "macro_rules! helper { () => { port.qualify() }; }",
        false,
    );

    assert_eq!(find_production_callers(&[caller, helper]).len(), 1);
}

#[test]
fn later_local_macro_unambiguously_shadows_a_conditional_include() {
    let caller = fixture(
        "src/main.rs",
        "#[cfg(feature = \"optional\")] include!(\"helpers.rs\"); macro_rules! helper { () => {}; } fn run() { helper!(); }",
        false,
    );
    let helper = fixture(
        "src/helpers.rs",
        "macro_rules! helper { () => { port.qualify() }; }",
        false,
    );

    assert!(find_production_callers(&[caller, helper]).is_empty());
}

#[test]
fn conditional_macro_definition_in_an_included_file_stays_fail_closed() {
    let caller = fixture(
        "src/main.rs",
        "include!(\"helpers.rs\"); fn run() { helper!(); }",
        false,
    );
    let helper = fixture(
        "src/helpers.rs",
        "#[cfg(feature = \"optional\")] macro_rules! helper { () => {}; }",
        false,
    );

    assert_eq!(find_production_callers(&[caller, helper]).len(), 1);
}

#[test]
fn conditional_macro_definition_shadows_an_earlier_included_definition() {
    let caller = fixture(
        "src/main.rs",
        "include!(\"helpers.rs\"); fn run() { helper!(); }",
        false,
    );
    let helper = fixture(
        "src/helpers.rs",
        "macro_rules! helper { () => {}; } #[cfg(feature = \"optional\")] macro_rules! helper { () => { port.qualify() }; }",
        false,
    );

    assert_eq!(find_production_callers(&[caller, helper]).len(), 1);
}

#[test]
fn include_after_call_and_test_only_include_do_not_resolve_macro() {
    let after_call = fixture(
        "src/main.rs",
        "fn run() { helper!(); } include!(\"helpers.rs\");",
        false,
    );
    let cfg_test_include = fixture(
        "src/test_only.rs",
        "#[cfg(test)] include!(\"helpers.rs\"); fn run() { helper!(); }",
        false,
    );
    let helper = fixture("src/helpers.rs", "macro_rules! helper { () => {}; }", false);

    assert_eq!(
        find_production_callers(&[after_call, helper.clone()]).len(),
        1
    );
    assert_eq!(
        find_production_callers(&[cfg_test_include, helper]).len(),
        1
    );
}

#[test]
fn dynamic_missing_and_ambiguous_includes_do_not_resolve_sibling_macros() {
    let dynamic = fixture(
        "src/dynamic.rs",
        "include!(HELPER_PATH); fn run() { helper!(); }",
        false,
    );
    let missing = fixture(
        "src/missing.rs",
        "include!(\"missing.rs\"); fn run() { helper!(); }",
        false,
    );
    let ambiguous = fixture(
        "src/ambiguous.rs",
        "#[cfg_attr(feature = \"other\", cfg(test))] include!(\"helpers.rs\"); fn run() { helper!(); }",
        false,
    );
    let conditional_dynamic = fixture(
        "src/conditional_dynamic.rs",
        "macro_rules! helper { () => {}; } #[cfg(feature = \"optional\")] include!(HELPER_PATH); fn run() { helper!(); }",
        false,
    );
    let helper = fixture("src/helpers.rs", "macro_rules! helper { () => {}; }", false);

    for source in [dynamic, missing, ambiguous, conditional_dynamic] {
        assert!(!find_production_callers(&[source, helper.clone()]).is_empty());
    }
}
