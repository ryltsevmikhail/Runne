use super::{find_production_callers, fixture};

#[test]
fn opaque_external_macros_cannot_hide_qualification_invocations() {
    let invocation = fixture(
        "src/external_invocation.rs",
        "fn selected() -> Client { Client } fn release() { external_proc::invoke!(selected()); }",
        false,
    );
    let attribute = fixture(
        "src/external_attribute.rs",
        "#[external_proc::inject] fn release() {}",
        false,
    );
    let conditional_attribute = fixture(
        "src/conditional_external_attribute.rs",
        "#[cfg_attr(any(), external_proc::inject)] fn release() {}",
        false,
    );
    let local = fixture(
        "src/local.rs",
        "macro_rules! invoke { () => { selected().qualify() } } fn release() { invoke!(); }",
        false,
    );
    let imported = fixture(
        "src/imported.rs",
        "use external_proc::invoke; fn release() { invoke!(selected()); }",
        false,
    );
    let item = fixture("src/item.rs", "external_proc::generate!();", false);
    assert_eq!(
        find_production_callers(&[
            invocation,
            attribute,
            conditional_attribute,
            local,
            imported,
            item,
        ])
        .len(),
        5
    );
}

#[test]
fn audited_external_macros_remain_usable_outside_qualification_context() {
    let mut unit = fixture(
        "src/release.rs",
        "#[cfg_attr(test, allow(dead_code))] fn release() { let _ = serde_json::json!({\"ready\": true}); }",
        false,
    );
    unit.trusted_external_roots.insert("serde_json".to_owned());
    let findings = find_production_callers(&[unit]);

    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn trusted_macro_spelling_cannot_be_impersonated() {
    let mut unit = fixture(
        "src/spoof.rs",
        "use external_proc as serde_json; fn release() { serde_json::json!(); }",
        false,
    );
    unit.trusted_external_roots.insert("serde_json".to_owned());
    assert_eq!(find_production_callers(&[unit]).len(), 1);
}

#[test]
fn inferred_and_temporary_qualification_receivers_are_rejected() {
    let source = fixture(
        "src/inferred.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } fn selected() -> Client { Client } fn release() { let client = Client; client.qualify(); selected().qualify(); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 2);
}

#[test]
fn statement_include_fragments_are_parsed_and_fail_closed() {
    let fragment = fixture(
        "src/body.inc",
        "if enabled() { external_proc::invoke!(selected()); }",
        false,
    );
    assert_eq!(find_production_callers(&[fragment]).len(), 1);
}

#[test]
fn opaque_member_attributes_and_derives_are_rejected() {
    let member = fixture(
        "src/member.rs",
        "struct Host; impl Host { #[external_proc::inject] fn release() {} }",
        false,
    );
    let derive = fixture(
        "src/derive.rs",
        "#[derive(external_proc::Inject)] struct Marker;",
        false,
    );
    assert_eq!(find_production_callers(&[member, derive]).len(), 2);
}

#[test]
fn trusted_spellings_cannot_hide_imported_macros_or_derives() {
    let imported_builtin = fixture(
        "src/imported_builtin.rs",
        "use external_proc::matches; fn release() { matches!(); }",
        false,
    );
    let imported_derive = fixture(
        "src/imported_derive.rs",
        "use external_proc::Clone; #[derive(Clone)] struct Marker;",
        false,
    );
    assert_eq!(
        find_production_callers(&[imported_builtin, imported_derive]).len(),
        2
    );
}

#[test]
fn nested_local_module_cannot_spoof_a_trusted_macro_root() {
    let mut unit = fixture(
        "src/nested_std_spoof.rs",
        "mod child { mod std { pub use crate::evil_matches as matches; } fn release<T: CredentialServiceQualificationPort>(port: &T) { std::matches!(port); } }",
        false,
    );
    unit.trusted_external_roots.insert("std".to_owned());
    assert_eq!(find_production_callers(&[unit]).len(), 1);
}

#[test]
fn macro_bodies_cannot_hide_imported_attributes_or_derives() {
    let imported_attribute = fixture(
        "src/imported_attribute_body.rs",
        "use external_proc::inject; macro_rules! outer { () => { #[inject] fn generated() {} } } outer!();",
        false,
    );
    let imported_derive = fixture(
        "src/imported_derive_body.rs",
        "use external_proc::Serialize; macro_rules! outer { () => { #[derive(Serialize)] struct Generated; } } outer!();",
        false,
    );
    assert_eq!(
        find_production_callers(&[imported_attribute, imported_derive]).len(),
        2
    );
}

#[test]
fn macro_bodies_fail_closed_on_qualified_proc_derives_and_macro_paths() {
    let qualified_derive = fixture(
        "src/qualified_derive_body.rs",
        "macro_rules! outer { () => { #[derive(external_proc::Serialize)] struct Generated; } } outer!();",
        false,
    );
    let qualified_macro = fixture(
        "src/qualified_macro_body.rs",
        "macro_rules! outer { () => { serde_json::json!({}); } } outer!();",
        false,
    );
    let shadowed_derive_root = fixture(
        "src/shadowed_derive_root.rs",
        "use external_proc as serde; macro_rules! outer { () => { #[derive(serde::Serialize)] struct Generated; } } outer!();",
        false,
    );
    assert_eq!(
        find_production_callers(&[qualified_derive, qualified_macro, shadowed_derive_root]).len(),
        3
    );
}

#[test]
fn every_attribute_is_checked() {
    let mut unit = fixture(
        "src/stacked.rs",
        "#[tauri::command] #[external_proc::inject] fn release() {}",
        false,
    );
    unit.trusted_external_roots.insert("tauri".to_owned());
    assert_eq!(find_production_callers(&[unit]).len(), 1);
}

#[test]
fn cfg_attr_uses_production_truth() {
    let false_case = fixture(
        "src/false.rs",
        "#[cfg_attr(test, external_proc::inject)] fn release() {}",
        false,
    );
    let true_case = fixture(
        "src/true.rs",
        "#[cfg_attr(not(test), external_proc::inject)] fn release() {}",
        false,
    );
    let symbolic = fixture(
        "src/symbolic.rs",
        "#[cfg_attr(feature = \"x\", external_proc::inject)] fn release() {}",
        false,
    );
    assert_eq!(
        find_production_callers(&[false_case, true_case, symbolic]).len(),
        2
    );
}

#[test]
fn raw_identifiers_and_carrier_receivers_are_rejected() {
    let raw = fixture(
        "src/raw.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } fn release<T: r#CredentialServiceQualificationPort>(p: &T) { p.r#qualify(); r#CredentialServiceQualificationPort::r#qualify(p); }",
        false,
    );
    let carriers = fixture(
        "src/carriers.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } struct Holder { client: Client } fn selected() -> Client { Client } fn release(holder: Holder) { holder.client.qualify(); let client = selected(); client.qualify(); let referenced = &client; referenced.qualify(); }",
        false,
    );
    assert_eq!(find_production_callers(&[raw]).len(), 2);
    assert_eq!(find_production_callers(&[carriers]).len(), 3);
}
