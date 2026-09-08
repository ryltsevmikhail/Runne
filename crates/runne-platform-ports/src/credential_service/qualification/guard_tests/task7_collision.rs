use super::{find_production_callers, fixture};

#[test]
fn caller_guard_fails_closed_on_same_named_inline_module_macros() {
    let source = fixture(
        "src/module_macro_collision.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod a { use super::CredentialServiceQualificationPort; macro_rules! invoke { ($port:expr) => { $port.qualify() }; } pub fn release<T: CredentialServiceQualificationPort>(port: &T) { invoke!(port); } } mod b { macro_rules! invoke { ($port:expr) => {}; } pub fn release() { invoke!(()); } }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_allows_a_unique_inline_module_macro_for_an_unrelated_trait() {
    let source = fixture(
        "src/module_macro_control.rs",
        "trait Probe { fn qualify(&self); } mod control { macro_rules! invoke { ($port:expr) => { $port.qualify() }; } pub fn release(port: &dyn super::Probe) { invoke!(port); } }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn caller_guard_catches_a_local_concrete_implementer_through_a_macro() {
    let source = fixture(
        "src/concrete_macro.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } macro_rules! invoke { ($port:expr) => { $port.qualify() }; } fn release(port: &Client) { invoke!(port); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_ignores_a_function_local_macro_definition_without_invocation() {
    let source = fixture(
        "src/function_macro_definition.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } fn inspect<T: CredentialServiceQualificationPort>(_port: &T) { macro_rules! helper { () => {}; } }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn caller_guard_fails_closed_on_imported_macro_before_later_local_shadowing() {
    let source = fixture(
        "src/macro_order.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } #[macro_export] macro_rules! external { ($port:expr) => { $port.qualify() }; } mod nested { use crate::{external as invoke, CredentialServiceQualificationPort}; pub fn before<T: CredentialServiceQualificationPort>(port: &T) { invoke!(port); } macro_rules! invoke { ($port:expr) => {}; } pub fn after<T: CredentialServiceQualificationPort>(_port: &T) { invoke!(_port); } }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_catches_qualification_function_items() {
    let source = fixture(
        "src/function_items.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } fn generic<T: CredentialServiceQualificationPort>(port: &T) { let action: fn(&T) = T::qualify; action(port); } fn concrete(port: &Client) { let action: fn(&Client) = Client::qualify; action(port); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 2);
}
