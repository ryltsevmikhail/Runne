use super::{find_production_callers, fixture};

#[test]
fn caller_guard_follows_cross_file_aliases_to_concrete_implementers() {
    let sources = [
        fixture(
            "src/client.rs",
            "pub trait CredentialServiceQualificationPort { fn qualify(&self); } pub struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } pub struct ProbeClient; trait Probe { fn qualify(&self); } impl Probe for ProbeClient { fn qualify(&self) {} }",
            false,
        ),
        fixture(
            "src/aliases.rs",
            "pub type ClientAlias = crate::client::Client; pub type ProbeAlias = crate::client::ProbeClient;",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::client::*; use crate::aliases::{ClientAlias, ProbeAlias}; fn release(client: &ClientAlias) { client.qualify(); } fn control(probe: &ProbeAlias) { probe.qualify(); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 1);
}

#[test]
fn caller_guard_resolves_imported_macro_order_for_all_delimiters_and_whitespace() {
    let brace = fixture(
        "src/brace.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } #[macro_export] macro_rules! external { ($port:expr) => { $port.qualify() }; } mod nested { use crate::{external as invoke, CredentialServiceQualificationPort}; fn before<T: CredentialServiceQualificationPort>(port: &T) { invoke! { port }; } macro_rules! invoke { ($port:expr) => {}; } fn after<T: CredentialServiceQualificationPort>(_port: &T) { invoke![_port]; } }",
        false,
    );
    let newline = fixture(
        "src/newline.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } #[macro_export] macro_rules! external { ($port:expr) => { $port.qualify() }; } mod nested { use crate::{external as\ninvoke, CredentialServiceQualificationPort}; fn before<T: CredentialServiceQualificationPort>(port: &T) { invoke! (port); } macro_rules! invoke { ($port:expr) => {}; } fn after<T: CredentialServiceQualificationPort>(_port: &T) { invoke! { _port }; } }",
        false,
    );
    assert_eq!(find_production_callers(&[brace]).len(), 1);
    assert_eq!(find_production_callers(&[newline]).len(), 1);
}

#[test]
fn caller_guard_ignores_cfg_test_match_arms_and_trait_members() {
    let source = fixture(
        "src/cfg_members.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); #[cfg(test)] fn helper(&self) { self.qualify(); } #[cfg_attr(not(test), cfg(test))] fn nested(&self) { self.qualify(); } } fn release<T: CredentialServiceQualificationPort>(port: &T, value: bool) { match value { #[cfg(test)] _ => port.qualify(), #[cfg_attr(not(test), cfg(test))] false => port.qualify(), _ => {} } }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn caller_guard_allows_clean_function_local_and_module_local_macro_collisions() {
    let source = fixture(
        "src/clean_macros.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); fn observe(&self); } fn local<T: CredentialServiceQualificationPort>(port: &T) { macro_rules! helper { ($port:expr) => { $port.observe() }; } helper!(port); } mod a { use super::CredentialServiceQualificationPort; macro_rules! invoke { ($port:expr) => { $port.observe() }; } pub fn release<T: CredentialServiceQualificationPort>(port: &T) { invoke!(port); } } mod b { use super::CredentialServiceQualificationPort; macro_rules! invoke { ($port:expr) => { $port.observe() }; } pub fn release<T: CredentialServiceQualificationPort>(port: &T) { invoke!(port); } }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn caller_guard_keeps_method_evidence_at_the_call_site() {
    let source = fixture(
        "src/evidence.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } trait Probe { fn qualify(&self); } fn protected(port: &Client) { port.qualify(); } fn inspect(probe: &dyn Probe) { probe.qualify(); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}
