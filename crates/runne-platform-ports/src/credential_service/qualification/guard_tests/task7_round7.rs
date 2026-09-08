use super::{find_production_callers, fixture};

#[test]
fn catches_inherent_method_and_local_typed_receiver() {
    let inherent = fixture(
        "src/inherent.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Host; impl Host { fn release<T: CredentialServiceQualificationPort>(&self, port: &T) { port.qualify(); } }",
        false,
    );
    let local = fixture(
        "src/local.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } fn release() { let port: &dyn CredentialServiceQualificationPort = todo!(); port.qualify(); }",
        false,
    );
    assert_eq!(find_production_callers(&[inherent]).len(), 1);
    assert_eq!(find_production_callers(&[local]).len(), 1);
}

#[test]
fn catches_renamed_concrete_import() {
    let sources = [
        fixture(
            "src/client.rs",
            "pub trait CredentialServiceQualificationPort { fn qualify(&self); } pub struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} }",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::client::{CredentialServiceQualificationPort, Client as QualifiedClient}; fn release(client: &QualifiedClient) { client.qualify(); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 1);
}

#[test]
fn follows_ancestor_and_imported_macro_wrappers() {
    let ancestor = fixture(
        "src/ancestor.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } macro_rules! dangerous { ($port:expr) => { $port.qualify() }; } mod nested { use super::CredentialServiceQualificationPort; macro_rules! wrapper { ($port:expr) => { dangerous!($port) }; } fn release<T: CredentialServiceQualificationPort>(port: &T) { wrapper!(port); } }",
        false,
    );
    let imported = fixture(
        "src/imported.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::dangerous; macro_rules! wrapper { ($port:expr) => { dangerous!($port) }; } fn release<T: CredentialServiceQualificationPort>(port: &T) { wrapper!(port); }",
        false,
    );
    assert_eq!(find_production_callers(&[ancestor]).len(), 1);
    assert_eq!(find_production_callers(&[imported]).len(), 1);
}

#[test]
fn clean_nested_macro_and_matcher_name_do_not_trigger() {
    let source = fixture(
        "src/clean.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); fn observe(&self); } fn release<T: CredentialServiceQualificationPort>(port: &T, yes: bool) { if yes { macro_rules! helper { ($qualify:expr) => { $qualify.observe() }; } helper!(port); } }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn unrelated_short_name_collision_does_not_trigger() {
    let sources = [
        fixture(
            "src/q.rs",
            "pub trait CredentialServiceQualificationPort { fn qualify(&self); } pub struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} }",
            false,
        ),
        fixture(
            "src/probe.rs",
            "pub struct Client; pub type Alias = crate::probe::Client; impl Alias { pub fn qualify(&self) {} }",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::probe::Alias; fn inspect(value: &Alias) { value.qualify(); }",
            false,
        ),
    ];
    assert!(find_production_callers(&sources).is_empty());
}

#[test]
fn catches_closure_and_parenthesized_typed_receivers() {
    let source = fixture(
        "src/closure.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } fn release() { let call = |port: &dyn CredentialServiceQualificationPort| (port).qualify(); let _ = call; }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn nested_clean_macro_does_not_mask_outer_dangerous_macro() {
    let source = fixture(
        "src/scopes.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } macro_rules! invoke { ($port:expr) => { $port.qualify() }; } fn release<T: CredentialServiceQualificationPort>(port: &T) { if false { macro_rules! invoke { ($port:expr) => {}; } invoke!(port); } invoke!(port); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn cfg_test_inherent_member_is_ignored() {
    let source = fixture(
        "src/cfg_impl.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Host; impl Host { #[cfg(test)] fn release<T: CredentialServiceQualificationPort>(&self, port: &T) { port.qualify(); } }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn unrelated_qualified_rename_collision_is_ignored() {
    let sources = [
        fixture(
            "src/q.rs",
            "pub trait CredentialServiceQualificationPort { fn qualify(&self); } pub struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} }",
            false,
        ),
        fixture(
            "src/probe.rs",
            "pub struct Client; impl Client { pub fn qualify(&self) {} }",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::probe::Client as QualifiedClient; fn inspect(value: &QualifiedClient) { value.qualify(); }",
            false,
        ),
    ];
    assert!(find_production_callers(&sources).is_empty());
}
