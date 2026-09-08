use std::path::Path;

use super::{find_production_callers, fixture, inventory_for_manifest};

#[test]
fn caller_guard_does_not_miss_a_type_alias_to_the_qualification_port() {
    let sources = [
        fixture(
            "src/type_alias.rs",
            "pub type Qualified = dyn crate::CredentialServiceQualificationPort;",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::type_alias::Qualified; fn release(port: &Qualified) { port.qualify(); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 1);
}

#[test]
fn caller_guard_does_not_miss_a_same_file_type_alias_without_an_import() {
    let source = fixture(
        "src/direct_type_alias.rs",
        "type Qualified = dyn crate::CredentialServiceQualificationPort; fn release(port: &Qualified) { port.qualify(); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_follows_reference_and_generic_type_aliases() {
    let sources = [
        fixture(
            "src/aliases.rs",
            "pub type Borrowed = &'static dyn crate::CredentialServiceQualificationPort; pub type Boxed = Box<dyn crate::CredentialServiceQualificationPort>;",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::aliases::{Borrowed, Boxed}; fn borrowed(port: Borrowed) { port.qualify(); } fn boxed(port: Boxed) { port.qualify(); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 2);
}

#[test]
fn caller_guard_follows_cross_file_composite_type_aliases() {
    let sources = [
        fixture(
            "src/aliases.rs",
            "pub type Tuple<'a> = (&'a dyn crate::CredentialServiceQualificationPort,); pub type Array<'a> = [&'a dyn crate::CredentialServiceQualificationPort; 1]; pub type Slice<'a> = &'a [&'a dyn crate::CredentialServiceQualificationPort]; pub type Generic<'a> = Option<Box<&'a dyn crate::CredentialServiceQualificationPort>>; pub type Bare<'a> = fn(Option<&'a dyn crate::CredentialServiceQualificationPort>);",
            false,
        ),
        fixture(
            "src/tuple_caller.rs",
            "use crate::aliases::Tuple; fn release(port: Tuple<'_>) { port.0.qualify(); }",
            false,
        ),
        fixture(
            "src/array_caller.rs",
            "use crate::aliases::Array; fn release(port: &Array<'_>) { port[0].qualify(); }",
            false,
        ),
        fixture(
            "src/slice_caller.rs",
            "use crate::aliases::Slice; fn release(port: Slice<'_>) { port[0].qualify(); }",
            false,
        ),
        fixture(
            "src/generic_caller.rs",
            "use crate::aliases::Generic; fn release(port: Generic<'_>) { port.as_deref().unwrap().qualify(); }",
            false,
        ),
        fixture(
            "src/bare_caller.rs",
            "use crate::aliases::Bare; struct Client; fn release(_callback: Bare<'_>, client: Client) { client.qualify(); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 5);
}

#[test]
fn caller_guard_ignores_unrelated_cross_file_composite_type_aliases() {
    let sources = [
        fixture(
            "src/aliases.rs",
            "pub type Tuple<'a> = (&'a dyn Probe,); pub type Array<'a> = [&'a dyn Probe; 1]; pub type Slice<'a> = &'a [&'a dyn Probe]; pub type Generic<'a> = Option<Box<&'a dyn Probe>>; pub type Bare<'a> = fn(Option<&'a dyn Probe>);",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::aliases::{Array, Bare, Generic, Slice, Tuple}; trait Probe { fn qualify(&self); } fn tuple(port: Tuple<'_>) { port.0.qualify(); } fn array(port: &Array<'_>) { port[0].qualify(); } fn slice(port: Slice<'_>) { port[0].qualify(); } fn generic(port: Generic<'_>) { port.as_deref().unwrap().qualify(); } fn bare(port: Bare<'_>) { port.1.qualify(); }",
            false,
        ),
    ];
    assert!(find_production_callers(&sources).is_empty());
}

#[test]
fn caller_guard_fails_closed_on_an_opaque_type_macro_carrier() {
    let sources = [
        fixture(
            "src/aliases.rs",
            "pub type Qualified = type_carrier!(crate::CredentialServiceQualificationPort);",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::aliases::Qualified; fn release(port: Qualified) { port.qualify(); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 1);
}

#[test]
fn caller_guard_does_not_treat_a_macro_definition_as_an_invocation() {
    let source = fixture(
        "src/macro_definition.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } macro_rules! invoke_qualification { ($port:expr) => { $port.qualify(); }; }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn caller_guard_follows_a_local_macro_invocation_after_ignoring_its_definition() {
    let source = fixture(
        "src/macro_invocation.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } macro_rules! invoke_qualification { ($port:expr) => { $port.qualify(); }; } fn release<T: CredentialServiceQualificationPort>(port: &T) { invoke_qualification!(port); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_follows_a_transitive_local_macro_call() {
    let source = fixture(
        "src/macro_forwarding.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } macro_rules! inner { ($port:expr) => { $port.qualify() }; } macro_rules! outer { ($port:expr) => { inner!($port) }; } fn release<T: CredentialServiceQualificationPort>(port: &T) { outer!(port); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_follows_a_selected_qualification_method_in_a_local_macro() {
    let source = fixture(
        "src/macro_selected_method.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } macro_rules! selected { ($method:ident, $port:expr) => { $port.$method() }; } fn release<T: CredentialServiceQualificationPort>(port: &T) { selected!(qualify, port); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_ignores_a_selected_unrelated_method_in_a_local_macro() {
    let source = fixture(
        "src/macro_selected_control.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); fn observe(&self); } macro_rules! selected { ($method:ident, $port:expr) => { $port.$method() }; } fn release<T: CredentialServiceQualificationPort>(port: &T) { selected!(observe, port); }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn caller_guard_ignores_test_only_statements_inside_a_production_function() {
    let source = fixture(
        "src/test_only_statements.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } fn release<T: CredentialServiceQualificationPort>(port: &T) { #[cfg(test)] { port.qualify(); } { #[cfg(test)] { port.qualify(); } } #[cfg_attr(not(test), cfg(test))] { port.qualify(); } #[cfg_attr(not(test), cfg(test))] { { port.qualify(); } } port.qualify(); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_fails_closed_on_a_path_only_macro_carrier() {
    let source = fixture(
        "src/path_macro.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } fn release<T: CredentialServiceQualificationPort>(port: &T) { qualification_carrier!(port); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_fails_closed_on_item_and_attribute_macro_carriers() {
    let sources = [
        fixture(
            "src/item_macro.rs",
            "qualification_carrier! { fn release<T: CredentialServiceQualificationPort>(port: &T) { port.qualify(); } }",
            false,
        ),
        fixture(
            "src/attribute_macro.rs",
            "#[qualification_carrier] fn release<T: CredentialServiceQualificationPort>(port: &T) {}",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 2);
}

#[test]
fn caller_guard_allows_a_local_qualify_macro_for_an_unrelated_trait() {
    let source = fixture(
        "src/probe.rs",
        "trait Probe { fn qualify(&self); } macro_rules! probe { ($value:expr) => { $value.qualify() }; } fn release(value: &dyn Probe) { probe!(value); }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn caller_guard_catches_a_direct_call_on_a_local_concrete_implementer() {
    let source = fixture(
        "src/local_implementer.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } fn release(client: &Client) { client.qualify(); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_fails_closed_on_an_attributed_qualification_trait() {
    let source = fixture(
        "src/attributed_trait.rs",
        "#[qualification_carrier] trait CredentialServiceQualificationPort { fn qualify(&self); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_fails_closed_on_an_attributed_qualification_supertrait() {
    let source = fixture(
        "src/attributed_supertrait.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } #[qualification_carrier] trait QualificationAdapter: CredentialServiceQualificationPort {}",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_fails_closed_on_an_attributed_qualification_impl() {
    let source = fixture(
        "src/attributed_impl.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Client; #[qualification_carrier] impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_ignores_attributed_qualification_items_under_cfg_test() {
    let source = fixture(
        "src/test_only_attributes.rs",
        "struct Client; #[cfg(test)] #[qualification_carrier] trait CredentialServiceQualificationPort { fn qualify(&self); } #[cfg(test)] #[qualification_carrier] impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn caller_guard_allows_non_expanding_builtin_function_attributes() {
    let source = fixture(
        "src/builtin_function_attributes.rs",
        "trait CredentialServiceQualificationPort {} #[inline] #[cold] #[track_caller] fn inspect<T: CredentialServiceQualificationPort>(_port: &T) {}",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

#[test]
fn caller_guard_allows_non_expanding_builtin_trait_and_impl_attributes() {
    let source = fixture(
        "src/builtin_item_attributes.rs",
        "#[diagnostic::on_unimplemented(message = \"qualification unavailable\")] trait CredentialServiceQualificationPort {} struct Client; #[automatically_derived] impl CredentialServiceQualificationPort for Client {}",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}
#[test]
fn caller_guard_catches_compile_valid_cross_file_alias_and_external_macro_carriers() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/credential_service/qualification/guard_tests/fixtures/task7_target/Cargo.toml");
    let sources = inventory_for_manifest(&manifest);
    let main = manifest.parent().unwrap().join("test_fixture/main.rs");
    let findings = find_production_callers(&sources);
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.path == main)
            .count(),
        22
    );
}
