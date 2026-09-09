use super::{find_production_callers, fixture};

#[test]
fn edition_specific_fragments_select_the_same_arm_as_rustc() {
    let expression = fixture(
        "src/expr_2021_arm.rs",
        "macro_rules! outer { ($value:expr_2021, $keyword:ident, $path:path) => {}; ($value:expr, $keyword:ident, $path:path) => { $keyword $path as serde_json; } } outer!(const { 1 }, use, external_proc); fn release() { serde_json::json!(); }",
        false,
    );
    let pattern = fixture(
        "src/pattern_arm.rs",
        "macro_rules! outer { ($value:pat_param, $keyword:ident, $path:path) => {}; ($value:pat, $keyword:ident, $path:path) => { $keyword $path as serde_json; } } outer!(A | B, use, external_proc); fn release() { serde_json::json!(); }",
        false,
    );
    for unit in [expression, pattern] {
        let path = unit.path.clone();
        assert!(!find_production_callers(&[unit]).is_empty(), "{path:?}");
    }
}

#[test]
fn associated_constants_cannot_hide_qualification_function_items() {
    let unit = fixture(
        "src/associated_const.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Pending; impl CredentialServiceQualificationPort for Pending { fn qualify(&self) {} } impl Pending { const RELEASE: fn(&Pending) = <Pending as CredentialServiceQualificationPort>::qualify; } fn release(value: &Pending) { (Pending::RELEASE)(value); }",
        false,
    );
    assert!(!find_production_callers(&[unit]).is_empty());
}

#[test]
fn nested_functions_seed_their_own_signature_receivers() {
    let unit = fixture(
        "src/nested_function.rs",
        "trait Probe { fn qualify(&self); } trait CredentialServiceQualificationPort { fn qualify(&self); } struct Pending; impl CredentialServiceQualificationPort for Pending { fn qualify(&self) {} } fn release(probe: impl Probe) { fn nested(probe: impl CredentialServiceQualificationPort) { probe.qualify(); } nested(Pending); let _ = probe; }",
        false,
    );
    assert!(!find_production_callers(&[unit]).is_empty());
}

#[test]
fn test_only_locals_do_not_taint_production_receiver_classification() {
    let unit = fixture(
        "src/cfg_test_local.rs",
        "trait Probe { fn qualify(&self); } trait CredentialServiceQualificationPort { fn qualify(&self); } fn release(probe: impl Probe) { #[cfg(test)] let probe: &dyn CredentialServiceQualificationPort = unreachable!(); probe.qualify(); }",
        false,
    );
    assert!(find_production_callers(&[unit]).is_empty());
}

#[test]
fn compiler_stringify_payload_is_not_executed() {
    let unit = fixture(
        "src/stringify_payload.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } fn release(port: impl CredentialServiceQualificationPort) { let _ = stringify!(port.qualify()); }",
        false,
    );
    let local = fixture(
        "src/local_stringify_ignores_payload.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } macro_rules! stringify { ($($ignored:tt)*) => { () }; } fn release(port: impl CredentialServiceQualificationPort) { stringify!(port.qualify()); }",
        false,
    );
    let qualified = fixture(
        "src/std_stringify_payload.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } fn release(port: impl CredentialServiceQualificationPort) { let _ = std::stringify!(port.qualify()); }",
        false,
    );
    let core_qualified = fixture(
        "src/core_stringify_payload.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } fn release(port: impl CredentialServiceQualificationPort) { let _ = core::stringify!(port.qualify()); }",
        false,
    );
    let unrelated_forwarding = fixture(
        "src/local_stringify_unrelated_forwarding.rs",
        "trait Probe { fn qualify(&self); } struct Pending; impl Probe for Pending { fn qualify(&self) {} } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } fn release(probe: Pending) { stringify!(probe.qualify()); }",
        false,
    );
    let sibling_collision = fixture(
        "src/sibling_type_collision.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod qualified { pub struct Pending; impl super::CredentialServiceQualificationPort for Pending { fn qualify(&self) {} } } mod unrelated { trait Probe { fn qualify(&self); } struct Pending; impl Probe for Pending { fn qualify(&self) {} } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } pub fn release() { stringify!(Pending.qualify()); } }",
        false,
    );
    for unit in [
        unit,
        local,
        qualified,
        core_qualified,
        unrelated_forwarding,
        sibling_collision,
    ] {
        let path = unit.path.clone();
        assert!(find_production_callers(&[unit]).is_empty(), "{path:?}");
    }
}

#[test]
fn local_builtin_spelling_forwards_concrete_qualification_carriers() {
    let unit = fixture(
        "src/local_stringify_concrete_carrier.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Pending; impl CredentialServiceQualificationPort for Pending { fn qualify(&self) {} } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } fn release() { stringify!(Pending.qualify()); }",
        false,
    );
    assert!(!find_production_callers(&[unit]).is_empty());

    let sibling_collision = fixture(
        "src/sibling_qualification_collision.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod unrelated { trait Probe { fn qualify(&self); } struct Pending; impl Probe for Pending { fn qualify(&self) {} } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } pub fn release() { stringify!(Pending.qualify()); } } mod qualified { pub struct Pending; impl super::CredentialServiceQualificationPort for Pending { fn qualify(&self) {} } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } pub fn release() { stringify!(Pending.qualify()); } }",
        false,
    );
    assert!(!find_production_callers(&[sibling_collision]).is_empty());
}

#[test]
fn sibling_unrelated_alias_cannot_mask_a_qualification_alias() {
    let unit = fixture(
        "src/sibling_alias_collision.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod qualified { use super::CredentialServiceQualificationPort; #[derive(Default)] pub struct Client; impl super::CredentialServiceQualificationPort for Client { fn qualify(&self) {} } type Pending = Client; macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } pub fn release() { stringify!(Pending::default().qualify()); } } mod unrelated { trait Probe { fn qualify(&self); } struct ProbeImpl; impl Probe for ProbeImpl { fn qualify(&self) {} } type Pending = ProbeImpl; }",
        false,
    );
    assert!(!find_production_callers(&[unit]).is_empty());

    let clean = fixture(
        "src/nested_unrelated_alias_shadow.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod outer { pub struct Client; impl super::CredentialServiceQualificationPort for Client { fn qualify(&self) {} } type Pending = Client; mod inner { trait Probe { fn qualify(&self); } #[derive(Default)] struct ProbeImpl; impl Probe for ProbeImpl { fn qualify(&self) {} } type Pending = ProbeImpl; macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } pub fn release() { stringify!(Pending::default().qualify()); } } pub fn release() { inner::release(); } }",
        false,
    );
    assert!(find_production_callers(&[clean]).is_empty());

    let reverse_clean = fixture(
        "src/reverse_unrelated_alias_chain.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod qualified { type Pending = dyn super::CredentialServiceQualificationPort; } mod unrelated { trait Probe { fn qualify(&self); } struct ProbeImpl; impl Probe for ProbeImpl { fn qualify(&self) {} } type Pending = Actual; type Actual = ProbeImpl; macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } fn release(value: Pending) { stringify!(value.qualify()); } }",
        false,
    );
    assert!(find_production_callers(&[reverse_clean]).is_empty());

    let reverse_qualification = fixture(
        "src/reverse_qualification_alias_chain.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod qualified { #[derive(Default)] struct Client; impl super::CredentialServiceQualificationPort for Client { fn qualify(&self) {} } type Pending = Alias; type Alias = Client; macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } pub fn release() { stringify!(Pending::default().qualify()); } }",
        false,
    );
    assert!(!find_production_callers(&[reverse_qualification]).is_empty());

    let mixed = fixture(
        "src/mixed_qualification_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod mixed { #[derive(Default)] struct Client; impl super::CredentialServiceQualificationPort for Client { fn qualify(&self) {} } trait Probe { fn qualify(&self); } #[derive(Default)] struct ProbeImpl; impl Probe for ProbeImpl { fn qualify(&self) {} } type Mixed = (Client, ProbeImpl); macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } pub fn release() { stringify!(Mixed::default().0.qualify()); } }",
        false,
    );
    assert!(!find_production_callers(&[mixed]).is_empty());
}

#[test]
fn nested_trait_name_shadows_the_qualification_port() {
    let clean = fixture(
        "src/nested_trait_shadow.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod unrelated { trait CredentialServiceQualificationPort { fn qualify(&self); fn release(&self) { self.qualify(); } } struct Probe; impl CredentialServiceQualificationPort for Probe { fn qualify(&self) {} } }",
        false,
    );
    assert!(find_production_callers(&[clean]).is_empty());

    let explicit_root = fixture(
        "src/nested_trait_shadow_explicit_root.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod nested { trait CredentialServiceQualificationPort { fn qualify(&self); } macro_rules! invoke { ($port:expr) => { $port.qualify() }; } fn release(port: &dyn super::CredentialServiceQualificationPort) { invoke!(port); } }",
        false,
    );
    assert!(!find_production_callers(&[explicit_root]).is_empty());

    let root_alias = fixture(
        "src/nested_trait_shadow_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod nested { trait CredentialServiceQualificationPort { fn qualify(&self); } use crate as root; macro_rules! invoke { ($port:expr) => { $port.qualify() }; } fn release(port: &dyn root::CredentialServiceQualificationPort) { invoke!(port); } }",
        false,
    );
    assert!(!find_production_callers(&[root_alias]).is_empty());

    let nested_function = fixture(
        "src/nested_item_function_root_port.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } mod nested { trait CredentialServiceQualificationPort { fn qualify(&self); } fn outer() { macro_rules! invoke { ($port:expr) => { $port.qualify() }; } fn inner(port: &dyn super::CredentialServiceQualificationPort) { invoke!(port); } let _ = inner as fn(&dyn super::CredentialServiceQualificationPort); } }",
        false,
    );
    assert!(!find_production_callers(&[nested_function]).is_empty());

    let trait_alias = fixture(
        "src/nested_trait_shadow_qualified_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::CredentialServiceQualificationPort as RootPort; mod nested { trait RootPort { fn qualify(&self); } macro_rules! invoke { ($port:expr) => { $port.qualify() }; } fn release(port: &dyn super::RootPort) { invoke!(port); } }",
        false,
    );
    assert!(!find_production_callers(&[trait_alias]).is_empty());

    let grandparent_alias = fixture(
        "src/grandparent_trait_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::CredentialServiceQualificationPort as RootPort; mod outer { trait RootPort { fn qualify(&self); } mod inner { macro_rules! invoke { ($port:expr) => { $port.qualify() }; } fn release(port: &dyn super::super::RootPort) { invoke!(port); } } }",
        false,
    );
    assert!(!find_production_callers(&[grandparent_alias]).is_empty());

    let associated_method = fixture(
        "src/associated_method_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::CredentialServiceQualificationPort as RootPort; mod nested { trait RootPort { fn qualify(&self); } macro_rules! invoke { ($port:expr) => { $port.qualify() }; } struct Holder; impl Holder { fn release(port: &dyn super::RootPort) { invoke!(port); } } }",
        false,
    );
    assert!(!find_production_callers(&[associated_method]).is_empty());

    let closure = fixture(
        "src/closure_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::CredentialServiceQualificationPort as RootPort; mod nested { trait RootPort { fn qualify(&self); } fn release() { macro_rules! invoke { ($port:expr) => { $port.qualify() }; } let action = |port: &dyn super::RootPort| { invoke!(port); }; let _ = action; } }",
        false,
    );
    assert!(!find_production_callers(&[closure]).is_empty());

    let typed_local = fixture(
        "src/typed_local_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::CredentialServiceQualificationPort as RootPort; mod nested { trait RootPort { fn qualify(&self); } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } fn source<T>() -> T { unreachable!() } fn release() { let port: &dyn super::RootPort = source(); stringify!(port.qualify()); } }",
        false,
    );
    assert!(!find_production_callers(&[typed_local]).is_empty());

    let inferred_local = fixture(
        "src/inferred_local_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::CredentialServiceQualificationPort as RootPort; mod nested { trait RootPort { fn qualify(&self); } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } fn source<T>() -> T { unreachable!() } fn release() { let port = source::<&dyn super::RootPort>(); stringify!(port.qualify()); } }",
        false,
    );
    assert!(!find_production_callers(&[inferred_local]).is_empty());
}

#[test]
fn generated_members_and_factories_preserve_qualification_provenance() {
    let item_macro = fixture(
        "src/item_macro_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } type RootPort = dyn CredentialServiceQualificationPort; mod nested { trait RootPort { fn ignored(&self); } macro_rules! make_release { ($port:ty) => { fn release(port: &$port) { port.qualify(); } }; } make_release!(super::RootPort); }",
        false,
    );
    assert!(!find_production_callers(&[item_macro]).is_empty());

    let impl_macro = fixture(
        "src/impl_macro_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } type RootPort = dyn CredentialServiceQualificationPort; mod nested { trait RootPort { fn ignored(&self); } struct Holder; macro_rules! make_release { ($port:ty) => { fn release(port: &$port) { port.qualify(); } }; } impl Holder { make_release!(super::RootPort); } }",
        false,
    );
    let trait_macro = fixture(
        "src/trait_macro_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } type RootPort = dyn CredentialServiceQualificationPort; mod nested { trait RootPort { fn ignored(&self); } macro_rules! make_release { ($port:ty) => { fn release(port: &$port) { port.qualify(); } }; } trait Holder { make_release!(super::RootPort); } }",
        false,
    );
    for unit in [impl_macro, trait_macro] {
        assert!(!find_production_callers(&[unit]).is_empty());
    }

    let nested_factory = fixture(
        "src/nested_factory_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::CredentialServiceQualificationPort as RootPort; struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } static CLIENT: Client = Client; mod nested { trait RootPort { fn qualify(&self); } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } fn source() -> &'static dyn super::RootPort { &super::CLIENT } fn release() { let port = source(); stringify!(port.qualify()); } }",
        false,
    );
    assert!(!find_production_callers(&[nested_factory]).is_empty());

    let associated_factory = fixture(
        "src/associated_factory_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::CredentialServiceQualificationPort as RootPort; struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } static CLIENT: Client = Client; mod nested { trait RootPort { fn qualify(&self); } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } struct Factory; impl Factory { fn source() -> &'static dyn super::RootPort { &super::CLIENT } } fn release() { let port = Factory::source(); stringify!(port.qualify()); } }",
        false,
    );
    assert!(!find_production_callers(&[associated_factory]).is_empty());

    let qualification_members = fixture(
        "src/qualification_member_macros.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Holder; macro_rules! make_qualify { () => { fn qualify(&self) { self.qualify(); } }; } impl CredentialServiceQualificationPort for Holder { make_qualify!(); } macro_rules! make_default { () => { fn retry(&self) { self.qualify(); } }; } trait Extension: CredentialServiceQualificationPort { make_default!(); }",
        false,
    );
    assert!(!find_production_callers(&[qualification_members]).is_empty());

    let associated_constants = fixture(
        "src/qualification_associated_constants.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); const HELPER: () = { fn release<T: CredentialServiceQualificationPort>(port: &T) { port.qualify(); } }; } struct Holder; impl CredentialServiceQualificationPort for Holder { fn qualify(&self) {} const HELPER: () = { fn release<T: CredentialServiceQualificationPort>(port: &T) { port.qualify(); } }; }",
        false,
    );
    assert!(!find_production_callers(&[associated_constants]).is_empty());

    let trait_factory = fixture(
        "src/trait_factory_root_alias.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } use crate::CredentialServiceQualificationPort as RootPort; struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } static CLIENT: Client = Client; mod nested { trait RootPort { fn qualify(&self); } macro_rules! stringify { ($($tokens:tt)*) => { $($tokens)* }; } trait Factory { fn source() -> &'static dyn super::RootPort { &super::CLIENT } } struct Maker; impl Factory for Maker {} fn release() { let port = Maker::source(); stringify!(port.qualify()); } }",
        false,
    );
    assert!(!find_production_callers(&[trait_factory]).is_empty());
}
