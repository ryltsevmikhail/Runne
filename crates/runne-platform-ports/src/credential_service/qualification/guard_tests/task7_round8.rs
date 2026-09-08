use super::{find_production_callers, fixture};

#[test]
fn local_typed_receiver_macro_argument_keeps_qualification_context() {
    let target = fixture(
        "src/typed_macro.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } struct Client; impl CredentialServiceQualificationPort for Client { fn qualify(&self) {} } static CLIENT: Client = Client; macro_rules! invoke { ($port:expr) => { $port.qualify() }; } fn target() -> &'static dyn CredentialServiceQualificationPort { &CLIENT } fn release() { let port: &dyn CredentialServiceQualificationPort = target(); invoke!(port); }",
        false,
    );
    let probe = fixture(
        "src/probe_macro.rs",
        "trait Probe { fn qualify(&self); } struct Client; impl Probe for Client { fn qualify(&self) {} } static CLIENT: Client = Client; macro_rules! invoke { ($port:expr) => { $port.qualify() }; } fn target() -> &'static dyn Probe { &CLIENT } fn release() { let port: &dyn Probe = target(); invoke!(port); }",
        false,
    );
    let definition = fixture(
        "src/definition_only.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } macro_rules! invoke { ($port:expr) => { $port.qualify() }; }",
        false,
    );
    assert_eq!(find_production_callers(&[target]).len(), 1);
    assert!(find_production_callers(&[probe, definition]).is_empty());
}

#[test]
fn impl_associated_type_alias_keeps_qualification_provenance() {
    let target = fixture(
        "src/associated_target.rs",
        "trait CredentialServiceQualificationPort { fn qualify(&self); } trait Carrier { type Port: ?Sized; } struct Host; impl Carrier for Host { type Port = dyn CredentialServiceQualificationPort; } fn release(port: &<Host as Carrier>::Port) { port.qualify(); }",
        false,
    );
    let probe = fixture(
        "src/associated_probe.rs",
        "trait Probe { fn qualify(&self); } trait Carrier { type Port: ?Sized; } struct Host; impl Carrier for Host { type Port = dyn Probe; } fn release(port: &<Host as Carrier>::Port) { port.qualify(); }",
        false,
    );
    assert_eq!(find_production_callers(&[target]).len(), 1);
    assert!(find_production_callers(&[probe]).is_empty());
}
