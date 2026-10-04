mod edges;
mod macro_inequality_tests;
mod nested_qualified_macro_trust_tests;
mod source_audit;
mod source_inventory;
mod source_inventory_tests;
mod task7;
mod task7_collision;
mod task7_round10;
mod task7_round11;
mod task7_round6;
mod task7_round7;
mod task7_round8;
mod task7_round9;

use std::path::{Path, PathBuf};

use source_audit::{SourceUnit, find_production_callers};
use source_inventory::{compiled_source_inventory, inventory_for_manifest};

#[test]
fn qualification_surface_has_no_production_callers() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sources = compiled_source_inventory(&workspace);
    let offenders = find_production_callers(&sources);
    assert!(
        offenders.is_empty(),
        "unexpected qualification callers: {offenders:?}"
    );
}

#[test]
fn actual_remote_identity_included_macros_are_not_qualification_callers() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let units = compiled_source_inventory(&workspace);
    let target =
        Path::new("crates/runne-store/src/provider/execution_store/remote_identity_write.rs");
    let expected = [
        target,
        Path::new("crates/runne-store/src/provider/execution_store/remote_identity_cancel.rs"),
        Path::new(
            "crates/runne-store/src/provider/execution_store/remote_identity_load_methods.rs",
        ),
    ];
    let selected = units
        .into_iter()
        .filter(|unit| expected.iter().any(|path| unit.path.ends_with(path)))
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), expected.len());
    assert!(
        find_production_callers(&selected).is_empty(),
        "unexpected findings in actual remote identity include tree"
    );
}

#[test]
fn caller_guard_allows_definitions_and_test_only_references_but_rejects_invocation() {
    let sources = [
        fixture(
            "src/definitions.rs",
            "pub trait CredentialServiceQualificationPort { fn qualify(&self); }\nimpl CredentialServiceQualificationPort for Client { fn qualify(&self) {} }",
            false,
        ),
        fixture(
            "src/test_only.rs",
            "#[cfg(test)] mod tests { fn case(port: impl CredentialServiceQualificationPort) { port.qualify(); } }",
            false,
        ),
        fixture(
            "src/production.rs",
            "use x::CredentialServiceQualificationPort; fn release(port: impl CredentialServiceQualificationPort) { port.qualify(); }",
            false,
        ),
    ];
    let findings = find_production_callers(&sources);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, PathBuf::from("src/production.rs"));
}

#[test]
fn caller_guard_does_not_miss_an_alias_reexport_ufcs_caller() {
    let sources = [
        fixture(
            "src/qualification_alias.rs",
            "pub use runne_platform_ports::credential_service::CredentialServiceQualificationPort as QualificationPort;",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::qualification_alias::QualificationPort; fn release(port: impl QualificationPort) { QualificationPort::qualify(&port); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 1);
}

#[test]
fn caller_guard_does_not_miss_a_private_glob_reexport_caller() {
    let sources = [
        fixture(
            "src/qualification_alias.rs",
            "pub use runne_platform_ports::credential_service::CredentialServiceQualificationPort as QualificationPort;",
            false,
        ),
        fixture(
            "src/caller.rs",
            "use crate::qualification_alias::*; fn release(port: impl QualificationPort) { QualificationPort::qualify(&port); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 1);
}

#[test]
fn caller_guard_does_not_miss_qself_and_function_item_carriers() {
    let source = fixture(
        "src/qself.rs",
        "use x::CredentialServiceQualificationPort as Q; struct Pending; impl Q for Pending { fn qualify(&self) {} } const QUALIFY: fn(&Pending) = <Pending as Q>::qualify; fn release(p: &Pending) { let _ = QUALIFY; <Pending>::capture_current(p); <Pending>::verify_exact(p); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 3);
}

#[test]
fn caller_guard_does_not_miss_a_macro_carrier() {
    let source = fixture(
        "src/macro_carrier.rs",
        "use x::CredentialServiceQualificationPort; macro_rules! invoke_qualification { ($port:expr) => { $port.qualify(); }; } fn release(port: impl CredentialServiceQualificationPort) { invoke_qualification!(port); }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_does_not_miss_a_fully_qualified_trait_bound_caller() {
    let source = fixture(
        "src/trait_bound.rs",
        "trait Adapter { fn release<T>(port: &T) where T: ::runne_platform_ports::credential_service::CredentialServiceQualificationPort { port.qualify(); } }",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn caller_guard_does_not_miss_a_fully_qualified_reexport_alias_without_use() {
    let sources = [
        fixture(
            "src/public_namespace.rs",
            "pub mod private_namespace { pub use runne_platform_ports::credential_service::CredentialServiceQualificationPort as QualificationPort; } pub use private_namespace::*;",
            false,
        ),
        fixture(
            "src/caller.rs",
            "fn release<T>(port: &T) where T: crate::public_namespace::QualificationPort { port.qualify(); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 1);
}

#[test]
fn caller_guard_scans_qualification_trait_and_impl_bodies_only() {
    let source = fixture(
        "src/qualification_bodies.rs",
        r"
trait CredentialServiceQualificationPort {
    fn qualify(&self);
    fn default_release(&self) {
        self.qualify();
    }
}
struct Client;
impl CredentialServiceQualificationPort for Client {
    fn qualify(&self) {}
    fn default_release(&self) {
        self.qualify();
    }
}
",
        false,
    );
    assert_eq!(find_production_callers(&[source]).len(), 2);
}

#[test]
fn caller_guard_fails_closed_on_an_unresolved_semantic_supertrait_alias() {
    let sources = [
        fixture(
            "src/semantic_alias.rs",
            "trait QualificationSupertrait: crate::CredentialServiceQualificationPort {}",
            false,
        ),
        fixture(
            "src/semantic_caller.rs",
            "fn release<T: crate::semantic_alias::QualificationSupertrait>(port: &T) { port.qualify(); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 1);
}

#[test]
fn caller_guard_follows_a_production_include_fragment() {
    let sources = [
        fixture(
            "src/client.rs",
            "use crate::qualification_alias::QualificationPort; include!(\"qualification.inc\");",
            false,
        ),
        fixture(
            "src/qualification.inc",
            "fn release(port: impl QualificationPort) { port.qualify(); }",
            false,
        ),
    ];
    assert_eq!(find_production_callers(&sources).len(), 1);
}

#[test]
fn caller_guard_uses_item_semantics_not_a_tests_filename() {
    let production = fixture(
        "src/compiled_tests.rs",
        "use x::CredentialServiceQualificationPort; fn release(port: impl CredentialServiceQualificationPort) { port.qualify(); }",
        false,
    );
    let test_only = fixture(
        "src/also_tests.rs",
        "use x::CredentialServiceQualificationPort; #[test] fn release(port: impl CredentialServiceQualificationPort) { port.qualify(); }",
        true,
    );
    let findings = find_production_callers(&[production, test_only]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, PathBuf::from("src/compiled_tests.rs"));
}

#[test]
fn unrelated_qualification_named_methods_are_not_port_callers() {
    let source = fixture(
        "src/unrelated.rs",
        "trait Probe { fn qualify(&self); } fn release(probe: impl Probe) { probe.qualify(); }",
        false,
    );
    assert!(find_production_callers(&[source]).is_empty());
}

fn fixture(path: &str, source: &str, test_only: bool) -> SourceUnit {
    SourceUnit {
        path: PathBuf::from(path),
        source: source.to_owned(),
        test_only,
        trusted_external_roots: std::collections::BTreeSet::default(),
    }
}
