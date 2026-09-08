use super::analyzer::{GuardVerdict, analyze_source};
use super::semantic_acceptance_support::assert_compiles;

fn assert_verdict(source: &str, calls: bool) {
    let verdict = analyze_source(source);
    if calls {
        assert!(
            matches!(verdict, GuardVerdict::Calls(ref sites) if !sites.is_empty()),
            "proven target invocation required: {verdict:?}"
        );
    } else {
        assert!(
            matches!(verdict, GuardVerdict::Clean),
            "fixture must resolve as clean: {verdict:?}"
        );
    }
}

macro_rules! acceptance_case {
    ($name:ident, $calls:literal) => {
        #[test]
        fn $name() {
            let source = include_str!(concat!(
                "fixtures/semantic_acceptance/",
                stringify!($name),
                ".rs"
            ));
            assert_compiles(source, stringify!($name));
            assert_verdict(source, $calls);
        }
    };
}

acceptance_case!(scope_overwrite_miss, true);
acceptance_case!(destructured_argument, true);
acceptance_case!(self_field_receiver, true);
acceptance_case!(tuple_struct_destructure, true);
acceptance_case!(local_typed_holder, true);
acceptance_case!(local_callable_array, true);
acceptance_case!(local_callable_tuple, true);
acceptance_case!(generic_callback, true);
acceptance_case!(macro_alias, true);

acceptance_case!(scope_overwrite_false_positive, false);
acceptance_case!(cfg_double_not, false);
acceptance_case!(cfg_match_arm, false);
acceptance_case!(local_import_unrelated_call, false);
acceptance_case!(macro_function_reference, false);
acceptance_case!(safe_macro_target_argument, false);
acceptance_case!(test_module_macro_collision, false);
acceptance_case!(type_scope_collision, false);

#[test]
fn generic_callback_return_type_does_not_prove_capture_invocation() {
    let source = include_str!("fixtures/semantic_acceptance/generic_callback.rs").replace(
        "invoke(runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::capture_current)",
        "invoke(unrelated)",
    ) + "\nfn unrelated() -> Result<runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1, runne_macos_process_identity::MacOsCredentialServicePackageObservationError> { panic!() }";
    assert_compiles(&source, "generic_unrelated");
    assert_verdict(&source, false);
}

#[test]
fn renamed_module_reexport_preserves_target_identity() {
    let source = r"
        mod reexport {
            pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Reexported;
        }
        use crate::reexport::Reexported as Pending;
        fn call() { let _ = Pending::capture_current(); }
    ";
    assert_compiles(source, "renamed_module_reexport");
    assert_verdict(source, true);
}

#[test]
fn local_generic_carrier_never_erases_target_argument() {
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        struct Holder<T> { value: T }
        fn call(holder: Holder<Pending>, release: &runne_api::VerifiedSignedInstalledReleaseV2) {
            let _ = holder.value.verify_exact(release);
        }
    ";
    assert_compiles(source, "local_generic_carrier");
    assert!(
        !matches!(analyze_source(source), GuardVerdict::Clean),
        "generic target argument must survive the carrier type"
    );
    let reference_only = source.replace("holder.value.verify_exact(release)", "holder.value");
    assert_compiles(&reference_only, "local_generic_carrier_reference");
    assert_verdict(&reference_only, false);
}

#[test]
fn macro_definition_local_binding_survives_call_site_shadowing() {
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        use runne_macos_process_identity::MacOsCredentialServicePackageObservationError as Error;
        fn call() {
            let capture = Pending::capture_current;
            macro_rules! invoke { () => { capture() }; }
            {
                let capture = || ();
                let _: Result<Pending, Error> = invoke!();
            }
        }
    ";
    assert_compiles(source, "macro_definition_binding");
    assert!(
        !matches!(analyze_source(source), GuardVerdict::Clean),
        "definition-site callable must not become the unrelated call-site binding"
    );
    let reference_only = source.replace("capture()", "capture").replace(
        "Result<Pending, Error> =",
        "fn() -> Result<Pending, Error> =",
    );
    assert_compiles(&reference_only, "macro_definition_binding_reference");
    assert_verdict(&reference_only, false);
}
