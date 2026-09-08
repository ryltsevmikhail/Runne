use super::count_credential_service_calls;

#[test]
fn ast_guard_counts_indirect_function_item_capture() {
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        fn production(release: &Release) -> Result<(), Error> {
            let capture = Pending::capture_current;
            let pending = capture()?;
            pending.verify_exact(release)?;
            Ok(())
        }
    ";
    assert_eq!(count_credential_service_calls(source), 2);
}

#[test]
fn ast_guard_counts_qself_ufcs_calls() {
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        fn production(pending: Pending, release: &Release) -> Result<(), Error> {
            <Pending>::capture_current()?;
            <Pending>::verify_exact(pending, release)?;
            Ok(())
        }
    ";
    assert_eq!(count_credential_service_calls(source), 2);
}

#[test]
fn ast_guard_counts_function_pointer_carriers_and_casts() {
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        const CAPTURE: fn() -> Result<Pending, Error> = <Pending>::capture_current;
        static VERIFY: fn(Pending, &Release) -> Result<Verified, Error> = <Pending>::verify_exact;
        fn production(release: &Release) -> Result<(), Error> {
            let first = CAPTURE;
            let capture = first as fn() -> Result<Pending, Error>;
            let pending = capture()?;
            let verify = VERIFY;
            verify(pending, release)?;
            Ok(())
        }
    ";
    assert_eq!(count_credential_service_calls(source), 2);
}

#[test]
fn ast_guard_counts_macro_calls_and_namespaced_test_is_production() {
    let macro_source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        macro_rules! emit { () => { Pending::capture_current(); Pending::verify_exact(pending, release); } }
        fn production(pending: Pending, release: &Release) { emit!(); }
    ";
    assert_eq!(count_credential_service_calls(macro_source), 2);
    let namespaced_test = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        #[shipping::test]
        fn production() { Pending::capture_current(); }
    ";
    assert_eq!(count_credential_service_calls(namespaced_test), 1);
}

#[test]
fn ast_guard_counts_type_alias_and_macro_carriers_without_counting_definitions() {
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        type Alias = Pending;
        macro_rules! capture { ($path:path) => { <$path>::capture_current() } }
        macro_rules! verify { ($pending:expr, $release:expr) => { $pending.verify_exact($release) } }
        fn unused() { }
        fn production(pending: Alias, release: &Release) {
            let _ = capture!(Pending);
            let _ = verify!(pending, release);
        }
    ";
    assert_eq!(count_credential_service_calls(source), 2);
}

#[test]
fn ast_guard_counts_field_argument_and_receiver_alias_carriers() {
    let field = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        struct Functions { capture: fn() -> Pending }
        fn production() { let functions = Functions { capture: Pending::capture_current }; let _ = (functions.capture)(); }
    ";
    let argument = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        fn invoke(capture: fn() -> Pending) -> Pending { capture() }
        fn production() { let _ = invoke(Pending::capture_current); }
    ";
    let receiver = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        fn production(pending: Pending) { let alias = pending; alias.verify_exact(); }
    ";
    assert_eq!(count_credential_service_calls(field), 1);
    assert_eq!(count_credential_service_calls(argument), 1);
    assert_eq!(count_credential_service_calls(receiver), 1);
}

#[test]
fn ast_guard_ignores_semantically_test_only_statement() {
    let source = r"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        fn production() { #[cfg(test)] Pending::capture_current(); }
    ";
    assert_eq!(count_credential_service_calls(source), 0);
}
