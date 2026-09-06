pub fn exact_reviewed_consumer_method(source: &str, method: &syn::ImplItemFn) -> bool {
    let expected = match (source, method.sig.ident.to_string().as_str()) {
        (
            "runne-platform-desktop/src/updater_metadata/enrollment_tuple/daemon_peer.rs",
            "revalidate_and_measure_current_peer_for_claims",
        ) => {
            "pub fn revalidate_and_measure_current_peer_for_claims(self, stream: &UnixStream, claims: &VerifiedProtectedCredentialEnrollmentPrepareV2<'_>) -> Option<super::VerifiedInstalledEnrollmentMeasurementFacts> {}"
        }
        (
            "runne-platform-desktop/src/updater_metadata/enrollment_tuple/daemon_peer/round.rs",
            "verify_and_measure_current_v3_peer",
        ) => {
            "pub fn verify_and_measure_current_v3_peer(profile_directory: &Path, owned: &ProtectedCredentialEnrollmentOwnedLaunchV3, stream: &UnixStream) -> Option<crate::VerifiedInstalledEnrollmentMeasurementFacts> {}"
        }
        (
            "runne-platform-desktop/src/protected_runtime/test_enrollment_fixture.rs",
            "into_parts",
        ) => {
            "pub fn into_parts(self) -> (ProtectedBundledRuntimeSupervisor, std::os::unix::net::UnixStream, runne_api::ProtectedActivationKeys, runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, crate::VerifiedInstalledEnrollmentMeasurementFacts,) {}"
        }
        _ => return false,
    };
    exact_method(method, expected)
}

pub fn exact_reviewed_consumer_struct(source: &str, item: &syn::ItemStruct) -> bool {
    if source != "runne-platform-desktop/src/protected_runtime/test_enrollment_fixture.rs" {
        return false;
    }
    let expected: syn::ItemStruct = syn::parse_str(
        "pub struct TestOnlyConnectedReadyV3EnrollmentSupervisor { supervisor: ProtectedBundledRuntimeSupervisor, daemon_channel: std::os::unix::net::UnixStream, keys: runne_api::ProtectedActivationKeys, owned: runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, installed: crate::VerifiedInstalledEnrollmentMeasurementFacts, }",
    )
    .unwrap();
    item.ident == expected.ident
        && item.vis == expected.vis
        && item.generics == expected.generics
        && item.fields == expected.fields
}

fn exact_method(actual: &syn::ImplItemFn, expected: &str) -> bool {
    let expected: syn::ImplItemFn = syn::parse_str(expected).unwrap();
    let mut actual_signature = actual.sig.clone();
    let mut expected_signature = expected.sig;
    actual_signature.inputs.pop_punct();
    expected_signature.inputs.pop_punct();
    actual.vis == expected.vis && actual_signature == expected_signature
}
