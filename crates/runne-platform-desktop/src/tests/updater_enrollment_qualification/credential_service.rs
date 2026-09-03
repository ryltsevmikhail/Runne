use super::*;

#[test]
fn unqualified_v3_admission_cannot_open_the_credential_service_endpoint() {
    let mut target = super::super::updater_enrollment_macos_identity::target();
    target.native_enrollment_tuple = None;
    let measured = macos_tuple_v3(&target, '4');
    target.native_enrollment_tuple_v3 = Some(measured.clone());
    let verified =
        super::super::updater_enrollment_macos_identity::verify_target(&target).unwrap();
    let admission = verified.admit_native_enrollment_v3(&measured).unwrap();

    assert_eq!(
        admission.desktop_credential_service_configuration(),
        Err(runne_macos_xpc::CredentialServiceXpcError::Rejected)
    );
}
