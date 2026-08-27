use super::super::{CredentialBindingDigest, CredentialEnrollmentAuthorityPair};

#[test]
fn qualified_release_tuple_is_issued_only_by_enrollment_authority() {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let manifest = measurements.release_manifest_digest([41; 32]).unwrap();
    let tuple = measurements
        .issue_qualified_credential_release_tuple(manifest)
        .unwrap();

    assert_eq!(
        tuple.digest(),
        CredentialBindingDigest::from_measured([41; 32]).unwrap()
    );
}
