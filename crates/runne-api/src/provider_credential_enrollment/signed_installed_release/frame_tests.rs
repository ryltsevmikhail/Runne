use std::io::Cursor;

use runne_domain::DigestEqualityMatcherV1;

use super::{PendingSignedInstalledReleaseMetadataV2, verify_current_pinned_with};
use crate::provider_credential_enrollment::signed_installed_release::tests::pinned_test_facts;
use crate::provider_credential_enrollment::{
    SignedInstalledReleaseVerificationErrorV2, UpdateMetadataV2, verify_signed_update_metadata_v2,
};

const MAGIC: &[u8; 8] = b"GCRMDV2\0";

#[test]
fn private_core_verifies_exact_match_with_supplied_test_facts() {
    let (metadata, trust, release_binding) = pinned_test_facts();
    assert_eq!(
        verify_signed_update_metadata_v2(&metadata, &trust, 100)
            .expect("generic fixture")
            .qualified_release_candidate()
            .expect("qualified fixture")
            .release_binding_digest(),
        release_binding,
    );
    let pending = pending(&metadata);
    let expected = DigestEqualityMatcherV1::from_expected(release_binding);

    let release =
        verify_current_pinned_with(pending, &trust, 100, &expected).expect("pinned exact release");
    assert!(release.matches_release_binding(&release_binding));
}

#[test]
fn private_core_rejects_an_unequal_opaque_expectation() {
    let (metadata, trust, _) = pinned_test_facts();
    let expected = DigestEqualityMatcherV1::from_expected([0x5a; 32]);
    assert_eq!(
        verify_current_pinned_with(pending(&metadata), &trust, 100, &expected),
        Err(SignedInstalledReleaseVerificationErrorV2::ReleaseBindingMismatch),
    );
}

fn pending(metadata: &UpdateMetadataV2) -> PendingSignedInstalledReleaseMetadataV2 {
    let fixture = serde_json::to_vec(metadata).expect("canonical fixture");
    let mut framed = MAGIC.to_vec();
    framed.extend_from_slice(&u32::try_from(fixture.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&fixture);
    PendingSignedInstalledReleaseMetadataV2::read_from(&mut Cursor::new(framed))
        .expect("pending fixture")
}
