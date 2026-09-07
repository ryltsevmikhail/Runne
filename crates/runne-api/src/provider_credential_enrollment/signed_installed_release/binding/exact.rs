use runne_domain::DigestEqualityMatcherV1;

use super::*;

pub(in super::super) fn exact(
    verified: VerifiedSignedUpdateMetadataV2,
    expected: [u8; 32],
) -> Result<VerifiedSignedInstalledReleaseV2, SignedInstalledReleaseVerificationErrorV2> {
    if expected == [0; 32] {
        return Err(SignedInstalledReleaseVerificationErrorV2::ReleaseBindingMismatch);
    }
    exact_with_matcher(verified, &DigestEqualityMatcherV1::from_expected(expected))
}

pub(in super::super) fn exact_with_matcher(
    verified: VerifiedSignedUpdateMetadataV2,
    expected: &DigestEqualityMatcherV1,
) -> Result<VerifiedSignedInstalledReleaseV2, SignedInstalledReleaseVerificationErrorV2> {
    let retained_target =
        candidate_binding::VerifiedCandidateBindingV3::from_target(verified.target());
    let (candidate, candidate_v3, release_binding) = match (
        verified.qualified_release_candidate,
        verified.qualified_release_candidate_v3,
    ) {
        (Some(candidate), None) => {
            let release = candidate.release_binding_digest;
            (Some(candidate), None, release)
        }
        (None, Some(candidate)) => {
            let release = candidate.release_binding_digest();
            (None, Some(candidate), release)
        }
        (None, None) => return Err(SignedInstalledReleaseVerificationErrorV2::Unqualified),
        (Some(_), Some(_)) => {
            return Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata);
        }
    };
    if release_binding == [0; 32] || !expected.matches(&release_binding) {
        return Err(SignedInstalledReleaseVerificationErrorV2::ReleaseBindingMismatch);
    }
    let candidate_binding_v3 = candidate_v3.as_ref().map(|_| retained_target);
    Ok(VerifiedSignedInstalledReleaseV2 {
        signed_candidate: candidate,
        signed_candidate_v3: candidate_v3,
        candidate_binding_v3,
    })
}
