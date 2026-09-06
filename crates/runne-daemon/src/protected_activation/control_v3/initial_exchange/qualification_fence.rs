use super::VerifiedQualificationAdmission;
use runne_api::{
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProviderCredentialEnrollmentHostError as Error,
};

impl VerifiedQualificationAdmission {
    pub(crate) fn retained_owned(&self) -> &ProtectedCredentialEnrollmentOwnedLaunchV3 {
        &self.owned
    }

    pub(crate) fn reverify_for_fence(
        &self,
        installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        current: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        verifier: &mut runne_native_qualification::QualificationAdmissionVerifier,
        now_unix_seconds: u64,
    ) -> Result<runne_native_qualification::VerifiedQualificationFenceFacts, Error> {
        if *self.owned != *current {
            return Err(Error::AccessDenied);
        }
        installed
            .verify_qualification_for_fence(current, verifier, &self._admission, now_unix_seconds)
            .map_err(|_| Error::AccessDenied)
    }
}
