//! Provider-neutral fail-closed root-admission adapter.

use runne_api::{
    RootAdmissionVerificationContext, RootHandleAdmission, VerifiedRootAdmissionClaims,
};
use runne_application::ports::{
    CurrentRootAdmissionContext, RootAdmissionLease, RootAdmissionVerifier,
    RootAdmissionVerifierError,
};

pub(super) struct UnavailableRootAdmission;

impl CurrentRootAdmissionContext for UnavailableRootAdmission {
    type Lease = Self;
    fn acquire_root_admission_lease(&self) -> Result<Self::Lease, RootAdmissionVerifierError> {
        Err(RootAdmissionVerifierError::Unavailable)
    }
}

impl RootAdmissionLease for UnavailableRootAdmission {
    fn current_root_admission_context(
        &self,
    ) -> Result<RootAdmissionVerificationContext, RootAdmissionVerifierError> {
        Err(RootAdmissionVerifierError::Unavailable)
    }
}

impl RootAdmissionVerifier for UnavailableRootAdmission {
    fn verify_root_admission(
        &self,
        _: RootHandleAdmission,
    ) -> Result<VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        Err(RootAdmissionVerifierError::Unavailable)
    }
}
