use runne_api::{
    BeginProviderCredentialEnrollment, ProtectedCredentialEnrollmentAdmissionBinding,
    ProtectedCredentialEnrollmentAuthenticator, ProtectedCredentialEnrollmentRequestBinding,
    ProviderCredentialCommandContext, ProviderCredentialEnrollmentHostError,
    ProviderCredentialRequestAuthorityIssuer, ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialEnrollmentMeasurementAuthority, CredentialLifecycleSnapshot,
    ProviderCredentialEnrollmentStore,
};

use super::coordinator::{ProviderCredentialAdmission, ProviderCredentialBeginAdmission};

/// Daemon-side composition of the protected enrollment control transport.
///
/// Frame authentication, authority-bridge consumption, and the durable one-use
/// begin admission run in this exact order, so unauthenticated, expired, or
/// cross-domain frames never reach the lifecycle store. The bridge consumes the
/// verified request and admission by value, and the store CAS makes the same
/// frame pair replay only as the original projection.
#[allow(dead_code)]
pub(super) struct ProviderCredentialVerifiedFrameGate {
    authenticator: ProtectedCredentialEnrollmentAuthenticator,
    issuer: ProviderCredentialRequestAuthorityIssuer,
    admission: ProviderCredentialAdmission,
}

#[allow(dead_code)]
impl ProviderCredentialVerifiedFrameGate {
    /// Binds one authenticator key domain to one authority issuer/verifier pair.
    pub(super) fn new(
        authenticator: ProtectedCredentialEnrollmentAuthenticator,
        pair: ProviderCredentialRequestAuthorityPair,
        measurements: CredentialEnrollmentMeasurementAuthority,
    ) -> Self {
        let (issuer, verifier) = pair.split();
        Self {
            authenticator,
            issuer,
            admission: ProviderCredentialAdmission::new(verifier, measurements),
        }
    }

    /// Admits one authenticated request/admission frame pair into the durable begin CAS.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit_verified_begin<S: ProviderCredentialEnrollmentStore>(
        &self,
        request_frame: &[u8],
        admission_frame: &[u8],
        request_binding: &ProtectedCredentialEnrollmentRequestBinding,
        admission_binding: &ProtectedCredentialEnrollmentAdmissionBinding,
        previous_request_sequence: u64,
        previous_admission_sequence: u64,
        now_unix_millis: u64,
        command: &BeginProviderCredentialEnrollment,
        context: &ProviderCredentialCommandContext,
        snapshot: CredentialLifecycleSnapshot,
        store: &S,
    ) -> Result<ProviderCredentialBeginAdmission, ProviderCredentialEnrollmentHostError> {
        let request = self
            .authenticator
            .decode_request(
                request_frame,
                request_binding,
                previous_request_sequence,
                now_unix_millis,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let admission = self
            .authenticator
            .decode_admission(
                admission_frame,
                &request,
                admission_binding,
                previous_admission_sequence,
                now_unix_millis,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let (authority, proof) = self
            .issuer
            .issue_from_verified_enrollment(request, admission)?;
        self.admission
            .admit_begin(&authority, &proof, command, context, snapshot, store)
    }
}
