use crate::credential::enrollment::CredentialEnrollmentError;

use super::{CredentialServiceProtocolCodec, payload};

impl CredentialServiceProtocolCodec {
    /// Validates runtime framing only; it does not claim semantic request validity.
    pub fn validate_runtime_provider_frame(bytes: &[u8]) -> Result<(), CredentialEnrollmentError> {
        payload(bytes, Self::MAX_RUNTIME_PROVIDER_FRAME_BYTES).map(|_| ())
    }
}
