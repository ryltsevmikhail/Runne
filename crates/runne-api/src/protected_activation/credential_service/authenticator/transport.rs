use super::{CredentialServiceRegistrationSecret, CredentialServiceSessionAuthenticator};
use crate::protected_activation::credential_service::{
    AcceptedCredentialServiceRegistration, CredentialServiceRegistrationBinding,
    CredentialServiceRegistrationError, CredentialServiceRegistrationInstall,
    CredentialServiceRuntimeEnvelope, VerifiedCredentialServiceRuntimePayload,
};

impl CredentialServiceSessionAuthenticator {
    /// Creates the sole install transport carrying this key and authenticated binding.
    pub fn registration_install(
        &self,
        binding: CredentialServiceRegistrationBinding,
    ) -> Result<CredentialServiceRegistrationInstall, CredentialServiceRegistrationError> {
        crate::protected_activation::credential_service::transport::registration_install(
            self, binding,
        )
    }

    /// Verifies transported-key MAC, then admits it only through service-owned policy.
    pub fn accept_registration_install_with_policy(
        bytes: &[u8],
        now_unix_millis: u64,
        policy: impl FnOnce(
            &CredentialServiceRegistrationBinding,
        ) -> Result<(), CredentialServiceRegistrationError>,
    ) -> Result<AcceptedCredentialServiceRegistration, CredentialServiceRegistrationError> {
        crate::protected_activation::credential_service::transport::accept_registration_install(
            bytes,
            now_unix_millis,
            policy,
        )
    }

    /// MACs one complete canonical provider request frame with no parallel metadata.
    pub fn authenticate_runtime_request(
        &self,
        canonical_provider_frame: &[u8],
    ) -> Result<CredentialServiceRuntimeEnvelope, CredentialServiceRegistrationError> {
        crate::protected_activation::credential_service::transport::authenticate_runtime_payload(
            self,
            false,
            canonical_provider_frame,
        )
    }

    /// Verifies a request MAC before any provider field is decoded.
    pub fn verify_runtime_request(
        &self,
        bytes: &[u8],
    ) -> Result<VerifiedCredentialServiceRuntimePayload, CredentialServiceRegistrationError> {
        crate::protected_activation::credential_service::transport::verify_runtime_payload(
            self, bytes, false,
        )
    }

    /// MACs one complete context-bound canonical provider reply frame.
    pub fn authenticate_runtime_reply(
        &self,
        canonical_provider_frame: &[u8],
    ) -> Result<CredentialServiceRuntimeEnvelope, CredentialServiceRegistrationError> {
        crate::protected_activation::credential_service::transport::authenticate_runtime_payload(
            self,
            true,
            canonical_provider_frame,
        )
    }

    /// Verifies a reply MAC before any provider field is decoded.
    pub fn verify_runtime_reply(
        &self,
        bytes: &[u8],
    ) -> Result<VerifiedCredentialServiceRuntimePayload, CredentialServiceRegistrationError> {
        crate::protected_activation::credential_service::transport::verify_runtime_payload(
            self, bytes, true,
        )
    }

    pub(crate) fn with_registration_secret_for_install<R>(
        &self,
        encode: impl FnOnce(&[u8; 32]) -> R,
    ) -> R {
        encode(&self.secret.0)
    }

    pub(crate) fn from_transported_secret(secret: CredentialServiceRegistrationSecret) -> Self {
        Self { secret }
    }
}
