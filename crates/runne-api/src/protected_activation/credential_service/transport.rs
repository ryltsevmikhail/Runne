use zeroize::Zeroizing;

use super::{
    CredentialServiceRegistrationAck, CredentialServiceRegistrationError,
    CredentialServiceSessionAuthenticator, VerifiedCredentialServiceRegistration,
};

mod install;
mod runtime;
pub(super) use install::{accept_registration_install, registration_install};
pub(super) use runtime::{authenticate_runtime_payload, verify_runtime_payload};

/// Move-only, zeroizing authenticated runtime request frame.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_api::CredentialServiceRuntimeEnvelope>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_api::CredentialServiceRuntimeEnvelope>();
/// ```
pub struct CredentialServiceRuntimeEnvelope(pub(super) Zeroizing<Vec<u8>>);

/// Move-only verified canonical payload; only the provider decoder may inspect it.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_api::VerifiedCredentialServiceRuntimePayload>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_api::VerifiedCredentialServiceRuntimePayload>();
/// ```
pub struct VerifiedCredentialServiceRuntimePayload(pub(super) Zeroizing<Vec<u8>>);

impl CredentialServiceRuntimeEnvelope {
    /// Consumes the envelope at the XPC adapter boundary and zeroizes it afterwards.
    pub fn send<E>(self, send: impl FnOnce(&[u8]) -> Result<(), E>) -> Result<(), E> {
        send(&self.0)
    }

    #[cfg(test)]
    pub(crate) fn test_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl VerifiedCredentialServiceRuntimePayload {
    /// Consumes verified bytes at the trusted composition decoder boundary.
    ///
    /// The callback deliberately cannot return an owned value. Task 3 wiring must
    /// decode immediately and retain only the typed provider ingress value.
    pub fn consume(self, decode: impl FnOnce(&[u8])) {
        decode(&self.0);
    }
}

/// Move-only registration frame containing authenticated request and transported key.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_api::CredentialServiceRegistrationInstall>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_api::CredentialServiceRegistrationInstall>();
/// ```
/// ```compile_fail
/// fn needs_serialize<T: serde::Serialize>() {}
/// needs_serialize::<runne_api::CredentialServiceRegistrationInstall>();
/// ```
/// ```compile_fail
/// fn needs_deserialize<T: serde::Deserialize<'static>>() {}
/// needs_deserialize::<runne_api::CredentialServiceRegistrationInstall>();
/// ```
pub struct CredentialServiceRegistrationInstall(pub(super) Zeroizing<Vec<u8>>);

impl CredentialServiceRegistrationInstall {
    /// Consumes the install frame at the exact Desktop XPC adapter boundary.
    pub fn send<E>(self, send: impl FnOnce(&[u8]) -> Result<(), E>) -> Result<(), E> {
        send(&self.0)
    }

    #[cfg(test)]
    pub(crate) fn test_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Service type state proving key MAC verification and service policy acceptance.
pub struct AcceptedCredentialServiceRegistration {
    pub(super) authenticator: CredentialServiceSessionAuthenticator,
    pub(super) verified: VerifiedCredentialServiceRegistration,
}

impl AcceptedCredentialServiceRegistration {
    /// Produces the separate ACK and retains the admitted session authenticator.
    pub fn complete(
        self,
        now_unix_millis: u64,
    ) -> Result<
        (
            CredentialServiceSessionAuthenticator,
            CredentialServiceRegistrationAck,
        ),
        CredentialServiceRegistrationError,
    > {
        let ack = self
            .authenticator
            .registration_ack(self.verified, now_unix_millis)?;
        Ok((self.authenticator, ack))
    }
}
