use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::super::ProtectedActivationKeys;
use super::{
    CredentialServiceRegistrationAck, CredentialServiceRegistrationBinding,
    CredentialServiceRegistrationError, CredentialServiceRegistrationRequest,
    VerifiedCredentialServiceRegistration,
};

const DERIVATION_DOMAIN: &[u8] = b"gocode/macos-credential-service/registration-key/v1\0";
const REGISTRATION_DOMAIN: &[u8] = b"gocode/macos-credential-service/registration/v1\0";
const ACK_DOMAIN: &[u8] = b"gocode/macos-credential-service/registration-ack/v1\0";
const XPC_DOMAIN: &[u8] = b"gocode/macos-credential-service/xpc/v1\0";
const DESKTOP_REGISTRATION_ROLE: u8 = 1;

/// Move-only registration secret. Its bytes remain available only to the authenticator.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_api::CredentialServiceRegistrationSecret>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_api::CredentialServiceRegistrationSecret>();
/// ```
/// ```compile_fail
/// fn needs_serde<T: serde::Serialize>() {}
/// needs_serde::<runne_api::CredentialServiceRegistrationSecret>();
/// ```
/// ```compile_fail
/// fn needs_serde<T: serde::Deserialize<'static>>() {}
/// needs_serde::<runne_api::CredentialServiceRegistrationSecret>();
/// ```
pub struct CredentialServiceRegistrationSecret(Zeroizing<[u8; 32]>);

/// Authenticates the immutable Desktop-to-service registration transcript.
///
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_api::CredentialServiceSessionAuthenticator>();
/// ```
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_api::CredentialServiceSessionAuthenticator>();
/// ```
/// ```compile_fail
/// fn needs_serde<T: serde::Serialize>() {}
/// needs_serde::<runne_api::CredentialServiceSessionAuthenticator>();
/// ```
/// ```compile_fail
/// fn needs_serde<T: serde::Deserialize<'static>>() {}
/// needs_serde::<runne_api::CredentialServiceSessionAuthenticator>();
/// ```
pub struct CredentialServiceSessionAuthenticator {
    secret: CredentialServiceRegistrationSecret,
}

impl CredentialServiceSessionAuthenticator {
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            secret: CredentialServiceRegistrationSecret(Zeroizing::new(derive(
                keys.readiness_key(),
                DERIVATION_DOMAIN,
            ))),
        }
    }

    pub fn authenticate_registration(
        &self,
        binding: CredentialServiceRegistrationBinding,
    ) -> Result<CredentialServiceRegistrationRequest, CredentialServiceRegistrationError> {
        let payload = super::codec::encode_binding(&binding);
        Ok(CredentialServiceRegistrationRequest {
            binding,
            mac: self.mac(REGISTRATION_DOMAIN, &payload),
        })
    }

    pub(crate) fn decode_registration(
        &self,
        bytes: &[u8],
    ) -> Result<CredentialServiceRegistrationRequest, CredentialServiceRegistrationError> {
        let request = super::codec::decode_request(bytes)?;
        self.verify_registration(&request)?;
        Ok(request)
    }

    pub(crate) fn verify_registration(
        &self,
        request: &CredentialServiceRegistrationRequest,
    ) -> Result<(), CredentialServiceRegistrationError> {
        let expected = self.mac(
            REGISTRATION_DOMAIN,
            &super::codec::encode_binding(&request.binding),
        );
        if bool::from(expected.ct_eq(&request.mac)) {
            Ok(())
        } else {
            Err(CredentialServiceRegistrationError::AuthenticationFailed)
        }
    }

    pub(crate) fn verify_registration_at(
        &self,
        request: &CredentialServiceRegistrationRequest,
        expected: &CredentialServiceRegistrationBinding,
        now_unix_millis: u64,
    ) -> Result<(), CredentialServiceRegistrationError> {
        self.verify_registration(request)?;
        if request.binding == *expected {
            if request.binding.expires_at_unix_millis > now_unix_millis {
                Ok(())
            } else {
                Err(CredentialServiceRegistrationError::Expired)
            }
        } else {
            Err(CredentialServiceRegistrationError::BindingMismatch)
        }
    }

    pub fn decode_and_verify_registration_for(
        &self,
        bytes: &[u8],
        expected: &CredentialServiceRegistrationBinding,
        now_unix_millis: u64,
    ) -> Result<VerifiedCredentialServiceRegistration, CredentialServiceRegistrationError> {
        let request = self.decode_registration(bytes)?;
        self.verify_registration_at(&request, expected, now_unix_millis)?;
        Ok(VerifiedCredentialServiceRegistration(request))
    }

    pub fn registration_ack(
        &self,
        verified: VerifiedCredentialServiceRegistration,
        now_unix_millis: u64,
    ) -> Result<CredentialServiceRegistrationAck, CredentialServiceRegistrationError> {
        let request = verified.into_request();
        let binding = &request.binding;
        if binding.expires_at_unix_millis <= now_unix_millis {
            return Err(CredentialServiceRegistrationError::Expired);
        }
        let payload = super::codec::encode_binding(binding);
        Ok(CredentialServiceRegistrationAck {
            service_epoch: binding.service_epoch,
            protected_session_id: binding.protected_session_id,
            join_attempt: binding.join_attempt,
            installed_generation: binding.installed_generation,
            mac: self.mac(ACK_DOMAIN, &payload),
        })
    }

    pub fn decode_and_verify_ack_for(
        &self,
        bytes: &[u8],
        expected: &CredentialServiceRegistrationBinding,
        now_unix_millis: u64,
    ) -> Result<CredentialServiceRegistrationAck, CredentialServiceRegistrationError> {
        let ack = super::codec::decode_ack(bytes)?;
        if ack.service_epoch != expected.service_epoch
            || ack.protected_session_id != expected.protected_session_id
            || ack.join_attempt != expected.join_attempt
            || ack.installed_generation != expected.installed_generation
        {
            return Err(CredentialServiceRegistrationError::BindingMismatch);
        }
        if expected.expires_at_unix_millis <= now_unix_millis {
            return Err(CredentialServiceRegistrationError::Expired);
        }
        let payload = super::codec::encode_binding(expected);
        if bool::from(self.mac(ACK_DOMAIN, &payload).ct_eq(&ack.mac)) {
            Ok(ack)
        } else {
            Err(CredentialServiceRegistrationError::AuthenticationFailed)
        }
    }

    #[cfg(test)]
    pub(crate) fn registration_ack_unchecked(
        &self,
        request: &CredentialServiceRegistrationRequest,
    ) -> Result<CredentialServiceRegistrationAck, CredentialServiceRegistrationError> {
        self.verify_registration(request)?;
        let bytes = self
            .authenticate_registration(request.binding.clone())?
            .into_bytes();
        let verified = self.decode_and_verify_registration_for(&bytes, &request.binding, 0)?;
        self.registration_ack(verified, 0)
    }

    fn mac(&self, domain: &[u8], payload: &[u8]) -> [u8; 32] {
        mac(&self.secret.0, domain, payload)
    }
}

fn derive(key: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut value = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    value.update(domain);
    value.finalize().into_bytes().into()
}
fn mac(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut value = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    value.update(XPC_DOMAIN);
    value.update(&[DESKTOP_REGISTRATION_ROLE]);
    value.update(domain);
    value.update(payload);
    value.finalize().into_bytes().into()
}
