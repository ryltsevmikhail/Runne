use runne_domain::id::validate_uuid_v7_bytes;
use std::fmt;

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialServiceRegistrationBinding {
    pub(crate) service_epoch: [u8; 16],
    pub(crate) protected_session_id: [u8; 16],
    pub(crate) daemon_authority_generation: u64,
    pub(crate) runtime_generation: u64,
    pub(crate) supervisor_generation: u64,
    pub(crate) installed_generation: u64,
    pub(crate) installation_owner: [u8; 32],
    pub(crate) release_binding: [u8; 32],
    pub(crate) challenge_nonce: [u8; 16],
    pub(crate) join_attempt: u64,
    pub(crate) expires_at_unix_millis: u64,
}

impl CredentialServiceRegistrationBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service_epoch: [u8; 16],
        protected_session_id: [u8; 16],
        daemon_authority_generation: u64,
        runtime_generation: u64,
        supervisor_generation: u64,
        installed_generation: u64,
        installation_owner: [u8; 32],
        release_binding: [u8; 32],
        challenge_nonce: [u8; 16],
        join_attempt: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, CredentialServiceRegistrationError> {
        if service_epoch == [0; 16]
            || daemon_authority_generation == 0
            || runtime_generation == 0
            || supervisor_generation == 0
            || installed_generation == 0
            || join_attempt == 0
            || expires_at_unix_millis == 0
            || validate_uuid_v7_bytes(&protected_session_id).is_err()
            || installation_owner == [0; 32]
            || release_binding == [0; 32]
            || challenge_nonce == [0; 16]
        {
            return Err(CredentialServiceRegistrationError::InvalidBinding);
        }
        Ok(Self {
            service_epoch,
            protected_session_id,
            daemon_authority_generation,
            runtime_generation,
            supervisor_generation,
            installed_generation,
            installation_owner,
            release_binding,
            challenge_nonce,
            join_attempt,
            expires_at_unix_millis,
        })
    }

    #[must_use]
    pub fn service_epoch(&self) -> &[u8; 16] {
        &self.service_epoch
    }
    #[must_use]
    pub fn protected_session_id(&self) -> &[u8; 16] {
        &self.protected_session_id
    }
    #[must_use]
    pub const fn installed_generation(&self) -> u64 {
        self.installed_generation
    }
}

pub struct CredentialServiceRegistrationRequest {
    pub(crate) binding: CredentialServiceRegistrationBinding,
    pub(crate) mac: [u8; 32],
}

/// A registration accepted against one exact current binding and clock value.
pub struct VerifiedCredentialServiceRegistration(pub(crate) CredentialServiceRegistrationRequest);

impl VerifiedCredentialServiceRegistration {
    pub(crate) fn into_request(self) -> CredentialServiceRegistrationRequest {
        self.0
    }
}

impl CredentialServiceRegistrationRequest {
    #[must_use]
    pub const fn binding(&self) -> &CredentialServiceRegistrationBinding {
        &self.binding
    }
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        super::codec::encode_request(&self)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CredentialServiceRegistrationAck {
    pub(crate) service_epoch: [u8; 16],
    pub(crate) protected_session_id: [u8; 16],
    pub(crate) join_attempt: u64,
    pub(crate) installed_generation: u64,
    pub(crate) mac: [u8; 32],
}

impl CredentialServiceRegistrationAck {
    #[must_use]
    pub fn service_epoch(&self) -> &[u8; 16] {
        &self.service_epoch
    }
    #[must_use]
    pub const fn installed_generation(&self) -> u64 {
        self.installed_generation
    }
}

impl CredentialServiceRegistrationAck {
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        super::codec::encode_ack(&self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialServiceRegistrationError {
    InvalidBinding,
    InvalidFrame,
    AuthenticationFailed,
    BindingMismatch,
    Expired,
}
impl fmt::Display for CredentialServiceRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("credential_service_registration_invalid")
    }
}
impl std::error::Error for CredentialServiceRegistrationError {}
