mod authenticator;
mod codec;
mod registration;

pub use authenticator::{
    CredentialServiceRegistrationSecret, CredentialServiceSessionAuthenticator,
};
pub use registration::{
    CredentialServiceRegistrationAck, CredentialServiceRegistrationBinding,
    CredentialServiceRegistrationError, CredentialServiceRegistrationRequest,
    VerifiedCredentialServiceRegistration,
};

pub const CREDENTIAL_SERVICE_MAX_FRAME_BYTES: usize = 16 * 1024;

#[cfg(test)]
mod tests;
