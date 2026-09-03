mod authenticator;
mod codec;
mod registration;
mod rejoin;
mod transport;

pub use authenticator::{
    CredentialServiceRegistrationSecret, CredentialServiceSessionAuthenticator,
};
pub use registration::{
    CredentialServiceRegistrationAck, CredentialServiceRegistrationBinding,
    CredentialServiceRegistrationError, CredentialServiceRegistrationRequest,
    VerifiedCredentialServiceRegistration,
};
pub use rejoin::{CredentialServiceRejoinBinding, CredentialServiceRejoinRequired};
pub use transport::{
    AcceptedCredentialServiceRegistration, CredentialServiceRegistrationInstall,
    CredentialServiceRuntimeEnvelope, VerifiedCredentialServiceRuntimePayload,
};

pub const CREDENTIAL_SERVICE_MAX_FRAME_BYTES: usize = 16 * 1024;
pub const CREDENTIAL_SERVICE_RUNTIME_PROVIDER_FRAME_MAX_BYTES: usize =
    CREDENTIAL_SERVICE_MAX_FRAME_BYTES - 14 - 32 - 32;

#[cfg(test)]
mod tests;
