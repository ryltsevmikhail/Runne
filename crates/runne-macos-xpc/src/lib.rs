//! Safe Rust boundary around the audited macOS credential-service transport.

mod client;
#[cfg(any(test, target_os = "macos"))]
mod frame;
mod listener;
mod peer_requirement;
mod service_management;

pub use client::{
    CredentialServiceDesktopXpcClient, CredentialServiceRuntimeXpcClient,
    CredentialServiceWriterXpcClient,
};
pub use listener::{CredentialServiceRequestHandler, CredentialServiceXpcListener};
pub use peer_requirement::{
    CredentialServiceEndpointConfiguration, CredentialServiceEndpointRole,
    CredentialServicePeerRequirement,
};
pub use service_management::{
    CredentialServiceRegistrationManager, CredentialServiceRegistrationStatus,
};

/// Closed native transport failures; no Objective-C object or `NSError` escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialServiceXpcError {
    Rejected,
    Unsupported,
    Unavailable,
    TimedOut,
    Cancelled,
    Interrupted,
    Invalidated,
    InvalidReply,
    OutcomeUnknown,
    ApprovalRequired,
    NotFound,
    VersionSkew,
}

impl std::fmt::Display for CredentialServiceXpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("credential service native transport failed")
    }
}

impl std::error::Error for CredentialServiceXpcError {}

impl From<CredentialServiceXpcError>
    for runne_platform_ports::credential_service::CredentialServicePortError
{
    fn from(error: CredentialServiceXpcError) -> Self {
        match error {
            CredentialServiceXpcError::Unsupported => Self::Unsupported,
            CredentialServiceXpcError::TimedOut => Self::TimedOut,
            CredentialServiceXpcError::Cancelled => Self::Cancelled,
            CredentialServiceXpcError::Interrupted => Self::Interrupted,
            CredentialServiceXpcError::Invalidated => Self::Invalidated,
            CredentialServiceXpcError::InvalidReply => Self::InvalidReply,
            CredentialServiceXpcError::OutcomeUnknown => Self::OutcomeUnknown,
            CredentialServiceXpcError::Unavailable
            | CredentialServiceXpcError::ApprovalRequired
            | CredentialServiceXpcError::NotFound => Self::Unavailable,
            CredentialServiceXpcError::Rejected | CredentialServiceXpcError::VersionSkew => {
                Self::Rejected
            }
        }
    }
}

#[cfg(test)]
mod frame_tests;
#[cfg(test)]
mod tests;
