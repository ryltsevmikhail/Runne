//! Opaque authority boundary for the authenticated packaged credential writer.

mod session;
#[cfg(target_os = "macos")]
mod untrusted_writer_endpoint_handoff;

pub use session::{
    AuthenticatedProviderCredentialWriterSession, AuthenticatedWriterClaimContext,
    AuthenticatedWriterEffectAdmission,
};
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub use untrusted_writer_endpoint_handoff::{
    PendingPinnedProviderCredentialWriterSessionV1,
    UntrustedProviderCredentialWriterEndpointHandoffV1,
};

#[cfg(test)]
mod surface_policy_tests;
