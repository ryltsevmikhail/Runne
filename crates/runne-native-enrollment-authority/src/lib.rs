//! Opaque authority boundary for the authenticated packaged credential writer.

#[cfg(all(target_os = "macos", feature = "local-native-enrollment-test"))]
mod persistent_reference_parent_channel;
mod session;
#[cfg(target_os = "macos")]
mod untrusted_writer_endpoint_handoff;

#[cfg(all(target_os = "macos", feature = "local-native-enrollment-test"))]
#[doc(hidden)]
pub use persistent_reference_parent_channel::validate_persistent_reference_parent_channel;
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
