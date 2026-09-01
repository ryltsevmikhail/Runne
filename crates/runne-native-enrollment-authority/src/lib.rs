//! Opaque authority boundary for the authenticated packaged credential writer.

mod session;

pub use session::{
    AuthenticatedProviderCredentialWriterSession, AuthenticatedWriterClaimContext,
    AuthenticatedWriterEffectAdmission,
};

#[cfg(test)]
mod surface_policy_tests;
