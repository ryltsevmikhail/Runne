use std::path::Path;

use super::VerifiedWriterArtifact;

// This opaque, non-secret wire token is duplicated at the platform boundary so
// this domain-neutral port does not depend on provider implementation code.
// Any different argv remains impossible because `arguments` has no inputs.
const PROVIDER_CREDENTIAL_BROKER_MODE_V1: &str = "__provider-credential-broker-v1";

/// Exact non-secret invocation of the packaged one-shot credential writer.
///
/// The launcher intentionally has no API for provider names, credentials,
/// tickets, environment values, or additional arguments. Those values must be
/// transported only over authenticated inherited native channels.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedWriterLaunchSpec {
    artifact: VerifiedWriterArtifact,
}

impl VerifiedWriterLaunchSpec {
    /// Converts an already measured artifact into its only legal invocation.
    #[must_use]
    pub const fn new(artifact: VerifiedWriterArtifact) -> Self {
        Self { artifact }
    }

    /// Returns the exact measured executable, never a `PATH`-resolved name.
    #[must_use]
    pub fn executable(&self) -> &Path {
        self.artifact.executable()
    }

    /// Returns the complete fixed argv tail for the writer process.
    #[must_use]
    pub const fn arguments(&self) -> [&'static str; 1] {
        [PROVIDER_CREDENTIAL_BROKER_MODE_V1]
    }

    /// Returns the immutable writer measurement retained by the native launcher.
    #[must_use]
    pub const fn artifact(&self) -> &VerifiedWriterArtifact {
        &self.artifact
    }
}

impl std::fmt::Debug for VerifiedWriterLaunchSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedWriterLaunchSpec(<fixed>)")
    }
}
