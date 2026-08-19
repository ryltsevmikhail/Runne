use runne_provider::{CredentialDispatchCapability, ProviderFuture};
use thiserror::Error;
use zeroize::Zeroizing;

/// Closed credential materialization failure before any network effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenAiCredentialError {
    /// No native credential is configured for the exact provider profile.
    #[error("OpenAI credential is unavailable")]
    Missing,
    /// Native runne-secure-store policy denied credential access.
    #[error("OpenAI credential access is denied")]
    AccessDenied,
}

/// Native credential boundary invoked only inside an admitted dispatch.
///
/// Implementations must not expose a secret reference, path, environment
/// variable or diagnostic value. Returned bytes are zeroized on drop.
pub trait OpenAiCredentialMaterializer: Send + Sync {
    /// Materializes the exact API credential into short-lived zeroizing memory.
    ///
    /// # Errors
    ///
    /// Returns a typed pre-effect error without secret material.
    fn materialize(
        &self,
        capability: &CredentialDispatchCapability,
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, OpenAiCredentialError>>;
}
