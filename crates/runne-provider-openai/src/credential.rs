use runne_provider::{
    CredentialDispatchCapability, CredentialFence, CredentialLifecycleRevision, ProviderFuture,
};
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
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        effect_receipt_digest: [u8; 32],
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, OpenAiCredentialError>>;

    /// Preserves pre-online transport fixtures without granting a native read.
    /// Production materializers must keep the default fail-closed result.
    #[doc(hidden)]
    fn materialize_legacy_fixture(
        &self,
        _capability: &CredentialDispatchCapability,
        _effect_receipt_digest: [u8; 32],
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, OpenAiCredentialError>> {
        Box::pin(async { Err(OpenAiCredentialError::AccessDenied) })
    }
}

/// Explicit marker for a separately enrolled background-profile API credential.
///
/// Implementors must resolve the background credential account independently;
/// the legacy `OpenAI` or `ChatGPT` credential must never be reused implicitly.
pub trait OpenAiBackgroundCredentialMaterializer: OpenAiCredentialMaterializer {}
