use core::any::Any;

use gocode_provider::{DispatchError, DispatchRequest, ProviderFuture, ProviderStreamId};

use super::{CredentialDispatchBinding, ProviderEffectStartReceipt};

/// Store-local external-effect boundary; production implementations consume a
/// receipt created only by the concrete SQLite effect CAS.
pub trait ProviderEffectPort: Send + Sync {
    /// Builds private credential-bearing state without beginning a network effect.
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>>;

    /// Starts exactly one staged effect after receipt and binding verification.
    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>>;
}

/// Opaque daemon-private staged state accepted only by its effect executor.
pub trait ProviderReadyEffect: Send + Any {
    /// Moves the value into executor-private downcasting.
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send>;
}
