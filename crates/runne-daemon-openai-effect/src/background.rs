mod capabilities;
mod create;
mod recovery;

use runne_provider::{ProviderRecoveryControlAuthorizer, ProviderRecoveryDispatchContextProvider};
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use std::sync::Arc;

pub use capabilities::background_recovery_capabilities;
pub use create::{
    effect_from_loopback_background_fixture, effect_from_loopback_background_fixture_with_timeout,
    production_background_effect,
};
pub(crate) use recovery::{cancel_remote, check_remote_status};

/// Builds the production background sender from the already realm-bound native credential reader.
pub fn production_background_effect_from_materializer(
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    contexts: Arc<dyn ProviderRecoveryDispatchContextProvider>,
    controls: Arc<dyn ProviderRecoveryControlAuthorizer>,
) -> Result<Arc<dyn crate::OpenAiEffect>, crate::OpenAiEffectError> {
    create::production_background_effect(
        crate::client::NativeBackgroundCredential::new(materializer),
        contexts,
        controls,
    )
}
