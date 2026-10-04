use std::sync::Arc;

use runne_provider::{
    CredentialDispatchCapability, CredentialFence, CredentialLifecycleRevision, ProviderFuture,
};
use runne_provider_openai::{
    OpenAiBackgroundCredentialMaterializer, OpenAiCredentialError, OpenAiCredentialMaterializer,
};
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use zeroize::Zeroizing;

/// Production native reader reserved for the separately enrolled background realm.
pub(crate) struct NativeBackgroundCredential(super::NativeCredential);

impl NativeBackgroundCredential {
    pub(crate) fn new(materializer: Arc<dyn ProviderCredentialDispatchMaterializer>) -> Self {
        Self(super::NativeCredential::from_materializer(materializer))
    }
}

impl OpenAiCredentialMaterializer for NativeBackgroundCredential {
    fn materialize(
        &self,
        capability: &CredentialDispatchCapability,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        effect_receipt_digest: [u8; 32],
    ) -> ProviderFuture<'_, Result<Zeroizing<Vec<u8>>, OpenAiCredentialError>> {
        self.0
            .materialize(capability, lifecycle, fence, effect_receipt_digest)
    }
}

impl OpenAiBackgroundCredentialMaterializer for NativeBackgroundCredential {}
