use std::sync::Arc;

use crate::canonical_provider::RuntimeStoreDecorator;
use gocode_daemon_openai_effect::OpenAiEffect;
use gocode_secure_store::ProviderJournalKeyring;

/// Complete provider dependencies selected by a workspace-only startup caller.
///
/// This capsule intentionally has no raw accessors: provider composition is the
/// sole consumer that may select its complete production or fixture state.
pub(crate) struct ProtectedProviderDependencyCapsule(ProviderDependencyState);

pub(crate) enum ProviderDependencyState {
    Production,
    LoopbackFixture {
        effect: Arc<dyn OpenAiEffect>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
    },
}

impl ProtectedProviderDependencyCapsule {
    pub(crate) const fn production() -> Self {
        Self(ProviderDependencyState::Production)
    }

    pub(crate) fn from_loopback_fixture(
        effect: Arc<dyn OpenAiEffect>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
    ) -> Self {
        Self(ProviderDependencyState::LoopbackFixture {
            effect,
            keyring,
            decorator,
        })
    }

    pub(crate) fn into_provider_state(self) -> ProviderDependencyState {
        self.0
    }
}
