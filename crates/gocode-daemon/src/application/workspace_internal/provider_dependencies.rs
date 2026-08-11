use std::sync::Arc;

use crate::canonical_provider::RuntimeStoreDecorator;
use gocode_daemon_openai_effect::OpenAiEffect;
use gocode_provider::NativeCredentialAuthority;
use gocode_secure_store::{NativeProviderCredentialVersionStore, ProviderJournalKeyring};

/// Fixture-only constructor for an authority-bound native credential store.
#[doc(hidden)]
pub type LoopbackCredentialVersionStoreFactory = dyn Fn(NativeCredentialAuthority) -> Arc<dyn NativeProviderCredentialVersionStore>
    + Send
    + Sync;

/// Complete provider dependencies selected by a workspace-only startup caller.
///
/// This capsule intentionally has no raw accessors: provider composition is the
/// sole consumer that may select its complete production or fixture state.
#[doc(hidden)]
pub struct ProtectedProviderDependencyCapsule(ProviderDependencyState);

pub(crate) enum ProviderDependencyState {
    Production,
    LoopbackFixture {
        effect: Arc<dyn OpenAiEffect>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
        credential_versions: Arc<LoopbackCredentialVersionStoreFactory>,
    },
}

impl ProtectedProviderDependencyCapsule {
    #[doc(hidden)]
    pub const fn production() -> Self {
        Self(ProviderDependencyState::Production)
    }

    #[doc(hidden)]
    pub fn from_loopback_fixture(
        effect: Arc<dyn OpenAiEffect>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
        credential_versions: Arc<LoopbackCredentialVersionStoreFactory>,
    ) -> Self {
        Self(ProviderDependencyState::LoopbackFixture {
            effect,
            keyring,
            decorator,
            credential_versions,
        })
    }

    pub(crate) fn into_provider_state(self) -> ProviderDependencyState {
        self.0
    }
}
