use std::sync::Arc;

use crate::canonical_provider::CanonicalProviderEffect;
use crate::canonical_provider::RuntimeStoreDecorator;
use runne_provider::NativeCredentialAuthority;
use runne_secure_store::{NativeProviderCredentialVersionStore, ProviderJournalKeyring};

/// Fixture-only constructor for an authority-bound native credential store.
#[doc(hidden)]
pub type LoopbackCredentialVersionStoreFactory = dyn Fn(NativeCredentialAuthority) -> Arc<dyn NativeProviderCredentialVersionStore>
    + Send
    + Sync;

/// Complete provider dependencies selected by a workspace-only startup caller.
///
/// This capsule intentionally has no raw accessors: provider composition is the
/// sole consumer that may select its complete production or fixture state.
pub(crate) struct ProtectedProviderDependencyCapsule(ProviderDependencyState);

pub(crate) enum ProviderDependencyState {
    Production,
    #[cfg_attr(not(test), allow(dead_code))]
    LoopbackFixture {
        effect: Arc<dyn CanonicalProviderEffect>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
        credential_versions: Arc<LoopbackCredentialVersionStoreFactory>,
    },
}

impl ProtectedProviderDependencyCapsule {
    pub(crate) const fn production() -> Self {
        Self(ProviderDependencyState::Production)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_loopback_fixture(
        effect: Arc<dyn CanonicalProviderEffect>,
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
