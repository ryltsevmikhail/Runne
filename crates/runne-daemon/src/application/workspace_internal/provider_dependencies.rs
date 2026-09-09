#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;

#[cfg(any(test, feature = "test-support"))]
use crate::canonical_provider::CanonicalProviderEffect;
#[cfg(all(unix, feature = "test-support", not(test)))]
use crate::canonical_provider::ProviderEffectFactory;
#[cfg(any(test, feature = "test-support"))]
use crate::canonical_provider::RuntimeStoreDecorator;
// fixture-only capability begin
#[cfg(any(test, feature = "test-support"))]
use runne_secure_store::ProviderJournalKeyring;
// fixture-only capability end

#[cfg(test)]
mod credential_writer_fixture;
#[cfg(test)]
pub(crate) use credential_writer_fixture::FixtureCredentialVersionStoreFactory;

/// Complete provider dependencies selected by a workspace-only startup caller.
///
/// This capsule intentionally has no raw accessors: provider composition is the
/// sole consumer that may select its complete production or fixture state.
pub(crate) struct ProtectedProviderDependencyCapsule(ProviderDependencyState);

pub(crate) enum ProviderDependencyState {
    Production,
    // fixture-only capability begin
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    LoopbackFixture {
        effect: Arc<dyn CanonicalProviderEffect>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
        #[cfg(test)]
        credential_versions: Arc<FixtureCredentialVersionStoreFactory>,
    },
    #[cfg(all(unix, feature = "test-support", not(test)))]
    ServiceLoopbackFixture {
        adapter_factory: Arc<ProviderEffectFactory>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
    },
    // fixture-only capability end
}

impl ProtectedProviderDependencyCapsule {
    pub(crate) const fn production() -> Self {
        Self(ProviderDependencyState::Production)
    }

    // fixture-only capability begin
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn from_loopback_fixture(
        effect: Arc<dyn CanonicalProviderEffect>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
        credential_versions: Arc<FixtureCredentialVersionStoreFactory>,
    ) -> Self {
        Self(ProviderDependencyState::LoopbackFixture {
            effect,
            keyring,
            decorator,
            credential_versions,
        })
    }

    #[cfg(all(unix, feature = "test-support", not(test)))]
    pub(crate) fn from_service_loopback_fixture(
        adapter_factory: Arc<ProviderEffectFactory>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
    ) -> Self {
        Self(ProviderDependencyState::ServiceLoopbackFixture {
            adapter_factory,
            keyring,
            decorator,
        })
    }

    #[cfg(all(feature = "test-support", not(test)))]
    #[allow(dead_code)]
    pub(crate) fn from_loopback_fixture(
        effect: Arc<dyn CanonicalProviderEffect>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
    ) -> Self {
        Self(ProviderDependencyState::LoopbackFixture {
            effect,
            keyring,
            decorator,
        })
    }
    // fixture-only capability end

    pub(crate) fn into_provider_state(self) -> ProviderDependencyState {
        self.0
    }
}
