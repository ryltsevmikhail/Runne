#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;

#[cfg(any(test, feature = "test-support"))]
use crate::canonical_provider::CanonicalProviderEffect;
#[cfg(any(test, feature = "test-support"))]
use crate::canonical_provider::RuntimeStoreDecorator;
// fixture-only capability begin
#[cfg(any(test, feature = "test-support"))]
use runne_provider::NativeCredentialAuthority;
#[cfg(any(test, feature = "test-support"))]
use runne_secure_store::{NativeProviderCredentialVersionStore, ProviderJournalKeyring};

/// Fixture-only constructor for an authority-bound native credential store.
#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub type LoopbackCredentialVersionStoreFactory = dyn Fn(NativeCredentialAuthority) -> Arc<dyn NativeProviderCredentialVersionStore>
    + Send
    + Sync;
// fixture-only capability end

/// Complete provider dependencies selected by a workspace-only startup caller.
///
/// This capsule intentionally has no raw accessors: provider composition is the
/// sole consumer that may select its complete production or fixture state.
pub(crate) struct ProtectedProviderDependencyCapsule(ProviderDependencyState);

pub(crate) enum ProviderDependencyState {
    Production,
    // fixture-only capability begin
    #[cfg(any(test, feature = "test-support"))]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the fixture capsule is selected only by protected launch integration tests"
        )
    )]
    LoopbackFixture {
        effect: Arc<dyn CanonicalProviderEffect>,
        keyring: Arc<dyn ProviderJournalKeyring>,
        decorator: Arc<RuntimeStoreDecorator>,
        credential_versions: Arc<LoopbackCredentialVersionStoreFactory>,
    },
    // fixture-only capability end
}

impl ProtectedProviderDependencyCapsule {
    pub(crate) const fn production() -> Self {
        Self(ProviderDependencyState::Production)
    }

    // fixture-only capability begin
    #[cfg(any(test, feature = "test-support"))]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the fixture capsule is selected only by protected launch integration tests"
        )
    )]
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
    // fixture-only capability end

    pub(crate) fn into_provider_state(self) -> ProviderDependencyState {
        self.0
    }
}
