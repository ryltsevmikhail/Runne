use std::sync::Arc;

use runne_secure_store::ProviderJournalKeyring;

#[cfg(all(feature = "test-support", not(test)))]
use super::ProviderEffectFactory;
use super::{CanonicalProviderEffect, RuntimeStoreDecorator};
use crate::application::workspace_internal::{
    ProtectedProviderDependencyCapsule, ProviderDependencyState,
};

pub(super) struct SelectedDependencies {
    pub(super) effect: Option<Arc<dyn CanonicalProviderEffect>>,
    #[cfg(test)]
    pub(super) secondary_effect: Option<Arc<dyn CanonicalProviderEffect>>,
    #[cfg(all(feature = "test-support", not(test)))]
    pub(super) adapter_override: Option<Arc<ProviderEffectFactory>>,
    pub(super) keyring: Option<Arc<dyn ProviderJournalKeyring>>,
    pub(super) decorator: Option<Arc<RuntimeStoreDecorator>>,
    pub(super) fixture_transport: bool,
    #[cfg(test)]
    pub(super) primary_missing_fixture: bool,
    #[cfg(test)]
    pub(super) credential_versions:
        Option<Arc<crate::application::workspace_internal::FixtureCredentialVersionStoreFactory>>,
}

pub(super) fn select(dependencies: ProtectedProviderDependencyCapsule) -> SelectedDependencies {
    #[cfg(test)]
    return match dependencies.into_provider_state() {
        ProviderDependencyState::Production => selected(None, None, None, None, None),
        ProviderDependencyState::ProductionWithSecondaryFixture {
            secondary_effect,
            keyring,
            decorator,
        } => {
            let mut selected = selected(
                Some(Arc::clone(&secondary_effect)),
                Some(secondary_effect),
                Some(keyring),
                Some(decorator),
                None,
            );
            selected.fixture_transport = true;
            selected.primary_missing_fixture = true;
            selected
        }
        ProviderDependencyState::LoopbackFixture {
            effect,
            secondary_effect,
            keyring,
            decorator,
            credential_versions,
        } => selected(
            Some(effect),
            secondary_effect,
            Some(keyring),
            Some(decorator),
            Some(credential_versions),
        ),
    };
    #[cfg(all(feature = "test-support", not(test)))]
    return match dependencies.into_provider_state() {
        ProviderDependencyState::Production => selected(None, None, None, None),
        ProviderDependencyState::LoopbackFixture {
            effect,
            keyring,
            decorator,
        } => selected(Some(effect), None, Some(keyring), Some(decorator)),
        #[cfg(unix)]
        ProviderDependencyState::ServiceLoopbackFixture {
            adapter_factory,
            keyring,
            decorator,
        } => selected(None, Some(adapter_factory), Some(keyring), Some(decorator)),
    };
    #[cfg(not(any(test, feature = "test-support")))]
    match dependencies.into_provider_state() {
        ProviderDependencyState::Production => selected(None, None, None),
    }
}

#[cfg(test)]
fn selected(
    effect: Option<Arc<dyn CanonicalProviderEffect>>,
    secondary_effect: Option<Arc<dyn CanonicalProviderEffect>>,
    keyring: Option<Arc<dyn ProviderJournalKeyring>>,
    decorator: Option<Arc<RuntimeStoreDecorator>>,
    credential_versions: Option<
        Arc<crate::application::workspace_internal::FixtureCredentialVersionStoreFactory>,
    >,
) -> SelectedDependencies {
    SelectedDependencies {
        fixture_transport: effect.is_some(),
        primary_missing_fixture: false,
        effect,
        secondary_effect,
        keyring,
        decorator,
        credential_versions,
    }
}

#[cfg(all(feature = "test-support", not(test)))]
fn selected(
    effect: Option<Arc<dyn CanonicalProviderEffect>>,
    adapter_override: Option<Arc<ProviderEffectFactory>>,
    keyring: Option<Arc<dyn ProviderJournalKeyring>>,
    decorator: Option<Arc<RuntimeStoreDecorator>>,
) -> SelectedDependencies {
    SelectedDependencies {
        fixture_transport: effect.is_some() || adapter_override.is_some(),
        effect,
        adapter_override,
        keyring,
        decorator,
    }
}

#[cfg(not(any(test, feature = "test-support")))]
fn selected(
    effect: Option<Arc<dyn CanonicalProviderEffect>>,
    keyring: Option<Arc<dyn ProviderJournalKeyring>>,
    decorator: Option<Arc<RuntimeStoreDecorator>>,
) -> SelectedDependencies {
    SelectedDependencies {
        fixture_transport: effect.is_some(),
        effect,
        keyring,
        decorator,
    }
}
