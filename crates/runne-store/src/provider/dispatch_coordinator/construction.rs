use runne_application::prohibited_content::ProhibitedContentPort;
use runne_provider::ProviderPort;
use runne_provider_quota::SubscriptionBudgetAuthority;
use std::sync::Arc;

use super::{
    CredentialDispatchAuthority, ProviderEffectPort, SqliteProviderDispatchCoordinator,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};

impl<'a, P, E> SqliteProviderDispatchCoordinator<'a, P, E>
where
    P: ProviderPort + ?Sized,
    E: ProviderEffectPort + ?Sized,
{
    /// Constructs the only production coordinator from concrete SQLite stores.
    pub const fn new(
        dispatch_store: &'a SqliteProviderDispatchStore,
        execution_store: &'a SqliteProviderExecutionStore,
        credential: CredentialDispatchAuthority<'a>,
        provider: &'a P,
        effect: &'a E,
        prohibited_content: &'a dyn ProhibitedContentPort,
    ) -> Self {
        Self::new_with_budget(
            dispatch_store,
            execution_store,
            credential,
            provider,
            effect,
            prohibited_content,
            false,
            None,
        )
    }

    /// Constructs the coordinator with the durable subscription gate.
    pub const fn new_with_budget(
        dispatch_store: &'a SqliteProviderDispatchStore,
        execution_store: &'a SqliteProviderExecutionStore,
        credential: CredentialDispatchAuthority<'a>,
        provider: &'a P,
        effect: &'a E,
        prohibited_content: &'a dyn ProhibitedContentPort,
        subscription_provider: bool,
        subscription_budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    ) -> Self {
        Self {
            dispatch_store,
            execution_store,
            credential,
            provider,
            effect,
            prohibited_content,
            subscription_provider,
            subscription_budget,
        }
    }
}
