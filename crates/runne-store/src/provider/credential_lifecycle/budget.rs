use super::SqliteProviderCredentialLifecycleStore;
use crate::schema::{
    refresh_subscription_budget, seed_subscription_budget, spend_subscription_budget,
    subscription_budget,
};
use runne_provider_quota::{RemainingState, SubscriptionBudgetAuthority};

/// Conservative local allowance used until a provider reports an absolute value.
pub const SUBSCRIPTION_LOCAL_TOKEN_BUDGET: u64 = 1_000_000;

impl SubscriptionBudgetAuthority for SqliteProviderCredentialLifecycleStore {
    fn seed_and_remaining(
        &self,
        provider_id: &str,
        credential_version: u64,
    ) -> Result<RemainingState, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "budget lock poisoned".to_owned())?;
        seed_subscription_budget(
            &connection,
            provider_id,
            credential_version,
            SUBSCRIPTION_LOCAL_TOKEN_BUDGET,
        )
        .map_err(|error| error.to_string())?;
        Ok(state(
            subscription_budget(&connection, provider_id, credential_version)
                .map_err(|error| error.to_string())?,
        ))
    }

    fn spend(
        &self,
        provider_id: &str,
        credential_version: u64,
        tokens: u64,
    ) -> Result<RemainingState, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "budget lock poisoned".to_owned())?;
        spend_subscription_budget(&connection, provider_id, credential_version, tokens)
            .map_err(|error| error.to_string())?;
        Ok(state(
            subscription_budget(&connection, provider_id, credential_version)
                .map_err(|error| error.to_string())?,
        ))
    }

    fn refill_if_known(
        &self,
        provider_id: &str,
        credential_version: u64,
        remaining_tokens: u64,
        observed_at_high_water: i64,
    ) {
        if let Ok(connection) = self.connection.lock() {
            let _ = refresh_subscription_budget(
                &connection,
                provider_id,
                credential_version,
                remaining_tokens,
                observed_at_high_water,
            );
        }
    }
}

fn state(value: Option<u64>) -> RemainingState {
    match value {
        None => RemainingState::Missing,
        Some(0) => RemainingState::Exhausted,
        Some(value) => RemainingState::Remaining(value),
    }
}
