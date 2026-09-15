use super::SelectedProviderRuntime;
use crate::canonical_provider::{SharedTextProviderProfile, radius_effect_adapter};
use crate::error::DaemonError;
use crate::provider_activation::ProviderAccountingMode;
use crate::provider_activation::ProviderActivation;
use runne_daemon_radius_effect::{RadiusAuth, RadiusEffect};
use runne_provider_quota::QuotaStateStore;
use runne_provider_radius::{DEFAULT_RADIUS_GATEWAY, RadiusAccounting, RadiusCatalog};
use runne_secure_store::ProviderCredentialId;
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use std::borrow::Cow;
use std::sync::Arc;

pub(super) fn runtime(
    activation: &ProviderActivation,
    quota_store: Arc<QuotaStateStore>,
) -> Result<SelectedProviderRuntime, DaemonError> {
    let ProviderActivation::RadiusText(binding, settings) = activation else {
        return Err(DaemonError::Config("Radius activation expected".into()));
    };
    ProviderActivation::validate_settings(binding.mode(), binding.profile_id(), settings)
        .map_err(|message| DaemonError::Config(message.into()))?;
    let bytes = settings
        .radius_catalog
        .as_deref()
        .ok_or_else(|| DaemonError::Config("Radius catalog snapshot is required".into()))?;
    let model_id = settings
        .radius_model_id
        .as_deref()
        .ok_or_else(|| DaemonError::Config("Radius model is required".into()))?;
    let revision = settings
        .radius_revision
        .as_deref()
        .ok_or_else(|| DaemonError::Config("Radius catalog revision is required".into()))?;
    let catalog = RadiusCatalog::from_json_at(bytes, DEFAULT_RADIUS_GATEWAY)
        .map_err(|_| DaemonError::Config("Radius catalog snapshot is invalid".into()))?;
    let accounting = match settings.accounting_mode {
        None | Some(ProviderAccountingMode::Subscription) => RadiusAccounting::SubscriptionQuota,
        Some(ProviderAccountingMode::Payg) => RadiusAccounting::Payg,
        Some(ProviderAccountingMode::TokenPlan) => {
            return Err(DaemonError::Config(
                "token-plan accounting is not valid for Radius".into(),
            ));
        }
    };
    let profile = catalog
        .select_with_accounting("radius", model_id, revision, accounting)
        .map_err(|_| DaemonError::Config("Radius model is not in the bound catalog".into()))?;
    if binding.profile_digest() != &profile.profile_digest() {
        return Err(DaemonError::Config("Radius profile digest mismatch".into()));
    }
    let profile_for_factory = profile.clone();
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile.clone()))),
        adapter_factory: Arc::new(
            move |authority, budget_store: Arc<SqliteProviderCredentialLifecycleStore>| {
                RadiusEffect::new_with_quota_and_budget(
                    profile_for_factory.clone(),
                    RadiusAuth::ApiKey,
                    authority,
                    Default::default(),
                    Some(quota_store.clone()),
                    Some(budget_store),
                )
                .map(radius_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("Radius provider adapter unavailable".into()))
            },
        ),
        provider_id: Cow::Owned("radius".to_owned()),
        model_id: Cow::Owned(model_id.to_owned()),
        model_revision: Cow::Owned(revision.to_owned()),
        scope: Cow::Borrowed("provider.radius.text"),
        credential_id: ProviderCredentialId::Generic("radius"),
    })
}
