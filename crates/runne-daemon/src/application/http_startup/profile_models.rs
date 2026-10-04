use crate::canonical_provider::DaemonCanonicalProviderService;
use runne_domain::task_run::SelectedProviderProfile;
use std::sync::Arc;

pub(super) fn selected_profile_models(
    provider: Option<&Arc<DaemonCanonicalProviderService>>,
) -> (
    Vec<SelectedProviderProfile>,
    Vec<(SelectedProviderProfile, String)>,
) {
    let profiles = provider
        .map(|service| service.selected_profile_identities())
        .unwrap_or_default();
    let models = provider
        .map(|service| {
            profiles
                .iter()
                .filter_map(|profile| {
                    service
                        .model_for_selected_profile(profile)
                        .map(|model| (profile.clone(), model.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    (profiles, models)
}
