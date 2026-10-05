//! Exact-model admission surface of the canonical provider composition
//! (D1.4b, 2026-09-28).

use super::DaemonCanonicalProviderService;
use runne_domain::task_run::SelectedProviderProfile;
use runne_provider::TextProviderProfile;

impl DaemonCanonicalProviderService {
    /// Exact immutable profile identity used for admission before a TaskRun claim.
    pub(crate) fn selected_profile_identity(&self) -> SelectedProviderProfile {
        SelectedProviderProfile::new(
            self.profile.profile_id().to_owned(),
            self.profile.profile_digest(),
        )
        .expect("validated runtime profile identity")
    }

    /// Exact profile identities accepted by TaskRun submission in this runtime.
    /// Secondary profiles remain explicit-only; this list does not alter the
    /// selected default or route an unspecified submission away from primary.
    pub(crate) fn selected_profile_identities(&self) -> Vec<SelectedProviderProfile> {
        let mut profiles = vec![self.selected_profile_identity()];
        if let Some(profile) = &self.tool_profile
            && let Ok(identity) = SelectedProviderProfile::new(
                profile.profile_id().to_owned(),
                profile.profile_digest(),
            )
        {
            profiles.push(identity);
        }
        if let Some(route) = self
            .secondary_profile
            .as_ref()
            .filter(|route| route.grant.is_some())
            && let Ok(identity) = SelectedProviderProfile::new(
                route.profile.profile_id().to_owned(),
                route.profile.profile_digest(),
            )
        {
            profiles.push(identity);
        }
        profiles
    }

    /// Model bound to an exact profile identity accepted by this runtime.
    /// Unknown or stale identities are rejected; the lookup never falls back.
    pub(crate) fn model_for_selected_profile(
        &self,
        selected: &SelectedProviderProfile,
    ) -> Option<&str> {
        if selected == &self.selected_profile_identity() {
            return Some(&self.model_id);
        }
        if self.tool_profile.as_ref().is_some_and(|profile| {
            SelectedProviderProfile::new(profile.profile_id().to_owned(), profile.profile_digest())
                .is_ok_and(|identity| selected == &identity)
        }) {
            return Some(&self.model_id);
        }
        let route = self
            .secondary_profile
            .as_ref()
            .filter(|route| route.grant.is_some())?;
        let identity = SelectedProviderProfile::new(
            route.profile.profile_id().to_owned(),
            route.profile.profile_digest(),
        )
        .ok()?;
        (selected == &identity).then_some(route.model_id.as_ref())
    }

    /// The provider model pinned by this composition; exact-model admission
    /// compares requested models against it.
    pub fn pinned_model_id(&self) -> &str {
        &self.model_id
    }
}
