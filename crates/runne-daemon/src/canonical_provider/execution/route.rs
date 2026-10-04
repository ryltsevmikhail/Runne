use super::super::*;
use runne_domain::task_run::SelectedProviderProfile;
use runne_provider::TextProviderProfile;

pub(in crate::canonical_provider) struct SecondaryProfileRoute {
    pub(in crate::canonical_provider) profile: Arc<SharedTextProviderProfile>,
    pub(in crate::canonical_provider) adapter: Arc<dyn CanonicalProviderEffect>,
    pub(in crate::canonical_provider) credential_store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(in crate::canonical_provider) credential_enrollment_control: Option<Arc<crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl>>,
    pub(in crate::canonical_provider) credential_readback: Option<Arc<dyn runne_secure_store::ProviderCredentialReadback>>,
    #[cfg(test)]
    pub(in crate::canonical_provider) credential_status: runne_secure_store::ProviderCredentialStatus,
    pub(in crate::canonical_provider) defer_credential_reconciliation: bool,
    pub(in crate::canonical_provider) provider_id: std::borrow::Cow<'static, str>,
    pub(in crate::canonical_provider) model_id: std::borrow::Cow<'static, str>,
    pub(in crate::canonical_provider) model_revision: std::borrow::Cow<'static, str>,
    pub(in crate::canonical_provider) grant:
        Option<runne_store::provider::ProviderSecondaryProfileGrant>,
}

#[derive(Clone, Copy)]
pub(super) enum RouteAdmission<'a> {
    Primary,
    Secondary(&'a runne_store::provider::ProviderSecondaryProfileGrant),
}

pub(super) struct ExecutionRoute<'a> {
    pub(super) profile: &'a Arc<SharedTextProviderProfile>,
    pub(super) adapter: &'a dyn CanonicalProviderEffect,
    pub(super) credential_store: &'a Arc<SqliteProviderCredentialLifecycleStore>,
    pub(super) provider_id: &'a str,
    pub(super) model_id: &'a str,
    pub(super) model_revision: &'a str,
    pub(super) admission: RouteAdmission<'a>,
}

pub(super) fn request_ceiling(
    profile: &SharedTextProviderProfile,
) -> Result<(u64, u32, u64), CanonicalProviderExecutionError> {
    let input_tokens = u64::try_from(profile.max_input_bytes())
        .map_err(|_| CanonicalProviderExecutionError::Conflict)?;
    let output_tokens = profile.max_output_tokens();
    let usage = ProviderUsage::new(input_tokens, u64::from(output_tokens), 0, 0)
        .map_err(|_| CanonicalProviderExecutionError::Conflict)?;
    let maximum_cost = profile
        .price_usage_micros(usage)
        .map_err(|_| CanonicalProviderExecutionError::Conflict)?;
    Ok((input_tokens, output_tokens, maximum_cost))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedRoute {
    Primary,
    Secondary,
}

fn select_route(
    selected: Option<&SelectedProviderProfile>,
    primary: &SelectedProviderProfile,
    secondary: Option<&SelectedProviderProfile>,
    policy: Option<runne_api::ProviderSelectionPolicyV1>,
) -> Option<SelectedRoute> {
    let Some(selected) = selected else {
        return Some(SelectedRoute::Primary);
    };
    if selected == primary {
        return Some(SelectedRoute::Primary);
    }
    (policy == Some(runne_api::ProviderSelectionPolicyV1::ExplicitOnly)
        && secondary == Some(selected))
    .then_some(SelectedRoute::Secondary)
}

impl DaemonCanonicalProviderService {
    pub(super) fn execution_route(
        &self,
        selected: Option<&SelectedProviderProfile>,
    ) -> Option<ExecutionRoute<'_>> {
        let primary = SelectedProviderProfile::new(
            self.profile.profile_id().to_owned(),
            self.profile.profile_digest(),
        )
        .ok()?;
        let secondary = self.secondary_profile.as_ref().and_then(|route| {
            SelectedProviderProfile::new(
                route.profile.profile_id().to_owned(),
                route.profile.profile_digest(),
            )
            .ok()
        });
        let policy = self.secondary_profile.as_ref().and_then(|route| {
            runne_api::provider_catalog_entry(route.provider_id.as_ref())
                .map(|entry| entry.selection_policy())
        });
        match select_route(selected, &primary, secondary.as_ref(), policy)? {
            SelectedRoute::Primary => Some(ExecutionRoute {
                profile: &self.profile,
                adapter: self.adapter.as_ref(),
                credential_store: &self.credential_store,
                provider_id: self.provider_id.as_ref(),
                model_id: self.model_id.as_ref(),
                model_revision: self.model_revision.as_ref(),
                admission: RouteAdmission::Primary,
            }),
            SelectedRoute::Secondary => {
                let route = self.secondary_profile.as_ref()?;
                let grant = route.grant.as_ref()?;
                Some(ExecutionRoute {
                    profile: &route.profile,
                    adapter: route.adapter.as_ref(),
                    credential_store: &route.credential_store,
                    provider_id: route.provider_id.as_ref(),
                    model_id: route.model_id.as_ref(),
                    model_revision: route.model_revision.as_ref(),
                    admission: RouteAdmission::Secondary(grant),
                })
            }
        }
    }

    pub(crate) fn accepts_profile_selection(
        &self,
        selected: Option<&SelectedProviderProfile>,
    ) -> bool {
        self.execution_route(selected).is_some()
    }

    pub(crate) fn execute_claimed_selected_profile(
        &self,
        job: CanonicalProviderExecutionJob,
        assignment: runne_application::ports::TaskRunAssignmentIdentity,
        selected: Option<SelectedProviderProfile>,
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<runne_application::ports::TextGenerationReceipt, CanonicalProviderExecutionError>,
    > {
        self.execute_internal(job, Some(assignment), selected)
    }

    pub(crate) fn accepts_model_for_profile(
        &self,
        selected: Option<&SelectedProviderProfile>,
        requested: Option<&str>,
    ) -> bool {
        self.execution_route(selected)
            .is_some_and(|route| requested.is_none_or(|model| model == route.model_id))
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::SharedTextProviderProfile;
    use super::{SelectedRoute, select_route};
    use runne_api::ProviderSelectionPolicyV1;
    use runne_domain::task_run::SelectedProviderProfile;
    use runne_provider::{
        ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
        TextProviderProfile,
    };
    use std::sync::Arc;

    struct FixedPrice(u64);
    impl ProviderTerminalPricing for FixedPrice {
        fn price_terminal_usage(
            &self,
            _: &[u8; 32],
            _: &[u8; 32],
            _: i64,
            _: ProviderUsage,
        ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
            ProviderPricedUsage::new(self.0, "USD".into())
        }
    }
    impl TextProviderProfile for FixedPrice {
        fn profile_id(&self) -> &str {
            "test"
        }
        fn profile_digest(&self) -> [u8; 32] {
            [1; 32]
        }
        fn pricing_revision_digest(&self) -> [u8; 32] {
            [2; 32]
        }
        fn currency(&self) -> &str {
            "USD"
        }
        fn max_input_bytes(&self) -> usize {
            1024
        }
        fn max_input_entries(&self) -> usize {
            1
        }
        fn max_input_entry_bytes(&self) -> usize {
            1024
        }
        fn max_output_tokens(&self) -> u32 {
            10
        }
        fn max_request_bytes(&self) -> usize {
            2048
        }
        fn price_usage_micros(
            &self,
            _: ProviderUsage,
        ) -> Result<u64, ProviderTerminalPricingError> {
            Ok(self.0)
        }
    }

    #[test]
    fn none_stays_primary_and_secondary_requires_exact_explicit_identity() {
        let primary = SelectedProviderProfile::new("primary".into(), [1; 32]).unwrap();
        let secondary = SelectedProviderProfile::new("secondary".into(), [2; 32]).unwrap();
        let wrong_digest = SelectedProviderProfile::new("secondary".into(), [3; 32]).unwrap();
        let unknown = SelectedProviderProfile::new("unknown".into(), [2; 32]).unwrap();
        let explicit = Some(ProviderSelectionPolicyV1::ExplicitOnly);

        assert_eq!(
            select_route(None, &primary, Some(&secondary), explicit),
            Some(SelectedRoute::Primary)
        );
        assert_eq!(
            select_route(Some(&primary), &primary, Some(&secondary), explicit),
            Some(SelectedRoute::Primary)
        );
        assert_eq!(
            select_route(Some(&secondary), &primary, Some(&secondary), explicit),
            Some(SelectedRoute::Secondary)
        );
        assert_eq!(
            select_route(
                Some(&secondary),
                &primary,
                Some(&secondary),
                Some(ProviderSelectionPolicyV1::DefaultEligible)
            ),
            None
        );
        assert_eq!(
            select_route(Some(&wrong_digest), &primary, Some(&secondary), explicit),
            None
        );
        assert_eq!(
            select_route(Some(&unknown), &primary, Some(&secondary), explicit),
            None
        );
    }

    #[test]
    fn admission_ceiling_uses_the_selected_profile_pricing() {
        let primary = SharedTextProviderProfile::new(Arc::new(FixedPrice(11)));
        let secondary = SharedTextProviderProfile::new(Arc::new(FixedPrice(29)));
        assert_eq!(super::request_ceiling(&primary).unwrap().2, 11);
        assert_eq!(super::request_ceiling(&secondary).unwrap().2, 29);
    }
}
