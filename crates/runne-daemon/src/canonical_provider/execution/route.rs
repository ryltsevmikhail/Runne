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
    pub(super) tool_mode: bool,
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
        #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
        if selected.is_some_and(|selected| {
            self.tool_profile.as_ref().is_some_and(|profile| {
                SelectedProviderProfile::new(
                    profile.profile_id().to_owned(),
                    profile.profile_digest(),
                )
                .is_ok_and(|identity| identity == *selected)
            })
        }) {
            let profile = self.tool_profile.as_ref()?;
            let grant = self.tool_profile_grant.as_ref()?;
            return Some(ExecutionRoute {
                profile,
                adapter: self.tool_adapter.as_ref()?.as_ref(),
                credential_store: &self.credential_store,
                provider_id: self.provider_id.as_ref(),
                model_id: self.model_id.as_ref(),
                model_revision: self.model_revision.as_ref(),
                admission: RouteAdmission::Secondary(grant),
                tool_mode: true,
            });
        }
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
                tool_mode: false,
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
                    tool_mode: false,
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

    pub(crate) fn accepts_tool_profile_selection(
        &self,
        selected: Option<&SelectedProviderProfile>,
    ) -> bool {
        #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
        {
            selected.is_some_and(|selected| {
                self.tool_profile.as_ref().is_some_and(|profile| {
                    SelectedProviderProfile::new(
                        profile.profile_id().to_owned(),
                        profile.profile_digest(),
                    )
                    .is_ok_and(|identity| identity == *selected)
                })
            })
        }
        #[cfg(not(all(target_os = "linux", feature = "desktop-protected")))]
        {
            let _ = selected;
            false
        }
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
        Box::pin(async move {
            match self
                .execute_internal(job, Some(assignment), selected, false, None)
                .await?
            {
                super::InternalProviderResult::Text(receipt) => Ok(receipt),
                #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
                super::InternalProviderResult::ToolRound(_) => {
                    Err(CanonicalProviderExecutionError::Uncertain)
                }
            }
        })
    }

    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    pub(crate) fn execute_claimed_tool_round(
        &self,
        job: CanonicalProviderExecutionJob,
        assignment: runne_application::ports::TaskRunAssignmentIdentity,
        selected: SelectedProviderProfile,
        round: super::D2ProviderRound,
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<super::D2ProviderRoundOutcome, CanonicalProviderExecutionError>,
    > {
        Box::pin(async move {
            match self
                .execute_internal(job, Some(assignment), Some(selected), true, Some(round))
                .await?
            {
                super::InternalProviderResult::ToolRound(outcome) => Ok(outcome),
                _ => Err(CanonicalProviderExecutionError::Uncertain),
            }
        })
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
#[path = "route_tests.rs"]
mod tests;
