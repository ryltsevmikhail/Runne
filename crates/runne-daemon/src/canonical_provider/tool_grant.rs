use super::*;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(super) fn install(
    tool_profile: Option<&SharedTextProviderProfile>,
    budget: Option<crate::config::D2SafeToolLoopBudgetConfig>,
    provider_id: &str,
    execution_store: &SqliteProviderExecutionStore,
    launch_capability: &ProviderRuntimeLaunchCapability,
) -> Result<Option<runne_store::provider::ProviderSecondaryProfileGrant>, DaemonError> {
    Ok(match (tool_profile, budget) {
        (Some(tool_profile), Some(budget)) => {
            let (tokens, micros) = budget
                .limits()
                .ok_or_else(|| DaemonError::Bootstrap("D2 tool budget invalid".into()))?;
            let provider_name = provider_id.to_owned();
            let provider_id = runne_provider::ProviderId::new(&provider_name)
                .map_err(|_| DaemonError::Bootstrap("D2 provider identity invalid".into()))?;
            let spec = runne_application::provider::ProviderSecondaryProfileGrantSpec::new(
                &provider_id,
                tool_profile.profile_id(),
                provider_name.as_str(),
                tool_profile.profile_digest(),
                tool_profile.pricing_revision_digest(),
                tokens,
                micros,
            )
            .map_err(|_| DaemonError::Bootstrap("D2 tool grant invalid".into()))?;
            Some(
                execution_store
                    .install_secondary_profile_grant(launch_capability, spec)
                    .map_err(|_| DaemonError::Bootstrap("D2 tool grant unavailable".into()))?,
            )
        }
        _ => None,
    })
}
