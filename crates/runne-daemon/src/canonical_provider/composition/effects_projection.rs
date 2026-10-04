use super::composition::DaemonCanonicalProviderService;
use runne_application::provider::{
    ProviderRemoteAttemptBinding, ProviderRemoteFactAuthenticator,
    ProviderUnknownTerminalFactAuthenticator,
};

pub(crate) struct TaskRunEffectsRuntimeProjection {
    pub(crate) matched_profile: bool,
    pub(crate) capabilities: runne_api::RemoteEffectCapabilitiesV1,
}

impl DaemonCanonicalProviderService {
    pub(crate) fn task_run_effects_authenticator(
        &self,
    ) -> std::sync::Arc<dyn ProviderRemoteFactAuthenticator> {
        std::sync::Arc::clone(&self.remote_fact_authenticator)
    }

    pub(crate) fn task_run_unknown_terminal_authenticator(
        &self,
    ) -> std::sync::Arc<dyn ProviderUnknownTerminalFactAuthenticator> {
        std::sync::Arc::new(
            runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter::new(
                std::sync::Arc::clone(&self.keyring),
                std::sync::Arc::clone(&self.execution_store),
            ),
        )
    }

    pub(crate) fn task_run_effects_static_capabilities(
        &self,
        binding: &ProviderRemoteAttemptBinding,
    ) -> TaskRunEffectsRuntimeProjection {
        let current_database = binding.runtime_authority_id == self.runtime_authority_id
            && binding.database_generation == self.database_generation;
        if current_database
            && profile_matches_effect_binding(
                binding,
                self.provider_id.as_ref(),
                self.profile.as_ref(),
            )
        {
            return TaskRunEffectsRuntimeProjection {
                matched_profile: true,
                capabilities: project(self.adapter.recovery_capabilities()).capabilities,
            };
        }
        let Some(metadata) = self.secondary_effects_metadata.as_ref().filter(|metadata| {
            metadata.matches(binding, self.runtime_authority_id, self.database_generation)
        }) else {
            return unavailable_projection();
        };
        if let Some(route) = self.secondary_profile.as_ref()
            && (!profile_matches_effect_binding(
                binding,
                route.provider_id.as_ref(),
                route.profile.as_ref(),
            ) || route.adapter.recovery_capabilities() != metadata.capabilities())
        {
            return unavailable_projection();
        }
        TaskRunEffectsRuntimeProjection {
            matched_profile: true,
            capabilities: project(metadata.capabilities()).capabilities,
        }
    }
}

fn profile_matches_effect_binding(
    binding: &ProviderRemoteAttemptBinding,
    provider_id: &str,
    profile: &dyn runne_provider::TextProviderProfile,
) -> bool {
    binding.provider_id == provider_id
        && binding.credential_realm == provider_id
        && binding.profile_id == profile.profile_id()
        && binding.profile_digest == profile.profile_digest()
        && binding.pricing_digest == profile.pricing_revision_digest()
}

fn project(
    capabilities: runne_provider::ProviderRecoveryCapabilities,
) -> TaskRunEffectsRuntimeProjection {
    TaskRunEffectsRuntimeProjection {
        matched_profile: true,
        capabilities: runne_api::RemoteEffectCapabilitiesV1 {
            status_check: capabilities.status_check,
            stream_resume: capabilities.stream_resume,
            remote_cancel: capabilities.remote_cancel,
        },
    }
}

fn unavailable_capabilities() -> runne_api::RemoteEffectCapabilitiesV1 {
    runne_api::RemoteEffectCapabilitiesV1 {
        status_check: false,
        stream_resume: false,
        remote_cancel: false,
    }
}

fn unavailable_projection() -> TaskRunEffectsRuntimeProjection {
    TaskRunEffectsRuntimeProjection {
        matched_profile: false,
        capabilities: unavailable_capabilities(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Profile {
        id: &'static str,
        digest: [u8; 32],
        pricing: [u8; 32],
    }

    impl runne_provider::ProviderTerminalPricing for Profile {
        fn price_terminal_usage(
            &self,
            _: &[u8; 32],
            _: &[u8; 32],
            _: i64,
            _: runne_provider::ProviderUsage,
        ) -> Result<runne_provider::ProviderPricedUsage, runne_provider::ProviderTerminalPricingError>
        {
            Err(runne_provider::ProviderTerminalPricingError::Unavailable)
        }
    }

    impl runne_provider::TextProviderProfile for Profile {
        fn profile_id(&self) -> &str {
            self.id
        }
        fn profile_digest(&self) -> [u8; 32] {
            self.digest
        }
        fn pricing_revision_digest(&self) -> [u8; 32] {
            self.pricing
        }
        fn currency(&self) -> &str {
            "USD"
        }
        fn max_input_bytes(&self) -> usize {
            1
        }
        fn max_input_entries(&self) -> usize {
            1
        }
        fn max_input_entry_bytes(&self) -> usize {
            1
        }
        fn max_output_tokens(&self) -> u32 {
            1
        }
        fn max_request_bytes(&self) -> usize {
            1
        }
        fn price_usage_micros(
            &self,
            _: runne_provider::ProviderUsage,
        ) -> Result<u64, runne_provider::ProviderTerminalPricingError> {
            Err(runne_provider::ProviderTerminalPricingError::Unavailable)
        }
    }

    fn binding() -> ProviderRemoteAttemptBinding {
        ProviderRemoteAttemptBinding {
            taskrun_id: runne_domain::id::TaskRunId::from_bytes([1; 16]),
            taskrun_attempt_id: runne_domain::id::AttemptId::from_bytes([2; 16]),
            dispatch_attempt_id: runne_provider::DispatchAttemptId::from_bytes([3; 16]),
            provider_id: "background-provider".to_owned(),
            credential_realm: "background-provider".to_owned(),
            profile_id: "background-profile".to_owned(),
            profile_digest: [4; 32],
            pricing_digest: [5; 32],
            semantic_digest: [6; 32],
            prepared_digest: [7; 32],
            request_digest: [8; 32],
            runtime_authority_id: [9; 16],
            database_generation: 1,
            runtime_generation: 1,
            fencing_token: 1,
        }
    }

    #[test]
    fn secondary_binding_never_falls_back_to_primary_profile() {
        let binding = binding();
        let primary = Profile {
            id: "primary",
            digest: [10; 32],
            pricing: [11; 32],
        };
        let secondary = Profile {
            id: "background-profile",
            digest: [4; 32],
            pricing: [5; 32],
        };
        assert!(!profile_matches_effect_binding(
            &binding,
            "primary-provider",
            &primary
        ));
        assert!(profile_matches_effect_binding(
            &binding,
            "background-provider",
            &secondary
        ));
    }

    #[test]
    fn static_capabilities_do_not_depend_on_secondary_grant_state() {
        let projection = project(runne_provider::ProviderRecoveryCapabilities {
            status_check: true,
            stream_resume: false,
            remote_cancel: true,
        });
        assert!(projection.capabilities.status_check);
        assert!(projection.capabilities.remote_cancel);
        assert!(!projection.capabilities.stream_resume);
    }
}
