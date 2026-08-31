use super::VerifiedOwnerPrivateConfig;
use super::provider_selection::{provider_credential_id, select_provider_runtime};
use super::workspace_internal::ProtectedProviderDependencyCapsule;
use super::*;
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
use crate::protected_activation::VerifiedProtectedApplicationStart;

mod composition;
pub(super) struct StartupProvider {
    activation: ProviderActivation,
    provenance: Option<DaemonActivationProvenance>,
    launch_authority_id: Option<[u8; 16]>,
    dependencies: Option<ProtectedProviderDependencyCapsule>,
    root_admission_keys: Option<runne_api::ProtectedActivationKeys>,
}

type StartupProviderParts = (
    ProviderActivation,
    Option<DaemonActivationProvenance>,
    Option<[u8; 16]>,
    bool,
    Option<ProtectedProviderDependencyCapsule>,
    Option<runne_api::ProtectedActivationKeys>,
);
impl StartupProvider {
    pub(super) fn deterministic(config: &ConfigurationSnapshot) -> Result<Self, DaemonError> {
        if config.provider_activation.requires_openai_execution()
            || config.provider_activation.requires_deepseek_execution()
        {
            return Err(DaemonError::Bootstrap(
                "verified provider activation provenance is unavailable".into(),
            ));
        }
        Ok(Self {
            activation: config.provider_activation.clone(),
            provenance: None,
            launch_authority_id: None,
            dependencies: None,
            root_admission_keys: None,
        })
    }

    pub(super) fn verified_external(
        config: &VerifiedOwnerPrivateConfig,
        dependencies: ProtectedProviderDependencyCapsule,
    ) -> Self {
        Self {
            activation: config.provider_activation().clone(),
            provenance: Some(
                DaemonActivationProvenance::from_verified_owner_private_config(config),
            ),
            launch_authority_id: None,
            dependencies: Some(dependencies),
            root_admission_keys: None,
        }
    }

    #[cfg(all(any(unix, windows), feature = "desktop-protected"))]
    pub(super) fn verified_protected(
        start: &VerifiedProtectedApplicationStart,
        keys: runne_api::ProtectedActivationKeys,
        dependencies: ProtectedProviderDependencyCapsule,
    ) -> Self {
        Self {
            activation: start.provider_activation().clone(),
            provenance: Some(DaemonActivationProvenance::from_verified_protected_launch(
                start,
            )),
            launch_authority_id: Some(start.launch_authority_id()),
            dependencies: Some(dependencies),
            root_admission_keys: Some(keys),
        }
    }

    pub(super) fn is_protected(&self) -> bool {
        self.provenance
            .is_some_and(|provenance| provenance.is_protected())
    }

    pub(super) fn into_parts(self) -> StartupProviderParts {
        let protected = self.is_protected();
        (
            self.activation,
            self.provenance,
            self.launch_authority_id,
            protected,
            self.dependencies,
            self.root_admission_keys,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("provider_startup/tests.rs");
}
