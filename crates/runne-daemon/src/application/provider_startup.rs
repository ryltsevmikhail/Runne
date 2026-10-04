use super::VerifiedOwnerPrivateConfig;
use super::provider_selection::{provider_credential_id, select_provider_runtime_with_quota};
use super::workspace_internal::ProtectedProviderDependencyCapsule;
use super::*;
use crate::canonical_provider::VerifiedSecondaryCatalog;
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
use crate::protected_activation::VerifiedProtectedApplicationStart;

mod composition;
mod composition_diagnostics;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
mod installed_candidate;
#[cfg(all(target_os = "linux", feature = "test-support"))]
mod t1_fixture_secret;
pub(super) struct StartupProvider {
    activation: ProviderActivation,
    provenance: Option<DaemonActivationProvenance>,
    launch_authority_id: Option<[u8; 16]>,
    dependencies: Option<ProtectedProviderDependencyCapsule>,
    root_admission_keys: Option<runne_api::ProtectedActivationKeys>,
    enrollment_capability:
        Option<crate::protected_activation::VerifiedProtectedEnrollmentCapability>,
    secondary_catalog: Option<VerifiedSecondaryCatalog>,
}

type StartupProviderParts = (
    ProviderActivation,
    Option<DaemonActivationProvenance>,
    Option<[u8; 16]>,
    bool,
    Option<ProtectedProviderDependencyCapsule>,
    Option<runne_api::ProtectedActivationKeys>,
    Option<crate::protected_activation::VerifiedProtectedEnrollmentCapability>,
    Option<VerifiedSecondaryCatalog>,
);
impl StartupProvider {
    pub(super) fn deterministic(config: &ConfigurationSnapshot) -> Result<Self, DaemonError> {
        if !matches!(
            config.provider_activation,
            ProviderActivation::Deterministic(_) | ProviderActivation::LocalEngineText(_)
        ) {
            return Err(DaemonError::Bootstrap(
                "verified provider activation provenance is unavailable".into(),
            ));
        }
        if config.secondary_profile_catalog.is_some() {
            return Err(DaemonError::Bootstrap(
                "secondary provider catalog requires verified owner-private startup".into(),
            ));
        }
        Ok(Self {
            activation: config.provider_activation.clone(),
            provenance: None,
            launch_authority_id: None,
            dependencies: None,
            root_admission_keys: None,
            enrollment_capability: None,
            secondary_catalog: None,
        })
    }

    pub(super) fn verified_external(
        config: &VerifiedOwnerPrivateConfig,
        dependencies: ProtectedProviderDependencyCapsule,
    ) -> Result<Self, DaemonError> {
        Ok(Self {
            activation: config.provider_activation().clone(),
            provenance: Some(
                DaemonActivationProvenance::from_verified_owner_private_config(config),
            ),
            launch_authority_id: None,
            dependencies: Some(dependencies),
            root_admission_keys: None,
            enrollment_capability: None,
            secondary_catalog: config.secondary_catalog().cloned(),
        })
    }

    #[cfg(all(any(unix, windows), feature = "desktop-protected"))]
    pub(super) fn verified_protected(
        start: &VerifiedProtectedApplicationStart,
        keys: runne_api::ProtectedActivationKeys,
        dependencies: ProtectedProviderDependencyCapsule,
        enrollment_capability: Option<
            crate::protected_activation::VerifiedProtectedEnrollmentCapability,
        >,
        secondary_catalog: Option<VerifiedSecondaryCatalog>,
    ) -> Self {
        Self {
            activation: start.provider_activation().clone(),
            provenance: Some(DaemonActivationProvenance::from_verified_protected_launch(
                start,
            )),
            launch_authority_id: Some(start.launch_authority_id()),
            dependencies: Some(dependencies),
            root_admission_keys: Some(keys),
            enrollment_capability,
            secondary_catalog,
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
            self.enrollment_capability,
            self.secondary_catalog,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("provider_startup/tests.rs");
}
