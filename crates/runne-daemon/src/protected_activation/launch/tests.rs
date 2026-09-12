#[cfg(all(test, feature = "desktop-protected"))]
mod tests {
    use super::*;
    use crate::canonical_provider::DaemonActivationProvenance;

    #[test]
    fn typed_protected_start_derives_protected_provenance() {
        let directory = tempfile::tempdir().unwrap();
        let config = ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(directory.path()));
        let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
        let start = VerifiedProtectedApplicationStart {
            config,
            provider_activation: ProviderActivation::deterministic_v1(),
            launch_authority_id: bootstrap.local_session_authority_id,
            bootstrap,
            enrollment_capability: None,
            #[cfg(target_os = "macos")]
            installation: None,
        };

        #[cfg(target_os = "macos")]
        assert!(start.installation().is_none());
        assert!(DaemonActivationProvenance::from_verified_protected_launch(&start).is_protected());
    }
}
