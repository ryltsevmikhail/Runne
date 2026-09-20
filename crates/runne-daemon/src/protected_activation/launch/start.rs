/// Opaque release capability measured from the authenticated desktop peer.
/// It carries no credential, session, or mutation authority.
pub(crate) struct VerifiedProtectedEnrollmentCapability {
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    _sealed: runne_platform_desktop::VerifiedInstalledEnrollmentCapability,
}

impl VerifiedProtectedEnrollmentCapability {
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    pub(crate) const fn from_installed(
        capability: runne_platform_desktop::VerifiedInstalledEnrollmentCapability,
    ) -> Self {
        Self {
            _sealed: capability,
        }
    }

    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    pub(crate) fn revalidate_for_authenticated_desktop_peer(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> bool {
        self._sealed
            .revalidate_for_authenticated_desktop_peer(stream)
    }

    pub(crate) const fn is_qualified(&self) -> bool {
        #[cfg(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        ))]
        {
            true
        }
        #[cfg(not(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        )))]
        {
            false
        }
    }
}

/// Validated protected launch retained only by the daemon native host.
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
pub struct VerifiedProtectedApplicationStart {
    config: ConfigurationSnapshot,
    provider_activation: ProviderActivation,
    launch_authority_id: [u8; 16],
    bootstrap: BootstrapOutcome,
    enrollment_capability: Option<VerifiedProtectedEnrollmentCapability>,
    #[cfg(target_os = "macos")]
    #[cfg_attr(not(test), expect(dead_code, reason = "sealed composition"))]
    installation: Option<VerifiedNativeEnrollmentInstallation>,
}
/// Opaque verified startup package; its admission keys cannot be substituted.
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
pub struct VerifiedProtectedRuntimeStart {
    application: VerifiedProtectedApplicationStart,
    keys: ProtectedActivationKeys,
}
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
impl VerifiedProtectedRuntimeStart {
    pub(crate) fn into_parts(self) -> (VerifiedProtectedApplicationStart, ProtectedActivationKeys) {
        (self.application, self.keys)
    }
}
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
impl VerifiedProtectedApplicationStart {
    pub(crate) const fn provider_activation(&self) -> &ProviderActivation {
        &self.provider_activation
    }
    pub(crate) const fn authority_id(&self) -> [u8; 16] {
        self.bootstrap.authority_id
    }
    pub(crate) const fn launch_authority_id(&self) -> [u8; 16] {
        self.launch_authority_id
    }
    #[cfg(target_os = "macos")]
    #[cfg_attr(not(test), expect(dead_code, reason = "sealed composition"))]
    pub(crate) const fn installation(&self) -> Option<&VerifiedNativeEnrollmentInstallation> {
        self.installation.as_ref()
    }
    pub(crate) fn take_enrollment_capability(
        &mut self,
    ) -> Option<VerifiedProtectedEnrollmentCapability> {
        self.enrollment_capability.take()
    }
    pub(crate) fn into_parts(
        self,
    ) -> (ConfigurationSnapshot, BootstrapOutcome, ProviderActivation) {
        (self.config, self.bootstrap, self.provider_activation)
    }
    #[cfg(all(test, unix))]
    pub(crate) fn from_test_parts(
        config: ConfigurationSnapshot,
        provider_activation: ProviderActivation,
        bootstrap: BootstrapOutcome,
    ) -> Self {
        let launch_authority_id = bootstrap.local_session_authority_id;
        Self {
            config,
            provider_activation,
            launch_authority_id,
            bootstrap,
            enrollment_capability: None,
            #[cfg(target_os = "macos")]
            installation: None,
        }
    }
}
