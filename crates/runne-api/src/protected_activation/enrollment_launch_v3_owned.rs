#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialEnrollmentOwnedLaunchV3 {
    core: EnrollmentOwnedCoreV3,
    provider: ProviderActivationBindingV1,
    enrollment: ProtectedCredentialEnrollmentLaunchBindingV1,
}

impl ProtectedCredentialEnrollmentOwnedLaunchV3 {
    fn exact(&self, other: &Self) -> Result<(), LaunchAuthorityError> {
        if self.core != other.core || self.enrollment != other.enrollment {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        self.provider.verify_exact(&other.provider)
    }

    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.core.session_id
    }

    #[must_use]
    pub const fn launch_authority_id(&self) -> &[u8; 16] {
        &self.core.authority_id
    }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> &[u8; 16] {
        &self.core.desktop_id
    }

    #[must_use]
    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        &self.core.daemon_id
    }

    #[must_use]
    pub const fn launch_generation(&self) -> u64 {
        self.core.generation
    }

    #[must_use]
    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.core.executable
    }

    #[must_use]
    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.core.profile
    }

    #[must_use]
    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        &self.core.stable
    }

    #[must_use]
    pub const fn provider_binding(&self) -> &ProviderActivationBindingV1 {
        &self.provider
    }

    #[must_use]
    pub const fn enrollment_binding(&self) -> &ProtectedCredentialEnrollmentLaunchBindingV1 {
        &self.enrollment
    }
}

impl fmt::Debug for ProtectedCredentialEnrollmentOwnedLaunchV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedCredentialEnrollmentOwnedLaunchV3(<redacted>)")
    }
}
