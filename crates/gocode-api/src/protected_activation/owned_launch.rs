/// Exact launch tuple required for renewal and shutdown ownership proofs.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedOwnedLaunchV1 {
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    executable: ExecutableIdentityV1,
    profile: ProtectedRuntimeProfileV1,
    stable: StableRuntimeBindingV1,
    daemon_instance_id: [u8; 16],
    launch_generation: u64,
    session_id: [u8; 16],
}

impl ProtectedOwnedLaunchV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        executable: ExecutableIdentityV1,
        profile: ProtectedRuntimeProfileV1,
        stable: StableRuntimeBindingV1,
        daemon_instance_id: [u8; 16],
        launch_generation: u64,
        session_id: [u8; 16],
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&launch_authority_id).is_err()
            || validate_uuid_v7_bytes(&desktop_host_instance_id).is_err()
            || validate_uuid_v7_bytes(&daemon_instance_id).is_err()
            || validate_uuid_v7_bytes(&session_id).is_err()
            || daemon_instance_id == session_id
            || launch_generation == 0
        {
            return Err(LaunchAuthorityError::InstanceGenerationSessionMismatch);
        }
        Ok(Self {
            launch_authority_id,
            desktop_host_instance_id,
            executable,
            profile,
            stable,
            daemon_instance_id,
            launch_generation,
            session_id,
        })
    }

    pub const fn launch_authority_id(&self) -> &[u8; 16] {
        &self.launch_authority_id
    }

    pub const fn desktop_host_instance_id(&self) -> &[u8; 16] {
        &self.desktop_host_instance_id
    }

    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.executable
    }

    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.profile
    }

    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        &self.stable
    }

    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        &self.daemon_instance_id
    }

    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }

    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }
}

impl fmt::Debug for ProtectedOwnedLaunchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedOwnedLaunchV1")
            .field("launch_generation", &self.launch_generation)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}
