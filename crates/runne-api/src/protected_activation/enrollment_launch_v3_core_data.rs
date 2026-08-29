const PROTOCOL_SCHEMA_VERSION_V3: u32 = 3;

#[derive(Clone, Eq, PartialEq)]
struct EnrollmentLaunchCoreV3 {
    authority_id: [u8; 16],
    desktop_id: [u8; 16],
    secret: LaunchSecret,
    issued: u64,
    expires: u64,
    principal: String,
    profile: ProtectedRuntimeProfileV1,
    executable: ExecutableIdentityV1,
    runtime_root: PathBuf,
    disposition: ActivationDispositionV1,
}

impl EnrollmentLaunchCoreV3 {
    fn from_v1(value: ProtectedLaunchRequestV1) -> Self {
        Self {
            authority_id: value.launch_authority_id,
            desktop_id: value.desktop_host_instance_id,
            secret: value.launch_secret,
            issued: value.issued_at_unix_millis,
            expires: value.expires_at_unix_millis,
            principal: value.principal_id,
            profile: value.profile,
            executable: value.executable,
            runtime_root: value.runtime_root,
            disposition: value.activation_disposition,
        }
    }

    fn validate(
        &self,
        now: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
    ) -> Result<(), LaunchAuthorityError> {
        if self.profile.transport_profile_id != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
            || expected.profile.transport_profile_id != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        if now < self.issued || now > self.expires {
            return Err(LaunchAuthorityError::StaleLaunchAuthority);
        }
        if self.principal != expected.principal_id {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        if self.executable != *expected.executable {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        if self.profile != *expected.profile {
            return Err(LaunchAuthorityError::ProfileHashMismatch);
        }
        Ok(())
    }

    fn keys(&self) -> ProtectedActivationKeys {
        self.secret.derive_keys()
    }

    fn keys_and_forget(&mut self) -> ProtectedActivationKeys {
        let keys = self.secret.derive_keys();
        self.secret.0.zeroize();
        keys
    }
}

#[derive(Clone, Eq, PartialEq)]
struct EnrollmentOwnedCoreV3 {
    authority_id: [u8; 16],
    desktop_id: [u8; 16],
    executable: ExecutableIdentityV1,
    profile: ProtectedRuntimeProfileV1,
    stable: StableRuntimeBindingV1,
    daemon_id: [u8; 16],
    generation: u64,
    session_id: [u8; 16],
}

impl EnrollmentOwnedCoreV3 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        authority_id: [u8; 16],
        desktop_id: [u8; 16],
        executable: ExecutableIdentityV1,
        profile: ProtectedRuntimeProfileV1,
        stable: StableRuntimeBindingV1,
        daemon_id: [u8; 16],
        generation: u64,
        session_id: [u8; 16],
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&authority_id).is_err()
            || validate_uuid_v7_bytes(&desktop_id).is_err()
            || validate_uuid_v7_bytes(&daemon_id).is_err()
            || validate_uuid_v7_bytes(&session_id).is_err()
            || daemon_id == session_id
            || generation == 0
        {
            return Err(LaunchAuthorityError::InstanceGenerationSessionMismatch);
        }
        Ok(Self {
            authority_id,
            desktop_id,
            executable,
            profile,
            stable,
            daemon_id,
            generation,
            session_id,
        })
    }

    fn next(&self, session_id: [u8; 16]) -> Result<Self, LaunchAuthorityError> {
        Self::new(
            self.authority_id,
            self.desktop_id,
            self.executable.clone(),
            self.profile.clone(),
            self.stable.clone(),
            self.daemon_id,
            self.generation,
            session_id,
        )
    }
}
