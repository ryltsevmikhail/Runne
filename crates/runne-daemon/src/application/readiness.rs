use super::*;

impl DaemonApplication {
    /// Returns the bound local address before the accept loop starts.
    pub fn local_addr(&self) -> Result<SocketAddr, DaemonError> {
        Ok(self.http_host.local_addr()?)
    }

    /// Returns the stable runtime authority without exposing credentials.
    pub fn authority_id(&self) -> [u8; 16] {
        self.bootstrap.authority_id
    }

    /// Reports whether bootstrap reopened an existing database.
    pub fn db_existed(&self) -> bool {
        self.bootstrap.db_existed
    }

    /// Builds exact authenticated readiness without exposing legacy profile files.
    #[cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
    pub(crate) fn protected_ready(
        &self,
        request: &ProtectedLaunchRequestV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<ProtectedReadyV1, DaemonError> {
        if !self.protected_activation || self.client_profile.is_some() {
            return Err(DaemonError::Bootstrap(
                "protected readiness is unavailable".into(),
            ));
        }
        let executable = super::executable_identity::measure_launched_executable()?;
        if &executable != request.executable() {
            return Err(DaemonError::Bootstrap(
                "launched executable identity mismatch".into(),
            ));
        }
        let stable = self.binding.stable();
        let stable = StableRuntimeBindingV1::new(
            *stable.authority_id(),
            stable.principal_id().as_str(),
            *stable.lineage_id().as_bytes(),
            stable.profile_id(),
            *stable.schema_hash(),
            *stable.capability_digest(),
        )
        .map_err(|_| DaemonError::Bootstrap("build protected readiness binding".into()))?;
        let ephemeral = self.binding.ephemeral();
        let mut ready = ProtectedReadyV1::new(
            request.launch_authority_id(),
            request.desktop_host_instance_id(),
            executable,
            request.profile().clone(),
            stable,
            ephemeral.daemon_instance_id().into_bytes(),
            ephemeral.launch_generation(),
            *ephemeral.session_id(),
            format!("https://{}", self.local_addr()?),
            *self.bootstrap.launch_identity.certificate_sha256(),
            self.bootstrap
                .launch_identity
                .certificate_der()
                .as_ref()
                .to_vec(),
            self.runtime_capabilities
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
        )
        .map_err(|_| DaemonError::Bootstrap("build protected readiness".into()))?;
        ready.sign(keys);
        Ok(ready)
    }

    /// Builds V2 readiness only for the exact protected provider binding.
    #[cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
    pub(crate) fn protected_ready_v2(
        &self,
        request: &ProtectedLaunchRequestV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<ProtectedReadyV2, DaemonError> {
        if self.provider_activation.binding() != request.provider_binding() {
            return Err(DaemonError::Bootstrap(
                "provider-bound readiness is unavailable".into(),
            ));
        }
        let ready = self.protected_ready(request.compatibility_request(), keys)?;
        let mut ready = ProtectedReadyV2::new(
            ready,
            request.provider_binding().clone(),
            self.provider_readiness,
        )
        .map_err(|_| DaemonError::Bootstrap("build provider-bound readiness".into()))?;
        ready.sign(keys);
        Ok(ready)
    }

    /// Shares the in-memory protected session service with the control loop.
    #[cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
    pub(crate) fn protected_session_service(
        &self,
    ) -> Result<Arc<Mutex<LocalSessionService>>, DaemonError> {
        if !self.protected_activation {
            return Err(DaemonError::Bootstrap(
                "protected session service is unavailable".into(),
            ));
        }
        Ok(Arc::clone(&self.local_session_service))
    }

    /// Shares the daemon monotonic clock used to enforce bootstrap deadlines.
    #[cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
    pub(crate) fn protected_session_clock(
        &self,
    ) -> Result<Arc<dyn Fn() -> Duration + Send + Sync>, DaemonError> {
        if !self.protected_activation {
            return Err(DaemonError::Bootstrap(
                "protected session clock is unavailable".into(),
            ));
        }
        Ok(Arc::clone(&self.session_clock))
    }

    #[cfg(feature = "desktop-protected")]
    pub(crate) fn protected_root_control(
        &self,
    ) -> Result<Arc<crate::protected_activation::ProtectedRootControl>, DaemonError> {
        self.root_control
            .as_ref()
            .cloned()
            .ok_or_else(|| DaemonError::Bootstrap("protected root control is unavailable".into()))
    }

    /// Daemon-owned facts for the same-process enrollment control transition.
    #[cfg(all(unix, feature = "desktop-protected"))]
    pub(crate) fn protected_enrollment_facts(
        &self,
    ) -> Result<ProtectedEnrollmentFacts, DaemonError> {
        if !self.protected_activation {
            return Err(DaemonError::Bootstrap(
                "protected enrollment facts are unavailable".into(),
            ));
        }
        let installation =
            crate::protected_activation::load_read_only(&self.bootstrap).map_err(|_| {
                DaemonError::Bootstrap("enrollment installation anchor unavailable".into())
            })?;
        Ok(ProtectedEnrollmentFacts {
            endpoint: format!("https://{}", self.local_addr()?),
            certificate_sha256: *self.bootstrap.launch_identity.certificate_sha256(),
            certificate_der: self
                .bootstrap
                .launch_identity
                .certificate_der()
                .as_ref()
                .to_vec(),
            capabilities: self
                .runtime_capabilities
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
            provider_readiness: self.provider_readiness,
            installation,
            credential_enrollment_control: self.credential_enrollment_control.clone(),
            credential_enrollment_controls: self.credential_enrollment_controls.clone(),
        })
    }
}

/// Readiness-path facts retained only by the protected activation host.
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) struct ProtectedEnrollmentFacts {
    pub(crate) endpoint: String,
    pub(crate) certificate_sha256: [u8; 32],
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) capabilities: Vec<String>,
    pub(crate) provider_readiness: runne_api::ProviderActivationReadinessV1,
    pub(crate) installation: crate::protected_activation::VerifiedNativeEnrollmentInstallation,
    pub(crate) credential_enrollment_control: Option<
        Arc<
            crate::application::provider_credential_enrollment::
                DaemonProviderCredentialEnrollmentControl,
        >,
    >,
    pub(crate) credential_enrollment_controls: Vec<(
        String,
        Arc<
            crate::application::provider_credential_enrollment::
                DaemonProviderCredentialEnrollmentControl,
        >,
    )>,
}
