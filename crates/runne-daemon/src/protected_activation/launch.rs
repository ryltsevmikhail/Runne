#![cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
use super::first_activation::{
    expected_profile, preflight_existing, preflight_resume_first_activation,
    prepare_first_activation, validate_runtime_root, verify_pending_request,
};
#[cfg(target_os = "macos")]
use super::installation_anchor::{self, VerifiedNativeEnrollmentInstallation};
use super::request::DaemonLaunchRequest;
use super::*;
/// Validated protected launch retained only by the daemon native host.
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
pub struct VerifiedProtectedApplicationStart {
    config: ConfigurationSnapshot,
    provider_activation: ProviderActivation,
    launch_authority_id: [u8; 16],
    bootstrap: BootstrapOutcome,
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
    pub(crate) fn into_parts(
        self,
    ) -> (ConfigurationSnapshot, BootstrapOutcome, ProviderActivation) {
        (self.config, self.bootstrap, self.provider_activation)
    }
    #[cfg(test)]
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
            #[cfg(target_os = "macos")]
            installation: None,
        }
    }
}
/// Validated protected launch retained only by the daemon native host.
pub(crate) struct ProtectedDaemonLaunch {
    request: DaemonLaunchRequest,
    keys: ProtectedActivationKeys,
    config: ConfigurationSnapshot,
    pending_first_activation: Option<PendingFirstActivationV1>,
    provider_activation: ProviderActivation,
}
#[cfg(any(unix, windows))]
impl ProtectedDaemonLaunch {
    /// Reads, validates, and—when needed—two-phase commits first activation.
    pub(crate) fn accept<F>(
        channel: &mut ProtectedActivationChannel,
        executable_path: &Path,
        mut now_unix_millis: F,
    ) -> Result<Self, LaunchAuthorityError>
    where
        F: FnMut() -> Result<u64, LaunchAuthorityError>,
    {
        let frame = channel
            .read_frame()
            .inspect_err(|error| eprintln!("runne-child-diag: read_frame failed: {error:?}"))?;
        let mut request = DaemonLaunchRequest::decode_frame(&frame).inspect_err(|error| {
            eprintln!("runne-child-diag: decode_frame failed: {error:?}");
        })?;
        let executable = ExecutableIdentityV1::measure(executable_path).inspect_err(|error| {
            eprintln!("runne-child-diag: measure failed: {error:?}");
        })?;
        let profile = expected_profile().inspect_err(|error| {
            eprintln!("runne-child-diag: expected_profile failed: {error:?}");
        })?;
        let provider_activation = request
            .validate(
                now_unix_millis()?,
                &LaunchAuthorityValidationV1 {
                    principal_id: LOCAL_PRINCIPAL,
                    profile: &profile,
                    executable: &executable,
                },
            )
            .inspect_err(|error| {
                eprintln!("runne-child-diag: validate failed: {error:?}");
                eprintln!(
                    "runne-child-diag: request launch_authority_id={:?} desktop_host_instance_id={:?} runtime_root={:?} disposition={:?}",
                    request.launch_authority_id(),
                    request.desktop_host_instance_id(),
                    request.runtime_root(),
                    request.activation_disposition()
                );
            })?;
        let canonical_root = validate_runtime_root(request.runtime_root()).inspect_err(|error| {
            eprintln!("runne-child-diag: validate_runtime_root failed: {error:?}");
        })?;
        if canonical_root != request.runtime_root() {
            eprintln!(
                "runne-child-diag: canonical mismatch canonical={:?} requested={:?}",
                canonical_root,
                request.runtime_root()
            );
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let mut defaults = BuiltInDefaults::new(&canonical_root);
        defaults.http_bind = "127.0.0.1:0".to_owned();
        let config = ConfigurationSnapshot::from_defaults(&defaults);
        let keys = request.derive_keys_and_forget();
        let compatibility = request
            .compatibility()
            .ok_or(LaunchAuthorityError::InvalidContract)?;

        let pending_first_activation = match request.activation_disposition() {
            ActivationDispositionV1::FirstActivation => {
                if Path::new(&config.db_path).exists() {
                    return Err(LaunchAuthorityError::UnexpectedExistingEventLog);
                }
                let pending = prepare_first_activation(compatibility, &canonical_root)?;
                let mut prepared = ProtectedFirstActivationPreparedV1::new(
                    request.launch_authority_id(),
                    request.desktop_host_instance_id(),
                    pending.clone(),
                );
                prepared.sign(&keys);
                channel.write_frame(
                    &prepared
                        .encode_frame()
                        .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                )?;
                let commit = ProtectedFirstActivationCommitV1::decode_frame(&channel.read_frame()?)
                    .map_err(|_| LaunchAuthorityError::FirstActivationCommitIncomplete)?;
                commit.verify_exact(compatibility, &pending, &keys)?;
                request.validate_freshness(now_unix_millis()?)?;
                Some(pending)
            }
            ActivationDispositionV1::Existing(expected) => {
                preflight_existing(&config, expected, None)?;
                None
            }
            ActivationDispositionV1::ResumeFirstActivation(pending) => {
                verify_pending_request(compatibility, pending, &canonical_root)?;
                if Path::new(&config.db_path).exists() {
                    preflight_resume_first_activation(&config, pending)?;
                }
                Some(pending.as_ref().clone())
            }
        };
        Ok(Self {
            request,
            keys,
            config,
            pending_first_activation,
            provider_activation,
        })
    }
    /// Produces the opaque application start only from this authenticated launch.
    #[cfg(feature = "desktop-protected")]
    pub(crate) fn bootstrap_application_start<F>(
        &mut self,
        now_unix_millis: F,
    ) -> Result<VerifiedProtectedApplicationStart, LaunchAuthorityError>
    where
        F: FnMut() -> Result<u64, LaunchAuthorityError>,
    {
        let bootstrap = self.bootstrap(now_unix_millis)?;
        if bootstrap.authority_id == [0; 16] || bootstrap.launch_generation == 0 {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        #[cfg(target_os = "macos")]
        let installation = self
            .request_v2()
            .is_some()
            .then(|| installation_anchor::provision_after_provider_bound_v2(&bootstrap))
            .transpose()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        Ok(VerifiedProtectedApplicationStart {
            config: self.config.clone(),
            provider_activation: self.provider_activation.clone(),
            launch_authority_id: self.request.launch_authority_id(),
            bootstrap,
            #[cfg(target_os = "macos")]
            installation,
        })
    }
    /// Produces the only sealed daemon startup package for this verified launch.
    #[cfg(feature = "desktop-protected")]
    pub(crate) fn bootstrap_runtime_start<F>(
        &mut self,
        now_unix_millis: F,
    ) -> Result<VerifiedProtectedRuntimeStart, LaunchAuthorityError>
    where
        F: FnMut() -> Result<u64, LaunchAuthorityError>,
    {
        let application = self.bootstrap_application_start(now_unix_millis)?;
        Ok(VerifiedProtectedRuntimeStart {
            application,
            keys: self.keys.clone(),
        })
    }

    /// Completes storage bootstrap only after protected admission succeeded.
    pub(crate) fn bootstrap<F>(
        &mut self,
        mut now_unix_millis: F,
    ) -> Result<BootstrapOutcome, LaunchAuthorityError>
    where
        F: FnMut() -> Result<u64, LaunchAuthorityError>,
    {
        self.request.validate_freshness(now_unix_millis()?)?;
        let bootstrap_key = self.keys.bootstrap_key();
        let expected_stable = match self.request.activation_disposition() {
            ActivationDispositionV1::FirstActivation => self
                .pending_first_activation
                .as_ref()
                .map(PendingFirstActivationV1::stable)
                .ok_or(LaunchAuthorityError::FirstActivationPreparationMismatch)?,
            ActivationDispositionV1::Existing(expected) => expected,
            ActivationDispositionV1::ResumeFirstActivation(pending) => pending.stable(),
        };
        let result = bootstrap_protected(
            &self.config,
            self.request.launch_authority_id(),
            *bootstrap_key,
            expected_stable,
            self.pending_first_activation.as_ref(),
            || {
                let now = now_unix_millis().map_err(|_| {
                    crate::error::DaemonError::Bootstrap(
                        "protected launch authority expired".into(),
                    )
                })?;
                self.request.validate_freshness(now).map_err(|_| {
                    crate::error::DaemonError::Bootstrap(
                        "protected launch authority expired".into(),
                    )
                })
            },
        );
        self.keys.forget_bootstrap_key();
        result.map_err(|error| {
            if error.to_string().contains("already consumed") {
                LaunchAuthorityError::ReusedLaunchAuthority
            } else if error.to_string().contains("expired") {
                LaunchAuthorityError::StaleLaunchAuthority
            } else if error.to_string().contains("prepared") {
                LaunchAuthorityError::FirstActivationPreparationMismatch
            } else {
                LaunchAuthorityError::InvalidContract
            }
        })
    }

    pub(crate) const fn request_v1(&self) -> Option<&ProtectedLaunchRequestV1> {
        match &self.request {
            DaemonLaunchRequest::V1(request) => Some(request),
            DaemonLaunchRequest::V2(_) | DaemonLaunchRequest::V3(_) => None,
        }
    }

    pub(crate) const fn request_v2(&self) -> Option<&ProtectedLaunchRequestV2> {
        match &self.request {
            DaemonLaunchRequest::V1(_) | DaemonLaunchRequest::V3(_) => None,
            DaemonLaunchRequest::V2(request) => Some(request),
        }
    }

    pub(crate) const fn keys(&self) -> &ProtectedActivationKeys {
        &self.keys
    }

    pub(crate) const fn config(&self) -> &ConfigurationSnapshot {
        &self.config
    }
}

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
            #[cfg(target_os = "macos")]
            installation: None,
        };

        #[cfg(target_os = "macos")]
        assert!(start.installation().is_none());
        assert!(DaemonActivationProvenance::from_verified_protected_launch(&start).is_protected());
    }
}
