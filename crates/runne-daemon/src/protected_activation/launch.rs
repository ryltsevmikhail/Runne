#![cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]
use super::first_activation::{
    expected_profile, preflight_existing, preflight_resume_first_activation,
    prepare_first_activation, validate_runtime_root, verify_pending_request,
};
#[cfg(unix)]
use super::installation_anchor::{self, VerifiedNativeEnrollmentInstallation};
use super::request::DaemonLaunchRequest;
use super::*;
use crate::bootstrap::bootstrap_protected_with_profile;
include!("launch/start.rs");
/// Validated protected launch retained only by the daemon native host.
pub(crate) struct ProtectedDaemonLaunch {
    request: DaemonLaunchRequest,
    keys: ProtectedActivationKeys,
    config: ConfigurationSnapshot,
    pending_first_activation: Option<PendingFirstActivationV1>,
    provider_activation: ProviderActivation,
    enrollment_capability: Option<VerifiedProtectedEnrollmentCapability>,
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
        let canonical_root =
            validate_runtime_root(request.runtime_root()).inspect_err(|error| {
                eprintln!("runne-child-diag: validate_runtime_root failed: {error:?}");
            })?;
        #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "desktop-protected"))]
        let enrollment_capability = matches!(&request, DaemonLaunchRequest::V2(_))
            .then(|| {
                runne_platform_desktop::VerifiedInstalledEnrollmentCapability::load_current_for_authenticated_desktop_peer(
                    &canonical_root,
                    &canonical_root,
                    channel.unix_stream(),
                )
            })
            .flatten()
            .map(VerifiedProtectedEnrollmentCapability::from_installed);
        #[cfg(not(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        )))]
        let enrollment_capability = None;
        let profile = expected_profile(enrollment_capability.as_ref()).inspect_err(|error| {
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
        #[cfg(all(unix, feature = "desktop-protected"))]
        let config = {
            // Protected children start with a cleared environment; the launcher
            // restores the adopting account so this fixed owner-private source
            // is the exact installed configuration. Only the separately bounded
            // finite tool budget is imported, never ambient policy.
            let external = crate::config::load_verified_fixed_external_config()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?;
            config.with_d2_tool_budget_from(external.snapshot())
        };
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
                preflight_existing(&config, expected, None, enrollment_capability.as_ref())?;
                None
            }
            ActivationDispositionV1::ResumeFirstActivation(pending) => {
                verify_pending_request(compatibility, pending, &canonical_root)?;
                if Path::new(&config.db_path).exists() {
                    preflight_resume_first_activation(
                        &config,
                        pending,
                        enrollment_capability.as_ref(),
                    )?;
                }
                Some(pending.as_ref().clone())
            }
        };
        #[cfg(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        ))]
        if enrollment_capability.as_ref().is_some_and(|capability| {
            !capability.revalidate_for_authenticated_desktop_peer(channel.unix_stream())
        }) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(Self {
            request,
            keys,
            config,
            pending_first_activation,
            provider_activation,
            enrollment_capability,
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
        #[cfg(unix)]
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
            enrollment_capability: self.enrollment_capability.take(),
            #[cfg(unix)]
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
        let profile = expected_profile(self.enrollment_capability.as_ref())?;
        let result = bootstrap_protected_with_profile(
            &self.config,
            self.request.launch_authority_id(),
            *bootstrap_key,
            expected_stable,
            self.pending_first_activation.as_ref(),
            Some(&profile),
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

include!("launch/capability.rs");

#[cfg(all(test, feature = "desktop-protected"))]
include!("launch/tests.rs");
