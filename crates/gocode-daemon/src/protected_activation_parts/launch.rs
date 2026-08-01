/// Validated protected launch retained only by the daemon native host.
#[cfg(unix)]
pub struct ProtectedDaemonLaunch {
    request: ProtectedLaunchRequestV1,
    keys: ProtectedActivationKeys,
    config: ConfigurationSnapshot,
    pending_first_activation: Option<PendingFirstActivationV1>,
}

#[cfg(unix)]
impl ProtectedDaemonLaunch {
    /// Reads, validates, and—when needed—two-phase commits first activation.
    pub fn accept<F>(
        channel: &mut ProtectedActivationChannel,
        executable_path: &Path,
        mut now_unix_millis: F,
    ) -> Result<Self, LaunchAuthorityError>
    where
        F: FnMut() -> Result<u64, LaunchAuthorityError>,
    {
        let frame = channel.read_frame()?;
        let mut request = ProtectedLaunchRequestV1::decode_frame(&frame)
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        let executable = ExecutableIdentityV1::measure(executable_path)?;
        let profile = expected_profile()?;
        request.validate(
            now_unix_millis()?,
            &LaunchAuthorityValidationV1 {
                principal_id: LOCAL_PRINCIPAL,
                profile: &profile,
                executable: &executable,
            },
        )?;
        let canonical_root = validate_runtime_root(request.runtime_root())?;
        if canonical_root != request.runtime_root() {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let mut defaults = BuiltInDefaults::new(&canonical_root);
        defaults.http_bind = "127.0.0.1:0".to_owned();
        let config = ConfigurationSnapshot::from_defaults(&defaults);
        let keys = request.derive_keys_and_forget();

        let pending_first_activation = match request.activation_disposition() {
            ActivationDispositionV1::FirstActivation => {
                if Path::new(&config.db_path).exists() {
                    return Err(LaunchAuthorityError::UnexpectedExistingEventLog);
                }
                let pending = prepare_first_activation(&request, &canonical_root)?;
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
                commit.verify_exact(&request, &pending, &keys)?;
                request.validate_freshness(now_unix_millis()?)?;
                Some(pending)
            }
            ActivationDispositionV1::Existing(expected) => {
                preflight_existing(&config, expected, None)?;
                None
            }
            ActivationDispositionV1::ResumeFirstActivation(pending) => {
                verify_pending_request(&request, pending, &canonical_root)?;
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
        })
    }

    /// Completes storage bootstrap only after protected admission succeeded.
    pub fn bootstrap<F>(
        &mut self,
        mut now_unix_millis: F,
    ) -> Result<BootstrapOutcome, LaunchAuthorityError>
    where
        F: FnMut() -> Result<u64, LaunchAuthorityError>,
    {
        self.request.validate_freshness(now_unix_millis()?)?;
        let bootstrap_key = self.keys.bootstrap_key();
        let result = bootstrap_protected(
            &self.config,
            self.request.launch_authority_id(),
            *bootstrap_key,
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

    pub const fn request(&self) -> &ProtectedLaunchRequestV1 {
        &self.request
    }

    pub const fn keys(&self) -> &ProtectedActivationKeys {
        &self.keys
    }

    pub const fn config(&self) -> &ConfigurationSnapshot {
        &self.config
    }
}
