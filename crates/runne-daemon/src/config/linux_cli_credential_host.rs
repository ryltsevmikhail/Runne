/// Explicit owner-session CLI enrollment. This is not Desktop release qualification.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxCliCredentialHostConfig {
    pub cli_sha256: String,
    pub daemon_sha256: String,
    pub host_sha256: String,
}

impl LinuxCliCredentialHostConfig {
    fn validate(
        &self,
        mode: runne_api::ProviderActivationModeV1,
    ) -> Result<(), crate::error::DaemonError> {
        if !cfg!(target_os = "linux")
            || !matches!(
                mode,
                runne_api::ProviderActivationModeV1::DeterministicV1
                    | runne_api::ProviderActivationModeV1::DeepSeekResponsesTextV1
            )
            || [&self.cli_sha256, &self.daemon_sha256, &self.host_sha256]
                .iter()
                .any(|value| {
                    value.len() != 64
                        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                        || value.bytes().all(|byte| byte == b'0')
                })
        {
            return Err(crate::error::DaemonError::Config(
                "invalid Linux CLI credential host selection".into(),
            ));
        }
        Ok(())
    }
}
