//! Reader-only selection for the separate standalone Linux credential host.
pub mod policy;
use policy::ImagePolicy;

pub(crate) fn execution_access_policy()
-> Result<Option<runne_secure_store::ProviderCredentialAccessPolicy>, crate::error::DaemonError> {
    let config = crate::config::load_external_config()?;
    if config.linux_cli_credential_host.is_none() {
        return Ok(None);
    }
    ImagePolicy::load(&config)
        .and_then(|policy| policy.access())
        .map(Some)
        .map_err(|message| crate::error::DaemonError::Bootstrap(message.into()))
}
