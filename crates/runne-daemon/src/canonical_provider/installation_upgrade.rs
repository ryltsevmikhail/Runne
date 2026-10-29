use super::*;
use crate::config::ConfigurationSnapshot;

pub(crate) fn upgrade_cli_installation(
    before: &ConfigurationSnapshot,
    after: &ConfigurationSnapshot,
    bootstrap: crate::bootstrap::BootstrapOutcome,
) -> Result<(), DaemonError> {
    after.validate_cli_upgrade_from(before)?;
    let profile = runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .map_err(|_| DaemonError::Bootstrap("upgrade profile unavailable".into()))?;
    let profile = SharedTextProviderProfile::new(Arc::new(profile));
    let config = |snapshot| {
        runtime_launch::configuration(
            bootstrap.authority_id,
            bootstrap.launch_generation,
            &DaemonActivationProvenance::for_cli_upgrade(snapshot, bootstrap.authority_id),
            &profile,
            "provider.deepseek.responses.text",
        )
    };
    let previous = config(before);
    let next = config(after);
    let store =
        SqliteProviderExecutionStore::open_with_connection(&after.db_path, bootstrap.db_conn)
            .map_err(|_| DaemonError::Bootstrap("upgrade store unavailable".into()))?;
    store
        .upgrade_external_installation(&previous, &next)
        .map_err(|_| {
            DaemonError::Bootstrap(
                "installation upgrade rejected; preserve both installations for recovery".into(),
            )
        })?;
    drop(bootstrap.locks);
    Ok(())
}
