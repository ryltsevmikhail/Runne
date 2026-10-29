//! Provider binding transition invoked only by the verified offline owner ceremony.
use super::*;
use crate::config::ConfigurationSnapshot;

pub(crate) fn adopt_terminal_provider(
    config: &ConfigurationSnapshot,
    authority: [u8; 16],
    generation: u64,
    connection: runne_store::schema::ManagedConnection,
) -> Result<(), DaemonError> {
    let profile = runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .map_err(|_| DaemonError::Bootstrap("adoption profile unavailable".into()))?;
    let profile = SharedTextProviderProfile::new(Arc::new(profile));
    let before = runtime_launch::configuration(
        authority,
        generation,
        &DaemonActivationProvenance::for_cli_upgrade(config, authority),
        &profile,
        "provider.deepseek.responses.text",
    );
    let after = runtime_launch::configuration(
        authority,
        generation,
        &DaemonActivationProvenance::for_terminal_adoption(
            config.provider_activation.binding(),
            authority,
        ),
        &profile,
        "provider.deepseek.responses.text",
    );
    let store = SqliteProviderExecutionStore::open_with_connection(&config.db_path, connection)
        .map_err(|_| DaemonError::Bootstrap("adoption store unavailable".into()))?;
    store
        .adopt_external_installation(&before, &after)
        .map_err(|_| {
            DaemonError::Bootstrap("adoption requires exact idle unrevoked authority".into())
        })
}

#[cfg(test)]
#[path = "terminal_adoption_native_tests.rs"]
mod native_tests;
