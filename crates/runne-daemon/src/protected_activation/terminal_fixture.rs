//! Synthetic coding-agent composition, compiled only for test-support.
use super::loopback_fixture::RetainedFixtureKeyring;
use crate::{
    application::workspace_internal::ProtectedProviderDependencyCapsule, error::DaemonError,
};
use std::{path::Path, sync::Arc};
#[path = "terminal_fixture/responses.rs"]
mod responses;
#[path = "terminal_fixture/server.rs"]
pub(crate) mod server;

pub(crate) async fn dependencies(
    root: &Path,
) -> Result<(ProtectedProviderDependencyCapsule, server::Server), DaemonError> {
    let server = server::Server::start(root).await.map_err(|_| error())?;
    let profile = runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .map_err(|_| error())?;
    let policy = runne_provider_deepseek::DeepSeekTransportPolicy::for_profile(&profile)
        .map_err(|_| error())?;
    let client = runne_daemon_deepseek_effect::loopback_fixture_client(
        &policy,
        server.address,
        &server.certificate,
    )
    .map_err(|_| error())?;
    let (effect, auth) = runne_daemon_deepseek_effect::tool_effect_from_loopback_fixture(client)
        .map_err(|_| error())?;
    server.set_auth(auth)?;
    let keyring = Arc::new(RetainedFixtureKeyring::open(root).map_err(|_| error())?);
    Ok((
        ProtectedProviderDependencyCapsule::from_loopback_fixture(
            crate::canonical_provider::deepseek_effect_adapter(effect),
            keyring,
            Arc::new(|store, _| {
                let execution: Arc<dyn runne_application::provider::ProviderExecutionStore> =
                    store.clone();
                let terminal: Arc<
                    dyn runne_runtime::provider_execution::ProviderTerminalPersistence,
                > = store;
                (execution, terminal)
            }),
            #[cfg(test)]
            Arc::new(crate::canonical_provider::credential_versions::fixture_native),
        ),
        server,
    ))
}
fn error() -> DaemonError {
    DaemonError::Bootstrap("terminal synthetic fixture unavailable".into())
}
