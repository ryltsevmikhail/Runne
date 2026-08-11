//! Internal process fixture dependencies for protected OpenAI qualification.

mod ack_failure_store;
mod bootstrap;
mod fixed_response;
mod request_validation;
mod tls_sse_server;

use std::path::Path;
use std::sync::Arc;

use crate::application::workspace_internal::ProtectedProviderDependencyCapsule;
use crate::canonical_provider::RuntimeStoreDecorator;
use crate::error::DaemonError;
use ack_failure_store::AckFailureStore;
use bootstrap::RetainedFixtureKeyring;
use tls_sse_server::TlsSseServer;

pub(crate) fn run_inherited_channel() -> Result<(), DaemonError> {
    let channel = super::ProtectedActivationChannel::from_inherited_stdin()
        .map_err(|_| DaemonError::Bootstrap("fixture channel".into()))?
        .ok_or_else(|| DaemonError::Bootstrap("fixture channel".into()))?;
    super::host::run_verified_protected_channel_with_fixture(channel, |runtime_root| {
        let runtime_root = runtime_root.to_path_buf();
        async move { dependencies(&runtime_root).await }
    })
}

pub(crate) async fn dependencies(
    runtime_root: &Path,
) -> Result<(ProtectedProviderDependencyCapsule, TlsSseServer), DaemonError> {
    let server = TlsSseServer::start(
        runtime_root,
        gocode_daemon_openai_effect::loopback_fixture_request_authenticator(),
    )
    .await
    .map_err(|_| DaemonError::Bootstrap("fixture server".into()))?;
    let keyring = Arc::new(
        RetainedFixtureKeyring::open(runtime_root)
            .map_err(|_| DaemonError::Bootstrap("fixture keyring".into()))?,
    );
    let client = server
        .client()
        .map_err(|_| DaemonError::Bootstrap("fixture client".into()))?;
    let (effect, _) = gocode_daemon_openai_effect::effect_from_loopback_fixture(client)
        .map_err(|_| DaemonError::Bootstrap("fixture effect".into()))?;
    Ok((
        ProtectedProviderDependencyCapsule::from_loopback_fixture(
            effect,
            keyring,
            acknowledgement_failure_decorator(),
        ),
        server,
    ))
}

fn acknowledgement_failure_decorator() -> Arc<RuntimeStoreDecorator> {
    Arc::new(|store, runtime_generation| {
        let decorated = Arc::new(AckFailureStore::new(store, runtime_generation));
        (decorated.clone(), decorated)
    })
}
