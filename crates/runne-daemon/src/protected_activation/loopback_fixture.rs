//! Internal process fixture dependencies for protected OpenAI qualification.

mod ack_failure_store;
mod bootstrap;
mod fixed_response;
mod request_validation;
mod t1_scan_receipt;
mod tls_sse_server;

use std::path::Path;
use std::sync::Arc;

use crate::application::workspace_internal::ProtectedProviderDependencyCapsule;
#[cfg(not(test))]
use crate::canonical_provider::ProviderEffectFactory;
use crate::canonical_provider::{RuntimeStoreDecorator, openai_effect_adapter};
use crate::error::DaemonError;
use ack_failure_store::AckFailureStore;
use bootstrap::RetainedFixtureKeyring;
use tls_sse_server::TlsSseServer;
#[cfg(not(test))]
use zeroize::Zeroizing;

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
        runne_daemon_openai_effect::loopback_fixture_request_authenticator(),
        request_validation::FixtureRequestKind::Pinned,
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
    let (effect, _) = runne_daemon_openai_effect::effect_from_loopback_fixture(client)
        .map_err(|_| DaemonError::Bootstrap("fixture effect".into()))?;
    let effect = openai_effect_adapter(effect);
    Ok((
        ProtectedProviderDependencyCapsule::from_loopback_fixture(
            effect,
            keyring,
            acknowledgement_failure_decorator(),
            #[cfg(test)]
            Arc::new(crate::canonical_provider::credential_versions::fixture_native),
        ),
        server,
    ))
}

/// Clean Linux T1 provider fixture: real TLS/OpenAI adapter with ordinary
/// durable stores and no acknowledgement fault decorator.
#[cfg(all(target_os = "linux", feature = "test-support", not(test)))]
pub(crate) async fn t1_dependencies(
    runtime_root: &Path,
) -> Result<(ProtectedProviderDependencyCapsule, TlsSseServer), DaemonError> {
    let server = TlsSseServer::start_t1(
        runtime_root,
        runne_daemon_openai_effect::loopback_fixture_request_authenticator(),
        std::env::var_os("RUNNE_TEST_T1_TRUST_TRANSPORT_LOSS").as_deref()
            == Some(std::ffi::OsStr::new("1")),
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
    let (effect, _) = runne_daemon_openai_effect::effect_from_loopback_fixture(client)
        .map_err(|_| DaemonError::Bootstrap("fixture effect".into()))?;
    Ok((
        ProtectedProviderDependencyCapsule::from_loopback_fixture(
            openai_effect_adapter(effect),
            keyring,
            passthrough_decorator(),
        ),
        server,
    ))
}

#[cfg(not(test))]
pub(crate) async fn service_dependencies(
    runtime_root: &Path,
) -> Result<(ProtectedProviderDependencyCapsule, TlsSseServer), DaemonError> {
    let fixture_root = runtime_root
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| DaemonError::Bootstrap("fixture root".into()))?;
    let authenticator =
        runne_daemon_openai_effect::loopback_fixture_request_authenticator_for_material(
            service_fixture_secret(fixture_root),
        );
    let server = TlsSseServer::start(
        runtime_root,
        authenticator,
        request_validation::FixtureRequestKind::ServicePointOfUse,
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
    let adapter_factory: Arc<ProviderEffectFactory> =
        Arc::new(move |materializer, _budget_store| {
            runne_daemon_openai_effect::effect_from_loopback_fixture_with_materializer(
                client.clone(),
                materializer,
            )
            .map(openai_effect_adapter)
            .map_err(|_| DaemonError::Bootstrap("fixture effect".into()))
        });
    Ok((
        ProtectedProviderDependencyCapsule::from_service_loopback_fixture(
            adapter_factory,
            keyring,
            passthrough_decorator(),
        ),
        server,
    ))
}

#[cfg(not(test))]
fn passthrough_decorator() -> Arc<RuntimeStoreDecorator> {
    Arc::new(|store, _| {
        let execution: Arc<dyn runne_application::provider::ProviderExecutionStore> = store.clone();
        let terminal: Arc<dyn runne_runtime::provider_execution::ProviderTerminalPersistence> =
            store;
        (execution, terminal)
    })
}

#[cfg(not(test))]
fn service_fixture_secret(root: &Path) -> Zeroizing<Vec<u8>> {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::ffi::OsStrExt as _;

    let mut digest = Sha256::new();
    digest.update(b"runne-slice-e-secret-canary-v1\0");
    digest.update(root.as_os_str().as_bytes());
    Zeroizing::new(format!("sk-slice-e-{}", hex::encode(digest.finalize())).into_bytes())
}

fn acknowledgement_failure_decorator() -> Arc<RuntimeStoreDecorator> {
    Arc::new(|store, runtime_generation| {
        let decorated = Arc::new(AckFailureStore::new(store, runtime_generation));
        (decorated.clone(), decorated)
    })
}
