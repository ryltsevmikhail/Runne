//! Non-shipped loopback-only fixture infrastructure.

mod ack_failure_store;
mod bootstrap;
mod fixed_response;
#[cfg(unix)]
mod protected_process;
mod request_validation;
mod tls_sse_server;

pub use ack_failure_store::AckFailureStore;
pub use bootstrap::{FixtureJournalKey, RetainedFixtureKeyring, prepare_runtime_root};
#[cfg(unix)]
pub use protected_process::run_protected_fixture;
pub use tls_sse_server::{TlsSseServer, loopback_client, request_count};

/// Rejects the Unix inherited-channel fixture on unsupported platforms.
#[cfg(not(unix))]
#[allow(clippy::result_unit_err)]
pub fn run_protected_fixture() -> Result<(), ()> {
    Err(())
}

#[doc(hidden)]
pub fn loopback_request_authenticator() -> runne_daemon_openai_effect::FixtureRequestAuthenticator {
    runne_daemon_openai_effect::loopback_fixture_request_authenticator()
}

/// Builds the fixture-only terminal acknowledgement fault over the daemon-opened store.
#[allow(clippy::type_complexity)]
pub fn ack_failure_decorator() -> std::sync::Arc<
    dyn Fn(
            std::sync::Arc<runne_store::provider::SqliteProviderExecutionStore>,
            u64,
        ) -> (
            std::sync::Arc<dyn runne_application::provider::ProviderExecutionStore>,
            std::sync::Arc<dyn runne_runtime::provider_execution::ProviderTerminalPersistence>,
        ) + Send
        + Sync,
> {
    std::sync::Arc::new(|store, runtime_generation| {
        let decorated = std::sync::Arc::new(AckFailureStore::new(store, runtime_generation));
        let execution: std::sync::Arc<dyn runne_application::provider::ProviderExecutionStore> =
            decorated.clone();
        let terminal: std::sync::Arc<
            dyn runne_runtime::provider_execution::ProviderTerminalPersistence,
        > = decorated;
        (execution, terminal)
    })
}

/// Binds a fixture-owned loopback client to the sealed sender object.
#[allow(clippy::result_unit_err)]
pub fn loopback_effect(
    client: reqwest::Client,
) -> Result<
    (
        std::sync::Arc<dyn runne_daemon_openai_effect::OpenAiEffect>,
        runne_daemon_openai_effect::FixtureRequestAuthenticator,
    ),
    (),
> {
    runne_daemon_openai_effect::effect_from_loopback_fixture(client).map_err(|_| ())
}
