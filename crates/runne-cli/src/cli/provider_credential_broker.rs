/// Fixed internal-only entry point for the credential writer broker.
///
/// This token intentionally carries no provider, ticket, path, or secret. The
/// real writer adapter will be enabled only after Task 11 supplies authenticated
/// inherited channel evidence; direct invocation stays closed in the meantime.
#[path = "provider_credential_broker/secret.rs"]
mod secret;
#[cfg(unix)]
#[path = "provider_credential_broker/bootstrap.rs"]
mod bootstrap;

#[cfg(all(test, unix))]
#[path = "provider_credential_broker/bootstrap_tests.rs"]
mod bootstrap_tests;

#[cfg(test)]
use secret::{BrokerClaimed, read_secret_after_claim};

use runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1;

fn run_provider_credential_broker(
    mut arguments: VecDeque<OsString>,
) -> Result<String, CliError> {
    expect_token(&mut arguments, PROVIDER_CREDENTIAL_BROKER_MODE_V1)?;
    expect_end(&arguments)?;
    #[cfg(unix)]
    let _endpoint = bootstrap::receive_prepared_daemon_endpoint_from_stdin()?;
    Err(CliError::UnsupportedCredentialBackend)
}
