/// Fixed internal-only entry point for the credential writer broker.
///
/// This token intentionally carries no provider, ticket, path, or secret. The
/// real writer adapter will be enabled only after Task 11 supplies authenticated
/// inherited channel evidence; direct invocation stays closed in the meantime.
#[path = "provider_credential_broker/secret.rs"]
mod secret;

#[cfg(test)]
use secret::{BrokerClaimed, read_secret_after_claim};

use runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1;

fn run_provider_credential_broker(
    mut arguments: VecDeque<OsString>,
) -> Result<String, CliError> {
    expect_token(&mut arguments, PROVIDER_CREDENTIAL_BROKER_MODE_V1)?;
    expect_end(&arguments)?;
    Err(CliError::UnsupportedCredentialBackend)
}
