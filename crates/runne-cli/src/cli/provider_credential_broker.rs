#[cfg(unix)]
#[path = "provider_credential_broker/bootstrap.rs"]
mod bootstrap;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "native daemon admission has not yet minted the writer claim authority"
    )
)]
#[path = "provider_credential_broker/claim.rs"]
mod claim;
#[path = "provider_credential_broker/effect.rs"]
mod effect;
#[path = "provider_credential_broker/secret.rs"]
mod secret;

#[cfg(all(test, unix))]
#[path = "provider_credential_broker/bootstrap_tests.rs"]
mod bootstrap_tests;
#[cfg(test)]
#[path = "provider_credential_broker/claim_tests.rs"]
mod claim_tests;
#[cfg(test)]
#[path = "provider_credential_broker/effect_tests.rs"]
mod effect_tests;
#[cfg(test)]
#[path = "provider_credential_broker/effect_test_support.rs"]
mod effect_test_support;

#[cfg(test)]
use secret::read_secret_line;

use runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1;

/// Fixed internal-only entry point for the credential writer broker.
///
/// This token intentionally carries no provider, ticket, path, or secret. The
/// real writer adapter will be enabled only after Task 11 supplies authenticated
/// inherited channel evidence; direct invocation stays closed in the meantime.
fn run_provider_credential_broker(mut arguments: VecDeque<OsString>) -> Result<String, CliError> {
    expect_token(&mut arguments, PROVIDER_CREDENTIAL_BROKER_MODE_V1)?;
    expect_end(&arguments)?;
    #[cfg(unix)]
    let _endpoint = bootstrap::receive_prepared_daemon_endpoint_from_stdin()?;
    Err(CliError::UnsupportedCredentialBackend)
}
