/// Fixed internal-only entry point for the credential writer broker.
///
/// This token intentionally carries no provider, ticket, path, or secret. The
/// real writer adapter will be enabled only after Task 11 supplies authenticated
/// inherited channel evidence; direct invocation stays closed in the meantime.
const PROVIDER_CREDENTIAL_BROKER_MODE: &str = "__provider-credential-broker-v1";

fn run_provider_credential_broker(
    mut arguments: VecDeque<OsString>,
) -> Result<String, CliError> {
    expect_token(&mut arguments, PROVIDER_CREDENTIAL_BROKER_MODE)?;
    expect_end(&arguments)?;
    Err(CliError::UnsupportedCredentialBackend)
}
