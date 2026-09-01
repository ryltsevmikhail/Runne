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
#[path = "provider_credential_broker/pair.rs"]
mod pair;
#[path = "provider_credential_broker/secret.rs"]
mod secret;

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
#[path = "provider_credential_broker/pair_tests.rs"]
mod pair_tests;

#[cfg(test)]
use secret::read_sealed_pair_envelope;

use runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1;

/// Fixed internal-only entry point for the credential writer broker.
///
/// This token intentionally carries no provider, ticket, path, or secret. The
/// real writer adapter will be enabled only after Task 11 supplies authenticated
/// inherited channel evidence; direct invocation stays closed in the meantime.
fn run_provider_credential_broker(mut arguments: VecDeque<OsString>) -> Result<String, CliError> {
    expect_token(&mut arguments, PROVIDER_CREDENTIAL_BROKER_MODE_V1)?;
    expect_end(&arguments)?;
    #[cfg(target_os = "macos")]
    {
        let handoff = runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1::receive_from_stdin()
            .map_err(|_| CliError::CredentialOperation)?;
        let _pinned = handoff
            .observe_current_pinned_writer_session()
            .map_err(|_| CliError::CredentialOperation)?;
        Err(CliError::UnsupportedCredentialBackend)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CliError::UnsupportedCredentialBackend)
    }
}
