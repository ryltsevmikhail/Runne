#[path = "provider_credential_broker/claim.rs"]
mod claim;
#[cfg(target_os = "macos")]
#[path = "provider_credential_broker/channel.rs"]
mod channel;
#[path = "provider_credential_broker/effect.rs"]
mod effect;
#[path = "provider_credential_broker/pair.rs"]
mod pair;
#[path = "provider_credential_broker/run.rs"]
mod run;
#[path = "provider_credential_broker/secret.rs"]
mod secret;

#[cfg(test)]
#[path = "provider_credential_broker/claim_tests.rs"]
mod claim_tests;
#[cfg(test)]
#[path = "provider_credential_broker/channel_tests.rs"]
mod channel_tests;
#[cfg(test)]
#[path = "provider_credential_broker/effect_tests.rs"]
mod effect_tests;
#[cfg(all(test, target_os = "macos"))]
#[path = "provider_credential_broker/effect_service_migration_tests.rs"]
mod effect_service_migration_tests;
#[cfg(test)]
#[path = "provider_credential_broker/leakage_tests.rs"]
mod leakage_tests;
#[cfg(test)]
#[path = "provider_credential_broker/effect_test_support.rs"]
mod effect_test_support;
#[cfg(test)]
#[path = "provider_credential_broker/pair_tests.rs"]
mod pair_tests;
#[cfg(test)]
#[path = "provider_credential_broker/run_tests.rs"]
mod run_tests;

#[cfg(test)]
use secret::read_sealed_pair_envelope;

use runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1;

/// Fixed internal-only entry point for the credential writer broker.
///
/// This token intentionally carries no provider, ticket, path, or secret.
fn run_provider_credential_broker(mut arguments: VecDeque<OsString>) -> Result<(), CliError> {
    expect_token(&mut arguments, PROVIDER_CREDENTIAL_BROKER_MODE_V1)?;
    expect_end(&arguments)?;
    #[cfg(target_os = "macos")]
    {
        let secret = channel::InheritedSecretInputSlot::inspect()
            .map_err(|_| CliError::CredentialOperation)?;
        let handoff = runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1::receive_from_stdin()
            .map_err(|_| CliError::CredentialOperation)?;
        let pinned = handoff
            .observe_current_pinned_writer_session()
            .map_err(|_| CliError::CredentialOperation)?;
        run::run_authenticated_writer(pinned, secret)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CliError::UnsupportedCredentialBackend)
    }
}
