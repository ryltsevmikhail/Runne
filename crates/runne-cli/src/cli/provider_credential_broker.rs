#[cfg(any(test, target_os = "macos"))]
#[path = "provider_credential_broker/claim.rs"]
mod claim;
#[cfg(target_os = "macos")]
#[path = "provider_credential_broker/channel.rs"]
mod channel;
#[cfg(any(test, target_os = "macos"))]
#[path = "provider_credential_broker/effect.rs"]
mod effect;
#[cfg(any(test, target_os = "macos"))]
#[path = "provider_credential_broker/pair.rs"]
mod pair;
#[cfg(any(test, target_os = "macos"))]
#[path = "provider_credential_broker/run.rs"]
mod run;
#[cfg(any(test, target_os = "macos"))]
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
#[cfg(test)]
#[cfg(target_os = "macos")]
#[path = "provider_credential_broker/effect_service_migration_tests.rs"]
mod effect_service_migration_tests;
#[cfg(test)]
#[path = "provider_credential_broker/leakage_tests.rs"]
mod leakage_tests;
#[cfg(test)]
#[path = "provider_credential_broker/effect_test_support.rs"]
mod effect_test_support;
#[cfg(test)]
#[path = "provider_credential_broker/legacy_cleanup_test_support.rs"]
mod legacy_cleanup_test_support;
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
        #[cfg(feature = "local-native-enrollment-test")]
        let report = |stage: &'static str| {
            eprintln!("writer-stage={stage}");
        };
        #[cfg(feature = "local-native-enrollment-test")]
        let report_failed = |stage: &'static str| {
            eprintln!("writer-stage-failed={stage}");
        };
        #[cfg(not(feature = "local-native-enrollment-test"))]
        let report = |stage: &'static str| {
            let _ = stage;
        };
        #[cfg(not(feature = "local-native-enrollment-test"))]
        let report_failed = |stage: &'static str| {
            let _ = stage;
        };
        report("secret-inspect");
        let secret = channel::InheritedSecretInputSlot::inspect()
            .inspect_err(|_| report_failed("secret-inspect"))
            .map_err(|_| CliError::CredentialOperation)?;
        report("endpoint-receive");
        let handoff = runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1::receive_from_stdin()
            .inspect_err(|_| report_failed("endpoint-receive"))
            .map_err(|_| CliError::CredentialOperation)?;
        report("session-observe");
        let pinned = handoff
            .observe_current_pinned_writer_session()
            .inspect_err(|_| report_failed("session-observe"))
            .map_err(|_| CliError::CredentialOperation)?;
        report("authenticated-run");
        run::run_authenticated_writer(pinned, secret).inspect_err(|_| report_failed("authenticated-run"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CliError::UnsupportedCredentialBackend)
    }
}
