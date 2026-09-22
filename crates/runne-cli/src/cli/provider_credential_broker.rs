#[cfg(any(test, unix))]
#[path = "provider_credential_broker/claim.rs"]
mod claim;
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[path = "provider_credential_broker/channel.rs"]
mod channel;
#[cfg(any(test, unix))]
#[path = "provider_credential_broker/effect.rs"]
mod effect;
#[cfg(any(test, unix))]
#[path = "provider_credential_broker/pair.rs"]
mod pair;
#[cfg(any(test, unix))]
#[path = "provider_credential_broker/run.rs"]
mod run;
#[cfg(any(test, unix))]
#[path = "provider_credential_broker/secret.rs"]
mod secret;

#[cfg(target_os = "linux")]
#[path = "provider_credential_broker/writer_fd_sweep.rs"]
mod writer_fd_sweep;

#[cfg(target_os = "linux")]
#[path = "provider_credential_broker/writer_handshake.rs"]
mod writer_handshake;





#[cfg(feature = "local-native-enrollment-test")]
#[path = "provider_credential_broker/writer_stage_live.rs"]
mod writer_stage;
#[cfg(not(feature = "local-native-enrollment-test"))]
#[path = "provider_credential_broker/writer_stage_silent.rs"]
mod writer_stage;

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
        writer_stage::secret_inspect();
        let secret = channel::InheritedSecretInputSlot::inspect()
            .inspect_err(|_| writer_stage::secret_inspect_failed())
            .map_err(|_| CliError::CredentialOperation)?;
        writer_stage::endpoint_receive();
        let handoff = runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1::receive_from_stdin()
            .inspect_err(|_| writer_stage::endpoint_receive_failed())
            .map_err(|_| CliError::CredentialOperation)?;
        writer_stage::session_observe();
        let pinned = handoff
            .observe_current_pinned_writer_session()
            .inspect_err(|_| writer_stage::session_observe_failed())
            .map_err(|_| CliError::CredentialOperation)?;
        writer_stage::authenticated_run();
        run::run_authenticated_writer(pinned, secret)
            .inspect_err(|_| writer_stage::authenticated_run_failed())
    }
    #[cfg(target_os = "linux")]
    {
        // Validate the pipe shape without reading any secret, then close all
        // other inherited descriptors before authenticating or claiming.
        let secret = channel::InheritedSecretInputSlot::inspect()?;
        let retained = secret.validated_descriptor_for_sweep()?;
        writer_fd_sweep::close_inherited_descriptors_except(
            writer_fd_sweep::enumerate_proc_fds,
            retained,
        )
        .map_err(|_| CliError::CredentialOperation)?;
        writer_handshake::respond_startup_from_stdout(secret)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(CliError::UnsupportedCredentialBackend)
    }
}
