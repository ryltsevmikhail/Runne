//! Native/service effect dispatch after an accepted writer claim.

use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialOperationAction,
};
use runne_secure_store::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, NativeProviderCredentialEffectRoute,
};

use super::{
    CliError,
    claim::{AuthorizedWriterControl, NonPairWriterEffectKind},
    pair::AuthorizedPairWriterControl,
};

#[cfg(target_os = "macos")]
#[path = "effect/service.rs"]
mod service;
#[cfg(target_os = "macos")]
use service::{consume_service_control, consume_service_legacy_migration, consume_service_pair};
#[cfg(all(
    any(
        feature = "local-native-enrollment-test",
        feature = "linux-native-enrollment-qualification"
    ),
    target_os = "linux"
))]
#[path = "effect/linux_post_delete_test.rs"]
mod linux_post_delete_test;
#[cfg(all(test, target_os = "macos"))]
pub use service::{
    consume_service_control_with_port, consume_service_legacy_migration_with_port,
    consume_service_pair_with_port,
};

fn write_native_effect_observed(
    control: &mut dyn super::claim::BrokerControl,
    command: &CredentialBrokerCommand,
    binding: CredentialBindingDigest,
) -> Result<(), CliError> {
    control.write_frame(CredentialBrokerFrame::NativeEffectObserved {
        operation_id: command.operation_id(),
        binding,
    })
}

/// Executes a sealed Pair effect only after source decoding and claim acceptance.
pub fn execute_pair_effect(authority: AuthorizedPairWriterControl) -> Result<(), CliError> {
    let super::pair::PairEffectParts {
        mut control,
        effect_route,
        authorization,
        command,
        binding,
        channel,
        pending,
        envelope,
        service_handoff,
    } = authority.into_effect_parts();
    #[cfg(not(target_os = "macos"))]
    drop(service_handoff);
    if command.action() != CredentialOperationAction::Pair {
        return Err(CliError::CredentialOperation);
    }
    let result = match effect_route {
        NativeProviderCredentialEffectRoute::Legacy(writer) => {
            let input = BrokeredCreateInput::new(command.clone(), binding, channel)
                .map_err(|_| CliError::CredentialOperation)?;
            writer
                .create_sealed_exact(authorization, input, pending, envelope)
                .map_err(|_| CliError::CredentialOperation)
        }
        #[cfg(target_os = "macos")]
        NativeProviderCredentialEffectRoute::CredentialService {
            effects,
            configuration,
            legacy: _,
        } => consume_service_pair(
            &effects,
            configuration,
            service_handoff.ok_or(CliError::CredentialOperation)?,
            authorization,
            &channel,
            binding,
            pending,
            envelope,
        ),
    };
    result?;
    write_native_effect_observed(control.as_mut(), &command, binding)?;
    Ok(())
}

#[cfg(all(feature = "local-native-enrollment-test", target_os = "macos"))]
fn pause_after_legacy_source_delete(
    result: &Result<(), CliError>,
    action: CredentialOperationAction,
) -> Result<(), CliError> {
    if result.is_ok()
        && legacy_source_cleanup
        && runne_api::test_support::local_native_enrollment_case().is_some_and(
            runne_api::test_support::LocalNativeEnrollmentCase::crashes_after_legacy_source_delete,
        )
    {
        wait_for_legacy_delete_release()?;
        // This is the exact retained writer process. It runs after the
        // authenticated native deletion and before the durable observation frame.
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGKILL)
            .map_err(|_| CliError::CredentialOperation)?;
    }
    Ok(())
}

#[cfg(all(feature = "local-native-enrollment-test", target_os = "macos"))]
fn wait_for_legacy_delete_release() -> Result<(), CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::{Duration, Instant};

    let root = std::fs::canonicalize(
        std::env::var_os("RUNNE_SLICE_E_FIXTURE_ROOT").ok_or(CliError::CredentialOperation)?,
    )
    .map_err(|_| CliError::CredentialOperation)?;
    let marker = root.join(format!("{name}.marker"));
    let release = root.join(format!("{name}.release"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .map_err(|_| CliError::CredentialOperation)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| CliError::CredentialOperation)?;
    file.write_all(b"post-delete")
        .and_then(|()| file.sync_all())
        .map_err(|_| CliError::CredentialOperation)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if release.is_file() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(CliError::CredentialOperation)
}

#[cfg(all(
    any(
        feature = "local-native-enrollment-test",
        feature = "linux-native-enrollment-qualification"
    ),
    target_os = "linux"
))]
fn pause_after_linux_revoke(
    result: &Result<(), CliError>,
    action: CredentialOperationAction,
) -> Result<(), CliError> {
    if action == CredentialOperationAction::Revoke {
        linux_post_delete_test::kill_after_delete(result)?;
    }
    Ok(())
}

/// Executes a closed non-Pair effect only after native endpoint admission.
pub fn execute_non_pair_effect(authority: AuthorizedWriterControl) -> Result<(), CliError> {
    let super::claim::NonPairEffectParts {
        mut control,
        effect_route,
        authorization,
        command,
        binding,
        channel,
        effect_kind,
        service_handoff,
    } = authority.into_effect_parts();
    #[cfg(not(target_os = "macos"))]
    drop(service_handoff);
    #[cfg(all(feature = "local-native-enrollment-test", target_os = "macos"))]
    let legacy_source_cleanup = matches!(&effect_kind, NonPairWriterEffectKind::DeleteLegacySource);
    let result = match (effect_route, effect_kind) {
        (NativeProviderCredentialEffectRoute::Legacy(writer), effect_kind) => match effect_kind {
            NonPairWriterEffectKind::Delete => {
                let input = BrokeredDeleteInput::new(command.clone(), binding, channel)
                    .map_err(|_| CliError::CredentialOperation)?;
                writer
                    .delete_exact(authorization, input)
                    .map(|_| ())
                    .map_err(|_| CliError::CredentialOperation)
            }
            NonPairWriterEffectKind::ImportLegacy => {
                let input = BrokeredMigrateLegacyInput::new(command.clone(), binding, channel)
                    .map_err(|_| CliError::CredentialOperation)?;
                writer
                    .import_legacy_exact(authorization, input)
                    .map_err(|_| CliError::CredentialOperation)
            }
            NonPairWriterEffectKind::DeleteLegacySource => {
                let input = BrokeredLegacySourceDeleteInput::new(command.clone(), binding, channel)
                    .map_err(|_| CliError::CredentialOperation)?;
                writer
                    .delete_legacy_source_exact(authorization, input)
                    .map_err(|_| CliError::CredentialOperation)
            }
        },
        #[cfg(target_os = "macos")]
        (
            NativeProviderCredentialEffectRoute::CredentialService {
                effects,
                configuration,
                legacy: _,
            },
            NonPairWriterEffectKind::Delete,
        ) => consume_service_control(
            &effects,
            configuration,
            service_handoff.ok_or(CliError::CredentialOperation)?,
            authorization,
            &channel,
            binding,
        ),
        #[cfg(target_os = "macos")]
        (
            NativeProviderCredentialEffectRoute::CredentialService {
                effects,
                configuration,
                legacy,
            },
            NonPairWriterEffectKind::ImportLegacy,
        ) => consume_service_legacy_migration(
            &effects,
            configuration,
            legacy.as_ref(),
            service_handoff.ok_or(CliError::CredentialOperation)?,
            authorization,
            &channel,
            binding,
        ),
        #[cfg(target_os = "macos")]
        (
            NativeProviderCredentialEffectRoute::CredentialService {
                effects,
                configuration: _,
                legacy,
            },
            NonPairWriterEffectKind::DeleteLegacySource,
        ) => {
            let input = BrokeredLegacySourceDeleteInput::new(command.clone(), binding, channel)
                .map_err(|_| CliError::CredentialOperation)?;
            legacy
                .delete_exact(&effects, authorization, input)
                .map_err(|_| CliError::CredentialOperation)
        }
    };
    #[cfg(all(
        any(
            feature = "local-native-enrollment-test",
            feature = "linux-native-enrollment-qualification"
        ),
        target_os = "linux"
    ))]
    pause_after_linux_revoke(&result, command.action())?;
    #[cfg(all(feature = "local-native-enrollment-test", target_os = "macos"))]
    pause_after_legacy_source_delete(&result, legacy_source_cleanup)?;
    result?;
    write_native_effect_observed(control.as_mut(), &command, binding)
}
