//! Native/service effect dispatch after an accepted writer claim.

use runne_provider::{CredentialBrokerFrame, CredentialOperationAction};
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
use service::{
    consume_service_control, consume_service_legacy_migration, consume_service_pair,
};
#[cfg(all(test, target_os = "macos"))]
pub use service::{
    consume_service_control_with_port, consume_service_legacy_migration_with_port,
    consume_service_pair_with_port,
};

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
    control.write_frame(CredentialBrokerFrame::NativeEffectObserved {
        operation_id: command.operation_id(),
        binding,
    })?;
    result
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
    control.write_frame(CredentialBrokerFrame::NativeEffectObserved {
        operation_id: command.operation_id(),
        binding,
    })?;
    result
}
