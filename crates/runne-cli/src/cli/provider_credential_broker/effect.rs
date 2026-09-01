//! Non-Pair native effect dispatch after an accepted writer claim.

use runne_provider::{CredentialBrokerFrame, CredentialOperationAction};
use runne_secure_store::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput,
};

use super::{CliError, claim::AuthorizedWriterControl, pair::AuthorizedPairWriterControl};

/// Executes a sealed Pair effect only after source decoding and claim acceptance.
pub fn execute_pair_effect(authority: AuthorizedPairWriterControl) -> Result<(), CliError> {
    let super::pair::PairEffectParts {
        mut control,
        writer,
        authorization,
        command,
        binding,
        channel,
        pending,
        envelope,
    } = authority.into_effect_parts();
    if command.action() != CredentialOperationAction::Pair {
        return Err(CliError::CredentialOperation);
    }
    let input =
        BrokeredCreateInput::new(command.clone(), binding, channel).map_err(|_| CliError::CredentialOperation)?;
    let result = writer
        .create_sealed_exact(authorization, input, pending, envelope)
        .map_err(|_| CliError::CredentialOperation);
    control.write_frame(CredentialBrokerFrame::NativeEffectObserved {
        operation_id: command.operation_id(),
        binding,
    })?;
    result
}

/// Executes a closed non-Pair effect only after native endpoint admission.
pub fn execute_non_pair_effect(authority: AuthorizedWriterControl) -> Result<(), CliError> {
    let (mut control, writer, authorization, command, binding, channel) =
        authority.into_effect_parts();
    let result = match command.action() {
        CredentialOperationAction::Revoke | CredentialOperationAction::RetiredVersionCleanup => {
            let input = BrokeredDeleteInput::new(command.clone(), binding, channel)
                .map_err(|_| CliError::CredentialOperation)?;
            writer
                .delete_exact(authorization, input)
                .map(|_| ())
                .map_err(|_| CliError::CredentialOperation)
        }
        CredentialOperationAction::MigrateLegacy => {
            let input = BrokeredMigrateLegacyInput::new(command.clone(), binding, channel)
                .map_err(|_| CliError::CredentialOperation)?;
            writer
                .import_legacy_exact(authorization, input)
                .map_err(|_| CliError::CredentialOperation)
        }
        CredentialOperationAction::LegacySourceCleanup => {
            let input = BrokeredLegacySourceDeleteInput::new(command.clone(), binding, channel)
                .map_err(|_| CliError::CredentialOperation)?;
            writer
                .delete_legacy_source_exact(authorization, input)
                .map_err(|_| CliError::CredentialOperation)
        }
        CredentialOperationAction::Pair
        | CredentialOperationAction::WriterIdentityMigrationEffect
        | CredentialOperationAction::WriterIdentityMigrationVerify => {
            return Err(CliError::CredentialOperation);
        }
    };
    control.write_frame(CredentialBrokerFrame::NativeEffectObserved {
        operation_id: command.operation_id(),
        binding,
    })?;
    result
}
