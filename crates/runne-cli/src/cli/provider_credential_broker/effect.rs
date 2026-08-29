//! Non-Pair native effect dispatch after an accepted writer claim.

use runne_provider::{CredentialBrokerFrame, CredentialOperationAction};
use runne_secure_store::{
    BrokeredDeleteInput, BrokeredLegacySourceDeleteInput, BrokeredMigrateLegacyInput,
};

use super::{CliError, claim::AuthorizedWriterControl};

/// Executes a closed non-Pair effect only after native endpoint admission.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "native daemon admission has not yet reached the writer effect executor"
    )
)]
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
