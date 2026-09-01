use runne_provider::{CredentialOperationAction, CredentialSecretInputPresence};

use super::{accepted, binding, claim_for_test, endpoint, issue};

#[test]
fn secret_slot_presence_must_match_the_retained_command_before_claim() {
    for (action, presence) in std::iter::once((
        CredentialOperationAction::Pair,
        CredentialSecretInputPresence::Absent,
    ))
    .chain(
        [
            CredentialOperationAction::Revoke,
            CredentialOperationAction::RetiredVersionCleanup,
            CredentialOperationAction::MigrateLegacy,
            CredentialOperationAction::LegacySourceCleanup,
            CredentialOperationAction::WriterIdentityMigrationEffect,
            CredentialOperationAction::WriterIdentityMigrationVerify,
        ]
        .map(|action| (action, CredentialSecretInputPresence::Present)),
    ) {
        let command = super::super::effect_test_support::command(action);
        let (endpoint, written) = endpoint(
            issue(command.clone(), binding(), [11; 32]),
            Some(accepted(&command)),
        );

        assert!(claim_for_test(endpoint, presence).is_err());
        assert!(written.lock().expect("written").is_empty());
    }
}
