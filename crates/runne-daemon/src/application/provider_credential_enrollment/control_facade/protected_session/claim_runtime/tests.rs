use runne_provider::CredentialOperationAction;

#[test]
fn only_legacy_source_cleanup_skips_the_credential_service_arm() {
    for action in [
        CredentialOperationAction::Pair,
        CredentialOperationAction::Revoke,
        CredentialOperationAction::MigrateLegacy,
        CredentialOperationAction::RetiredVersionCleanup,
        CredentialOperationAction::WriterIdentityMigrationEffect,
        CredentialOperationAction::WriterIdentityMigrationVerify,
    ] {
        assert!(super::requires_service_arm(action));
    }
    assert!(!super::requires_service_arm(
        CredentialOperationAction::LegacySourceCleanup
    ));
}
