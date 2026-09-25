pub(super) const MIGRATION_CREDENTIAL_V35: &str = r#"
DROP INDEX provider_credential_one_non_terminal_operation;
CREATE UNIQUE INDEX provider_credential_one_non_terminal_operation
    ON provider_credential_operations(provider_id)
    WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')
      AND action NOT IN ('LEGACY_SOURCE_CLEANUP', 'RETIRED_VERSION_CLEANUP');
CREATE UNIQUE INDEX provider_credential_one_pending_retired_version_cleanup
    ON provider_credential_operations(provider_id)
    WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')
      AND action = 'RETIRED_VERSION_CLEANUP';
"#;
