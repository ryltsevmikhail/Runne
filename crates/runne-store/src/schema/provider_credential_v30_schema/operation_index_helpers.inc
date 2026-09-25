const V35_OPERATION_INDEXES: [&str; 3] = [
    "provider_credential_one_non_terminal_operation",
    "provider_credential_one_pending_legacy_source_cleanup",
    "provider_credential_one_pending_retired_version_cleanup",
];

fn v35_operation_index_names() -> &'static [&'static str] {
    &V35_OPERATION_INDEXES
}

fn v35_operation_indexes_match(connection: &Connection) -> SqliteResult<bool> {
    V35_OPERATION_INDEXES
        .into_iter()
        .try_fold(true, |valid, name| {
            let expected = match name {
                "provider_credential_one_pending_legacy_source_cleanup" => MIGRATION_V32
                    .split(';')
                    .map(str::trim)
                    .find(|sql| sql.starts_with(&format!("CREATE UNIQUE INDEX {name}"))),
                "provider_credential_one_non_terminal_operation" => Some(
                    "CREATE UNIQUE INDEX provider_credential_one_non_terminal_operation
                     ON provider_credential_operations(provider_id)
                     WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')
                       AND action NOT IN ('LEGACY_SOURCE_CLEANUP', 'RETIRED_VERSION_CLEANUP')",
                ),
                "provider_credential_one_pending_retired_version_cleanup" => Some(
                    "CREATE UNIQUE INDEX provider_credential_one_pending_retired_version_cleanup
                     ON provider_credential_operations(provider_id)
                     WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')
                       AND action = 'RETIRED_VERSION_CLEANUP'",
                ),
                _ => None,
            };
            Ok(valid && v24_index_matches_with_source(connection, name, expected)?)
        })
}
