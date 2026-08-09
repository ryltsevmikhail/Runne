include!("implementation_parts/prelude_and_anchor.inc");
include!("implementation_parts/provider_credential_store.inc");
include!("implementation_parts/provider_credential_source.inc");
include!("implementation_parts/provider_credential_version_store.inc");
include!("implementation_parts/migration.inc");
include!("implementation_parts/recovery_and_lookup.inc");
include!("implementation_parts/keyring_and_codec.inc");

#[cfg(test)]
mod tests {
    include!("implementation_parts/tests_support.inc");
    include!("implementation_parts/tests_keyring_and_enrollment.inc");
    include!("implementation_parts/tests_migration_recovery.inc");
    include!("implementation_parts/tests_migration_guards.inc");
    include!("implementation_parts/tests_process_lock.inc");
}
