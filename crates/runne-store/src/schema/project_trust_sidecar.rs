use crate::project_trust_store::{
    PROJECT_TRUST_IDENTITY_V2_SQL, PROJECT_TRUST_IDENTITY_V3_SQL, PROJECT_TRUST_SCHEMA_KIND,
    PROJECT_TRUST_SCHEMA_V2_VERSION, PROJECT_TRUST_SCHEMA_VERSION, PROJECT_TRUST_SIDECAR_VERSION,
    PROJECT_TRUST_TRUST_SQL,
};

#[path = "project_trust_sidecar/admin_catalog.rs"]
mod project_trust_sidecar_admin_catalog;
#[path = "project_trust_sidecar/catalog.rs"]
mod project_trust_sidecar_catalog;
#[path = "project_trust_sidecar/migration_v3.rs"]
mod project_trust_sidecar_migration_v3;

pub(crate) const PROJECT_TRUST_EFFECT_POLICY_V1_SQL: &str =
    include_str!("project_trust_sidecar/schema_v3.sql");
pub(crate) const PROJECT_TRUST_EFFECT_POLICY_DEFAULT_TRIGGER_SQL: &str =
    "CREATE TRIGGER project_trust_default_effect_policy AFTER INSERT ON project_trust
     BEGIN
       INSERT OR IGNORE INTO managed_effect_policies
       (project_id, policy_version, fs_read, fs_create, fs_write, fs_delete,
        process_start, network_use)
       VALUES (NEW.project_id, 1, 0, 0, 0, 0, 0, 0);
     END";
pub(crate) const PROJECT_TRUST_ADMIN_ROLE_SQL: &str =
    project_trust_sidecar_admin_catalog::ADMIN_ROLE_SQL;
pub(crate) const PROJECT_TRUST_ADMIN_COMMANDS_SQL: &str =
    project_trust_sidecar_admin_catalog::ADMIN_COMMANDS_SQL;
pub(crate) const PROJECT_TRUST_ADMIN_RECEIPTS_SQL: &str =
    project_trust_sidecar_admin_catalog::ADMIN_RECEIPTS_SQL;
pub(crate) const PROJECT_TRUST_ADMIN_TRIGGERS_SQL: &str =
    project_trust_sidecar_admin_catalog::ADMIN_TRIGGERS_SQL;

pub(crate) fn reopen_managed_project_trust_sidecar(
    path: &Path,
    expected_authority: [u8; 16],
) -> SqliteResult<(ManagedConnection, u64)> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, expected_authority);
        Err(diagnostic_error(SchemaOpenDiagnostic::SidecarPresent))
    }
    #[cfg(any(unix, windows))]
    {
        let mut identity =
            ConnectionIdentityGuard::owner_private(path).map_err(diagnostic_error)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        identity.retain_created_sidecars()?;
        identity.verify(&connection)?;
        connection.execute_batch("PRAGMA query_only = ON;")?;
        let layout = project_trust_sidecar_catalog::classify(&connection)?;
        let instance_epoch = project_trust_sidecar_catalog::validate_authority(
            &connection,
            expected_authority,
            layout,
        )?;
        if layout == project_trust_sidecar_catalog::CatalogVersion::V2 {
            project_trust_sidecar_catalog::validate_v2_records(&connection)?;
        }
        identity.retain_created_sidecars()?;
        identity.verify_with_sidecar_handle(&connection)?;
        if layout == project_trust_sidecar_catalog::CatalogVersion::V2 {
            connection.execute_batch("PRAGMA query_only = OFF;")?;
            project_trust_sidecar_migration_v3::migrate(
                &connection,
                &mut identity,
                instance_epoch,
                expected_authority,
            )?;
        }
        connection.execute_batch("PRAGMA query_only = ON;")?;
        project_trust_sidecar_catalog::classify_v3(&connection)?;
        let current_epoch = project_trust_sidecar_catalog::validate_authority(
            &connection,
            expected_authority,
            project_trust_sidecar_catalog::CatalogVersion::V3,
        )?;
        if current_epoch != instance_epoch {
            return Err(rusqlite::Error::InvalidQuery);
        }
        identity.retain_created_sidecars()?;
        identity.verify_with_sidecar_handle(&connection)?;
        connection.execute_batch("PRAGMA query_only = OFF;")?;
        let managed = managed_after_profile(
            connection,
            ConnectionMode::ValidatedReopen,
            false,
            Some(identity),
        )?;
        Ok((managed, instance_epoch))
    }
}
