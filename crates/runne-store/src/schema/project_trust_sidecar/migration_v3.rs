use super::*;
use crate::project_trust_store::PROJECT_TRUST_IDENTITY_V3_SQL;

pub(super) fn migrate(
    connection: &Connection,
    identity: &mut ConnectionIdentityGuard,
    expected_epoch: u64,
    expected_authority: [u8; 16],
) -> SqliteResult<()> {
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let migration = migrate_under_fence(connection, identity, expected_epoch, expected_authority);
    match migration {
        Ok(true) => {
            let commit = (|| {
                identity.retain_created_sidecars()?;
                identity.verify_with_sidecar_handle(connection)?;
                project_trust_sidecar_catalog::classify_v3(connection)?;
                let epoch = project_trust_sidecar_catalog::validate_authority(
                    connection,
                    expected_authority,
                    project_trust_sidecar_catalog::CatalogVersion::V3,
                )?;
                if epoch != expected_epoch {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                connection.execute_batch("COMMIT")
            })();
            if let Err(error) = commit {
                let _ = connection.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        Ok(false) => connection.execute_batch("ROLLBACK")?,
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(error);
        }
    }
    identity.retain_created_sidecars()?;
    identity.verify_with_sidecar_handle(connection)?;
    Ok(())
}

fn migrate_under_fence(
    connection: &Connection,
    identity: &mut ConnectionIdentityGuard,
    expected_epoch: u64,
    expected_authority: [u8; 16],
) -> SqliteResult<bool> {
    identity.retain_created_sidecars()?;
    identity.verify_with_sidecar_handle(connection)?;
    match project_trust_sidecar_catalog::classify(connection)? {
        project_trust_sidecar_catalog::CatalogVersion::V3 => {
            let epoch = project_trust_sidecar_catalog::validate_authority(
                connection,
                expected_authority,
                project_trust_sidecar_catalog::CatalogVersion::V3,
            )?;
            if epoch != expected_epoch {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(false)
        }
        project_trust_sidecar_catalog::CatalogVersion::V2 => {
            let epoch = project_trust_sidecar_catalog::validate_authority(
                connection,
                expected_authority,
                project_trust_sidecar_catalog::CatalogVersion::V2,
            )?;
            if epoch != expected_epoch {
                return Err(rusqlite::Error::InvalidQuery);
            }
            project_trust_sidecar_catalog::validate_v2_records(connection)?;
            let schema_kind: String = connection.query_row(
                "SELECT schema_kind FROM project_trust_schema WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            let authority: Vec<u8> = connection.query_row(
                "SELECT authority_id FROM project_trust_schema WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            connection.execute_batch(PROJECT_TRUST_EFFECT_POLICY_V1_SQL)?;
            connection.execute(
                "INSERT INTO managed_effect_policies
                 (project_id, policy_version, fs_read, fs_create, fs_write, fs_delete,
                  process_start, network_use)
                 SELECT project_id, 1, 0, 0, 0, 0, 0, 0 FROM project_trust",
                [],
            )?;
            connection.execute_batch(PROJECT_TRUST_EFFECT_POLICY_DEFAULT_TRIGGER_SQL)?;
            connection.execute_batch(super::project_trust_sidecar_admin_catalog::ADMIN_ROLE_SQL)?;
            connection
                .execute_batch(super::project_trust_sidecar_admin_catalog::ADMIN_COMMANDS_SQL)?;
            connection
                .execute_batch(super::project_trust_sidecar_admin_catalog::ADMIN_RECEIPTS_SQL)?;
            connection
                .execute_batch(super::project_trust_sidecar_admin_catalog::ADMIN_TRIGGERS_SQL)?;
            connection.execute("DROP TABLE project_trust_schema", [])?;
            connection.execute_batch(PROJECT_TRUST_IDENTITY_V3_SQL)?;
            connection.execute(
                "INSERT INTO project_trust_schema
                 (id, schema_kind, schema_version, instance_epoch, authority_id)
                 VALUES (1, ?1, 3, ?2, ?3)",
                rusqlite::params![
                    schema_kind,
                    i64::try_from(epoch).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    authority
                ],
            )?;
            connection.pragma_update(None, "user_version", PROJECT_TRUST_SIDECAR_VERSION)?;
            Ok(true)
        }
    }
}
