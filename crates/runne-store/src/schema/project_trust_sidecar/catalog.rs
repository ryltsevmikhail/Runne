use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CatalogVersion {
    V2,
    V3,
}

pub(super) fn classify(connection: &Connection) -> SqliteResult<CatalogVersion> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let catalog = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    let v2 = [
        ("table", "project_trust", PROJECT_TRUST_TRUST_SQL),
        (
            "table",
            "project_trust_schema",
            PROJECT_TRUST_IDENTITY_V2_SQL,
        ),
    ];
    let policy_sql = PROJECT_TRUST_EFFECT_POLICY_V1_SQL.trim_end();
    let mut v3 = vec![
        ("table", "managed_effect_policies", policy_sql),
        ("table", "project_trust", PROJECT_TRUST_TRUST_SQL),
        (
            "table",
            "project_trust_schema",
            PROJECT_TRUST_IDENTITY_V3_SQL,
        ),
        (
            "trigger",
            "project_trust_default_effect_policy",
            PROJECT_TRUST_EFFECT_POLICY_DEFAULT_TRIGGER_SQL,
        ),
    ];
    v3.extend(super::project_trust_sidecar_admin_catalog::expected_objects());
    v3.sort_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));
    let exact = |expected: &[(&str, &str, &str)]| {
        catalog.len() == expected.len()
            && catalog.iter().zip(expected).all(
                |((kind, name, sql), (expected_kind, expected_name, expected_sql))| {
                    kind == expected_kind && name == expected_name && sql == expected_sql
                },
            )
    };
    match version {
        PROJECT_TRUST_SCHEMA_V2_VERSION if exact(&v2) => Ok(CatalogVersion::V2),
        PROJECT_TRUST_SIDECAR_VERSION if exact(&v3) => Ok(CatalogVersion::V3),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

pub(super) fn classify_v3(connection: &Connection) -> SqliteResult<()> {
    if classify(connection)? == CatalogVersion::V3 {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

pub(super) fn validate_v2_records(connection: &Connection) -> SqliteResult<()> {
    let records = connection
        .prepare("SELECT project_id, status, managed_deny_mask, revision FROM project_trust")?
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    if records.iter().any(|(project, status, mask, revision)| {
        project.len() != 16
            || !(1..=3).contains(status)
            || match u32::try_from(*mask) {
                Ok(mask) => mask & !0x7f != 0,
                Err(_) => true,
            }
            || *revision < 1
    }) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

pub(super) fn validate_authority(
    connection: &Connection,
    expected_authority: [u8; 16],
    layout: CatalogVersion,
) -> SqliteResult<u64> {
    let identity = connection.query_row(
        "SELECT schema_kind, schema_version, instance_epoch, authority_id
         FROM project_trust_schema WHERE id = 1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        },
    )?;
    let expected_schema = match layout {
        CatalogVersion::V2 => PROJECT_TRUST_SCHEMA_V2_VERSION,
        CatalogVersion::V3 => PROJECT_TRUST_SCHEMA_VERSION,
    };
    if identity.0 != PROJECT_TRUST_SCHEMA_KIND
        || identity.1 != expected_schema
        || identity.2 <= 0
        || identity.3 != expected_authority
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    u64::try_from(identity.2).map_err(|_| rusqlite::Error::InvalidQuery)
}
