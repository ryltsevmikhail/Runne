fn apply_execution_migrations(
    conn: &Connection,
    source_version: i64,
    target_version: i64,
) -> SqliteResult<()> {
    if source_version < 41 && target_version >= 41 {
        apply_v41_migration(conn)?;
    }
    if source_version < 42 && target_version >= 42 {
        apply_v42_migration(conn)?;
    }
    if source_version < 43 && target_version >= 43 {
        apply_v43_migration(conn)?;
    }
    if source_version < 44 && target_version >= 44 {
        apply_v44_migration(conn)?;
    }
    if source_version < 45 && target_version >= 45 {
        apply_v45_migration(conn)?;
    }
    if source_version < 46 && target_version >= 46 {
        apply_v46_migration(conn)?;
    }
    if source_version < 47 && target_version >= 47 {
        apply_v47_migration(conn)?;
    }
    Ok(())
}
