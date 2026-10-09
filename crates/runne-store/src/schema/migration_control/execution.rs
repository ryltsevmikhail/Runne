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
    if source_version < 48 && target_version >= 48 {
        apply_v48_migration(conn)?;
    }
    if source_version < 49 && target_version >= 49 {
        apply_v49_migration(conn)?;
    }
    if source_version < 50 && target_version >= 50 {
        apply_v50_migration(conn)?;
    }
    if source_version < 51 && target_version >= 51 {
        apply_v51_migration(conn)?;
    }
    if source_version < 52 && target_version >= 52 {
        apply_v52_migration(conn)?;
    }
    if source_version < 53 && target_version >= 53 {
        apply_v53_migration(conn)?;
    }
    if source_version < 54 && target_version >= 54 {
        apply_v54_migration(conn)?;
    }
    if source_version < 55 && target_version >= 55 {
        apply_v55_migration(conn)?;
    }
    if source_version < 56 && target_version >= 56 {
        apply_v56_migration(conn)?;
    }
    if source_version < 57 && target_version >= 57 {
        apply_v57_migration(conn)?;
    }
    if source_version < 58 && target_version >= 58 {
        apply_v58_migration(conn)?;
    }
    if source_version < 59 && target_version >= 59 {
        apply_v59_migration(conn)?;
    }
    if source_version < 60 && target_version >= 60 {
        apply_v60_migration(conn)?;
    }
    if source_version < 61 && target_version >= 61 {
        apply_v61_migration(conn)?;
    }
    if source_version < 62 && target_version >= 62 {
        apply_v62_migration(conn)?;
    }
    if source_version < 63 && target_version >= 63 {
        apply_v63_migration(conn)?;
    }
    if source_version < 64 && target_version >= 64 {
        apply_v64_migration(conn)?;
    }
    if source_version < 65 && target_version >= 65 {
        apply_v65_migration(conn)?;
    }
    if source_version < 66 && target_version >= 66 {
        apply_v66_migration(conn)?;
    }
    if source_version < 67 && target_version >= 67 {
        apply_v67_migration(conn)?;
    }
    if source_version < 68 && target_version >= 68 {
        apply_v68_migration(conn)?;
    }
    Ok(())
}
