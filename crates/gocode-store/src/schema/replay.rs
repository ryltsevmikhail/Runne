/// Purge stale replay subscriptions at startup.
pub fn purge_replay_subscriptions(conn: &Connection) -> SqliteResult<()> {
    conn.execute("DELETE FROM _replay_subscriptions", [])?;
    Ok(())
}

// ── Platform-specific file ACL ──────────────────────────────────────────

/// Platform-specific file ACL (Windows: private DACL, Unix: 0600).
#[cfg(unix)]
pub fn secure_file_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
pub fn secure_file_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    // Windows ACL is handled during file creation in lock.rs
    Ok(())
}

/// Protect parent directory: 0700 (Unix) / private DACL (Windows).
#[cfg(unix)]
pub fn secure_dir_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
pub fn secure_dir_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}
