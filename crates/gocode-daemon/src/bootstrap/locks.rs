// ── Helpers ──────────────────────────────────────────────────────────

/// Ensure `dir` exists with secure permissions (0700).
fn ensure_dir_secured(dir: &Path) -> Result<(), DaemonError> {
    fs::create_dir_all(dir)
        .map_err(|e| DaemonError::Bootstrap(format!("cannot create {dir:?}: {e}")))?;
    schema::secure_dir_permissions(dir)
        .map_err(|e| DaemonError::Bootstrap(format!("cannot secure {dir:?}: {e}")))
}

/// Open DB file with no-follow for verify / file-identity lock.
fn open_verify_no_follow(db_path: &Path) -> Result<fs::File, DaemonError> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true).write(false).create(false);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        const O_NOFOLLOW: i32 = 0x0100;
        const O_CLOEXEC: i32 = 0x1000000;
        opts.custom_flags(O_NOFOLLOW | O_CLOEXEC);
    }

    opts.open(db_path)
        .map_err(|e| DaemonError::Bootstrap(format!("cannot open DB for verify: {e}")))
}

/// Read, generate, or validate the authority ID.
///
/// Returns `(authority_id, db_authority_after)` where `db_authority_after`
/// is `Some` with the authority that is now in the database.
fn acquire_authority(
    db_existed: bool,
    conn: &rusqlite::Connection,
    locks: &mut LockSet,
    runtime_dir: &Path,
    prepared_authority: Option<[u8; 16]>,
) -> Result<([u8; 16], Option<[u8; 16]>), DaemonError> {
    let db_authority = schema::read_authority_id(conn)
        .map_err(|e| DaemonError::Bootstrap(format!("read authority: {e}")))?;

    match (db_existed, db_authority) {
        // New DB — generate fresh authority
        (false, None) => {
            let aid = prepared_authority.unwrap_or_else(|| *uuid::Uuid::now_v7().as_bytes());
            schema::ensure_authority_id(conn, &aid)
                .map_err(|e| DaemonError::Bootstrap(format!("ensure authority: {e}")))?;

            locks
                .acquire_authority_lock(&aid, runtime_dir)
                .map_err(|e| DaemonError::Bootstrap(format!("authority lock: {e}")))?;

            // Re-read to confirm
            let after = schema::read_authority_id(conn)
                .map_err(|e| DaemonError::Bootstrap(format!("re-read authority: {e}")))?;
            Ok((aid, after))
        }

        // New DB somehow already has authority (shouldn't happen outside backup restore)
        (false, Some(_)) => Err(DaemonError::Bootstrap(
            "newly created DB unexpectedly has authority ID".into(),
        )),

        // Existing DB — must have authority
        (true, Some(aid)) => {
            if prepared_authority.is_some_and(|prepared| prepared != aid) {
                return Err(DaemonError::Bootstrap(
                    "prepared authority does not match Event Log".into(),
                ));
            }
            locks
                .acquire_authority_lock(&aid, runtime_dir)
                .map_err(|e| DaemonError::Bootstrap(format!("authority lock: {e}")))?;
            Ok((aid, Some(aid)))
        }

        // Existing DB without authority — schema corruption
        (true, None) => Err(DaemonError::Bootstrap(
            "existing DB has no authority ID".into(),
        )),
    }
}

/// Reconcile lock metadata with DB authority.
///
/// This implements the crash-recovery table from ADR-0014 §6:
///
/// | Metadata | DB exists | DB authority | Action |
/// |----------|-----------|-------------|--------|
/// | Valid (=) | yes      | =           | nothing |
/// | Valid (!=)| yes      | !=          | **exit 5** |
/// | Empty    | yes      | present     | write metadata (upgrade) |
/// | Malformed| yes      | present     | write metadata (repair) |
/// | Empty    | no       | generated   | write metadata (first start) |
/// | Valid/Malformed | no | *         | **exit 5** |
fn reconcile_metadata(
    snapshot: &MetadataSnapshot,
    db_existed: bool,
    db_authority: &Option<[u8; 16]>,
    authority_id: &[u8; 16],
    locks: &LockSet,
) -> Result<(), DaemonError> {
    match (snapshot, db_existed, db_authority) {
        // Normal restart — authority matches lock metadata
        (
            MetadataSnapshot::Valid {
                authority_id: expected,
            },
            true,
            Some(present),
        ) if *expected == *present => {
            // Nothing to do
        }

        // Authority mismatch — DB was replaced under a live lock (exit 5)
        (MetadataSnapshot::Valid { .. }, true, Some(_)) => {
            return Err(DaemonError::Bootstrap(
                "authority mismatch: DB replaced".into(),
            ));
        }

        // Upgrade: empty metadata on existing DB — publish authority
        (MetadataSnapshot::Empty, true, Some(present)) => {
            locks
                .write_metadata(present)
                .map_err(|e| DaemonError::Bootstrap(format!("write metadata (upgrade): {e}")))?;
        }

        // Repair torn metadata on existing DB
        (MetadataSnapshot::Malformed, true, Some(present)) => {
            locks
                .write_metadata(present)
                .map_err(|e| DaemonError::Bootstrap(format!("write metadata (repair): {e}")))?;
        }

        // First start: empty metadata, no DB existed, authority just generated
        (MetadataSnapshot::Empty, false, _) => {
            locks.write_metadata(authority_id).map_err(|e| {
                DaemonError::Bootstrap(format!("write metadata (first start): {e}"))
            })?;
        }

        // Authority published but DB does not exist (exit 5)
        (MetadataSnapshot::Valid { .. } | MetadataSnapshot::Malformed, false, _) => {
            return Err(DaemonError::Bootstrap("authority without Event Log".into()));
        }

        // Catch-all for unexpected combinations
        _ => {
            return Err(DaemonError::Bootstrap(format!(
                "unexpected bootstrap state: \
                 metadata={:?}, db_existed={}, authority={:?}",
                snapshot, db_existed, db_authority
            )));
        }
    }

    Ok(())
}

/// Verify metadata writeback: re-read and check version, length, CRC, authority_id.
fn verify_metadata_writeback(locks: &LockSet, authority_id: &[u8; 16]) -> Result<(), DaemonError> {
    let snap = locks
        .read_metadata_snapshot()
        .map_err(|e| DaemonError::Bootstrap(format!("verify metadata readback: {e}")))?;

    match &snap {
        MetadataSnapshot::Valid {
            authority_id: verified,
        } if *verified == *authority_id => Ok(()),

        MetadataSnapshot::Valid { .. } => Err(DaemonError::Bootstrap(
            "metadata write verification failed: authority mismatch".into(),
        )),

        _ => Err(DaemonError::Bootstrap(
            "metadata write verification failed: record is not valid".into(),
        )),
    }
}
