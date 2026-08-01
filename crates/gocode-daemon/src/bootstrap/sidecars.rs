struct SidecarMigrationMarker {
    replay_key_digest: [u8; 32],
    local_authority_digest: [u8; 32],
}

fn load_or_migrate_local_sidecars(
    conn: &rusqlite::Connection,
    replay_key_path: &Path,
    database_authority: [u8; 16],
) -> Result<(ReplayIntegrityKey, [u8; 16]), DaemonError> {
    let authority_path = replay_key_path.with_file_name("local-session-authority-id");
    match read_sidecar_migration_marker(conn)? {
        Some(marker) => {
            let replay_key = ReplayIntegrityKeyManager::load_existing(replay_key_path)
                .map_err(|_| sidecar_state_error())?;
            let local_authority =
                load_local_session_authority(&authority_path).map_err(|_| sidecar_state_error())?;
            if replay_key.sidecar_digest() != marker.replay_key_digest
                || Sha256::digest(local_authority).as_slice() != marker.local_authority_digest
            {
                return Err(sidecar_state_error());
            }
            Ok((replay_key, local_authority))
        }
        None => {
            let replay_key = ReplayIntegrityKeyManager::load_or_provision(replay_key_path)
                .map_err(|_| sidecar_state_error())?;
            let local_authority =
                load_or_provision_local_session_authority(&authority_path, database_authority)?;
            let marker = SidecarMigrationMarker {
                replay_key_digest: replay_key.sidecar_digest(),
                local_authority_digest: Sha256::digest(local_authority).into(),
            };
            write_sidecar_migration_marker(conn, &marker)?;
            Ok((replay_key, local_authority))
        }
    }
}

/// Read-only validation for sidecars left before first launch consumption.
pub(crate) fn preflight_recoverable_first_activation_sidecars(
    config: &ConfigurationSnapshot,
    expected_authority: &[u8; 16],
) -> Result<(), DaemonError> {
    let replay_key_path = Path::new(&config.replay_integrity_key_path);
    let authority_path = replay_key_path.with_file_name("local-session-authority-id");
    let db = rusqlite::Connection::open_with_flags(
        &config.db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| sidecar_state_error())?;
    match read_sidecar_migration_marker(&db)? {
        Some(marker) => {
            let replay_key = ReplayIntegrityKeyManager::load_existing(replay_key_path)
                .map_err(|_| sidecar_state_error())?;
            let authority =
                load_local_session_authority(&authority_path).map_err(|_| sidecar_state_error())?;
            if &authority != expected_authority
                || replay_key.sidecar_digest() != marker.replay_key_digest
                || Sha256::digest(authority).as_slice() != marker.local_authority_digest
            {
                return Err(sidecar_state_error());
            }
        }
        None => {
            if replay_key_path.exists() {
                ReplayIntegrityKeyManager::load_existing(replay_key_path)
                    .map_err(|_| sidecar_state_error())?;
            }
            if authority_path.exists() {
                match load_local_session_authority(&authority_path) {
                    Ok(authority) if authority == *expected_authority => {}
                    Ok(_) | Err(_) => return Err(sidecar_state_error()),
                }
            }
        }
    }
    Ok(())
}

fn read_sidecar_migration_marker(
    conn: &rusqlite::Connection,
) -> Result<Option<SidecarMigrationMarker>, DaemonError> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = ?1",
            [SIDECAR_MIGRATION_MARKER_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| sidecar_state_error())?;
    value
        .map(|value| parse_sidecar_migration_marker(&value))
        .transpose()
}

fn parse_sidecar_migration_marker(value: &str) -> Result<SidecarMigrationMarker, DaemonError> {
    let mut parts = value.split(':');
    let (Some("1"), Some(replay_digest), Some(authority_digest), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(sidecar_state_error());
    };
    Ok(SidecarMigrationMarker {
        replay_key_digest: decode_lower_hex_32(replay_digest)?,
        local_authority_digest: decode_lower_hex_32(authority_digest)?,
    })
}

fn write_sidecar_migration_marker(
    conn: &rusqlite::Connection,
    marker: &SidecarMigrationMarker,
) -> Result<(), DaemonError> {
    let value = format!(
        "1:{}:{}",
        hex::encode(marker.replay_key_digest),
        hex::encode(marker.local_authority_digest)
    );
    conn.execute(
        "INSERT INTO _daemon_info (key, value) VALUES (?1, ?2)",
        (SIDECAR_MIGRATION_MARKER_KEY, value),
    )
    .map_err(|_| sidecar_state_error())?;
    Ok(())
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], DaemonError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(sidecar_state_error());
    }
    let mut output = [0; 32];
    hex::decode_to_slice(value, &mut output).map_err(|_| sidecar_state_error())?;
    Ok(output)
}

fn sidecar_state_error() -> DaemonError {
    DaemonError::Bootstrap("load local session sidecar state".into())
}

fn load_or_provision_local_session_authority(
    path: &Path,
    database_authority: [u8; 16],
) -> Result<[u8; 16], DaemonError> {
    match load_local_session_authority(path) {
        Ok(authority) => return Ok(authority),
        Err(_) if path.exists() => {
            return Err(DaemonError::Bootstrap(
                "load local session authority".into(),
            ));
        }
        Err(_) => {}
    }
    let authority = if validate_uuid_v7_bytes(&database_authority).is_ok() {
        database_authority
    } else {
        *uuid::Uuid::now_v7().as_bytes()
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(crate::lock::O_NOFOLLOW_VAL);
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(_) if path.exists() => return load_local_session_authority(path),
        Err(_) => {
            return Err(DaemonError::Bootstrap(
                "provision local session authority".into(),
            ));
        }
    };
    file.write_all(&authority)
        .and_then(|()| file.sync_all())
        .map_err(|_| DaemonError::Bootstrap("provision local session authority".into()))?;
    Ok(authority)
}

fn load_local_session_authority(path: &Path) -> Result<[u8; 16], DaemonError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(crate::lock::O_NOFOLLOW_VAL);
    }
    let mut file = options
        .open(path)
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    let metadata = file
        .metadata()
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    if !metadata.file_type().is_file() {
        return Err(DaemonError::Bootstrap(
            "load local session authority".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(DaemonError::Bootstrap(
                "load local session authority".into(),
            ));
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    let authority: [u8; 16] = bytes
        .try_into()
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    validate_uuid_v7_bytes(&authority)
        .map_err(|_| DaemonError::Bootstrap("load local session authority".into()))?;
    Ok(authority)
}
