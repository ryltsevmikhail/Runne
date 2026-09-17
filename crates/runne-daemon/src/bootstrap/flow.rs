/// Full bootstrap sequence.
///
/// Returns a `BootstrapOutcome` with all acquired resources, or a
/// `DaemonError` for fatal startup failures (invalid replay key, DB change
/// under live lock, authority without Event Log, etc.).
pub fn bootstrap(config: &ConfigurationSnapshot) -> Result<BootstrapOutcome, DaemonError> {
    bootstrap_inner(config, None)
}

include!("protected_profile.rs");

fn bootstrap_inner(
    config: &ConfigurationSnapshot,
    mut protected: Option<ProtectedBootstrap<'_>>,
) -> Result<BootstrapOutcome, DaemonError> {
    let db_path = PathBuf::from(&config.db_path);
    let replay_integrity_key_path = PathBuf::from(&config.replay_integrity_key_path);

    // Derive runtime dir from config paths (parent of runne-daemon/).
    let daemon_dir = db_path
        .parent()
        .ok_or_else(|| DaemonError::Bootstrap("db_path has no parent directory".into()))?
        .to_path_buf();
    let runtime_dir = daemon_dir
        .parent()
        .ok_or_else(|| DaemonError::Bootstrap("daemon dir has no parent".into()))?
        .to_path_buf();

    // ── Step 2 & 3: canonicalise parent, create runtime dir ────────
    ensure_dir_secured(&daemon_dir)?;

    // ── Step 6: check DB existence BEFORE any file creation ─────────
    let db_existed = db_path.exists();
    if protected.is_some()
        && !db_existed
        && protected
            .as_ref()
            .and_then(|value| value.pending_first_activation)
            .is_none()
    {
        return Err(DaemonError::Bootstrap(
            "protected first activation was not prepared".into(),
        ));
    }

    // ── Step 4: acquire provisional path lock ───────────────────────
    let mut locks = LockSet::acquire_path(&db_path, &runtime_dir)
        .map_err(|e| DaemonError::Bootstrap(format!("path lock: {e}")))?;

    // ── Step 5: read pre-open metadata snapshot ─────────────────────
    let metadata_snapshot = locks
        .read_metadata_snapshot()
        .map_err(|e| DaemonError::Bootstrap(format!("read metadata: {e}")))?;

    // ── Step 7: determine startup mode ──────────────────────────────
    let startup_mode = match (&metadata_snapshot, db_existed) {
        (MetadataSnapshot::Empty, false) => StartupMode::FirstStart,
        _ => StartupMode::Restart,
    };
    let prepared_authority = protected
        .as_ref()
        .and_then(|value| value.pending_first_activation)
        .map(|pending| *pending.stable().authority_id());

    // ── Step 9: DB verify / create ──────────────────────────────────
    if db_existed {
        // Open verify handle (no-follow) for existing DB
        let db_handle = open_verify_no_follow(&db_path)?;
        locks
            .acquire_file_lock(&db_handle, &runtime_dir)
            .map_err(|e| DaemonError::Bootstrap(format!("file lock: {e}")))?;
    }
    // ── Step 10: open SQLite writable ───────────────────────────────
    let db_conn = if db_existed {
        open_existing_bootstrap_database(
            config,
            protected.as_ref(),
            &metadata_snapshot,
            &mut locks,
            &runtime_dir,
        )
    } else {
        schema::open_managed_connection(&db_path, schema::ConnectionMode::Writer)
    }
    .map_err(|e| DaemonError::Bootstrap(format!("open DB: {e}")))?;

    if db_existed
        && locks.authority_lock.is_none()
        && let Some(authority_id) =
            acquire_existing_authority_lock(&db_conn, &mut locks, &runtime_dir)?
        && prepared_authority.is_some_and(|prepared| prepared != authority_id)
    {
        return Err(DaemonError::Bootstrap(
            "prepared authority does not match Event Log".into(),
        ));
    }

    // ── Step 11: schema migration ───────────────────────────────────
    schema::apply_migrations(&db_conn)
        .map_err(|e| DaemonError::Bootstrap(format!("schema migration: {e}")))?;
    // ── Step 12: authority ID ───────────────────────────────────────
    let (authority_id, db_authority_after) = acquire_authority(
        db_existed,
        &db_conn,
        &mut locks,
        &runtime_dir,
        prepared_authority,
    )?;
    if let Some(pending) = protected
        .as_ref()
        .and_then(|value| value.pending_first_activation)
    {
        let expected_lineage = uuid::Uuid::from_bytes(*pending.stable().lineage_id())
            .to_string()
            .parse()
            .map_err(|_| DaemonError::Bootstrap("invalid prepared Event Log lineage".into()))?;
        if authority_id != *pending.stable().authority_id() {
            return Err(DaemonError::Bootstrap(
                "prepared stable authority mismatch".into(),
            ));
        }
        schema::ensure_exact_first_activation_identity(
            &db_conn,
            pending.stable().authority_id(),
            expected_lineage,
            pending.preparation_id(),
        )
        .map_err(|_| DaemonError::Bootstrap("prepared first activation mismatch".into()))?;
    }
    schema::readiness_from_managed(&db_conn)
        .map_err(|_| DaemonError::Bootstrap("pre-sidecar readiness".into()))?;
    let (replay_integrity_key, local_session_authority_id) =
        load_or_migrate_local_sidecars(&db_conn, &replay_integrity_key_path, authority_id)?;
    if let Some(protected) = protected.as_mut() {
        if let Some(pending) = protected.pending_first_activation
            && local_session_authority_id != *pending.stable().authority_id()
        {
            return Err(DaemonError::Bootstrap(
                "prepared stable authority mismatch".into(),
            ));
        }
        (protected.freshness_check)()?;
        schema::consume_protected_launch_authority(&db_conn, &protected.launch_authority_id)
            .map_err(|error| match error {
                LaunchAuthorityConsumptionError::AlreadyConsumed => {
                    DaemonError::Bootstrap("protected launch authority already consumed".into())
                }
                LaunchAuthorityConsumptionError::InvalidAuthority
                | LaunchAuthorityConsumptionError::Storage => {
                    DaemonError::Bootstrap("consume protected launch authority".into())
                }
            })?;
    }
    let launch_generation = schema::next_launch_generation(&db_conn)
        .map_err(|_| DaemonError::Bootstrap("allocate launch generation: corrupt state".into()))?;
    let launch_identity = if let Some(protected) = protected.as_ref() {
        LaunchIdentity::generate_protected(launch_generation, protected.bootstrap_secret)
    } else {
        LaunchIdentity::generate(launch_generation)
    }
    .map_err(|_| DaemonError::Bootstrap("generate launch TLS identity".into()))?;

    reconcile_metadata(
        &metadata_snapshot,
        db_existed,
        &db_authority_after,
        &authority_id,
        &locks,
    )?;
    verify_metadata_writeback(&locks, &authority_id)?;
    schema::purge_replay_subscriptions(&db_conn)
        .map_err(|e| DaemonError::Bootstrap(format!("startup purge: {e}")))?;
    #[cfg(unix)]
    let installation_anchor_dir =
        InstallationAnchorDir::retain(&daemon_dir, &db_path, &replay_integrity_key_path)?;
    schema::readiness_from_managed(&db_conn)
        .and_then(|_| schema::publication_from_managed(&db_conn).map(|_| ()))
        .map_err(|e| DaemonError::Bootstrap(format!("publish bootstrap database: {e}")))?;
    #[cfg(unix)]
    installation_anchor_dir.verify_current()?;
    Ok(BootstrapOutcome {
        locks,
        db_conn,
        authority_id,
        local_session_authority_id,
        db_existed,
        startup_mode,
        launch_identity,
        launch_generation,
        replay_integrity_key,
        #[cfg(unix)]
        installation_anchor_dir,
    })
}

fn open_existing_bootstrap_database(
    config: &ConfigurationSnapshot,
    protected: Option<&ProtectedBootstrap<'_>>,
    metadata: &MetadataSnapshot,
    locks: &mut LockSet,
    runtime_dir: &Path,
) -> rusqlite::Result<schema::ManagedConnection> {
    let path = Path::new(&config.db_path);
    #[cfg(any(unix, windows))]
    {
        schema::reopen_managed_connection_validated(
            path,
            schema::ConnectionMode::ValidatedReopen,
            |connection| {
                if let Some(protected) = protected {
                    validate_protected_bootstrap_connection(
                        config,
                        connection,
                        protected.expected_stable,
                        protected.pending_first_activation,
                        protected.expected_profile,
                    )
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                }
                let authority_id = schema::read_authority_id(connection)?
                    .or_else(|| {
                        protected
                            .and_then(|value| value.pending_first_activation)
                            .map(|pending| *pending.stable().authority_id())
                    })
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                if let MetadataSnapshot::Valid {
                    authority_id: expected,
                } = metadata
                    && expected != &authority_id
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                locks
                    .acquire_authority_lock(&authority_id, runtime_dir)
                    .map_err(|_| rusqlite::Error::InvalidQuery)
            },
        )
    }

    #[cfg(not(any(unix, windows)))]
    let _ = (protected, locks, runtime_dir);
    #[cfg(not(any(unix, windows)))]
    match schema::open_managed_connection(path, schema::ConnectionMode::Writer) {
        Ok(connection) => Ok(connection),
        Err(default_error) => match metadata {
            MetadataSnapshot::Valid { authority_id } => {
                schema::reopen_managed_connection_validated(
                    path,
                    schema::ConnectionMode::ValidatedReopen,
                    |connection| {
                        if schema::read_authority_id(connection)? == Some(*authority_id) {
                            Ok(())
                        } else {
                            Err(rusqlite::Error::InvalidQuery)
                        }
                    },
                )
            }
            MetadataSnapshot::Empty | MetadataSnapshot::Malformed => Err(default_error),
        },
    }
}
