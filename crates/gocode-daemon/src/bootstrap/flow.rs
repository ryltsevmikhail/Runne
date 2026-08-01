/// Full bootstrap sequence.
///
/// Returns a `BootstrapOutcome` with all acquired resources, or a
/// `DaemonError` for fatal startup failures (invalid replay key, DB change
/// under live lock, authority without Event Log, etc.).
pub fn bootstrap(config: &ConfigurationSnapshot) -> Result<BootstrapOutcome, DaemonError> {
    bootstrap_inner(config, None)
}

struct ProtectedBootstrap<'a> {
    launch_authority_id: [u8; 16],
    bootstrap_secret: [u8; 32],
    pending_first_activation: Option<&'a PendingFirstActivationV1>,
    freshness_check: &'a mut dyn FnMut() -> Result<(), DaemonError>,
}

/// Bootstraps one protected bundled launch without publishing a credential profile.
pub fn bootstrap_protected<F>(
    config: &ConfigurationSnapshot,
    launch_authority_id: [u8; 16],
    bootstrap_secret: [u8; 32],
    pending_first_activation: Option<&PendingFirstActivationV1>,
    mut freshness_check: F,
) -> Result<BootstrapOutcome, DaemonError>
where
    F: FnMut() -> Result<(), DaemonError>,
{
    if validate_uuid_v7_bytes(&launch_authority_id).is_err() || bootstrap_secret == [0; 32] {
        return Err(DaemonError::Bootstrap(
            "invalid protected launch authority".into(),
        ));
    }
    bootstrap_inner(
        config,
        Some(ProtectedBootstrap {
            launch_authority_id,
            bootstrap_secret,
            pending_first_activation,
            freshness_check: &mut freshness_check,
        }),
    )
}

fn bootstrap_inner(
    config: &ConfigurationSnapshot,
    mut protected: Option<ProtectedBootstrap<'_>>,
) -> Result<BootstrapOutcome, DaemonError> {
    let db_path = PathBuf::from(&config.db_path);
    let replay_integrity_key_path = PathBuf::from(&config.replay_integrity_key_path);

    // Derive runtime dir from config paths (parent of gocode-daemon/).
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

    // ── Step 9: DB verify / create ──────────────────────────────────
    if db_existed {
        // Open verify handle (no-follow) for existing DB
        let db_handle = open_verify_no_follow(&db_path)?;
        locks
            .acquire_file_lock(&db_handle, &runtime_dir)
            .map_err(|e| DaemonError::Bootstrap(format!("file lock: {e}")))?;
    }
    // ── Step 10: open SQLite writable ───────────────────────────────
    let db_conn = schema::open_with_pragmas(&config.db_path)
        .map_err(|e| DaemonError::Bootstrap(format!("open DB: {e}")))?;

    // ── Step 11: schema migration ───────────────────────────────────
    schema::apply_migrations(&db_conn)
        .map_err(|e| DaemonError::Bootstrap(format!("schema migration: {e}")))?;
    // ── Step 12: authority ID ───────────────────────────────────────
    let prepared_authority = protected
        .as_ref()
        .and_then(|value| value.pending_first_activation)
        .map(|pending| *pending.stable().authority_id());
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

    // ── Step 13: reconcile metadata ─────────────────────────────────
    reconcile_metadata(
        &metadata_snapshot,
        db_existed,
        &db_authority_after,
        &authority_id,
        &locks,
    )?;

    // Verify metadata was written correctly
    verify_metadata_writeback(&locks, &authority_id)?;

    // ── Step 14: startup purge ──────────────────────────────────────
    schema::purge_replay_subscriptions(&db_conn)
        .map_err(|e| DaemonError::Bootstrap(format!("startup purge: {e}")))?;

    // ── Step 15: recovery is informational; caller may invoke
    //    `crate::recovery::enumerate_recovery_tasks` separately. ──────

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
    })
}
