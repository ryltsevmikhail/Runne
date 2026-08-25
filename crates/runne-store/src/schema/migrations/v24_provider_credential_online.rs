pub(super) const MIGRATION_V24: &str = r#"
CREATE TABLE provider_credential_operations (
    operation_id BLOB PRIMARY KEY CHECK(length(operation_id) = 16),
    provider_id TEXT NOT NULL CHECK(typeof(provider_id) = 'text' AND length(CAST(provider_id AS BLOB)) = length(provider_id) AND length(CAST(provider_id AS BLOB)) BETWEEN 1 AND 128 AND provider_id NOT GLOB '*[^!-~]*'),
    action TEXT NOT NULL CHECK(action IN ('PAIR', 'REVOKE', 'MIGRATE_LEGACY', 'RETIRED_VERSION_CLEANUP', 'LEGACY_SOURCE_CLEANUP', 'WRITER_IDENTITY_MIGRATION_EFFECT', 'WRITER_IDENTITY_MIGRATION_VERIFY')),
    command_id BLOB NOT NULL UNIQUE CHECK(length(command_id) = 16),
    idempotency_key TEXT NOT NULL UNIQUE CHECK(typeof(idempotency_key) = 'text' AND length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256 AND instr(idempotency_key, char(0)) = 0 AND instr(idempotency_key, char(1)) = 0 AND instr(idempotency_key, char(2)) = 0 AND instr(idempotency_key, char(3)) = 0 AND instr(idempotency_key, char(4)) = 0 AND instr(idempotency_key, char(5)) = 0 AND instr(idempotency_key, char(6)) = 0 AND instr(idempotency_key, char(7)) = 0 AND instr(idempotency_key, char(8)) = 0 AND instr(idempotency_key, char(9)) = 0 AND instr(idempotency_key, char(10)) = 0 AND instr(idempotency_key, char(11)) = 0 AND instr(idempotency_key, char(12)) = 0 AND instr(idempotency_key, char(13)) = 0 AND instr(idempotency_key, char(14)) = 0 AND instr(idempotency_key, char(15)) = 0 AND instr(idempotency_key, char(16)) = 0 AND instr(idempotency_key, char(17)) = 0 AND instr(idempotency_key, char(18)) = 0 AND instr(idempotency_key, char(19)) = 0 AND instr(idempotency_key, char(20)) = 0 AND instr(idempotency_key, char(21)) = 0 AND instr(idempotency_key, char(22)) = 0 AND instr(idempotency_key, char(23)) = 0 AND instr(idempotency_key, char(24)) = 0 AND instr(idempotency_key, char(25)) = 0 AND instr(idempotency_key, char(26)) = 0 AND instr(idempotency_key, char(27)) = 0 AND instr(idempotency_key, char(28)) = 0 AND instr(idempotency_key, char(29)) = 0 AND instr(idempotency_key, char(30)) = 0 AND instr(idempotency_key, char(31)) = 0 AND instr(idempotency_key, char(127)) = 0),
    expected_lifecycle_revision INTEGER NOT NULL CHECK(expected_lifecycle_revision > 0),
    expected_credential_fence INTEGER NOT NULL CHECK(expected_credential_fence > 0),
    allocated_credential_version INTEGER CHECK(allocated_credential_version > 0),
    allocated_ref_digest BLOB CHECK(allocated_ref_digest IS NULL OR length(allocated_ref_digest) = 32),
    state TEXT NOT NULL CHECK(state IN ('PREPARED', 'CLAIMED', 'NATIVE_EFFECT_OBSERVED', 'READBACK_VERIFIED', 'COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')),
    begin_proof_digest BLOB NOT NULL UNIQUE CHECK(length(begin_proof_digest) = 32),
    continuation_binding_digest BLOB CHECK(continuation_binding_digest IS NULL OR length(continuation_binding_digest) = 32),
    process_release_binding_digest BLOB CHECK(process_release_binding_digest IS NULL OR length(process_release_binding_digest) = 32),
    native_effect_disposition TEXT CHECK(native_effect_disposition IS NULL OR length(CAST(native_effect_disposition AS BLOB)) BETWEEN 1 AND 64),
    readback_observation_digest BLOB CHECK(readback_observation_digest IS NULL OR length(readback_observation_digest) = 32),
    terminal_disposition TEXT CHECK(terminal_disposition IS NULL OR length(CAST(terminal_disposition AS BLOB)) BETWEEN 1 AND 64),
    migration_id BLOB CHECK(migration_id IS NULL OR length(migration_id) = 16),
    migration_phase TEXT CHECK(migration_phase IS NULL OR migration_phase IN ('EFFECT', 'VERIFY')),
    migration_old_tuple_digest BLOB CHECK(migration_old_tuple_digest IS NULL OR length(migration_old_tuple_digest) = 32),
    migration_new_tuple_digest BLOB CHECK(migration_new_tuple_digest IS NULL OR length(migration_new_tuple_digest) = 32),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
    tombstone_digest BLOB CHECK(tombstone_digest IS NULL OR length(tombstone_digest) = 32),
    CHECK((allocated_credential_version IS NULL) = (allocated_ref_digest IS NULL)),
    CHECK((action = 'WRITER_IDENTITY_MIGRATION_EFFECT' AND migration_id IS NOT NULL AND migration_phase = 'EFFECT' AND migration_old_tuple_digest IS NOT NULL AND migration_new_tuple_digest IS NOT NULL) OR (action = 'WRITER_IDENTITY_MIGRATION_VERIFY' AND migration_id IS NOT NULL AND migration_phase = 'VERIFY' AND migration_old_tuple_digest IS NOT NULL AND migration_new_tuple_digest IS NOT NULL) OR (action NOT IN ('WRITER_IDENTITY_MIGRATION_EFFECT', 'WRITER_IDENTITY_MIGRATION_VERIFY') AND migration_id IS NULL AND migration_phase IS NULL AND migration_old_tuple_digest IS NULL AND migration_new_tuple_digest IS NULL)),
    CHECK((state = 'TOMBSTONED') = (tombstone_digest IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX provider_credential_one_non_terminal_operation
    ON provider_credential_operations(provider_id)
    WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED');
CREATE TABLE provider_credential_ticket_attempts (
    operation_id BLOB NOT NULL REFERENCES provider_credential_operations(operation_id),
    attempt INTEGER NOT NULL CHECK(attempt > 0),
    ticket_digest BLOB NOT NULL UNIQUE CHECK(length(ticket_digest) = 32),
    continuation_binding_digest BLOB NOT NULL UNIQUE CHECK(length(continuation_binding_digest) = 32),
    issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
    state TEXT NOT NULL CHECK(state IN ('ISSUED', 'CLAIMED', 'EXPIRED', 'TOMBSTONED')),
    terminal_digest BLOB CHECK(terminal_digest IS NULL OR length(terminal_digest) = 32),
    PRIMARY KEY(operation_id, attempt),
    CHECK((state = 'TOMBSTONED') = (terminal_digest IS NOT NULL))
) STRICT;
CREATE TABLE provider_credential_authority_heads (
    provider_id TEXT PRIMARY KEY CHECK(typeof(provider_id) = 'text' AND length(CAST(provider_id AS BLOB)) = length(provider_id) AND length(CAST(provider_id AS BLOB)) BETWEEN 1 AND 128 AND provider_id NOT GLOB '*[^!-~]*'),
    lifecycle_revision INTEGER NOT NULL CHECK(lifecycle_revision > 0),
    credential_fence INTEGER NOT NULL CHECK(credential_fence > 0),
    readiness_revision INTEGER NOT NULL CHECK(readiness_revision > 0),
    next_credential_version INTEGER NOT NULL CHECK(next_credential_version > 0),
    active_credential_version INTEGER,
    active_ref_digest BLOB CHECK(active_ref_digest IS NULL OR length(active_ref_digest) = 32),
    hard_fence_disposition TEXT CHECK(hard_fence_disposition IS NULL OR hard_fence_disposition = 'INVARIANT_FAILURE'),
    hard_fence_diagnostic_digest BLOB CHECK(hard_fence_diagnostic_digest IS NULL OR length(hard_fence_diagnostic_digest) = 32),
    legacy_import_consumed INTEGER NOT NULL DEFAULT 0 CHECK(legacy_import_consumed IN (0, 1)),
    legacy_source_binding_digest BLOB CHECK(legacy_source_binding_digest IS NULL OR length(legacy_source_binding_digest) = 32),
    legacy_consumed_lifecycle_revision INTEGER,
    legacy_cleanup_operation_id BLOB CHECK(legacy_cleanup_operation_id IS NULL OR length(legacy_cleanup_operation_id) = 16),
    observed_at_high_water INTEGER NOT NULL DEFAULT 0 CHECK(observed_at_high_water >= 0),
    pre_v24_quarantine_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000' CHECK(length(pre_v24_quarantine_digest) = 32),
    pre_v24_quarantine_count INTEGER NOT NULL DEFAULT 0 CHECK(pre_v24_quarantine_count >= 0),
    release_migration_fence INTEGER NOT NULL DEFAULT 0 CHECK(release_migration_fence >= 0),
    release_migration_binding_digest BLOB CHECK(release_migration_binding_digest IS NULL OR length(release_migration_binding_digest) = 32),
    release_migration_operation_id BLOB CHECK(release_migration_operation_id IS NULL OR length(release_migration_operation_id) = 16),
    release_migration_state TEXT NOT NULL DEFAULT 'NONE' CHECK(release_migration_state IN ('NONE', 'PENDING', 'VERIFIED', 'CLEARED')),
    FOREIGN KEY(legacy_cleanup_operation_id) REFERENCES provider_credential_operations(operation_id),
    FOREIGN KEY(release_migration_operation_id) REFERENCES provider_credential_operations(operation_id),
    CHECK((active_credential_version IS NULL) = (active_ref_digest IS NULL)),
    CHECK(active_credential_version IS NULL OR (active_credential_version > 0 AND active_credential_version < next_credential_version)),
    CHECK((hard_fence_disposition IS NULL) = (hard_fence_diagnostic_digest IS NULL)),
    CHECK((legacy_import_consumed = 0 AND legacy_source_binding_digest IS NULL AND legacy_consumed_lifecycle_revision IS NULL AND legacy_cleanup_operation_id IS NULL) OR (legacy_import_consumed = 1 AND legacy_source_binding_digest IS NOT NULL AND legacy_consumed_lifecycle_revision IS NOT NULL AND legacy_cleanup_operation_id IS NOT NULL)),
    CHECK(legacy_consumed_lifecycle_revision IS NULL OR legacy_consumed_lifecycle_revision > 0),
    CHECK((release_migration_state = 'NONE' AND release_migration_fence = 0 AND release_migration_binding_digest IS NULL AND release_migration_operation_id IS NULL) OR (release_migration_state IN ('PENDING', 'VERIFIED', 'CLEARED') AND release_migration_fence > 0 AND release_migration_binding_digest IS NOT NULL AND release_migration_operation_id IS NOT NULL))
) STRICT;
CREATE TABLE provider_credential_readiness_observations (
    observation_id BLOB PRIMARY KEY CHECK(length(observation_id) = 16),
    provider_id TEXT NOT NULL REFERENCES provider_credential_authority_heads(provider_id),
    lifecycle_revision INTEGER NOT NULL CHECK(lifecycle_revision > 0),
    readiness_revision INTEGER NOT NULL CHECK(readiness_revision > 0),
    disposition TEXT NOT NULL CHECK(disposition IN ('READY', 'MISSING', 'STALE', 'UNAVAILABLE', 'UNSUPPORTED', 'ACCESS_DENIED', 'CONFLICT', 'INVARIANT_FAILURE')),
    active_binding_digest BLOB CHECK(active_binding_digest IS NULL OR length(active_binding_digest) = 32),
    release_tuple_digest BLOB NOT NULL CHECK(length(release_tuple_digest) = 32),
    observed_at INTEGER NOT NULL CHECK(observed_at >= 0),
    operation_id BLOB REFERENCES provider_credential_operations(operation_id),
    UNIQUE(provider_id, readiness_revision)
) STRICT;
CREATE TABLE provider_credential_verification_observations (
    observation_id BLOB PRIMARY KEY CHECK(length(observation_id) = 16),
    provider_id TEXT NOT NULL REFERENCES provider_credential_authority_heads(provider_id),
    verification_kind TEXT NOT NULL CHECK(verification_kind IN ('LOCAL', 'REMOTE')),
    lifecycle_revision INTEGER NOT NULL CHECK(lifecycle_revision > 0),
    credential_fence INTEGER NOT NULL CHECK(credential_fence > 0),
    state TEXT NOT NULL CHECK(state IN ('LEASED', 'COMPLETED')),
    result TEXT CHECK(result IS NULL OR result IN ('VERIFIED', 'FAILED', 'UNSUPPORTED', 'UNAVAILABLE', 'ACCESS_DENIED', 'CONFLICT')),
    intent_proof_digest BLOB NOT NULL UNIQUE CHECK(length(intent_proof_digest) = 32),
    proof_consumed INTEGER NOT NULL CHECK(proof_consumed IN (0, 1)),
    verifier_revision INTEGER NOT NULL CHECK(verifier_revision > 0),
    started_at INTEGER NOT NULL CHECK(started_at >= 0),
    expires_at_high_water INTEGER NOT NULL CHECK(expires_at_high_water > started_at),
    observed_at INTEGER CHECK(observed_at IS NULL OR observed_at >= started_at),
    operation_id BLOB REFERENCES provider_credential_operations(operation_id),
    CHECK((state = 'LEASED') = (result IS NULL AND observed_at IS NULL))
) STRICT;
"#;

pub(super) fn apply_v24_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V24)?;
    for legacy in legacy_provider_heads(&transaction)? {
        transaction.execute(
            "INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version, pre_v24_quarantine_digest, pre_v24_quarantine_count) VALUES (?1, 1, 1, 1, ?2, ?3, ?4)",
            rusqlite::params![legacy.provider_id, legacy.next_version, legacy.digest, legacy.count],
        )?;
    }
    install_missing_v12_fence_triggers(&transaction)?;
    install_v24_triggers(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (24)", [])?;
    transaction.commit()
}

struct LegacyProviderHead {
    provider_id: String,
    next_version: i64,
    digest: Vec<u8>,
    count: i64,
}

fn legacy_provider_heads(transaction: &Transaction<'_>) -> SqliteResult<Vec<LegacyProviderHead>> {
    let mut statement = transaction.prepare("SELECT provider_id, credential_version, ref_digest FROM provider_credential_versions ORDER BY provider_id, credential_version")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    let mut heads = Vec::new();
    let mut current: Option<(String, i64, i64, Sha256)> = None;
    for (provider_id, version, ref_digest) in rows {
        match current.as_mut() {
            Some((provider, maximum, count, digest)) if *provider == provider_id => {
                *maximum = (*maximum).max(version);
                *count += 1;
                digest.update(version.to_be_bytes());
                digest.update(ref_digest);
            }
            _ => {
                if let Some((provider, maximum, count, digest)) = current.take() {
                    heads.push(LegacyProviderHead {
                        provider_id: provider,
                        next_version: maximum
                            .checked_add(1)
                            .ok_or(rusqlite::Error::InvalidQuery)?,
                        digest: digest.finalize().to_vec(),
                        count,
                    });
                }
                let mut digest = Sha256::new();
                digest.update(b"runne-provider-credential-v24-quarantine\\0");
                digest.update(provider_id.as_bytes());
                digest.update(version.to_be_bytes());
                digest.update(ref_digest);
                current = Some((provider_id, version, 1, digest));
            }
        }
    }
    if let Some((provider, maximum, count, digest)) = current {
        heads.push(LegacyProviderHead {
            provider_id: provider,
            next_version: maximum
                .checked_add(1)
                .ok_or(rusqlite::Error::InvalidQuery)?,
            digest: digest.finalize().to_vec(),
            count,
        });
    }
    Ok(heads)
}
