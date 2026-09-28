use crate::{LocalStore, SecurityAnchorV1, SecurityStateError, TransactionBehavior};
use runne_secure_store::SecureStore;

impl LocalStore {
    pub(crate) fn install_security_root(
        &mut self,
        anchor: &SecurityAnchorV1,
    ) -> Result<(), SecurityStateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(&format!(
            "DROP TABLE mutation_ledger; {}; {}; {}; {}; PRAGMA user_version=9;",
            crate::security_schema_v7::LEDGER_SQL,
            crate::security_schema_v6::TRANSACTIONS_SQL,
            crate::security_schema_v6::PROFILE_SQL,
            crate::security_schema_v8::SHADOW_TABLES_SQL,
        ))?;
        transaction.execute(
            "INSERT INTO security_profile VALUES (1, ?1, ?2)",
            rusqlite::params![
                anchor.profile_identity_digest.to_vec(),
                anchor.database_identity.to_vec()
            ],
        )?;
        transaction.execute(
            "INSERT INTO security_transactions VALUES (?1, ?2, ?3, ?4, 1)",
            rusqlite::params![
                1_i64,
                anchor.transaction_digest.to_vec(),
                anchor.previous_anchor_digest.to_vec(),
                anchor.sealed_transaction.as_bytes()
            ],
        )?;
        transaction.execute("UPDATE meta SET schema_version=9,last_transaction_digest=?1,commit_marker=1 WHERE singleton=1", [hex(&anchor.transaction_digest)])?;
        transaction.commit()?;
        Ok(())
    }
    pub(crate) fn install_v7_migration(
        &mut self,
        secure: &dyn SecureStore,
        lock: &runne_secure_store::SecurityProfileLock<'_>,
        profile: [u8; 32],
        database: [u8; 32],
        generation: u64,
        previous: [u8; 32],
    ) -> Result<SecurityAnchorV1, SecurityStateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(&format!(
            "DROP TABLE mutation_ledger; {}; {}; {}; PRAGMA user_version=7;",
            crate::security_schema_v7::LEDGER_SQL,
            crate::security_schema_v6::TRANSACTIONS_SQL,
            crate::security_schema_v6::PROFILE_SQL
        ))?;
        transaction.execute(
            "INSERT INTO security_profile VALUES (1, ?1, ?2)",
            rusqlite::params![profile.to_vec(), database.to_vec()],
        )?;
        let digest = crate::security_state_root::protected_state_root(&transaction)?;
        let seal =
            secure.seal_security_transaction(lock, database, generation, digest, previous)?;
        let anchor = SecurityAnchorV1::new(profile, database, generation, digest, previous, seal)?;
        transaction.execute(
            "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
            rusqlite::params![
                i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?,
                anchor.transaction_digest.to_vec(),
                anchor.previous_anchor_digest.to_vec(),
                anchor.sealed_transaction.as_bytes()
            ],
        )?;
        transaction.execute("UPDATE meta SET schema_version=7,db_generation=?1,last_transaction_digest=?2,commit_marker=1 WHERE singleton=1", rusqlite::params![i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?,hex(&anchor.transaction_digest)])?;
        transaction.commit()?;
        Ok(anchor)
    }

    pub(crate) fn migrate_v6_ledger(
        &mut self,
        secure: &dyn SecureStore,
        lock: &runne_secure_store::SecurityProfileLock<'_>,
        profile: [u8; 32],
        database: [u8; 32],
        previous: &SecurityAnchorV1,
    ) -> Result<SecurityAnchorV1, SecurityStateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(&format!(
            "ALTER TABLE mutation_ledger RENAME TO mutation_ledger_v6; {}; INSERT INTO mutation_ledger (runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest,normalized_command,canonical_outcome,resend_count,client_disposition,runtime_disposition,command_ref,outcome_ref,recovery_summary,created_at,updated_at) SELECT runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest,NULL,NULL,0,'manual_resolution','indeterminate',NULL,NULL,'v6_unrecoverable',created_at,updated_at FROM mutation_ledger_v6; DROP TABLE mutation_ledger_v6; PRAGMA user_version=7;",
            crate::security_schema_v7::LEDGER_SQL
        ))?;
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(SecurityStateError::InvalidTransition)?;
        let digest = crate::security_state_root::protected_state_root(&transaction)?;
        let seal = secure.seal_security_transaction(
            lock,
            database,
            generation,
            digest,
            previous.digest(),
        )?;
        let anchor = SecurityAnchorV1::new(
            profile,
            database,
            generation,
            digest,
            previous.digest(),
            seal,
        )?;
        transaction.execute(
            "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
            rusqlite::params![
                i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?,
                anchor.transaction_digest.to_vec(),
                anchor.previous_anchor_digest.to_vec(),
                anchor.sealed_transaction.as_bytes()
            ],
        )?;
        transaction.execute("UPDATE meta SET schema_version=7,db_generation=?1,last_transaction_digest=?2,commit_marker=1 WHERE singleton=1", rusqlite::params![i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?, hex(&anchor.transaction_digest)])?;
        transaction.commit()?;
        Ok(anchor)
    }

    pub(crate) fn migrate_v7_to_v8(
        &mut self,
        secure: &dyn SecureStore,
        lock: &runne_secure_store::SecurityProfileLock<'_>,
        previous: &SecurityAnchorV1,
    ) -> Result<SecurityAnchorV1, SecurityStateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authenticate_v7_migration_source(&transaction, secure, lock, previous)?;
        let scopes = transaction
            .prepare("SELECT runtime_authority,principal,lineage,scope,binding_digest FROM replay_cursors")?
            .query_map([], |row| {
                Ok(crate::ReplayScopeKey {
                    runtime_authority: row.get(0)?, principal: row.get(1)?,
                    lineage: row.get(2)?, scope: row.get(3)?, binding_digest: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let distinct_scopes: i64 = transaction.query_row("SELECT COUNT(*) FROM (SELECT runtime_authority,principal,lineage,scope FROM replay_cursors UNION SELECT runtime_authority,principal,lineage,scope FROM projections UNION SELECT runtime_authority,principal,lineage,scope FROM event_journal)", [], |row| row.get(0))?;
        if usize::try_from(distinct_scopes).ok() != Some(scopes.len())
            || scopes.iter().any(|scope| {
                crate::read_replay_state(&transaction, scope)
                    .ok()
                    .flatten()
                    .is_none()
            })
        {
            return Err(SecurityStateError::AdmissionFailed);
        }
        transaction.execute_batch(crate::security_schema_v8::SHADOW_TABLES_SQL)?;
        transaction.execute("INSERT INTO replay_active_generations(runtime_authority,principal,lineage,scope,selector,shadow_id) SELECT runtime_authority,principal,lineage,scope,'legacy',NULL FROM replay_cursors", [])?;
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(SecurityStateError::InvalidTransition)?;
        transaction.execute(
            "UPDATE meta SET schema_version=8,db_generation=?1,commit_marker=1 WHERE singleton=1",
            [i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?],
        )?;
        transaction.pragma_update(None, "user_version", 8_i64)?;
        let digest = crate::security_state_root::protected_state_root(&transaction)?;
        let seal = secure.seal_security_transaction(
            lock,
            previous.database_identity,
            generation,
            digest,
            previous.digest(),
        )?;
        let anchor = SecurityAnchorV1::new(
            previous.profile_identity_digest,
            previous.database_identity,
            generation,
            digest,
            previous.digest(),
            seal,
        )?;
        transaction.execute(
            "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
            rusqlite::params![
                i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?,
                anchor.transaction_digest.to_vec(),
                anchor.previous_anchor_digest.to_vec(),
                anchor.sealed_transaction.as_bytes()
            ],
        )?;
        transaction.execute(
            "UPDATE meta SET last_transaction_digest=?1 WHERE singleton=1",
            [hex(&anchor.transaction_digest)],
        )?;
        transaction.commit()?;
        Ok(anchor)
    }
}

fn authenticate_v7_migration_source(
    transaction: &rusqlite::Transaction<'_>,
    secure: &dyn SecureStore,
    lock: &runne_secure_store::SecurityProfileLock<'_>,
    previous: &SecurityAnchorV1,
) -> Result<(), SecurityStateError> {
    crate::security_schema_v7::validate_v7_schema(transaction)?;
    let bound: (Vec<u8>, Vec<u8>) = transaction.query_row(
        "SELECT profile_identity_digest,database_identity FROM security_profile WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (generation, digest): (i64, String) = transaction.query_row(
        "SELECT db_generation,last_transaction_digest FROM meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let persisted = crate::security_recovery::verify_persisted_anchor_chain(
        transaction,
        secure,
        lock,
        previous.profile_identity_digest,
        previous.database_identity,
    )?;
    if bound
        != (
            previous.profile_identity_digest.to_vec(),
            previous.database_identity.to_vec(),
        )
        || u64::try_from(generation).ok() != Some(previous.generation)
        || digest != hex(&previous.transaction_digest)
        || persisted != *previous
    {
        return Err(SecurityStateError::AnchorMismatch);
    }
    Ok(())
}

fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
