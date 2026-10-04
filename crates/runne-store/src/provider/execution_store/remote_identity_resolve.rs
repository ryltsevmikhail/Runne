impl SqliteProviderExecutionStore {
    /// Resolves a full remote-attempt identity from the exact claimed
    /// admission, current effect/credential bindings, and applicable profile
    /// authorization (primary binding or secondary grant).
    pub fn resolve_remote_attempt_binding(
        &self,
        claim: &ProviderDispatchClaim,
        expected_provider: &runne_provider::ProviderId,
        expected_credential_realm: &runne_provider::ProviderId,
        expected_profile_id: &str,
    ) -> Result<ProviderRemoteAttemptBinding, ProviderExecutionError> {
        if claim.provider_id != *expected_provider
            || expected_profile_id.is_empty()
            || expected_profile_id.len() > 128
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let row = tx
            .query_row(
                "SELECT a.taskrun_id,a.execution_attempt_id,a.semantic_digest,
                        a.pricing_revision_digest,a.runtime_authority_id,
                        a.database_generation,a.generation,a.fencing_token,
                        a.profile_digest,a.prepared_digest,a.render_digest,
                        p.provider_id,c.provider_id,g.profile_id,a.call_id,a.permit_id,
                        a.token_reservation_id,a.cost_reservation_id,a.provider_idempotency_key
                 FROM provider_execution_admissions a
                 JOIN provider_online_dispatch_claim_providers p USING(dispatch_attempt_id)
                 JOIN provider_online_credential_effect_bindings c USING(dispatch_attempt_id)
                 LEFT JOIN provider_secondary_profile_attempts s USING(dispatch_attempt_id)
                 LEFT JOIN provider_secondary_profile_grants g USING(grant_id)
                 WHERE a.dispatch_attempt_id=?1 AND a.prepared_digest=?2
                   AND a.render_digest=?3 AND a.profile_digest=?4
                   AND p.provider_id=?5 AND c.provider_id=?6
                   AND (g.profile_id=?7 OR (s.dispatch_attempt_id IS NULL
                        AND ?5=?6 AND ?5<>'openai-background'))",
                rusqlite::params![
                    claim.attempt_id.as_bytes().as_slice(),
                    claim.prepared_digest.as_slice(),
                    claim.render_digest.as_slice(),
                    claim.profile_digest.as_slice(),
                    expected_provider.as_str(),
                    expected_credential_realm.as_str(),
                    expected_profile_id,
                ],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, i64>(7)?,
                        r.get::<_, Vec<u8>>(8)?,
                        r.get::<_, Vec<u8>>(9)?,
                        r.get::<_, Vec<u8>>(10)?,
                        r.get::<_, String>(11)?,
                        r.get::<_, String>(12)?,
                        r.get::<_, Option<String>>(13)?,
                        r.get::<_, Vec<u8>>(14)?,
                        r.get::<_, Vec<u8>>(15)?,
                        r.get::<_, Vec<u8>>(16)?,
                        r.get::<_, Vec<u8>>(17)?,
                        r.get::<_, String>(18)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .ok_or(ProviderExecutionError::TerminalConflict)?;
        let bytes16 = |value: &[u8]| {
            <[u8; 16]>::try_from(value).map_err(|_| ProviderExecutionError::JournalCorrupt)
        };
        let bytes32 = |value: &[u8]| {
            <[u8; 32]>::try_from(value).map_err(|_| ProviderExecutionError::JournalCorrupt)
        };
        if bytes16(&row.14)? != *claim.call_id.as_bytes()
            || bytes16(&row.15)? != claim.permit_id
            || bytes16(&row.16)? != claim.token_reservation_id
            || bytes16(&row.17)? != claim.cost_reservation_id
            || row.18 != claim.provider_idempotency_key
            || positive_u64(row.7).map_err(|_| ProviderExecutionError::JournalCorrupt)?
                != claim.fencing_token
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let binding = runne_application::provider::ProviderRemoteAttemptBinding {
            taskrun_id: TaskRunId::from_bytes(bytes16(&row.0)?),
            taskrun_attempt_id: AttemptId::from_bytes(bytes16(&row.1)?),
            dispatch_attempt_id: claim.attempt_id,
            provider_id: row.11,
            credential_realm: row.12,
            profile_id: row.13.unwrap_or_else(|| expected_profile_id.to_owned()),
            profile_digest: bytes32(&row.8)?,
            pricing_digest: bytes32(&row.3)?,
            semantic_digest: bytes32(&row.2)?,
            prepared_digest: bytes32(&row.9)?,
            request_digest: bytes32(&row.10)?,
            runtime_authority_id: bytes16(&row.4)?,
            database_generation: positive_u64(row.5)
                .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
            runtime_generation: positive_u64(row.6)
                .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
            fencing_token: positive_u64(row.7)
                .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        };
        let key = load_active_journal_key(&tx)?
            .ok_or(ProviderExecutionError::JournalKeyUnavailable)?
            .binding;
        validate_current_remote_binding(&tx, &binding, key, (self.now)())?;
        if binding.provider_id != expected_provider.as_str()
            || binding.credential_realm != expected_credential_realm.as_str()
            || binding.profile_id != expected_profile_id
            || binding.profile_digest != claim.profile_digest
            || binding.prepared_digest != claim.prepared_digest
            || binding.request_digest != claim.render_digest
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        tx.commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        Ok(binding)
    }
}
