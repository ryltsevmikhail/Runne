type OnlineDispatchRow = (i64, i64, i64, Vec<u8>, String, Vec<u8>, i64, i64, i64, i64);

impl SqliteProviderCredentialLifecycleStore {
    /// Resolves the authority-head-selected online version at dispatch time.
    /// The compatibility mirror is accepted only as its exact native locator.
    pub(crate) fn authorize_online_dispatch(
        &self,
        launch: &crate::provider::ProviderRuntimeLaunchCapability,
        claim: &runne_provider::ProviderDispatchClaim,
        now: i64,
    ) -> Result<crate::provider::OnlineCredentialDispatchBinding, CredentialLifecycleError> {
        if now < 0 {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        #[cfg(test)]
        if let Some((reached, release)) = self
            .before_online_authorization_pause
            .lock()
            .map_err(map_lock)?
            .take()
        {
            reached.wait();
            release.wait();
        }
        let mut connection = self.connection.lock().map_err(map_lock)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        launch
            .verify_current_admission(&transaction, claim)
            .map_err(|error| match error {
                runne_application::provider::ProviderAdmissionError::StaleFencingToken => {
                    CredentialLifecycleError::StaleLease
                }
                runne_application::provider::ProviderAdmissionError::RepositoryFailure => {
                    CredentialLifecycleError::StoreUnavailable
                }
                _ => CredentialLifecycleError::CorruptState,
            })?;
        let row: Option<OnlineDispatchRow> = transaction
            .query_row(
                "SELECT h.lifecycle_revision, h.credential_fence, h.active_credential_version,
                        h.active_ref_digest, v.lifecycle_state, v.lease_owner,
                        v.lease_expires_at, v.lease_fencing_token, v.revocation_fence,
                        admission.generation
                   FROM provider_credential_authority_heads h
                   JOIN provider_credential_versions v ON v.provider_id=h.provider_id
                     AND v.credential_version=h.active_credential_version AND v.ref_digest=h.active_ref_digest
                   JOIN provider_online_dispatch_claim_providers claim_provider
                     ON claim_provider.provider_id=h.provider_id
                   JOIN provider_execution_admissions admission
                     ON admission.dispatch_attempt_id=claim_provider.dispatch_attempt_id
                   JOIN provider_runtime_authority_state runtime ON runtime.id=1
                  WHERE h.provider_id=?1 AND h.active_credential_version IS NOT NULL
                    AND h.hard_fence_disposition IS NULL
                    AND h.release_migration_state IN ('NONE', 'CLEARED')
                    AND admission.dispatch_attempt_id=?2 AND admission.permit_id=?3
                    AND admission.provider_idempotency_key=?4 AND admission.prepared_digest=?5
                    AND admission.render_digest=?6 AND admission.profile_digest=?7
                    AND admission.fencing_token=?8 AND admission.token_reservation_id=?9
                    AND admission.cost_reservation_id=?10
                    AND runtime.active=1 AND runtime.expected_generation=runtime.lease_generation
                    AND runtime.expected_fencing_token=runtime.lease_fencing_token
                    AND runtime.expected_generation=admission.generation
                    AND runtime.expected_fencing_token=admission.fencing_token",
                rusqlite::params![
                    claim.provider_id.as_str(), claim.attempt_id.as_bytes().as_slice(),
                    claim.permit_id.as_slice(), claim.provider_idempotency_key,
                    claim.prepared_digest.as_slice(), claim.render_digest.as_slice(),
                    claim.profile_digest.as_slice(), to_i64(claim.fencing_token)?,
                    claim.token_reservation_id.as_slice(), claim.cost_reservation_id.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?)),
            )
            .optional()
            .map_err(map_sql)?;
        let Some((
            lifecycle,
            fence,
            version,
            digest,
            state,
            owner,
            expires,
            lease_fence,
            revoked,
            generation,
        )) = row
        else {
            return Err(CredentialLifecycleError::StaleLease);
        };
        let (lifecycle, fence, version, lease_fence, generation) = (
            positive(lifecycle)?,
            positive(fence)?,
            positive(version)?,
            positive(lease_fence)?,
            positive(generation)?,
        );
        if state != "ACTIVE"
            || owner.as_slice() != b"RUNNE_V24_MIRROR"
            || expires <= now
            || revoked
                >= i64::try_from(lease_fence).map_err(|_| CredentialLifecycleError::CorruptState)?
        {
            return Err(CredentialLifecycleError::StaleLease);
        }
        let active = runne_provider::CredentialVersionRef::new(claim.provider_id.clone(), version)?;
        if digest.as_slice() != active.ref_digest() {
            return Err(CredentialLifecycleError::CorruptState);
        }
        let lease = CredentialLease::new(active, *b"RUNNE_V24_MIRROR", expires, lease_fence)?;
        let binding = CredentialDispatchBinding::from_authoritative_capability(
            self.authority.issue_dispatch(lease),
        );
        transaction.commit().map_err(map_sql)?;
        Ok(crate::provider::OnlineCredentialDispatchBinding::new(
            binding, lifecycle, fence, generation,
        ))
    }

    #[cfg(test)]
    pub(crate) fn pause_before_online_authorization(
        &self,
    ) -> (Arc<Barrier>, Arc<Barrier>) {
        let reached = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        *self.before_online_authorization_pause.lock().unwrap() =
            Some((Arc::clone(&reached), Arc::clone(&release)));
        (reached, release)
    }

    /// Produces a dispatch binding only while the exact lease remains active.
    pub fn authorize_dispatch(
        &self,
        lease: &CredentialLease,
        now: i64,
    ) -> Result<CredentialDispatchBinding, CredentialLifecycleError> {
        if now < 0 {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        let connection = self.connection.lock().map_err(map_lock)?;
        rows::validate_dispatch_head(&connection, lease.version_ref().provider())?;
        let row = load_row(&connection, lease.version_ref())?
            .ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, lease.version_ref())?;
        if row.state != CredentialVersionState::Active
            || row.lease_owner.as_deref() != Some(lease.owner().as_slice())
            || row.lease_expires_at != Some(lease.expires_at())
            || row.lease_fencing_token != Some(to_i64(lease.fencing_token())?)
            || lease.expires_at() <= now
            || row.revocation_fence >= to_i64(lease.fencing_token())?
        {
            return Err(CredentialLifecycleError::StaleLease);
        }
        Ok(CredentialDispatchBinding::from_authoritative_capability(
            self.authority.issue_dispatch(lease.clone()),
        ))
    }

    /// Selects the sole active provider version and binds its exact authority.
    pub fn authorize_active(
        &self,
        provider: &runne_provider::ProviderId,
        owner: [u8; 16],
        fencing_token: u64,
        now: i64,
    ) -> Result<CredentialDispatchBinding, CredentialLifecycleError> {
        if now < 0 || owner == [0; 16] || fencing_token == 0 {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        let connection = self.connection.lock().map_err(map_lock)?;
        rows::validate_dispatch_head(&connection, provider)?;
        let (row, reference) =
            load_active_row(&connection, provider)?.ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, &reference)?;
        if row.lease_owner.as_deref() != Some(owner.as_slice())
            || row.lease_expires_at.is_none_or(|expiry| expiry <= now)
            || row.lease_fencing_token != Some(to_i64(fencing_token)?)
            || row.revocation_fence >= to_i64(fencing_token)?
        {
            return Err(CredentialLifecycleError::StaleLease);
        }
        let lease = CredentialLease::new(
            reference,
            owner,
            row.lease_expires_at
                .ok_or(CredentialLifecycleError::CorruptState)?,
            fencing_token,
        )?;
        Ok(CredentialDispatchBinding::from_authoritative_capability(
            self.authority.issue_dispatch(lease),
        ))
    }

    /// Revalidates a previously issued binding immediately before effect.
    pub fn validate_dispatch(
        &self,
        binding: &CredentialDispatchBinding,
        now: i64,
    ) -> Result<(), CredentialLifecycleError> {
        self.authorize_dispatch(binding.lease(), now).map(|_| ())
    }

    /// Marks a tombstone only after the caller completed native deletion.
    pub fn complete_native_delete(
        &self,
        proof: NativeCredentialDeletionProof,
    ) -> Result<(), CredentialLifecycleError> {
        let reference = self.authority.verify_deletion(&proof)?.clone();
        let digest = tombstone_digest(&reference);
        let _progression = self.authority.invalidate_native_create_claims()?;
        let mut connection = self.connection.lock().map_err(map_lock)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let row = load_row(&transaction, &reference)?.ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, &reference)?;
        match row.state {
            CredentialVersionState::GcClaimed => {
                let changed = transaction
                    .execute(
                        "UPDATE provider_credential_versions
                         SET lifecycle_state='DELETED', tombstone_digest=?1
                         WHERE provider_id=?2 AND credential_version=?3
                           AND lifecycle_state='GC_CLAIMED'",
                        params![
                            digest.as_slice(),
                            reference.provider().as_str(),
                            to_i64(reference.version())?
                        ],
                    )
                    .map_err(map_sql)?;
                if changed != 1 {
                    return Err(CredentialLifecycleError::Conflict);
                }
                transaction.commit().map_err(map_sql)
            }
            CredentialVersionState::Deleted if row.tombstone_digest.as_deref() == Some(&digest) => {
                transaction.commit().map_err(map_sql)
            }
            CredentialVersionState::Deleted => Err(CredentialLifecycleError::CorruptState),
            _ => Err(CredentialLifecycleError::LifecycleClosed),
        }
    }
}

fn positive(value: i64) -> Result<u64, CredentialLifecycleError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(CredentialLifecycleError::CorruptState)
}
