impl SqliteProviderCredentialLifecycleStore {
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
        provider: &gocode_provider::ProviderId,
        owner: [u8; 16],
        fencing_token: u64,
        now: i64,
    ) -> Result<CredentialDispatchBinding, CredentialLifecycleError> {
        if now < 0 || owner == [0; 16] || fencing_token == 0 {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        let connection = self.connection.lock().map_err(map_lock)?;
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
