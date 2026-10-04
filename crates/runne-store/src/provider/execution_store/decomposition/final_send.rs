impl SqliteProviderExecutionStore {
    /// Revalidates legacy authority and returns a receipt with a final-send gate.
    pub fn start_effect(
        &self,
        claim: &ProviderDispatchClaim,
        credential: &crate::provider::CredentialDispatchBinding,
    ) -> Result<ProviderEffectStartReceipt, ProviderAdmissionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let mut receipt = start_effect(
            &mut connection,
            claim,
            credential,
            || self.now(),
            || {
                #[cfg(test)]
                if let Some((reached, release)) = self.effect_receipt_pause.lock().unwrap().take() {
                    reached.wait();
                    release.wait();
                }
            },
            {
                #[cfg(test)]
                {
                    self.fail_effect_readback.swap(false, Ordering::SeqCst)
                }
                #[cfg(not(test))]
                {
                    false
                }
            },
        )?;
        let database = Arc::clone(&self.connection);
        let claim = claim.clone();
        let credential = credential.clone();
        let now = Arc::clone(&self.now);
        receipt.install_final_send_authority(crate::provider::ProviderFinalSendAuthority::new(
            move || {
                let mut connection = database
                    .lock()
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                let observed = now();
                crate::provider::credential_lifecycle::advance_provider_clock(
                    &transaction,
                    credential.version_ref().provider(),
                    observed,
                )
                .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
                crate::store::taskrun_provider_start::verify_admitted_running_attempt(
                    &transaction,
                    claim.attempt_id.as_bytes(),
                )
                .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
                crate::provider::effect_start::verify_legacy_final_send(
                    &transaction,
                    &claim,
                    &credential,
                    observed,
                )?;
                let current_revision: bool = transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions admission
                 JOIN provider_runtime_authority_state runtime ON runtime.id=1
                 WHERE admission.dispatch_attempt_id=?1 AND admission.permit_id=?2
                   AND admission.provider_idempotency_key=?3
                   AND runtime.state_revision=admission.authority_revision)",
                        rusqlite::params![
                            claim.attempt_id.as_bytes().as_slice(),
                            claim.permit_id.as_slice(),
                            claim.provider_idempotency_key
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                let binding_matches: bool = transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM provider_credential_effect_bindings binding
                 JOIN provider_effect_starts effect USING(dispatch_attempt_id)
                 WHERE binding.dispatch_attempt_id=?1 AND binding.provider_id=?2
                   AND binding.credential_version=?3 AND binding.ref_digest=?4
                   AND binding.lease_owner=?5 AND binding.lease_expires_at=?6
                   AND binding.lease_fencing_token=?7
                   AND effect.provider_idempotency_key=?8 AND effect.permit_id=?9
                   AND effect.state=1 AND effect.effect_expires_at>?10)",
                        rusqlite::params![
                            claim.attempt_id.as_bytes().as_slice(),
                            credential.version_ref().provider().as_str(),
                            i64::try_from(credential.version_ref().version())
                                .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                            credential.version_ref().ref_digest().as_slice(),
                            credential.owner().as_slice(),
                            credential.expires_at(),
                            i64::try_from(credential.fencing_token())
                                .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                            claim.provider_idempotency_key,
                            claim.permit_id.as_slice(),
                            observed,
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
                if !current_revision || !binding_matches {
                    return Err(ProviderAdmissionError::AuthorityDenied);
                }
                transaction
                    .commit()
                    .map_err(|_| ProviderAdmissionError::RepositoryFailure)
            },
        ));
        Ok(receipt)
    }
}
