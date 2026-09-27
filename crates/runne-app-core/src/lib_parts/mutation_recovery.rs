impl AppCore {
    /// Recovers one bounded page of exact nonterminal v7 mutations.
    ///
    /// Recovered leases retain only durable normalized evidence. Callers must
    /// reconcile them; a bind without its move-only admission cannot resend.
    ///
    /// # Errors
    ///
    /// Returns a closed error for unavailable admission, noncanonical evidence,
    /// or a durable runtime identity mismatch.
    #[cfg(test)]
    async fn recover_anchored_mutations_v7(
        &self,
    ) -> Result<Vec<PreparedMutationLease>, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let client = self.live_runtime_client()?;
        let runtime_identity = replay::StableRuntimeIdentity::from_client(&client);
        let binding = self.mutation_binding_for(&runtime_identity);
        let security = self
            .mutation_security
            .as_ref()
            .ok_or(AppCoreError::MutationUnavailable)?;
        let recovery_binding = runne_local_store::MutationRecoveryBinding::new(
            binding.runtime_identity_digest,
            binding.principal_digest,
        )
        .map_err(|_| AppCoreError::MutationUnavailable)?;
        let evidence = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?
            .recover_anchored_mutations_v7(
                security.secure.as_ref(),
                recovery_binding,
                runne_local_store::MutationRecoveryLimit::new(
                    runne_local_store::MAX_MUTATION_RECOVERY_RECORDS,
                )
                .map_err(|_| AppCoreError::MutationUnavailable)?,
            )
            .map_err(|_| AppCoreError::MutationUnavailable)?;
        if evidence.has_more() {
            return Err(AppCoreError::MutationUnavailable);
        }
        evidence
            .records()
            .iter()
            .map(|value| self.recover_mutation_lease(value, &runtime_identity, binding))
            .collect()
    }

    async fn recover_anchored_mutations_v7_under_operation(&self) -> Result<(), AppCoreError> {
        crate::qualification_diagnostics::record(
            crate::qualification_diagnostics::Stage::RecoveryStarted,
        );
        let Some(security) = self.mutation_security.as_ref() else {
            crate::qualification_diagnostics::record(
                crate::qualification_diagnostics::Stage::RecoverySkippedNoSecurity,
            );
            return Ok(());
        };
        let client = match self.runtime_operation_context() {
            Ok(client) => client,
            Err(error) => {
                crate::qualification_diagnostics::record(
                    crate::qualification_diagnostics::Stage::RecoveryClientUnavailable,
                );
                return Err(error);
            }
        };
        let runtime_identity = client.identity.clone();
        let binding = self.mutation_binding_for(&runtime_identity);
        let Ok(recovery_binding) = runne_local_store::MutationRecoveryBinding::new(
            binding.runtime_identity_digest,
            binding.principal_digest,
        ) else {
            crate::qualification_diagnostics::record(
                crate::qualification_diagnostics::Stage::RecoveryBindingUnavailable,
            );
            return Err(AppCoreError::MutationUnavailable);
        };
        let evidence = match self.load_recovery_evidence(security, recovery_binding) {
            Ok(evidence) => evidence,
            Err(error) => return Err(error),
        };
        crate::qualification_diagnostics::record(
            crate::qualification_diagnostics::Stage::RecoveryEvidenceLoaded,
        );
        if evidence.has_more() {
            crate::qualification_diagnostics::record(
                crate::qualification_diagnostics::Stage::RecoveryEvidenceExhausted,
            );
            return Err(AppCoreError::MutationUnavailable);
        }
        for value in evidence.records() {
            let mut lease = self
                .recover_mutation_lease(value, &runtime_identity, binding)
                .inspect_err(|_| {
                    crate::qualification_diagnostics::record(
                        crate::qualification_diagnostics::Stage::RecoveryLeaseUnavailable,
                    );
                })?;
            crate::qualification_diagnostics::record(
                crate::qualification_diagnostics::Stage::RecoveryLeaseRecovered,
            );
            self.reconcile_recovered_lease(&mut lease).await?;
        }
        crate::qualification_diagnostics::record(
            crate::qualification_diagnostics::Stage::RecoveryComplete,
        );
        Ok(())
    }

    async fn reconcile_recovered_lease(
        &self,
        lease: &mut PreparedMutationLease,
    ) -> Result<(), AppCoreError> {
        if lease.anchored_record.disposition()
            == runne_local_store::ClientMutationDisposition::Prepared
        {
            self.close_manual_resolution(lease).inspect_err(|_| {
                crate::qualification_diagnostics::record(
                    crate::qualification_diagnostics::Stage::RecoveryLeaseUnavailable,
                );
            })?;
            crate::qualification_diagnostics::record(
                crate::qualification_diagnostics::Stage::RecoveryPreparedClosed,
            );
            return Ok(());
        }
        crate::qualification_diagnostics::record(
            crate::qualification_diagnostics::Stage::ReconcileStarted,
        );
        if let Err(error) = self
            .dispatch_prepared_mutation_under_operation(lease, None, false, false, true)
            .await
        {
            if matches!(
                lease.anchored_record.disposition(),
                runne_local_store::ClientMutationDisposition::CanonicalOutcome
                    | runne_local_store::ClientMutationDisposition::ManualResolution
            ) {
                crate::qualification_diagnostics::record(
                    crate::qualification_diagnostics::Stage::ReconcileFailedTerminal,
                );
                return Ok(());
            }
            crate::qualification_diagnostics::record(
                crate::qualification_diagnostics::Stage::ReconcileFailed,
            );
            return Err(error);
        }
        crate::qualification_diagnostics::record(
            crate::qualification_diagnostics::Stage::ReconcileComplete,
        );
        Ok(())
    }

    fn load_recovery_evidence(
        &self,
        security: &MutationSecurityContext,
        recovery_binding: runne_local_store::MutationRecoveryBinding,
    ) -> Result<runne_local_store::MutationRecoveryBatch, AppCoreError> {
        let Ok(mut store) = self.store.lock() else {
            crate::qualification_diagnostics::record(
                crate::qualification_diagnostics::Stage::RecoveryStoreUnavailable,
            );
            return Err(AppCoreError::StateUnavailable);
        };
        crate::qualification_diagnostics::record(
            crate::qualification_diagnostics::Stage::RecoveryStoreLocked,
        );
        let limit = runne_local_store::MutationRecoveryLimit::new(
            runne_local_store::MAX_MUTATION_RECOVERY_RECORDS,
        )
        .map_err(|_| AppCoreError::MutationUnavailable)?;
        let Ok(evidence) =
            store.recover_anchored_mutations_v7(security.secure.as_ref(), recovery_binding, limit)
        else {
            crate::qualification_diagnostics::record(
                crate::qualification_diagnostics::Stage::RecoveryEvidenceUnavailable,
            );
            return Err(AppCoreError::MutationUnavailable);
        };
        Ok(evidence)
    }

    fn recover_mutation_lease(
        &self,
        evidence: &runne_local_store::MutationRecoveryEvidence,
        runtime_identity: &replay::StableRuntimeIdentity,
        binding: MutationAdmissionBinding,
    ) -> Result<PreparedMutationLease, AppCoreError> {
        let request = recovery_request(evidence)?;
        if ledger_identity(binding, &request)? != recovery_identity(binding, evidence)?
            || request.ledger_command()? != *evidence.normalized_command()
            || request.semantic_digest() != evidence.semantic_digest()
        {
            return Err(AppCoreError::MutationUnavailable);
        }
        let security = self
            .mutation_security
            .as_ref()
            .ok_or(AppCoreError::MutationUnavailable)?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let permit = store
            .prepare_anchored_mutation_v7(
                security.secure.as_ref(),
                ledger_identity(binding, &request)?,
                request.ledger_command()?,
            )
            .map_err(|_| AppCoreError::MutationUnavailable)?;
        let record = permit.record().clone();
        drop(store);
        (record.disposition() == evidence.disposition()
            && record.resend_count() == evidence.resend_count())
        .then_some(PreparedMutationLease {
            runtime_identity: runtime_identity.clone(),
            gate_epoch: binding.gate_epoch,
            anchored_record: record,
            request,
            finalized_root: None,
        })
        .ok_or(AppCoreError::MutationUnavailable)
    }
}

include!("mutation_recovery/request.rs");

fn recovery_identity(
    binding: MutationAdmissionBinding,
    evidence: &runne_local_store::MutationRecoveryEvidence,
) -> Result<runne_local_store::MutationIdentity, AppCoreError> {
    runne_local_store::MutationIdentity::new(
        binding.runtime_identity_digest,
        binding.principal_digest,
        evidence.operation(),
        evidence.target().kind(),
        evidence.target().canonical_id().clone(),
        evidence.idempotency_key().to_owned(),
        evidence.expected_version(),
        evidence.semantic_digest(),
    )
    .map_err(|_| AppCoreError::MutationUnavailable)
}
