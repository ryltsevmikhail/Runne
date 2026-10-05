use runne_runtime_client::CommandReconciliationDisposition as Disposition;

impl AppCore {
    /// Reads accepted terminal receipts or reconciles nonterminal submit
    /// evidence without dispatching from a stored receipt.
    ///
    /// # Errors
    /// Returns an error when native ledger evidence or runtime authority cannot
    /// be verified. No submit dispatch occurs in this method.
    pub async fn recover_managed_task_run(
        &self,
        recovery_token: &str,
    ) -> Result<ManagedTaskRunRecovery, AppCoreError> {
        let command_id =
            CanonicalId::parse(recovery_token).map_err(|_| AppCoreError::InvalidMutation)?;
        if command_id.to_string() != recovery_token {
            return Err(AppCoreError::InvalidMutation);
        }
        let _intent_operation = self.managed_intent_operation.lock().await;
        let _operation = self.runtime_operation.lock().await;
        self.recover_managed_task_run_locked(recovery_token).await
    }

    async fn recover_managed_task_run_locked(
        &self,
        recovery_token: &str,
    ) -> Result<ManagedTaskRunRecovery, AppCoreError> {
        let client = self.live_runtime_client()?;
        let runtime_identity = replay::StableRuntimeIdentity::from_client(&client);
        let binding = self.mutation_binding_for(&runtime_identity);
        let recovery_binding = runne_local_store::MutationRecoveryBinding::new(
            binding.runtime_identity_digest,
            binding.principal_digest,
        )
        .map_err(|_| AppCoreError::MutationUnavailable)?;
        let security = self
            .mutation_security
            .as_ref()
            .ok_or(AppCoreError::MutationUnavailable)?;
        let receipt = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?
            .lookup_anchored_mutation_receipt_v7(
                security.secure.as_ref(),
                recovery_binding,
                recovery_token,
            )
            .map_err(|_| AppCoreError::MutationUnavailable)?;
        self.require_same_runtime_identity(&runtime_identity)?;
        if let Some(accepted) =
            self.accept_managed_receipt(receipt, recovery_token, &runtime_identity, binding)?
        {
            return Ok(accepted);
        }
        self.recover_nonterminal_managed_task_run(
            recovery_token,
            &runtime_identity,
            binding,
            recovery_binding,
        )
        .await
    }

    fn accept_managed_receipt(
        &self,
        receipt: Option<runne_local_store::MutationReceiptV7>,
        recovery_token: &str,
        runtime_identity: &replay::StableRuntimeIdentity,
        binding: MutationAdmissionBinding,
    ) -> Result<Option<ManagedTaskRunRecovery>, AppCoreError> {
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        match receipt.record().disposition() {
            runne_local_store::ClientMutationDisposition::CanonicalOutcome => {
                let accepted = accepted_managed_receipt(
                    &receipt,
                    recovery_token,
                    binding.runtime_identity_digest,
                    binding.principal_digest,
                )?;
                self.mark_managed_token_accepted(
                    recovery_token,
                    runtime_identity,
                    accepted
                        .workspace_id
                        .as_deref()
                        .ok_or(AppCoreError::MutationUnavailable)?,
                    accepted
                        .conversation_id
                        .as_deref()
                        .ok_or(AppCoreError::MutationUnavailable)?,
                    runtime_identity.launch_generation,
                )?;
                Ok(Some(accepted))
            }
            runne_local_store::ClientMutationDisposition::ManualResolution => {
                Err(AppCoreError::MutationUnavailable)
            }
            _ => Ok(None),
        }
    }

    async fn recover_nonterminal_managed_task_run(
        &self,
        recovery_token: &str,
        runtime_identity: &replay::StableRuntimeIdentity,
        binding: MutationAdmissionBinding,
        recovery_binding: runne_local_store::MutationRecoveryBinding,
    ) -> Result<ManagedTaskRunRecovery, AppCoreError> {
        let evidence = self.lookup_managed_recovery_evidence(recovery_token, recovery_binding)?;
        let Some(evidence) = evidence else {
            return Ok(ManagedTaskRunRecovery {
                status: "unavailable",
                task_run_id: None,
                stream_version: None,
                workspace_id: None,
                conversation_id: None,
            });
        };
        if evidence.operation() != runne_local_store::MutationOperation::TaskRunSubmit
            || evidence.idempotency_key() != recovery_token
        {
            return Err(AppCoreError::MutationUnavailable);
        }
        let lease = self.recover_mutation_lease(&evidence, runtime_identity, binding)?;
        let (workspace_id, conversation_id) = submit_target(&lease)?;
        let result = self.reconcile_anchored_command(&lease, true).await;
        self.require_same_runtime_identity(runtime_identity)?;
        let (status, task_run_id, stream_version) = reconciliation_result(&result);
        if status == "accepted" {
            self.mark_managed_token_accepted(
                recovery_token,
                runtime_identity,
                &workspace_id,
                &conversation_id,
                runtime_identity.launch_generation,
            )?;
        }
        Ok(ManagedTaskRunRecovery {
            status,
            task_run_id,
            stream_version,
            workspace_id: (status == "accepted").then_some(workspace_id),
            conversation_id: (status == "accepted").then_some(conversation_id),
        })
    }

    fn lookup_managed_recovery_evidence(
        &self,
        recovery_token: &str,
        recovery_binding: runne_local_store::MutationRecoveryBinding,
    ) -> Result<Option<runne_local_store::MutationRecoveryEvidence>, AppCoreError> {
        let security = self
            .mutation_security
            .as_ref()
            .ok_or(AppCoreError::MutationUnavailable)?;
        self.store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?
            .lookup_anchored_mutation_recovery_v7(
                security.secure.as_ref(),
                recovery_binding,
                recovery_token,
            )
            .map_err(|_| AppCoreError::MutationUnavailable)
    }

    fn require_same_runtime_identity(
        &self,
        expected: &replay::StableRuntimeIdentity,
    ) -> Result<(), AppCoreError> {
        let current = self
            .runtime_client()?
            .ok_or(AppCoreError::RuntimeUnavailable)?;
        if replay::StableRuntimeIdentity::from_client(&current) != *expected {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        Ok(())
    }
}

fn submit_target(lease: &PreparedMutationLease) -> Result<(String, String), AppCoreError> {
    match &lease.request.semantic_command {
        CanonicalMutationCommand::SubmitTaskRun {
            workspace_id,
            conversation_id,
            ..
        } => Ok((workspace_id.to_string(), conversation_id.to_string())),
        _ => Err(AppCoreError::MutationUnavailable),
    }
}

fn reconciliation_result(
    result: &Result<Disposition, ReconciliationFailure>,
) -> (&'static str, Option<String>, Option<u64>) {
    match result {
        Ok(Disposition::DurablyRecorded(
            runne_runtime_client::CommandReconciliationOutcome::TaskRunSubmitted(value),
        )) => (
            "accepted",
            Some(value.task_run_id().to_string()),
            Some(value.stream_version()),
        ),
        Ok(Disposition::NotCommittedRetryable) => ("not_committed", None, None),
        Ok(Disposition::Indeterminate) | Err(ReconciliationFailure::Runtime(_)) => {
            ("uncertain", None, None)
        }
        Ok(_) | Err(_) => ("unavailable", None, None),
    }
}

fn accepted_managed_receipt(
    receipt: &runne_local_store::MutationReceiptV7,
    token: &str,
    runtime_digest: [u8; 32],
    principal_digest: [u8; 32],
) -> Result<ManagedTaskRunRecovery, AppCoreError> {
    let record = receipt.record();
    let identity = record.identity();
    if receipt.runtime_identity_digest() != runtime_digest
        || receipt.principal_digest() != principal_digest
        || identity.runtime_identity_digest() != runtime_digest
        || identity.principal_digest() != principal_digest
        || identity.operation_kind() != runne_local_store::MutationOperation::TaskRunSubmit
        || identity.idempotency_key() != token
        || identity.stored_target().kind() != runne_local_store::MutationTargetKind::Conversation
        || record.runtime_disposition()
            != Some(runne_local_store::RuntimeCommitDisposition::DurablyRecorded)
    {
        return Err(AppCoreError::MutationUnavailable);
    }
    let Some(runne_local_store::NormalizedMutationCommand::SubmitTaskRun {
        conversation_id,
        workspace_id,
        ..
    }) = record.normalized_command()
    else {
        return Err(AppCoreError::MutationUnavailable);
    };
    if identity.stored_target().canonical_id().as_bytes() != conversation_id.as_bytes() {
        return Err(AppCoreError::MutationUnavailable);
    }
    let Some(runne_local_store::CanonicalMutationOutcome::TaskRunSubmitted {
        task_run_id,
        new_version,
    }) = record.canonical_outcome()
    else {
        return Err(AppCoreError::MutationUnavailable);
    };
    let canonical_id = |bytes: &[u8]| -> Result<String, AppCoreError> {
        let value = std::str::from_utf8(bytes).map_err(|_| AppCoreError::MutationUnavailable)?;
        let parsed = CanonicalId::parse(value).map_err(|_| AppCoreError::MutationUnavailable)?;
        if parsed.to_string() != value {
            return Err(AppCoreError::MutationUnavailable);
        }
        Ok(value.to_owned())
    };
    let task_run_id = canonical_id(task_run_id.as_bytes())?;
    let workspace_id = canonical_id(workspace_id.as_bytes())?;
    let conversation_id = canonical_id(conversation_id.as_bytes())?;
    if *new_version == 0 {
        return Err(AppCoreError::MutationUnavailable);
    }
    Ok(ManagedTaskRunRecovery {
        status: "accepted",
        task_run_id: Some(task_run_id),
        stream_version: Some(*new_version),
        workspace_id: Some(workspace_id),
        conversation_id: Some(conversation_id),
    })
}
