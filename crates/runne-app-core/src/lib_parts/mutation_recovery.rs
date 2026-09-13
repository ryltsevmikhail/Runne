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
        if self.mutation_security.is_none() {
            return Ok(());
        }
        let client = self.runtime_operation_context()?;
        let runtime_identity = client.identity.clone();
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
        for value in evidence.records() {
            let mut lease = self.recover_mutation_lease(value, &runtime_identity, binding)?;
            if lease.anchored_record.disposition()
                == runne_local_store::ClientMutationDisposition::Prepared
            {
                self.close_manual_resolution(&mut lease)?;
                continue;
            }
            if let Err(error) = self
                .dispatch_prepared_mutation_under_operation(&mut lease, None, false, false, true)
                .await
                && !matches!(
                    lease.anchored_record.disposition(),
                    runne_local_store::ClientMutationDisposition::CanonicalOutcome
                        | runne_local_store::ClientMutationDisposition::ManualResolution
                )
            {
                return Err(error);
            }
        }
        Ok(())
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
        let mut store = self.store.lock().map_err(|_| AppCoreError::StateUnavailable)?;
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

fn recovery_request(
    evidence: &runne_local_store::MutationRecoveryEvidence,
) -> Result<MutationRequest, AppCoreError> {
    use runne_local_store::NormalizedMutationCommand as Command;

    let key = evidence.idempotency_key();
    let command_id = CanonicalId::parse(key).map_err(|_| AppCoreError::MutationUnavailable)?;
    if command_id.to_string() != key {
        return Err(AppCoreError::MutationUnavailable);
    }
    let identity = CommandIdentity::new(command_id, key.to_owned())
        .map_err(|_| AppCoreError::MutationUnavailable)?;
    let id = |value: &runne_local_store::BoundedCanonicalId| {
        CanonicalId::parse(std::str::from_utf8(value.as_bytes()).map_err(|_| AppCoreError::MutationUnavailable)?)
            .map_err(|_| AppCoreError::MutationUnavailable)
    };
    let command = match evidence.normalized_command() {
        Command::CreateProject { project_id, display_name } => CanonicalMutationCommand::CreateProject { project_id: id(project_id)?, display_name: display_name.clone() },
        Command::RenameProject { project_id, display_name, .. } => CanonicalMutationCommand::RenameProject { project_id: id(project_id)?, display_name: display_name.clone() },
        Command::ArchiveProject { project_id, .. } => CanonicalMutationCommand::ArchiveProject { project_id: id(project_id)? },
        Command::DeleteProject { project_id, .. } => CanonicalMutationCommand::DeleteProject { project_id: id(project_id)? },
        Command::CreateWorkspace { workspace_id, project_id, display_name } => CanonicalMutationCommand::CreateWorkspace { workspace_id: id(workspace_id)?, project_id: id(project_id)?, display_name: display_name.clone() },
        Command::BindWorkspaceRoot { workspace_id, admission_digest, .. } => CanonicalMutationCommand::BindWorkspaceRoot { workspace_id: id(workspace_id)?, admission_digest: *admission_digest },
        Command::OpenWorkspace { workspace_id, .. } => CanonicalMutationCommand::OpenWorkspace { workspace_id: id(workspace_id)? },
        Command::CreateConversation { conversation_id, workspace_id } => CanonicalMutationCommand::CreateConversation { conversation_id: id(conversation_id)?, workspace_id: id(workspace_id)? },
        Command::GenerateText { conversation_id, text, .. } => CanonicalMutationCommand::GenerateText { conversation_id: id(conversation_id)?, text: text.clone() },
        Command::CancelTaskRun { task_run_id, .. } => CanonicalMutationCommand::CancelTaskRun { task_run_id: id(task_run_id)? },
        Command::ApprovalRespond { approval_id, decision, action_digest, policy_revision, renderer_generation, .. } => CanonicalMutationCommand::ApprovalRespond {
            approval_id: id(approval_id)?,
            decision: match decision {
                runne_local_store::ApprovalDecisionKind::Approve => runne_runtime_client::ApprovalDecisionDto::Approve,
                runne_local_store::ApprovalDecisionKind::Deny => runne_runtime_client::ApprovalDecisionDto::Deny,
            },
            action_digest: *action_digest,
            policy_revision: *policy_revision,
            renderer_generation: *renderer_generation,
        },
    };
    let request = MutationRequest::for_conversation(
        evidence.operation(),
        evidence.target().clone(),
        evidence.expected_version(),
        command,
        identity,
        key.to_owned(),
    );
    request.validate_invariants()?;
    Ok(request)
}

fn recovery_identity(
    binding: MutationAdmissionBinding,
    evidence: &runne_local_store::MutationRecoveryEvidence,
) -> Result<runne_local_store::MutationIdentity, AppCoreError> {
    runne_local_store::MutationIdentity::new(
        binding.runtime_identity_digest, binding.principal_digest, evidence.operation(),
        evidence.target().kind(), evidence.target().canonical_id().clone(),
        evidence.idempotency_key().to_owned(), evidence.expected_version(), evidence.semantic_digest(),
    )
    .map_err(|_| AppCoreError::MutationUnavailable)
}
