enum MutationDispatchResult {
    Project(runne_runtime_client::ProjectCommandAcknowledgement),
    Workspace(runne_runtime_client::WorkspaceCommandAcknowledgement),
    ConversationCreated(runne_runtime_client::ConversationCreated),
    TextGenerated(runne_runtime_client::ConversationTextResult),
    TaskRunCancellationRequested(runne_runtime_client::TaskRunCancellationAcknowledgement),
    TaskRunSubmitted(runne_runtime_client::TaskRunSubmitAcknowledgement),
    ApprovalDecision(runne_runtime_client::ApprovalDecisionAcknowledgementDto),
}
include!("mutation_dispatch/public.rs");
impl AppCore {
    async fn dispatch_prepared_mutation_under_operation(
        &self,
        lease: &mut PreparedMutationLease,
        possible_send: Option<&mut bool>,
        defer_workspace_open_outcome: bool,
        _composite_failure: bool,
        recovery: bool,
    ) -> Result<MutationDispatchResult, AppCoreError> {
        let anchored = lease
            .anchored_record
            .normalized_command()
            .ok_or(AppCoreError::MutationUnavailable)?;
        request_matches_anchored_command(&lease.request, anchored)?;
        #[cfg(any(test, feature = "test-support"))]
        if self
            .mutation_test_hold_before_dispatch
            .load(Ordering::Acquire)
        {
            self.mutation_test_before_dispatch.notify_one();
            std::future::pending::<()>().await;
        }
        let state = lease.anchored_record.disposition();
        if state == runne_local_store::ClientMutationDisposition::ManualResolution {
            return Err(AppCoreError::MutationUnavailable);
        }
        if recovery && state == runne_local_store::ClientMutationDisposition::Prepared {
            self.close_manual_resolution(lease)?;
            return Err(AppCoreError::MutationUnavailable);
        }
        if state == runne_local_store::ClientMutationDisposition::Prepared {
            self.transition_v7_under_operation(lease, runne_local_store::V7MutationTransition::Dispatching { timestamp: unix_timestamp() })?;
            if Self::can_resend_bind(lease) {
                if let Some(value) = possible_send { *value = true; }
                let _ = self.send_exact_command(lease, recovery).await;
            }
        } else if state == runne_local_store::ClientMutationDisposition::Retryable {
            if lease.anchored_record.resend_count() != 0
                || !Self::can_resend_bind(lease)
                || (recovery && matches!(lease.request.semantic_command, CanonicalMutationCommand::BindWorkspaceRoot { .. }))
            {
                self.close_manual_resolution(lease)?;
                return Err(AppCoreError::MutationUnavailable);
            }
            self.resend_v7_under_operation(lease, unix_timestamp())?;
            if let Some(value) = possible_send { *value = true; }
            let _ = self.send_exact_command(lease, recovery).await;
        }
        let observed = self.reconcile_anchored_command(lease, recovery).await;
        let disposition = lease.anchored_record.disposition();
        if disposition == runne_local_store::ClientMutationDisposition::CanonicalOutcome {
            return match observed {
                Ok(runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(outcome)) => {
                    self.persist_reconciled_outcome(lease, &outcome).await?;
                    Self::project_reconciled_result(&outcome)
                }
                Ok(_) | Err(_) => Err(AppCoreError::MutationUnavailable),
            };
        }
        match observed {
            Ok(runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(outcome)) => {
                self.persist_reconciled_outcome(lease, &outcome).await?;
                if defer_workspace_open_outcome { return Self::project_reconciled_result(&outcome); }
                Self::project_reconciled_result(&outcome)
            }
            Ok(runne_runtime_client::CommandReconciliationDisposition::NotCommittedRetryable) => {
                if disposition == runne_local_store::ClientMutationDisposition::Observing {
                    self.transition_v7_under_operation(lease, runne_local_store::V7MutationTransition::Indeterminate { timestamp: unix_timestamp() })?;
                }
                self.transition_v7_under_operation(lease, runne_local_store::V7MutationTransition::NotCommittedRetryable { timestamp: unix_timestamp() })?;
                Err(AppCoreError::RuntimeUnavailable)
            }
            Err(ReconciliationFailure::Runtime(
                runne_runtime_client::RuntimeApiErrorKind::Conflict
                | runne_runtime_client::RuntimeApiErrorKind::InvalidResponse,
            ) | ReconciliationFailure::Local) => {
                self.close_manual_resolution(lease)?;
                Err(AppCoreError::MutationUnavailable)
            }
            Ok(runne_runtime_client::CommandReconciliationDisposition::Indeterminate)
            | Err(ReconciliationFailure::Unavailable | ReconciliationFailure::Runtime(_)) => {
                if disposition != runne_local_store::ClientMutationDisposition::Reconciling {
                    self.transition_v7_under_operation(lease, runne_local_store::V7MutationTransition::Indeterminate { timestamp: unix_timestamp() })?;
                }
                Err(AppCoreError::RuntimeUnavailable)
            }
        }
    }
    fn close_manual_resolution(&self, lease: &mut PreparedMutationLease) -> Result<(), AppCoreError> {
        use runne_local_store::ClientMutationDisposition as State;
        if matches!(lease.anchored_record.disposition(), State::Dispatching | State::Observing) {
            self.transition_v7_under_operation(lease, runne_local_store::V7MutationTransition::Indeterminate { timestamp: unix_timestamp() })?;
        }
        if lease.anchored_record.disposition() != State::ManualResolution {
            self.transition_v7_under_operation(lease, runne_local_store::V7MutationTransition::ManualResolution { summary: "manual_resolution".into(), timestamp: unix_timestamp() })?;
        }
        Ok(())
    }
    fn can_resend_bind(lease: &PreparedMutationLease) -> bool {
        let CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, .. } = &lease.request.semantic_command else { return true; };
        lease.finalized_root.as_ref().is_some_and(|finalized| {
            finalized.runtime_identity == lease.runtime_identity
                && finalized.workspace_id == *workspace_id
                && finalized.expected_version == lease.request.expected_version
                && finalized.admission_digest == finalized.admission.admission_digest()
        })
    }
    fn final_dispatch_client(
        &self,
        lease: &PreparedMutationLease,
    ) -> Result<AuthenticatedRuntimeClient, AppCoreError> {
        self.final_dispatch_client_for_identity(&lease.runtime_identity, lease.gate_epoch)
    }
    fn refresh_reconciling_lease(
        &self,
        lease: &mut PreparedMutationLease,
    ) -> Result<(), AppCoreError> {
        if lease.anchored_record.disposition()
            != runne_local_store::ClientMutationDisposition::Reconciling
        {
            return Ok(());
        }
        self.refresh_lease_for_current_identity(lease)
    }
    fn refresh_lease_for_current_identity(
        &self,
        lease: &mut PreparedMutationLease,
    ) -> Result<(), AppCoreError> {
        if lease.anchored_record.disposition()
            != runne_local_store::ClientMutationDisposition::Reconciling
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let client = self.live_runtime_client()?;
        let identity = replay::StableRuntimeIdentity::from_client(&client);
        if identity != lease.runtime_identity {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        if let Some(finalized) = lease.finalized_root.as_ref()
            && (finalized.runtime_identity != identity
                || finalized.workspace_id != root_workspace_id(&lease.request)?
                || finalized.expected_version != lease.request.expected_version
                || finalized.admission_digest != finalized.admission.admission_digest())
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        lease.gate_epoch = self.mutation_gate_epoch.load(Ordering::Acquire);
        Ok(())
    }
    fn final_dispatch_client_for_identity(
        &self,
        identity: &replay::StableRuntimeIdentity,
        gate_epoch: u64,
    ) -> Result<AuthenticatedRuntimeClient, AppCoreError> {
        let binding = self.mutation_binding_for(identity);
        if binding.gate_epoch != gate_epoch
            || !self.effective_runtime_availability()?.allows_mutations()
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let client = self
            .runtime_client()?
            .ok_or(AppCoreError::RuntimeUnavailable)?;
        let current = replay::StableRuntimeIdentity::from_client(&client);
        (current == *identity)
            .then_some(client)
            .ok_or(AppCoreError::RuntimeUnavailable)
    }
}
const fn root_workspace_id(request: &MutationRequest) -> Result<CanonicalId, AppCoreError> {
    match &request.semantic_command {
        CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, .. } => Ok(*workspace_id),
        _ => Err(AppCoreError::InvalidMutation),
    }
}

include!("mutation_dispatch/send.rs");
