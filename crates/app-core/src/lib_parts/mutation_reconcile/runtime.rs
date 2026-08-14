impl AppCore {
    async fn reconcile_anchored_command(
        &self,
        lease: &PreparedMutationLease,
        recovery: bool,
    ) -> Result<gocode_runtime_client::CommandReconciliationDisposition, ReconciliationFailure> {
        let command = lease
            .anchored_record
            .normalized_command()
            .ok_or(ReconciliationFailure::Local)?;
        request_matches_anchored_command(&lease.request, command).map_err(|_| ReconciliationFailure::Local)?;
        let request = reconciliation_request_from_anchored(
            lease.request.command_identity.clone(),
            command,
        ).map_err(|_| ReconciliationFailure::Local)?;
        // A live-session lookup can fail after the exact POST has left the
        // process. That is transport availability, not corrupt anchored
        // evidence; keep the record reconciling for the next session.
        self.reconciliation_client(lease, recovery)
            .map_err(|_| ReconciliationFailure::Unavailable)?
            .reconcile_command(request)
            .await
            .map_err(|error| ReconciliationFailure::Runtime(error.kind()))
    }

    async fn persist_reconciled_outcome(
        &self,
        lease: &mut PreparedMutationLease,
        outcome: &gocode_runtime_client::CommandReconciliationOutcome,
    ) -> Result<(), AppCoreError> {
        // The production path stays asynchronous because the test-only failpoint
        // below deliberately suspends at this exact atomicity boundary.
        std::future::ready(()).await;
        let command = lease
            .anchored_record
            .normalized_command()
            .ok_or(AppCoreError::MutationUnavailable)?;
        let outcome = reconciliation_outcome_to_ledger(command, outcome)?;
        if lease.anchored_record.disposition()
            == gocode_local_store::ClientMutationDisposition::CanonicalOutcome
        {
            return (lease.anchored_record.canonical_outcome() == Some(&outcome))
                .then_some(())
                .ok_or(AppCoreError::MutationUnavailable);
        }
        #[cfg(any(test, feature = "test-support"))]
        if self
            .mutation_test_hold_before_canonical
            .load(Ordering::Acquire)
        {
            self.mutation_test_before_canonical_reached.notify_one();
            self.mutation_test_continue_canonical.notified().await;
        }
        if lease.anchored_record.disposition()
            != gocode_local_store::ClientMutationDisposition::Observing
        {
            self.transition_v7_under_operation(
                lease,
                gocode_local_store::V7MutationTransition::Observing { timestamp: unix_timestamp() },
            )?;
        }
        self.transition_v7_under_operation(
            lease,
            gocode_local_store::V7MutationTransition::CanonicalOutcome {
                outcome: Box::new(outcome),
                summary: "durably_recorded".into(),
                timestamp: unix_timestamp(),
            },
        )
    }

    fn project_reconciled_result(
        outcome: &gocode_runtime_client::CommandReconciliationOutcome,
    ) -> Result<MutationDispatchResult, AppCoreError> {
        use gocode_runtime_client::CommandReconciliationOutcome as Outcome;
        match outcome {
            Outcome::ProjectCreated(value) | Outcome::ProjectArchived(value) | Outcome::ProjectDeleted(value) => Ok(MutationDispatchResult::Project(value.clone())),
            Outcome::WorkspaceCreated(value) | Outcome::WorkspaceRootBound(value) | Outcome::WorkspaceOpened(value) => Ok(MutationDispatchResult::Workspace(value.clone())),
            Outcome::ConversationCreated(value) => Ok(MutationDispatchResult::ConversationCreated(value.clone())),
            Outcome::ConversationTextCompleted(value) => Ok(MutationDispatchResult::TextGenerated((**value).clone())),
            Outcome::ConversationTextRejected(_) => Err(AppCoreError::GenerationRejected),
            Outcome::ConversationTextProhibitedInputRejected(_) => Err(AppCoreError::ProhibitedInputRejected),
        }
    }
}

impl AppCore {
    fn reconciliation_client(
        &self,
        lease: &PreparedMutationLease,
        recovery: bool,
    ) -> Result<AuthenticatedRuntimeClient, AppCoreError> {
        if !(self.effective_runtime_availability()?.allows_mutations()
            || recovery && self.runtime_availability()? == RuntimeAvailability::Reconciling)
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let client = self.runtime_client()?.ok_or(AppCoreError::RuntimeUnavailable)?;
        replay::StableRuntimeIdentity::from_client(&client)
            .same_durable_runtime(&lease.runtime_identity)
            .then_some(client)
            .ok_or(AppCoreError::MutationUnavailable)
    }

    fn recovery_dispatch_client(
        &self,
        lease: &PreparedMutationLease,
    ) -> Result<AuthenticatedRuntimeClient, AppCoreError> {
        if self.runtime_availability()? != RuntimeAvailability::Reconciling
            || self.mutation_gate_epoch.load(Ordering::Acquire) != lease.gate_epoch
        {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let client = self.runtime_client()?.ok_or(AppCoreError::RuntimeUnavailable)?;
        (replay::StableRuntimeIdentity::from_client(&client) == lease.runtime_identity)
            .then_some(client)
            .ok_or(AppCoreError::RuntimeUnavailable)
    }
}

enum ReconciliationFailure {
    Local,
    Unavailable,
    Runtime(gocode_runtime_client::RuntimeApiErrorKind),
}
