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
    fn close_manual_resolution(
        &self,
        lease: &mut PreparedMutationLease,
    ) -> Result<(), AppCoreError> {
        use runne_local_store::ClientMutationDisposition as State;
        if matches!(
            lease.anchored_record.disposition(),
            State::Dispatching | State::Observing
        ) {
            self.transition_v7_under_operation(
                lease,
                runne_local_store::V7MutationTransition::Indeterminate {
                    timestamp: unix_timestamp(),
                },
            )?;
        }
        if lease.anchored_record.disposition() != State::ManualResolution {
            self.transition_v7_under_operation(
                lease,
                runne_local_store::V7MutationTransition::ManualResolution {
                    summary: "manual_resolution".into(),
                    timestamp: unix_timestamp(),
                },
            )?;
        }
        Ok(())
    }
    fn can_resend_bind(lease: &PreparedMutationLease) -> bool {
        let CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, .. } =
            &lease.request.semantic_command
        else {
            return true;
        };
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
include!("mutation_dispatch/flow.rs");
const fn root_workspace_id(request: &MutationRequest) -> Result<CanonicalId, AppCoreError> {
    match &request.semantic_command {
        CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, .. } => Ok(*workspace_id),
        _ => Err(AppCoreError::InvalidMutation),
    }
}

include!("mutation_dispatch/send.rs");
