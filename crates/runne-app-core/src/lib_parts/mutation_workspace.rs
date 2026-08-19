impl AppCore {
    /// Reports whether this exact composite may have reached the runtime.
    #[must_use]
    pub const fn prepared_workspace_open_possible_send(prepared: &PreparedWorkspaceOpen) -> bool {
        prepared.possible_send
    }

    /// Pre-anchors the two exact native Workspace mutations under one gate.
    ///
    /// # Errors
    ///
    /// Returns a closed error for stale Workspace state, unavailable runtime,
    /// or unavailable anchored mutation storage.
    pub async fn prepare_open_selected_workspace(
        &self,
        workspace_id: runne_api::WorkspaceId,
        expected_version: u64,
        admission: runne_api::ProtectedRootHandleAdmission,
    ) -> Result<PreparedWorkspaceOpen, AppCoreError> {
        let workspace_id = CanonicalId::parse(&workspace_id.to_string())
            .map_err(|_| AppCoreError::InvalidMutation)?;
        let admission = runne_runtime_client::ProtectedRootAdmission::from_verified(admission)
            .map_err(|_| AppCoreError::InvalidMutation)?;
        let _operation = self.runtime_operation.lock().await;
        let client = self.protected_root_bind_client()?;
        let workspace = client
            .get_workspace(workspace_id)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        if workspace.version() != expected_version || workspace.is_open() {
            return Err(AppCoreError::InvalidMutation);
        }
        let bind = self.prepare_mutation_under_operation(workspace_request(
            runne_local_store::MutationOperation::WorkspaceBindRoot,
            workspace_id,
            expected_version,
            CanonicalMutationCommand::BindWorkspaceRoot {
                workspace_id,
                admission_digest: admission.admission_digest(),
            },
        )?)?;
        let open = self.prepare_mutation_under_operation(workspace_request(
            runne_local_store::MutationOperation::WorkspaceOpen,
            workspace_id,
            expected_version
                .checked_add(1)
                .ok_or(AppCoreError::InvalidMutation)?,
            CanonicalMutationCommand::OpenWorkspace { workspace_id },
        )?)?;
        let finalized = FinalizedRootAdmission {
            admission,
            runtime_identity: bind.runtime_identity.clone(),
            workspace_id,
            expected_version,
            admission_digest: binding_digest(&bind.request.semantic_command)?,
        };
        let mut bind = bind;
        bind.finalized_root = Some(finalized);
        Ok(PreparedWorkspaceOpen {
            bind,
            open,
            possible_send: false,
        })
    }
    /// Dispatches the anchored bind and open without exposing the bind ACK.
    ///
    /// # Errors
    ///
    /// Returns a redacted lifecycle disposition that lets the host reap only
    /// before a bind can have been sent.
    pub async fn dispatch_prepared_workspace_open(
        &self,
        prepared: &mut PreparedWorkspaceOpen,
    ) -> Result<runne_runtime_client::WorkspaceSnapshotDto, NativeMutationFailure> {
        let (bind, open, possible_send) = prepared.parts_and_possible_send_mut();
        let _operation = self.runtime_operation.lock().await;
        let workspace_id = match &open.request.semantic_command {
            CanonicalMutationCommand::OpenWorkspace { workspace_id } => *workspace_id,
            _ => {
                return Err(NativeMutationFailure::new(
                    NativeAuthorityDisposition::ReapBeforeDispatch,
                ));
            }
        };
        let bind_version = bind
            .request
            .expected_version
            .checked_add(1)
            .ok_or_else(|| {
                NativeMutationFailure::new(NativeAuthorityDisposition::ReapBeforeDispatch)
            })?;
        let open_version = bind_version.checked_add(1).ok_or_else(|| {
            NativeMutationFailure::new(NativeAuthorityDisposition::ReapBeforeDispatch)
        })?;
        self.refresh_reconciling_lease(bind).map_err(|_| {
            NativeMutationFailure::new(NativeAuthorityDisposition::ReapBeforeDispatch)
        })?;
        let bind_ack = self
            .dispatch_prepared_mutation_under_operation(bind, Some(possible_send), false, true, false)
            .await
            .map_err(|_| {
                NativeMutationFailure::new(if *possible_send {
                    NativeAuthorityDisposition::ReleaseWithoutReap
                } else {
                    NativeAuthorityDisposition::ReapBeforeDispatch
                })
            })?;
        match bind_ack {
            MutationDispatchResult::Workspace(ack)
                if ack.workspace_id() == workspace_id && ack.new_version() == bind_version => {}
            _ => {
                return Err(NativeMutationFailure::new(
                    NativeAuthorityDisposition::ReleaseWithoutReap,
                ));
            }
        }
        self.admit_unstarted_composite_successor(bind, open)
            .map_err(|_| {
                NativeMutationFailure::new(NativeAuthorityDisposition::ReleaseWithoutReap)
            })?;
        self.refresh_reconciling_lease(open).map_err(|_| {
            NativeMutationFailure::new(NativeAuthorityDisposition::ReleaseWithoutReap)
        })?;
        let open_ack = self
            .dispatch_prepared_mutation_under_operation(open, Some(possible_send), true, true, false)
            .await
            .map_err(|_| {
                NativeMutationFailure::new(NativeAuthorityDisposition::ReleaseWithoutReap)
            })?;
        match &open_ack {
            MutationDispatchResult::Workspace(ack)
                if ack.workspace_id() == workspace_id && ack.new_version() == open_version => {}
            _ => {
                return Err(NativeMutationFailure::new(
                    NativeAuthorityDisposition::ReleaseWithoutReap,
                ));
            }
        }
        let identity = open.runtime_identity.clone();
        let epoch = open.gate_epoch;
        let result = self
            .final_dispatch_client_for_identity(&identity, epoch)
            .map_err(|_| {
                NativeMutationFailure::new(NativeAuthorityDisposition::ReleaseWithoutReap)
            })?
            .get_workspace(workspace_id)
            .await;
        let Ok(snapshot) = result else {
            return Err(NativeMutationFailure::new(
                NativeAuthorityDisposition::ReleaseWithoutReap,
            ));
        };
        if snapshot.id() != workspace_id
            || !snapshot.is_open()
            || snapshot.version() != open_version
        {
            return Err(NativeMutationFailure::new(
                NativeAuthorityDisposition::ReleaseWithoutReap,
            ));
        }
        Ok(snapshot)
    }
}
impl AppCore {
    fn admit_unstarted_composite_successor(
        &self,
        bind: &PreparedMutationLease,
        open: &mut PreparedMutationLease,
    ) -> Result<(), AppCoreError> {
        if open.anchored_record.disposition()
            != runne_local_store::ClientMutationDisposition::Prepared
            || bind.runtime_identity != open.runtime_identity
        {
            return Ok(());
        }
        let client = self.live_runtime_client()?;
        (replay::StableRuntimeIdentity::from_client(&client) == open.runtime_identity)
            .then_some(())
            .ok_or(AppCoreError::RuntimeUnavailable)?;
        open.gate_epoch = self.mutation_gate_epoch.load(Ordering::Acquire);
        Ok(())
    }

    fn protected_root_bind_client(&self) -> Result<AuthenticatedRuntimeClient, AppCoreError> {
        if self.runtime_mode != RuntimeMode::Bundled {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        let client = self.live_runtime_client()?;
        runne_runtime_client::protected_profile_matches(&client)
            .then_some(client)
            .ok_or(AppCoreError::RuntimeUnavailable)
    }
}
const fn binding_digest(command: &CanonicalMutationCommand) -> Result<[u8; 32], AppCoreError> {
    match command {
        CanonicalMutationCommand::BindWorkspaceRoot {
            admission_digest, ..
        } => Ok(*admission_digest),
        _ => Err(AppCoreError::InvalidMutation),
    }
}
fn workspace_request(
    operation: runne_local_store::MutationOperation,
    workspace_id: CanonicalId,
    expected_version: u64,
    semantic_command: CanonicalMutationCommand,
) -> Result<MutationRequest, AppCoreError> {
    let command_id = CanonicalId::now_v7();
    let idempotency_key = command_id.to_string();
    let identity = CommandIdentity::new(command_id, idempotency_key.clone())
        .map_err(|_| AppCoreError::InvalidMutation)?;
    let target = MutationTarget::try_new(
        operation,
        runne_local_store::MutationTargetKind::Workspace,
        runne_local_store::BoundedCanonicalId::parse(workspace_id.to_string().as_bytes())
            .map_err(|_| AppCoreError::InvalidMutation)?,
    )
    .map_err(|_| AppCoreError::InvalidMutation)?;
    Ok(MutationRequest::for_conversation(
        operation,
        target,
        expected_version,
        semantic_command,
        identity,
        idempotency_key,
    ))
}
