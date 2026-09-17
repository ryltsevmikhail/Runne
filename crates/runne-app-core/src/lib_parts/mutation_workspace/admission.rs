impl AppCore {
    fn validate_finalized_root_binding(
        bind: &PreparedMutationLease,
    ) -> Result<(), AppCoreError> {
        let CanonicalMutationCommand::BindWorkspaceRoot {
            workspace_id,
            admission_digest,
        } = &bind.request.semantic_command
        else {
            return Err(AppCoreError::InvalidMutation);
        };
        let finalized = bind
            .finalized_root
            .as_ref()
            .ok_or(AppCoreError::InvalidMutation)?;
        (finalized.runtime_identity == bind.runtime_identity
            && finalized.workspace_id == *workspace_id
            && finalized.expected_version == bind.request.expected_version
            && finalized.admission_digest == *admission_digest
            && finalized.admission_digest == finalized.admission.admission_digest())
        .then_some(())
        .ok_or(AppCoreError::InvalidMutation)
    }
}

const fn early_root_validation_disposition(
    possible_send: bool,
) -> NativeAuthorityDisposition {
    if possible_send {
        NativeAuthorityDisposition::ReleaseWithoutReap
    } else {
        NativeAuthorityDisposition::ReapBeforeDispatch
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
