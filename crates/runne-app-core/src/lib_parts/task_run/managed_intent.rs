const MANAGED_ACCEPTED_TOKEN_LIMIT: usize = 256;
const MANAGED_ACTIVE_INTENT_LIMIT: usize = 256;

fn validate_managed_lease_identity(
    lease: &PreparedMutationLease,
    recovery_token: &str,
) -> Result<(), AppCoreError> {
    if lease.request.idempotency_key != recovery_token
        || lease.anchored_record.idempotency_key() != recovery_token
    {
        return Err(AppCoreError::MutationUnavailable);
    }
    let command = lease
        .anchored_record
        .normalized_command()
        .ok_or(AppCoreError::MutationUnavailable)?;
    request_matches_anchored_command(&lease.request, command)
}

fn managed_lease_accepted_result(
    lease: &PreparedMutationLease,
    recovery_token: &str,
) -> Result<Option<ManagedTaskRunStart>, AppCoreError> {
    let Some(runne_local_store::CanonicalMutationOutcome::TaskRunSubmitted {
        task_run_id,
        new_version,
    }) = lease.anchored_record.canonical_outcome()
    else {
        return Ok(None);
    };
    let task_run_id = std::str::from_utf8(task_run_id.as_bytes())
        .map_err(|_| AppCoreError::MutationUnavailable)?;
    Ok(Some(ManagedTaskRunStart {
        status: "accepted",
        task_run_id: Some(task_run_id.to_owned()),
        stream_version: Some(*new_version),
        recovery_token: recovery_token.to_owned(),
    }))
}

impl AppCore {
    fn ensure_managed_intent(
        &self,
        intent: ManagedTaskRunIntent,
    ) -> Result<String, AppCoreError> {
        let mut active = self
            .managed_intent
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        if let Some(existing) = active.iter().find(|existing| {
            existing.runtime == intent.runtime
                && existing.project_id == intent.project_id
                && existing.workspace_id == intent.workspace_id
                && existing.conversation_id == intent.conversation_id
                && existing.generation == intent.generation
        }) {
            return Ok(existing.recovery_token.clone());
        }
        if active.len() >= MANAGED_ACTIVE_INTENT_LIMIT {
            return Err(AppCoreError::MutationUnavailable);
        }
        let token = intent.recovery_token.clone();
        active.push_back(intent);
        drop(active);
        Ok(token)
    }

    fn validate_managed_intent(
        &self,
        runtime: &replay::StableRuntimeIdentity,
        workspace_id: &str,
        conversation_id: &str,
        generation: u64,
        token: &str,
    ) -> Result<(), AppCoreError> {
        let accepted = self
            .accepted_managed_tokens
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?
            .iter()
            .any(|intent| {
                intent.runtime == *runtime
                    && intent.generation == generation
                    && intent.workspace_id == workspace_id
                    && intent.conversation_id == conversation_id
                    && intent.recovery_token == token
            });
        if accepted {
            return Ok(());
        }
        let active = self
            .managed_intent
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let matches = active.iter().any(|intent| {
            intent.runtime == *runtime
                && intent.generation == generation
                && intent.workspace_id == workspace_id
                && intent.conversation_id == conversation_id
                && intent.recovery_token == token
        });
        drop(active);
        matches.then_some(()).ok_or(AppCoreError::InvalidMutation)
    }

    fn mark_managed_token_accepted(
        &self,
        token: &str,
        runtime: &replay::StableRuntimeIdentity,
        workspace_id: &str,
        conversation_id: &str,
        generation: u64,
    ) -> Result<(), AppCoreError> {
        let mut active = self
            .managed_intent
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let position = active.iter().position(|intent| {
            intent.recovery_token == token
                && intent.runtime == *runtime
                && intent.generation == generation
                && intent.workspace_id == workspace_id
                && intent.conversation_id == conversation_id
        });
        let intent = position.and_then(|index| active.remove(index));
        drop(active);
        let Some(intent) = intent else {
            return Ok(());
        };
        let mut accepted = self
            .accepted_managed_tokens
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        if !accepted
            .iter()
            .any(|value| value.recovery_token == token && value.runtime == *runtime)
        {
            accepted.push_back(intent);
        }
        while accepted.len() > MANAGED_ACCEPTED_TOKEN_LIMIT {
            accepted.pop_front();
        }
        drop(accepted);
        Ok(())
    }
}
