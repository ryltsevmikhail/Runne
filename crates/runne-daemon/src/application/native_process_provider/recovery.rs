use runne_domain::id::{AttemptId, TaskRunId};
use runne_platform_ports::process::{
    HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessGenerationIdV1, ProcessOwnerIdV1,
    ProcessSessionIdV1,
};
use runne_security::broker::process::OwnerBoundProcessLauncher;

impl<R: ProcessInvocationResolver> NativeProcessProvider<R> {
    fn re_adopt_durable(&self, process_id: ProcessId) -> Result<bool, ProcessHostError> {
        let durable = self
            .store
            .load_process_records(OWNER_PRINCIPAL)
            .map_err(map_store_error)?
            .into_iter()
            .find(|record| record.process_id == process_id.into_bytes());
        let Some(durable) = durable else { return Ok(false) };
        if !matches!(durable.state, 1..=3) {
            return Ok(false);
        }
        let invocation = ProcessInvocationIdV1::new(durable.invocation_id)
            .map_err(|_| ProcessHostError::InvariantViolation)?;
        let binding = ProcessLifecycleBindingV1::new(
            ProcessOwnerIdV1::new(durable.owner_id)
                .map_err(|_| ProcessHostError::InvariantViolation)?,
            ProcessAttemptIdV1::new(durable.binding_attempt_id)
                .map_err(|_| ProcessHostError::InvariantViolation)?,
            ProcessSessionIdV1::new(durable.session_id)
                .map_err(|_| ProcessHostError::InvariantViolation)?,
            ProcessGenerationIdV1::new(durable.generation_id)
                .map_err(|_| ProcessHostError::InvariantViolation)?,
            HeldProcessTreeHandleV1::new(durable.tree_handle)
                .map_err(|_| ProcessHostError::InvariantViolation)?,
        );
        let handle = runne_security::broker::process::OwnedProcessHandleV1::recovered(
            binding.clone(),
            invocation,
            durable.pid,
            durable.start_identity,
            durable.launch_nonce,
        )
        .map_err(map_owner_error)?;
        let workspace_id = WorkspaceId::from_bytes(durable.workspace_id);
        let (launcher, output) = self
            .root
            .with_process_root(workspace_id, |root| {
                let launcher = Arc::new(NativeOwnerBoundProcessLauncher::new(
                    root.try_clone()
                        .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)?,
                ));
                launcher.re_adopt(handle.clone()).map_err(map_re_adopt_root_error)?;
                let output = self
                    .store
                    .load_process_output(durable.process_id, 0)
                    .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)?
                    .into_iter()
                    .map(recovered_output)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((launcher, output))
            })
            .map_err(map_re_adopt_host_error)?;
        if let Err(error) = self
            .broker
            .adopt_owner_bound(
                binding.clone(),
                invocation,
                handle.clone(),
                durable.intent_digest,
            )
        {
            let _ = launcher.stop(&handle);
            return Err(map_owner_error(error));
        }
        let snapshot = ProcessSnapshot {
            process_id,
            invocation_id: InvocationId::from_bytes(durable.invocation_id),
            workspace_id,
            state: recovered_state(durable.state)?,
            version: durable.version,
            next_output_sequence: durable.next_output_sequence,
        };
        let record = ProcessRecord {
            snapshot,
            task_run_id: TaskRunId::from_bytes(durable.task_run_id),
            attempt_id: AttemptId::from_bytes(durable.attempt_id),
            principal_id: durable.principal_id,
            request_digest: durable.request_digest,
            intent_digest: durable.intent_digest,
            binding,
            invocation,
            handle,
            launcher,
            adopted: true,
            output,
        };
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| ProcessHostError::Unavailable)?;
        if registry.by_invocation.contains_key(&durable.invocation_id) {
            return Err(ProcessHostError::Conflict);
        }
        registry.by_invocation.insert(durable.invocation_id, process_id);
        registry.records.insert(process_id, record);
        Ok(true)
    }
}

fn recovered_state(value: i64) -> Result<ProcessState, ProcessHostError> {
    match value {
        1 => Ok(ProcessState::Starting),
        2 => Ok(ProcessState::Running),
        3 => Ok(ProcessState::Stopping),
        _ => Err(ProcessHostError::InvariantViolation),
    }
}

fn recovered_output(
    chunk: DurableProcessOutput,
) -> Result<ProcessOutputChunk, runne_platform_desktop::RootHandleBrokerError> {
    let stream = match chunk.stream {
        1 => ProcessOutputStream::Stdout,
        2 => ProcessOutputStream::Stderr,
        _ => return Err(runne_platform_desktop::RootHandleBrokerError::Rejected),
    };
    ProcessOutputChunk::new(chunk.sequence, stream, chunk.text)
        .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)
}

fn map_re_adopt_root_error(
    error: OwnerBoundProcessError,
) -> runne_platform_desktop::RootHandleBrokerError {
    match error {
        OwnerBoundProcessError::LifecycleRejected
        | OwnerBoundProcessError::RegistryUnavailable => {
            runne_platform_desktop::RootHandleBrokerError::Unavailable
        }
        _ => runne_platform_desktop::RootHandleBrokerError::Rejected,
    }
}

/// Trust denial on the process channel is a Forbidden (policy denial), not a
/// Conflict (state clash): the re-adopt pre-check (R-2) denies before any
/// native access, and the denial direction must survive any future
/// unfreeze-channel decision (P2-1, report 2026-09-19-t1 §2).
fn map_re_adopt_host_error(
    error: runne_platform_desktop::RootHandleBrokerError,
) -> ProcessHostError {
    match error {
        runne_platform_desktop::RootHandleBrokerError::Rejected => ProcessHostError::Forbidden,
        runne_platform_desktop::RootHandleBrokerError::Unavailable => ProcessHostError::Unavailable,
    }
}

/// Test-only access to the re-adopt error mapping (P2-1 pin).
#[cfg(test)]
pub(crate) fn map_re_adopt_host_error_for_tests(
    error: runne_platform_desktop::RootHandleBrokerError,
) -> ProcessHostError {
    map_re_adopt_host_error(error)
}
