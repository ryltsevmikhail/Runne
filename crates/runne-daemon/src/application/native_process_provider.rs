use super::native_process::{
    CapturedOutput, NativeOwnerBoundProcessLauncher, NativeProcessPreparationError,
};
use super::native_process_registry::{NativeProcessRegistry, ProcessRecord};
use super::root_handle_admission::RootAdmissionGateway;
use runne_api::{
    ExistingProcessCommand, ProcessCommandContext, ProcessHostError, ProcessOutputChunk,
    ProcessOutputPage, ProcessOutputStream, ProcessQueryContext, ProcessSnapshot, ProcessState,
    StartProcessCommand,
};
use runne_application::ports::ProcessProvider;
use runne_domain::id::{InvocationId, ProcessId, WorkspaceId};
use runne_platform::containment::{ContainmentRequest, NativeCertificate, RuntimeProbe};
use runne_platform_ports::process::ProcessLifecycleBindingV1;
use runne_security::broker::process::{
    CommandPolicy, OwnerBoundProcessError, OwnerBoundProcessRequest, ProcessBroker,
    ProcessInvocationIdV1, ProcessSpec,
};
use runne_store::store::StoreTransaction;
use runne_store::store::process::{DurableProcessOutput, DurableProcessRecord, ProcessStoreError};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

mod invocation_registry;
pub(crate) use invocation_registry::AuthoritativeProcessInvocationRegistry;
#[cfg(test)]
pub(crate) use invocation_registry::ProcessInvocationRegistrationError;

include!("native_process_provider/recovery.rs");

const OWNER_PRINCIPAL: &str = "local-owner";

/// Runtime-owned native invocation resolved from an authoritative task-run path.
#[derive(Clone)]
pub(crate) struct ResolvedProcessInvocation {
    pub(crate) request_digest: [u8; 32],
    pub(crate) spec: ProcessSpec,
    pub(crate) executable_relative: String,
    pub(crate) cwd_relative: String,
    pub(crate) binding: ProcessLifecycleBindingV1,
    pub(crate) containment: ContainmentRequest,
    pub(crate) certificate: Option<NativeCertificate>,
    pub(crate) probes: Vec<RuntimeProbe>,
}

/// Resolves an exact runtime-owned invocation; it never accepts renderer launch material.
pub(crate) trait ProcessInvocationResolver: Clone + Send + Sync + 'static {
    fn resolve(
        &self,
        command: &StartProcessCommand,
    ) -> Result<ResolvedProcessInvocation, ProcessHostError>;
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) struct UnavailableProcessInvocationResolver;

impl ProcessInvocationResolver for UnavailableProcessInvocationResolver {
    fn resolve(
        &self,
        _: &StartProcessCommand,
    ) -> Result<ResolvedProcessInvocation, ProcessHostError> {
        Err(ProcessHostError::Unavailable)
    }
}

/// Protected process provider composed from the runtime resolver and owner-bound broker.
#[derive(Clone)]
pub(crate) struct NativeProcessProvider<R> {
    resolver: R,
    root: RootAdmissionGateway,
    broker: Arc<ProcessBroker>,
    registry: Arc<Mutex<NativeProcessRegistry>>,
    store: StoreTransaction,
}

impl<R: ProcessInvocationResolver> NativeProcessProvider<R> {
    pub(crate) fn new(resolver: R, root: RootAdmissionGateway, store: StoreTransaction) -> Self {
        Self {
            resolver,
            root,
            broker: Arc::new(ProcessBroker::new(CommandPolicy::StructuredOnly)),
            registry: Arc::new(Mutex::new(NativeProcessRegistry::default())),
            store,
        }
    }

    fn check_principal(principal: &str) -> Result<(), ProcessHostError> {
        (principal == OWNER_PRINCIPAL)
            .then_some(())
            .ok_or(ProcessHostError::Forbidden)
    }

    fn record(&self, process_id: ProcessId) -> Result<ProcessRecordGuard<'_>, ProcessHostError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| ProcessHostError::Unavailable)?;
        if !registry.records.contains_key(&process_id) {
            return Err(ProcessHostError::NotFound);
        }
        Ok(ProcessRecordGuard {
            registry,
            process_id,
        })
    }

    fn durable_snapshot(&self, process_id: ProcessId) -> Result<ProcessSnapshot, ProcessHostError> {
        let record = self
            .store
            .load_process_records(OWNER_PRINCIPAL)
            .map_err(map_store_error)?
            .into_iter()
            .find(|record| record.process_id == process_id.into_bytes())
            .ok_or(ProcessHostError::NotFound)?;
        let state = match record.state {
            4 => ProcessState::Exited,
            5 => ProcessState::Failed,
            1..=3 => return Err(ProcessHostError::Unavailable),
            _ => return Err(ProcessHostError::InvariantViolation),
        };
        Ok(ProcessSnapshot {
            process_id: ProcessId::from_bytes(record.process_id),
            invocation_id: InvocationId::from_bytes(record.invocation_id),
            workspace_id: WorkspaceId::from_bytes(record.workspace_id),
            state,
            version: record.version,
            next_output_sequence: record.next_output_sequence,
        })
    }

    fn durable_output(
        &self,
        process_id: ProcessId,
        after_sequence: u64,
        limit: u16,
    ) -> Result<ProcessOutputPage, ProcessHostError> {
        let output = self
            .store
            .load_process_output(process_id.into_bytes(), after_sequence)
            .map_err(map_store_error)?
            .into_iter()
            .take(usize::from(limit))
            .map(|chunk| {
                let stream = match chunk.stream {
                    1 => ProcessOutputStream::Stdout,
                    2 => ProcessOutputStream::Stderr,
                    _ => return Err(ProcessHostError::InvariantViolation),
                };
                ProcessOutputChunk::new(chunk.sequence, stream, chunk.text)
            })
            .collect::<Result<Vec<_>, _>>()?;
        ProcessOutputPage::new(limit, output)
    }

    fn prepare(
        &self,
        command: &StartProcessCommand,
        resolved: ResolvedProcessInvocation,
    ) -> Result<
        (
            Arc<NativeOwnerBoundProcessLauncher>,
            OwnerBoundProcessRequest,
        ),
        ProcessHostError,
    > {
        let invocation = ProcessInvocationIdV1::new(*command.invocation_id.as_bytes())
            .map_err(|_| ProcessHostError::InvariantViolation)?;
        let request_digest = resolved.request_digest;
        let spec = resolved.spec;
        let binding = resolved.binding;
        let executable = resolved.executable_relative;
        let cwd = resolved.cwd_relative;
        self.root
            .with_process_root(command.workspace_id, |root| {
                let root = root
                    .try_clone()
                    .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)?;
                let launcher = Arc::new(NativeOwnerBoundProcessLauncher::new(root));
                let prepared = launcher
                    .prepare(request_digest, &executable, &cwd)
                    .map_err(|error| match error {
                        NativeProcessPreparationError::Rejected => {
                            runne_platform_desktop::RootHandleBrokerError::Rejected
                        }
                        NativeProcessPreparationError::Unavailable => {
                            runne_platform_desktop::RootHandleBrokerError::Unavailable
                        }
                    })?;
                let request =
                    OwnerBoundProcessRequest::new_prepared(spec, prepared, binding, invocation)
                        .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)?;
                Ok((launcher, request))
            })
            .map_err(|error| match error {
                runne_platform_desktop::RootHandleBrokerError::Rejected => {
                    ProcessHostError::Forbidden
                }
                runne_platform_desktop::RootHandleBrokerError::Unavailable => {
                    ProcessHostError::Unavailable
                }
            })
    }

    fn refresh_output(record: &mut ProcessRecord) -> Result<(), ProcessHostError> {
        let raw = record
            .launcher
            .output(record.handle.pid())
            .map_err(map_owner_error)?;
        record.output = sanitize_output(raw)?;
        record.snapshot.next_output_sequence = u64::try_from(record.output.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ProcessHostError::InvariantViolation)?;
        Ok(())
    }

    fn persist_record(&self, record: &ProcessRecord) -> Result<(), ProcessHostError> {
        self.store
            .save_process_record(&DurableProcessRecord {
                process_id: record.snapshot.process_id.into_bytes(),
                invocation_id: record.snapshot.invocation_id.into_bytes(),
                workspace_id: record.snapshot.workspace_id.into_bytes(),
                task_run_id: record.task_run_id.into_bytes(),
                attempt_id: record.attempt_id.into_bytes(),
                principal_id: record.principal_id.clone(),
                state: process_state_value(record.snapshot.state),
                version: record.snapshot.version,
                next_output_sequence: record.snapshot.next_output_sequence,
                request_digest: record.request_digest,
                intent_digest: record.intent_digest,
                owner_id: *record.binding.owner().as_bytes(),
                binding_attempt_id: *record.binding.attempt().as_bytes(),
                session_id: *record.binding.session().as_bytes(),
                generation_id: *record.binding.generation().as_bytes(),
                tree_handle: *record.binding.tree_handle().as_bytes(),
                pid: record.handle.pid(),
                start_identity: *record.handle.start_identity(),
                launch_nonce: *record.handle.launch_nonce(),
            })
            .map_err(map_store_error)
    }

    fn persist_output(&self, record: &ProcessRecord) -> Result<(), ProcessHostError> {
        record.output.iter().try_for_each(|chunk| {
            self.store
                .append_process_output(&DurableProcessOutput {
                    process_id: record.snapshot.process_id.into_bytes(),
                    sequence: chunk.sequence(),
                    stream: match chunk.stream() {
                        ProcessOutputStream::Stdout => 1,
                        ProcessOutputStream::Stderr => 2,
                    },
                    text: chunk.text().to_owned(),
                })
                .map_err(map_store_error)
        })
    }
}

fn process_state_value(state: ProcessState) -> i64 {
    match state {
        ProcessState::Starting => 1,
        ProcessState::Running => 2,
        ProcessState::Stopping => 3,
        ProcessState::Exited => 4,
        ProcessState::Failed => 5,
    }
}

fn map_store_error(error: ProcessStoreError) -> ProcessHostError {
    match error {
        ProcessStoreError::Unavailable | ProcessStoreError::CorruptData => {
            ProcessHostError::Unavailable
        }
        ProcessStoreError::Conflict => ProcessHostError::Conflict,
    }
}

include!("native_process_provider/lifecycle.rs");

#[cfg(test)]
mod tests {
    include!("native_process_provider/tests.rs");
}
