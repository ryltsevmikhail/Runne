use super::native_process::NativeOwnerBoundProcessLauncher;
use runne_api::{ProcessOutputChunk, ProcessSnapshot};
use runne_domain::id::ProcessId;
use runne_domain::id::{AttemptId, TaskRunId};
use runne_platform_ports::process::ProcessLifecycleBindingV1;
use runne_security::broker::process::{OwnedProcessHandleV1, ProcessInvocationIdV1};
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) struct ProcessRecord {
    pub(crate) snapshot: ProcessSnapshot,
    pub(crate) task_run_id: TaskRunId,
    pub(crate) attempt_id: AttemptId,
    pub(crate) principal_id: String,
    pub(crate) request_digest: [u8; 32],
    pub(crate) intent_digest: [u8; 32],
    pub(crate) binding: ProcessLifecycleBindingV1,
    pub(crate) invocation: ProcessInvocationIdV1,
    pub(crate) handle: OwnedProcessHandleV1,
    pub(crate) launcher: Arc<NativeOwnerBoundProcessLauncher>,
    pub(crate) adopted: bool,
    pub(crate) output: Vec<ProcessOutputChunk>,
}

#[derive(Default)]
pub(crate) struct NativeProcessRegistry {
    pub(crate) records: HashMap<ProcessId, ProcessRecord>,
    pub(crate) by_invocation: HashMap<[u8; 16], ProcessId>,
}
