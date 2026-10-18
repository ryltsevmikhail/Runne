use super::*;
use runne_application::ports::{
    TaskRunAssignmentIdentity, TaskRunExecutionInputPort, TaskRunQueueCandidate,
};
use runne_application::service::ClaimTaskRunInput;
use runne_platform::local_command_linux::{LinuxCommandExecutable, LinuxCommandSpec};
use runne_platform::process_managed_area::{LinuxManagedAreaRoot, ManagedAreaBinding};
use std::ffi::OsString;
use std::sync::atomic::Ordering;
#[path = "run/settlement.rs"]
mod settlement;
#[path = "run/supervise.rs"]
mod supervise;
#[path = "run/test_barrier.rs"]
pub(in crate::application::exec_taskrun_worker) mod test_barrier;
#[path = "run/tool_executor.rs"]
pub(in crate::application) mod tool_executor;
#[path = "run/x2_supervisor.rs"]
pub(super) mod x2_supervisor;
use supervise::{mark_unconfirmed, supervise};

impl DaemonAutomaticTaskRuns {
    pub(super) async fn launch_local_command(
        &self,
        candidate: TaskRunQueueCandidate,
        workspace: runne_domain::id::WorkspaceId,
        command: runne_domain::task_run::TaskRunLocalCommand,
        prepared: PreparedLocalCommand,
        principal: ApiPrincipalId,
    ) -> Result<(), AutomaticTaskRunError> {
        let context = Self::runtime_context();
        let epoch = self.current_epoch.load(Ordering::Acquire);
        let claim = self
            .taskruns
            .claim_task_run(
                &context,
                ClaimTaskRunInput {
                    taskrun_id: candidate.taskrun_id,
                    expected_version: candidate.current_version,
                    node_id: self.node_id.clone(),
                    node_epoch: epoch,
                    capability_descriptor: "linux-executor-v1".into(),
                    lease_duration_ms: 300_000,
                },
                &self.store,
            )
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
        let receipt = match claim {
            runne_application::ports::TaskRunClaimResult::Committed(value)
            | runne_application::ports::TaskRunClaimResult::Duplicate(value) => value,
        };
        let identity = TaskRunAssignmentIdentity {
            taskrun_id: receipt.taskrun_id,
            attempt_id: receipt.attempt_id,
            node_id: receipt.node_id,
            node_epoch: receipt.node_epoch,
            fence: receipt.fence,
        };
        let claimed = self
            .store
            .read_taskrun_execution_input(identity.clone(), receipt.new_version)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        if claimed.workspace_id != workspace
            || claimed.principal_id.0 != principal.as_str()
            || claimed
                .input
                .local_command()
                .map(|value| value.intent_digest())
                != Some(prepared.binding.command_digest)
        {
            return Err(AutomaticTaskRunError::Uncertain);
        }
        let taskruns = self.taskruns.clone();
        let store = self.store.clone();
        let roots = self.root_admission.clone();
        let current_epoch = self.current_epoch.clone();
        let expected_version = claimed.stream_version;
        tokio::task::spawn_blocking(move || {
            run_claimed(
                taskruns,
                store,
                roots,
                current_epoch,
                identity,
                expected_version,
                workspace,
                command,
                prepared,
            )
        })
        .await
        .map_err(|_| AutomaticTaskRunError::Uncertain)?
    }
}

#[allow(clippy::too_many_arguments)]
fn run_claimed(
    taskruns: Arc<SqliteTaskRunService>,
    store: StoreTransaction,
    roots: super::super::RootAdmissionGateway,
    current_epoch: Arc<AtomicU64>,
    identity: TaskRunAssignmentIdentity,
    claimed_version: u64,
    workspace: runne_domain::id::WorkspaceId,
    command: runne_domain::task_run::TaskRunLocalCommand,
    prepared: PreparedLocalCommand,
) -> Result<(), AutomaticTaskRunError> {
    if current_epoch.load(Ordering::Acquire) != identity.node_epoch {
        return Err(AutomaticTaskRunError::Uncertain);
    }
    let trust_lease = roots
        .acquire_local_command_effect_lease(workspace, prepared.trust)
        .map_err(map_root_error)?;
    let root = LinuxManagedAreaRoot::open_current_cgroup()
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let binding = ManagedAreaBinding::new(
        *identity.taskrun_id.as_bytes(),
        *identity.attempt_id.as_bytes(),
        *uuid::Uuid::now_v7().as_bytes(),
    )
    .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let area = root
        .create_area(binding)
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let area_identity = area.identity().to_bytes();
    let argv = command.argv().iter().map(OsString::from).collect();
    let env = command
        .env()
        .iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect();
    let spec = LinuxCommandSpec {
        executable: LinuxCommandExecutable::SealedSnapshot(&prepared.executable),
        workspace: prepared.files.workspace(),
        cwd: prepared.files.cwd(),
        argv,
        env,
    };
    store
        .persist_local_command_launch_intent(&identity, claimed_version, &area_identity)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    let mut child =
        x2_supervisor::spawn_gated(&spec, &area).map_err(|_| AutomaticTaskRunError::Unavailable)?;
    if test_barrier::pause_at(test_barrier::Point::BeforeRelease).is_err() {
        let error = mark_unconfirmed(&store, &identity, &area_identity);
        let _ = child.terminate_area(std::time::Duration::from_secs(2));
        return Err(error);
    }
    let release = store.with_local_command_release(
        &identity,
        claimed_version,
        &area_identity,
        prepared.binding,
        prepared.approval_digest,
        || {
            roots
                .with_local_command_root_version(
                    workspace,
                    prepared.binding.workspace_version,
                    prepared.binding.admitted_root_version,
                    prepared.binding.admitted_root_identity,
                    |_| {
                        child
                            .release()
                            .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)
                    },
                )
                .map_err(|_| ())
        },
    );
    if release.is_err() {
        let stream = store
            .load_task_run(identity.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        let task = runne_domain::task_run::TaskRun::replay(&stream.events)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        if task.state() == runne_domain::task_run::TaskRunState::Cancelling {
            store
                .request_local_command_stop(&identity, &area_identity)
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            child
                .terminate_area(std::time::Duration::from_secs(2))
                .map_err(|_| mark_unconfirmed(&store, &identity, &area_identity))?;
            if area.is_populated().unwrap_or(true) {
                return Err(mark_unconfirmed(&store, &identity, &area_identity));
            }
            child
                .reap_after_stop(std::time::Duration::from_secs(3))
                .map_err(|_| mark_unconfirmed(&store, &identity, &area_identity))?;
            let empty = area
                .prove_empty()
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            store
                .confirm_local_command_stopped(&identity, &area_identity, empty)
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            drop(child);
            settlement::complete_cancelled(
                &taskruns,
                &store,
                identity.taskrun_id,
                stream.current_version,
            )?;
            area.remove_empty()
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            return Ok(());
        }
        let error = mark_unconfirmed(&store, &identity, &area_identity);
        let _ = child.terminate_area(std::time::Duration::ZERO);
        return Err(error);
    }
    drop(trust_lease);
    let result = supervise(
        taskruns,
        &store,
        &identity,
        &area,
        &area_identity,
        &mut child,
        &current_epoch,
    );
    drop(child);
    result?;
    area.remove_empty()
        .map_err(|_| AutomaticTaskRunError::Uncertain)
}
