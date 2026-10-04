use super::*;
use runne_api::{
    ApiPrincipalId, ApprovalCreateCommand, ApprovalQueryContext, ApprovalQueryHostPort,
    ApprovalRequestHostPort, ApprovalState,
};
use runne_application::ports::{EventStore, TaskRunQueueCandidate};
use runne_application::project_trust::TrustToken;
use runne_domain::id::{ApprovalId, InvocationId};
use runne_domain::task_run::{TaskRun, TaskRunExecutable, TaskRunState};
use runne_platform::local_command_linux::SealedExecutableSnapshot;
use runne_platform::local_command_linux::{LinuxCommandExecutable, LinuxCommandSpec};
use runne_store::ProjectWorkspaceStore;
use runne_store::store::{LocalCommandApprovalBinding, LocalCommandAttemptState};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Read;
#[path = "local/helpers.rs"]
mod helpers;
#[path = "local/no_effect.rs"]
mod no_effect;
#[path = "local/run.rs"]
mod run;
use helpers::*;
#[cfg(feature = "test-support")]
#[path = "local/diagnostic.rs"]
mod diagnostic;
#[path = "local/prepared.rs"]
mod prepared;
use prepared::{LocalApprovalDecision, PreparedLocalCommand};

impl DaemonAutomaticTaskRuns {
    pub(super) async fn execute_local_candidate(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> Option<Result<(), AutomaticTaskRunError>> {
        match self.prepare_local_candidate(candidate) {
            Ok(None) => None,
            Err(AutomaticTaskRunError::RejectedBeforeEffect) => {
                Some(self.fail_rejected_local_command(candidate))
            }
            Err(error) => Some(Err(error)),
            Ok(Some((workspace_id, command, prepared, principal))) => {
                let decision = match self
                    .resolve_local_approval(
                        candidate.taskrun_id,
                        workspace_id,
                        &command,
                        &prepared,
                        principal.clone(),
                    )
                    .await
                {
                    Ok(value) => value,
                    Err(AutomaticTaskRunError::RejectedBeforeEffect) => {
                        return Some(self.fail_rejected_local_command(candidate));
                    }
                    Err(error) => return Some(Err(error)),
                };
                match decision {
                    LocalApprovalDecision::Pending => return Some(Ok(())),
                    LocalApprovalDecision::Rejected => {
                        return Some(self.fail_rejected_local_command(candidate));
                    }
                    LocalApprovalDecision::Approved => {}
                }
                Some(
                    self.launch_local_command(
                        candidate,
                        workspace_id,
                        command,
                        prepared,
                        principal,
                    )
                    .await,
                )
            }
        }
    }

    fn prepare_local_candidate(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> Result<
        Option<(
            runne_domain::id::WorkspaceId,
            runne_domain::task_run::TaskRunLocalCommand,
            PreparedLocalCommand,
            ApiPrincipalId,
        )>,
        AutomaticTaskRunError,
    > {
        #[cfg(feature = "test-support")]
        diagnostic::begin();
        let stream = self
            .store
            .load_task_run(candidate.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
        if stream.current_version != candidate.current_version {
            return Err(AutomaticTaskRunError::Unavailable);
        }
        let task = TaskRun::replay(&stream.events).map_err(|_| AutomaticTaskRunError::Uncertain)?;
        let snapshot = task.snapshot_v1();
        if snapshot.state() != TaskRunState::Queued {
            return Err(AutomaticTaskRunError::Unavailable);
        }
        let input = snapshot.input().ok_or(AutomaticTaskRunError::Uncertain)?;
        let Some(command) = input.local_command().cloned() else {
            return Ok(None);
        };
        input
            .validate_execution_selection()
            .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
        let workspace_id = snapshot
            .workspace_id()
            .ok_or(AutomaticTaskRunError::Uncertain)?;
        let principal = self
            .store
            .taskrun_submit_principal(candidate.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Unavailable)?
            .ok_or(AutomaticTaskRunError::RejectedBeforeEffect)?;
        let principal = ApiPrincipalId::new(principal.0)
            .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
        #[cfg(feature = "test-support")]
        diagnostic::stage("admission");
        let (
            files,
            executable,
            workspace_version,
            project_id,
            root_version,
            root_identity,
            admission,
        ) = self
            .root_admission
            .with_local_command_root(workspace_id, |root, wv, project, rv, ri, admission| {
                #[cfg(feature = "test-support")]
                diagnostic::stage("open_held_files");
                let files = match command.executable() {
                    TaskRunExecutable::WorkspaceRelative(path) => root.open_linux_command_files(
                        std::path::Path::new(path),
                        std::path::Path::new(command.cwd()),
                    ),
                    TaskRunExecutable::SystemProgram(catalog_id) => root
                        .open_linux_system_command_files(
                            catalog_id,
                            std::path::Path::new(command.cwd()),
                        ),
                }?;
                #[cfg(feature = "test-support")]
                diagnostic::stage("sealed_snapshot");
                let executable = SealedExecutableSnapshot::from_held_file(files.executable())
                    .map_err(|error| match error {
                        runne_platform::local_command_linux::LinuxCommandError::Unavailable => {
                            runne_platform_desktop::RootHandleBrokerError::Unavailable
                        }
                        _ => runne_platform_desktop::RootHandleBrokerError::Rejected,
                    })?;
                let spec = LinuxCommandSpec {
                    executable: LinuxCommandExecutable::SealedSnapshot(&executable),
                    workspace: files.workspace(),
                    cwd: files.cwd(),
                    argv: command.argv().iter().map(OsString::from).collect(),
                    env: command
                        .env()
                        .iter()
                        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                        .collect(),
                };
                #[cfg(feature = "test-support")]
                diagnostic::stage("preflight");
                spec.preflight().map_err(|error| match error {
                    runne_platform::local_command_linux::LinuxCommandError::Unavailable => {
                        runne_platform_desktop::RootHandleBrokerError::Unavailable
                    }
                    _ => runne_platform_desktop::RootHandleBrokerError::Rejected,
                })?;
                Ok((files, executable, wv, project, rv, ri, admission))
            })
            .map_err(map_root_error)?;
        #[cfg(feature = "test-support")]
        diagnostic::stage("digest");
        let executable_digest = digest_file(executable.file())?;
        let command_digest = command.intent_digest();
        let trust = admission.token;
        let approval_digest = approval_digest(ApprovalDigestInput {
            command: command_digest,
            executable: executable_digest,
            project: project_id,
            workspace: workspace_version,
            root: root_version,
            root_id: root_identity,
            trust,
            source_policy: admission.source_policy_version,
            command_policy: admission.command_policy_version,
        });
        let binding = LocalCommandApprovalBinding {
            command_digest,
            executable_digest,
            workspace_version,
            admitted_root_version: root_version,
            admitted_root_identity: root_identity,
            trust_epoch: trust.instance_epoch,
            trust_revision: trust.revision,
            source_policy_version: admission.source_policy_version,
            command_policy_version: admission.command_policy_version,
            approval_id: stable_id(candidate.taskrun_id.as_bytes(), b"approval"),
        };
        #[cfg(feature = "test-support")]
        diagnostic::stage("managed_area_support");
        require_managed_area_support(candidate.taskrun_id)?;
        #[cfg(feature = "test-support")]
        diagnostic::stage("ready");
        Ok(Some((
            workspace_id,
            command,
            PreparedLocalCommand {
                files,
                executable,
                binding,
                approval_digest,
                trust,
            },
            principal,
        )))
    }

    async fn resolve_local_approval(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        workspace_id: runne_domain::id::WorkspaceId,
        command: &runne_domain::task_run::TaskRunLocalCommand,
        prepared: &PreparedLocalCommand,
        principal: ApiPrincipalId,
    ) -> Result<LocalApprovalDecision, AutomaticTaskRunError> {
        let approvals = ProjectWorkspaceStore::from_store(self.store.clone());
        let approval_id = ApprovalId::from_bytes(prepared.binding.approval_id);
        let query = ApprovalQueryContext {
            principal: principal.clone(),
        };
        let summary = match approvals.get_approval(query, approval_id).await {
            Ok(summary) => summary,
            Err(runne_api::ApprovalHostError::NotFound) => {
                let command = ApprovalCreateCommand::new(
                    approval_id,
                    taskrun_id,
                    None,
                    InvocationId::from_bytes(stable_id(taskrun_id.as_bytes(), b"invocation")),
                    principal,
                    APPROVAL_ACTION,
                    approval_resource(taskrun_id, workspace_id),
                    prepared.approval_digest,
                    prepared.binding.command_policy_version,
                    1,
                    now_millis().saturating_add(APPROVAL_LIFETIME_MS),
                    approval_review_summary(command)?,
                )
                .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
                approvals
                    .create_pending_approval(command)
                    .await
                    .map_err(|_| AutomaticTaskRunError::Unavailable)?
            }
            Err(_) => return Err(AutomaticTaskRunError::Unavailable),
        };
        if summary.task_run_id() != taskrun_id
            || summary.attempt_id().is_some()
            || summary.invocation_id().as_bytes()
                != &stable_id(taskrun_id.as_bytes(), b"invocation")
            || summary.action() != APPROVAL_ACTION
            || summary.resource() != approval_resource(taskrun_id, workspace_id)
            || summary.action_digest() != &prepared.approval_digest
            || summary.policy_revision() != prepared.binding.command_policy_version
            || summary.expires_at() <= now_millis()
        {
            return Err(AutomaticTaskRunError::RejectedBeforeEffect);
        }
        let state = match summary.state() {
            ApprovalState::Pending => LocalCommandAttemptState::ApprovalPending,
            ApprovalState::Approved => LocalCommandAttemptState::Approved,
            ApprovalState::Denied | ApprovalState::Expired | ApprovalState::Cancelled => {
                LocalCommandAttemptState::Denied
            }
        };
        self.store
            .bind_local_command_approval(taskrun_id, prepared.binding, state)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        match state {
            LocalCommandAttemptState::Approved => Ok(LocalApprovalDecision::Approved),
            LocalCommandAttemptState::Denied => Ok(LocalApprovalDecision::Rejected),
            LocalCommandAttemptState::ApprovalPending => Ok(LocalApprovalDecision::Pending),
            _ => Err(AutomaticTaskRunError::Uncertain),
        }
    }
}
