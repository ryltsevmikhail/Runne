use super::*;
use crate::application::exec_taskrun_worker::local::run::tool_executor as executor;
use runne_application::ports::EventStore;
use runne_domain::id::IntegrityDigest;
use runne_platform::process_managed_area::LinuxManagedArea;
use runne_platform_desktop::LinuxCommandWorkspaceFiles;

impl crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns {
    pub(in crate::application::exec_taskrun_worker) fn preflight_d2_tool_helper(
        &self,
        workspace_id: runne_domain::id::WorkspaceId,
    ) -> Result<(), ()> {
        self.root_admission
            .with_local_command_root(workspace_id, |root, _, _, _, _, _| {
                let files = root
                    .open_linux_command_workspace(std::path::Path::new("."))
                    .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Unavailable)?;
                executor::preflight_helper(&files)
                    .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)
            })
            .map_err(|_| ())
    }

    // Keep helper, area, target and approval bindings explicit at the GO boundary.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_d2_tool_helper(
        &self,
        files: &LinuxCommandWorkspaceFiles,
        input: &[u8],
        area: &LinuxManagedArea,
        workspace_id: runne_domain::id::WorkspaceId,
        assignment: &TaskRunAssignmentIdentity,
        binding: &ToolInvocationBindingV1,
        path: &str,
        workspace_version: u64,
        root_revision: u64,
        root_identity: [u8; 32],
        prepared: &super::super::permission::PreparedPermissionInvocation,
    ) -> Result<
        (i32, Vec<u8>, Vec<u8>),
        crate::application::exec_taskrun_worker::local::run::tool_executor::HelperRunFailure,
    > {
        executor::run_helper(
            files,
            input,
            area,
            &prepared.scope,
            prepared.native_receipt,
            self.permission_admission.as_deref(),
            |child| {
                if crate::application::exec_taskrun_worker::local::run::test_barrier::pause_at(
                    crate::application::exec_taskrun_worker::local::run::test_barrier::Point::BeforeRelease,
                ).is_err() {
                    return Err(());
                }
                let released = self.store.with_taskrun_tool_invocation_release(
                    binding.key,
                    binding.semantic_digest,
                    assignment,
                    now_millis(),
                    || {
                        self.root_admission.with_local_command_root_version(
                            workspace_id,
                            workspace_version,
                            root_revision,
                            root_identity,
                            |root| {
                                let current_files = root
                                    .open_linux_command_workspace(std::path::Path::new("."))
                                    .map_err(|_| {
                                        runne_platform_desktop::RootHandleBrokerError::Unavailable
                                    })?;
                                let current_target = executor::capture_target_precondition(
                                    &current_files,
                                    &binding.tool_name,
                                    path,
                                )
                                .map_err(|_| {
                                    runne_platform_desktop::RootHandleBrokerError::Rejected
                                })?;
                                let current_digest = current_target.as_ref().map(|value| {
                                    IntegrityDigest::from_bytes(
                                        Sha256::digest(
                                            serde_json::to_vec(value).expect("version serializes"),
                                        )
                                        .into(),
                                    )
                                });
                                if current_digest != binding.target_precondition {
                                    return Err(
                                        runne_platform_desktop::RootHandleBrokerError::Rejected,
                                    );
                                }
                                child.release().map_err(|_| {
                                    runne_platform_desktop::RootHandleBrokerError::Unavailable
                                })
                            },
                        )
                    },
                );
                match released {
                    Ok(Ok(())) => Ok(()),
                    _ => Err(()),
                }
            },
            || {
                if self.current_epoch.load(Ordering::Acquire) != assignment.node_epoch {
                    return true;
                }
                self.store
                    .load_task_run(assignment.taskrun_id)
                    .ok()
                    .and_then(|stream| runne_domain::task_run::TaskRun::replay(&stream.events).ok())
                    .is_none_or(|task| {
                        task.state() != runne_domain::task_run::TaskRunState::Running
                    })
            },
        )
    }
}
