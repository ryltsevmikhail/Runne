use super::*;
use crate::application::exec_taskrun_worker::local::run::tool_executor as executor;
use runne_application::ports::EventStore;
use runne_platform::process_managed_area::LinuxManagedArea;

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
    pub(super) fn run_d2_tool_helper<'area>(
        &self,
        input: &[u8],
        area: &'area LinuxManagedArea,
        assignment: &TaskRunAssignmentIdentity,
        binding: &ToolInvocationBindingV1,
        prepared: &super::super::permission::PreparedPermissionInvocation,
    ) -> Result<
        crate::application::exec_taskrun_worker::local::run::tool_executor::HelperRunOutput<'area>,
        crate::application::exec_taskrun_worker::local::run::tool_executor::HelperRunFailure,
    > {
        let helper = prepared
            .take_helper()
            .map_err(|_| executor::HelperRunError::Unavailable)?;
        executor::run_helper(
            helper,
            input,
            area,
            |child| {
                if crate::application::exec_taskrun_worker::local::run::test_barrier::pause_at(
                    crate::application::exec_taskrun_worker::local::run::test_barrier::Point::BeforeRelease,
                ).is_err() {
                    return Err(());
                }
                self.store
                    .release_taskrun_tool_invocation_helper(
                        binding.key,
                        binding.semantic_digest,
                        assignment,
                        now_millis(),
                        child,
                    )
                    .map_err(|_| ())
            },
            || {
                if self.current_epoch.load(Ordering::Acquire) != assignment.node_epoch {
                    return true;
                }
                if !self
                    .store
                    .observe_taskrun_tool_permission(
                        binding.key,
                        binding.semantic_digest,
                        assignment,
                    )
                    .unwrap_or(false)
                {
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
