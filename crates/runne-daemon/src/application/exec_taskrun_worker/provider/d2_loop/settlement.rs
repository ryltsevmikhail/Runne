use super::*;
use runne_domain::{
    agent_loop::LoopDisposition,
    task_run::{TaskRun, TaskRunState},
};

impl DaemonAutomaticTaskRuns {
    pub(in crate::application::exec_taskrun_worker::provider) fn current_cycle_id(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
    ) -> Result<runne_domain::id::CycleId, ()> {
        use runne_application::ports::EventStore;
        let stream = self.store.load_task_run(taskrun_id).map_err(|_| ())?;
        let task = TaskRun::replay(&stream.events).map_err(|_| ())?;
        if task.state() != TaskRunState::Running {
            return Err(());
        }
        task.snapshot_v1()
            .active_cycle()
            .map(|cycle| cycle.cycle_id)
            .ok_or(())
    }

    pub(in crate::application::exec_taskrun_worker::provider) fn fail_d2_cycle(
        &self,
        job: &CanonicalProviderExecutionJob,
        assignment: &TaskRunAssignmentIdentity,
        cycle_id: runne_domain::id::CycleId,
        reason: runne_domain::conversation::GenerationFailureReason,
    ) -> Result<(), ()> {
        use runne_application::{commands::CompleteLoopCycleInput, ports::EventStore};
        let service = self.tool_loop_service.as_ref().ok_or(())?;
        let taskrun_id = assignment.taskrun_id;
        let stream = self.store.load_task_run(taskrun_id).map_err(|_| ())?;
        let task = TaskRun::replay(&stream.events).map_err(|_| ())?;
        if task.state() != TaskRunState::Running {
            return Err(());
        }
        let snapshot = task.snapshot_v1();
        let cycle = snapshot.active_cycle().ok_or(())?;
        let unresolved_proposals = cycle
            .expected_proposal_indexes
            .iter()
            .copied()
            .filter(|index| {
                !cycle
                    .recorded_outcomes
                    .iter()
                    .any(|record| record.proposal_index == *index)
            })
            .collect();
        let invocation_rows = self
            .store
            .load_taskrun_tool_invocations_for_taskrun(taskrun_id)
            .map_err(|_| ())?;
        let failure_reason = if invocation_rows
            .iter()
            .any(|row| row.binding.key.attempt_id == assignment.attempt_id)
        {
            "D2 tool approval or effect did not complete safely"
        } else {
            "provider_execution_rejected"
        };
        self.store
            .verify_d2_tool_loop_safe_stop(
                taskrun_id,
                assignment.attempt_id,
                cycle.cycle_id,
                assignment,
                stream.current_version,
                false,
            )
            .map_err(|_| ())?;
        service
            .complete_loop_cycle(
                &Self::d2_command_context(
                    job.context.principal_id.clone(),
                    job.context.actor.clone(),
                    taskrun_id,
                    assignment.attempt_id,
                    Some(cycle.cycle_id),
                    "fail-cycle",
                    None,
                ),
                CompleteLoopCycleInput {
                    taskrun_id,
                    expected_version: stream.current_version,
                    cycle_id,
                    disposition: LoopDisposition::Fail {
                        reason: failure_reason.into(),
                        unresolved_proposals,
                    },
                },
            )
            .map_err(|_| ())?;
        crate::application::tool_loop_failure::fail_d2_tool_loop(
            &self.store,
            &job.context,
            &job.original,
            &job.started,
            assignment,
            cycle_id,
            reason,
            None,
        )
        .map_err(|_| ())?;
        Ok(())
    }
}
