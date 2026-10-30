use super::*;
impl DaemonAutomaticTaskRuns {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn complete_d2_stop(
        &self,
        provider: &crate::canonical_provider::DaemonCanonicalProviderService,
        job: CanonicalProviderExecutionJob,
        assignment: TaskRunAssignmentIdentity,
        round: crate::canonical_provider::D2ProviderRound,
        workspace_id: runne_domain::id::WorkspaceId,
        terminal: crate::canonical_provider::D2ToolTerminalRef,
        sources: Vec<runne_store::store::taskrun_tool_invocation::ToolSourceRef>,
    ) -> Result<super::super::ClaimedProviderOutcome, CanonicalProviderExecutionError> {
        d2_stage("final_stop_received");
        if !provider.coding_agent_tools_enabled()
            && (round.round_index != 2 || round.previous_tool_result.is_none())
        {
            let cycle_id = round
                .previous_tool_result
                .as_ref()
                .map(|previous| previous.cycle_id)
                .or_else(|| self.current_cycle_id(assignment.taskrun_id).ok())
                .ok_or(CanonicalProviderExecutionError::Uncertain)?;
            self.fail_d2_cycle(
                &job,
                &assignment,
                cycle_id,
                runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
            )
            .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
            return Ok(super::super::ClaimedProviderOutcome::ToolLoopFailed);
        }
        d2_stage("final_text_start");
        let final_text = provider
            .recover_d2_final_text(&job, &terminal)
            .inspect_err(|_error| {
                d2_stage("final_text_error");
            })?;
        d2_stage("final_text_recovered");
        d2_stage("current_targets_start");
        self.validate_d2_current_targets(workspace_id, assignment.taskrun_id)
            .map_err(|_| {
                d2_stage("current_targets_error");
                CanonicalProviderExecutionError::Uncertain
            })?;
        d2_stage("current_targets_valid");
        d2_stage("evaluation_start");
        let evaluation = crate::application::tool_authorities::derive_expected_evaluation(
            self.store.clone(),
            self.provider.clone(),
            self.root_admission.clone(),
            assignment.taskrun_id,
        )
        .map_err(|_| {
            d2_stage("evaluation_error");
            CanonicalProviderExecutionError::Uncertain
        })?;
        d2_stage("evaluation_ready");
        let cycle_id = self
            .current_cycle_id(assignment.taskrun_id)
            .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
        let head = self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| CanonicalProviderExecutionError::Unavailable)?
            .current_version;
        let loop_service = self
            .tool_loop_service
            .as_ref()
            .ok_or(CanonicalProviderExecutionError::Unavailable)?;
        d2_stage("complete_cycle_start");
        loop_service
            .complete_loop_cycle(
                &Self::d2_command_context(
                    job.context.principal_id.clone(),
                    job.context.actor.clone(),
                    assignment.taskrun_id,
                    assignment.attempt_id,
                    Some(cycle_id),
                    "complete-cycle",
                    None,
                ),
                CompleteLoopCycleInput {
                    taskrun_id: assignment.taskrun_id,
                    expected_version: head,
                    cycle_id,
                    disposition: LoopDisposition::Complete {
                        plan_evaluation_ref: evaluation.reference.clone(),
                    },
                },
            )
            .map_err(|_| {
                d2_stage("complete_cycle_error");
                CanonicalProviderExecutionError::Uncertain
            })?;
        d2_stage("cycle_completed");
        let started = job.started.clone();
        d2_stage("conversation_projection_start");
        let _receipt = crate::application::tool_loop_completion::complete_d2_tool_loop(
            &self.store,
            &job.context,
            &job.original,
            &started,
            &assignment,
            cycle_id,
            evaluation.reference,
            &terminal,
            &sources,
            final_text,
        )
        .map_err(|_| {
            d2_stage("conversation_projection_error");
            CanonicalProviderExecutionError::Uncertain
        })?;
        d2_stage("conversation_projected");
        Ok(super::super::ClaimedProviderOutcome::ToolLoopCompleted)
    }
}
