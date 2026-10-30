use super::*;
use runne_application::ports::TaskRunExecutionInputV2;

impl DaemonAutomaticTaskRuns {
    /// Commits the first coding-loop plan for a freshly claimed run.
    ///
    /// Kept beside the claim so a failure before provider delivery is visible to
    /// the caller, which settles the already approved claim instead of leaving a
    /// claimed run without an owner.
    pub(in crate::application::exec_taskrun_worker::provider) fn commit_d2_plan_for_claim(
        &self,
        identity: &TaskRunAssignmentIdentity,
        claimed: &TaskRunExecutionInputV2,
    ) -> Result<crate::canonical_provider::D2ProviderRound, AutomaticTaskRunError> {
        let current_head = self
            .store
            .load_task_run(claimed.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Unavailable)?
            .current_version;
        let current_conversation = self
            .store
            .load_conversation(claimed.conversation_id)
            .map_err(|_| AutomaticTaskRunError::Unavailable)?
            .current_version;
        let (_cycle_id, _plan, head) = self.commit_d2_plan(
            identity,
            current_head,
            claimed.conversation_id,
            current_conversation,
            claimed.workspace_id,
            claimed.principal_id.clone(),
            claimed.submit_actor.clone(),
            *claimed
                .selected_profile
                .as_ref()
                .ok_or(AutomaticTaskRunError::Uncertain)?
                .profile_digest(),
            claimed.input.prompt(),
        )?;
        Ok(crate::canonical_provider::D2ProviderRound {
            current_taskrun_head: head,
            round_index: 0,
            previous_tool_result: None,
            continuation_target_fence: None,
        })
    }
}
