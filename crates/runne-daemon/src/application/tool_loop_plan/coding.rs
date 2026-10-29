use super::*;
use runne_application::{
    commands::CommitPlanInput,
    ports::{ApplicationCommandContext, EventStore, TaskRunAssignmentIdentity},
};
use runne_domain::{plan::PlanParentRef, task_run::TaskRun};
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunError as E;

pub(super) fn initialize(plan: &mut PlanRevisionRef) {
    plan.expected_proposal_indexes.clear();
    plan.proposal_batch_digest = digest(
        Sha256::new()
            .chain_update(b"runne:terminal-coding-plan:v1\0")
            .chain_update(plan.context_manifest_ref.integrity_digest.as_bytes())
            .chain_update(plan.planning_policy_ref.integrity_digest().as_bytes())
            .finalize()
            .into(),
    );
    plan.plan_id = PlanId::from_bytes(stable_id(
        plan.proposal_batch_digest.as_bytes(),
        b"coding-plan",
    ));
    plan.integrity_digest = digest(
        Sha256::new()
            .chain_update(plan.proposal_batch_digest.as_bytes())
            .chain_update(plan.planning_budget_ref.reservation_digest.as_bytes())
            .finalize()
            .into(),
    );
}
impl crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns {
    pub(in crate::application) fn extend_coding_plan(
        &self,
        context: &ApplicationCommandContext,
        assignment: &TaskRunAssignmentIdentity,
        expected_version: u64,
        proposal_index: u32,
        proposal_digest: IntegrityDigest,
    ) -> Result<u64, E> {
        if proposal_index >= 32
            || !self
                .provider
                .as_ref()
                .is_some_and(|p| p.coding_agent_tools_enabled())
        {
            return Err(E::Unavailable);
        }
        let stream = self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| E::Unavailable)?;
        if stream.current_version != expected_version {
            return Err(E::Uncertain);
        }
        let task = TaskRun::replay(&stream.events).map_err(|_| E::Uncertain)?;
        let snapshot = task.snapshot_v1();
        let cycle = snapshot.active_cycle().ok_or(E::Uncertain)?;
        if cycle.attempt_id != assignment.attempt_id {
            return Err(E::Uncertain);
        }
        let previous = cycle.plan_revision_ref.as_ref().ok_or(E::Uncertain)?;
        if previous.expected_proposal_indexes != (0..proposal_index).collect::<Vec<_>>() {
            return Err(E::Uncertain);
        }
        let mut plan = previous.clone();
        plan.revision = previous.revision.checked_add(1).ok_or(E::Uncertain)?;
        plan.parent_ref = Some(PlanParentRef {
            plan_id: previous.plan_id,
            revision: previous.revision,
            integrity_digest: previous.integrity_digest,
        });
        plan.expected_proposal_indexes.push(proposal_index);
        plan.proposal_batch_digest = digest(
            Sha256::new()
                .chain_update(b"runne:terminal-coding-proposal:v1\0")
                .chain_update(previous.proposal_batch_digest.as_bytes())
                .chain_update(proposal_index.to_be_bytes())
                .chain_update(proposal_digest.as_bytes())
                .finalize()
                .into(),
        );
        plan.integrity_digest = digest(
            Sha256::new()
                .chain_update(b"runne:terminal-coding-revision:v1\0")
                .chain_update(previous.integrity_digest.as_bytes())
                .chain_update(plan.revision.to_be_bytes())
                .chain_update(plan.proposal_batch_digest.as_bytes())
                .finalize()
                .into(),
        );
        self.tool_loop_service
            .as_ref()
            .ok_or(E::Unavailable)?
            .commit_plan(
                &Self::d2_command_context(
                    context.principal_id.clone(),
                    context.actor.clone(),
                    assignment.taskrun_id,
                    assignment.attempt_id,
                    Some(cycle.cycle_id),
                    &format!("coding-plan-{proposal_index}"),
                    None,
                ),
                CommitPlanInput {
                    taskrun_id: assignment.taskrun_id,
                    expected_version,
                    cycle_id: cycle.cycle_id,
                    input_digest: plan.context_manifest_ref.integrity_digest,
                    output_digest: plan.integrity_digest,
                    expected_proposal_indexes: plan.expected_proposal_indexes.clone(),
                    plan_revision_ref: plan,
                },
            )
            .map_err(|_| E::Uncertain)?;
        Ok(self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| E::Unavailable)?
            .current_version)
    }
}
