use super::*;
use runne_domain::{id::CycleId, plan::PlanRevisionRef};

#[path = "worker/diagnostics.rs"]
pub(crate) mod diagnostics;
use diagnostics::{application_error_code, application_error_stage, d2_test_stage};

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
impl crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns {
    // This command binds the exact planning inputs to the committed stream head.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::application) fn commit_d2_plan(
        &self,
        assignment: &runne_application::ports::TaskRunAssignmentIdentity,
        expected_version: u64,
        conversation_id: runne_domain::id::ConversationId,
        conversation_version: u64,
        workspace_id: runne_domain::id::WorkspaceId,
        principal: runne_application::ports::PrincipalId,
        actor: runne_domain::event::Actor,
        profile_digest: [u8; 32],
        prompt: &str,
    ) -> Result<
        (CycleId, PlanRevisionRef, u64),
        runne_runtime::taskrun_auto_worker::AutomaticTaskRunError,
    > {
        use runne_application::{
            commands::{CommitContextInput, CommitPlanInput, StartLoopCycleInput},
            ports::{ConversationRepository, EventStore},
        };
        use runne_domain::{agent_loop::LoopCycleState, task_run::TaskRun};
        use runne_runtime::taskrun_auto_worker::AutomaticTaskRunError as E;
        let service = self.tool_loop_service.as_ref().ok_or(E::Unavailable)?;
        let mut stream = self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| E::Unavailable)?;
        if stream.current_version != expected_version {
            return Err(E::Uncertain);
        }
        let task = TaskRun::replay(&stream.events).map_err(|_| E::Uncertain)?;
        let mut cycle = task.snapshot_v1().active_cycle().cloned();
        if cycle.is_none() {
            d2_test_stage("start_cycle");
            let context = Self::d2_command_context(
                principal.clone(),
                actor.clone(),
                assignment.taskrun_id,
                assignment.attempt_id,
                None,
                &format!("start-cycle-at-{expected_version}"),
                None,
            );
            service
                .start_loop_cycle(
                    &context,
                    StartLoopCycleInput {
                        taskrun_id: assignment.taskrun_id,
                        expected_version,
                    },
                )
                .map_err(|error| {
                    d2_test_stage("start_cycle_error");
                    eprintln!(
                        "runne-child-diag: d2-plan stage=start_cycle error_code={}",
                        application_error_code(&error)
                    );
                    E::Uncertain
                })?;
            d2_test_stage("cycle_started");
            stream = self
                .store
                .load_task_run(assignment.taskrun_id)
                .map_err(|_| E::Unavailable)?;
            cycle = TaskRun::replay(&stream.events)
                .map_err(|_| E::Uncertain)?
                .snapshot_v1()
                .active_cycle()
                .cloned();
        }
        let cycle = cycle.ok_or(E::Uncertain)?;
        if cycle.attempt_id != assignment.attempt_id || cycle.state == LoopCycleState::Completed {
            return Err(E::Uncertain);
        }
        let workspace_binding = self
            .root_admission
            .with_local_command_root(workspace_id, |_, wv, _, rv, ri, admission| {
                Ok((wv, rv, ri, admission.token))
            })
            .map_err(|_| E::Unavailable)?;
        let conversation = self
            .store
            .load_conversation(conversation_id)
            .map_err(|_| E::Unavailable)?;
        if conversation.current_version != conversation_version {
            return Err(E::Uncertain);
        }
        let event_refs = conversation
            .events
            .iter()
            .map(|event| {
                (
                    event.sequence(),
                    *event.event_id().as_bytes(),
                    *event.integrity_digest(),
                )
            })
            .collect::<Vec<_>>();
        // The immutable context records the TaskRun prefix at cycle start.
        // On recovery, later ContextCommitted/PlanCommitted events must not
        // be included or a harmless restart would manufacture new inputs.
        let planning_prefix_end = stream
            .events
            .iter()
            .find_map(|event| match event.payload() {
                runne_domain::task_run::TaskRunEvent::ContextCommitted { cycle_id, .. }
                    if *cycle_id == cycle.cycle_id =>
                {
                    Some(event.sequence())
                }
                _ => None,
            });
        let taskrun_event_refs = stream
            .events
            .iter()
            .filter(|event| planning_prefix_end.is_none_or(|end| event.sequence() < end))
            .map(|event| {
                (
                    event.sequence(),
                    *event.event_id().as_bytes(),
                    *event.integrity_digest(),
                )
            })
            .collect::<Vec<_>>();
        let coding = self
            .provider
            .as_ref()
            .is_some_and(|provider| provider.coding_agent_tools_enabled());
        let declarations = if coding {
            runne_provider::ProviderToolDeclarationV1::coding_agent_v1()
        } else {
            vec![
                runne_provider::ProviderToolDeclarationV1::for_name(
                    runne_provider::ProviderToolNameV1::WorkspaceFileRead,
                ),
                runne_provider::ProviderToolDeclarationV1::for_name(
                    runne_provider::ProviderToolNameV1::WorkspaceFileCreateNew,
                ),
            ]
        };
        let schema_digest = digest(
            Sha256::digest(serde_json::to_vec(&declarations).map_err(|_| E::Unavailable)?).into(),
        );
        let budget = if coding {
            self.store.ensure_taskrun_coding_tool_loop_budget(
                assignment.taskrun_id,
                stream.current_version,
                assignment,
                now_millis(),
            )
        } else {
            self.store.ensure_taskrun_tool_loop_budget(
                assignment.taskrun_id,
                stream.current_version,
                assignment,
                now_millis(),
            )
        }
        .map_err(|_| E::Uncertain)?;
        let (manifest, mut plan) = references(
            assignment.taskrun_id,
            assignment.attempt_id,
            cycle.cycle_id,
            conversation_id,
            conversation_version,
            &event_refs,
            &taskrun_event_refs,
            digest(Sha256::digest(prompt.as_bytes()).into()),
            workspace_binding.0,
            workspace_binding.1,
            workspace_binding.2,
            workspace_binding.3.instance_epoch,
            workspace_binding.3.revision,
            profile_digest,
            schema_digest,
            budget,
        );
        if coding {
            super::coding::initialize(&mut plan);
        }
        let mut version = stream.current_version;
        if cycle.context_manifest_ref.is_none() {
            d2_test_stage("commit_context");
            service
                .commit_context(
                    &Self::d2_command_context(
                        principal.clone(),
                        actor.clone(),
                        assignment.taskrun_id,
                        assignment.attempt_id,
                        Some(cycle.cycle_id),
                        "commit-context",
                        None,
                    ),
                    CommitContextInput {
                        taskrun_id: assignment.taskrun_id,
                        expected_version: version,
                        cycle_id: cycle.cycle_id,
                        manifest_ref: manifest.clone(),
                    },
                )
                .map_err(|error| {
                    d2_test_stage(application_error_stage("context", &error));
                    eprintln!(
                        "runne-child-diag: d2-plan stage=commit_context error_code={}",
                        application_error_code(&error)
                    );
                    E::Uncertain
                })?;
            d2_test_stage("context_committed");
            version = self
                .store
                .load_task_run(assignment.taskrun_id)
                .map_err(|_| E::Unavailable)?
                .current_version;
        } else if cycle.context_manifest_ref.as_ref() != Some(&manifest) {
            return Err(E::Uncertain);
        }
        if cycle.plan_revision_ref.is_none() {
            d2_test_stage("commit_plan");
            service
                .commit_plan(
                    &Self::d2_command_context(
                        principal,
                        actor,
                        assignment.taskrun_id,
                        assignment.attempt_id,
                        Some(cycle.cycle_id),
                        "commit-plan",
                        None,
                    ),
                    CommitPlanInput {
                        taskrun_id: assignment.taskrun_id,
                        expected_version: version,
                        cycle_id: cycle.cycle_id,
                        plan_revision_ref: plan.clone(),
                        input_digest: manifest.integrity_digest,
                        output_digest: plan.integrity_digest,
                        expected_proposal_indexes: plan.expected_proposal_indexes.clone(),
                    },
                )
                .map_err(|error| {
                    d2_test_stage(application_error_stage("plan", &error));
                    eprintln!(
                        "runne-child-diag: d2-plan stage=commit_plan error_code={}",
                        application_error_code(&error)
                    );
                    E::Uncertain
                })?;
            d2_test_stage("plan_committed");
            version = self
                .store
                .load_task_run(assignment.taskrun_id)
                .map_err(|_| E::Unavailable)?
                .current_version;
        } else if coding {
            let existing = cycle.plan_revision_ref.as_ref().ok_or(E::Uncertain)?;
            if existing.plan_id != plan.plan_id
                || existing.context_manifest_ref != plan.context_manifest_ref
                || existing.planning_policy_ref != plan.planning_policy_ref
                || existing.planning_budget_ref != plan.planning_budget_ref
                || existing.expected_proposal_indexes.len() > 32
            {
                return Err(E::Uncertain);
            }
            plan = existing.clone();
        } else if cycle.plan_revision_ref.as_ref() != Some(&plan) {
            return Err(E::Uncertain);
        }
        Ok((cycle.cycle_id, plan, version))
    }
}
